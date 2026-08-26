from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import secrets
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


PLAN_SCHEMA = "k_guard_l2_runtime_plan.v1"
SOURCE_SCHEMA = "k_guard_l2_source_materialization.v3"
RECEIPT_SCHEMA = "k_guard_l2_runtime_receipt.v1"
REPLAY_SCHEMA = "k_guard_l2_runtime_replay_comparison.v1"
APP_IDS = frozenset(
    {"juice-shop", "webgoat", "nodegoat", "pygoat", "crapi", "wrongsecrets"}
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DOCKER_OBJECT_ID_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_REF_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
IMAGE_REF_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9][A-Za-z0-9._-]*)?$")
OBJECT_NAME_RE = re.compile(r"^kguard-l2-[a-z0-9][a-z0-9_.-]{0,62}$")
RUN_AS_RE = re.compile(r"^([1-9][0-9]{0,9}):([0-9]{1,10})$")
SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
TMPFS_MODE_RE = re.compile(r"^0[0-7]{3}$")
HTTP_STATUS_RE = re.compile(rb"(?m)^\s*HTTP/\d(?:\.\d)?\s+([1-5][0-9]{2})(?:\s|$)")
WGET_SERVER_RESPONSE_FLAG_RE = re.compile(rb"(?m)^\s*-S\s")

PIDS_LIMIT = 256
MEMORY_BYTES = 512 * 1024 * 1024
NANO_CPUS = 1_000_000_000
MAX_UNIX_ID = 2**32 - 1
HELPER_PIDS_LIMIT = 32
HELPER_MEMORY_BYTES = 64 * 1024 * 1024
HELPER_NANO_CPUS = 250_000_000
HELPER_COMMAND = (
    "wget",
    "-q",
    "-T",
    "5",
    "-O",
    "/dev/null",
    "http://1.1.1.1/",
)
HELPER_SELF_TEST = ("wget", "--help")
MAX_COMMAND_SECONDS = 30 * 60
MAX_INSPECT_BYTES = 4 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_ARG_COUNT = 256
MAX_ARG_BYTES = 64 * 1024
MAX_DOCKERFILE_BYTES = 2 * 1024 * 1024
MAX_ADAPTER_FILE_BYTES = 2 * 1024 * 1024
MAX_ADAPTER_TOTAL_BYTES = 16 * 1024 * 1024
MAX_ADAPTER_FILES = 512


class RuntimeContractError(ValueError):
    pass


class DockerCommandError(RuntimeError):
    def __init__(self, operation: str, result: "CommandResult") -> None:
        super().__init__(operation)
        self.operation = operation
        self.result = result


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    output_truncated: bool = False


class CommandRunner(Protocol):
    def run(self, argv: list[str], *, timeout: int) -> CommandResult: ...


class SubprocessRunner:
    def run(self, argv: list[str], *, timeout: int) -> CommandResult:
        if (
            not argv
            or len(argv) > MAX_ARG_COUNT
            or any(not isinstance(item, str) or "\x00" in item for item in argv)
            or sum(len(item.encode("utf-8")) + 1 for item in argv) > MAX_ARG_BYTES
        ):
            raise RuntimeContractError("command argv is invalid")
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                shell=False,
                env=_command_environment(),
            )
            timed_out = False
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                process.wait()
                returncode = 124
            stdout.seek(0)
            stderr.seek(0)
            stdout_raw = stdout.read(MAX_COMMAND_OUTPUT_BYTES + 1)
            stderr_raw = stderr.read(MAX_COMMAND_OUTPUT_BYTES + 1)
        truncated = (
            len(stdout_raw) > MAX_COMMAND_OUTPUT_BYTES
            or len(stderr_raw) > MAX_COMMAND_OUTPUT_BYTES
        )
        return CommandResult(
            returncode,
            stdout_raw[:MAX_COMMAND_OUTPUT_BYTES],
            stderr_raw[:MAX_COMMAND_OUTPUT_BYTES],
            timed_out=timed_out,
            output_truncated=truncated,
        )


def _command_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "DOCKER_CLI_HINTS": "false",
            "DOCKER_SCAN_SUGGEST": "false",
            "LC_ALL": "C",
        }
    )
    return environment


def canonical_json_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise RuntimeContractError("value is not canonical-JSON serializable") from exc


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _load_canonical(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        if len(raw) > 64 * 1024 * 1024:
            raise RuntimeContractError(f"{label} exceeds size limit")
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise RuntimeContractError(f"{label} must be a canonical JSON object")
    return value, raw


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise RuntimeContractError(f"{label} fields differ from the locked contract")


def _load_source_module() -> tuple[Any, str]:
    path = Path(__file__).with_name("materialize_l2_sources.py")
    raw_before = path.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l2_sources_runtime", path)
    if spec is None or spec.loader is None:
        raise RuntimeContractError("L2 source verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if path.read_bytes() != raw_before:
        raise RuntimeContractError("L2 source verifier changed while loading")
    return module, sha256_bytes(raw_before)


def _safe_root(value: object, *, label: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RuntimeContractError(f"{label} must be a canonical absolute directory")
    path = Path(value)
    if not path.is_absolute():
        raise RuntimeContractError(f"{label} must be absolute")
    if _has_link_or_reparse_ancestor(path.absolute()):
        raise RuntimeContractError(f"{label} must be a real directory without links")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir() or _has_link_or_reparse_ancestor(resolved):
        raise RuntimeContractError(f"{label} must be a real directory without links")
    return resolved


def _has_link_or_reparse_ancestor(path: Path) -> bool:
    current = path
    while True:
        try:
            info = current.lstat()
        except OSError:
            return True
        attributes = int(getattr(info, "st_file_attributes", 0))
        reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if stat.S_ISLNK(info.st_mode) or attributes & reparse:
            return True
        if current.parent == current:
            return False
        current = current.parent


def _safe_relative(base: Path, value: object, *, label: str, file: bool = False) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RuntimeContractError(f"{label} must be a normalized relative path")
    relative = Path(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise RuntimeContractError(f"{label} must be a normalized relative path")
    unresolved = base / relative
    if _has_link_or_reparse_ancestor(unresolved):
        raise RuntimeContractError(f"{label} contains a link or reparse point")
    target = unresolved.resolve(strict=True)
    try:
        target.relative_to(base)
    except ValueError as exc:
        raise RuntimeContractError(f"{label} escapes its root") from exc
    if _has_link_or_reparse_ancestor(target):
        raise RuntimeContractError(f"{label} contains a link or reparse point")
    if file and not target.is_file():
        raise RuntimeContractError(f"{label} must be a regular file")
    if not file and not target.is_dir():
        raise RuntimeContractError(f"{label} must be a directory")
    return target


def _regular_tree_receipt(root: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in sorted(directories + files):
            target = current_path / name
            info = target.lstat()
            attributes = int(getattr(info, "st_file_attributes", 0))
            reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
            if stat.S_ISLNK(info.st_mode) or attributes & reparse:
                raise RuntimeContractError("adapter tree contains a link or reparse point")
        for name in sorted(files):
            target = current_path / name
            info = target.stat()
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeContractError("adapter tree contains a non-regular file")
            if info.st_size > MAX_ADAPTER_FILE_BYTES:
                raise RuntimeContractError("adapter file exceeds size limit")
            raw = target.read_bytes()
            rows.append(
                {
                    "path": target.relative_to(root).as_posix(),
                    "sha256": sha256_bytes(raw),
                    "byte_count": len(raw),
                }
            )
            if len(rows) > MAX_ADAPTER_FILES or sum(
                int(row["byte_count"]) for row in rows
            ) > MAX_ADAPTER_TOTAL_BYTES:
                raise RuntimeContractError("adapter tree exceeds size limit")
    rows.sort(key=lambda row: row["path"])
    return {
        "file_count": len(rows),
        "total_bytes": sum(row["byte_count"] for row in rows),
        "tree_sha256": sha256_bytes(
            b"k_guard_l2_adapter_tree.v1\0" + canonical_json_bytes(rows)
        ),
        "files": rows,
    }


def _bounded_file_receipt(path: Path, *, maximum_bytes: int) -> dict[str, Any]:
    size = path.stat().st_size
    if size < 0 or size > maximum_bytes:
        raise RuntimeContractError("file exceeds size limit")
    raw = path.read_bytes()
    if len(raw) != size:
        raise RuntimeContractError("file changed while hashing")
    return {"sha256": sha256_bytes(raw), "byte_count": size}


def _docker(
    runner: CommandRunner,
    operation: str,
    arguments: list[str],
    *,
    timeout: int = 60,
    check: bool = True,
) -> CommandResult:
    if timeout < 1 or timeout > MAX_COMMAND_SECONDS:
        raise RuntimeContractError("Docker timeout is outside the locked bound")
    result = runner.run(["docker", *arguments], timeout=timeout)
    if check and (result.returncode != 0 or result.timed_out or result.output_truncated):
        raise DockerCommandError(operation, result)
    return result


def _docker_json(
    runner: CommandRunner, operation: str, arguments: list[str], *, timeout: int = 60
) -> Any:
    result = _docker(runner, operation, arguments, timeout=timeout)
    if result.output_truncated or len(result.stdout) > MAX_INSPECT_BYTES:
        raise RuntimeContractError(f"{operation} output exceeds size limit")
    try:
        return json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError(f"{operation} did not return JSON") from exc


def _command_receipt(result: CommandResult) -> dict[str, Any]:
    return {
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "output_truncated": result.output_truncated,
        "stdout_sha256": sha256_bytes(result.stdout),
        "stdout_bytes": len(result.stdout),
        "stderr_sha256": sha256_bytes(result.stderr),
        "stderr_bytes": len(result.stderr),
        "raw_returned": False,
    }


def _single_inspect(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise RuntimeContractError(f"{label} must contain exactly one Docker object")
    return value[0]


def _validate_source_admission(
    admission: dict[str, Any], raw: bytes, source_module: Any, source_module_sha256: str
) -> dict[str, dict[str, Any]]:
    if admission.get("schema") != SOURCE_SCHEMA:
        raise RuntimeContractError("source admission schema is not v2")
    if admission.get("source_license_admission") != "PASS":
        raise RuntimeContractError("source and license admission did not pass")
    if admission.get("runtime_isolation_gate") != "HOLD":
        raise RuntimeContractError("source evidence improperly claims runtime isolation")
    if admission.get("release_gate_passed") is not False:
        raise RuntimeContractError("source evidence improperly claims release authority")
    provenance = admission.get("tool_provenance")
    try:
        _verifier, verifier_sha256 = source_module._load_source_materialization_with_hash()
    except (AttributeError, OSError, RuntimeError) as exc:
        raise RuntimeContractError("source verifier provenance cannot be loaded") from exc
    if (
        not isinstance(provenance, dict)
        or provenance.get("materializer_artifact") != "materialize_l2_sources.py"
        or provenance.get("materializer_sha256") != source_module_sha256
        or provenance.get("verifier_artifact") != "holdout_source_materialization.py"
        or provenance.get("verifier_sha256") != verifier_sha256
    ):
        raise RuntimeContractError("source materializer provenance differs from local verifier")
    apps = admission.get("apps")
    if not isinstance(apps, list) or len(apps) != len(APP_IDS):
        raise RuntimeContractError("source admission must contain the exact six apps")
    indexed: dict[str, dict[str, Any]] = {}
    for row in apps:
        if not isinstance(row, dict):
            raise RuntimeContractError("source app evidence must be an object")
        app_id = row.get("app_id")
        if app_id not in APP_IDS or app_id in indexed:
            raise RuntimeContractError("source app set is missing, duplicated, or unknown")
        locked = source_module.EXPECTED_IDENTITIES[app_id]
        expected = {
            "repository_id": locked["repository_id"],
            "commit": locked["commit"],
            "commit_tree": locked["commit_tree"],
            "source_tree_sha256": locked["source_tree_sha256"],
            "receipt_sha256": locked["receipt_sha256"],
        }
        if any(row.get(key) != expected_value for key, expected_value in expected.items()):
            raise RuntimeContractError(f"{app_id} source identity is not preregistered")
        if row.get("source_license_admission") != "PASS":
            raise RuntimeContractError(f"{app_id} source admission did not pass")
        indexed[app_id] = row
    if set(indexed) != APP_IDS:
        raise RuntimeContractError("source app set is incomplete")
    return indexed


def _verify_checkout(
    root: Path, app_id: str, source_module: Any, source_row: dict[str, Any]
) -> dict[str, Any]:
    locked = source_module.EXPECTED_IDENTITIES[app_id]
    verifier = source_module._load_source_materialization()
    receipt = verifier.build_git_materialization_receipt(
        root,
        expected_repository_id=locked["repository_id"],
        expected_commit=locked["commit"],
        expected_tree=locked["commit_tree"],
    )
    required = (
        "source_worktree_clean",
        "origin_repository_match",
        "commit_match",
        "commit_object_hash_match",
        "commit_tree_match",
        "tree_object_reconstruction_match",
        "index_tree_match",
        "physical_bytes_match_git_blobs",
        "git_fsck_strict_passed",
    )
    if (
        receipt.get("passed") is not True
        or receipt.get("source_tree_sha256") != source_row["source_tree_sha256"]
        or any(receipt.get(field) is not True for field in required)
    ):
        raise RuntimeContractError(f"{app_id} checkout no longer matches source admission")
    return {
        "source_tree_sha256": receipt["source_tree_sha256"],
        "file_count": receipt["file_count"],
        "total_bytes": receipt["total_bytes"],
        "verification_projection_sha256": _canonical_sha256(
            {field: receipt.get(field) for field in ("passed", *required)}
        ),
    }


def _validate_plan(
    plan: dict[str, Any], admission_sha256: str, source_root: Path
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    _exact_keys(
        plan,
        {"schema", "source_admission_sha256", "source_root", "helper", "apps"},
        "runtime plan",
    )
    if plan["schema"] != PLAN_SCHEMA or plan["source_admission_sha256"] != admission_sha256:
        raise RuntimeContractError("runtime plan is not bound to source admission")
    if Path(plan["source_root"]).resolve(strict=True) != source_root:
        raise RuntimeContractError("runtime plan source root is not canonical")
    helper = _validate_helper_plan(plan["helper"])
    apps = plan["apps"]
    if not isinstance(apps, list) or len(apps) != len(APP_IDS):
        raise RuntimeContractError("runtime plan must contain exactly six apps")
    indexed: dict[str, dict[str, Any]] = {}
    for row in apps:
        app = _validate_app_plan(row)
        if app["app_id"] in indexed:
            raise RuntimeContractError("runtime plan app_id is duplicated")
        indexed[app["app_id"]] = app
    if set(indexed) != APP_IDS:
        raise RuntimeContractError("runtime plan app set is incomplete")
    names = [
        value
        for app in indexed.values()
        for value in (app["runtime"]["container_name"], app["runtime"]["network_name"])
    ]
    if len(names) != len(set(names)):
        raise RuntimeContractError("container and network names must be globally unique")
    return helper, indexed


def _validate_helper_plan(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RuntimeContractError("helper must be an object")
    _exact_keys(value, {"image_reference", "expected_image_id"}, "helper")
    reference = value["image_reference"]
    image_id = value["expected_image_id"]
    if not isinstance(reference, str) or DIGEST_REF_RE.fullmatch(reference) is None:
        raise RuntimeContractError("helper image must be pinned by repository digest")
    if not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None:
        raise RuntimeContractError("helper expected image id must be immutable")
    return {"image_reference": reference, "expected_image_id": image_id}


def _validate_app_plan(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeContractError("runtime app plan must be an object")
    _exact_keys(value, {"app_id", "checkout_relative", "build", "runtime"}, "runtime app")
    app_id = value["app_id"]
    if app_id not in APP_IDS:
        raise RuntimeContractError("runtime app is outside the locked set")
    checkout = value["checkout_relative"]
    if not isinstance(checkout, str) or checkout != app_id:
        raise RuntimeContractError("checkout_relative must equal the locked app id")
    build = value["build"]
    if not isinstance(build, dict):
        raise RuntimeContractError("build plan must be an object")
    _exact_keys(build, {"source", "adapter"}, "build plan")
    source = _validate_source_build(build["source"])
    adapter = _validate_adapter_plan(build["adapter"])
    runtime = _validate_runtime_plan(value["runtime"])
    return {
        "app_id": app_id,
        "checkout_relative": checkout,
        "build": {"source": source, "adapter": adapter},
        "runtime": runtime,
    }


def _validate_source_build(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RuntimeContractError("source build must be an object")
    _exact_keys(
        value,
        {"mode", "image_reference", "dockerfile_relative", "context_relative"},
        "source build",
    )
    if value["mode"] not in {"build", "inspect_existing"}:
        raise RuntimeContractError("source build mode is invalid")
    reference = value["image_reference"]
    if not isinstance(reference, str) or IMAGE_REF_RE.fullmatch(reference) is None:
        raise RuntimeContractError("source image reference must be a local immutable plan tag")
    for field in ("dockerfile_relative", "context_relative"):
        item = value[field]
        if not isinstance(item, str) or not item or Path(item).is_absolute() or ".." in Path(item).parts:
            raise RuntimeContractError(f"source {field} is unsafe")
    return dict(value)


def _validate_adapter_plan(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RuntimeContractError("adapter must be null or an object")
    _exact_keys(
        value,
        {"root", "image_reference", "dockerfile_relative", "context_relative"},
        "adapter",
    )
    reference = value["image_reference"]
    if not isinstance(reference, str) or IMAGE_REF_RE.fullmatch(reference) is None:
        raise RuntimeContractError("adapter image reference is invalid")
    for field in ("root", "dockerfile_relative", "context_relative"):
        if not isinstance(value[field], str) or not value[field] or "\x00" in value[field]:
            raise RuntimeContractError(f"adapter {field} is invalid")
    return dict(value)


def _validate_runtime_plan(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeContractError("runtime settings must be an object")
    _exact_keys(
        value,
        {
            "container_name",
            "network_name",
            "container_port",
            "run_as",
            "tmpfs",
            "health_probe",
        },
        "runtime settings",
    )
    if any(
        not isinstance(value[field], str) or OBJECT_NAME_RE.fullmatch(value[field]) is None
        for field in ("container_name", "network_name")
    ):
        raise RuntimeContractError("runtime object names must use the kguard-l2 prefix")
    port = value["container_port"]
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise RuntimeContractError("container_port is invalid")
    run_as = _parse_run_as(value["run_as"])
    tmpfs = _validate_tmpfs(value["tmpfs"], run_as)
    health = _validate_health_plan(value["health_probe"])
    return {**value, "tmpfs": tmpfs, "health_probe": health}


def _parse_run_as(value: Any) -> tuple[int, int]:
    if not isinstance(value, str):
        raise RuntimeContractError("run_as must be a non-root numeric uid:gid")
    match = RUN_AS_RE.fullmatch(value)
    if match is None:
        raise RuntimeContractError("run_as must be a non-root numeric uid:gid")
    uid, gid = (int(part) for part in match.groups())
    if uid > MAX_UNIX_ID or gid > MAX_UNIX_ID:
        raise RuntimeContractError("run_as uid:gid is outside the locked bound")
    return uid, gid


def _validate_tmpfs(value: Any, run_as: tuple[int, int]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 8:
        raise RuntimeContractError("tmpfs must be a bounded array")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    base_keys = {"path", "size_bytes"}
    ownership_keys = {"uid", "gid", "mode"}
    for row in value:
        if not isinstance(row, dict):
            raise RuntimeContractError("tmpfs row must be an object")
        row_keys = set(row)
        if row_keys != base_keys and row_keys != base_keys | ownership_keys:
            raise RuntimeContractError(
                "tmpfs row must declare uid, gid, and mode together when ownership is set"
            )
        path, size = row["path"], row["size_bytes"]
        if (
            not isinstance(path, str)
            or SAFE_PATH_RE.fullmatch(path) is None
            or "//" in path
            or "/../" in path
            or path in seen
        ):
            raise RuntimeContractError("tmpfs path is unsafe or duplicated")
        if not isinstance(size, int) or isinstance(size, bool) or not 4096 <= size <= 64 * 1024 * 1024:
            raise RuntimeContractError("tmpfs size is outside the locked bound")
        seen.add(path)
        normalized = {"path": path, "size_bytes": size}
        if ownership_keys.issubset(row_keys):
            uid, gid, mode = row["uid"], row["gid"], row["mode"]
            if (
                not isinstance(uid, int)
                or isinstance(uid, bool)
                or not isinstance(gid, int)
                or isinstance(gid, bool)
                or not 0 <= uid <= MAX_UNIX_ID
                or not 0 <= gid <= MAX_UNIX_ID
            ):
                raise RuntimeContractError("tmpfs ownership ids are invalid")
            if (uid, gid) != run_as:
                raise RuntimeContractError(
                    "tmpfs ownership must exactly match the non-root runtime user"
                )
            if (
                not isinstance(mode, str)
                or TMPFS_MODE_RE.fullmatch(mode) is None
                or mode[-1] != "0"
                or int(mode[1], 8) & 0o2 == 0
            ):
                raise RuntimeContractError(
                    "tmpfs mode must be owner-writable and deny all world permissions"
                )
            normalized.update({"uid": uid, "gid": gid, "mode": mode})
        rows.append(normalized)
    rows.sort(key=lambda row: row["path"])
    return rows


def _validate_health_plan(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeContractError("health probe must be an object")
    _exact_keys(
        value,
        {"path", "expected_status", "timeout_seconds", "attempts", "interval_seconds"},
        "health probe",
    )
    path = value["path"]
    statuses = value["expected_status"]
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or "\x00" in path
        or "\r" in path
        or "\n" in path
        or len(path.encode("utf-8")) > 512
    ):
        raise RuntimeContractError("health path is unsafe")
    if (
        not isinstance(statuses, list)
        or not statuses
        or len(statuses) > 8
        or any(
            not isinstance(status, int)
            or isinstance(status, bool)
            or not 200 <= status <= 399
            for status in statuses
        )
        or len(statuses) != len(set(statuses))
    ):
        raise RuntimeContractError("health expected_status is invalid")
    timeout = value["timeout_seconds"]
    attempts = value["attempts"]
    interval = value["interval_seconds"]
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 30:
        raise RuntimeContractError("health timeout is outside the locked bound")
    if not isinstance(attempts, int) or isinstance(attempts, bool) or not 1 <= attempts <= 30:
        raise RuntimeContractError("health attempts are outside the locked bound")
    if not isinstance(interval, int) or isinstance(interval, bool) or not 0 <= interval <= 10:
        raise RuntimeContractError("health interval is outside the locked bound")
    return {
        "path": path,
        "expected_status": sorted(statuses),
        "timeout_seconds": timeout,
        "attempts": attempts,
        "interval_seconds": interval,
    }


def _image_projection(image: dict[str, Any]) -> dict[str, Any]:
    config = image.get("Config") if isinstance(image.get("Config"), dict) else {}
    rootfs = image.get("RootFS") if isinstance(image.get("RootFS"), dict) else {}
    labels = config.get("Labels") if isinstance(config.get("Labels"), dict) else {}
    env = config.get("Env") if isinstance(config.get("Env"), list) else []
    layers = rootfs.get("Layers") if isinstance(rootfs.get("Layers"), list) else []
    normalized_layers = [item for item in layers if isinstance(item, str)]
    return {
        "id": image.get("Id"),
        "repo_digests": sorted(item for item in image.get("RepoDigests", []) if isinstance(item, str)),
        "rootfs_type": rootfs.get("Type"),
        "rootfs_layers": normalized_layers,
        "rootfs_layers_sha256": _canonical_sha256(normalized_layers),
        "config": {
            "user": config.get("User") or "",
            "working_dir": config.get("WorkingDir") or "",
            "entrypoint_sha256": _canonical_sha256(config.get("Entrypoint")),
            "cmd_sha256": _canonical_sha256(config.get("Cmd")),
            "env_names": sorted(
                {item.split("=", 1)[0] for item in env if isinstance(item, str) and "=" in item}
            ),
            "exposed_ports": sorted((config.get("ExposedPorts") or {}).keys()),
            "labels": {
                key: labels.get(key)
                for key in sorted(labels)
                if key.startswith("io.k-guard.") or key == "org.opencontainers.image.revision"
            },
        },
    }


def _inspect_image(runner: CommandRunner, reference: str) -> dict[str, Any]:
    image = _single_inspect(
        _docker_json(runner, "image_inspect", ["image", "inspect", reference]),
        "image inspect",
    )
    projection = _image_projection(image)
    if not isinstance(projection["id"], str) or IMAGE_ID_RE.fullmatch(projection["id"]) is None:
        raise RuntimeContractError("Docker image id is not immutable")
    return projection


def _source_labels(app_id: str, source_row: dict[str, Any], dockerfile_sha256: str) -> dict[str, str]:
    return {
        "io.k-guard.app-id": app_id,
        "io.k-guard.source-tree-sha256": source_row["source_tree_sha256"],
        "io.k-guard.dockerfile-sha256": dockerfile_sha256,
        "org.opencontainers.image.revision": source_row["commit"],
    }


def _build_image(
    runner: CommandRunner,
    *,
    reference: str,
    dockerfile: Path,
    context: Path,
    labels: dict[str, str],
    source_image_reference: str | None = None,
) -> dict[str, Any]:
    arguments = ["build", "--pull=false", "--progress=plain"]
    for key, value in sorted(labels.items()):
        arguments.extend(["--label", f"{key}={value}"])
    if source_image_reference is not None:
        if IMAGE_REF_RE.fullmatch(source_image_reference) is None:
            raise RuntimeContractError("source image reference is invalid")
        arguments.extend(["--build-arg", f"SOURCE_IMAGE={source_image_reference}"])
    arguments.extend(["--file", str(dockerfile), "--tag", reference, str(context)])
    result = _docker(runner, "image_build", arguments, timeout=MAX_COMMAND_SECONDS, check=False)
    receipt = _command_receipt(result)
    if result.returncode != 0 or result.timed_out or result.output_truncated:
        raise DockerCommandError("image_build", result)
    return receipt


def _verify_image_labels(image: dict[str, Any], expected: dict[str, str]) -> dict[str, bool]:
    labels = image.get("config", {}).get("labels", {})
    return {key: labels.get(key) == value for key, value in sorted(expected.items())}


def _prepare_images(
    runner: CommandRunner,
    app_id: str,
    app: dict[str, Any],
    checkout: Path,
    source_row: dict[str, Any],
    source_root: Path,
) -> tuple[dict[str, Any], str]:
    source = app["build"]["source"]
    context = checkout if source["context_relative"] == "." else _safe_relative(
        checkout, source["context_relative"], label="source build context"
    )
    dockerfile = _safe_relative(
        checkout, source["dockerfile_relative"], label="source Dockerfile", file=True
    )
    dockerfile_receipt = _bounded_file_receipt(
        dockerfile, maximum_bytes=MAX_DOCKERFILE_BYTES
    )
    dockerfile_sha256 = dockerfile_receipt["sha256"]
    labels = _source_labels(app_id, source_row, dockerfile_sha256)
    build_receipt: dict[str, Any] | None = None
    if source["mode"] == "build":
        build_receipt = _build_image(
            runner,
            reference=source["image_reference"],
            dockerfile=dockerfile,
            context=context,
            labels=labels,
        )
    source_image = _inspect_image(runner, source["image_reference"])
    source_checks = _verify_image_labels(source_image, labels)
    source_result: dict[str, Any] = {
        "mode": source["mode"],
        "reference_sha256": sha256_bytes(source["image_reference"].encode("utf-8")),
        "dockerfile": {
            "path": dockerfile.relative_to(checkout).as_posix(),
            "sha256": dockerfile_sha256,
            "byte_count": dockerfile_receipt["byte_count"],
        },
        "context_relative": context.relative_to(checkout).as_posix() or ".",
        "build_command": build_receipt,
        "image": source_image,
        "label_checks": source_checks,
        "passed": source["mode"] == "build"
        and build_receipt is not None
        and all(source_checks.values())
        and bool(source_image["repo_digests"]),
        "claim_boundary": (
            "harness_built_from_verified_checkout"
            if source["mode"] == "build"
            else "existing_image_observed_not_proven"
        ),
    }
    runtime_image_id = source_image["id"]
    adapter_plan = app["build"]["adapter"]
    adapter_result: dict[str, Any] | None = None
    if adapter_plan is not None:
        adapter_root = _safe_root(adapter_plan["root"], label="adapter root")
        try:
            adapter_root.relative_to(source_root)
        except ValueError:
            pass
        else:
            raise RuntimeContractError("adapter root must be outside the source root")
        context = adapter_root if adapter_plan["context_relative"] == "." else _safe_relative(
            adapter_root, adapter_plan["context_relative"], label="adapter context"
        )
        dockerfile = _safe_relative(
            adapter_root,
            adapter_plan["dockerfile_relative"],
            label="adapter Dockerfile",
            file=True,
        )
        adapter_tree_before = _regular_tree_receipt(adapter_root)
        adapter_labels = {
            "io.k-guard.adapter-tree-sha256": adapter_tree_before["tree_sha256"],
            "io.k-guard.app-id": app_id,
            "io.k-guard.source-image-id": source_image["id"],
            "io.k-guard.source-tree-sha256": source_row["source_tree_sha256"],
        }
        command_receipt = _build_image(
            runner,
            reference=adapter_plan["image_reference"],
            dockerfile=dockerfile,
            context=context,
            labels=adapter_labels,
            # BuildKit resolves a local tag but treats a bare image ID as a registry name.
            source_image_reference=source["image_reference"],
        )
        adapter_tree_after = _regular_tree_receipt(adapter_root)
        if adapter_tree_after != adapter_tree_before:
            raise RuntimeContractError("adapter tree changed during build")
        source_after_adapter = _inspect_image(runner, source["image_reference"])
        source_reference_unchanged = (
            source_after_adapter["id"] == source_image["id"]
            and source_after_adapter["rootfs_layers"] == source_image["rootfs_layers"]
        )
        adapter_image = _inspect_image(runner, adapter_plan["image_reference"])
        adapter_checks = _verify_image_labels(adapter_image, adapter_labels)
        adapter_checks["source_reference_unchanged"] = source_reference_unchanged
        source_layers = source_image["rootfs_layers"]
        adapter_layers = adapter_image["rootfs_layers"]
        adapter_checks["source_layers_are_prefix"] = bool(source_layers) and (
            adapter_layers[: len(source_layers)] == source_layers
        )
        adapter_dockerfile_receipt = _bounded_file_receipt(
            dockerfile, maximum_bytes=MAX_DOCKERFILE_BYTES
        )
        adapter_result = {
            "tree": adapter_tree_before,
            "dockerfile": {
                "path": dockerfile.relative_to(adapter_root).as_posix(),
                "sha256": adapter_dockerfile_receipt["sha256"],
                "byte_count": adapter_dockerfile_receipt["byte_count"],
            },
            "source_image_id": source_image["id"],
            "source_image_reference_sha256": sha256_bytes(
                source["image_reference"].encode("utf-8")
            ),
            "build_command": command_receipt,
            "image": adapter_image,
            "label_checks": adapter_checks,
            "passed": all(adapter_checks.values()) and bool(adapter_image["repo_digests"]),
        }
        runtime_image_id = adapter_image["id"]
    return {"source": source_result, "adapter": adapter_result}, runtime_image_id


def _ensure_absent(runner: CommandRunner, kind: str, name: str) -> None:
    result = _docker(runner, f"{kind}_absence", [kind, "inspect", name], check=False)
    if result.timed_out or result.output_truncated:
        raise DockerCommandError(f"{kind}_absence", result)
    if result.returncode == 0:
        raise RuntimeContractError(f"refusing pre-existing Docker {kind} object")


def _named_object_listing(
    runner: CommandRunner, kind: str, name: str
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    if kind == "container":
        arguments = [
            "container",
            "ls",
            "--all",
            "--filter",
            f"name=^/{name}$",
            "--format",
            "{{.Names}}\t{{.ID}}",
        ]
    elif kind == "network":
        arguments = [
            "network",
            "ls",
            "--filter",
            f"name=^{name}$",
            "--format",
            "{{.Name}}\t{{.ID}}",
        ]
    else:
        raise RuntimeContractError("cleanup object kind is invalid")
    result = _docker(
        runner,
        f"{kind}_cleanup_listing",
        arguments,
        timeout=60,
        check=False,
    )
    receipt = _command_receipt(result)
    receipt["argv_sha256"] = _canonical_sha256(arguments)
    if result.returncode != 0 or result.timed_out or result.output_truncated:
        raise DockerCommandError(f"{kind}_cleanup_listing", result)
    try:
        lines = result.stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise RuntimeContractError("Docker cleanup listing is not UTF-8") from exc
    rows: list[dict[str, str]] = []
    for line in lines:
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) != 2 or parts[0] != name or not parts[1]:
            raise RuntimeContractError("Docker cleanup listing is ambiguous")
        rows.append({"name": parts[0], "id": parts[1]})
    if len(rows) > 1:
        raise RuntimeContractError("Docker cleanup listing contains duplicate names")
    return rows, receipt


def _cleanup_owned_object(
    runner: CommandRunner,
    *,
    kind: str,
    name: str,
    app_id: str,
    expected_object_id: str | None,
) -> dict[str, Any]:
    try:
        before, before_receipt = _named_object_listing(runner, kind, name)
    except (DockerCommandError, RuntimeContractError):
        return {
            "kind": kind,
            "name_sha256": sha256_bytes(name.encode("utf-8")),
            "present_before": None,
            "ownership_verified": False,
            "removed": False,
            "absent_after": False,
            "passed": False,
            "blocker": "cleanup_listing_failed",
            "raw_returned": False,
        }
    if not before:
        return {
            "kind": kind,
            "name_sha256": sha256_bytes(name.encode("utf-8")),
            "present_before": False,
            "ownership_verified": True,
            "removed": False,
            "absent_after": True,
            "listing_before": before_receipt,
            "passed": True,
            "blocker": None,
            "raw_returned": False,
        }
    if expected_object_id is None:
        return {
            "kind": kind,
            "name_sha256": sha256_bytes(name.encode("utf-8")),
            "present_before": True,
            "ownership_verified": False,
            "removed": False,
            "absent_after": False,
            "listing_before": before_receipt,
            "passed": False,
            "blocker": "cleanup_unexpected_preexisting_object",
            "raw_returned": False,
        }
    try:
        value = _single_inspect(
            _docker_json(
                runner,
                f"{kind}_cleanup_inspect",
                [kind, "inspect", name],
            ),
            f"{kind} cleanup inspect",
        )
    except (DockerCommandError, RuntimeContractError):
        return {
            "kind": kind,
            "name_sha256": sha256_bytes(name.encode("utf-8")),
            "present_before": True,
            "ownership_verified": False,
            "removed": False,
            "absent_after": False,
            "listing_before": before_receipt,
            "passed": False,
            "blocker": "cleanup_inspect_failed",
            "raw_returned": False,
        }
    labels_source = (
        value.get("Config", {}).get("Labels", {})
        if kind == "container" and isinstance(value.get("Config"), dict)
        else value.get("Labels", {})
    )
    labels = labels_source if isinstance(labels_source, dict) else {}
    object_id = str(value.get("Id") or "")
    listed_id = before[0]["id"]
    ownership_verified = (
        labels.get("io.k-guard.runtime-contract") == "v1"
        and labels.get("io.k-guard.app-id") == app_id
        and bool(object_id)
        and object_id == expected_object_id
        and object_id.startswith(listed_id)
    )
    if not ownership_verified:
        return {
            "kind": kind,
            "name_sha256": sha256_bytes(name.encode("utf-8")),
            "object_id_sha256": sha256_bytes(object_id.encode("utf-8")),
            "present_before": True,
            "ownership_verified": False,
            "removed": False,
            "absent_after": False,
            "listing_before": before_receipt,
            "passed": False,
            "blocker": "cleanup_ownership_mismatch",
            "raw_returned": False,
        }
    arguments = (
        ["container", "rm", "--force", name]
        if kind == "container"
        else ["network", "rm", name]
    )
    removal = _docker(
        runner,
        f"{kind}_cleanup_remove",
        arguments,
        timeout=60,
        check=False,
    )
    removal_receipt = _command_receipt(removal)
    removal_receipt["argv_sha256"] = _canonical_sha256(arguments)
    try:
        after, after_receipt = _named_object_listing(runner, kind, name)
        absent_after = not after
    except (DockerCommandError, RuntimeContractError):
        after_receipt = None
        absent_after = False
    removed = (
        removal.returncode == 0
        and not removal.timed_out
        and not removal.output_truncated
    )
    passed = removed and absent_after
    return {
        "kind": kind,
        "name_sha256": sha256_bytes(name.encode("utf-8")),
        "object_id_sha256": sha256_bytes(object_id.encode("utf-8")),
        "present_before": True,
        "ownership_verified": True,
        "removed": removed,
        "absent_after": absent_after,
        "listing_before": before_receipt,
        "remove_command": removal_receipt,
        "listing_after": after_receipt,
        "passed": passed,
        "blocker": None if passed else "cleanup_remove_failed",
        "raw_returned": False,
    }


def _cleanup_runtime_objects(
    runner: CommandRunner,
    app_id: str,
    runtime: dict[str, Any],
    created_object_ids: dict[str, str | None],
) -> dict[str, Any]:
    container = _cleanup_owned_object(
        runner,
        kind="container",
        name=runtime["container_name"],
        app_id=app_id,
        expected_object_id=created_object_ids.get("container"),
    )
    network = _cleanup_owned_object(
        runner,
        kind="network",
        name=runtime["network_name"],
        app_id=app_id,
        expected_object_id=created_object_ids.get("network"),
    )
    return {
        "container": container,
        "network": network,
        "passed": container["passed"] is True and network["passed"] is True,
        "raw_returned": False,
    }


def _created_object_id(result: CommandResult, *, label: str) -> str:
    try:
        value = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise RuntimeContractError(f"{label} did not return an ASCII object id") from exc
    if DOCKER_OBJECT_ID_RE.fullmatch(value) is None:
        raise RuntimeContractError(f"{label} did not return a full Docker object id")
    return value


def _create_network(
    runner: CommandRunner,
    app_id: str,
    name: str,
    created_object_ids: dict[str, str | None],
) -> dict[str, Any]:
    _ensure_absent(runner, "network", name)
    result = _docker(
        runner,
        "network_create",
        [
            "network",
            "create",
            "--driver",
            "bridge",
            "--internal",
            "--label",
            f"io.k-guard.app-id={app_id}",
            "--label",
            "io.k-guard.runtime-contract=v1",
            name,
        ],
    )
    created_object_ids["network"] = _created_object_id(
        result, label="network create"
    )
    network = _single_inspect(
        _docker_json(runner, "network_inspect", ["network", "inspect", name]),
        "network inspect",
    )
    labels = network.get("Labels") if isinstance(network.get("Labels"), dict) else {}
    checks = {
        "created_id_exact": network.get("Id") == created_object_ids["network"],
        "driver_bridge": network.get("Driver") == "bridge",
        "internal_true": network.get("Internal") is True,
        "ingress_false": network.get("Ingress") is False,
        "scope_local": network.get("Scope") == "local",
        "contract_label": labels.get("io.k-guard.runtime-contract") == "v1",
        "app_label": labels.get("io.k-guard.app-id") == app_id,
    }
    return {
        "id": network.get("Id"),
        "create_command": _command_receipt(result),
        "checks": checks,
        "passed": all(checks.values()),
    }


def _tmpfs_option(row: dict[str, Any]) -> str:
    tokens = [
        f"{row['path']}:rw",
        "noexec",
        "nosuid",
        "nodev",
        f"size={row['size_bytes']}",
    ]
    if "uid" in row:
        tokens.extend([f"uid={row['uid']}", f"gid={row['gid']}", f"mode={row['mode']}"])
    return ",".join(tokens)


def _tmpfs_options_hardened(row: dict[str, Any], value: Any) -> bool:
    if not isinstance(value, str):
        return False
    tokens = [token.strip() for token in value.split(",")]
    if not tokens or any(not token for token in tokens):
        return False
    token_keys = [token.split("=", 1)[0] for token in tokens]
    if len(token_keys) != len(set(token_keys)):
        return False
    expected = {
        "rw",
        "noexec",
        "nosuid",
        "nodev",
        f"size={row['size_bytes']}",
    }
    if "uid" in row:
        expected.update(
            {f"uid={row['uid']}", f"gid={row['gid']}", f"mode={row['mode']}"}
        )
    actual = set(tokens)
    return expected.issubset(actual) and not actual.intersection(
        {"ro", "exec", "suid", "dev"}
    )


def _create_container(
    runner: CommandRunner,
    app_id: str,
    runtime: dict[str, Any],
    image_id: str,
    created_object_ids: dict[str, str | None],
) -> dict[str, Any]:
    name = runtime["container_name"]
    _ensure_absent(runner, "container", name)
    arguments = [
        "container",
        "create",
        "--name",
        name,
        "--label",
        f"io.k-guard.app-id={app_id}",
        "--label",
        "io.k-guard.runtime-contract=v1",
        "--network",
        runtime["network_name"],
        "--network-alias",
        app_id,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--pids-limit",
        str(PIDS_LIMIT),
        "--memory",
        str(MEMORY_BYTES),
        "--cpus",
        "1.0",
        "--user",
        runtime["run_as"],
        "--restart",
        "no",
    ]
    for row in runtime["tmpfs"]:
        arguments.extend(["--tmpfs", _tmpfs_option(row)])
    arguments.append(image_id)
    result = _docker(runner, "container_create", arguments)
    created_object_ids["container"] = _created_object_id(
        result, label="container create"
    )
    container = _single_inspect(
        _docker_json(runner, "container_inspect", ["container", "inspect", name]),
        "container inspect",
    )
    projection, checks = _container_projection(container, runtime, image_id, app_id)
    checks["created_id_exact"] = (
        container.get("Id") == created_object_ids["container"]
    )
    return {
        "id": container.get("Id"),
        "create_command": _command_receipt(result),
        "projection": projection,
        "checks": checks,
        "passed": all(checks.values()),
    }


def _observe_container_after_start(
    runner: CommandRunner,
    app_id: str,
    runtime: dict[str, Any],
    image_id: str,
    expected_container_id: str,
) -> dict[str, Any]:
    container = _single_inspect(
        _docker_json(
            runner,
            "container_post_start_inspect",
            ["container", "inspect", runtime["container_name"]],
        ),
        "post-start container inspect",
    )
    projection, checks = _container_projection(container, runtime, image_id, app_id)
    state = container.get("State") if isinstance(container.get("State"), dict) else {}
    state_projection = {
        "status": state.get("Status"),
        "running": state.get("Running"),
        "paused": state.get("Paused"),
        "restarting": state.get("Restarting"),
        "oom_killed": state.get("OOMKilled"),
        "dead": state.get("Dead"),
        "exit_code": state.get("ExitCode"),
        "error_sha256": sha256_bytes(str(state.get("Error") or "").encode("utf-8")),
        "raw_error_returned": False,
    }
    state_checks = {
        "same_container_id": container.get("Id") == expected_container_id,
        "running": state.get("Running") is True and state.get("Status") == "running",
        "not_paused": state.get("Paused") is False,
        "not_restarting": state.get("Restarting") is False,
        "not_oom_killed": state.get("OOMKilled") is False,
        "not_dead": state.get("Dead") is False,
    }
    combined_checks = {
        **{f"isolation_{key}": value for key, value in checks.items()},
        **state_checks,
    }
    return {
        "id": container.get("Id"),
        "projection": projection,
        "state": state_projection,
        "checks": combined_checks,
        "passed": all(combined_checks.values()),
    }


def _observe_network_after_runtime(
    runner: CommandRunner,
    app_id: str,
    network_name: str,
    expected_container_id: str,
) -> dict[str, Any]:
    network = _single_inspect(
        _docker_json(
            runner,
            "network_post_runtime_inspect",
            ["network", "inspect", network_name],
        ),
        "post-runtime network inspect",
    )
    labels = network.get("Labels") if isinstance(network.get("Labels"), dict) else {}
    containers = network.get("Containers") if isinstance(network.get("Containers"), dict) else {}
    checks = {
        "same_internal_bridge": network.get("Driver") == "bridge"
        and network.get("Internal") is True
        and network.get("Ingress") is False
        and network.get("Scope") == "local",
        "contract_label": labels.get("io.k-guard.runtime-contract") == "v1",
        "app_label": labels.get("io.k-guard.app-id") == app_id,
        "only_expected_container_attached": set(containers) == {expected_container_id},
    }
    return {
        "id": network.get("Id"),
        "attached_container_ids_sha256": _canonical_sha256(sorted(containers)),
        "attached_container_count": len(containers),
        "checks": checks,
        "passed": all(checks.values()),
    }


def _container_projection(
    container: dict[str, Any],
    runtime: dict[str, Any],
    image_id: str,
    app_id: str,
) -> tuple[dict[str, Any], dict[str, bool]]:
    host = container.get("HostConfig") if isinstance(container.get("HostConfig"), dict) else {}
    config = container.get("Config") if isinstance(container.get("Config"), dict) else {}
    network_settings = (
        container.get("NetworkSettings")
        if isinstance(container.get("NetworkSettings"), dict)
        else {}
    )
    networks = network_settings.get("Networks") if isinstance(network_settings.get("Networks"), dict) else {}
    port_bindings = host.get("PortBindings")
    runtime_ports = network_settings.get("Ports")

    def no_host_publish(value: Any) -> bool:
        if value is None:
            return True
        if not isinstance(value, dict):
            return False
        return all(binding is None or binding == [] for binding in value.values())

    attachment = networks.get(runtime["network_name"])
    aliases = (
        attachment.get("Aliases")
        if isinstance(attachment, dict) and isinstance(attachment.get("Aliases"), list)
        else []
    )
    mounts = container.get("Mounts") if isinstance(container.get("Mounts"), list) else []
    expected_tmpfs = {row["path"]: row for row in runtime["tmpfs"]}
    actual_tmpfs = host.get("Tmpfs") if isinstance(host.get("Tmpfs"), dict) else {}
    tmpfs_paths = set(actual_tmpfs)
    mount_types = {row.get("Type") for row in mounts if isinstance(row, dict)}
    mount_destinations = {row.get("Destination") for row in mounts if isinstance(row, dict)}
    labels = config.get("Labels") if isinstance(config.get("Labels"), dict) else {}
    cap_drop = {str(item).upper() for item in host.get("CapDrop", []) if isinstance(item, str)}
    cap_add = host.get("CapAdd") or []
    security = {str(item).casefold() for item in host.get("SecurityOpt", []) if isinstance(item, str)}
    checks = {
        "image_id_exact": container.get("Image") == image_id,
        "app_label_exact": labels.get("io.k-guard.app-id") == app_id,
        "contract_label_exact": labels.get("io.k-guard.runtime-contract") == "v1",
        "network_mode_exact": host.get("NetworkMode") == runtime["network_name"],
        "single_internal_network": set(networks) == {runtime["network_name"]},
        "network_alias_present": app_id in aliases,
        "no_host_port_publish": no_host_publish(port_bindings)
        and no_host_publish(runtime_ports),
        "read_only_rootfs": host.get("ReadonlyRootfs") is True,
        "tmpfs_paths_exact": tmpfs_paths == set(expected_tmpfs)
        and mount_destinations.issubset(set(expected_tmpfs)),
        "tmpfs_options_hardened": all(
            _tmpfs_options_hardened(row, actual_tmpfs.get(path))
            for path, row in expected_tmpfs.items()
        ),
        "no_bind_or_volume_mounts": not host.get("Binds")
        and not host.get("Mounts")
        and mount_types.issubset({"tmpfs"}),
        "docker_socket_absent": all(
            "docker.sock" not in str(row).casefold() for row in mounts
        ),
        "cap_drop_all": "ALL" in cap_drop and not cap_add,
        "no_new_privileges": any(item.startswith("no-new-privileges") for item in security),
        "pids_bounded": host.get("PidsLimit") == PIDS_LIMIT,
        "memory_bounded": host.get("Memory") == MEMORY_BYTES,
        "cpu_bounded": host.get("NanoCpus") == NANO_CPUS,
        "not_privileged": host.get("Privileged") is False,
        "non_root_user": config.get("User") == runtime["run_as"],
        "no_host_pid": str(host.get("PidMode") or "") not in {"host", "private:host"},
        "no_host_ipc": str(host.get("IpcMode") or "") != "host",
        "no_host_uts": str(host.get("UTSMode") or "") != "host",
        "no_host_userns": str(host.get("UsernsMode") or "") != "host",
        "no_devices": not host.get("Devices") and not host.get("DeviceRequests"),
        "restart_disabled": (host.get("RestartPolicy") or {}).get("Name", "") in {"", "no"},
    }
    projection = {
        "image_id": container.get("Image"),
        "user": config.get("User") or "",
        "network_mode": host.get("NetworkMode"),
        "network_names": sorted(networks),
        "host_port_publish_shape_sha256": _canonical_sha256(port_bindings),
        "runtime_port_shape_sha256": _canonical_sha256(runtime_ports),
        "network_aliases_sha256": _canonical_sha256(sorted(str(alias) for alias in aliases)),
        "tmpfs_projection_sha256": _canonical_sha256(actual_tmpfs),
        "mount_projection_sha256": _canonical_sha256(mounts),
        "security_opt": sorted(security),
        "cap_drop": sorted(cap_drop),
        "pids_limit": host.get("PidsLimit"),
        "memory_bytes": host.get("Memory"),
        "nano_cpus": host.get("NanoCpus"),
        "privileged": host.get("Privileged"),
        "pid_mode": host.get("PidMode") or "",
        "ipc_mode": host.get("IpcMode") or "",
        "uts_mode": host.get("UTSMode") or "",
        "userns_mode": host.get("UsernsMode") or "",
    }
    return projection, checks


def _helper_hardening() -> list[str]:
    return [
        "run",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=4194304",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--pids-limit",
        str(HELPER_PIDS_LIMIT),
        "--memory",
        str(HELPER_MEMORY_BYTES),
        "--cpus",
        "0.25",
        "--user",
        "65534:65534",
    ]


def _helper_identity_checks(helper: dict[str, str], helper_image: dict[str, Any]) -> dict[str, bool]:
    return {
        "helper_reference_digest_pinned": DIGEST_REF_RE.fullmatch(
            helper["image_reference"]
        )
        is not None,
        "helper_repo_digest_present": helper["image_reference"]
        in helper_image["repo_digests"],
        "helper_image_id_exact": helper_image["id"] == helper["expected_image_id"],
    }


def _internal_health_probe(
    runner: CommandRunner,
    helper: dict[str, str],
    network_name: str,
    app_id: str,
    runtime: dict[str, Any],
) -> dict[str, Any]:
    helper_image = _inspect_image(runner, helper["image_reference"])
    identity_checks = _helper_identity_checks(helper, helper_image)
    plan = runtime["health_probe"]
    target = f"http://{app_id}:{runtime['container_port']}{plan['path']}"
    base_checks = {
        **identity_checks,
        "helper_command_available": False,
        "helper_server_response_supported": False,
    }
    if not all(identity_checks.values()):
        return {
            "helper_image": helper_image,
            "executed": False,
            "passed": False,
            "status": None,
            "attempt": None,
            "self_test": None,
            "command": None,
            "checks": {
                **base_checks,
                "probe_executed": False,
                "request_succeeded": False,
                "response_status_observed": False,
                "response_status_expected": False,
            },
            "raw_returned": False,
        }
    self_test_arguments = [
        *_helper_hardening(),
        "--network",
        "none",
        helper["image_reference"],
        *HELPER_SELF_TEST,
    ]
    self_test = _docker(
        runner, "internal_health_helper_self_test", self_test_arguments, timeout=20, check=False
    )
    self_test_receipt = _command_receipt(self_test)
    self_test_receipt["argv_sha256"] = _canonical_sha256(self_test_arguments)
    base_checks["helper_command_available"] = (
        self_test.returncode == 0
        and not self_test.timed_out
        and not self_test.output_truncated
    )
    base_checks["helper_server_response_supported"] = (
        base_checks["helper_command_available"]
        and WGET_SERVER_RESPONSE_FLAG_RE.search(self_test.stdout + b"\n" + self_test.stderr)
        is not None
    )
    if not all(base_checks.values()):
        return {
            "helper_image": helper_image,
            "executed": False,
            "passed": False,
            "status": None,
            "attempt": None,
            "self_test": self_test_receipt,
            "command": None,
            "checks": {
                **base_checks,
                "probe_executed": False,
                "request_succeeded": False,
                "response_status_observed": False,
                "response_status_expected": False,
            },
            "raw_returned": False,
        }
    last: dict[str, Any] = {
        "helper_image": helper_image,
        "executed": False,
        "passed": False,
        "status": None,
        "attempt": None,
        "self_test": self_test_receipt,
        "command": None,
        "checks": {
            **base_checks,
            "probe_executed": False,
            "request_succeeded": False,
            "response_status_observed": False,
            "response_status_expected": False,
        },
        "raw_returned": False,
    }
    for attempt in range(1, plan["attempts"] + 1):
        arguments = [
            *_helper_hardening(),
            "--network",
            network_name,
            helper["image_reference"],
            "wget",
            "-q",
            "-S",
            "-T",
            str(plan["timeout_seconds"]),
            "-O",
            "/dev/null",
            target,
        ]
        result = _docker(
            runner,
            "internal_health_probe",
            arguments,
            timeout=min(MAX_COMMAND_SECONDS, plan["timeout_seconds"] + 10),
            check=False,
        )
        statuses = HTTP_STATUS_RE.findall(result.stderr)
        status = int(statuses[0]) if statuses else None
        command = _command_receipt(result)
        command["argv_sha256"] = _canonical_sha256(arguments)
        checks = {
            **base_checks,
            "probe_executed": not result.timed_out and not result.output_truncated,
            "request_succeeded": result.returncode == 0
            and not result.timed_out
            and not result.output_truncated,
            "response_status_observed": status is not None,
            "response_status_expected": status in plan["expected_status"],
        }
        last = {
            "helper_image": helper_image,
            "executed": checks["probe_executed"],
            "passed": all(checks.values()),
            "status": status,
            "attempt": attempt,
            "self_test": self_test_receipt,
            "command": command,
            "checks": checks,
            "raw_returned": False,
        }
        if last["passed"]:
            return last
        if attempt < plan["attempts"] and plan["interval_seconds"]:
            time.sleep(plan["interval_seconds"])
    return last


def _egress_probe(
    runner: CommandRunner, helper: dict[str, str], network_name: str
) -> dict[str, Any]:
    helper_image = _inspect_image(runner, helper["image_reference"])
    identity_checks = _helper_identity_checks(helper, helper_image)
    hardening = _helper_hardening()
    self_test_arguments = [
        *hardening,
        "--network",
        "none",
        helper["image_reference"],
        *HELPER_SELF_TEST,
    ]
    self_test = _docker(
        runner, "helper_self_test", self_test_arguments, timeout=20, check=False
    )
    arguments = [
        *hardening,
        "--network",
        network_name,
        helper["image_reference"],
        *HELPER_COMMAND,
    ]
    result = _docker(runner, "egress_probe", arguments, timeout=20, check=False)
    command = _command_receipt(result)
    command["argv_sha256"] = _canonical_sha256(arguments)
    self_test_receipt = _command_receipt(self_test)
    self_test_receipt["argv_sha256"] = _canonical_sha256(self_test_arguments)
    checks = {
        **identity_checks,
        "helper_command_available": self_test.returncode == 0
        and not self_test.timed_out
        and not self_test.output_truncated,
        "probe_executed": not result.timed_out and not result.output_truncated,
        "external_request_denied": not result.timed_out
        and not result.output_truncated
        and result.returncode == 1,
    }
    return {
        "helper_image": helper_image,
        "self_test": self_test_receipt,
        "command": command,
        "checks": checks,
        "passed": all(checks.values()),
        "raw_returned": False,
    }


def _docker_environment(runner: CommandRunner) -> dict[str, Any]:
    version = _docker_json(runner, "docker_version", ["version", "--format", "{{json .}}"])
    info = _docker_json(runner, "docker_info", ["info", "--format", "{{json .}}"])
    if not isinstance(version, dict) or not isinstance(info, dict):
        raise RuntimeContractError("Docker environment evidence is invalid")
    server = version.get("Server") if isinstance(version.get("Server"), dict) else {}
    components = server.get("Components") if isinstance(server.get("Components"), list) else []
    return {
        "server_version": server.get("Version"),
        "api_version": server.get("ApiVersion"),
        "os": info.get("OperatingSystem"),
        "architecture": info.get("Architecture"),
        "driver": info.get("Driver"),
        "security_options_sha256": _canonical_sha256(info.get("SecurityOptions", [])),
        "components_sha256": _canonical_sha256(components),
        "rootless": bool(info.get("Rootless", False)),
    }


def _app_hold(app_id: str, source_row: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "app_id": app_id,
        "repository_id": source_row["repository_id"],
        "commit": source_row["commit"],
        "source_tree_sha256": source_row["source_tree_sha256"],
        "status": "HOLD",
        "blockers": [reason],
        "source_checkout": None,
        "build": None,
        "network": None,
        "container": None,
        "health_probe": None,
        "egress_probe": None,
        "cleanup": None,
        "raw_returned": False,
    }


def _materialize_app(
    runner: CommandRunner,
    app_id: str,
    app: dict[str, Any],
    source_row: dict[str, Any],
    source_module: Any,
    source_root: Path,
    helper: dict[str, str],
    created_object_ids: dict[str, str | None],
) -> dict[str, Any]:
    checkout = _safe_relative(
        source_root, app["checkout_relative"], label=f"{app_id} checkout"
    )
    source_before = _verify_checkout(checkout, app_id, source_module, source_row)
    build, runtime_image_id = _prepare_images(
        runner, app_id, app, checkout, source_row, source_root
    )
    source_after_build = _verify_checkout(checkout, app_id, source_module, source_row)
    if source_after_build != source_before:
        raise RuntimeContractError("source checkout changed during image preparation")
    network = _create_network(
        runner,
        app_id,
        app["runtime"]["network_name"],
        created_object_ids,
    )
    container = _create_container(
        runner,
        app_id,
        app["runtime"],
        runtime_image_id,
        created_object_ids,
    )
    start = _docker(
        runner,
        "container_start",
        ["container", "start", app["runtime"]["container_name"]],
        check=False,
    )
    post_start = _observe_container_after_start(
        runner,
        app_id,
        app["runtime"],
        runtime_image_id,
        str(container["id"]),
    )
    eligible_for_health = (
        start.returncode == 0
        and not start.timed_out
        and not start.output_truncated
        and post_start["passed"] is True
    )
    health = (
        _internal_health_probe(
            runner,
            helper,
            app["runtime"]["network_name"],
            app_id,
            app["runtime"],
        )
        if eligible_for_health
        else {
            "executed": False,
            "passed": False,
            "status": None,
            "attempt": None,
            "command": None,
            "raw_returned": False,
        }
    )
    health["start_command"] = _command_receipt(start)
    post_health = (
        _observe_container_after_start(
            runner,
            app_id,
            app["runtime"],
            runtime_image_id,
            str(container["id"]),
        )
        if eligible_for_health
        else None
    )
    egress = _egress_probe(runner, helper, app["runtime"]["network_name"])
    container["post_start"] = post_start
    container["post_health"] = post_health
    container["passed"] = (
        container["passed"]
        and post_start["passed"]
        and isinstance(post_health, dict)
        and post_health.get("passed") is True
    )
    post_runtime_network = _observe_network_after_runtime(
        runner,
        app_id,
        app["runtime"]["network_name"],
        str(container["id"]),
    )
    network["post_runtime"] = post_runtime_network
    network["passed"] = network["passed"] and post_runtime_network["passed"]
    source_after_runtime = _verify_checkout(checkout, app_id, source_module, source_row)
    source_immutable = source_after_runtime == source_before
    build_passed = build["source"]["passed"] and (
        build["adapter"] is None or build["adapter"]["passed"]
    )
    checks = {
        "source_checkout_immutable": source_immutable,
        "build_provenance": build_passed,
        "network_isolation": network["passed"],
        "container_isolation": container["passed"],
        "health_probe": health.get("passed") is True,
        "egress_denied": egress["passed"],
    }
    blockers = sorted(key for key, passed in checks.items() if not passed)
    return {
        "app_id": app_id,
        "repository_id": source_row["repository_id"],
        "commit": source_row["commit"],
        "source_tree_sha256": source_row["source_tree_sha256"],
        "status": "PASS" if all(checks.values()) else "HOLD",
        "blockers": blockers,
        "checks": checks,
        "source_checkout": source_before,
        "build": build,
        "network": network,
        "container": container,
        "health_probe": health,
        "egress_probe": egress,
        "raw_returned": False,
    }


def materialize_l2_runtime(
    source_admission_path: Path,
    plan_path: Path,
    *,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    script_path = Path(__file__).resolve(strict=True)
    script_raw = script_path.read_bytes()
    source_admission, source_raw = _load_canonical(
        source_admission_path.resolve(strict=True), label="source admission"
    )
    plan, plan_raw = _load_canonical(plan_path.resolve(strict=True), label="runtime plan")
    source_module, source_module_sha256 = _load_source_module()
    source_rows = _validate_source_admission(
        source_admission, source_raw, source_module, source_module_sha256
    )
    source_root = _safe_root(plan.get("source_root"), label="source root")
    helper, app_plans = _validate_plan(
        plan, sha256_bytes(source_raw), source_root
    )
    active_runner = runner or SubprocessRunner()
    environment: dict[str, Any] | None = None
    environment_blocker: str | None = None
    try:
        environment = _docker_environment(active_runner)
    except (DockerCommandError, RuntimeContractError):
        environment_blocker = "docker_environment_unavailable"
    results: list[dict[str, Any]] = []
    for app_id in sorted(APP_IDS):
        if environment_blocker is not None:
            results.append(_app_hold(app_id, source_rows[app_id], environment_blocker))
            continue
        created_object_ids: dict[str, str | None] = {
            "container": None,
            "network": None,
        }
        try:
            result = _materialize_app(
                active_runner,
                app_id,
                app_plans[app_id],
                source_rows[app_id],
                source_module,
                source_root,
                helper,
                created_object_ids,
            )
        except DockerCommandError as exc:
            result = _app_hold(
                app_id, source_rows[app_id], f"docker_{exc.operation}_failed"
            )
            result["failure_command"] = _command_receipt(exc.result)
        except (OSError, RuntimeContractError, ValueError) as exc:
            reason = str(exc)
            allowed = {
                "source checkout changed during image preparation",
                "adapter tree changed during build",
            }
            result = _app_hold(
                app_id,
                source_rows[app_id],
                reason if reason in allowed else "runtime_contract_validation_failed",
            )
        cleanup = _cleanup_runtime_objects(
            active_runner,
            app_id,
            app_plans[app_id]["runtime"],
            created_object_ids,
        )
        result["cleanup"] = cleanup
        checks = result.get("checks")
        if isinstance(checks, dict):
            checks["runtime_cleanup"] = cleanup["passed"] is True
        if cleanup["passed"] is not True:
            blockers = result.get("blockers")
            if not isinstance(blockers, list):
                blockers = []
                result["blockers"] = blockers
            if "runtime_cleanup" not in blockers:
                blockers.append("runtime_cleanup")
                blockers.sort()
            result["status"] = "HOLD"
        results.append(result)
    app_status = {row["app_id"]: row["status"] for row in results}
    all_passed = set(app_status) == APP_IDS and all(
        status == "PASS" for status in app_status.values()
    )
    if script_path.read_bytes() != script_raw:
        raise RuntimeError("runtime materializer changed while evidence was produced")
    unsigned = {
        "schema": RECEIPT_SCHEMA,
        "run_nonce_sha256": sha256_bytes(secrets.token_bytes(32)),
        "source_admission_sha256": sha256_bytes(source_raw),
        "runtime_plan_sha256": sha256_bytes(plan_raw),
        "tool_provenance": {
            "runtime_materializer_sha256": sha256_bytes(script_raw),
            "source_materializer_sha256": source_module_sha256,
            "source_verifier_sha256": source_admission["tool_provenance"][
                "verifier_sha256"
            ],
        },
        "docker_environment": environment,
        "expected_app_count": 6,
        "observed_app_count": len(results),
        "app_status": app_status,
        "runtime_isolation_gate": "PASS" if all_passed else "HOLD",
        "release_gate_passed": False,
        "claim_boundary": {
            "runtime_build_isolation_only": True,
            "proves_scanner_accuracy": False,
            "proves_release_readiness": False,
        },
        "apps": results,
        "raw_returned": False,
    }
    validation_projection = {
        "schema": unsigned["schema"],
        "run_nonce_sha256": unsigned["run_nonce_sha256"],
        "source_admission_sha256": unsigned["source_admission_sha256"],
        "runtime_plan_sha256": unsigned["runtime_plan_sha256"],
        "tool_provenance": unsigned["tool_provenance"],
        "app_status": app_status,
        "runtime_isolation_gate": unsigned["runtime_isolation_gate"],
    }
    unsigned["validation_projection_sha256"] = _canonical_sha256(validation_projection)
    unsigned["receipt_sha256"] = _canonical_sha256(unsigned)
    return unsigned


def _load_verified_runtime_receipt(path: Path) -> dict[str, Any]:
    receipt, _raw = _load_canonical(path.resolve(strict=True), label="runtime receipt")
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise RuntimeContractError("runtime receipt schema is invalid")
    run_nonce_sha256 = receipt.get("run_nonce_sha256")
    if not isinstance(run_nonce_sha256, str) or SHA256_RE.fullmatch(run_nonce_sha256) is None:
        raise RuntimeContractError("runtime receipt execution nonce is invalid")
    claimed = receipt.get("receipt_sha256")
    unsigned = dict(receipt)
    unsigned.pop("receipt_sha256", None)
    if not isinstance(claimed, str) or claimed != _canonical_sha256(unsigned):
        raise RuntimeContractError("runtime receipt integrity hash is invalid")
    provenance = receipt.get("tool_provenance")
    source_module, source_materializer_sha256 = _load_source_module()
    _source_verifier, source_verifier_sha256 = (
        source_module._load_source_materialization_with_hash()
    )
    if (
        not isinstance(provenance, dict)
        or provenance.get("runtime_materializer_sha256")
        != sha256_bytes(Path(__file__).resolve(strict=True).read_bytes())
        or provenance.get("source_materializer_sha256")
        != source_materializer_sha256
        or provenance.get("source_verifier_sha256") != source_verifier_sha256
    ):
        raise RuntimeContractError("runtime receipt tool provenance is stale")
    statuses = receipt.get("app_status")
    apps = receipt.get("apps")
    if (
        not isinstance(statuses, dict)
        or set(statuses) != APP_IDS
        or not isinstance(apps, list)
        or len(apps) != 6
        or {row.get("app_id") for row in apps if isinstance(row, dict)} != APP_IDS
    ):
        raise RuntimeContractError("runtime receipt app set is invalid")
    computed_statuses = {row["app_id"]: row.get("status") for row in apps}
    if computed_statuses != statuses:
        raise RuntimeContractError("runtime receipt app status projection is inconsistent")
    for row in apps:
        status = row.get("status")
        blockers = row.get("blockers")
        if status not in {"PASS", "HOLD"} or not isinstance(blockers, list):
            raise RuntimeContractError("runtime receipt app decision is invalid")
        if status == "HOLD" and not blockers:
            raise RuntimeContractError("HOLD app must preserve at least one blocker")
        if status == "PASS":
            checks = row.get("checks")
            build = row.get("build")
            adapter = build.get("adapter") if isinstance(build, dict) else None
            nested_passed = (
                isinstance(checks, dict)
                and bool(checks)
                and all(value is True for value in checks.values())
                and isinstance(build, dict)
                and isinstance(build.get("source"), dict)
                and build["source"].get("passed") is True
                and (adapter is None or adapter.get("passed") is True)
                and isinstance(row.get("network"), dict)
                and row["network"].get("passed") is True
                and isinstance(row.get("container"), dict)
                and row["container"].get("passed") is True
                and isinstance(row.get("health_probe"), dict)
                and row["health_probe"].get("passed") is True
                and isinstance(row.get("egress_probe"), dict)
                and row["egress_probe"].get("passed") is True
                and isinstance(row.get("cleanup"), dict)
                and row["cleanup"].get("passed") is True
            )
            if blockers or not nested_passed:
                raise RuntimeContractError("PASS app lacks complete nested runtime evidence")
    all_passed = all(status == "PASS" for status in statuses.values())
    if receipt.get("runtime_isolation_gate") != ("PASS" if all_passed else "HOLD"):
        raise RuntimeContractError("runtime receipt gate is inconsistent")
    if receipt.get("release_gate_passed") is not False:
        raise RuntimeContractError("runtime receipt cannot grant release authority")
    projection = {
        "schema": receipt["schema"],
        "run_nonce_sha256": run_nonce_sha256,
        "source_admission_sha256": receipt.get("source_admission_sha256"),
        "runtime_plan_sha256": receipt.get("runtime_plan_sha256"),
        "tool_provenance": receipt.get("tool_provenance"),
        "app_status": statuses,
        "runtime_isolation_gate": receipt.get("runtime_isolation_gate"),
    }
    if receipt.get("validation_projection_sha256") != _canonical_sha256(projection):
        raise RuntimeContractError("runtime validation projection was tampered")
    return receipt


def verify_runtime_receipt(path: Path) -> dict[str, Any]:
    receipt = _load_verified_runtime_receipt(path)
    return {
        "valid": True,
        "runtime_isolation_gate": receipt["runtime_isolation_gate"],
        "receipt_sha256": receipt["receipt_sha256"],
    }


def _replay_boolean_map(value: Any) -> dict[str, bool] | None:
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not isinstance(item, bool)
        for key, item in value.items()
    ):
        return None
    return {key: value[key] for key in sorted(value)}


def _replay_step_projection(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    passed = value.get("passed")
    return {
        "passed": passed if isinstance(passed, bool) else None,
        "checks": _replay_boolean_map(value.get("checks")),
    }


def _replay_container_projection(value: Any) -> dict[str, Any] | None:
    projection = _replay_step_projection(value)
    if projection is None or not isinstance(value, dict):
        return projection
    return {
        **projection,
        "post_start": _replay_step_projection(value.get("post_start")),
        "post_health": _replay_step_projection(value.get("post_health")),
    }


def _replay_health_projection(value: Any) -> dict[str, Any] | None:
    projection = _replay_step_projection(value)
    if projection is None or not isinstance(value, dict):
        return projection
    status = value.get("status")
    return {
        **projection,
        "status": status if isinstance(status, int) and not isinstance(status, bool) else None,
    }


def _replay_build_projection(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {
        "source": _replay_step_projection(value.get("source")),
        "adapter": _replay_step_projection(value.get("adapter")),
    }


def _runtime_replay_projection(receipt: dict[str, Any]) -> dict[str, Any]:
    apps = receipt.get("apps")
    if not isinstance(apps, list):
        raise RuntimeContractError("runtime replay receipt app list is invalid")
    projection_apps: list[dict[str, Any]] = []
    for row in sorted(apps, key=lambda item: str(item.get("app_id", "")) if isinstance(item, dict) else ""):
        if not isinstance(row, dict):
            raise RuntimeContractError("runtime replay receipt app is invalid")
        blockers = row.get("blockers")
        if not isinstance(blockers, list) or any(
            not isinstance(blocker, str) for blocker in blockers
        ):
            raise RuntimeContractError("runtime replay blockers are invalid")
        projection_apps.append(
            {
                "app_id": row.get("app_id"),
                "status": row.get("status"),
                "blockers": sorted(blockers),
                "checks": _replay_boolean_map(row.get("checks")),
                "build": _replay_build_projection(row.get("build")),
                "network": _replay_step_projection(row.get("network")),
                "container": _replay_container_projection(row.get("container")),
                "health_probe": _replay_health_projection(row.get("health_probe")),
                "egress_probe": _replay_step_projection(row.get("egress_probe")),
                "cleanup": _replay_step_projection(row.get("cleanup")),
            }
        )
    return {
        "app_status": receipt.get("app_status"),
        "runtime_isolation_gate": receipt.get("runtime_isolation_gate"),
        "apps": projection_apps,
    }


def compare_runtime_replays(first_path: Path, second_path: Path) -> dict[str, Any]:
    first_resolved = first_path.resolve(strict=True)
    second_resolved = second_path.resolve(strict=True)
    if first_resolved == second_resolved:
        raise RuntimeContractError("runtime replay comparison requires two distinct receipts")
    first = _load_verified_runtime_receipt(first_resolved)
    second = _load_verified_runtime_receipt(second_resolved)
    first_projection = _runtime_replay_projection(first)
    second_projection = _runtime_replay_projection(second)
    source_admission_equal = (
        first.get("source_admission_sha256") == second.get("source_admission_sha256")
    )
    runtime_plan_equal = first.get("runtime_plan_sha256") == second.get("runtime_plan_sha256")
    tool_provenance_equal = first.get("tool_provenance") == second.get("tool_provenance")
    app_status_equal = first.get("app_status") == second.get("app_status")
    decision_projection_equal = first_projection == second_projection
    distinct_run_nonce = first.get("run_nonce_sha256") != second.get("run_nonce_sha256")
    distinct_receipt = first.get("receipt_sha256") != second.get("receipt_sha256")
    replay_passed = all(
        (
            source_admission_equal,
            runtime_plan_equal,
            tool_provenance_equal,
            app_status_equal,
            decision_projection_equal,
            distinct_run_nonce,
            distinct_receipt,
        )
    )
    return {
        "schema": REPLAY_SCHEMA,
        "first_receipt_sha256": first["receipt_sha256"],
        "second_receipt_sha256": second["receipt_sha256"],
        "first_run_nonce_sha256": first.get("run_nonce_sha256"),
        "second_run_nonce_sha256": second.get("run_nonce_sha256"),
        "first_source_admission_sha256": first.get("source_admission_sha256"),
        "second_source_admission_sha256": second.get("source_admission_sha256"),
        "first_runtime_plan_sha256": first.get("runtime_plan_sha256"),
        "second_runtime_plan_sha256": second.get("runtime_plan_sha256"),
        "first_runtime_isolation_gate": first.get("runtime_isolation_gate"),
        "second_runtime_isolation_gate": second.get("runtime_isolation_gate"),
        "source_admission_equal": source_admission_equal,
        "runtime_plan_equal": runtime_plan_equal,
        "tool_provenance_equal": tool_provenance_equal,
        "app_status_equal": app_status_equal,
        "decision_projection_equal": decision_projection_equal,
        "distinct_run_nonce": distinct_run_nonce,
        "distinct_receipt": distinct_receipt,
        "first_decision_projection_sha256": _canonical_sha256(first_projection),
        "second_decision_projection_sha256": _canonical_sha256(second_projection),
        "replay_gate": "PASS" if replay_passed else "HOLD",
        "release_gate_passed": False,
        "claim_boundary": {
            "decision_reproducibility_only": True,
            "does_not_grant_runtime_isolation_pass": True,
            "does_not_grant_release_authority": True,
        },
        "raw_returned": False,
    }


def write_new_output(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite runtime receipt: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(canonical_json_bytes(payload))
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise FileExistsError(f"refusing to overwrite runtime receipt: {path}") from exc
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Materialize or verify fail-closed L2 Docker runtime evidence."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect = subparsers.add_parser("collect")
    collect.add_argument("--source-admission", type=Path, required=True)
    collect.add_argument("--plan", type=Path, required=True)
    collect.add_argument("--output", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--receipt", type=Path, required=True)
    compare = subparsers.add_parser("compare-replays")
    compare.add_argument("--first", type=Path, required=True)
    compare.add_argument("--second", type=Path, required=True)
    compare.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "collect":
        payload = materialize_l2_runtime(args.source_admission, args.plan)
        write_new_output(args.output, payload)
        return 0 if payload["runtime_isolation_gate"] == "PASS" else 2
    if args.command == "verify":
        result = verify_runtime_receipt(args.receipt)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    result = compare_runtime_replays(args.first, args.second)
    write_new_output(args.output, result)
    return 0 if result["replay_gate"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
