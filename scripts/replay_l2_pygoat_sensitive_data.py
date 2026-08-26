from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


SCHEMA = "k_guard_l2_pygoat_sensitive_data_execution_contract.v1"
NEGATIVE_CONTROL_SCHEMA = "k_guard_l2_pygoat_sensitive_data_negative_control.v1"
DRIVER_RESULT_SCHEMA = "k_guard_l2_pygoat_sensitive_data_driver_result.v1"

APP_ID = "pygoat"
REPOSITORY_ID = "adeyosemanputra/pygoat"
SOURCE_COMMIT = "19d17cc8874861142b330636d068bbde54e86b85"
SOURCE_TREE = "1ee82a01f5ac80df289327eca929c9f5aff2a9c4"
SOURCE_TREE_SHA256 = "156486b1531432930bf9df68f2886a20531c28a7aeffe95c9f095286eee3821c"
P23A_APP_RECEIPT_SHA256 = "0bf2824174f6e979893bda964f87e394c3689db69a3825cab646880156f2fa5c"
P23A_APP_SEMANTIC_SHA256 = "29b7f1119840084e6022732d7aeb2b07e6402ae3a96fa74819e8470f200eb44a"

SOURCE_SUBPROJECT = "dockerized_labs/sensitive_data_exposure"
SOURCE_IMAGE_REF = "kguard-l2/pygoat-sensitive-data:19d17cc"
SOURCE_IMAGE_ID = "sha256:62547bfe90c8b67d23531610c991146baba0416b7eb8bdb625d9fca91885758d"
SOURCE_DOCKERFILE_SHA256 = "007de200786f943a4905cf245a4049fe403848b14122a9ef728c2c0697da31da"

SOURCE_FILES = {
    "Dockerfile": "007de200786f943a4905cf245a4049fe403848b14122a9ef728c2c0697da31da",
    "entrypoint.sh": "4541d884503bd86e0091acae911a2fd8987b0e561b0884a0ea49c384bbb40cbb",
    "dataexposure/views.py": "458b2a920c4d32653e57a62f60c0a723e7fc4a8324ef0eb400f8afc5febf9e15",
    "dataexposure/urls.py": "f7962d4ab21a0f98b89c40f3d818713a614a8112aca542fd0edc63d598044ba3",
    "dataexposure/models.py": "58f1d21d044c985d3a6539aa64019e2cd6fa99e2fad37aa7f45cd8cbbfb7c119",
    "requirements.txt": "645eeaa08c92d7d209e6919a6fc8c28265f2b5c5014484d79892c26e3d5e9a00",
}
IMAGE_FILE_PATHS = {
    "entrypoint.sh": "/entrypoint.sh",
    "dataexposure/views.py": "/app/dataexposure/views.py",
    "dataexposure/urls.py": "/app/dataexposure/urls.py",
    "dataexposure/models.py": "/app/dataexposure/models.py",
    "requirements.txt": "/app/requirements.txt",
}

VIEW_PATH = "dataexposure/views.py"
EXECUTION_CONTRACT_LABEL = "pygoat-sensitive-data-exposure-v1"
NEGATIVE_CONTROL_LABEL = "pygoat-sensitive-data-login-required-negative-control-v1"
NEGATIVE_CONTROL_PATCH_ID = "add-login-required-to-all-users-view.v1"
NETWORK_POLICY = "internal_bridge_loopback_driver_v1"
APP_USER = "10001:10001"
APP_UID = 10001
APP_GID = 10001
APP_MEMORY_BYTES = 512 * 1024 * 1024
NANO_CPUS = 1_000_000_000
APP_PIDS_LIMIT = 256
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
OBJECT_ID_RE = re.compile(r"^[0-9a-f]{64}$")

ADMISSION_BLOCKERS = tuple(
    sorted(
        {
            "evidence_signature_missing",
            "independent_upstream_fixed_revision_missing",
            "scanner_finding_mapping_missing",
            "source_bound_severity_rubric_missing",
        }
    )
)
NEGATIVE_CONTROL_ADMISSION_BLOCKERS = ADMISSION_BLOCKERS

APP_TMPFS = {
    "/app": "rw,noexec,nosuid,nodev,size=268435456,uid=10001,gid=10001,mode=0750",
    "/tmp": "rw,noexec,nosuid,nodev,size=67108864,uid=10001,gid=10001,mode=0700",
    "/home/kguard": "rw,noexec,nosuid,nodev,size=67108864,uid=10001,gid=10001,mode=0700",
}


# The driver only emits status and structural booleans. It never writes response
# bytes, fixture credentials, raw headers, or database contents to host evidence.
DRIVER_SCRIPT = r'''from __future__ import annotations

import http.client
import json
import os
import sys
import time
from typing import Any


MARKER = "K_GUARD_PYGOAT_SENSITIVE_DATA_RESULT:"
SCHEMA = "k_guard_l2_pygoat_sensitive_data_driver_result.v1"
MAX_RESPONSE_BYTES = 65536


def emit(payload: dict[str, Any]) -> None:
    print(MARKER + json.dumps(payload, sort_keys=True, separators=(",", ":")), flush=True)


def failed(mode: str, expected_status: int, code: str) -> int:
    emit(
        {
            "schema": SCHEMA,
            "mode": mode,
            "expected_status": expected_status,
            "observed_status": None,
            "users_json_observed": False,
            "users_nonempty": False,
            "expected_field_shape_observed": False,
            "login_redirect_observed": False,
            "driver_error_code": code,
            "passed": False,
            "raw_returned": False,
        }
    )
    return 81


def request() -> tuple[int, str | None, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", 8000, timeout=5)
    try:
        connection.request("GET", "/api/all-users/", headers={"Accept": "application/json"})
        response = connection.getresponse()
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise RuntimeError("response_too_large")
        return int(response.status), response.getheader("Location"), body
    finally:
        connection.close()


def wait_for_application() -> tuple[int, str | None, bytes]:
    deadline = time.monotonic() + 90
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            status, location, body = request()
            if status in {200, 302}:
                return status, location, body
        except Exception as exc:  # The error detail is intentionally not emitted.
            last_error = exc
        time.sleep(0.5)
    raise RuntimeError("application_not_ready" if last_error is not None else "application_timeout")


def main() -> int:
    mode = os.environ.get("KGUARD_MODE", "")
    expected_raw = os.environ.get("KGUARD_EXPECTED_STATUS", "")
    try:
        expected_status = int(expected_raw)
    except ValueError:
        return failed(mode, 0, "driver_contract_invalid")
    if mode not in {"positive", "negative"} or expected_status not in {200, 302}:
        return failed(mode, expected_status, "driver_contract_invalid")
    try:
        status, location, body = wait_for_application()
        parsed: object = None
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = None
        users = parsed.get("users") if isinstance(parsed, dict) else None
        users_json_observed = isinstance(users, list)
        users_nonempty = users_json_observed and len(users) > 0
        expected_fields = ("username", "credit_card", "ssn", "api_key")
        expected_field_shape_observed = bool(
            users_nonempty
            and all(
                isinstance(record, dict) and all(field in record for field in expected_fields)
                for record in users
            )
        )
        login_redirect_observed = bool(
            status == 302
            and isinstance(location, str)
            and location.startswith("/")
            and "next=" in location
        )
        passed = (
            status == 200
            and users_json_observed
            and users_nonempty
            and expected_field_shape_observed
            if mode == "positive"
            else status == 302
            and not users_json_observed
            and not users_nonempty
            and not expected_field_shape_observed
            and login_redirect_observed
        )
        emit(
            {
                "schema": SCHEMA,
                "mode": mode,
                "expected_status": expected_status,
                "observed_status": status,
                "users_json_observed": users_json_observed,
                "users_nonempty": users_nonempty,
                "expected_field_shape_observed": expected_field_shape_observed,
                "login_redirect_observed": login_redirect_observed,
                "driver_error_code": None,
                "passed": passed,
                "raw_returned": False,
            }
        )
        return 0 if passed and status == expected_status else 81
    except Exception:
        return failed(mode, expected_status, "driver_runtime_failed")


if __name__ == "__main__":
    raise SystemExit(main())
'''


# The source image's entrypoint must write migrations and its demo fixture under
# /app. The adapter preserves the source tree immutably, copies it into a
# non-root tmpfs at runtime, then applies only the pre-registered view variant.
ADAPTER_ENTRYPOINT = r'''#!/bin/sh
set -eu

test "$(id -u)" = "10001"
test -d /app
test -w /app
test ! -w /opt/pygoat-source

cp -R /opt/pygoat-source/. /app/
chmod -R u+w /app
cp /opt/kguard/views.py /app/dataexposure/views.py
cd /app
exec /entrypoint.sh "$@"
'''


class RuntimeContractError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_truncated: bool


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_sha256(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _command_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "DOCKER_CLI_HINTS": "false",
            "DOCKER_SCAN_SUGGEST": "false",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    return environment


def _run_bounded(argv: list[str], *, cwd: Path, timeout: int) -> CommandResult:
    with tempfile.SpooledTemporaryFile(max_size=MAX_OUTPUT_BYTES) as stdout, tempfile.SpooledTemporaryFile(
        max_size=MAX_OUTPUT_BYTES
    ) as stderr:
        process = subprocess.Popen(
            argv,
            cwd=str(cwd),
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
        stdout_raw = stdout.read(MAX_OUTPUT_BYTES + 1)
        stderr_raw = stderr.read(MAX_OUTPUT_BYTES + 1)
    return CommandResult(
        returncode=returncode,
        stdout=stdout_raw[:MAX_OUTPUT_BYTES],
        stderr=stderr_raw[:MAX_OUTPUT_BYTES],
        timed_out=timed_out,
        output_truncated=len(stdout_raw) > MAX_OUTPUT_BYTES or len(stderr_raw) > MAX_OUTPUT_BYTES,
    )


def _docker(arguments: list[str], *, cwd: Path, timeout: int) -> CommandResult:
    return _run_bounded(["docker", *arguments], cwd=cwd, timeout=timeout)


def _expect_success(result: CommandResult, label: str) -> None:
    if result.returncode != 0 or result.timed_out or result.output_truncated:
        raise RuntimeContractError(f"{label}_failed")


def _load_json_stdout(result: CommandResult, label: str) -> Any:
    _expect_success(result, label)
    try:
        return json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError(f"{label}_not_json") from exc


def _command_receipt(result: CommandResult) -> dict[str, Any]:
    return {
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "output_truncated": result.output_truncated,
        "stdout_sha256": sha256_bytes(result.stdout),
        "stderr_sha256": sha256_bytes(result.stderr),
        "stdout_bytes": len(result.stdout),
        "stderr_bytes": len(result.stderr),
        "raw_returned": False,
    }


def _load_source_verifier() -> tuple[Any, str]:
    path = Path(__file__).with_name("holdout_source_materialization.py")
    raw_before = path.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l2_pygoat_source_verifier", path)
    if spec is None or spec.loader is None:
        raise RuntimeContractError("source_verifier_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if path.read_bytes() != raw_before:
        raise RuntimeContractError("source_verifier_changed_while_loading")
    return module, sha256_bytes(raw_before)


def _load_p23a_registry(path: Path) -> tuple[dict[str, Any], str]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeContractError("p23a_registry_invalid_path")
    raw = path.read_bytes()
    try:
        registry = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError("p23a_registry_not_json") from exc
    if not isinstance(registry, dict) or canonical_json_bytes(registry) != raw:
        raise RuntimeContractError("p23a_registry_not_canonical")
    if (
        registry.get("schema") != "k_guard_l2_source_materialization.v3"
        or registry.get("seed_sha256") != "95f48fd53d3d411be9dbaa7b78a130a893d1fbf87bbc92f7ce40f1d6dbaf2fef"
        or registry.get("expected_app_count") != 6
        or registry.get("materialized_app_count") != 6
        or registry.get("source_license_admission") != "PASS"
        or registry.get("raw_returned") is not False
    ):
        raise RuntimeContractError("p23a_registry_contract_invalid")
    apps = registry.get("apps")
    if not isinstance(apps, list):
        raise RuntimeContractError("p23a_registry_apps_invalid")
    candidates = [item for item in apps if isinstance(item, dict) and item.get("app_id") == APP_ID]
    if len(candidates) != 1:
        raise RuntimeContractError("p23a_registry_pygoat_missing")
    app = candidates[0]
    expected = {
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
        "receipt_sha256": P23A_APP_RECEIPT_SHA256,
        "receipt_semantic_sha256": P23A_APP_SEMANTIC_SHA256,
        "source_license_admission": "PASS",
        "scanner_output_observed": False,
        "oracle_gate_status": "HOLD",
        "oracle_missing": True,
    }
    if any(app.get(key) != value for key, value in expected.items()):
        raise RuntimeContractError("p23a_registry_pygoat_binding_invalid")
    return app, sha256_bytes(raw)


def _source_projection(
    receipt: Mapping[str, Any], *, p23a_app: Mapping[str, Any], p23a_registry_sha256: str
) -> dict[str, Any]:
    expected = {
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
    }
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise RuntimeContractError("source_identity_mismatch")
    required_truths = (
        "source_worktree_clean",
        "origin_repository_match",
        "commit_match",
        "commit_tree_match",
        "tree_object_reconstruction_match",
        "index_tree_match",
        "physical_bytes_match_git_blobs",
        "git_fsck_strict_passed",
    )
    if any(receipt.get(key) is not True for key in required_truths):
        raise RuntimeContractError("source_receipt_not_blob_exact")
    if any(receipt.get(key) != p23a_app.get(key) for key in ("file_count", "total_bytes")):
        raise RuntimeContractError("source_receipt_size_mismatch")
    return {
        **expected,
        "p23a_registry_sha256": p23a_registry_sha256,
        "p23a_app_receipt_sha256": P23A_APP_RECEIPT_SHA256,
        "p23a_app_receipt_semantic_sha256": P23A_APP_SEMANTIC_SHA256,
        "current_source_receipt_sha256": _canonical_sha256(dict(receipt)),
        "file_count": receipt.get("file_count"),
        "total_bytes": receipt.get("total_bytes"),
        "raw_returned": False,
    }


def verify_source_workspace(source_root: Path, p23a_registry: Path) -> tuple[dict[str, Any], Any, str]:
    if not source_root.is_absolute() or not source_root.is_dir():
        raise RuntimeContractError("source_root_invalid")
    p23a_app, p23a_registry_sha256 = _load_p23a_registry(p23a_registry)
    verifier, verifier_sha256 = _load_source_verifier()
    receipt = verifier.build_git_materialization_receipt(
        source_root,
        expected_repository_id=REPOSITORY_ID,
        expected_commit=SOURCE_COMMIT,
        expected_tree=SOURCE_TREE,
    )
    return (
        _source_projection(receipt, p23a_app=p23a_app, p23a_registry_sha256=p23a_registry_sha256),
        verifier,
        verifier_sha256,
    )


def _safe_source_file(source_root: Path, relative: str) -> Path:
    if not relative or "\\" in relative or relative.startswith("/") or ".." in Path(relative).parts:
        raise RuntimeContractError("source_relative_path_invalid")
    root = source_root.resolve(strict=True)
    subproject = root / SOURCE_SUBPROJECT
    path = (subproject / Path(relative)).resolve(strict=True)
    try:
        path.relative_to(subproject)
    except ValueError as exc:
        raise RuntimeContractError("source_file_escapes_subproject") from exc
    if path.is_symlink() or not path.is_file():
        raise RuntimeContractError("source_file_invalid")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise RuntimeContractError("source_file_too_large")
    return path


def _read_source_files(source_root: Path) -> dict[str, bytes]:
    values: dict[str, bytes] = {}
    for relative, expected_sha256 in SOURCE_FILES.items():
        raw = _safe_source_file(source_root, relative).read_bytes()
        if sha256_bytes(raw) != expected_sha256:
            raise RuntimeContractError("source_file_hash_mismatch")
        values[relative] = raw
    views = values[VIEW_PATH]
    urls = values["dataexposure/urls.py"]
    entrypoint = values["entrypoint.sh"]
    if (
        b"from django.contrib.auth.decorators import login_required" not in views
        or views.count(b"def all_users_data_view(request):") != 1
        or b"path('api/all-users/', views.all_users_data_view" not in urls
        or b'exec "$@"' not in entrypoint
    ):
        raise RuntimeContractError("source_oracle_anchor_invalid")
    return values


def _read_image(ref: str, *, work_root: Path) -> dict[str, Any]:
    rows = _load_json_stdout(_docker(["image", "inspect", ref], cwd=work_root, timeout=60), "image_inspect")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise RuntimeContractError("image_inspect_shape_invalid")
    return rows[0]


def _labels(value: Mapping[str, Any]) -> Mapping[str, Any]:
    config = value.get("Config")
    labels = config.get("Labels") if isinstance(config, Mapping) else None
    return labels if isinstance(labels, Mapping) else {}


def _rootfs_layers(value: Mapping[str, Any]) -> tuple[str, ...]:
    rootfs = value.get("RootFS")
    layers = rootfs.get("Layers") if isinstance(rootfs, Mapping) else None
    if (
        not isinstance(layers, list)
        or not layers
        or not all(isinstance(layer, str) and IMAGE_ID_RE.fullmatch(layer) for layer in layers)
    ):
        raise RuntimeContractError("image_rootfs_layers_invalid")
    return tuple(layers)


def _container_id(result: CommandResult, label: str) -> str:
    _expect_success(result, label)
    try:
        value = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise RuntimeContractError(f"{label}_id_invalid") from exc
    if OBJECT_ID_RE.fullmatch(value) is None:
        raise RuntimeContractError(f"{label}_id_invalid")
    return value


def _cleanup_container(
    *,
    work_root: Path,
    name: str,
    expected_id: str | None,
    nonce: str,
    contract_label: str,
    role: str,
) -> dict[str, Any]:
    inspected = _docker(["container", "inspect", name], cwd=work_root, timeout=60)
    if inspected.returncode != 0:
        return {
            "ownership_verified": expected_id is None,
            "removed": False,
            "absent_after": expected_id is None,
            "passed": expected_id is None,
            "raw_returned": False,
        }
    try:
        rows = json.loads(inspected.stdout.decode("utf-8"))
        row = rows[0] if isinstance(rows, list) and len(rows) == 1 else None
        labels = _labels(row) if isinstance(row, Mapping) else {}
        owned = (
            isinstance(row, Mapping)
            and row.get("Id") == expected_id
            and labels.get("io.k-guard.app-id") == APP_ID
            and labels.get("io.k-guard.execution-contract") == contract_label
            and labels.get("io.k-guard.run-nonce") == nonce
            and labels.get("io.k-guard.role") == role
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        owned = False
    removed = False
    if owned:
        deletion = _docker(["container", "rm", "--force", name], cwd=work_root, timeout=60)
        removed = deletion.returncode == 0 and not deletion.timed_out and not deletion.output_truncated
    post = _docker(["container", "inspect", name], cwd=work_root, timeout=60)
    absent_after = post.returncode != 0 and not post.timed_out and not post.output_truncated
    return {
        "ownership_verified": owned,
        "removed": removed,
        "absent_after": absent_after,
        "passed": owned and removed and absent_after,
        "raw_returned": False,
    }


def _cleanup_network(
    *, work_root: Path, name: str, expected_id: str | None, nonce: str, contract_label: str
) -> dict[str, Any]:
    inspected = _docker(["network", "inspect", name], cwd=work_root, timeout=60)
    if inspected.returncode != 0:
        return {
            "ownership_verified": expected_id is None,
            "removed": False,
            "absent_after": expected_id is None,
            "passed": expected_id is None,
            "raw_returned": False,
        }
    try:
        rows = json.loads(inspected.stdout.decode("utf-8"))
        row = rows[0] if isinstance(rows, list) and len(rows) == 1 else None
        labels = row.get("Labels") if isinstance(row, Mapping) and isinstance(row.get("Labels"), Mapping) else {}
        owned = (
            isinstance(row, Mapping)
            and row.get("Id") == expected_id
            and labels.get("io.k-guard.app-id") == APP_ID
            and labels.get("io.k-guard.execution-contract") == contract_label
            and labels.get("io.k-guard.run-nonce") == nonce
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        owned = False
    removed = False
    if owned:
        deletion = _docker(["network", "rm", name], cwd=work_root, timeout=60)
        removed = deletion.returncode == 0 and not deletion.timed_out and not deletion.output_truncated
    post = _docker(["network", "inspect", name], cwd=work_root, timeout=60)
    absent_after = post.returncode != 0 and not post.timed_out and not post.output_truncated
    return {
        "ownership_verified": owned,
        "removed": removed,
        "absent_after": absent_after,
        "passed": owned and removed and absent_after,
        "raw_returned": False,
    }


def _extract_image_file(
    *, work_root: Path, image_id: str, image_path: str, nonce: str, contract_label: str
) -> bytes:
    name = f"kguard-l2-pygoat-extract-{nonce}"
    container_id: str | None = None
    destination = work_root / f"extract-{sha256_bytes(image_path.encode('utf-8'))}"
    try:
        created = _docker(
            [
                "container",
                "create",
                "--name",
                name,
                "--label",
                f"io.k-guard.app-id={APP_ID}",
                "--label",
                f"io.k-guard.execution-contract={contract_label}",
                "--label",
                f"io.k-guard.run-nonce={nonce}",
                "--label",
                "io.k-guard.role=source-extract",
                "--network",
                "none",
                "--entrypoint",
                "/bin/sh",
                image_id,
                "-c",
                "exit 0",
            ],
            cwd=work_root,
            timeout=60,
        )
        container_id = _container_id(created, "source_extract_container")
        copied = _docker(["container", "cp", f"{name}:{image_path}", str(destination)], cwd=work_root, timeout=60)
        _expect_success(copied, "source_extract_copy")
        if not destination.is_file() or destination.is_symlink():
            raise RuntimeContractError("source_extract_file_invalid")
        raw = destination.read_bytes()
        if not raw or len(raw) > MAX_FILE_BYTES:
            raise RuntimeContractError("source_extract_file_size_invalid")
        return raw
    finally:
        if destination.exists():
            destination.unlink()
        cleanup = _cleanup_container(
            work_root=work_root,
            name=name,
            expected_id=container_id,
            nonce=nonce,
            contract_label=contract_label,
            role="source-extract",
        )
        if not cleanup["passed"]:
            raise RuntimeContractError("source_extract_cleanup_failed")


def _validate_base_image(source_root: Path, *, work_root: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    source_files = _read_source_files(source_root)
    source = _read_image(SOURCE_IMAGE_REF, work_root=work_root)
    labels = _labels(source)
    if source.get("Id") != SOURCE_IMAGE_ID:
        raise RuntimeContractError("source_image_id_mismatch")
    expected_labels = {
        "io.kguard.source-dockerfile-sha256": SOURCE_DOCKERFILE_SHA256,
        "io.kguard.source-subproject": SOURCE_SUBPROJECT,
        "io.kguard.source-tree-sha256": SOURCE_TREE_SHA256,
        "org.opencontainers.image.revision": SOURCE_COMMIT,
    }
    if any(labels.get(key) != value for key, value in expected_labels.items()):
        raise RuntimeContractError("source_image_provenance_mismatch")
    image_files: dict[str, bytes] = {}
    for relative, image_path in IMAGE_FILE_PATHS.items():
        raw = _extract_image_file(
            work_root=work_root,
            image_id=SOURCE_IMAGE_ID,
            image_path=image_path,
            nonce=secrets.token_hex(16),
            contract_label=EXECUTION_CONTRACT_LABEL,
        )
        if raw != source_files[relative]:
            raise RuntimeContractError("source_image_file_binding_invalid")
        image_files[relative] = raw
    return (
        {
            "source_image_id": SOURCE_IMAGE_ID,
            "source_image_ref": SOURCE_IMAGE_REF,
            "source_image_rootfs_layers_sha256": _canonical_sha256(_rootfs_layers(source)),
            "source_image_commit_label": SOURCE_COMMIT,
            "source_dockerfile_sha256": SOURCE_DOCKERFILE_SHA256,
            "source_subproject": SOURCE_SUBPROJECT,
            "source_file_sha256": {key: sha256_bytes(value) for key, value in source_files.items()},
            "image_file_sha256": {key: sha256_bytes(value) for key, value in image_files.items()},
            "source_image_current_source_provenance_only": True,
            "fresh_dependency_rebuild_proven": False,
            "runtime_supply_chain_proven": False,
            "raw_returned": False,
        },
        source_files,
    )


def _negative_view_patch(views: bytes) -> tuple[bytes, dict[str, Any]]:
    if b"\r\n" in views and b"\n" in views.replace(b"\r\n", b""):
        raise RuntimeContractError("negative_control_line_endings_ambiguous")
    newline = b"\r\n" if b"\r\n" in views else b"\n"
    marker = b"def all_users_data_view(request):"
    decorator = b"@login_required" + newline + marker
    if (
        views.count(marker) != 1
        or views.count(decorator) != 0
        or views.count(b"from django.contrib.auth.decorators import login_required") != 1
    ):
        raise RuntimeContractError("negative_control_patch_anchor_invalid")
    patched = views.replace(marker, decorator, 1)
    if patched == views or patched.count(marker) != 1 or patched.count(decorator) != 1:
        raise RuntimeContractError("negative_control_patch_not_single")
    return patched, {
        "patch_id": NEGATIVE_CONTROL_PATCH_ID,
        "source_path": VIEW_PATH,
        "original_file_sha256": sha256_bytes(views),
        "patched_file_sha256": sha256_bytes(patched),
        "patch_sha256": sha256_bytes(decorator),
        "marker_count": 1,
        "replacement_count": 1,
        "source_checkout_mutated": False,
        "raw_returned": False,
    }


def _dockerfile_template() -> str:
    return f"""ARG BASE_SOURCE={SOURCE_IMAGE_REF}
FROM ${{BASE_SOURCE}}
USER root
RUN groupadd --gid {APP_GID} kguard \\
    && useradd --uid {APP_UID} --gid {APP_GID} --create-home --shell /usr/sbin/nologin kguard \\
    && mkdir -p /opt/pygoat-source /opt/kguard /app \\
    && cp -R /app/. /opt/pygoat-source/ \\
    && chown -R root:root /opt/pygoat-source /opt/kguard \\
    && chmod -R a-w /opt/pygoat-source
COPY views.py /opt/kguard/views.py
COPY driver.py /opt/kguard/driver.py
COPY adapter-entrypoint.sh /usr/local/bin/kguard-pygoat-entrypoint
RUN chown root:root /opt/kguard/views.py /opt/kguard/driver.py /usr/local/bin/kguard-pygoat-entrypoint \\
    && chmod 0444 /opt/kguard/views.py /opt/kguard/driver.py \\
    && chmod 0555 /usr/local/bin/kguard-pygoat-entrypoint
USER {APP_UID}:{APP_GID}
ENTRYPOINT ["/usr/local/bin/kguard-pygoat-entrypoint"]
"""


def _build_contract_sha256(
    *, variant: str, base_image: Mapping[str, Any], view: Mapping[str, Any]
) -> str:
    return _canonical_sha256(
        {
            "base_source_image_id": base_image["source_image_id"],
            "base_source_image_ref": base_image["source_image_ref"],
            "build_network": "none",
            "dockerfile_sha256": sha256_bytes(_dockerfile_template().encode("utf-8")),
            "driver_sha256": sha256_bytes(DRIVER_SCRIPT.encode("utf-8")),
            "adapter_entrypoint_sha256": sha256_bytes(ADAPTER_ENTRYPOINT.encode("utf-8")),
            "no_cache": True,
            "pull": False,
            "view_original_file_sha256": view["original_file_sha256"],
            "view_patched_file_sha256": view.get("patched_file_sha256"),
            "variant": variant,
        }
    )


def _build_replay_image(
    *,
    work_root: Path,
    timeout: int,
    base_image: Mapping[str, Any],
    views: bytes,
    view_projection: Mapping[str, Any],
    variant: str,
) -> tuple[dict[str, Any], str]:
    if variant not in {"positive", "negative"}:
        raise RuntimeContractError("replay_variant_invalid")
    context = work_root / f"build-{variant}"
    context.mkdir()
    (context / "views.py").write_bytes(views)
    (context / "driver.py").write_text(DRIVER_SCRIPT, encoding="utf-8", newline="\n")
    (context / "adapter-entrypoint.sh").write_text(ADAPTER_ENTRYPOINT, encoding="utf-8", newline="\n")
    dockerfile = _dockerfile_template()
    dockerfile_path = context / "Dockerfile.kguard"
    dockerfile_path.write_text(dockerfile, encoding="utf-8", newline="\n")
    nonce = secrets.token_hex(16)
    tag = f"kguard-l2-pygoat-{variant}-{nonce}"
    contract_label = EXECUTION_CONTRACT_LABEL if variant == "positive" else NEGATIVE_CONTROL_LABEL
    build = _docker(
        [
            "build",
            "--no-cache",
            "--pull=false",
            "--network",
            "none",
            "--build-arg",
            f"BASE_SOURCE={base_image['source_image_ref']}",
            "--label",
            f"io.k-guard.app-id={APP_ID}",
            "--label",
            f"io.k-guard.execution-contract={contract_label}",
            "--label",
            f"io.k-guard.source-image-id={base_image['source_image_id']}",
            "--label",
            f"io.k-guard.build-nonce={nonce}",
            "--file",
            str(dockerfile_path),
            "--tag",
            tag,
            str(context),
        ],
        cwd=work_root,
        timeout=timeout,
    )
    _expect_success(build, "replay_image_build")
    image = _read_image(tag, work_root=work_root)
    image_id = image.get("Id")
    labels = _labels(image)
    layers = _rootfs_layers(image)
    base_layers = _rootfs_layers(_read_image(SOURCE_IMAGE_ID, work_root=work_root))
    if (
        not isinstance(image_id, str)
        or IMAGE_ID_RE.fullmatch(image_id) is None
        or labels.get("io.k-guard.app-id") != APP_ID
        or labels.get("io.k-guard.execution-contract") != contract_label
        or labels.get("io.k-guard.source-image-id") != base_image["source_image_id"]
        or labels.get("io.k-guard.build-nonce") != nonce
        or len(layers) <= len(base_layers)
        or layers[: len(base_layers)] != base_layers
    ):
        raise RuntimeContractError("replay_image_lineage_invalid")
    return (
        {
            "image_id": image_id,
            "image_id_sha256": sha256_bytes(image_id.encode("ascii")),
            "base_source_image_id": base_image["source_image_id"],
            "contract_label": contract_label,
            "dockerfile_sha256": sha256_bytes(dockerfile.encode("utf-8")),
            "driver_sha256": sha256_bytes(DRIVER_SCRIPT.encode("utf-8")),
            "adapter_entrypoint_sha256": sha256_bytes(ADAPTER_ENTRYPOINT.encode("utf-8")),
            "build_contract_sha256": _build_contract_sha256(
                variant=variant, base_image=base_image, view=view_projection
            ),
            "rootfs_lineage_sha256": _canonical_sha256(layers),
            "view": dict(view_projection),
            "source_derived": True,
            "build_network": "none",
            "fresh_dependency_rebuild_proven": False,
            "raw_returned": False,
        },
        image_id,
    )


def _cleanup_image(image_id: str, *, work_root: Path, contract_label: str) -> dict[str, Any]:
    inspected = _docker(["image", "inspect", image_id], cwd=work_root, timeout=60)
    owned = False
    if inspected.returncode == 0 and not inspected.timed_out and not inspected.output_truncated:
        try:
            rows = json.loads(inspected.stdout.decode("utf-8"))
            row = rows[0] if isinstance(rows, list) and len(rows) == 1 else None
            labels = _labels(row) if isinstance(row, Mapping) else {}
            owned = (
                isinstance(row, Mapping)
                and labels.get("io.k-guard.app-id") == APP_ID
                and labels.get("io.k-guard.execution-contract") == contract_label
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            owned = False
    removed = False
    if owned:
        deletion = _docker(["image", "rm", "--force", image_id], cwd=work_root, timeout=120)
        removed = deletion.returncode == 0 and not deletion.timed_out and not deletion.output_truncated
    post = _docker(["image", "inspect", image_id], cwd=work_root, timeout=60)
    absent_after = post.returncode != 0 and not post.timed_out and not post.output_truncated
    return {
        "ownership_verified": owned,
        "removed": removed,
        "absent_after": absent_after,
        "passed": owned and removed and absent_after,
        "raw_returned": False,
    }


def _tmpfs_matches(actual: object, expected: Mapping[str, str]) -> bool:
    return isinstance(actual, Mapping) and dict(actual) == dict(expected)


def _container_isolation(
    container: Mapping[str, Any],
    *,
    image_id: str,
    network_name: str,
    alias: str,
    nonce: str,
    contract_label: str,
) -> dict[str, Any]:
    host = container.get("HostConfig")
    config = container.get("Config")
    network = container.get("NetworkSettings")
    mounts = container.get("Mounts")
    host = host if isinstance(host, Mapping) else {}
    config = config if isinstance(config, Mapping) else {}
    network = network if isinstance(network, Mapping) else {}
    labels = _labels(container)
    networks = network.get("Networks")
    network_row = networks.get(network_name) if isinstance(networks, Mapping) else None
    aliases = network_row.get("Aliases") if isinstance(network_row, Mapping) else None
    security_opt = host.get("SecurityOpt")
    cap_drop = host.get("CapDrop")
    checks = {
        "image": container.get("Image") == image_id,
        "network": host.get("NetworkMode") == network_name,
        "network_alias": isinstance(aliases, list) and alias in aliases,
        "no_host_port": network.get("Ports") in ({}, None) and host.get("PortBindings") in ({}, None),
        "read_only_rootfs": host.get("ReadonlyRootfs") is True,
        "cap_drop_all": isinstance(cap_drop, list) and cap_drop == ["ALL"],
        "cap_add_empty": host.get("CapAdd") in (None, []),
        "no_new_privileges": isinstance(security_opt, list) and "no-new-privileges=true" in security_opt,
        "pids_limit": host.get("PidsLimit") == APP_PIDS_LIMIT,
        "memory_limit": host.get("Memory") == APP_MEMORY_BYTES,
        "cpu_limit": host.get("NanoCpus") == NANO_CPUS,
        "not_privileged": host.get("Privileged") is False,
        "no_binds": host.get("Binds") in (None, []),
        "tmpfs": _tmpfs_matches(host.get("Tmpfs"), APP_TMPFS),
        "no_non_tmpfs_mount": isinstance(mounts, list)
        and all(isinstance(mount, Mapping) and mount.get("Type") == "tmpfs" for mount in mounts),
        "non_root_user": config.get("User") == APP_USER,
        "owned_labels": labels.get("io.k-guard.app-id") == APP_ID
        and labels.get("io.k-guard.execution-contract") == contract_label
        and labels.get("io.k-guard.run-nonce") == nonce
        and labels.get("io.k-guard.role") == "application",
    }
    return {
        "checks": checks,
        "passed": all(checks.values()),
        "raw_returned": False,
    }


def _create_network(
    *, work_root: Path, nonce: str, contract_label: str
) -> tuple[str, str, dict[str, Any]]:
    name = f"kguard-l2-pygoat-net-{nonce}"
    created = _docker(
        [
            "network",
            "create",
            "--internal",
            "--label",
            f"io.k-guard.app-id={APP_ID}",
            "--label",
            f"io.k-guard.execution-contract={contract_label}",
            "--label",
            f"io.k-guard.run-nonce={nonce}",
            name,
        ],
        cwd=work_root,
        timeout=60,
    )
    network_id = _container_id(created, "network_create")
    inspected = _load_json_stdout(_docker(["network", "inspect", name], cwd=work_root, timeout=60), "network_inspect")
    row = inspected[0] if isinstance(inspected, list) and len(inspected) == 1 and isinstance(inspected[0], Mapping) else {}
    labels = row.get("Labels") if isinstance(row.get("Labels"), Mapping) else {}
    checks = {
        "id": row.get("Id") == network_id,
        "internal": row.get("Internal") is True,
        "scope": row.get("Scope") == "local",
        "owned_labels": labels.get("io.k-guard.app-id") == APP_ID
        and labels.get("io.k-guard.execution-contract") == contract_label
        and labels.get("io.k-guard.run-nonce") == nonce,
    }
    return (
        name,
        network_id,
        {
            "id_sha256": sha256_bytes(network_id.encode("ascii")),
            "checks": checks,
            "passed": all(checks.values()),
            "raw_returned": False,
        },
    )


def _create_application_container(
    *,
    work_root: Path,
    image_id: str,
    network_name: str,
    nonce: str,
    contract_label: str,
) -> tuple[str, str, dict[str, Any]]:
    name = f"kguard-l2-pygoat-app-{nonce}"
    alias = "pygoat-app"
    arguments = [
        "container",
        "create",
        "--name",
        name,
        "--network",
        network_name,
        "--network-alias",
        alias,
        "--read-only",
        "--user",
        APP_USER,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--pids-limit",
        str(APP_PIDS_LIMIT),
        "--memory",
        str(APP_MEMORY_BYTES),
        "--cpus",
        "1",
    ]
    for target, options in APP_TMPFS.items():
        arguments.extend(["--tmpfs", f"{target}:{options}"])
    arguments.extend(
        [
            "--label",
            f"io.k-guard.app-id={APP_ID}",
            "--label",
            f"io.k-guard.execution-contract={contract_label}",
            "--label",
            f"io.k-guard.run-nonce={nonce}",
            "--label",
            "io.k-guard.role=application",
            image_id,
            "python",
            "manage.py",
            "runserver",
            "127.0.0.1:8000",
            "--noreload",
        ]
    )
    created = _docker(arguments, cwd=work_root, timeout=60)
    container_id = _container_id(created, "application_create")
    rows = _load_json_stdout(
        _docker(["container", "inspect", name], cwd=work_root, timeout=60), "application_inspect"
    )
    container = rows[0] if isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], Mapping) else {}
    isolation = _container_isolation(
        container,
        image_id=image_id,
        network_name=network_name,
        alias=alias,
        nonce=nonce,
        contract_label=contract_label,
    )
    return name, container_id, isolation


def _parse_driver_result(output: bytes, *, mode: str, expected_status: int) -> dict[str, Any]:
    marker = "K_GUARD_PYGOAT_SENSITIVE_DATA_RESULT:".encode("ascii")
    rows = [line[len(marker) :] for line in output.splitlines() if line.startswith(marker)]
    if len(rows) != 1:
        raise RuntimeContractError("driver_result_marker_invalid")
    try:
        value = json.loads(rows[0].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError("driver_result_not_json") from exc
    if not isinstance(value, dict):
        raise RuntimeContractError("driver_result_shape_invalid")
    expected = {
        "schema": DRIVER_RESULT_SCHEMA,
        "mode": mode,
        "expected_status": expected_status,
        "passed": True,
        "raw_returned": False,
        "driver_error_code": None,
    }
    if any(value.get(key) != item for key, item in expected.items()):
        raise RuntimeContractError("driver_result_contract_invalid")
    positive = (
        value.get("observed_status") == 200
        and value.get("users_json_observed") is True
        and value.get("users_nonempty") is True
        and value.get("expected_field_shape_observed") is True
        and value.get("login_redirect_observed") is False
    )
    negative = (
        value.get("observed_status") == 302
        and value.get("users_json_observed") is False
        and value.get("users_nonempty") is False
        and value.get("expected_field_shape_observed") is False
        and value.get("login_redirect_observed") is True
    )
    if not (positive if mode == "positive" else negative):
        raise RuntimeContractError("driver_result_outcome_invalid")
    return value


def _live_run(image_id: str, *, work_root: Path, timeout: int, variant: str) -> dict[str, Any]:
    contract_label = EXECUTION_CONTRACT_LABEL if variant == "positive" else NEGATIVE_CONTROL_LABEL
    expected_status = 200 if variant == "positive" else 302
    nonce = secrets.token_hex(16)
    network_name: str | None = None
    network_id: str | None = None
    application_name: str | None = None
    application_id: str | None = None
    isolation: dict[str, Any] | None = None
    execution: dict[str, Any] | None = None
    normalized_result: dict[str, Any] | None = None
    failure: str | None = None
    cleanup: dict[str, Any] | None = None
    try:
        network_name, network_id, network_isolation = _create_network(
            work_root=work_root, nonce=nonce, contract_label=contract_label
        )
        if not network_isolation["passed"]:
            raise RuntimeContractError("network_isolation_invalid")
        application_name, application_id, isolation = _create_application_container(
            work_root=work_root,
            image_id=image_id,
            network_name=network_name,
            nonce=nonce,
            contract_label=contract_label,
        )
        if not isolation["passed"]:
            raise RuntimeContractError("application_isolation_invalid")
        started = _docker(["container", "start", application_name], cwd=work_root, timeout=60)
        _expect_success(started, "application_start")
        executed = _docker(
            [
                "container",
                "exec",
                "--env",
                f"KGUARD_MODE={variant}",
                "--env",
                f"KGUARD_EXPECTED_STATUS={expected_status}",
                application_name,
                "python",
                "/opt/kguard/driver.py",
            ],
            cwd=work_root,
            timeout=timeout,
        )
        execution = _command_receipt(executed)
        _expect_success(executed, "loopback_driver")
        normalized_result = _parse_driver_result(
            executed.stdout, mode=variant, expected_status=expected_status
        )
    except RuntimeContractError as exc:
        failure = str(exc)
    finally:
        application_cleanup = (
            _cleanup_container(
                work_root=work_root,
                name=application_name,
                expected_id=application_id,
                nonce=nonce,
                contract_label=contract_label,
                role="application",
            )
            if application_name is not None
            else {
                "ownership_verified": application_id is None,
                "removed": False,
                "absent_after": application_id is None,
                "passed": application_id is None,
                "raw_returned": False,
            }
        )
        network_cleanup = (
            _cleanup_network(
                work_root=work_root,
                name=network_name,
                expected_id=network_id,
                nonce=nonce,
                contract_label=contract_label,
            )
            if network_name is not None
            else {
                "ownership_verified": network_id is None,
                "removed": False,
                "absent_after": network_id is None,
                "passed": network_id is None,
                "raw_returned": False,
            }
        )
        cleanup = {
            "application": application_cleanup,
            "network": network_cleanup,
            "passed": application_cleanup["passed"] and network_cleanup["passed"],
            "raw_returned": False,
        }
        if failure is None and not cleanup["passed"]:
            failure = "runtime_cleanup_failed"
    return {
        "run_nonce_sha256": sha256_bytes(nonce.encode("ascii")),
        "image_id": image_id,
        "driver_sha256": sha256_bytes(DRIVER_SCRIPT.encode("utf-8")),
        "network_policy": NETWORK_POLICY,
        "expected_status": expected_status,
        "mode": variant,
        "isolation": isolation,
        "execution": execution,
        "normalized_result": normalized_result,
        "cleanup": cleanup,
        "failure_code": failure,
        "passed": failure is None
        and isolation is not None
        and isolation.get("passed") is True
        and execution is not None
        and execution.get("returncode") == 0
        and normalized_result is not None
        and normalized_result.get("passed") is True
        and cleanup is not None
        and cleanup.get("passed") is True,
        "raw_returned": False,
    }


def _isolation_consensus_projection(value: object) -> object:
    if not isinstance(value, Mapping):
        return value
    return {
        "checks": value.get("checks"),
        "passed": value.get("passed"),
        "raw_returned": value.get("raw_returned"),
    }


def _consensus_projection(run: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "driver_sha256": run.get("driver_sha256"),
        "network_policy": run.get("network_policy"),
        "expected_status": run.get("expected_status"),
        "mode": run.get("mode"),
        "isolation": _isolation_consensus_projection(run.get("isolation")),
        "normalized_result": run.get("normalized_result"),
        "passed": run.get("passed"),
        "raw_returned": run.get("raw_returned"),
    }


def _claim_boundary(*, negative: bool) -> dict[str, bool]:
    return {
        "source_bound_execution_repeatability_only": True,
        "source_mutated_negative_control_only": negative,
        "scanner_accuracy_proven": False,
        "korean_personal_data_detection_proven": False,
        "severity_or_cwe_admitted": False,
        "tp_fp_fn_admitted": False,
        "guardian_or_release_admitted": False,
    }


def _tool_provenance(verifier_sha256: str) -> dict[str, Any]:
    runner_path = Path(__file__).resolve(strict=True)
    return {
        "runner_sha256": sha256_bytes(runner_path.read_bytes()),
        "source_verifier_sha256": verifier_sha256,
        "driver_sha256": sha256_bytes(DRIVER_SCRIPT.encode("utf-8")),
        "adapter_entrypoint_sha256": sha256_bytes(ADAPTER_ENTRYPOINT.encode("utf-8")),
        "source_image_id": SOURCE_IMAGE_ID,
        "raw_returned": False,
    }


def _expected_positive_execution_tool_provenance() -> dict[str, Any]:
    _verifier, verifier_sha256 = _load_source_verifier()
    return _tool_provenance(verifier_sha256)


def _execute(
    source_root: Path,
    p23a_registry: Path,
    *,
    timeout: int,
    variant: str,
    positive_reference: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    source, _verifier, verifier_sha256 = verify_source_workspace(
        source_root.resolve(), p23a_registry.resolve()
    )
    tool_provenance = _tool_provenance(verifier_sha256)
    contract_label = EXECUTION_CONTRACT_LABEL if variant == "positive" else NEGATIVE_CONTROL_LABEL
    with tempfile.TemporaryDirectory(prefix=f"kguard-l2-pygoat-{variant}-") as temporary:
        work_root = Path(temporary)
        base_image, source_files = _validate_base_image(source_root.resolve(), work_root=work_root)
        image: dict[str, Any] | None = None
        image_id: str | None = None
        image_cleanup: dict[str, Any] | None = None
        runs: list[dict[str, Any]] = []
        view_projection: dict[str, Any] | None = None
        failure: str | None = None
        try:
            views = source_files[VIEW_PATH]
            if variant == "negative":
                views, view_projection = _negative_view_patch(views)
            else:
                view_projection = {
                    "source_path": VIEW_PATH,
                    "original_file_sha256": sha256_bytes(views),
                    "source_checkout_mutated": False,
                    "raw_returned": False,
                }
            image, image_id = _build_replay_image(
                work_root=work_root,
                timeout=timeout,
                base_image=base_image,
                views=views,
                view_projection=view_projection,
                variant=variant,
            )
            runs = [
                _live_run(image_id, work_root=work_root, timeout=timeout, variant=variant)
                for _ in range(2)
            ]
        except RuntimeContractError as exc:
            failure = str(exc)
        finally:
            if image_id is not None:
                image_cleanup = _cleanup_image(
                    image_id, work_root=work_root, contract_label=contract_label
                )
    projections = [_consensus_projection(run) for run in runs]
    consensus_passed = (
        len(projections) == 2
        and projections[0] == projections[1]
        and all(run.get("passed") is True for run in runs)
    )
    if failure is None and not consensus_passed:
        failure = "execution_repeatability_or_runtime_failed"
    status = (
        "EXECUTION_CONTRACT_PASS" if variant == "positive" else "NEGATIVE_CONTROL_PASS"
    ) if (
        failure is None
        and image is not None
        and image_cleanup is not None
        and image_cleanup.get("passed") is True
        and consensus_passed
    ) else "HOLD"
    common = {
        "tool_provenance": tool_provenance,
        "source": source,
        "base_image": base_image,
        "image": image,
        "runs": runs,
        "consensus": {
            "run_count": len(runs),
            "two_runs_byte_equivalent_after_normalization": consensus_passed,
            "projection_sha256": _canonical_sha256(projections) if projections else None,
            "raw_returned": False,
        },
        "image_cleanup": image_cleanup,
        "release_gate_passed": False,
        "failure_code": failure,
        "raw_returned": False,
    }
    if variant == "positive":
        receipt = {
            "schema": SCHEMA,
            **common,
            "claim_boundary": _claim_boundary(negative=False),
            "admission_blockers": list(ADMISSION_BLOCKERS),
            "execution_contract_status": status,
        }
        validate_receipt(receipt)
        return receipt
    if positive_reference is None:
        raise RuntimeContractError("negative_control_positive_reference_missing")
    receipt = {
        "schema": NEGATIVE_CONTROL_SCHEMA,
        **common,
        "positive_execution_contract": dict(positive_reference),
        "negative_control": view_projection,
        "claim_boundary": _claim_boundary(negative=True),
        "admission_blockers": list(NEGATIVE_CONTROL_ADMISSION_BLOCKERS),
        "negative_control_status": status,
    }
    validate_negative_control_receipt(receipt)
    return receipt


def execute_contract(source_root: Path, p23a_registry: Path, *, timeout: int) -> dict[str, Any]:
    return _execute(source_root, p23a_registry, timeout=timeout, variant="positive")


def _load_positive_execution_contract(path: Path, *, source: Mapping[str, Any]) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeContractError("positive_execution_receipt_invalid_path")
    raw = path.read_bytes()
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError("positive_execution_receipt_not_json") from exc
    if not isinstance(receipt, dict) or canonical_json_bytes(receipt) != raw:
        raise RuntimeContractError("positive_execution_receipt_not_canonical")
    validate_receipt(receipt)
    if receipt.get("execution_contract_status") != "EXECUTION_CONTRACT_PASS":
        raise RuntimeContractError("positive_execution_receipt_not_passed")
    if receipt.get("tool_provenance") != _expected_positive_execution_tool_provenance():
        raise RuntimeContractError("positive_execution_tool_provenance_mismatch")
    positive_source = receipt.get("source")
    source_keys = (
        "repository_id",
        "commit",
        "commit_tree",
        "source_tree_sha256",
        "p23a_registry_sha256",
        "p23a_app_receipt_sha256",
        "p23a_app_receipt_semantic_sha256",
        "current_source_receipt_sha256",
    )
    if not isinstance(positive_source, Mapping) or any(
        positive_source.get(key) != source.get(key) for key in source_keys
    ):
        raise RuntimeContractError("positive_execution_source_mismatch")
    return {
        "receipt_sha256": sha256_bytes(raw),
        "source_receipt_sha256": source["current_source_receipt_sha256"],
        "execution_contract_status": "EXECUTION_CONTRACT_PASS",
        "raw_returned": False,
    }


def execute_negative_control(
    source_root: Path, p23a_registry: Path, positive_receipt: Path, *, timeout: int
) -> dict[str, Any]:
    source, _verifier, _verifier_sha256 = verify_source_workspace(
        source_root.resolve(), p23a_registry.resolve()
    )
    positive_reference = _load_positive_execution_contract(positive_receipt, source=source)
    return _execute(
        source_root,
        p23a_registry,
        timeout=timeout,
        variant="negative",
        positive_reference=positive_reference,
    )


def _assert_raw_free(value: object) -> None:
    if isinstance(value, Mapping):
        if "raw_returned" in value and value["raw_returned"] is not False:
            raise RuntimeContractError("raw_boundary_invalid")
        for nested in value.values():
            _assert_raw_free(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_raw_free(nested)


def _validate_hash(value: object, label: str) -> None:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise RuntimeContractError(f"{label}_invalid")


def _validate_source(source: object) -> None:
    if not isinstance(source, Mapping):
        raise RuntimeContractError("receipt_source_invalid")
    expected = {
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
        "p23a_app_receipt_sha256": P23A_APP_RECEIPT_SHA256,
        "p23a_app_receipt_semantic_sha256": P23A_APP_SEMANTIC_SHA256,
        "raw_returned": False,
    }
    if any(source.get(key) != value for key, value in expected.items()):
        raise RuntimeContractError("receipt_source_binding_invalid")
    for key in ("p23a_registry_sha256", "current_source_receipt_sha256"):
        _validate_hash(source.get(key), f"receipt_source_{key}")
    if (
        not isinstance(source.get("file_count"), int)
        or source["file_count"] <= 0
        or not isinstance(source.get("total_bytes"), int)
        or source["total_bytes"] <= 0
    ):
        raise RuntimeContractError("receipt_source_size_invalid")


def _validate_tool(tool: object) -> None:
    if not isinstance(tool, Mapping) or tool.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_tool_invalid")
    for key in (
        "runner_sha256",
        "source_verifier_sha256",
        "driver_sha256",
        "adapter_entrypoint_sha256",
    ):
        _validate_hash(tool.get(key), f"receipt_tool_{key}")
    if tool.get("source_image_id") != SOURCE_IMAGE_ID:
        raise RuntimeContractError("receipt_tool_image_binding_invalid")


def _validate_base_image_receipt(base_image: object) -> None:
    if not isinstance(base_image, Mapping) or base_image.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_base_image_invalid")
    expected = {
        "source_image_id": SOURCE_IMAGE_ID,
        "source_image_ref": SOURCE_IMAGE_REF,
        "source_image_commit_label": SOURCE_COMMIT,
        "source_dockerfile_sha256": SOURCE_DOCKERFILE_SHA256,
        "source_subproject": SOURCE_SUBPROJECT,
        "source_image_current_source_provenance_only": True,
        "fresh_dependency_rebuild_proven": False,
        "runtime_supply_chain_proven": False,
    }
    if any(base_image.get(key) != value for key, value in expected.items()):
        raise RuntimeContractError("receipt_base_image_binding_invalid")
    _validate_hash(base_image.get("source_image_rootfs_layers_sha256"), "receipt_base_image_layers")
    for key in ("source_file_sha256", "image_file_sha256"):
        row = base_image.get(key)
        if not isinstance(row, Mapping):
            raise RuntimeContractError("receipt_base_image_file_hashes_invalid")
        expected_keys = set(SOURCE_FILES) if key == "source_file_sha256" else set(IMAGE_FILE_PATHS)
        if set(row) != expected_keys:
            raise RuntimeContractError("receipt_base_image_file_hashes_invalid")
        for name, digest in row.items():
            if SOURCE_FILES.get(name) != digest:
                raise RuntimeContractError("receipt_base_image_file_hashes_invalid")


def _validate_view(view: object, *, variant: str) -> None:
    if not isinstance(view, Mapping) or view.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_view_invalid")
    if (
        view.get("source_path") != VIEW_PATH
        or view.get("source_checkout_mutated") is not False
        or view.get("original_file_sha256") != SOURCE_FILES[VIEW_PATH]
    ):
        raise RuntimeContractError("receipt_view_binding_invalid")
    if variant == "positive":
        if set(view) != {"source_path", "original_file_sha256", "source_checkout_mutated", "raw_returned"}:
            raise RuntimeContractError("receipt_positive_view_shape_invalid")
        return
    if (
        view.get("patch_id") != NEGATIVE_CONTROL_PATCH_ID
        or view.get("marker_count") != 1
        or view.get("replacement_count") != 1
    ):
        raise RuntimeContractError("receipt_negative_view_patch_invalid")
    for key in ("patched_file_sha256", "patch_sha256"):
        _validate_hash(view.get(key), f"receipt_view_{key}")
    if view["patched_file_sha256"] == view["original_file_sha256"]:
        raise RuntimeContractError("receipt_negative_view_patch_unchanged")


def _validate_image(image: object, *, variant: str) -> None:
    if not isinstance(image, Mapping) or image.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_image_invalid")
    if (
        not isinstance(image.get("image_id"), str)
        or IMAGE_ID_RE.fullmatch(image["image_id"]) is None
        or image.get("base_source_image_id") != SOURCE_IMAGE_ID
        or image.get("contract_label")
        != (EXECUTION_CONTRACT_LABEL if variant == "positive" else NEGATIVE_CONTROL_LABEL)
        or image.get("source_derived") is not True
        or image.get("build_network") != "none"
        or image.get("fresh_dependency_rebuild_proven") is not False
    ):
        raise RuntimeContractError("receipt_image_binding_invalid")
    for key in (
        "image_id_sha256",
        "dockerfile_sha256",
        "driver_sha256",
        "adapter_entrypoint_sha256",
        "build_contract_sha256",
        "rootfs_lineage_sha256",
    ):
        _validate_hash(image.get(key), f"receipt_image_{key}")
    _validate_view(image.get("view"), variant=variant)


def _validate_run(run: object, *, variant: str) -> None:
    if not isinstance(run, Mapping) or run.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_run_invalid")
    expected_status = 200 if variant == "positive" else 302
    isolation = run.get("isolation")
    execution = run.get("execution")
    normalized = run.get("normalized_result")
    cleanup = run.get("cleanup")
    if (
        run.get("network_policy") != NETWORK_POLICY
        or run.get("expected_status") != expected_status
        or run.get("mode") != variant
        or run.get("passed") is not True
        or not isinstance(isolation, Mapping)
        or isolation.get("passed") is not True
        or not isinstance(execution, Mapping)
        or execution.get("returncode") != 0
        or not isinstance(normalized, Mapping)
        or normalized.get("passed") is not True
        or not isinstance(cleanup, Mapping)
        or cleanup.get("passed") is not True
        or run.get("failure_code") is not None
    ):
        raise RuntimeContractError("receipt_run_contract_invalid")
    _validate_hash(run.get("run_nonce_sha256"), "receipt_run_nonce")
    _validate_hash(run.get("driver_sha256"), "receipt_run_driver")
    if run.get("driver_sha256") != sha256_bytes(DRIVER_SCRIPT.encode("utf-8")):
        raise RuntimeContractError("receipt_run_driver_binding_invalid")


def _validate_common_receipt(receipt: Mapping[str, Any], *, variant: str) -> None:
    _assert_raw_free(receipt)
    _validate_tool(receipt.get("tool_provenance"))
    _validate_source(receipt.get("source"))
    if receipt.get("release_gate_passed") is not False:
        raise RuntimeContractError("receipt_release_promotion_invalid")
    status_key = "execution_contract_status" if variant == "positive" else "negative_control_status"
    passed_status = "EXECUTION_CONTRACT_PASS" if variant == "positive" else "NEGATIVE_CONTROL_PASS"
    status = receipt.get(status_key)
    if status not in {passed_status, "HOLD"}:
        raise RuntimeContractError("receipt_status_invalid")
    if status == passed_status:
        _validate_base_image_receipt(receipt.get("base_image"))
        _validate_image(receipt.get("image"), variant=variant)
        runs = receipt.get("runs")
        consensus = receipt.get("consensus")
        cleanup = receipt.get("image_cleanup")
        if (
            not isinstance(runs, list)
            or len(runs) != 2
            or not all(isinstance(run, Mapping) for run in runs)
            or not isinstance(consensus, Mapping)
            or consensus.get("run_count") != 2
            or consensus.get("two_runs_byte_equivalent_after_normalization") is not True
            or not isinstance(cleanup, Mapping)
            or cleanup.get("passed") is not True
            or receipt.get("failure_code") is not None
        ):
            raise RuntimeContractError("receipt_pass_incomplete")
        for run in runs:
            _validate_run(run, variant=variant)
    elif receipt.get("failure_code") is None:
        raise RuntimeContractError("receipt_hold_without_failure")


def validate_receipt(receipt: dict[str, Any]) -> None:
    required = {
        "schema",
        "tool_provenance",
        "source",
        "base_image",
        "image",
        "runs",
        "consensus",
        "image_cleanup",
        "claim_boundary",
        "admission_blockers",
        "execution_contract_status",
        "release_gate_passed",
        "failure_code",
        "raw_returned",
    }
    if (
        set(receipt) != required
        or receipt.get("schema") != SCHEMA
        or receipt.get("raw_returned") is not False
        or receipt.get("claim_boundary") != _claim_boundary(negative=False)
        or tuple(receipt.get("admission_blockers", ())) != ADMISSION_BLOCKERS
    ):
        raise RuntimeContractError("receipt_schema_invalid")
    _validate_common_receipt(receipt, variant="positive")


def validate_negative_control_receipt(receipt: dict[str, Any]) -> None:
    required = {
        "schema",
        "tool_provenance",
        "source",
        "base_image",
        "image",
        "runs",
        "consensus",
        "image_cleanup",
        "positive_execution_contract",
        "negative_control",
        "claim_boundary",
        "admission_blockers",
        "negative_control_status",
        "release_gate_passed",
        "failure_code",
        "raw_returned",
    }
    if (
        set(receipt) != required
        or receipt.get("schema") != NEGATIVE_CONTROL_SCHEMA
        or receipt.get("raw_returned") is not False
        or receipt.get("claim_boundary") != _claim_boundary(negative=True)
        or tuple(receipt.get("admission_blockers", ())) != NEGATIVE_CONTROL_ADMISSION_BLOCKERS
    ):
        raise RuntimeContractError("negative_control_receipt_schema_invalid")
    positive = receipt.get("positive_execution_contract")
    if (
        not isinstance(positive, Mapping)
        or positive.get("execution_contract_status") != "EXECUTION_CONTRACT_PASS"
        or positive.get("raw_returned") is not False
    ):
        raise RuntimeContractError("negative_control_positive_reference_invalid")
    for key in ("receipt_sha256", "source_receipt_sha256"):
        _validate_hash(positive.get(key), f"negative_control_positive_{key}")
    _validate_view(receipt.get("negative_control"), variant="negative")
    _validate_common_receipt(receipt, variant="negative")


def _write_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise RuntimeContractError("refusing_to_overwrite_execution_evidence")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical_json_bytes(dict(receipt)))
        stream.flush()
        os.fsync(stream.fileno())


def _load_canonical_receipt(path: Path, *, negative: bool) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeContractError("receipt_invalid_path")
    raw = path.read_bytes()
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError("receipt_not_json") from exc
    if not isinstance(receipt, dict) or canonical_json_bytes(receipt) != raw:
        raise RuntimeContractError("receipt_not_canonical")
    if negative:
        validate_negative_control_receipt(receipt)
    else:
        validate_receipt(receipt)
    return receipt


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replay a source-bound PyGoat sensitive-data exposure execution pair without detector or release promotion."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    positive = subparsers.add_parser("positive")
    positive.add_argument("--source-root", type=Path, required=True)
    positive.add_argument("--p23a-registry", type=Path, required=True)
    positive.add_argument("--output", type=Path, required=True)
    positive.add_argument("--timeout-seconds", type=int, default=240)
    negative = subparsers.add_parser("negative-control")
    negative.add_argument("--source-root", type=Path, required=True)
    negative.add_argument("--p23a-registry", type=Path, required=True)
    negative.add_argument("--positive-receipt", type=Path, required=True)
    negative.add_argument("--output", type=Path, required=True)
    negative.add_argument("--timeout-seconds", type=int, default=240)
    verify_positive = subparsers.add_parser("verify-positive")
    verify_positive.add_argument("--receipt", type=Path, required=True)
    verify_negative = subparsers.add_parser("verify-negative-control")
    verify_negative.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-positive":
            receipt = _load_canonical_receipt(args.receipt, negative=False)
            print(json.dumps({"status": receipt["execution_contract_status"], "raw_returned": False}, sort_keys=True))
            return 0 if receipt["execution_contract_status"] == "EXECUTION_CONTRACT_PASS" else 2
        if args.command == "verify-negative-control":
            receipt = _load_canonical_receipt(args.receipt, negative=True)
            print(json.dumps({"status": receipt["negative_control_status"], "raw_returned": False}, sort_keys=True))
            return 0 if receipt["negative_control_status"] == "NEGATIVE_CONTROL_PASS" else 2
        if args.timeout_seconds < 60:
            raise RuntimeContractError("timeout_seconds_too_small")
        if args.command == "positive":
            receipt = execute_contract(args.source_root, args.p23a_registry, timeout=args.timeout_seconds)
            _write_receipt(args.output, receipt)
            print(json.dumps({"status": receipt["execution_contract_status"], "raw_returned": False}, sort_keys=True))
            return 0 if receipt["execution_contract_status"] == "EXECUTION_CONTRACT_PASS" else 2
        receipt = execute_negative_control(
            args.source_root,
            args.p23a_registry,
            args.positive_receipt,
            timeout=args.timeout_seconds,
        )
        _write_receipt(args.output, receipt)
        print(json.dumps({"status": receipt["negative_control_status"], "raw_returned": False}, sort_keys=True))
        return 0 if receipt["negative_control_status"] == "NEGATIVE_CONTROL_PASS" else 2
    except (OSError, json.JSONDecodeError, RuntimeContractError) as exc:
        print(json.dumps({"status": "HOLD", "failure_code": str(exc), "raw_returned": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
