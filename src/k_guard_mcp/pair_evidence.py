from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .pair_admission import (
    PAIR_VERIFICATION_SCHEMA,
    pair_subject_sha256,
    validate_pair_admission,
)


PLAN_SCHEMA = "k_guard_pair_evidence_plan.v1"
RESULT_SCHEMA = "k_guard_pair_evidence_result.v1"
ORACLE_RESULT_SCHEMA = "k_guard_pair_oracle_result.v1"
DIFF_RESULT_SCHEMA = "k_guard_pair_diff_result.v1"
INVARIANT_RESULT_SCHEMA = "k_guard_pair_invariant_result.v1"

MAX_FILES = 4096
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TREE_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_ARG_COUNT = 128
MAX_ARG_BYTES = 32 * 1024
MAX_TIMEOUT_SECONDS = 120

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DIGEST_REF_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
_ALLOWED_CONTAINER_EXECUTABLES = frozenset(
    {
        "/bin/cat",
        "/bin/grep",
        "/usr/bin/dotnet",
        "/usr/bin/java",
        "/usr/bin/node",
        "/usr/bin/php",
        "/usr/bin/python3",
        "/usr/bin/ruby",
        "/usr/local/bin/node",
        "/usr/local/bin/php",
        "/usr/local/bin/python",
        "/usr/local/bin/python3",
        "/usr/local/bin/ruby",
        "/usr/local/go/bin/go",
    }
)
_CASE_CONTRACTS = {
    "exploit_vulnerable": ("exploit", "exploit_succeeded", True, "vulnerable"),
    "exploit_fixed": ("exploit", "exploit_succeeded", False, "fixed"),
    "fixed_functional": ("regression", "functional_passed", True, "fixed"),
    "negative_control": ("negative_control", "control_triggered", False, "fixed"),
}
_ISOLATION_CONTRACT = {
    "network": "none",
    "read_only_root": True,
    "cap_drop": "ALL",
    "no_new_privileges": True,
    "user": "65532:65532",
    "pids_limit": 64,
    "memory_bytes": 256 * 1024 * 1024,
    "nano_cpus": 500_000_000,
    "tmpfs_bytes": 16 * 1024 * 1024,
}


class PairEvidenceError(ValueError):
    pass


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    output_truncated: bool = False


class CommandRunner(Protocol):
    def run(self, argv: Sequence[str], *, timeout_seconds: int) -> ProcessResult: ...


class SubprocessDockerRunner:
    def run(self, argv: Sequence[str], *, timeout_seconds: int) -> ProcessResult:
        _validate_host_command(argv, timeout_seconds)
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                shell=False,
                env=_docker_environment(),
            )
            timed_out = False
            try:
                returncode = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                process.wait()
                returncode = 124
            stdout.seek(0)
            stderr.seek(0)
            stdout_raw = stdout.read(MAX_OUTPUT_BYTES + 1)
            stderr_raw = stderr.read(MAX_OUTPUT_BYTES + 1)
        truncated = len(stdout_raw) > MAX_OUTPUT_BYTES or len(stderr_raw) > MAX_OUTPUT_BYTES
        return ProcessResult(
            int(returncode),
            stdout_raw[:MAX_OUTPUT_BYTES],
            stderr_raw[:MAX_OUTPUT_BYTES],
            timed_out=timed_out,
            output_truncated=truncated,
        )


def canonical_json_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PairEvidenceError("value is not canonical JSON") from exc


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verifier_artifact_sha256() -> str:
    artifacts = {
        path.name: sha256_bytes(path.read_bytes())
        for path in (Path(__file__), Path(__file__).with_name("pair_admission.py"))
    }
    return _domain_hash(b"k_guard_pair_verifier_artifacts.v1\0", artifacts)


def command_sha256(command: Mapping[str, Any]) -> str:
    normalized = _validate_command(command, "command")
    return _domain_hash(b"k_guard_pair_command.v1\0", normalized)


def regular_tree_receipt(root: Path) -> dict[str, Any]:
    canonical_root = _safe_root(root, label="tree root")
    rows: list[dict[str, Any]] = []
    total_bytes = 0
    for current, directories, files in os.walk(canonical_root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.sort()
        files.sort()
        for name in directories:
            _reject_link_or_reparse(current_path / name, "tree directory")
            if name in {".git", ".hg", ".svn"}:
                raise PairEvidenceError("tree contains version-control metadata")
        for name in files:
            target = current_path / name
            _reject_link_or_reparse(target, "tree file")
            info = target.stat()
            if not stat.S_ISREG(info.st_mode):
                raise PairEvidenceError("tree contains a non-regular file")
            if info.st_size < 0 or info.st_size > MAX_FILE_BYTES:
                raise PairEvidenceError("tree file exceeds size limit")
            raw = target.read_bytes()
            if len(raw) != info.st_size:
                raise PairEvidenceError("tree file changed while hashing")
            total_bytes += len(raw)
            rows.append(
                {
                    "path": target.relative_to(canonical_root).as_posix(),
                    "sha256": sha256_bytes(raw),
                    "byte_count": len(raw),
                }
            )
            if len(rows) > MAX_FILES or total_bytes > MAX_TREE_BYTES:
                raise PairEvidenceError("tree exceeds file or byte limit")
    if not rows:
        raise PairEvidenceError("tree must contain at least one file")
    rows.sort(key=lambda row: row["path"])
    return {
        "file_count": len(rows),
        "total_bytes": total_bytes,
        "tree_sha256": _domain_hash(b"k_guard_pair_source_tree.v1\0", rows),
        "files": rows,
    }


def _copy_tree_snapshot(
    source_root: Path,
    expected_receipt: Mapping[str, Any],
    snapshot_root: Path,
) -> None:
    snapshot_root.mkdir(parents=True, exist_ok=False)
    rows = expected_receipt.get("files")
    if not isinstance(rows, list):
        raise PairEvidenceError("source receipt files are invalid")
    for row in rows:
        if not isinstance(row, Mapping):
            raise PairEvidenceError("source receipt row is invalid")
        path = row.get("path")
        source = _safe_relative_file(source_root, path, label="snapshot source file")
        raw = source.read_bytes()
        if (
            len(raw) != row.get("byte_count")
            or sha256_bytes(raw) != row.get("sha256")
        ):
            raise PairEvidenceError("source changed while snapshotting")
        destination = snapshot_root / Path(str(path))
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as handle:
            handle.write(raw)
        try:
            destination.chmod(stat.S_IREAD)
        except OSError as exc:
            raise PairEvidenceError("snapshot file cannot be made read-only") from exc


def _snapshot_pair_roots(
    source_roots: Mapping[str, Path],
    source_receipts: Mapping[str, Mapping[str, Any]],
    snapshot_parent: Path,
) -> dict[str, Path]:
    parent = _safe_root(snapshot_parent, label="snapshot root")
    snapshots: dict[str, Path] = {}
    for name in ("vulnerable", "fixed", "oracle"):
        snapshot = parent / name
        _copy_tree_snapshot(source_roots[name], source_receipts[name], snapshot)
        receipt = regular_tree_receipt(snapshot)
        if receipt != source_receipts[name]:
            raise PairEvidenceError("snapshot receipt differs from source receipt")
        snapshots[name] = snapshot
    return snapshots


def _assert_snapshot_receipts(
    roots: Mapping[str, Path], source_receipts: Mapping[str, Mapping[str, Any]]
) -> None:
    for name in ("vulnerable", "fixed", "oracle"):
        if regular_tree_receipt(roots[name]) != source_receipts[name]:
            raise PairEvidenceError("snapshot changed before container execution")


def verify_pair_evidence(
    bundle_root: Path,
    manifest: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    if not isinstance(manifest, Mapping):
        raise PairEvidenceError("pair manifest must be an object")
    source_manifest = dict(manifest)
    supplied_verification = source_manifest.pop("verification", None)
    subject_sha256 = pair_subject_sha256(source_manifest)
    root = _safe_root(bundle_root, label="bundle root")
    verifier_before = verifier_artifact_sha256()
    normalized_plan = _validate_plan(plan, root, source_manifest, subject_sha256, verifier_before)
    paths = normalized_plan["paths"]
    roots = {
        name: _safe_relative_directory(root, relative, label=f"{name} root")
        for name, relative in paths.items()
    }
    source_receipts = {
        name: regular_tree_receipt(roots[name])
        for name in ("vulnerable", "fixed", "oracle")
    }
    hashes = source_manifest.get("hashes")
    if not isinstance(hashes, Mapping):
        raise PairEvidenceError("pair manifest hashes are missing")
    if hashes.get("vulnerable_source_sha256") != source_receipts["vulnerable"]["tree_sha256"]:
        raise PairEvidenceError("vulnerable source tree hash mismatch")
    if hashes.get("fixed_source_sha256") != source_receipts["fixed"]["tree_sha256"]:
        raise PairEvidenceError("fixed source tree hash mismatch")
    _verify_oracle_inventory(root, source_manifest, source_receipts["oracle"])
    _verify_command_bindings(source_manifest, normalized_plan["commands"])

    selected_runner = runner or SubprocessDockerRunner()
    with tempfile.TemporaryDirectory(prefix="k-guard-pair-replay-") as temporary:
        snapshot_roots = _snapshot_pair_roots(
            roots,
            source_receipts,
            Path(temporary),
        )
        (
            image_receipt,
            process_receipts,
            execution_receipts,
            physical_diff,
            diff_result,
            invariant_result,
            parsed_invariants,
        ) = _replay_in_snapshot(
            selected_runner,
            normalized_plan,
            snapshot_roots,
            source_receipts,
            source_manifest,
        )

    plan_sha256 = _domain_hash(b"k_guard_pair_evidence_plan.v1\0", normalized_plan)
    source_receipts_sha256 = _domain_hash(
        b"k_guard_pair_source_receipts.v1\0", source_receipts
    )
    execution_receipts_sha256 = _domain_hash(
        b"k_guard_pair_execution_receipts.v1\0",
        {"claims": execution_receipts, "processes": process_receipts},
    )
    diff_receipt_sha256 = _domain_hash(
        b"k_guard_pair_diff_receipt.v1\0",
        {"physical": physical_diff, "result_sha256": sha256_bytes(diff_result.stdout)},
    )
    invariants_receipt_sha256 = _domain_hash(
        b"k_guard_pair_invariants_receipt.v1\0",
        {"result_sha256": sha256_bytes(invariant_result.stdout), "values": parsed_invariants["invariants"]},
    )
    evidence_bundle_sha256 = _domain_hash(
        b"k_guard_pair_evidence_bundle.v2\0",
        {
            "subject_sha256": subject_sha256,
            "plan_sha256": plan_sha256,
            "image": image_receipt,
            "source_receipts_sha256": source_receipts_sha256,
            "execution_receipts_sha256": execution_receipts_sha256,
            "diff_receipt_sha256": diff_receipt_sha256,
            "invariants_receipt_sha256": invariants_receipt_sha256,
        },
    )
    verification = {
        "schema": PAIR_VERIFICATION_SCHEMA,
        "verified": True,
        "verifier_id": "k-guard-pair-evidence",
        "verifier_version": "2.1.0",
        "verifier_sha256": verifier_before,
        "runtime_image_reference": image_receipt["reference"],
        "runtime_image_id": image_receipt["image_id"],
        "plan_sha256": plan_sha256,
        "evidence_bundle_sha256": evidence_bundle_sha256,
        "subject_sha256": subject_sha256,
        "source_receipts_sha256": source_receipts_sha256,
        "execution_receipts_sha256": execution_receipts_sha256,
        "diff_receipt_sha256": diff_receipt_sha256,
        "invariants_receipt_sha256": invariants_receipt_sha256,
        "files_rehashed": True,
        "commands_executed": True,
        "diff_recomputed": True,
        "invariants_recomputed": True,
        "isolated_execution": True,
        "network_disabled": True,
        "snapshot_replayed": True,
        "raw_sensitive_output_returned": False,
    }
    if supplied_verification is not None and supplied_verification != verification:
        raise PairEvidenceError("supplied verification receipt differs from replay")
    if verifier_artifact_sha256() != verifier_before:
        raise PairEvidenceError("verifier artifact changed during replay")
    verified_manifest = {**source_manifest, "verification": verification}
    admission = validate_pair_admission(
        verified_manifest,
        expected_verifier_sha256=verifier_before,
    )
    if admission.get("schema_valid") is not True:
        raise PairEvidenceError(
            "pair schema validation failed after replay: " + ",".join(admission.get("errors", []))
        )
    return {
        "schema": RESULT_SCHEMA,
        "status": "PASS",
        "pair_admission": "LIVE_REPLAY_PASS",
        "release_gate_passed": False,
        "claim_boundary": {
            "generated_pair_machine_oracle": True,
            "scanner_accuracy_proved": False,
            "product_release_proved": False,
        },
        "manifest": verified_manifest,
        "verification_receipt": verification,
    }


def _replay_in_snapshot(
    runner: CommandRunner,
    plan: Mapping[str, Any],
    roots: Mapping[str, Path],
    source_receipts: Mapping[str, Mapping[str, Any]],
    manifest: Mapping[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    list[dict[str, Any]],
    ProcessResult,
    ProcessResult,
    dict[str, Any],
]:
    _assert_snapshot_receipts(roots, source_receipts)
    image_receipt = _inspect_image(runner, plan["runtime_image"])
    process_receipts: dict[str, Any] = {}
    execution_receipts: dict[str, Any] = {}
    for case_id, (command_id, outcome_name, expected, workspace) in _CASE_CONTRACTS.items():
        _assert_snapshot_receipts(roots, source_receipts)
        result = _run_container(
            runner,
            plan,
            roots,
            workspace=workspace,
            command_id=command_id,
        )
        parsed = _parse_execution_result(result, case_id, outcome_name, expected)
        process_receipts[case_id] = _process_receipt(result)
        execution_receipts[case_id] = {
            "executed": True,
            "harness_passed": True,
            "exit_code": 0,
            "command_sha256": command_sha256(plan["commands"][command_id]),
            "result_sha256": sha256_bytes(result.stdout),
            outcome_name: parsed["outcome"]["value"],
        }
    if manifest.get("executions") != execution_receipts:
        raise PairEvidenceError("execution receipts differ from physical replay")

    _assert_snapshot_receipts(roots, source_receipts)
    physical_diff = _physical_diff(roots["vulnerable"], roots["fixed"])
    _verify_physical_diff(manifest.get("diff"), physical_diff)
    diff_result = _run_container(
        runner,
        plan,
        roots,
        workspace="fixed",
        command_id="diff",
    )
    parsed_diff = _parse_structured_result(
        diff_result,
        schema=DIFF_RESULT_SCHEMA,
        case_id="diff",
        payload_key="production_changes",
    )
    if parsed_diff["production_changes"] != manifest.get("diff", {}).get("production_changes"):
        raise PairEvidenceError("semantic diff result differs from manifest")
    process_receipts["diff"] = _process_receipt(diff_result)

    _assert_snapshot_receipts(roots, source_receipts)
    invariant_result = _run_container(
        runner,
        plan,
        roots,
        workspace="fixed",
        command_id="invariants",
    )
    parsed_invariants = _parse_structured_result(
        invariant_result,
        schema=INVARIANT_RESULT_SCHEMA,
        case_id="invariants",
        payload_key="invariants",
    )
    if parsed_invariants["invariants"] != manifest.get("invariants"):
        raise PairEvidenceError("invariant result differs from manifest")
    process_receipts["invariants"] = _process_receipt(invariant_result)
    return (
        image_receipt,
        process_receipts,
        execution_receipts,
        physical_diff,
        diff_result,
        invariant_result,
        parsed_invariants,
    )


def load_canonical_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if len(raw) > 64 * 1024 * 1024:
            raise PairEvidenceError(f"{label} exceeds size limit")
        value = json.loads(raw.decode("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PairEvidenceError(f"{label} is not ASCII JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise PairEvidenceError(f"{label} must be a canonical JSON object")
    return value


def write_new_json(path: Path, value: object) -> None:
    raw = canonical_json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(raw)


def _validate_plan(
    plan: Mapping[str, Any],
    root: Path,
    manifest: Mapping[str, Any],
    subject_sha256: str,
    verifier_sha256: str,
) -> dict[str, Any]:
    if not isinstance(plan, Mapping):
        raise PairEvidenceError("verification plan must be an object")
    expected_keys = {
        "schema",
        "lineage_id",
        "bundle_root",
        "manifest_subject_sha256",
        "verifier_sha256",
        "runtime_image",
        "isolation",
        "paths",
        "commands",
    }
    if set(plan) != expected_keys:
        raise PairEvidenceError("verification plan fields differ from contract")
    if plan.get("schema") != PLAN_SCHEMA:
        raise PairEvidenceError("verification plan schema is invalid")
    if plan.get("lineage_id") != manifest.get("lineage_id"):
        raise PairEvidenceError("verification plan lineage differs from manifest")
    try:
        planned_root = Path(str(plan.get("bundle_root"))).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PairEvidenceError("verification plan bundle root is invalid") from exc
    if planned_root != root:
        raise PairEvidenceError("verification plan bundle root differs from replay root")
    if plan.get("manifest_subject_sha256") != subject_sha256:
        raise PairEvidenceError("verification plan subject hash mismatch")
    if plan.get("verifier_sha256") != verifier_sha256:
        raise PairEvidenceError("verification plan does not pin this verifier")
    image = _validate_image(plan.get("runtime_image"))
    if plan.get("isolation") != _ISOLATION_CONTRACT:
        raise PairEvidenceError("isolation profile differs from locked contract")
    paths = plan.get("paths")
    expected_paths = {"vulnerable": "vulnerable", "fixed": "fixed", "oracle": "oracle"}
    if paths != expected_paths:
        raise PairEvidenceError("pair paths differ from locked contract")
    commands = plan.get("commands")
    if not isinstance(commands, Mapping) or set(commands) != {
        "exploit",
        "regression",
        "negative_control",
        "diff",
        "invariants",
    }:
        raise PairEvidenceError("verification command set is incomplete")
    normalized_commands = {
        name: _validate_command(value, f"commands.{name}")
        for name, value in commands.items()
    }
    return {
        **dict(plan),
        "runtime_image": image,
        "isolation": dict(_ISOLATION_CONTRACT),
        "paths": dict(expected_paths),
        "commands": normalized_commands,
    }


def _validate_image(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"reference", "expected_image_id"}:
        raise PairEvidenceError("runtime image fields differ from contract")
    reference = value.get("reference")
    image_id = value.get("expected_image_id")
    if not isinstance(reference, str) or _DIGEST_REF_RE.fullmatch(reference) is None:
        raise PairEvidenceError("runtime image must use a repository digest")
    if not isinstance(image_id, str) or _IMAGE_ID_RE.fullmatch(image_id) is None:
        raise PairEvidenceError("runtime image ID is invalid")
    return {"reference": reference, "expected_image_id": image_id}


def _validate_command(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"argv", "timeout_seconds"}:
        raise PairEvidenceError(f"{label} fields differ from contract")
    argv = value.get("argv")
    timeout = value.get("timeout_seconds")
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > MAX_ARG_COUNT
        or any(not isinstance(item, str) or not item or "\x00" in item for item in argv)
        or sum(len(item.encode("utf-8")) + 1 for item in argv) > MAX_ARG_BYTES
    ):
        raise PairEvidenceError(f"{label} argv is invalid")
    executable = argv[0]
    if executable not in _ALLOWED_CONTAINER_EXECUTABLES:
        raise PairEvidenceError(f"{label} executable is not an allowlisted non-shell path")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
        raise PairEvidenceError(f"{label} timeout is outside the locked bound")
    return {"argv": list(argv), "timeout_seconds": timeout}


def _verify_command_bindings(
    manifest: Mapping[str, Any], commands: Mapping[str, Mapping[str, Any]]
) -> None:
    hashes = manifest.get("hashes")
    if not isinstance(hashes, Mapping):
        raise PairEvidenceError("manifest command hashes are missing")
    expected = {
        "exploit_command_sha256": command_sha256(commands["exploit"]),
        "regression_command_sha256": command_sha256(commands["regression"]),
        "negative_control_command_sha256": command_sha256(commands["negative_control"]),
        "diff_command_sha256": command_sha256(commands["diff"]),
        "invariants_command_sha256": command_sha256(commands["invariants"]),
    }
    if any(hashes.get(key) != value for key, value in expected.items()):
        raise PairEvidenceError("manifest command hash differs from verification plan")


def _verify_oracle_inventory(
    root: Path, manifest: Mapping[str, Any], oracle_receipt: Mapping[str, Any]
) -> None:
    rows = manifest.get("test_oracle_files")
    if not isinstance(rows, list):
        raise PairEvidenceError("oracle inventory is missing")
    physical = {
        f"oracle/{row['path']}": row
        for row in oracle_receipt.get("files", [])
        if isinstance(row, Mapping)
    }
    claimed: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise PairEvidenceError("oracle inventory row is invalid")
        path = row.get("path")
        if not isinstance(path, str) or not path.startswith("oracle/"):
            raise PairEvidenceError("oracle inventory path is outside oracle root")
        target = _safe_relative_file(root, path, label="oracle inventory file")
        if path in claimed:
            raise PairEvidenceError("oracle inventory path is duplicated")
        raw = target.read_bytes()
        if row.get("content_sha256") != sha256_bytes(raw):
            raise PairEvidenceError("oracle inventory content hash mismatch")
        claimed[path] = row
    if set(claimed) != set(physical):
        raise PairEvidenceError("oracle inventory does not cover the physical oracle tree")


def _inspect_image(runner: CommandRunner, image: Mapping[str, str]) -> dict[str, Any]:
    result = runner.run(
        ["docker", "image", "inspect", image["reference"]],
        timeout_seconds=30,
    )
    _require_process_success(result, "verifier image inspect")
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PairEvidenceError("runtime image inspect did not return JSON") from exc
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], Mapping):
        raise PairEvidenceError("runtime image inspect returned an unexpected shape")
    row = value[0]
    repo_digests = row.get("RepoDigests")
    if row.get("Id") != image["expected_image_id"]:
        raise PairEvidenceError("runtime image ID differs from plan")
    if not isinstance(repo_digests, list) or image["reference"] not in repo_digests:
        raise PairEvidenceError("runtime image repository digest is absent")
    return {
        "reference": image["reference"],
        "image_id": image["expected_image_id"],
        "inspect_sha256": sha256_bytes(result.stdout),
    }


def _run_container(
    runner: CommandRunner,
    plan: Mapping[str, Any],
    roots: Mapping[str, Path],
    *,
    workspace: str,
    command_id: str,
) -> ProcessResult:
    command = plan["commands"][command_id]
    image = plan["runtime_image"]["reference"]
    isolation = plan["isolation"]
    mounts = [
        (roots["vulnerable"], "/vulnerable"),
        (roots["fixed"], "/fixed"),
        (roots["oracle"], "/oracle"),
        (roots[workspace], "/workspace"),
    ]
    argv = [
        "docker",
        "run",
        "--rm",
        "--pull",
        "never",
        "--network",
        isolation["network"],
        "--read-only",
        "--cap-drop",
        isolation["cap_drop"],
        "--security-opt",
        "no-new-privileges=true",
        "--pids-limit",
        str(isolation["pids_limit"]),
        "--memory",
        str(isolation["memory_bytes"]),
        "--cpus",
        f"{isolation['nano_cpus'] / 1_000_000_000:.3f}",
        "--user",
        isolation["user"],
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,size={isolation['tmpfs_bytes']}",
    ]
    for source, destination in mounts:
        source_text = str(source)
        if "," in source_text:
            raise PairEvidenceError("Docker mount source contains a comma")
        argv.extend(
            ["--mount", f"type=bind,src={source_text},dst={destination},readonly"]
        )
    argv.extend(
        [
            "--workdir",
            "/oracle",
            "--entrypoint",
            command["argv"][0],
            image,
            *command["argv"][1:],
        ]
    )
    result = runner.run(argv, timeout_seconds=command["timeout_seconds"])
    _require_process_success(result, command_id)
    return result


def _parse_execution_result(
    result: ProcessResult,
    case_id: str,
    outcome_name: str,
    expected: bool,
) -> dict[str, Any]:
    value = _parse_canonical_stdout(result.stdout, case_id)
    if set(value) != {"schema", "case_id", "harness_passed", "outcome", "evidence_sha256"}:
        raise PairEvidenceError(f"{case_id} oracle result fields differ from contract")
    if value.get("schema") != ORACLE_RESULT_SCHEMA or value.get("case_id") != case_id:
        raise PairEvidenceError(f"{case_id} oracle result identity mismatch")
    if value.get("harness_passed") is not True:
        raise PairEvidenceError(f"{case_id} harness did not pass")
    outcome = value.get("outcome")
    if (
        not isinstance(outcome, Mapping)
        or set(outcome) != {"name", "value"}
        or outcome.get("name") != outcome_name
        or outcome.get("value") is not expected
    ):
        raise PairEvidenceError(f"{case_id} oracle outcome mismatch")
    _verify_embedded_hash(value, b"k_guard_pair_oracle_result.v1\0", case_id)
    return value


def _parse_structured_result(
    result: ProcessResult,
    *,
    schema: str,
    case_id: str,
    payload_key: str,
) -> dict[str, Any]:
    value = _parse_canonical_stdout(result.stdout, case_id)
    if set(value) != {"schema", "case_id", "passed", payload_key, "evidence_sha256"}:
        raise PairEvidenceError(f"{case_id} result fields differ from contract")
    if value.get("schema") != schema or value.get("case_id") != case_id:
        raise PairEvidenceError(f"{case_id} result identity mismatch")
    if value.get("passed") is not True:
        raise PairEvidenceError(f"{case_id} result did not pass")
    _verify_embedded_hash(value, (schema + "\0").encode("ascii"), case_id)
    return value


def _parse_canonical_stdout(raw: bytes, case_id: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PairEvidenceError(f"{case_id} result is not ASCII JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise PairEvidenceError(f"{case_id} result is not canonical JSON")
    return value


def _verify_embedded_hash(value: Mapping[str, Any], domain: bytes, case_id: str) -> None:
    unsigned = dict(value)
    supplied = unsigned.pop("evidence_sha256", None)
    if supplied != _domain_hash(domain, unsigned):
        raise PairEvidenceError(f"{case_id} embedded evidence hash mismatch")


def _physical_diff(vulnerable_root: Path, fixed_root: Path) -> list[dict[str, Any]]:
    vulnerable = _tree_file_map(vulnerable_root)
    fixed = _tree_file_map(fixed_root)
    if set(vulnerable) != set(fixed):
        raise PairEvidenceError("bounded causal patch cannot add or remove source files")
    changes: list[dict[str, Any]] = []
    for path in sorted(vulnerable):
        before = vulnerable[path]
        after = fixed[path]
        if before == after:
            continue
        changes.append(
            {
                "path": path,
                "before_sha256": sha256_bytes(before),
                "after_sha256": sha256_bytes(after),
                "logical_changed_lines": _logical_changed_lines(before, after),
            }
        )
    if not changes:
        raise PairEvidenceError("vulnerable and fixed trees have no physical diff")
    return changes


def _verify_physical_diff(value: object, physical: Sequence[Mapping[str, Any]]) -> None:
    if not isinstance(value, Mapping) or set(value) != {"production_changes"}:
        raise PairEvidenceError("manifest diff fields differ from contract")
    changes = value.get("production_changes")
    if not isinstance(changes, list):
        raise PairEvidenceError("manifest production changes are missing")
    claimed: dict[str, Mapping[str, Any]] = {}
    for row in changes:
        if not isinstance(row, Mapping) or not isinstance(row.get("path"), str):
            raise PairEvidenceError("manifest production change is invalid")
        if row["path"] in claimed:
            raise PairEvidenceError("manifest production change path is duplicated")
        claimed[row["path"]] = row
    physical_by_path = {row["path"]: row for row in physical}
    if set(claimed) != set(physical_by_path):
        raise PairEvidenceError("manifest diff does not cover the physical source diff")
    for path, observed in physical_by_path.items():
        row = claimed[path]
        for field in ("before_sha256", "after_sha256", "logical_changed_lines"):
            if row.get(field) != observed[field]:
                raise PairEvidenceError(f"manifest diff {field} mismatch for {path}")


def _tree_file_map(root: Path) -> dict[str, bytes]:
    receipt = regular_tree_receipt(root)
    result: dict[str, bytes] = {}
    for row in receipt["files"]:
        path = _safe_relative_file(root, row["path"], label="source file")
        result[row["path"]] = path.read_bytes()
    return result


def _logical_changed_lines(before: bytes, after: bytes) -> int:
    try:
        before_lines = before.decode("utf-8").splitlines()
        after_lines = after.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise PairEvidenceError("bounded causal patch contains a non-UTF-8 file") from exc
    if "\x00" in "\n".join(before_lines) or "\x00" in "\n".join(after_lines):
        raise PairEvidenceError("bounded causal patch contains a binary file")
    changed = 0
    matcher = difflib.SequenceMatcher(a=before_lines, b=after_lines, autojunk=False)
    for operation, before_start, before_end, after_start, after_end in matcher.get_opcodes():
        if operation != "equal":
            changed += (before_end - before_start) + (after_end - after_start)
    if changed <= 0:
        raise PairEvidenceError("bounded causal patch line diff is empty")
    return changed


def _process_receipt(result: ProcessResult) -> dict[str, Any]:
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


def _require_process_success(result: ProcessResult, label: str) -> None:
    if result.timed_out:
        raise PairEvidenceError(f"{label} timed out")
    if (
        result.output_truncated
        or len(result.stdout) > MAX_OUTPUT_BYTES
        or len(result.stderr) > MAX_OUTPUT_BYTES
    ):
        raise PairEvidenceError(f"{label} exceeded output bound")
    if result.returncode != 0:
        raise PairEvidenceError(f"{label} failed")


def _validate_host_command(argv: Sequence[str], timeout_seconds: int) -> None:
    if (
        not argv
        or argv[0] != "docker"
        or len(argv) > 512
        or any(not isinstance(item, str) or "\x00" in item for item in argv)
        or sum(len(item.encode("utf-8")) + 1 for item in argv) > 128 * 1024
    ):
        raise PairEvidenceError("host command is not a bounded Docker argv")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise PairEvidenceError("host command timeout is outside the locked bound")


def _docker_environment() -> dict[str, str]:
    keep = {key: os.environ[key] for key in ("PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE") if key in os.environ}
    keep.update({"DOCKER_CLI_HINTS": "false", "DOCKER_SCAN_SUGGEST": "false", "LC_ALL": "C"})
    return keep


def _safe_root(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise PairEvidenceError(f"{label} must be absolute")
    if _has_link_or_reparse_ancestor(path.absolute()):
        raise PairEvidenceError(f"{label} contains a link or reparse point")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PairEvidenceError(f"{label} does not exist") from exc
    if not resolved.is_dir() or _has_link_or_reparse_ancestor(resolved):
        raise PairEvidenceError(f"{label} must be a real directory")
    return resolved


def _safe_relative_directory(root: Path, value: object, *, label: str) -> Path:
    return _safe_relative(root, value, label=label, expect_file=False)


def _safe_relative_file(root: Path, value: object, *, label: str) -> Path:
    return _safe_relative(root, value, label=label, expect_file=True)


def _safe_relative(root: Path, value: object, *, label: str, expect_file: bool) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise PairEvidenceError(f"{label} is not a normalized relative path")
    relative = Path(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise PairEvidenceError(f"{label} is not a normalized relative path")
    unresolved = root / relative
    if _has_link_or_reparse_ancestor(unresolved):
        raise PairEvidenceError(f"{label} contains a link or reparse point")
    try:
        resolved = unresolved.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise PairEvidenceError(f"{label} escapes its root or does not exist") from exc
    if expect_file and not resolved.is_file():
        raise PairEvidenceError(f"{label} must be a regular file")
    if not expect_file and not resolved.is_dir():
        raise PairEvidenceError(f"{label} must be a directory")
    return resolved


def _reject_link_or_reparse(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PairEvidenceError(f"{label} cannot be inspected") from exc
    attributes = int(getattr(info, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    if stat.S_ISLNK(info.st_mode) or attributes & reparse:
        raise PairEvidenceError(f"{label} is a link or reparse point")


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


def _domain_hash(domain: bytes, value: object) -> str:
    return sha256_bytes(domain + canonical_json_bytes(value))
