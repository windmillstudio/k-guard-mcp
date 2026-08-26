from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from capture_supervisor_target import TARGET_SCHEMA, capture_target
from evidence_tree import TREE_HASH_SCHEMA, package_tree_sha256


SCHEMA = "k_guard_current_baseline_receipt.v1"
RECEIPT_HASH_SCHEMA = "k_guard_current_baseline_receipt_sha256.v1"
BASELINE_STATUS = "BASELINE_SEALED"
PACKAGE_PATH = Path("src/k_guard_mcp")
REPOSITORY_FILES = (
    Path("pyproject.toml"),
    Path("requirements-build.lock"),
    Path("requirements-evidence.lock"),
)
TOOL_KEYS = ("python", "git", "pytest", "docker")
DEPENDENCY_NAMES = (
    "mcp",
    "pydantic",
    "PyYAML",
    "PyJWT",
    "sqlglot",
    "tree-sitter",
    "tree-sitter-java",
)
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")


class BaselineSealError(ValueError):
    pass


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _require_exact_keys(value: object, expected: set[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise BaselineSealError(f"{label}_keys_invalid")
    return value


def _require_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise BaselineSealError(f"{label}_sha256_invalid")
    return value


def _require_version_map(value: object, *, expected: Sequence[str], label: str) -> dict[str, str]:
    payload = _require_exact_keys(value, set(expected), label=label)
    normalized: dict[str, str] = {}
    for key in expected:
        item = payload[key]
        if (
            not isinstance(item, str)
            or not item.strip()
            or len(item) > 240
            or "\x00" in item
            or "\n" in item
            or "\r" in item
        ):
            raise BaselineSealError(f"{label}_{key}_invalid")
        normalized[key] = item
    return normalized


def _validate_target(value: object) -> dict[str, str]:
    target = _require_exact_keys(
        value,
        {"head_git_oid", "dirty_path_set_sha256", "dirty_worktree_sha256"},
        label="target",
    )
    head = target["head_git_oid"]
    if not isinstance(head, str) or COMMIT_RE.fullmatch(head) is None:
        raise BaselineSealError("target_head_invalid")
    return {
        "head_git_oid": head,
        "dirty_path_set_sha256": _require_sha256(
            target["dirty_path_set_sha256"], label="target_dirty_path_set"
        ),
        "dirty_worktree_sha256": _require_sha256(
            target["dirty_worktree_sha256"], label="target_dirty_worktree"
        ),
    }


def _command_version(name: str, command: Sequence[str]) -> str:
    try:
        completed = subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BaselineSealError(f"tool_unavailable:{name}") from exc
    raw = completed.stdout + (b"\n" if completed.stdout and completed.stderr else b"") + completed.stderr
    line = next((item.strip() for item in raw.decode("utf-8", "replace").splitlines() if item.strip()), "")
    if completed.returncode != 0 or not line or len(line) > 240 or "\x00" in line:
        raise BaselineSealError(f"tool_unavailable:{name}")
    return line


def collect_toolchain() -> dict[str, str]:
    return {
        "python": ".".join(str(part) for part in sys.version_info[:3]),
        "git": _command_version("git", ("git", "--version")),
        "pytest": _command_version("pytest", (sys.executable, "-m", "pytest", "--version")),
        "docker": _command_version("docker", ("docker", "--version")),
    }


def collect_dependency_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for name in DEPENDENCY_NAMES:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise BaselineSealError(f"dependency_unavailable:{name}") from exc
    return versions


def _file_sha256(root: Path, relative: Path) -> str:
    path = (root / relative).resolve(strict=True)
    try:
        path.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise BaselineSealError("repository_file_path_invalid") from exc
    if not path.is_file():
        raise BaselineSealError(f"repository_file_missing:{relative.as_posix()}")
    return sha256_bytes(path.read_bytes())


def _receipt_without_hash(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in receipt.items() if key != "receipt_sha256"}


def build_baseline_receipt(
    repo_root: Path,
    *,
    toolchain: Mapping[str, str] | None = None,
    dependency_versions: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = repo_root.resolve(strict=True)
    selected_toolchain = dict(collect_toolchain() if toolchain is None else toolchain)
    selected_dependencies = dict(
        collect_dependency_versions() if dependency_versions is None else dependency_versions
    )
    receipt: dict[str, Any] = {
        "schema": SCHEMA,
        "receipt_hash_schema": RECEIPT_HASH_SCHEMA,
        "target": capture_target(root),
        "analyzer": {
            "package_path": PACKAGE_PATH.as_posix(),
            "tree_hash_schema": TREE_HASH_SCHEMA,
            "package_tree_sha256": package_tree_sha256(root / PACKAGE_PATH),
        },
        "repository": {
            "pyproject_sha256": _file_sha256(root, Path("pyproject.toml")),
            "requirements_build_lock_sha256": _file_sha256(root, Path("requirements-build.lock")),
            "requirements_evidence_lock_sha256": _file_sha256(root, Path("requirements-evidence.lock")),
        },
        "toolchain": selected_toolchain,
        "dependencies": selected_dependencies,
        "claim_boundary": {
            "baseline_is_performance_measurement": False,
            "product_accuracy_proven": False,
            "release_gate_passed": False,
            "raw_returned": False,
        },
        "baseline_status": BASELINE_STATUS,
        "release_gate_passed": False,
        "raw_returned": False,
    }
    receipt["receipt_sha256"] = _canonical_sha256(_receipt_without_hash(receipt))
    validate_baseline_receipt(receipt)
    return receipt


def validate_baseline_receipt(value: object) -> dict[str, Any]:
    receipt = _require_exact_keys(
        value,
        {
            "schema",
            "receipt_hash_schema",
            "target",
            "analyzer",
            "repository",
            "toolchain",
            "dependencies",
            "claim_boundary",
            "baseline_status",
            "release_gate_passed",
            "raw_returned",
            "receipt_sha256",
        },
        label="receipt",
    )
    if receipt["schema"] != SCHEMA or receipt["receipt_hash_schema"] != RECEIPT_HASH_SCHEMA:
        raise BaselineSealError("receipt_schema_invalid")
    _validate_target(receipt["target"])
    analyzer = _require_exact_keys(
        receipt["analyzer"],
        {"package_path", "tree_hash_schema", "package_tree_sha256"},
        label="analyzer",
    )
    if analyzer["package_path"] != PACKAGE_PATH.as_posix() or analyzer["tree_hash_schema"] != TREE_HASH_SCHEMA:
        raise BaselineSealError("analyzer_contract_invalid")
    _require_sha256(analyzer["package_tree_sha256"], label="analyzer_package_tree")
    repository = _require_exact_keys(
        receipt["repository"],
        {
            "pyproject_sha256",
            "requirements_build_lock_sha256",
            "requirements_evidence_lock_sha256",
        },
        label="repository",
    )
    for key, item in repository.items():
        _require_sha256(item, label=f"repository_{key}")
    _require_version_map(receipt["toolchain"], expected=TOOL_KEYS, label="toolchain")
    _require_version_map(receipt["dependencies"], expected=DEPENDENCY_NAMES, label="dependencies")
    boundary = _require_exact_keys(
        receipt["claim_boundary"],
        {
            "baseline_is_performance_measurement",
            "product_accuracy_proven",
            "release_gate_passed",
            "raw_returned",
        },
        label="claim_boundary",
    )
    if any(boundary.get(key) is not False for key in boundary):
        raise BaselineSealError("claim_boundary_invalid")
    if receipt["baseline_status"] != BASELINE_STATUS:
        raise BaselineSealError("baseline_status_invalid")
    if receipt["release_gate_passed"] is not False or receipt["raw_returned"] is not False:
        raise BaselineSealError("baseline_claim_invalid")
    expected_hash = _canonical_sha256(_receipt_without_hash(receipt))
    if receipt["receipt_sha256"] != expected_hash:
        raise BaselineSealError("receipt_hash_invalid")
    return receipt


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve(strict=True))
    except ValueError:
        return False
    return True


def write_baseline_receipt(repo_root: Path, output: Path, receipt: Mapping[str, Any]) -> None:
    root = repo_root.resolve(strict=True)
    destination = output.resolve()
    if _is_inside(destination, root):
        raise BaselineSealError("receipt_output_must_be_outside_repository")
    if destination.exists():
        raise BaselineSealError("receipt_output_already_exists")
    validate_baseline_receipt(dict(receipt))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(canonical_json_bytes(receipt))
    raw = destination.read_bytes()
    parsed = json.loads(raw.decode("utf-8"))
    if canonical_json_bytes(parsed) != raw:
        raise BaselineSealError("receipt_output_not_canonical")
    validate_baseline_receipt(parsed)


def seal_current_baseline(
    repo_root: Path,
    output: Path,
    *,
    toolchain: Mapping[str, str] | None = None,
    dependency_versions: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = repo_root.resolve(strict=True)
    receipt = build_baseline_receipt(
        root,
        toolchain=toolchain,
        dependency_versions=dependency_versions,
    )
    if capture_target(root) != receipt["target"]:
        raise BaselineSealError("target_changed_during_baseline_seal")
    write_baseline_receipt(root, output, receipt)
    if capture_target(root) != receipt["target"]:
        raise BaselineSealError("target_changed_during_baseline_seal")
    return receipt


def validate_current_baseline(
    repo_root: Path,
    receipt: Mapping[str, Any],
    *,
    toolchain: Mapping[str, str] | None = None,
    dependency_versions: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    historical = validate_baseline_receipt(dict(receipt))
    current = build_baseline_receipt(
        repo_root,
        toolchain=toolchain,
        dependency_versions=dependency_versions,
    )
    if canonical_json_bytes(historical) != canonical_json_bytes(current):
        raise BaselineSealError("baseline_not_current")
    return historical


def _load_canonical_receipt(path: Path) -> dict[str, Any]:
    try:
        raw = path.resolve(strict=True).read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineSealError("receipt_unreadable") from exc
    if canonical_json_bytes(payload) != raw:
        raise BaselineSealError("receipt_not_canonical")
    return validate_baseline_receipt(payload)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Seal or validate a deterministic, raw-free K-Guard baseline receipt."
    )
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output", type=Path, help="New external receipt path for sealing.")
    action.add_argument("--validate", type=Path, help="Existing receipt path to validate.")
    action.add_argument(
        "--validate-current",
        type=Path,
        help="Existing receipt path that must also match the current repository and environment.",
    )
    args = parser.parse_args(argv)
    if args.validate is not None:
        receipt = _load_canonical_receipt(args.validate)
        print(
            json.dumps(
                {
                    "baseline_status": receipt["baseline_status"],
                    "receipt_sha256": receipt["receipt_sha256"],
                    "raw_returned": False,
                    "valid": True,
                },
                sort_keys=True,
            )
        )
        return 0
    if args.validate_current is not None:
        receipt = _load_canonical_receipt(args.validate_current)
        validate_current_baseline(args.repo_root, receipt)
        print(
            json.dumps(
                {
                    "baseline_status": receipt["baseline_status"],
                    "receipt_sha256": receipt["receipt_sha256"],
                    "raw_returned": False,
                    "valid": True,
                    "current": True,
                },
                sort_keys=True,
            )
        )
        return 0
    receipt = seal_current_baseline(args.repo_root, args.output)
    print(
        json.dumps(
            {
                "baseline_status": receipt["baseline_status"],
                "receipt_sha256": receipt["receipt_sha256"],
                "raw_returned": False,
                "target": receipt["target"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
