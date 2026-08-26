from __future__ import annotations

import base64
import configparser
import csv
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Iterable

from k_guard_mcp.release_policy import (
    AUTOMATIC_RELEASE_RULES,
    RELEASE_BLOCKING_POLICY,
    automatic_release_rules_for_policy,
)

try:
    from scripts.evidence_tree import (
        TREE_HASH_SCHEMA,
        package_tree_sha256,
        package_tree_sha256_at_revision,
        wheel_package_contract,
    )
except ModuleNotFoundError:
    from evidence_tree import (
        TREE_HASH_SCHEMA,
        package_tree_sha256,
        package_tree_sha256_at_revision,
        wheel_package_contract,
    )


LEGACY_PROTOCOL_SCHEMA = "k_guard_holdout_protocol.v1"
SOURCE_BOUND_PROTOCOL_SCHEMA = "k_guard_holdout_protocol.v2"
PREEXECUTION_PROTOCOL_SCHEMA = "k_guard_holdout_protocol.v3"
STRUCTURAL_PROTOCOL_SCHEMA = "k_guard_holdout_protocol.v4"
BLOB_EXACT_PROTOCOL_SCHEMA = "k_guard_holdout_protocol.v5"
PROTOCOL_SCHEMA = "k_guard_holdout_protocol.v6"
RUNTIME_ENVIRONMENT_SCHEMA = "k_guard_holdout_runtime_environment.v2"
RUNTIME_RECEIPT_SCHEMA = "k_guard_holdout_scan_runtime_receipt.v4"
RUNTIME_NOTIFICATION_CLASSIFIER = "prewarmed_zero_notification_boundary_v2"
NATIVE_RUNTIME_LOCK_GUARD = "createfile_deny_write_delete_share_v1"
NATIVE_RUNTIME_PREWARM_GUARD = "sec_image_readonly_mapping_policy_bound_v1"
RUNTIME_OBJECT_ATTESTATION_GUARD = (
    "prewarm_boundary_file_basic_owner_group_dacl_file_id_usn_v2"
)
SOURCE_METADATA_SCHEMA = "k_guard_holdout_source_metadata.v1"
STRUCTURAL_SOURCE_METADATA_SCHEMA = "k_guard_holdout_source_metadata.v2"
SOURCE_METADATA_SCHEMAS = frozenset(
    {SOURCE_METADATA_SCHEMA, STRUCTURAL_SOURCE_METADATA_SCHEMA}
)
SOURCE_METADATA_GIT_TREE_ENTRY_POLICY = "regular_files_and_directories_only_v1"
SOURCE_METADATA_GIT_TREE_MODES = frozenset({"040000", "100644", "100755"})
WHEELHOUSE_SCHEMA = "k_guard_holdout_wheelhouse.v1"
SCANNER_SCAFFOLD_SCHEMA = "k_guard_scanner_venv_scaffold.v1"
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_ID_RE = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.-]+$")
UTC_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
LEGACY_REQUIRED_PROTOCOL_FILES = (
    "pyproject.toml",
    "scripts/assemble_public_field_labels.py",
    "scripts/build_holdout_source_metadata.py",
    "scripts/evidence_tree.py",
    "scripts/holdout_integrity.py",
    "scripts/holdout_protocol.py",
    "scripts/holdout_runtime_probe.py",
    "scripts/holdout_scan_launcher.py",
    "scripts/prepare_holdout_runtime.py",
    "scripts/public_field_effectiveness.py",
    "scripts/run_public_app_campaign.py",
    "scripts/run_public_field_campaign.py",
    "src/k_guard_mcp/release_policy.py",
)
SOURCE_BOUND_REQUIRED_PROTOCOL_FILES = tuple(
    sorted((*LEGACY_REQUIRED_PROTOCOL_FILES, "scripts/holdout_source_materialization.py"))
)
PREEXECUTION_REQUIRED_PROTOCOL_FILES = tuple(
    sorted((*SOURCE_BOUND_REQUIRED_PROTOCOL_FILES, "scripts/verify_holdout_git_sources.py"))
)
STRUCTURAL_REQUIRED_PROTOCOL_FILES = tuple(
    sorted(
        (
            *PREEXECUTION_REQUIRED_PROTOCOL_FILES,
            "scripts/build_structural_replacement_selection.py",
        )
    )
)
REQUIRED_PROTOCOL_FILES = STRUCTURAL_REQUIRED_PROTOCOL_FILES
ALL_PROTOCOL_FILES = frozenset(
    (
        *LEGACY_REQUIRED_PROTOCOL_FILES,
        *SOURCE_BOUND_REQUIRED_PROTOCOL_FILES,
        *PREEXECUTION_REQUIRED_PROTOCOL_FILES,
        *STRUCTURAL_REQUIRED_PROTOCOL_FILES,
        *REQUIRED_PROTOCOL_FILES,
    )
)


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_scanner_scaffold_manifest(root: Path) -> dict[str, Any]:
    resolved_root = root.resolve(strict=True)
    rows: list[dict[str, Any]] = []
    seen_casefold: dict[str, str] = {}
    pending = [resolved_root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda value: value.name.casefold()):
                path = Path(entry.path)
                relative = path.relative_to(resolved_root).as_posix()
                metadata = path.stat(follow_symlinks=False)
                if entry.is_symlink() or getattr(metadata, "st_file_attributes", 0) & 0x400:
                    raise ValueError(f"scanner scaffold contains a reparse point: {relative}")
                folded = relative.casefold()
                previous = seen_casefold.setdefault(folded, relative)
                if previous != relative:
                    raise ValueError("scanner scaffold contains a case-insensitive path collision")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise ValueError(f"scanner scaffold contains a non-regular entry: {relative}")
                if metadata.st_nlink != 1:
                    raise ValueError(f"scanner scaffold contains a hardlinked file: {relative}")
                rows.append(
                    {
                        "path": relative,
                        "sha256": sha256_file(path),
                        "byte_count": metadata.st_size,
                    }
                )
    rows.sort(key=lambda row: row["path"])
    return {
        "schema": SCANNER_SCAFFOLD_SCHEMA,
        "tree_sha256": hashlib.sha256(
            (SCANNER_SCAFFOLD_SCHEMA + "\0").encode("ascii")
            + json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "file_count": len(rows),
        "files": rows,
        "raw_returned": False,
    }


def _safe_artifact(root: Path, relative_value: Any) -> Path:
    relative = Path(str(relative_value or ""))
    resolved_root = root.resolve()
    unresolved = resolved_root / relative
    current = resolved_root
    symlink_component = False
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            symlink_component = True
            break
    candidate = unresolved.resolve()
    if (
        not relative.name
        or relative.is_absolute()
        or ".." in relative.parts
        or not candidate.is_relative_to(resolved_root)
        or symlink_component
    ):
        raise ValueError("holdout protocol artifact path is invalid")
    return candidate


def _load_canonical_json(path: Path, *, maximum_bytes: int = 100 * 1024 * 1024) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > maximum_bytes:
        raise ValueError(f"holdout protocol artifact is missing or oversized: {path.name}")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"holdout protocol artifact is not valid JSON: {path.name}") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError(f"holdout protocol artifact is not canonical JSON: {path.name}")
    return payload


def _run_git(repo_root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise ValueError(f"git verification failed: {' '.join(args)}")
    return result


def file_sha256_at_revision(repo_root: Path, revision: str, relative_path: str) -> str:
    if REVISION_RE.fullmatch(revision) is None or relative_path not in ALL_PROTOCOL_FILES:
        raise ValueError("protocol revision or file path is invalid")
    result = _run_git(repo_root.resolve(strict=True), "show", f"{revision}:{relative_path}")
    return hashlib.sha256(result.stdout).hexdigest()


def _active_requirement(value: str, environment: dict[str, str]):
    try:
        from packaging.requirements import Requirement
    except ImportError as exc:
        raise ValueError("packaging is required to capture the holdout dependency closure") from exc
    try:
        requirement = Requirement(value)
    except Exception as exc:
        raise ValueError(f"installed distribution contains an invalid requirement: {value}") from exc
    if requirement.marker is not None and not requirement.marker.evaluate(environment):
        return None
    return requirement


def capture_declared_dependency_closure(pyproject_path: Path) -> dict[str, Any]:
    try:
        from packaging.markers import default_environment
        from packaging.utils import canonicalize_name
    except ImportError as exc:
        raise ValueError("packaging is required to capture the holdout dependency closure") from exc

    pyproject_raw = pyproject_path.read_bytes()
    project = tomllib.loads(pyproject_raw.decode("utf-8")).get("project")
    if not isinstance(project, dict):
        raise ValueError("pyproject project metadata is missing")
    dependency_values = project.get("dependencies")
    if not isinstance(dependency_values, list) or not dependency_values:
        raise ValueError("pyproject runtime dependencies are missing")

    environment = default_environment()
    environment["extra"] = ""
    roots = []
    pending: list[str] = []
    for value in dependency_values:
        if not isinstance(value, str):
            raise ValueError("pyproject runtime dependency is invalid")
        requirement = _active_requirement(value, environment)
        if requirement is None:
            continue
        name = canonicalize_name(requirement.name)
        roots.append({"name": name, "requirement": str(requirement)})
        pending.append(name)

    distributions: dict[str, dict[str, Any]] = {}
    while pending:
        name = pending.pop()
        if name in distributions:
            continue
        try:
            distribution = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise ValueError(f"holdout runtime dependency is not installed: {name}") from exc
        active_requires: list[str] = []
        child_names: list[str] = []
        for value in distribution.requires or []:
            requirement = _active_requirement(value, environment)
            if requirement is None:
                continue
            active_requires.append(str(requirement))
            child = canonicalize_name(requirement.name)
            child_names.append(child)
            if child not in distributions:
                pending.append(child)
        distributions[name] = {
            "name": name,
            "version": distribution.version,
            "active_requires": sorted(set(active_requires)),
            "active_dependency_names": sorted(set(child_names)),
        }

    return {
        "schema": "k_guard_declared_dependency_closure.v1",
        "project": {
            "name": canonicalize_name(str(project.get("name") or "")),
            "version": str(project.get("version") or ""),
            "pyproject_sha256": hashlib.sha256(pyproject_raw).hexdigest(),
            "dependency_roots": sorted(roots, key=lambda row: (row["name"], row["requirement"])),
        },
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "cache_tag": str(sys.implementation.cache_tag or ""),
            "byteorder": sys.byteorder,
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        "distributions": [distributions[name] for name in sorted(distributions)],
        "raw_returned": False,
    }


def capture_runtime_environment(
    scanner_python: Path,
    probe_script: Path,
    scanner_scaffold: dict[str, Any],
) -> dict[str, Any]:
    python_path = scanner_python.resolve(strict=True)
    probe_path = probe_script.resolve(strict=True)
    if not python_path.is_file() or python_path.is_symlink():
        raise ValueError("holdout scanner Python must be a regular executable file")
    if not probe_path.is_file() or probe_path.is_symlink():
        raise ValueError("holdout runtime probe must be a regular file")
    environment = dict(os.environ)
    for key in ("PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONUSERBASE"):
        environment.pop(key, None)
    environment.update({"PYTHONHASHSEED": "0", "PYTHONUTF8": "1"})
    if (
        not isinstance(scanner_scaffold, dict)
        or scanner_scaffold.get("schema") != SCANNER_SCAFFOLD_SCHEMA
        or scanner_scaffold.get("raw_returned") is not False
    ):
        raise ValueError("holdout scanner scaffold manifest is invalid")
    with tempfile.TemporaryDirectory(prefix="k-guard-scaffold-") as temporary:
        scaffold_path = Path(temporary) / "scanner-scaffold.json"
        scaffold_path.write_bytes(canonical_json_bytes(scanner_scaffold))
        completed = subprocess.run(
            [
                str(python_path),
                "-I",
                "-B",
                "-S",
                str(probe_path),
                "--scaffold-manifest",
                str(scaffold_path),
            ],
            cwd=probe_path.parent,
            env=environment,
            capture_output=True,
            check=False,
            timeout=300,
        )
    try:
        payload = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("holdout scanner runtime probe did not return valid JSON") from exc
    if (
        completed.returncode != 0
        or not isinstance(payload, dict)
        or payload.get("schema") != RUNTIME_ENVIRONMENT_SCHEMA
        or payload.get("attestation_passed") is not True
        or payload.get("attestation_errors") != []
        or payload.get("raw_returned") is not False
        or canonical_json_bytes(payload) != completed.stdout
    ):
        raw_errors = payload.get("attestation_errors") if isinstance(payload, dict) else []
        error_classes = sorted(
            {
                str(error).partition(":")[0]
                for error in raw_errors
                if isinstance(error, str) and error
            }
        )
        subtype = ",".join(error_classes[:12]) or "invalid_envelope"
        raise ValueError(
            f"holdout scanner runtime attestation failed; subtype={subtype}"
        )
    executable_hash = hashlib.sha256(python_path.read_bytes()).hexdigest()
    if payload.get("python", {}).get("executable_sha256") != executable_hash:
        raise ValueError("holdout scanner Python executable hash is inconsistent")
    return payload


def write_runtime_environment(
    scanner_python: Path,
    probe_script: Path,
    output_path: Path,
    scanner_scaffold: dict[str, Any],
) -> dict[str, Any]:
    payload = capture_runtime_environment(scanner_python, probe_script, scanner_scaffold)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canonical_json_bytes(payload))
    return payload


def _repository_set_sha256(repository_ids: Iterable[str]) -> str:
    encoded = json.dumps(
        sorted(set(repository_ids)),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def load_source_metadata(path: Path) -> dict[str, Any]:
    payload = _load_canonical_json(path, maximum_bytes=20 * 1024 * 1024)
    source_schema = payload.get("schema")
    if source_schema not in SOURCE_METADATA_SCHEMAS:
        raise ValueError("holdout source metadata schema is invalid")
    if payload.get("metadata_source") != "github_api_v3":
        raise ValueError("holdout source metadata provider is invalid")
    if UTC_TIMESTAMP_RE.fullmatch(str(payload.get("retrieved_at") or "")) is None:
        raise ValueError("holdout source metadata retrieval time is invalid")
    boundary = payload.get("selection_boundary")
    if not isinstance(boundary, dict) or any(
        boundary.get(key) is not expected
        for key, expected in {
            "k_guard_imported": False,
            "scanner_output_observed": False,
            "github_metadata_cryptographically_attested": False,
        }.items()
    ):
        raise ValueError("holdout source selection boundary is invalid")
    structurally_verified = source_schema == STRUCTURAL_SOURCE_METADATA_SCHEMA
    if structurally_verified and (
        boundary.get("git_tree_entry_modes_verified") is not True
        or payload.get("git_tree_entry_policy") != SOURCE_METADATA_GIT_TREE_ENTRY_POLICY
        or payload.get("all_source_trees_structurally_eligible") is not True
    ):
        raise ValueError("holdout source Git tree eligibility contract is invalid")

    rows = payload.get("repositories")
    if not isinstance(rows, list) or not rows:
        raise ValueError("holdout source metadata is empty")
    repository_ids: list[str] = []
    node_ids: list[str] = []
    commit_trees: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("holdout source metadata row is invalid")
        repository_id = str(row.get("repository_id") or "")
        node_id = str(row.get("github_node_id") or "")
        repository_url = str(row.get("repository") or "")
        if REPOSITORY_ID_RE.fullmatch(repository_id) is None or repository_id != repository_id.casefold():
            raise ValueError("holdout source repository identity is invalid")
        if repository_url != f"https://github.com/{repository_id}.git":
            raise ValueError(f"holdout source repository URL is not canonical: {repository_id}")
        if not node_id or len(node_id) > 256:
            raise ValueError(f"holdout source GitHub node id is invalid: {repository_id}")
        if row.get("is_fork") is not False or row.get("fork_parent_repository_id") is not None:
            raise ValueError(f"holdout source must be a root non-fork: {repository_id}")
        if row.get("archived") is not False or not str(row.get("default_branch") or ""):
            raise ValueError(f"holdout source must be active: {repository_id}")
        if REVISION_RE.fullmatch(str(row.get("commit") or "")) is None:
            raise ValueError(f"holdout source commit is invalid: {repository_id}")
        commit_tree = str(row.get("commit_tree") or "")
        if REVISION_RE.fullmatch(commit_tree) is None:
            raise ValueError(f"holdout source tree is invalid: {repository_id}")
        stars = row.get("stars_at_registration")
        if not isinstance(stars, int) or isinstance(stars, bool) or stars < 0:
            raise ValueError(f"holdout source star count is invalid: {repository_id}")
        for optional in ("language", "license_spdx"):
            if row.get(optional) is not None and not isinstance(row.get(optional), str):
                raise ValueError(f"holdout source metadata field is invalid: {repository_id}:{optional}")
        if structurally_verified:
            entry_count = row.get("git_tree_entry_count")
            mode_counts = row.get("git_tree_mode_counts")
            if (
                not isinstance(entry_count, int)
                or isinstance(entry_count, bool)
                or entry_count < 0
                or not isinstance(mode_counts, dict)
                or any(
                    mode not in SOURCE_METADATA_GIT_TREE_MODES
                    or not isinstance(count, int)
                    or isinstance(count, bool)
                    or count <= 0
                    for mode, count in mode_counts.items()
                )
                or sum(mode_counts.values()) != entry_count
                or row.get("git_tree_recursive_truncated") is not False
                or SHA256_RE.fullmatch(str(row.get("git_tree_structure_sha256") or "")) is None
            ):
                raise ValueError(
                    f"holdout source Git tree eligibility is invalid: {repository_id}"
                )
        repository_ids.append(repository_id)
        node_ids.append(node_id)
        commit_trees.append(commit_tree)

    if repository_ids != sorted(repository_ids) or len(repository_ids) != len(set(repository_ids)):
        raise ValueError("holdout source repositories must be unique and sorted")
    if len(node_ids) != len(set(node_ids)):
        raise ValueError("holdout source GitHub node ids must be unique")
    if len(commit_trees) != len(set(commit_trees)):
        raise ValueError("holdout source commit trees must be unique")
    if payload.get("repository_count") != len(repository_ids):
        raise ValueError("holdout source repository count is invalid")
    if payload.get("repository_set_sha256") != _repository_set_sha256(repository_ids):
        raise ValueError("holdout source repository set hash is invalid")
    if payload.get("raw_returned") is not False:
        raise ValueError("holdout source metadata raw boundary is invalid")
    return payload


def _validate_source_app_binding(source_metadata: dict[str, Any], apps: list[Any]) -> None:
    source_rows = {
        str(row["repository_id"]): row
        for row in source_metadata["repositories"]
        if isinstance(row, dict)
    }
    app_rows = {
        str(row.get("repository_id") or ""): row
        for row in apps
        if isinstance(row, dict)
    }
    if set(source_rows) != set(app_rows) or len(app_rows) != len(apps):
        raise ValueError("holdout source metadata app set does not match the preregistration")
    fields = (
        "repository",
        "repository_id",
        "github_node_id",
        "default_branch",
        "is_fork",
        "fork_parent_repository_id",
        "archived",
        "commit",
        "commit_tree",
        "stars_at_registration",
        "language",
        "license_spdx",
    )
    for repository_id, source_row in source_rows.items():
        app_row = app_rows[repository_id]
        for field in fields:
            if app_row.get(field) != source_row.get(field):
                raise ValueError(f"holdout source metadata binding mismatch: {repository_id}:{field}")


def _validate_protocol_files(rows: Any, schema: str) -> dict[str, str]:
    if not isinstance(rows, list):
        raise ValueError("holdout protocol file manifest is missing")
    values: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("holdout protocol file row is invalid")
        path = str(row.get("path") or "")
        digest = str(row.get("sha256") or "")
        if path in values or SHA256_RE.fullmatch(digest) is None:
            raise ValueError("holdout protocol file binding is invalid")
        values[path] = digest
    expected_by_schema = {
        LEGACY_PROTOCOL_SCHEMA: LEGACY_REQUIRED_PROTOCOL_FILES,
        SOURCE_BOUND_PROTOCOL_SCHEMA: SOURCE_BOUND_REQUIRED_PROTOCOL_FILES,
        PREEXECUTION_PROTOCOL_SCHEMA: PREEXECUTION_REQUIRED_PROTOCOL_FILES,
        STRUCTURAL_PROTOCOL_SCHEMA: STRUCTURAL_REQUIRED_PROTOCOL_FILES,
        BLOB_EXACT_PROTOCOL_SCHEMA: REQUIRED_PROTOCOL_FILES,
        PROTOCOL_SCHEMA: REQUIRED_PROTOCOL_FILES,
    }
    expected_files = expected_by_schema.get(schema)
    if expected_files is None:
        raise ValueError("holdout protocol schema is unsupported")
    if tuple(sorted(values)) != expected_files:
        raise ValueError("holdout protocol required file set is incomplete")
    return values


def wheel_qualification_contract(wheel: Path) -> dict[str, Any]:
    package_contract = wheel_package_contract(wheel)
    with zipfile.ZipFile(wheel) as archive:
        file_names = sorted(info.filename for info in archive.infolist() if not info.is_dir())
        if len(file_names) != len(set(file_names)) or len(file_names) != len(
            {name.casefold() for name in file_names}
        ):
            raise ValueError("wheel contains duplicate or case-colliding archive paths")
        metadata_names = [name for name in file_names if name.casefold().endswith(".dist-info/metadata")]
        if len(metadata_names) != 1:
            raise ValueError("wheel must contain exactly one METADATA file")
        dist_info = metadata_names[0].rsplit("/", 1)[0]
        metadata_name = f"{dist_info}/METADATA"
        wheel_name = f"{dist_info}/WHEEL"
        record_name = f"{dist_info}/RECORD"
        if wheel_name not in file_names or record_name not in file_names:
            raise ValueError("wheel WHEEL or RECORD metadata is missing")
        metadata_raw = archive.read(metadata_name)
        wheel_raw = archive.read(wheel_name)
        record_raw = archive.read(record_name)
        metadata = BytesParser().parsebytes(metadata_raw)
        wheel_metadata = BytesParser().parsebytes(wheel_raw)
        recorded: dict[str, tuple[str, str]] = {}
        try:
            rows = csv.reader(io.StringIO(record_raw.decode("utf-8"), newline=""))
            for row in rows:
                if len(row) != 3 or not row[0] or row[0] in recorded:
                    raise ValueError("wheel RECORD row is invalid")
                recorded[row[0]] = (row[1], row[2])
        except (UnicodeError, csv.Error) as exc:
            raise ValueError("wheel RECORD is invalid") from exc
        if set(recorded) != set(file_names):
            raise ValueError("wheel RECORD does not cover the exact archive file set")
        if len(recorded) != len({name.casefold() for name in recorded}):
            raise ValueError("wheel RECORD contains case-colliding paths")
        for name in file_names:
            hash_value, size_value = recorded[name]
            payload = archive.read(name)
            if name == record_name:
                if hash_value or size_value:
                    raise ValueError("wheel RECORD self-entry must not contain a hash or size")
                continue
            if not hash_value.startswith("sha256=") or not size_value.isdecimal():
                raise ValueError("wheel RECORD requires sha256 and size for every member")
            expected = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode("ascii").rstrip("=")
            if hash_value[len("sha256=") :] != expected or int(size_value) != len(payload):
                raise ValueError(f"wheel RECORD verification failed: {name}")
    return {
        "package_contract": package_contract,
        "wheel_byte_count": wheel.stat().st_size,
        "metadata_sha256": hashlib.sha256(metadata_raw).hexdigest(),
        "wheel_metadata_sha256": hashlib.sha256(wheel_raw).hexdigest(),
        "record_sha256": hashlib.sha256(record_raw).hexdigest(),
        "record_verified": True,
        "record_member_count": len(recorded),
        "requires_python": str(metadata.get("Requires-Python") or ""),
        "requires_dist": sorted(str(value) for value in metadata.get_all("Requires-Dist", [])),
        "wheel_version": str(wheel_metadata.get("Wheel-Version") or ""),
        "root_is_purelib": str(wheel_metadata.get("Root-Is-Purelib") or ""),
        "tags": sorted(str(value) for value in wheel_metadata.get_all("Tag", [])),
    }


def _generic_wheel_artifact(
    wheel: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not wheel.is_file() or wheel.suffix.casefold() != ".whl" or wheel.is_symlink():
        raise ValueError("wheelhouse artifact must be a regular .whl file")
    with zipfile.ZipFile(wheel) as archive:
        files: dict[str, bytes] = {}
        casefold_names: set[str] = set()
        total = 0
        for info in archive.infolist():
            name = info.filename
            if (
                not name
                or "\\" in name
                or name.startswith("/")
                or ".." in name.split("/")
                or name in files
                or name.casefold() in casefold_names
                or info.flag_bits & 0x1
                or ((info.external_attr >> 16) & 0o170000) == 0o120000
            ):
                raise ValueError("wheelhouse artifact contains an unsafe member")
            if info.is_dir():
                continue
            if info.file_size < 0 or info.file_size > 100 * 1024 * 1024:
                raise ValueError("wheelhouse member exceeds the verification budget")
            total += info.file_size
            if total > 500 * 1024 * 1024 or len(files) > 100_000:
                raise ValueError("wheelhouse artifact exceeds the verification budget")
            payload = archive.read(info)
            if len(payload) != info.file_size:
                raise ValueError("wheelhouse member size is inconsistent")
            files[name] = payload
            casefold_names.add(name.casefold())
        metadata_names = [name for name in files if name.casefold().endswith(".dist-info/metadata")]
        if len(metadata_names) != 1:
            raise ValueError("wheelhouse artifact must contain one METADATA file")
        dist_info = metadata_names[0].rsplit("/", 1)[0]
        metadata_name = f"{dist_info}/METADATA"
        wheel_name = f"{dist_info}/WHEEL"
        record_name = f"{dist_info}/RECORD"
        if wheel_name not in files or record_name not in files:
            raise ValueError("wheelhouse artifact WHEEL or RECORD is missing")
        metadata = BytesParser().parsebytes(files[metadata_name])
        distribution = re.sub(r"[-_.]+", "-", str(metadata.get("Name") or "")).casefold()
        version = str(metadata.get("Version") or "")
        if not distribution or not version:
            raise ValueError("wheelhouse artifact identity is invalid")
        recorded: dict[str, tuple[str, str]] = {}
        for row in csv.reader(io.StringIO(files[record_name].decode("utf-8"), newline="")):
            if len(row) != 3 or not row[0] or row[0] in recorded:
                raise ValueError("wheelhouse RECORD row is invalid")
            recorded[row[0]] = (row[1], row[2])
        if set(recorded) != set(files):
            raise ValueError("wheelhouse RECORD does not cover the exact artifact")
        entry_point_script_names: list[str] = []
        entry_points_name = f"{dist_info}/entry_points.txt"
        if entry_points_name in files:
            parser = configparser.ConfigParser(interpolation=None)
            parser.optionxform = str
            try:
                parser.read_string(files[entry_points_name].decode("utf-8"))
            except (UnicodeError, configparser.Error) as exc:
                raise ValueError("wheelhouse entry_points.txt is invalid") from exc
            for section in ("console_scripts", "gui_scripts"):
                if not parser.has_section(section):
                    continue
                for script_name in parser[section]:
                    if re.fullmatch(r"[A-Za-z0-9_.-]+", script_name) is None:
                        raise ValueError("wheelhouse entry point script name is unsafe")
                    entry_point_script_names.append(script_name)
        install_members: list[dict[str, Any]] = []
        for name, payload in sorted(files.items()):
            hash_value, size_value = recorded[name]
            if name == record_name:
                if hash_value or size_value:
                    raise ValueError("wheelhouse RECORD self-entry is invalid")
                install_members.append(
                    {
                        "archive_path": name,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "byte_count": len(payload),
                        "verify_installed_bytes": False,
                    }
                )
                continue
            digest = hashlib.sha256(payload).hexdigest()
            encoded = base64.urlsafe_b64encode(bytes.fromhex(digest)).decode("ascii").rstrip("=")
            if (
                hash_value != f"sha256={encoded}"
                or not size_value.isdecimal()
                or int(size_value) != len(payload)
            ):
                raise ValueError(f"wheelhouse RECORD verification failed: {name}")
            install_members.append(
                {
                    "archive_path": name,
                    "sha256": digest,
                    "byte_count": len(payload),
                    "verify_installed_bytes": True,
                }
            )
    contract = {
        "distribution": distribution,
        "version": version,
        "sha256": sha256_file(wheel),
        "byte_count": wheel.stat().st_size,
        "metadata_sha256": hashlib.sha256(files[metadata_name]).hexdigest(),
        "wheel_metadata_sha256": hashlib.sha256(files[wheel_name]).hexdigest(),
        "record_sha256": hashlib.sha256(files[record_name]).hexdigest(),
        "record_member_count": len(recorded),
        "dist_info_archive_path": dist_info,
        "entry_point_script_names": sorted(set(entry_point_script_names)),
        "requires_python": str(metadata.get("Requires-Python") or ""),
        "requires_dist": sorted(str(value) for value in metadata.get_all("Requires-Dist", [])),
    }
    return contract, install_members


def build_wheelhouse_manifest(wheelhouse_dir: Path, preregistration_root: Path) -> dict[str, Any]:
    root = preregistration_root.resolve(strict=True)
    wheelhouse = wheelhouse_dir.resolve(strict=True)
    if not wheelhouse.is_dir() or not wheelhouse.is_relative_to(root) or wheelhouse.is_symlink():
        raise ValueError("wheelhouse must be a regular directory under the preregistration root")
    rows: list[dict[str, Any]] = []
    for wheel in sorted(wheelhouse.glob("*.whl"), key=lambda path: path.name.casefold()):
        contract, _members = _generic_wheel_artifact(wheel)
        rows.append({"artifact_path": wheel.relative_to(root).as_posix(), **contract})
    if not rows:
        raise ValueError("wheelhouse contains no wheel artifacts")
    identities = [(row["distribution"], row["version"]) for row in rows]
    if len(identities) != len(set(identities)):
        raise ValueError("wheelhouse distribution identities must be unique")
    artifact_set_sha256 = hashlib.sha256(
        json.dumps(
            [
                {
                    "artifact_path": row["artifact_path"],
                    "distribution": row["distribution"],
                    "version": row["version"],
                    "sha256": row["sha256"],
                }
                for row in rows
            ],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "schema": WHEELHOUSE_SCHEMA,
        "artifact_count": len(rows),
        "artifact_set_sha256": artifact_set_sha256,
        "artifacts": rows,
        "raw_returned": False,
    }


def _install_scheme_relative(runtime_environment: dict[str, Any], scheme: str) -> Path:
    key = "include" if scheme == "headers" else scheme
    value = str(runtime_environment.get("install_scheme", {}).get(key) or "")
    if not value.startswith("<prefix>/"):
        raise ValueError(f"runtime installation scheme is outside the scanner prefix: {scheme}")
    return Path(value[len("<prefix>/") :])


def _installed_path_for_wheel_member(
    archive_path: str,
    runtime_environment: dict[str, Any],
) -> str:
    match = re.match(r"^[^/]+\.data/(purelib|platlib|scripts|data|headers)/(.*)$", archive_path)
    if match:
        scheme, relative = match.groups()
        return (_install_scheme_relative(runtime_environment, scheme) / Path(relative)).as_posix()
    return (_install_scheme_relative(runtime_environment, "purelib") / Path(archive_path)).as_posix()


def load_wheelhouse_manifest(
    preregistration_root: Path,
    binding: dict[str, Any],
    *,
    runtime_environment: dict[str, Any],
    install_report: dict[str, Any],
) -> dict[str, Any]:
    path = _safe_artifact(preregistration_root, binding.get("manifest_path"))
    expected_hash = str(binding.get("manifest_sha256") or "")
    if SHA256_RE.fullmatch(expected_hash) is None or sha256_file(path) != expected_hash:
        raise ValueError("wheelhouse manifest hash is invalid")
    payload = _load_canonical_json(path, maximum_bytes=50 * 1024 * 1024)
    rows = payload.get("artifacts")
    if payload.get("schema") != WHEELHOUSE_SCHEMA or not isinstance(rows, list) or not rows:
        raise ValueError("wheelhouse manifest schema is invalid")
    expected_install = {
        (
            re.sub(r"[-_.]+", "-", str(row.get("metadata", {}).get("name") or "")).casefold(),
            str(row.get("metadata", {}).get("version") or ""),
            str(row.get("download_info", {}).get("archive_info", {}).get("hashes", {}).get("sha256") or ""),
        )
        for row in install_report.get("install", [])
        if isinstance(row, dict)
    }
    runtime_rows = {
        (str(row.get("name") or ""), str(row.get("version") or "")): row
        for row in runtime_environment.get("installed_distributions", [])
        if isinstance(row, dict)
    }
    install_report_rows = {
        (
            re.sub(r"[-_.]+", "-", str(row.get("metadata", {}).get("name") or "")).casefold(),
            str(row.get("metadata", {}).get("version") or ""),
        ): row
        for row in install_report.get("install", [])
        if isinstance(row, dict) and isinstance(row.get("metadata"), dict)
    }
    actual_install: set[tuple[str, str, str]] = set()
    artifact_paths: list[Path] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("wheelhouse manifest row is invalid")
        artifact = _safe_artifact(preregistration_root, row.get("artifact_path"))
        contract, members = _generic_wheel_artifact(artifact)
        expected_row = {"artifact_path": row.get("artifact_path"), **contract}
        if row != expected_row:
            raise ValueError("wheelhouse artifact contract is invalid")
        identity = (contract["distribution"], contract["version"])
        runtime_row = runtime_rows.get(identity)
        if runtime_row is None:
            raise ValueError("wheelhouse artifact is absent from the attested runtime")
        installed_files = {
            str(value.get("path") or ""): value
            for value in runtime_row.get("installed_files", [])
            if isinstance(value, dict)
        }
        if len(installed_files) != len({path.casefold() for path in installed_files}):
            raise ValueError("attested runtime contains case-colliding installed paths")
        expected_installed_paths: set[str] = set()
        expected_installed_casefold: set[str] = set()
        for member in members:
            installed_path = _installed_path_for_wheel_member(
                str(member["archive_path"]),
                runtime_environment,
            )
            if (
                installed_path in expected_installed_paths
                or installed_path.casefold() in expected_installed_casefold
            ):
                raise ValueError("wheelhouse members map to a duplicate installed path")
            expected_installed_paths.add(installed_path)
            expected_installed_casefold.add(installed_path.casefold())
            installed = installed_files.get(installed_path)
            if (
                installed is None
                or (
                    member.get("verify_installed_bytes") is True
                    and (
                        installed.get("sha256") != member["sha256"]
                        or installed.get("byte_count") != member["byte_count"]
                    )
                )
            ):
                raise ValueError(
                    f"installed runtime file does not match its wheel artifact: {identity[0]}:{installed_path}"
                )
        report_row = install_report_rows.get(identity)
        if report_row is None:
            raise ValueError("wheelhouse artifact is absent from the pip installation rows")
        purelib = _install_scheme_relative(runtime_environment, "purelib")
        dist_info_path = purelib / Path(str(contract["dist_info_archive_path"]))
        expected_installed_paths.add((dist_info_path / "INSTALLER").as_posix())
        if report_row.get("requested") is True:
            expected_installed_paths.add((dist_info_path / "REQUESTED").as_posix())
        if report_row.get("is_direct") is True:
            expected_installed_paths.add((dist_info_path / "direct_url.json").as_posix())
        scripts_root = _install_scheme_relative(runtime_environment, "scripts")
        expected_installed_paths.update(
            (scripts_root / f"{name}.exe").as_posix()
            for name in contract["entry_point_script_names"]
        )
        if len(expected_installed_paths) != len(
            {path.casefold() for path in expected_installed_paths}
        ):
            raise ValueError("wheelhouse members map to case-colliding installed paths")
        if set(installed_files) != expected_installed_paths:
            raise ValueError(f"installed runtime file set is not exactly wheel-derived: {identity[0]}")
        actual_install.add((identity[0], identity[1], contract["sha256"]))
        artifact_paths.append(artifact)
    if actual_install != expected_install:
        raise ValueError("wheelhouse artifact set does not exactly match the pip installation report")
    if payload.get("artifact_count") != len(rows):
        raise ValueError("wheelhouse artifact count is invalid")
    recomputed = build_wheelhouse_manifest(path.parent, preregistration_root)
    if recomputed != payload or binding.get("artifact_set_sha256") != payload.get("artifact_set_sha256"):
        raise ValueError("wheelhouse artifact set hash is invalid")
    payload["_manifest_path"] = path
    payload["_artifact_paths"] = artifact_paths
    return payload


def load_install_report(
    path: Path,
    *,
    wheel_sha256: str,
    runtime_environment: dict[str, Any],
) -> dict[str, Any]:
    payload = _load_canonical_json(path, maximum_bytes=20 * 1024 * 1024)
    install_rows = payload.get("install")
    if payload.get("version") != "1" or not isinstance(install_rows, list) or not install_rows:
        raise ValueError("pip installation report contract is invalid")
    installed_runtime = {
        (str(row.get("name") or ""), str(row.get("version") or ""))
        for row in runtime_environment.get("installed_distributions", [])
        if isinstance(row, dict)
    }
    names: set[str] = set()
    root_matches = 0
    artifact_rows: list[dict[str, str]] = []
    for row in install_rows:
        if not isinstance(row, dict) or row.get("is_yanked") is True:
            raise ValueError("pip installation report row is invalid")
        metadata = row.get("metadata")
        download = row.get("download_info")
        if not isinstance(metadata, dict) or not isinstance(download, dict):
            raise ValueError("pip installation report metadata is missing")
        name = re.sub(r"[-_.]+", "-", str(metadata.get("name") or "")).casefold()
        version = str(metadata.get("version") or "")
        if not name or name in names or (name, version) not in installed_runtime:
            raise ValueError("pip installation report does not match the attested runtime")
        names.add(name)
        archive_info = download.get("archive_info")
        hashes = archive_info.get("hashes") if isinstance(archive_info, dict) else None
        digest = str(hashes.get("sha256") or "") if isinstance(hashes, dict) else ""
        if SHA256_RE.fullmatch(digest) is None:
            raise ValueError("pip installation artifact is not sha256-bound")
        dir_info = download.get("dir_info")
        if row.get("is_direct") is True and isinstance(dir_info, dict) and dir_info.get("editable") is True:
            raise ValueError("editable installation is forbidden for the holdout scanner")
        if name == "k-guard-mcp":
            root_matches += int(digest == wheel_sha256 and row.get("requested") is True)
        artifact_rows.append({"name": name, "version": version, "sha256": digest})
    if root_matches != 1:
        raise ValueError("pip installation report is not rooted in the bound K-Guard wheel")
    reported_runtime = {(row["name"], row["version"]) for row in artifact_rows}
    if installed_runtime != reported_runtime:
        raise ValueError("attested runtime contains a distribution absent from the wheel installation report")
    expected_set_hash = hashlib.sha256(
        json.dumps(sorted(artifact_rows, key=lambda row: row["name"]), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    if payload.get("k_guard_install_artifact_set_sha256") != expected_set_hash:
        raise ValueError("pip installation artifact set hash is invalid")
    return payload


def validate_bound_protocol(
    preregistration: dict[str, Any],
    preregistration_path: Path,
) -> dict[str, Any]:
    binding = preregistration.get("holdout_protocol")
    if not isinstance(binding, dict):
        raise ValueError("v4 holdout protocol binding is missing")
    preregistration_root = preregistration_path.resolve().parent
    manifest_path = _safe_artifact(preregistration_root, binding.get("manifest_path"))
    expected_manifest_hash = str(binding.get("manifest_sha256") or "")
    if SHA256_RE.fullmatch(expected_manifest_hash) is None or sha256_file(manifest_path) != expected_manifest_hash:
        raise ValueError("v4 holdout protocol manifest hash is invalid")
    manifest = _load_canonical_json(manifest_path, maximum_bytes=5 * 1024 * 1024)
    manifest_schema = str(manifest.get("schema") or "")
    if manifest_schema not in {
        LEGACY_PROTOCOL_SCHEMA,
        SOURCE_BOUND_PROTOCOL_SCHEMA,
        PREEXECUTION_PROTOCOL_SCHEMA,
        STRUCTURAL_PROTOCOL_SCHEMA,
        BLOB_EXACT_PROTOCOL_SCHEMA,
        PROTOCOL_SCHEMA,
    } or manifest.get("raw_returned") is not False:
        raise ValueError("v4 holdout protocol manifest schema is invalid")
    implementation_revision = str(manifest.get("implementation_revision") or "")
    if REVISION_RE.fullmatch(implementation_revision) is None:
        raise ValueError("v4 holdout implementation revision is invalid")
    if manifest.get("package_tree_hash_schema") != TREE_HASH_SCHEMA:
        raise ValueError("v4 holdout package tree hash schema is invalid")
    analyzer_tree = str(manifest.get("analyzer_package_tree_sha256") or "")
    if (
        SHA256_RE.fullmatch(analyzer_tree) is None
        or analyzer_tree != preregistration.get("analyzer_package_tree_sha256")
    ):
        raise ValueError("v4 holdout analyzer package binding is invalid")
    bound_policy = str(manifest.get("release_blocking_policy") or "")
    bound_automatic_rules = automatic_release_rules_for_policy(bound_policy)
    if bound_automatic_rules is None:
        raise ValueError("v4 holdout release policy binding is invalid")
    if manifest.get("automatic_release_rule_ids") != sorted(bound_automatic_rules):
        raise ValueError("v4 holdout automatic release rule binding is invalid")
    if manifest.get("execution_package_source") != "isolated_venv_installed_from_bound_wheel":
        raise ValueError("v4 holdout execution package source is invalid")
    protocol_files = _validate_protocol_files(manifest.get("protocol_files"), manifest_schema)

    wheel_binding = manifest.get("wheel")
    if not isinstance(wheel_binding, dict):
        raise ValueError("v4 holdout wheel binding is missing")
    wheel_path = _safe_artifact(preregistration_root, wheel_binding.get("artifact_path"))
    wheel_hash = str(wheel_binding.get("sha256") or "")
    if SHA256_RE.fullmatch(wheel_hash) is None or sha256_file(wheel_path) != wheel_hash:
        raise ValueError("v4 holdout wheel artifact hash is invalid")
    expected_wheel_contract = wheel_binding.get("qualification_contract")
    if (
        not isinstance(expected_wheel_contract, dict)
        or wheel_qualification_contract(wheel_path) != expected_wheel_contract
    ):
        raise ValueError("v4 holdout wheel package contract is invalid")
    if expected_wheel_contract.get("package_contract", {}).get("package_tree_sha256") != analyzer_tree:
        raise ValueError("v4 holdout wheel does not match the analyzer package tree")

    runtime_binding = manifest.get("runtime_environment")
    if not isinstance(runtime_binding, dict):
        raise ValueError("v4 holdout runtime environment binding is missing")
    runtime_path = _safe_artifact(preregistration_root, runtime_binding.get("artifact_path"))
    runtime_hash = str(runtime_binding.get("sha256") or "")
    if SHA256_RE.fullmatch(runtime_hash) is None or sha256_file(runtime_path) != runtime_hash:
        raise ValueError("v4 holdout runtime environment hash is invalid")
    runtime_environment = _load_canonical_json(runtime_path, maximum_bytes=5 * 1024 * 1024)
    if (
        runtime_environment.get("schema") != RUNTIME_ENVIRONMENT_SCHEMA
        or runtime_environment.get("attestation_passed") is not True
        or runtime_environment.get("attestation_errors") != []
        or runtime_environment.get("duplicate_distribution_names") != []
        or runtime_environment.get("shared_distribution_files") != []
        or runtime_environment.get("unowned_site_package_files") != []
        or runtime_environment.get("scaffold_distribution_overlaps") != []
        or runtime_environment.get("unowned_prefix_files") != []
        or runtime_environment.get("missing_prefix_files") != []
        or runtime_environment.get("modified_scaffold_files") != []
        or runtime_environment.get("outside_import_search_paths") != []
        or runtime_environment.get("base_site_package_import_paths") != []
        or runtime_environment.get("raw_returned") is not False
    ):
        raise ValueError("v4 holdout runtime environment schema is invalid")
    runtime_python = runtime_environment.get("python")
    runtime_k_guard = runtime_environment.get("k_guard")
    runtime_scaffold = runtime_environment.get("scanner_scaffold")
    scaffold_rows = runtime_scaffold.get("files") if isinstance(runtime_scaffold, dict) else None
    scaffold_hash = (
        hashlib.sha256(
            (SCANNER_SCAFFOLD_SCHEMA + "\0").encode("ascii")
            + json.dumps(scaffold_rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if isinstance(scaffold_rows, list)
        else None
    )
    if (
        not isinstance(runtime_python, dict)
        or runtime_python.get("prefix_is_virtual_environment") is not True
        or runtime_python.get("isolated_flag") != 1
        or runtime_python.get("ignore_environment_flag") != 1
        or runtime_python.get("no_user_site_flag") != 1
        or runtime_python.get("dont_write_bytecode_flag") != 1
        or runtime_python.get("safe_path_flag") != 1
        or runtime_python.get("no_site_flag") != 1
        or runtime_python.get("user_site_enabled") is not False
        or runtime_python.get("include_system_site_packages") is not False
        or runtime_python.get("manual_site_bootstrap") is not True
        or SHA256_RE.fullmatch(str(runtime_python.get("executable_sha256") or "")) is None
        or not isinstance(runtime_k_guard, dict)
        or runtime_k_guard.get("package_tree_sha256") != analyzer_tree
        or not isinstance(runtime_scaffold, dict)
        or runtime_scaffold.get("schema") != SCANNER_SCAFFOLD_SCHEMA
        or runtime_scaffold.get("file_count") != len(scaffold_rows or [])
        or runtime_scaffold.get("tree_sha256") != scaffold_hash
        or runtime_scaffold.get("raw_returned") is not False
        or runtime_binding.get("scanner_scaffold_tree_sha256") != scaffold_hash
        or runtime_binding.get("scanner_python_sha256") != runtime_python.get("executable_sha256")
        or runtime_binding.get("installed_distribution_set_sha256")
        != runtime_environment.get("installed_distribution_set_sha256")
        or runtime_binding.get("prefix_tree_sha256")
        != runtime_environment.get("prefix_tree", {}).get("sha256")
        or runtime_binding.get("base_runtime_tree_sha256")
        != runtime_environment.get("base_runtime_tree", {}).get("sha256")
        or runtime_binding.get("runtime_mutation_guard")
        != "windows_read_directory_changes_overlapped_v2"
        or (
            manifest_schema == PROTOCOL_SCHEMA
            and runtime_binding.get("runtime_notification_classifier")
            != RUNTIME_NOTIFICATION_CLASSIFIER
        )
        or (
            manifest_schema == PROTOCOL_SCHEMA
            and runtime_binding.get("native_runtime_lock_guard")
            != NATIVE_RUNTIME_LOCK_GUARD
        )
        or (
            manifest_schema == PROTOCOL_SCHEMA
            and runtime_binding.get("native_runtime_prewarm_guard")
            != NATIVE_RUNTIME_PREWARM_GUARD
        )
        or (
            manifest_schema == PROTOCOL_SCHEMA
            and runtime_binding.get("runtime_object_attestation_guard")
            != RUNTIME_OBJECT_ATTESTATION_GUARD
        )
        or runtime_environment.get("platform", {}).get("system") != "Windows"
    ):
        raise ValueError("v4 holdout isolated scanner runtime contract is invalid")
    legacy_source_materialization = {
        "schema": "k_guard_git_source_materialization.v1",
        "runtime_receipt_schema": "k_guard_holdout_scan_runtime_receipt.v3",
        "mutation_guard": "windows_read_directory_changes_overlapped_v2",
        "required_scan_event_count": 0,
    }
    legacy_blob_exact_source_materialization = {
        "schema": "k_guard_git_source_materialization.v2",
        "cleanliness_method": "git_blob_sha256_file_set_plus_index_tree_v2",
        "git_porcelain_clean_required": False,
        "direct_git_blob_sha256_required": True,
        "runtime_receipt_schema": "k_guard_holdout_scan_runtime_receipt.v3",
        "mutation_guard": "windows_read_directory_changes_overlapped_v2",
        "required_scan_event_count": 0,
    }
    blob_exact_source_materialization = {
        **legacy_blob_exact_source_materialization,
        "runtime_receipt_schema": RUNTIME_RECEIPT_SCHEMA,
    }
    if manifest_schema in {
        SOURCE_BOUND_PROTOCOL_SCHEMA,
        PREEXECUTION_PROTOCOL_SCHEMA,
        STRUCTURAL_PROTOCOL_SCHEMA,
    } and manifest.get("source_materialization") != legacy_source_materialization:
        raise ValueError("v4 holdout source materialization contract is invalid")
    if (
        manifest_schema == BLOB_EXACT_PROTOCOL_SCHEMA
        and manifest.get("source_materialization")
        != legacy_blob_exact_source_materialization
    ):
        raise ValueError("v5 holdout source materialization contract is invalid")
    if (
        manifest_schema == PROTOCOL_SCHEMA
        and manifest.get("source_materialization")
        != blob_exact_source_materialization
    ):
        raise ValueError("current holdout source materialization contract is invalid")
    if manifest_schema in {
        PREEXECUTION_PROTOCOL_SCHEMA,
        STRUCTURAL_PROTOCOL_SCHEMA,
        BLOB_EXACT_PROTOCOL_SCHEMA,
        PROTOCOL_SCHEMA,
    } and manifest.get("independent_git_verification") != {
        "schema": "k_guard_independent_git_verification.v3",
        "artifact_path": "independent-git-verification.json",
        "mirror_layout": "one_unlinked_full_bare_sha1_input_mirror_per_app",
        "verification_method": "verifier_owned_no_local_snapshot_and_raw_object_reconstruction",
        "byte_binding": "git_sha1_graph_plus_independent_sha256_file_bytes",
        "storage_binding": "pre_post_sha256_manifest_plus_file_identity",
        "path_policy": "windows_ntfs_materialization_fail_closed_v1",
        "execution_provenance": "unsigned_local_replay_receipt",
        "external_signed_provenance_required_for_contest_go": True,
        "source_contents_embedded": False,
    }:
        raise ValueError("v4 holdout independent Git verification contract is invalid")
    install_binding = runtime_binding.get("pip_install_report")
    if not isinstance(install_binding, dict):
        raise ValueError("v4 holdout pip installation report binding is missing")
    install_report_path = _safe_artifact(
        preregistration_root,
        install_binding.get("artifact_path"),
    )
    install_report_hash = str(install_binding.get("sha256") or "")
    if (
        SHA256_RE.fullmatch(install_report_hash) is None
        or sha256_file(install_report_path) != install_report_hash
    ):
        raise ValueError("v4 holdout pip installation report hash is invalid")
    install_report = load_install_report(
        install_report_path,
        wheel_sha256=wheel_hash,
        runtime_environment=runtime_environment,
    )
    if (
        install_binding.get("artifact_set_sha256")
        != install_report.get("k_guard_install_artifact_set_sha256")
    ):
        raise ValueError("v4 holdout pip installation artifact set binding is invalid")
    wheelhouse_binding = runtime_binding.get("wheelhouse")
    if not isinstance(wheelhouse_binding, dict):
        raise ValueError("v4 holdout wheelhouse binding is missing")
    wheelhouse = load_wheelhouse_manifest(
        preregistration_root,
        wheelhouse_binding,
        runtime_environment=runtime_environment,
        install_report=install_report,
    )
    if runtime_binding.get("bootstrap_distributions") != []:
        raise ValueError("v4 holdout scanner must not contain bootstrap distributions")

    source_binding = manifest.get("source_metadata")
    if not isinstance(source_binding, dict):
        raise ValueError("v4 holdout source metadata binding is missing")
    source_path = _safe_artifact(preregistration_root, source_binding.get("artifact_path"))
    source_hash = str(source_binding.get("sha256") or "")
    if SHA256_RE.fullmatch(source_hash) is None or sha256_file(source_path) != source_hash:
        raise ValueError("v4 holdout source metadata hash is invalid")
    source_metadata = load_source_metadata(source_path)
    if (
        source_binding.get("schema") != source_metadata.get("schema")
        or (
            manifest_schema
            in {
                STRUCTURAL_PROTOCOL_SCHEMA,
                BLOB_EXACT_PROTOCOL_SCHEMA,
                PROTOCOL_SCHEMA,
            }
            and source_metadata.get("schema") != STRUCTURAL_SOURCE_METADATA_SCHEMA
        )
    ):
        raise ValueError("v4 holdout source metadata protocol version is invalid")
    _validate_source_app_binding(source_metadata, preregistration.get("apps", []))

    return {
        "manifest": manifest,
        "manifest_path": manifest_path,
        "manifest_sha256": expected_manifest_hash,
        "protocol_files": protocol_files,
        "wheel_path": wheel_path,
        "runtime_path": runtime_path,
        "runtime_environment": runtime_environment,
        "install_report_path": install_report_path,
        "install_report": install_report,
        "wheelhouse": wheelhouse,
        "source_path": source_path,
        "source_metadata": source_metadata,
    }


def build_protocol_manifest(
    repo_root: Path,
    implementation_revision: str,
    preregistration_root: Path,
    wheel_path: Path,
    runtime_environment_path: Path,
    install_report_path: Path,
    wheelhouse_manifest_path: Path,
    source_metadata_path: Path,
    scanner_python: Path,
) -> dict[str, Any]:
    root = repo_root.resolve(strict=True)
    prereg_root = preregistration_root.resolve(strict=True)
    if REVISION_RE.fullmatch(implementation_revision) is None:
        raise ValueError("implementation revision must be a full lowercase commit SHA")
    analyzer_tree = package_tree_sha256_at_revision(root, implementation_revision)

    def artifact_binding(path: Path) -> tuple[str, str]:
        unresolved = path.absolute()
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(prereg_root) or unresolved.is_symlink():
            raise ValueError("holdout protocol artifacts must be regular files under the preregistration root")
        return resolved.relative_to(prereg_root).as_posix(), sha256_file(resolved)

    wheel_relative, wheel_hash = artifact_binding(wheel_path)
    runtime_relative, runtime_hash = artifact_binding(runtime_environment_path)
    install_relative, install_hash = artifact_binding(install_report_path)
    wheelhouse_relative, wheelhouse_hash = artifact_binding(wheelhouse_manifest_path)
    source_relative, source_hash = artifact_binding(source_metadata_path)
    runtime_payload = _load_canonical_json(runtime_environment_path, maximum_bytes=5 * 1024 * 1024)
    if runtime_payload != capture_runtime_environment(
        scanner_python,
        root / "scripts" / "holdout_runtime_probe.py",
        runtime_payload.get("scanner_scaffold"),
    ):
        raise ValueError("runtime environment artifact does not match the current dependency closure")
    if runtime_payload.get("platform", {}).get("system") != "Windows":
        raise ValueError("strict holdout runtime mutation monitoring currently requires Windows")
    source_payload = load_source_metadata(source_metadata_path)
    wheel_contract = wheel_qualification_contract(wheel_path)
    if wheel_contract["package_contract"]["package_tree_sha256"] != analyzer_tree:
        raise ValueError("wheel package tree does not match the implementation revision")
    install_report = load_install_report(
        install_report_path,
        wheel_sha256=wheel_hash,
        runtime_environment=runtime_payload,
    )
    wheelhouse_payload = load_wheelhouse_manifest(
        prereg_root,
        {
            "manifest_path": wheelhouse_relative,
            "manifest_sha256": wheelhouse_hash,
            "artifact_set_sha256": _load_canonical_json(wheelhouse_manifest_path).get(
                "artifact_set_sha256"
            ),
        },
        runtime_environment=runtime_payload,
        install_report=install_report,
    )
    return {
        "schema": PROTOCOL_SCHEMA,
        "implementation_revision": implementation_revision,
        "package_tree_hash_schema": TREE_HASH_SCHEMA,
        "analyzer_package_tree_sha256": analyzer_tree,
        "release_blocking_policy": RELEASE_BLOCKING_POLICY,
        "automatic_release_rule_ids": sorted(AUTOMATIC_RELEASE_RULES),
        "execution_package_source": "isolated_venv_installed_from_bound_wheel",
        "protocol_files": [
            {
                "path": relative,
                "sha256": file_sha256_at_revision(root, implementation_revision, relative),
            }
            for relative in REQUIRED_PROTOCOL_FILES
        ],
        "wheel": {
            "artifact_path": wheel_relative,
            "sha256": wheel_hash,
            "qualification_contract": wheel_contract,
        },
        "runtime_environment": {
            "artifact_path": runtime_relative,
            "sha256": runtime_hash,
            "schema": runtime_payload["schema"],
            "scanner_python_sha256": runtime_payload["python"]["executable_sha256"],
            "installed_distribution_set_sha256": runtime_payload[
                "installed_distribution_set_sha256"
            ],
            "prefix_tree_sha256": runtime_payload["prefix_tree"]["sha256"],
            "base_runtime_tree_sha256": runtime_payload["base_runtime_tree"]["sha256"],
            "scanner_scaffold_tree_sha256": runtime_payload["scanner_scaffold"][
                "tree_sha256"
            ],
            "runtime_mutation_guard": "windows_read_directory_changes_overlapped_v2",
            "runtime_notification_classifier": RUNTIME_NOTIFICATION_CLASSIFIER,
            "native_runtime_lock_guard": NATIVE_RUNTIME_LOCK_GUARD,
            "native_runtime_prewarm_guard": NATIVE_RUNTIME_PREWARM_GUARD,
            "runtime_object_attestation_guard": RUNTIME_OBJECT_ATTESTATION_GUARD,
            "pip_install_report": {
                "artifact_path": install_relative,
                "sha256": install_hash,
                "artifact_set_sha256": install_report[
                    "k_guard_install_artifact_set_sha256"
                ],
            },
            "wheelhouse": {
                "manifest_path": wheelhouse_relative,
                "manifest_sha256": wheelhouse_hash,
                "artifact_set_sha256": wheelhouse_payload["artifact_set_sha256"],
            },
            "bootstrap_distributions": [],
        },
        "source_materialization": {
            "schema": "k_guard_git_source_materialization.v2",
            "cleanliness_method": "git_blob_sha256_file_set_plus_index_tree_v2",
            "git_porcelain_clean_required": False,
            "direct_git_blob_sha256_required": True,
            "runtime_receipt_schema": RUNTIME_RECEIPT_SCHEMA,
            "mutation_guard": "windows_read_directory_changes_overlapped_v2",
            "required_scan_event_count": 0,
        },
        "independent_git_verification": {
            "schema": "k_guard_independent_git_verification.v3",
            "artifact_path": "independent-git-verification.json",
            "mirror_layout": "one_unlinked_full_bare_sha1_input_mirror_per_app",
            "verification_method": "verifier_owned_no_local_snapshot_and_raw_object_reconstruction",
            "byte_binding": "git_sha1_graph_plus_independent_sha256_file_bytes",
            "storage_binding": "pre_post_sha256_manifest_plus_file_identity",
            "path_policy": "windows_ntfs_materialization_fail_closed_v1",
            "execution_provenance": "unsigned_local_replay_receipt",
            "external_signed_provenance_required_for_contest_go": True,
            "source_contents_embedded": False,
        },
        "source_metadata": {
            "artifact_path": source_relative,
            "sha256": source_hash,
            "schema": source_payload["schema"],
        },
        "raw_returned": False,
    }


def _tracked_artifact_binding(repo_root: Path, path: Path, revision: str) -> dict[str, str]:
    root = repo_root.resolve(strict=True)
    unresolved = path.absolute()
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root) or unresolved.is_symlink():
        raise ValueError("holdout execution artifact is outside the repository or is a symlink")
    relative = resolved.relative_to(root).as_posix()
    _run_git(root, "ls-files", "--error-unmatch", "--", relative)
    committed = _run_git(root, "show", f"{revision}:{relative}").stdout
    current = resolved.read_bytes()
    if committed != current:
        raise ValueError(f"holdout execution artifact is not committed at HEAD: {relative}")
    return {"path": relative, "sha256": hashlib.sha256(committed).hexdigest()}


def verify_protocol_execution(
    repo_root: Path,
    preregistration_path: Path,
    protocol: dict[str, Any],
    *,
    scanner_python: Path,
    extra_committed_paths: Iterable[Path] = (),
) -> dict[str, Any]:
    root = repo_root.resolve(strict=True)
    manifest = protocol["manifest"]
    implementation_revision = str(manifest["implementation_revision"])
    head = _run_git(root, "rev-parse", "HEAD").stdout.decode("ascii").strip()
    if REVISION_RE.fullmatch(head) is None:
        raise ValueError("holdout execution HEAD is invalid")
    if _run_git(root, "merge-base", "--is-ancestor", implementation_revision, head, check=False).returncode != 0:
        raise ValueError("holdout implementation revision is not an ancestor of execution HEAD")
    if package_tree_sha256_at_revision(root, implementation_revision) != manifest["analyzer_package_tree_sha256"]:
        raise ValueError("holdout implementation package tree does not match its revision")
    if package_tree_sha256(root / "src" / "k_guard_mcp") != manifest["analyzer_package_tree_sha256"]:
        raise ValueError("holdout execution package tree differs from the bound implementation")
    for relative, expected_hash in protocol["protocol_files"].items():
        if file_sha256_at_revision(root, implementation_revision, relative) != expected_hash:
            raise ValueError(f"holdout protocol revision hash mismatch: {relative}")
        current = root / relative
        if not current.is_file() or current.is_symlink() or sha256_file(current) != expected_hash:
            raise ValueError(f"holdout protocol file changed after implementation lock: {relative}")
    current_runtime = capture_runtime_environment(
        scanner_python,
        root / "scripts" / "holdout_runtime_probe.py",
        protocol["runtime_environment"].get("scanner_scaffold"),
    )
    if current_runtime != protocol["runtime_environment"]:
        raise ValueError("holdout runtime environment differs from the preregistered dependency closure")

    committed_paths = [
        preregistration_path,
        protocol["manifest_path"],
        protocol["wheel_path"],
        protocol["runtime_path"],
        protocol["install_report_path"],
        protocol["wheelhouse"]["_manifest_path"],
        *protocol["wheelhouse"]["_artifact_paths"],
        protocol["source_path"],
        *extra_committed_paths,
    ]
    committed = sorted(
        (_tracked_artifact_binding(root, path, head) for path in committed_paths),
        key=lambda row: row["path"],
    )
    execution = {
        "holdout_protocol_schema": manifest["schema"],
        "implementation_revision": implementation_revision,
        "execution_revision": head,
        "protocol_manifest_sha256": protocol["manifest_sha256"],
        "analyzer_package_tree_sha256": manifest["analyzer_package_tree_sha256"],
        "wheel_sha256": manifest["wheel"]["sha256"],
        "runtime_environment_sha256": manifest["runtime_environment"]["sha256"],
        "pip_install_report_sha256": manifest["runtime_environment"]["pip_install_report"][
            "sha256"
        ],
        "pip_install_artifact_set_sha256": manifest["runtime_environment"][
            "pip_install_report"
        ]["artifact_set_sha256"],
        "wheelhouse_manifest_sha256": manifest["runtime_environment"]["wheelhouse"][
            "manifest_sha256"
        ],
        "wheelhouse_artifact_set_sha256": manifest["runtime_environment"]["wheelhouse"][
            "artifact_set_sha256"
        ],
        "scanner_python_sha256": manifest["runtime_environment"]["scanner_python_sha256"],
        "runtime_launcher_sha256": protocol["protocol_files"]["scripts/holdout_scan_launcher.py"],
        "runtime_probe_sha256": protocol["protocol_files"]["scripts/holdout_runtime_probe.py"],
        "installed_distribution_set_sha256": manifest["runtime_environment"][
            "installed_distribution_set_sha256"
        ],
        "prefix_tree_sha256": manifest["runtime_environment"]["prefix_tree_sha256"],
        "base_runtime_tree_sha256": manifest["runtime_environment"][
            "base_runtime_tree_sha256"
        ],
        "scanner_scaffold_tree_sha256": manifest["runtime_environment"][
            "scanner_scaffold_tree_sha256"
        ],
        "runtime_mutation_guard": manifest["runtime_environment"]["runtime_mutation_guard"],
        "runtime_notification_classifier": manifest["runtime_environment"].get(
            "runtime_notification_classifier"
        ),
        "native_runtime_lock_guard": manifest["runtime_environment"].get(
            "native_runtime_lock_guard"
        ),
        "native_runtime_prewarm_guard": manifest["runtime_environment"].get(
            "native_runtime_prewarm_guard"
        ),
        "runtime_object_attestation_guard": manifest["runtime_environment"].get(
            "runtime_object_attestation_guard"
        ),
        "source_metadata_sha256": manifest["source_metadata"]["sha256"],
        "release_blocking_policy": manifest["release_blocking_policy"],
        "automatic_release_rule_ids": manifest["automatic_release_rule_ids"],
        "tracked_artifacts_committed_at_execution_head": committed,
        "raw_returned": False,
    }
    source_probe_sha256 = protocol["protocol_files"].get(
        "scripts/holdout_source_materialization.py"
    )
    if source_probe_sha256 is not None:
        execution["source_materialization_probe_sha256"] = source_probe_sha256
    independent_verifier_sha256 = protocol["protocol_files"].get(
        "scripts/verify_holdout_git_sources.py"
    )
    if independent_verifier_sha256 is not None:
        execution["independent_git_verifier_sha256"] = independent_verifier_sha256
    return execution


def source_metadata_by_repository(protocol: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row["repository_id"]): row
        for row in protocol["source_metadata"]["repositories"]
        if isinstance(row, dict)
    }
