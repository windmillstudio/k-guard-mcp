from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import tempfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA = "k_guard_l2_oracle_registry.v7"
WEBGOAT_EXECUTION_EVIDENCE_SCHEMA = "k_guard_l2_webgoat_idor_execution_evidence.v1"
WEBGOAT_CVSS_EVIDENCE_SCHEMA = "k_guard_l2_webgoat_idor_cvss_evidence.v1"
WEBGOAT_STATE_RESET_EVIDENCE_SCHEMA = "k_guard_l2_webgoat_idor_state_reset_evidence.v1"
WEBGOAT_MISSING_FUNCTION_AC_EXECUTION_EVIDENCE_SCHEMA = (
    "k_guard_l2_webgoat_missing_function_ac_execution_evidence.v1"
)
WEBGOAT_MISSING_FUNCTION_AC_CWE_EVIDENCE_SCHEMA = (
    "k_guard_l2_webgoat_missing_function_ac_cwe_evidence.v1"
)
WEBGOAT_MISSING_FUNCTION_AC_CVSS_EVIDENCE_SCHEMA = (
    "k_guard_l2_webgoat_missing_function_ac_cvss_evidence.v1"
)
WEBGOAT_MISSING_FUNCTION_AC_STATE_RESET_EVIDENCE_SCHEMA = (
    "k_guard_l2_webgoat_missing_function_ac_state_reset_evidence.v1"
)
WEBGOAT_SQL_INJECTION_ADVANCED_EXECUTION_EVIDENCE_SCHEMA = (
    "k_guard_l2_webgoat_sql_injection_advanced_execution_evidence.v1"
)
WEBGOAT_SQL_INJECTION_ADVANCED_CWE_EVIDENCE_SCHEMA = (
    "k_guard_l2_webgoat_sql_injection_advanced_cwe_evidence.v1"
)
WEBGOAT_SQL_INJECTION_ADVANCED_CVSS_EVIDENCE_SCHEMA = (
    "k_guard_l2_webgoat_sql_injection_advanced_cvss_evidence.v1"
)
WEBGOAT_SQL_INJECTION_ADVANCED_STATE_RESET_EVIDENCE_SCHEMA = (
    "k_guard_l2_webgoat_sql_injection_advanced_state_reset_evidence.v1"
)
DEFAULT_CALCULATOR_ID = "FIRST-CVSS-v4.0-c5b0d409"
EXPECTED_APPS = (
    "crapi",
    "juice-shop",
    "nodegoat",
    "pygoat",
    "webgoat",
    "wrongsecrets",
)
PLANES = frozenset({"site", "api", "data", "operations"})
SEVERITIES = frozenset({"high", "critical"})
NETWORK_POLICIES = frozenset({"offline", "isolated_loopback"})
COMMAND_KINDS = frozenset({"http", "process"})
ALLOWED_EXECUTABLES = frozenset(
    {"./gradlew", "./mvnw", "docker", "gradlew.bat", "mvnw.cmd", "npm", "npx", "pytest", "python", "python3"}
)
CVSS_BASE_ORDER = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
CVSS_BASE_VALUES = {
    "AV": frozenset({"N", "A", "L", "P"}),
    "AC": frozenset({"L", "H"}),
    "AT": frozenset({"N", "P"}),
    "PR": frozenset({"N", "L", "H"}),
    "UI": frozenset({"N", "P", "A"}),
    "VC": frozenset({"H", "L", "N"}),
    "VI": frozenset({"H", "L", "N"}),
    "VA": frozenset({"H", "L", "N"}),
    "SC": frozenset({"H", "L", "N"}),
    "SI": frozenset({"H", "L", "N"}),
    "SA": frozenset({"H", "L", "N"}),
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CWE_RE = re.compile(r"\bCWE-([1-9][0-9]*)\b", re.IGNORECASE)
CVSS_RE = re.compile(r"CVSS:4\.0(?:/[A-Z]{1,3}:[A-Z]){11}")
SCORE_RE = re.compile(
    r"\b(?:score|cvss(?:\s+v?4)?\s+score)\s*[:=]\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)\b",
    re.IGNORECASE,
)
UNSAFE_COMMAND_RE = re.compile(r"(?:https?://|[;&|`<>\r\n\x00])", re.IGNORECASE)
UNSAFE_DOCKER_ARG_RE = re.compile(
    r"(?:--privileged|--network(?:=|\s*)host|--cap-add|docker\.sock|--pid(?:=|\s*)host)", re.IGNORECASE
)
MECHANISM_EVIDENCE_RE = re.compile(
    r"\b(?:attack\w*|exploit\w*|expos\w*|injection|leak\w*|secret\w*|unauthori[sz]\w*|vulnerab\w*)\b",
    re.IGNORECASE,
)
MAX_SOURCE_BYTES = 8 * 1024 * 1024
SOURCE_ADMISSION_SCHEMAS = frozenset(
    {
        "k_guard_l2_source_materialization.v1",
        "k_guard_l2_source_materialization.v2",
        "k_guard_l2_source_materialization.v3",
    }
)
SOURCE_RECEIPT_SCHEMA = "k_guard_git_source_materialization.v2"
LOCKED_SOURCE_ADMISSION_SHA256 = "32b9618dfdcb3ff4f8e87fa5012c36eff51a1beba2dd0e0357a7bbd9c99ecc1a"
LOCKED_SOURCE_CONTRACT_SHA256 = "28ae0b40a97c19d0478f7a71acab743dd03749a1901f51d06011ecdb90a6f9d0"
LOCKED_SOURCE_VERIFIER_SHA256 = "0197723df7c3da7833f1f541259f2d530fa95343ccda66508e5cb536ecff0f90"
LOCKED_CALCULATOR_REPOSITORY_ID = "firstdotorg/cvss-v4-calculator"
LOCKED_CALCULATOR_COMMIT = "c5b0d409ae9f57c44264c6ce5f27d89298e1d32a"
LOCKED_CALCULATOR_TREE = "adcd96477871b4a9fc8ba2e3c9c225b52e980eb5"
LOCKED_CALCULATOR_SOURCE_TREE_SHA256 = "d4832324d93937db54949819597208c8ca5a44d9ac43d2705b4f7e4de17e520b"
LOCKED_CALCULATOR_RECEIPT_SHA256 = "abed66c802f6c397bf5542dfd3af88665e308fec818a1c22e006ccdd79b7ec7b"
LOCKED_CALCULATOR_FILE_MANIFEST_SHA256 = "4713bc4b8978ecc1f77d3b45cafdadf77557f9ed582b8d8a53486604a507c2cd"
LOCKED_CALCULATOR_FILE_COUNT = 13
LOCKED_CALCULATOR_TOTAL_BYTES = 97914
LOCKED_CALCULATOR_LICENSE = {
    "path": "LICENSE",
    "spdx": "BSD-2-Clause",
    "sha256": "5d672639189da9bda914dd8c847069cc6959135000b17c45262bb742e5d3b392",
    "byte_count": 1307,
}
LOCKED_CALCULATOR_CORE_FILES = {
    "cvss_lookup.js": "d533fe625d95e15b7b488a4bf93dab5f7df16b7e38b0c8ee01281d7b31a8165e",
    "cvss_score.js": "453ce6767b5c3939b51d1f21315f2649e47b5abeca674be287e94b524472a1bc",
    "max_composed.js": "be707cc82c17993a04a84e47b1a8aaa1d0d212b56852254659ce77fd7d959f63",
    "max_severity.js": "f838ecb41bfd5114456e7fa7df8a8449ca2735c176867886fa34bd011dee0b24",
    "metrics.js": "99ee2643587071bf744cd090c4bb2db58d523ed0276efd809871b00a12985a4c",
}
SOURCE_RECEIPT_TRUTHS = (
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


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _source_receipt_semantic_sha256(receipt: dict[str, Any]) -> str:
    """Bind every receipt field except the explicitly informational porcelain flag."""

    porcelain_clean = receipt.get("git_porcelain_clean")
    if not isinstance(porcelain_clean, bool):
        raise ValueError("source receipt git_porcelain_clean must be boolean")
    semantic = dict(receipt)
    del semantic["git_porcelain_clean"]
    return sha256_bytes(canonical_json_bytes(semantic))


def _safe_relative_path(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 500:
        raise ValueError(f"{label} must be a bounded non-empty relative path")
    if any(character in value for character in "\x00\r\n\\"):
        raise ValueError(f"{label} contains a forbidden character")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{label} must be a normalized POSIX relative path")
    return value


def _bound_file(root: Path, relative: str, *, label: str) -> tuple[Path, bytes]:
    normalized = _safe_relative_path(relative, label=label)
    try:
        root_resolved = root.resolve(strict=True)
        target = (root_resolved / Path(*PurePosixPath(normalized).parts)).resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError(f"{label} does not exist") from exc
    try:
        target.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"{label} escapes the app root") from exc
    if target.is_symlink() or not target.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    size = target.stat().st_size
    if size > MAX_SOURCE_BYTES:
        raise ValueError(f"{label} exceeds the extraction size limit")
    return target, target.read_bytes()


def _read_utf8(root: Path, relative: str, *, label: str) -> tuple[str, bytes]:
    _path, raw = _bound_file(root, relative, label=label)
    try:
        return raw.decode("utf-8"), raw
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} must be UTF-8") from exc


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return normalized[:96] or "unnamed"


def _load_module(path: Path, name: str) -> tuple[Any, str]:
    raw_before = path.read_bytes()
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load authoritative source module: {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if path.read_bytes() != raw_before:
        raise RuntimeError(f"authoritative source module changed while loading: {path.name}")
    return module, sha256_bytes(raw_before)


def _load_authoritative_source_modules() -> tuple[Any, Any, str, str]:
    directory = Path(__file__).resolve(strict=True).parent
    contract, contract_sha256 = _load_module(
        directory / "materialize_l2_sources.py", "k_guard_l2_oracle_source_contract"
    )
    verifier, verifier_sha256 = _load_module(
        directory / "holdout_source_materialization.py", "k_guard_l2_oracle_source_verifier"
    )
    return contract, verifier, contract_sha256, verifier_sha256


def _load_canonical_object(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.resolve(strict=True).read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} must be UTF-8 JSON") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError(f"{label} must be a canonical JSON object")
    return payload, raw


def _locked_identity(value: Any) -> dict[str, Any]:
    return {
        "repository_id": value["repository_id"],
        "commit": value["commit"],
        "commit_tree": value["commit_tree"],
        "source_tree_sha256": value["source_tree_sha256"],
        "receipt_sha256": value["receipt_sha256"],
        "license": dict(value["license"]),
    }


def _source_admission_rows(
    admission: dict[str, Any], expected_identities: Any
) -> dict[str, dict[str, Any]]:
    if admission.get("schema") not in SOURCE_ADMISSION_SCHEMAS:
        raise ValueError("L2 source admission schema is not supported")
    if admission.get("scanner_output_observed") is not False:
        raise ValueError("L2 source admission crossed the scanner evidence boundary")
    apps = admission.get("apps")
    if not isinstance(apps, list) or len(apps) != len(EXPECTED_APPS):
        raise ValueError("L2 source admission must contain exactly six apps")
    rows: dict[str, dict[str, Any]] = {}
    for row in apps:
        if not isinstance(row, dict) or row.get("app_id") not in EXPECTED_APPS:
            raise ValueError("L2 source admission contains an unknown app")
        app_id = row["app_id"]
        if app_id in rows:
            raise ValueError("L2 source admission contains a duplicate app")
        observed = {
            "repository_id": row.get("repository_id"),
            "commit": row.get("commit"),
            "commit_tree": row.get("commit_tree"),
            "source_tree_sha256": row.get("source_tree_sha256"),
            "receipt_sha256": row.get("receipt_sha256"),
            "license": {
                key: row.get("license", {}).get(key)
                for key in ("path", "spdx", "sha256", "byte_count")
            } if isinstance(row.get("license"), dict) else None,
        }
        if observed != _locked_identity(expected_identities[app_id]):
            raise ValueError(f"{app_id} source identity differs from immutable preregistration")
        source_status = row.get("source_admission", row.get("source_license_admission"))
        if source_status != "PASS" or row.get("scanner_output_observed") is not False:
            raise ValueError(f"{app_id} authoritative source admission is not PASS")
        rows[app_id] = row
    if set(rows) != set(EXPECTED_APPS):
        raise ValueError("L2 source admission does not bind the locked six apps")
    return rows


def _verify_source_receipts(
    sources_root: Path,
    source_admission_path: Path,
    source_receipts_dir: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    contract, verifier, contract_sha256, verifier_sha256 = _load_authoritative_source_modules()
    if contract_sha256 != LOCKED_SOURCE_CONTRACT_SHA256:
        raise ValueError("authoritative L2 source contract artifact hash is not preregistered")
    if verifier_sha256 != LOCKED_SOURCE_VERIFIER_SHA256:
        raise ValueError("authoritative raw-blob verifier artifact hash is not preregistered")
    expected_identities = contract.EXPECTED_IDENTITIES
    if set(expected_identities) != set(EXPECTED_APPS):
        raise ValueError("authoritative L2 contract does not contain the locked six apps")
    admission, admission_raw = _load_canonical_object(
        source_admission_path, label="L2 source admission"
    )
    if sha256_bytes(admission_raw) != LOCKED_SOURCE_ADMISSION_SHA256:
        raise ValueError("L2 source admission artifact hash is not preregistered")
    admission_rows = _source_admission_rows(admission, expected_identities)
    receipt_directory = source_receipts_dir.resolve(strict=True)
    if not receipt_directory.is_dir():
        raise ValueError("source receipts path must be a directory")
    expected_names = {f"{app_id}.json" for app_id in EXPECTED_APPS}
    observed_names = {path.name for path in receipt_directory.iterdir() if path.is_file()}
    if observed_names != expected_names:
        raise ValueError("source receipt directory must contain exactly the locked six receipts")

    summaries: list[dict[str, Any]] = []
    for app_id in EXPECTED_APPS:
        immutable_identity = expected_identities[app_id]
        locked = _locked_identity(immutable_identity)
        root = (sources_root / app_id).resolve(strict=True)
        receipt, receipt_raw = _load_canonical_object(
            receipt_directory / f"{app_id}.json", label=f"{app_id} source receipt"
        )
        receipt_sha256 = sha256_bytes(receipt_raw)
        receipt_semantic_sha256 = _source_receipt_semantic_sha256(receipt)
        locked_semantic_sha256 = immutable_identity.get("receipt_semantic_sha256")
        if not isinstance(locked_semantic_sha256, str) or SHA256_RE.fullmatch(locked_semantic_sha256) is None:
            raise ValueError(f"{app_id} source receipt semantic preregistration is invalid")
        if receipt_sha256 == locked["receipt_sha256"]:
            receipt_equivalence = "exact_raw_receipt"
        elif receipt_semantic_sha256 == locked_semantic_sha256:
            receipt_equivalence = "informational_porcelain_variance"
        else:
            raise ValueError(f"{app_id} source receipt differs from preregistration")
        if receipt.get("schema") != SOURCE_RECEIPT_SCHEMA or receipt.get("passed") is not True:
            raise ValueError(f"{app_id} source receipt schema or pass state is invalid")
        recomputed = verifier.build_git_materialization_receipt(
            root,
            expected_repository_id=locked["repository_id"],
            expected_commit=locked["commit"],
            expected_tree=locked["commit_tree"],
        )
        if recomputed != receipt:
            raise ValueError(f"{app_id} source receipt no longer matches raw Git blobs and index")
        if any(receipt.get(field) is not True for field in SOURCE_RECEIPT_TRUTHS):
            raise ValueError(f"{app_id} source receipt lacks required raw-blob proof")
        if receipt.get("git_repository_layout") != "ordinary_non_shallow_standalone_clone":
            raise ValueError(f"{app_id} is not an ordinary full standalone clone")
        if (
            receipt.get("repository_id") != locked["repository_id"]
            or receipt.get("commit") != locked["commit"]
            or receipt.get("commit_tree") != locked["commit_tree"]
            or receipt.get("source_tree_sha256") != locked["source_tree_sha256"]
        ):
            raise ValueError(f"{app_id} receipt identity differs from preregistration")
        license_row = next(
            (row for row in receipt.get("files", []) if row.get("path") == locked["license"]["path"]),
            None,
        )
        if not isinstance(license_row, dict) or {
            "sha256": license_row.get("sha256"), "byte_count": license_row.get("byte_count")
        } != {
            "sha256": locked["license"]["sha256"], "byte_count": locked["license"]["byte_count"]
        }:
            raise ValueError(f"{app_id} license is not bound by the raw-blob receipt")
        admission_row = admission_rows[app_id]
        summaries.append(
            {
                "app_id": app_id,
                "schema": SOURCE_RECEIPT_SCHEMA,
                "repository_id": locked["repository_id"],
                "commit": locked["commit"],
                "commit_tree": locked["commit_tree"],
                "source_tree_sha256": locked["source_tree_sha256"],
                "lineage_id": admission_row["lineage_id"],
                "receipt_sha256": locked["receipt_sha256"],
                "observed_receipt_sha256": receipt_sha256,
                "receipt_semantic_sha256": receipt_semantic_sha256,
                "receipt_equivalence": receipt_equivalence,
                "license": locked["license"],
                "file_count": receipt["file_count"],
                "total_bytes": receipt["total_bytes"],
                "source_admission": "PASS",
                "source_worktree_clean": True,
                "source_worktree_clean_method": receipt["source_worktree_clean_method"],
                "physical_bytes_match_git_blobs": True,
                "index_tree_match": True,
                "git_porcelain_clean": receipt.get("git_porcelain_clean"),
                "git_porcelain_is_informational": True,
                "scanner_output_observed": False,
            }
        )
    provenance = {
        "schema": admission["schema"],
        "artifact_name": source_admission_path.name,
        "artifact_sha256": sha256_bytes(admission_raw),
        "contract_artifact": "materialize_l2_sources.py",
        "contract_sha256": contract_sha256,
        "verifier_artifact": "holdout_source_materialization.py",
        "verifier_sha256": verifier_sha256,
        "receipt_schema": SOURCE_RECEIPT_SCHEMA,
        "status": "PASS",
    }
    return provenance, summaries


def _verify_calculator_source(calculator_root: Path, receipt_path: Path) -> dict[str, Any]:
    _contract, verifier, _contract_sha256, verifier_sha256 = _load_authoritative_source_modules()
    if verifier_sha256 != LOCKED_SOURCE_VERIFIER_SHA256:
        raise ValueError("authoritative raw-blob verifier artifact hash is not preregistered")
    root = calculator_root.resolve(strict=True)
    receipt, receipt_raw = _load_canonical_object(receipt_path, label="FIRST calculator source receipt")
    if sha256_bytes(receipt_raw) != LOCKED_CALCULATOR_RECEIPT_SHA256:
        raise ValueError("FIRST calculator source receipt hash is not preregistered")
    if receipt.get("schema") != SOURCE_RECEIPT_SCHEMA or receipt.get("passed") is not True:
        raise ValueError("FIRST calculator source receipt schema or pass state is invalid")
    recomputed = verifier.build_git_materialization_receipt(
        root,
        expected_repository_id=LOCKED_CALCULATOR_REPOSITORY_ID,
        expected_commit=LOCKED_CALCULATOR_COMMIT,
        expected_tree=LOCKED_CALCULATOR_TREE,
    )
    if recomputed != receipt:
        raise ValueError("FIRST calculator receipt no longer matches raw Git blobs and index")
    if any(receipt.get(field) is not True for field in SOURCE_RECEIPT_TRUTHS):
        raise ValueError("FIRST calculator receipt lacks required raw-blob proof")
    if receipt.get("git_repository_layout") != "ordinary_non_shallow_standalone_clone":
        raise ValueError("FIRST calculator is not an ordinary full standalone clone")
    expected_identity = {
        "repository_id": LOCKED_CALCULATOR_REPOSITORY_ID,
        "commit": LOCKED_CALCULATOR_COMMIT,
        "commit_tree": LOCKED_CALCULATOR_TREE,
        "source_tree_sha256": LOCKED_CALCULATOR_SOURCE_TREE_SHA256,
        "file_count": LOCKED_CALCULATOR_FILE_COUNT,
        "total_bytes": LOCKED_CALCULATOR_TOTAL_BYTES,
    }
    observed_identity = {key: receipt.get(key) for key in expected_identity}
    if observed_identity != expected_identity:
        raise ValueError("FIRST calculator source identity differs from preregistration")
    files = receipt.get("files")
    if not isinstance(files, list):
        raise ValueError("FIRST calculator file manifest is missing")
    manifest_sha256 = sha256_bytes(canonical_json_bytes({"files": files}))
    if manifest_sha256 != LOCKED_CALCULATOR_FILE_MANIFEST_SHA256:
        raise ValueError("FIRST calculator full file manifest differs from preregistration")
    files_by_path = {row.get("path"): row for row in files if isinstance(row, dict)}
    if len(files_by_path) != len(files):
        raise ValueError("FIRST calculator file manifest contains malformed or duplicate paths")
    core_files = []
    for path, expected_sha256 in sorted(LOCKED_CALCULATOR_CORE_FILES.items()):
        row = files_by_path.get(path)
        if not isinstance(row, dict) or row.get("sha256") != expected_sha256:
            raise ValueError(f"FIRST calculator core file differs from preregistration: {path}")
        core_files.append({"path": path, "sha256": expected_sha256, "byte_count": row["byte_count"]})
    license_row = files_by_path.get(LOCKED_CALCULATOR_LICENSE["path"])
    if not isinstance(license_row, dict) or {
        "sha256": license_row.get("sha256"), "byte_count": license_row.get("byte_count")
    } != {
        "sha256": LOCKED_CALCULATOR_LICENSE["sha256"],
        "byte_count": LOCKED_CALCULATOR_LICENSE["byte_count"],
    }:
        raise ValueError("FIRST calculator license differs from preregistration")
    return {
        "id": DEFAULT_CALCULATOR_ID,
        "repository_id": LOCKED_CALCULATOR_REPOSITORY_ID,
        "commit": LOCKED_CALCULATOR_COMMIT,
        "commit_tree": LOCKED_CALCULATOR_TREE,
        "source_tree_sha256": LOCKED_CALCULATOR_SOURCE_TREE_SHA256,
        "source_receipt_artifact": receipt_path.name,
        "source_receipt_sha256": LOCKED_CALCULATOR_RECEIPT_SHA256,
        "file_manifest_sha256": LOCKED_CALCULATOR_FILE_MANIFEST_SHA256,
        "file_count": receipt["file_count"],
        "total_bytes": receipt["total_bytes"],
        "license": dict(LOCKED_CALCULATOR_LICENSE),
        "core_files": core_files,
        "source_worktree_clean": True,
        "source_worktree_clean_method": receipt["source_worktree_clean_method"],
        "physical_bytes_match_git_blobs": True,
        "index_tree_match": True,
        "git_fsck_strict_passed": True,
        "git_porcelain_clean": receipt.get("git_porcelain_clean"),
        "git_porcelain_is_informational": True,
        "verifier_artifact": "holdout_source_materialization.py",
        "verifier_sha256": verifier_sha256,
        "pin_verified": True,
    }


def _unique_explicit_cwe(text: str) -> str | None:
    values = sorted({f"CWE-{match.group(1)}" for match in CWE_RE.finditer(text)})
    return values[0] if len(values) == 1 else None


def _semantic_window(text: str, line: int) -> str:
    lines = text.splitlines()
    start = max(0, line - 16)
    end = min(len(lines), line + 80)
    return "\n".join(lines[start:end])


def _explicit_mechanism_truth(text: str) -> str | None:
    return "present" if MECHANISM_EVIDENCE_RE.search(text) else None


def _plane_for(*values: str) -> tuple[str, list[str]]:
    text = " ".join(values).casefold()
    if any(token in text for token in ("docker", "kubernetes", "config", "dependency", "component", "secret")):
        primary = "operations"
    elif any(token in text for token in ("sql", "database", "data exposure", "privacy", "personal data", "rls")):
        primary = "data"
    elif any(token in text for token in ("api", "idor", "bola", "auth", "jwt", "access control", "mass assignment")):
        primary = "api"
    else:
        primary = "site"
    applicable = {primary}
    if primary in {"site", "data"} and any(token in text for token in ("api", "endpoint", "request")):
        applicable.add("api")
    return primary, sorted(applicable)


def _cvss_from_official_text(text: str, calculator_id: str, calculator_binding_sha256: str) -> dict[str, Any]:
    vector_match = CVSS_RE.search(text)
    score_match = SCORE_RE.search(text)
    vector = vector_match.group(0) if vector_match else None
    score = score_match.group(1) if score_match else None
    if score is not None and "." not in score:
        score = f"{score}.0"
    severity: str | None = None
    if score is not None:
        numeric = float(score)
        if numeric >= 9.0:
            severity = "critical"
        elif numeric >= 7.0:
            severity = "high"
    return {
        "vector": vector,
        "score": score,
        "severity": severity,
        "calculator_id": calculator_id,
        "calculator_binding_sha256": calculator_binding_sha256,
        "source": "official_source_text" if vector or score else None,
    }


def _command(argv: list[str], *, network_policy: str) -> dict[str, Any]:
    return {
        "argv": argv,
        "cwd": ".",
        "kind": "process",
        "network_policy": network_policy,
        "expected_exit_code": 0,
        "expected_http_status": None,
        "expected_body_sha256": None,
        "expected_result_sha256": None,
    }


def _discover_java_tests(root: Path, pattern: str, *, integration: bool) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(root.glob(pattern), key=lambda item: item.as_posix().casefold()):
        relative = path.relative_to(root).as_posix()
        text, raw = _read_utf8(root, relative, label="upstream Java test")
        package_match = re.search(r"^\s*package\s+([A-Za-z0-9_.]+)\s*;", text, re.MULTILINE)
        package = package_match.group(1) if package_match else ""
        class_name = path.stem
        selector_prefix = f"{package}.{class_name}" if package else class_name
        matches: list[tuple[str, int]] = []
        method_re = re.compile(
            r"@Test(?:Factory)?(?:\s*\([^\n]*\))?\s*(?:\n\s*@[^\n]+)*\s*"
            r"(?:public\s+|protected\s+|private\s+)?(?:void|[A-Za-z0-9_<>, ?]+)\s+([A-Za-z][A-Za-z0-9_]*)\s*\(",
            re.MULTILINE,
        )
        matches.extend((match.group(1), match.start()) for match in method_re.finditer(text))
        matches.extend(
            (f"dynamic-{_slug(match.group(1))}", match.start())
            for match in re.finditer(r"dynamicTest\(\s*\"([^\"]+)\"", text)
        )
        for method, offset in sorted(set(matches), key=lambda row: (row[1], row[0])):
            source_line = _line_number(text, offset)
            official_text = _semantic_window(text, source_line)
            selector = f"{selector_prefix}#{method}" if not method.startswith("dynamic-") else selector_prefix
            argv = ["./mvnw", "-o"]
            argv.append(f"-Dit.test={selector}" if integration else f"-Dtest={selector}")
            argv.append("verify" if integration else "test")
            records.append(
                {
                    "title": f"{class_name} {method}",
                    "root_cause": f"upstream-test:{selector}",
                    "source_path": relative,
                    "source_line": source_line,
                    "source_kind": "upstream_executable_test",
                    "source_sha256": sha256_bytes(raw),
                    "cwe": _unique_explicit_cwe(official_text),
                    "mechanism_truth": _explicit_mechanism_truth(official_text),
                    "oracle": _command(argv, network_policy="isolated_loopback"),
                    "official_text": official_text,
                }
            )
    return records


def _discover_juice(root: Path) -> list[dict[str, Any]]:
    relative = "data/static/challenges.yml"
    text, raw = _read_utf8(root, relative, label="Juice Shop challenge metadata")
    starts = [match.start() for match in re.finditer(r"(?m)^-\s*$", text)]
    starts.append(len(text))
    records: list[dict[str, Any]] = []
    for start, end in zip(starts, starts[1:]):
        block = text[start:end]
        name = re.search(r"(?m)^\s+name:\s*['\"]?(.+?)['\"]?\s*$", block)
        key = re.search(r"(?m)^\s+key:\s*([A-Za-z0-9_-]+)\s*$", block)
        category = re.search(r"(?m)^\s+category:\s*['\"]?(.+?)['\"]?\s*$", block)
        if not name or not key:
            continue
        title = name.group(1).replace("''", "'").strip("'\"")
        source_line = _line_number(text, start + key.start())
        official_text = _semantic_window(text, source_line)
        records.append(
            {
                "title": title,
                "root_cause": f"challenge-key:{key.group(1)}",
                "source_path": relative,
                "source_line": source_line,
                "source_kind": "official_challenge_metadata",
                "source_sha256": sha256_bytes(raw),
                "cwe": _unique_explicit_cwe(official_text),
                "mechanism_truth": _explicit_mechanism_truth(official_text),
                "oracle": None,
                "category": category.group(1).strip("'\"") if category else "",
                "official_text": official_text,
            }
        )
    return records


def _discover_markdown_challenges(root: Path) -> list[dict[str, Any]]:
    relative = "docs/challenges.md"
    text, raw = _read_utf8(root, relative, label="crAPI challenge metadata")
    records: list[dict[str, Any]] = []
    current_category = ""
    for match in re.finditer(r"(?m)^(##|###)\s+(.+?)\s*$", text):
        level, title = match.group(1), match.group(2).strip()
        if level == "##":
            current_category = title
            continue
        if not re.match(r"Challenge\s+[0-9]+\b", title, re.IGNORECASE):
            continue
        number = re.search(r"[0-9]+", title)
        source_line = _line_number(text, match.start())
        official_text = _semantic_window(text, source_line)
        records.append(
            {
                "title": title,
                "root_cause": f"challenge-number:{number.group(0) if number else _slug(title)}",
                "source_path": relative,
                "source_line": source_line,
                "source_kind": "official_challenge_metadata",
                "source_sha256": sha256_bytes(raw),
                "cwe": _unique_explicit_cwe(official_text),
                "mechanism_truth": _explicit_mechanism_truth(official_text),
                "oracle": None,
                "category": current_category,
                "official_text": official_text,
            }
        )
    return records


def _discover_pygoat(root: Path) -> list[dict[str, Any]]:
    relative = "challenge/challenge.json"
    text, raw = _read_utf8(root, relative, label="PyGoat challenge metadata")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("PyGoat challenge metadata is invalid JSON") from exc
    if not isinstance(payload, list):
        raise ValueError("PyGoat challenge metadata must be an array")
    records: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        title = item["name"]
        offset = text.find(json.dumps(title))
        if offset < 0:
            offset = text.find(title)
        source_line = _line_number(text, max(offset, 0))
        official_text = _semantic_window(text, source_line)
        records.append(
            {
                "title": title,
                "root_cause": f"challenge-name:{_slug(title)}",
                "source_path": relative,
                "source_line": source_line,
                "source_kind": "official_challenge_metadata",
                "source_sha256": sha256_bytes(raw),
                "cwe": _unique_explicit_cwe(official_text),
                "mechanism_truth": _explicit_mechanism_truth(official_text),
                "oracle": None,
                "official_text": official_text,
            }
        )
    return records


def _discover_nodegoat(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted((root / "app/views/tutorial").glob("*.html"), key=lambda item: item.name.casefold()):
        relative = path.relative_to(root).as_posix()
        text, raw = _read_utf8(root, relative, label="NodeGoat tutorial metadata")
        title_match = re.search(r"\{\%\s*block\s+title\s*\%\}(.+?)\{\%\s*endblock\s*\%\}", text, re.DOTALL)
        title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else path.stem
        official_text = _semantic_window(text, 1)
        records.append(
            {
                "title": title,
                "root_cause": f"tutorial:{path.stem.casefold()}",
                "source_path": relative,
                "source_line": 1,
                "source_kind": "official_vulnerability_tutorial",
                "source_sha256": sha256_bytes(raw),
                "cwe": _unique_explicit_cwe(official_text),
                "mechanism_truth": _explicit_mechanism_truth(official_text),
                "oracle": None,
                "official_text": official_text,
            }
        )
    return records


def _discover(app_id: str, root: Path) -> list[dict[str, Any]]:
    if app_id == "juice-shop":
        return _discover_juice(root)
    if app_id == "crapi":
        return _discover_markdown_challenges(root)
    if app_id == "pygoat":
        return _discover_pygoat(root)
    if app_id == "nodegoat":
        return _discover_nodegoat(root)
    if app_id == "webgoat":
        return _discover_java_tests(root, "src/it/java/**/*IntegrationTest.java", integration=True)
    if app_id == "wrongsecrets":
        return _discover_java_tests(root, "src/test/java/**/Challenge*Test.java", integration=False)
    raise ValueError(f"unsupported L2 app: {app_id}")


def _candidate(
    app_id: str,
    receipt: dict[str, Any],
    receipt_sha256: str,
    record: dict[str, Any],
    calculator_id: str,
    calculator_sha256: str,
) -> dict[str, Any]:
    primary, applicable = _plane_for(
        record["title"], record["root_cause"], record.get("category", ""), record["source_path"]
    )
    official_text = record.get("official_text", record["title"])
    cvss = _cvss_from_official_text(official_text, calculator_id, calculator_sha256)
    cwe = _unique_explicit_cwe(official_text)
    mechanism_truth = _explicit_mechanism_truth(official_text)
    expected_disposition = (
        "block" if cvss["severity"] == "critical" else "warn" if cvss["severity"] == "high" else None
    )
    identity_material = "\0".join(
        (
            receipt["lineage_id"],
            record["source_path"],
            str(record["source_line"]),
            record["source_sha256"],
        )
    )
    source_root_cause_identity = sha256_bytes(
        ("k_guard_l2_source_root_cause.v1\0" + identity_material).encode("utf-8")
    )
    scenario_id = f"{app_id}:{_slug(record['root_cause'])}:{source_root_cause_identity[:16]}"
    candidate = {
        "scenario_id": scenario_id,
        "app_id": app_id,
        "app_lineage": {
            "lineage_id": receipt["lineage_id"],
            "repository_id": receipt["repository_id"],
            "commit": receipt["commit"],
            "commit_tree": receipt["commit_tree"],
            "source_tree_sha256": receipt["source_tree_sha256"],
        },
        "source_root_cause_identity": source_root_cause_identity,
        "root_cause": record["root_cause"],
        "official_source": {
            "path": record["source_path"],
            "line": record["source_line"],
            "content_sha256": record["source_sha256"],
            "kind": record["source_kind"],
        },
        "cwe": cwe,
        "primary_plane": primary,
        "applicable_planes": applicable,
        "cvss_v4": cvss,
        "mechanism_truth": mechanism_truth,
        "expected_disposition": expected_disposition,
        "oracle": record["oracle"],
        "negative_control": None,
        "state_reset": None,
        "source_receipt_sha256": receipt_sha256,
        "scanner_output_observed": False,
        "admission": "HOLD",
        "deficits": [],
    }
    candidate["deficits"] = _candidate_deficits(candidate)
    if not candidate["deficits"]:
        candidate["admission"] = "PASS"
    return candidate


def _command_deficits(value: Any, *, label: str) -> list[str]:
    if value is None:
        return [f"{label}_missing"]
    if not isinstance(value, dict):
        return [f"{label}_malformed"]
    required = {
        "argv", "cwd", "kind", "network_policy", "expected_exit_code", "expected_http_status",
        "expected_body_sha256", "expected_result_sha256",
    }
    if set(value) != required:
        return [f"{label}_malformed"]
    argv = value.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(part, str) or not part or len(part) > 500 or UNSAFE_COMMAND_RE.search(part) for part in argv)
    ):
        return [f"{label}_unsafe"]
    if argv[0] not in ALLOWED_EXECUTABLES or any(UNSAFE_DOCKER_ARG_RE.search(part) for part in argv):
        return [f"{label}_unsafe"]
    if value.get("cwd") != "." or value.get("network_policy") not in NETWORK_POLICIES:
        return [f"{label}_unsafe"]
    kind = value.get("kind")
    if kind not in COMMAND_KINDS:
        return [f"{label}_malformed"]
    deficits: list[str] = []
    exit_code = value.get("expected_exit_code")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool) or not 0 <= exit_code <= 255:
        deficits.append(f"{label}_expected_exit_missing")
    elif label in {"oracle", "state_reset"} and exit_code != 0:
        deficits.append(f"{label}_expected_exit_missing")
    status = value.get("expected_http_status")
    body_digest = value.get("expected_body_sha256")
    if kind == "http":
        if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
            deficits.append(f"{label}_expected_status_missing")
        if not isinstance(body_digest, str) or SHA256_RE.fullmatch(body_digest) is None:
            deficits.append(f"{label}_expected_body_sha256_missing")
    elif status is not None or body_digest is not None:
        return [f"{label}_malformed"]
    for field in ("expected_result_sha256",):
        digest = value.get(field)
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            deficits.append(f"{label}_{field}_missing")
    return deficits


def _command_outcome_projection(value: Any) -> tuple[Any, ...] | None:
    if not isinstance(value, dict):
        return None
    return tuple(
        value.get(field)
        for field in (
            "kind",
            "expected_exit_code",
            "expected_http_status",
            "expected_body_sha256",
            "expected_result_sha256",
        )
    )


def _candidate_deficits(candidate: dict[str, Any]) -> list[str]:
    deficits: list[str] = []
    if not isinstance(candidate.get("cwe"), str) or not re.fullmatch(r"CWE-[1-9][0-9]*", candidate["cwe"] or ""):
        deficits.append("cwe_missing")
    cvss = candidate.get("cvss_v4")
    if not isinstance(cvss, dict) or not cvss.get("vector") or not cvss.get("score") or cvss.get("severity") not in SEVERITIES:
        deficits.append("cvss_v4_high_critical_missing")
    if candidate.get("mechanism_truth") != "present":
        deficits.append("mechanism_truth_not_present")
    if candidate.get("expected_disposition") not in {"block", "warn"}:
        deficits.append("expected_disposition_missing")
    if isinstance(cvss, dict) and cvss.get("severity") == "critical" and candidate.get("expected_disposition") != "block":
        deficits.append("critical_not_blocking")
    oracle_deficits = _command_deficits(candidate.get("oracle"), label="oracle")
    negative_deficits = _command_deficits(candidate.get("negative_control"), label="negative_control")
    reset_deficits = _command_deficits(candidate.get("state_reset"), label="state_reset")
    deficits.extend(oracle_deficits)
    deficits.extend(negative_deficits)
    deficits.extend(reset_deficits)
    if not oracle_deficits and not negative_deficits:
        if _command_outcome_projection(candidate.get("oracle")) == _command_outcome_projection(
            candidate.get("negative_control")
        ):
            deficits.append("negative_control_not_distinguishing")
    return sorted(set(deficits))


def _validate_cvss_v4(value: Any, expected_calculator_binding_sha256: str) -> None:
    required = {
        "vector", "score", "severity", "calculator_id", "calculator_binding_sha256", "source"
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("scenario CVSS v4 contract is malformed")
    if value.get("calculator_binding_sha256") != expected_calculator_binding_sha256:
        raise ValueError("scenario CVSS full-source calculator binding is invalid")
    vector = value.get("vector")
    score = value.get("score")
    severity = value.get("severity")
    if vector is None and score is None and severity is None and value.get("source") is None:
        return
    if vector is not None:
        if not isinstance(vector, str) or not vector.startswith("CVSS:4.0/"):
            raise ValueError("scenario CVSS v4 vector is invalid")
        components: dict[str, str] = {}
        for component in vector.split("/")[1:]:
            if component.count(":") != 1:
                raise ValueError("scenario CVSS v4 vector is invalid")
            metric, metric_value = component.split(":", 1)
            if metric in components or metric not in CVSS_BASE_VALUES or metric_value not in CVSS_BASE_VALUES[metric]:
                raise ValueError("scenario CVSS v4 vector is invalid")
            components[metric] = metric_value
        if tuple(components) != CVSS_BASE_ORDER:
            raise ValueError("scenario CVSS v4 vector must be complete and canonical")
    if score is not None:
        if not isinstance(score, str) or re.fullmatch(r"(?:10\.0|[0-9]\.[0-9])", score) is None:
            raise ValueError("scenario CVSS v4 score is invalid")
        whole, _separator, fraction = score.partition(".")
        numeric = int(whole) * 10 + int(fraction)
        expected_severity = "critical" if numeric >= 90 else "high" if numeric >= 70 else None
        if severity != expected_severity:
            raise ValueError("scenario CVSS v4 severity differs from score")
    elif severity is not None:
        raise ValueError("scenario CVSS v4 severity lacks a score")
    if not isinstance(value.get("calculator_id"), str) or not value["calculator_id"]:
        raise ValueError("scenario CVSS calculator id is missing")
    if (vector is not None or score is not None) and value.get("source") not in {
        "official_source_text",
        "source_bound_benchmark_profile",
    }:
        raise ValueError("scenario CVSS v4 value is not bound to official source text")


def _summary(candidates: list[dict[str, Any]], receipts: list[dict[str, Any]]) -> dict[str, Any]:
    scenarios = [row for row in candidates if row["admission"] == "PASS"]
    represented = sorted({row["app_id"] for row in scenarios})
    critical = sum(row["cvss_v4"]["severity"] == "critical" for row in scenarios)
    deficit_counts = Counter(deficit for row in candidates for deficit in row["deficits"])
    oracle_missing = sum(any(item.startswith("oracle_") for item in row["deficits"]) for row in candidates)
    gates = {
        "all_six_apps_represented": represented == list(EXPECTED_APPS),
        "high_critical_scenarios_at_least_120": len(scenarios) >= 120,
        "critical_scenarios_at_least_30": critical >= 30,
        "no_oracle_missing_or_uncertain": oracle_missing == 0,
        "unique_source_root_cause_identities": len({row["source_root_cause_identity"] for row in candidates}) == len(candidates),
        "all_source_receipts_blob_exact": all(
            receipt["source_worktree_clean"] is True
            and receipt["physical_bytes_match_git_blobs"] is True
            and receipt["index_tree_match"] is True
            for receipt in receipts
        ),
        "scanner_output_unobserved": all(row["scanner_output_observed"] is False for row in candidates),
    }
    return {
        "candidate_count": len(candidates),
        "admitted_high_critical_scenario_count": len(scenarios),
        "critical_scenario_count": critical,
        "admitted_apps": represented,
        "required_apps": list(EXPECTED_APPS),
        "oracle_missing_candidate_count": oracle_missing,
        "oracle_uncertain_candidate_count": 0,
        "deficits_by_code": dict(sorted(deficit_counts.items())),
        "gates": gates,
        "status": "PASS" if all(gates.values()) else "HOLD",
    }


def _load_webgoat_execution_evidence_adapter() -> tuple[Any, str, str]:
    directory = Path(__file__).resolve(strict=True).parent
    adapter, adapter_sha256 = _load_module(
        directory / "derive_l2_webgoat_idor_execution_evidence.py",
        "k_guard_l2_oracle_execution_evidence_adapter",
    )
    replay_sha256 = sha256_bytes((directory / "replay_l2_webgoat_idor.py").read_bytes())
    return adapter, adapter_sha256, replay_sha256


def _load_webgoat_cvss_evidence_adapter() -> tuple[Any, str]:
    directory = Path(__file__).resolve(strict=True).parent
    return _load_module(
        directory / "derive_l2_webgoat_idor_cvss_evidence.py",
        "k_guard_l2_oracle_cvss_evidence_adapter",
    )


def _load_webgoat_state_reset_evidence_adapter() -> tuple[Any, str]:
    directory = Path(__file__).resolve(strict=True).parent
    return _load_module(
        directory / "derive_l2_webgoat_idor_state_reset_evidence.py",
        "k_guard_l2_oracle_state_reset_evidence_adapter",
    )


def _load_webgoat_missing_function_ac_execution_evidence_adapter() -> tuple[Any, str, str]:
    directory = Path(__file__).resolve(strict=True).parent
    adapter, adapter_sha256 = _load_module(
        directory / "derive_l2_webgoat_missing_function_ac_execution_evidence.py",
        "k_guard_l2_missing_function_ac_execution_evidence_adapter",
    )
    replay_sha256 = sha256_bytes(
        (directory / "replay_l2_webgoat_missing_function_ac.py").read_bytes()
    )
    return adapter, adapter_sha256, replay_sha256


def _load_webgoat_missing_function_ac_cwe_evidence_adapter() -> tuple[Any, str]:
    directory = Path(__file__).resolve(strict=True).parent
    return _load_module(
        directory / "derive_l2_webgoat_missing_function_ac_cwe_evidence.py",
        "k_guard_l2_missing_function_ac_cwe_evidence_adapter",
    )


def _load_webgoat_missing_function_ac_cvss_evidence_adapter() -> tuple[Any, str]:
    directory = Path(__file__).resolve(strict=True).parent
    return _load_module(
        directory / "derive_l2_webgoat_missing_function_ac_cvss_evidence.py",
        "k_guard_l2_missing_function_ac_cvss_evidence_adapter",
    )


def _load_webgoat_missing_function_ac_state_reset_evidence_adapter() -> tuple[Any, str]:
    directory = Path(__file__).resolve(strict=True).parent
    return _load_module(
        directory / "derive_l2_webgoat_missing_function_ac_state_reset_evidence.py",
        "k_guard_l2_missing_function_ac_state_reset_evidence_adapter",
    )


def _load_webgoat_sql_injection_advanced_execution_evidence_adapter() -> tuple[Any, str, str]:
    directory = Path(__file__).resolve(strict=True).parent
    adapter, adapter_sha256 = _load_module(
        directory / "derive_l2_webgoat_sql_injection_advanced_execution_evidence.py",
        "k_guard_l2_sql_injection_advanced_execution_evidence_adapter",
    )
    replay_sha256 = sha256_bytes(
        (directory / "replay_l2_webgoat_sql_injection_advanced.py").read_bytes()
    )
    return adapter, adapter_sha256, replay_sha256


def _load_webgoat_sql_injection_advanced_cwe_evidence_adapter() -> tuple[Any, str]:
    directory = Path(__file__).resolve(strict=True).parent
    return _load_module(
        directory / "derive_l2_webgoat_sql_injection_advanced_cwe_evidence.py",
        "k_guard_l2_sql_injection_advanced_cwe_evidence_adapter",
    )


def _load_webgoat_sql_injection_advanced_cvss_evidence_adapter() -> tuple[Any, str]:
    directory = Path(__file__).resolve(strict=True).parent
    return _load_module(
        directory / "derive_l2_webgoat_sql_injection_advanced_cvss_evidence.py",
        "k_guard_l2_sql_injection_advanced_cvss_evidence_adapter",
    )


def _load_webgoat_sql_injection_advanced_state_reset_evidence_adapter() -> tuple[Any, str]:
    directory = Path(__file__).resolve(strict=True).parent
    return _load_module(
        directory / "derive_l2_webgoat_sql_injection_advanced_state_reset_evidence.py",
        "k_guard_l2_sql_injection_advanced_state_reset_evidence_adapter",
    )


def _empty_execution_evidence() -> dict[str, Any]:
    return {
        "status": "NONE",
        "evidence_sha256": None,
        "evidence_schema": None,
        "adapter_sha256": None,
        "replay_contract_sha256": None,
        "scenario_id": None,
        "source_root_cause_identity": None,
        "oracle_result_sha256": None,
        "negative_control_result_sha256": None,
        "registry_state_reset_admitted": False,
        "raw_returned": False,
    }


def _empty_cvss_evidence() -> dict[str, Any]:
    return {
        "status": "NONE",
        "evidence_sha256": None,
        "evidence_schema": None,
        "adapter_sha256": None,
        "source_cwe_evidence_sha256": None,
        "source_execution_evidence_sha256": None,
        "scenario_id": None,
        "source_root_cause_identity": None,
        "registry_classification_attached": False,
        "registry_scenario_admitted": False,
        "raw_returned": False,
    }


def _empty_state_reset_evidence() -> dict[str, Any]:
    return {
        "status": "NONE",
        "evidence_sha256": None,
        "evidence_schema": None,
        "adapter_sha256": None,
        "source_execution_evidence_sha256": None,
        "positive_execution_receipt_sha256": None,
        "negative_control_receipt_sha256": None,
        "scenario_id": None,
        "source_root_cause_identity": None,
        "registry_state_reset_attached": False,
        "registry_scenario_admitted": False,
        "raw_returned": False,
    }


def _empty_missing_function_ac_evidence() -> dict[str, Any]:
    return {
        "status": "NONE",
        "execution_evidence_sha256": None,
        "execution_evidence_schema": None,
        "execution_adapter_sha256": None,
        "replay_contract_sha256": None,
        "cwe_evidence_sha256": None,
        "cwe_evidence_schema": None,
        "cwe_adapter_sha256": None,
        "cvss_evidence_sha256": None,
        "cvss_evidence_schema": None,
        "cvss_adapter_sha256": None,
        "state_reset_evidence_sha256": None,
        "state_reset_evidence_schema": None,
        "state_reset_adapter_sha256": None,
        "state_reset_positive_execution_receipt_sha256": None,
        "state_reset_negative_control_receipt_sha256": None,
        "scenario_id": None,
        "source_root_cause_identity": None,
        "source_receipt_equivalence": None,
        "cwe": None,
        "mechanism_truth": None,
        "registry_execution_attached": False,
        "registry_classification_attached": False,
        "registry_cvss_attached": False,
        "registry_state_reset_attached": False,
        "registry_scenario_admitted": False,
        "raw_returned": False,
    }


def _empty_sql_injection_advanced_evidence() -> dict[str, Any]:
    return {
        "status": "NONE",
        "execution_evidence_sha256": None,
        "execution_evidence_schema": None,
        "execution_adapter_sha256": None,
        "replay_contract_sha256": None,
        "cwe_evidence_sha256": None,
        "cwe_evidence_schema": None,
        "cwe_adapter_sha256": None,
        "cvss_evidence_sha256": None,
        "cvss_evidence_schema": None,
        "cvss_adapter_sha256": None,
        "state_reset_evidence_sha256": None,
        "state_reset_evidence_schema": None,
        "state_reset_adapter_sha256": None,
        "state_reset_positive_execution_receipt_sha256": None,
        "state_reset_negative_control_receipt_sha256": None,
        "scenario_id": None,
        "source_root_cause_identity": None,
        "source_receipt_equivalence": None,
        "cwe": None,
        "mechanism_truth": None,
        "registry_execution_attached": False,
        "registry_classification_attached": False,
        "registry_cvss_attached": False,
        "registry_state_reset_attached": False,
        "registry_scenario_admitted": False,
        "raw_returned": False,
    }


def _validate_webgoat_evidence_selector(selector: Any, *, label: str) -> None:
    required_selector = {
        "root_cause",
        "source_path",
        "source_line",
        "source_content_sha256",
        "source_root_cause_identity",
        "scenario_id",
        "raw_returned",
    }
    if (
        not isinstance(selector, dict)
        or set(selector) != required_selector
        or selector.get("raw_returned") is not False
        or not isinstance(selector.get("root_cause"), str)
        or not selector["root_cause"]
        or not isinstance(selector.get("source_path"), str)
        or not selector["source_path"]
        or not isinstance(selector.get("source_line"), int)
        or isinstance(selector.get("source_line"), bool)
        or selector["source_line"] < 1
        or not isinstance(selector.get("scenario_id"), str)
        or not selector["scenario_id"]
        or not isinstance(selector.get("source_root_cause_identity"), str)
        or SHA256_RE.fullmatch(selector["source_root_cause_identity"]) is None
        or not isinstance(selector.get("source_content_sha256"), str)
        or SHA256_RE.fullmatch(selector["source_content_sha256"]) is None
    ):
        raise ValueError(f"{label} selector is malformed")


def _webgoat_semantic_source_equivalence(
    source: Any,
    webgoat_receipt: dict[str, Any],
    *,
    label: str,
) -> tuple[dict[str, Any], str]:
    expected_source = {
        "app_id": "webgoat",
        "repository_id": webgoat_receipt["repository_id"],
        "commit": webgoat_receipt["commit"],
        "commit_tree": webgoat_receipt["commit_tree"],
        "source_tree_sha256": webgoat_receipt["source_tree_sha256"],
        "lineage_id": webgoat_receipt["lineage_id"],
    }
    if (
        not isinstance(source, dict)
        or any(source.get(key) != value for key, value in expected_source.items())
        or source.get("raw_returned") is not False
        or not isinstance(source.get("source_receipt_sha256"), str)
        or SHA256_RE.fullmatch(source["source_receipt_sha256"]) is None
        or not isinstance(source.get("source_receipt_semantic_sha256"), str)
        or SHA256_RE.fullmatch(source["source_receipt_semantic_sha256"]) is None
    ):
        raise ValueError(f"{label} source is not bound to the registry source receipt")
    if source["source_receipt_semantic_sha256"] != webgoat_receipt["receipt_semantic_sha256"]:
        raise ValueError(f"{label} source receipt semantic fingerprint is not current")
    if source["source_receipt_sha256"] == webgoat_receipt["receipt_sha256"]:
        equivalence = "exact_raw_receipt"
    elif source["source_receipt_sha256"] == webgoat_receipt["observed_receipt_sha256"]:
        equivalence = "informational_porcelain_variance"
    else:
        raise ValueError(f"{label} source receipt is not an authoritative registry receipt")
    selector = source.get("selector")
    _validate_webgoat_evidence_selector(selector, label=label)
    return dict(selector), equivalence


def _load_missing_function_ac_evidence(
    execution_evidence_path: Path | None,
    cwe_evidence_path: Path | None,
    cvss_evidence_path: Path | None,
    state_reset_evidence_path: Path | None,
    state_reset_positive_receipt_path: Path | None,
    state_reset_negative_receipt_path: Path | None,
    webgoat_receipt: dict[str, Any],
    *,
    calculator_root: Path,
    calculator_receipt_path: Path,
    calculator_id: str,
    calculator_binding_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if (
        execution_evidence_path is None
        and cwe_evidence_path is None
        and cvss_evidence_path is None
        and state_reset_evidence_path is None
        and state_reset_positive_receipt_path is None
        and state_reset_negative_receipt_path is None
    ):
        return _empty_missing_function_ac_evidence(), None
    if execution_evidence_path is None or cwe_evidence_path is None:
        raise ValueError(
            "MissingFunctionAC registry attachment requires both execution and CWE evidence"
        )
    if state_reset_evidence_path is None and (
        state_reset_positive_receipt_path is not None
        or state_reset_negative_receipt_path is not None
    ):
        raise ValueError(
            "MissingFunctionAC state-reset receipts require a state-reset evidence attachment"
        )
    if state_reset_evidence_path is not None and (
        state_reset_positive_receipt_path is None
        or state_reset_negative_receipt_path is None
    ):
        raise ValueError(
            "MissingFunctionAC state-reset evidence requires bound positive and negative receipts"
        )

    execution_payload, execution_raw = _load_canonical_object(
        execution_evidence_path, label="MissingFunctionAC execution evidence"
    )
    cwe_payload, cwe_raw = _load_canonical_object(
        cwe_evidence_path, label="MissingFunctionAC CWE evidence"
    )
    execution_adapter, execution_adapter_sha256, replay_sha256 = (
        _load_webgoat_missing_function_ac_execution_evidence_adapter()
    )
    cwe_adapter, cwe_adapter_sha256 = _load_webgoat_missing_function_ac_cwe_evidence_adapter()
    try:
        execution_adapter.validate_execution_evidence(execution_payload)
        cwe_adapter.validate_cwe_evidence(cwe_payload)
    except Exception as exc:
        raise ValueError("MissingFunctionAC evidence does not satisfy its typed adapter contract") from exc
    if execution_payload.get("schema") != WEBGOAT_MISSING_FUNCTION_AC_EXECUTION_EVIDENCE_SCHEMA:
        raise ValueError("MissingFunctionAC execution evidence schema is not supported")
    if cwe_payload.get("schema") != WEBGOAT_MISSING_FUNCTION_AC_CWE_EVIDENCE_SCHEMA:
        raise ValueError("MissingFunctionAC CWE evidence schema is not supported")

    execution_provenance = execution_payload.get("tool_provenance")
    if not isinstance(execution_provenance, dict) or {
        "adapter_sha256": execution_provenance.get("adapter_sha256"),
        "replay_contract_sha256": execution_provenance.get("replay_contract_sha256"),
        "raw_returned": execution_provenance.get("raw_returned"),
    } != {
        "adapter_sha256": execution_adapter_sha256,
        "replay_contract_sha256": replay_sha256,
        "raw_returned": False,
    }:
        raise ValueError("MissingFunctionAC execution evidence tool provenance is not current")
    cwe_provenance = cwe_payload.get("tool_provenance")
    if not isinstance(cwe_provenance, dict) or {
        "adapter_sha256": cwe_provenance.get("adapter_sha256"),
        "raw_returned": cwe_provenance.get("raw_returned"),
    } != {
        "adapter_sha256": cwe_adapter_sha256,
        "raw_returned": False,
    }:
        raise ValueError("MissingFunctionAC CWE evidence tool provenance is not current")

    execution_source = execution_payload.get("source")
    cwe_source = cwe_payload.get("source")
    execution_selector, equivalence = _webgoat_semantic_source_equivalence(
        execution_source, webgoat_receipt, label="MissingFunctionAC execution evidence"
    )
    cwe_selector, cwe_equivalence = _webgoat_semantic_source_equivalence(
        cwe_source, webgoat_receipt, label="MissingFunctionAC CWE evidence"
    )
    if execution_source != cwe_source or execution_selector != cwe_selector or equivalence != cwe_equivalence:
        raise ValueError("MissingFunctionAC execution and CWE evidence must bind one exact source selector")

    execution_boundary = execution_payload.get("claim_boundary")
    required_execution_boundary = {
        "execution_result_pair_proven": True,
        "source_bound_execution_selector_proven": True,
        "process_oracle_contract_proven": True,
        "generated_control_pair_only": True,
        "independent_upstream_fixed_revision_proven": False,
        "scanner_accuracy_proven": False,
        "severity_or_cwe_admitted": False,
        "tp_fp_fn_admitted": False,
        "registry_evidence_integrated": False,
        "l2_gate_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }
    if not isinstance(execution_boundary, dict) or any(
        execution_boundary.get(key) != value for key, value in required_execution_boundary.items()
    ):
        raise ValueError("MissingFunctionAC execution evidence claim boundary is invalid")
    reset = execution_payload.get("state_reset_evidence")
    if not isinstance(reset, dict) or reset.get("registry_state_reset_admitted") is not False:
        raise ValueError("MissingFunctionAC execution evidence cannot self-admit registry state reset")
    oracle = execution_payload.get("oracle")
    negative_control = execution_payload.get("negative_control")
    if (
        _command_deficits(oracle, label="oracle")
        or _command_deficits(negative_control, label="negative_control")
        or not isinstance(oracle, dict)
        or not isinstance(negative_control, dict)
        or oracle.get("kind") != "process"
        or negative_control.get("kind") != "process"
        or oracle.get("expected_exit_code") != 0
        or negative_control.get("expected_exit_code") != 1
        or oracle.get("expected_result_sha256") == negative_control.get("expected_result_sha256")
    ):
        raise ValueError("MissingFunctionAC execution evidence process pair is invalid")

    classification = cwe_payload.get("classification")
    cwe = classification.get("cwe") if isinstance(classification, dict) else None
    source_evidence = classification.get("source_evidence") if isinstance(classification, dict) else None
    test_evidence = source_evidence.get("test") if isinstance(source_evidence, dict) else None
    if (
        not isinstance(classification, dict)
        or not isinstance(cwe, dict)
        or not isinstance(cwe.get("id"), str)
        or re.fullmatch(r"CWE-[1-9][0-9]*", cwe["id"]) is None
        or classification.get("mechanism_truth") != "present"
        or classification.get("cvss_v4") is not None
        or classification.get("expected_disposition") is not None
        or not isinstance(test_evidence, dict)
        or test_evidence.get("path") != execution_selector["source_path"]
        or test_evidence.get("content_sha256") != execution_selector["source_content_sha256"]
        or test_evidence.get("raw_returned") is not False
    ):
        raise ValueError("MissingFunctionAC CWE classification is not source-bound")
    cwe_boundary = cwe_payload.get("claim_boundary")
    required_cwe_boundary = {
        "source_bound_cwe_mapping_supported": True,
        "source_bound_mechanism_truth_supported": True,
        "source_bound_cvss_profile_proven": False,
        "customer_deployment_severity_admitted": False,
        "scanner_accuracy_proven": False,
        "tp_fp_fn_admitted": False,
        "registry_evidence_integrated": False,
        "l2_gate_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }
    if not isinstance(cwe_boundary, dict) or any(
        cwe_boundary.get(key) != value for key, value in required_cwe_boundary.items()
    ):
        raise ValueError("MissingFunctionAC CWE evidence claim boundary is invalid")
    if execution_payload.get("release_gate_passed") is not False or cwe_payload.get("release_gate_passed") is not False:
        raise ValueError("MissingFunctionAC evidence cannot self-admit the release gate")

    execution_evidence_sha256 = sha256_bytes(execution_raw)
    cwe_evidence_sha256 = sha256_bytes(cwe_raw)
    cvss_evidence_sha256: str | None = None
    cvss_evidence_schema: str | None = None
    cvss_adapter_sha256: str | None = None
    cvss_attachment: dict[str, Any] | None = None
    if cvss_evidence_path is not None:
        cvss_payload, cvss_raw = _load_canonical_object(
            cvss_evidence_path, label="MissingFunctionAC CVSS evidence"
        )
        cvss_adapter, cvss_adapter_sha256 = (
            _load_webgoat_missing_function_ac_cvss_evidence_adapter()
        )
        try:
            expected_cvss_payload = cvss_adapter.derive_cvss_evidence(
                cwe_evidence_path,
                execution_evidence_path,
                calculator_root,
                calculator_receipt_path,
            )
            cvss_adapter.validate_cvss_evidence(cvss_payload)
        except Exception as exc:
            raise ValueError(
                "MissingFunctionAC CVSS evidence does not satisfy its source-bound adapter contract"
            ) from exc
        if cvss_payload != expected_cvss_payload:
            raise ValueError(
                "MissingFunctionAC CVSS evidence does not reproduce from its exact bound inputs"
            )
        if cvss_payload.get("schema") != WEBGOAT_MISSING_FUNCTION_AC_CVSS_EVIDENCE_SCHEMA:
            raise ValueError("MissingFunctionAC CVSS evidence schema is not supported")
        provenance = cvss_payload.get("tool_provenance")
        expected_registry_sha256 = sha256_bytes(Path(__file__).resolve(strict=True).read_bytes())
        if not isinstance(provenance, dict) or {
            "adapter_sha256": provenance.get("adapter_sha256"),
            "registry_contract_sha256": provenance.get("registry_contract_sha256"),
            "raw_returned": provenance.get("raw_returned"),
        } != {
            "adapter_sha256": cvss_adapter_sha256,
            "registry_contract_sha256": expected_registry_sha256,
            "raw_returned": False,
        }:
            raise ValueError("MissingFunctionAC CVSS evidence tool provenance is not current")
        expected_cvss_source = {
            "selector": execution_selector,
            "cwe_evidence_sha256": cwe_evidence_sha256,
            "cwe_adapter_sha256": cwe_adapter_sha256,
            "execution_evidence_sha256": execution_evidence_sha256,
            "execution_adapter_sha256": execution_adapter_sha256,
            "raw_returned": False,
        }
        if cvss_payload.get("source") != expected_cvss_source:
            raise ValueError("MissingFunctionAC CVSS evidence is not bound to the supplied source evidence")
        profile = cvss_payload.get("cvss_profile")
        if not isinstance(profile, dict) or {
            "scope": profile.get("scope"),
            "vector": profile.get("vector"),
            "score": profile.get("score"),
            "severity": profile.get("severity"),
            "expected_disposition": profile.get("expected_disposition"),
            "raw_returned": profile.get("raw_returned"),
        } != {
            "scope": "pinned_webgoat_benchmark_scenario",
            "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
            "score": "7.1",
            "severity": "high",
            "expected_disposition": "warn",
            "raw_returned": False,
        }:
            raise ValueError("MissingFunctionAC CVSS benchmark profile is invalid")
        calculator = profile.get("calculator")
        if not isinstance(calculator, dict) or {
            "id": calculator.get("id"),
            "binding_sha256": calculator.get("binding_sha256"),
            "source_receipt_sha256": calculator.get("source_receipt_sha256"),
            "raw_returned": calculator.get("raw_returned"),
        } != {
            "id": calculator_id,
            "binding_sha256": calculator_binding_sha256,
            "source_receipt_sha256": LOCKED_CALCULATOR_RECEIPT_SHA256,
            "raw_returned": False,
        }:
            raise ValueError(
                "MissingFunctionAC CVSS evidence calculator is not bound to the registry calculator"
            )
        required_cvss_boundary = {
            "benchmark_cvss_profile_proven": True,
            "customer_deployment_severity_admitted": False,
            "registry_evidence_integrated": False,
            "scanner_accuracy_proven": False,
            "tp_fp_fn_admitted": False,
            "l2_gate_admitted": False,
            "release_gate_admitted": False,
            "raw_returned": False,
        }
        if cvss_payload.get("claim_boundary") != required_cvss_boundary:
            raise ValueError("MissingFunctionAC CVSS evidence claim boundary is invalid")
        if cvss_payload.get("release_gate_passed") is not False:
            raise ValueError("MissingFunctionAC CVSS evidence cannot self-admit the release gate")
        candidate_cvss = {
            "vector": profile["vector"],
            "score": profile["score"],
            "severity": profile["severity"],
            "calculator_id": calculator_id,
            "calculator_binding_sha256": calculator_binding_sha256,
            "source": "source_bound_benchmark_profile",
        }
        _validate_cvss_v4(candidate_cvss, calculator_binding_sha256)
        cvss_evidence_sha256 = sha256_bytes(cvss_raw)
        cvss_evidence_schema = cvss_payload["schema"]
        cvss_attachment = {
            "cvss_v4": candidate_cvss,
            "expected_disposition": "warn",
        }
    state_reset_evidence_sha256: str | None = None
    state_reset_evidence_schema: str | None = None
    state_reset_adapter_sha256: str | None = None
    state_reset_positive_execution_receipt_sha256: str | None = None
    state_reset_negative_control_receipt_sha256: str | None = None
    state_reset_attachment: dict[str, Any] | None = None
    if state_reset_evidence_path is not None:
        assert state_reset_positive_receipt_path is not None
        assert state_reset_negative_receipt_path is not None
        state_reset_payload, state_reset_raw = _load_canonical_object(
            state_reset_evidence_path, label="MissingFunctionAC state-reset evidence"
        )
        state_reset_adapter, state_reset_adapter_sha256 = (
            _load_webgoat_missing_function_ac_state_reset_evidence_adapter()
        )
        try:
            expected_state_reset_payload = state_reset_adapter.derive_state_reset_evidence(
                execution_evidence_path,
                state_reset_positive_receipt_path,
                state_reset_negative_receipt_path,
            )
            state_reset_adapter.validate_state_reset_evidence(state_reset_payload)
        except Exception as exc:
            raise ValueError(
                "MissingFunctionAC state-reset evidence does not satisfy its typed adapter contract"
            ) from exc
        if state_reset_payload != expected_state_reset_payload:
            raise ValueError(
                "MissingFunctionAC state-reset evidence does not reproduce from its exact bound inputs"
            )
        if state_reset_payload.get("schema") != WEBGOAT_MISSING_FUNCTION_AC_STATE_RESET_EVIDENCE_SCHEMA:
            raise ValueError("MissingFunctionAC state-reset evidence schema is not supported")
        provenance = state_reset_payload.get("tool_provenance")
        expected_registry_sha256 = sha256_bytes(Path(__file__).resolve(strict=True).read_bytes())
        if not isinstance(provenance, dict) or {
            "adapter_sha256": provenance.get("adapter_sha256"),
            "execution_adapter_sha256": provenance.get("execution_adapter_sha256"),
            "replay_contract_sha256": provenance.get("replay_contract_sha256"),
            "registry_contract_sha256": provenance.get("registry_contract_sha256"),
            "raw_returned": provenance.get("raw_returned"),
        } != {
            "adapter_sha256": state_reset_adapter_sha256,
            "execution_adapter_sha256": execution_adapter_sha256,
            "replay_contract_sha256": replay_sha256,
            "registry_contract_sha256": expected_registry_sha256,
            "raw_returned": False,
        }:
            raise ValueError("MissingFunctionAC state-reset evidence tool provenance is not current")
        state_reset_selector, state_reset_equivalence = _webgoat_semantic_source_equivalence(
            state_reset_payload.get("source"),
            webgoat_receipt,
            label="MissingFunctionAC state-reset evidence",
        )
        if (
            state_reset_payload.get("source") != execution_source
            or state_reset_selector != execution_selector
            or state_reset_equivalence != equivalence
        ):
            raise ValueError(
                "MissingFunctionAC state-reset evidence must bind the same exact source selector"
            )
        inputs = state_reset_payload.get("inputs")
        state_reset_positive_execution_receipt_sha256 = sha256_bytes(
            state_reset_positive_receipt_path.read_bytes()
        )
        state_reset_negative_control_receipt_sha256 = sha256_bytes(
            state_reset_negative_receipt_path.read_bytes()
        )
        if not isinstance(inputs, dict) or {
            "execution_evidence_sha256": inputs.get("execution_evidence_sha256"),
            "positive_execution_receipt_sha256": inputs.get("positive_execution_receipt_sha256"),
            "negative_control_receipt_sha256": inputs.get("negative_control_receipt_sha256"),
            "raw_returned": inputs.get("raw_returned"),
        } != {
            "execution_evidence_sha256": execution_evidence_sha256,
            "positive_execution_receipt_sha256": state_reset_positive_execution_receipt_sha256,
            "negative_control_receipt_sha256": state_reset_negative_control_receipt_sha256,
            "raw_returned": False,
        }:
            raise ValueError("MissingFunctionAC state-reset evidence input chain is invalid")
        state_reset_boundary = state_reset_payload.get("claim_boundary")
        required_state_reset_boundary = {
            "state_reset_cleanup_chain_proven": True,
            "registry_state_reset_admitted": False,
            "registry_scenario_admitted": False,
            "scanner_accuracy_proven": False,
            "severity_or_cwe_admitted": False,
            "tp_fp_fn_admitted": False,
            "l2_gate_admitted": False,
            "release_gate_admitted": False,
            "raw_returned": False,
        }
        if state_reset_boundary != required_state_reset_boundary:
            raise ValueError(
                "MissingFunctionAC state-reset evidence cannot self-admit a registry scenario"
            )
        state_reset = state_reset_payload.get("state_reset")
        if _command_deficits(state_reset, label="state_reset"):
            raise ValueError("MissingFunctionAC state-reset evidence command is invalid")
        if not isinstance(state_reset, dict) or state_reset.get("kind") != "process":
            raise ValueError("MissingFunctionAC state-reset evidence must provide a process oracle")
        if state_reset_payload.get("release_gate_passed") is not False:
            raise ValueError("MissingFunctionAC state-reset evidence cannot self-admit the release gate")
        state_reset_evidence_sha256 = sha256_bytes(state_reset_raw)
        state_reset_evidence_schema = state_reset_payload["schema"]
        state_reset_attachment = copy.deepcopy(state_reset)

    attachment = {
        "selector": execution_selector,
        "oracle": copy.deepcopy(oracle),
        "negative_control": copy.deepcopy(negative_control),
        "cwe": cwe["id"],
        "mechanism_truth": "present",
        "cvss_v4": cvss_attachment["cvss_v4"] if cvss_attachment is not None else None,
        "expected_disposition": (
            cvss_attachment["expected_disposition"] if cvss_attachment is not None else None
        ),
        "state_reset": state_reset_attachment,
    }
    return {
        "status": "ATTACHED",
        "execution_evidence_sha256": execution_evidence_sha256,
        "execution_evidence_schema": execution_payload["schema"],
        "execution_adapter_sha256": execution_adapter_sha256,
        "replay_contract_sha256": replay_sha256,
        "cwe_evidence_sha256": cwe_evidence_sha256,
        "cwe_evidence_schema": cwe_payload["schema"],
        "cwe_adapter_sha256": cwe_adapter_sha256,
        "cvss_evidence_sha256": cvss_evidence_sha256,
        "cvss_evidence_schema": cvss_evidence_schema,
        "cvss_adapter_sha256": cvss_adapter_sha256,
        "state_reset_evidence_sha256": state_reset_evidence_sha256,
        "state_reset_evidence_schema": state_reset_evidence_schema,
        "state_reset_adapter_sha256": state_reset_adapter_sha256,
        "state_reset_positive_execution_receipt_sha256": state_reset_positive_execution_receipt_sha256,
        "state_reset_negative_control_receipt_sha256": state_reset_negative_control_receipt_sha256,
        "scenario_id": execution_selector["scenario_id"],
        "source_root_cause_identity": execution_selector["source_root_cause_identity"],
        "source_receipt_equivalence": equivalence,
        "cwe": cwe["id"],
        "mechanism_truth": "present",
        "registry_execution_attached": True,
        "registry_classification_attached": True,
        "registry_cvss_attached": cvss_attachment is not None,
        "registry_state_reset_attached": state_reset_attachment is not None,
        "registry_scenario_admitted": False,
        "raw_returned": False,
    }, attachment


def _load_sql_injection_advanced_evidence(
    execution_evidence_path: Path | None,
    cwe_evidence_path: Path | None,
    cvss_evidence_path: Path | None,
    state_reset_evidence_path: Path | None,
    positive_receipt_path: Path | None,
    negative_receipt_path: Path | None,
    webgoat_receipt: dict[str, Any],
    *,
    webgoat_source_root: Path,
    webgoat_source_receipt_path: Path,
    calculator_root: Path,
    calculator_receipt_path: Path,
    calculator_id: str,
    calculator_binding_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    supplied = (
        execution_evidence_path,
        cwe_evidence_path,
        cvss_evidence_path,
        state_reset_evidence_path,
        positive_receipt_path,
        negative_receipt_path,
    )
    if all(path is None for path in supplied):
        return _empty_sql_injection_advanced_evidence(), None
    if any(path is None for path in supplied):
        raise ValueError(
            "SQL Injection Advanced registry attachment requires execution, CWE, CVSS, "
            "state-reset, positive, and negative evidence"
        )
    assert execution_evidence_path is not None
    assert cwe_evidence_path is not None
    assert cvss_evidence_path is not None
    assert state_reset_evidence_path is not None
    assert positive_receipt_path is not None
    assert negative_receipt_path is not None

    execution_payload, execution_raw = _load_canonical_object(
        execution_evidence_path, label="SQL Injection Advanced execution evidence"
    )
    cwe_payload, cwe_raw = _load_canonical_object(
        cwe_evidence_path, label="SQL Injection Advanced CWE evidence"
    )
    cvss_payload, cvss_raw = _load_canonical_object(
        cvss_evidence_path, label="SQL Injection Advanced CVSS evidence"
    )
    state_reset_payload, state_reset_raw = _load_canonical_object(
        state_reset_evidence_path, label="SQL Injection Advanced state-reset evidence"
    )

    execution_adapter, execution_adapter_sha256, replay_sha256 = (
        _load_webgoat_sql_injection_advanced_execution_evidence_adapter()
    )
    cwe_adapter, cwe_adapter_sha256 = _load_webgoat_sql_injection_advanced_cwe_evidence_adapter()
    cvss_adapter, cvss_adapter_sha256 = _load_webgoat_sql_injection_advanced_cvss_evidence_adapter()
    state_reset_adapter, state_reset_adapter_sha256 = (
        _load_webgoat_sql_injection_advanced_state_reset_evidence_adapter()
    )
    try:
        expected_execution_payload = execution_adapter.derive_execution_evidence(
            webgoat_source_receipt_path, positive_receipt_path, negative_receipt_path
        )
        expected_cwe_payload = cwe_adapter.derive_cwe_evidence(
            webgoat_source_root, webgoat_source_receipt_path
        )
        expected_cvss_payload = cvss_adapter.derive_cvss_evidence(
            cwe_evidence_path,
            execution_evidence_path,
            calculator_root,
            calculator_receipt_path,
        )
        expected_state_reset_payload = state_reset_adapter.derive_state_reset_evidence(
            execution_evidence_path, positive_receipt_path, negative_receipt_path
        )
        execution_adapter.validate_execution_evidence(execution_payload)
        cwe_adapter.validate_cwe_evidence(cwe_payload)
        cvss_adapter.validate_cvss_evidence(cvss_payload)
        state_reset_adapter.validate_state_reset_evidence(state_reset_payload)
    except Exception as exc:
        raise ValueError(
            "SQL Injection Advanced evidence does not satisfy its typed adapter contract"
        ) from exc
    if execution_payload != expected_execution_payload:
        raise ValueError("SQL Injection Advanced execution evidence is not reproducible")
    if cwe_payload != expected_cwe_payload:
        raise ValueError("SQL Injection Advanced CWE evidence is not reproducible")
    if cvss_payload != expected_cvss_payload:
        raise ValueError("SQL Injection Advanced CVSS evidence is not reproducible")
    if state_reset_payload != expected_state_reset_payload:
        raise ValueError("SQL Injection Advanced state-reset evidence is not reproducible")
    if {
        execution_payload.get("schema"),
        cwe_payload.get("schema"),
        cvss_payload.get("schema"),
        state_reset_payload.get("schema"),
    } != {
        WEBGOAT_SQL_INJECTION_ADVANCED_EXECUTION_EVIDENCE_SCHEMA,
        WEBGOAT_SQL_INJECTION_ADVANCED_CWE_EVIDENCE_SCHEMA,
        WEBGOAT_SQL_INJECTION_ADVANCED_CVSS_EVIDENCE_SCHEMA,
        WEBGOAT_SQL_INJECTION_ADVANCED_STATE_RESET_EVIDENCE_SCHEMA,
    }:
        raise ValueError("SQL Injection Advanced evidence schema is not supported")

    source = execution_payload.get("source")
    selector, equivalence = _webgoat_semantic_source_equivalence(
        source, webgoat_receipt, label="SQL Injection Advanced execution evidence"
    )
    if (
        cwe_payload.get("source") != source
        or state_reset_payload.get("source") != source
        or cvss_payload.get("source", {}).get("selector") != selector
    ):
        raise ValueError("SQL Injection Advanced evidence must bind one exact source selector")
    classification = cwe_payload.get("classification")
    cwe = classification.get("cwe") if isinstance(classification, dict) else None
    if (
        not isinstance(cwe, dict)
        or cwe.get("id") != "CWE-89"
        or classification.get("mechanism_truth") != "present"
        or execution_payload.get("release_gate_passed") is not False
        or cwe_payload.get("release_gate_passed") is not False
        or cvss_payload.get("release_gate_passed") is not False
        or state_reset_payload.get("release_gate_passed") is not False
    ):
        raise ValueError("SQL Injection Advanced claim boundary is invalid")
    execution_pair = execution_payload.get("execution_pair")
    oracle = execution_payload.get("oracle")
    negative_control = execution_payload.get("negative_control")
    if (
        not isinstance(execution_pair, dict)
        or _command_deficits(oracle, label="SQL Injection Advanced oracle")
        or _command_deficits(negative_control, label="SQL Injection Advanced negative control")
        or not isinstance(oracle, dict)
        or not isinstance(negative_control, dict)
        or oracle.get("expected_exit_code") != 0
        or negative_control.get("expected_exit_code") != 1
        or oracle.get("expected_result_sha256")
        == negative_control.get("expected_result_sha256")
    ):
        raise ValueError("SQL Injection Advanced execution process pair is invalid")
    profile = cvss_payload.get("cvss_profile")
    expected_profile = {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "score": "7.1",
        "severity": "high",
        "expected_disposition": "warn",
    }
    if not isinstance(profile, dict) or any(
        profile.get(key) != value for key, value in expected_profile.items()
    ):
        raise ValueError("SQL Injection Advanced CVSS benchmark profile is invalid")
    candidate_cvss = {
        "vector": profile["vector"],
        "score": profile["score"],
        "severity": profile["severity"],
        "calculator_id": calculator_id,
        "calculator_binding_sha256": calculator_binding_sha256,
        "source": "source_bound_benchmark_profile",
    }
    _validate_cvss_v4(candidate_cvss, calculator_binding_sha256)
    state_reset = state_reset_payload.get("state_reset")
    inputs = state_reset_payload.get("inputs")
    positive_receipt_sha256 = sha256_bytes(positive_receipt_path.read_bytes())
    negative_receipt_sha256 = sha256_bytes(negative_receipt_path.read_bytes())
    if (
        _command_deficits(state_reset, label="SQL Injection Advanced state reset")
        or not isinstance(state_reset, dict)
        or not isinstance(inputs, dict)
        or inputs
        != {
            "execution_evidence_sha256": sha256_bytes(execution_raw),
            "positive_execution_receipt_sha256": positive_receipt_sha256,
            "negative_control_receipt_sha256": negative_receipt_sha256,
            "raw_returned": False,
        }
    ):
        raise ValueError("SQL Injection Advanced state-reset evidence input chain is invalid")

    attachment = {
        "selector": selector,
        "oracle": copy.deepcopy(oracle),
        "negative_control": copy.deepcopy(negative_control),
        "cwe": cwe["id"],
        "mechanism_truth": "present",
        "cvss_v4": candidate_cvss,
        "expected_disposition": "warn",
        "state_reset": copy.deepcopy(state_reset),
    }
    return {
        "status": "ATTACHED",
        "execution_evidence_sha256": sha256_bytes(execution_raw),
        "execution_evidence_schema": execution_payload["schema"],
        "execution_adapter_sha256": execution_adapter_sha256,
        "replay_contract_sha256": replay_sha256,
        "cwe_evidence_sha256": sha256_bytes(cwe_raw),
        "cwe_evidence_schema": cwe_payload["schema"],
        "cwe_adapter_sha256": cwe_adapter_sha256,
        "cvss_evidence_sha256": sha256_bytes(cvss_raw),
        "cvss_evidence_schema": cvss_payload["schema"],
        "cvss_adapter_sha256": cvss_adapter_sha256,
        "state_reset_evidence_sha256": sha256_bytes(state_reset_raw),
        "state_reset_evidence_schema": state_reset_payload["schema"],
        "state_reset_adapter_sha256": state_reset_adapter_sha256,
        "state_reset_positive_execution_receipt_sha256": positive_receipt_sha256,
        "state_reset_negative_control_receipt_sha256": negative_receipt_sha256,
        "scenario_id": selector["scenario_id"],
        "source_root_cause_identity": selector["source_root_cause_identity"],
        "source_receipt_equivalence": equivalence,
        "cwe": cwe["id"],
        "mechanism_truth": "present",
        "registry_execution_attached": True,
        "registry_classification_attached": True,
        "registry_cvss_attached": True,
        "registry_state_reset_attached": True,
        "registry_scenario_admitted": False,
        "raw_returned": False,
    }, attachment


def _load_execution_evidence(
    path: Path | None, webgoat_receipt: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if path is None:
        return _empty_execution_evidence(), None
    payload, raw = _load_canonical_object(path, label="WebGoat execution evidence")
    adapter, adapter_sha256, replay_sha256 = _load_webgoat_execution_evidence_adapter()
    try:
        adapter.validate_execution_evidence(payload)
    except Exception as exc:
        raise ValueError("WebGoat execution evidence does not satisfy its adapter contract") from exc
    if payload.get("schema") != WEBGOAT_EXECUTION_EVIDENCE_SCHEMA:
        raise ValueError("WebGoat execution evidence schema is not supported")
    provenance = payload.get("tool_provenance")
    if not isinstance(provenance, dict) or {
        "adapter_sha256": provenance.get("adapter_sha256"),
        "replay_contract_sha256": provenance.get("replay_contract_sha256"),
        "raw_returned": provenance.get("raw_returned"),
    } != {
        "adapter_sha256": adapter_sha256,
        "replay_contract_sha256": replay_sha256,
        "raw_returned": False,
    }:
        raise ValueError("WebGoat execution evidence tool provenance is not current")
    source = payload.get("source")
    expected_source = {
        "app_id": "webgoat",
        "repository_id": webgoat_receipt["repository_id"],
        "commit": webgoat_receipt["commit"],
        "commit_tree": webgoat_receipt["commit_tree"],
        "source_tree_sha256": webgoat_receipt["source_tree_sha256"],
        "source_receipt_sha256": webgoat_receipt["receipt_sha256"],
        "lineage_id": webgoat_receipt["lineage_id"],
    }
    if not isinstance(source, dict) or any(source.get(key) != value for key, value in expected_source.items()):
        raise ValueError("WebGoat execution evidence source is not bound to the registry source receipt")
    selector = source.get("selector")
    required_selector = {
        "root_cause",
        "source_path",
        "source_line",
        "source_content_sha256",
        "source_root_cause_identity",
        "scenario_id",
        "raw_returned",
    }
    if (
        not isinstance(selector, dict)
        or set(selector) != required_selector
        or selector.get("raw_returned") is not False
        or not isinstance(selector.get("root_cause"), str)
        or not isinstance(selector.get("source_path"), str)
        or not isinstance(selector.get("source_line"), int)
        or isinstance(selector.get("source_line"), bool)
        or selector["source_line"] < 1
        or not isinstance(selector.get("scenario_id"), str)
        or not isinstance(selector.get("source_root_cause_identity"), str)
        or SHA256_RE.fullmatch(selector["source_root_cause_identity"]) is None
        or not isinstance(selector.get("source_content_sha256"), str)
        or SHA256_RE.fullmatch(selector["source_content_sha256"]) is None
    ):
        raise ValueError("WebGoat execution evidence selector is malformed")
    boundary = payload.get("claim_boundary")
    required_boundary = {
        "execution_result_pair_proven": True,
        "source_bound_execution_selector_proven": True,
        "process_oracle_contract_proven": True,
        "state_reset_evidence_proven": True,
        "registry_state_reset_admitted": False,
        "generated_control_pair_only": True,
        "independent_upstream_fixed_revision_proven": False,
        "scanner_accuracy_proven": False,
        "severity_or_cwe_admitted": False,
        "tp_fp_fn_admitted": False,
        "registry_evidence_integrated": False,
        "l2_gate_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }
    if boundary != required_boundary:
        raise ValueError("WebGoat execution evidence claim boundary is invalid")
    reset = payload.get("state_reset_evidence")
    if not isinstance(reset, dict) or reset.get("registry_state_reset_admitted") is not False:
        raise ValueError("WebGoat execution evidence cannot self-admit registry state reset")
    oracle = payload.get("oracle")
    negative_control = payload.get("negative_control")
    if (
        _command_deficits(oracle, label="oracle")
        or _command_deficits(negative_control, label="negative_control")
        or not isinstance(oracle, dict)
        or not isinstance(negative_control, dict)
        or oracle.get("kind") != "process"
        or negative_control.get("kind") != "process"
        or oracle.get("expected_exit_code") != 0
        or negative_control.get("expected_exit_code") != 1
        or oracle.get("expected_result_sha256") == negative_control.get("expected_result_sha256")
    ):
        raise ValueError("WebGoat execution evidence process pair is invalid")
    attachment = {
        "status": "ATTACHED",
        "evidence_sha256": sha256_bytes(raw),
        "evidence_schema": payload["schema"],
        "adapter_sha256": adapter_sha256,
        "replay_contract_sha256": replay_sha256,
        "scenario_id": selector["scenario_id"],
        "source_root_cause_identity": selector["source_root_cause_identity"],
        "oracle_result_sha256": oracle["expected_result_sha256"],
        "negative_control_result_sha256": negative_control["expected_result_sha256"],
        "registry_state_reset_admitted": False,
        "raw_returned": False,
    }
    return attachment, {
        "selector": dict(selector),
        "oracle": copy.deepcopy(oracle),
        "negative_control": copy.deepcopy(negative_control),
    }


def _load_cvss_evidence(
    cvss_evidence_path: Path | None,
    cwe_evidence_path: Path | None,
    execution_evidence_path: Path | None,
    execution_evidence: dict[str, Any],
    *,
    calculator_root: Path,
    calculator_receipt_path: Path,
    calculator_id: str,
    calculator_binding_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if cvss_evidence_path is None:
        if cwe_evidence_path is not None:
            raise ValueError("WebGoat CWE evidence requires a CVSS evidence attachment")
        return _empty_cvss_evidence(), None
    if cwe_evidence_path is None or execution_evidence_path is None:
        raise ValueError("WebGoat CVSS evidence requires the bound CWE and execution evidence inputs")
    if execution_evidence.get("status") != "ATTACHED":
        raise ValueError("WebGoat CVSS evidence requires an attached execution evidence input")

    payload, raw = _load_canonical_object(cvss_evidence_path, label="WebGoat CVSS evidence")
    adapter, adapter_sha256 = _load_webgoat_cvss_evidence_adapter()
    try:
        expected_payload = adapter.derive_cvss_evidence(
            cwe_evidence_path,
            execution_evidence_path,
            calculator_root,
            calculator_receipt_path,
        )
        adapter.validate_cvss_evidence(payload)
        cwe_payload, cwe_evidence_sha256, _cwe_adapter_sha256 = adapter._load_cwe_evidence(
            cwe_evidence_path
        )
    except Exception as exc:
        raise ValueError("WebGoat CVSS evidence does not satisfy its source-bound adapter contract") from exc
    if payload != expected_payload:
        raise ValueError("WebGoat CVSS evidence does not reproduce from its exact bound inputs")
    if payload.get("schema") != WEBGOAT_CVSS_EVIDENCE_SCHEMA:
        raise ValueError("WebGoat CVSS evidence schema is not supported")

    provenance = payload.get("tool_provenance")
    expected_registry_sha256 = sha256_bytes(Path(__file__).resolve(strict=True).read_bytes())
    if not isinstance(provenance, dict) or {
        "adapter_sha256": provenance.get("adapter_sha256"),
        "registry_contract_sha256": provenance.get("registry_contract_sha256"),
        "raw_returned": provenance.get("raw_returned"),
    } != {
        "adapter_sha256": adapter_sha256,
        "registry_contract_sha256": expected_registry_sha256,
        "raw_returned": False,
    }:
        raise ValueError("WebGoat CVSS evidence tool provenance is not current")

    source = payload.get("source")
    if not isinstance(source, dict):
        raise ValueError("WebGoat CVSS evidence source is malformed")
    selector = source.get("selector")
    required_selector = {
        "root_cause",
        "source_path",
        "source_line",
        "source_content_sha256",
        "source_root_cause_identity",
        "scenario_id",
        "raw_returned",
    }
    if (
        not isinstance(selector, dict)
        or set(selector) != required_selector
        or selector.get("raw_returned") is not False
        or not isinstance(selector.get("root_cause"), str)
        or not isinstance(selector.get("source_path"), str)
        or not isinstance(selector.get("source_line"), int)
        or isinstance(selector.get("source_line"), bool)
        or selector["source_line"] < 1
        or not isinstance(selector.get("scenario_id"), str)
        or not isinstance(selector.get("source_root_cause_identity"), str)
        or SHA256_RE.fullmatch(selector["source_root_cause_identity"]) is None
        or not isinstance(selector.get("source_content_sha256"), str)
        or SHA256_RE.fullmatch(selector["source_content_sha256"]) is None
        or source.get("cwe_evidence_sha256") != cwe_evidence_sha256
        or source.get("execution_evidence_sha256") != execution_evidence["evidence_sha256"]
        or source.get("raw_returned") is not False
    ):
        raise ValueError("WebGoat CVSS evidence is not bound to the supplied source evidence")

    classification = cwe_payload.get("classification")
    cwe = classification.get("cwe") if isinstance(classification, dict) else None
    if (
        not isinstance(classification, dict)
        or not isinstance(cwe, dict)
        or cwe.get("id") != "CWE-639"
        or classification.get("mechanism_truth") != "present"
    ):
        raise ValueError("WebGoat CVSS evidence lacks the bound CWE-639 mechanism classification")
    profile = payload.get("cvss_profile")
    if not isinstance(profile, dict) or {
        "scope": profile.get("scope"),
        "vector": profile.get("vector"),
        "score": profile.get("score"),
        "severity": profile.get("severity"),
        "expected_disposition": profile.get("expected_disposition"),
        "raw_returned": profile.get("raw_returned"),
    } != {
        "scope": "pinned_webgoat_benchmark_scenario",
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
        "score": "7.1",
        "severity": "high",
        "expected_disposition": "warn",
        "raw_returned": False,
    }:
        raise ValueError("WebGoat CVSS benchmark profile is invalid")
    calculator = profile.get("calculator")
    if not isinstance(calculator, dict) or {
        "id": calculator.get("id"),
        "binding_sha256": calculator.get("binding_sha256"),
        "source_receipt_sha256": calculator.get("source_receipt_sha256"),
        "raw_returned": calculator.get("raw_returned"),
    } != {
        "id": calculator_id,
        "binding_sha256": calculator_binding_sha256,
        "source_receipt_sha256": LOCKED_CALCULATOR_RECEIPT_SHA256,
        "raw_returned": False,
    }:
        raise ValueError("WebGoat CVSS evidence calculator is not bound to the registry calculator")
    boundary = payload.get("claim_boundary")
    required_boundary = {
        "benchmark_cvss_profile_proven": True,
        "customer_deployment_severity_admitted": False,
        "registry_evidence_integrated": False,
        "scanner_accuracy_proven": False,
        "tp_fp_fn_admitted": False,
        "l2_gate_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }
    if not isinstance(boundary, dict) or any(boundary.get(key) != value for key, value in required_boundary.items()):
        raise ValueError("WebGoat CVSS evidence claim boundary is invalid")

    candidate_cvss = {
        "vector": profile["vector"],
        "score": profile["score"],
        "severity": profile["severity"],
        "calculator_id": calculator_id,
        "calculator_binding_sha256": calculator_binding_sha256,
        "source": "source_bound_benchmark_profile",
    }
    _validate_cvss_v4(candidate_cvss, calculator_binding_sha256)
    attachment = {
        "selector": dict(selector),
        "cwe": "CWE-639",
        "cvss_v4": candidate_cvss,
        "mechanism_truth": "present",
        "expected_disposition": "warn",
    }
    return {
        "status": "ATTACHED",
        "evidence_sha256": sha256_bytes(raw),
        "evidence_schema": payload["schema"],
        "adapter_sha256": adapter_sha256,
        "source_cwe_evidence_sha256": cwe_evidence_sha256,
        "source_execution_evidence_sha256": execution_evidence["evidence_sha256"],
        "scenario_id": selector["scenario_id"],
        "source_root_cause_identity": selector["source_root_cause_identity"],
        "registry_classification_attached": True,
        "registry_scenario_admitted": False,
        "raw_returned": False,
    }, attachment


def _load_state_reset_evidence(
    state_reset_evidence_path: Path | None,
    execution_evidence_path: Path | None,
    positive_receipt_path: Path | None,
    negative_receipt_path: Path | None,
    execution_evidence: dict[str, Any],
    webgoat_receipt: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if state_reset_evidence_path is None:
        if positive_receipt_path is not None or negative_receipt_path is not None:
            raise ValueError("WebGoat state-reset receipts require a state-reset evidence attachment")
        return _empty_state_reset_evidence(), None
    if (
        execution_evidence_path is None
        or positive_receipt_path is None
        or negative_receipt_path is None
    ):
        raise ValueError(
            "WebGoat state-reset evidence requires bound execution, positive, and negative inputs"
        )
    if execution_evidence.get("status") != "ATTACHED":
        raise ValueError("WebGoat state-reset evidence requires attached execution evidence")

    payload, raw = _load_canonical_object(
        state_reset_evidence_path, label="WebGoat state-reset evidence"
    )
    adapter, adapter_sha256 = _load_webgoat_state_reset_evidence_adapter()
    try:
        expected_payload = adapter.derive_state_reset_evidence(
            execution_evidence_path, positive_receipt_path, negative_receipt_path
        )
        adapter.validate_state_reset_evidence(payload)
    except Exception as exc:
        raise ValueError("WebGoat state-reset evidence does not satisfy its adapter contract") from exc
    if payload != expected_payload:
        raise ValueError("WebGoat state-reset evidence does not reproduce from its exact bound inputs")
    if payload.get("schema") != WEBGOAT_STATE_RESET_EVIDENCE_SCHEMA:
        raise ValueError("WebGoat state-reset evidence schema is not supported")

    provenance = payload.get("tool_provenance")
    expected_registry_sha256 = sha256_bytes(Path(__file__).resolve(strict=True).read_bytes())
    if not isinstance(provenance, dict) or {
        "adapter_sha256": provenance.get("adapter_sha256"),
        "registry_contract_sha256": provenance.get("registry_contract_sha256"),
        "raw_returned": provenance.get("raw_returned"),
    } != {
        "adapter_sha256": adapter_sha256,
        "registry_contract_sha256": expected_registry_sha256,
        "raw_returned": False,
    }:
        raise ValueError("WebGoat state-reset evidence tool provenance is not current")

    source = payload.get("source")
    expected_source = {
        "app_id": "webgoat",
        "repository_id": webgoat_receipt["repository_id"],
        "commit": webgoat_receipt["commit"],
        "commit_tree": webgoat_receipt["commit_tree"],
        "source_tree_sha256": webgoat_receipt["source_tree_sha256"],
        "source_receipt_sha256": webgoat_receipt["receipt_sha256"],
        "lineage_id": webgoat_receipt["lineage_id"],
        "raw_returned": False,
    }
    if not isinstance(source, dict) or any(source.get(key) != value for key, value in expected_source.items()):
        raise ValueError("WebGoat state-reset evidence source is not bound to the registry source receipt")
    selector = source.get("selector")
    required_selector = {
        "root_cause",
        "source_path",
        "source_line",
        "source_content_sha256",
        "source_root_cause_identity",
        "scenario_id",
        "raw_returned",
    }
    if (
        not isinstance(selector, dict)
        or set(selector) != required_selector
        or selector.get("raw_returned") is not False
        or selector.get("scenario_id") != execution_evidence["scenario_id"]
        or selector.get("source_root_cause_identity")
        != execution_evidence["source_root_cause_identity"]
        or not isinstance(selector.get("root_cause"), str)
        or not isinstance(selector.get("source_path"), str)
        or not isinstance(selector.get("source_line"), int)
        or isinstance(selector.get("source_line"), bool)
        or selector["source_line"] < 1
        or not isinstance(selector.get("source_content_sha256"), str)
        or SHA256_RE.fullmatch(selector["source_content_sha256"]) is None
    ):
        raise ValueError("WebGoat state-reset evidence selector is not bound to execution evidence")

    inputs = payload.get("inputs")
    if not isinstance(inputs, dict) or {
        "execution_evidence_sha256": inputs.get("execution_evidence_sha256"),
        "positive_execution_receipt_sha256": inputs.get("positive_execution_receipt_sha256"),
        "negative_control_receipt_sha256": inputs.get("negative_control_receipt_sha256"),
        "raw_returned": inputs.get("raw_returned"),
    } != {
        "execution_evidence_sha256": execution_evidence["evidence_sha256"],
        "positive_execution_receipt_sha256": sha256_bytes(positive_receipt_path.read_bytes()),
        "negative_control_receipt_sha256": sha256_bytes(negative_receipt_path.read_bytes()),
        "raw_returned": False,
    }:
        raise ValueError("WebGoat state-reset evidence input chain is invalid")
    boundary = payload.get("claim_boundary")
    required_boundary = {
        "state_reset_cleanup_chain_proven": True,
        "registry_state_reset_admitted": False,
        "registry_scenario_admitted": False,
        "scanner_accuracy_proven": False,
        "severity_or_cwe_admitted": False,
        "tp_fp_fn_admitted": False,
        "l2_gate_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }
    if boundary != required_boundary:
        raise ValueError("WebGoat state-reset evidence cannot self-admit a registry scenario")
    state_reset = payload.get("state_reset")
    if _command_deficits(state_reset, label="state_reset"):
        raise ValueError("WebGoat state-reset evidence command is invalid")
    if not isinstance(state_reset, dict) or state_reset.get("kind") != "process":
        raise ValueError("WebGoat state-reset evidence must provide a process oracle")

    attachment = {
        "selector": dict(selector),
        "state_reset": copy.deepcopy(state_reset),
    }
    return {
        "status": "ATTACHED",
        "evidence_sha256": sha256_bytes(raw),
        "evidence_schema": payload["schema"],
        "adapter_sha256": adapter_sha256,
        "source_execution_evidence_sha256": execution_evidence["evidence_sha256"],
        "positive_execution_receipt_sha256": inputs["positive_execution_receipt_sha256"],
        "negative_control_receipt_sha256": inputs["negative_control_receipt_sha256"],
        "scenario_id": selector["scenario_id"],
        "source_root_cause_identity": selector["source_root_cause_identity"],
        "registry_state_reset_attached": True,
        "registry_scenario_admitted": False,
        "raw_returned": False,
    }, attachment


def _apply_execution_evidence(candidates: list[dict[str, Any]], attachment: dict[str, Any] | None) -> None:
    if attachment is None:
        return
    selector = attachment["selector"]
    matches = [
        candidate
        for candidate in candidates
        if candidate["app_id"] == "webgoat"
        and candidate["scenario_id"] == selector["scenario_id"]
        and candidate["source_root_cause_identity"] == selector["source_root_cause_identity"]
    ]
    if len(matches) != 1:
        raise ValueError("WebGoat execution evidence does not select exactly one source candidate")
    candidate = matches[0]
    source = candidate["official_source"]
    if {
        "root_cause": candidate["root_cause"],
        "source_path": source["path"],
        "source_line": source["line"],
        "source_content_sha256": source["content_sha256"],
        "source_root_cause_identity": candidate["source_root_cause_identity"],
        "scenario_id": candidate["scenario_id"],
        "raw_returned": False,
    } != selector:
        raise ValueError("WebGoat execution evidence selector is not source-bound")
    if candidate["state_reset"] is not None:
        raise ValueError("WebGoat execution evidence cannot replace an existing state reset contract")
    candidate["oracle"] = attachment["oracle"]
    candidate["negative_control"] = attachment["negative_control"]
    candidate["deficits"] = _candidate_deficits(candidate)
    candidate["admission"] = "PASS" if not candidate["deficits"] else "HOLD"


def _apply_cvss_evidence(candidates: list[dict[str, Any]], attachment: dict[str, Any] | None) -> None:
    if attachment is None:
        return
    selector = attachment["selector"]
    matches = [
        candidate
        for candidate in candidates
        if candidate["app_id"] == "webgoat"
        and candidate["scenario_id"] == selector["scenario_id"]
        and candidate["source_root_cause_identity"] == selector["source_root_cause_identity"]
    ]
    if len(matches) != 1:
        raise ValueError("WebGoat CVSS evidence does not select exactly one source candidate")
    candidate = matches[0]
    source = candidate["official_source"]
    expected_selector = {
        "root_cause": candidate["root_cause"],
        "source_path": source["path"],
        "source_line": source["line"],
        "source_content_sha256": source["content_sha256"],
        "source_root_cause_identity": candidate["source_root_cause_identity"],
        "scenario_id": candidate["scenario_id"],
        "raw_returned": False,
    }
    if selector != expected_selector:
        raise ValueError("WebGoat CVSS evidence selector is not source-bound")
    existing_cvss = candidate["cvss_v4"]
    cvss_placeholder = (
        isinstance(existing_cvss, dict)
        and existing_cvss.get("vector") is None
        and existing_cvss.get("score") is None
        and existing_cvss.get("severity") is None
        and existing_cvss.get("source") is None
    )
    if (
        candidate["cwe"] not in {None, attachment["cwe"]}
        or candidate["mechanism_truth"] not in {None, attachment["mechanism_truth"]}
        or candidate["expected_disposition"] not in {None, attachment["expected_disposition"]}
        or (existing_cvss is not None and not cvss_placeholder)
    ):
        raise ValueError("WebGoat CVSS evidence cannot replace an existing source classification")
    candidate["cwe"] = attachment["cwe"]
    candidate["cvss_v4"] = copy.deepcopy(attachment["cvss_v4"])
    candidate["mechanism_truth"] = attachment["mechanism_truth"]
    candidate["expected_disposition"] = attachment["expected_disposition"]
    candidate["deficits"] = _candidate_deficits(candidate)
    candidate["admission"] = "PASS" if not candidate["deficits"] else "HOLD"


def _apply_state_reset_evidence(
    candidates: list[dict[str, Any]], attachment: dict[str, Any] | None
) -> None:
    if attachment is None:
        return
    selector = attachment["selector"]
    matches = [
        candidate
        for candidate in candidates
        if candidate["app_id"] == "webgoat"
        and candidate["scenario_id"] == selector["scenario_id"]
        and candidate["source_root_cause_identity"] == selector["source_root_cause_identity"]
    ]
    if len(matches) != 1:
        raise ValueError("WebGoat state-reset evidence does not select exactly one source candidate")
    candidate = matches[0]
    source = candidate["official_source"]
    expected_selector = {
        "root_cause": candidate["root_cause"],
        "source_path": source["path"],
        "source_line": source["line"],
        "source_content_sha256": source["content_sha256"],
        "source_root_cause_identity": candidate["source_root_cause_identity"],
        "scenario_id": candidate["scenario_id"],
        "raw_returned": False,
    }
    if selector != expected_selector:
        raise ValueError("WebGoat state-reset evidence selector is not source-bound")
    if candidate["oracle"] is None or candidate["negative_control"] is None:
        raise ValueError("WebGoat state-reset evidence requires the attached execution process pair")
    if candidate["state_reset"] is not None:
        raise ValueError("WebGoat state-reset evidence cannot replace an existing state-reset contract")
    candidate["state_reset"] = copy.deepcopy(attachment["state_reset"])
    candidate["deficits"] = _candidate_deficits(candidate)
    candidate["admission"] = "PASS" if not candidate["deficits"] else "HOLD"


def _apply_missing_function_ac_evidence(
    candidates: list[dict[str, Any]], attachment: dict[str, Any] | None
) -> None:
    if attachment is None:
        return
    selector = attachment["selector"]
    matches = [
        candidate
        for candidate in candidates
        if candidate["app_id"] == "webgoat"
        and candidate["scenario_id"] == selector["scenario_id"]
        and candidate["source_root_cause_identity"] == selector["source_root_cause_identity"]
    ]
    if len(matches) != 1:
        raise ValueError("MissingFunctionAC evidence does not select exactly one source candidate")
    candidate = matches[0]
    source = candidate["official_source"]
    expected_selector = {
        "root_cause": candidate["root_cause"],
        "source_path": source["path"],
        "source_line": source["line"],
        "source_content_sha256": source["content_sha256"],
        "source_root_cause_identity": candidate["source_root_cause_identity"],
        "scenario_id": candidate["scenario_id"],
        "raw_returned": False,
    }
    if selector != expected_selector:
        raise ValueError("MissingFunctionAC evidence selector is not source-bound")
    existing_oracle = candidate["oracle"]
    if (
        not isinstance(existing_oracle, dict)
        or existing_oracle.get("expected_result_sha256") is not None
        or candidate["negative_control"] is not None
        or candidate["state_reset"] is not None
    ):
        raise ValueError("MissingFunctionAC evidence cannot replace an existing execution contract")
    if (
        candidate["cwe"] not in {None, attachment["cwe"]}
        or candidate["mechanism_truth"] not in {None, attachment["mechanism_truth"]}
    ):
        raise ValueError("MissingFunctionAC evidence cannot replace an existing source classification")
    attached_cvss = attachment["cvss_v4"]
    attached_disposition = attachment["expected_disposition"]
    if attached_cvss is not None:
        existing_cvss = candidate["cvss_v4"]
        cvss_placeholder = (
            isinstance(existing_cvss, dict)
            and existing_cvss.get("vector") is None
            and existing_cvss.get("score") is None
            and existing_cvss.get("severity") is None
            and existing_cvss.get("source") is None
        )
        if (
            (existing_cvss is not None and not cvss_placeholder)
            or candidate["expected_disposition"] not in {None, attached_disposition}
        ):
            raise ValueError("MissingFunctionAC evidence cannot replace an existing CVSS classification")
    candidate["oracle"] = copy.deepcopy(attachment["oracle"])
    candidate["negative_control"] = copy.deepcopy(attachment["negative_control"])
    candidate["cwe"] = attachment["cwe"]
    candidate["mechanism_truth"] = attachment["mechanism_truth"]
    if attached_cvss is not None:
        candidate["cvss_v4"] = copy.deepcopy(attached_cvss)
        candidate["expected_disposition"] = attached_disposition
    if attachment["state_reset"] is not None:
        candidate["state_reset"] = copy.deepcopy(attachment["state_reset"])
    candidate["deficits"] = _candidate_deficits(candidate)
    candidate["admission"] = "PASS" if not candidate["deficits"] else "HOLD"


def _apply_sql_injection_advanced_evidence(
    candidates: list[dict[str, Any]], attachment: dict[str, Any] | None
) -> None:
    if attachment is None:
        return
    selector = attachment["selector"]
    matches = [
        candidate
        for candidate in candidates
        if candidate["app_id"] == "webgoat"
        and candidate["scenario_id"] == selector["scenario_id"]
        and candidate["source_root_cause_identity"] == selector["source_root_cause_identity"]
    ]
    if len(matches) != 1:
        raise ValueError("SQL Injection Advanced evidence does not select exactly one source candidate")
    candidate = matches[0]
    source = candidate["official_source"]
    expected_selector = {
        "root_cause": candidate["root_cause"],
        "source_path": source["path"],
        "source_line": source["line"],
        "source_content_sha256": source["content_sha256"],
        "source_root_cause_identity": candidate["source_root_cause_identity"],
        "scenario_id": candidate["scenario_id"],
        "raw_returned": False,
    }
    if selector != expected_selector:
        raise ValueError("SQL Injection Advanced evidence selector is not source-bound")
    existing_oracle = candidate["oracle"]
    if (
        not isinstance(existing_oracle, dict)
        or existing_oracle.get("expected_result_sha256") is not None
        or candidate["negative_control"] is not None
        or candidate["state_reset"] is not None
    ):
        raise ValueError("SQL Injection Advanced evidence cannot replace an existing execution contract")
    if (
        candidate["cwe"] not in {None, attachment["cwe"]}
        or candidate["mechanism_truth"] not in {None, attachment["mechanism_truth"]}
    ):
        raise ValueError("SQL Injection Advanced evidence cannot replace an existing source classification")
    existing_cvss = candidate["cvss_v4"]
    cvss_placeholder = (
        isinstance(existing_cvss, dict)
        and existing_cvss.get("vector") is None
        and existing_cvss.get("score") is None
        and existing_cvss.get("severity") is None
        and existing_cvss.get("source") is None
    )
    if (
        (existing_cvss is not None and not cvss_placeholder)
        or candidate["expected_disposition"] not in {None, attachment["expected_disposition"]}
    ):
        raise ValueError("SQL Injection Advanced evidence cannot replace an existing CVSS classification")
    candidate["oracle"] = copy.deepcopy(attachment["oracle"])
    candidate["negative_control"] = copy.deepcopy(attachment["negative_control"])
    candidate["cwe"] = attachment["cwe"]
    candidate["mechanism_truth"] = attachment["mechanism_truth"]
    candidate["cvss_v4"] = copy.deepcopy(attachment["cvss_v4"])
    candidate["expected_disposition"] = attachment["expected_disposition"]
    candidate["state_reset"] = copy.deepcopy(attachment["state_reset"])
    candidate["deficits"] = _candidate_deficits(candidate)
    candidate["admission"] = "PASS" if not candidate["deficits"] else "HOLD"


def _reextract_candidates(
    sources_root: Path,
    receipts: list[dict[str, Any]],
    source_receipts_dir: Path,
    calculator_id: str,
    calculator_binding_sha256: str,
    execution_evidence_path: Path | None,
    cwe_evidence_path: Path | None,
    cvss_evidence_path: Path | None,
    state_reset_evidence_path: Path | None,
    state_reset_positive_receipt_path: Path | None,
    state_reset_negative_receipt_path: Path | None,
    missing_function_ac_execution_evidence_path: Path | None,
    missing_function_ac_cwe_evidence_path: Path | None,
    missing_function_ac_cvss_evidence_path: Path | None,
    missing_function_ac_state_reset_evidence_path: Path | None,
    missing_function_ac_state_reset_positive_receipt_path: Path | None,
    missing_function_ac_state_reset_negative_receipt_path: Path | None,
    sql_injection_advanced_execution_evidence_path: Path | None,
    sql_injection_advanced_cwe_evidence_path: Path | None,
    sql_injection_advanced_cvss_evidence_path: Path | None,
    sql_injection_advanced_state_reset_evidence_path: Path | None,
    sql_injection_advanced_positive_receipt_path: Path | None,
    sql_injection_advanced_negative_receipt_path: Path | None,
    calculator_root: Path,
    calculator_receipt_path: Path,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    list[dict[str, Any]],
]:
    receipt_by_app = {receipt["app_id"]: receipt for receipt in receipts}
    execution_evidence, execution_attachment = _load_execution_evidence(
        execution_evidence_path, receipt_by_app["webgoat"]
    )
    cvss_evidence, cvss_attachment = _load_cvss_evidence(
        cvss_evidence_path,
        cwe_evidence_path,
        execution_evidence_path,
        execution_evidence,
        calculator_root=calculator_root,
        calculator_receipt_path=calculator_receipt_path,
        calculator_id=calculator_id,
        calculator_binding_sha256=calculator_binding_sha256,
    )
    state_reset_evidence, state_reset_attachment = _load_state_reset_evidence(
        state_reset_evidence_path,
        execution_evidence_path,
        state_reset_positive_receipt_path,
        state_reset_negative_receipt_path,
        execution_evidence,
        receipt_by_app["webgoat"],
    )
    missing_function_ac_evidence, missing_function_ac_attachment = _load_missing_function_ac_evidence(
        missing_function_ac_execution_evidence_path,
        missing_function_ac_cwe_evidence_path,
        missing_function_ac_cvss_evidence_path,
        missing_function_ac_state_reset_evidence_path,
        missing_function_ac_state_reset_positive_receipt_path,
        missing_function_ac_state_reset_negative_receipt_path,
        receipt_by_app["webgoat"],
        calculator_root=calculator_root,
        calculator_receipt_path=calculator_receipt_path,
        calculator_id=calculator_id,
        calculator_binding_sha256=calculator_binding_sha256,
    )
    sql_injection_advanced_evidence, sql_injection_advanced_attachment = (
        _load_sql_injection_advanced_evidence(
            sql_injection_advanced_execution_evidence_path,
            sql_injection_advanced_cwe_evidence_path,
            sql_injection_advanced_cvss_evidence_path,
            sql_injection_advanced_state_reset_evidence_path,
            sql_injection_advanced_positive_receipt_path,
            sql_injection_advanced_negative_receipt_path,
            receipt_by_app["webgoat"],
            webgoat_source_root=sources_root / "webgoat",
            webgoat_source_receipt_path=source_receipts_dir / "webgoat.json",
            calculator_root=calculator_root,
            calculator_receipt_path=calculator_receipt_path,
            calculator_id=calculator_id,
            calculator_binding_sha256=calculator_binding_sha256,
        )
    )
    candidates: list[dict[str, Any]] = []
    for app_id in EXPECTED_APPS:
        receipt = receipt_by_app[app_id]
        discovered = _discover(app_id, sources_root / app_id)
        if not discovered:
            raise ValueError(f"{app_id} did not yield any official challenge or upstream test rows")
        candidates.extend(
            _candidate(
                app_id,
                receipt,
                receipt["receipt_sha256"],
                record,
                calculator_id,
                calculator_binding_sha256,
            )
            for record in discovered
        )
    _apply_execution_evidence(candidates, execution_attachment)
    _apply_cvss_evidence(candidates, cvss_attachment)
    _apply_state_reset_evidence(candidates, state_reset_attachment)
    _apply_missing_function_ac_evidence(candidates, missing_function_ac_attachment)
    _apply_sql_injection_advanced_evidence(candidates, sql_injection_advanced_attachment)
    candidates.sort(key=lambda row: (row["app_id"], row["scenario_id"]))
    identities = [row["source_root_cause_identity"] for row in candidates]
    if len(identities) != len(set(identities)):
        raise ValueError("duplicate source-root-cause identity discovered")
    return (
        execution_evidence,
        cvss_evidence,
        state_reset_evidence,
        missing_function_ac_evidence,
        sql_injection_advanced_evidence,
        candidates,
    )


def materialize_l2_oracles(
    sources_root: Path,
    calculator_root: Path,
    calculator_receipt_path: Path,
    *,
    calculator_id: str = DEFAULT_CALCULATOR_ID,
    source_admission_path: Path | None = None,
    source_receipts_dir: Path | None = None,
    execution_evidence_path: Path | None = None,
    cwe_evidence_path: Path | None = None,
    cvss_evidence_path: Path | None = None,
    state_reset_evidence_path: Path | None = None,
    state_reset_positive_receipt_path: Path | None = None,
    state_reset_negative_receipt_path: Path | None = None,
    missing_function_ac_execution_evidence_path: Path | None = None,
    missing_function_ac_cwe_evidence_path: Path | None = None,
    missing_function_ac_cvss_evidence_path: Path | None = None,
    missing_function_ac_state_reset_evidence_path: Path | None = None,
    missing_function_ac_state_reset_positive_receipt_path: Path | None = None,
    missing_function_ac_state_reset_negative_receipt_path: Path | None = None,
    sql_injection_advanced_execution_evidence_path: Path | None = None,
    sql_injection_advanced_cwe_evidence_path: Path | None = None,
    sql_injection_advanced_cvss_evidence_path: Path | None = None,
    sql_injection_advanced_state_reset_evidence_path: Path | None = None,
    sql_injection_advanced_positive_receipt_path: Path | None = None,
    sql_injection_advanced_negative_receipt_path: Path | None = None,
) -> dict[str, Any]:
    sources_root = sources_root.resolve(strict=True)
    if calculator_id != DEFAULT_CALCULATOR_ID:
        raise ValueError("calculator_id does not match the locked calculator identity")
    calculator_binding = _verify_calculator_source(calculator_root, calculator_receipt_path)
    calculator_binding_sha256 = sha256_bytes(canonical_json_bytes(calculator_binding))
    if set(path.name for path in sources_root.iterdir() if path.is_dir()) != set(EXPECTED_APPS):
        raise ValueError("sources root must contain exactly the locked six app directories")
    source_admission_path = source_admission_path or sources_root.parent / "source-admission.json"
    source_receipts_dir = source_receipts_dir or sources_root.parent / "source-receipts"
    source_admission, receipts = _verify_source_receipts(
        sources_root, source_admission_path, source_receipts_dir
    )

    (
        execution_evidence,
        cvss_evidence,
        state_reset_evidence,
        missing_function_ac_evidence,
        sql_injection_advanced_evidence,
        candidates,
    ) = _reextract_candidates(
        sources_root,
        receipts,
        source_receipts_dir,
        calculator_id,
        calculator_binding_sha256,
        execution_evidence_path,
        cwe_evidence_path,
        cvss_evidence_path,
        state_reset_evidence_path,
        state_reset_positive_receipt_path,
        state_reset_negative_receipt_path,
        missing_function_ac_execution_evidence_path,
        missing_function_ac_cwe_evidence_path,
        missing_function_ac_cvss_evidence_path,
        missing_function_ac_state_reset_evidence_path,
        missing_function_ac_state_reset_positive_receipt_path,
        missing_function_ac_state_reset_negative_receipt_path,
        sql_injection_advanced_execution_evidence_path,
        sql_injection_advanced_cwe_evidence_path,
        sql_injection_advanced_cvss_evidence_path,
        sql_injection_advanced_state_reset_evidence_path,
        sql_injection_advanced_positive_receipt_path,
        sql_injection_advanced_negative_receipt_path,
        calculator_root,
        calculator_receipt_path,
    )
    payload = {
        "schema": SCHEMA,
        "calculator": {**calculator_binding, "binding_sha256": calculator_binding_sha256},
        "source_admission": source_admission,
        "source_receipts": sorted(receipts, key=lambda row: row["app_id"]),
        "execution_evidence": execution_evidence,
        "cvss_evidence": cvss_evidence,
        "state_reset_evidence": state_reset_evidence,
        "missing_function_ac_evidence": missing_function_ac_evidence,
        "sql_injection_advanced_evidence": sql_injection_advanced_evidence,
        "retained_candidates": candidates,
        "scenarios": [row for row in candidates if row["admission"] == "PASS"],
        "summary": _summary(candidates, receipts),
        "inventory_gate": "HOLD",
        "oracle_replay": {
            "executed": False,
            "passed_scenario_count": 0,
            "receipt_count": 0,
            "status": "HOLD",
            "blocker": "machine_oracle_replay_not_executed",
        },
        "phase_2_l2_status": "HOLD",
        "release_gate_passed": False,
        "claim_boundary": {
            "source_candidate_inventory_only": True,
            "proves_machine_oracle_replay": False,
            "proves_scanner_accuracy": False,
            "proves_release_readiness": False,
        },
        "scanner_output_observed": False,
        "raw_returned": False,
    }
    payload["inventory_gate"] = payload["summary"]["status"]
    validate_registry(
        payload,
        sources_root,
        calculator_root,
        calculator_receipt_path,
        source_admission_path=source_admission_path,
        source_receipts_dir=source_receipts_dir,
        execution_evidence_path=execution_evidence_path,
        cwe_evidence_path=cwe_evidence_path,
        cvss_evidence_path=cvss_evidence_path,
        state_reset_evidence_path=state_reset_evidence_path,
        state_reset_positive_receipt_path=state_reset_positive_receipt_path,
        state_reset_negative_receipt_path=state_reset_negative_receipt_path,
        missing_function_ac_execution_evidence_path=missing_function_ac_execution_evidence_path,
        missing_function_ac_cwe_evidence_path=missing_function_ac_cwe_evidence_path,
        missing_function_ac_cvss_evidence_path=missing_function_ac_cvss_evidence_path,
        missing_function_ac_state_reset_evidence_path=missing_function_ac_state_reset_evidence_path,
        missing_function_ac_state_reset_positive_receipt_path=(
            missing_function_ac_state_reset_positive_receipt_path
        ),
        missing_function_ac_state_reset_negative_receipt_path=(
            missing_function_ac_state_reset_negative_receipt_path
        ),
        sql_injection_advanced_execution_evidence_path=(
            sql_injection_advanced_execution_evidence_path
        ),
        sql_injection_advanced_cwe_evidence_path=sql_injection_advanced_cwe_evidence_path,
        sql_injection_advanced_cvss_evidence_path=sql_injection_advanced_cvss_evidence_path,
        sql_injection_advanced_state_reset_evidence_path=(
            sql_injection_advanced_state_reset_evidence_path
        ),
        sql_injection_advanced_positive_receipt_path=sql_injection_advanced_positive_receipt_path,
        sql_injection_advanced_negative_receipt_path=sql_injection_advanced_negative_receipt_path,
    )
    return payload

def _validate_command(value: Any, *, label: str) -> None:
    deficits = _command_deficits(value, label=label)
    if deficits:
        raise ValueError(f"{label} contract invalid: {deficits}")


def validate_registry(
    payload: dict[str, Any],
    sources_root: Path,
    calculator_root: Path,
    calculator_receipt_path: Path,
    *,
    source_admission_path: Path | None = None,
    source_receipts_dir: Path | None = None,
    execution_evidence_path: Path | None = None,
    cwe_evidence_path: Path | None = None,
    cvss_evidence_path: Path | None = None,
    state_reset_evidence_path: Path | None = None,
    state_reset_positive_receipt_path: Path | None = None,
    state_reset_negative_receipt_path: Path | None = None,
    missing_function_ac_execution_evidence_path: Path | None = None,
    missing_function_ac_cwe_evidence_path: Path | None = None,
    missing_function_ac_cvss_evidence_path: Path | None = None,
    missing_function_ac_state_reset_evidence_path: Path | None = None,
    missing_function_ac_state_reset_positive_receipt_path: Path | None = None,
    missing_function_ac_state_reset_negative_receipt_path: Path | None = None,
    sql_injection_advanced_execution_evidence_path: Path | None = None,
    sql_injection_advanced_cwe_evidence_path: Path | None = None,
    sql_injection_advanced_cvss_evidence_path: Path | None = None,
    sql_injection_advanced_state_reset_evidence_path: Path | None = None,
    sql_injection_advanced_positive_receipt_path: Path | None = None,
    sql_injection_advanced_negative_receipt_path: Path | None = None,
) -> None:
    required = {
        "schema", "calculator", "source_admission", "source_receipts", "execution_evidence", "cvss_evidence", "state_reset_evidence", "missing_function_ac_evidence", "sql_injection_advanced_evidence", "retained_candidates", "scenarios",
        "summary", "inventory_gate", "oracle_replay", "phase_2_l2_status", "release_gate_passed",
        "claim_boundary", "scanner_output_observed", "raw_returned",
    }
    if not isinstance(payload, dict) or set(payload) != required or payload.get("schema") != SCHEMA:
        raise ValueError("registry schema or top-level fields are invalid")
    calculator_binding = _verify_calculator_source(calculator_root, calculator_receipt_path)
    calculator_binding_sha256 = sha256_bytes(canonical_json_bytes(calculator_binding))
    expected_calculator = {**calculator_binding, "binding_sha256": calculator_binding_sha256}
    calculator = payload.get("calculator")
    if calculator != expected_calculator:
        raise ValueError("registry calculator is not bound to the full pinned FIRST source tree")
    source_admission_path = source_admission_path or sources_root.parent / "source-admission.json"
    source_receipts_dir = source_receipts_dir or sources_root.parent / "source-receipts"
    recomputed_admission, recomputed_receipts = _verify_source_receipts(
        sources_root.resolve(strict=True), source_admission_path, source_receipts_dir
    )
    if payload.get("source_admission") != recomputed_admission:
        raise ValueError("registry source admission provenance is invalid")
    receipts = payload.get("source_receipts")
    candidates = payload.get("retained_candidates")
    scenarios = payload.get("scenarios")
    if not isinstance(receipts, list) or not isinstance(candidates, list) or not isinstance(scenarios, list):
        raise ValueError("registry collections are malformed")
    if [row.get("app_id") for row in receipts] != list(EXPECTED_APPS):
        raise ValueError("registry must bind exactly the six ordered app receipts")
    if receipts != recomputed_receipts:
        raise ValueError("registry source receipts differ from authoritative raw-blob verification")
    receipt_by_app = {receipt["app_id"]: receipt for receipt in receipts}

    (
        expected_execution_evidence,
        expected_cvss_evidence,
        expected_state_reset_evidence,
        expected_missing_function_ac_evidence,
        expected_sql_injection_advanced_evidence,
        expected_candidates,
    ) = _reextract_candidates(
        sources_root.resolve(strict=True),
        receipts,
        source_receipts_dir,
        calculator["id"],
        calculator_binding_sha256,
        execution_evidence_path,
        cwe_evidence_path,
        cvss_evidence_path,
        state_reset_evidence_path,
        state_reset_positive_receipt_path,
        state_reset_negative_receipt_path,
        missing_function_ac_execution_evidence_path,
        missing_function_ac_cwe_evidence_path,
        missing_function_ac_cvss_evidence_path,
        missing_function_ac_state_reset_evidence_path,
        missing_function_ac_state_reset_positive_receipt_path,
        missing_function_ac_state_reset_negative_receipt_path,
        sql_injection_advanced_execution_evidence_path,
        sql_injection_advanced_cwe_evidence_path,
        sql_injection_advanced_cvss_evidence_path,
        sql_injection_advanced_state_reset_evidence_path,
        sql_injection_advanced_positive_receipt_path,
        sql_injection_advanced_negative_receipt_path,
        calculator_root,
        calculator_receipt_path,
    )
    if payload.get("execution_evidence") != expected_execution_evidence:
        raise ValueError("registry execution evidence attachment is not reproducible")
    if payload.get("cvss_evidence") != expected_cvss_evidence:
        raise ValueError("registry CVSS evidence attachment is not reproducible")
    if payload.get("state_reset_evidence") != expected_state_reset_evidence:
        raise ValueError("registry state-reset evidence attachment is not reproducible")
    if payload.get("missing_function_ac_evidence") != expected_missing_function_ac_evidence:
        raise ValueError("registry MissingFunctionAC evidence attachment is not reproducible")
    if payload.get("sql_injection_advanced_evidence") != expected_sql_injection_advanced_evidence:
        raise ValueError("registry SQL Injection Advanced evidence attachment is not reproducible")

    seen_ids: set[str] = set()
    seen_identities: set[str] = set()
    for row in candidates:
        if not isinstance(row, dict):
            raise ValueError("scenario candidate must be an object")
        required_candidate_fields = {
            "scenario_id", "app_id", "app_lineage", "source_root_cause_identity", "root_cause",
            "official_source", "cwe", "primary_plane", "applicable_planes", "cvss_v4",
            "mechanism_truth", "expected_disposition", "oracle", "negative_control", "state_reset",
            "source_receipt_sha256", "scanner_output_observed", "admission", "deficits",
        }
        if set(row) != required_candidate_fields:
            raise ValueError("scenario candidate fields are malformed")
        app_id = row.get("app_id")
        if app_id not in receipt_by_app or row.get("scanner_output_observed") is not False:
            raise ValueError("scenario candidate app or scanner boundary is invalid")
        scenario_id = row.get("scenario_id")
        identity = row.get("source_root_cause_identity")
        if not isinstance(scenario_id, str) or scenario_id in seen_ids:
            raise ValueError("scenario_id is malformed or duplicated")
        if not isinstance(identity, str) or SHA256_RE.fullmatch(identity) is None or identity in seen_identities:
            raise ValueError("source-root-cause identity is malformed or duplicated")
        seen_ids.add(scenario_id)
        seen_identities.add(identity)
        source = row.get("official_source")
        if not isinstance(source, dict) or set(source) != {"path", "line", "content_sha256", "kind"}:
            raise ValueError("official source contract is malformed")
        relative = _safe_relative_path(source.get("path"), label="official source path")
        _path, raw = _bound_file(sources_root / app_id, relative, label="official source")
        if source.get("content_sha256") != sha256_bytes(raw):
            raise ValueError("official source content SHA-256 differs from checkout")
        if not isinstance(source.get("line"), int) or isinstance(source.get("line"), bool) or source["line"] < 1:
            raise ValueError("official source line is invalid")
        if source["line"] > raw.count(b"\n") + 1:
            raise ValueError("official source line exceeds the bound file")
        if row.get("source_receipt_sha256") != receipt_by_app[app_id]["receipt_sha256"]:
            raise ValueError("scenario source receipt binding is invalid")
        lineage = row.get("app_lineage")
        expected_lineage = {
            "lineage_id": receipt_by_app[app_id]["lineage_id"],
            "repository_id": receipt_by_app[app_id]["repository_id"],
            "commit": receipt_by_app[app_id]["commit"],
            "commit_tree": receipt_by_app[app_id]["commit_tree"],
            "source_tree_sha256": receipt_by_app[app_id]["source_tree_sha256"],
        }
        if lineage != expected_lineage:
            raise ValueError("scenario app lineage binding is invalid")
        root_cause = row.get("root_cause")
        if not isinstance(root_cause, str) or not root_cause or len(root_cause.encode("utf-8")) > 500:
            raise ValueError("scenario root cause is invalid")
        identity_material = "\0".join(
            (
                expected_lineage["lineage_id"],
                relative,
                str(source["line"]),
                source["content_sha256"],
            )
        )
        recomputed_identity = sha256_bytes(
            ("k_guard_l2_source_root_cause.v1\0" + identity_material).encode("utf-8")
        )
        if identity != recomputed_identity:
            raise ValueError("source-root-cause identity does not bind its evidence")
        expected_scenario_id = f"{app_id}:{_slug(root_cause)}:{identity[:16]}"
        if scenario_id != expected_scenario_id:
            raise ValueError("scenario_id does not bind its source-root-cause identity")
        if row.get("primary_plane") not in PLANES:
            raise ValueError("scenario primary plane is invalid")
        applicable = row.get("applicable_planes")
        if not isinstance(applicable, list) or applicable != sorted(set(applicable)) or row["primary_plane"] not in applicable or not set(applicable) <= PLANES:
            raise ValueError("scenario applicable planes are invalid")
        cvss = row.get("cvss_v4")
        _validate_cvss_v4(cvss, calculator_binding_sha256)
        for command_label in ("oracle", "negative_control", "state_reset"):
            command_value = row.get(command_label)
            if command_value is not None:
                unsafe = _command_deficits(command_value, label=command_label)
                if any(item.endswith("_unsafe") or item.endswith("_malformed") for item in unsafe):
                    raise ValueError(f"{command_label} command or network policy is unsafe")
        expected_deficits = _candidate_deficits(row)
        if row.get("deficits") != expected_deficits:
            raise ValueError("scenario deficit ledger is not reproducible")
        expected_admission = "PASS" if not expected_deficits else "HOLD"
        if row.get("admission") != expected_admission:
            raise ValueError("scenario admission does not match its evidence")
        if expected_admission == "PASS":
            _validate_command(row["oracle"], label="oracle")
            _validate_command(row["negative_control"], label="negative_control")
            _validate_command(row["state_reset"], label="state_reset")

    if candidates != expected_candidates:
        raise ValueError("registry candidates do not exactly match deterministic source re-extraction")

    expected_scenarios = [row for row in candidates if row["admission"] == "PASS"]
    if scenarios != expected_scenarios:
        raise ValueError("scenarios must contain exactly the fully admitted candidates")
    computed_summary = _summary(candidates, receipts)
    if payload.get("summary") != computed_summary:
        raise ValueError("registry summary is not reproducible")
    if payload.get("inventory_gate") != computed_summary["status"]:
        raise ValueError("candidate inventory gate is inconsistent")
    expected_replay = {
        "executed": False,
        "passed_scenario_count": 0,
        "receipt_count": 0,
        "status": "HOLD",
        "blocker": "machine_oracle_replay_not_executed",
    }
    if payload.get("oracle_replay") != expected_replay:
        raise ValueError("machine oracle replay boundary is inconsistent")
    expected_boundary = {
        "source_candidate_inventory_only": True,
        "proves_machine_oracle_replay": False,
        "proves_scanner_accuracy": False,
        "proves_release_readiness": False,
    }
    if payload.get("claim_boundary") != expected_boundary:
        raise ValueError("oracle registry claim boundary is inconsistent")
    if payload.get("phase_2_l2_status") != "HOLD":
        raise ValueError("Phase 2 L2 must remain HOLD before machine replay")
    if payload.get("release_gate_passed") is not False:
        raise ValueError("candidate inventory cannot grant release authority")
    if payload.get("scanner_output_observed") is not False or payload.get("raw_returned") is not False:
        raise ValueError("registry violates the scanner/raw evidence boundary")


def _load_canonical(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("registry must be UTF-8 JSON") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError("registry must use canonical JSON serialization")
    return payload


def write_new_output(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite L2 oracle registry: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(canonical_json_bytes(payload))
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise FileExistsError(
                f"refusing to overwrite L2 oracle registry: {path}"
            ) from exc
    finally:
        temporary.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Materialize or validate the fail-closed L2 oracle registry")
    subparsers = parser.add_subparsers(dest="command", required=True)
    materialize = subparsers.add_parser("materialize")
    materialize.add_argument("--sources-root", type=Path, required=True)
    materialize.add_argument("--calculator-root", type=Path, required=True)
    materialize.add_argument("--calculator-receipt", type=Path, required=True)
    materialize.add_argument("--calculator-id", default=DEFAULT_CALCULATOR_ID, choices=(DEFAULT_CALCULATOR_ID,))
    materialize.add_argument("--source-admission", type=Path, required=True)
    materialize.add_argument("--source-receipts-dir", type=Path, required=True)
    materialize.add_argument("--execution-evidence", type=Path)
    materialize.add_argument("--cwe-evidence", type=Path)
    materialize.add_argument("--cvss-evidence", type=Path)
    materialize.add_argument("--state-reset-evidence", type=Path)
    materialize.add_argument("--state-reset-positive-receipt", type=Path)
    materialize.add_argument("--state-reset-negative-receipt", type=Path)
    materialize.add_argument("--missing-function-ac-execution-evidence", type=Path)
    materialize.add_argument("--missing-function-ac-cwe-evidence", type=Path)
    materialize.add_argument("--missing-function-ac-cvss-evidence", type=Path)
    materialize.add_argument("--missing-function-ac-state-reset-evidence", type=Path)
    materialize.add_argument("--missing-function-ac-state-reset-positive-receipt", type=Path)
    materialize.add_argument("--missing-function-ac-state-reset-negative-receipt", type=Path)
    materialize.add_argument("--sql-injection-advanced-execution-evidence", type=Path)
    materialize.add_argument("--sql-injection-advanced-cwe-evidence", type=Path)
    materialize.add_argument("--sql-injection-advanced-cvss-evidence", type=Path)
    materialize.add_argument("--sql-injection-advanced-state-reset-evidence", type=Path)
    materialize.add_argument("--sql-injection-advanced-positive-receipt", type=Path)
    materialize.add_argument("--sql-injection-advanced-negative-receipt", type=Path)
    materialize.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--sources-root", type=Path, required=True)
    validate.add_argument("--registry", type=Path, required=True)
    validate.add_argument("--calculator-root", type=Path, required=True)
    validate.add_argument("--calculator-receipt", type=Path, required=True)
    validate.add_argument("--source-admission", type=Path, required=True)
    validate.add_argument("--source-receipts-dir", type=Path, required=True)
    validate.add_argument("--execution-evidence", type=Path)
    validate.add_argument("--cwe-evidence", type=Path)
    validate.add_argument("--cvss-evidence", type=Path)
    validate.add_argument("--state-reset-evidence", type=Path)
    validate.add_argument("--state-reset-positive-receipt", type=Path)
    validate.add_argument("--state-reset-negative-receipt", type=Path)
    validate.add_argument("--missing-function-ac-execution-evidence", type=Path)
    validate.add_argument("--missing-function-ac-cwe-evidence", type=Path)
    validate.add_argument("--missing-function-ac-cvss-evidence", type=Path)
    validate.add_argument("--missing-function-ac-state-reset-evidence", type=Path)
    validate.add_argument("--missing-function-ac-state-reset-positive-receipt", type=Path)
    validate.add_argument("--missing-function-ac-state-reset-negative-receipt", type=Path)
    validate.add_argument("--sql-injection-advanced-execution-evidence", type=Path)
    validate.add_argument("--sql-injection-advanced-cwe-evidence", type=Path)
    validate.add_argument("--sql-injection-advanced-cvss-evidence", type=Path)
    validate.add_argument("--sql-injection-advanced-state-reset-evidence", type=Path)
    validate.add_argument("--sql-injection-advanced-positive-receipt", type=Path)
    validate.add_argument("--sql-injection-advanced-negative-receipt", type=Path)
    return parser


def _phase_2_l2_exit_code(payload: dict[str, Any]) -> int:
    """Reserve exit 2 for a structurally valid registry that remains HOLD."""

    status = payload["phase_2_l2_status"]
    if status == "PASS":
        return 0
    if status == "HOLD":
        return 2
    raise ValueError("phase 2 L2 status is invalid")


def _cli_report(payload: dict[str, Any], registry: Path) -> tuple[dict[str, Any], int]:
    exit_code = _phase_2_l2_exit_code(payload)
    report = {
        **payload["summary"],
        "evaluation": {
            "exit_code": exit_code,
            "exit_contract": "0=phase_2_l2_pass;2=validated_hold_not_release",
            "phase_2_l2_status": payload["phase_2_l2_status"],
            "registry_contract_valid": True,
        },
        "registry_path": str(registry),
        "registry_sha256": sha256_bytes(registry.read_bytes()),
    }
    return report, exit_code


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    if args.command == "materialize":
        payload = materialize_l2_oracles(
            args.sources_root,
            args.calculator_root,
            args.calculator_receipt,
            calculator_id=args.calculator_id,
            source_admission_path=args.source_admission,
            source_receipts_dir=args.source_receipts_dir,
            execution_evidence_path=args.execution_evidence,
            cwe_evidence_path=args.cwe_evidence,
            cvss_evidence_path=args.cvss_evidence,
            state_reset_evidence_path=args.state_reset_evidence,
            state_reset_positive_receipt_path=args.state_reset_positive_receipt,
            state_reset_negative_receipt_path=args.state_reset_negative_receipt,
            missing_function_ac_execution_evidence_path=args.missing_function_ac_execution_evidence,
            missing_function_ac_cwe_evidence_path=args.missing_function_ac_cwe_evidence,
            missing_function_ac_cvss_evidence_path=args.missing_function_ac_cvss_evidence,
            missing_function_ac_state_reset_evidence_path=args.missing_function_ac_state_reset_evidence,
            missing_function_ac_state_reset_positive_receipt_path=(
                args.missing_function_ac_state_reset_positive_receipt
            ),
            missing_function_ac_state_reset_negative_receipt_path=(
                args.missing_function_ac_state_reset_negative_receipt
            ),
            sql_injection_advanced_execution_evidence_path=(
                args.sql_injection_advanced_execution_evidence
            ),
            sql_injection_advanced_cwe_evidence_path=args.sql_injection_advanced_cwe_evidence,
            sql_injection_advanced_cvss_evidence_path=args.sql_injection_advanced_cvss_evidence,
            sql_injection_advanced_state_reset_evidence_path=(
                args.sql_injection_advanced_state_reset_evidence
            ),
            sql_injection_advanced_positive_receipt_path=(
                args.sql_injection_advanced_positive_receipt
            ),
            sql_injection_advanced_negative_receipt_path=(
                args.sql_injection_advanced_negative_receipt
            ),
        )
        write_new_output(args.output, payload)
        output = args.output.resolve(strict=True)
        report, exit_code = _cli_report(payload, output)
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return exit_code
    payload = _load_canonical(args.registry)
    validate_registry(
        payload,
        args.sources_root.resolve(strict=True),
        args.calculator_root,
        args.calculator_receipt,
        source_admission_path=args.source_admission,
        source_receipts_dir=args.source_receipts_dir,
        execution_evidence_path=args.execution_evidence,
        cwe_evidence_path=args.cwe_evidence,
        cvss_evidence_path=args.cvss_evidence,
        state_reset_evidence_path=args.state_reset_evidence,
        state_reset_positive_receipt_path=args.state_reset_positive_receipt,
        state_reset_negative_receipt_path=args.state_reset_negative_receipt,
        missing_function_ac_execution_evidence_path=args.missing_function_ac_execution_evidence,
        missing_function_ac_cwe_evidence_path=args.missing_function_ac_cwe_evidence,
        missing_function_ac_cvss_evidence_path=args.missing_function_ac_cvss_evidence,
        missing_function_ac_state_reset_evidence_path=args.missing_function_ac_state_reset_evidence,
        missing_function_ac_state_reset_positive_receipt_path=(
            args.missing_function_ac_state_reset_positive_receipt
        ),
        missing_function_ac_state_reset_negative_receipt_path=(
            args.missing_function_ac_state_reset_negative_receipt
        ),
        sql_injection_advanced_execution_evidence_path=(
            args.sql_injection_advanced_execution_evidence
        ),
        sql_injection_advanced_cwe_evidence_path=args.sql_injection_advanced_cwe_evidence,
        sql_injection_advanced_cvss_evidence_path=args.sql_injection_advanced_cvss_evidence,
        sql_injection_advanced_state_reset_evidence_path=(
            args.sql_injection_advanced_state_reset_evidence
        ),
        sql_injection_advanced_positive_receipt_path=(args.sql_injection_advanced_positive_receipt),
        sql_injection_advanced_negative_receipt_path=(args.sql_injection_advanced_negative_receipt),
    )
    registry = args.registry.resolve(strict=True)
    report, exit_code = _cli_report(payload, registry)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
