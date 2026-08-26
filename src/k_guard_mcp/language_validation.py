from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from k_guard_mcp.analyzers import (
    DEFAULT_SEMGREP_PROFILE,
    PATH_SET_SCHEMA,
    TARGET_COVERAGE_SCHEMA,
    AnalyzerAdapter,
    AnalyzerFinding,
    AnalyzerRun,
    SemgrepAnalyzerAdapter,
)
from k_guard_mcp.provenance import evidence_bundle, object_artifact


PACK_SCHEMA = "k_guard_language_validation_pack.v1"
EXPECTATIONS_SCHEMA = "k_guard_language_validation_expectations.v1"
REPORT_SCHEMA = "k_guard_language_validation_report.v1"
DEFAULT_LANGUAGE_VALIDATION_PACK = Path(__file__).with_name("validation_packs") / "java-kotlin-go"
CLAIM_BOUNDARY = "development_validation_not_field_accuracy"
PINNED_SEMGREP_VERSION = "1.174.0"
PROFILE_RULE_COUNT = 40
REQUIRED_LANGUAGES = (
    "python",
    "javascript",
    "typescript",
    "java",
    "kotlin",
    "go",
    "php",
    "ruby",
    "csharp",
)
REQUIRED_CATEGORIES = (
    "sql-injection",
    "command-injection",
    "path-traversal",
    "ssrf",
    "authorization-review",
)

_RULE_IDS = {
    "python": {
        "sql-injection": "k-guard.python.http-to-sql",
        "command-injection": "k-guard.python.http-to-command",
        "path-traversal": "k-guard.python.http-to-file-path",
        "ssrf": "k-guard.python.http-to-ssrf",
        "authorization-review": "k-guard.python.direct-object-lookup-from-request-id",
    },
    "javascript": {
        "sql-injection": "k-guard.javascript.http-to-sql",
        "command-injection": "k-guard.javascript.http-to-command",
        "path-traversal": "k-guard.javascript.http-to-file-path",
        "ssrf": "k-guard.javascript.http-to-ssrf",
        "authorization-review": "k-guard.javascript.direct-object-lookup-from-route-id",
    },
    "typescript": {
        "sql-injection": "k-guard.javascript.http-to-sql",
        "command-injection": "k-guard.javascript.http-to-command",
        "path-traversal": "k-guard.javascript.http-to-file-path",
        "ssrf": "k-guard.javascript.http-to-ssrf",
        "authorization-review": "k-guard.javascript.direct-object-lookup-from-route-id",
    },
    "java": {
        "sql-injection": "k-guard.java.http-to-sql",
        "command-injection": "k-guard.java.http-to-command",
        "path-traversal": "k-guard.java.http-to-file-path",
        "ssrf": "k-guard.java.http-to-ssrf",
        "authorization-review": "k-guard.java.direct-object-lookup-from-request-id",
    },
    "kotlin": {
        "sql-injection": "k-guard.kotlin.http-to-sql",
        "command-injection": "k-guard.kotlin.http-to-command",
        "path-traversal": "k-guard.kotlin.http-to-file-path",
        "ssrf": "k-guard.kotlin.http-to-ssrf",
        "authorization-review": "k-guard.kotlin.direct-object-lookup-from-request-id",
    },
    "go": {
        "sql-injection": "k-guard.go.http-to-sql",
        "command-injection": "k-guard.go.http-to-command",
        "path-traversal": "k-guard.go.http-to-file-path",
        "ssrf": "k-guard.go.http-to-ssrf",
        "authorization-review": "k-guard.go.direct-object-lookup-from-route-id",
    },
    "php": {
        "sql-injection": "k-guard.php.http-to-sql",
        "command-injection": "k-guard.php.http-to-command",
        "path-traversal": "k-guard.php.http-to-file-path",
        "ssrf": "k-guard.php.http-to-ssrf",
        "authorization-review": "k-guard.php.direct-object-lookup-from-request-id",
    },
    "ruby": {
        "sql-injection": "k-guard.ruby.http-to-sql",
        "command-injection": "k-guard.ruby.http-to-command",
        "path-traversal": "k-guard.ruby.http-to-file-path",
        "ssrf": "k-guard.ruby.http-to-ssrf",
        "authorization-review": "k-guard.ruby.direct-object-lookup-from-request-id",
    },
    "csharp": {
        "sql-injection": "k-guard.csharp.http-to-sql",
        "command-injection": "k-guard.csharp.http-to-command",
        "path-traversal": "k-guard.csharp.http-to-file-path",
        "ssrf": "k-guard.csharp.http-to-ssrf",
        "authorization-review": "k-guard.csharp.direct-object-lookup-from-route-id",
    },
}
_LANGUAGE_SUFFIX = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "java": ".java",
    "kotlin": ".kt",
    "go": ".go",
    "php": ".php",
    "ruby": ".rb",
    "csharp": ".cs",
}
_CASE_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{2,95}\Z")
_RULE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}\Z")
_CONTROL_RE = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,127}\Z")
_VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_PROFILE_RULE_ID_RE = re.compile(
    r"^\s*-\s+id:\s*['\"]?([A-Za-z0-9][A-Za-z0-9_.:/-]{0,255})['\"]?\s*(?:#.*)?$",
    re.MULTILINE,
)
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_EXPECTATIONS_BYTES = 1024 * 1024
_MAX_FIXTURE_BYTES = 256 * 1024


@dataclass(frozen=True, slots=True)
class _Case:
    case_id: str
    language: str
    category: str
    expected: str
    rule_id: str
    file: str
    source_sha256: str


@dataclass(frozen=True, slots=True)
class _Pack:
    root: Path
    fixture_root: Path
    pack_id: str
    cases: tuple[_Case, ...]
    pack_sha256: str
    expectations_sha256: str
    profile_sha256: str
    rules_sha256: str
    profile_name: str
    executable_version: str
    target_path_set_sha256: str


class _PackValidationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _DuplicateJsonKey(ValueError):
    pass


def run_language_validation_pack(
    pack_path: str | Path,
    adapter: AnalyzerAdapter,
    repeat: bool = True,
) -> dict[str, Any]:
    """Run the pinned nine-language intrafile validation pack without raw source output."""
    if not isinstance(repeat, bool):
        return _failure_report(("repeat_option_invalid",))
    if not isinstance(adapter, AnalyzerAdapter):
        return _failure_report(("analyzer_adapter_invalid",))

    try:
        pack = _load_pack(pack_path)
    except _PackValidationError as exc:
        return _failure_report((exc.code,))

    runs: list[AnalyzerRun] = []
    for _ in range(2 if repeat else 1):
        try:
            run = adapter.analyze(pack.fixture_root, profile_path=DEFAULT_SEMGREP_PROFILE)
        except Exception:
            return _failure_report(
                ("analyzer_adapter_exception",),
                pack=pack,
                runs=tuple(runs),
                repeat_requested=repeat,
            )
        if not isinstance(run, AnalyzerRun):
            return _failure_report(
                ("analyzer_run_contract_invalid",),
                pack=pack,
                runs=tuple(runs),
                repeat_requested=repeat,
            )
        runs.append(run)

    control_errors: list[str] = []
    if any(not run.complete for run in runs):
        control_errors.append("analyzer_run_incomplete")
        for run in runs:
            control_errors.extend(_safe_control_errors(run.control_errors))
    if not all(_profile_matches_pack(run, pack) for run in runs):
        control_errors.append("analyzer_profile_contract_mismatch")
    if not all(_executable_version_matches_pack(run, pack) for run in runs):
        control_errors.append("analyzer_executable_version_mismatch")
    if not all(_target_coverage_matches_pack(run, pack) for run in runs):
        control_errors.append("analyzer_target_coverage_mismatch")
    if not all(_analyzer_identity_complete(run) for run in runs):
        control_errors.append("analyzer_identity_incomplete")
    if len(runs) == 2 and not _run_contract_equal(runs[0], runs[1]):
        control_errors.append("analyzer_contract_drift")
    if control_errors:
        return _failure_report(
            tuple(dict.fromkeys(control_errors)),
            pack=pack,
            runs=tuple(runs),
            repeat_requested=repeat,
        )

    primary = runs[0]
    primary_multiset = Counter(finding.fingerprint for finding in primary.findings)
    repeat_multiset = Counter(finding.fingerprint for finding in runs[1].findings) if len(runs) == 2 else Counter()
    exact_repeat = len(runs) == 2 and primary_multiset == repeat_multiset
    metrics, case_results, unmapped = _score_cases(pack.cases, primary.findings)
    coverage = _coverage(pack.cases)
    requirements = {
        "all_expected_positives_found": metrics["overall"]["confusion_matrix"]["fn"] == 0,
        "zero_clean_case_false_positives": metrics["overall"]["confusion_matrix"]["fp"] == 0,
        "exact_repeat_fingerprint_multiset": exact_repeat,
        "all_nine_languages": coverage["all_nine_languages"],
        "minimum_five_vulnerable_and_five_clean_per_language": coverage["minimum_case_balance"],
        "all_five_categories_per_language_and_outcome": coverage["all_categories"],
        "all_findings_mapped": not unmapped,
        "bundled_profile_exact": True,
        "pinned_semgrep_executable_version": True,
        "exact_target_coverage": True,
        "analyzer_complete": True,
    }
    ready = all(requirements.values())

    return _seal_report({
        "schema": REPORT_SCHEMA,
        "complete": True,
        "ready": ready,
        "status": "development_validation_ready" if ready else "development_validation_not_ready",
        "control_errors": [],
        "raw_free": True,
        "claim_boundary": _claim_boundary(),
        "pack": {
            "pack_id": pack.pack_id,
            "schema": PACK_SCHEMA,
            "expectations_schema": EXPECTATIONS_SCHEMA,
            "expectations_immutable": True,
            "profile_name": pack.profile_name,
            "analyzer": {
                "name": "semgrep",
                "executable_version": pack.executable_version,
            },
        },
        "languages": list(REQUIRED_LANGUAGES),
        "case_counts": _case_counts(pack.cases),
        "metrics": metrics,
        "case_results": case_results,
        "unmapped_findings": unmapped,
        "repeat": _repeat_report(primary_multiset, repeat_multiset, repeat, exact_repeat),
        "requirements": requirements,
        "hashes": _hash_report(pack, primary),
        "analyzer_runs": [_run_summary(run) for run in runs],
    })


def current_language_validation_contract() -> dict[str, Any]:
    try:
        pack = _load_pack(DEFAULT_LANGUAGE_VALIDATION_PACK)
        adapter = SemgrepAnalyzerAdapter()
        hashes = {
            "pack_sha256": pack.pack_sha256,
            "expectations_sha256": pack.expectations_sha256,
            "profile_sha256": pack.profile_sha256,
            "profile_rules_sha256": pack.rules_sha256,
            "validator_sha256": _sha256(Path(__file__).read_bytes()),
            "adapter_sha256": adapter._adapter_sha256,
            "adapter_command_contract_sha256": adapter._command_contract_sha256,
            "semgrep_executable_version_sha256": _sha256(pack.executable_version.encode("ascii")),
        }
        complete = all(_valid_sha256(value) for value in hashes.values())
        analyzer = {"name": "semgrep", "executable_version": pack.executable_version}
    except Exception:
        hashes = _empty_hash_report()
        complete = False
        analyzer = {"name": "", "executable_version": ""}
    return {
        "schema": "k_guard_language_validation_contract.v1",
        "complete": complete,
        "analyzer": analyzer,
        "hashes": hashes,
        "raw_free": True,
    }


def _load_pack(value: str | Path) -> _Pack:
    root = _pack_root(value)
    manifest_path = _contained_file(root, "pack.json", "pack_manifest_path_invalid")
    manifest_bytes, manifest = _read_json(manifest_path, _MAX_MANIFEST_BYTES, "pack_manifest")
    _exact_keys(
        manifest,
        {
            "schema",
            "pack_id",
            "languages",
            "fixture_root",
            "expectations",
            "profile",
            "analyzer",
            "claim_boundary",
            "raw_free",
        },
        "pack_manifest_schema_invalid",
    )
    if manifest.get("schema") != PACK_SCHEMA:
        raise _PackValidationError("pack_manifest_schema_invalid")
    pack_id = manifest.get("pack_id")
    if not isinstance(pack_id, str) or not _CASE_ID_RE.fullmatch(pack_id):
        raise _PackValidationError("pack_id_invalid")
    if manifest.get("languages") != list(REQUIRED_LANGUAGES):
        raise _PackValidationError("pack_languages_invalid")
    if manifest.get("claim_boundary") != CLAIM_BOUNDARY or manifest.get("raw_free") is not True:
        raise _PackValidationError("pack_claim_boundary_invalid")
    executable_version = _validate_analyzer_reference(manifest.get("analyzer"))

    fixture_relative = manifest.get("fixture_root")
    if not isinstance(fixture_relative, str) or not _safe_relative_path(fixture_relative):
        raise _PackValidationError("fixture_root_invalid")
    fixture_root = _contained_directory(root, fixture_relative, "fixture_root_invalid")

    expectation_ref = manifest.get("expectations")
    _exact_keys(expectation_ref, {"path", "sha256"}, "expectations_reference_invalid")
    expectation_relative = expectation_ref.get("path")
    expected_expectations_sha256 = expectation_ref.get("sha256")
    if expectation_relative != "expectations.json" or not _valid_sha256(expected_expectations_sha256):
        raise _PackValidationError("expectations_reference_invalid")
    expectations_path = _contained_file(root, expectation_relative, "expectations_path_invalid")
    expectations_bytes, expectations = _read_json(
        expectations_path,
        _MAX_EXPECTATIONS_BYTES,
        "expectations",
    )
    expectations_sha256 = _sha256(expectations_bytes)
    if expectations_sha256 != expected_expectations_sha256:
        raise _PackValidationError("expectations_hash_mismatch")

    _exact_keys(
        expectations,
        {"schema", "pack_id", "immutable", "raw_free", "cases"},
        "expectations_schema_invalid",
    )
    if (
        expectations.get("schema") != EXPECTATIONS_SCHEMA
        or expectations.get("pack_id") != pack_id
        or expectations.get("immutable") is not True
        or expectations.get("raw_free") is not True
        or not isinstance(expectations.get("cases"), list)
    ):
        raise _PackValidationError("expectations_schema_invalid")

    profile_name, profile_sha256, rules_sha256 = _validate_profile_reference(manifest.get("profile"))
    cases = _validated_cases(expectations["cases"], fixture_root)
    target_path_set_sha256 = _path_set_sha256(case.file for case in cases)
    fixture_inventory = _fixture_inventory(fixture_root)
    expected_inventory = {case.file for case in cases}
    if fixture_inventory != expected_inventory:
        raise _PackValidationError("fixture_inventory_mismatch")

    pack_sha256 = _pack_digest(
        root,
        fixture_relative,
        manifest_bytes,
        expectation_relative,
        expectations_bytes,
        cases,
    )
    return _Pack(
        root=root,
        fixture_root=fixture_root,
        pack_id=pack_id,
        cases=cases,
        pack_sha256=pack_sha256,
        expectations_sha256=expectations_sha256,
        profile_sha256=profile_sha256,
        rules_sha256=rules_sha256,
        profile_name=profile_name,
        executable_version=executable_version,
        target_path_set_sha256=target_path_set_sha256,
    )


def _pack_root(value: str | Path) -> Path:
    try:
        text = str(value)
    except Exception as exc:
        raise _PackValidationError("pack_path_invalid") from exc
    if not text.strip() or "\x00" in text:
        raise _PackValidationError("pack_path_invalid")
    candidate = Path(value)
    try:
        if candidate.is_symlink() or not candidate.exists():
            raise _PackValidationError("pack_path_invalid")
        if candidate.is_file():
            if candidate.name != "pack.json":
                raise _PackValidationError("pack_path_invalid")
            candidate = candidate.parent
        if not candidate.is_dir() or candidate.is_symlink():
            raise _PackValidationError("pack_path_invalid")
        return candidate.resolve(strict=True)
    except _PackValidationError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise _PackValidationError("pack_path_invalid") from exc


def _read_json(path: Path, max_bytes: int, prefix: str) -> tuple[bytes, dict[str, Any]]:
    try:
        size = path.stat().st_size
        if size <= 0 or size > max_bytes:
            raise _PackValidationError(f"{prefix}_size_invalid")
        content = path.read_bytes()
        text = content.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except _PackValidationError:
        raise
    except _DuplicateJsonKey as exc:
        raise _PackValidationError(f"{prefix}_duplicate_json_key") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _PackValidationError(f"{prefix}_json_invalid") from exc
    if not isinstance(value, dict):
        raise _PackValidationError(f"{prefix}_schema_invalid")
    return content, value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKey(key)
        value[key] = item
    return value


def _exact_keys(value: Any, expected: set[str], error: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise _PackValidationError(error)


def _validate_analyzer_reference(value: Any) -> str:
    _exact_keys(value, {"name", "executable_version"}, "analyzer_reference_invalid")
    if value.get("name") != "semgrep":
        raise _PackValidationError("analyzer_reference_invalid")
    if value.get("executable_version") != PINNED_SEMGREP_VERSION:
        raise _PackValidationError("semgrep_version_reference_invalid")
    return PINNED_SEMGREP_VERSION


def _validate_profile_reference(value: Any) -> tuple[str, str, str]:
    _exact_keys(value, {"name", "sha256", "rules_sha256", "rule_count"}, "profile_reference_invalid")
    if value.get("name") != DEFAULT_SEMGREP_PROFILE.name or value.get("rule_count") != PROFILE_RULE_COUNT:
        raise _PackValidationError("profile_reference_invalid")
    if not _valid_sha256(value.get("sha256")) or not _valid_sha256(value.get("rules_sha256")):
        raise _PackValidationError("profile_reference_invalid")
    try:
        if DEFAULT_SEMGREP_PROFILE.is_symlink() or not DEFAULT_SEMGREP_PROFILE.is_file():
            raise _PackValidationError("bundled_profile_invalid")
        content = DEFAULT_SEMGREP_PROFILE.read_bytes()
        profile_text = content.decode("utf-8")
    except _PackValidationError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise _PackValidationError("bundled_profile_invalid") from exc
    profile_sha256 = _sha256(content)
    rule_ids = _PROFILE_RULE_ID_RE.findall(profile_text)
    if len(rule_ids) != PROFILE_RULE_COUNT or len(set(rule_ids)) != PROFILE_RULE_COUNT:
        raise _PackValidationError("bundled_profile_invalid")
    required_rule_ids = {rule_id for categories in _RULE_IDS.values() for rule_id in categories.values()}
    if not required_rule_ids.issubset(rule_ids):
        raise _PackValidationError("bundled_profile_invalid")
    rules_contract = json.dumps(
        {"profile_sha256": profile_sha256, "rule_ids": sorted(rule_ids)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    rules_sha256 = _sha256(rules_contract.encode("ascii"))
    if value["sha256"] != profile_sha256 or value["rules_sha256"] != rules_sha256:
        raise _PackValidationError("profile_hash_mismatch")
    return DEFAULT_SEMGREP_PROFILE.name, profile_sha256, rules_sha256


def _validated_cases(rows: list[Any], fixture_root: Path) -> tuple[_Case, ...]:
    if not rows:
        raise _PackValidationError("expectations_cases_empty")
    cases: list[_Case] = []
    case_ids: set[str] = set()
    files: set[str] = set()
    for row in rows:
        _exact_keys(
            row,
            {"case_id", "language", "category", "expected", "rule_id", "file", "source_sha256"},
            "case_schema_invalid",
        )
        case_id = row.get("case_id")
        language = row.get("language")
        category = row.get("category")
        expected = row.get("expected")
        rule_id = row.get("rule_id")
        file = row.get("file")
        source_sha256 = row.get("source_sha256")
        if not isinstance(case_id, str) or not _CASE_ID_RE.fullmatch(case_id):
            raise _PackValidationError("case_id_invalid")
        if case_id in case_ids:
            raise _PackValidationError("duplicate_case_id")
        if language not in REQUIRED_LANGUAGES or category not in REQUIRED_CATEGORIES:
            raise _PackValidationError("case_taxonomy_invalid")
        if expected not in {"vulnerable", "clean"}:
            raise _PackValidationError("case_expected_outcome_invalid")
        if not isinstance(rule_id, str) or not _RULE_ID_RE.fullmatch(rule_id):
            raise _PackValidationError("case_rule_id_invalid")
        if rule_id != _RULE_IDS[language][category]:
            raise _PackValidationError("case_rule_contract_invalid")
        if not isinstance(file, str) or not _safe_relative_path(file):
            raise _PackValidationError("case_file_invalid")
        if not file.endswith(_LANGUAGE_SUFFIX[language]):
            raise _PackValidationError("case_file_language_mismatch")
        if file in files:
            raise _PackValidationError("duplicate_case_file")
        if not _valid_sha256(source_sha256):
            raise _PackValidationError("case_source_hash_invalid")
        source_path = _contained_file(fixture_root, file, "case_file_invalid")
        try:
            if source_path.stat().st_size <= 0 or source_path.stat().st_size > _MAX_FIXTURE_BYTES:
                raise _PackValidationError("fixture_size_invalid")
            actual_source_sha256 = _sha256(source_path.read_bytes())
        except _PackValidationError:
            raise
        except OSError as exc:
            raise _PackValidationError("case_file_invalid") from exc
        if actual_source_sha256 != source_sha256:
            raise _PackValidationError("fixture_hash_mismatch")
        case_ids.add(case_id)
        files.add(file)
        cases.append(
            _Case(
                case_id=case_id,
                language=language,
                category=category,
                expected=expected,
                rule_id=rule_id,
                file=file,
                source_sha256=source_sha256,
            )
        )
    result = tuple(sorted(cases, key=lambda item: (REQUIRED_LANGUAGES.index(item.language), item.case_id)))
    coverage = _coverage(result)
    if not coverage["all_nine_languages"] or not coverage["minimum_case_balance"]:
        raise _PackValidationError("case_language_coverage_invalid")
    if not coverage["all_categories"]:
        raise _PackValidationError("case_category_coverage_invalid")
    return result


def _fixture_inventory(root: Path) -> set[str]:
    inventory: set[str] = set()
    try:
        for path in root.rglob("*"):
            if path.is_symlink():
                raise _PackValidationError("fixture_symlink_disallowed")
            if path.is_file():
                relative_path = path.relative_to(root)
                if "__pycache__" in relative_path.parts and path.suffix in {".pyc", ".pyo"}:
                    continue
                relative = relative_path.as_posix()
                if not _safe_relative_path(relative):
                    raise _PackValidationError("fixture_inventory_invalid")
                inventory.add(relative)
    except _PackValidationError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise _PackValidationError("fixture_inventory_invalid") from exc
    return inventory


def _pack_digest(
    root: Path,
    fixture_relative: str,
    manifest_bytes: bytes,
    expectation_relative: str,
    expectations_bytes: bytes,
    cases: tuple[_Case, ...],
) -> str:
    files = [
        {"path": "pack.json", "sha256": _sha256(manifest_bytes)},
        {"path": expectation_relative, "sha256": _sha256(expectations_bytes)},
    ]
    for case in sorted(cases, key=lambda item: item.file):
        files.append({"path": f"{fixture_relative}/{case.file}", "sha256": case.source_sha256})
    contract = json.dumps(
        {"schema": "k_guard_language_validation_pack_digest.v1", "files": files},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return _sha256(contract.encode("ascii"))


def _contained_file(root: Path, relative: str, error: str) -> Path:
    candidate = _contained_path(root, relative, error)
    try:
        if not candidate.is_file():
            raise _PackValidationError(error)
    except OSError as exc:
        raise _PackValidationError(error) from exc
    return candidate


def _contained_directory(root: Path, relative: str, error: str) -> Path:
    candidate = _contained_path(root, relative, error)
    try:
        if not candidate.is_dir():
            raise _PackValidationError(error)
    except OSError as exc:
        raise _PackValidationError(error) from exc
    return candidate


def _contained_path(root: Path, relative: str, error: str) -> Path:
    if not _safe_relative_path(relative):
        raise _PackValidationError(error)
    current = root
    try:
        for part in PurePosixPath(relative).parts:
            current = current / part
            if current.is_symlink():
                raise _PackValidationError("pack_symlink_disallowed")
        resolved = current.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise _PackValidationError("pack_path_escape")
    except _PackValidationError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise _PackValidationError(error) from exc
    return resolved


def _safe_relative_path(value: str) -> bool:
    if not value or "\\" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and value == path.as_posix()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _profile_matches_pack(run: AnalyzerRun, pack: _Pack) -> bool:
    return (
        run.profile_name == pack.profile_name
        and run.profile_sha256 == pack.profile_sha256
        and run.rules_sha256 == pack.rules_sha256
    )


def _executable_version_matches_pack(run: AnalyzerRun, pack: _Pack) -> bool:
    return run.executable_version == pack.executable_version


def _target_coverage_matches_pack(run: AnalyzerRun, pack: _Pack) -> bool:
    coverage = dict(run.target_coverage)
    return (
        coverage.get("schema") == TARGET_COVERAGE_SCHEMA
        and coverage.get("result") == "exact"
        and coverage.get("eligible_target_count") == len(pack.cases)
        and coverage.get("scanned_target_count") == len(pack.cases)
        and coverage.get("eligible_path_set_sha256") == pack.target_path_set_sha256
        and coverage.get("scanned_path_set_sha256") == pack.target_path_set_sha256
        and coverage.get("raw_free") is True
    )


def _analyzer_identity_complete(run: AnalyzerRun) -> bool:
    return all(
        _valid_sha256(value)
        for value in (run.adapter_sha256, run.profile_sha256, run.rules_sha256, run.command_contract_sha256)
    )


def _run_contract_equal(left: AnalyzerRun, right: AnalyzerRun) -> bool:
    fields = (
        "analyzer",
        "analyzer_subtype",
        "executable_version",
        "adapter_version",
        "profile_name",
        "adapter_sha256",
        "profile_sha256",
        "rules_sha256",
        "command_contract_sha256",
    )
    return (
        all(getattr(left, field) == getattr(right, field) for field in fields)
        and dict(left.input_snapshot) == dict(right.input_snapshot)
        and dict(left.target_coverage) == dict(right.target_coverage)
    )


def _score_cases(
    cases: tuple[_Case, ...],
    findings: tuple[AnalyzerFinding, ...],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    by_file = {case.file: case for case in cases}
    findings_by_file: dict[str, list[AnalyzerFinding]] = {}
    unmapped: list[dict[str, Any]] = []
    for finding in findings:
        findings_by_file.setdefault(finding.file, []).append(finding)
        case = by_file.get(finding.file)
        if case is None or (case.expected == "vulnerable" and finding.rule_id != case.rule_id):
            unmapped.append(
                {
                    "rule_id": finding.rule_id,
                    "file": finding.file,
                    "fingerprint": finding.fingerprint,
                }
            )

    counters = {language: Counter() for language in REQUIRED_LANGUAGES}
    overall: Counter[str] = Counter()
    case_results: list[dict[str, Any]] = []
    for case in cases:
        observed = findings_by_file.get(case.file, [])
        expected_matches = [finding for finding in observed if finding.rule_id == case.rule_id]
        if case.expected == "vulnerable":
            outcome = "tp" if expected_matches else "fn"
        else:
            outcome = "fp" if observed else "tn"
        counters[case.language][outcome] += 1
        overall[outcome] += 1
        case_results.append(
            {
                "case_id": case.case_id,
                "language": case.language,
                "category": case.category,
                "expected": case.expected,
                "rule_id": case.rule_id,
                "file": case.file,
                "outcome": outcome,
                "observed_finding_count": len(observed),
                "expected_rule_finding_count": len(expected_matches),
                "observed_rule_ids": sorted({finding.rule_id for finding in observed}),
            }
        )
    metrics = {
        "by_language": {language: _metric(counters[language]) for language in REQUIRED_LANGUAGES},
        "overall": _metric(overall),
    }
    unmapped.sort(key=lambda item: (item["file"], item["rule_id"], item["fingerprint"]))
    return metrics, case_results, unmapped


def _metric(counts: Counter[str]) -> dict[str, Any]:
    tp = counts["tp"]
    fn = counts["fn"]
    fp = counts["fp"]
    tn = counts["tn"]
    return {
        "confusion_matrix": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
        "recall": _rate(tp, tp + fn),
        "specificity": _rate(tn, tn + fp),
        "precision": _rate(tp, tp + fp),
    }


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _coverage(cases: tuple[_Case, ...]) -> dict[str, bool]:
    languages = {case.language for case in cases}
    minimum_case_balance = True
    all_categories = True
    for language in REQUIRED_LANGUAGES:
        language_cases = [case for case in cases if case.language == language]
        for expected in ("vulnerable", "clean"):
            selected = [case for case in language_cases if case.expected == expected]
            minimum_case_balance = minimum_case_balance and len(selected) >= 5
            all_categories = all_categories and {case.category for case in selected} == set(REQUIRED_CATEGORIES)
    return {
        "all_nine_languages": languages == set(REQUIRED_LANGUAGES),
        "minimum_case_balance": minimum_case_balance,
        "all_categories": all_categories,
    }


def _case_counts(cases: tuple[_Case, ...]) -> dict[str, Any]:
    by_language: dict[str, dict[str, int]] = {}
    for language in REQUIRED_LANGUAGES:
        selected = [case for case in cases if case.language == language]
        vulnerable = sum(case.expected == "vulnerable" for case in selected)
        clean = sum(case.expected == "clean" for case in selected)
        by_language[language] = {"total": len(selected), "vulnerable": vulnerable, "clean": clean}
    return {
        "total": len(cases),
        "vulnerable": sum(case.expected == "vulnerable" for case in cases),
        "clean": sum(case.expected == "clean" for case in cases),
        "by_language": by_language,
    }


def _repeat_report(
    primary: Counter[str],
    repeated: Counter[str],
    requested: bool,
    exact: bool,
) -> dict[str, Any]:
    primary_rows = _multiset_rows(primary)
    repeated_rows = _multiset_rows(repeated) if requested else []
    return {
        "requested": requested,
        "performed": requested,
        "exact": exact,
        "primary_finding_count": sum(primary.values()),
        "repeat_finding_count": sum(repeated.values()) if requested else 0,
        "primary_fingerprint_multiset": primary_rows,
        "repeat_fingerprint_multiset": repeated_rows,
        "primary_fingerprint_multiset_sha256": _json_sha256(primary_rows),
        "repeat_fingerprint_multiset_sha256": _json_sha256(repeated_rows) if requested else "",
    }


def _multiset_rows(values: Counter[str]) -> list[dict[str, Any]]:
    return [{"fingerprint": fingerprint, "count": values[fingerprint]} for fingerprint in sorted(values)]


def _run_summary(run: AnalyzerRun) -> dict[str, Any]:
    return {
        "complete": run.complete,
        "control_errors": _safe_control_errors(run.control_errors),
        "finding_count": len(run.findings),
        "analyzer": run.analyzer,
        "analyzer_subtype": run.analyzer_subtype,
        "executable_version": run.executable_version if _VERSION_RE.fullmatch(run.executable_version) else "",
        "adapter_version": run.adapter_version if _VERSION_RE.fullmatch(run.adapter_version) else "",
        "profile_name": run.profile_name if run.profile_name == DEFAULT_SEMGREP_PROFILE.name else "",
        "input_tree_sha256": str(run.input_snapshot.get("tree_sha256") or "") if run.input_snapshot.get("complete") is True else "",
        "input_snapshot_complete": run.input_snapshot.get("complete") is True,
        "target_coverage": dict(run.target_coverage),
        "raw_free": True,
    }


def _hash_report(pack: _Pack, run: AnalyzerRun | None) -> dict[str, str]:
    return {
        "pack_sha256": pack.pack_sha256,
        "expectations_sha256": pack.expectations_sha256,
        "profile_sha256": pack.profile_sha256,
        "profile_rules_sha256": pack.rules_sha256,
        "validator_sha256": _sha256(Path(__file__).read_bytes()),
        "adapter_sha256": run.adapter_sha256 if run and _valid_sha256(run.adapter_sha256) else "",
        "adapter_command_contract_sha256": (
            run.command_contract_sha256 if run and _valid_sha256(run.command_contract_sha256) else ""
        ),
        "semgrep_executable_version_sha256": _sha256(pack.executable_version.encode("ascii")),
    }


def _seal_report(report: dict[str, Any]) -> dict[str, Any]:
    report["evidence_bundle"] = evidence_bundle(
        subject="nine_language_intrafile_development_validation",
        producer="k_guard_mcp.language_validation",
        artifacts=[object_artifact("language-validation-report", report, role="validation")],
    )
    return report


def _failure_report(
    errors: tuple[str, ...],
    *,
    pack: _Pack | None = None,
    runs: tuple[AnalyzerRun, ...] = (),
    repeat_requested: bool = True,
) -> dict[str, Any]:
    safe_errors = list(dict.fromkeys(_safe_control_errors(errors))) or ["language_validation_control_failure"]
    primary = runs[0] if runs else None
    return _seal_report({
        "schema": REPORT_SCHEMA,
        "complete": False,
        "ready": False,
        "status": "control_failure",
        "control_errors": safe_errors,
        "raw_free": True,
        "claim_boundary": _claim_boundary(),
        "pack": {
            "pack_id": pack.pack_id if pack else "",
            "schema": PACK_SCHEMA,
            "expectations_schema": EXPECTATIONS_SCHEMA,
            "expectations_immutable": bool(pack),
            "profile_name": pack.profile_name if pack else DEFAULT_SEMGREP_PROFILE.name,
            "analyzer": {
                "name": "semgrep" if pack else "",
                "executable_version": pack.executable_version if pack else "",
            },
        },
        "languages": list(REQUIRED_LANGUAGES) if pack else [],
        "case_counts": _case_counts(pack.cases) if pack else {},
        "metrics": None,
        "case_results": [],
        "unmapped_findings": [],
        "repeat": {
            "requested": repeat_requested,
            "performed": repeat_requested and len(runs) == 2,
            "exact": False,
            "primary_finding_count": len(primary.findings) if primary and primary.complete else 0,
            "repeat_finding_count": len(runs[1].findings) if len(runs) == 2 and runs[1].complete else 0,
            "primary_fingerprint_multiset": [],
            "repeat_fingerprint_multiset": [],
            "primary_fingerprint_multiset_sha256": "",
            "repeat_fingerprint_multiset_sha256": "",
        },
        "requirements": {
            "all_expected_positives_found": False,
            "zero_clean_case_false_positives": False,
            "exact_repeat_fingerprint_multiset": False,
            "all_nine_languages": False,
            "minimum_five_vulnerable_and_five_clean_per_language": False,
            "all_five_categories_per_language_and_outcome": False,
            "all_findings_mapped": False,
            "bundled_profile_exact": False,
            "pinned_semgrep_executable_version": False,
            "exact_target_coverage": False,
            "analyzer_complete": False,
        },
        "hashes": _hash_report(pack, primary) if pack else _empty_hash_report(),
        "analyzer_runs": [_run_summary(run) for run in runs],
    })


def _empty_hash_report() -> dict[str, str]:
    return {
        "pack_sha256": "",
        "expectations_sha256": "",
        "profile_sha256": "",
        "profile_rules_sha256": "",
        "validator_sha256": "",
        "adapter_sha256": "",
        "adapter_command_contract_sha256": "",
        "semgrep_executable_version_sha256": "",
    }


def _claim_boundary() -> dict[str, Any]:
    return {
        "claim": CLAIM_BOUNDARY,
        "development_validation": True,
        "field_accuracy_claimed": False,
        "analysis_scope": "semgrep_ce_intrafile",
        "interfile_dataflow_claimed": False,
        "framework_authorization_proof_claimed": False,
        "not_a_certificate": True,
    }


def _safe_control_errors(values: tuple[str, ...] | list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value)
        result.append(text if _CONTROL_RE.fullmatch(text) else "analyzer_control_error")
    return list(dict.fromkeys(result))


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _json_sha256(value: Any) -> str:
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return _sha256(rendered.encode("ascii"))


def _path_set_sha256(paths: Iterable[str]) -> str:
    return _json_sha256({"schema": PATH_SET_SCHEMA, "paths": sorted(paths)})
