from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping

from k_guard_mcp.benchmark_adapters import OWASP_CATEGORY_RULES
from k_guard_mcp.scanner import KGuardScanner


SCHEMA = "k_guard_l1_full_baseline.v1"
MANIFEST_SCHEMA = "k_guard_l1_corpus_manifest.v1"
HIGH_CRITICAL = frozenset({"high", "critical"})
CASE_ID_RE = re.compile(r"BenchmarkTest\d{5}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
SAFE_RULE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}\Z")


class L1BenchmarkError(ValueError):
    """Raised when a pinned L1 corpus or execution contract is invalid."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_count = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            byte_count += len(chunk)
    return digest.hexdigest(), byte_count


def _reject_duplicate_keys(pairs: Iterable[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise L1BenchmarkError("manifest_duplicate_json_key")
        result[key] = value
    return result


def _safe_relative(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise L1BenchmarkError("manifest_path_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise L1BenchmarkError("manifest_path_invalid")
    return value


def _sha256(value: object, code: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise L1BenchmarkError(code)
    return value


def _regular_file(root: Path, relative: str) -> Path:
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    try:
        metadata = candidate.stat(follow_symlinks=False)
    except OSError as exc:
        raise L1BenchmarkError("corpus_file_missing") from exc
    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        candidate.is_symlink()
        or (reparse_point and getattr(metadata, "st_file_attributes", 0) & reparse_point)
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise L1BenchmarkError("corpus_file_not_regular")
    return candidate


def _read_manifest(path: str | Path) -> tuple[dict[str, Any], str]:
    try:
        raw = Path(path).resolve(strict=True).read_bytes()
        decoded = raw.decode("utf-8")
        value = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
    except L1BenchmarkError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise L1BenchmarkError("manifest_unreadable") from exc
    if not isinstance(value, dict):
        raise L1BenchmarkError("manifest_not_object")
    return value, _sha256_bytes(raw)


def _validate_manifest(value: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    required = {
        "corpora",
        "corpus_count",
        "coverage_policy",
        "lane",
        "scanner_output_observed",
        "schema",
        "status",
        "total_case_count",
        "unsupported_detector_category_policy",
    }
    if set(value) != required:
        raise L1BenchmarkError("manifest_schema_invalid")
    if (
        value.get("schema") != MANIFEST_SCHEMA
        or value.get("status") != "locked_before_scan"
        or value.get("lane") != "L1"
        or value.get("scanner_output_observed") is not False
        or value.get("coverage_policy") != "all_official_rows_exactly_once"
        or value.get("unsupported_detector_category_policy") != "retain_in_denominator"
    ):
        raise L1BenchmarkError("manifest_contract_invalid")
    corpora = value.get("corpora")
    if not isinstance(corpora, list) or value.get("corpus_count") != 2:
        raise L1BenchmarkError("manifest_corpora_invalid")
    by_language: dict[str, dict[str, Any]] = {}
    total = 0
    for corpus in corpora:
        if not isinstance(corpus, dict):
            raise L1BenchmarkError("manifest_corpus_invalid")
        language = corpus.get("language")
        if language not in {"java", "python"} or language in by_language:
            raise L1BenchmarkError("manifest_language_invalid")
        _validate_corpus_shape(corpus)
        cases = corpus["cases"]
        total += len(cases)
        by_language[language] = corpus
    if set(by_language) != {"java", "python"} or value.get("total_case_count") != total:
        raise L1BenchmarkError("manifest_case_count_invalid")
    return by_language


def _validate_corpus_shape(corpus: Mapping[str, Any]) -> None:
    required = {
        "case_set_schema",
        "case_set_sha256",
        "cases",
        "commit_tree_sha1",
        "corpus_id",
        "expected_results",
        "language",
        "license",
        "repository_origin",
        "revision_sha1",
        "source_tree",
    }
    if set(corpus) != required:
        raise L1BenchmarkError("manifest_corpus_schema_invalid")
    if not isinstance(corpus.get("corpus_id"), str) or not corpus["corpus_id"]:
        raise L1BenchmarkError("manifest_corpus_id_invalid")
    _sha256(corpus.get("case_set_sha256"), "manifest_case_set_sha256_invalid")
    if not isinstance(corpus.get("cases"), list) or not corpus["cases"]:
        raise L1BenchmarkError("manifest_cases_invalid")
    for value in (corpus.get("revision_sha1"), corpus.get("commit_tree_sha1")):
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
            raise L1BenchmarkError("manifest_revision_invalid")
    if not isinstance(corpus.get("repository_origin"), str) or not corpus["repository_origin"].startswith("https://"):
        raise L1BenchmarkError("manifest_origin_invalid")
    _validate_file_binding(corpus.get("expected_results"), "manifest_expected_results")
    _validate_file_binding(corpus.get("license"), "manifest_license")
    _validate_source_tree(corpus.get("source_tree"))
    seen_case_ids: set[str] = set()
    seen_paths: set[str] = set()
    for case in corpus["cases"]:
        if not isinstance(case, dict) or set(case) != {
            "case_id",
            "category",
            "cwe",
            "source_bytes",
            "source_path",
            "source_sha256",
            "truth",
        }:
            raise L1BenchmarkError("manifest_case_schema_invalid")
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or CASE_ID_RE.fullmatch(case_id) is None or case_id in seen_case_ids:
            raise L1BenchmarkError("manifest_case_id_invalid")
        source_path = _safe_relative(case.get("source_path"))
        if source_path in seen_paths:
            raise L1BenchmarkError("manifest_case_source_duplicate")
        if not isinstance(case.get("category"), str) or not case["category"]:
            raise L1BenchmarkError("manifest_case_category_invalid")
        if not isinstance(case.get("cwe"), str) or re.fullmatch(r"CWE-\d{1,5}", case["cwe"]) is None:
            raise L1BenchmarkError("manifest_case_cwe_invalid")
        if case.get("truth") not in {"present", "absent"}:
            raise L1BenchmarkError("manifest_case_truth_invalid")
        if not isinstance(case.get("source_bytes"), int) or case["source_bytes"] < 0:
            raise L1BenchmarkError("manifest_case_bytes_invalid")
        _sha256(case.get("source_sha256"), "manifest_case_source_sha256_invalid")
        seen_case_ids.add(case_id)
        seen_paths.add(source_path)


def _validate_file_binding(value: object, prefix: str) -> None:
    if not isinstance(value, dict) or set(value) - {"path", "sha256", "byte_count", "row_count", "unique_case_count", "spdx"}:
        raise L1BenchmarkError(f"{prefix}_invalid")
    _safe_relative(value.get("path"))
    _sha256(value.get("sha256"), f"{prefix}_sha256_invalid")
    if not isinstance(value.get("byte_count"), int) or value["byte_count"] < 0:
        raise L1BenchmarkError(f"{prefix}_bytes_invalid")


def _validate_source_tree(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "file_count",
        "files",
        "index_tree_match",
        "no_untracked_or_ignored_physical_files",
        "physical_bytes_match_git_blobs",
        "schema",
        "source_tree_sha256",
        "source_worktree_clean",
        "source_worktree_clean_method",
        "total_bytes",
    }:
        raise L1BenchmarkError("manifest_source_tree_invalid")
    if (
        value.get("schema") != "k_guard_materialized_source_tree.v1"
        or value.get("index_tree_match") is not True
        or value.get("no_untracked_or_ignored_physical_files") is not True
        or value.get("physical_bytes_match_git_blobs") is not True
        or value.get("source_worktree_clean") is not True
    ):
        raise L1BenchmarkError("manifest_source_tree_contract_invalid")
    _sha256(value.get("source_tree_sha256"), "manifest_source_tree_sha256_invalid")
    files = value.get("files")
    if not isinstance(files, list) or value.get("file_count") != len(files):
        raise L1BenchmarkError("manifest_source_tree_files_invalid")
    if not isinstance(value.get("total_bytes"), int) or value["total_bytes"] < 0:
        raise L1BenchmarkError("manifest_source_tree_bytes_invalid")
    seen: set[str] = set()
    for row in files:
        if not isinstance(row, dict) or set(row) != {"byte_count", "git_blob_sha1", "mode", "path", "sha256"}:
            raise L1BenchmarkError("manifest_source_tree_file_schema_invalid")
        path = _safe_relative(row.get("path"))
        if path in seen:
            raise L1BenchmarkError("manifest_source_tree_file_duplicate")
        if not isinstance(row.get("byte_count"), int) or row["byte_count"] < 0:
            raise L1BenchmarkError("manifest_source_tree_file_bytes_invalid")
        _sha256(row.get("sha256"), "manifest_source_tree_file_sha256_invalid")
        if not isinstance(row.get("git_blob_sha1"), str) or re.fullmatch(r"[0-9a-f]{40}", row["git_blob_sha1"]) is None:
            raise L1BenchmarkError("manifest_source_tree_blob_invalid")
        seen.add(path)


def _verify_corpus(corpus: Mapping[str, Any], root: Path) -> dict[str, Any]:
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise L1BenchmarkError("corpus_root_unreadable") from exc
    if not resolved.is_dir() or resolved.is_symlink():
        raise L1BenchmarkError("corpus_root_invalid")
    source_tree = corpus["source_tree"]
    expected_files = {str(item["path"]): item for item in source_tree["files"]}
    observed_paths = _workspace_regular_files(resolved)
    if set(observed_paths) != set(expected_files):
        raise L1BenchmarkError("corpus_tree_file_set_mismatch")
    total_bytes = 0
    for relative, expected in expected_files.items():
        path = _regular_file(resolved, relative)
        actual_hash, actual_bytes = _sha256_file(path)
        if actual_hash != expected["sha256"] or actual_bytes != expected["byte_count"]:
            raise L1BenchmarkError("corpus_tree_content_mismatch")
        total_bytes += actual_bytes
    if total_bytes != source_tree["total_bytes"]:
        raise L1BenchmarkError("corpus_tree_total_bytes_mismatch")
    for label in ("expected_results", "license"):
        binding = corpus[label]
        path = _regular_file(resolved, str(binding["path"]))
        actual_hash, actual_bytes = _sha256_file(path)
        if actual_hash != binding["sha256"] or actual_bytes != binding["byte_count"]:
            raise L1BenchmarkError(f"corpus_{label}_mismatch")
    for case in corpus["cases"]:
        path = _regular_file(resolved, str(case["source_path"]))
        actual_hash, actual_bytes = _sha256_file(path)
        if actual_hash != case["source_sha256"] or actual_bytes != case["source_bytes"]:
            raise L1BenchmarkError("corpus_case_content_mismatch")
    return {
        "corpus_id": corpus["corpus_id"],
        "language": corpus["language"],
        "case_count": len(corpus["cases"]),
        "source_tree_sha256": source_tree["source_tree_sha256"],
        "source_tree_file_count": source_tree["file_count"],
        "source_tree_total_bytes": source_tree["total_bytes"],
        "expected_results_sha256": corpus["expected_results"]["sha256"],
        "license_sha256": corpus["license"]["sha256"],
        "verified": True,
        "raw_returned": False,
    }


def _workspace_regular_files(root: Path) -> set[str]:
    discovered: set[str] = set()
    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        directories[:] = [name for name in directories if name != ".git"]
        for name in directories:
            candidate = current / name
            metadata = candidate.stat(follow_symlinks=False)
            if candidate.is_symlink() or (reparse_point and getattr(metadata, "st_file_attributes", 0) & reparse_point):
                raise L1BenchmarkError("corpus_tree_link_invalid")
        for name in files:
            if name == ".git":
                continue
            candidate = current / name
            metadata = candidate.stat(follow_symlinks=False)
            if candidate.is_symlink() or (reparse_point and getattr(metadata, "st_file_attributes", 0) & reparse_point):
                raise L1BenchmarkError("corpus_tree_link_invalid")
            if not stat.S_ISREG(metadata.st_mode):
                raise L1BenchmarkError("corpus_tree_nonregular_file")
            relative = candidate.relative_to(root).as_posix()
            discovered.add(_safe_relative(relative))
    return discovered


def _finding_value(finding: object, name: str, default: object = None) -> object:
    if isinstance(finding, Mapping):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _relative_finding_path(value: object, root: Path) -> str | None:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        return None
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=False)
        return resolved.relative_to(root).as_posix()
    except (OSError, RuntimeError, ValueError):
        return None


def _candidate_rows(scan_result: object, corpus: Mapping[str, Any], root: Path) -> list[dict[str, Any]]:
    findings = getattr(scan_result, "findings", None)
    if not isinstance(findings, Iterable):
        raise L1BenchmarkError("scanner_result_contract_invalid")
    source_to_case = {str(case["source_path"]): case for case in corpus["cases"]}
    candidates: list[dict[str, Any]] = []
    for finding in findings:
        severity = str(_finding_value(finding, "severity", "")).lower()
        if severity not in HIGH_CRITICAL:
            continue
        rule_id = str(_finding_value(finding, "rule_id", ""))
        if SAFE_RULE_RE.fullmatch(rule_id) is None:
            raise L1BenchmarkError("scanner_rule_id_invalid")
        relative = _relative_finding_path(_finding_value(finding, "file"), root)
        case = source_to_case.get(relative or "")
        source = str(_finding_value(finding, "source", "unknown"))
        if not source or len(source) > 128 or "\x00" in source or "\n" in source or "\r" in source:
            raise L1BenchmarkError("scanner_source_invalid")
        line_start = _finding_value(finding, "line_start", None)
        line_end = _finding_value(finding, "line_end", None)
        if not isinstance(line_start, int) or line_start < 1:
            line_start = 0
        if not isinstance(line_end, int) or line_end < line_start:
            line_end = line_start
        fingerprint_input = {
            "corpus_id": corpus["corpus_id"],
            "case_id": case["case_id"] if case else "",
            "source": source,
            "rule_id": rule_id,
            "severity": severity,
            "line_start": line_start,
            "line_end": line_end,
        }
        candidates.append(
            {
                "candidate_ref": _sha256_bytes(canonical_json_bytes(fingerprint_input)),
                "case_id": case["case_id"] if case else "",
                "rule_id": rule_id,
                "severity": severity,
                "detector_subtype": source,
                "location_kind": "source" if relative else "outside_workspace",
                "line_present": line_start > 0,
                "oracle_disposition": "outside_official_case_unpaired" if case is None else "pending",
                "raw_returned": False,
            }
        )
    return sorted(candidates, key=lambda item: (str(item["candidate_ref"]), str(item["rule_id"])))


def _wilson_lower(successes: int, total: int, z: float = 1.959963984540054) -> float:
    if total <= 0:
        return 0.0
    observed = successes / total
    denominator = 1 + z * z / total
    centre = observed + z * z / (2 * total)
    margin = z * ((observed * (1 - observed) + z * z / (4 * total)) / total) ** 0.5
    return round((centre - margin) / denominator, 6)


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _metric(counts: Counter[str]) -> dict[str, Any]:
    tp = counts["tp"]
    fp = counts["fp"]
    fn = counts["fn"]
    tn = counts["tn"]
    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": _ratio(tp, tp + fp),
        "precision_wilson_95_lower": _wilson_lower(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
        "recall_wilson_95_lower": _wilson_lower(tp, tp + fn),
        "specificity": _ratio(tn, tn + fp),
        "specificity_wilson_95_lower": _wilson_lower(tn, tn + fp),
    }


def _score_corpus(corpus: Mapping[str, Any], candidates: list[dict[str, Any]]) -> dict[str, Any]:
    by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        if candidate["case_id"]:
            by_case[str(candidate["case_id"])].append(candidate)
    counters: Counter[str] = Counter()
    per_category: dict[str, Counter[str]] = defaultdict(Counter)
    case_results: list[dict[str, Any]] = []
    for case in corpus["cases"]:
        case_id = str(case["case_id"])
        category = str(case["category"])
        rules = frozenset(OWASP_CATEGORY_RULES.get(category, ()))
        observed = by_case.get(case_id, [])
        matched = [candidate for candidate in observed if candidate["rule_id"] in rules]
        unmatched = [candidate for candidate in observed if candidate["rule_id"] not in rules]
        supported = bool(rules)
        if not supported:
            outcome = "unsupported"
            for candidate in observed:
                candidate["oracle_disposition"] = "unsupported_category_unpaired"
        elif case["truth"] == "present":
            outcome = "tp" if matched else "fn"
            counters[outcome] += 1
            per_category[category][outcome] += 1
            if matched:
                matched[0]["oracle_disposition"] = "true_positive"
                for candidate in matched[1:]:
                    candidate["oracle_disposition"] = "duplicate_match_unpaired"
            for candidate in unmatched:
                candidate["oracle_disposition"] = "unmapped_rule_unpaired"
        else:
            outcome = "fp" if matched else "tn"
            counters[outcome] += 1
            per_category[category][outcome] += 1
            for candidate in matched:
                candidate["oracle_disposition"] = "false_positive"
            for candidate in unmatched:
                candidate["oracle_disposition"] = "unmapped_rule_unpaired"
        case_results.append(
            {
                "case_id": case_id,
                "category": category,
                "cwe": case["cwe"],
                "expected": "vulnerable" if case["truth"] == "present" else "clean",
                "mapped_rule_ids": sorted(rules),
                "supported": supported,
                "outcome": outcome,
                "matched_candidate_refs": sorted(str(candidate["candidate_ref"]) for candidate in matched),
                "unpaired_candidate_refs": sorted(
                    str(candidate["candidate_ref"])
                    for candidate in observed
                    if candidate["oracle_disposition"].endswith("unpaired")
                ),
                "raw_returned": False,
            }
        )
    labeled_tp = sum(candidate["oracle_disposition"] == "true_positive" for candidate in candidates)
    labeled_fp = sum(candidate["oracle_disposition"] == "false_positive" for candidate in candidates)
    unpaired = [candidate for candidate in candidates if str(candidate["oracle_disposition"]).endswith("unpaired")]
    distribution = Counter(str(candidate["rule_id"]) for candidate in candidates)
    total_candidates = len(candidates)
    supported_count = sum(item["supported"] for item in case_results)
    return {
        "corpus_id": corpus["corpus_id"],
        "language": corpus["language"],
        "official_denominator": {
            "total_case_count": len(case_results),
            "supported_case_count": supported_count,
            "unsupported_case_count": len(case_results) - supported_count,
            "unsupported_cases_retained": True,
            "full_official_metric_eligible": supported_count == len(case_results),
        },
        "scenario_metrics": {
            "mapped_categories_only": True,
            "metrics": _metric(counters),
            "by_category": {category: _metric(per_category[category]) for category in sorted(per_category)},
        },
        "candidate_oracle_coverage": {
            "total_high_critical_candidate_count": total_candidates,
            "labeled_true_positive_count": labeled_tp,
            "labeled_false_positive_count": labeled_fp,
            "unpaired_candidate_count": len(unpaired),
            "one_finding_to_one_oracle_complete": len(unpaired) == 0,
            "candidate_precision_eligible": len(unpaired) == 0,
            "labeled_candidate_precision": _ratio(labeled_tp, labeled_tp + labeled_fp),
            "labeled_candidate_precision_wilson_95_lower": _wilson_lower(
                labeled_tp, labeled_tp + labeled_fp
            ),
        },
        "candidate_rule_distribution": [
            {"rule_id": rule_id, "count": count, "share": _ratio(count, total_candidates)}
            for rule_id, count in sorted(distribution.items(), key=lambda item: (-item[1], item[0]))
        ],
        "case_results": case_results,
        "candidate_registry": candidates,
        "raw_returned": False,
    }


def _report_fingerprint(report: Mapping[str, Any]) -> str:
    payload = {
        "case_results": report["case_results"],
        "candidate_registry": report["candidate_registry"],
        "official_denominator": report["official_denominator"],
    }
    return _sha256_bytes(canonical_json_bytes(payload))


def _execution_binding(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {"bound": False, "raw_returned": False}
    if set(value) != {"baseline_receipt_sha256", "target"}:
        raise L1BenchmarkError("execution_binding_schema_invalid")
    target = value.get("target")
    if not isinstance(target, Mapping) or set(target) != {
        "head_git_oid",
        "dirty_path_set_sha256",
        "dirty_worktree_sha256",
    }:
        raise L1BenchmarkError("execution_binding_target_invalid")
    for key in ("baseline_receipt_sha256", "dirty_path_set_sha256", "dirty_worktree_sha256"):
        _sha256(value[key] if key == "baseline_receipt_sha256" else target[key], "execution_binding_hash_invalid")
    if not isinstance(target["head_git_oid"], str) or re.fullmatch(r"[0-9a-f]{40}", target["head_git_oid"]) is None:
        raise L1BenchmarkError("execution_binding_head_invalid")
    return {
        "bound": True,
        "baseline_receipt_sha256": value["baseline_receipt_sha256"],
        "target": dict(target),
        "raw_returned": False,
    }


def _control_hold(
    *,
    manifest_sha256: str,
    binding: Mapping[str, Any],
    errors: Iterable[str],
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "complete": False,
        "status": "CONTROL_HOLD",
        "control_errors": sorted(set(errors)) or ["l1_control_failure"],
        "manifest_sha256": manifest_sha256,
        "execution_binding": dict(binding),
        "runs": [],
        "aggregate": None,
        "repeat": {"requested": True, "performed": False, "exact": False, "raw_returned": False},
        "claim_boundary": {
            "public_development_benchmark_only": True,
            "release_gate_passed": False,
            "product_accuracy_proven": False,
            "raw_returned": False,
        },
        "raw_returned": False,
    }


def run_l1_baseline(
    manifest_path: str | Path,
    *,
    benchmark_java: str | Path,
    benchmark_python: str | Path,
    scanner_factory: Callable[[], object] = KGuardScanner,
    execution_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the complete pinned L1 corpus twice without promoting a release claim.

    Official OWASP rows stay visible even when K-Guard has no declared category
    mapping. Such rows never become a hidden accuracy denominator.
    """

    try:
        manifest, manifest_sha256 = _read_manifest(manifest_path)
        corpora = _validate_manifest(manifest)
        binding = _execution_binding(execution_binding)
        roots = {
            "java": Path(benchmark_java),
            "python": Path(benchmark_python),
        }
        corpus_integrity_before = {
            language: _verify_corpus(corpus, roots[language])
            for language, corpus in sorted(corpora.items())
        }
    except L1BenchmarkError as exc:
        return _control_hold(
            manifest_sha256=locals().get("manifest_sha256", ""),
            binding=locals().get("binding", {"bound": False, "raw_returned": False}),
            errors=(str(exc),),
        )

    runs: list[dict[str, Any]] = []
    try:
        for run_number in (1, 2):
            per_corpus: list[dict[str, Any]] = []
            for language in ("java", "python"):
                scanner = scanner_factory()
                if not hasattr(scanner, "scan_workspace"):
                    raise L1BenchmarkError("scanner_factory_contract_invalid")
                result = scanner.scan_workspace(roots[language], include_flow=True)
                candidates = _candidate_rows(result, corpora[language], roots[language].resolve(strict=True))
                scored = _score_corpus(corpora[language], candidates)
                scored["candidate_multiset_sha256"] = _sha256_bytes(
                    canonical_json_bytes(sorted(str(item["candidate_ref"]) for item in candidates))
                )
                scored["semantic_fingerprint_sha256"] = _report_fingerprint(scored)
                per_corpus.append(scored)
            runs.append({"run": run_number, "corpora": per_corpus, "raw_returned": False})
        corpus_integrity_after = {
            language: _verify_corpus(corpus, roots[language])
            for language, corpus in sorted(corpora.items())
        }
    except L1BenchmarkError as exc:
        return _control_hold(manifest_sha256=manifest_sha256, binding=binding, errors=(str(exc),))
    except Exception:
        return _control_hold(manifest_sha256=manifest_sha256, binding=binding, errors=("scanner_exception",))

    first_by_language = {row["language"]: row for row in runs[0]["corpora"]}
    second_by_language = {row["language"]: row for row in runs[1]["corpora"]}
    per_corpus_repeat = {
        language: first_by_language[language]["semantic_fingerprint_sha256"]
        == second_by_language[language]["semantic_fingerprint_sha256"]
        for language in ("java", "python")
    }
    aggregate_cases = [case for language in ("java", "python") for case in first_by_language[language]["case_results"]]
    aggregate_candidates = [
        candidate
        for language in ("java", "python")
        for candidate in first_by_language[language]["candidate_registry"]
    ]
    aggregate = _aggregate_results(aggregate_cases, aggregate_candidates)
    repeat_exact = all(per_corpus_repeat.values())
    top_rule_share = max(
        (float(item["share"]) for item in aggregate["candidate_rule_distribution"]),
        default=0.0,
    )
    gate_eligibility = {
        "two_complete_runs": len(runs) == 2,
        "exact_repeat": repeat_exact,
        "all_official_categories_mapped": aggregate["official_denominator"]["full_official_metric_eligible"],
        "one_finding_to_one_oracle_complete": aggregate["candidate_oracle_coverage"]["one_finding_to_one_oracle_complete"],
        "single_rule_candidate_concentration_within_limit": top_rule_share <= 0.5,
        "release_gate_passed": False,
    }
    return {
        "schema": SCHEMA,
        "complete": True,
        "status": "MEASURED_HOLD",
        "control_errors": [],
        "manifest_sha256": manifest_sha256,
        "execution_binding": binding,
        "corpus_integrity_before": corpus_integrity_before,
        "corpus_integrity_after": corpus_integrity_after,
        "runs": runs,
        "aggregate": aggregate,
        "repeat": {
            "requested": True,
            "performed": True,
            "exact": repeat_exact,
            "per_corpus": per_corpus_repeat,
            "raw_returned": False,
        },
        "gate_eligibility": gate_eligibility,
        "claim_boundary": {
            "public_development_benchmark_only": True,
            "official_rows_not_silently_dropped": True,
            "unsupported_categories_retained_in_denominator": True,
            "candidate_oracle_gap_blocks_promotion": True,
            "release_gate_passed": False,
            "product_accuracy_proven": False,
            "raw_returned": False,
        },
        "raw_returned": False,
    }


def _aggregate_results(cases: list[dict[str, Any]], candidates: list[dict[str, Any]]) -> dict[str, Any]:
    counters: Counter[str] = Counter()
    for case in cases:
        if case["outcome"] in {"tp", "fp", "fn", "tn"}:
            counters[str(case["outcome"])] += 1
    labeled_tp = sum(candidate["oracle_disposition"] == "true_positive" for candidate in candidates)
    labeled_fp = sum(candidate["oracle_disposition"] == "false_positive" for candidate in candidates)
    unpaired = [candidate for candidate in candidates if str(candidate["oracle_disposition"]).endswith("unpaired")]
    distribution = Counter(str(candidate["rule_id"]) for candidate in candidates)
    total_candidates = len(candidates)
    supported = sum(case["supported"] for case in cases)
    return {
        "official_denominator": {
            "total_case_count": len(cases),
            "supported_case_count": supported,
            "unsupported_case_count": len(cases) - supported,
            "unsupported_cases_retained": True,
            "full_official_metric_eligible": supported == len(cases),
        },
        "scenario_metrics": {"mapped_categories_only": True, "metrics": _metric(counters)},
        "candidate_oracle_coverage": {
            "total_high_critical_candidate_count": total_candidates,
            "labeled_true_positive_count": labeled_tp,
            "labeled_false_positive_count": labeled_fp,
            "unpaired_candidate_count": len(unpaired),
            "one_finding_to_one_oracle_complete": len(unpaired) == 0,
            "candidate_precision_eligible": len(unpaired) == 0,
            "labeled_candidate_precision": _ratio(labeled_tp, labeled_tp + labeled_fp),
            "labeled_candidate_precision_wilson_95_lower": _wilson_lower(
                labeled_tp, labeled_tp + labeled_fp
            ),
        },
        "candidate_rule_distribution": [
            {"rule_id": rule_id, "count": count, "share": _ratio(count, total_candidates)}
            for rule_id, count in sorted(distribution.items(), key=lambda item: (-item[1], item[0]))
        ],
        "raw_returned": False,
    }


def write_l1_baseline_report(report: Mapping[str, Any], output: str | Path) -> None:
    destination = Path(output)
    if destination.exists() or destination.is_symlink():
        raise L1BenchmarkError("baseline_output_already_exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(dict(report))
    try:
        with destination.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise L1BenchmarkError("baseline_output_already_exists") from exc
