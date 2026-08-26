from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from k_guard_mcp import scanner as _scanner_module
from k_guard_mcp.scanner import KGuardScanner

ANALYZER_PACKAGE_DIR = Path(_scanner_module.__file__).resolve().parent
EXPECTED_ANALYZER_PACKAGE_DIR = (SOURCE_ROOT / "k_guard_mcp").resolve()
if ANALYZER_PACKAGE_DIR != EXPECTED_ANALYZER_PACKAGE_DIR:
    raise RuntimeError(
        "Korean privacy holdout must import k_guard_mcp from this repository's src tree"
    )

try:
    from scripts.evidence_tree import (
        TREE_HASH_SCHEMA,
        package_tree_sha256,
        package_tree_sha256_at_revision,
    )
except ModuleNotFoundError:
    from evidence_tree import (
        TREE_HASH_SCHEMA,
        package_tree_sha256,
        package_tree_sha256_at_revision,
    )


MANIFEST_SCHEMA = "k_guard_korean_sensitive_org_holdout_manifest.v1"
REPORT_SCHEMA = "k_guard_korean_sensitive_org_holdout_report.v1"
MANIFEST_SHA256 = "5d350eb55b6640dac8fbcdc1a08f0723d0a9828358a6a11b14a995c18523e043"
EXPECTED_CASE_COUNT = 68
EXPECTED_GROUP_COUNTS = {
    "business": 6,
    "corp_current": 6,
    "corp_historical": 6,
    "disability_positive": 8,
    "format": 6,
    "org_collision": 2,
    "org_negative": 6,
    "prose_negative": 20,
    "sensitive_positive": 8,
}
EXPECTED_IDS = (
    *(f"H{index:02d}" for index in range(1, 7)),
    *(f"C{index:02d}" for index in range(1, 7)),
    *(f"B{index:02d}" for index in range(1, 7)),
    "N01",
    "N02",
    "N03",
    "N04",
    "N05",
    "N08",
    "N06",
    "N07",
    *(f"F{index:02d}" for index in range(1, 7)),
    *(f"D{index:02d}" for index in range(1, 9)),
    *(f"S{index:02d}" for index in range(1, 9)),
    *(f"P{index:02d}" for index in range(1, 21)),
)
CASE_KEYS = {"file", "forbidden", "group", "id", "must_all", "must_any", "text"}
CLAIM_BOUNDARY = {
    "evaluator_authored": True,
    "field_accuracy": False,
    "post_implementation_inspection": True,
    "pristine_blind": False,
    "registry_validation": False,
    "synthetic": True,
}
RULE_RE = re.compile(r"^[A-Z][A-Z0-9_]+$")
CASE_ID_RE = re.compile(r"^[HCBNFDSP][0-9]{2}$")
MAXIMUM_MANIFEST_BYTES = 512 * 1024
SOURCE_FILES = (
    "scripts/evaluate_korean_privacy_holdout.py",
    "src/k_guard_mcp/detectors/pii.py",
    "src/k_guard_mcp/scanner.py",
    "src/k_guard_mcp/sensitive_vocabulary.py",
)


class HoldoutError(ValueError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sorted_unique_rules(value: Any, *, label: str, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise HoldoutError(f"{label} must be {'a non-empty' if not allow_empty else 'an'} array")
    if any(not isinstance(rule, str) or RULE_RE.fullmatch(rule) is None for rule in value):
        raise HoldoutError(f"{label} contains an invalid rule id")
    if value != sorted(set(value)):
        raise HoldoutError(f"{label} must contain unique sorted rule ids")
    return list(value)


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    if not path.is_file() or path.is_symlink():
        raise HoldoutError("holdout manifest must be a regular non-symlink file")
    if path.stat().st_size <= 0 or path.stat().st_size > MAXIMUM_MANIFEST_BYTES:
        raise HoldoutError("holdout manifest size is invalid")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != MANIFEST_SHA256:
        raise HoldoutError("holdout manifest digest is not the frozen evaluator digest")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise HoldoutError("holdout manifest is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise HoldoutError("holdout manifest is not canonical JSON")
    if payload.get("schema") != MANIFEST_SCHEMA:
        raise HoldoutError("holdout manifest schema is invalid")
    if payload.get("case_count") != EXPECTED_CASE_COUNT:
        raise HoldoutError("holdout manifest case count is not frozen at 68")
    if payload.get("claim_boundary") != CLAIM_BOUNDARY or payload.get("raw_returned") is not False:
        raise HoldoutError("holdout manifest claim boundary is invalid")
    oracle = payload.get("oracle")
    if not isinstance(oracle, dict) or set(oracle) != {
        "business_registration",
        "corporate_current",
        "corporate_historical",
        "negative_prose",
    } or any(not isinstance(value, str) or not value.strip() for value in oracle.values()):
        raise HoldoutError("holdout manifest oracle contract is invalid")

    cases = payload.get("cases")
    if not isinstance(cases, list) or len(cases) != EXPECTED_CASE_COUNT:
        raise HoldoutError("holdout manifest cases are invalid")
    ids: list[str] = []
    groups: Counter[str] = Counter()
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or set(case) != CASE_KEYS:
            raise HoldoutError(f"holdout case {index} has an invalid shape")
        case_id = case.get("id")
        group = case.get("group")
        filename = case.get("file")
        text = case.get("text")
        if not isinstance(case_id, str) or CASE_ID_RE.fullmatch(case_id) is None:
            raise HoldoutError(f"holdout case {index} has an invalid id")
        if not isinstance(group, str) or group not in EXPECTED_GROUP_COUNTS:
            raise HoldoutError(f"holdout case {case_id} has an invalid group")
        if (
            not isinstance(filename, str)
            or not filename
            or Path(filename).name != filename
            or len(filename) > 80
        ):
            raise HoldoutError(f"holdout case {case_id} has an invalid synthetic filename")
        if not isinstance(text, str) or not text or len(text.encode("utf-8")) > 16 * 1024:
            raise HoldoutError(f"holdout case {case_id} has invalid synthetic input")

        must_all = _sorted_unique_rules(case.get("must_all"), label=f"{case_id}.must_all")
        forbidden = _sorted_unique_rules(case.get("forbidden"), label=f"{case_id}.forbidden")
        raw_any = case.get("must_any")
        if not isinstance(raw_any, list):
            raise HoldoutError(f"{case_id}.must_any must be an array")
        must_any = [
            _sorted_unique_rules(options, label=f"{case_id}.must_any[{option_index}]", allow_empty=False)
            for option_index, options in enumerate(raw_any)
        ]
        required = set(must_all).union(*(set(options) for options in must_any))
        if required.intersection(forbidden):
            raise HoldoutError(f"holdout case {case_id} requires and forbids the same rule")
        ids.append(case_id)
        groups[group] += 1

    if tuple(ids) != EXPECTED_IDS or len(set(ids)) != EXPECTED_CASE_COUNT:
        raise HoldoutError("holdout case ids or frozen order changed")
    if dict(sorted(groups.items())) != EXPECTED_GROUP_COUNTS:
        raise HoldoutError("holdout group counts changed")
    return payload, digest


def _case_result(case: dict[str, Any], scanner: KGuardScanner) -> dict[str, Any]:
    findings = scanner.scan_text(case["text"], case["file"]).findings
    observed_sequence = [finding.rule_id for finding in findings]
    observed = set(observed_sequence)
    missing_all = sorted(set(case["must_all"]) - observed)
    missing_any = [
        list(options)
        for options in case["must_any"]
        if not set(options).intersection(observed)
    ]
    forbidden_observed = sorted(set(case["forbidden"]).intersection(observed))
    passed = not missing_all and not missing_any and not forbidden_observed
    expected_positive = bool(case["must_all"] or case["must_any"])
    failure_kinds = []
    if missing_all or missing_any:
        failure_kinds.append("missing_required")
    if forbidden_observed:
        failure_kinds.append("forbidden_observed")
    fingerprint_payload = {
        "failure_kinds": failure_kinds,
        "forbidden_observed": forbidden_observed,
        "id": case["id"],
        "missing_all": missing_all,
        "missing_any": missing_any,
        "observed_sequence": observed_sequence,
        "passed": passed,
    }
    return {
        "case_fingerprint_sha256": _fingerprint(fingerprint_payload),
        "expected_positive": expected_positive,
        "failure_kinds": failure_kinds,
        "file": case["file"],
        "forbidden_observed": forbidden_observed,
        "group": case["group"],
        "id": case["id"],
        "missing_all": missing_all,
        "missing_any": missing_any,
        "observed_rule_count": len(observed_sequence),
        "observed_rules": sorted(observed),
        "observed_sequence": observed_sequence,
        "passed": passed,
        "raw_returned": False,
    }


def _metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_group: dict[str, dict[str, Any]] = {}
    for group_name in EXPECTED_GROUP_COUNTS:
        group_rows = [row for row in rows if row["group"] == group_name]
        tp = sum(row["expected_positive"] and row["passed"] for row in group_rows)
        fn = sum(row["expected_positive"] and not row["passed"] for row in group_rows)
        tn = sum(not row["expected_positive"] and row["passed"] for row in group_rows)
        fp = sum(not row["expected_positive"] and not row["passed"] for row in group_rows)
        by_group[group_name] = {
            "case_count": len(group_rows),
            "failed_count": fn + fp,
            "fn": fn,
            "fp": fp,
            "passed_count": tp + tn,
            "tn": tn,
            "tp": tp,
        }

    tp = sum(row["expected_positive"] and row["passed"] for row in rows)
    fn = sum(row["expected_positive"] and not row["passed"] for row in rows)
    tn = sum(not row["expected_positive"] and row["passed"] for row in rows)
    fp = sum(not row["expected_positive"] and not row["passed"] for row in rows)
    return {
        "accuracy": (tp + tn) / len(rows),
        "by_group": dict(sorted(by_group.items())),
        "case_count": len(rows),
        "failed_count": fn + fp,
        "fn": fn,
        "fp": fp,
        "negative_case_count": tn + fp,
        "passed_count": tp + tn,
        "positive_case_count": tp + fn,
        "recall": tp / (tp + fn) if tp + fn else None,
        "specificity": tn / (tn + fp) if tn + fp else None,
        "tn": tn,
        "tp": tp,
    }


def _git_head(repo_root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    head = result.stdout.decode("ascii", errors="strict").strip() if result.returncode == 0 else ""
    if re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise HoldoutError("repository HEAD is unavailable")
    return head


def _git_head_blob_sha256(repo_root: Path, relative: str, head: str) -> str | None:
    git_path = relative.replace("\\", "/")
    result = subprocess.run(
        ["git", "show", f"{head}:{git_path}"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return hashlib.sha256(result.stdout).hexdigest()


def _source_binding(repo_root: Path) -> dict[str, Any]:
    head = _git_head(repo_root)
    working_hash = package_tree_sha256(repo_root / "src" / "k_guard_mcp")
    head_hash = package_tree_sha256_at_revision(repo_root, head)
    files = []
    for relative in SOURCE_FILES:
        path = repo_root / relative
        if not path.is_file() or path.is_symlink():
            raise HoldoutError(f"source binding file is missing: {relative}")
        working_sha256 = _sha256_file(path)
        head_sha256 = _git_head_blob_sha256(repo_root, relative, head)
        files.append(
            {
                "byte_count": path.stat().st_size,
                "head_sha256": head_sha256,
                "path": relative,
                "sha256": working_sha256,
                "working_matches_head": head_sha256 is not None and working_sha256 == head_sha256,
            }
        )
    return {
        "git_head": head,
        "git_head_package_tree_sha256": head_hash,
        "package_tree_hash_schema": TREE_HASH_SCHEMA,
        "source_files": files,
        "working_package_tree_matches_head": working_hash == head_hash,
        "working_package_tree_sha256": working_hash,
        "working_source_files_match_head": all(item["working_matches_head"] is True for item in files),
    }


def evaluate_manifest(
    manifest: dict[str, Any],
    manifest_sha256: str,
    *,
    repeat: int,
    repo_root: Path,
) -> dict[str, Any]:
    if isinstance(repeat, bool) or repeat < 1 or repeat > 10:
        raise HoldoutError("repeat must be an integer from 1 to 10")
    runs: list[list[dict[str, Any]]] = []
    run_fingerprints: list[str] = []
    for _ in range(repeat):
        scanner = KGuardScanner()
        rows = [_case_result(case, scanner) for case in manifest["cases"]]
        runs.append(rows)
        run_fingerprints.append(
            _fingerprint([row["case_fingerprint_sha256"] for row in rows])
        )
    exact = len(set(run_fingerprints)) == 1
    primary = runs[0]
    metrics = _metrics(primary)
    failures = [
        {
            "failure_kinds": row["failure_kinds"],
            "forbidden_observed": row["forbidden_observed"],
            "group": row["group"],
            "id": row["id"],
            "missing_all": row["missing_all"],
            "missing_any": row["missing_any"],
            "observed_rules": row["observed_rules"],
            "raw_returned": False,
        }
        for row in primary
        if not row["passed"]
    ]
    source_binding = _source_binding(repo_root)
    source_bound = (
        source_binding["working_package_tree_matches_head"] is True
        and source_binding["working_source_files_match_head"] is True
    )
    passed = metrics["passed_count"] == EXPECTED_CASE_COUNT and exact and source_bound
    return {
        "case_results": primary,
        "claim_boundary": CLAIM_BOUNDARY,
        "failures": failures,
        "manifest": {
            "case_count": manifest["case_count"],
            "group_counts": EXPECTED_GROUP_COUNTS,
            "schema": manifest["schema"],
            "sha256": manifest_sha256,
        },
        "metrics": metrics,
        "passed": passed,
        "raw_returned": False,
        "repeat": {
            "exact": exact,
            "performed": repeat,
            "repeat_fingerprint_multiset_sha256": _fingerprint(sorted(run_fingerprints)),
            "requested": repeat,
            "run_fingerprints": run_fingerprints,
        },
        "schema": REPORT_SCHEMA,
        "source_binding": source_binding,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate the frozen evaluator-authored Korean privacy holdout without returning raw cases."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--repeat", type=int, default=2)
    parser.add_argument(
        "--require-exact",
        action="store_true",
        help="Accepted for compatibility. The CLI already returns nonzero when the report is not passed.",
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    try:
        manifest, manifest_sha256 = load_manifest(args.manifest.resolve())
        report = evaluate_manifest(
            manifest,
            manifest_sha256,
            repeat=args.repeat,
            repo_root=repo_root,
        )
        output = args.output.resolve()
        if output.exists() and output.is_symlink():
            raise HoldoutError("output must not be a symlink")
        if not output.parent.is_dir():
            raise HoldoutError("output parent directory must already exist")
        output.write_bytes(canonical_json_bytes(report))
    except (HoldoutError, OSError, UnicodeError, ValueError) as exc:
        print(
            json.dumps(
                {"ok": False, "error": str(exc), "raw_returned": False},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2

    summary = {
        "case_count": report["metrics"]["case_count"],
        "failed_count": report["metrics"]["failed_count"],
        "manifest_sha256": report["manifest"]["sha256"],
        "passed": report["passed"],
        "repeat_exact": report["repeat"]["exact"],
        "raw_returned": False,
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    if report["passed"] is not True:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
