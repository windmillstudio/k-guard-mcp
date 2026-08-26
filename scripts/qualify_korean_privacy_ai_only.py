from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for import_root in (ROOT, SRC):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from k_guard_mcp.detectors.pii import PiiDetector
from k_guard_mcp.governance import UNIQUE_IDENTIFIER_FIELDS
from k_guard_mcp.scanner import KGuardScanner
from k_guard_mcp.scoreboard import evaluate_fixture_corpus
from k_guard_mcp.sensitive_vocabulary import (
    CONTEST_SENSITIVE_CONCEPT_PROBES,
    CONTEST_SENSITIVE_CONCEPT_TERMS,
    raw_text_has_sensitive_concept,
)
from k_guard_mcp.server import scan_text as server_scan_text
from scripts import evaluate_korean_privacy_holdout as holdout
from scripts.evidence_tree import TREE_HASH_SCHEMA, package_tree_sha256, package_tree_sha256_at_revision


REPORT_SCHEMA = "k_guard_ai_only_korean_privacy_qualification.v1"
METHOD = "current_fixture_plus_frozen_holdout_separate_lane_projection_v1"
DEFAULT_FIXTURE = ROOT / "tests" / "fixtures" / "korean_fixture_corpus.json"
DEFAULT_HOLDOUT = ROOT / "evidence" / "holdout" / "korean-sensitive-org-v1.cjson"
DEFAULT_OUTPUT = ROOT / "evidence" / "qualification" / "korean-privacy-ai-only-v1.json"
FIXTURE_SHA256 = "cdc8dbad05598eca12f622ea7d130765ebbb1fffe6049837f3c160341a42052f"
EXPECTED_FIXTURE_POSITIVE_COUNT = 70
EXPECTED_FIXTURE_NEGATIVE_COUNT = 47
EXPECTED_FIXTURE_WORKSPACE_COUNT = 5
MINIMUM_SEPARATE_LANE_EVALUATIONS = 150
QUALIFICATION_SOURCE_FILES = (
    "scripts/qualify_korean_privacy_ai_only.py",
    "scripts/evaluate_korean_privacy_holdout.py",
    "scripts/evidence_tree.py",
)

CLAIM_BOUNDARY = {
    "ai_only_development_qualification": True,
    "evaluator_authored": True,
    "field_accuracy": False,
    "field_validation": False,
    "human_adjudication": False,
    "live_registry_validation": False,
    "owned_or_partner_evidence": False,
    "post_implementation_inspection": True,
    "pristine_blind": False,
    "release_authority": False,
    "synthetic": True,
}

OFFICIAL_UNIQUE_IDENTIFIER_CONTRACTS: dict[str, dict[str, Any]] = {
    "resident_registration_number": {
        "fixture_case": "rrn",
        "governance_field": "주민등록번호",
        "required_any": ("PII_RRN", "PII_RRN_VALID"),
    },
    "foreigner_registration_number": {
        "fixture_case": "frn",
        "governance_field": "외국인등록번호",
        "required_any": ("PII_FRN", "PII_FRN_VALID"),
    },
    "passport_number": {
        "fixture_case": "passport",
        "governance_field": "여권번호",
        "required_any": ("PII_PASSPORT",),
    },
    "driver_license_number": {
        "fixture_case": "driver_license",
        "governance_field": "운전면허번호",
        "required_any": ("PII_DRIVER_LICENSE",),
    },
}

ORGANIZATION_BOUNDARY_CONTRACTS: dict[str, dict[str, Any]] = {
    "business_checksum_valid": {
        "cohort": "positives",
        "fixture_case": "org_business_registration",
        "required_any": ("KR_ORG_BUSINESS_REGISTRATION",),
        "forbidden": ("PII_RRN", "PII_RRN_VALID"),
    },
    "business_checksum_invalid": {
        "cohort": "negatives",
        "fixture_case": "invalid_business_registration_checksum",
        "required_any": (),
        "forbidden": ("KR_ORG_BUSINESS_REGISTRATION", "PII_RRN", "PII_RRN_VALID"),
    },
    "corporate_historical_checksum": {
        "cohort": "positives",
        "fixture_case": "org_corporate_registration_independent_historical",
        "required_any": ("KR_ORG_CORPORATE_REGISTRATION",),
        "forbidden": ("PII_CREDIT_CARD", "PII_RRN", "PII_RRN_VALID"),
    },
    "corporate_current_explicit_context_unverified": {
        "cohort": "positives",
        "fixture_case": "org_corporate_current_context_unverified",
        "required_any": ("KR_ORG_CORPORATE_REGISTRATION",),
        "forbidden": ("PII_CREDIT_CARD", "PII_RRN", "PII_RRN_VALID"),
    },
    "privacy_first_person_identifier_wins": {
        "cohort": "positives",
        "fixture_case": "privacy_first_rrn_under_corporate_label",
        "required_any": ("PII_RRN", "PII_RRN_VALID"),
        "forbidden": ("KR_ORG_BUSINESS_REGISTRATION", "KR_ORG_CORPORATE_REGISTRATION"),
    },
}


class QualificationError(ValueError):
    pass


@contextmanager
def _trusted_repo_for_git_subprocesses():
    """Trust only this worktree for child Git calls without mutating Git config."""
    raw_count = os.environ.get("GIT_CONFIG_COUNT", "0")
    try:
        count = int(raw_count)
    except ValueError as exc:
        raise QualificationError("GIT_CONFIG_COUNT must be an integer") from exc
    tracked = {
        "GIT_CONFIG_COUNT": os.environ.get("GIT_CONFIG_COUNT"),
        f"GIT_CONFIG_KEY_{count}": os.environ.get(f"GIT_CONFIG_KEY_{count}"),
        f"GIT_CONFIG_VALUE_{count}": os.environ.get(f"GIT_CONFIG_VALUE_{count}"),
    }
    os.environ["GIT_CONFIG_COUNT"] = str(count + 1)
    os.environ[f"GIT_CONFIG_KEY_{count}"] = "safe.directory"
    os.environ[f"GIT_CONFIG_VALUE_{count}"] = str(ROOT)
    try:
        yield
    finally:
        for key, value in tracked.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise QualificationError(f"input must be a regular non-symlink file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise QualificationError(f"input is not valid UTF-8 JSON: {path}") from exc
    if not isinstance(value, dict):
        raise QualificationError(f"input must contain a JSON object: {path}")
    return value


def _git_output(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    output = completed.stdout.decode("utf-8", errors="strict").strip()
    if completed.returncode != 0 or not output:
        raise QualificationError(f"git {' '.join(args)} failed")
    return output


def _source_file_binding(revision: str, relative: str) -> dict[str, Any]:
    path = ROOT / relative
    working = path.read_bytes()
    completed = subprocess.run(
        ["git", "show", f"{revision}:{relative}"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise QualificationError(f"source binding unavailable: {relative}")
    head = completed.stdout
    return {
        "path": relative,
        "sha256": hashlib.sha256(working).hexdigest(),
        "head_sha256": hashlib.sha256(head).hexdigest(),
        "working_matches_head": working == head,
    }


def _analyzer_binding() -> dict[str, Any]:
    revision = _git_output("log", "-1", "--format=%H", "--", "src/k_guard_mcp")
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise QualificationError("analyzer revision is invalid")
    working_hash = package_tree_sha256(ROOT / "src" / "k_guard_mcp")
    revision_hash = package_tree_sha256_at_revision(ROOT, revision)
    qualification_revision = _git_output(
        "log",
        "-1",
        "--format=%H",
        "--",
        *QUALIFICATION_SOURCE_FILES,
    )
    source_files = [
        _source_file_binding(qualification_revision, relative)
        for relative in QUALIFICATION_SOURCE_FILES
    ]
    return {
        "analyzer_revision": revision,
        "package_tree_hash_schema": TREE_HASH_SCHEMA,
        "package_tree_sha256": working_hash,
        "qualification_revision": qualification_revision,
        "qualification_source_files": source_files,
        "qualification_sources_match_revision": all(
            row["working_matches_head"] is True for row in source_files
        ),
        "working_tree_matches_analyzer_revision": working_hash == revision_hash,
    }


def _fixture_case(corpus: dict[str, Any], cohort: str, name: str) -> dict[str, Any]:
    rows = corpus.get(cohort)
    if not isinstance(rows, list):
        raise QualificationError(f"fixture cohort is invalid: {cohort}")
    matches = [row for row in rows if isinstance(row, dict) and row.get("name") == name]
    if len(matches) != 1:
        raise QualificationError(f"fixture case identity is invalid: {cohort}:{name}")
    return matches[0]


def _scan_fixture_contract(
    corpus: dict[str, Any],
    contract_id: str,
    spec: dict[str, Any],
    scanner: KGuardScanner,
) -> dict[str, Any]:
    cohort = str(spec.get("cohort") or "positives")
    case = _fixture_case(corpus, cohort, str(spec["fixture_case"]))
    result = scanner.scan_text(str(case.get("text", "")), str(case.get("file", "fixture.txt")))
    observed = {finding.rule_id for finding in result.findings}
    required_any = set(spec.get("required_any", ()))
    forbidden = set(spec.get("forbidden", ()))
    passed = (not required_any or bool(required_any & observed)) and not (forbidden & observed)
    return {
        "contract_id": contract_id,
        "forbidden_rules": sorted(forbidden),
        "observed_rules": sorted(observed),
        "passed": passed,
        "required_any": sorted(required_any),
        "raw_returned": False,
    }


def _official_unique_identifier_contracts(
    corpus: dict[str, Any], scanner: KGuardScanner
) -> dict[str, Any]:
    rows = []
    governance_fields = set(UNIQUE_IDENTIFIER_FIELDS)
    for concept, spec in OFFICIAL_UNIQUE_IDENTIFIER_CONTRACTS.items():
        case = _fixture_case(corpus, "positives", str(spec["fixture_case"]))
        result = scanner.scan_text(str(case.get("text", "")), str(case.get("file", "fixture.txt")))
        observed = {finding.rule_id for finding in result.findings}
        required = set(spec["required_any"])
        governance_declared = spec["governance_field"] in governance_fields
        rows.append(
            {
                "concept": concept,
                "governance_declared": governance_declared,
                "observed_rules": sorted(observed),
                "passed": governance_declared and bool(required & observed),
                "required_any": sorted(required),
                "raw_returned": False,
            }
        )
    return {
        "concept_count": len(rows),
        "concepts": rows,
        "passed": all(row["passed"] for row in rows),
        "raw_returned": False,
    }


def _sensitive_vocabulary_parity() -> dict[str, Any]:
    terms = tuple(CONTEST_SENSITIVE_CONCEPT_TERMS)
    expected = ("장애", "장애정보", "생체정보", "지문", "홍채", "건강상태")
    if terms != expected or set(CONTEST_SENSITIVE_CONCEPT_PROBES) != set(expected):
        raise QualificationError("contest sensitive vocabulary contract drifted")

    detector = PiiDetector()
    scanner = KGuardScanner()
    rows = []
    for term in terms:
        probe = CONTEST_SENSITIVE_CONCEPT_PROBES[term]
        raw_predicate = raw_text_has_sensitive_concept(probe)
        raw_labels = {entity.label for entity in detector.detect_entities(probe, "ai-only-probe.txt")}
        scanner_rules = {
            finding.rule_id for finding in scanner.scan_text(probe, "ai-only-probe.txt").findings
        }
        server_rules = {
            str(finding.get("rule_id"))
            for finding in server_scan_text(probe, "ai-only-probe.txt").get("findings", [])
            if isinstance(finding, dict)
        }
        passed = (
            raw_predicate
            and "SENSITIVE_INFO" in raw_labels
            and "PII_SENSITIVE_INFO" in scanner_rules
            and "PII_SENSITIVE_INFO" in server_rules
        )
        rows.append(
            {
                "concept": term,
                "passed": passed,
                "raw_detector_labels": sorted(raw_labels),
                "raw_predicate": raw_predicate,
                "raw_returned": False,
                "scanner_rules": sorted(scanner_rules),
                "server_rules": sorted(server_rules),
            }
        )
    return {
        "concept_count": len(rows),
        "concepts": rows,
        "passed": all(row["passed"] for row in rows),
        "parity_semantics": "each surface must emit the canonical sensitive concept/rule; unrelated extra rules are not compared",
        "raw_returned": False,
    }


def _fixture_projection(corpus: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    positives = corpus.get("positives") if isinstance(corpus.get("positives"), list) else []
    negatives = corpus.get("negatives") if isinstance(corpus.get("negatives"), list) else []
    workspace = corpus.get("workspace_cases") if isinstance(corpus.get("workspace_cases"), list) else []
    if (
        len(positives) != EXPECTED_FIXTURE_POSITIVE_COUNT
        or len(negatives) != EXPECTED_FIXTURE_NEGATIVE_COUNT
        or len(workspace) != EXPECTED_FIXTURE_WORKSPACE_COUNT
    ):
        raise QualificationError("fixture case counts drifted")

    positive_rows = report.get("positives") if isinstance(report.get("positives"), list) else []
    negative_rows = report.get("negatives") if isinstance(report.get("negatives"), list) else []
    if len(positive_rows) != len(positives) or len(negative_rows) != len(negatives):
        raise QualificationError("fixture projection rows are incomplete")
    positive_tp = sum(row.get("passed") is True for row in positive_rows)
    positive_fn = len(positive_rows) - positive_tp
    measurable_indexes = {
        index for index, case in enumerate(negatives) if isinstance(case, dict) and "expected_absent" not in case
    }
    clean_fp = sum(bool(negative_rows[index].get("rules")) for index in measurable_indexes)
    clean_tn = len(measurable_indexes) - clean_fp
    targeted_rows = [
        negative_rows[index]
        for index, case in enumerate(negatives)
        if isinstance(case, dict) and "expected_absent" in case
    ]
    return {
        "case_count": len(positives) + len(negatives),
        "category_confusion": {
            "clean_negative_cases": {"fn": 0, "fp": clean_fp, "tn": clean_tn, "tp": 0},
            "positive_detection_cases": {"fn": positive_fn, "fp": 0, "tn": 0, "tp": positive_tp},
        },
        "clean_negative_case_count": len(measurable_indexes),
        "false_positive_rate": report.get("false_positive_rate"),
        "negative_count": len(negatives),
        "passed": report.get("passed") is True,
        "positive_count": len(positives),
        "raw_returned": False,
        "recall": report.get("recall"),
        "targeted_absence_case_count": len(targeted_rows),
        "targeted_absence_failed_count": sum(row.get("passed") is not True for row in targeted_rows),
        "workspace_case_count": len(workspace),
        "workspace_passed_count": report.get("workspace_passed_count"),
    }


def _holdout_projection(report: dict[str, Any]) -> dict[str, Any]:
    metrics = report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
    repeat = report.get("repeat") if isinstance(report.get("repeat"), dict) else {}
    category = metrics.get("by_group") if isinstance(metrics.get("by_group"), dict) else {}
    run_fingerprints = repeat.get("run_fingerprints") if isinstance(repeat.get("run_fingerprints"), list) else []
    exact_two_run = (
        repeat.get("requested") == 2
        and repeat.get("performed") == 2
        and repeat.get("exact") is True
        and len(run_fingerprints) == 2
        and len(set(run_fingerprints)) == 1
    )
    return {
        "case_count": metrics.get("case_count"),
        "category_confusion": category,
        "exact_two_run": exact_two_run,
        "fn": metrics.get("fn"),
        "fp": metrics.get("fp"),
        "negative_case_count": metrics.get("negative_case_count"),
        "passed": report.get("passed") is True and exact_two_run,
        "positive_case_count": metrics.get("positive_case_count"),
        "raw_returned": False,
        "recall": metrics.get("recall"),
        "run_digest_sha256": run_fingerprints[0] if exact_two_run else None,
        "specificity": metrics.get("specificity"),
        "tn": metrics.get("tn"),
        "tp": metrics.get("tp"),
    }


def build_report(
    fixture_path: Path = DEFAULT_FIXTURE,
    holdout_path: Path = DEFAULT_HOLDOUT,
) -> dict[str, Any]:
    fixture_path = fixture_path.resolve()
    holdout_path = holdout_path.resolve()
    fixture_digest = _sha256_file(fixture_path)
    if fixture_digest != FIXTURE_SHA256:
        raise QualificationError("fixture digest is not the qualified current fixture digest")
    corpus = _load_json(fixture_path)
    fixture_report = evaluate_fixture_corpus(fixture_path)
    manifest, holdout_digest = holdout.load_manifest(holdout_path)
    with _trusted_repo_for_git_subprocesses():
        holdout_report = holdout.evaluate_manifest(
            manifest, holdout_digest, repeat=2, repo_root=ROOT
        )

    scanner = KGuardScanner()
    official = _official_unique_identifier_contracts(corpus, scanner)
    organization_rows = [
        _scan_fixture_contract(corpus, contract_id, spec, scanner)
        for contract_id, spec in ORGANIZATION_BOUNDARY_CONTRACTS.items()
    ]
    organization = {
        "contracts": organization_rows,
        "passed": all(row["passed"] for row in organization_rows),
        "raw_returned": False,
        "registry_status": "current corporate syntax/context recognition remains unverified and is not registry validation",
    }
    sensitive = _sensitive_vocabulary_parity()
    fixture_projection = _fixture_projection(corpus, fixture_report)
    holdout_projection = _holdout_projection(holdout_report)
    with _trusted_repo_for_git_subprocesses():
        analyzer = _analyzer_binding()
    separate_lane_evaluations = fixture_projection["case_count"] + holdout_projection["case_count"]

    projection: dict[str, Any] = {
        "analyzer": analyzer,
        "case_accounting": {
            "combined_confusion_matrix": None,
            "cross_lane_deduplication_claimed": False,
            "fixture_case_count": fixture_projection["case_count"],
            "holdout_case_count": holdout_projection["case_count"],
            "meets_minimum_separate_lane_evaluations": (
                separate_lane_evaluations >= MINIMUM_SEPARATE_LANE_EVALUATIONS
            ),
            "minimum_separate_lane_evaluations": MINIMUM_SEPARATE_LANE_EVALUATIONS,
            "pooled_unique_case_count": None,
            "separate_lane_evaluation_count": separate_lane_evaluations,
            "workspace_contract_case_count": fixture_projection["workspace_case_count"],
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "contracts": {
            "official_unique_identifiers": official,
            "organization_identifiers": organization,
            "sensitive_vocabulary_surface_parity": sensitive,
        },
        "inputs": {
            "fixture": {
                "path": "tests/fixtures/korean_fixture_corpus.json",
                "sha256": fixture_digest,
            },
            "holdout": {
                "path": "evidence/holdout/korean-sensitive-org-v1.cjson",
                "sha256": holdout_digest,
            },
        },
        "lanes": {
            "current_fixture": fixture_projection,
            "frozen_evaluator_holdout": holdout_projection,
        },
        "method": METHOD,
        "raw_returned": False,
        "schema": REPORT_SCHEMA,
    }
    passed = (
        analyzer["working_tree_matches_analyzer_revision"] is True
        and analyzer["qualification_sources_match_revision"] is True
        and fixture_projection["passed"] is True
        and holdout_projection["passed"] is True
        and official["passed"] is True
        and organization["passed"] is True
        and sensitive["passed"] is True
        and projection["case_accounting"]["meets_minimum_separate_lane_evaluations"] is True
        and holdout_report.get("claim_boundary") == holdout.CLAIM_BOUNDARY
        and holdout.CLAIM_BOUNDARY == {
            "evaluator_authored": True,
            "field_accuracy": False,
            "post_implementation_inspection": True,
            "pristine_blind": False,
            "registry_validation": False,
            "synthetic": True,
        }
    )
    projection["passed"] = passed
    projection["projection_sha256"] = _canonical_digest(projection)
    return projection


def validate_report(report: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if report.get("schema") != REPORT_SCHEMA:
        errors.append("schema_invalid")
    digest = report.get("projection_sha256")
    unsigned = dict(report)
    unsigned.pop("projection_sha256", None)
    if not isinstance(digest, str) or digest != _canonical_digest(unsigned):
        errors.append("projection_digest_invalid")
    if report.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("claim_boundary_invalid")
    accounting = report.get("case_accounting") if isinstance(report.get("case_accounting"), dict) else {}
    if (
        accounting.get("fixture_case_count") != 117
        or accounting.get("holdout_case_count") != 68
        or accounting.get("separate_lane_evaluation_count") != 185
        or accounting.get("combined_confusion_matrix") is not None
        or accounting.get("pooled_unique_case_count") is not None
        or accounting.get("cross_lane_deduplication_claimed") is not False
    ):
        errors.append("case_accounting_invalid")
    if report.get("passed") is not True:
        errors.append("qualification_not_passed")
    if report.get("raw_returned") is not False:
        errors.append("raw_boundary_invalid")
    return errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build the deterministic AI-only Korean privacy development qualification report."
    )
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--holdout", type=Path, default=DEFAULT_HOLDOUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = build_report(args.fixture, args.holdout)
    errors = validate_report(report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json_bytes(report))
    print(
        json.dumps(
            {
                "case_accounting": report["case_accounting"],
                "errors": errors,
                "passed": not errors,
                "projection_sha256": report["projection_sha256"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
