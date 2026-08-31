from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from client_interop_evidence import (
    build_status as build_client_interop_status,
    validate_status as validate_client_interop_status,
)
from public_app_effectiveness_v2 import build_status as build_public_effectiveness_status
from evidence_tree import (
    TREE_HASH_SCHEMA,
    package_tree_sha256,
    package_tree_sha256_at_revision,
    wheel_package_contract,
)
from contest_claim_contract import (
    DECLARED_SBOM_COMPONENT_COUNT,
    claim_surface_errors,
    source_metrics_match_contract,
)
from verify_release_archives import committed_release_archive_errors
from media_evidence import validate_attestation
from k_guard_mcp.raw_free_evidence import public_candidate_evidence_shape_valid
from submission_artifacts import validate_manifest as validate_submission_manifest
from verify_official_contest_report import (
    EXPECTED_APPENDIX_PAGES as OFFICIAL_REPORT_APPENDIX_PAGES,
    EXPECTED_TOTAL_PAGES as OFFICIAL_REPORT_TOTAL_PAGES,
    MAX_BODY_PAGES as OFFICIAL_REPORT_MAX_BODY_PAGES,
    OfficialReportVerificationError,
    verify_official_report,
)
from k_guard_mcp.data_release import _field_validation_evidence_envelope_matches
from k_guard_mcp.field_campaign import evaluate_field_campaign_readiness
from k_guard_mcp.field_validation import field_validation_projection, run_field_validation
from k_guard_mcp.language_validation import current_language_validation_contract


ACTIVE_TEXT_ROOTS = ("README.md", "docs", "src", "tests", "examples")
ACTIVE_TEXT_SUFFIXES = {".md", ".py", ".json", ".csv", ".toml", ".yml", ".yaml"}
PUBLIC_SNAPSHOT_METADATA = Path("PUBLIC-SNAPSHOT.json")
PUBLIC_SNAPSHOT_SCHEMA = "k_guard_public_source_snapshot.v1"
PUBLIC_AUDIT_REGRESSION_COMMAND = "python scripts/public_source_tests.py"
INTERNAL_AUDIT_REGRESSION_COMMAND = "python -m pytest -q"
LEGACY_PERSONA = "\uccb4\ud06c\ub0a8\ubc29"
LEGACY_ASSET = "checknam" + "-hero.png"
SUBMISSION_VIDEO = Path("submission/demo/k-guard-contest-demo.mp4")
SUBMISSION_VIDEO_ATTESTATION = Path("submission/demo/video-verification.json")
SUBMISSION_REPORT_HTML = Path("submission/report/k-guard-contest-result-report.html")
SUBMISSION_REPORT_DOCX = Path("submission/report/2026 오픈소스 개발자대회 결과보고서_1123(AI쀼).docx")
SUBMISSION_REPORT_PDF = Path("submission/report/2026 오픈소스 개발자대회 결과보고서_1123(AI쀼).pdf")
SUBMISSION_REPORT_ATTESTATION = Path("submission/report/official-report-verification.json")
CURRENT_WHEEL_SMOKE = Path("evidence/release/fresh-wheel-stdio-smoke.json")
CURRENT_PUBLIC_REPLAY = Path("evidence/public/current-source-replay-v1")
CURRENT_PUBLIC_MANIFEST = Path("evidence/public/development-apps-12-v3-manifest.json")
SUBMISSION_WHEEL_DIR = Path("submission/release")
FIELD_EVIDENCE_PATHS = {
    "roster": Path("evidence/field/field-app-roster.csv"),
    "primary_guardian": Path("evidence/field/guardian-primary.json"),
    "repeat_guardian": Path("evidence/field/guardian-repeat.json"),
    "ground_truth": Path("evidence/field/ground-truth.csv"),
    "candidate_review": Path("evidence/field/candidate-review.csv"),
    "preregistration": Path("evidence/field/preregistration.json"),
    "validation_report": Path("evidence/field/field-validation.json"),
    "external_attestation": Path("evidence/field/external-verifier-attestation.json"),
}
TRUSTED_FIELD_ATTESTATION_SHA256_ENV = "K_GUARD_TRUSTED_FIELD_ATTESTATION_SHA256"
R2_SUCCESSION_CONTRACT_SCHEMA = "k_guard_r2_current_source_evidence_succession_contract.v1"
R2_SUCCESSION_CONTRACT_VERSION = "r2-phase0-external-current-source-succession-v1"
R2_SUCCESSION_MANIFEST_SCHEMA = "k_guard_r2_current_source_evidence_succession_manifest.v1"
R2_GATE_STATUS_SCHEMA = "k_guard_phase0_gate_status.v1"
R2_SUCCESSION_REQUIRED_GATES = (
    "current_public_replay",
    "full_regression",
    "submission_report_current_binding",
    "current_source_readiness",
)
R2_SUCCESSION_REQUIRED_ARTIFACTS = {
    "gate_status",
    "fresh_wheel",
    "supervisor_health",
    "public_queue",
    "public_probes",
    "regression_repeat",
    "readiness",
    "report_attestation",
}
R2_SUCCESSION_GATE_PASSES = {
    "clean_head": True,
    "current_public_replay": False,
    "current_source_readiness": False,
    "fresh_wheel_external": True,
    "full_regression": False,
    "required_supervisor_runtime_health": True,
    "submission_report_current_binding": False,
}
R2_SUCCESSION_ACTIVATION_ACTION = "current-source-evidence-succession-contract-activated"
R2_SUCCESSION_ACTIVATION_WORK_ITEM = "R2-P0-CONTRACT-001"
R2_WORK_EVENT_SCHEMA = "k_guard_work_event.v1"
PUBLIC_FINDING_KEYS = {
    "artifact_scope",
    "audit_depth",
    "components",
    "confidence",
    "evidence",
    "file",
    "fix_verification",
    "id",
    "inspected_scope",
    "line_end",
    "line_start",
    "method",
    "not_inspected",
    "pipc_basis",
    "privacy_class",
    "recommendation",
    "rule_id",
    "scope",
    "severity",
    "source",
    "status",
    "title",
    "url",
    "why_it_matters",
}
PUBLIC_ARTIFACT_SCOPES = {
    "configuration",
    "content_data",
    "documentation",
    "repository_asset",
    "runtime_source",
    "test_fixture",
    "third_party",
}
SUBMISSION_RIGHTS = Path("submission/RIGHTS.md")
SUBMISSION_CLAIM_FILES = (
    Path("docs/contest-2026-submission-ko.md"),
    Path("docs/contest-2026-result-report-draft-ko.md"),
    Path("docs/contest-2026-result-report.html"),
    Path("submission/report/k-guard-contest-result-report.html"),
)
DECLARED_SBOM_COMPONENT_COUNT_ARTIFACTS: tuple[tuple[str, str], ...] = (
    ("sbom.cdx.json", "components"),
    ("license-report.json", "component_count"),
    ("submission/release/sbom.cdx.json", "components"),
    ("submission/release/license-report.json", "component_count"),
)


def build_report(
    root: Path = ROOT,
    *,
    r2_current_source_succession_contract: Path | None = None,
) -> dict[str, Any]:
    current_package_hash = package_tree_sha256(root / "src" / "k_guard_mcp")
    language_validation = current_language_validation_contract()
    language_validation_errors = _language_validation_contract_errors(language_validation)
    evidence_errors = _evidence_errors(root)
    brand_hits = _legacy_brand_hits(root)
    demo = _json(root / "evidence" / "demo" / "contest-demo-scorecard.json")
    license_report = _json(root / "license-report.json")
    sbom = _json(root / "sbom.cdx.json")
    declared_sbom_component_count_errors = _declared_sbom_component_count_errors(root)
    campaign = _json(root / "evidence" / "field" / "campaign-status.json")
    clients = _json(root / "evidence" / "clients" / "interop-status.json")
    public_evidence_dir = root / "evidence" / "public" / "development-apps-12-v3"
    public_effectiveness = _json(public_evidence_dir / "effectiveness-status.json")
    juliet_first = _json(root / "evidence" / "public" / "holdout" / "juliet-java-cwe89-first-result.json")
    juliet_replay = _json(root / "evidence" / "public" / "holdout" / "juliet-java-cwe89-remediation-replay.json")
    video_status, video_errors = _submission_video_status(
        root / SUBMISSION_VIDEO,
        root / SUBMISSION_VIDEO_ATTESTATION,
    )
    wheel_smoke = _json(root / CURRENT_WHEEL_SMOKE)
    wheel_smoke_errors = _fresh_wheel_smoke_errors(wheel_smoke, current_package_hash, root)
    release_archive_errors = _submission_release_archive_errors(root)
    current_public_metrics, current_public_errors = _current_public_replay_status(
        root / CURRENT_PUBLIC_REPLAY,
        current_package_hash,
        root,
    )
    claim_errors = _submission_claim_errors(
        root,
        public_effectiveness,
        juliet_first,
        juliet_replay,
        current_public_metrics,
    )
    submission_manifest_errors = validate_submission_manifest(root)
    report_evidence_errors = _submission_report_errors(root)
    rights_errors = _submission_rights_errors(root)
    release_workflow_errors = _release_workflow_contract_errors(root)
    field_app_count, field_evidence_errors = _field_award_evidence_status(root, campaign)

    client_verified_count, client_evidence_errors = validate_client_interop_status(clients)
    reproduced_clients = build_client_interop_status(root / "evidence" / "clients" / "runs")
    if clients != reproduced_clients:
        client_evidence_errors.append("status_not_reproducible_from_verified_runs")
    client_verified_count = _exact_int(reproduced_clients.get("verified_client_count")) or 0
    client_evidence_errors = sorted(set(client_evidence_errors))
    reproduced_public_effectiveness = build_public_effectiveness_status(public_evidence_dir)
    public_effectiveness_errors = list(reproduced_public_effectiveness.get("validation_errors", []))
    if public_effectiveness != reproduced_public_effectiveness:
        public_effectiveness_errors.append("status_not_reproducible_from_public_campaign_evidence")
    public_effectiveness_errors = sorted(set(public_effectiveness_errors))
    r2_succession_contract: dict[str, Any] = {}
    r2_succession_gate_status: dict[str, Any] = {}
    r2_succession_errors: list[str] = []
    if r2_current_source_succession_contract is not None:
        (
            r2_succession_contract,
            r2_succession_gate_status,
            r2_succession_errors,
        ) = _r2_current_source_succession_status(r2_current_source_succession_contract, root)
    internal_checks = {
        "submission_documented": all(
            (root / path).is_file()
            for path in (
                "README.md",
                "docs/contest-2026-submission-ko.md",
                "docs/product-north-star-ko.md",
                "examples/contest-demo/v1/demo.py",
                "examples/contest-demo/v1/README.md",
            )
        ),
        "submission_claims_current": not claim_errors,
        "three_minute_demo_video_valid": video_status.get("valid") is True,
        "submission_video_attestation_valid": not video_errors,
        "submission_report_bound_and_verified": not report_evidence_errors,
        "submission_artifact_manifest_valid": not submission_manifest_errors,
        "submission_rights_documented": not rights_errors,
        "fresh_wheel_stdio_current_source_passed": not wheel_smoke_errors,
        "submission_release_archives_match_current_source": not release_archive_errors,
        "current_source_public_replay_passed": not current_public_errors,
        "current_language_validation_pack_complete": not language_validation_errors,
        "brand_consistent": not brand_hits and (root / "src" / "k_guard_mcp" / "assets" / "glasses-senpai-hero.png").is_file(),
        "demo_contract_passed": _demo_contract_valid(demo),
        "license_policy_passed": (
            license_report.get("passed") is True
            and _exact_int(license_report.get("unknown_license_count")) == 0
            and _exact_int(license_report.get("review_required_count")) == 0
            and (root / "THIRD_PARTY_NOTICES.md").is_file()
            and (root / "LICENSES" / "Apache-2.0.txt").is_file()
        ),
        "sbom_present": sbom.get("bomFormat") == "CycloneDX" and len(sbom.get("components", [])) > 0,
        "declared_sbom_component_count_matches_live_artifacts": not declared_sbom_component_count_errors,
        "evidence_integrity_passed": not evidence_errors,
        "historical_client_evidence_contract_valid": not client_evidence_errors,
        "current_self_attested_client_process_evidence_at_least_3": (
            client_verified_count >= 3
            and clients.get("ready") is True
            and not client_evidence_errors
        ),
        "historical_public_effectiveness_evidence_contract_valid": not public_effectiveness_errors,
        "release_workflow_static_contract_valid": not release_workflow_errors,
        "community_files_present": all((root / path).is_file() for path in ("CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md")),
    }
    if r2_current_source_succession_contract is not None:
        gates = r2_succession_gate_status.get("gates") if isinstance(r2_succession_gate_status.get("gates"), dict) else {}
        if r2_succession_errors:
            # An explicit but invalid successor must never silently fall back to
            # legacy evidence or preserve a ready result.
            internal_checks.update(
                {
                    "submission_report_bound_and_verified": False,
                    "fresh_wheel_stdio_current_source_passed": False,
                    "current_source_public_replay_passed": False,
                    "r2_current_source_evidence_succession_contract_valid": False,
                    "r2_current_source_full_regression_passed": False,
                }
            )
        else:
            internal_checks.update(
                {
                    "submission_report_bound_and_verified": _local_and_inherited(
                        internal_checks["submission_report_bound_and_verified"],
                        _r2_gate_passed(gates, "submission_report_current_binding"),
                    ),
                    "fresh_wheel_stdio_current_source_passed": _local_and_inherited(
                        internal_checks["fresh_wheel_stdio_current_source_passed"],
                        _r2_gate_passed(gates, "fresh_wheel_external"),
                    ),
                    "current_source_public_replay_passed": _local_and_inherited(
                        internal_checks["current_source_public_replay_passed"],
                        _r2_gate_passed(gates, "current_public_replay"),
                    ),
                    "r2_current_source_evidence_succession_contract_valid": True,
                    "r2_current_source_full_regression_passed": _r2_gate_passed(gates, "full_regression"),
                }
            )
    external_checks = {
        "owned_partner_field_apps_at_least_12": not field_evidence_errors,
        "historical_client_recordings_at_least_3": (
            client_verified_count >= 3
            and clients.get("ready") is True
            and clients.get("external_independence_verified") is True
            and not client_evidence_errors
        ),
        "historical_public_app_effectiveness_qualified": (
            reproduced_public_effectiveness.get("integrity_passed") is True
            and reproduced_public_effectiveness.get("qualified") is True
            and not public_effectiveness_errors
        ),
    }
    package_ready = all(internal_checks.values())
    award_evidence_ready = package_ready and all(external_checks.values())
    blockers = [name for name, passed in {**internal_checks, **external_checks}.items() if not passed]
    field_boundary = (
        f"Field evidence remains pending at {field_app_count} contract-verified apps."
        if field_evidence_errors
        else f"Field evidence is source-reproduced and externally pinned for {field_app_count} apps."
    )
    return {
        "schema": "k_guard_contest_readiness.v3",
        "official_program": {
            "name": "2026 오픈소스 개발자대회",
            "track": "자유과제 / 보안·안전 / 인공지능 개발자 도구",
            "source": "https://www.oss.kr/pages/2",
            "required_submission": ["결과보고서", "3분 시연영상", "소스코드"],
            "second_stage": ["기능테스트", "라이선스 검증", "발표평가"],
        },
        "package_ready": package_ready,
        "submission_ready": package_ready,
        "submission_ready_meaning": "Deprecated compatibility alias for package_ready; it does not mean field effectiveness or award readiness.",
        "award_evidence_ready": award_evidence_ready,
        "status": (
            "award_evidence_ready"
            if award_evidence_ready
            else "package_ready_field_evidence_pending"
            if package_ready
            else "package_verification_blocked"
        ),
        "internal_checks": internal_checks,
        "external_checks": external_checks,
        "metrics": {
            "owned_partner_app_count": field_app_count,
            "verified_client_count": client_verified_count,
            "evidence_error_count": len(evidence_errors),
            "client_evidence_error_count": len(client_evidence_errors),
            "public_effectiveness_error_count": len(public_effectiveness_errors),
            "public_app_count": _exact_int(reproduced_public_effectiveness.get("metrics", {}).get("app_count")) or 0,
            "public_candidate_count": _exact_int(reproduced_public_effectiveness.get("metrics", {}).get("candidate_count")) or 0,
            "public_reviewer_count": _exact_int(reproduced_public_effectiveness.get("metrics", {}).get("reviewer_count")) or 0,
            "public_true_positive_probe_count": _exact_int(reproduced_public_effectiveness.get("metrics", {}).get("true_positive_probe_count")) or 0,
            "public_true_positive_probe_detected": _exact_int(reproduced_public_effectiveness.get("metrics", {}).get("true_positive_probe_detected")) or 0,
            "public_candidate_actionable_rate": float(
                reproduced_public_effectiveness.get("metrics", {}).get("candidate_actionable_rate", 0.0)
            ),
            "public_reference_probe_detection_rate": float(
                reproduced_public_effectiveness.get("metrics", {}).get("true_positive_probe_rate", 0.0)
            ),
            "juliet_first_true_positive": _exact_int(juliet_first.get("metrics", {}).get("true_positive")) or 0,
            "juliet_first_false_negative": _exact_int(juliet_first.get("metrics", {}).get("false_negative")) or 0,
            "juliet_replay_true_positive": _exact_int(juliet_replay.get("metrics", {}).get("true_positive")) or 0,
            "juliet_replay_false_negative": _exact_int(juliet_replay.get("metrics", {}).get("false_negative")) or 0,
            "submission_video_duration_seconds": video_status.get("duration_seconds"),
            "current_public_app_count": current_public_metrics.get("app_count", 0),
            "current_public_candidate_count": current_public_metrics.get("candidate_count", 0),
            "current_public_true_positive_probe_count": current_public_metrics.get("true_positive_probe_count", 0),
            "current_public_true_positive_probe_detected": current_public_metrics.get("true_positive_probe_detected", 0),
            "current_public_benign_probe_count": current_public_metrics.get("benign_probe_count", 0),
            "current_public_benign_probe_detected": current_public_metrics.get("benign_probe_detected", 0),
            "current_package_tree_sha256": current_package_hash,
            "current_language_validation_pack_sha256": language_validation.get("hashes", {}).get("pack_sha256"),
            "submission_claim_error_count": len(claim_errors),
            "legacy_brand_hit_count": len(brand_hits),
            "r2_current_source_failed_gate_count": len(
                r2_succession_gate_status.get("failed_gate_ids", [])
                if isinstance(r2_succession_gate_status.get("failed_gate_ids"), list)
                else []
            ),
        },
        "blockers": blockers,
        "diagnostics": {
            "evidence_errors": evidence_errors,
            "client_evidence_errors": client_evidence_errors,
            "public_effectiveness_errors": public_effectiveness_errors,
            "public_effectiveness_blockers": reproduced_public_effectiveness.get("blockers", []),
            "submission_claim_errors": claim_errors,
            "submission_video": video_status,
            "submission_video_errors": video_errors,
            "submission_report_errors": report_evidence_errors,
            "submission_manifest_errors": submission_manifest_errors,
            "submission_rights_errors": rights_errors,
            "release_workflow_errors": release_workflow_errors,
            "field_evidence_errors": field_evidence_errors,
            "fresh_wheel_smoke_errors": wheel_smoke_errors,
            "declared_sbom_component_count_errors": declared_sbom_component_count_errors,
            "submission_release_archive_errors": release_archive_errors,
            "current_public_replay_errors": current_public_errors,
            "language_validation_errors": language_validation_errors,
            "legacy_brand_hits": brand_hits,
            "r2_current_source_evidence_succession_contract": {
                "path": str(r2_current_source_succession_contract) if r2_current_source_succession_contract is not None else None,
                "schema": r2_succession_contract.get("schema") if r2_succession_contract else None,
                "errors": r2_succession_errors,
                "gate_status": r2_succession_gate_status,
            },
            "raw_returned": False,
        },
        "claim_boundary": (
            "Package readiness proves that the current analyzer package was replayed deterministically on the pinned public-app corpus, "
            "that a freshly installed wheel completed the real stdio workflow, and that the bound report, media, manifest, and rights records verify. "
            "The release-workflow check validates committed static policy only; it does not assert that a hosted release run succeeded. "
            "The three client UI recordings and AI-reviewed public-app labels are historical process evidence. Public source-oracle probes and the "
            "preregistered Juliet first result support bounded detector claims only; the post-tuning replay is regression evidence. None substitutes "
            "for independent human adjudication on owned/partner field apps or grants release authority. "
            + field_boundary
        ),
        "raw_returned": False,
    }


def _legacy_brand_hits(root: Path) -> list[str]:
    hits: list[str] = []
    for relative in ACTIVE_TEXT_ROOTS:
        start = root / relative
        paths = [start] if start.is_file() else list(start.rglob("*")) if start.is_dir() else []
        for path in paths:
            if not path.is_file() or path.suffix.lower() not in ACTIVE_TEXT_SUFFIXES:
                continue
            if "__pycache__" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                hits.append(f"unreadable:{path.relative_to(root).as_posix()}")
                continue
            if LEGACY_PERSONA in text or LEGACY_ASSET in text:
                hits.append(path.relative_to(root).as_posix())
    return sorted(set(hits))


def _evidence_errors(root: Path) -> list[str]:
    manifest = root / "evidence" / "SHA256SUMS"
    if not manifest.is_file():
        return ["missing:evidence/SHA256SUMS"]
    errors: list[str] = []
    listed: set[str] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        try:
            expected, relative = line.split("  ", 1)
        except ValueError:
            errors.append("invalid_manifest_row")
            continue
        listed.add(relative)
        path = root / relative
        if not path.is_file():
            errors.append(f"missing:{relative}")
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            errors.append(f"digest_mismatch:{relative}")
    actual = {
        path.relative_to(root).as_posix()
        for path in (root / "evidence").rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    for relative in sorted(actual - listed):
        errors.append(f"unlisted:{relative}")
    for relative in sorted(listed - actual):
        errors.append(f"stale:{relative}")
    return errors


def _json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _exact_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _field_campaign_contract_errors(campaign: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    expected_keys = {
        "schema",
        "content_sha256",
        "roster_content_sha256",
        "row_count",
        "app_count",
        "target_count",
        "stratum_count",
        "stratum_counts",
        "blockers",
        "blocker_counts",
        "passed",
        "ready",
        "roster_refs",
        "raw_returned",
    }
    if set(campaign) != expected_keys:
        errors.append("field_campaign_schema_fields_invalid")
    if campaign.get("schema") != "k_guard_field_campaign_readiness.v1":
        errors.append("field_campaign_schema_invalid")
    if campaign.get("raw_returned") is not False:
        errors.append("field_campaign_raw_returned_invalid")
    if campaign.get("passed") is not True or campaign.get("ready") is not True:
        errors.append("field_campaign_not_ready")
    if campaign.get("blockers") != [] or campaign.get("blocker_counts") != {}:
        errors.append("field_campaign_blockers_present")

    content_sha256 = str(campaign.get("content_sha256") or "")
    if (
        re.fullmatch(r"[0-9a-f]{64}", content_sha256) is None
        or campaign.get("roster_content_sha256") != content_sha256
    ):
        errors.append("field_campaign_roster_digest_invalid")

    app_count = _exact_int(campaign.get("app_count"))
    row_count = _exact_int(campaign.get("row_count"))
    target_count = _exact_int(campaign.get("target_count"))
    if app_count is None or not 12 <= app_count <= 20:
        errors.append("field_campaign_app_count_invalid")
    if app_count is None or row_count != app_count or target_count != app_count:
        errors.append("field_campaign_row_target_count_invalid")

    strata = campaign.get("stratum_counts") if isinstance(campaign.get("stratum_counts"), dict) else {}
    if set(strata) != {"top", "mid", "long_tail"}:
        errors.append("field_campaign_strata_invalid")
    else:
        counts = [_exact_int(strata.get(name)) for name in ("top", "mid", "long_tail")]
        if any(count is None or count <= 0 for count in counts):
            errors.append("field_campaign_strata_invalid")
        elif app_count is None or sum(counts) != app_count or campaign.get("stratum_count") != 3:
            errors.append("field_campaign_strata_count_invalid")

    refs = campaign.get("roster_refs") if isinstance(campaign.get("roster_refs"), list) else []
    if app_count is None or len(refs) != app_count:
        errors.append("field_campaign_roster_refs_invalid")
    else:
        expected_ref_keys = {
            "app_ref",
            "target_ref",
            "source_revision_ref",
            "scope_assertion_ref",
            "raw_returned",
        }
        for row in refs:
            if not isinstance(row, dict) or set(row) != expected_ref_keys or row.get("raw_returned") is not False:
                errors.append("field_campaign_roster_refs_invalid")
                break
            for name in expected_ref_keys - {"raw_returned"}:
                ref = row.get(name)
                if (
                    not isinstance(ref, dict)
                    or set(ref) != {"hash", "hash_scheme", "raw_returned"}
                    or re.fullmatch(r"[0-9a-f]{16}", str(ref.get("hash") or "")) is None
                    or ref.get("hash_scheme") != "hmac-sha256:operator-keyed:len16"
                    or ref.get("raw_returned") is not False
                ):
                    errors.append("field_campaign_roster_refs_invalid")
                    break
            if errors and errors[-1] == "field_campaign_roster_refs_invalid":
                break
    return sorted(set(errors))


def _field_validation_contract_errors(
    campaign: dict[str, Any],
    validation: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    sample = validation.get("sample") if isinstance(validation.get("sample"), dict) else {}
    gate_checks = validation.get("gate_checks") if isinstance(validation.get("gate_checks"), list) else []
    roster_source = (
        validation.get("field_roster_source")
        if isinstance(validation.get("field_roster_source"), dict)
        else {}
    )
    reviewer_assertions = (
        validation.get("reviewer_assertions")
        if isinstance(validation.get("reviewer_assertions"), dict)
        else {}
    )
    ground_truth_assertions = (
        validation.get("ground_truth_assertions")
        if isinstance(validation.get("ground_truth_assertions"), dict)
        else {}
    )
    app_count = _exact_int(campaign.get("app_count"))
    candidate_count = _exact_int(sample.get("candidate_count"))
    case_count = _exact_int(sample.get("case_count"))
    candidate_finding_refs = (
        validation.get("candidate_finding_refs")
        if isinstance(validation.get("candidate_finding_refs"), list)
        else []
    )
    evaluation_app_refs = (
        validation.get("evaluation_app_refs")
        if isinstance(validation.get("evaluation_app_refs"), list)
        else []
    )
    reviewer_count = _exact_int(reviewer_assertions.get("reviewer_count"))
    ground_truth_reviewer_count = _exact_int(ground_truth_assertions.get("reviewer_count"))

    required_values = {
        "field_validation_schema_invalid": validation.get("schema") == "k_guard_field_validation.v1",
        "field_validation_method_invalid": validation.get("method") == "ground_truth_field_validation",
        "field_validation_profile_invalid": validation.get("profile") == "field",
        "field_validation_tier_invalid": validation.get("evidence_tier") == "field",
        "field_validation_raw_contract_invalid": validation.get("raw_free") is True,
        "field_validation_claim_not_ready": validation.get("claim_status") == "field_validation_ready",
        "field_validation_gate_checks_invalid": bool(gate_checks)
        and all(isinstance(item, dict) and item.get("passed") is True for item in gate_checks),
        "field_validation_app_count_mismatch": app_count is not None
        and sample.get("app_count") == app_count
        and sample.get("owned_partner_app_count") == app_count,
        "field_validation_candidate_sample_invalid": candidate_count is not None
        and candidate_count >= 20
        and sample.get("reviewed_candidate_count") == candidate_count,
        "field_validation_ground_truth_sample_invalid": case_count is not None
        and case_count >= 120
        and sample.get("invalid_ground_truth_count") == 0
        and sample.get("invalid_review_count") == 0,
        "field_validation_roster_binding_invalid": roster_source.get("schema")
        == "k_guard_field_roster_source.v1"
        and roster_source.get("content_sha256") == campaign.get("roster_content_sha256")
        and roster_source.get("row_count") == campaign.get("row_count")
        and roster_source.get("exists_at_generation") is True
        and roster_source.get("sha256_verified_at_generation") is True,
        "field_validation_primary_guardian_invalid": isinstance(validation.get("primary_guardian_evidence"), dict)
        and validation["primary_guardian_evidence"].get("passed") is True,
        "field_validation_repeat_guardian_invalid": isinstance(validation.get("repeat_guardian_evidence"), dict)
        and validation["repeat_guardian_evidence"].get("passed") is True,
        "field_validation_candidate_refs_invalid": candidate_count is not None
        and len(candidate_finding_refs) == candidate_count,
        "field_validation_evaluation_refs_invalid": app_count is not None
        and len(evaluation_app_refs) == app_count,
        "field_validation_reviewer_assertions_invalid": candidate_count is not None
        and reviewer_assertions.get("reviewed_row_count") == candidate_count
        and reviewer_assertions.get("dual_reviewed_row_count") == candidate_count
        and reviewer_assertions.get("cryptographically_verified_row_count") == candidate_count
        and reviewer_count is not None
        and reviewer_count >= 2,
        "field_validation_ground_truth_assertions_invalid": case_count is not None
        and ground_truth_assertions.get("case_count") == case_count
        and ground_truth_assertions.get("dual_reviewed_case_count") == case_count
        and ground_truth_assertions.get("cryptographically_verified_case_count") == case_count
        and ground_truth_assertions.get("source_ref_count") == case_count
        and ground_truth_reviewer_count is not None
        and ground_truth_reviewer_count >= 2,
        "field_validation_signed_envelope_invalid": _field_validation_evidence_envelope_matches(validation),
    }
    errors.extend(name for name, passed in required_values.items() if not passed)
    if validation.get("invalid_reviews") != [] or validation.get("invalid_ground_truth") != []:
        errors.append("field_validation_invalid_rows_present")
    return sorted(set(errors))


def _external_field_attestation_errors(
    root: Path,
    campaign: dict[str, Any],
    validation: dict[str, Any],
    attestation_path: Path,
) -> list[str]:
    attestation = _json(attestation_path)
    errors: list[str] = []
    expected_keys = {
        "schema",
        "issued_at",
        "campaign_status_sha256",
        "field_validation_sha256",
        "roster_content_sha256",
        "app_count",
        "verifier",
        "assertions",
        "claim_boundary",
        "raw_returned",
    }
    if set(attestation) != expected_keys or attestation.get("schema") != "k_guard_external_field_attestation.v1":
        errors.append("field_external_attestation_schema_invalid")
    if attestation.get("raw_returned") is not False:
        errors.append("field_external_attestation_raw_returned_invalid")
    try:
        issued_at = datetime.fromisoformat(str(attestation.get("issued_at") or "").replace("Z", "+00:00"))
    except ValueError:
        issued_at = None
    if issued_at is None or issued_at.tzinfo is None:
        errors.append("field_external_attestation_timestamp_invalid")

    campaign_path = root / "evidence" / "field" / "campaign-status.json"
    validation_path = root / FIELD_EVIDENCE_PATHS["validation_report"]
    if (
        not campaign_path.is_file()
        or attestation.get("campaign_status_sha256") != _sha256(campaign_path)
        or not validation_path.is_file()
        or attestation.get("field_validation_sha256") != _sha256(validation_path)
        or attestation.get("roster_content_sha256") != campaign.get("roster_content_sha256")
        or attestation.get("app_count") != campaign.get("app_count")
        or validation.get("claim_status") != "field_validation_ready"
    ):
        errors.append("field_external_attestation_evidence_binding_invalid")

    verifier = attestation.get("verifier") if isinstance(attestation.get("verifier"), dict) else {}
    if (
        set(verifier) != {"verifier_id", "organization", "role", "independence_statement", "raw_returned"}
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}", str(verifier.get("verifier_id") or "")) is None
        or not str(verifier.get("organization") or "").strip()
        or verifier.get("role") != "independent_field_evidence_verifier"
        or not str(verifier.get("independence_statement") or "").strip()
        or verifier.get("raw_returned") is not False
    ):
        errors.append("field_external_attestation_verifier_invalid")

    assertions = attestation.get("assertions") if isinstance(attestation.get("assertions"), dict) else {}
    required_assertions = {
        "ownership_scope_assertions_reviewed",
        "partner_authorizations_reviewed",
        "scan_and_aggregate_consent_reviewed",
        "independent_dual_review_process_reviewed",
        "primary_and_repeat_executions_reviewed",
        "no_synthetic_or_training_apps",
        "reviewer_identity_assurance_is_external",
    }
    if (
        set(assertions) != required_assertions | {"raw_returned"}
        or any(assertions.get(name) is not True for name in required_assertions)
        or assertions.get("raw_returned") is not False
    ):
        errors.append("field_external_attestation_assertions_invalid")
    if attestation.get("claim_boundary") != (
        "External verifier attestation confirms reviewed assertions and process evidence; "
        "K-Guard still does not independently prove legal ownership, human identity, or award eligibility."
    ):
        errors.append("field_external_attestation_claim_boundary_invalid")

    trusted_digest = os.environ.get(TRUSTED_FIELD_ATTESTATION_SHA256_ENV, "").strip().casefold()
    if re.fullmatch(r"[0-9a-f]{64}", trusted_digest) is None:
        errors.append("field_external_attestation_trust_anchor_missing")
    elif not attestation_path.is_file() or not hmac.compare_digest(trusted_digest, _sha256(attestation_path)):
        errors.append("field_external_attestation_trust_anchor_mismatch")
    return sorted(set(errors))


def _field_award_evidence_status(
    root: Path,
    campaign: dict[str, Any],
) -> tuple[int, list[str]]:
    app_count = _exact_int(campaign.get("app_count")) or 0
    errors = _field_campaign_contract_errors(campaign)
    paths = {name: root / relative for name, relative in FIELD_EVIDENCE_PATHS.items()}
    missing = [name for name, path in paths.items() if not path.is_file()]
    errors.extend(f"field_evidence_source_missing:{name}" for name in missing)
    if missing:
        return app_count, sorted(set(errors))

    reproduced_campaign = evaluate_field_campaign_readiness(paths["roster"])
    if reproduced_campaign != campaign:
        errors.append("field_campaign_status_not_reproducible_from_roster")

    validation = _json(paths["validation_report"])
    errors.extend(_field_validation_contract_errors(campaign, validation))
    errors.extend(
        _external_field_attestation_errors(
            root,
            campaign,
            validation,
            paths["external_attestation"],
        )
    )
    try:
        reproduced_validation = run_field_validation(
            paths["primary_guardian"],
            paths["repeat_guardian"],
            paths["ground_truth"],
            paths["candidate_review"],
            profile="field",
            preregistration_path=paths["preregistration"],
            roster_path=paths["roster"],
        )
    except Exception as exc:
        errors.append(f"field_validation_reexecution_failed:{type(exc).__name__}")
    else:
        if reproduced_validation.get("claim_status") != "field_validation_ready":
            errors.append("field_validation_reexecution_not_ready")
        if field_validation_projection(reproduced_validation) != field_validation_projection(validation):
            errors.append("field_validation_report_not_reproducible_from_sources")
    return app_count, sorted(set(errors))


def _demo_contract_valid(demo: dict[str, Any]) -> bool:
    checks = demo.get("checks", {}) if isinstance(demo.get("checks"), dict) else {}
    required_checks = {
        "stage_order_is_scripted",
        "targets_are_local_only",
        "hold_blocks_app_risk",
        "first_actionable_blocker_is_report_derived",
        "safe_patch_is_visible_and_applied",
        "fix_clears_app_risk",
        "qualification_remains_fail_closed",
        "canonical_release_authority_not_granted",
        "four_review_domains_complete",
        "expected_cli_gate_codes",
        "runtime_within_180_seconds",
    }
    return (
        demo.get("schema") == "k_guard_contest_demo_scorecard.v2"
        and demo.get("passed") is True
        and demo.get("stage_order") == [
            "vulnerable_fixture",
            "first_review_hold",
            "first_actionable_blocker",
            "visible_safe_patch",
            "guardian_rerun",
            "bounded_result",
        ]
        and required_checks.issubset(checks)
        and all(checks.get(name) is True for name in required_checks)
        and demo.get("public_targets_called") is False
        and demo.get("mcp_client_exercised") is False
        and demo.get("award_evidence_claimed") is False
        and demo.get("release_authority_claimed") is False
        and demo.get("canonical_release_authority") is False
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _r2_gate_passed(gates: dict[str, Any], name: str) -> bool:
    gate = gates.get(name)
    return isinstance(gate, dict) and gate.get("pass") is True


def _local_and_inherited(local: object, inherited: object) -> bool:
    return local is True and inherited is True


def _canonical_json_sha256(value: object) -> str:
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _r2_cycle_root(contract_path: Path) -> Path | None:
    for parent in contract_path.parents:
        if parent.name == "evidence":
            return parent.parent
    return None


def _r2_activation_event_error(
    contract_path: Path,
    manifest_path: Path,
    binding: dict[str, Any],
) -> str | None:
    if not manifest_path.is_file():
        return None
    cycle_root = _r2_cycle_root(contract_path)
    if cycle_root is None:
        return "r2_current_source_succession_activation_event_missing"
    events_root = cycle_root / "operations" / "logs" / "events"
    if not events_root.is_dir():
        return "r2_current_source_succession_activation_event_missing"
    candidates: list[tuple[Path, dict[str, Any]]] = []
    for event_path in sorted(events_root.glob("*.json")):
        event = _json(event_path)
        if (
            event.get("schema") == R2_WORK_EVENT_SCHEMA
            and event.get("action") == R2_SUCCESSION_ACTIVATION_ACTION
            and event.get("work_item_id") == R2_SUCCESSION_ACTIVATION_WORK_ITEM
        ):
            candidates.append((event_path, event))
    if not candidates:
        return "r2_current_source_succession_activation_event_missing"
    if len(candidates) != 1:
        return "r2_current_source_succession_activation_event_ambiguous"
    event_path, event = candidates[0]
    required_fields = {
        "schema", "sequence", "event_id", "recorded_at_kst", "cycle_id", "phase_id", "work_item_id",
        "actor", "action", "status", "summary", "repository", "artifacts", "previous_event_sha256",
        "event_sha256", "raw_returned",
    }
    if (
        set(event) != required_fields
        or not isinstance(event.get("sequence"), int)
        or isinstance(event.get("sequence"), bool)
        or event.get("sequence", 0) < 1
        or not isinstance(event.get("event_id"), str)
        or event_path.name != f"{event['sequence']:06d}-{event['event_id']}.json"
        or event.get("event_sha256") != _canonical_json_sha256({key: value for key, value in event.items() if key != "event_sha256"})
        or event.get("cycle_id") != "product-hardening-r2"
        or event.get("phase_id") != "phase-0"
        or event.get("status") != "PASS"
        or event.get("raw_returned") is not False
    ):
        return "r2_current_source_succession_activation_event_invalid"
    repository = event.get("repository") if isinstance(event.get("repository"), dict) else {}
    if (
        repository.get("commit") != binding.get("head")
        or repository.get("tree") != binding.get("tree")
        or repository.get("dirty_count") != 0
    ):
        return "r2_current_source_succession_activation_event_invalid"
    try:
        expected_artifacts = {
            contract_path.relative_to(cycle_root).as_posix(): contract_path,
            manifest_path.relative_to(cycle_root).as_posix(): manifest_path,
        }
    except ValueError:
        return "r2_current_source_succession_activation_event_invalid"
    artifacts = event.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(expected_artifacts):
        return "r2_current_source_succession_activation_event_invalid"
    observed_artifacts = {item.get("path"): item for item in artifacts if isinstance(item, dict)}
    if set(observed_artifacts) != set(expected_artifacts):
        return "r2_current_source_succession_activation_event_invalid"
    for relative, artifact_path in expected_artifacts.items():
        item = observed_artifacts[relative]
        if (
            set(item) != {"path", "byte_count", "sha256"}
            or item.get("byte_count") != artifact_path.stat().st_size
            or item.get("sha256") != _sha256(artifact_path)
        ):
            return "r2_current_source_succession_activation_event_invalid"
    return None


def _r2_gate_status_errors(gate_status: dict[str, Any], binding: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    gates = gate_status.get("gates") if isinstance(gate_status.get("gates"), dict) else {}
    failed_ids = gate_status.get("failed_gate_ids")
    if (
        gate_status.get("schema") != R2_GATE_STATUS_SCHEMA
        or gate_status.get("status") != "HOLD"
        or gate_status.get("release_status") != "HOLD"
        or failed_ids != list(R2_SUCCESSION_REQUIRED_GATES)
        or set(gates) != set(R2_SUCCESSION_GATE_PASSES)
    ):
        errors.append("r2_current_source_succession_gate_status_invalid")
    for name, expected_pass in R2_SUCCESSION_GATE_PASSES.items():
        gate = gates.get(name)
        if not isinstance(gate, dict) or not isinstance(gate.get("pass"), bool) or gate.get("pass") is not expected_pass:
            errors.append("r2_current_source_succession_gate_status_invalid")
            continue
        if (name in (failed_ids or [])) is gate["pass"]:
            errors.append("r2_current_source_succession_gate_status_invalid")
    clean_head = gates.get("clean_head") if isinstance(gates.get("clean_head"), dict) else {}
    observed = clean_head.get("observed") if isinstance(clean_head.get("observed"), dict) else {}
    if (
        binding.get("head") != observed.get("head")
        or binding.get("tree") != observed.get("tree")
        or binding.get("repo_clean_before") is not True
        or observed.get("dirty") is not False
        or clean_head.get("pass") is not True
    ):
        errors.append("r2_current_source_succession_source_binding_invalid")
    return sorted(set(errors))


def _r2_current_source_succession_status(
    contract_path: Path,
    root: Path,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """Validate an explicit R2 successor contract; never discover one implicitly."""
    errors: list[str] = []
    path = contract_path.resolve()
    if not path.is_file():
        return {}, {}, ["r2_current_source_succession_contract_missing"]
    contract = _json(path)
    if not contract:
        return {}, {}, ["r2_current_source_succession_contract_unreadable"]
    if contract.get("schema") != R2_SUCCESSION_CONTRACT_SCHEMA:
        errors.append("r2_current_source_succession_contract_schema_invalid")
    if contract.get("contract_version") != R2_SUCCESSION_CONTRACT_VERSION:
        errors.append("r2_current_source_succession_contract_version_invalid")
    if contract.get("raw_returned") is not False:
        errors.append("r2_current_source_succession_contract_raw_boundary_invalid")
    invariants = contract.get("invariants") if isinstance(contract.get("invariants"), dict) else {}
    required_invariants = {
        "historical_sealed_artifacts_immutable": True,
        "fixed_thresholds_unchanged": True,
        "denominators_unchanged": True,
        "oracle_definitions_unchanged": True,
        "labels_severity_and_exclusions_unchanged": True,
        "legacy_readiness_pass_claim_prohibited": True,
        "release_status": "HOLD",
        "phase_status": "HOLD",
    }
    if any(invariants.get(name) != expected for name, expected in required_invariants.items()):
        errors.append("r2_current_source_succession_invariants_invalid")
    binding = contract.get("source_binding") if isinstance(contract.get("source_binding"), dict) else {}
    active_binding = contract.get("active_contract_binding") if isinstance(contract.get("active_contract_binding"), dict) else {}
    active_refs = [active_binding.get("active"), *(active_binding.get("documents") or [])]
    if not active_refs or any(
        not isinstance(item, dict)
        or not isinstance(item.get("path"), str)
        or not isinstance(item.get("sha256"), str)
        or not Path(item["path"]).is_file()
        or _sha256(Path(item["path"])) != item["sha256"]
        for item in active_refs
    ):
        errors.append("r2_current_source_succession_active_contract_binding_invalid")
    inherited = contract.get("inherited_evidence") if isinstance(contract.get("inherited_evidence"), list) else []
    inherited_by_name: dict[str, dict[str, Any]] = {}
    for item in inherited:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or item["name"] in inherited_by_name:
            errors.append("r2_current_source_succession_inherited_evidence_shape_invalid")
            continue
        inherited_by_name[item["name"]] = item
    if set(inherited_by_name) != R2_SUCCESSION_REQUIRED_ARTIFACTS:
        errors.append("r2_current_source_succession_inherited_evidence_set_invalid")
    for item in inherited_by_name.values():
        item_path = Path(str(item.get("path") or ""))
        if not item_path.is_file() or _sha256(item_path) != item.get("sha256"):
            errors.append("r2_current_source_succession_inherited_evidence_hash_invalid")
            break
    manifest_path = path.with_name("hash-manifest.json")
    manifest = _json(manifest_path)
    active = active_binding.get("active") if isinstance(active_binding.get("active"), dict) else {}
    if not manifest_path.is_file():
        errors.append("r2_current_source_succession_manifest_missing")
    elif (
        manifest.get("schema") != R2_SUCCESSION_MANIFEST_SCHEMA
        or manifest.get("raw_returned") is not False
        or manifest.get("contract") != {"path": path.name, "sha256": _sha256(path)}
        or manifest.get("source_binding") != binding
        or manifest.get("active_contract_sha256") != active.get("sha256")
        or manifest.get("inherited_evidence") != inherited
    ):
        errors.append("r2_current_source_succession_manifest_invalid")
    gate_status: dict[str, Any] = {}
    gate_ref = inherited_by_name.get("gate_status")
    if gate_ref:
        gate_path = Path(str(gate_ref.get("path") or ""))
        gate_status = _json(gate_path)
    errors.extend(_r2_gate_status_errors(gate_status, binding))
    measured = contract.get("measured_gate_status") if isinstance(contract.get("measured_gate_status"), dict) else {}
    if (
        measured.get("status") != gate_status.get("status")
        or measured.get("release_status") != gate_status.get("release_status")
        or measured.get("failed_gate_ids") != gate_status.get("failed_gate_ids")
    ):
        errors.append("r2_current_source_succession_measured_gate_binding_invalid")
    activation_error = _r2_activation_event_error(path, manifest_path, binding)
    if activation_error:
        errors.append(activation_error)
    return contract, gate_status, sorted(set(errors))


def _language_validation_contract_errors(contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if contract.get("schema") != "k_guard_language_validation_contract.v1":
        errors.append("language_validation_contract_schema_invalid")
    if contract.get("complete") is not True:
        errors.append("language_validation_pack_incomplete")
    hashes = contract.get("hashes") if isinstance(contract.get("hashes"), dict) else {}
    required = (
        "pack_sha256",
        "expectations_sha256",
        "profile_sha256",
        "profile_rules_sha256",
        "validator_sha256",
        "adapter_sha256",
        "adapter_command_contract_sha256",
        "semgrep_executable_version_sha256",
    )
    for name in required:
        if re.fullmatch(r"[0-9a-f]{64}", str(hashes.get(name) or "")) is None:
            errors.append(f"language_validation_{name}_invalid")
    if contract.get("raw_free") is not True:
        errors.append("language_validation_contract_raw_free_invalid")
    return sorted(set(errors))


def _revision_package_errors(root: Path, revision: str, expected_hash: str, prefix: str) -> list[str]:
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        return [f"{prefix}_source_revision_invalid"]
    try:
        revision_hash = package_tree_sha256_at_revision(root, revision)
    except (OSError, ValueError):
        return [f"{prefix}_source_revision_unresolvable"]
    if revision_hash != expected_hash:
        return [f"{prefix}_source_revision_package_mismatch"]
    return []


def _read_json_object(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.is_file():
        return None, "missing"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, "malformed"
    if not isinstance(payload, dict):
        return None, "malformed"
    return payload, None


def _declared_sbom_live_count(payload: dict[str, Any], field: str) -> int | None:
    if field == "components":
        components = payload.get("components")
        return len(components) if isinstance(components, list) else None
    return _exact_int(payload.get(field))


def _declared_sbom_component_count_errors(root: Path) -> list[str]:
    errors: list[str] = []
    expected = DECLARED_SBOM_COMPONENT_COUNT
    for relative, field in DECLARED_SBOM_COMPONENT_COUNT_ARTIFACTS:
        payload, load_error = _read_json_object(root / relative)
        if load_error == "missing":
            errors.append(f"declared_sbom_component_count_missing:{relative}")
            continue
        if load_error == "malformed" or payload is None:
            errors.append(f"declared_sbom_component_count_malformed:{relative}")
            continue
        count = _declared_sbom_live_count(payload, field)
        if count is None:
            errors.append(f"declared_sbom_component_count_wrong_type:{relative}")
            continue
        if count != expected:
            errors.append(f"declared_sbom_component_count_mismatch:{relative}")
    return errors


def _submission_release_archive_errors(root: Path) -> list[str]:
    return committed_release_archive_errors(
        dist=root / SUBMISSION_WHEEL_DIR,
        repo_root=root,
    )


def _fresh_wheel_smoke_errors(
    smoke: dict[str, Any],
    current_package_hash: str,
    root: Path = ROOT,
) -> list[str]:
    errors: list[str] = []
    if smoke.get("schema") != "k_guard_fresh_wheel_stdio_smoke.v3":
        errors.append("fresh_wheel_smoke_schema_invalid")
    if smoke.get("passed") is not True:
        errors.append("fresh_wheel_smoke_not_passed")
    if smoke.get("package_tree_hash_schema") != TREE_HASH_SCHEMA:
        errors.append("fresh_wheel_smoke_hash_schema_invalid")
    for field in ("source_package_tree_sha256", "installed_package_tree_sha256"):
        if smoke.get(field) != current_package_hash:
            errors.append(f"fresh_wheel_smoke_{field}_not_current")
    if smoke.get("site_packages_loaded") is not True:
        errors.append("fresh_wheel_smoke_not_loaded_from_site_packages")
    source_revision = str(smoke.get("source_revision") or "")
    errors.extend(_revision_package_errors(root, source_revision, current_package_hash, "fresh_wheel_smoke"))
    wheel_digest = str(smoke.get("wheel_sha256") or "")
    if re.fullmatch(r"[0-9a-f]{64}", wheel_digest) is None:
        errors.append("fresh_wheel_smoke_wheel_digest_invalid")
    wheel_artifact = smoke.get("wheel_artifact") if isinstance(smoke.get("wheel_artifact"), dict) else {}
    artifact_filename = str(wheel_artifact.get("filename") or "")
    package_version = str(smoke.get("package_version") or "")
    expected_artifact_keys = {
        "filename",
        "byte_count",
        "sha256",
        "package_tree_sha256",
        "package_file_count",
        "distribution",
        "version",
        "artifact_role",
        "raw_returned",
    }
    if (
        set(wheel_artifact) != expected_artifact_keys
        or not artifact_filename
        or Path(artifact_filename).name != artifact_filename
        or artifact_filename != f"k_guard_mcp-{package_version}-py3-none-any.whl"
        or wheel_artifact.get("artifact_role") != "installed_smoke_input"
        or wheel_artifact.get("raw_returned") is not False
        or wheel_artifact.get("sha256") != wheel_digest
        or wheel_artifact.get("package_tree_sha256") != current_package_hash
        or _exact_int(wheel_artifact.get("package_file_count")) is None
        or wheel_artifact.get("package_file_count", 0) <= 0
        or str(wheel_artifact.get("distribution") or "").casefold().replace("_", "-") != "k-guard-mcp"
        or wheel_artifact.get("version") != package_version
        or _exact_int(wheel_artifact.get("byte_count")) is None
        or wheel_artifact.get("byte_count", 0) <= 0
    ):
        errors.append("fresh_wheel_smoke_wheel_artifact_contract_invalid")
    wheel_dir = root / SUBMISSION_WHEEL_DIR
    submitted_wheels = sorted(path for path in wheel_dir.glob("*.whl") if path.is_file()) if wheel_dir.is_dir() else []
    if len(submitted_wheels) != 1 or not artifact_filename or submitted_wheels[0].name != artifact_filename:
        errors.append("fresh_wheel_smoke_wheel_artifact_set_invalid")
    else:
        wheel_path = submitted_wheels[0]
        if (
            _sha256(wheel_path) != wheel_digest
            or wheel_path.stat().st_size != wheel_artifact.get("byte_count")
        ):
            errors.append("fresh_wheel_smoke_wheel_artifact_digest_mismatch")
        try:
            submitted_contract = wheel_package_contract(wheel_path)
        except Exception:
            errors.append("fresh_wheel_smoke_wheel_artifact_unreadable")
        else:
            if any(
                submitted_contract.get(name) != wheel_artifact.get(name)
                for name in ("package_tree_sha256", "package_file_count", "distribution", "version")
            ):
                errors.append("fresh_wheel_smoke_wheel_artifact_package_mismatch")

    contract = smoke.get("contract") if isinstance(smoke.get("contract"), dict) else {}
    true_fields = (
        "initial_review_terminal",
        "initial_review_flow_included",
        "release_review_terminal",
        "release_source_snapshot_bound",
        "invalid_review_id_failed_closed",
        "text_structured_parity",
    )
    for field in true_fields:
        if contract.get(field) is not True:
            errors.append(f"fresh_wheel_smoke_contract_{field}_invalid")
    if contract.get("raw_workspace_path_returned") is not False:
        errors.append("fresh_wheel_smoke_contract_raw_path_exposed")
    if contract.get("primary_tools") != ["check_my_app", "continue_review", "start_review_before_ship"]:
        errors.append("fresh_wheel_smoke_primary_tools_invalid")
    if contract.get("primary_output_schema_required") != ["method", "experience"]:
        errors.append("fresh_wheel_smoke_output_schema_invalid")
    tool_count = _exact_int(contract.get("tool_count"))
    tool_call_count = _exact_int(contract.get("tool_call_count"))
    if tool_count is None or tool_count < 3 or tool_call_count is None or tool_call_count < 5:
        errors.append("fresh_wheel_smoke_workflow_too_shallow")
    for field in ("guardian_passed", "guardian_canonical_release_authority"):
        if not isinstance(contract.get(field), bool):
            errors.append(f"fresh_wheel_smoke_contract_{field}_missing")
    if smoke.get("raw_returned") is not False:
        errors.append("fresh_wheel_smoke_raw_returned_invalid")
    return sorted(set(errors))


def _public_finding_valid(finding: object) -> bool:
    if not isinstance(finding, dict) or set(finding) != PUBLIC_FINDING_KEYS:
        return False
    required_text = (
        "evidence",
        "file",
        "fix_verification",
        "id",
        "recommendation",
        "rule_id",
        "source",
        "title",
        "why_it_matters",
    )
    if any(not isinstance(finding.get(name), str) or not finding.get(name) for name in required_text):
        return False
    if (
        re.fullmatch(r"finding-\d{4,}", str(finding["id"])) is None
        or re.fullmatch(r"[A-Z][A-Z0-9_]{2,127}", str(finding["rule_id"])) is None
        or finding.get("severity") not in {"critical", "high", "medium", "low", "info"}
        or finding.get("confidence") not in {"high", "medium", "low"}
        or finding.get("artifact_scope") not in PUBLIC_ARTIFACT_SCOPES
        or not (
            finding["file"] == "<workspace>"
            or str(finding["file"]).startswith(("<workspace>/", "<untrusted-path-ref:"))
        )
    ):
        return False
    audit_depth = finding.get("audit_depth")
    if audit_depth is not None and (_exact_int(audit_depth) is None or not 1 <= audit_depth <= 5):
        return False
    line_start = finding.get("line_start")
    line_end = finding.get("line_end")
    if not (
        (line_start is None and line_end is None)
        or (
            _exact_int(line_start) is not None
            and _exact_int(line_end) is not None
            and 1 <= line_start <= line_end
        )
    ):
        return False
    optional_text = (
        "inspected_scope",
        "method",
        "not_inspected",
        "pipc_basis",
        "privacy_class",
        "scope",
        "status",
        "url",
    )
    if any(value is not None and not isinstance(value, str) for value in (finding.get(name) for name in optional_text)):
        return False
    components = finding.get("components")
    return isinstance(components, list) and all(
        isinstance(component, dict)
        and set(component) == {"evidence", "label", "line"}
        and isinstance(component.get("evidence"), str)
        and bool(component.get("evidence"))
        and isinstance(component.get("label"), str)
        and bool(component.get("label"))
        and _exact_int(component.get("line")) is not None
        and component["line"] > 0
        for component in components
    )


def _public_report_contract(
    path: Path,
    app_row: dict[str, Any],
) -> tuple[set[tuple[str, str]], list[str]]:
    errors: list[str] = []
    report = _json(path)
    if set(report) != {"findings", "flow_map", "metadata", "summary"}:
        errors.append("report_schema_invalid")
    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    expected_summary_keys = {"critical", "high", "medium", "low", "info"}
    if set(summary) != expected_summary_keys or any(
        _exact_int(summary.get(name)) is None or summary.get(name) < 0
        for name in expected_summary_keys
    ):
        errors.append("report_summary_invalid")
    else:
        calculated = {name: 0 for name in expected_summary_keys}
        finding_ids: set[str] = set()
        for finding in findings:
            if not _public_finding_valid(finding):
                errors.append("report_finding_invalid")
                continue
            if str(finding["id"]) in finding_ids:
                errors.append("report_finding_id_duplicate")
            finding_ids.add(str(finding["id"]))
            calculated[str(finding["severity"])] += 1
        if calculated != summary or len(findings) != sum(summary.values()):
            errors.append("report_summary_mismatch")

    finding_counts = app_row.get("finding_counts") if isinstance(app_row.get("finding_counts"), dict) else {}
    if (
        any(finding_counts.get(name) != summary.get(name) for name in expected_summary_keys)
        or finding_counts.get("total") != len(findings)
    ):
        errors.append("report_campaign_counts_mismatch")

    metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
    review_coverage = (
        metadata.get("review_coverage")
        if isinstance(metadata.get("review_coverage"), dict)
        else {}
    )
    inventory = (
        review_coverage.get("inventory")
        if isinstance(review_coverage.get("inventory"), dict)
        else {}
    )
    if (
        not isinstance(report.get("flow_map"), dict)
        or review_coverage.get("raw_returned") is not False
        or inventory.get("raw_returned") is not False
        or inventory.get("supported_file_count") != app_row.get("supported_files")
    ):
        errors.append("report_review_coverage_invalid")

    refs: set[tuple[str, str]] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        rule_id = str(finding.get("rule_id") or "")
        filename = str(finding.get("file") or "").replace("\\", "/")
        if filename.startswith("<workspace>/"):
            filename = filename[len("<workspace>/") :]
        line = _exact_int(finding.get("line_start"))
        if rule_id and filename and line is not None and line > 0:
            refs.add((rule_id, f"{filename}:{line}"))
    return refs, sorted(set(errors))


def _public_manifest_contract(
    root: Path,
    campaign: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    manifest = _json(root / CURRENT_PUBLIC_MANIFEST)
    errors: list[str] = []
    if manifest.get("schema") != "k_guard_public_app_manifest.v2":
        errors.append("current_public_manifest_schema_invalid")
    if manifest.get("campaign_id") != campaign.get("campaign_id"):
        errors.append("current_public_manifest_campaign_id_mismatch")
    if manifest.get("campaign_kind") != campaign.get("campaign_kind"):
        errors.append("current_public_manifest_campaign_kind_mismatch")
    if manifest.get("claim_boundary") != campaign.get("claim_boundary"):
        errors.append("current_public_manifest_claim_boundary_mismatch")

    app_rows = manifest.get("apps") if isinstance(manifest.get("apps"), list) else []
    probe_rows = manifest.get("probes") if isinstance(manifest.get("probes"), list) else []
    apps: dict[str, dict[str, Any]] = {}
    probes: dict[str, dict[str, Any]] = {}
    for row in app_rows:
        app = str(row.get("app") or "") if isinstance(row, dict) else ""
        if (
            not isinstance(row, dict)
            or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", app) is None
            or app in apps
            or re.fullmatch(r"[0-9a-f]{40}", str(row.get("commit") or "")) is None
            or row.get("stratum") not in {"top", "mid", "long_tail"}
            or not str(row.get("repository") or "").startswith("https://github.com/")
        ):
            errors.append("current_public_manifest_app_invalid")
            continue
        apps[app] = row
    for row in probe_rows:
        probe_id = str(row.get("probe_id") or "") if isinstance(row, dict) else ""
        if not isinstance(row, dict) or not probe_id or probe_id in probes or str(row.get("app") or "") not in apps:
            errors.append("current_public_manifest_probe_invalid")
            continue
        probes[probe_id] = row
    if len(apps) != 12 or len(probes) != 12 or set(apps) != {str(row.get("app") or "") for row in probe_rows if isinstance(row, dict)}:
        errors.append("current_public_manifest_coverage_invalid")
    return apps, probes, sorted(set(errors))


def _public_probe_metrics_valid(metrics: object) -> bool:
    if not isinstance(metrics, dict):
        return False
    return (
        _exact_int(metrics.get("probe_count")) == 12
        and _exact_int(metrics.get("detected")) == 12
        and _exact_int(metrics.get("false_negative")) == 0
    )


def _current_public_replay_status(
    evidence_dir: Path,
    current_package_hash: str,
    root: Path = ROOT,
) -> tuple[dict[str, int], list[str]]:
    campaign = _json(evidence_dir / "campaign.json")
    candidates = _json(evidence_dir / "candidate-queue.json")
    probes = _json(evidence_dir / "reference-probes.json")
    errors: list[str] = []
    manifest_apps, manifest_probes, manifest_errors = _public_manifest_contract(root, campaign)
    errors.extend(manifest_errors)
    expected_schemas = (
        (campaign, "k_guard_public_app_campaign.v2", "campaign"),
        (candidates, "k_guard_public_candidate_queue.v2", "candidates"),
        (probes, "k_guard_public_reference_probe_run.v2", "probes"),
    )
    for payload, schema, name in expected_schemas:
        if payload.get("schema") != schema:
            errors.append(f"current_public_{name}_schema_invalid")
        if payload.get("analyzer_package_tree_hash_schema") != TREE_HASH_SCHEMA:
            errors.append(f"current_public_{name}_hash_schema_invalid")
        if payload.get("analyzer_package_tree_sha256") != current_package_hash:
            errors.append(f"current_public_{name}_analyzer_not_current")
        if payload.get("raw_returned") is not False:
            errors.append(f"current_public_{name}_raw_returned_invalid")

    campaign_ids = {str(payload.get("campaign_id") or "") for payload, _, _ in expected_schemas}
    revisions = {str(payload.get("source_revision") or "") for payload, _, _ in expected_schemas}
    if len(campaign_ids) != 1 or "" in campaign_ids:
        errors.append("current_public_campaign_id_mismatch")
    if len(revisions) != 1 or any(re.fullmatch(r"[0-9a-f]{40}", revision) is None for revision in revisions):
        errors.append("current_public_source_revision_mismatch")
    else:
        errors.extend(
            _revision_package_errors(root, next(iter(revisions)), current_package_hash, "current_public")
        )
    if campaign.get("tracked_worktree_clean") is not True:
        errors.append("current_public_analyzer_worktree_not_clean")

    app_rows = campaign.get("apps") if isinstance(campaign.get("apps"), list) else []
    if len(app_rows) != 12:
        errors.append("current_public_app_count_not_12")
    stratum_counts = {name: 0 for name in ("top", "mid", "long_tail")}
    report_hashes: dict[str, str] = {}
    report_finding_refs: dict[str, set[tuple[str, str]]] = {}
    expected_report_files: set[str] = set()
    for row in app_rows:
        if not isinstance(row, dict):
            errors.append("current_public_app_row_invalid")
            continue
        app = str(row.get("app") or "")
        stratum = str(row.get("stratum") or "")
        manifest_row = manifest_apps.get(app, {})
        if any(row.get(name) != manifest_row.get(name) for name in ("repository", "commit", "stratum")):
            errors.append(f"current_public_app_manifest_binding_invalid:{app or 'unknown'}")
        if stratum in stratum_counts:
            stratum_counts[stratum] += 1
        else:
            errors.append(f"current_public_app_stratum_invalid:{app}")
        runs = row.get("runs") if isinstance(row.get("runs"), list) else []
        hashes = {str(run.get("report_sha256") or "") for run in runs if isinstance(run, dict)}
        supported_files = _exact_int(row.get("supported_files"))
        run_numbers = {
            _exact_int(run.get("run"))
            for run in runs
            if isinstance(run, dict) and _exact_int(run.get("run")) is not None
        }
        if (
            not app
            or row.get("source_worktree_clean") is not True
            or row.get("exact_repeat") is not True
            or supported_files is None
            or supported_files <= 0
            or len(runs) != 2
            or run_numbers != {1, 2}
            or len(hashes) != 1
            or any(not isinstance(run, dict) or run.get("exit_code") != 0 for run in runs)
            or any(re.fullmatch(r"[0-9a-f]{64}", digest) is None for digest in hashes)
        ):
            errors.append(f"current_public_app_replay_invalid:{app or 'unknown'}")
        elif app in report_hashes:
            errors.append(f"current_public_duplicate_app:{app}")
        else:
            report_hashes[app] = next(iter(hashes))
            first_refs: set[tuple[str, str]] | None = None
            for run in runs:
                run_number = int(run["run"])
                report_name = f"{app}-run{run_number}.json"
                expected_report_files.add(report_name)
                report_path = evidence_dir / "reports" / report_name
                if not report_path.is_file():
                    errors.append(f"current_public_report_missing:{report_name}")
                    continue
                if _sha256(report_path) != run.get("report_sha256"):
                    errors.append(f"current_public_report_digest_mismatch:{report_name}")
                refs, report_errors = _public_report_contract(report_path, row)
                errors.extend(f"current_public_{error}:{report_name}" for error in report_errors)
                if first_refs is None:
                    first_refs = refs
                elif refs != first_refs:
                    errors.append(f"current_public_report_finding_set_mismatch:{app}")
            if first_refs is not None:
                report_finding_refs[app] = first_refs
    if stratum_counts != {"top": 4, "mid": 4, "long_tail": 4}:
        errors.append("current_public_stratification_invalid")
    report_dir = evidence_dir / "reports"
    actual_report_files = {
        path.name for path in report_dir.iterdir() if path.is_file()
    } if report_dir.is_dir() else set()
    if actual_report_files != expected_report_files:
        errors.append("current_public_report_file_set_invalid")

    sampling = candidates.get("sampling") if isinstance(candidates.get("sampling"), dict) else {}
    available_by_app = (
        sampling.get("available_by_app")
        if isinstance(sampling.get("available_by_app"), dict)
        else {}
    )
    sampled_by_app = (
        sampling.get("sampled_by_app")
        if isinstance(sampling.get("sampled_by_app"), dict)
        else {}
    )
    target_per_app = _exact_int(sampling.get("target_per_app"))
    sampling_apps = set(report_hashes)
    if (
        set(available_by_app) != sampling_apps
        or set(sampled_by_app) != sampling_apps
        or target_per_app is None
        or target_per_app <= 0
        or sampling.get("sample_all_available_when_below_target") is not True
        or any(
            _exact_int(available_by_app.get(app)) is None
            or available_by_app[app] < 0
            or _exact_int(sampled_by_app.get(app)) is None
            or sampled_by_app[app] < 0
            or sampled_by_app[app] != min(available_by_app[app], target_per_app)
            for app in sampling_apps
        )
    ):
        errors.append("current_public_candidate_sampling_contract_invalid")

    campaign_by_app = {
        str(row.get("app") or ""): row
        for row in app_rows
        if isinstance(row, dict) and str(row.get("app") or "")
    }
    if any(
        campaign_by_app.get(app, {}).get("available_release_blocking_findings")
        != available_by_app.get(app)
        or campaign_by_app.get(app, {}).get("sampled_release_blocking_candidates")
        != sampled_by_app.get(app)
        for app in sampling_apps
    ):
        errors.append("current_public_candidate_campaign_sampling_mismatch")

    candidate_rows = candidates.get("candidates") if isinstance(candidates.get("candidates"), list) else []
    if len(candidate_rows) < 12:
        errors.append("current_public_candidate_sample_too_small")
    candidate_apps: set[str] = set()
    candidate_counts: dict[str, int] = {}
    for row in candidate_rows:
        if not isinstance(row, dict):
            errors.append("current_public_candidate_row_invalid")
            continue
        app = str(row.get("app") or "")
        candidate_apps.add(app)
        candidate_counts[app] = candidate_counts.get(app, 0) + 1
        location = row.get("location") if isinstance(row.get("location"), dict) else {}
        if (
            row.get("severity") not in {"critical", "high"}
            or not str(row.get("redacted_fingerprint") or "").startswith("sha256-truncated:")
            or not str(row.get("detector_subtype") or "")
            or not str(row.get("artifact_scope") or "")
            or not str(location.get("kind") or "")
            or row.get("raw_returned") is not False
            or row.get("scan_report_sha256") != report_hashes.get(app)
            or (str(row.get("rule_id") or ""), str(row.get("source_location") or ""))
            not in report_finding_refs.get(app, set())
        ):
            errors.append(f"current_public_candidate_binding_invalid:{app or 'unknown'}")
        if not public_candidate_evidence_shape_valid(row):
            errors.append(f"current_public_candidate_evidence_shape_invalid:{app or 'unknown'}")
    expected_candidate_apps = {
        app
        for app in sampling_apps
        if _exact_int(sampled_by_app.get(app)) is not None and sampled_by_app[app] > 0
    }
    if candidate_apps != expected_candidate_apps:
        errors.append("current_public_candidate_app_coverage_invalid")
    if any(candidate_counts.get(app, 0) != sampled_by_app.get(app) for app in sampling_apps):
        errors.append("current_public_candidate_sample_count_invalid")

    probe_rows = probes.get("probes") if isinstance(probes.get("probes"), list) else []
    true_positive = [row for row in probe_rows if isinstance(row, dict) and row.get("oracle_classification") == "true_positive"]
    benign = [row for row in probe_rows if isinstance(row, dict) and row.get("oracle_classification") == "benign_training_fixture"]
    if len(true_positive) != 11 or len(benign) != 1:
        errors.append("current_public_probe_class_balance_invalid")
    for row in probe_rows:
        if not isinstance(row, dict):
            errors.append("current_public_probe_row_invalid")
            continue
        app = str(row.get("app") or "")
        manifest_probe = manifest_probes.get(str(row.get("probe_id") or ""), {})
        manifest_fields = (
            "app",
            "risk_domain",
            "oracle_classification",
            "vulnerability",
            "oracle_refs",
            "accepted_rule_ids",
        )
        matching_findings = row.get("matching_findings") if isinstance(row.get("matching_findings"), list) else []
        finding_refs_valid = bool(matching_findings) and all(
            isinstance(item, dict)
            and (str(item.get("rule_id") or ""), str(item.get("source_location") or ""))
            in report_finding_refs.get(app, set())
            for item in matching_findings
        )
        if (
            row.get("detected") is not True
            or row.get("result") != "detected"
            or row.get("entire_report_reviewed") is not True
            or row.get("reviewer_kind") != "deterministic_source_oracle"
            or row.get("raw_returned") is not False
            or row.get("scan_report_sha256") != report_hashes.get(app)
            or any(row.get(name) != manifest_probe.get(name) for name in manifest_fields)
            or not finding_refs_valid
        ):
            errors.append(f"current_public_probe_binding_invalid:{app or 'unknown'}")
    if {str(row.get("probe_id") or "") for row in probe_rows if isinstance(row, dict)} != set(manifest_probes):
        errors.append("current_public_probe_manifest_coverage_invalid")
    probe_metrics = probes.get("metrics") if isinstance(probes.get("metrics"), dict) else {}
    if not _public_probe_metrics_valid(probe_metrics):
        errors.append("current_public_probe_metrics_invalid")

    metrics = {
        "app_count": len(app_rows),
        "runs_per_app": 2,
        "total_app_runs": len(app_rows) * 2,
        "exact_repeat_app_count": sum(
            isinstance(row, dict) and row.get("exact_repeat") is True for row in app_rows
        ),
        "candidate_count": len(candidate_rows),
        "probe_count": len(probe_rows),
        "true_positive_probe_count": len(true_positive),
        "true_positive_probe_detected": sum(row.get("detected") is True for row in true_positive),
        "benign_probe_count": len(benign),
        "benign_probe_detected": sum(row.get("detected") is True for row in benign),
    }
    return metrics, sorted(set(errors))


def _submission_report_errors(root: Path) -> list[str]:
    docx = root / SUBMISSION_REPORT_DOCX
    pdf = root / SUBMISSION_REPORT_PDF
    attestation = _json(root / SUBMISSION_REPORT_ATTESTATION)
    errors: list[str] = []
    for path, name in ((docx, "docx"), (pdf, "pdf")):
        if not path.is_file():
            errors.append(f"submission_report_{name}_missing")
    if errors:
        return sorted(errors)
    try:
        verified = verify_official_report(docx, pdf, require_external_urls=False)
    except (OSError, OfficialReportVerificationError):
        errors.append("submission_report_official_pair_invalid")
        return sorted(errors)
    if attestation.get("schema") != "k_guard_official_contest_report_verification.v1":
        errors.append("submission_report_attestation_schema_invalid")
    if attestation.get("package_tree_hash_schema") != TREE_HASH_SCHEMA:
        errors.append("submission_report_attestation_hash_schema_invalid")
    current_package_hash = package_tree_sha256(root / "src" / "k_guard_mcp")
    if attestation.get("analyzer_package_tree_sha256") != current_package_hash:
        errors.append("submission_report_attestation_analyzer_not_current")
    if attestation.get("docx_sha256") != _sha256(docx):
        errors.append("submission_report_attestation_docx_digest_mismatch")
    if attestation.get("pdf_sha256") != _sha256(pdf):
        errors.append("submission_report_attestation_pdf_digest_mismatch")
    errors.extend(
        _revision_package_errors(
            root,
            str(attestation.get("source_revision") or ""),
            current_package_hash,
            "submission_report_attestation",
        )
    )
    if (
        attestation.get("page_count") != OFFICIAL_REPORT_TOTAL_PAGES
        or attestation.get("body_page_count") != verified.body_page_count
        or attestation.get("body_page_limit") != OFFICIAL_REPORT_MAX_BODY_PAGES
        or attestation.get("appendix_page_count") != OFFICIAL_REPORT_APPENDIX_PAGES
        or attestation.get("docx_section_count") != verified.docx_section_count
        or attestation.get("a4_mixed_orientation_verified") is not True
        or attestation.get("visual_reviewed_all_pages") is not True
        or attestation.get("raw_returned") is not False
    ):
        errors.append("submission_report_attestation_contract_invalid")
    if attestation.get("placeholder_count") != verified.placeholder_count:
        errors.append("submission_report_attestation_placeholder_count_mismatch")
    if attestation.get("repository_url") != verified.repository_url:
        errors.append("submission_report_attestation_repository_url_mismatch")
    if attestation.get("youtube_url") != verified.youtube_url:
        errors.append("submission_report_attestation_youtube_url_mismatch")
    if attestation.get("external_urls_complete") is not verified.external_urls_complete:
        errors.append("submission_report_attestation_external_url_state_mismatch")
    if not verified.external_urls_complete:
        errors.append("submission_report_external_urls_incomplete")
    return sorted(set(errors))


def _workflow_checkout_history_errors(text: str, source_name: str) -> list[str]:
    lines = text.splitlines()
    errors: list[str] = []
    for index, line in enumerate(lines):
        if re.search(r"\buses:\s+actions/checkout@[0-9a-f]{40}\b", line) is None:
            continue
        indentation = len(line) - len(line.lstrip())
        block: list[str] = []
        for following in lines[index + 1 :]:
            following_indentation = len(following) - len(following.lstrip())
            if following.lstrip().startswith("- ") and following_indentation <= indentation:
                break
            block.append(following)
        if not any(re.fullmatch(r"\s*fetch-depth:\s*0\s*", item) for item in block):
            errors.append(f"{source_name}_checkout_full_history_missing:{index + 1}")
    return errors


def _audit_regression_contract(root: Path) -> tuple[str, list[str]]:
    """Select the audit command from a validated distribution marker."""
    marker = root / PUBLIC_SNAPSHOT_METADATA
    if not marker.exists():
        return INTERNAL_AUDIT_REGRESSION_COMMAND, []
    if not marker.is_file():
        return INTERNAL_AUDIT_REGRESSION_COMMAND, ["public_snapshot_audit_contract_invalid"]
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return INTERNAL_AUDIT_REGRESSION_COMMAND, ["public_snapshot_audit_contract_invalid"]
    if not isinstance(payload, dict):
        return INTERNAL_AUDIT_REGRESSION_COMMAND, ["public_snapshot_audit_contract_invalid"]
    if (
        payload.get("schema") != PUBLIC_SNAPSHOT_SCHEMA
        or payload.get("public_ci") != PUBLIC_AUDIT_REGRESSION_COMMAND
    ):
        return INTERNAL_AUDIT_REGRESSION_COMMAND, ["public_snapshot_audit_contract_invalid"]
    return PUBLIC_AUDIT_REGRESSION_COMMAND, []


def _release_workflow_contract_errors(root: Path) -> list[str]:
    ci_path = root / ".github" / "workflows" / "ci.yml"
    release_path = root / ".github" / "workflows" / "release.yml"
    audit_path = root / ".github" / "workflows" / "k-guard-audit.yml"
    errors: list[str] = []
    if not ci_path.is_file():
        errors.append("release_workflow_ci_missing")
    if not release_path.is_file():
        errors.append("release_workflow_release_missing")
    if not audit_path.is_file():
        errors.append("release_workflow_audit_missing")
    if errors:
        return errors
    try:
        ci = ci_path.read_text(encoding="utf-8")
        release = release_path.read_text(encoding="utf-8")
        audit = audit_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ["release_workflow_unreadable"]

    audit_regression_command, snapshot_errors = _audit_regression_contract(root)
    errors.extend(snapshot_errors)
    required = {
        "ci_workflow_call_missing": (ci, "workflow_call:"),
        "ci_python_314_missing": (ci, '"3.14"'),
        "release_compatibility_call_missing": (release, "uses: ./.github/workflows/ci.yml"),
        "release_compatibility_dependency_missing": (release, "needs: compatibility"),
        "release_tag_version_check_missing": (release, "--expected-tag"),
        "release_pip_audit_lock_missing": (release, "requirements-pip-audit.lock"),
        "release_semgrep_lock_missing": (release, "requirements-semgrep.lock"),
        "release_attestation_missing": (release, "actions/attest@"),
        "release_durable_publish_missing": (release, "gh release create"),
        "release_write_permission_missing": (release, "contents: write"),
        "audit_regression_tests_missing": (audit, audit_regression_command),
    }
    errors.extend(name for name, (text, token) in required.items() if token not in text)
    errors.extend(_workflow_checkout_history_errors(ci, "ci"))
    errors.extend(_workflow_checkout_history_errors(release, "release"))
    errors.extend(_workflow_checkout_history_errors(audit, "audit"))
    if "pip install --upgrade pip" in release:
        errors.append("release_mutable_pip_upgrade_present")
    for source_name, text in (("ci", ci), ("release", release), ("audit", audit)):
        for line_number, line in enumerate(text.splitlines(), start=1):
            match = re.search(r"\buses:\s+([^\s@]+)@([^\s#]+)", line)
            if match and not match.group(1).startswith("./") and re.fullmatch(r"[0-9a-f]{40}", match.group(2)) is None:
                errors.append(f"{source_name}_action_not_sha_pinned:{line_number}")
    return sorted(set(errors))


def _submission_rights_errors(root: Path) -> list[str]:
    path = root / SUBMISSION_RIGHTS
    if not path.is_file():
        return ["submission_rights_record_missing"]
    try:
        text = path.read_text(encoding="utf-8").casefold()
    except (OSError, UnicodeError):
        return ["submission_rights_record_unreadable"]
    required = {
        "project_generated_artwork": "project-generated artwork",
        "no_external_font_files": "no external font files",
        "voxcpm2_narration": "voxcpm2",
        "no_reference_audio": "no reference recording",
        "no_music": "no reference recording, cloned identity, real person's voice sample, music",
        "synthetic_sample_data": "synthetic sample data",
        "no_vendor_certification": "no vendor certification",
        "third_party_notices": "third_party_notices.md",
        "not_legal_opinion": "not a legal opinion",
    }
    return sorted(
        f"submission_rights_missing:{name}"
        for name, token in required.items()
        if token not in text
    )


def _submission_claim_errors(
    root: Path,
    public_effectiveness: dict[str, Any],
    juliet_first: dict[str, Any],
    juliet_replay: dict[str, Any],
    current_public: dict[str, Any],
) -> list[str]:
    public = public_effectiveness.get("metrics", {}) if isinstance(public_effectiveness.get("metrics"), dict) else {}
    first = juliet_first.get("metrics", {}) if isinstance(juliet_first.get("metrics"), dict) else {}
    replay = juliet_replay.get("metrics", {}) if isinstance(juliet_replay.get("metrics"), dict) else {}
    current = current_public if isinstance(current_public, dict) else {}
    replay_contract = dict(replay)
    replay_contract["claim_boundary"] = (
        juliet_replay.get("claim_boundary")
        if isinstance(juliet_replay.get("claim_boundary"), dict)
        else {}
    )
    if not source_metrics_match_contract(public, current, first, replay_contract):
        return ["source_evidence_metrics_not_at_expected_revision"]

    errors: list[str] = []
    for relative in SUBMISSION_CLAIM_FILES:
        path = root / relative
        if not path.is_file():
            errors.append(f"missing:{relative.as_posix()}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            errors.append(f"unreadable:{relative.as_posix()}")
            continue
        for code in claim_surface_errors(text):
            errors.append(f"{code}:{relative.as_posix()}")
    return sorted(errors)


def _submission_video_status(path: Path, attestation_path: Path) -> tuple[dict[str, Any], list[str]]:
    live_probe = bool(shutil.which("ffprobe") and shutil.which("ffmpeg"))
    status, errors = validate_attestation(path, attestation_path, live_probe=live_probe)
    normalized = dict(status)
    normalized.update(
        {
            "path": SUBMISSION_VIDEO.as_posix(),
            "exists": path.is_file(),
            "live_reverified": live_probe and not errors,
            "raw_returned": False,
        }
    )
    normalized["valid"] = normalized.get("valid") is True and not errors
    return normalized, sorted(set(errors))


def write_markdown(report: dict[str, Any], path: Path) -> None:
    checks = {**report["internal_checks"], **report["external_checks"]}
    lines = [
        "# 안경선배 공모전 준비도",
        "",
        f"- package_ready: `{report['package_ready']}`",
        f"- submission_ready (compatibility alias): `{report['submission_ready']}`",
        f"- external_field_evidence_ready: `{report['award_evidence_ready']}`",
        f"- status: `{report['status']}`",
        "",
        "## Checks",
        "",
        "| check | passed |",
        "|---|---|",
        *[f"| `{name}` | `{passed}` |" for name, passed in checks.items()],
        "",
        "## Remaining Blockers",
        "",
        *([f"- `{name}`" for name in report["blockers"]] or ["- none"]),
        "",
        "## Claim Boundary",
        "",
        str(report["claim_boundary"]),
    ]
    path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate K-Guard's reproducible contest package and external award evidence.")
    parser.add_argument("--output", default="contest-readiness-report.json")
    parser.add_argument("--markdown", default="contest-readiness-report.md")
    parser.add_argument("--r2-current-source-succession-contract", type=Path)
    parser.add_argument("--require-award-evidence", action="store_true")
    args = parser.parse_args()
    report = build_report(r2_current_source_succession_contract=args.r2_current_source_succession_contract)
    Path(args.output).write_bytes((json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    write_markdown(report, Path(args.markdown))
    print(json.dumps({key: report[key] for key in ("package_ready", "award_evidence_ready", "status", "blockers")}, ensure_ascii=False))
    required = report["award_evidence_ready"] if args.require_award_evidence else report["package_ready"]
    return 0 if required else 1


if __name__ == "__main__":
    raise SystemExit(main())
