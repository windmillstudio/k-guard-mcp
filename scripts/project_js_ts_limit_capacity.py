from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for candidate in (str(ROOT), str(SRC)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from k_guard_mcp.scanner import KGuardScanner  # noqa: E402
from k_guard_mcp.taint import (  # noqa: E402
    DEFAULT_JS_TS_EDGES_PER_FILE,
    DEFAULT_JS_TS_FINDINGS_PER_RULE_PER_FILE,
)
from scripts.evidence_tree import package_tree_sha256  # noqa: E402


LIMIT_RULE = "STATIC_ANALYSIS_LIMIT_REACHED"
CONTROL_MAX_EDGES_PER_FILE = 20
CONTROL_MAX_FINDINGS_PER_RULE_PER_FILE = 10
VOLATILE_AGGREGATE_RULES = frozenset(
    {
        "RETENTION_ERASURE_PATH_MISSING_FOR_PERSONAL_DATA",
        "RETENTION_POLICY_MISSING_FOR_PERSONAL_DATA",
    }
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()


def _contained_file(root: Path, relative: str) -> Path:
    if not relative:
        raise ValueError("bound artifact path missing")
    base = root.resolve()
    candidate = root / relative
    if candidate.is_symlink():
        raise ValueError(f"bound artifact uses a symlink: {relative}")
    resolved = candidate.resolve()
    if resolved != base and base not in resolved.parents:
        raise ValueError(f"bound artifact escapes root: {relative}")
    if not resolved.is_file():
        raise ValueError(f"bound artifact missing: {relative}")
    return resolved


def _relative_locator(raw: str | None, app_root: Path) -> str | None:
    value = str(raw or "").replace("\\", "/")
    if not value:
        return None
    if value == "<workspace>":
        return "."
    if value.startswith("<workspace>/"):
        return value[len("<workspace>/") :]
    candidate = Path(str(raw))
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(app_root.resolve()).as_posix()
        except ValueError:
            return f"external:{hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]}"
    if ".." in candidate.parts:
        raise ValueError(f"finding locator escapes app root: {value}")
    return candidate.as_posix()


def _finding_record(
    finding: Any,
    *,
    app: str,
    app_root: Path,
) -> dict[str, Any]:
    is_mapping = isinstance(finding, dict)

    def value(name: str) -> Any:
        return finding.get(name) if is_mapping else getattr(finding, name)

    evidence = str(value("evidence") or "")
    evidence_sha256 = hashlib.sha256(evidence.encode("utf-8")).hexdigest()
    record = {
        "app": app,
        "artifact_scope": value("artifact_scope"),
        "confidence": str(value("confidence") or ""),
        "evidence_sha256": evidence_sha256,
        "line": int(value("line_start") or 0),
        "relative_path": _relative_locator(value("file"), app_root),
        "rule_id": str(value("rule_id") or ""),
        "severity": str(value("severity") or ""),
        "source": str(value("source") or ""),
    }
    identity = {
        key: item
        for key, item in record.items()
        if key != "evidence_sha256"
    }
    if record["rule_id"] not in VOLATILE_AGGREGATE_RULES:
        identity["evidence_sha256"] = evidence_sha256
    record["semantic_key"] = _canonical_sha256(identity)
    record["content_sha256"] = _canonical_sha256(record)
    record["redacted_fingerprint"] = (
        f"sha256-truncated:{record['semantic_key'][:20]}"
    )
    record["raw_returned"] = False
    return record


def _report_findings(
    report: dict[str, Any],
    *,
    app: str,
    app_root: Path,
) -> list[dict[str, Any]]:
    rows = [
        _finding_record(finding, app=app, app_root=app_root)
        for finding in report.get("findings", [])
    ]
    keys = [row["semantic_key"] for row in rows]
    if len(keys) != len(set(keys)):
        raise ValueError(f"baseline finding identity collision: {app}")
    return sorted(rows, key=lambda row: row["semantic_key"])


def _scan(
    *,
    app: str,
    app_root: Path,
    max_edges_per_file: int,
    max_findings_per_rule_per_file: int,
) -> dict[str, Any]:
    scanner = KGuardScanner()
    scanner.flow_analyzer.ast_taint.max_js_ts_edges_per_file = (
        max_edges_per_file
    )
    scanner.flow_analyzer.ast_taint.max_js_ts_findings_per_rule_per_file = (
        max_findings_per_rule_per_file
    )
    started = time.perf_counter()
    result = scanner.scan_workspace(app_root, include_flow=True)
    duration = time.perf_counter() - started
    rows = [
        _finding_record(finding, app=app, app_root=app_root)
        for finding in result.findings
    ]
    keys = [row["semantic_key"] for row in rows]
    if len(keys) != len(set(keys)):
        raise ValueError(f"current finding identity collision: {app}")
    coverage = result.metadata.get("review_coverage") or {}
    inventory = coverage.get("inventory") or {}
    normalized_inventory = {
        "candidate_content_set_sha256": inventory.get(
            "candidate_content_set_sha256"
        ),
        "candidate_path_set_sha256": inventory.get(
            "candidate_path_set_sha256"
        ),
        "candidate_set_complete": inventory.get("candidate_set_complete")
        is True,
        "content_fingerprint_complete": inventory.get(
            "content_fingerprint_complete"
        )
        is True,
        "flow_analysis_executed": coverage.get("flow_analysis_executed") is True,
        "reviewed_candidate_count": int(
            inventory.get("reviewed_candidate_count") or 0
        ),
        "supported_file_count": int(
            inventory.get("supported_file_count") or 0
        ),
        "unscanned_candidate_count": int(
            inventory.get("unscanned_candidate_count") or 0
        ),
        "raw_returned": False,
    }
    normalized = {
        "findings": sorted(rows, key=lambda row: row["semantic_key"]),
        "inventory": normalized_inventory,
    }
    return {
        **normalized,
        "duration_seconds": round(duration, 6),
        "normalized_sha256": _canonical_sha256(normalized),
    }


def _load_baseline_report(
    *,
    campaign_dir: Path,
    app: str,
    app_root: Path,
    runs: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any], float, list[dict[str, Any]]]:
    loaded: list[tuple[list[dict[str, Any]], dict[str, Any], str]] = []
    receipts: list[dict[str, Any]] = []
    duration = 0.0
    for run in sorted(runs, key=lambda row: row["run"]):
        artifact = _contained_file(
            campaign_dir,
            str(run.get("report_artifact_path") or ""),
        )
        if _sha256_file(artifact) != run.get("report_artifact_sha256"):
            raise ValueError(f"baseline report artifact hash mismatch: {app}")
        raw = gzip.decompress(artifact.read_bytes())
        if hashlib.sha256(raw).hexdigest() != run.get("report_sha256"):
            raise ValueError(f"baseline report hash mismatch: {app}")
        report = json.loads(raw.decode("utf-8"))
        findings = _report_findings(report, app=app, app_root=app_root)
        coverage = report.get("metadata", {}).get("review_coverage", {})
        inventory = coverage.get("inventory", {})
        normalized_inventory = {
            "candidate_content_set_sha256": inventory.get(
                "candidate_content_set_sha256"
            ),
            "candidate_path_set_sha256": inventory.get(
                "candidate_path_set_sha256"
            ),
            "candidate_set_complete": inventory.get("candidate_set_complete")
            is True,
            "content_fingerprint_complete": inventory.get(
                "content_fingerprint_complete"
            )
            is True,
            "flow_analysis_executed": coverage.get("flow_analysis_executed")
            is True,
            "reviewed_candidate_count": int(
                inventory.get("reviewed_candidate_count") or 0
            ),
            "supported_file_count": int(
                inventory.get("supported_file_count") or 0
            ),
            "unscanned_candidate_count": int(
                inventory.get("unscanned_candidate_count") or 0
            ),
            "raw_returned": False,
        }
        loaded.append((findings, normalized_inventory, run["report_sha256"]))
        duration += float(run.get("duration_seconds") or 0.0)
        receipts.append(
            {
                "run": int(run["run"]),
                "report_sha256": run["report_sha256"],
                "report_artifact_sha256": run["report_artifact_sha256"],
                "raw_returned": False,
            }
        )
    if (
        len(loaded) != 2
        or loaded[0][0] != loaded[1][0]
        or loaded[0][1] != loaded[1][1]
        or loaded[0][2] != loaded[1][2]
    ):
        raise ValueError(f"baseline report repeat mismatch: {app}")
    return loaded[0][0], loaded[0][1], duration, receipts


def _verify_source_receipt(
    *,
    campaign_dir: Path,
    source_root: Path,
    app: str,
    campaign_app: dict[str, Any],
) -> dict[str, Any]:
    receipt_path = _contained_file(
        campaign_dir,
        str(campaign_app.get("source_materialization_receipt_path") or ""),
    )
    if _sha256_file(receipt_path) != campaign_app.get(
        "source_materialization_receipt_sha256"
    ):
        raise ValueError(f"source receipt hash mismatch: {app}")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    required = (
        "passed",
        "commit_match",
        "commit_tree_match",
        "index_tree_match",
        "physical_bytes_match_git_blobs",
        "source_worktree_clean",
    )
    if (
        receipt.get("schema") != "k_guard_git_source_materialization.v2"
        or receipt.get("raw_returned") is not False
        or any(receipt.get(field) is not True for field in required)
    ):
        raise ValueError(f"source receipt qualification invalid: {app}")
    app_root = source_root / app
    if app_root.is_symlink() or not app_root.is_dir():
        raise ValueError(f"source app root invalid: {app}")
    verified: list[tuple[str, str, int]] = []
    for row in receipt.get("files", []):
        relative = str(row.get("path") or "").replace("\\", "/")
        candidate = app_root / relative
        resolved = candidate.resolve()
        if (
            not relative
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or candidate.is_symlink()
            or (resolved != app_root.resolve() and app_root.resolve() not in resolved.parents)
            or not resolved.is_file()
        ):
            raise ValueError(f"source receipt path invalid: {app}/{relative}")
        expected_bytes = row.get("byte_count")
        if not isinstance(expected_bytes, int) or expected_bytes < 0:
            raise ValueError(f"source receipt byte count invalid: {app}/{relative}")
        expected_hash = str(row.get("sha256") or "")
        if (
            not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
            or _sha256_file(resolved) != expected_hash
            or resolved.stat().st_size != expected_bytes
        ):
            raise ValueError(f"source receipt physical mismatch: {app}/{relative}")
        verified.append((relative, expected_hash, expected_bytes))
    if (
        len(verified) != int(receipt.get("file_count") or -1)
        or sum(row[2] for row in verified) != int(receipt.get("total_bytes") or -1)
    ):
        raise ValueError(f"source receipt aggregate mismatch: {app}")
    return {
        "app": app,
        "file_count": len(verified),
        "physical_file_set_sha256": _canonical_sha256(sorted(verified)),
        "receipt_sha256": _sha256_file(receipt_path),
        "source_tree_sha256": receipt.get("source_tree_sha256"),
        "total_bytes": sum(row[2] for row in verified),
        "raw_returned": False,
    }


def _git_object(*arguments: str) -> str:
    value = subprocess.check_output(
        ["git", *arguments],
        cwd=ROOT,
        text=True,
    ).strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", value):
        raise ValueError(f"git object id invalid: {' '.join(arguments)}")
    return value


def build_projection(
    *,
    campaign_dir: Path,
    source_root: Path,
) -> dict[str, Any]:
    campaign_path = _contained_file(campaign_dir, "campaign.json")
    campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    if (
        campaign.get("schema") != "k_guard_public_field_campaign.v1"
        or campaign.get("raw_returned") is not False
        or campaign.get("tracked_worktree_clean") is not True
    ):
        raise ValueError("campaign manifest contract invalid")
    apps = campaign.get("apps", [])
    app_ids = [str(row.get("app") or "") for row in apps]
    if not app_ids or len(app_ids) != len(set(app_ids)):
        raise ValueError("campaign app set invalid")

    source_before: dict[str, dict[str, Any]] = {}
    historical_by_app: dict[str, list[dict[str, Any]]] = {}
    historical_inventory: dict[str, dict[str, Any]] = {}
    historical_receipts: list[dict[str, Any]] = []
    historical_duration = 0.0
    for campaign_app in apps:
        app = str(campaign_app["app"])
        source_before[app] = _verify_source_receipt(
            campaign_dir=campaign_dir,
            source_root=source_root,
            app=app,
            campaign_app=campaign_app,
        )
        findings, inventory, duration, receipts = _load_baseline_report(
            campaign_dir=campaign_dir,
            app=app,
            app_root=source_root / app,
            runs=list(campaign_app.get("runs", [])),
        )
        historical_by_app[app] = findings
        historical_inventory[app] = inventory
        historical_duration += duration
        historical_receipts.extend(
            {"app": app, **receipt} for receipt in receipts
        )

    app_rows: list[dict[str, Any]] = []
    all_control: dict[str, dict[str, Any]] = {}
    all_treatment: dict[str, dict[str, Any]] = {}
    control_duration = 0.0
    treatment_duration = 0.0
    control_exact_repeat_count = 0
    treatment_exact_repeat_count = 0
    control_coverage_complete_count = 0
    treatment_coverage_complete_count = 0

    def coverage_complete(
        first: dict[str, Any],
        second: dict[str, Any],
        expected: dict[str, Any],
        campaign_app: dict[str, Any],
    ) -> bool:
        inventory = first["inventory"]
        return bool(
            inventory == second["inventory"]
            and inventory["candidate_set_complete"]
            and inventory["content_fingerprint_complete"]
            and inventory["flow_analysis_executed"]
            and inventory["unscanned_candidate_count"] == 0
            and inventory["reviewed_candidate_count"]
            == inventory["supported_file_count"]
            and inventory["candidate_content_set_sha256"]
            == expected["candidate_content_set_sha256"]
            and inventory["candidate_path_set_sha256"]
            == expected["candidate_path_set_sha256"]
            and inventory["supported_file_count"]
            == expected["supported_file_count"]
            == int(campaign_app.get("supported_files") or -1)
        )

    for campaign_app in apps:
        app = str(campaign_app["app"])
        app_root = source_root / app
        control_1 = _scan(
            app=app,
            app_root=app_root,
            max_edges_per_file=CONTROL_MAX_EDGES_PER_FILE,
            max_findings_per_rule_per_file=(
                CONTROL_MAX_FINDINGS_PER_RULE_PER_FILE
            ),
        )
        treatment_1 = _scan(
            app=app,
            app_root=app_root,
            max_edges_per_file=DEFAULT_JS_TS_EDGES_PER_FILE,
            max_findings_per_rule_per_file=(
                DEFAULT_JS_TS_FINDINGS_PER_RULE_PER_FILE
            ),
        )
        treatment_2 = _scan(
            app=app,
            app_root=app_root,
            max_edges_per_file=DEFAULT_JS_TS_EDGES_PER_FILE,
            max_findings_per_rule_per_file=(
                DEFAULT_JS_TS_FINDINGS_PER_RULE_PER_FILE
            ),
        )
        control_2 = _scan(
            app=app,
            app_root=app_root,
            max_edges_per_file=CONTROL_MAX_EDGES_PER_FILE,
            max_findings_per_rule_per_file=(
                CONTROL_MAX_FINDINGS_PER_RULE_PER_FILE
            ),
        )
        control_duration += (
            control_1["duration_seconds"] + control_2["duration_seconds"]
        )
        treatment_duration += (
            treatment_1["duration_seconds"] + treatment_2["duration_seconds"]
        )
        control_exact_repeat = (
            control_1["normalized_sha256"]
            == control_2["normalized_sha256"]
        )
        treatment_exact_repeat = (
            treatment_1["normalized_sha256"]
            == treatment_2["normalized_sha256"]
        )
        control_exact_repeat_count += int(control_exact_repeat)
        treatment_exact_repeat_count += int(treatment_exact_repeat)
        control_coverage = coverage_complete(
            control_1,
            control_2,
            historical_inventory[app],
            campaign_app,
        )
        treatment_coverage = coverage_complete(
            treatment_1,
            treatment_2,
            historical_inventory[app],
            campaign_app,
        )
        control_coverage_complete_count += int(control_coverage)
        treatment_coverage_complete_count += int(treatment_coverage)
        historical_limits = sum(
            row["rule_id"] == LIMIT_RULE
            for row in historical_by_app[app]
        )
        control_limits = sum(
            row["rule_id"] == LIMIT_RULE
            for row in control_1["findings"]
        )
        treatment_limits = sum(
            row["rule_id"] == LIMIT_RULE
            for row in treatment_1["findings"]
        )
        app_rows.append(
            {
                "app": app,
                "historical_analysis_limit_count": historical_limits,
                "control_analysis_limit_count": control_limits,
                "treatment_analysis_limit_count": treatment_limits,
                "control_coverage_complete": control_coverage,
                "treatment_coverage_complete": treatment_coverage,
                "control_exact_repeat": control_exact_repeat,
                "treatment_exact_repeat": treatment_exact_repeat,
                "control_duration_seconds": round(
                    control_1["duration_seconds"]
                    + control_2["duration_seconds"],
                    6,
                ),
                "treatment_duration_seconds": round(
                    treatment_1["duration_seconds"]
                    + treatment_2["duration_seconds"],
                    6,
                ),
                "control_run_1_sha256": control_1["normalized_sha256"],
                "control_run_2_sha256": control_2["normalized_sha256"],
                "treatment_run_1_sha256": treatment_1[
                    "normalized_sha256"
                ],
                "treatment_run_2_sha256": treatment_2[
                    "normalized_sha256"
                ],
                "raw_returned": False,
            }
        )
        for row in control_1["findings"]:
            all_control[row["semantic_key"]] = row
        for row in treatment_1["findings"]:
            all_treatment[row["semantic_key"]] = row

    source_after = {
        str(campaign_app["app"]): _verify_source_receipt(
            campaign_dir=campaign_dir,
            source_root=source_root,
            app=str(campaign_app["app"]),
            campaign_app=campaign_app,
        )
        for campaign_app in apps
    }
    source_unchanged = source_before == source_after
    control_keys = set(all_control)
    treatment_keys = set(all_treatment)
    removed = [
        all_control[key] for key in sorted(control_keys - treatment_keys)
    ]
    added = [
        all_treatment[key] for key in sorted(treatment_keys - control_keys)
    ]
    retained_evidence_updates = [
        {
            "app": all_control[key]["app"],
            "rule_id": all_control[key]["rule_id"],
            "relative_path": all_control[key]["relative_path"],
            "line": all_control[key]["line"],
            "control_evidence_sha256": all_control[key]["evidence_sha256"],
            "treatment_evidence_sha256": all_treatment[key][
                "evidence_sha256"
            ],
            "redacted_fingerprint": all_control[key][
                "redacted_fingerprint"
            ],
            "raw_returned": False,
        }
        for key in sorted(control_keys & treatment_keys)
        if all_control[key]["evidence_sha256"]
        != all_treatment[key]["evidence_sha256"]
    ]
    removed_non_limit = [row for row in removed if row["rule_id"] != LIMIT_RULE]
    removed_limit = [row for row in removed if row["rule_id"] == LIMIT_RULE]
    treatment_limits = [
        row for row in all_treatment.values() if row["rule_id"] == LIMIT_RULE
    ]
    control_limits = [
        row for row in all_control.values() if row["rule_id"] == LIMIT_RULE
    ]
    runtime_ratio = (
        treatment_duration / control_duration
        if control_duration > 0
        else None
    )
    hypothesis_passed = bool(
        source_unchanged
        and control_exact_repeat_count == len(apps)
        and treatment_exact_repeat_count == len(apps)
        and control_coverage_complete_count == len(apps)
        and treatment_coverage_complete_count == len(apps)
        and bool(control_limits)
        and not treatment_limits
        and not removed_non_limit
        and len(removed_limit) == len(control_limits)
        and all(
            row["rule_id"] in VOLATILE_AGGREGATE_RULES
            for row in retained_evidence_updates
        )
        and runtime_ratio is not None
        and runtime_ratio <= 1.25
    )
    diff = subprocess.check_output(["git", "diff", "--no-color"], cwd=ROOT)
    status = subprocess.check_output(
        ["git", "status", "--porcelain=v1", "-z"],
        cwd=ROOT,
    )
    return {
        "schema": "k_guard_js_ts_limit_capacity_projection.v2",
        "evidence_use": "development_hypothesis_projection",
        "hypothesis": (
            "A 32-edge and 32-finding-per-rule JS/TS file budget removes the "
            "observed truncation while preserving fail-closed hard bounds."
        ),
        "campaign_id": campaign.get("campaign_id"),
        "campaign_app_count": len(apps),
        "ab_execution_order": "control_1,treatment_1,treatment_2,control_2",
        "historical_recorded_analysis_limit_count": sum(
            row["rule_id"] == LIMIT_RULE
            for rows in historical_by_app.values()
            for row in rows
        ),
        "control_analysis_limit_count": len(control_limits),
        "treatment_analysis_limit_count": len(treatment_limits),
        "removed_analysis_limit_count": len(removed_limit),
        "removed_non_limit_finding_count": len(removed_non_limit),
        "removed_non_limit_findings": removed_non_limit,
        "retained_finding_evidence_change_count": len(
            retained_evidence_updates
        ),
        "retained_finding_evidence_changes": retained_evidence_updates,
        "added_finding_count": len(added),
        "added_finding_rule_counts": dict(
            sorted(Counter(row["rule_id"] for row in added).items())
        ),
        "added_findings": added,
        "control_finding_count": len(all_control),
        "treatment_finding_count": len(all_treatment),
        "control_exact_repeat_app_count": control_exact_repeat_count,
        "treatment_exact_repeat_app_count": treatment_exact_repeat_count,
        "control_coverage_complete_app_count": (
            control_coverage_complete_count
        ),
        "treatment_coverage_complete_app_count": (
            treatment_coverage_complete_count
        ),
        "source_unchanged": source_unchanged,
        "historical_recorded_duration_seconds": round(
            historical_duration,
            6,
        ),
        "control_duration_seconds": round(control_duration, 6),
        "treatment_duration_seconds": round(treatment_duration, 6),
        "treatment_to_control_runtime_ratio": (
            round(runtime_ratio, 6) if runtime_ratio is not None else None
        ),
        "performance_contract_max_ratio": 1.25,
        "control_max_edges_per_file": CONTROL_MAX_EDGES_PER_FILE,
        "control_max_findings_per_rule_per_file": (
            CONTROL_MAX_FINDINGS_PER_RULE_PER_FILE
        ),
        "default_max_edges_per_file": DEFAULT_JS_TS_EDGES_PER_FILE,
        "default_max_findings_per_rule_per_file": (
            DEFAULT_JS_TS_FINDINGS_PER_RULE_PER_FILE
        ),
        "app_rows": sorted(app_rows, key=lambda row: row["app"]),
        "source_materialization_set_sha256": _canonical_sha256(
            [source_before[app] for app in sorted(source_before)]
        ),
        "historical_report_receipt_set_sha256": _canonical_sha256(
            sorted(
                historical_receipts,
                key=lambda row: (row["app"], row["run"]),
            )
        ),
        "campaign_manifest_sha256": _sha256_file(campaign_path),
        "git_head": _git_object("rev-parse", "HEAD"),
        "git_head_tree": _git_object("rev-parse", "HEAD^{tree}"),
        "working_tree_diff_sha256": hashlib.sha256(diff).hexdigest(),
        "working_tree_status_sha256": hashlib.sha256(status).hexdigest(),
        "working_tree_package_sha256": package_tree_sha256(
            ROOT / "src" / "k_guard_mcp"
        ),
        "projector_sha256": _sha256_file(Path(__file__).resolve()),
        "hypothesis_passed": hypothesis_passed,
        "qualification_eligible": False,
        "release_gate_passed": False,
        "release_claim_allowed": False,
        "release_gate_blockers": [
            "This is an exposed development corpus, not a fresh unseen holdout.",
            "Newly enumerated findings still require actionability adjudication.",
            "The product-wide locked precision, recall, and reviewer thresholds remain unevaluated.",
        ],
        "raw_returned": False,
    }


def write_projection(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite projection: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    payload = build_projection(
        campaign_dir=arguments.campaign_dir.resolve(),
        source_root=arguments.source_root.resolve(),
    )
    write_projection(arguments.output.resolve(), payload)
    print(
        json.dumps(
            {
                "output": str(arguments.output.resolve()),
                "control_analysis_limit_count": payload[
                    "control_analysis_limit_count"
                ],
                "treatment_analysis_limit_count": payload[
                    "treatment_analysis_limit_count"
                ],
                "removed_non_limit_finding_count": payload[
                    "removed_non_limit_finding_count"
                ],
                "added_finding_count": payload["added_finding_count"],
                "control_exact_repeat_app_count": payload[
                    "control_exact_repeat_app_count"
                ],
                "treatment_exact_repeat_app_count": payload[
                    "treatment_exact_repeat_app_count"
                ],
                "hypothesis_passed": payload["hypothesis_passed"],
                "release_gate_passed": payload["release_gate_passed"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
