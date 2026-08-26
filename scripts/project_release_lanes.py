from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from k_guard_mcp.release_policy import (
    DIRECT_RELEASE_SCOPES,
    RELEASE_BLOCKING_POLICY,
    REPOSITORY_WIDE_RULE_PREFIXES,
    SUPPORTING_REVIEW_SCOPES,
    is_release_blocking_finding,
    release_lane,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _legacy_blocks(finding: dict[str, Any]) -> bool:
    scope = str(finding.get("artifact_scope") or "workspace_evidence")
    if scope in DIRECT_RELEASE_SCOPES or scope not in SUPPORTING_REVIEW_SCOPES:
        return True
    rule_id = str(finding.get("rule_id") or "")
    confidence = str(finding.get("confidence") or "low")
    return (
        scope != "third_party"
        and confidence == "high"
        and rule_id.startswith(REPOSITORY_WIDE_RULE_PREFIXES)
    )


def project_reports(reports_dir: Path) -> dict[str, Any]:
    paths = sorted(reports_dir.glob("*-run1.json"))
    if not paths:
        raise ValueError("no run1 reports found")

    lane_counts: Counter[str] = Counter()
    lane_rules: defaultdict[str, Counter[str]] = defaultdict(Counter)
    legacy_rules: Counter[str] = Counter()
    new_hold_rules: Counter[str] = Counter()
    lost_rules: Counter[str] = Counter()
    added_rules: Counter[str] = Counter()
    high_critical_total = 0

    for path in paths:
        report = json.loads(path.read_text(encoding="utf-8"))
        findings = report.get("findings", [])
        if not isinstance(findings, list):
            raise ValueError(f"findings must be a list: {path}")
        for finding in findings:
            if not isinstance(finding, dict) or finding.get("severity") not in {"critical", "high"}:
                continue
            high_critical_total += 1
            rule_id = str(finding.get("rule_id") or "")
            lane = release_lane(finding, "high")
            lane_counts[lane] += 1
            lane_rules[lane][rule_id] += 1

            legacy = _legacy_blocks(finding)
            current = is_release_blocking_finding(finding, "high")
            if legacy:
                legacy_rules[rule_id] += 1
            if current:
                new_hold_rules[rule_id] += 1
            if legacy and not current:
                lost_rules[rule_id] += 1
            if current and not legacy:
                added_rules[rule_id] += 1

    bindings = [
        {
            "report": path.name,
            "sha256": _sha256(path),
        }
        for path in paths
    ]
    return {
        "schema_version": "k_guard_release_lane_projection.v1",
        "evidence_role": "post_hoc_development_regression",
        "blocking_policy": RELEASE_BLOCKING_POLICY,
        "source_campaign": reports_dir.parent.name,
        "run_selection": "run1; run2 equality is established by the source campaign",
        "report_bindings": bindings,
        "population": {
            "report_count": len(paths),
            "high_critical_finding_count": high_critical_total,
            "lane_counts": dict(sorted(lane_counts.items())),
            "lane_rule_counts": {
                lane: dict(sorted(counts.items()))
                for lane, counts in sorted(lane_rules.items())
            },
        },
        "legacy_comparison": {
            "legacy_blocking_count": sum(legacy_rules.values()),
            "current_hold_count": sum(new_hold_rules.values()),
            "legacy_blockers_lost_count": sum(lost_rules.values()),
            "legacy_blockers_lost_rule_counts": dict(sorted(lost_rules.items())),
            "newly_held_count": sum(added_rules.values()),
            "newly_held_rule_counts": dict(sorted(added_rules.items())),
        },
        "checks": {
            "every_high_critical_finding_assigned_once": sum(lane_counts.values()) == high_critical_total,
            "no_legacy_blocker_dropped": not lost_rules,
        },
        "claim_boundary": {
            "proves_detection_precision": False,
            "qualifies_release_blocker_actionability": False,
            "may_be_reused_as_independent_holdout": False,
            "purpose": "Verify that lane calibration preserves or strengthens fail-closed handling on inspected development data.",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Project checked reports through the current release-lane policy.")
    parser.add_argument("--reports-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    payload = project_reports(args.reports_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
