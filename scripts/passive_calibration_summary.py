from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from k_guard_mcp.redaction import sanitize_any


STRICT_MIN_ELIGIBLE_MEASUREMENT_YIELD = 0.8


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize one or more raw-free passive calibration reports.")
    parser.add_argument("--reports", nargs="+", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--markdown")
    args = parser.parse_args(argv)

    summary = summarize_reports([Path(path) for path in args.reports])
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.markdown:
        markdown = Path(args.markdown)
        markdown.parent.mkdir(parents=True, exist_ok=True)
        markdown.write_text(to_markdown(summary), encoding="utf-8")
    print(json.dumps({"written": str(output), "decision": summary["decision"]["status"]}, ensure_ascii=False))
    return 0 if summary["decision"]["status"] == "pass" else 2


def summarize_reports(paths: list[Path]) -> dict[str, object]:
    reports = [_read_report(path) for path in paths]
    cohorts: dict[str, dict[str, object]] = {}
    report_summaries = []
    candidate_review_queue = _merge_candidate_review_queues(paths, reports)
    for path, report in zip(paths, reports, strict=False):
        gate = report.get("release_gate", {})
        queue = report.get("candidate_review_queue", {})
        if not isinstance(queue, dict):
            queue = {}
        report_summaries.append(
            {
                "path": str(path),
                "passed": bool(report.get("passed")),
                "release_gate_status": str(gate.get("status", "unknown")),
                "completed_count": int(report.get("completed_count", 0)),
                "target_manifest_count": int(report.get("target_manifest_count", 0)),
                "source_manifest_count": int(report.get("source_manifest_count", report.get("target_manifest_count", 0))),
                "max_targets": report.get("max_targets"),
                "candidate_review": {
                    "high_or_critical_count": int(queue.get("high_or_critical_count", 0)),
                    "strong_identifier_count": int(queue.get("strong_identifier_count", 0)),
                    "needs_review_count": int(queue.get("needs_review_count", 0)),
                },
            }
        )
        by_cohort = ((report.get("aggregate") or {}).get("by_cohort") or {})
        if isinstance(by_cohort, dict):
            for cohort, aggregate in by_cohort.items():
                if not isinstance(aggregate, dict):
                    continue
                cohorts.setdefault(str(cohort), _empty_cohort())
                _merge_cohort(cohorts[str(cohort)], aggregate)
    normalized = {cohort: _finalize_cohort(aggregate) for cohort, aggregate in sorted(cohorts.items())}
    decision = _decision(normalized, report_summaries)
    return sanitize_any(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "method": "passive_calibration_multi_report_summary",
            "decision": decision,
            "reports": report_summaries,
            "candidate_review_queue": candidate_review_queue,
            "cohorts": normalized,
        }
    )


def to_markdown(summary: dict[str, object]) -> str:
    decision = summary["decision"]
    lines = [
        "# Passive Calibration Summary",
        "",
        f"- decision: `{decision['status']}`",
        f"- reason: {decision['reason']}",
        "",
        "| cohort | targets | measured | high/critical | strong identifiers | boundary | top rules |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    cohorts = summary.get("cohorts", {})
    if isinstance(cohorts, dict):
        for cohort, aggregate in cohorts.items():
            top_rules = ", ".join(f"{row['rule_id']}={row['count']}" for row in aggregate.get("top_rules", [])[:3])
            lines.append(
                "| {cohort} | {targets} | {measured} ({measured_rate}) | {high} | {strong} | {boundary} | {rules} |".format(
                    cohort=cohort,
                    targets=aggregate["target_count"],
                    measured=f"{aggregate['eligible_measured_count']} / eligible {aggregate['eligible_target_count']}",
                    measured_rate=aggregate["eligible_measured_rate"],
                    high=aggregate["high_critical_target_rate"],
                    strong=aggregate["strong_identifier_target_rate"],
                    boundary=aggregate["boundary_target_rate"],
                    rules=top_rules or "none",
                )
            )
    concerns = decision.get("concerns", [])
    if concerns:
        lines.extend(["", "## Concerns", ""])
        for concern in concerns:
            lines.append(f"- `{concern['cohort']}` {concern['metric']}: {concern['message']}")
    queue = summary.get("candidate_review_queue", {})
    if isinstance(queue, dict) and int(queue.get("needs_review_count", 0)):
        lines.extend(["", "## Candidate Review Queue", ""])
        lines.append(f"- needs review: `{queue.get('needs_review_count', 0)}`")
        lines.append(f"- high/critical observed: `{queue.get('high_or_critical_count', 0)}`")
        lines.append(f"- strong identifier observed: `{queue.get('strong_identifier_count', 0)}`")
    observations = decision.get("observations", [])
    if observations:
        lines.extend(["", "## Non-Gating Observations", ""])
        for observation in observations:
            lines.append(f"- `{observation['cohort']}` {observation['metric']}: {observation['message']}")
    return "\n".join(lines) + "\n"


def _read_report(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _merge_candidate_review_queues(paths: list[Path], reports: list[dict[str, object]]) -> dict[str, object]:
    high: list[dict[str, object]] = []
    strong: list[dict[str, object]] = []
    needs: dict[str, dict[str, object]] = {}
    unresolved_high_count = 0
    unresolved_strong_count = 0
    for path, report in zip(paths, reports, strict=False):
        queue = report.get("candidate_review_queue", {})
        if not isinstance(queue, dict):
            continue
        high.extend(_tag_review_targets(path, queue.get("high_or_critical_targets", [])))
        strong.extend(_tag_review_targets(path, queue.get("strong_identifier_targets", [])))
        unresolved_high_count += int(queue.get("unresolved_high_or_critical_count", queue.get("needs_review_count", 0)))
        unresolved_strong_count += int(queue.get("unresolved_strong_identifier_count", 0))
        for target in _tag_review_targets(path, queue.get("needs_review_targets", [])):
            key = "|".join(
                [
                    str(target.get("report_path", "")),
                    str(target.get("target_id", "")),
                    str(target.get("domain", "")),
                    ",".join(str(rule_id) for rule_id in target.get("rule_ids", []) if rule_id),
                ]
            )
            needs[key] = target
    return {
        "high_or_critical_count": len(high),
        "strong_identifier_count": len(strong),
        "unresolved_high_or_critical_count": unresolved_high_count,
        "unresolved_strong_identifier_count": unresolved_strong_count,
        "needs_review_count": len(needs),
        "high_or_critical_targets": high,
        "strong_identifier_targets": strong,
        "needs_review_targets": list(needs.values()),
    }


def _tag_review_targets(path: Path, targets: object) -> list[dict[str, object]]:
    if not isinstance(targets, list):
        return []
    tagged: list[dict[str, object]] = []
    for target in targets:
        if not isinstance(target, dict):
            continue
        row = dict(target)
        row["report_path"] = str(path)
        tagged.append(row)
    return tagged


def _empty_cohort() -> dict[str, object]:
    return {
        "target_count": 0,
        "measured_count": 0,
        "eligible_target_count": 0,
        "eligible_measured_count": 0,
        "not_homepage_candidate_count": 0,
        "high_critical_target_count": 0,
        "strong_identifier_target_count": 0,
        "boundary_target_count": 0,
        "rules": Counter(),
        "observed_rules": Counter(),
        "outcomes": Counter(),
        "hygiene_tiers": Counter(),
    }


def _merge_cohort(target: dict[str, object], source: dict[str, object]) -> None:
    target["target_count"] += int(source.get("target_count", 0))
    target["measured_count"] += int(source.get("measured_count", 0))
    target["eligible_target_count"] += int(source.get("eligible_target_count", source.get("target_count", 0)))
    target["eligible_measured_count"] += int(source.get("eligible_measured_count", source.get("measured_count", 0)))
    target["not_homepage_candidate_count"] += int(source.get("not_homepage_candidate_count", 0))
    target["high_critical_target_count"] += int(source.get("high_critical_target_count", 0))
    target["strong_identifier_target_count"] += int(source.get("strong_identifier_target_count", 0))
    target["boundary_target_count"] += int(source.get("boundary_target_count", 0))
    _merge_named_counts(target["rules"], source.get("top_rules", []), "rule_id")
    _merge_named_counts(target["observed_rules"], source.get("top_observed_rules", []), "rule_id")
    _merge_named_counts(target["outcomes"], source.get("outcome_counts", []), "outcome")
    _merge_named_counts(target["hygiene_tiers"], source.get("hygiene_tier_counts", []), "hygiene_tier")


def _merge_named_counts(counter: Counter[str], rows: object, key: str) -> None:
    if not isinstance(rows, list):
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get(key, "")).strip()
        if name:
            counter[name] += int(row.get("count", 0))


def _finalize_cohort(aggregate: dict[str, object]) -> dict[str, object]:
    target_count = int(aggregate["target_count"])
    measured_count = int(aggregate["measured_count"])
    eligible_target_count = int(aggregate["eligible_target_count"])
    eligible_measured_count = int(aggregate["eligible_measured_count"])
    return {
        "target_count": target_count,
        "measured_count": measured_count,
        "measured_rate": _rate(measured_count, target_count),
        "unmeasured_count": max(0, target_count - measured_count),
        "unmeasured_rate": _rate(max(0, target_count - measured_count), target_count),
        "eligible_target_count": eligible_target_count,
        "eligible_measured_count": eligible_measured_count,
        "eligible_measured_rate": _rate(eligible_measured_count, eligible_target_count),
        "not_homepage_candidate_count": int(aggregate["not_homepage_candidate_count"]),
        "high_critical_target_count": int(aggregate["high_critical_target_count"]),
        "high_critical_target_rate": _rate(int(aggregate["high_critical_target_count"]), measured_count),
        "strong_identifier_target_count": int(aggregate["strong_identifier_target_count"]),
        "strong_identifier_target_rate": _rate(int(aggregate["strong_identifier_target_count"]), measured_count),
        "boundary_target_count": int(aggregate["boundary_target_count"]),
        "boundary_target_rate": _rate(int(aggregate["boundary_target_count"]), measured_count),
        "top_rules": _top_counter(aggregate["rules"]),
        "top_observed_rules": _top_counter(aggregate["observed_rules"]),
        "outcome_counts": _top_counter(aggregate["outcomes"], "outcome"),
        "hygiene_tier_counts": _top_counter(aggregate["hygiene_tiers"], "hygiene_tier"),
    }


def _decision(cohorts: dict[str, dict[str, object]], reports: list[dict[str, object]]) -> dict[str, object]:
    concerns = []
    observations = []
    if any(report["release_gate_status"] == "fail" for report in reports):
        concerns.append({"cohort": "report", "metric": "release_gate", "message": "At least one source report failed its release gate."})
    for report in reports:
        source_manifest_count = int(report.get("source_manifest_count", report.get("target_manifest_count", 0)))
        target_manifest_count = int(report.get("target_manifest_count", 0))
        completed_count = int(report.get("completed_count", 0))
        if source_manifest_count > target_manifest_count:
            observations.append(
                {
                    "cohort": "report",
                    "metric": "manifest_shard",
                    "message": f"{report['path']} evaluated a {target_manifest_count}-target shard from {source_manifest_count} manifest rows.",
                }
            )
        if target_manifest_count and completed_count < target_manifest_count:
            observations.append(
                {
                    "cohort": "report",
                    "metric": "partial_manifest_shard",
                    "message": f"{report['path']} completed {completed_count} of {target_manifest_count} manifest rows. Treat this as a shard result, not full-manifest validation.",
                }
            )
    for cohort, aggregate in cohorts.items():
        if aggregate["eligible_target_count"] == 0:
            concerns.append({"cohort": cohort, "metric": "eligible_population", "message": "No homepage-eligible targets remain after filtering."})
        elif aggregate["eligible_measured_rate"] < STRICT_MIN_ELIGIBLE_MEASUREMENT_YIELD:
            concerns.append(
                {
                    "cohort": cohort,
                    "metric": "eligible_measurement_yield",
                    "message": f"Eligible measured rate is below {STRICT_MIN_ELIGIBLE_MEASUREMENT_YIELD}.",
                }
            )
        if aggregate["high_critical_target_rate"] > 0:
            concerns.append({"cohort": cohort, "metric": "high_critical", "message": "Actionable high/critical findings are present."})
        if aggregate["strong_identifier_target_rate"] > 0:
            concerns.append({"cohort": cohort, "metric": "strong_identifier", "message": "Strong personal identifier findings are present."})
        if aggregate["boundary_target_rate"] > 0.75:
            concerns.append({"cohort": cohort, "metric": "boundary_rate", "message": "Boundary redirects exceed warning threshold."})
        if aggregate["not_homepage_candidate_count"] > 0:
            observations.append(
                {
                    "cohort": cohort,
                    "metric": "not_homepage_candidate",
                    "message": f"{aggregate['not_homepage_candidate_count']} probable infrastructure/non-homepage domains were excluded from the release denominator but retained in the report.",
                }
            )
        if aggregate["boundary_target_rate"] > 0:
            observations.append(
                {
                    "cohort": cohort,
                    "metric": "boundary_rate",
                    "message": f"Boundary redirects were observed at rate {aggregate['boundary_target_rate']}; this is tracked but does not fail unless above threshold.",
                }
            )
        rules = {row["rule_id"]: row["count"] for row in aggregate.get("top_rules", [])}
        if rules.get("DYN_SECURITY_HEADERS_MISSING", 0) > 0:
            observations.append(
                {
                    "cohort": cohort,
                    "metric": "security_headers_missing",
                    "message": f"{rules['DYN_SECURITY_HEADERS_MISSING']} measured homepages lacked one or more baseline security headers.",
                }
            )
        if rules.get("DYN_DIRECTORY_LISTING", 0) > 0:
            observations.append(
                {
                    "cohort": cohort,
                    "metric": "directory_listing",
                    "message": f"{rules['DYN_DIRECTORY_LISTING']} measured homepage responses looked like directory listings and need manual review.",
                }
            )
    status = "pass" if not concerns else "fail"
    reason = (
        "All strict passive calibration gates passed; non-gating observations still require product review."
        if status == "pass"
        else "One or more strict passive calibration gates failed."
    )
    return {"status": status, "reason": reason, "concerns": concerns, "observations": observations}


def _top_counter(counter: Counter[str], key: str = "rule_id") -> list[dict[str, object]]:
    return [{key: name, "count": count} for name, count in counter.most_common(10)]


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
