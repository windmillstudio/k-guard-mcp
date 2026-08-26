from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any

from k_guard_mcp.dashboard import scan_url
from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.redaction import sanitize_any


COHORTS = ("general", "vibecoded_suspected", "authorized_owned_partner")
REQUIRED_COUNTS = {"general": 20, "vibecoded_suspected": 20, "authorized_owned_partner": 10}
REVIEW_VERDICTS = {"true_positive", "false_positive", "needs_review", "unknown", ""}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def write_benchmark_template(path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, str]] = []
    for cohort, count in REQUIRED_COUNTS.items():
        prefix = {"general": "general", "vibecoded_suspected": "vibe", "authorized_owned_partner": "auth"}[cohort]
        for index in range(1, count + 1):
            rows.append(
                {
                    "target_id": f"{prefix}-{index:02d}",
                    "cohort": cohort,
                    "url": "",
                    "mode": "report",
                    "authorized": "false",
                    "authorization_note": "",
                    "deep_active": "false",
                    "report_path": "",
                    "manual_verdict": "needs_review",
                    "notes": "",
                }
            )
    _write_csv(output, rows)


def run_field_benchmark(manifest_path: str | Path, review_path: str | Path | None = None, run_probes: bool = False) -> dict[str, Any]:
    manifest = Path(manifest_path)
    rows = _read_manifest(manifest)
    reviews = _read_reviews(Path(review_path), manifest.parent) if review_path else {}
    results = []
    for row in rows:
        results.append(_evaluate_target(row, manifest.parent, reviews, run_probes))
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "manifest": str(manifest),
        "run_probes": run_probes,
        "required_counts": REQUIRED_COUNTS,
        "actual_counts": dict(Counter(row["cohort"] for row in rows)),
        "missing_counts": _missing_counts(rows),
        "rows": results,
        "aggregate": _aggregate(results),
        "safety": {
            "raw_free": True,
            "probe_default": "disabled unless --run-probes and per-target authorization are present",
            "external_probe_boundary": "fixed-path read-only GET/OPTIONS, same-origin, no redirect follow, no login/password guessing/mutation/fuzzing/exploit chain",
        },
    }
    return sanitize_any(report)


def benchmark_to_markdown(report: dict[str, Any]) -> str:
    aggregate = report.get("aggregate", {})
    by_cohort = aggregate.get("by_cohort", {}) if isinstance(aggregate, dict) else {}
    lines = [
        "# K-Guard Field Benchmark",
        "",
        f"- Generated: `{report.get('generated_at', '')}`",
        f"- Manifest: `{report.get('manifest', '')}`",
        f"- Run probes: `{report.get('run_probes', False)}`",
        "",
        "## Cohort Summary",
        "",
        "| Cohort | Targets | Runnable/Loaded | High/Critical Target Rate | Strong Identifier Rate | Manual FP Rate | Top Rules |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for cohort in COHORTS:
        item = by_cohort.get(cohort, {}) if isinstance(by_cohort, dict) else {}
        lines.append(
            "| "
            + " | ".join(
                [
                    cohort,
                    str(item.get("target_count", 0)),
                    str(item.get("measured_count", 0)),
                    _pct(item.get("high_critical_target_rate", 0)),
                    _pct(item.get("strong_identifier_target_rate", 0)),
                    _pct(item.get("manual_false_positive_rate", 0)),
                    ", ".join(rule["rule_id"] for rule in item.get("top_rules", [])[:5]) if isinstance(item.get("top_rules"), list) else "",
                ]
            )
            + " |"
        )
    lines.extend(["", "## Target Rows", "", "| Target | Cohort | Status | Critical | High | Strong ID | Manual | Notes |", "|---|---|---|---:|---:|---|---|---|"])
    for row in report.get("rows", []):
        lines.append(
            "| "
            + " | ".join(
                [
                    str(row.get("target_id", "")),
                    str(row.get("cohort", "")),
                    str(row.get("status", "")),
                    str(row.get("summary", {}).get("critical", 0) if isinstance(row.get("summary"), dict) else 0),
                    str(row.get("summary", {}).get("high", 0) if isinstance(row.get("summary"), dict) else 0),
                    "yes" if row.get("strong_identifier_detected") else "no",
                    _manual_summary(row),
                    _notes_summary(row),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def benchmark_to_html(report: dict[str, Any]) -> str:
    aggregate = report.get("aggregate", {})
    by_cohort = aggregate.get("by_cohort", {}) if isinstance(aggregate, dict) else {}
    cohort_rows = []
    for cohort in COHORTS:
        item = by_cohort.get(cohort, {}) if isinstance(by_cohort, dict) else {}
        cohort_rows.append(
            "<tr>"
            f"<td>{escape(cohort)}</td>"
            f"<td>{escape(str(item.get('target_count', 0)))}</td>"
            f"<td>{escape(str(item.get('measured_count', 0)))}</td>"
            f"<td>{escape(_pct(item.get('high_critical_target_rate', 0)))}</td>"
            f"<td>{escape(_pct(item.get('strong_identifier_target_rate', 0)))}</td>"
            f"<td>{escape(_pct(item.get('manual_false_positive_rate', 0)))}</td>"
            f"<td>{escape(', '.join(rule['rule_id'] for rule in item.get('top_rules', [])[:5]) if isinstance(item.get('top_rules'), list) else '')}</td>"
            "</tr>"
        )
    target_rows = []
    for row in report.get("rows", []):
        summary = row.get("summary", {}) if isinstance(row.get("summary"), dict) else {}
        cls = "hot" if row.get("high_or_critical") else "quiet"
        target_rows.append(
            f'<tr class="{cls}">'
            f"<td>{escape(str(row.get('target_id', '')))}</td>"
            f"<td>{escape(str(row.get('cohort', '')))}</td>"
            f"<td>{escape(str(row.get('status', '')))}</td>"
            f"<td>{escape(str(summary.get('critical', 0)))}</td>"
            f"<td>{escape(str(summary.get('high', 0)))}</td>"
            f"<td>{'yes' if row.get('strong_identifier_detected') else 'no'}</td>"
            f"<td>{escape(_manual_summary(row))}</td>"
            f"<td>{escape(_notes_summary(row))}</td>"
            "</tr>"
        )
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="ko">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            "<title>K-Guard Field Benchmark</title>",
            "<style>body{font-family:Inter,system-ui,sans-serif;margin:24px;background:#f6f8fb;color:#172033}main{max-width:1180px;margin:auto}section{background:white;border:1px solid #d7dde8;border-radius:8px;padding:16px;margin:14px 0}table{width:100%;border-collapse:collapse;background:white}th,td{border:1px solid #d7dde8;padding:8px;text-align:left;font-size:13px}th{background:#eef2f6}.hot td:first-child{border-left:4px solid #b42318}.quiet td:first-child{border-left:4px solid #067647}.note{color:#667085}</style>",
            "</head>",
            "<body><main>",
            "<h1>K-Guard Field Benchmark</h1>",
            f"<p class=\"note\">Generated {escape(str(report.get('generated_at', '')))} · raw-free aggregate report</p>",
            "<section><h2>Cohort Summary</h2><table><thead><tr><th>Cohort</th><th>Targets</th><th>Measured</th><th>High/Critical Rate</th><th>Strong Identifier Rate</th><th>Manual FP Rate</th><th>Top Rules</th></tr></thead><tbody>",
            "\n".join(cohort_rows),
            "</tbody></table></section>",
            "<section><h2>Target Rows</h2><table><thead><tr><th>Target</th><th>Cohort</th><th>Status</th><th>Critical</th><th>High</th><th>Strong ID</th><th>Manual</th><th>Notes</th></tr></thead><tbody>",
            "\n".join(target_rows),
            "</tbody></table></section>",
            "<section><h2>Boundary</h2><p class=\"note\">External probes require explicit authorization in the manifest and --run-probes. The benchmark report stores counts, rule ids, and verdicts, not raw personal data.</p></section>",
            "</main></body></html>",
        ]
    )


def write_benchmark_report(report: dict[str, Any], output: str | Path, markdown: str | Path | None = None, html: str | Path | None = None) -> None:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if markdown:
        Path(markdown).parent.mkdir(parents=True, exist_ok=True)
        Path(markdown).write_text(benchmark_to_markdown(report), encoding="utf-8")
    if html:
        Path(html).parent.mkdir(parents=True, exist_ok=True)
        Path(html).write_text(benchmark_to_html(report), encoding="utf-8")


def _evaluate_target(row: dict[str, str], base_dir: Path, reviews: dict[tuple[str, str], str], run_probes: bool) -> dict[str, Any]:
    target_id = row["target_id"]
    cohort = row["cohort"]
    mode = row.get("mode", "report") or "report"
    data: dict[str, Any] | None = None
    status = "skipped"
    error = ""
    if row.get("report_path"):
        try:
            data = json.loads(_resolve(base_dir, row["report_path"]).read_text(encoding="utf-8"))
            status = "loaded_report"
        except Exception as exc:
            status = "error"
            error = str(exc)
    elif mode == "probe":
        if not run_probes:
            status = "skipped_probe_requires_flag"
        elif not _truthy(row.get("authorized")):
            status = "blocked_authorization_required"
        else:
            try:
                data = scan_url(row.get("url", ""), authorized=True, deep_active=_truthy(row.get("deep_active")))
                status = "probed"
            except Exception as exc:
                status = "error"
                error = str(exc)
    else:
        status = "skipped_no_report"
    findings = _findings(data)
    summary = _summary(data, findings)
    manual = _manual_counts(target_id, findings, reviews, row.get("manual_verdict", "needs_review"))
    strong = _strong_identifier_findings(findings)
    high_rules = [str(finding.get("rule_id", "")) for finding in findings if str(finding.get("severity")) in {"critical", "high"}]
    return sanitize_any(
        {
            "target_id": target_id,
            "cohort": cohort,
            "url": row.get("url", ""),
            "mode": mode,
            "status": status,
            "error": error,
            "authorization": {
                "authorized": _truthy(row.get("authorized")),
                "note_present": bool(row.get("authorization_note", "").strip()),
                "note_ref": _raw_free_ref(row.get("authorization_note", ""), "authorization_note") if row.get("authorization_note", "").strip() else {},
                "deep_active": _truthy(row.get("deep_active")),
            },
            "summary": summary,
            "finding_count": len(findings),
            "high_or_critical": summary.get("critical", 0) + summary.get("high", 0) > 0,
            "critical_or_high_rule_ids": sorted(set(high_rules)),
            "strong_identifier_detected": bool(strong),
            "strong_identifier_rule_ids": sorted({str(finding.get("rule_id", "")) for finding in strong}),
            "manual_review": manual,
            "notes": _raw_free_note(row.get("notes", ""), "notes"),
        }
    )


def _aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_cohort = {}
    for cohort in COHORTS:
        cohort_rows = [row for row in rows if row.get("cohort") == cohort]
        measured = [row for row in cohort_rows if row.get("status") in {"loaded_report", "probed"}]
        high = [row for row in measured if row.get("high_or_critical")]
        strong = [row for row in measured if row.get("strong_identifier_detected")]
        rules: Counter[str] = Counter()
        manual_reviewed = 0
        manual_fp = 0
        for row in measured:
            rules.update(row.get("critical_or_high_rule_ids", []))
            manual = row.get("manual_review", {})
            if isinstance(manual, dict):
                manual_reviewed += int(manual.get("reviewed_count", 0))
                manual_fp += int(manual.get("false_positive_count", 0))
        by_cohort[cohort] = {
            "target_count": len(cohort_rows),
            "measured_count": len(measured),
            "skipped_or_blocked_count": len(cohort_rows) - len(measured),
            "high_critical_target_count": len(high),
            "high_critical_target_rate": _rate(len(high), len(measured)),
            "strong_identifier_target_count": len(strong),
            "strong_identifier_target_rate": _rate(len(strong), len(measured)),
            "manual_reviewed_count": manual_reviewed,
            "manual_false_positive_count": manual_fp,
            "manual_false_positive_rate": _rate(manual_fp, manual_reviewed),
            "top_rules": [{"rule_id": rule, "count": count} for rule, count in rules.most_common(10)],
        }
    return {"by_cohort": by_cohort}


def _read_manifest(path: Path) -> list[dict[str, str]]:
    rows = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for index, row in enumerate(csv.DictReader(handle), start=2):
            normalized = {str(key or "").strip(): str(value or "").strip() for key, value in row.items()}
            target_id = normalized.get("target_id") or f"row-{index}"
            cohort = normalized.get("cohort", "")
            if cohort not in COHORTS:
                raise ValueError(f"Invalid cohort {cohort!r} on manifest row {index}; expected {COHORTS}.")
            normalized["target_id"] = target_id
            normalized["cohort"] = cohort
            rows.append(normalized)
    return rows


def _read_reviews(path: Path, base_dir: Path) -> dict[tuple[str, str], str]:
    resolved = _resolve(base_dir, str(path))
    if not resolved.exists():
        return {}
    reviews: dict[tuple[str, str], str] = {}
    with resolved.open("r", encoding="utf-8-sig", newline="") as handle:
        for index, row in enumerate(csv.DictReader(handle), start=2):
            target_id = str(row.get("target_id", "")).strip()
            rule_id = str(row.get("rule_id", "")).strip()
            verdict = str(row.get("verdict", "")).strip() or "needs_review"
            if verdict not in REVIEW_VERDICTS:
                raise ValueError(f"Invalid manual review verdict {verdict!r} on row {index}.")
            if target_id and rule_id:
                reviews[(target_id, rule_id)] = verdict
    return reviews


def _manual_counts(target_id: str, findings: list[dict[str, Any]], reviews: dict[tuple[str, str], str], default_verdict: str | None) -> dict[str, int]:
    counts = {"true_positive_count": 0, "false_positive_count": 0, "needs_review_count": 0, "unknown_count": 0, "reviewed_count": 0}
    default = default_verdict if default_verdict in REVIEW_VERDICTS else "needs_review"
    for finding in findings:
        rule_id = str(finding.get("rule_id", ""))
        verdict = reviews.get((target_id, rule_id), reviews.get(("*", rule_id), default or "needs_review"))
        if verdict == "true_positive":
            counts["true_positive_count"] += 1
            counts["reviewed_count"] += 1
        elif verdict == "false_positive":
            counts["false_positive_count"] += 1
            counts["reviewed_count"] += 1
        elif verdict == "needs_review":
            counts["needs_review_count"] += 1
        else:
            counts["unknown_count"] += 1
    return counts


def _findings(data: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    findings = data.get("findings", [])
    return [finding for finding in findings if isinstance(finding, dict)] if isinstance(findings, list) else []


def _summary(data: dict[str, Any] | None, findings: list[dict[str, Any]]) -> dict[str, int]:
    if isinstance(data, dict) and isinstance(data.get("summary"), dict):
        summary = {severity: int(data["summary"].get(severity, 0) or 0) for severity in SEVERITY_ORDER}
    else:
        summary = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in findings:
            severity = str(finding.get("severity", "info"))
            if severity in summary:
                summary[severity] += 1
    return summary


def _strong_identifier_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for finding in findings:
        evidence = str(finding.get("evidence", ""))
        if finding.get("rule_id") == "DYN_RESPONSE_PII_LEAK" and "Strong identifier tier" in evidence:
            result.append(finding)
    return result


def _missing_counts(rows: list[dict[str, str]]) -> dict[str, int]:
    counts = Counter(row["cohort"] for row in rows)
    return {cohort: max(0, REQUIRED_COUNTS[cohort] - counts.get(cohort, 0)) for cohort in COHORTS}


def _resolve(base_dir: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base_dir / path


def _truthy(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _pct(value: object) -> str:
    try:
        return f"{float(value) * 100:.1f}%"
    except Exception:
        return "0.0%"


def _manual_summary(row: dict[str, Any]) -> str:
    manual = row.get("manual_review", {})
    if not isinstance(manual, dict):
        return "n/a"
    return f"TP {manual.get('true_positive_count', 0)} / FP {manual.get('false_positive_count', 0)} / review {manual.get('needs_review_count', 0)}"


def _notes_summary(row: dict[str, Any]) -> str:
    notes = row.get("notes", {}) if isinstance(row.get("notes"), dict) else {}
    return "present" if notes.get("present") else ""


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    fieldnames = ["target_id", "cohort", "url", "mode", "authorized", "authorization_note", "deep_active", "report_path", "manual_verdict", "notes"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _raw_free_note(value: str, label: str) -> dict[str, Any]:
    present = bool(str(value or "").strip())
    return {
        "present": present,
        "ref": _raw_free_ref(value, label) if present else {},
        "raw_returned": False,
    }


def _raw_free_ref(value: str, label: str) -> dict[str, Any]:
    return {
        "label": label,
        "hash": evidence_hash(str(value or "")),
        "hash_scheme": evidence_hash_scheme(),
        "raw_returned": False,
    }
