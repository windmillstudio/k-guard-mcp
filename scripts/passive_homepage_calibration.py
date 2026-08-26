from __future__ import annotations

import argparse
import csv
import hashlib
import json
import time
import urllib.parse
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from k_guard_mcp.dynamic import ALLOWED_HOSTS, SafeHttpProbe
from k_guard_mcp.hashing import EVIDENCE_HMAC_ENV, evidence_hash, evidence_hash_scheme, uses_public_evidence_key
from k_guard_mcp.redaction import sanitize_any


PASSIVE_BOUNDARY_RULE_IDS = {"DYN_REDIRECT_TO_DISALLOWED_HOST"}
PASSIVE_CANONICAL_REDIRECT_RULE_ID = "DYN_CANONICAL_REDIRECT_OBSERVED"
DEFAULT_MIN_MEASUREMENT_YIELD = 0.8
DEFAULT_MAX_HIGH_CRITICAL_RATE = 0.0
DEFAULT_MAX_STRONG_IDENTIFIER_RATE = 0.0
DEFAULT_WARN_BOUNDARY_RATE = 0.75
MANUAL_VERDICTS = {"true_positive", "false_positive", "benign", "inconclusive"}
NON_BLOCKING_MANUAL_VERDICTS = {"false_positive", "benign"}
NON_BLOCKING_REVIEW_REQUIRED_ANCHORS = ("redacted_fingerprint", "detector_subtype", "body_sha256")
COMMON_SECOND_LEVEL_TLDS = {"ac", "co", "go", "ne", "or", "re", "pe", "com", "net", "org", "gov", "edu"}
INFRA_EXACT_DOMAINS = {
    "aaplimg.com",
    "aiv-delivery.net",
    "akam.net",
    "akamai.net",
    "akadns.net",
    "akamaiedge.net",
    "akamaihd.net",
    "akamaitech.net",
    "akamaized.net",
    "alibabadns.com",
    "amazon.dev",
    "aws.dev",
    "awsglobalaccelerator.com",
    "awswaf.com",
    "apple-dns.net",
    "ax-msedge.net",
    "bytefcdn-oversea.com",
    "byteoversea.net",
    "capcutapi.com",
    "cdnbuild.net",
    "cdn77.org",
    "cdngslb.com",
    "cdninstagram.com",
    "cloudflare-dns.com",
    "cloudfront.net",
    "dns-parking.com",
    "dns.google",
    "dnspod.net",
    "domaincontrol.com",
    "douyincdn.com",
    "dual-s-msedge.net",
    "edgcdn.net",
    "edgekey.net",
    "edgecdn.ru",
    "edgesuite.net",
    "enacdn.net",
    "facebook.net",
    "fastly-edge.com",
    "fbcdn.net",
    "gcdn.co",
    "googleapis.com",
    "googlevideo.com",
    "gstatic.com",
    "gvt1.com",
    "gvt2.com",
    "gtld-servers.net",
    "ibyteimg.com",
    "ipv4only.arpa",
    "jomodns.com",
    "jsdelivr.net",
    "ksyuncdn.com",
    "live-video.net",
    "media-amazon.com",
    "microsoftonline.com",
    "msedge.net",
    "mzstatic.com",
    "name-services.com",
    "namebrightdns.com",
    "nflximg.com",
    "nflxso.net",
    "nominetdns.uk",
    "nr-data.net",
    "office.net",
    "online-metrix.net",
    "pv-cdn.net",
    "rbxcdn.com",
    "ripn.net",
    "rocket-cdn.com",
    "root-servers.net",
    "rzone.de",
    "shopifysvc.com",
    "sfx.ms",
    "spo-msedge.net",
    "spov-msedge.net",
    "static.microsoft",
    "steamserver.net",
    "tbcache.com",
    "tiktokcdn-eu.com",
    "tiktokcdn-us.com",
    "tiktokcdn.com",
    "tm-azurefd.net",
    "trafficmanager.net",
    "trbcdn.net",
    "ttvnw.net",
    "vedcdnlb.com",
    "vecdnlb.com",
    "windowsupdate.com",
    "worldnic.com",
    "wac-msedge.net",
    "yccdn.ru",
    "ytimg.com",
}
INFRA_SUFFIXES = (
    ".akamaiedge.net",
    ".akadns.net",
    ".cloudfront.net",
    ".edgekey.net",
    ".edgesuite.net",
    ".fbcdn.net",
    ".msedge.net",
    ".trafficmanager.net",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run passive root-page calibration against public homepages without path probing.")
    parser.add_argument("--targets", required=True, help="CSV with target_id,cohort,url columns.")
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-targets", type=int, help="Optional cap for sharded runs, for example 10000.")
    parser.add_argument("--delay-ms", type=int, default=250, help="Delay between homepage requests. Defaults to 250ms.")
    parser.add_argument("--checkpoint-jsonl", help="Append each target result as raw-free JSONL for resume and crash recovery.")
    parser.add_argument("--resume", action="store_true", help="Load completed target ids from checkpoint-jsonl and skip them.")
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--max-body-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--retries", type=int, default=1, help="Retry failed homepage GET requests this many times. Defaults to 1.")
    parser.add_argument("--review", help="Optional CSV with target_id,rule_id,verdict,reviewer,notes for high/critical candidate adjudication.")
    parser.add_argument("--require-operator-key", action="store_true", help=f"Fail unless {EVIDENCE_HMAC_ENV} is set for operator-keyed evidence fingerprints.")
    parser.add_argument("--disable-homepage-fallbacks", action="store_true", help="Do not try same-site www/http homepage fallbacks after DNS/TLS/timeout failures.")
    parser.add_argument("--include-infrastructure-domains", action="store_true", help="Probe probable infrastructure/non-homepage domains instead of recording them as not-homepage candidates.")
    parser.add_argument("--min-measurement-yield", type=float, default=DEFAULT_MIN_MEASUREMENT_YIELD)
    parser.add_argument("--max-high-critical-rate", type=float, default=DEFAULT_MAX_HIGH_CRITICAL_RATE)
    parser.add_argument("--max-strong-identifier-rate", type=float, default=DEFAULT_MAX_STRONG_IDENTIFIER_RATE)
    parser.add_argument("--warn-boundary-rate", type=float, default=DEFAULT_WARN_BOUNDARY_RATE)
    args = parser.parse_args(argv)
    if args.require_operator_key and uses_public_evidence_key():
        print(json.dumps({"error": f"{EVIDENCE_HMAC_ENV} is required when --require-operator-key is set"}, ensure_ascii=False))
        return 2

    report = run_passive_homepage_calibration(
        Path(args.targets),
        max_targets=args.max_targets,
        delay_ms=max(args.delay_ms, 0),
        checkpoint_jsonl=Path(args.checkpoint_jsonl) if args.checkpoint_jsonl else None,
        resume=args.resume,
        timeout=max(args.timeout, 1.0),
        max_body_bytes=max(args.max_body_bytes, 4096),
        retries=max(args.retries, 0),
        review_path=Path(args.review) if args.review else None,
        homepage_fallbacks=not args.disable_homepage_fallbacks,
        skip_infrastructure_domains=not args.include_infrastructure_domains,
        min_measurement_yield=_clamp_rate(args.min_measurement_yield),
        max_high_critical_rate=_clamp_rate(args.max_high_critical_rate),
        max_strong_identifier_rate=_clamp_rate(args.max_strong_identifier_rate),
        warn_boundary_rate=_clamp_rate(args.warn_boundary_rate),
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"written": str(output), "passed": report["passed"], "target_count": len(report["targets"])}, ensure_ascii=False))
    return 0 if report["passed"] else 2


def run_passive_homepage_calibration(
    targets_path: Path,
    max_targets: int | None = None,
    delay_ms: int = 250,
    checkpoint_jsonl: Path | None = None,
    resume: bool = False,
    timeout: float = 6.0,
    max_body_bytes: int = 1024 * 1024,
    retries: int = 1,
    review_path: Path | None = None,
    homepage_fallbacks: bool = True,
    skip_infrastructure_domains: bool = True,
    min_measurement_yield: float = DEFAULT_MIN_MEASUREMENT_YIELD,
    max_high_critical_rate: float = DEFAULT_MAX_HIGH_CRITICAL_RATE,
    max_strong_identifier_rate: float = DEFAULT_MAX_STRONG_IDENTIFIER_RATE,
    warn_boundary_rate: float = DEFAULT_WARN_BOUNDARY_RATE,
) -> dict[str, object]:
    source_rows = _read_targets(targets_path)
    manual_reviews = _read_manual_reviews(review_path)
    rows = source_rows[: max(max_targets, 0)] if max_targets is not None else source_rows
    row_ids = {row["target_id"] for row in rows}
    completed_all = _read_checkpoint(checkpoint_jsonl) if checkpoint_jsonl and resume else {}
    completed = {target_id: result for target_id, result in completed_all.items() if target_id in row_ids}
    pending = [row for row in rows if row["target_id"] not in completed]
    results = [completed[row["target_id"]] for row in rows if row["target_id"] in completed]
    checkpoint_handle = None
    try:
        if checkpoint_jsonl:
            checkpoint_jsonl.parent.mkdir(parents=True, exist_ok=True)
            checkpoint_handle = checkpoint_jsonl.open("a", encoding="utf-8")
        for index, row in enumerate(pending):
            result = _probe_homepage(
                row,
                timeout=timeout,
                max_body_bytes=max_body_bytes,
                retries=max(retries, 0),
                manual_reviews=manual_reviews,
                homepage_fallbacks=homepage_fallbacks,
                skip_infrastructure_domains=skip_infrastructure_domains,
            )
            results.append(result)
            if checkpoint_handle:
                checkpoint_handle.write(json.dumps(sanitize_any(result), ensure_ascii=False) + "\n")
                checkpoint_handle.flush()
            if delay_ms > 0 and index < len(pending) - 1:
                time.sleep(delay_ms / 1000)
    finally:
        if checkpoint_handle:
            checkpoint_handle.close()
    by_cohort: dict[str, dict[str, object]] = {}
    for cohort in sorted({row["cohort"] for row in rows}):
        cohort_rows = [row for row in results if row["cohort"] == cohort]
        by_cohort[cohort] = _aggregate_rows(cohort_rows)
    by_hygiene_tier = {tier: _aggregate_rows([row for row in results if row.get("hygiene_tier") == tier]) for tier in sorted({str(row.get("hygiene_tier", "unknown")) for row in results})}
    by_rank_bucket = {bucket: _aggregate_rows([row for row in results if row.get("rank_bucket") == bucket]) for bucket in sorted({str(row.get("rank_bucket", "unknown")) for row in results})}
    release_gate = _release_gate(
        by_cohort,
        min_measurement_yield=min_measurement_yield,
        max_high_critical_rate=max_high_critical_rate,
        max_strong_identifier_rate=max_strong_identifier_rate,
        warn_boundary_rate=warn_boundary_rate,
    )
    candidate_review_queue = _candidate_review_queue(results)
    passed = release_gate["status"] != "fail"
    return sanitize_any(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "method": "passive_homepage_get_only",
            "external_network_used": True,
            "active_security_paths_used": False,
            "paths": ["/"],
            "requests": "GET / for each homepage candidate; no OPTIONS, no /admin, no /api, no .env, no .git, no recursive crawl",
            "claim_boundary": _claim_boundary(),
            "source_manifest_count": len(source_rows),
            "target_manifest_count": len(rows),
            "completed_count": len(results),
            "pending_count": max(0, len(rows) - len(results)),
            "loaded_from_checkpoint": len(completed),
            "executed_this_run": len(pending),
            "max_targets": max_targets,
            "delay_ms": delay_ms,
            "timeout_seconds": timeout,
            "max_body_bytes": max_body_bytes,
            "retries": retries,
            "review_path": str(review_path) if review_path else "",
            "homepage_fallbacks": homepage_fallbacks,
            "skip_infrastructure_domains": skip_infrastructure_domains,
            "checkpoint_jsonl": str(checkpoint_jsonl) if checkpoint_jsonl else "",
            "passed": passed,
            "release_gate": release_gate,
            "candidate_review_queue": candidate_review_queue,
            "aggregate": {"by_cohort": by_cohort, "by_hygiene_tier": by_hygiene_tier, "by_rank_bucket": by_rank_bucket},
            "targets": results,
        }
    )


def _probe_homepage(
    row: dict[str, str],
    timeout: float = 6.0,
    max_body_bytes: int = 1024 * 1024,
    retries: int = 1,
    manual_reviews: dict[tuple[str, str], dict[str, object]] | None = None,
    homepage_fallbacks: bool = True,
    skip_infrastructure_domains: bool = True,
) -> dict[str, object]:
    parsed = urllib.parse.urlparse(row["url"])
    host = (parsed.hostname or "").strip("[]").lower()
    if not host:
        return _target_result(row, "error", "missing host", {}, [], attempts=0, candidate_count=0)
    domain_role = _domain_role(row.get("domain", "") or host)
    if skip_infrastructure_domains and domain_role == "probable_infrastructure":
        return _target_result(
            row,
            "skipped",
            "probable infrastructure or non-homepage domain",
            {},
            [],
            domain_role=domain_role,
            eligible_for_release_gate=False,
            attempts=0,
            candidate_count=0,
        )
    candidates = _homepage_candidate_urls(parsed, homepage_fallbacks=homepage_fallbacks)
    candidate_hosts = {urllib.parse.urlparse(candidate).hostname or "" for candidate in candidates}
    probe = SafeHttpProbe(allowed_hosts=set(ALLOWED_HOSTS) | {candidate.strip("[]").lower() for candidate in candidate_hosts if candidate}, timeout=timeout, max_body_bytes=max_body_bytes)
    response = None
    attempts = 0
    fallback_used = False
    for candidate_index, homepage in enumerate(candidates):
        response = probe._request(homepage, "GET", probe_path="/")  # noqa: SLF001 - script intentionally uses the GET-only primitive.
        attempts += 1
        while response.status is None and attempts <= retries + candidate_index + 1:
            attempts += 1
            response = probe._request(homepage, "GET", probe_path="/")  # noqa: SLF001 - retry remains GET / only.
        if response.status is not None:
            fallback_used = candidate_index > 0
            break
    if response is None:
        response = probe._request(candidates[0], "GET", probe_path="/")  # noqa: SLF001 - defensive fallback, should not happen.
        attempts += 1
    findings = probe._findings_for_response(response)  # noqa: SLF001 - avoids default multi-path/OPTIONS probing.
    actionable_findings = [finding for finding in findings if finding.rule_id not in PASSIVE_BOUNDARY_RULE_IDS]
    notable_findings = [finding for finding in actionable_findings if finding.severity in {"critical", "high"} or finding.rule_id == "DYN_RESPONSE_PII_LEAK"]
    response_fingerprint = _response_fingerprint(response)
    finding_evidence = _finding_evidence_items(row["target_id"], notable_findings, response, response_fingerprint, manual_reviews or {})
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in actionable_findings:
        summary[finding.severity] += 1
    rule_ids = sorted({finding.rule_id for finding in actionable_findings})
    redirect_scope = _redirect_scope(response, host)
    observed_rules = {finding.rule_id for finding in findings}
    if redirect_scope in {"same_host_redirect", "same_site_canonical_redirect", "relative_redirect"}:
        observed_rules.discard("DYN_REDIRECT_TO_DISALLOWED_HOST")
        observed_rules.add(PASSIVE_CANONICAL_REDIRECT_RULE_ID)
    observed_rule_ids = sorted(observed_rules)
    strong = any(
        finding.rule_id == "DYN_RESPONSE_PII_LEAK" and str(getattr(finding, "scope", "") or "") == "strong_identifier_tier_detected"
        for finding in actionable_findings
    )
    boundary_observed = redirect_scope == "cross_site_boundary_redirect" and any(finding.rule_id in PASSIVE_BOUNDARY_RULE_IDS for finding in findings)
    status = "measured" if response.status is not None else "error"
    error = response.error or ""
    return _target_result(
        row,
        status,
        error,
        summary,
        rule_ids,
        status_code=response.status,
        content_type=response.headers.get("content-type", ""),
        high_or_critical=summary["critical"] + summary["high"] > 0,
        strong_identifier_detected=strong,
        observed_rule_ids=observed_rule_ids,
        boundary_observed=boundary_observed,
        redirect_scope=redirect_scope,
        attempts=attempts,
        effective_url=response.url,
        fallback_used=fallback_used,
        candidate_count=len(candidates),
        domain_role=domain_role,
        eligible_for_release_gate=domain_role != "probable_infrastructure",
        response_fingerprint=response_fingerprint,
        finding_evidence=finding_evidence,
        manual_review=_target_manual_review(finding_evidence),
    )


def _target_result(
    row: dict[str, str],
    status: str,
    error: str,
    summary: dict[str, int],
    rule_ids: list[str],
    status_code: int | None = None,
    content_type: str = "",
    high_or_critical: bool = False,
    strong_identifier_detected: bool = False,
    observed_rule_ids: list[str] | None = None,
    boundary_observed: bool = False,
    redirect_scope: str = "none",
    attempts: int = 1,
    effective_url: str = "",
    fallback_used: bool = False,
    candidate_count: int = 1,
    domain_role: str | None = None,
    eligible_for_release_gate: bool = True,
    response_fingerprint: dict[str, object] | None = None,
    finding_evidence: list[dict[str, object]] | None = None,
    manual_review: dict[str, object] | None = None,
) -> dict[str, object]:
    role = domain_role or _domain_role(row.get("domain", "") or urllib.parse.urlparse(row.get("url", "")).hostname or "")
    effective = effective_url or row["url"]
    request_executed = attempts > 0 and status != "skipped" and error != "missing host"
    return {
        "target_id": row["target_id"],
        "cohort": row["cohort"],
        "url": row["url"],
        "effective_url": effective,
        "fallback_used": fallback_used,
        "candidate_count": candidate_count,
        "rank": row.get("rank", ""),
        "rank_bucket": _rank_bucket(row.get("rank", "")),
        "domain": row.get("domain", ""),
        "source_url": row.get("source_url", ""),
        "status": status,
        "http_status": status_code,
        "content_type": content_type,
        "error": error,
        "domain_role": role,
        "eligible_for_release_gate": eligible_for_release_gate,
        "summary": summary,
        "rule_ids": rule_ids,
        "observed_rule_ids": observed_rule_ids if observed_rule_ids is not None else rule_ids,
        "high_or_critical": high_or_critical,
        "strong_identifier_detected": strong_identifier_detected,
        "boundary_observed": boundary_observed,
        "redirect_scope": redirect_scope,
        "attempts": attempts,
        "request_audit": {
            "request_executed": request_executed,
            "method": "GET" if request_executed else "",
            "requested_path": "/" if request_executed else "",
            "effective_url": effective,
            "attempts": attempts,
            "fallback_used": fallback_used,
            "candidate_count": candidate_count,
            "redirect_followed": False,
        },
        "response_fingerprint": response_fingerprint or {},
        "finding_evidence": finding_evidence or [],
        "manual_review": manual_review or {"verdict": "not_required", "reviewed_rule_count": 0, "unreviewed_rule_count": 0},
        "hygiene_tier": _hygiene_tier(status, status_code, summary, rule_ids, observed_rule_ids if observed_rule_ids is not None else rule_ids, boundary_observed, role),
        "outcome": _outcome_bucket(status, status_code, error, boundary_observed, redirect_scope, role),
    }


def _claim_boundary() -> dict[str, object]:
    return {
        "passive_homepage_claim": "GET / only candidate-signal calibration for public homepage responses.",
        "allowed_claims": [
            "The runner completed bounded homepage requests and grouped raw-free candidate signals.",
            "High/critical candidate signals require manual adjudication before being called confirmed issues.",
            "Security header and redirect observations are hardening/comparability signals, not proof of compromise.",
        ],
        "not_claimed": [
            "confirmed vulnerability discovery",
            "confirmed secret validity",
            "confirmed personal-data breach",
            "deep path, API, admin, .env, .git, authenticated, recursive, or exploit coverage",
        ],
        "deep_or_authorized_validation_requires": "Use explicitly authorized dynamic/deep probe or field benchmark rows, then attach manual TP/FP/FN adjudication.",
    }


def _response_fingerprint(response: object) -> dict[str, object]:
    headers = getattr(response, "headers", {}) or {}
    body = str(getattr(response, "body_sample", "") or "")
    header_payload = json.dumps(dict(sorted((str(key), str(value)) for key, value in headers.items())), ensure_ascii=False, sort_keys=True)
    return {
        "body_sha256": hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest().upper(),
        "headers_sha256": hashlib.sha256(header_payload.encode("utf-8", errors="ignore")).hexdigest().upper(),
        "body_sample_chars": len(body),
        "body_truncated": bool(getattr(response, "body_truncated", False)),
        "inspection_cap_bytes": int(getattr(response, "inspection_cap_bytes", 0) or 0),
        "content_type": str(headers.get("content-type", "")),
        "status": getattr(response, "status", None),
    }


def _finding_evidence_items(
    target_id: str,
    findings: list[object],
    response: object,
    response_fingerprint: dict[str, object],
    manual_reviews: dict[tuple[str, str], dict[str, object]],
) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for finding in findings:
        rule_id = str(getattr(finding, "rule_id", ""))
        evidence = str(getattr(finding, "evidence", ""))
        redacted_evidence = str(sanitize_any(evidence))
        item = {
            "rule_id": rule_id,
            "severity": str(getattr(finding, "severity", "")),
            "confidence": str(getattr(finding, "confidence", "")),
            "title": str(getattr(finding, "title", "")),
            "detector_subtype": _detector_subtype(rule_id, str(getattr(finding, "scope", "") or "")),
            "location": _finding_location(rule_id),
            "redacted_evidence": redacted_evidence,
            "redacted_fingerprint": evidence_hash(f"{rule_id}|{redacted_evidence}", length=16),
            "evidence_hash_scheme": evidence_hash_scheme(),
            "method": str(getattr(response, "method", "")),
            "probe_path": str(getattr(response, "probe_path", "") or urllib.parse.urlparse(str(getattr(response, "url", ""))).path or "/"),
            "status": getattr(response, "status", None),
            "content_type": response_fingerprint.get("content_type", ""),
            "body_sha256": response_fingerprint.get("body_sha256", ""),
            "headers_sha256": response_fingerprint.get("headers_sha256", ""),
            "body_truncated": response_fingerprint.get("body_truncated", False),
            "inspection_cap_bytes": response_fingerprint.get("inspection_cap_bytes", 0),
        }
        item["manual_review"] = _manual_review_for(target_id, rule_id, item, manual_reviews)
        items.append(item)
    return items


def _detector_subtype(rule_id: str, scope: str) -> str:
    allowed_scopes = {
        "secret_indicator:SECRET_PRIVATE_KEY",
        "secret_indicator:SECRET_GITHUB_PAT",
        "secret_indicator:SECRET_AWS_ACCESS_KEY",
        "secret_indicator:SECRET_JWT",
        "secret_indicator:SECRET_DB_URL",
        "secret_indicator:SECRET_OPENAI_STYLE_KEY",
        "secret_indicator:SECRET_WEBHOOK_URL",
        "secret_indicator",
        "strong_identifier_tier_detected",
        "bulk_record_tier_detected",
        "linked_record_tier_detected",
        "contact_cluster_review_tier",
    }
    if scope in allowed_scopes:
        return scope
    if rule_id == "DYN_RESPONSE_SECRET_LEAK":
        return "secret_indicator"
    if rule_id == "DYN_RESPONSE_PII_LEAK":
        return "pii_response_tier"
    if rule_id == "DYN_SECURITY_HEADERS_MISSING":
        return "missing_security_headers"
    if rule_id == "DYN_REDIRECT_TO_DISALLOWED_HOST":
        return "cross_site_redirect_boundary"
    return rule_id.lower()


def _finding_location(rule_id: str) -> str:
    if rule_id == "DYN_SECURITY_HEADERS_MISSING":
        return "headers"
    if rule_id == "DYN_REDIRECT_TO_DISALLOWED_HOST":
        return "headers.location"
    return "body_sample"


def _target_manual_review(finding_evidence: list[dict[str, object]]) -> dict[str, object]:
    if not finding_evidence:
        return {"verdict": "not_required", "reviewed_rule_count": 0, "unreviewed_rule_count": 0}
    verdicts = [str((item.get("manual_review") or {}).get("verdict", "needs_review")) for item in finding_evidence]
    reviewed = [verdict for verdict in verdicts if verdict in MANUAL_VERDICTS]
    unreviewed = len(verdicts) - len(reviewed)
    if unreviewed:
        verdict = "needs_review"
    elif "true_positive" in reviewed:
        verdict = "true_positive"
    elif "inconclusive" in reviewed:
        verdict = "inconclusive"
    elif "false_positive" in reviewed:
        verdict = "false_positive"
    else:
        verdict = "benign"
    return {"verdict": verdict, "reviewed_rule_count": len(reviewed), "unreviewed_rule_count": unreviewed}


def _manual_review_for(
    target_id: str,
    rule_id: str,
    item: dict[str, object],
    manual_reviews: dict[tuple[str, str], dict[str, object]],
) -> dict[str, object]:
    review = manual_reviews.get((target_id, rule_id))
    if not review:
        return {"verdict": "needs_review", "reviewer": "", "notes": ""}

    bound_review = dict(review)
    mismatches = _review_anchor_mismatches(bound_review, item)
    if mismatches:
        return _blocked_manual_review(bound_review, "manual review evidence anchors do not match current evidence", mismatches)

    verdict = str(bound_review.get("verdict", "needs_review"))
    if verdict in NON_BLOCKING_MANUAL_VERDICTS:
        missing = [field for field in NON_BLOCKING_REVIEW_REQUIRED_ANCHORS if not str(bound_review.get(field, "")).strip()]
        if missing:
            return _blocked_manual_review(bound_review, "non-blocking manual verdict requires current evidence anchors", missing)

    bound_review["evidence_bound"] = all(str(bound_review.get(field, "")).strip() for field in NON_BLOCKING_REVIEW_REQUIRED_ANCHORS)
    return bound_review


def _review_anchor_mismatches(review: dict[str, object], item: dict[str, object]) -> list[str]:
    mismatches: list[str] = []
    for field in ("redacted_fingerprint", "detector_subtype", "body_sha256", "headers_sha256"):
        expected = str(review.get(field, "")).strip()
        if not expected:
            continue
        actual = str(item.get(field, "")).strip()
        if field.endswith("_sha256"):
            expected = expected.upper()
            actual = actual.upper()
        if expected != actual:
            mismatches.append(field)
    return mismatches


def _blocked_manual_review(review: dict[str, object], reason: str, fields: list[str]) -> dict[str, object]:
    return {
        "verdict": "needs_review",
        "reviewer": str(review.get("reviewer", "")),
        "notes": str(review.get("notes", "")),
        "recorded_verdict": str(review.get("verdict", "")),
        "stale_review": True,
        "stale_review_reason": reason,
        "stale_review_fields": fields,
    }


def _candidate_review_queue(rows: list[dict[str, object]]) -> dict[str, object]:
    high = [_candidate_review_row(row) for row in rows if row.get("high_or_critical")]
    strong = [_candidate_review_row(row, strong_only=True) for row in rows if row.get("strong_identifier_detected")]
    needs_review_by_target: dict[str, dict[str, object]] = {}
    for row in rows:
        if not (row.get("high_or_critical") or row.get("strong_identifier_detected")):
            continue
        if not _manual_review_blocks(row):
            continue
        review_row = _candidate_review_row(row)
        needs_review_by_target[str(review_row.get("target_id", ""))] = review_row
    unresolved_high = [row for row in rows if row.get("high_or_critical") and _manual_review_blocks(row)]
    unresolved_strong = [row for row in rows if row.get("strong_identifier_detected") and _manual_review_blocks(row)]
    return {
        "high_or_critical_count": len(high),
        "strong_identifier_count": len(strong),
        "unresolved_high_or_critical_count": len(unresolved_high),
        "unresolved_strong_identifier_count": len(unresolved_strong),
        "needs_review_count": len(needs_review_by_target),
        "high_or_critical_targets": high,
        "strong_identifier_targets": strong,
        "needs_review_targets": list(needs_review_by_target.values()),
    }


def _candidate_review_row(row: dict[str, object], *, strong_only: bool = False) -> dict[str, object]:
    evidence = row.get("finding_evidence", [])
    detector_subtypes: list[str] = []
    evidence_summary: list[dict[str, object]] = []
    if isinstance(evidence, list):
        selected = [item for item in evidence if isinstance(item, dict)]
        if strong_only:
            selected = [item for item in selected if item.get("detector_subtype") == "strong_identifier_tier_detected"]
        detector_subtypes = sorted({str(item.get("detector_subtype", "")) for item in selected if item.get("detector_subtype")})
        evidence_summary = [_candidate_evidence_summary(item) for item in selected]
    return {
        "target_id": row.get("target_id", ""),
        "cohort": row.get("cohort", ""),
        "rank": row.get("rank", ""),
        "domain": row.get("domain", ""),
        "rule_ids": sorted({str(item.get("rule_id", "")) for item in evidence_summary if item.get("rule_id")}) if strong_only else row.get("rule_ids", []),
        "detector_subtypes": detector_subtypes,
        "finding_evidence": evidence_summary,
        "manual_review": row.get("manual_review", {}),
    }


def _candidate_evidence_summary(item: dict[str, object]) -> dict[str, object]:
    keys = (
        "rule_id",
        "severity",
        "confidence",
        "detector_subtype",
        "location",
        "redacted_fingerprint",
        "evidence_hash_scheme",
        "method",
        "probe_path",
        "status",
        "content_type",
        "body_sha256",
        "headers_sha256",
        "body_truncated",
        "inspection_cap_bytes",
        "manual_review",
    )
    return {key: item.get(key, "") for key in keys}


def _read_manual_reviews(path: Path | None) -> dict[tuple[str, str], dict[str, object]]:
    if not path or not path.exists():
        return {}
    reviews: dict[tuple[str, str], dict[str, object]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            target_id = str(row.get("target_id", "")).strip()
            rule_id = str(row.get("rule_id", "")).strip()
            verdict = str(row.get("verdict", "")).strip()
            if not target_id or not rule_id:
                continue
            normalized_verdict = verdict if verdict in MANUAL_VERDICTS else "inconclusive"
            reviews[(target_id, rule_id)] = {
                "verdict": normalized_verdict,
                "reviewer": str(row.get("reviewer", "")).strip(),
                "notes": str(row.get("notes", "")).strip(),
                "redacted_fingerprint": str(row.get("redacted_fingerprint", "")).strip(),
                "detector_subtype": str(row.get("detector_subtype", "")).strip(),
                "body_sha256": str(row.get("body_sha256", "")).strip().upper(),
                "headers_sha256": str(row.get("headers_sha256", "")).strip().upper(),
            }
    return reviews


def _read_targets(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for index, row in enumerate(csv.DictReader(handle), start=2):
            target_id = str(row.get("target_id") or f"target-{index}").strip()
            cohort = str(row.get("cohort") or "unknown").strip()
            url = str(row.get("url") or "").strip()
            if not url:
                continue
            parsed = urllib.parse.urlparse(url if "://" in url else "https://" + url)
            if parsed.scheme not in {"http", "https"}:
                raise ValueError(f"Unsupported URL scheme on row {index}: {url}")
            normalized = {"target_id": target_id, "cohort": cohort, "url": urllib.parse.urlunparse(parsed)}
            for optional in ("rank", "domain", "source_url"):
                value = str(row.get(optional) or "").strip()
                if value:
                    normalized[optional] = value
            rows.append(normalized)
    return rows


def _read_checkpoint(path: Path | None) -> dict[str, dict[str, object]]:
    if not path or not path.exists():
        return {}
    completed: dict[str, dict[str, object]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        target_id = str(row.get("target_id", "")).strip()
        if target_id:
            completed[target_id] = row
    return completed


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _clamp_rate(value: float) -> float:
    return max(0.0, min(1.0, value))


def _aggregate_rows(rows: list[dict[str, object]]) -> dict[str, object]:
    eligible = [row for row in rows if row.get("eligible_for_release_gate", True)]
    measured = [row for row in rows if row["status"] == "measured"]
    eligible_measured = [row for row in eligible if row["status"] == "measured"]
    high = [row for row in measured if row["high_or_critical"]]
    strong = [row for row in measured if row["strong_identifier_detected"]]
    unresolved_high = [row for row in high if _manual_review_blocks(row)]
    unresolved_strong = [row for row in strong if _manual_review_blocks(row)]
    boundary = [row for row in measured if row.get("boundary_observed")]
    rules: Counter[str] = Counter()
    observed_rules: Counter[str] = Counter()
    outcomes: Counter[str] = Counter()
    hygiene_tiers: Counter[str] = Counter()
    for row in rows:
        outcomes.update([str(row.get("outcome", "unknown"))])
        hygiene_tiers.update([str(row.get("hygiene_tier", "unknown"))])
    for row in measured:
        rules.update(row["rule_ids"])
        observed_rules.update(row.get("observed_rule_ids", []))
    unmeasured_count = len(rows) - len(measured)
    eligible_unmeasured_count = len(eligible) - len(eligible_measured)
    return {
        "target_count": len(rows),
        "measured_count": len(measured),
        "measured_rate": _rate(len(measured), len(rows)),
        "unmeasured_count": unmeasured_count,
        "unmeasured_rate": _rate(unmeasured_count, len(rows)),
        "eligible_target_count": len(eligible),
        "eligible_measured_count": len(eligible_measured),
        "eligible_measured_rate": _rate(len(eligible_measured), len(eligible)),
        "not_homepage_candidate_count": len(rows) - len(eligible),
        "eligible_unmeasured_count": eligible_unmeasured_count,
        "eligible_unmeasured_rate": _rate(eligible_unmeasured_count, len(eligible)),
        "high_critical_observed_target_count": len(high),
        "high_critical_observed_target_rate": _rate(len(high), len(measured)),
        "strong_identifier_observed_target_count": len(strong),
        "strong_identifier_observed_target_rate": _rate(len(strong), len(measured)),
        "high_critical_target_count": len(unresolved_high),
        "high_critical_target_rate": _rate(len(unresolved_high), len(measured)),
        "strong_identifier_target_count": len(unresolved_strong),
        "strong_identifier_target_rate": _rate(len(unresolved_strong), len(measured)),
        "boundary_target_count": len(boundary),
        "boundary_target_rate": _rate(len(boundary), len(measured)),
        "outcome_counts": [{"outcome": outcome, "count": count} for outcome, count in outcomes.most_common(10)],
        "hygiene_tier_counts": [{"hygiene_tier": tier, "count": count} for tier, count in hygiene_tiers.most_common(10)],
        "top_rules": [{"rule_id": rule, "count": count} for rule, count in rules.most_common(10)],
        "top_observed_rules": [{"rule_id": rule, "count": count} for rule, count in observed_rules.most_common(10)],
    }


def _manual_review_blocks(row: dict[str, object]) -> bool:
    verdict = str((row.get("manual_review") or {}).get("verdict", "needs_review"))
    return verdict not in {"false_positive", "benign"}


def _release_gate(
    by_cohort: dict[str, dict[str, object]],
    min_measurement_yield: float,
    max_high_critical_rate: float,
    max_strong_identifier_rate: float,
    warn_boundary_rate: float,
) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    thresholds = {
        "min_measurement_yield": min_measurement_yield,
        "max_high_critical_rate": max_high_critical_rate,
        "max_strong_identifier_rate": max_strong_identifier_rate,
        "warn_boundary_rate": warn_boundary_rate,
    }
    for cohort, aggregate in sorted(by_cohort.items()):
        if int(aggregate.get("target_count", 0)) == 0:
            continue
        measured_rate = float(aggregate.get("measured_rate", 0.0))
        eligible_measured_rate = float(aggregate.get("eligible_measured_rate", measured_rate))
        high_rate = float(aggregate.get("high_critical_target_rate", 0.0))
        strong_rate = float(aggregate.get("strong_identifier_target_rate", 0.0))
        boundary_rate = float(aggregate.get("boundary_target_rate", 0.0))
        if eligible_measured_rate < min_measurement_yield:
            checks.append(_gate_check(cohort, "eligible_measurement_yield", "fail", eligible_measured_rate, min_measurement_yield, "Measured homepage-candidate share is too low for a reliable calibration decision."))
        else:
            checks.append(_gate_check(cohort, "eligible_measurement_yield", "pass", eligible_measured_rate, min_measurement_yield, "Enough homepage candidates produced an HTTP response to compare noise."))
        if high_rate > max_high_critical_rate:
            checks.append(_gate_check(cohort, "actionable_high_critical_rate", "fail", high_rate, max_high_critical_rate, "Actionable high/critical findings require manual review before this calibration can pass."))
        else:
            checks.append(_gate_check(cohort, "actionable_high_critical_rate", "pass", high_rate, max_high_critical_rate, "No actionable high/critical excess over the release threshold."))
        if strong_rate > max_strong_identifier_rate:
            checks.append(_gate_check(cohort, "strong_identifier_rate", "fail", strong_rate, max_strong_identifier_rate, "Strong personal identifier findings require manual review or detector tuning."))
        else:
            checks.append(_gate_check(cohort, "strong_identifier_rate", "pass", strong_rate, max_strong_identifier_rate, "Strong personal identifier rate is within the calibration threshold."))
        if boundary_rate > warn_boundary_rate:
            checks.append(_gate_check(cohort, "boundary_rate", "warn", boundary_rate, warn_boundary_rate, "Many sites redirected outside the starting host; this is not treated as a vulnerability but weakens homepage comparability."))
    status = "fail" if any(check["status"] == "fail" for check in checks) else "warn" if any(check["status"] == "warn" for check in checks) else "pass"
    return {"status": status, "thresholds": thresholds, "checks": checks}


def _gate_check(cohort: str, metric: str, status: str, value: float, threshold: float, message: str) -> dict[str, object]:
    return {
        "cohort": cohort,
        "metric": metric,
        "status": status,
        "value": value,
        "threshold": threshold,
        "message": message,
    }


def _rank_bucket(raw_rank: object) -> str:
    try:
        rank = int(str(raw_rank).strip())
    except Exception:
        return "unknown"
    if rank <= 1000:
        return "top_1k"
    if rank <= 10000:
        return "top_10k"
    if rank <= 100000:
        return "top_100k"
    if rank <= 500000:
        return "mid_500k"
    return "long_tail"


def _hygiene_tier(
    status: str,
    status_code: int | None,
    summary: dict[str, int],
    rule_ids: list[str],
    observed_rule_ids: list[str],
    boundary_observed: bool,
    domain_role: str = "homepage_candidate",
) -> str:
    if domain_role == "probable_infrastructure":
        return "not_homepage_candidate"
    if status != "measured":
        return "unmeasured"
    if "DYN_DEBUG_ERROR_LEAK" in rule_ids or summary.get("critical", 0) + summary.get("high", 0) > 0:
        return "messy_or_risky_signal"
    if "DYN_DIRECTORY_LISTING" in rule_ids:
        return "messy_directory_listing"
    if status_code is not None and status_code >= 500:
        return "messy_server_error"
    if status_code is not None and status_code >= 400:
        return "blocked_or_missing_page"
    if "DYN_SECURITY_HEADERS_MISSING" in rule_ids:
        return "hardening_gap"
    if PASSIVE_CANONICAL_REDIRECT_RULE_ID in observed_rule_ids:
        return "canonical_redirect"
    if boundary_observed or "DYN_REDIRECT_TO_DISALLOWED_HOST" in observed_rule_ids:
        return "boundary_redirect"
    if status_code is not None and 200 <= status_code < 300 and not rule_ids:
        return "well_managed_quiet"
    return "measured_other"


def _outcome_bucket(status: str, status_code: int | None, error: str, boundary_observed: bool, redirect_scope: str = "none", domain_role: str = "homepage_candidate") -> str:
    if domain_role == "probable_infrastructure":
        return "skipped_probable_infrastructure"
    if status == "skipped":
        return "skipped"
    if status != "measured":
        lower = (error or "").lower()
        if "timed out" in lower or "timeout" in lower:
            return "error_timeout"
        if "certificate" in lower or "ssl" in lower or "tls" in lower:
            return "error_tls"
        if "name or service not known" in lower or "getaddrinfo" in lower or "nodename" in lower:
            return "error_dns"
        if "refused" in lower or "reset" in lower or "connection" in lower:
            return "error_connection"
        return "error_other"
    if boundary_observed:
        return "http_3xx_boundary_redirect"
    if redirect_scope in {"same_host_redirect", "same_site_canonical_redirect", "relative_redirect"}:
        return "http_3xx_canonical_redirect"
    if status_code is None:
        return "error_unknown"
    if 200 <= status_code < 300:
        return "http_2xx"
    if 300 <= status_code < 400:
        return "http_3xx_allowed_redirect"
    if 400 <= status_code < 500:
        return "http_4xx"
    if status_code >= 500:
        return "http_5xx"
    return "http_other"


def _redirect_scope(response: object, origin_host: str) -> str:
    status = getattr(response, "status", None)
    if status not in {301, 302, 303, 307, 308}:
        return "none"
    headers = getattr(response, "headers", {}) or {}
    location = str(headers.get("location", "")).strip()
    if not location:
        return "relative_redirect"
    target = urllib.parse.urljoin(str(getattr(response, "url", "")), location)
    target_host = (urllib.parse.urlparse(target).hostname or "").strip("[]").lower()
    origin = (origin_host or "").strip("[]").lower()
    if not target_host:
        return "relative_redirect"
    if target_host == origin:
        return "same_host_redirect"
    if _registrable_domain_approx(target_host) and _registrable_domain_approx(target_host) == _registrable_domain_approx(origin):
        return "same_site_canonical_redirect"
    return "cross_site_boundary_redirect"


def _homepage_candidate_urls(parsed: urllib.parse.ParseResult, homepage_fallbacks: bool = True) -> list[str]:
    base = urllib.parse.urlunparse(parsed._replace(path="/", params="", query="", fragment=""))
    if not homepage_fallbacks:
        return [base]
    host = (parsed.hostname or "").strip("[]").lower()
    if not host or _is_ip_like(host):
        return [base]
    hosts = [host]
    if host.startswith("www."):
        hosts.append(host[4:])
    else:
        hosts.append("www." + host)
    schemes = [parsed.scheme or "https"]
    if "https" not in schemes:
        schemes.append("https")
    if "http" not in schemes:
        schemes.append("http")
    candidates: list[str] = []
    for candidate_host in hosts:
        for scheme in schemes:
            candidate = urllib.parse.urlunparse((scheme, candidate_host, "/", "", "", ""))
            if candidate not in candidates:
                candidates.append(candidate)
    return candidates


def _is_ip_like(host: str) -> bool:
    return all(part.isdigit() for part in host.split(".") if part) or ":" in host


def _registrable_domain_approx(host: str) -> str:
    labels = [label for label in host.strip(".").lower().split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels) >= 3 and labels[-2] in COMMON_SECOND_LEVEL_TLDS and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _domain_role(domain: str) -> str:
    value = (domain or "").strip(".").lower()
    if not value:
        return "homepage_candidate"
    if value.endswith(".arpa"):
        return "probable_infrastructure"
    labels = value.split(".")
    if value in INFRA_EXACT_DOMAINS or any(value.endswith(suffix) for suffix in INFRA_SUFFIXES):
        return "probable_infrastructure"
    if len(labels) > 2 and labels[0] in {"ns", "dns", "cdn", "static", "img", "assets", "edge"}:
        return "probable_infrastructure"
    return "homepage_candidate"


if __name__ == "__main__":
    raise SystemExit(main())
