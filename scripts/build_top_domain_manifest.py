from __future__ import annotations

import argparse
import csv
import io
import json
import urllib.request
import zipfile
from pathlib import Path


DEFAULT_TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a passive homepage calibration manifest from a public top-domain CSV/ZIP source.")
    parser.add_argument("--source-url", default=DEFAULT_TRANCO_URL)
    parser.add_argument("--output", required=True)
    parser.add_argument("--limit", type=int, default=10000)
    parser.add_argument("--start-rank", type=int, default=1)
    parser.add_argument("--cohort", default="large_general")
    parser.add_argument("--target-prefix", default="tranco")
    parser.add_argument("--scheme", choices=("https", "http"), default="https")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args(argv)

    rows = build_manifest_rows(
        source_url=args.source_url,
        limit=max(args.limit, 0),
        start_rank=max(args.start_rank, 1),
        cohort=args.cohort,
        target_prefix=args.target_prefix,
        scheme=args.scheme,
        timeout=max(args.timeout, 5.0),
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["target_id", "cohort", "url", "rank", "domain", "source_url"])
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps({"written": str(output), "rows": len(rows), "source_url": args.source_url}, ensure_ascii=False))
    return 0


def build_manifest_rows(source_url: str, limit: int, start_rank: int, cohort: str, target_prefix: str, scheme: str, timeout: float) -> list[dict[str, str]]:
    text = _download_text(source_url, timeout=timeout)
    rows: list[dict[str, str]] = []
    seen_domains: set[str] = set()
    for rank, domain in _iter_ranked_domains(text):
        if rank < start_rank:
            continue
        normalized = _normalize_domain(domain)
        if not normalized or normalized in seen_domains:
            continue
        seen_domains.add(normalized)
        rows.append(
            {
                "target_id": f"{target_prefix}-{len(rows) + 1:05d}",
                "cohort": cohort,
                "url": f"{scheme}://{normalized}/",
                "rank": str(rank),
                "domain": normalized,
                "source_url": source_url,
            }
        )
        if len(rows) >= limit:
            break
    return rows


def _download_text(source_url: str, timeout: float) -> str:
    request = urllib.request.Request(source_url, headers={"User-Agent": "k-guard-manifest-builder/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
    if source_url.lower().endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            csv_names = [name for name in archive.namelist() if name.lower().endswith(".csv")]
            if not csv_names:
                raise ValueError("No CSV file found in ZIP source.")
            with archive.open(csv_names[0]) as handle:
                return handle.read().decode("utf-8", errors="ignore")
    return raw.decode("utf-8", errors="ignore")


def _iter_ranked_domains(text: str):
    reader = csv.reader(io.StringIO(text))
    for index, row in enumerate(reader, start=1):
        if not row:
            continue
        if index == 1 and any(cell.lower() in {"rank", "domain", "domain name"} for cell in row):
            continue
        rank = _parse_rank(row, index)
        domain = _parse_domain(row)
        if domain:
            yield rank, domain


def _parse_rank(row: list[str], fallback: int) -> int:
    try:
        return int(str(row[0]).strip())
    except Exception:
        return fallback


def _parse_domain(row: list[str]) -> str:
    candidates = row[1:] if len(row) > 1 and str(row[0]).strip().isdigit() else row
    for candidate in candidates:
        value = str(candidate).strip()
        if "." in value and " " not in value and "/" not in value:
            return value
    return ""


def _normalize_domain(value: str) -> str:
    domain = value.strip().strip(".").lower()
    if not domain or "/" in domain or ":" in domain or "@" in domain:
        return ""
    return domain


if __name__ == "__main__":
    raise SystemExit(main())
