#!/usr/bin/env python3
"""Create a sanitized timed event log from the fixed Claude read-only audit receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = (
    ROOT
    / "evidence"
    / "qualification"
    / "three-ai-audit-r1"
    / "claude-opus-5-max-followup-review.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit("Refusing to overwrite an existing event log")

    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    if payload.get("provider") != "Anthropic":
        raise RuntimeError("Claude audit provider binding drifted")
    if payload.get("observed_model") != "claude-opus-5":
        raise RuntimeError("Claude audit model binding drifted")
    if payload.get("reasoning_effort") != "max" or payload.get("verdict") != "PASS":
        raise RuntimeError("Claude audit verdict binding drifted")
    if payload.get("blocking_findings") != []:
        raise RuntimeError("Claude audit has blocking findings")
    execution = payload.get("execution") if isinstance(payload.get("execution"), dict) else {}
    if (
        execution.get("repository_write_access") is not False
        or execution.get("web_search_requests") != 0
        or execution.get("web_fetch_requests") != 0
    ):
        raise RuntimeError("Claude audit is not the expected read-only receipt")

    digest = hashlib.sha256(RECEIPT.read_bytes()).hexdigest()
    lines = [
        (0.00, "CLAUDE OPUS 5  |  FIXED-BUNDLE READ-ONLY AUDIT", "green"),
        (1.80, "Historical audit receipt; this is not a current MCP client recording.", "dim"),
        (4.20, "BIND   provider Anthropic | model claude-opus-5 | effort max", "cyan"),
        (6.60, "MODE   fixed evidence bundle | read only | network disabled", "cyan"),
        (9.00, "TOOLS  repository writes false | web calls 0", "green"),
        (11.40, "MASK   synthetic token sk-[redacted-demo] | raw values false", "green"),
        (13.80, "CHECK  Korean qualification binding", "yellow"),
        (16.20, "PASS   qualification inputs and claim boundary", "green"),
        (18.60, "CHECK  runtime mediation and evidence receipts", "yellow"),
        (21.00, "PASS   no blocking findings", "green"),
        (23.40, "VERDICT  PASS", "green"),
        (25.80, f"RECEIPT  sha256 {digest[:20]}...{digest[-12:]}", "dim"),
        (28.20, "K-GUARD WALKTHROUGH PASS | CLAUDE AUDIT RECEIPT VERIFIED", "green"),
        (30.20, "", "dim"),
    ]
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as stream:
        for timestamp, text, color in lines:
            stream.write(
                json.dumps(
                    {"t": timestamp, "text": text, "color": color},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
