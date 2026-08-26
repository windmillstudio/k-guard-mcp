from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from k_guard_mcp.collector import read_text
from k_guard_mcp.release_policy import (
    MANUAL_REVIEW_HOLD_LANE,
    RELEASE_BLOCKING_POLICY,
    is_release_blocking_finding,
    release_lane,
)
from k_guard_mcp.scanner import KGuardScanner


SCHEMA = "k_guard_docker_lane_replay.v1"
RULE_ID = "CONFIG_DOCKER_SOCK"
SUBTYPE_PATTERN = re.compile(r"\bdetector_subtype=([^\s;]+)")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _source_ref(source_location: str) -> tuple[Path, int]:
    try:
        relative, raw_line = source_location.rsplit(":", 1)
        line = int(raw_line)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid source location: {source_location or '<missing>'}") from exc
    candidate = Path(relative.replace("\\", "/"))
    if not relative or line <= 0 or candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"unsafe source location: {source_location or '<missing>'}")
    return candidate, line


def _contract_hashes(root: Path) -> dict[str, str]:
    relative_paths = (
        "src/k_guard_mcp/detectors/config.py",
        "src/k_guard_mcp/release_policy.py",
        "src/k_guard_mcp/scanner.py",
    )
    hashes = {relative: _sha256_file(root / relative) for relative in relative_paths}
    hashes["contract_sha256"] = _sha256_bytes(_canonical_json(hashes).encode("utf-8"))
    return hashes


def replay_docker_lane(labels_path: Path, apps_root: Path) -> dict[str, Any]:
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    candidates = labels.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError("candidate labels must contain a candidates list")
    selected = [row for row in candidates if isinstance(row, dict) and row.get("rule_id") == RULE_ID]
    if not selected:
        raise ValueError(f"no {RULE_ID} candidates found")

    repository_root = Path(__file__).resolve().parents[1]
    apps_root = apps_root.resolve(strict=True)
    scanner = KGuardScanner()
    scan_cache: dict[tuple[str, str], tuple[str, list[Any], str]] = {}
    rows: list[dict[str, Any]] = []

    for candidate in selected:
        app = str(candidate.get("app") or "")
        candidate_id = str(candidate.get("candidate_id") or "")
        source_location = str(candidate.get("source_location") or "")
        if not app or not candidate_id:
            raise ValueError("Docker candidates require app and candidate_id")
        relative, line = _source_ref(source_location)
        app_root = (apps_root / app).resolve(strict=True)
        source_path = (app_root / relative).resolve(strict=True)
        if not source_path.is_relative_to(app_root) or not source_path.is_file():
            raise ValueError(f"source location escapes app root: {source_location}")

        cache_key = (app, relative.as_posix())
        if cache_key not in scan_cache:
            text = read_text(source_path)
            if text is None:
                raise ValueError(f"source file is not reviewable text: {source_location}")
            findings = scanner.scan_text(text, relative.as_posix()).findings
            scan_cache[cache_key] = (text, findings, _sha256_file(source_path))
        text, findings, source_file_sha256 = scan_cache[cache_key]
        matches = [
            finding
            for finding in findings
            if finding.rule_id == RULE_ID and finding.line_start == line
        ]
        if len(matches) != 1:
            raise ValueError(
                f"expected one current Docker finding at {app}:{source_location}; found {len(matches)}"
            )
        finding = matches[0]
        subtype_match = SUBTYPE_PATTERN.search(finding.evidence or "")
        if subtype_match is None:
            raise ValueError(f"Docker finding lacks detector subtype: {app}:{source_location}")
        source_lines = text.splitlines()
        if line > len(source_lines):
            raise ValueError(f"source line is outside file: {app}:{source_location}")
        lane = release_lane(finding, "high")
        rows.append(
            {
                "app": app,
                "artifact_scope": finding.artifact_scope,
                "candidate_id": candidate_id,
                "current_confidence": finding.confidence,
                "current_detector_subtype": subtype_match.group(1),
                "current_release_blocks": is_release_blocking_finding(finding, "high"),
                "current_release_lane": lane,
                "current_severity": finding.severity,
                "frozen_label": candidate.get("label"),
                "source_file_sha256": source_file_sha256,
                "source_line_sha256": _sha256_bytes(source_lines[line - 1].encode("utf-8")),
                "source_location": source_location,
            }
        )

    rows.sort(key=lambda row: (str(row["app"]), str(row["source_location"]), str(row["candidate_id"])))
    candidate_ids = [str(row["candidate_id"]) for row in rows]
    subtype_counts = Counter(str(row["current_detector_subtype"]) for row in rows)
    lane_counts = Counter(str(row["current_release_lane"]) for row in rows)
    label_counts = Counter(str(row["frozen_label"]) for row in rows)
    source_binding = [
        {
            "app": row["app"],
            "candidate_id": row["candidate_id"],
            "source_file_sha256": row["source_file_sha256"],
            "source_line_sha256": row["source_line_sha256"],
            "source_location": row["source_location"],
        }
        for row in rows
    ]
    checks = {
        "all_candidates_reproduced_once": len(rows) == len(selected),
        "all_current_findings_release_block": all(bool(row["current_release_blocks"]) for row in rows),
        "all_current_findings_manual_review_hold": all(
            row["current_release_lane"] == MANUAL_REVIEW_HOLD_LANE for row in rows
        ),
        "candidate_ids_unique": len(candidate_ids) == len(set(candidate_ids)),
        "source_material_content_bound": all(
            len(str(row["source_file_sha256"])) == 64 and len(str(row["source_line_sha256"])) == 64
            for row in rows
        ),
    }
    return {
        "schema": SCHEMA,
        "evidence_role": "same_set_post_fix_development_regression",
        "release_blocking_policy": RELEASE_BLOCKING_POLICY,
        "analyzer_contract": _contract_hashes(repository_root),
        "source": {
            "candidate_labels": labels_path.as_posix(),
            "candidate_labels_sha256": _sha256_file(labels_path),
            "campaign_id": labels.get("campaign_id"),
            "frozen_source_revision": labels.get("source_revision"),
            "source_material_sha256": _sha256_bytes(_canonical_json(source_binding).encode("utf-8")),
        },
        "population": {
            "candidate_count": len(rows),
            "current_lane_counts": dict(sorted(lane_counts.items())),
            "current_subtype_counts": dict(sorted(subtype_counts.items())),
            "frozen_label_counts": dict(sorted(label_counts.items())),
        },
        "checks": checks,
        "rows": rows,
        "claim_boundary": {
            "independent_post_fix_holdout": False,
            "qualifies_release_blocking_policy": False,
            "proves_field_prevalence_or_recall": False,
            "reason": "This replay reuses frozen R4 candidates to verify lane behavior only; it cannot qualify v4 or replace a disjoint preregistered holdout.",
        },
        "raw_returned": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay frozen Docker candidates through the current release lane.")
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--apps-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    payload = replay_docker_lane(args.labels, args.apps_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0 if all(payload["checks"].values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
