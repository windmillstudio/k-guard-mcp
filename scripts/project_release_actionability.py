from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from math import sqrt
from pathlib import Path
from typing import Any

from k_guard_mcp.release_policy import RELEASE_BLOCKING_LANE, RELEASE_BLOCKING_POLICY, release_lane


ALLOWED_LABELS = frozenset({"true_positive", "false_positive", "benign", "inconclusive"})


def _wilson_lower(successes: int, total: int, z: float = 1.959963984540054) -> float:
    if total <= 0:
        return 0.0
    proportion = successes / total
    denominator = 1 + (z * z / total)
    center = proportion + (z * z / (2 * total))
    margin = z * sqrt((proportion * (1 - proportion) / total) + (z * z / (4 * total * total)))
    return round((center - margin) / denominator, 6)


def project_labels(labels_path: Path) -> dict[str, Any]:
    payload = json.loads(labels_path.read_text(encoding="utf-8"))
    candidates = payload.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError("candidate labels must contain a candidates list")

    selected: list[dict[str, Any]] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise ValueError("every candidate label must be an object")
        label = str(candidate.get("label") or "")
        if label not in ALLOWED_LABELS:
            raise ValueError(f"unsupported candidate label: {label or '<missing>'}")
        projected_finding = {
            **candidate,
            "severity": str(candidate.get("severity") or "high"),
            "confidence": str(candidate.get("confidence") or "high"),
            "artifact_scope": str(candidate.get("artifact_scope") or "runtime_source"),
            "evidence": str(candidate.get("evidence") or f"detector_subtype={candidate.get('detector_subtype') or 'unknown'}"),
        }
        if release_lane(projected_finding, "high") != RELEASE_BLOCKING_LANE:
            continue
        selected.append(candidate)

    label_counts = Counter(str(row["label"]) for row in selected)
    candidate_count = len(selected)
    true_positive_count = label_counts["true_positive"]
    return {
        "schema": "k_guard_release_actionability_projection.v1",
        "release_blocking_policy": RELEASE_BLOCKING_POLICY,
        "source": {
            "candidate_labels": labels_path.as_posix(),
            "candidate_labels_sha256": hashlib.sha256(labels_path.read_bytes()).hexdigest(),
            "source_revision": payload.get("source_revision"),
        },
        "population": {
            "candidate_count": candidate_count,
            "candidate_label_counts": {
                label: label_counts[label]
                for label in ("true_positive", "false_positive", "benign", "inconclusive")
            },
            "candidate_rule_counts": dict(
                sorted(Counter(str(row["rule_id"]) for row in selected).items())
            ),
            "candidate_app_count": len({str(row.get("app") or "") for row in selected}),
            "candidate_apps": sorted({str(row.get("app") or "") for row in selected}),
        },
        "metrics": {
            "automatic_block_actionability": round(true_positive_count / candidate_count, 6)
            if candidate_count
            else 0.0,
            "automatic_block_actionability_wilson_95_lower": _wilson_lower(
                true_positive_count, candidate_count
            ),
        },
        "claim_boundary": {
            "evidence_role": "post_hoc_development_projection",
            "independent_post_fix_holdout": False,
            "qualifies_release_blocking_policy": False,
            "reason": "The policy was selected after inspecting these labels; a disjoint preregistered holdout is required.",
        },
        "raw_returned": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Project labeled candidates onto the current automatic-block lane.")
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    result = project_labels(args.labels)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
