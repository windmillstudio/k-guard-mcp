from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for candidate in (str(ROOT), str(SRC)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from k_guard_mcp.detectors.config import ConfigDetector  # noqa: E402
from k_guard_mcp.release_policy import release_lane  # noqa: E402
from scripts.evidence_tree import package_tree_sha256  # noqa: E402

RULE_ID = "CONFIG_GHA_MUTABLE_ACTION_REF"
ACCEPTED_LABELS = frozenset({"true_positive", "false_positive", "benign"})
LOCKED_THRESHOLDS = ("critical", "high", "medium", "low", "info")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _wilson_lower(successes: int, total: int, z: float = 1.959963984540054) -> float:
    if total <= 0:
        return 0.0
    proportion = successes / total
    denominator = 1 + z * z / total
    center = proportion + z * z / (2 * total)
    margin = z * math.sqrt(
        (proportion * (1 - proportion) + z * z / (4 * total)) / total
    )
    return (center - margin) / denominator


def _evidence_value(evidence: str, key: str) -> str | None:
    match = re.search(rf"(?:^|\s){re.escape(key)}=([^\s]+)", evidence)
    return match.group(1) if match else None


def _scan_file(path: Path, relative: str) -> list[Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return [
        finding
        for finding in ConfigDetector().scan_text(text, relative)
        if finding.rule_id == RULE_ID
    ]


def _assert_no_automatic_lane(finding: Any) -> dict[str, str]:
    lanes = {threshold: release_lane(finding, threshold) for threshold in LOCKED_THRESHOLDS}
    if "release_blocking" in lanes.values():
        raise ValueError(
            f"{RULE_ID} entered the automatic lane at {finding.file}:{finding.line_start}"
        )
    return lanes


def _candidate_location(candidate: dict[str, Any]) -> tuple[str, int]:
    raw = str(candidate.get("source_location") or "")
    location, separator, line = raw.rpartition(":")
    if not separator or not location or not line.isdigit():
        raise ValueError(f"invalid source_location: {raw!r}")
    return location.replace("\\", "/"), int(line)


def _new_candidate_row(
    *,
    app: str,
    relative: str,
    finding: Any,
    lanes: dict[str, str],
) -> dict[str, Any]:
    source = f"{app}\0{relative}\0{finding.line_start}\0{finding.rule_id}"
    return {
        "app": app,
        "confidence": finding.confidence,
        "default_release_lane": lanes["high"],
        "detector_subtype": _evidence_value(finding.evidence, "detector_subtype"),
        "label": "unreviewed",
        "medium_threshold_release_lane": lanes["medium"],
        "raw_returned": False,
        "redacted_fingerprint": (
            "sha256-truncated:"
            + hashlib.sha256(source.encode("utf-8")).hexdigest()[:20]
        ),
        "severity": finding.severity,
        "source_location": f"{relative}:{finding.line_start}",
    }


def build_projection(
    *,
    repo_root: Path,
    campaign_dir: Path,
    source_root: Path,
) -> dict[str, Any]:
    queue_path = campaign_dir / "candidate-queue.json"
    labels_path = campaign_dir / "candidate-labels.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    label_by_id = {
        str(candidate["candidate_id"]): candidate
        for candidate in labels.get("candidates", [])
    }
    prior = [
        candidate
        for candidate in queue.get("candidates", [])
        if candidate.get("rule_id") == RULE_ID
    ]
    if not prior:
        raise ValueError(f"candidate queue has no {RULE_ID} rows")

    file_cache: dict[tuple[str, str], list[Any]] = {}
    prior_keys: set[tuple[str, str, int]] = set()
    rows: list[dict[str, Any]] = []
    confusion = Counter(
        {
            "true_positive": 0,
            "false_positive": 0,
            "false_negative": 0,
            "true_negative": 0,
        }
    )
    for candidate in prior:
        candidate_id = str(candidate["candidate_id"])
        if candidate_id not in label_by_id:
            raise ValueError(f"missing label for candidate {candidate_id}")
        label = str(label_by_id[candidate_id].get("label") or "")
        if label not in ACCEPTED_LABELS:
            raise ValueError(f"non-evaluable label for candidate {candidate_id}: {label}")

        app = str(candidate["app"])
        relative, line = _candidate_location(candidate)
        prior_keys.add((app, relative.casefold(), line))
        cache_key = (app, relative)
        if cache_key not in file_cache:
            file_cache[cache_key] = _scan_file(source_root / app / relative, relative)
        finding = next(
            (
                item
                for item in file_cache[cache_key]
                if int(item.line_start or 0) == line
            ),
            None,
        )
        actual_positive = label == "true_positive"
        predicted_positive = finding is not None and finding.severity == "high"
        if actual_positive and predicted_positive:
            confusion["true_positive"] += 1
        elif not actual_positive and predicted_positive:
            confusion["false_positive"] += 1
        elif actual_positive:
            confusion["false_negative"] += 1
        else:
            confusion["true_negative"] += 1

        if finding is None:
            rows.append(
                {
                    "adjudicated_label": label,
                    "candidate_id": candidate_id,
                    "confidence": None,
                    "context_hash": None,
                    "default_release_lane": None,
                    "detected": False,
                    "detector_subtype": "missing",
                    "medium_threshold_release_lane": None,
                    "severity": None,
                    "shadow_release_authority_candidate": False,
                }
            )
            continue

        finding.artifact_scope = str(candidate["artifact_scope"])
        lanes = _assert_no_automatic_lane(finding)
        rows.append(
            {
                "adjudicated_label": label,
                "candidate_id": candidate_id,
                "confidence": finding.confidence,
                "context_hash": _evidence_value(finding.evidence, "context_hash"),
                "default_release_lane": lanes["high"],
                "detected": True,
                "detector_subtype": _evidence_value(
                    finding.evidence, "detector_subtype"
                ),
                "medium_threshold_release_lane": lanes["medium"],
                "severity": finding.severity,
                "shadow_release_authority_candidate": predicted_positive,
            }
        )

    new_candidates: list[dict[str, Any]] = []
    for app_root in sorted(path for path in source_root.iterdir() if path.is_dir()):
        for path in sorted(app_root.rglob("*")):
            if not path.is_file() or path.suffix.casefold() not in {".yml", ".yaml"}:
                continue
            relative = path.relative_to(app_root).as_posix()
            if not relative.casefold().startswith(".github/workflows/"):
                continue
            for finding in _scan_file(path, relative):
                key = (
                    app_root.name,
                    relative.casefold(),
                    int(finding.line_start or 0),
                )
                finding.artifact_scope = "configuration"
                lanes = _assert_no_automatic_lane(finding)
                if key not in prior_keys:
                    new_candidates.append(
                        _new_candidate_row(
                            app=app_root.name,
                            relative=relative,
                            finding=finding,
                            lanes=lanes,
                        )
                    )

    true_positive = confusion["true_positive"]
    predicted_positive = true_positive + confusion["false_positive"]
    actual_positive = true_positive + confusion["false_negative"]
    precision = true_positive / predicted_positive if predicted_positive else 0.0
    recall = true_positive / actual_positive if actual_positive else 0.0
    working_diff = subprocess.check_output(
        ["git", "diff", "--no-color"],
        cwd=repo_root,
    )
    return {
        "campaign_id": queue["campaign_id"],
        "current_release_lane_contract": {
            "automatic_release_blocking": False,
            "automatic_rule_membership": False,
            "generic_mutable_ref_default_high": "supporting_review",
            "parse_or_job_boundary_failure": "manual_review_hold",
            "release_authority_shadow": "manual_review_hold",
        },
        "evidence_use": "development_baseline_only",
        "known_scope_limits": [
            "moving major tags such as @v4 are not part of this hypothesis",
            "arbitrary branch and tag refs require a separate observe-only hypothesis",
        ],
        "locked_promotion_thresholds": {
            "minimum_precision": 0.9,
            "minimum_precision_wilson_95_lower": 0.8,
            "minimum_recall": 0.9,
        },
        "new_unlabeled_candidate_count": len(new_candidates),
        "new_unlabeled_candidates": new_candidates,
        "prior_candidate_detection_miss_count": sum(
            not row["detected"] for row in rows
        ),
        "prior_labeled_candidate_count": len(prior),
        "promotion_allowed": False,
        "promotion_blockers": [
            "recovery replay is nonqualifying",
            "fresh unseen holdout is required",
            "prior positive count does not clear the locked Wilson floor",
            "newly detected candidates require independent labels",
        ],
        "pyproject_sha256": _sha256_file(repo_root / "pyproject.toml"),
        "qualification_eligible": False,
        "raw_returned": False,
        "release_claim_allowed": False,
        "rows": rows,
        "schema": "k_guard_mutable_action_shadow_projection.v3",
        "shadow_confusion_on_prior_labels": dict(confusion),
        "shadow_precision_on_prior_labels": round(precision, 6),
        "shadow_precision_wilson_95_lower": round(
            _wilson_lower(true_positive, predicted_positive), 6
        ),
        "shadow_recall_on_prior_labels": round(recall, 6),
        "shadow_recall_wilson_95_lower": round(
            _wilson_lower(true_positive, actual_positive), 6
        ),
        "source_labels_sha256": _sha256_file(labels_path),
        "source_queue_sha256": _sha256_file(queue_path),
        "subtype_counts_on_prior_labels": dict(
            sorted(Counter(row["detector_subtype"] for row in rows).items())
        ),
        "working_tree_diff_sha256": hashlib.sha256(working_diff).hexdigest(),
        "working_tree_package_sha256": package_tree_sha256(
            repo_root / "src" / "k_guard_mcp"
        ),
    }


def write_projection(output: Path, payload: dict[str, Any]) -> None:
    if output.exists():
        raise FileExistsError(f"refusing to overwrite projection: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = build_projection(
        repo_root=ROOT,
        campaign_dir=args.campaign_dir.resolve(),
        source_root=args.source_root.resolve(),
    )
    write_projection(args.output.resolve(), payload)
    print(
        json.dumps(
            {
                "output": str(args.output.resolve()),
                "prior_labeled_candidate_count": payload[
                    "prior_labeled_candidate_count"
                ],
                "new_unlabeled_candidate_count": payload[
                    "new_unlabeled_candidate_count"
                ],
                "shadow_confusion_on_prior_labels": payload[
                    "shadow_confusion_on_prior_labels"
                ],
                "shadow_precision_on_prior_labels": payload[
                    "shadow_precision_on_prior_labels"
                ],
                "shadow_precision_wilson_95_lower": payload[
                    "shadow_precision_wilson_95_lower"
                ],
                "shadow_recall_on_prior_labels": payload[
                    "shadow_recall_on_prior_labels"
                ],
                "shadow_recall_wilson_95_lower": payload[
                    "shadow_recall_wilson_95_lower"
                ],
                "working_tree_package_sha256": payload[
                    "working_tree_package_sha256"
                ],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
