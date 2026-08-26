from __future__ import annotations

import csv
import hashlib
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from k_guard_mcp.field_validation import FIELD_REVIEW_FIELDS, GROUND_TRUTH_FIELDS, run_field_validation
from k_guard_mcp.guardian import build_validation_guardian_evidence
from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.provenance import source_tree_snapshot
from k_guard_mcp.scanner import KGuardScanner
from k_guard_mcp.validation import finding_fingerprint


MUTATION_PLAN_SCHEMA = "k_guard_mutation_plan.v1"
MUTATION_REPORT_SCHEMA = "k_guard_mutation_pack.v1"
_IGNORED_COPY_NAMES = {".git", ".venv", "node_modules", "dist", "build", ".next", "coverage", "__pycache__"}


def write_mutation_plan_template(path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": MUTATION_PLAN_SCHEMA,
        "app_id": "owned-app-seeded-copy",
        "source_scope_ref": "owned-app-or-partner-authorization-ticket",
        "mutations": [
            {
                "mutation_id": "express-idor-001",
                "relative_path": "src/routes/profile.ts",
                "find": "where: { id: req.params.id, ownerId: req.user.id }",
                "replace": "where: { id: req.params.id }",
                "expected_rule_ids": ["JS_TS_EXPRESS_IDOR_ROUTE_PARAM"],
                "severity": "high",
                "stratum": "mid",
                "split": "holdout",
            }
        ],
    }
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def apply_mutation_plan(source_path: str | Path, output_path: str | Path, plan_path: str | Path) -> dict[str, Any]:
    source = Path(source_path).resolve()
    output = Path(output_path).resolve()
    plan_file = Path(plan_path).resolve()
    if not source.is_dir():
        raise ValueError("Mutation source must be an existing directory.")
    _validate_copy_boundaries(source, output)
    if output.exists():
        raise ValueError("Mutation output must not already exist.")
    plan = _load_plan(plan_file)

    baseline = output / "baseline"
    mutated = output / "mutated"
    output.mkdir(parents=True)
    shutil.copytree(source, baseline, symlinks=True, ignore=_copy_ignore)
    shutil.copytree(source, mutated, symlinks=True, ignore=_copy_ignore)

    mutation_rows: list[dict[str, Any]] = []
    touched_files: set[str] = set()
    for mutation in plan["mutations"]:
        relative = _safe_relative_path(mutation["relative_path"])
        baseline_file = _safe_pack_file(baseline, relative)
        mutated_file = _safe_pack_file(mutated, relative)
        if not baseline_file.is_file() or not mutated_file.is_file():
            raise ValueError(f"Mutation target does not exist: {relative.as_posix()}")
        if baseline_file.is_symlink() or mutated_file.is_symlink():
            raise ValueError("Mutation targets cannot be symbolic links or reparse aliases.")
        baseline_text = baseline_file.read_text(encoding="utf-8")
        mutated_text = mutated_file.read_text(encoding="utf-8")
        find = mutation["find"]
        replace = mutation["replace"]
        occurrence_count = mutated_text.count(find)
        if occurrence_count != 1:
            raise ValueError(f"Mutation {mutation['mutation_id']} expected exactly one match, found {occurrence_count}.")
        before_sha256 = _sha256_bytes(mutated_text.encode("utf-8"))
        updated = mutated_text.replace(find, replace, 1)
        mutated_file.write_text(updated, encoding="utf-8")
        after_sha256 = _sha256_bytes(updated.encode("utf-8"))
        if before_sha256 == after_sha256 or (relative.as_posix() not in touched_files and baseline_text != mutated_text):
            raise RuntimeError("Mutation copy integrity check failed.")
        touched_files.add(relative.as_posix())
        mutation_rows.append(
            {
                "mutation_ref": _ref(mutation["mutation_id"]),
                "relative_path_ref": _ref(relative.as_posix()),
                "find_ref": _ref(find),
                "replace_ref": _ref(replace),
                "expected_rule_ids": list(mutation["expected_rule_ids"]),
                "severity": mutation["severity"],
                "stratum": mutation["stratum"],
                "split": mutation["split"],
                "before_sha256": before_sha256,
                "after_sha256": after_sha256,
                "replacement_count": 1,
                "raw_returned": False,
            }
        )

    baseline_tree = _tree_sha256(baseline)
    mutated_tree = _tree_sha256(mutated)
    if baseline_tree == mutated_tree:
        raise RuntimeError("Mutation pack did not change the source tree.")
    report = {
        "schema": MUTATION_REPORT_SCHEMA,
        "generated_at": datetime.now(UTC).isoformat(),
        "method": "copy_then_exact_seeded_mutation",
        "raw_free": True,
        "app_ref": _ref(plan["app_id"]),
        "source_scope_ref": _ref(plan["source_scope_ref"]),
        "source_path_ref": _ref(str(source)),
        "plan_path_ref": _ref(str(plan_file)),
        "plan_content_sha256": _sha256_file(plan_file),
        "baseline_tree_sha256": baseline_tree,
        "mutated_tree_sha256": mutated_tree,
        "mutation_count": len(mutation_rows),
        "mutations": mutation_rows,
        "evaluation_status": "not_run",
        "claim_boundary": {
            "seeded_mutations_are_not_naturally_occurring_field_findings": True,
            "does_not_count_as_owned_partner_accuracy": True,
            "original_source_was_not_modified": _tree_sha256(source) == baseline_tree,
            "raw_returned": False,
        },
    }
    _write_json(output / "mutation-report.json", report)
    shutil.copy2(plan_file, output / "mutation-plan.json")
    return report


def evaluate_mutation_pack(pack_path: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    pack = Path(pack_path).resolve()
    output = Path(output_path).resolve() if output_path else pack / "evaluation"
    baseline = pack / "baseline"
    mutated = pack / "mutated"
    plan_file = pack / "mutation-plan.json"
    report_file = pack / "mutation-report.json"
    if not baseline.is_dir() or not mutated.is_dir() or not plan_file.is_file() or not report_file.is_file():
        raise ValueError("Mutation pack is incomplete.")
    if output.exists() and any(output.iterdir()):
        raise ValueError("Mutation evaluation output must be empty or absent.")
    output.mkdir(parents=True, exist_ok=True)
    plan = _load_plan(plan_file)
    pack_report = json.loads(report_file.read_text(encoding="utf-8"))
    if pack_report.get("plan_content_sha256") != _sha256_file(plan_file):
        raise ValueError("Mutation plan changed after the pack was created.")
    if pack_report.get("baseline_tree_sha256") != _tree_sha256(baseline) or pack_report.get("mutated_tree_sha256") != _tree_sha256(mutated):
        raise ValueError("Mutation pack source trees changed after creation.")

    scanner = KGuardScanner()
    first_baseline = scanner.scan_workspace(baseline, include_flow=True)
    first_mutated = scanner.scan_workspace(mutated, include_flow=True)
    second_baseline = scanner.scan_workspace(baseline, include_flow=True)
    second_mutated = scanner.scan_workspace(mutated, include_flow=True)
    app_id = plan["app_id"]
    baseline_target = f"{app_id}-baseline"
    mutated_target = f"{app_id}-mutated"
    generated = datetime.now(UTC)
    source_snapshots = {
        baseline_target: source_tree_snapshot(baseline),
        mutated_target: source_tree_snapshot(mutated),
    }
    target_refs = {
        baseline_target: _ref(str(baseline)),
        mutated_target: _ref(str(mutated)),
    }
    primary = _combined_guardian(
        app_id,
        baseline_target,
        first_baseline.findings,
        mutated_target,
        first_mutated.findings,
        generated.isoformat(),
        scanner=scanner,
        evidence_input_path=report_file,
        source_snapshots=source_snapshots,
        target_refs=target_refs,
    )
    repeat = _combined_guardian(
        app_id,
        baseline_target,
        second_baseline.findings,
        mutated_target,
        second_mutated.findings,
        (generated + timedelta(microseconds=2)).isoformat(),
        scanner=scanner,
        evidence_input_path=report_file,
        source_snapshots=source_snapshots,
        target_refs=target_refs,
    )
    primary_path = output / "primary-guardian.json"
    repeat_path = output / "repeat-guardian.json"
    _write_json(primary_path, primary)
    _write_json(repeat_path, repeat)
    ground_truth_path = output / "ground-truth.csv"
    review_path = output / "candidate-review.csv"
    _write_mutation_ground_truth(ground_truth_path, plan, app_id, baseline_target, mutated_target, pack_report)
    _write_mutation_reviews(review_path, primary, plan, app_id, baseline_target, mutated_target)
    profile = "mutation" if len(plan["mutations"]) >= 25 else "pilot"
    validation = run_field_validation(primary_path, repeat_path, ground_truth_path, review_path, profile=profile)
    validation_path = output / "mutation-validation.json"
    _write_json(validation_path, validation)
    unique_paths = {str(item["relative_path"]) for item in plan["mutations"]}
    unique_rules = {str(rule) for item in plan["mutations"] for rule in item["expected_rule_ids"]}
    unique_operators = {
        hashlib.sha256(
            json.dumps(
                {"find": item["find"], "replace": item["replace"], "rules": item["expected_rule_ids"]},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        for item in plan["mutations"]
    }
    summary = {
        "schema": "k_guard_mutation_evaluation.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "method": "baseline_mutated_repeat_scan",
        "raw_free": True,
        "profile": profile,
        "mutation_count": len(plan["mutations"]),
        "diversity": {
            "app_count": 1,
            "unique_path_count": len(unique_paths),
            "unique_expected_rule_count": len(unique_rules),
            "unique_operator_count": len(unique_operators),
            "evidence_grade": (
                "multi_operator_seeded_regression"
                if len(unique_paths) >= 5 and len(unique_rules) >= 3 and len(unique_operators) >= 5
                else "single_pattern_seeded_regression"
            ),
            "raw_returned": False,
        },
        "validation_claim_status": validation.get("claim_status"),
        "rates": validation.get("rates", {}),
        "case_counts": validation.get("case_counts", {}),
        "reproducibility": validation.get("reproducibility", {}),
        "artifacts": {
            "primary_guardian": _file_ref(primary_path),
            "repeat_guardian": _file_ref(repeat_path),
            "ground_truth": _file_ref(ground_truth_path),
            "candidate_review": _file_ref(review_path),
            "validation": _file_ref(validation_path),
        },
        "claim_boundary": {
            "seeded_mutation_evidence_only": True,
            "minimum_25_mutations_for_benchmark_profile": True,
            "build_test_runtime_oracle_verified": False,
            "independent_vulnerability_adjudication": False,
            "not_a_public_or_field_benchmark": True,
            "does_not_count_as_owned_partner_field_validation": True,
            "raw_returned": False,
        },
    }
    _write_json(output / "mutation-score.json", summary)
    return summary


def _load_plan(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != MUTATION_PLAN_SCHEMA:
        raise ValueError(f"Mutation plan schema must be {MUTATION_PLAN_SCHEMA}.")
    app_id = str(payload.get("app_id") or "").strip()
    scope_ref = str(payload.get("source_scope_ref") or "").strip()
    mutations = payload.get("mutations")
    if not app_id or not scope_ref or not isinstance(mutations, list) or not mutations:
        raise ValueError("Mutation plan requires app_id, source_scope_ref, and at least one mutation.")
    normalized = []
    seen: set[str] = set()
    for item in mutations:
        if not isinstance(item, dict):
            raise ValueError("Every mutation must be an object.")
        mutation_id = str(item.get("mutation_id") or "").strip()
        relative_path = str(item.get("relative_path") or "").strip()
        find = str(item.get("find") or "")
        replace = str(item.get("replace") or "")
        rules = item.get("expected_rule_ids")
        severity = str(item.get("severity") or "").strip().lower()
        stratum = str(item.get("stratum") or "").strip()
        split = str(item.get("split") or "").strip()
        if not mutation_id or mutation_id in seen:
            raise ValueError("Mutation ids must be non-empty and unique.")
        if not relative_path or not find or find == replace:
            raise ValueError(f"Mutation {mutation_id} requires a path and distinct non-empty find/replace strings.")
        if not isinstance(rules, list) or not rules or not all(str(rule).strip() for rule in rules):
            raise ValueError(f"Mutation {mutation_id} requires expected_rule_ids.")
        if severity not in {"critical", "high"} or stratum not in {"top", "mid", "long_tail"} or split not in {"development", "holdout"}:
            raise ValueError(f"Mutation {mutation_id} has an invalid severity, stratum, or split.")
        _safe_relative_path(relative_path)
        seen.add(mutation_id)
        normalized.append(
            {
                "mutation_id": mutation_id,
                "relative_path": relative_path,
                "find": find,
                "replace": replace,
                "expected_rule_ids": [str(rule).strip() for rule in rules],
                "severity": severity,
                "stratum": stratum,
                "split": split,
            }
        )
    return {"schema": MUTATION_PLAN_SCHEMA, "app_id": app_id, "source_scope_ref": scope_ref, "mutations": normalized}


def _write_mutation_ground_truth(
    path: Path,
    plan: dict[str, Any],
    app_id: str,
    baseline_target: str,
    mutated_target: str,
    pack_report: dict[str, Any],
) -> None:
    source_ref = f"seeded-mutation:{pack_report['plan_content_sha256']}:{pack_report['baseline_tree_sha256']}:{pack_report['mutated_tree_sha256']}"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=GROUND_TRUTH_FIELDS)
        writer.writeheader()
        for mutation in plan["mutations"]:
            for target_id, outcome, suffix in (
                (baseline_target, "clean", "baseline"),
                (mutated_target, "vulnerable", "mutated"),
            ):
                writer.writerow(
                    {
                        "app_id": app_id,
                        "target_id": target_id,
                        "case_id": f"{mutation['mutation_id']}-{suffix}",
                        "severity": mutation["severity"],
                        "expected_outcome": outcome,
                        "expected_rule_ids": "|".join(mutation["expected_rule_ids"]),
                        "file": mutation["relative_path"],
                        "line_start": "",
                        "line_end": "",
                        "stratum": mutation["stratum"],
                        "split": mutation["split"],
                        "source_kind": "seeded_mutation",
                        "source_ref": source_ref,
                        "reproduction_count": 2,
                        "reviewer_1": "",
                        "verdict_1": "",
                        "reviewer_2": "",
                        "verdict_2": "",
                        "adjudicator": "",
                        "final_verdict": outcome,
                        "notes": "exact seeded mutation pair",
                    }
                )


def _write_mutation_reviews(
    path: Path,
    guardian: dict[str, Any],
    plan: dict[str, Any],
    app_id: str,
    baseline_target: str,
    mutated_target: str,
) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELD_REVIEW_FIELDS)
        writer.writeheader()
        for finding in _guardian_findings(guardian):
            if str(finding.get("severity") or "") not in {"critical", "high"}:
                continue
            target_id = str(finding.get("target_id") or "")
            matched = any(_finding_matches_mutation(finding, mutation) for mutation in plan["mutations"])
            verdict = "true_positive" if target_id == mutated_target and matched else "false_positive"
            writer.writerow(
                {
                    "app_id": app_id,
                    "target_id": target_id,
                    "rule_id": finding.get("rule_id", ""),
                    "finding_fingerprint": finding_fingerprint(finding),
                    "reviewer_1": "seeded-mutation-adapter",
                    "verdict_1": verdict,
                    "reviewer_2": "",
                    "verdict_2": "",
                    "adjudicator": "",
                    "final_verdict": verdict,
                    "notes": "machine-mapped exact seeded mutation",
                }
            )


def _finding_matches_mutation(finding: dict[str, Any], mutation: dict[str, Any]) -> bool:
    if str(finding.get("rule_id") or "") not in set(mutation["expected_rule_ids"]):
        return False
    finding_file = str(finding.get("file") or "").replace("\\", "/").lower()
    expected = mutation["relative_path"].replace("\\", "/").lower().lstrip("./")
    return finding_file == expected or finding_file.endswith("/" + expected)


def _combined_guardian(
    app_id: str,
    baseline_target: str,
    baseline_findings: list[Any],
    mutated_target: str,
    mutated_findings: list[Any],
    generated_at: str,
    *,
    scanner: KGuardScanner,
    evidence_input_path: str | Path,
    source_snapshots: dict[str, dict[str, Any]],
    target_refs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    targets = []
    for target_id, findings in ((baseline_target, baseline_findings), (mutated_target, mutated_findings)):
        normalized: dict[str, dict[str, Any]] = {}
        for finding in findings:
            item = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
            item["app_id"] = app_id
            item["target_id"] = target_id
            normalized.setdefault(finding_fingerprint(item), item)
        targets.append(
            {
                "app_id": app_id,
                "target_id": target_id,
                "kind": "workspace",
                "target_ref": target_refs[target_id],
                "kind_ref": target_refs[target_id],
                "locator_ref": target_refs[target_id],
                "status": "completed",
                "audit_profile": "seeded_mutation",
                "coverage": {"coverage_gap": False, "raw_returned": False},
                "review_evidence": {
                    "source_tree_snapshot": source_snapshots[target_id],
                    "raw_returned": False,
                },
                "findings": list(normalized.values()),
                "rule_ids": sorted({str(item.get("rule_id") or "") for item in normalized.values()}),
            }
        )
    return build_validation_guardian_evidence(
        method="seeded_mutation_scan",
        generated_at=generated_at,
        targets=targets,
        evidence_input_path=evidence_input_path,
        scanner=scanner,
    )


def _guardian_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    for target in report.get("targets", []):
        if not isinstance(target, dict):
            continue
        for finding in target.get("findings", []):
            if isinstance(finding, dict):
                item = dict(finding)
                item.setdefault("app_id", target.get("app_id", ""))
                item.setdefault("target_id", target.get("target_id", ""))
                findings.append(item)
    return findings


def _validate_copy_boundaries(source: Path, output: Path) -> None:
    if source == output or output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError("Mutation output must be outside and disjoint from the source tree.")


def _safe_relative_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("Mutation relative_path must stay inside the copied app.")
    return path


def _safe_pack_file(root: Path, relative: Path) -> Path:
    candidate = root / relative
    resolved_parent = candidate.parent.resolve()
    if not resolved_parent.is_relative_to(root.resolve()):
        raise ValueError("Mutation target escaped the copied app.")
    return candidate


def _copy_ignore(_directory: str, names: list[str]) -> set[str]:
    return {name for name in names if name in _IGNORED_COPY_NAMES}


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted((item for item in root.rglob("*") if item.is_file() and not item.is_symlink()), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(_sha256_file(path)))
    return digest.hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _file_ref(path: Path) -> dict[str, Any]:
    return {"path_ref": _ref(str(path)), "content_sha256": _sha256_file(path), "byte_count": path.stat().st_size, "raw_returned": False}


def _ref(value: object) -> dict[str, Any]:
    return {"hash": evidence_hash(str(value)), "hash_scheme": evidence_hash_scheme(), "raw_returned": False}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
