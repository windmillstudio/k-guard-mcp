from __future__ import annotations

import json
from pathlib import Path

import pytest

from k_guard_mcp.mutation_harness import apply_mutation_plan, evaluate_mutation_pack, write_mutation_plan_template


def _app_and_plan(root: Path) -> tuple[Path, Path]:
    app = root / "app"
    route = app / "src" / "routes" / "profile.ts"
    route.parent.mkdir(parents=True)
    route.write_text(
        "import express from 'express';\n"
        "const router = express.Router();\n"
        "router.get('/profiles/:id', async (req, res) => {\n"
        "  const profile = await db.findUnique({ where: { id: req.params.id, ownerId: req.user.id } });\n"
        "  return res.json(profile);\n"
        "});\n",
        encoding="utf-8",
    )
    plan = root / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "schema": "k_guard_mutation_plan.v1",
                "app_id": "seeded-profile-app",
                "source_scope_ref": "owned-fixture-scope",
                "mutations": [
                    {
                        "mutation_id": "remove-owner-boundary",
                        "relative_path": "src/routes/profile.ts",
                        "find": "id: req.params.id, ownerId: req.user.id",
                        "replace": "id: req.params.id",
                        "expected_rule_ids": ["JS_TS_EXPRESS_IDOR_ROUTE_PARAM"],
                        "severity": "high",
                        "stratum": "mid",
                        "split": "holdout",
                    }
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return app, plan


def test_mutation_harness_copies_before_mutating_and_keeps_report_raw_free(tmp_path):
    app, plan = _app_and_plan(tmp_path)
    original = (app / "src" / "routes" / "profile.ts").read_text(encoding="utf-8")

    report = apply_mutation_plan(app, tmp_path / "pack", plan)

    assert (app / "src" / "routes" / "profile.ts").read_text(encoding="utf-8") == original
    assert "ownerId" in (tmp_path / "pack" / "baseline" / "src" / "routes" / "profile.ts").read_text(encoding="utf-8")
    assert "ownerId" not in (tmp_path / "pack" / "mutated" / "src" / "routes" / "profile.ts").read_text(encoding="utf-8")
    assert report["claim_boundary"]["original_source_was_not_modified"] is True
    serialized = json.dumps(report)
    assert "req.params.id" not in serialized
    assert "ownerId" not in serialized


def test_mutation_harness_rejects_output_inside_source(tmp_path):
    app, plan = _app_and_plan(tmp_path)

    with pytest.raises(ValueError, match="outside and disjoint"):
        apply_mutation_plan(app, app / "mutation-output", plan)


def test_mutation_harness_requires_exactly_one_match(tmp_path):
    app, plan = _app_and_plan(tmp_path)
    payload = json.loads(plan.read_text(encoding="utf-8"))
    payload["mutations"][0]["find"] = "does-not-exist"
    plan.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="exactly one match"):
        apply_mutation_plan(app, tmp_path / "pack", plan)


def test_mutation_evaluation_detects_seeded_idor_without_field_overclaim(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "mutation-harness-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    app, plan = _app_and_plan(tmp_path)
    apply_mutation_plan(app, tmp_path / "pack", plan)

    report = evaluate_mutation_pack(tmp_path / "pack")

    assert report["case_counts"]["false_negative"] == 0
    assert report["rates"]["recall"] == 1.0
    assert report["reproducibility"]["exact_candidate_set_match"] is True
    assert report["reproducibility"]["distinct_execution_ids"] is True
    assert report["reproducibility"]["distinct_execution_attestations"] is True
    assert report["reproducibility"]["distinct_evidence_bundles"] is True
    assert report["reproducibility"]["toolchain_contract_match"] is True
    assert report["reproducibility"]["workspace_source_snapshots_match"] is True
    assert report["reproducibility"]["guardian_manifest_content_match"] is True
    assert report["reproducibility"]["target_input_bindings_match"] is True
    assert report["validation_claim_status"] == "blocked_pilot_not_field_claim"
    assert report["diversity"]["evidence_grade"] == "single_pattern_seeded_regression"
    assert report["claim_boundary"]["build_test_runtime_oracle_verified"] is False
    assert report["claim_boundary"]["does_not_count_as_owned_partner_field_validation"] is True


def test_mutation_plan_template_is_structured_json(tmp_path):
    output = tmp_path / "mutation-plan.json"

    write_mutation_plan_template(output)

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema"] == "k_guard_mutation_plan.v1"
    assert payload["mutations"][0]["expected_rule_ids"] == ["JS_TS_EXPRESS_IDOR_ROUTE_PARAM"]
