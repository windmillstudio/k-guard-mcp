from __future__ import annotations

import copy
import hashlib
import json

import pytest

from k_guard_mcp.pair_admission import (
    FAMILY_POLICIES,
    KPRIV_REQUIRED_FIELDS,
    canonical_admission_result,
    pair_subject_sha256,
    validate_kpriv_manifest,
    validate_pair_admission as _validate_pair_admission,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


VERIFIER_SHA256 = _sha("verifier")


def validate_pair_admission(manifest: object) -> dict:
    return _validate_pair_admission(
        manifest,
        expected_verifier_sha256=VERIFIER_SHA256,
    )


def _evidence(name: str, observable_type: str = "config_key") -> dict:
    return {
        "observable_type": observable_type,
        "path": f"evidence/{name}.json",
        "selector": f"$.{name}",
        "content_sha256": _sha(name),
    }


def _kpriv() -> dict:
    return {
        "schema": "KPRIV-v1",
        "legal_inconclusive": False,
        "claim_boundary": {
            "risk_signals_only": True,
            "legal_compliance_proved": False,
            "legal_advice": False,
        },
        "legal_sources": [
            {
                "authority": "Personal Information Protection Commission",
                "effective_date": "2026-07-18",
                "content_sha256": _sha("law-content"),
                "source_url_sha256": _sha("law-url"),
            }
        ],
        "required_fields": {
            field: {"outcome": "pass", "evidence": [_evidence(field)]}
            for field in KPRIV_REQUIRED_FIELDS
        },
        "forbidden_contradictions": [],
        "source_to_policy_consistent": True,
        "retention_evidence": [_evidence("retention", "retention_job")],
        "deletion_evidence": [_evidence("deletion", "deletion_job")],
        "config_evidence": [_evidence("config")],
    }


def _change(family: str) -> dict:
    values = {
        "source_flow": ("src/handler.py", "production", "guard", "ast.guard.request_input"),
        "auth_rls_db": ("db/policies.sql", "policy", "ddl_policy_statement", "ddl.rls.tenant_policy"),
        "dependency_sca": ("package.json", "manifest", "manifest_entry", "dependency.manifest.library"),
        "gha_docker_iac": (".github/workflows/ci.yml", "workflow", "workflow_step", "config.workflow.permissions"),
        "policy_kpriv": ("config/privacy.json", "config", "config_key", "kpriv.retention_and_deletion.days"),
    }
    path, role, kind, selector = values[family]
    row = {
        "path": path,
        "role": role,
        "change_kind": kind,
        "selector": selector,
        "root_cause_ref": "scenario-001",
        "logical_changed_lines": 4,
        "before_sha256": _sha(f"{family}-before"),
        "after_sha256": _sha(f"{family}-after"),
    }
    if family == "gha_docker_iac":
        row["connected_config_keys"] = ["permissions.contents"]
    if family == "policy_kpriv":
        row["kpriv_field"] = "retention_and_deletion"
    return row


def _manifest(family: str = "source_flow") -> dict:
    exploit = _sha("exploit-command")
    regression = _sha("regression-command")
    negative = _sha("negative-command")
    payload = {
        "schema": "k_guard_generated_pair_admission.v1",
        "family": family,
        "lineage_id": f"generated-{family}-001",
        "label_locked_before_scanner_output": True,
        "provenance": {
            "model": "deterministic-template",
            "version": "1.0.0",
            "prompt_sha256": _sha("prompt"),
            "seed": 7,
            "sampling": {"temperature": 0, "strategy": "deterministic"},
            "generator_commit": "a" * 40,
            "dependency_sha256": _sha("dependencies"),
            "framework": "fixture",
            "language": "python",
            "plane": "data" if family == "policy_kpriv" else "site",
            "cwe": "CWE-79",
            "license_spdx": "MIT",
            "source": {"kind": "generated", "identity_sha256": _sha("source-identity")},
        },
        "hashes": {
            "vulnerable_source_sha256": _sha("vulnerable"),
            "fixed_source_sha256": _sha("fixed"),
            "exploit_command_sha256": exploit,
            "regression_command_sha256": regression,
            "negative_control_command_sha256": negative,
            "diff_command_sha256": _sha("diff-command"),
            "invariants_command_sha256": _sha("invariants-command"),
        },
        "executions": {
            "exploit_vulnerable": {
                "executed": True,
                "harness_passed": True,
                "exit_code": 0,
                "command_sha256": exploit,
                "result_sha256": _sha("vulnerable-result"),
                "exploit_succeeded": True,
            },
            "exploit_fixed": {
                "executed": True,
                "harness_passed": True,
                "exit_code": 0,
                "command_sha256": exploit,
                "result_sha256": _sha("fixed-result"),
                "exploit_succeeded": False,
            },
            "fixed_functional": {
                "executed": True,
                "harness_passed": True,
                "exit_code": 0,
                "command_sha256": regression,
                "result_sha256": _sha("functional-result"),
                "functional_passed": True,
            },
            "negative_control": {
                "executed": True,
                "harness_passed": True,
                "exit_code": 0,
                "command_sha256": negative,
                "result_sha256": _sha("negative-result"),
                "control_triggered": False,
            },
        },
        "diff": {"production_changes": [_change(family)]},
        "invariants": {
            "route_inventory_unchanged": True,
            "public_api_shape_unchanged": True,
            "schema_unchanged": True,
            "unrelated_dependencies_unchanged": True,
            "feature_flags_unchanged": True,
            "logging_unchanged": True,
            "build_options_unchanged": True,
            "build_passed": True,
            "functional_snapshot_equal": True,
        },
        "test_oracle_files": [
            {
                "path": f"tests/{role}.json",
                "content_sha256": _sha(role),
                "role": role,
            }
            for role in ("exploit", "negative_control", "oracle", "regression")
        ],
    }
    if family == "policy_kpriv":
        payload["kpriv"] = _kpriv()
    payload["verification"] = {
        "schema": "k_guard_pair_evidence_verification.v2",
        "verified": True,
        "verifier_id": "k-guard-pair-materializer",
        "verifier_version": "2.0.0",
        "verifier_sha256": VERIFIER_SHA256,
        "runtime_image_reference": "kguard/pair-runtime@sha256:" + "1" * 64,
        "runtime_image_id": "sha256:" + "2" * 64,
        "plan_sha256": _sha("verification-plan"),
        "evidence_bundle_sha256": _sha("evidence-bundle"),
        "subject_sha256": pair_subject_sha256(payload),
        "source_receipts_sha256": _sha("source-receipts"),
        "execution_receipts_sha256": _sha("execution-receipts"),
        "diff_receipt_sha256": _sha("diff-receipt"),
        "invariants_receipt_sha256": _sha("invariants-receipt"),
        "files_rehashed": True,
        "commands_executed": True,
        "diff_recomputed": True,
        "invariants_recomputed": True,
        "isolated_execution": True,
        "network_disabled": True,
        "snapshot_replayed": True,
        "raw_sensitive_output_returned": False,
    }
    return payload


@pytest.mark.parametrize("family", sorted(FAMILY_POLICIES))
def test_every_bounded_causal_patch_family_is_schema_valid_but_not_live_admitted(family: str) -> None:
    result = validate_pair_admission(_manifest(family))
    assert result["schema_valid"] is True
    assert result["live_replay_proved"] is False
    assert result["errors"] == []
    assert result["status"] == "schema_valid_pending_live_replay"


def test_dependency_lockfile_hunk_must_be_deterministic() -> None:
    manifest = _manifest("dependency_sca")
    lock_change = copy.deepcopy(manifest["diff"]["production_changes"][0])
    lock_change.update(
        {
            "path": "package-lock.json",
            "role": "lockfile",
            "change_kind": "lockfile_dependency_hunk",
            "selector": "dependency.lockfile.library",
            "before_sha256": _sha("lock-before"),
            "after_sha256": _sha("lock-after"),
            "deterministically_generated": False,
        }
    )
    manifest["diff"]["production_changes"].append(lock_change)
    result = validate_pair_admission(manifest)
    assert result["schema_valid"] is False
    assert "diff:production_changes[1]:lockfile_not_deterministic" in result["errors"]


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (lambda m: m["diff"]["production_changes"][0].update(logical_changed_lines=26), "diff:line_limit_exceeded:26>25"),
        (lambda m: m["diff"]["production_changes"][0].update(selector="ast.unrelated.logging"), "diff:production_changes[0]:selector_not_allowlisted"),
        (lambda m: m["diff"]["production_changes"][0].update(path="../escape.py"), "diff:production_changes[0]:path_invalid"),
        (lambda m: m["invariants"].update(logging_unchanged=False), "invariants:logging_unchanged_not_true"),
        (lambda m: m["hashes"].update(vulnerable_source_sha256="not-a-hash"), "hashes:vulnerable_source_sha256_invalid"),
        (lambda m: m["executions"]["exploit_fixed"].update(exploit_succeeded=True), "executions:exploit_fixed:exploit_succeeded_invalid"),
        (lambda m: m["executions"]["fixed_functional"].update(functional_passed=False), "executions:fixed_functional:functional_passed_invalid"),
    ],
)
def test_pair_admission_rejects_unbounded_unrelated_or_unproved_changes(mutation, error: str) -> None:
    manifest = _manifest()
    mutation(manifest)
    result = validate_pair_admission(manifest)
    assert result["schema_valid"] is False
    assert result["status"] == "rejected_fail_closed"
    assert error in result["errors"]


def test_pair_admission_rejects_file_limit_and_command_hash_rebinding() -> None:
    manifest = _manifest()
    for index in range(2):
        row = copy.deepcopy(manifest["diff"]["production_changes"][0])
        row["path"] = f"src/extra_{index}.py"
        row["before_sha256"] = _sha(f"before-{index}")
        row["after_sha256"] = _sha(f"after-{index}")
        manifest["diff"]["production_changes"].append(row)
    manifest["executions"]["exploit_vulnerable"]["command_sha256"] = _sha("rebound")
    result = validate_pair_admission(manifest)
    assert "diff:file_limit_exceeded:3>2" in result["errors"]
    assert "executions:exploit_vulnerable:command_hash_mismatch" in result["errors"]


def test_kpriv_is_machine_observable_and_legal_uncertainty_fails_closed() -> None:
    manifest = _kpriv()
    assert validate_kpriv_manifest(manifest)["passed"] is True

    manifest["legal_inconclusive"] = True
    manifest["required_fields"]["cross_border_transfer"]["evidence"] = []
    manifest["forbidden_contradictions"] = ["retention policy conflicts with config"]
    result = validate_kpriv_manifest(manifest)
    assert result["passed"] is False
    assert result["status"] == "inconclusive_fail_closed"
    assert result["errors"] == sorted(result["errors"])
    assert "manifest:legal_inconclusive" in result["errors"]
    assert "required_fields:cross_border_transfer:evidence:missing" in result["errors"]
    assert "forbidden_contradictions:not_empty_list" in result["errors"]


def test_policy_pair_rejects_missing_field_bad_observable_and_selector_mismatch() -> None:
    manifest = _manifest("policy_kpriv")
    del manifest["kpriv"]["required_fields"]["backup"]
    manifest["kpriv"]["config_evidence"][0]["observable_type"] = "ai_opinion"
    manifest["diff"]["production_changes"][0]["kpriv_field"] = "encryption"
    result = validate_pair_admission(manifest)
    assert result["schema_valid"] is False
    assert "kpriv:required_fields:backup:missing" in result["errors"]
    assert "kpriv:config_evidence[0]:observable_type_invalid" in result["errors"]
    assert "diff:production_changes[0]:kpriv_selector_mismatch" in result["errors"]


def test_result_is_deterministic_and_malformed_input_never_raises() -> None:
    first = validate_pair_admission({"schema": "wrong", "family": "unknown"})
    second = validate_pair_admission({"family": "unknown", "schema": "wrong"})
    assert canonical_admission_result(first) == canonical_admission_result(second)
    assert validate_pair_admission(None)["status"] == "rejected_fail_closed"
    assert json.loads(canonical_admission_result(first))["schema_valid"] is False


def test_malformed_provenance_execution_and_hash_contracts_fail_closed() -> None:
    manifest = _manifest()
    manifest["provenance"].update(
        {
            "generator_commit": "bad",
            "seed": -1,
            "sampling": {"temperature": True, "strategy": ""},
            "license_spdx": "not valid!",
            "source": None,
        }
    )
    manifest["hashes"]["fixed_source_sha256"] = manifest["hashes"]["vulnerable_source_sha256"]
    manifest["executions"]["exploit_vulnerable"] = None
    manifest["executions"]["exploit_fixed"].update(
        {"executed": False, "harness_passed": False, "exit_code": 1, "result_sha256": "bad"}
    )
    result = validate_pair_admission(manifest)
    expected = {
        "provenance:generator_commit_invalid",
        "provenance:seed_invalid",
        "provenance:sampling_temperature_invalid",
        "provenance:sampling:strategy_invalid",
        "provenance:license_spdx_invalid",
        "provenance:source_not_object",
        "hashes:source_pair_identical",
        "executions:exploit_vulnerable:not_object",
        "executions:exploit_fixed:not_executed",
        "executions:exploit_fixed:harness_failed",
        "executions:exploit_fixed:exit_code_invalid",
        "executions:exploit_fixed:result_sha256_invalid",
    }
    assert expected <= set(result["errors"])

    manifest = _manifest()
    manifest["provenance"]["sampling"] = None
    manifest["provenance"]["source"] = {"kind": "", "identity_sha256": "bad"}
    result = validate_pair_admission(manifest)
    assert "provenance:sampling_not_object" in result["errors"]
    assert "provenance:source_kind_invalid" in result["errors"]
    assert "provenance:source_identity_sha256_invalid" in result["errors"]


def test_diff_shape_and_family_cardinality_are_strict() -> None:
    manifest = _manifest()
    manifest["diff"] = None
    assert "diff:not_object" in validate_pair_admission(manifest)["errors"]

    manifest = _manifest()
    manifest["diff"]["production_changes"] = []
    assert "diff:production_changes_missing" in validate_pair_admission(manifest)["errors"]

    manifest = _manifest()
    first = manifest["diff"]["production_changes"][0]
    duplicate = copy.deepcopy(first)
    duplicate.update(
        {
            "logical_changed_lines": 0,
            "role": "test",
            "change_kind": "logging",
            "before_sha256": first["after_sha256"],
            "after_sha256": first["after_sha256"],
        }
    )
    manifest["diff"]["production_changes"].extend([None, duplicate])
    result = validate_pair_admission(manifest)
    expected = {
        "diff:production_changes[1]:not_object",
        "diff:production_changes[2]:duplicate_path",
        "diff:production_changes[2]:logical_changed_lines_invalid",
        "diff:production_changes[2]:role_not_allowed",
        "diff:production_changes[2]:change_kind_not_allowed",
        "diff:production_changes[2]:content_unchanged",
    }
    assert expected <= set(result["errors"])

    dependency = _manifest("dependency_sca")
    dependency["diff"]["production_changes"][0]["change_kind"] = "lockfile_dependency_hunk"
    dependency["diff"]["production_changes"][0]["deterministically_generated"] = True
    second = copy.deepcopy(dependency["diff"]["production_changes"][0])
    second.update(path="other.lock", before_sha256=_sha("b"), after_sha256=_sha("a"))
    dependency["diff"]["production_changes"].append(second)
    result = validate_pair_admission(dependency)
    assert "diff:dependency_manifest_entry_count_invalid" in result["errors"]
    assert "diff:dependency_lockfile_hunk_count_invalid" in result["errors"]

    infrastructure = _manifest("gha_docker_iac")
    infrastructure["diff"]["production_changes"][0]["connected_config_keys"] = []
    assert "diff:production_changes[0]:connected_config_keys_missing" in validate_pair_admission(infrastructure)["errors"]
    infrastructure["diff"]["production_changes"].append(copy.deepcopy(infrastructure["diff"]["production_changes"][0]))
    assert "diff:infrastructure_root_change_count_invalid" in validate_pair_admission(infrastructure)["errors"]

    policy = _manifest("policy_kpriv")
    policy["diff"]["production_changes"][0].pop("kpriv_field")
    assert "diff:production_changes[0]:kpriv_field_invalid" in validate_pair_admission(policy)["errors"]


def test_test_oracle_inventory_rejects_bad_and_duplicate_rows() -> None:
    manifest = _manifest()
    manifest["test_oracle_files"] = []
    assert "test_oracle_files:missing" in validate_pair_admission(manifest)["errors"]

    manifest = _manifest()
    original = manifest["test_oracle_files"][0]
    manifest["test_oracle_files"] = [None, original, {**original, "role": "other", "content_sha256": "bad"}]
    result = validate_pair_admission(manifest)
    expected = {
        "test_oracle_files[0]:not_object",
        "test_oracle_files[2]:duplicate_path",
        "test_oracle_files[2]:content_sha256_invalid",
        "test_oracle_files[2]:role_invalid",
    }
    assert expected <= set(result["errors"])


def test_kpriv_all_nested_contract_failures_are_explicit() -> None:
    assert validate_kpriv_manifest(None)["errors"] == ["manifest:not_object"]

    manifest = _kpriv()
    manifest.update(
        {
            "schema": "wrong",
            "claim_boundary": None,
            "legal_sources": [],
            "required_fields": None,
            "source_to_policy_consistent": False,
            "retention_evidence": [],
        }
    )
    result = validate_kpriv_manifest(manifest)
    expected = {
        "manifest:schema_invalid",
        "claim_boundary:not_object",
        "legal_sources:missing",
        "required_fields:not_object",
        "source_to_policy_consistent:not_true",
        "retention_evidence:missing",
    }
    assert expected <= set(result["errors"])
    manifest = _kpriv()
    manifest["claim_boundary"] = {
        "risk_signals_only": False,
        "legal_compliance_proved": True,
        "legal_advice": True,
    }
    manifest["legal_sources"] = [None, {"authority": "", "effective_date": "18-07-2026"}]
    manifest["required_fields"]["unknown"] = {"outcome": "pass", "evidence": [_evidence("x")]}
    manifest["required_fields"]["access_logs"] = None
    manifest["required_fields"]["encryption"] = {"outcome": "warn", "evidence": [None]}
    manifest["config_evidence"] = [
        {"observable_type": "config_key", "path": "../outside", "selector": "", "content_sha256": "bad"}
    ]
    result = validate_kpriv_manifest(manifest)
    expected = {
        "claim_boundary:risk_signals_only_invalid",
        "claim_boundary:legal_compliance_proved_invalid",
        "claim_boundary:legal_advice_invalid",
        "legal_sources[0]:not_object",
        "legal_sources[1]:authority_invalid",
        "legal_sources[1]:effective_date_invalid",
        "legal_sources[1]:content_sha256_invalid",
        "legal_sources[1]:source_url_sha256_invalid",
        "required_fields:unknown:unknown",
        "required_fields:access_logs:not_object",
        "required_fields:encryption:outcome_not_pass",
        "required_fields:encryption:evidence[0]:not_object",
        "config_evidence[0]:path_invalid",
        "config_evidence[0]:selector_invalid",
        "config_evidence[0]:content_sha256_invalid",
    }
    assert expected <= set(result["errors"])


def test_pair_requires_recomputed_verifier_receipt_and_valid_calendar_date() -> None:
    manifest = _manifest()
    manifest.pop("verification")
    assert "verification:not_object" in validate_pair_admission(manifest)["errors"]

    manifest = _manifest()
    manifest["lineage_id"] = "tampered-after-verification"
    assert "verification:subject_hash_mismatch" in validate_pair_admission(manifest)["errors"]

    manifest = _manifest()
    wrong_pin = _validate_pair_admission(
        manifest,
        expected_verifier_sha256="b" * 64,
    )
    assert "verification:verifier_not_preregistered" in wrong_pin["errors"]

    manifest = _manifest()
    manifest["verification"].pop("network_disabled")
    manifest["verification"]["snapshot_replayed"] = False
    manifest["verification"]["raw_sensitive_output_returned"] = True
    result = validate_pair_admission(manifest)
    assert "verification:fields_invalid" in result["errors"]
    assert "verification:snapshot_replayed_not_true" in result["errors"]
    assert "verification:raw_sensitive_output_returned_not_false" in result["errors"]

    manifest = _manifest()
    manifest["verification"]["schema"] = "k_guard_pair_evidence_verification.v1"
    result = validate_pair_admission(manifest)
    assert "verification:schema_invalid" in result["errors"]

    kpriv = _kpriv()
    kpriv["legal_sources"][0]["effective_date"] = "2026-02-31"
    assert "legal_sources[0]:effective_date_invalid" in validate_kpriv_manifest(kpriv)["errors"]
