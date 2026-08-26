from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "replay_l2_webgoat_idor.py"
SPEC = importlib.util.spec_from_file_location("k_guard_l2_webgoat_idor", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
idor = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = idor
SPEC.loader.exec_module(idor)


def _reports(tmp_path: Path, *, suite_tests: str = "2", failed: bool = False) -> tuple[Path, Path]:
    summary = tmp_path / "failsafe-summary.xml"
    suite = tmp_path / f"TEST-{idor.TEST_CLASS}.xml"
    summary.write_text(
        "<failsafe-summary timeout=\"false\"><completed>2</completed><errors>0</errors>"
        "<failures>0</failures><skipped>0</skipped><flakes>0</flakes></failsafe-summary>",
        encoding="utf-8",
    )
    failure = "<failure/>" if failed else ""
    suite.write_text(
        f"<testsuite name=\"{idor.TEST_CLASS}\" tests=\"{suite_tests}\" errors=\"0\" failures=\"0\" skipped=\"0\" flakes=\"0\">"
        f"<testcase name=\"testIDORLesson()[1]\">{failure}</testcase><testcase name=\"testIDORLesson()[2]\"/></testsuite>",
        encoding="utf-8",
    )
    return summary, suite


def _negative_control_reports(tmp_path: Path, *, failed_case: str = "testIDORLesson()[2]") -> tuple[Path, Path]:
    summary = tmp_path / "failsafe-summary.xml"
    suite = tmp_path / f"TEST-{idor.TEST_CLASS}.xml"
    summary.write_text(
        "<failsafe-summary timeout=\"false\"><completed>3</completed><errors>0</errors>"
        "<failures>2</failures><skipped>0</skipped><flakes>0</flakes></failsafe-summary>",
        encoding="utf-8",
    )
    first = "<failure/>" if failed_case == "testIDORLesson()[1]" else ""
    second = "<failure/>" if failed_case == "testIDORLesson()[2]" else ""
    suite.write_text(
        f"<testsuite name=\"{idor.TEST_CLASS}\" tests=\"3\" errors=\"0\" failures=\"2\" skipped=\"0\" flakes=\"0\">"
        "<testcase name=\"testIDORLesson\"><failure/></testcase>"
        f"<testcase name=\"testIDORLesson()[1]\">{first}</testcase>"
        f"<testcase name=\"testIDORLesson()[2]\">{second}</testcase></testsuite>",
        encoding="utf-8",
    )
    return summary, suite


def _run() -> dict:
    isolation = {
        "checks": {"network_none": True, "no_host_port_publish": True},
        "passed": True,
        "raw_returned": False,
    }
    normalized = {
        "schema": idor.RESULT_SCHEMA,
        "test_class": idor.TEST_CLASS,
        "failsafe": {"completed": 2, "errors": 0, "failures": 0, "skipped": 0, "flakes": 0, "timeout": False},
        "suite": {"tests": 2, "errors": 0, "failures": 0, "skipped": 0, "flakes": 0, "testcase_count": 2, "all_cases_passed": True},
        "raw_returned": False,
    }
    return {
        "run_nonce_sha256": "a" * 64,
        "image_id": "sha256:" + "b" * 64,
        "maven_command_sha256": "c" * 64,
        "network_policy": "none",
        "isolation": isolation,
        "execution": {"returncode": 0},
        "normalized_result": normalized,
        "report_hashes": {"summary_sha256": "d" * 64, "suite_sha256": "e" * 64},
        "cleanup": {"passed": True},
        "passed": True,
        "raw_returned": False,
    }


def _receipt(status: str = "EXECUTION_CONTRACT_PASS") -> dict:
    one = _run()
    two = copy.deepcopy(one)
    two["run_nonce_sha256"] = "f" * 64
    receipt = {
        "schema": idor.SCHEMA,
        "tool_provenance": {"runner_sha256": "1" * 64, "base_image": idor.BASE_IMAGE, "raw_returned": False},
        "source": {"repository_id": idor.REPOSITORY_ID},
        "image": {"image_id": one["image_id"]},
        "runs": [one, two],
        "consensus": {
            "run_count": 2,
            "two_runs_byte_equivalent_after_normalization": True,
            "projection_sha256": "2" * 64,
            "raw_returned": False,
        },
        "image_cleanup": {"passed": True},
        "claim_boundary": idor._claim_boundary(),
        "admission_blockers": [
            "evidence_signature_missing",
            "negative_control_missing",
            "scanner_finding_mapping_missing",
            "source_bound_severity_rubric_missing",
        ],
        "execution_contract_status": status,
        "release_gate_passed": False,
        "failure_code": None,
        "raw_returned": False,
    }
    return receipt


def _positive_receipt() -> dict:
    receipt = _receipt()
    receipt["source"] = {
        "repository_id": idor.REPOSITORY_ID,
        "commit": idor.SOURCE_COMMIT,
        "commit_tree": idor.SOURCE_TREE,
        "source_tree_sha256": idor.SOURCE_TREE_SHA256,
        "source_receipt_sha256": "a" * 64,
    }
    return receipt


def _control_run() -> dict:
    run = _run()
    run["expected_exit_code"] = idor.NEGATIVE_CONTROL_EXPECTED_EXIT_CODE
    run["execution"] = {"returncode": idor.NEGATIVE_CONTROL_EXPECTED_EXIT_CODE}
    run["normalized_result"] = {
        "schema": idor.NEGATIVE_CONTROL_RESULT_SCHEMA,
        "test_class": idor.TEST_CLASS,
        "failsafe": {"completed": 3, "errors": 0, "failures": 2, "skipped": 0, "flakes": 0, "timeout": False},
        "suite": {"tests": 3, "errors": 0, "failures": 2, "skipped": 0, "flakes": 0, "testcase_count": 3, "all_cases_passed": False},
        "control_triggered": True,
        "case_outcomes": [
            {"name": name, "outcome": outcome}
            for name, outcome in idor.NEGATIVE_CONTROL_CASE_OUTCOMES
        ],
        "raw_returned": False,
    }
    return run


def _control_receipt(status: str = "NEGATIVE_CONTROL_PASS") -> dict:
    first = _control_run()
    second = copy.deepcopy(first)
    second["run_nonce_sha256"] = "f" * 64
    control = {
        "patch_id": idor.NEGATIVE_CONTROL_PATCH_ID,
        "source_path": idor.NEGATIVE_CONTROL_SOURCE_PATH.as_posix(),
        "original_file_sha256": "1" * 64,
        "patched_file_sha256": "2" * 64,
        "patch_sha256": "3" * 64,
        "variant_tree_sha256": "4" * 64,
        "source_checkout_mutated": False,
        "raw_returned": False,
    }
    projections = [idor._consensus_projection(first), idor._consensus_projection(second)]
    return {
        "schema": idor.NEGATIVE_CONTROL_SCHEMA,
        "tool_provenance": {"runner_sha256": "5" * 64, "raw_returned": False},
        "source": {"source_receipt_sha256": "a" * 64},
        "positive_execution_contract": {
            "receipt_sha256": idor.POSITIVE_EXECUTION_RECEIPT_SHA256,
            "source_receipt_sha256": "a" * 64,
            "execution_contract_status": "EXECUTION_CONTRACT_PASS",
            "raw_returned": False,
        },
        "negative_control": control,
        "image": {"image_id": first["image_id"], "source_variant": control},
        "runs": [first, second],
        "consensus": {
            "run_count": 2,
            "two_runs_byte_equivalent_after_normalization": True,
            "projection_sha256": idor._canonical_sha256(projections),
            "raw_returned": False,
        },
        "image_cleanup": {"passed": True},
        "claim_boundary": idor._negative_control_claim_boundary(),
        "admission_blockers": list(idor.NEGATIVE_CONTROL_ADMISSION_BLOCKERS),
        "negative_control_status": status,
        "release_gate_passed": False,
        "failure_code": None,
        "raw_returned": False,
    }


def test_normalizes_expected_failsafe_reports(tmp_path: Path) -> None:
    normalized, hashes = idor.normalize_failsafe_reports(*_reports(tmp_path))

    assert normalized["test_class"] == idor.TEST_CLASS
    assert normalized["failsafe"]["completed"] == 2
    assert normalized["suite"]["all_cases_passed"] is True
    assert set(hashes) == {"summary_sha256", "suite_sha256"}


@pytest.mark.parametrize("suite_tests,failed", [("1", False), ("2", True)])
def test_rejects_non_passing_or_non_matching_failsafe_reports(
    tmp_path: Path, suite_tests: str, failed: bool
) -> None:
    with pytest.raises(idor.RuntimeContractError):
        idor.normalize_failsafe_reports(*_reports(tmp_path, suite_tests=suite_tests, failed=failed))


def test_normalizes_the_single_expected_negative_control_failure(tmp_path: Path) -> None:
    normalized, hashes = idor.normalize_negative_control_failsafe_reports(*_negative_control_reports(tmp_path))

    assert normalized["schema"] == idor.NEGATIVE_CONTROL_RESULT_SCHEMA
    assert normalized["control_triggered"] is True
    assert normalized["suite"]["all_cases_passed"] is False
    assert normalized["case_outcomes"] == [
        {"name": name, "outcome": outcome}
        for name, outcome in idor.NEGATIVE_CONTROL_CASE_OUTCOMES
    ]
    assert set(hashes) == {"summary_sha256", "suite_sha256"}


def test_negative_control_rejects_failure_at_any_other_dynamic_case(tmp_path: Path) -> None:
    with pytest.raises(idor.RuntimeContractError, match="failsafe_case_outcome_invalid"):
        idor.normalize_negative_control_failsafe_reports(
            *_negative_control_reports(tmp_path, failed_case="testIDORLesson()[1]")
        )


def test_raw_free_failsafe_summary_retains_only_case_outcomes_and_counts(tmp_path: Path) -> None:
    observed, hashes = idor.summarize_failsafe_reports(
        *_negative_control_reports(tmp_path, failed_case="testIDORLesson()[1]")
    )

    assert observed["failsafe"]["failures"] == 2
    assert observed["suite"]["testcase_count"] == 3
    assert observed["case_outcomes"] == [
        {"name": "testIDORLesson", "outcome": "failure"},
        {"name": "testIDORLesson()[1]", "outcome": "failure"},
        {"name": "testIDORLesson()[2]", "outcome": "pass"},
    ]
    assert observed["raw_returned"] is False
    assert set(hashes) == {"summary_sha256", "suite_sha256"}


def test_negative_control_patch_is_single_anchor_and_leaves_original_workspace_outside_copy_untouched(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    target = source_root / idor.NEGATIVE_CONTROL_SOURCE_PATH
    target.parent.mkdir(parents=True)
    original = (
        b"class Fixture {\n"
        b"    if (userSubmittedProfile.getUserId() != null\n"
        b"        && !userSubmittedProfile.getUserId().equals(authUserId)) {\n"
        b"      vulnerable();\n"
        b"    } else if (userSubmittedProfile.getUserId() != null\n"
        b"        && userSubmittedProfile.getUserId().equals(authUserId)) {\n"
        b"      ownProfile();\n"
        b"    }\n"
        b"}\n"
    )
    target.write_bytes(original)

    class Verifier:
        def capture_materialized_tree(self, _root: Path) -> dict[str, str]:
            return {"tree_sha256": "f" * 64}

    control = idor._apply_negative_control_patch(source_root, Verifier())

    patched = target.read_bytes()
    assert control["patch_id"] == idor.NEGATIVE_CONTROL_PATCH_ID
    assert control["source_checkout_mutated"] is False
    assert patched.count(b"return failed(this).feedback(\"idor.edit.profile.failure4\").build();") == 1
    assert patched.count(b"Boolean.FALSE.booleanValue()") == 1
    assert original != patched


def test_positive_execution_reference_requires_a_canonical_passing_same_source_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = _positive_receipt()
    path = tmp_path / "positive.json"
    raw = idor.canonical_json_bytes(receipt)
    path.write_bytes(raw)
    monkeypatch.setattr(
        idor,
        "_expected_positive_execution_tool_provenance",
        lambda: receipt["tool_provenance"],
    )

    reference = idor._load_positive_execution_contract(path)

    assert reference["execution_contract_status"] == "EXECUTION_CONTRACT_PASS"
    assert reference["source_receipt_sha256"] == "a" * 64


def test_positive_execution_reference_rejects_stale_tool_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = _positive_receipt()
    path = tmp_path / "positive.json"
    raw = idor.canonical_json_bytes(receipt)
    path.write_bytes(raw)
    monkeypatch.setattr(
        idor,
        "_expected_positive_execution_tool_provenance",
        lambda: {**receipt["tool_provenance"], "runner_sha256": "f" * 64},
    )

    with pytest.raises(idor.RuntimeContractError, match="positive_execution_tool_provenance_mismatch"):
        idor._load_positive_execution_contract(path)


def test_dockerfile_bakes_a_pinned_source_derived_warmup() -> None:
    assert f"FROM {idor.BASE_IMAGE}" in idor.DOCKERFILE_TEMPLATE
    assert "USER 65532:65532" in idor.DOCKERFILE_TEMPLATE
    assert f"-Dit.test={idor.TEST_CLASS}" in idor.DOCKERFILE_TEMPLATE
    assert "-Dtest=__kguard_no_unit__" in idor.DOCKERFILE_TEMPLATE
    assert "/evidence" in idor.DOCKERFILE_TEMPLATE
    assert "/evidence/" in idor.RUNTIME_COMMAND
    assert "exit 0" in idor.NEGATIVE_CONTROL_DOCKERFILE_TEMPLATE
    assert idor.NEGATIVE_CONTROL_LABEL in idor.NEGATIVE_CONTROL_DOCKERFILE_TEMPLATE


def test_default_admission_blockers_are_sorted_and_never_empty() -> None:
    assert idor.ADMISSION_BLOCKERS == tuple(sorted(idor.ADMISSION_BLOCKERS))
    assert idor.ADMISSION_BLOCKERS


def test_consensus_projection_ignores_nonce_but_not_execution_result() -> None:
    first = _run()
    second = copy.deepcopy(first)
    second["run_nonce_sha256"] = "f" * 64
    assert idor._consensus_projection(first) == idor._consensus_projection(second)

    second["normalized_result"]["suite"]["tests"] = 1
    assert idor._consensus_projection(first) != idor._consensus_projection(second)


def test_rejects_unexpected_dynamic_test_case_identity(tmp_path: Path) -> None:
    summary, suite = _reports(tmp_path)
    suite.write_text(
        f"<testsuite name=\"{idor.TEST_CLASS}\" tests=\"2\" errors=\"0\" failures=\"0\" skipped=\"0\" flakes=\"0\">"
        "<testcase name=\"unexpected\"/><testcase name=\"also-unexpected\"/></testsuite>",
        encoding="utf-8",
    )
    with pytest.raises(idor.RuntimeContractError, match="failsafe_case_outcome_invalid"):
        idor.normalize_failsafe_reports(summary, suite)


def test_rejects_dtd_bearing_failsafe_reports(tmp_path: Path) -> None:
    summary, suite = _reports(tmp_path)
    summary.write_text("<!DOCTYPE x><failsafe-summary/>", encoding="utf-8")
    with pytest.raises(idor.RuntimeContractError, match="failsafe_report_dtd_forbidden"):
        idor.normalize_failsafe_reports(summary, suite)


def test_receipt_accepts_execution_contract_only() -> None:
    receipt = _receipt()
    idor.validate_receipt(receipt)
    assert receipt["claim_boundary"]["tp_fp_fn_admitted"] is False
    assert receipt["release_gate_passed"] is False


def test_receipt_rejects_pass_without_exact_two_run_consensus() -> None:
    receipt = _receipt()
    receipt["runs"][1]["normalized_result"]["suite"]["tests"] = 1
    with pytest.raises(idor.RuntimeContractError, match="receipt_consensus_invalid"):
        idor.validate_receipt(receipt)


def test_receipt_rejects_release_or_metric_promotion() -> None:
    receipt = _receipt()
    receipt["claim_boundary"]["tp_fp_fn_admitted"] = True
    with pytest.raises(idor.RuntimeContractError, match="receipt_claim_boundary_invalid"):
        idor.validate_receipt(receipt)


def test_receipt_rejects_missing_or_extra_admission_blockers() -> None:
    receipt = _receipt()
    receipt["admission_blockers"] = list(idor.ADMISSION_BLOCKERS[:-1])
    with pytest.raises(idor.RuntimeContractError, match="receipt_admission_blockers_invalid"):
        idor.validate_receipt(receipt)


def test_negative_control_receipt_accepts_execution_only_contract() -> None:
    receipt = _control_receipt()

    idor.validate_negative_control_receipt(receipt)
    assert receipt["claim_boundary"]["tp_fp_fn_admitted"] is False
    assert receipt["release_gate_passed"] is False


def test_negative_control_receipt_rejects_wrong_exit_or_missing_control_trigger() -> None:
    receipt = _control_receipt()
    receipt["runs"][1]["execution"]["returncode"] = 0

    with pytest.raises(idor.RuntimeContractError, match="negative_control_consensus_invalid"):
        idor.validate_negative_control_receipt(receipt)

    receipt = _control_receipt()
    receipt["claim_boundary"]["tp_fp_fn_admitted"] = True
    with pytest.raises(idor.RuntimeContractError, match="negative_control_claim_boundary_invalid"):
        idor.validate_negative_control_receipt(receipt)


def test_negative_control_receipt_preserves_a_prebuild_hold_without_promoting_it() -> None:
    receipt = _control_receipt("HOLD")
    receipt["negative_control"] = None
    receipt["image"] = None
    receipt["runs"] = []
    receipt["consensus"] = {
        "run_count": 0,
        "two_runs_byte_equivalent_after_normalization": False,
        "projection_sha256": None,
        "raw_returned": False,
    }
    receipt["image_cleanup"] = None
    receipt["failure_code"] = "source_derived_image_build_failed"

    idor.validate_negative_control_receipt(receipt)
    assert receipt["negative_control_status"] == "HOLD"
    assert receipt["release_gate_passed"] is False


def test_owned_cleanup_does_not_treat_created_resource_inspect_errors_as_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def docker(arguments: list[str], **_kwargs: object) -> idor.CommandResult:
        assert tuple(arguments[:2]) in {("container", "inspect"), ("volume", "inspect")}
        return idor.CommandResult(1, b"", b"not found", False, False)

    monkeypatch.setattr(idor, "_docker", docker)
    result = idor._owned_cleanup(
        work_root=tmp_path,
        container_name="kguard-test",
        volume_names=("kguard-created-volume",),
        expected_container_id="a" * 64,
        nonce="nonce",
        created_volume_names={"kguard-created-volume"},
    )

    assert result["container_removed"] is False
    assert result["volumes_removed"] is False
    assert result["passed"] is False
