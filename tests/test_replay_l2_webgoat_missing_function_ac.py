from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "replay_l2_webgoat_missing_function_ac.py"
SPEC = importlib.util.spec_from_file_location("k_guard_l2_webgoat_missing_function_ac", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
missing_ac = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = missing_ac
SPEC.loader.exec_module(missing_ac)


def _reports(tmp_path: Path, *, negative: bool = False) -> tuple[Path, Path]:
    summary = tmp_path / "failsafe-summary.xml"
    suite = tmp_path / f"TEST-{missing_ac.TEST_CLASS}.xml"
    failures = "1" if negative else "0"
    summary.write_text(
        "<failsafe-summary timeout=\"false\"><completed>1</completed><errors>0</errors>"
        f"<failures>{failures}</failures><skipped>0</skipped><flakes>0</flakes></failsafe-summary>",
        encoding="utf-8",
    )
    failure = "<failure/>" if negative else ""
    suite.write_text(
        f"<testsuite name=\"{missing_ac.TEST_CLASS}\" tests=\"1\" errors=\"0\" failures=\"{failures}\" skipped=\"0\" flakes=\"0\">"
        f"<testcase name=\"testLesson\">{failure}</testcase></testsuite>",
        encoding="utf-8",
    )
    return summary, suite


def _run(*, negative: bool = False) -> dict:
    expected_exit = missing_ac.NEGATIVE_CONTROL_EXPECTED_EXIT_CODE if negative else 0
    normalized = {
        "schema": missing_ac.NEGATIVE_CONTROL_RESULT_SCHEMA if negative else missing_ac.RESULT_SCHEMA,
        "test_class": missing_ac.TEST_CLASS,
        "failsafe": {
            "completed": 1,
            "errors": 0,
            "failures": 1 if negative else 0,
            "skipped": 0,
            "flakes": 0,
            "timeout": False,
        },
        "suite": {
            "tests": 1,
            "errors": 0,
            "failures": 1 if negative else 0,
            "skipped": 0,
            "flakes": 0,
            "testcase_count": 1,
            "all_cases_passed": not negative,
        },
        "raw_returned": False,
    }
    if negative:
        normalized["control_triggered"] = True
        normalized["case_outcomes"] = [
            {"name": name, "outcome": outcome}
            for name, outcome in missing_ac.NEGATIVE_CONTROL_CASE_OUTCOMES
        ]
    return {
        "run_nonce_sha256": "a" * 64,
        "image_id": "sha256:" + "b" * 64,
        "maven_command_sha256": missing_ac.sha256_bytes(missing_ac.MAVEN_ARGUMENTS.encode("utf-8")),
        "runtime_command_sha256": missing_ac.sha256_bytes(missing_ac.RUNTIME_COMMAND.encode("utf-8")),
        "network_policy": "none",
        "expected_exit_code": expected_exit,
        "isolation": {"passed": True, "raw_returned": False},
        "execution": {"returncode": expected_exit},
        "normalized_result": normalized,
        "observed_result": None,
        "report_hashes": {"summary_sha256": "c" * 64, "suite_sha256": "d" * 64},
        "cleanup": {"passed": True, "raw_returned": False},
        "failure_code": None,
        "passed": True,
        "raw_returned": False,
    }


def _source() -> dict:
    return {
        "repository_id": missing_ac.REPOSITORY_ID,
        "commit": missing_ac.SOURCE_COMMIT,
        "commit_tree": missing_ac.SOURCE_TREE,
        "source_tree_sha256": missing_ac.SOURCE_TREE_SHA256,
        "source_receipt_sha256": "e" * 64,
    }


def _provenance() -> dict:
    return {
        "runner_sha256": missing_ac.sha256_bytes(missing_ac.Path(missing_ac.__file__).read_bytes()),
        "shared_runtime_sha256": missing_ac.SHARED_RUNTIME_SHA256,
        "base_image": missing_ac.BASE_IMAGE,
        "raw_returned": False,
    }


def _positive_receipt() -> dict:
    first = _run()
    second = copy.deepcopy(first)
    second["run_nonce_sha256"] = "f" * 64
    projections = [missing_ac._consensus_projection(first), missing_ac._consensus_projection(second)]
    return {
        "schema": missing_ac.SCHEMA,
        "tool_provenance": _provenance(),
        "source": _source(),
        "image": {"base_image": missing_ac.BASE_IMAGE, "source_derived": True, "raw_returned": False},
        "runs": [first, second],
        "consensus": {
            "run_count": 2,
            "two_runs_byte_equivalent_after_normalization": True,
            "projection_sha256": missing_ac._canonical_sha256(projections),
            "raw_returned": False,
        },
        "image_cleanup": {"passed": True, "raw_returned": False},
        "claim_boundary": missing_ac._claim_boundary(),
        "admission_blockers": list(missing_ac.ADMISSION_BLOCKERS),
        "execution_contract_status": "EXECUTION_CONTRACT_PASS",
        "release_gate_passed": False,
        "failure_code": None,
        "raw_returned": False,
    }


def _negative_receipt() -> dict:
    first = _run(negative=True)
    second = copy.deepcopy(first)
    second["run_nonce_sha256"] = "f" * 64
    control = {
        "patch_id": missing_ac.NEGATIVE_CONTROL_PATCH_ID,
        "source_path": missing_ac.NEGATIVE_CONTROL_SOURCE_PATH.as_posix(),
        "original_file_sha256": "1" * 64,
        "patched_file_sha256": "2" * 64,
        "patch_sha256": "3" * 64,
        "variant_tree_sha256": "4" * 64,
        "source_checkout_mutated": False,
        "raw_returned": False,
    }
    projections = [missing_ac._consensus_projection(first), missing_ac._consensus_projection(second)]
    return {
        "schema": missing_ac.NEGATIVE_CONTROL_SCHEMA,
        "tool_provenance": _provenance(),
        "source": _source(),
        "positive_execution_contract": {
            "receipt_sha256": "9" * 64,
            "source_receipt_sha256": "e" * 64,
            "execution_contract_status": "EXECUTION_CONTRACT_PASS",
            "raw_returned": False,
        },
        "negative_control": control,
        "image": {
            "base_image": missing_ac.BASE_IMAGE,
            "source_derived": True,
            "source_variant": control,
            "raw_returned": False,
        },
        "runs": [first, second],
        "consensus": {
            "run_count": 2,
            "two_runs_byte_equivalent_after_normalization": True,
            "projection_sha256": missing_ac._canonical_sha256(projections),
            "raw_returned": False,
        },
        "image_cleanup": {"passed": True, "raw_returned": False},
        "claim_boundary": missing_ac._negative_control_claim_boundary(),
        "admission_blockers": list(missing_ac.NEGATIVE_CONTROL_ADMISSION_BLOCKERS),
        "negative_control_status": "NEGATIVE_CONTROL_PASS",
        "release_gate_passed": False,
        "failure_code": None,
        "raw_returned": False,
    }


def test_normalizes_expected_passing_report(tmp_path: Path) -> None:
    normalized, hashes = missing_ac.normalize_failsafe_reports(*_reports(tmp_path))

    assert normalized["suite"]["all_cases_passed"] is True
    assert normalized["test_class"] == missing_ac.TEST_CLASS
    assert set(hashes) == {"summary_sha256", "suite_sha256"}


def test_normalizes_only_the_expected_negative_control_failure(tmp_path: Path) -> None:
    normalized, _hashes = missing_ac.normalize_negative_control_failsafe_reports(
        *_reports(tmp_path, negative=True)
    )

    assert normalized["control_triggered"] is True
    assert normalized["case_outcomes"] == [{"name": "testLesson", "outcome": "failure"}]


def test_rejects_unexpected_negative_control_outcome(tmp_path: Path) -> None:
    summary, suite = _reports(tmp_path, negative=True)
    suite.write_text(
        f"<testsuite name=\"{missing_ac.TEST_CLASS}\" tests=\"1\" errors=\"1\" failures=\"0\" skipped=\"0\" flakes=\"0\">"
        "<testcase name=\"testLesson\"><error/></testcase></testsuite>",
        encoding="utf-8",
    )

    with pytest.raises(missing_ac.RuntimeContractError, match="failsafe_expected_outcome_mismatch"):
        missing_ac.normalize_negative_control_failsafe_reports(summary, suite)


def test_negative_control_patch_is_single_anchored_copy_only_change(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    target = source_root / missing_ac.NEGATIVE_CONTROL_SOURCE_PATH
    target.parent.mkdir(parents=True)
    original = (
        b"class Fixture {\n"
        b"  public User addUser(@RequestBody User newUser) {\n"
        b"    try {\n"
        b"      userRepository.save(newUser);\n"
        b"    }\n"
        b"  }\n"
        b"}\n"
    )
    target.write_bytes(original)

    class Verifier:
        def capture_materialized_tree(self, _root: Path) -> dict[str, str]:
            return {"tree_sha256": "f" * 64}

    control = missing_ac._apply_negative_control_patch(source_root, Verifier())

    patched = target.read_bytes()
    assert control["source_checkout_mutated"] is False
    assert patched.count(b"newUser.setAdmin(false);") == 1
    assert original != patched


def test_receipts_accept_only_execution_pair_claims() -> None:
    positive = _positive_receipt()
    negative = _negative_receipt()

    missing_ac.validate_receipt(positive)
    missing_ac.validate_negative_control_receipt(
        negative, positive_reference=negative["positive_execution_contract"]
    )
    assert positive["claim_boundary"]["release_gate_admitted"] is False
    assert negative["claim_boundary"]["independent_upstream_fixed_revision_proven"] is False


def test_receipt_rejects_non_consensus_or_foreign_positive_reference() -> None:
    positive = _positive_receipt()
    positive["runs"][1]["normalized_result"]["suite"]["tests"] = 2
    with pytest.raises(missing_ac.RuntimeContractError, match="receipt_run_invalid"):
        missing_ac.validate_receipt(positive)

    negative = _negative_receipt()
    foreign = copy.deepcopy(negative["positive_execution_contract"])
    foreign["receipt_sha256"] = "0" * 64
    with pytest.raises(missing_ac.RuntimeContractError, match="negative_control_positive_reference_invalid"):
        missing_ac.validate_negative_control_receipt(negative, positive_reference=foreign)


def test_hold_receipt_remains_machine_readable_when_execution_never_reaches_a_result() -> None:
    receipt = _positive_receipt()
    receipt["execution_contract_status"] = "HOLD"
    receipt["image"] = None
    receipt["runs"] = []
    receipt["consensus"] = {
        "run_count": 0,
        "two_runs_byte_equivalent_after_normalization": False,
        "projection_sha256": None,
        "raw_returned": False,
    }
    receipt["image_cleanup"] = None

    missing_ac.validate_receipt(receipt)

    receipt["failure_code"] = ""
    with pytest.raises(missing_ac.RuntimeContractError, match="receipt_hold_failure_invalid"):
        missing_ac.validate_receipt(receipt)
