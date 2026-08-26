from __future__ import annotations

import json
from pathlib import Path

from k_guard_mcp import cli
from k_guard_mcp.control_validation import (
    CONTROL_VALIDATION_SCHEMA,
    control_validation_toolchain_contract,
    run_control_validation,
)


def test_control_validation_repeats_exactly_and_covers_both_domains() -> None:
    report = run_control_validation()

    assert report["schema"] == CONTROL_VALIDATION_SCHEMA
    assert report["complete"] is True
    assert report["passed"] is True
    assert report["repeat"]["run_count"] == 2
    assert report["repeat"]["exact"] is True
    assert report["case_count"] == 18
    assert report["passed_case_count"] == 18
    assert report["domains"]["agent_jit_jea"] == {
        "passed": True,
        "case_count": 8,
        "failed_case_count": 0,
        "raw_returned": False,
    }
    assert report["domains"]["database_ast_rbac_isolation"]["passed"] is True
    assert report["evidence_bundle"]["schema"] == "k_guard_evidence_bundle.v1"
    assert all(case["raw_returned"] is False for case in report["cases"])


def test_control_validation_report_is_raw_free() -> None:
    rendered = json.dumps(run_control_validation(), ensure_ascii=False, sort_keys=True)

    for raw in (
        "one@example.invalid",
        "marker-one",
        "validation-agent",
        "SELECT id, email",
        "DELETE FROM users",
        "validation.sqlite",
    ):
        assert raw not in rendered


def test_control_validation_toolchain_is_complete_and_source_bound() -> None:
    first = control_validation_toolchain_contract()
    second = control_validation_toolchain_contract()

    assert first == second
    assert first["complete"] is True
    assert first["hashed_file_count"] == first["expected_file_count"] == 5
    assert len(first["sha256"]) == 64


def test_control_validate_cli_writes_the_bound_report(tmp_path: Path, capsys) -> None:
    output = tmp_path / "control-validation.json"

    assert cli.main(["control-validate", "--output", str(output)]) == 0

    stdout = json.loads(capsys.readouterr().out)
    report = json.loads(output.read_text(encoding="utf-8"))
    assert stdout["passed"] is True
    assert stdout["case_count"] == 18
    assert stdout["repeat_exact"] is True
    assert report["toolchain_contract"] == control_validation_toolchain_contract()
