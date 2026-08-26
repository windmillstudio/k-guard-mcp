from __future__ import annotations

from pathlib import Path

from k_guard_mcp import server


def _control_finding(rule_id: str = "TEST_CONTROL"):
    return server._tool_error_finding(
        rule_id,
        "Test control failure",
        "raw_returned=false",
        "Retry after fixing the test control.",
    )


def test_score_fixture_corpus_covers_argument_guard_and_success(monkeypatch) -> None:
    monkeypatch.setenv("K_GUARD_MCP_MAX_ARG_CHARS", "3")
    blocked = server.score_fixture_corpus("too-long")
    assert {item["rule_id"] for item in blocked["findings"]} == {"MCP_ARGUMENT_BUDGET_EXCEEDED"}

    monkeypatch.setenv("K_GUARD_MCP_MAX_ARG_CHARS", "100")
    expected = {"schema": "score", "passed": True}
    monkeypatch.setattr(server, "evaluate_fixture_corpus", lambda path, scanner: expected)
    assert server.score_fixture_corpus("ok") == expected


def test_deep_analyzer_mcp_tool_fails_closed_and_runs_adapter(monkeypatch) -> None:
    monkeypatch.setenv("K_GUARD_MCP_MAX_ARG_CHARS", "3")
    blocked = server.deep_analyzer_audit("too-long")
    assert blocked["experience"]["verdict"]["code"] == "hold_incomplete"

    monkeypatch.setenv("K_GUARD_MCP_MAX_ARG_CHARS", "100")
    monkeypatch.setattr(server, "_workspace_budget_finding", lambda *args: _control_finding("TEST_BUDGET"))
    budget = server.deep_analyzer_audit("app")
    assert {item["rule_id"] for item in budget["findings"]} == {"TEST_BUDGET"}

    captured: dict[str, object] = {}

    class FakeRun:
        def to_report(self) -> dict:
            return {"complete": True, "findings": [], "control_errors": []}

    class FakeAdapter:
        def __init__(self, *, executable: str) -> None:
            captured["executable"] = executable

        def analyze(self, workspace_path: str) -> FakeRun:
            captured["workspace"] = workspace_path
            return FakeRun()

    monkeypatch.setattr(server, "_workspace_budget_finding", lambda *args: None)
    monkeypatch.setattr(server, "SemgrepAnalyzerAdapter", FakeAdapter)
    monkeypatch.setenv("K_GUARD_SEMGREP_EXECUTABLE", "semgrep-pinned")
    report = server.deep_analyzer_audit("app")

    assert captured == {"executable": "semgrep-pinned", "workspace": "app"}
    assert report["complete"] is True
    assert report["experience"]["verdict"]["code"] == "scoped_clear"


def test_multilang_mcp_tool_guards_arguments_and_uses_default_pack(monkeypatch) -> None:
    monkeypatch.setenv("K_GUARD_MCP_MAX_ARG_CHARS", "3")
    blocked = server.validate_multilang_pack("too-long")
    assert {item["rule_id"] for item in blocked["findings"]} == {"MCP_ARGUMENT_BUDGET_EXCEEDED"}

    captured: dict[str, object] = {}

    class FakeAdapter:
        def __init__(self, *, executable: str) -> None:
            captured["executable"] = executable

    def run(pack, adapter) -> dict:
        captured["pack"] = pack
        captured["adapter"] = adapter
        return {"complete": True, "ready": True, "findings": []}

    monkeypatch.setenv("K_GUARD_MCP_MAX_ARG_CHARS", "1000")
    monkeypatch.setenv("K_GUARD_SEMGREP_EXECUTABLE", "semgrep-pinned")
    monkeypatch.setattr(server, "SemgrepAnalyzerAdapter", FakeAdapter)
    monkeypatch.setattr(server, "run_language_validation_pack", run)
    report = server.validate_multilang_pack()

    assert captured["pack"] == server.DEFAULT_LANGUAGE_VALIDATION_PACK
    assert captured["executable"] == "semgrep-pinned"
    assert isinstance(captured["adapter"], FakeAdapter)
    assert report["ready"] is True


def test_field_campaign_mcp_tools_create_and_evaluate_template(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("K_GUARD_MCP_MAX_ARG_CHARS", "4")
    blocked = server.create_field_campaign_template("too-long")
    assert {item["rule_id"] for item in blocked["findings"]} == {"MCP_ARGUMENT_BUDGET_EXCEEDED"}

    monkeypatch.setenv("K_GUARD_MCP_MAX_ARG_CHARS", "1000")
    roster = tmp_path / "roster.csv"
    status = tmp_path / "status.json"
    created = server.create_field_campaign_template(str(roster))
    evaluated = server.field_campaign_status(str(roster), str(status))

    assert created["ready"] is False
    assert roster.is_file()
    assert evaluated["ready"] is False
    assert "roster_empty" in evaluated["blockers"]
    assert status.is_file()

    monkeypatch.setenv("K_GUARD_MCP_MAX_ARG_CHARS", "3")
    blocked_status = server.field_campaign_status("too-long", "out")
    assert {item["rule_id"] for item in blocked_status["findings"]} == {"MCP_ARGUMENT_BUDGET_EXCEEDED"}


def test_data_release_mcp_tool_covers_budget_success_and_exception(monkeypatch) -> None:
    args = tuple("x" for _ in range(13))
    monkeypatch.setenv("K_GUARD_MCP_MAX_ARG_CHARS", "100")
    monkeypatch.setattr(server, "_guardian_budget_finding", lambda *args, **kwargs: _control_finding("TEST_BUDGET"))
    budget = server.data_release_gate(*args)
    assert budget["passed"] is False
    assert budget["checks"][0]["detail"] == "TEST_BUDGET"

    expected = {"passed": True, "data_release_gate": {"passed": True}}
    monkeypatch.setattr(server, "_guardian_budget_finding", lambda *args, **kwargs: None)
    monkeypatch.setattr(server, "run_data_release_gate", lambda *args, **kwargs: expected)
    assert server.data_release_gate(*args, max_validation_false_positive_rate=0.1) == expected

    def fail(*args, **kwargs):
        raise ValueError("operator@example.com")

    monkeypatch.setattr(server, "run_data_release_gate", fail)
    failed = server.data_release_gate(*args)
    assert failed["passed"] is False
    assert failed["checks"][0]["detail"] == "MCP_DATA_RELEASE_GATE_FAILED"
    assert "operator@example.com" not in str(failed)
