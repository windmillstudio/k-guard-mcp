from __future__ import annotations

import json
from pathlib import Path

from k_guard_mcp import cli
from k_guard_mcp import runtime_validation as runtime_validation_module
from k_guard_mcp.runtime_validation import (
    RUNTIME_VALIDATION_SCHEMA,
    run_mcp_http_runtime_validation,
)


def test_runtime_validation_covers_complete_mediation_twice() -> None:
    report = run_mcp_http_runtime_validation()
    validation = report["runtime_validation"]

    assert report["complete"] is True
    assert report["passed"] is True
    assert report["finding_count"] == 0
    assert report["control_errors"] == []
    assert validation["schema"] == RUNTIME_VALIDATION_SCHEMA
    assert validation["run_count"] == 2
    assert validation["repeat_exact"] is True
    assert validation["complete"] is True
    assert validation["passed"] is True
    assert all(validation["checks"].values())
    assert validation["official_sdk_interoperability"]["passed"] is True
    assert all(validation["official_sdk_interoperability"]["checks"].values())
    assert all(value > 0 for value in validation["matrix"].values())
    assert report["access_control"]["default_action"] == "deny"
    assert report["access_control"]["audit"]["enabled"] is True
    assert report["policy"]["settings"]["require_origin"] is True
    assert report["policy"]["settings"]["forward_authorization"] is False
    assert report["evidence_bundle"]["schema"] == "k_guard_evidence_bundle.v1"


def test_runtime_validation_report_is_raw_free() -> None:
    rendered = json.dumps(run_mcp_http_runtime_validation(), ensure_ascii=False, sort_keys=True)

    for raw in (
        "runtime-validation-agent",
        "admin.delete",
        "safe.echo",
        "server-validation-1",
        "Bearer ",
        "access-policy.json",
        "access-audit.jsonl",
    ):
        assert raw not in rendered


def test_runtime_validate_cli_writes_report(tmp_path: Path, capsys) -> None:
    output = tmp_path / "runtime-validation.json"

    assert cli.main(["runtime-validate", "--output", str(output)]) == 0

    summary = json.loads(capsys.readouterr().out)
    report = json.loads(output.read_text(encoding="utf-8"))
    assert summary["passed"] is True
    assert summary["run_count"] == 2
    assert summary["repeat_exact"] is True
    assert report["runtime_validation"]["matrix"] == summary["matrix"]


def test_running_uvicorn_close_forces_exit_after_graceful_deadline() -> None:
    class FakeServer:
        should_exit = False
        force_exit = False

    class FakeSocket:
        closed = False

        def fileno(self) -> int:
            return -1 if self.closed else 1

        def close(self) -> None:
            self.closed = True

    class FakeThread:
        def __init__(self, server: FakeServer) -> None:
            self.server = server
            self.join_count = 0

        def join(self, *, timeout: int) -> None:
            assert timeout == 10
            self.join_count += 1

        def is_alive(self) -> bool:
            return not self.server.force_exit

    running = object.__new__(runtime_validation_module._RunningUvicorn)
    running.server = FakeServer()
    running.socket = FakeSocket()
    running.thread = FakeThread(running.server)

    running.close()

    assert running.server.should_exit is True
    assert running.server.force_exit is True
    assert running.socket.closed is True
    assert running.thread.join_count == 2
