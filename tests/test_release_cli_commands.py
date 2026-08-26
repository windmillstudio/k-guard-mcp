from __future__ import annotations

import json
from pathlib import Path

import pytest

from k_guard_mcp import cli


def test_http_proxy_cli_builds_settings_and_runs_uvicorn(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}
    app = object()

    def create(upstream: str, settings, *, access_controller=None):
        captured["upstream"] = upstream
        captured["settings"] = settings
        captured["access_controller"] = access_controller
        return app

    def run(candidate, *, host: str, port: int, log_level: str) -> None:
        captured["run"] = (candidate, host, port, log_level)

    monkeypatch.setattr(cli, "create_mcp_http_proxy_app", create)
    monkeypatch.setattr("uvicorn.run", run)
    report = tmp_path / "runtime.json"

    code = cli.main(
        [
            "mcp-http-proxy",
            "--upstream",
            "http://127.0.0.1:9000/mcp",
            "--host",
            "localhost",
            "--port",
            "9876",
            "--endpoint",
            "/guarded",
            "--allowed-origin",
            "https://app.example",
            "--timeout",
            "4.5",
            "--forward-authorization",
            "--report",
            str(report),
        ]
    )

    assert code == 0
    assert captured["access_controller"] is None
    assert captured["upstream"] == "http://127.0.0.1:9000/mcp"
    settings = captured["settings"]
    assert settings.endpoint_path == "/guarded"
    assert settings.allowed_origins == ("https://app.example",)
    assert settings.timeout_seconds == 4.5
    assert settings.forward_authorization is True
    assert settings.report_path == str(report)
    assert captured["run"] == (app, "localhost", 9876, "info")


@pytest.mark.parametrize("port", [0, 65536])
def test_http_proxy_cli_rejects_invalid_ports(port: int, tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "mcp-http-proxy",
                "--upstream",
                "http://127.0.0.1:9000/mcp",
                "--port",
                str(port),
                "--report",
                str(tmp_path / "runtime.json"),
            ]
        )
    assert exc_info.value.code == 2


@pytest.mark.parametrize(("ready", "expected_code"), [(True, 0), (False, 3)])
def test_language_validation_cli_writes_ready_and_hold_reports(
    monkeypatch,
    tmp_path: Path,
    capsys,
    ready: bool,
    expected_code: int,
) -> None:
    adapter = object()
    report = {
        "complete": ready,
        "ready": ready,
        "status": "development_validation_ready" if ready else "control_error",
        "metrics": {"overall": {"tp": 15 if ready else 0}},
    }
    monkeypatch.setattr(cli, "SemgrepAnalyzerAdapter", lambda **kwargs: adapter)
    monkeypatch.setattr(cli, "run_language_validation_pack", lambda pack, actual: report)
    output = tmp_path / ("ready.json" if ready else "hold.json")

    code = cli.main(
        [
            "language-validate",
            "--pack",
            str(tmp_path / "pack"),
            "--output",
            str(output),
            "--semgrep-executable",
            "semgrep-test",
            "--timeout",
            "9",
        ]
    )

    assert code == expected_code
    assert json.loads(output.read_text(encoding="utf-8")) == report
    printed = json.loads(capsys.readouterr().out)
    assert printed["ready"] is ready
    assert printed["overall"] == report["metrics"]["overall"]


def test_field_queue_preregister_and_sign_cli_paths(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setattr(
        cli,
        "write_field_review_queue",
        lambda guardian, output: {"schema": "k_guard_field_queue.v1", "candidate_count": 3},
    )
    assert (
        cli.main(
            [
                "field-validation-queue",
                "--guardian-report",
                str(tmp_path / "guardian.json"),
                "--output",
                str(tmp_path / "queue.csv"),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["candidate_count"] == 3

    preregistration = {
        "schema": "k_guard_field_preregistration.v2",
        "ground_truth_row_count": 24,
        "preregistration_evidence_envelope": {"signature": {"key_mode": "operator-keyed"}},
    }
    monkeypatch.setattr(cli, "write_field_preregistration", lambda *args, **kwargs: preregistration)
    assert (
        cli.main(
            [
                "field-validation-preregister",
                "--ground-truth",
                str(tmp_path / "truth.csv"),
                "--roster",
                str(tmp_path / "roster.csv"),
                "--output",
                str(tmp_path / "preregister.json"),
                "--custodian-id",
                "custodian-a",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["operator_keyed"] is True

    assert cli.main(["field-validation-sign"]) == 2
    assert "requires --ground-truth" in capsys.readouterr().err
    monkeypatch.setattr(cli, "sign_field_validation_inputs", lambda **kwargs: {"signed": 2})
    assert cli.main(["field-validation-sign", "--ground-truth", str(tmp_path / "truth.csv")]) == 0
    assert json.loads(capsys.readouterr().out) == {"signed": 2}


@pytest.mark.parametrize(
    ("claim_status", "expected_code"),
    [("field_validation_ready", 0), ("field_validation_not_ready", 3)],
)
def test_field_report_cli_enforces_claim_status(
    monkeypatch,
    tmp_path: Path,
    capsys,
    claim_status: str,
    expected_code: int,
) -> None:
    report = {
        "claim_status": claim_status,
        "profile": "field",
        "sample": {"app_count": 12, "case_count": 36},
    }
    monkeypatch.setattr(cli, "run_field_validation", lambda *args, **kwargs: report)
    output = tmp_path / f"{expected_code}.json"

    code = cli.main(
        [
            "field-validation-report",
            "--guardian-report",
            "primary.json",
            "--repeat-guardian-report",
            "repeat.json",
            "--ground-truth",
            "truth.csv",
            "--review",
            "review.csv",
            "--preregistration",
            "preregister.json",
            "--roster",
            "roster.csv",
            "--output",
            str(output),
        ]
    )

    assert code == expected_code
    assert json.loads(output.read_text(encoding="utf-8")) == report
    assert json.loads(capsys.readouterr().out)["claim_status"] == claim_status


@pytest.mark.parametrize(("passed", "expected_code"), [(True, 0), (False, 3)])
def test_data_release_cli_preserves_fail_closed_exit(
    monkeypatch,
    tmp_path: Path,
    capsys,
    passed: bool,
    expected_code: int,
) -> None:
    report = {
        "passed": passed,
        "data_release_gate": {"blocking_check_count": 0 if passed else 1},
    }
    monkeypatch.setattr(cli, "run_data_release_gate", lambda *args, **kwargs: report)
    output = tmp_path / f"release-{expected_code}.json"
    args = [
        "data-release-gate",
        "--guardian-report",
        "guardian.json",
        "--guardian-manifest",
        "manifest.csv",
        "--validation-source-guardian-report",
        "validation-source.json",
        "--validation-repeat-guardian-report",
        "validation-repeat.json",
        "--validation-report",
        "validation.json",
        "--validation-review",
        "review.csv",
        "--validation-ground-truth",
        "truth.csv",
        "--validation-preregistration",
        "preregister.json",
        "--validation-roster",
        "roster.csv",
        "--korean-fixture-corpus",
        "corpus.json",
        "--korean-corpus-report",
        "corpus-report.json",
        "--mcp-intercept-report",
        "intercept.json",
        "--mcp-forwarded-output",
        "forwarded.jsonl",
        "--output",
        str(output),
    ]

    assert cli.main(args) == expected_code
    assert json.loads(output.read_text(encoding="utf-8")) == report
    assert json.loads(capsys.readouterr().out)["passed"] is passed
