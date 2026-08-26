from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from k_guard_mcp import cli
from k_guard_mcp.access_policy import AccessPolicyController, load_policy


SIGNING_KEY = "k-guard-cli-access-key-at-least-32-bytes-2026"


def _controller_args(policy: Path, audit: Path, **overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "access_policy": str(policy),
        "access_key_env": "K_GUARD_TEST_ACCESS_KEY",
        "access_app_id": "app-1",
        "access_session_id": "session-1",
        "access_purpose": "release-review-1",
        "access_audit_log": str(audit),
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_access_policy_template_is_strict_and_loadable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output = tmp_path / "access-policy.json"

    assert cli.main(["access-policy-template", "--output", str(output)]) == 0

    report = json.loads(capsys.readouterr().out)
    policy = load_policy(output)
    assert report["schema"] == "k_guard_agent_access_policy.v1"
    assert policy.max_ttl_seconds == 300
    reviewer = policy.roles["release-reviewer"]
    assert "tools/call" in reviewer.methods
    assert "check_my_app" in reviewer.tools
    assert "*" not in reviewer.methods
    assert "*" not in reviewer.tools


def test_agent_grant_is_written_privately_and_never_printed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    policy_path = tmp_path / "access-policy.json"
    token_path = tmp_path / "grant.jwt"
    assert cli.main(["access-policy-template", "--output", str(policy_path)]) == 0
    capsys.readouterr()
    monkeypatch.setenv("K_GUARD_TEST_ACCESS_KEY", SIGNING_KEY)

    argv = [
        "agent-grant",
        "--policy",
        str(policy_path),
        "--output",
        str(token_path),
        "--key-env",
        "K_GUARD_TEST_ACCESS_KEY",
        "--app-id",
        "app-1",
        "--session-id",
        "session-1",
        "--purpose",
        "release-review-1",
        "--subject",
        "agent-1",
        "--role",
        "release-reviewer",
        "--method",
        "tools/call",
        "--tool",
        "check_my_app",
        "--ttl",
        "60",
        "--max-calls",
        "2",
    ]
    assert cli.main(argv) == 0

    token = token_path.read_text(encoding="utf-8").strip()
    stdout = capsys.readouterr().out
    assert token
    assert token not in stdout
    assert SIGNING_KEY not in stdout
    controller = AccessPolicyController.from_file(
        policy_path,
        SIGNING_KEY,
        app_id="app-1",
        session_id="session-1",
        purpose="release-review-1",
    )
    assert controller.authenticate_grant(token).allowed is True

    assert cli.main(argv) == 2
    assert token_path.read_text(encoding="utf-8").strip() == token


def test_proxy_access_configuration_is_all_or_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_path = tmp_path / "access-policy.json"
    assert cli.main(["access-policy-template", "--output", str(policy_path)]) == 0
    monkeypatch.setenv("K_GUARD_TEST_ACCESS_KEY", SIGNING_KEY)

    disabled = argparse.Namespace(
        access_policy=None,
        access_key_env="K_GUARD_TEST_ACCESS_KEY",
        access_app_id="",
        access_session_id="",
        access_purpose="",
        access_audit_log=None,
    )
    assert cli._access_controller_from_args(disabled) is None

    with pytest.raises(ValueError, match="access_policy_required"):
        cli._access_controller_from_args(
            _controller_args(policy_path, tmp_path / "audit.jsonl", access_policy=None)
        )

    with pytest.raises(ValueError, match="access_policy_identity_and_audit_required"):
        cli._access_controller_from_args(
            _controller_args(policy_path, tmp_path / "audit.jsonl", access_purpose="")
        )

    controller = cli._access_controller_from_args(
        _controller_args(policy_path, tmp_path / "audit.jsonl")
    )
    assert controller is not None
    assert controller.controller_summary()["audit"]["enabled"] is True


def test_secret_environment_name_and_value_are_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("K_GUARD_MISSING_ACCESS_KEY", raising=False)
    with pytest.raises(ValueError, match="secret_environment_name_invalid"):
        cli._required_secret_env("BAD-NAME")
    with pytest.raises(ValueError, match="required_secret_environment_missing"):
        cli._required_secret_env("K_GUARD_MISSING_ACCESS_KEY")
