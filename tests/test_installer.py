from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import types
from pathlib import Path

import pytest

from k_guard_mcp import cli
from k_guard_mcp import installer


def _portable_private_hardening(monkeypatch: pytest.MonkeyPatch) -> None:
    def harden(path: Path, *, is_directory: bool, mode: int) -> None:
        del is_directory
        os.chmod(path, mode)

    monkeypatch.setattr(installer, "_harden_private_path", harden)


def _successful_command(argv, **kwargs):
    del argv, kwargs
    return installer._CommandOutcome(0)


def _private_acl_payload(sid: str, *, is_directory: bool = False, extra_rules: list[dict] | None = None) -> str:
    rules = [
        {
            "sid": sid,
            "access_type": "Allow",
            "inherited": False,
            "full_control": True,
            "inheritance_flags": "ContainerInherit, ObjectInherit" if is_directory else "None",
            "propagation_flags": "None",
        }
    ]
    rules.extend(extra_rules or [])
    return json.dumps({"protected": True, "owner_sid": sid, "rules": rules})


def test_dry_run_has_no_side_effects_or_client_commands(tmp_path, monkeypatch):
    def unexpected_command(argv, **kwargs):
        raise AssertionError(f"dry-run invoked a command: {argv!r} {kwargs!r}")

    monkeypatch.setattr(installer, "_run_command", unexpected_command)

    workspace = tmp_path / "audit-root"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    home = tmp_path / "home"
    report = installer.install(
        client="antigravity",
        profile="workspace",
        dry_run=True,
        home=home,
        python_executable=sys.executable,
    )

    assert report["ok"] is True
    assert report["dry_run"] is True
    assert report["external_probing_enabled"] is False
    assert report["clients"][0]["status"] == "planned"
    assert report["workspace_binding"]["basename"] == "audit-root"
    assert report["workspace_binding"]["raw_path_returned"] is False
    assert str(workspace.resolve()) not in json.dumps(report, ensure_ascii=False)
    assert not home.exists()


def test_missing_or_linked_workspace_fails_before_any_setting_change(tmp_path, monkeypatch):
    home = tmp_path / "home"
    missing = tmp_path / "missing-workspace"
    monkeypatch.setattr(installer, "_run_command", lambda *args, **kwargs: pytest.fail("command invoked"))

    missing_report = installer.install(
        client="antigravity",
        home=home,
        workspace=missing,
        python_executable=sys.executable,
    )

    assert missing_report["ok"] is False
    assert missing_report["error_code"] == "INVALID_WORKSPACE"
    assert not home.exists()

    target = tmp_path / "real-workspace"
    target.mkdir()
    linked = tmp_path / "linked-workspace"
    try:
        linked.symlink_to(target, target_is_directory=True)
    except OSError:
        linked.mkdir()
        original_is_unsafe_link = installer._is_unsafe_link
        monkeypatch.setattr(
            installer,
            "_is_unsafe_link",
            lambda path: Path(path) == linked or original_is_unsafe_link(path),
        )

    linked_report = installer.install(
        client="antigravity",
        home=home,
        workspace=linked,
        python_executable=sys.executable,
    )

    assert linked_report["ok"] is False
    assert linked_report["error_code"] == "INVALID_WORKSPACE"
    assert not home.exists()


def test_dry_run_rejects_invalid_existing_key_without_writing(tmp_path, monkeypatch):
    private_dir = tmp_path / ".k-guard"
    private_dir.mkdir()
    key = private_dir / "operator-evidence.key"
    key.write_text("too-short\n", encoding="utf-8")
    monkeypatch.setattr(installer, "_run_command", lambda *args, **kwargs: pytest.fail("command invoked"))

    report = installer.install(
        client="antigravity",
        dry_run=True,
        home=tmp_path,
        python_executable=sys.executable,
    )

    assert report["ok"] is False
    assert report["error_code"] == "PRIVATE_LAUNCHER_PREFLIGHT_FAILED"
    assert key.read_text(encoding="utf-8") == "too-short\n"
    assert not (tmp_path / ".gemini").exists()


def test_auto_discovers_antigravity_from_current_agy_cli(tmp_path, monkeypatch):
    agy = str(tmp_path / "agy")
    monkeypatch.setattr(installer.shutil, "which", lambda name: agy if name == "agy" else None)

    report = installer.install(
        client="auto",
        profile="workspace",
        dry_run=True,
        home=tmp_path,
        python_executable=sys.executable,
    )

    assert report["ok"] is True
    assert [(item["client"], item["status"]) for item in report["clients"]] == [("antigravity", "planned")]


@pytest.mark.skipif(os.name != "nt", reason="Windows junction integration")
def test_windows_junction_private_directory_is_rejected_before_key_or_receipt_write(tmp_path, monkeypatch):
    redirected = tmp_path / "redirected"
    redirected.mkdir()
    junction = tmp_path / ".k-guard"
    created = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(redirected)],
        capture_output=True,
        text=True,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip("junction creation unavailable")
    monkeypatch.setattr(installer, "_run_command", lambda *args, **kwargs: pytest.fail("client command invoked"))
    try:
        report = installer.install(
            client="antigravity",
            dry_run=True,
            home=tmp_path,
            python_executable=sys.executable,
        )
    finally:
        junction.rmdir()

    assert report["ok"] is False
    assert report["error_code"] == "PRIVATE_LAUNCHER_PREFLIGHT_FAILED"
    assert list(redirected.iterdir()) == []


def test_private_launcher_preserves_key_and_never_returns_it(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)

    first = installer.install(client="antigravity", home=tmp_path, python_executable=sys.executable)
    key_path = tmp_path / ".k-guard" / "operator-evidence.key"
    launcher_path = tmp_path / ".k-guard" / "mcp-launcher.py"
    key = key_path.read_text(encoding="utf-8").strip()
    launcher = launcher_path.read_text(encoding="utf-8")

    assert first["ok"] is True
    assert len(key) >= 32
    assert key not in launcher
    assert key not in json.dumps(first, ensure_ascii=False)
    assert "K_GUARD_PRIVATE_LAUNCHER_V1" in launcher
    assert "os.environ.pop(_name, None)" in launcher
    for name in installer._PROBE_ENV_VARS:
        assert name in launcher

    second = installer.install(client="antigravity", home=tmp_path, python_executable=sys.executable)
    assert second["ok"] is True
    assert key_path.read_text(encoding="utf-8").strip() == key
    assert key not in json.dumps(second, ensure_ascii=False)


def test_launcher_passes_private_workspace_binding_through_environment(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    home = tmp_path / "home"
    workspace = tmp_path / "audit-root"
    workspace.mkdir()

    installed = installer.install(
        client="antigravity",
        home=home,
        workspace=workspace,
        python_executable=sys.executable,
    )
    assert installed["ok"] is True

    canonical_root = str(workspace.resolve())
    binding = home / ".k-guard" / "workspace-binding.json"
    launcher = home / ".k-guard" / "mcp-launcher.py"
    receipt = home / ".k-guard" / "installation.json"
    launcher_source = launcher.read_text(encoding="utf-8")
    assert json.loads(binding.read_text(encoding="utf-8"))["canonical_root"] == canonical_root
    assert canonical_root not in launcher_source
    assert canonical_root not in receipt.read_text(encoding="utf-8")
    assert installer._WORKSPACE_ROOT_ENV in launcher_source

    captured: dict[str, str | None] = {}
    fake_server = types.ModuleType("k_guard_mcp.server")

    def fake_main() -> int:
        captured["workspace_root"] = os.environ.get(installer._WORKSPACE_ROOT_ENV)
        return 0

    fake_server.main = fake_main
    monkeypatch.setitem(sys.modules, "k_guard_mcp.server", fake_server)
    monkeypatch.setattr(sys, "argv", [str(launcher), "--profile", "workspace"])
    tracked_env = (installer.EVIDENCE_HMAC_ENV, installer._WORKSPACE_ROOT_ENV, *installer._PROBE_ENV_VARS)
    previous_env = {name: os.environ.get(name) for name in tracked_env}
    try:
        with pytest.raises(SystemExit) as stopped:
            exec(
                compile(launcher_source, str(launcher), "exec"),
                {"__name__": "__main__", "__file__": str(launcher)},
            )
    finally:
        for name, value in previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    assert stopped.value.code == 0
    assert captured["workspace_root"] == canonical_root


def test_official_cli_commands_use_user_scope_without_dirtying_the_project(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    tools = {name: str(tmp_path / "tools" / name) for name in ("codex", "grok", "tunnel-client")}
    monkeypatch.setattr(installer.shutil, "which", lambda name: tools.get(name))
    monkeypatch.setenv("CONTROL_PLANE_TUNNEL_ID", "tunnel_12345678")
    commands: list[list[str]] = []

    def capture(argv, **kwargs):
        del kwargs
        commands.append(list(argv))
        return installer._CommandOutcome(0)

    monkeypatch.setattr(installer, "_run_command", capture)
    report = installer.install(
        client="all",
        profile="workspace",
        home=tmp_path,
        cwd=tmp_path,
        python_executable=sys.executable,
    )

    launcher = str(tmp_path / ".k-guard" / "mcp-launcher.py")
    python = str(Path(sys.executable).resolve())
    launch = [python, launcher, "--profile", "workspace"]
    mcp_command = subprocess.list2cmdline(launch) if os.name == "nt" else installer.shlex.join(launch)
    assert report["ok"] is False
    assert report["status"] == "부분 연결 · 다음 단계 필요"
    assert next(item for item in report["clients"] if item["client"] == "chatgpt")["configured"] is True
    assert commands == [
        [
            tools["tunnel-client"],
            "init",
            "--sample",
            "sample_mcp_stdio_local",
            "--profile",
            "k-guard",
            "--tunnel-id",
            "tunnel_12345678",
            "--mcp-command",
            mcp_command,
        ],
        [tools["grok"], "mcp", "add", "--scope", "user", "k-guard", "--", *launch],
        [tools["codex"], "mcp", "add", "k-guard", "--", *launch],
    ]
    antigravity = json.loads((tmp_path / ".gemini" / "config" / "mcp_config.json").read_text(encoding="utf-8"))
    entry = antigravity["mcpServers"]["k-guard"]
    assert entry["command"] == python
    assert entry["args"] == [launcher, "--profile", "workspace"]
    assert set(entry["env"].values()) == {"0"}


def test_local_dev_enables_only_local_read_only_probe_flags(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    grok = str(tmp_path / "grok")
    monkeypatch.setattr(installer.shutil, "which", lambda name: grok if name == "grok" else None)
    commands: list[list[str]] = []

    def capture(argv, **kwargs):
        del kwargs
        commands.append(list(argv))
        return installer._CommandOutcome(0)

    monkeypatch.setattr(installer, "_run_command", capture)
    report = installer.install(
        client="grok",
        profile="local-dev",
        home=tmp_path,
        python_executable=sys.executable,
    )

    assert report["ok"] is True
    assert report["local_dynamic_probing_enabled"] is True
    assert report["external_probing_enabled"] is False
    assert commands[0][3:5] == ["--scope", "user"]
    assert commands[0][-3:] == [str(tmp_path / ".k-guard" / "mcp-launcher.py"), "--profile", "local-dev"]
    launcher = (tmp_path / ".k-guard" / "mcp-launcher.py").read_text(encoding="utf-8")
    assert "os.environ['K_GUARD_MCP_ENABLE_PROBE'] = '1'" in launcher
    assert "os.environ['K_GUARD_MCP_ENABLE_DEEP_ACTIVE_PROBE'] = '1'" in launcher
    assert "os.environ['K_GUARD_MCP_ENABLE_EXTERNAL_PROBE'] = '1'" not in launcher
    assert "os.environ['K_GUARD_MCP_ENABLE_SESSION_PROBE'] = '1'" not in launcher


def test_antigravity_merge_preserves_existing_json_and_creates_backup(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    config = tmp_path / ".gemini" / "config" / "mcp_config.json"
    config.parent.mkdir(parents=True)
    original = {
        "theme": "night",
        "mcpServers": {"existing": {"command": "existing-server", "args": ["--quiet"]}},
    }
    original_text = json.dumps(original, ensure_ascii=False, indent=4) + "\n"
    config.write_text(original_text, encoding="utf-8")

    report = installer.install(client="antigravity", home=tmp_path, python_executable=sys.executable)

    assert report["ok"] is True
    merged = json.loads(config.read_text(encoding="utf-8"))
    assert merged["theme"] == "night"
    assert merged["mcpServers"]["existing"] == original["mcpServers"]["existing"]
    assert "k-guard" in merged["mcpServers"]
    backups = list(config.parent.glob("mcp_config.json.bak-*"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == original_text
    assert str(backups[0]) in report["backups"]


def test_antigravity_empty_placeholder_is_backed_up_and_initialized(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    config = tmp_path / ".gemini" / "config" / "mcp_config.json"
    config.parent.mkdir(parents=True)
    config.write_text("", encoding="utf-8")

    report = installer.install(client="antigravity", home=tmp_path, python_executable=sys.executable)

    assert report["ok"] is True
    assert "k-guard" in json.loads(config.read_text(encoding="utf-8"))["mcpServers"]
    backups = list(config.parent.glob("mcp_config.json.bak-*"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == b""


def test_invalid_antigravity_json_is_not_overwritten(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    config = tmp_path / ".gemini" / "config" / "mcp_config.json"
    config.parent.mkdir(parents=True)
    original = "{ definitely-not-json\n"
    config.write_text(original, encoding="utf-8")

    report = installer.install(client="antigravity", home=tmp_path, python_executable=sys.executable)

    assert report["ok"] is False
    assert report["clients"][0]["failure_code"] == "INVALID_ANTIGRAVITY_CONFIG"
    assert config.read_text(encoding="utf-8") == original
    assert list(config.parent.glob("mcp_config.json.bak-*")) == []


def test_receipt_is_secret_free_and_backed_up_before_update(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    first = installer.install(client="antigravity", home=tmp_path, python_executable=sys.executable)
    key = (tmp_path / ".k-guard" / "operator-evidence.key").read_text(encoding="utf-8").strip()

    second = installer.install(client="antigravity", home=tmp_path, python_executable=sys.executable)
    receipt = tmp_path / ".k-guard" / "installation.json"
    receipt_text = receipt.read_text(encoding="utf-8")

    assert first["ok"] is True and second["ok"] is True
    assert key not in receipt_text
    bound_root = json.loads((tmp_path / ".k-guard" / "workspace-binding.json").read_text(encoding="utf-8"))["canonical_root"]
    receipt_payload = json.loads(receipt_text)
    assert bound_root not in receipt_text
    assert receipt_payload["workspace_binding"]["raw_path_stored"] is False
    assert receipt_payload["workspace_binding"]["private_permissions_required"] is True
    assert receipt_payload["workspace_binding"]["hash_scheme"] == installer._WORKSPACE_HASH_SCHEME
    backups = list(receipt.parent.glob("installation.json.bak-*"))
    assert len(backups) == 1
    assert key not in backups[0].read_text(encoding="utf-8")


def test_workspace_change_is_backed_up_before_atomic_rebinding(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    home = tmp_path / "home"
    first_workspace = tmp_path / "workspace-one"
    second_workspace = tmp_path / "workspace-two"
    first_workspace.mkdir()
    second_workspace.mkdir()

    first = installer.install(
        client="antigravity",
        home=home,
        workspace=first_workspace,
        python_executable=sys.executable,
    )
    assert first["ok"] is True
    binding = home / ".k-guard" / "workspace-binding.json"
    original_binding = binding.read_text(encoding="utf-8")
    original_atomic_write = installer._atomic_write_json
    binding_write_saw_backup = False

    def observe_atomic_write(path, payload, *, private):
        nonlocal binding_write_saw_backup
        if path == binding:
            binding_write_saw_backup = bool(list(binding.parent.glob("workspace-binding.json.bak-*")))
        return original_atomic_write(path, payload, private=private)

    monkeypatch.setattr(installer, "_atomic_write_json", observe_atomic_write)
    second = installer.install(
        client="antigravity",
        home=home,
        workspace=second_workspace,
        python_executable=sys.executable,
    )

    assert second["ok"] is True
    assert binding_write_saw_backup is True
    binding_backups = list(binding.parent.glob("workspace-binding.json.bak-*"))
    assert len(binding_backups) == 1
    assert binding_backups[0].read_text(encoding="utf-8") == original_binding
    assert json.loads(binding.read_text(encoding="utf-8"))["canonical_root"] == str(second_workspace.resolve())
    assert str(binding_backups[0]) in second["backups"]


def test_failed_client_registration_restores_existing_workspace_transaction(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    home = tmp_path / "home"
    first_workspace = tmp_path / "workspace-one"
    second_workspace = tmp_path / "workspace-two"
    first_workspace.mkdir()
    second_workspace.mkdir()

    first = installer.install(
        client="antigravity",
        home=home,
        workspace=first_workspace,
        python_executable=sys.executable,
    )
    assert first["ok"] is True

    private_dir = home / ".k-guard"
    binding = private_dir / "workspace-binding.json"
    receipt = private_dir / "installation.json"
    launcher = private_dir / "mcp-launcher.py"
    original_binding = binding.read_bytes()
    original_receipt = receipt.read_bytes()
    original_launcher = launcher.read_bytes()

    codex = str(tmp_path / "codex")
    monkeypatch.setattr(installer.shutil, "which", lambda name: codex if name == "codex" else None)
    monkeypatch.setattr(installer, "_run_command", lambda argv, **kwargs: installer._CommandOutcome(1))
    failed = installer.install(
        client="codex",
        home=home,
        workspace=second_workspace,
        python_executable=sys.executable,
    )

    assert failed["ok"] is False
    assert failed["error_code"] == "CLIENT_REGISTRATION_TRANSACTION_FAILED"
    assert failed["installation_transaction"]["shared_state_restored"] is True
    assert failed["workspace_binding"]["basename"] == first_workspace.name
    assert binding.read_bytes() == original_binding
    assert receipt.read_bytes() == original_receipt
    assert launcher.read_bytes() == original_launcher
    assert json.loads(binding.read_text(encoding="utf-8"))["canonical_root"] == str(first_workspace.resolve())


def test_doctor_rejects_workspace_binding_and_receipt_mismatch(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    home = tmp_path / "home"
    installed_workspace = tmp_path / "installed-workspace"
    mismatched_workspace = tmp_path / "mismatched-workspace"
    installed_workspace.mkdir()
    mismatched_workspace.mkdir()
    installed = installer.install(
        client="antigravity",
        home=home,
        workspace=installed_workspace,
        python_executable=sys.executable,
    )
    assert installed["ok"] is True

    binding = home / ".k-guard" / "workspace-binding.json"
    installer._atomic_write_json(
        binding,
        installer._workspace_binding_payload(mismatched_workspace.resolve()),
        private=True,
    )
    monkeypatch.setattr(installer, "_private_permissions_ok", lambda path, mode: True)
    monkeypatch.setattr(installer, "_run_command", _successful_command)

    report = installer.doctor(client="antigravity", home=home, python_executable=sys.executable)
    checks = {item["name"]: item for item in report["checks"]}
    serialized = json.dumps(report, ensure_ascii=False)

    assert report["ok"] is False
    assert checks["workspace_binding"]["ok"] is True
    assert checks["workspace_binding_consistency"]["ok"] is False
    assert report["clients"][0]["status"] == "needs_attention"
    assert str(installed_workspace.resolve()) not in serialized
    assert str(mismatched_workspace.resolve()) not in serialized


def test_doctor_requires_private_workspace_binding_permissions(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    installed = installer.install(
        client="antigravity",
        home=home,
        workspace=workspace,
        python_executable=sys.executable,
    )
    assert installed["ok"] is True

    binding = home / ".k-guard" / "workspace-binding.json"
    monkeypatch.setattr(installer, "_private_permissions_ok", lambda path, mode: path != binding)
    monkeypatch.setattr(installer, "_run_command", _successful_command)
    report = installer.doctor(client="antigravity", home=home, python_executable=sys.executable)
    checks = {item["name"]: item for item in report["checks"]}

    assert report["ok"] is False
    assert checks["workspace_binding"]["ok"] is True
    assert checks["workspace_binding_consistency"]["ok"] is True
    assert checks["private_permissions"]["ok"] is False


def test_doctor_antigravity_is_strict_and_secret_free(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    installed = installer.install(client="antigravity", home=tmp_path, python_executable=sys.executable)
    assert installed["ok"] is True
    key = (tmp_path / ".k-guard" / "operator-evidence.key").read_text(encoding="utf-8").strip()

    monkeypatch.setattr(installer, "_private_permissions_ok", lambda path, mode: True)
    monkeypatch.setattr(installer, "_run_command", _successful_command)
    report = installer.doctor(client="antigravity", home=tmp_path, python_executable=sys.executable)
    serialized = json.dumps(report, ensure_ascii=False)

    assert report["ok"] is True
    assert report["external_probing_enabled"] is False
    assert report["operator_key_value_returned"] is False
    assert key not in serialized

    config = tmp_path / ".gemini" / "config" / "mcp_config.json"
    payload = json.loads(config.read_text(encoding="utf-8"))
    payload["mcpServers"]["k-guard"]["env"]["K_GUARD_MCP_ENABLE_EXTERNAL_PROBE"] = "1"
    config.write_text(json.dumps(payload), encoding="utf-8")
    failed = installer.doctor(client="antigravity", home=tmp_path, python_executable=sys.executable)
    assert failed["ok"] is False
    assert failed["clients"][0]["status"] == "needs_attention"


def test_doctor_rejects_launcher_that_reenables_external_probe(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    installed = installer.install(client="antigravity", home=tmp_path, python_executable=sys.executable)
    assert installed["ok"] is True
    launcher = tmp_path / ".k-guard" / "mcp-launcher.py"
    launcher.write_text(
        launcher.read_text(encoding="utf-8") + "\nos.environ['K_GUARD_MCP_ENABLE_EXTERNAL_PROBE'] = '1'\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(installer, "_private_permissions_ok", lambda path, mode: True)
    monkeypatch.setattr(installer, "_run_command", _successful_command)
    report = installer.doctor(client="antigravity", home=tmp_path, python_executable=sys.executable)

    checks = {item["name"]: item for item in report["checks"]}
    assert report["ok"] is False
    assert report["external_probing_enabled"] is None
    assert checks["private_launcher"]["ok"] is False
    assert checks["external_probes_default_off"]["ok"] is False


def test_doctor_codex_verifies_cli_json_and_private_receipt(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    codex = str(tmp_path / "codex")
    monkeypatch.setattr(installer.shutil, "which", lambda name: codex if name == "codex" else None)
    monkeypatch.setattr(installer, "_run_command", _successful_command)
    installed = installer.install(client="codex", home=tmp_path, python_executable=sys.executable)
    assert installed["ok"] is True

    launcher = str(tmp_path / ".k-guard" / "mcp-launcher.py")
    python = str(Path(sys.executable).resolve())

    def diagnose(argv, **kwargs):
        del kwargs
        if argv[:4] == [codex, "mcp", "get", "k-guard"]:
            return installer._CommandOutcome(
                0,
                json.dumps(
                    {
                        "name": "k-guard",
                        "enabled": True,
                        "transport": {"type": "stdio", "command": python, "args": [launcher, "--profile", "workspace"]},
                    }
                ),
            )
        return installer._CommandOutcome(0)

    monkeypatch.setattr(installer, "_private_permissions_ok", lambda path, mode: True)
    monkeypatch.setattr(installer, "_run_command", diagnose)
    report = installer.doctor(client="codex", home=tmp_path, python_executable=sys.executable)
    assert report["ok"] is True
    assert report["status"] == "등록 확인 · 실제 호출 대기"
    assert report["connection_state"] == "configured_restart_required"
    assert report["runtime_and_app_connection_verified"] is False
    assert report["clients"][0]["status"] == "configured"
    assert report["clients"][0]["runtime_and_app_connection_verified"] is False
    assert report["clients"][0]["mechanism"] == "codex mcp get --json"


def test_explicit_missing_client_fails_without_creating_launcher(tmp_path, monkeypatch):
    monkeypatch.setattr(installer.shutil, "which", lambda name: None)
    _portable_private_hardening(monkeypatch)

    report = installer.install(client="codex", home=tmp_path, python_executable=sys.executable)

    assert report["ok"] is False
    assert report["clients"][0]["status"] == "not_found"
    assert not (tmp_path / ".k-guard").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not authoritative on Windows")
def test_posix_private_permissions(tmp_path):
    report = installer.install(client="antigravity", home=tmp_path, python_executable=sys.executable)
    assert report["ok"] is True
    assert stat.S_IMODE((tmp_path / ".k-guard").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / ".k-guard" / "operator-evidence.key").stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / ".k-guard" / "mcp-launcher.py").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / ".k-guard" / "workspace-binding.json").stat().st_mode) == 0o600


def test_cli_install_and_doctor_dispatch(monkeypatch, capsys):
    install_report = {"ok": True, "status": "설치 완료", "clients": []}
    doctor_report = {"ok": False, "status": "확인 필요", "message": "재설치가 필요합니다.", "checks": [], "clients": []}
    install_calls = []
    doctor_calls = []
    monkeypatch.setattr(cli, "install_clients", lambda **kwargs: install_calls.append(kwargs) or install_report)
    monkeypatch.setattr(cli, "doctor_installation", lambda **kwargs: doctor_calls.append(kwargs) or doctor_report)

    workspace = str(Path.cwd())
    assert cli.main(["install", "--client", "grok", "--profile", "local-dev", "--workspace", workspace, "--dry-run"]) == 0
    installed_text = capsys.readouterr().out
    assert "안경선배 MCP 연결" in installed_text
    assert "[3/3] 다음 행동" in installed_text

    assert cli.main(["install", "--client", "grok", "--profile", "local-dev", "--dry-run", "--json"]) == 0
    installed_output = json.loads(capsys.readouterr().out)
    assert installed_output["status"] == "설치 완료"
    assert install_calls == [
        {"client": "grok", "profile": "local-dev", "dry_run": True, "workspace": workspace},
        {"client": "grok", "profile": "local-dev", "dry_run": True, "workspace": None},
    ]

    assert cli.main(["doctor", "--client", "chatgpt", "--json"]) == 2
    doctor_output = json.loads(capsys.readouterr().out)
    assert doctor_output["status"] == "확인 필요"
    assert doctor_calls == [{"client": "chatgpt"}]


def test_install_reports_early_configuration_failures_without_side_effects(tmp_path, monkeypatch):
    monkeypatch.setattr(installer.shutil, "which", lambda name: None)

    with pytest.raises(ValueError):
        installer.install(client="unknown", home=tmp_path, python_executable=sys.executable)
    with pytest.raises(ValueError):
        installer.install(client="auto", profile="internet", home=tmp_path, python_executable=sys.executable)

    missing_python = installer.install(
        client="antigravity",
        home=tmp_path,
        python_executable=tmp_path / "missing-python",
    )
    assert missing_python["error_code"] == "PYTHON_EXECUTABLE_NOT_FOUND"

    no_clients = installer.install(client="auto", home=tmp_path, python_executable=sys.executable)
    assert no_clients["error_code"] == "NO_SUPPORTED_CLIENT_FOUND"

    receipt = tmp_path / ".k-guard" / "installation.json"
    receipt.parent.mkdir(parents=True)
    receipt.write_text("[]\n", encoding="utf-8")
    invalid_receipt = installer.install(client="antigravity", home=tmp_path, python_executable=sys.executable)
    assert invalid_receipt["error_code"] == "INVALID_INSTALL_RECEIPT"


def test_install_reports_launcher_and_receipt_failures(tmp_path, monkeypatch):
    codex = str(tmp_path / "codex")
    monkeypatch.setattr(installer.shutil, "which", lambda name: codex if name == "codex" else None)
    original_prepare = installer._prepare_launcher

    def fail_prepare(*args, **kwargs):
        del args, kwargs
        raise installer.InstallerError("private launcher failed")

    monkeypatch.setattr(installer, "_prepare_launcher", fail_prepare)
    failed_launcher = installer.install(client="codex", home=tmp_path, python_executable=sys.executable)
    assert failed_launcher["error_code"] == "PRIVATE_LAUNCHER_SETUP_FAILED"

    monkeypatch.setattr(installer, "_prepare_launcher", original_prepare)
    _portable_private_hardening(monkeypatch)
    monkeypatch.setattr(installer, "_run_command", _successful_command)

    def fail_receipt(*args, **kwargs):
        del args, kwargs
        raise installer.InstallerError("receipt failed")

    monkeypatch.setattr(installer, "_write_receipt", fail_receipt)
    failed_receipt = installer.install(client="codex", home=tmp_path, python_executable=sys.executable)
    assert failed_receipt["ok"] is False
    assert failed_receipt["clients"][-1]["status"] == "receipt_failed"


def test_cli_registration_failure_guides_login_before_exact_retry(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    codex = str(tmp_path / "codex")
    monkeypatch.setattr(installer.shutil, "which", lambda name: codex if name == "codex" else None)
    monkeypatch.setattr(installer, "_run_command", lambda argv, **kwargs: installer._CommandOutcome(1))

    report = installer.install(client="codex", profile="local-dev", home=tmp_path, python_executable=sys.executable)
    rendered = installer.format_install_text(report)

    assert report["ok"] is False
    assert report["next_steps"] == [
        "codex login으로 로그인 상태를 확인하세요.",
        "codex mcp --help로 MCP 명령 사용 가능 여부를 확인하세요.",
        "k-guard install --client codex --profile local-dev",
    ]
    assert rendered.index("codex login") < rendered.index("k-guard install --client codex")


def test_all_fails_preflight_without_partial_configuration_when_clients_are_missing(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    monkeypatch.setattr(installer.shutil, "which", lambda name: None)

    report = installer.install(client="all", home=tmp_path, python_executable=sys.executable)

    assert report["ok"] is False
    assert report["preflight_passed"] is False
    assert report["status"] == "연결 전 준비 필요"
    by_client = {item["client"]: item for item in report["clients"]}
    assert all(by_client[name]["status"] == "not_found" for name in ("chatgpt", "grok", "codex"))
    assert not (tmp_path / ".k-guard").exists()
    assert not (tmp_path / ".gemini").exists()


def test_all_preflights_antigravity_json_before_running_any_client_command(tmp_path, monkeypatch):
    tools = {name: str(tmp_path / name) for name in ("codex", "grok", "tunnel-client")}
    monkeypatch.setattr(installer.shutil, "which", lambda name: tools.get(name))
    monkeypatch.setenv("CONTROL_PLANE_TUNNEL_ID", "tunnel_12345678")
    config = tmp_path / ".gemini" / "config" / "mcp_config.json"
    config.parent.mkdir(parents=True)
    config.write_text("{broken", encoding="utf-8")
    commands: list[list[str]] = []
    monkeypatch.setattr(installer, "_run_command", lambda argv, **kwargs: commands.append(list(argv)) or installer._CommandOutcome(0))

    report = installer.install(client="all", profile="local-dev", home=tmp_path, python_executable=sys.executable)

    assert report["ok"] is False
    assert report["preflight_passed"] is False
    assert report["clients"][0]["failure_code"] == "INVALID_ANTIGRAVITY_CONFIG"
    assert commands == []
    assert not (tmp_path / ".k-guard").exists()


def test_doctor_missing_cli_starts_with_installing_the_client_not_a_failed_repair_loop(tmp_path, monkeypatch):
    monkeypatch.setattr(installer.shutil, "which", lambda name: None)

    report = installer.doctor(client="codex", home=tmp_path, python_executable=sys.executable)

    assert report["ok"] is False
    assert report["next_steps"] == [
        "Codex를 설치하거나 업데이트한 뒤 로그인하세요.",
        "터미널을 다시 열고 codex --help를 확인하세요.",
        "k-guard install --client codex --profile workspace",
    ]


def test_doctor_reports_invalid_receipt_no_targets_and_formats_status(tmp_path, monkeypatch):
    monkeypatch.setattr(installer.shutil, "which", lambda name: None)
    receipt = tmp_path / ".k-guard" / "installation.json"
    receipt.parent.mkdir(parents=True)
    receipt.write_text("{broken", encoding="utf-8")

    report = installer.doctor(client="auto", home=tmp_path, python_executable=sys.executable)
    rendered = installer.format_doctor_text(report)

    assert report["ok"] is False
    assert next(item for item in report["checks"] if item["name"] == "install_receipt")["ok"] is False
    assert report["clients"] == [
        {
            "client": "auto",
            "ok": False,
            "status": "not_found",
            "message": "진단할 지원 클라이언트를 찾지 못했습니다.",
            "mechanism": "auto discovery",
        }
    ]
    assert "[확인] 설치 기록" in rendered
    assert "[확인] 자동 찾기" in rendered


def test_doctor_covers_grok_chatgpt_and_unknown_client_paths(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    tools = {name: str(tmp_path / name) for name in ("grok", "tunnel-client")}
    monkeypatch.setattr(installer.shutil, "which", lambda name: tools.get(name))
    monkeypatch.setenv("CONTROL_PLANE_TUNNEL_ID", "tunnel_12345678")
    monkeypatch.setattr(installer, "_run_command", _successful_command)
    assert installer.install(client="grok", home=tmp_path, python_executable=sys.executable)["ok"] is True
    chatgpt_install = installer.install(client="chatgpt", home=tmp_path, python_executable=sys.executable)
    assert chatgpt_install["ok"] is False
    assert chatgpt_install["clients"][0]["status"] == "profile_initialized_needs_action"

    monkeypatch.setattr(installer, "_private_permissions_ok", lambda path, mode: True)
    python = str(Path(sys.executable).resolve())
    launcher = tmp_path / ".k-guard" / "mcp-launcher.py"

    def diagnose(argv, **kwargs):
        del kwargs
        if argv[1:4] == ["mcp", "list", "--json"]:
            return installer._CommandOutcome(
                0,
                json.dumps([{"name": "k-guard", "command": python, "args": [str(launcher), "--profile", "workspace"], "enabled": True}]),
            )
        if argv[1:4] == ["doctor", "--profile", "k-guard"]:
            return installer._CommandOutcome(
                0,
                json.dumps(
                    {
                        "result": "ok",
                        "checks": [
                            {
                                "id": "mcp_target",
                                "status": "PASS",
                                "summary": installer._expected_launch_command(python, launcher, "workspace"),
                            }
                        ],
                    }
                ),
            )
        return installer._CommandOutcome(0)

    monkeypatch.setattr(installer, "_run_command", diagnose)
    grok = installer.doctor(client="grok", home=tmp_path, python_executable=sys.executable)
    chatgpt = installer.doctor(client="chatgpt", home=tmp_path, python_executable=sys.executable)
    locations = installer._locations(tmp_path)
    unknown = installer._doctor_client(
        "unknown",
        None,
        locations,
        str(Path(sys.executable).resolve()),
        tmp_path,
        {},
        "workspace",
    )

    assert grok["ok"] is True
    assert grok["clients"][0]["status"] == "cli_diagnostic_passed"
    assert grok["clients"][0]["runtime_handshake_verified"] is True
    assert grok["clients"][0]["runtime_and_app_connection_verified"] is False
    assert grok["clients"][0]["mechanism"] == "grok mcp list --json + doctor --json"
    assert chatgpt["ok"] is False
    assert chatgpt["clients"][0]["profile_identity_verified"] is True
    assert chatgpt["clients"][0]["runtime_and_app_connection_verified"] is False
    assert any("CONTROL_PLANE_API_KEY" in step for step in chatgpt["clients"][0]["next_steps"])
    assert chatgpt["clients"][0]["mechanism"] == "tunnel-client doctor --profile k-guard --json"
    assert unknown["status"] == "not_found"


def test_grok_and_chatgpt_doctor_reject_healthy_but_wrong_registration(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    tools = {name: str(tmp_path / name) for name in ("grok", "tunnel-client")}
    monkeypatch.setattr(installer.shutil, "which", lambda name: tools.get(name))
    monkeypatch.setenv("CONTROL_PLANE_TUNNEL_ID", "tunnel_12345678")
    monkeypatch.setattr(installer, "_run_command", _successful_command)
    assert installer.install(client="grok", home=tmp_path, python_executable=sys.executable)["ok"] is True
    assert installer.install(client="chatgpt", home=tmp_path, python_executable=sys.executable)["clients"][0]["configured"] is True

    monkeypatch.setattr(installer, "_private_permissions_ok", lambda path, mode: True)

    def wrong_identity(argv, **kwargs):
        del kwargs
        if argv[1:4] == ["mcp", "list", "--json"]:
            return installer._CommandOutcome(
                0,
                json.dumps([{"name": "k-guard", "command": sys.executable, "args": ["wrong-server.py"], "enabled": True}]),
            )
        if argv[1:4] == ["doctor", "--profile", "k-guard"]:
            return installer._CommandOutcome(
                0,
                json.dumps({"result": "ok", "checks": [{"id": "mcp_target", "status": "PASS", "summary": "python wrong-server.py"}]}),
            )
        return installer._CommandOutcome(0)

    monkeypatch.setattr(installer, "_run_command", wrong_identity)
    grok = installer.doctor(client="grok", home=tmp_path, python_executable=sys.executable)
    chatgpt = installer.doctor(client="chatgpt", home=tmp_path, python_executable=sys.executable)

    assert grok["ok"] is False
    assert grok["clients"][0]["status"] == "needs_attention"
    assert chatgpt["ok"] is False
    assert chatgpt["clients"][0]["profile_identity_verified"] is False


def test_chatgpt_install_and_doctor_fail_closed_on_missing_tunnel_inputs(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    tunnel_executable = str(tmp_path / "tunnel-client")
    monkeypatch.setattr(installer.shutil, "which", lambda name: tunnel_executable if name == "tunnel-client" else None)
    monkeypatch.setattr(installer, "_run_command", _successful_command)
    missing = installer.install(client="chatgpt", home=tmp_path, python_executable=sys.executable)
    assert missing["ok"] is False
    assert missing["clients"][0]["failure_code"] == "CHATGPT_TUNNEL_ID_REQUIRED"
    assert "tunnel_12345678" not in json.dumps(missing)
    assert not (tmp_path / ".k-guard").exists()

    monkeypatch.setenv("CONTROL_PLANE_TUNNEL_ID", "tunnel_12345678")
    installed = installer.install(client="chatgpt", home=tmp_path, python_executable=sys.executable)
    assert installed["ok"] is False
    assert installed["status"] == "부분 연결 · 다음 단계 필요"
    assert installed["clients"][0]["configured"] is True
    receipt = json.loads((tmp_path / ".k-guard" / "installation.json").read_text(encoding="utf-8"))
    assert receipt["clients"]["chatgpt"]["installed"] is False
    assert "tunnel_12345678" not in json.dumps(installed)
    monkeypatch.setattr(installer, "_private_permissions_ok", lambda path, mode: True)
    monkeypatch.setattr(
        installer,
        "_run_command",
        lambda argv, **kwargs: installer._CommandOutcome(1) if "doctor" in argv else installer._CommandOutcome(0),
    )
    assert installer.doctor(client="chatgpt", home=tmp_path, python_executable=sys.executable)["ok"] is False


def test_antigravity_schema_and_write_failures_preserve_original(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    config = tmp_path / ".gemini" / "config" / "mcp_config.json"
    config.parent.mkdir(parents=True)
    config.write_text('{"mcpServers": []}\n', encoding="utf-8")

    invalid_schema = installer.install(client="antigravity", home=tmp_path, python_executable=sys.executable)
    assert invalid_schema["clients"][0]["failure_code"] == "INVALID_MCP_SERVERS_SCHEMA"

    config.write_text('{"mcpServers": {}}\n', encoding="utf-8")
    original_atomic = installer._atomic_write_json

    def fail_atomic(*args, **kwargs):
        if args and args[0] == config:
            raise installer.InstallerError("write blocked")
        return original_atomic(*args, **kwargs)

    monkeypatch.setattr(installer, "_atomic_write_json", fail_atomic)
    write_failed = installer.install(client="antigravity", home=tmp_path, python_executable=sys.executable)
    assert write_failed["clients"][0]["failure_code"] == "ANTIGRAVITY_CONFIG_WRITE_FAILED"
    assert json.loads(config.read_text(encoding="utf-8")) == {"mcpServers": {}}
    monkeypatch.setattr(installer, "_atomic_write_json", original_atomic)


def test_launcher_update_plan_and_private_directory_failure(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    first = installer.install(client="antigravity", profile="workspace", home=tmp_path, python_executable=sys.executable)
    second = installer.install(client="antigravity", profile="local-dev", home=tmp_path, python_executable=sys.executable)
    planned = installer._plan_launcher(installer._locations(tmp_path))

    assert first["launcher"]["status"] == "created"
    assert second["launcher"]["status"] == "preserved"
    assert first["clients"][0]["profile"] == "workspace"
    assert second["clients"][0]["profile"] == "local-dev"
    assert planned["ready"] is True

    blocked_home = tmp_path / "blocked"
    blocked_home.write_text("not a directory", encoding="utf-8")
    with pytest.raises(installer.InstallerError):
        installer._ensure_private_directory(blocked_home)

    bad_locations = installer._locations(tmp_path / "bad-plan")
    bad_locations.private_dir.mkdir(parents=True)
    bad_locations.key.write_text("x" * 40, encoding="utf-8")
    bad_locations.launcher.mkdir()
    with pytest.raises(installer.InstallerError):
        installer._plan_launcher(bad_locations)


def test_second_client_profile_does_not_mutate_first_client_profile_or_launcher(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    tools = {name: str(tmp_path / name) for name in ("grok", "codex")}
    monkeypatch.setattr(installer.shutil, "which", lambda name: tools.get(name))
    monkeypatch.setattr(installer, "_run_command", _successful_command)

    first = installer.install(client="grok", profile="workspace", home=tmp_path, python_executable=sys.executable)
    launcher = tmp_path / ".k-guard" / "mcp-launcher.py"
    source_before = launcher.read_text(encoding="utf-8")
    second = installer.install(client="codex", profile="local-dev", home=tmp_path, python_executable=sys.executable)
    source_after = launcher.read_text(encoding="utf-8")
    receipt = json.loads((tmp_path / ".k-guard" / "installation.json").read_text(encoding="utf-8"))

    assert first["ok"] is True and second["ok"] is True
    assert source_before == source_after
    assert second["launcher"]["status"] == "preserved"
    assert receipt["clients"]["grok"]["profile"] == "workspace"
    assert receipt["clients"]["codex"]["profile"] == "local-dev"


def test_json_command_and_process_helpers_cover_failure_boundaries(tmp_path, monkeypatch):
    python = str(Path(sys.executable).resolve())
    launcher = tmp_path / "launcher.py"
    assert installer._command_json_matches("{bad", python, launcher, "workspace") is False
    assert installer._receipt_matches(None, python, launcher) is False

    root_list = tmp_path / "list.json"
    root_list.write_text("[]", encoding="utf-8")
    with pytest.raises(installer.InstallerError):
        installer._load_json_object(root_list, "test")
    with pytest.raises(installer.InstallerError):
        installer._backup_json(tmp_path / "missing.json")

    plain = tmp_path / "plain.json"
    installer._atomic_write_json(plain, {"ok": True}, private=False)
    assert json.loads(plain.read_text(encoding="utf-8")) == {"ok": True}


def test_registration_identity_parsers_fail_closed_on_malformed_shapes(tmp_path, monkeypatch):
    python = str(Path(sys.executable).resolve())
    launcher = tmp_path / "launcher.py"
    profile = "workspace"
    expected_command = installer._expected_launch_command(python, launcher, profile)

    valid_codex = {
        "name": "k-guard",
        "enabled": True,
        "transport": {"type": "stdio", "command": python, "args": [str(launcher), "--profile", profile]},
    }
    assert installer._command_json_matches(json.dumps(valid_codex), python, launcher, profile) is True
    invalid_codex_payloads = [
        [],
        {"name": "other", "enabled": True, "transport": valid_codex["transport"]},
        {"name": "k-guard", "enabled": False, "transport": valid_codex["transport"]},
        {"name": "k-guard", "enabled": True, "transport": []},
        {"name": "k-guard", "enabled": True, "transport": {"type": "http", "command": python, "args": [str(launcher)]}},
        {
            "name": "k-guard",
            "enabled": True,
            "transport": {"type": "stdio", "command": "C:/malicious/other-server.exe", "args": [python, str(launcher)]},
        },
        {
            "name": "k-guard",
            "enabled": True,
            "transport": {"type": "stdio", "command": python, "args": [str(launcher), "--extra"]},
        },
    ]
    for payload in invalid_codex_payloads:
        assert installer._command_json_matches(json.dumps(payload), python, launcher, profile) is False

    assert installer._grok_registration_matches("{bad", python, launcher, profile) is False
    assert installer._grok_registration_matches(json.dumps({"servers": {"k-guard": {}}}), python, launcher, profile) is False
    assert installer._grok_registration_matches(
        json.dumps(
            {
                "servers": [
                    None,
                    {"name": "other", "command": python, "args": [str(launcher)]},
                    {"name": "k-guard", "command": python, "args": [str(launcher)], "enabled": False},
                ]
            }
        ),
        python,
        launcher,
        profile,
    ) is False

    assert installer._tunnel_doctor_matches("{bad", python, launcher, profile) is False
    assert installer._tunnel_doctor_matches("[]", python, launcher, profile) is False
    assert installer._tunnel_doctor_matches(json.dumps({"result": "fail", "checks": []}), python, launcher, profile) is False
    assert installer._tunnel_doctor_matches(json.dumps({"result": "ok", "checks": {}}), python, launcher, profile) is False
    assert installer._tunnel_doctor_matches(json.dumps({"result": "ok", "checks": []}), python, launcher, profile) is False
    assert installer._tunnel_doctor_matches(
        json.dumps({"result": "ok", "checks": [{"id": "mcp_target", "status": "FAIL", "summary": expected_command}]}),
        python,
        launcher,
        profile,
    ) is False
    assert installer._tunnel_doctor_matches(
        json.dumps({"result": "ok", "checks": [{"id": "mcp_target", "status": "PASS", "summary": expected_command}]}),
        python,
        launcher,
        profile,
    ) is True

    def timeout_run(*args, **kwargs):
        del args, kwargs
        raise subprocess.TimeoutExpired("test", 1)

    monkeypatch.setattr(installer.subprocess, "run", timeout_run)
    assert installer._run_command(["test"]).error == "COMMAND_TIMEOUT"

    def missing_run(*args, **kwargs):
        del args, kwargs
        raise OSError("missing")

    monkeypatch.setattr(installer.subprocess, "run", missing_run)
    assert installer._run_command(["test"]).error == "COMMAND_START_FAILED"

    run_kwargs = {}

    def completed_run(*args, **kwargs):
        run_kwargs.update(kwargs)
        return subprocess.CompletedProcess(args[0], 0, stdout="ok", stderr="")

    monkeypatch.setattr(installer.subprocess, "run", completed_run)
    completed = installer._run_command(["test"])
    assert completed.ok is True and completed.stdout == "ok"
    assert run_kwargs["encoding"] == "utf-8"
    assert run_kwargs["errors"] == "replace"


def test_windows_acl_and_sid_helpers_fail_closed(tmp_path, monkeypatch):
    if os.name != "nt":
        pytest.skip("Windows-specific ACL contract")

    monkeypatch.setattr(installer, "_run_command", lambda *args, **kwargs: installer._CommandOutcome(1))
    with pytest.raises(installer.InstallerError):
        installer._windows_current_sid()

    monkeypatch.setattr(installer, "_run_command", lambda *args, **kwargs: installer._CommandOutcome(0, '"user","bad"\n'))
    with pytest.raises(installer.InstallerError):
        installer._windows_current_sid()

    monkeypatch.setattr(installer, "_run_command", lambda *args, **kwargs: installer._CommandOutcome(0, '"user","S-1-5-21-123"\n'))
    assert installer._windows_current_sid() == "S-1-5-21-123"

    target = tmp_path / "private.txt"
    target.write_text("x", encoding="utf-8")
    sid = "S-1-5-21-123"
    requests = []

    def private_acl_command(argv, **kwargs):
        requests.append((list(argv), kwargs.get("input_text")))
        if argv[-1] == installer._WINDOWS_READ_PRIVATE_ACL_SCRIPT:
            return installer._CommandOutcome(0, _private_acl_payload(sid))
        return installer._CommandOutcome(0)

    monkeypatch.setattr(installer, "_windows_current_sid", lambda: sid)
    monkeypatch.setattr(installer, "_run_command", private_acl_command)
    installer._harden_private_path(target, is_directory=False, mode=0o600)
    assert installer._private_permissions_ok(target, 0o600) is True
    set_request = next(item for item in requests if item[0][-1] == installer._WINDOWS_SET_PRIVATE_ACL_SCRIPT)
    assert json.loads(set_request[1]) == {"path": str(target), "sid": sid, "is_directory": False}
    assert str(target) not in set_request[0][-1]

    foreign_rule = {
        "sid": "S-1-1-0",
        "access_type": "Allow",
        "inherited": False,
        "full_control": True,
        "inheritance_flags": "None",
        "propagation_flags": "None",
    }
    monkeypatch.setattr(
        installer,
        "_run_command",
        lambda *args, **kwargs: installer._CommandOutcome(
            0,
            _private_acl_payload(sid, extra_rules=[foreign_rule]),
        ),
    )
    assert installer._windows_private_acl_ok(target, sid=sid, is_directory=False) is False

    monkeypatch.setattr(installer, "_run_command", lambda *args, **kwargs: installer._CommandOutcome(0, "not-json"))
    assert installer._windows_private_acl_ok(target, sid=sid, is_directory=False) is False

    monkeypatch.setattr(installer, "_run_command", lambda *args, **kwargs: installer._CommandOutcome(1))
    with pytest.raises(installer.InstallerError):
        installer._harden_private_path(target, is_directory=False, mode=0o600)


def test_windows_private_acl_script_builds_a_fresh_protected_descriptor():
    script = installer._WINDOWS_SET_PRIVATE_ACL_SCRIPT

    assert "DirectorySecurity]::new()" in script
    assert "FileSecurity]::new()" in script
    assert "SetAccessRuleProtection($true, $false)" in script
    assert "::GetAccessControl($target)" not in script


@pytest.mark.skipif(os.name != "nt", reason="Windows-specific ACL integration contract")
def test_windows_private_acl_removes_and_detects_explicit_everyone_ace(tmp_path):
    target = tmp_path / "private-acl.txt"
    target.write_text("private", encoding="utf-8")
    everyone = "*S-1-1-0:F"

    seeded = installer._run_command(
        ["icacls", str(target), "/inheritance:r", "/grant:r", everyone],
        timeout=15,
    )
    assert seeded.ok is True

    installer._harden_private_path(target, is_directory=False, mode=0o600)
    assert installer._private_permissions_ok(target, 0o600) is True

    reintroduced = installer._run_command(["icacls", str(target), "/grant", everyone], timeout=15)
    assert reintroduced.ok is True
    assert installer._private_permissions_ok(target, 0o600) is False

    installer._harden_private_path(target, is_directory=False, mode=0o600)


@pytest.mark.skipif(os.name != "nt", reason="Windows-specific receipt ACL integration contract")
def test_doctor_rejects_receipt_with_explicit_everyone_ace(tmp_path):
    installed = installer.install(client="antigravity", home=tmp_path, python_executable=sys.executable)
    assert installed["ok"] is True
    receipt = tmp_path / ".k-guard" / "installation.json"
    everyone = "*S-1-1-0:F"

    widened = installer._run_command(["icacls", str(receipt), "/grant", everyone], timeout=15)
    assert widened.ok is True
    assert installer._private_permissions_ok(receipt, 0o600) is False
    try:
        report = installer.doctor(client="antigravity", home=tmp_path, python_executable=sys.executable)
        checks = {item["name"]: item for item in report["checks"]}
        assert report["ok"] is False
        assert checks["private_permissions"]["ok"] is False
    finally:
        installer._harden_private_path(receipt, is_directory=False, mode=0o600)


def test_workspace_binding_parser_and_keyed_identity_fail_closed(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    regular_file = tmp_path / "file.txt"
    regular_file.write_text("not a directory", encoding="utf-8")

    with pytest.raises(installer.InstallerError):
        installer._canonical_workspace(regular_file)
    with pytest.raises(installer.InstallerError):
        installer._workspace_root_hash(workspace, "too-short")

    binding = tmp_path / "binding.json"
    invalid_payloads = [
        [],
        {"schema_version": 999, "canonical_root": str(workspace)},
        {"schema_version": installer._WORKSPACE_BINDING_SCHEMA_VERSION, "canonical_root": "relative"},
        {"schema_version": installer._WORKSPACE_BINDING_SCHEMA_VERSION, "canonical_root": "bad\u0000root"},
    ]
    for payload in invalid_payloads:
        binding.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(installer.InstallerError):
            installer._load_workspace_binding(binding, require_live_root=False)

    binding.write_text(
        json.dumps(installer._workspace_binding_payload((tmp_path / "missing").resolve())),
        encoding="utf-8",
    )
    with pytest.raises(installer.InstallerError):
        installer._load_workspace_binding(binding, require_live_root=True)

    locations = installer._locations(tmp_path)
    assert installer._receipt_workspace_matches({}, locations, workspace, "short") is False
    assert installer._receipt_workspace_matches(None, locations, workspace, None) is False


def test_launcher_generation_rejects_key_leak_and_unreadable_existing_source(tmp_path, monkeypatch):
    _portable_private_hardening(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    locations = installer._locations(tmp_path / "home")

    def leak_key(key_path: Path, workspace_binding_path: Path | None = None) -> str:
        del workspace_binding_path
        return key_path.read_text(encoding="utf-8")

    monkeypatch.setattr(installer, "_launcher_source", leak_key)
    with pytest.raises(installer.InstallerError, match="운영자 키"):
        installer._prepare_launcher(locations, "workspace", sys.executable, workspace)

    monkeypatch.undo()
    _portable_private_hardening(monkeypatch)
    monkeypatch.setattr(installer, "_run_command", _successful_command)
    report = installer.install(
        client="antigravity",
        home=locations.user_home,
        workspace=workspace,
        python_executable=sys.executable,
    )
    assert report["ok"] is True
    locations.launcher.write_bytes(b"\xff\xfe\xfd")
    with pytest.raises(installer.InstallerError, match="기존 개인 런처"):
        installer._plan_launcher(locations, workspace)
