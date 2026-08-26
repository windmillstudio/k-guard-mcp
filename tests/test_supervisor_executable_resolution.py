from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "supervisor_executable_resolution.py"
SPEC = importlib.util.spec_from_file_location("supervisor_executable_resolution_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
resolution = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolution)


def test_bare_windows_npm_shim_resolves_to_subprocess_invocable_cmd(monkeypatch) -> None:
    expected = r"C:\\Users\\tester\\AppData\\Roaming\\npm\\claude.cmd"
    monkeypatch.setattr(resolution.shutil, "which", lambda value: expected if value == "claude" else None)

    assert resolution.resolve_supervisor_executable("claude") == str(Path(expected).resolve(strict=False))


def test_explicit_existing_path_is_preserved_when_path_lookup_fails(tmp_path: Path, monkeypatch) -> None:
    executable = tmp_path / "cline.cmd"
    executable.write_text("shim\n", encoding="utf-8")
    monkeypatch.setattr(resolution.shutil, "which", lambda _: None)

    assert resolution.resolve_supervisor_executable(str(executable)) == str(executable.resolve())


def test_claude_npm_shim_resolves_only_its_native_candidate(tmp_path: Path, monkeypatch) -> None:
    shim = tmp_path / "npm" / "claude.cmd"
    native = tmp_path / "npm" / "node_modules" / "@anthropic-ai" / "claude-code" / "bin" / "claude.exe"
    shim.parent.mkdir(parents=True)
    native.parent.mkdir(parents=True)
    shim.write_text("shim\n", encoding="utf-8")
    native.write_text("native\n", encoding="utf-8")
    monkeypatch.setattr(resolution.shutil, "which", lambda value: str(shim) if value == "claude" else None)

    assert resolution.resolve_supervisor_executable("claude", provider="claude") == str(native.resolve())
    assert resolution.resolve_supervisor_executable("claude", provider="glm") == str(shim.resolve())


def test_cline_npm_shim_resolves_one_native_candidate(tmp_path: Path, monkeypatch) -> None:
    shim = tmp_path / "npm" / "cline.cmd"
    native = (
        tmp_path
        / "npm"
        / "node_modules"
        / "cline"
        / "node_modules"
        / "@cline"
        / "cli-windows-x64"
        / "bin"
        / "cline.exe"
    )
    shim.parent.mkdir(parents=True)
    native.parent.mkdir(parents=True)
    shim.write_text("shim\n", encoding="utf-8")
    native.write_text("native\n", encoding="utf-8")
    monkeypatch.setattr(resolution.shutil, "which", lambda value: str(shim) if value == "cline" else None)

    assert resolution.resolve_supervisor_executable("cline", provider="glm") == str(native.resolve())


def test_missing_native_candidate_keeps_shim_for_fail_closed_provider_result(tmp_path: Path, monkeypatch) -> None:
    shim = tmp_path / "npm" / "cline.cmd"
    shim.parent.mkdir(parents=True)
    shim.write_text("shim\n", encoding="utf-8")
    monkeypatch.setattr(resolution.shutil, "which", lambda value: str(shim) if value == "cline" else None)

    assert resolution.resolve_supervisor_executable("cline", provider="glm") == str(shim.resolve())


def test_missing_command_remains_fail_closed_candidate(monkeypatch) -> None:
    monkeypatch.setattr(resolution.shutil, "which", lambda _: None)

    assert resolution.resolve_supervisor_executable("missing-supervisor") == "missing-supervisor"


def test_mapping_resolves_each_supervisor_once(monkeypatch) -> None:
    resolved = {"claude": "C:/tools/claude.cmd", "grok": "C:/tools/grok.exe", "cline": "C:/tools/cline.cmd"}
    calls: list[str] = []

    def fake_resolve(value: str, *, provider: str | None = None) -> str:
        calls.append(value)
        return resolved[value]

    monkeypatch.setattr(resolution, "resolve_supervisor_executable", fake_resolve)

    assert resolution.resolve_supervisor_executables({"claude": "claude", "grok": "grok", "glm": "cline"}) == {
        "claude": "C:/tools/claude.cmd",
        "grok": "C:/tools/grok.exe",
        "glm": "C:/tools/cline.cmd",
    }
    assert calls == ["claude", "grok", "cline"]
