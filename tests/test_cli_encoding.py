from __future__ import annotations

from types import SimpleNamespace

import k_guard_mcp.cli as cli


class _ReconfigurableStream:
    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    def reconfigure(self, **kwargs: str) -> None:
        self.calls.append(kwargs)


def test_windows_cli_forces_utf8_for_redirected_streams(monkeypatch) -> None:
    stdout = _ReconfigurableStream()
    stderr = _ReconfigurableStream()
    monkeypatch.setattr(cli, "sys", SimpleNamespace(platform="win32", stdout=stdout, stderr=stderr))

    cli._configure_windows_utf8_streams()

    assert stdout.calls == [{"encoding": "utf-8"}]
    assert stderr.calls == [{"encoding": "utf-8"}]


def test_non_windows_cli_leaves_streams_unchanged(monkeypatch) -> None:
    stdout = _ReconfigurableStream()
    stderr = _ReconfigurableStream()
    monkeypatch.setattr(cli, "sys", SimpleNamespace(platform="linux", stdout=stdout, stderr=stderr))

    cli._configure_windows_utf8_streams()

    assert stdout.calls == []
    assert stderr.calls == []
