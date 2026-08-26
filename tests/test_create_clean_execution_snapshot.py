from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "create_clean_execution_snapshot.py"
SPEC = importlib.util.spec_from_file_location("clean_execution_snapshot_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
snapshot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(snapshot)


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def _repository(root: Path) -> Path:
    root.mkdir(parents=True)
    _git(root, "init", "--quiet")
    _git(root, "config", "user.email", "tests@example.invalid")
    _git(root, "config", "user.name", "K-Guard Tests")
    (root / "src" / "k_guard_mcp").mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "LICENSES").mkdir()
    (root / "pyproject.toml").write_text("[project]\nname = 'example'\n", encoding="utf-8")
    (root / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
    (root / "README.md").write_text("# Example\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (root / "LICENSES" / "MIT.txt").write_text("MIT\n", encoding="utf-8")
    (root / "src" / "k_guard_mcp" / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "scripts" / "runner.py").write_text("print('run')\n", encoding="utf-8")
    _git(root, "add", "--all")
    _git(root, "commit", "--quiet", "-m", "baseline")
    return root


def test_snapshot_binds_dirty_source_content_without_dirtying_execution_carrier(tmp_path: Path) -> None:
    source = _repository(tmp_path / "source")
    (source / "src" / "k_guard_mcp" / "__init__.py").write_text("VALUE = 2\n", encoding="utf-8")
    (source / "scripts" / "untracked.py").write_text("print('new')\n", encoding="utf-8")
    snapshot_root = tmp_path / "external" / "execution-snapshot"
    manifest_path = tmp_path / "external" / "execution-snapshot-manifest.json"

    payload = snapshot.create_snapshot(source, snapshot_root, manifest_path)

    assert payload["source_target"] == snapshot.capture_target(source)
    assert payload["source_scope"] == payload["snapshot_scope"]
    assert (snapshot_root / "scripts" / "untracked.py").read_text(encoding="utf-8") == "print('new')\n"
    assert (snapshot_root / ".gitignore").read_text(encoding="utf-8") == "__pycache__/\n"
    assert _git(snapshot_root, "status", "--porcelain") == ""
    assert snapshot.validate_snapshot(payload, snapshot_root) == payload


def test_snapshot_rejects_outputs_inside_source_worktree(tmp_path: Path) -> None:
    source = _repository(tmp_path / "source")
    with pytest.raises(snapshot.SnapshotError, match="snapshot_output_must_be_external"):
        snapshot.create_snapshot(
            source,
            source / "external-snapshot",
            tmp_path / "manifest.json",
        )


def test_snapshot_rejects_a_destination_that_would_exceed_windows_path_budget(tmp_path: Path) -> None:
    source = _repository(tmp_path / "source")
    with pytest.raises(snapshot.SnapshotError, match="snapshot_destination_path_too_long"):
        snapshot.create_snapshot(
            source,
            tmp_path / ("snapshot" * 22),
            tmp_path / "manifest.json",
        )
