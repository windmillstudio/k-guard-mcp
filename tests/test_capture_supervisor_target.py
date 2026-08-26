from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "capture_supervisor_target.py"
SPEC = importlib.util.spec_from_file_location("capture_supervisor_target_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
target_capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(target_capture)


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


def _repository(tmp_path: Path) -> Path:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "tests@example.invalid")
    _git(tmp_path, "config", "user.name", "K-Guard Tests")
    (tmp_path / "app.txt").write_text("first\n", encoding="utf-8")
    _git(tmp_path, "add", "app.txt")
    _git(tmp_path, "commit", "-m", "baseline")
    return tmp_path


def test_content_bound_target_changes_for_same_dirty_path_when_file_contents_change(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "app.txt").write_text("second\n", encoding="utf-8")
    first = target_capture.capture_target(root)
    (root / "app.txt").write_text("third\n", encoding="utf-8")
    second = target_capture.capture_target(root)

    assert first["head_git_oid"] == second["head_git_oid"]
    assert first["dirty_path_set_sha256"] == second["dirty_path_set_sha256"]
    assert first["dirty_worktree_sha256"] != second["dirty_worktree_sha256"]


def test_content_bound_target_changes_for_untracked_file_contents(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    note = root / "evidence.txt"
    note.write_text("one\n", encoding="utf-8")
    first = target_capture.capture_target(root)
    note.write_text("two\n", encoding="utf-8")
    second = target_capture.capture_target(root)

    assert first["dirty_path_set_sha256"] == second["dirty_path_set_sha256"]
    assert first["dirty_worktree_sha256"] != second["dirty_worktree_sha256"]
