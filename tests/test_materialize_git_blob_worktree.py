from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "materialize_git_blob_worktree.py"
SPEC = importlib.util.spec_from_file_location("blob_worktree_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def test_materializes_raw_blob_bytes_despite_dirty_source_worktree(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "--quiet")
    _git(source, "config", "user.email", "tests@example.invalid")
    _git(source, "config", "user.name", "K-Guard Tests")
    (source / ".gitattributes").write_bytes(b"* text=auto\n")
    (source / "app.txt").write_bytes(b"one\ntwo\n")
    _git(source, "add", "--all")
    _git(source, "commit", "--quiet", "-m", "baseline")
    revision = _git(source, "rev-parse", "HEAD")
    (source / "app.txt").write_bytes(b"dirty\r\n")

    output = tmp_path / "outside" / "materialized"
    receipt = tool.materialize(source, output, revision, "https://github.com/example/repository.git")

    expected = subprocess.check_output(["git", "-C", str(source), "show", f"{revision}:app.txt"])
    assert (output / "app.txt").read_bytes() == expected == b"one\ntwo\n"
    assert _git(output, "status", "--porcelain") == ""
    assert receipt["file_count"] == 2
    assert receipt["worktree_clean"] is True
