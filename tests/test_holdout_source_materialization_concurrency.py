from __future__ import annotations

import concurrent.futures
import hashlib
import importlib.util
import subprocess
import threading
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "holdout_source_materialization.py"
SPEC = importlib.util.spec_from_file_location(
    "holdout_source_materialization_concurrency_test", SCRIPT
)
assert SPEC and SPEC.loader
source_materialization = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source_materialization)

EMPTY_GIT_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        check=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, str, str]:
    root = tmp_path / "app"
    root.mkdir()
    _git(root, "init", "--initial-branch=main")
    _git(root, "config", "user.email", "holdout@example.invalid")
    _git(root, "config", "user.name", "Holdout Fixture")
    _git(root, "config", "core.autocrlf", "false")
    _git(root, "remote", "add", "origin", "https://github.com/example/fixture.git")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_bytes(b"print('bound')\n")
    (root / "README.md").write_bytes(b"# Fixture\n")
    _git(root, "add", "--all")
    _git(root, "commit", "-m", "fixture")
    return root, _git(root, "rev-parse", "HEAD"), _git(root, "rev-parse", "HEAD^{tree}")


def _receipt(root: Path, commit: str, tree: str) -> dict:
    return source_materialization.build_git_materialization_receipt(
        root,
        expected_repository_id="example/fixture",
        expected_commit=commit,
        expected_tree=tree,
    )


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _git_metadata_snapshot(root: Path) -> dict:
    git_dir = root / ".git"
    object_rows: list[tuple[str, str, int]] = []
    for path in sorted((git_dir / "objects").rglob("*")):
        if path.is_file():
            raw = path.read_bytes()
            object_rows.append(
                (path.relative_to(git_dir).as_posix(), _sha256(raw), len(raw))
            )
    return {
        "config_sha256": _sha256((git_dir / "config").read_bytes()),
        "index_sha256": _sha256((git_dir / "index").read_bytes()),
        "objects": tuple(object_rows),
    }


def _completed(raw: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(["git"], 0, stdout=raw, stderr=b"")


def test_index_tree_check_uses_read_only_stage_zero_listing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    commands: list[tuple[str, ...]] = []

    def fake_run_git(
        root: Path,
        *args: str,
        **kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        commands.append(args)
        return _completed(b"")

    monkeypatch.setattr(source_materialization, "_run_git", fake_run_git)

    source_materialization._require_exact_index_tree(tmp_path, EMPTY_GIT_TREE)

    assert commands == [("ls-files", "--stage", "-z")]


def test_read_only_index_verifier_rejects_staged_divergence(tmp_path: Path) -> None:
    root, commit, tree = _repository(tmp_path)
    target = root / "src" / "app.py"
    original = target.read_bytes()
    target.write_bytes(b"print('staged-only')\n")
    _git(root, "add", "src/app.py")
    target.write_bytes(original)

    with pytest.raises(ValueError, match="index differs"):
        _receipt(root, commit, tree)


@pytest.mark.parametrize("stage", ["1", "2", "3"])
def test_index_stage_parser_rejects_unmerged_entries(stage: str) -> None:
    raw = (
        b"100644 "
        + b"1" * 40
        + f" {stage}\tsrc/app.py\0".encode("ascii")
    )

    with pytest.raises(ValueError, match="unmerged|nonzero-stage"):
        source_materialization._parse_ls_files_stage(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b"100644 " + b"1" * 40 + b" 0 src/app.py\0",
        b"100644 " + b"1" * 40 + b"\tsrc/app.py\0",
        b"100644 " + b"1" * 40 + b" 0\tsrc/app.py",
        b"100644 " + b"1" * 40 + b" 0\t\0",
    ],
)
def test_index_stage_parser_rejects_malformed_output(raw: bytes) -> None:
    with pytest.raises(ValueError):
        source_materialization._parse_ls_files_stage(raw)


@pytest.mark.parametrize("mode", ["120000", "160000"])
def test_index_stage_parser_rejects_symlink_and_submodule_modes(mode: str) -> None:
    raw = (
        mode.encode("ascii")
        + b" "
        + b"1" * 40
        + b" 0\tlinked-or-submodule\0"
    )

    with pytest.raises(ValueError, match="symlink, submodule"):
        source_materialization._parse_ls_files_stage(raw)


def test_concurrent_receipts_are_identical_and_do_not_mutate_git_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, commit, tree = _repository(tmp_path)
    before = _git_metadata_snapshot(root)
    original_run_git = source_materialization._run_git
    stage_barrier = threading.Barrier(2, timeout=10.0)

    def synchronized_run_git(
        root_arg: Path,
        *args: str,
        **kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        if args == ("ls-files", "--stage", "-z"):
            stage_barrier.wait()
        return original_run_git(root_arg, *args, **kwargs)

    monkeypatch.setattr(source_materialization, "_run_git", synchronized_run_git)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(_receipt, root, commit, tree) for _ in range(2)]
        receipts = [future.result(timeout=60.0) for future in futures]

    after = _git_metadata_snapshot(root)

    assert receipts[0] == receipts[1]
    assert source_materialization.canonical_json_bytes(receipts[0]) == (
        source_materialization.canonical_json_bytes(receipts[1])
    )
    assert before == after
