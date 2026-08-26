from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "holdout_source_materialization.py"
SPEC = importlib.util.spec_from_file_location("holdout_source_materialization_test", SCRIPT)
assert SPEC and SPEC.loader
source_materialization = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source_materialization)


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
    (root / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
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


def test_git_materialization_binds_every_working_byte_to_commit(tmp_path: Path) -> None:
    root, commit, tree = _repository(tmp_path)

    receipt = _receipt(root, commit, tree)

    assert receipt["passed"] is True
    assert receipt["commit"] == commit
    assert receipt["commit_object_hash_match"] is True
    assert receipt["commit_tree"] == tree
    assert receipt["tree_object_reconstruction_match"] is True
    assert receipt["source_worktree_clean"] is True
    assert receipt["source_worktree_clean_method"] == (
        source_materialization.BLOB_EXACT_CLEAN_METHOD
    )
    assert receipt["git_porcelain_clean"] is True
    assert receipt["index_tree_match"] is True
    assert receipt["physical_bytes_match_git_blobs"] is True
    assert receipt["git_fsck_strict_passed"] is True
    assert (
        receipt["scanner_visible_tree_contract"]
        == source_materialization.SCANNER_VISIBLE_TREE_CONTRACT
    )
    assert receipt["origin_repository_id"] == "example/fixture"
    assert receipt["file_count"] == 2
    assert [row["path"] for row in receipt["files"]] == [".gitignore", "src/app.py"]
    assert all(row["git_blob_sha1"] for row in receipt["files"])
    assert source_materialization.canonical_json_bytes(receipt).endswith(b"\n")
    parsed = json.loads(source_materialization.canonical_json_bytes(receipt))
    assert parsed == receipt


@pytest.mark.parametrize("kind", ["ignored", "untracked", "modified", "deleted"])
def test_git_materialization_rejects_any_filesystem_divergence(
    tmp_path: Path,
    kind: str,
) -> None:
    root, commit, tree = _repository(tmp_path)
    if kind == "ignored":
        (root / "ignored.txt").write_text("not in commit\n", encoding="utf-8")
    elif kind == "untracked":
        (root / "untracked.env").write_text("TOKEN=fixture\n", encoding="utf-8")
    elif kind == "modified":
        (root / "src" / "app.py").write_bytes(b"print('changed')\n")
    else:
        (root / "src" / "app.py").unlink()

    with pytest.raises(ValueError, match="materialized source"):
        _receipt(root, commit, tree)


def test_git_materialization_rejects_staged_index_divergence(tmp_path: Path) -> None:
    root, commit, tree = _repository(tmp_path)
    blob = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=root,
        input=b"print('staged-only')\n",
        capture_output=True,
        check=True,
    ).stdout.decode("ascii").strip()
    _git(root, "update-index", "--cacheinfo", f"100644,{blob},src/app.py")

    with pytest.raises(ValueError, match="index differs"):
        _receipt(root, commit, tree)


def test_git_materialization_accepts_blob_exact_noncanonical_text_commit(
    tmp_path: Path,
) -> None:
    root = tmp_path / "attribute-app"
    root.mkdir()
    _git(root, "init", "--initial-branch=main")
    _git(root, "config", "user.email", "holdout@example.invalid")
    _git(root, "config", "user.name", "Holdout Fixture")
    _git(root, "config", "core.autocrlf", "false")
    _git(root, "remote", "add", "origin", "https://github.com/example/fixture.git")
    (root / ".gitattributes").write_bytes(b"*.txt text\n")
    _git(root, "add", ".gitattributes")
    raw = b"legacy\r\nbytes\r\n"
    blob = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=root,
        input=raw,
        capture_output=True,
        check=True,
    ).stdout.decode("ascii").strip()
    _git(root, "update-index", "--add", "--cacheinfo", f"100644,{blob},legacy.txt")
    _git(root, "commit", "-m", "noncanonical text fixture")
    (root / "legacy.txt").write_bytes(raw)
    commit = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    assert _git(root, "status", "--porcelain=v1") == "M legacy.txt"

    receipt = _receipt(root, commit, tree)

    assert receipt["passed"] is True
    assert receipt["git_porcelain_clean"] is False
    assert receipt["physical_bytes_match_git_blobs"] is True
    assert receipt["index_tree_match"] is True


def test_explicit_blob_materialization_rewrites_disposable_checkout(
    tmp_path: Path,
) -> None:
    root = tmp_path / "attribute-checkout"
    root.mkdir()
    _git(root, "init", "--initial-branch=main")
    _git(root, "config", "user.email", "holdout@example.invalid")
    _git(root, "config", "user.name", "Holdout Fixture")
    _git(root, "config", "core.autocrlf", "false")
    _git(root, "remote", "add", "origin", "https://github.com/example/fixture.git")
    (root / ".gitattributes").write_bytes(b"*.txt text eol=crlf\n")
    (root / "source.txt").write_bytes(b"line one\nline two\n")
    _git(root, "add", "--all")
    _git(root, "commit", "-m", "attribute checkout fixture")
    commit = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    (root / "source.txt").write_bytes(b"line one\r\nline two\r\n")
    assert (root / "source.txt").read_bytes() != b"line one\nline two\n"

    rewritten = source_materialization.materialize_git_blob_exact_worktree(
        root,
        expected_repository_id="example/fixture",
        expected_commit=commit,
        expected_tree=tree,
        confirm_disposable_worktree=True,
    )

    assert rewritten == 1
    assert (root / "source.txt").read_bytes() == b"line one\nline two\n"
    assert _receipt(root, commit, tree)["physical_bytes_match_git_blobs"] is True


def test_explicit_blob_materialization_requires_disposable_confirmation(
    tmp_path: Path,
) -> None:
    root, commit, tree = _repository(tmp_path)

    with pytest.raises(ValueError, match="disposable-worktree confirmation"):
        source_materialization.materialize_git_blob_exact_worktree(
            root,
            expected_repository_id="example/fixture",
            expected_commit=commit,
            expected_tree=tree,
        )


def test_explicit_blob_materialization_rejects_untracked_or_ignored_files(
    tmp_path: Path,
) -> None:
    root, commit, tree = _repository(tmp_path)
    (root / "ignored.txt").write_text("not part of the pinned commit\n", encoding="utf-8")

    with pytest.raises(ValueError, match="untracked, or ignored"):
        source_materialization.materialize_git_blob_exact_worktree(
            root,
            expected_repository_id="example/fixture",
            expected_commit=commit,
            expected_tree=tree,
            confirm_disposable_worktree=True,
        )


def test_capture_rejects_hardlinked_source(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    first = workspace / "first.py"
    first.write_text("VALUE = 1\n", encoding="utf-8")
    try:
        os.link(first, workspace / "second.py")
    except OSError as exc:
        pytest.skip(f"hardlinks are unavailable: {type(exc).__name__}")

    with pytest.raises(ValueError, match="hardlinked"):
        source_materialization.capture_materialized_tree(workspace)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows extended-length path boundary")
def test_git_materialization_reads_tracked_file_at_windows_260_character_boundary(
    tmp_path: Path,
) -> None:
    root = tmp_path / "long-path-app"
    root.mkdir()
    _git(root, "init", "--initial-branch=main")
    _git(root, "config", "user.email", "holdout@example.invalid")
    _git(root, "config", "user.name", "Holdout Fixture")
    _git(root, "config", "core.autocrlf", "false")
    _git(root, "config", "core.longpaths", "true")
    _git(root, "remote", "add", "origin", "https://github.com/example/fixture.git")
    parent = root
    index = 0
    while len(str(parent / "evidence.py")) < 270:
        parent /= f"segment-{index:02d}-" + ("x" * 28)
        index += 1
    target = parent / "evidence.py"
    extended_target = source_materialization._filesystem_path(target)
    extended_target.parent.mkdir(parents=True)
    extended_target.write_bytes(b"VALUE = 'long-path-bound'\n")
    _git(root, "add", "--all")
    _git(root, "commit", "-m", "long path fixture")
    commit = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    extended_target.write_bytes(b"VALUE = 'temporary checkout transform'\n")

    rewritten = source_materialization.materialize_git_blob_exact_worktree(
        root,
        expected_repository_id="example/fixture",
        expected_commit=commit,
        expected_tree=tree,
        confirm_disposable_worktree=True,
    )

    receipt = _receipt(root, commit, tree)

    relative = target.relative_to(root).as_posix()
    assert len(str(target)) >= 270
    assert rewritten == 1
    assert extended_target.read_bytes() == b"VALUE = 'long-path-bound'\n"
    assert relative in {row["path"] for row in receipt["files"]}
    assert receipt["physical_bytes_match_git_blobs"] is True


def test_git_materialization_rejects_symlink_mode_from_commit(tmp_path: Path) -> None:
    root, _commit, _tree = _repository(tmp_path)
    blob = _git(root, "hash-object", "-w", "--stdin")
    subprocess.run(
        ["git", "update-index", "--add", "--cacheinfo", f"120000,{blob},linked.py"],
        cwd=root,
        input=b"src/app.py",
        capture_output=True,
        check=True,
    )
    _git(root, "commit", "-m", "add symlink entry")
    commit = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")

    with pytest.raises(ValueError, match="symlink, submodule"):
        _receipt(root, commit, tree)


@pytest.mark.parametrize(
    "paths",
    [
        ("App.py", "app.py"),
        ("caf\u00e9.py", "cafe\u0301.py"),
        ("A/x.py", "a/y.py"),
    ],
)
def test_git_tree_rejects_case_or_unicode_normalized_collisions(
    paths: tuple[str, str],
) -> None:
    raw = b"".join(
        b"100644 blob " + (f"{index + 1:040x}".encode("ascii")) + b"\t" + path.encode("utf-8") + b"\0"
        for index, path in enumerate(paths)
    )

    with pytest.raises(ValueError, match="collision"):
        source_materialization._parse_ls_tree(raw)


def test_git_tree_rejects_nested_git_component() -> None:
    raw = b"100644 blob " + b"1" * 40 + b"\tsrc/.git/config\0"

    with pytest.raises(ValueError, match="reserved"):
        source_materialization._parse_ls_tree(raw)


@pytest.mark.parametrize(
    "path",
    [
        "src/file.",
        "src/file ",
        "src/CON",
        "src/nul.txt",
        "src/COM1.log",
        "src/LPT9",
        "src/conin$",
        "src/bad:name",
        "src/bad<name",
        "src/bad\x01name",
        "src/GIT~1",
        "src/.git~1",
        "src/LONGFI~1.TXT",
    ],
)
def test_git_tree_rejects_windows_unsafe_or_alias_components(path: str) -> None:
    raw = b"100644 blob " + b"1" * 40 + b"\t" + path.encode("utf-8") + b"\0"

    with pytest.raises(ValueError, match="Windows|NTFS"):
        source_materialization._parse_ls_tree(raw)


def test_git_materialization_rejects_alternates(tmp_path: Path) -> None:
    root, commit, tree = _repository(tmp_path)
    alternates = root / ".git" / "objects" / "info" / "alternates"
    alternates.write_text(str(tmp_path / "foreign-objects") + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="alternates"):
        _receipt(root, commit, tree)


def test_git_materialization_rejects_linked_worktree(tmp_path: Path) -> None:
    root, commit, tree = _repository(tmp_path)
    linked = tmp_path / "linked-worktree"
    _git(root, "worktree", "add", "--detach", str(linked), commit)

    with pytest.raises(ValueError, match="standalone Git clone"):
        _receipt(linked, commit, tree)


def test_git_materialization_rejects_shallow_clone(tmp_path: Path) -> None:
    root, commit, tree = _repository(tmp_path)
    shallow = tmp_path / "shallow"
    completed = subprocess.run(
        ["git", "clone", "--depth", "1", root.as_uri(), str(shallow)],
        cwd=tmp_path,
        capture_output=True,
        check=True,
        text=True,
        encoding="utf-8",
    )
    assert completed.returncode == 0

    with pytest.raises(ValueError, match="shallow"):
        _receipt(shallow, commit, tree)


def test_git_materialization_rejects_origin_mismatch(tmp_path: Path) -> None:
    root, commit, tree = _repository(tmp_path)
    _git(root, "remote", "set-url", "origin", "https://github.com/other/fixture.git")

    with pytest.raises(ValueError, match="origin"):
        _receipt(root, commit, tree)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("extensions.partialClone", "origin"),
        ("fsck.missingEmail", "ignore"),
        ("include.path", "../attacker.config"),
    ],
)
def test_git_materialization_rejects_hostile_local_config(
    tmp_path: Path,
    key: str,
    value: str,
) -> None:
    root, commit, tree = _repository(tmp_path)
    _git(root, "config", key, value)

    with pytest.raises(ValueError, match="local config key is not allowed"):
        _receipt(root, commit, tree)


def test_git_materialization_rejects_promisor_pack_marker(tmp_path: Path) -> None:
    root, commit, tree = _repository(tmp_path)
    marker = root / ".git" / "objects" / "pack" / "forged.promisor"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_bytes(b"")

    with pytest.raises(ValueError, match="promisor object markers"):
        _receipt(root, commit, tree)


def test_git_materialization_ignores_ambient_git_control_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, commit, tree = _repository(tmp_path)
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "attacker.git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "attacker-worktree"))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(tmp_path / "attacker-objects"))
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", str(tmp_path / "alternate-objects"))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.bare")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "true")

    receipt = _receipt(root, commit, tree)

    assert receipt["passed"] is True
    assert receipt["commit"] == commit


def test_materialization_git_process_enforces_time_and_output_budgets(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="time budget"):
        source_materialization._run_bounded_process(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            cwd=tmp_path,
            environment=os.environ.copy(),
            timeout_seconds=0.1,
            maximum_output_bytes=1024,
            label="materialization timeout fixture",
        )

    with pytest.raises(ValueError, match="output budget"):
        source_materialization._run_bounded_process(
            [
                sys.executable,
                "-c",
                "import sys; sys.stderr.buffer.write(b'x' * 65536)",
            ],
            cwd=tmp_path,
            environment=os.environ.copy(),
            timeout_seconds=10,
            maximum_output_bytes=1024,
            label="materialization output fixture",
        )


def test_materialized_tree_hash_changes_with_path_or_content(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "app.py"
    target.write_bytes(b"VALUE = 1\n")
    first = source_materialization.capture_materialized_tree(workspace)
    target.write_bytes(b"VALUE = 2\n")
    second = source_materialization.capture_materialized_tree(workspace)
    target.rename(workspace / "renamed.py")
    third = source_materialization.capture_materialized_tree(workspace)

    assert len({first["tree_sha256"], second["tree_sha256"], third["tree_sha256"]}) == 3
    assert all(
        source_materialization.SHA256_RE.fullmatch(value)
        for value in (first["tree_sha256"], second["tree_sha256"], third["tree_sha256"])
    )


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/Owner/Repo.git", "owner/repo"),
        ("git@github.com:Owner/Repo.git", "owner/repo"),
        ("ssh://git@github.com/Owner/Repo", "owner/repo"),
        ("https://example.com/Owner/Repo.git", None),
    ],
)
def test_normalize_github_repository(url: str, expected: str | None) -> None:
    assert source_materialization.normalize_github_repository(url) == expected
