from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


materialization = _load(
    "holdout_source_materialization_for_git_verifier_test",
    ROOT / "scripts" / "holdout_source_materialization.py",
)
verifier = _load(
    "verify_holdout_git_sources_test",
    ROOT / "scripts" / "verify_holdout_git_sources.py",
)


def _git(cwd: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(verifier.canonical_json_bytes(payload))


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict, dict]:
    source = tmp_path / "scanner-source"
    source.mkdir()
    _git(source, "init")
    _git(source, "config", "user.email", "fixture@example.com")
    _git(source, "config", "user.name", "Fixture")
    _git(source, "config", "core.autocrlf", "false")
    workflow = source / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_bytes(b"name: ci\nuses: owner/action@main\n")
    (workflow.parent / "release.yml").write_bytes(workflow.read_bytes())
    _git(source, "add", ".")
    _git(source, "commit", "-m", "fixture")
    _git(source, "remote", "add", "origin", "https://github.com/example/fixture.git")
    commit = _git(source, "rev-parse", "HEAD")
    tree = _git(source, "rev-parse", "HEAD^{tree}")

    receipt = materialization.build_git_materialization_receipt(
        source,
        expected_repository_id="example/fixture",
        expected_commit=commit,
        expected_tree=tree,
    )
    preregistration = {
        "campaign_id": "git-verifier-fixture",
        "apps": [
            {
                "app": "fixture",
                "repository": "https://github.com/example/fixture.git",
                "repository_id": "example/fixture",
                "commit": commit,
                "commit_tree": tree,
            }
        ],
    }
    preregistration_path = tmp_path / "preregistration.json"
    _write(preregistration_path, preregistration)
    evidence = tmp_path / "evidence"
    receipt_path = evidence / "source-receipts" / "fixture.json"
    _write(receipt_path, receipt)
    receipt_hash = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    verifier_hash = hashlib.sha256(
        (ROOT / "scripts" / "verify_holdout_git_sources.py").read_bytes()
    ).hexdigest()
    campaign = {
        "campaign_id": preregistration["campaign_id"],
        "holdout_protocol": {
            "holdout_protocol_schema": "k_guard_holdout_protocol.v5",
            "protocol_manifest_sha256": "a" * 64,
            "independent_git_verifier_sha256": verifier_hash,
        },
        "apps": [
            {
                **preregistration["apps"][0],
                "source_materialization_receipt_path": "source-receipts/fixture.json",
                "source_materialization_receipt_sha256": receipt_hash,
                "source_materialization_schema": receipt["schema"],
                "source_tree_sha256": receipt["source_tree_sha256"],
                "source_total_bytes": receipt["total_bytes"],
                "tracked_files": receipt["file_count"],
            }
        ],
    }
    _write(evidence / "campaign.json", campaign)

    mirrors = tmp_path / "independent-mirrors"
    mirrors.mkdir()
    _git(mirrors, "clone", "--mirror", "--no-local", str(source), "fixture.git")
    _git(
        mirrors / "fixture.git",
        "remote",
        "set-url",
        "origin",
        "https://github.com/example/fixture.git",
    )
    return preregistration_path, evidence, mirrors, receipt, campaign


def test_independent_verifier_replays_real_bare_git_objects(tmp_path: Path) -> None:
    preregistration, evidence, mirrors, receipt, _campaign = _fixture(tmp_path)

    result = verifier.build_independent_verification(preregistration, evidence, mirrors)

    assert result["schema"] == verifier.VERIFICATION_SCHEMA
    assert result["app_count"] == 1
    assert result["apps"][0]["files"] == receipt["files"]
    assert result["apps"][0]["file_count"] == 2
    assert result["apps"][0]["commit"] == receipt["commit"]
    assert result["apps"][0]["commit_tree"] == receipt["commit_tree"]
    assert result["apps"][0]["source_tree_sha256"] == receipt["source_tree_sha256"]
    assert result["apps"][0]["private_snapshot_method"] == "git_clone_mirror_no_local"
    assert result["apps"][0]["storage_stable"] is True
    assert result["path_policy"] == "windows_ntfs_materialization_fail_closed_v1"
    assert verifier.SHA256_RE.fullmatch(
        result["apps"][0]["input_mirror_storage_manifest_sha256"]
    )
    assert verifier.SHA256_RE.fullmatch(
        result["apps"][0]["private_snapshot_storage_manifest_sha256"]
    )
    assert verifier.canonical_json_bytes(result).endswith(b"\n")


def test_independent_verifier_reads_each_evidence_json_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preregistration, evidence, mirrors, _receipt, _campaign = _fixture(tmp_path)
    reads: dict[Path, int] = {}
    original_read = verifier._read_stable_bytes

    def counted_read(path: Path, **kwargs) -> bytes:
        resolved = path.resolve(strict=True)
        reads[resolved] = reads.get(resolved, 0) + 1
        return original_read(path, **kwargs)

    monkeypatch.setattr(verifier, "_read_stable_bytes", counted_read)

    verifier.build_independent_verification(preregistration, evidence, mirrors)

    expected = {
        preregistration.resolve(strict=True),
        (evidence / "campaign.json").resolve(strict=True),
        (evidence / "source-receipts" / "fixture.json").resolve(strict=True),
    }
    assert reads == {path: 1 for path in expected}


def test_independent_verifier_rejects_hardlinked_evidence_json(tmp_path: Path) -> None:
    preregistration, evidence, mirrors, _receipt, _campaign = _fixture(tmp_path)
    try:
        os.link(preregistration, tmp_path / "preregistration-hardlink.json")
    except OSError as exc:
        pytest.skip(f"hardlinks are unavailable: {type(exc).__name__}")

    with pytest.raises(ValueError, match="one regular unlinked file"):
        verifier.build_independent_verification(preregistration, evidence, mirrors)


def test_independent_verification_output_is_exclusively_created(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    output = evidence / "independent.json"
    barrier = threading.Barrier(2)

    def write() -> str:
        barrier.wait(timeout=10)
        try:
            verifier._write_new_artifact(
                output,
                b'{"result":"stable"}\n',
                evidence_root=evidence.resolve(strict=True),
            )
        except OSError:
            return "rejected"
        return "created"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(lambda _index: write(), range(2)))

    assert outcomes == ["created", "rejected"]
    assert output.read_bytes() == b'{"result":"stable"}\n'


def test_bounded_process_enforces_time_and_output_budgets(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="time budget"):
        verifier._run_bounded_process(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            cwd=tmp_path,
            environment=os.environ.copy(),
            timeout_seconds=0.1,
            maximum_output_bytes=1024,
            label="timeout fixture",
        )

    with pytest.raises(ValueError, match="output budget"):
        verifier._run_bounded_process(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'x' * 65536)",
            ],
            cwd=tmp_path,
            environment=os.environ.copy(),
            timeout_seconds=10,
            maximum_output_bytes=1024,
            label="output fixture",
        )


def test_cat_file_batch_enforces_deadline_and_stderr_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(verifier, "CAT_FILE_OBJECT_TIMEOUT_SECONDS", 0.15)
    monkeypatch.setattr(verifier, "CAT_FILE_IDLE_TIMEOUT_SECONDS", 0.15)
    monkeypatch.setattr(
        verifier,
        "_git_command",
        lambda _mirror, *_args: [
            sys.executable,
            "-c",
            "import sys,time; sys.stdin.buffer.readline(); time.sleep(5)",
        ],
    )

    with pytest.raises(ValueError, match="budget"):
        with verifier._CatFileBatch(tmp_path) as batch:
            batch.read("0" * 40, expected_type="blob", capture_limit=None)

    monkeypatch.setattr(verifier, "CAT_FILE_OBJECT_TIMEOUT_SECONDS", 5.0)
    monkeypatch.setattr(verifier, "CAT_FILE_IDLE_TIMEOUT_SECONDS", 5.0)
    monkeypatch.setattr(verifier, "MAX_GIT_STDERR_BYTES", 1024)
    monkeypatch.setattr(
        verifier,
        "_git_command",
        lambda _mirror, *_args: [
            sys.executable,
            "-c",
            (
                "import sys,time; sys.stderr.buffer.write(b'x'*4096); "
                "sys.stderr.buffer.flush(); sys.stdin.buffer.readline(); time.sleep(5)"
            ),
        ],
    )

    with pytest.raises(ValueError, match="stderr budget"):
        with verifier._CatFileBatch(tmp_path) as batch:
            batch.read("0" * 40, expected_type="blob", capture_limit=None)


def test_cat_file_batch_rejects_oversized_blob_before_streaming(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oversized = verifier.MAX_BLOB_BYTES + 1
    monkeypatch.setattr(
        verifier,
        "_git_command",
        lambda _mirror, *_args: [
            sys.executable,
            "-c",
            (
                "import sys,time; oid=sys.stdin.buffer.readline().strip(); "
                f"sys.stdout.buffer.write(oid+b' blob {oversized}\\n'); "
                "sys.stdout.buffer.flush(); time.sleep(5)"
            ),
        ],
    )

    with pytest.raises(ValueError, match="exceeds the verification budget"):
        with verifier._CatFileBatch(tmp_path) as batch:
            batch.read("0" * 40, expected_type="blob", capture_limit=None)


def test_tree_reconstruction_rejects_excessive_depth_without_recursion() -> None:
    too_deep = "/".join(
        [f"d{index}" for index in range(verifier.MAX_PATH_DEPTH + 1)] + ["app.py"]
    )
    row = {
        "path": too_deep,
        "mode": "100644",
        "git_blob_sha1": "1" * 40,
        "sha256": "2" * 64,
        "byte_count": 1,
    }

    with pytest.raises(ValueError, match="maximum path depth"):
        verifier._reconstruct_tree_sha1([row])

    allowed = {**row, "path": "/".join(["d"] * 200 + ["app.py"])}
    assert verifier.REVISION_RE.fullmatch(verifier._reconstruct_tree_sha1([allowed]))


@pytest.mark.parametrize(
    "component",
    [
        "file.",
        "file ",
        "CON",
        "nul.txt",
        "COM1.log",
        "LPT9",
        "conin$",
        "bad:name",
        "bad<name",
        "bad\x01name",
        ".git",
        "GIT~1",
        ".git~1",
        "LONGFI~1.TXT",
    ],
)
def test_windows_component_policy_rejects_unsafe_or_alias_names(component: str) -> None:
    with pytest.raises(ValueError, match="Windows|NTFS"):
        verifier._windows_component_key(component)


@pytest.mark.parametrize(
    "component",
    ["component.git.txt", "com10", "auxiliary", "normal~0"],
)
def test_windows_component_policy_allows_unambiguous_names(component: str) -> None:
    assert verifier._windows_component_key(component)


def test_path_policy_rejects_parent_prefix_collisions() -> None:
    seen: dict[str, str] = {}
    verifier._register_path_prefixes("A/x.py", seen)

    with pytest.raises(ValueError, match="prefix collision"):
        verifier._register_path_prefixes("a/y.py", seen)


def test_raw_git_tree_rejects_windows_sibling_collision() -> None:
    raw = (
        b"40000 A\0"
        + bytes.fromhex("1" * 40)
        + b"40000 a\0"
        + bytes.fromhex("2" * 40)
    )

    with pytest.raises(ValueError, match="entry collision"):
        verifier._parse_tree(raw)


def test_git_walk_enforces_all_aggregate_budgets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _preregistration, _evidence, mirrors, receipt, _campaign = _fixture(tmp_path)
    checks = [
        ("MAX_REACHABLE_OBJECTS", 1, "reachable-object"),
        ("MAX_REACHABLE_COMMIT_BYTES", 0, "reachable-commit"),
        ("MAX_REACHABLE_TREE_BYTES", 0, "reachable-tree"),
        ("MAX_REACHABLE_BLOB_BYTES", 0, "reachable-blob"),
    ]
    for constant, limit, message in checks:
        original = getattr(verifier, constant)
        monkeypatch.setattr(verifier, constant, limit)
        with pytest.raises(ValueError, match=message):
            with verifier._CatFileBatch(mirrors / "fixture.git") as batch:
                verifier._walk_commit(
                    batch,
                    receipt["commit"],
                    receipt["commit_tree"],
                )
        monkeypatch.setattr(verifier, constant, original)


def test_evidence_json_budget_is_checked_before_reading_payload(tmp_path: Path) -> None:
    artifact = tmp_path / "oversized.json"
    artifact.write_bytes(b"x" * 4096)

    with pytest.raises(ValueError, match="exceeds its byte budget"):
        verifier._load_canonical_json_with_raw(artifact, maximum_bytes=1024)


def test_independent_verifier_hashes_a_shared_blob_once(tmp_path: Path) -> None:
    preregistration, evidence, mirrors, receipt, _campaign = _fixture(tmp_path)
    blob_reads: dict[str, int] = {}

    with verifier._CatFileBatch(mirrors / "fixture.git") as batch:
        original_read = batch.read

        def counting_read(oid: str, *, expected_type: str, capture_limit: int | None):
            if expected_type == "blob":
                blob_reads[oid] = blob_reads.get(oid, 0) + 1
            return original_read(
                oid,
                expected_type=expected_type,
                capture_limit=capture_limit,
            )

        batch.read = counting_read
        _commit, rows = verifier._walk_commit(
            batch,
            receipt["commit"],
            receipt["commit_tree"],
        )

    assert len(rows) == 2
    assert len({row["git_blob_sha1"] for row in rows}) == 1
    assert list(blob_reads.values()) == [1]


def test_independent_verifier_rejects_source_receipt_byte_digest_forgery(
    tmp_path: Path,
) -> None:
    preregistration, evidence, mirrors, receipt, campaign = _fixture(tmp_path)
    receipt["files"][0]["sha256"] = "f" * 64
    receipt["source_tree_sha256"] = verifier._source_tree_sha256(receipt["files"])
    receipt_path = evidence / "source-receipts" / "fixture.json"
    _write(receipt_path, receipt)
    campaign["apps"][0]["source_materialization_receipt_sha256"] = hashlib.sha256(
        receipt_path.read_bytes()
    ).hexdigest()
    campaign["apps"][0]["source_tree_sha256"] = receipt["source_tree_sha256"]
    _write(evidence / "campaign.json", campaign)

    with pytest.raises(ValueError, match="differs from scanned source receipt"):
        verifier.build_independent_verification(preregistration, evidence, mirrors)


def test_independent_verifier_rejects_non_github_mirror_origin(tmp_path: Path) -> None:
    preregistration, evidence, mirrors, _receipt, _campaign = _fixture(tmp_path)
    _git(
        mirrors / "fixture.git", "remote", "set-url", "origin", str(tmp_path / "other")
    )

    with pytest.raises(ValueError, match="origin differs"):
        verifier.build_independent_verification(preregistration, evidence, mirrors)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("extensions.partialClone", "origin"),
        ("fsck.missingEmail", "ignore"),
        ("include.path", "../attacker.config"),
    ],
)
def test_independent_verifier_rejects_hostile_local_config(
    tmp_path: Path,
    key: str,
    value: str,
) -> None:
    preregistration, evidence, mirrors, _receipt, _campaign = _fixture(tmp_path)
    _git(mirrors / "fixture.git", "config", key, value)

    with pytest.raises(ValueError, match="local config key is not allowed"):
        verifier.build_independent_verification(preregistration, evidence, mirrors)


def test_independent_verifier_rejects_promisor_pack_marker(tmp_path: Path) -> None:
    preregistration, evidence, mirrors, _receipt, _campaign = _fixture(tmp_path)
    marker = mirrors / "fixture.git" / "objects" / "pack" / "forged.promisor"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_bytes(b"")

    with pytest.raises(ValueError, match="promisor object markers"):
        verifier.build_independent_verification(preregistration, evidence, mirrors)


def test_independent_verifier_requires_mirror_refspec(tmp_path: Path) -> None:
    preregistration, evidence, _mirrors, _receipt, _campaign = _fixture(tmp_path)
    mirrors = tmp_path / "plain-bare-mirrors"
    mirrors.mkdir()
    _git(
        mirrors,
        "clone",
        "--bare",
        "--no-local",
        str(tmp_path / "scanner-source"),
        "fixture.git",
    )
    _git(
        mirrors / "fixture.git",
        "remote",
        "set-url",
        "origin",
        "https://github.com/example/fixture.git",
    )

    with pytest.raises(ValueError, match="local config is incomplete"):
        verifier.build_independent_verification(preregistration, evidence, mirrors)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("remote.origin.fetch", "+REFS/*:REFS/*"),
        ("remote.origin.mirror", "TRUE"),
    ],
)
def test_independent_verifier_requires_exact_mirror_config_values(
    tmp_path: Path,
    key: str,
    value: str,
) -> None:
    preregistration, evidence, mirrors, _receipt, _campaign = _fixture(tmp_path)
    _git(mirrors / "fixture.git", "config", key, value)

    with pytest.raises(ValueError, match="local config is unsafe"):
        verifier.build_independent_verification(preregistration, evidence, mirrors)


def test_independent_verifier_rejects_hardlinked_mirror_storage(tmp_path: Path) -> None:
    preregistration, evidence, mirrors, _receipt, _campaign = _fixture(tmp_path)
    config = mirrors / "fixture.git" / "config"
    try:
        os.link(config, tmp_path / "external-config-link")
    except OSError as exc:
        pytest.skip(f"hardlinks are unavailable: {type(exc).__name__}")

    with pytest.raises(ValueError, match="hardlinked file"):
        verifier.build_independent_verification(preregistration, evidence, mirrors)


def test_independent_verifier_rejects_nested_linked_storage(tmp_path: Path) -> None:
    preregistration, evidence, mirrors, _receipt, _campaign = _fixture(tmp_path)
    external = tmp_path / "external-objects"
    external.mkdir()
    linked = mirrors / "fixture.git" / "objects" / "linked"
    try:
        linked.symlink_to(external, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {type(exc).__name__}")

    with pytest.raises(ValueError, match="symlink or reparse point"):
        verifier.build_independent_verification(preregistration, evidence, mirrors)


def test_independent_verifier_rejects_input_storage_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preregistration, evidence, mirrors, _receipt, _campaign = _fixture(tmp_path)
    original_clone = verifier._clone_private_mirror

    def clone_then_mutate(source: Path, destination: Path, **kwargs) -> None:
        original_clone(source, destination, **kwargs)
        (source / "description").write_bytes(b"changed during verification\n")

    monkeypatch.setattr(verifier, "_clone_private_mirror", clone_then_mutate)

    with pytest.raises(ValueError, match="input mirror changed"):
        verifier.build_independent_verification(preregistration, evidence, mirrors)


def test_independent_verifier_rejects_private_snapshot_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preregistration, evidence, mirrors, _receipt, _campaign = _fixture(tmp_path)
    original_validate = verifier._validate_bare_mirror
    calls = 0

    def validate_then_mutate(mirror: Path, repository_id: str) -> str:
        nonlocal calls
        calls += 1
        origin = original_validate(mirror, repository_id)
        if calls == 2:
            (mirror / "description").write_bytes(b"changed private snapshot\n")
        return origin

    monkeypatch.setattr(verifier, "_validate_bare_mirror", validate_then_mutate)

    with pytest.raises(ValueError, match="snapshot changed"):
        verifier.build_independent_verification(preregistration, evidence, mirrors)


def test_independent_verifier_rejects_missing_parent_object(tmp_path: Path) -> None:
    _preregistration, _evidence, mirrors, receipt, _campaign = _fixture(tmp_path)
    mirror = mirrors / "fixture.git"
    original = subprocess.run(
        ["git", "cat-file", "commit", receipt["commit"]],
        cwd=mirror,
        check=True,
        capture_output=True,
    ).stdout
    tree_line, remainder = original.split(b"\n", 1)
    forged = tree_line + b"\nparent " + (b"f" * 40) + b"\n" + remainder
    forged_commit = subprocess.run(
        ["git", "hash-object", "-t", "commit", "-w", "--stdin"],
        cwd=mirror,
        input=forged,
        check=True,
        capture_output=True,
        text=False,
    ).stdout.decode("ascii").strip()

    with verifier._CatFileBatch(mirror) as batch:
        with pytest.raises(ValueError):
            verifier._walk_commit(batch, forged_commit, receipt["commit_tree"])


def test_independent_verifier_rejects_nested_source_receipt_artifacts(tmp_path: Path) -> None:
    preregistration, evidence, mirrors, _receipt, _campaign = _fixture(tmp_path)
    (evidence / "source-receipts" / "nested").mkdir()

    with pytest.raises(ValueError, match="non-regular direct artifact"):
        verifier.build_independent_verification(preregistration, evidence, mirrors)
