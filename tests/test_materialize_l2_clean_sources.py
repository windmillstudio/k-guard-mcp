from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CLEAN_SCRIPT = ROOT / "scripts" / "materialize_l2_clean_sources.py"
MATERIALIZER_SCRIPT = ROOT / "scripts" / "materialize_l2_sources.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


clean_sources = _load("materialize_l2_clean_sources_test", CLEAN_SCRIPT)
l2 = _load("materialize_l2_sources_for_clean_source_test", MATERIALIZER_SCRIPT)
source_verifier = l2._load_source_materialization()


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


@pytest.fixture(scope="module")
def transport_template(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, dict[str, dict[str, object]]]:
    root = tmp_path_factory.mktemp("l2-clean-source-transport")
    identities: dict[str, dict[str, object]] = {}
    for index, app_id in enumerate(sorted(l2.EXPECTED_APPS)):
        checkout = root / app_id
        checkout.mkdir()
        _git(checkout, "init", "--initial-branch=main")
        _git(checkout, "config", "user.email", "clean-source@example.invalid")
        _git(checkout, "config", "user.name", "Clean Source Fixture")
        _git(checkout, "config", "core.autocrlf", "false")
        repository_id = f"k-guard-fixtures/{app_id}"
        _git(checkout, "remote", "add", "origin", f"https://github.com/{repository_id}.git")
        license_raw = f"MIT license for {app_id}\n".encode("utf-8")
        (checkout / "LICENSE").write_bytes(license_raw)
        (checkout / "app.txt").write_text(
            f"fixture={app_id};index={index}\n", encoding="utf-8"
        )
        _git(checkout, "add", "--all")
        _git(checkout, "commit", "-m", f"bind {app_id}")
        commit = _git(checkout, "rev-parse", "HEAD")
        tree = _git(checkout, "rev-parse", "HEAD^{tree}")
        receipt = source_verifier.build_git_materialization_receipt(
            checkout,
            expected_repository_id=repository_id,
            expected_commit=commit,
            expected_tree=tree,
        )
        receipt_raw = l2.canonical_json_bytes(receipt)
        identities[app_id] = {
            "repository_id": repository_id,
            "commit": commit,
            "commit_tree": tree,
            "source_tree_sha256": receipt["source_tree_sha256"],
            "receipt_sha256": l2.sha256_bytes(receipt_raw),
            "receipt_semantic_sha256": l2._source_receipt_semantic_sha256(receipt),
            "license": {
                "path": "LICENSE",
                "spdx": "MIT",
                "sha256": hashlib.sha256(license_raw).hexdigest(),
                "byte_count": len(license_raw),
            },
        }
    return root, identities


@pytest.fixture()
def source_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    transport_template: tuple[Path, dict[str, dict[str, object]]],
) -> tuple[dict[str, str], Path]:
    template_root, identities = transport_template
    transport_root = tmp_path / "transport"
    shutil.copytree(template_root, transport_root)
    monkeypatch.setattr(l2, "EXPECTED_IDENTITIES", copy.deepcopy(identities))
    monkeypatch.setattr(l2, "EXPECTED_APPS", frozenset(identities))
    monkeypatch.setattr(
        clean_sources,
        "_load_materializer_with_hash",
        lambda: (l2, hashlib.sha256(MATERIALIZER_SCRIPT.read_bytes()).hexdigest()),
    )
    return {app_id: str(transport_root / app_id) for app_id in identities}, tmp_path


def test_materializes_ordinary_clean_sources_from_transport(
    source_context: tuple[dict[str, str], Path]
) -> None:
    transports, tmp_path = source_context
    output_root = (tmp_path / "external-output" / "sources").resolve()
    summary = (tmp_path / "external-evidence" / "summary.json").resolve()
    output_root.parent.mkdir(parents=True)

    result = clean_sources.materialize_clean_sources(
        output_root, summary, transport_sources=transports
    )

    assert result["source_license_admission"] == "PASS"
    assert result["ordinary_non_shallow_clone_verified"] is True
    assert result["network_fetch_performed"] is True
    assert result["release_gate_passed"] is False
    assert result["raw_returned"] is False
    assert all(row["raw_git_blob_rewrite_count"] >= 0 for row in result["apps"])
    assert json.loads(summary.read_text(encoding="utf-8")) == result
    assert str(next(iter(transports.values()))) not in summary.read_text(encoding="utf-8")
    for app_id in sorted(transports):
        checkout = output_root / app_id
        config = _git(checkout, "config", "--local", "--list")
        assert "promisor" not in config
        assert "partialclone" not in config
        assert _git(checkout, "rev-parse", "--is-shallow-repository") == "false"


def test_refuses_existing_output_root(source_context: tuple[dict[str, str], Path]) -> None:
    transports, tmp_path = source_context
    output_root = (tmp_path / "external-output" / "sources").resolve()
    output_root.parent.mkdir(parents=True)
    output_root.mkdir(parents=True)

    with pytest.raises(FileExistsError, match="refusing_to_overwrite"):
        clean_sources.materialize_clean_sources(
            output_root,
            (tmp_path / "external-evidence" / "summary.json").resolve(),
            transport_sources=transports,
        )


def test_cleans_its_partial_root_when_identity_fetch_fails(
    source_context: tuple[dict[str, str], Path]
) -> None:
    transports, tmp_path = source_context
    output_root = (tmp_path / "external-output" / "sources").resolve()
    output_root.parent.mkdir(parents=True)
    broken = dict(transports)
    broken["crapi"] = str(tmp_path / "missing-transport")

    with pytest.raises(ValueError, match="crapi_fetch_failed"):
        clean_sources.materialize_clean_sources(
            output_root,
            (tmp_path / "external-evidence" / "summary.json").resolve(),
            transport_sources=broken,
        )
    assert not output_root.exists()
    assert not list(output_root.parent.glob(f".{output_root.name}.partial-*"))


def test_refuses_summary_inside_output_or_repository(
    source_context: tuple[dict[str, str], Path]
) -> None:
    transports, tmp_path = source_context
    output_root = (tmp_path / "external-output" / "sources").resolve()
    output_root.parent.mkdir(parents=True)

    with pytest.raises(ValueError, match="summary_must_be_outside"):
        clean_sources.materialize_clean_sources(
            output_root,
            output_root / "summary.json",
            transport_sources=transports,
        )
