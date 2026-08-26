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
SEED_SCRIPT = ROOT / "scripts" / "materialize_l2_source_seed.py"
MATERIALIZER_SCRIPT = ROOT / "scripts" / "materialize_l2_sources.py"
COMPARATOR_SCRIPT = ROOT / "scripts" / "compare_l2_source_registry_repeats.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


seed_builder = _load("materialize_l2_seed_for_comparison_test", SEED_SCRIPT)
l2 = _load("materialize_l2_sources_for_comparison_test", MATERIALIZER_SCRIPT)
comparison = _load("compare_l2_source_registry_repeats_test", COMPARATOR_SCRIPT)
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
def source_template(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, dict[str, object]]]:
    source_root = tmp_path_factory.mktemp("l2-source-registry-template") / "external-sources"
    source_root.mkdir()
    identities: dict[str, dict[str, object]] = {}
    for index, app_id in enumerate(sorted(l2.EXPECTED_APPS)):
        checkout = source_root / app_id
        checkout.mkdir()
        _git(checkout, "init", "--initial-branch=main")
        _git(checkout, "config", "user.email", "comparison@example.invalid")
        _git(checkout, "config", "user.name", "Comparison Fixture")
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
        source_receipt = source_verifier.build_git_materialization_receipt(
            checkout,
            expected_repository_id=repository_id,
            expected_commit=commit,
            expected_tree=tree,
        )
        source_raw = l2.canonical_json_bytes(source_receipt)
        identities[app_id] = {
            "repository_id": repository_id,
            "commit": commit,
            "commit_tree": tree,
            "source_tree_sha256": source_receipt["source_tree_sha256"],
            "receipt_sha256": l2.sha256_bytes(source_raw),
            "receipt_semantic_sha256": l2._source_receipt_semantic_sha256(source_receipt),
            "license": {
                "path": "LICENSE",
                "spdx": "MIT",
                "sha256": hashlib.sha256(license_raw).hexdigest(),
                "byte_count": len(license_raw),
            },
        }
    return source_root, identities


@pytest.fixture()
def receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_template: tuple[Path, dict[str, dict[str, object]]],
) -> tuple[Path, Path, Path]:
    template_root, identities = source_template
    source_root = tmp_path / "external-sources"
    shutil.copytree(template_root, source_root)
    monkeypatch.setattr(l2, "EXPECTED_IDENTITIES", copy.deepcopy(identities))
    monkeypatch.setattr(l2, "EXPECTED_APPS", frozenset(identities))
    materializer_sha256 = hashlib.sha256(MATERIALIZER_SCRIPT.read_bytes()).hexdigest()
    monkeypatch.setattr(
        seed_builder, "_load_materializer_with_hash", lambda: (l2, materializer_sha256)
    )
    monkeypatch.setattr(
        comparison, "_load_materializer_with_hash", lambda: (l2, materializer_sha256)
    )
    bundle = seed_builder.build_seed_bundle(
        source_root,
        seed_name="p23a-seed.json",
        receipts_dir_name="p23a-receipts",
    )
    seed_path, _summary = seed_builder.write_seed_bundle(
        source_root,
        bundle,
        seed_name="p23a-seed.json",
        receipts_dir_name="p23a-receipts",
        summary_path=(tmp_path / "external-evidence" / "seed-summary.json").resolve(),
    )
    first = tmp_path / "external-evidence" / "first.json"
    second = tmp_path / "external-evidence" / "second.json"
    l2.write_new_output(first, l2.materialize_l2_sources(seed_path))
    l2.write_new_output(second, l2.materialize_l2_sources(seed_path))
    return seed_path, first, second


def test_compares_two_current_source_only_materializations(
    receipts: tuple[Path, Path, Path]
) -> None:
    seed, first, second = receipts

    result = comparison.compare_receipts(seed, first, second)

    assert result["status"] == "FIX"
    assert result["repeat_exact"] is True
    assert result["authority"]["may_mark_field_fix"] is True
    assert result["authority"]["may_affect_h100_or_release"] is False
    assert result["claim_boundary"]["runtime_isolation_proven"] is False


def test_rejects_output_not_equal_to_current_source_materialization(
    receipts: tuple[Path, Path, Path]
) -> None:
    seed, first, second = receipts
    altered = json.loads(second.read_text(encoding="utf-8"))
    altered["runtime_isolation_gate"] = "PASS"
    second.write_bytes(comparison.canonical_json_bytes(altered))

    with pytest.raises(ValueError, match="source_registry_output_differs"):
        comparison.compare_receipts(seed, first, second)


def test_rejects_raw_boundary_even_if_output_is_canonical(
    receipts: tuple[Path, Path, Path]
) -> None:
    seed, first, second = receipts
    altered = json.loads(second.read_text(encoding="utf-8"))
    altered["raw_returned"] = True
    second.write_bytes(comparison.canonical_json_bytes(altered))

    with pytest.raises(ValueError, match="source_registry_output_differs"):
        comparison.compare_receipts(seed, first, second)


def test_refuses_repository_or_existing_comparison_output(
    receipts: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    seed, first, second = receipts
    result = comparison.compare_receipts(seed, first, second)
    repo_output = ROOT / "comparison.json"

    with pytest.raises(ValueError, match="comparison_output_must_be_external"):
        comparison.write_comparison(repo_output, result)

    output = (tmp_path / "external-evidence" / "comparison.json").resolve()
    output.write_text("existing\n", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing_to_overwrite"):
        comparison.write_comparison(output, result)
