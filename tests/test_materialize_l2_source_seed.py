from __future__ import annotations

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


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


seed_builder = _load("materialize_l2_source_seed_test", SEED_SCRIPT)
l2 = _load("materialize_l2_sources_for_seed_test", MATERIALIZER_SCRIPT)
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
    root = tmp_path_factory.mktemp("l2-source-seed-template") / "external-sources"
    root.mkdir()
    identities: dict[str, dict[str, object]] = {}
    for index, app_id in enumerate(sorted(l2.EXPECTED_APPS)):
        checkout = root / app_id
        checkout.mkdir()
        _git(checkout, "init", "--initial-branch=main")
        _git(checkout, "config", "user.email", "seed@example.invalid")
        _git(checkout, "config", "user.name", "Seed Fixture")
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
def source_root(
    tmp_path: Path,
    source_template: tuple[Path, dict[str, dict[str, object]]],
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    template_root, identities = source_template
    root = tmp_path / "external-sources"
    shutil.copytree(template_root, root)
    monkeypatch.setattr(l2, "EXPECTED_IDENTITIES", json.loads(json.dumps(identities)))
    monkeypatch.setattr(l2, "EXPECTED_APPS", frozenset(identities))
    monkeypatch.setattr(
        seed_builder,
        "_load_materializer_with_hash",
        lambda: (l2, hashlib.sha256(MATERIALIZER_SCRIPT.read_bytes()).hexdigest()),
    )
    return root


def test_builds_a_seed_that_materializes_source_only_contract(
    source_root: Path, tmp_path: Path
) -> None:
    bundle = seed_builder.build_seed_bundle(
        source_root,
        seed_name="p23a-seed.json",
        receipts_dir_name="p23a-receipts",
    )
    seed_path, summary_path = seed_builder.write_seed_bundle(
        source_root,
        bundle,
        seed_name="p23a-seed.json",
        receipts_dir_name="p23a-receipts",
        summary_path=(tmp_path / "external-evidence" / "summary.json").resolve(),
    )

    result = l2.materialize_l2_sources(seed_path)
    summary_raw = summary_path.read_bytes()
    summary = json.loads(summary_raw)

    assert result["source_license_admission"] == "PASS"
    assert result["runtime_isolation_gate"] == "HOLD"
    assert result["machine_oracle_gate"] == "HOLD"
    assert result["release_gate_passed"] is False
    assert result["scanner_output_observed"] is False
    assert result["raw_returned"] is False
    assert summary_raw == seed_builder.canonical_json_bytes(summary)
    assert summary["seed"]["app_count"] == 6
    assert summary["runtime_allowance"]["runtime_gate"] == "HOLD"
    assert str(source_root) not in summary_raw.decode("utf-8")
    assert set(json.loads(seed_path.read_text(encoding="utf-8"))["apps"][0]) == {
        "app_id",
        "repository_id",
        "commit",
        "commit_tree",
        "source_tree_sha256",
        "lineage_id",
        "checkout_root",
        "receipt_path",
        "receipt_sha256",
        "receipt_semantic_sha256",
        "receipt_equivalence",
        "license",
        "isolation",
        "machine_oracles",
    }


def test_changed_checkout_fails_before_seed_write(source_root: Path) -> None:
    (source_root / "crapi" / "app.txt").write_text("tampered\n", encoding="utf-8")

    with pytest.raises(ValueError):
        seed_builder.build_seed_bundle(
            source_root,
            seed_name="p23a-seed.json",
            receipts_dir_name="p23a-receipts",
        )


def test_requires_exact_six_checkout_set(source_root: Path) -> None:
    (source_root / "crapi").rename(source_root / "crapi-missing")

    with pytest.raises(ValueError, match="source_checkout_missing_or_linked"):
        seed_builder.build_seed_bundle(
            source_root,
            seed_name="p23a-seed.json",
            receipts_dir_name="p23a-receipts",
        )


def test_refuses_overwrite_and_summary_inside_source_root(
    source_root: Path, tmp_path: Path
) -> None:
    bundle = seed_builder.build_seed_bundle(
        source_root,
        seed_name="p23a-seed.json",
        receipts_dir_name="p23a-receipts",
    )
    existing = source_root / "p23a-seed.json"
    existing.write_text("existing\n", encoding="utf-8")

    with pytest.raises(FileExistsError, match="refusing_to_overwrite_source_seed"):
        seed_builder.write_seed_bundle(
            source_root,
            bundle,
            seed_name="p23a-seed.json",
            receipts_dir_name="p23a-receipts",
            summary_path=(tmp_path / "evidence" / "summary.json").resolve(),
        )
    assert existing.read_text(encoding="utf-8") == "existing\n"

    with pytest.raises(ValueError, match="summary_must_be_outside"):
        seed_builder.write_seed_bundle(
            source_root,
            bundle,
            seed_name="p23a-next.json",
            receipts_dir_name="p23a-next-receipts",
            summary_path=source_root / "summary.json",
        )


def test_rejects_unsafe_output_names(source_root: Path) -> None:
    with pytest.raises(ValueError, match="seed_name_invalid"):
        seed_builder.build_seed_bundle(
            source_root,
            seed_name="../seed.json",
            receipts_dir_name="p23a-receipts",
        )
    with pytest.raises(ValueError, match="receipts_dir_name_invalid"):
        seed_builder.build_seed_bundle(
            source_root,
            seed_name="p23a-seed.json",
            receipts_dir_name="nested/receipts",
        )
