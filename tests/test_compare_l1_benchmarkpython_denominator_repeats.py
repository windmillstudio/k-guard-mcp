from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "compare_l1_benchmarkpython_denominator_repeats.py"
SPEC = importlib.util.spec_from_file_location(
    "compare_l1_benchmarkpython_denominator_repeats_test", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
comparison = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = comparison
SPEC.loader.exec_module(comparison)


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        capture_output=True,
        check=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture_corpus(tmp_path: Path, language: str) -> tuple[Path, object]:
    materializer = comparison._load_materializer()
    root = tmp_path / language
    root.mkdir(parents=True)
    _git(root, "init", "--initial-branch=main")
    _git(root, "config", "user.email", "p22a@example.invalid")
    _git(root, "config", "user.name", "P2.2A Fixture")
    _git(root, "config", "core.autocrlf", "false")
    origin = f"https://github.com/example/Benchmark{language.title()}.git"
    _git(root, "remote", "add", "origin", origin)
    expected_path = "expected.csv"
    source_prefix = "src/cases" if language == "java" else "testcode"
    suffix = ".java" if language == "java" else ".py"
    rows = [
        ("BenchmarkTest00001", "sqli", "true", "89"),
        ("BenchmarkTest00002", "xss", "false", "79"),
    ]
    (root / "LICENSE").write_text(f"{language} license\n", encoding="utf-8")
    with (root / expected_path).open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(["# test name", "category", "real vulnerability", "cwe"])
        writer.writerows(rows)
    source_root = root / source_prefix
    source_root.mkdir(parents=True)
    for case_id, *_ in rows:
        (source_root / f"{case_id}{suffix}").write_text(f"// {case_id}\n", encoding="utf-8")
    _git(root, "add", "--all")
    _git(root, "commit", "-m", "fixture")
    spec = materializer.CorpusSpec(
        corpus_id=f"fixture-{language}",
        language=language,
        repository_origin=origin,
        revision_sha1=_git(root, "rev-parse", "HEAD"),
        commit_tree_sha1=_git(root, "rev-parse", "HEAD^{tree}"),
        expected_results_path=expected_path,
        expected_results_sha256=_sha256(root / expected_path),
        license_path="LICENSE",
        license_spdx="MIT",
        license_sha256=_sha256(root / "LICENSE"),
        expected_case_count=len(rows),
        source_prefix=source_prefix,
        source_suffix=suffix,
        category_cwe=(("sqli", "89"), ("xss", "79")),
    )
    return root, spec


def _write_source_receipt(path: Path, python: Path, spec: object) -> None:
    materializer = comparison._load_materializer()
    blob_worktree = comparison._load_blob_worktree()
    expected = materializer._materialize_corpus(python, spec)
    receipt = {
        "schema": blob_worktree.SCHEMA,
        "revision": spec.revision_sha1,
        "tree": spec.commit_tree_sha1,
        "origin": spec.repository_origin,
        "file_count": expected["source_tree"]["file_count"],
        "worktree_clean": True,
        "byte_source": "git_cat_file_raw_blob",
        "raw_returned": False,
    }
    path.write_bytes(blob_worktree.canonical_json_bytes(receipt))


def _manifest_pair(tmp_path: Path) -> tuple[Path, Path, Path, Path, object]:
    materializer = comparison._load_materializer()
    java, java_spec = _fixture_corpus(tmp_path, "java")
    python, python_spec = _fixture_corpus(tmp_path, "python")
    manifest = materializer.build_manifest(java, python, specs=(java_spec, python_spec))
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_bytes(materializer.canonical_json_bytes(manifest))
    second.write_bytes(materializer.canonical_json_bytes(manifest))
    source_receipt = tmp_path / "python-source-receipt.json"
    _write_source_receipt(source_receipt, python, python_spec)
    return first, second, python, source_receipt, python_spec


def test_compares_equal_clean_python_denominator_manifests(tmp_path: Path) -> None:
    first, second, python, source_receipt, python_spec = _manifest_pair(tmp_path)

    result = comparison.compare_manifests(
        first,
        second,
        python,
        source_receipt,
        materializer_module=comparison._load_materializer(),
        python_spec=python_spec,
    )

    assert result["status"] == "FIX"
    assert result["field_id"] == "p2.2a-benchmarkpython-current-denominator"
    assert result["repeat_exact"] is True
    assert result["official_binding_exact"] is True
    assert result["benchmarkpython"]["case_count"] == 2
    assert result["target"]["head_git_oid"]
    assert len(result["tool_provenance"]["comparator_sha256"]) == 64
    assert result["authority"]["may_approve_benchmarkjava_denominator"] is False
    assert result["claim_boundary"]["detection_accuracy_proven"] is False
    assert str(python) not in comparison.canonical_json_bytes(result).decode("utf-8")


def test_holds_when_python_projection_differs_from_clean_source(tmp_path: Path) -> None:
    first, second, python, source_receipt, python_spec = _manifest_pair(tmp_path)
    materializer = comparison._load_materializer()
    altered = json.loads(second.read_text(encoding="utf-8"))
    python_corpus = next(corpus for corpus in altered["corpora"] if corpus["language"] == "python")
    python_corpus["expected_results"]["sha256"] = "0" * 64
    second.write_bytes(materializer.canonical_json_bytes(altered))

    result = comparison.compare_manifests(
        first,
        second,
        python,
        source_receipt,
        materializer_module=materializer,
        python_spec=python_spec,
    )

    assert result["status"] == "HOLD"
    assert result["repeat_exact"] is False
    assert result["official_binding_exact"] is False


def test_allows_lowercase_wbs_field_key_but_rejects_uppercase(tmp_path: Path) -> None:
    first, second, python, source_receipt, python_spec = _manifest_pair(tmp_path)

    result = comparison.compare_manifests(
        first,
        second,
        python,
        source_receipt,
        materializer_module=comparison._load_materializer(),
        python_spec=python_spec,
        field_id="p2.2b-benchmarkpython-independent-clean-worktree-replay",
    )

    assert result["field_id"] == "p2.2b-benchmarkpython-independent-clean-worktree-replay"
    with pytest.raises(ValueError, match="field_id_invalid"):
        comparison.compare_manifests(
            first,
            second,
            python,
            source_receipt,
            materializer_module=comparison._load_materializer(),
            python_spec=python_spec,
            field_id="P2.2B-invalid",
        )


def test_holds_when_source_receipt_is_valid_but_not_bound_to_python_source(
    tmp_path: Path,
) -> None:
    first, second, python, source_receipt, python_spec = _manifest_pair(tmp_path)
    blob_worktree = comparison._load_blob_worktree()
    altered = json.loads(source_receipt.read_text(encoding="utf-8"))
    altered["tree"] = "0" * 40
    source_receipt.write_bytes(blob_worktree.canonical_json_bytes(altered))

    result = comparison.compare_manifests(
        first,
        second,
        python,
        source_receipt,
        materializer_module=comparison._load_materializer(),
        python_spec=python_spec,
    )

    assert result["status"] == "HOLD"
    assert result["repeat_exact"] is True
    assert result["official_binding_exact"] is False


def test_refuses_to_overwrite_or_write_inside_repository(tmp_path: Path) -> None:
    output = tmp_path / "comparison.json"
    output.write_text("existing", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing_to_overwrite"):
        comparison.write_comparison(output, {"schema": comparison.SCHEMA})

    with pytest.raises(ValueError, match="output_must_be_external"):
        comparison.write_comparison(ROOT / "output" / "comparison.json", {"schema": comparison.SCHEMA})
