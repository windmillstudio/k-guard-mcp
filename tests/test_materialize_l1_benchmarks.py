from __future__ import annotations

import csv
import hashlib
import importlib.util
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "materialize_l1_benchmarks.py"
SPEC = importlib.util.spec_from_file_location("materialize_l1_benchmarks_test", SCRIPT)
assert SPEC and SPEC.loader
materializer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = materializer
SPEC.loader.exec_module(materializer)

RECEIPT_SCRIPT = ROOT / "scripts" / "holdout_source_materialization.py"
RECEIPT_SPEC = importlib.util.spec_from_file_location(
    "holdout_source_materialization_l1_compatibility_test",
    RECEIPT_SCRIPT,
)
assert RECEIPT_SPEC and RECEIPT_SPEC.loader
receipt_contract = importlib.util.module_from_spec(RECEIPT_SPEC)
sys.modules[RECEIPT_SPEC.name] = receipt_contract
RECEIPT_SPEC.loader.exec_module(receipt_contract)


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


def _hash_object(root: Path, raw: bytes) -> str:
    completed = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=root,
        input=raw,
        capture_output=True,
        check=True,
    )
    return completed.stdout.decode("ascii").strip()


def _fixture(
    tmp_path: Path,
    language: str,
    *,
    rows: list[tuple[str, str, str, str]] | None = None,
) -> tuple[Path, object]:
    root = tmp_path / language
    root.mkdir(parents=True)
    _git(root, "init", "--initial-branch=main")
    _git(root, "config", "user.email", "l1@example.invalid")
    _git(root, "config", "user.name", "L1 Fixture")
    _git(root, "config", "core.autocrlf", "false")
    origin = f"https://github.com/example/Benchmark{language.title()}"
    _git(root, "remote", "add", "origin", origin)
    expected_path = "expected.csv"
    license_path = "LICENSE"
    source_prefix = "src/cases" if language == "java" else "testcode"
    suffix = ".java" if language == "java" else ".py"
    category_cwe = (("sqli", "89"), ("xss", "79"))
    official_rows = rows or [
        ("BenchmarkTest00001", "sqli", "true", "89"),
        ("BenchmarkTest00002", "xss", "false", "79"),
    ]
    (root / license_path).write_bytes(f"{language} fixture license\n".encode())
    with (root / expected_path).open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(["# test name", "category", "real vulnerability", "cwe"])
        writer.writerows(official_rows)
    source_root = root / source_prefix
    source_root.mkdir(parents=True)
    for case_id, *_rest in {row[0]: row for row in official_rows}.values():
        (source_root / f"{case_id}{suffix}").write_text(
            f"// {case_id}\n" if language == "java" else f"# {case_id}\n",
            encoding="utf-8",
        )
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
        license_path=license_path,
        license_spdx="MIT",
        license_sha256=_sha256(root / license_path),
        expected_case_count=len(official_rows),
        source_prefix=source_prefix,
        source_suffix=suffix,
        category_cwe=category_cwe,
    )
    return root, spec


def test_build_manifest_binds_every_case_and_never_observes_scanner_output(tmp_path: Path) -> None:
    java, java_spec = _fixture(tmp_path, "java")
    python, python_spec = _fixture(tmp_path, "python")

    first = materializer.build_manifest(java, python, specs=(java_spec, python_spec))
    second = materializer.build_manifest(java, python, specs=(java_spec, python_spec))

    assert materializer.canonical_json_bytes(first) == materializer.canonical_json_bytes(second)
    assert first["status"] == "locked_before_scan"
    assert first["scanner_output_observed"] is False
    assert first["coverage_policy"] == "all_official_rows_exactly_once"
    assert first["unsupported_detector_category_policy"] == "retain_in_denominator"
    assert first["total_case_count"] == 4
    assert {row["truth"] for corpus in first["corpora"] for row in corpus["cases"]} == {
        "present",
        "absent",
    }
    assert all(
        len(row["source_sha256"]) == 64
        for corpus in first["corpora"]
        for row in corpus["cases"]
    )
    assert all(corpus["source_tree"]["files"] for corpus in first["corpora"])
    assert all(
        corpus["source_tree"]["source_worktree_clean_method"]
        == materializer.BLOB_EXACT_CLEAN_METHOD
        for corpus in first["corpora"]
    )
    assert all(
        corpus["source_tree"]["physical_bytes_match_git_blobs"] is True
        for corpus in first["corpora"]
    )


def test_source_tree_hash_is_byte_compatible_with_authoritative_contract(
    tmp_path: Path,
) -> None:
    root, spec = _fixture(tmp_path, "java")

    source_tree = materializer._materialize_corpus(root, spec)["source_tree"]
    normalized = materializer._normalized_source_tree_rows(source_tree["files"])

    assert source_tree["schema"] == receipt_contract.MATERIALIZED_TREE_SCHEMA
    assert source_tree["source_tree_sha256"] == receipt_contract._source_tree_sha256(
        normalized
    )
    assert all("git_blob_sha1" in row for row in normalized)


def test_source_tree_hash_commits_to_git_blob_identity(tmp_path: Path) -> None:
    root, spec = _fixture(tmp_path, "java")
    source_tree = materializer._materialize_corpus(root, spec)["source_tree"]
    normalized = materializer._normalized_source_tree_rows(source_tree["files"])
    changed = [dict(row) for row in normalized]
    changed[0]["git_blob_sha1"] = "0" * 40

    assert materializer._source_tree_sha256(changed) != source_tree["source_tree_sha256"]


def test_raw_git_blobs_pass_with_autocrlf_even_when_porcelain_reports_modified(
    tmp_path: Path,
) -> None:
    root, spec = _fixture(tmp_path, "java")
    source_relative = f"{spec.source_prefix}/BenchmarkTest00001{spec.source_suffix}"
    source = root / source_relative
    attributes = root / ".gitattributes"
    attributes.write_bytes(b"*.java text\n")
    _git(root, "add", ".gitattributes")
    raw = b"// raw commit blob\r\n"
    blob = _hash_object(root, raw)
    _git(root, "update-index", "--cacheinfo", f"100644,{blob},{source_relative}")
    _git(root, "commit", "-m", "raw CRLF blob")
    source.write_bytes(raw)
    _git(root, "config", "core.autocrlf", "true")
    raw_spec = replace(
        spec,
        revision_sha1=_git(root, "rev-parse", "HEAD"),
        commit_tree_sha1=_git(root, "rev-parse", "HEAD^{tree}"),
    )
    config_before = (root / ".git" / "config").read_bytes()
    source_before = source.read_bytes()
    assert _git(root, "status", "--porcelain=v1")

    corpus = materializer._materialize_corpus(root, raw_spec)

    case = next(row for row in corpus["cases"] if row["case_id"] == "BenchmarkTest00001")
    assert case["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert corpus["source_tree"]["index_tree_match"] is True
    assert corpus["source_tree"]["physical_bytes_match_git_blobs"] is True
    assert (root / ".git" / "config").read_bytes() == config_before
    assert source.read_bytes() == source_before


@pytest.mark.parametrize("field", ["revision_sha1", "commit_tree_sha1", "repository_origin"])
def test_revision_tree_and_origin_must_match_exactly(tmp_path: Path, field: str) -> None:
    root, spec = _fixture(tmp_path, "java")
    replacement = "0" * 40 if field != "repository_origin" else "https://github.com/wrong/repo"

    with pytest.raises(ValueError, match="mismatch"):
        materializer._materialize_corpus(root, replace(spec, **{field: replacement}))


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        (
            [
                ("BenchmarkTest00001", "sqli", "true", "89"),
                ("BenchmarkTest00001", "sqli", "false", "89"),
            ],
            "duplicate",
        ),
        (
            [("BenchmarkTest00001", "unknown", "true", "999")],
            "unsupported category/CWE",
        ),
        (
            [("BenchmarkTest00001", "sqli", "maybe", "89")],
            "invalid truth",
        ),
    ],
)
def test_expected_rows_fail_closed(tmp_path: Path, rows: list[tuple[str, str, str, str]], message: str) -> None:
    root, spec = _fixture(tmp_path, "java", rows=rows)

    with pytest.raises(ValueError, match=message):
        materializer._materialize_corpus(root, spec)


def test_malformed_csv_and_wrong_exact_count_fail_closed(tmp_path: Path) -> None:
    root, spec = _fixture(tmp_path, "java")
    expected = root / spec.expected_results_path
    expected.write_text("BenchmarkTest00001,sqli,true\n", encoding="utf-8")
    _git(root, "add", "--all")
    _git(root, "commit", "-m", "malformed")
    malformed = replace(
        spec,
        revision_sha1=_git(root, "rev-parse", "HEAD"),
        commit_tree_sha1=_git(root, "rev-parse", "HEAD^{tree}"),
        expected_results_sha256=_sha256(expected),
    )
    with pytest.raises(ValueError, match="malformed expected-results row"):
        materializer._materialize_corpus(root, malformed)

    root2, spec2 = _fixture(tmp_path / "count", "java")
    with pytest.raises(ValueError, match="expected exactly 3"):
        materializer._materialize_corpus(root2, replace(spec2, expected_case_count=3))


def test_missing_source_and_license_content_fail_closed(tmp_path: Path) -> None:
    root, spec = _fixture(tmp_path, "java")
    source = root / spec.source_prefix / f"BenchmarkTest00002{spec.source_suffix}"
    source.unlink()
    _git(root, "add", "--all")
    _git(root, "commit", "-m", "remove source")
    missing = replace(
        spec,
        revision_sha1=_git(root, "rev-parse", "HEAD"),
        commit_tree_sha1=_git(root, "rev-parse", "HEAD^{tree}"),
    )
    with pytest.raises(ValueError, match="source is missing"):
        materializer._materialize_corpus(root, missing)

    root2, spec2 = _fixture(tmp_path / "license", "java")
    with pytest.raises(ValueError, match="license content mismatch"):
        materializer._materialize_corpus(root2, replace(spec2, license_sha256="0" * 64))


@pytest.mark.parametrize(
    ("kind", "message"),
    [
        ("modified", "physical bytes differ"),
        ("untracked", "untracked or ignored"),
        ("ignored", "untracked or ignored"),
    ],
)
def test_dirty_tree_fails_closed(tmp_path: Path, kind: str, message: str) -> None:
    root, spec = _fixture(tmp_path, "java")
    if kind == "modified":
        (root / "LICENSE").write_text("changed\n", encoding="utf-8")
    elif kind == "untracked":
        (root / "token.env").write_text("TOKEN=test\n", encoding="utf-8")
    else:
        (root / ".gitignore").write_text("ignored.env\n", encoding="utf-8")
        _git(root, "add", ".gitignore")
        _git(root, "commit", "-m", "ignore fixture")
        (root / "ignored.env").write_text("ignored\n", encoding="utf-8")
        spec = replace(
            spec,
            revision_sha1=_git(root, "rev-parse", "HEAD"),
            commit_tree_sha1=_git(root, "rev-parse", "HEAD^{tree}"),
        )

    with pytest.raises(ValueError, match=message):
        materializer._materialize_corpus(root, spec)


def test_staged_index_tree_divergence_fails_closed(tmp_path: Path) -> None:
    root, spec = _fixture(tmp_path, "java")
    source_relative = f"{spec.source_prefix}/BenchmarkTest00001{spec.source_suffix}"
    blob = _hash_object(root, b"// staged replacement\n")
    _git(root, "update-index", "--cacheinfo", f"100644,{blob},{source_relative}")

    with pytest.raises(ValueError, match="index tree differs"):
        materializer._materialize_corpus(root, spec)


def test_symlink_source_fails_closed_when_supported(tmp_path: Path) -> None:
    root, spec = _fixture(tmp_path, "java")
    source = root / spec.source_prefix / f"BenchmarkTest00001{spec.source_suffix}"
    target = root / "target.java"
    target.write_text("// target\n", encoding="utf-8")
    source.unlink()
    try:
        source.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(ValueError, match="symlink|link"):
        materializer._materialize_corpus(root, spec)


def test_write_manifest_refuses_output_overwrite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    java, java_spec = _fixture(tmp_path, "java")
    python, python_spec = _fixture(tmp_path, "python")
    output = tmp_path / "manifest.json"
    output.write_text("existing\n", encoding="utf-8")
    monkeypatch.setattr(materializer, "L1_CORPORA", (java_spec, python_spec))

    with pytest.raises(ValueError, match="overwrite"):
        materializer.write_manifest(java, python, output)
    assert output.read_text(encoding="utf-8") == "existing\n"


def test_production_specs_lock_full_official_denominators() -> None:
    by_language = {spec.language: spec for spec in materializer.L1_CORPORA}

    assert by_language["java"].expected_case_count == 2740
    assert by_language["python"].expected_case_count == 1230
    assert by_language["java"].revision_sha1 == "79b9bd6177e07991a9c11dc19e457c840e229931"
    assert by_language["python"].revision_sha1 == "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"
    assert by_language["python"].repository_origin == (
        "https://github.com/OWASP-Benchmark/BenchmarkPython.git"
    )
    assert by_language["java"].license_sha256 == (
        "c03cea027b4b40e4402fabd08557736727ec3d5bc54ad64ab6472de432198cad"
    )
    assert by_language["python"].license_sha256 == (
        "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"
    )
    assert dict(by_language["java"].category_cwe)["sqli"] == "89"
    assert dict(by_language["python"].category_cwe)["deserialization"] == "502"
