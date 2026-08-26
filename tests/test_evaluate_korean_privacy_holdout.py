from __future__ import annotations

import json
from pathlib import Path

import pytest

from k_guard_mcp.sensitive_vocabulary import CONTEST_SENSITIVE_CONCEPT_TERMS
from scripts import evaluate_korean_privacy_holdout as holdout


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evidence" / "holdout" / "korean-sensitive-org-v1.cjson"


def test_holdout_directly_contains_every_contest_sensitive_expression() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    corpus = "\n".join(str(case["text"]) for case in manifest["cases"])

    assert set(CONTEST_SENSITIVE_CONCEPT_TERMS) == {
        "장애",
        "장애정보",
        "생체정보",
        "지문",
        "홍채",
        "건강상태",
    }
    assert all(term in corpus for term in CONTEST_SENSITIVE_CONCEPT_TERMS)


def test_holdout_imports_analyzer_from_this_repository() -> None:
    assert holdout.ANALYZER_PACKAGE_DIR == (ROOT / "src" / "k_guard_mcp").resolve()


def test_frozen_manifest_is_canonical_and_exact() -> None:
    manifest, digest = holdout.load_manifest(MANIFEST)

    assert digest == holdout.MANIFEST_SHA256
    assert manifest["case_count"] == 68
    assert len(manifest["cases"]) == 68
    assert tuple(case["id"] for case in manifest["cases"]) == holdout.EXPECTED_IDS
    assert digest == holdout._sha256_file(MANIFEST)
    assert holdout.canonical_json_bytes(manifest) == MANIFEST.read_bytes()

    groups: dict[str, int] = {}
    for case in manifest["cases"]:
        groups[case["group"]] = groups.get(case["group"], 0) + 1
    assert dict(sorted(groups.items())) == holdout.EXPECTED_GROUP_COUNTS


def test_report_is_deterministic_raw_free_and_repeat_bound() -> None:
    manifest, digest = holdout.load_manifest(MANIFEST)
    first = holdout.evaluate_manifest(manifest, digest, repeat=2, repo_root=ROOT)
    second = holdout.evaluate_manifest(manifest, digest, repeat=2, repo_root=ROOT)

    assert holdout.canonical_json_bytes(first) == holdout.canonical_json_bytes(second)
    assert first["schema"] == holdout.REPORT_SCHEMA
    assert first["raw_returned"] is False
    assert first["repeat"]["requested"] == 2
    assert first["repeat"]["performed"] == 2
    assert first["repeat"]["exact"] is True
    assert len(set(first["repeat"]["run_fingerprints"])) == 1
    assert first["manifest"]["sha256"] == digest

    metrics = first["metrics"]
    assert metrics["case_count"] == 68
    assert metrics["tp"] + metrics["fn"] + metrics["fp"] + metrics["tn"] == 68
    assert metrics["passed_count"] + metrics["failed_count"] == 68
    assert sum(row["case_count"] for row in metrics["by_group"].values()) == 68

    rendered = holdout.canonical_json_bytes(first).decode("utf-8")
    for case in manifest["cases"]:
        assert case["text"] not in rendered
    assert "901225-1234563" not in rendered
    assert "451311-0005055" not in rendered
    assert all("text" not in row for row in first["case_results"])
    assert all("text" not in row for row in first["failures"])


def test_cli_writes_canonical_report_without_relaxing_failed_oracles(
    tmp_path: Path,
) -> None:
    output = tmp_path / "report.json"
    returncode = holdout.main(
        [
            "--manifest",
            str(MANIFEST),
            "--repeat",
            "2",
            "--output",
            str(output),
        ]
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    assert output.read_bytes() == holdout.canonical_json_bytes(report)
    assert report["metrics"]["case_count"] == 68
    assert report["metrics"]["fn"] == 0
    assert report["metrics"]["fp"] == 0
    assert report["repeat"]["exact"] is True
    assert report["raw_returned"] is False
    binding = report["source_binding"]
    source_ok = (
        binding["working_package_tree_matches_head"] is True
        and binding["working_source_files_match_head"] is True
    )
    if source_ok and report["repeat"]["exact"] is True and report["metrics"]["passed_count"] == 68:
        assert returncode == 0
        assert report["passed"] is True
    else:
        assert returncode == 1
        assert report["passed"] is False


def test_manifest_rejects_oracle_or_identity_drift(tmp_path: Path) -> None:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    payload["cases"][0]["id"] = payload["cases"][1]["id"]
    changed = tmp_path / "changed.cjson"
    changed.write_bytes(holdout.canonical_json_bytes(payload))

    with pytest.raises(holdout.HoldoutError, match="frozen evaluator digest"):
        holdout.load_manifest(changed)


@pytest.mark.parametrize("repeat", [0, 11, True])
def test_repeat_budget_is_fail_closed(repeat: int) -> None:
    manifest, digest = holdout.load_manifest(MANIFEST)
    with pytest.raises(holdout.HoldoutError, match="repeat must be an integer"):
        holdout.evaluate_manifest(manifest, digest, repeat=repeat, repo_root=ROOT)


def test_holdout_case_metrics_are_complete_independent_of_source_binding() -> None:
    manifest, digest = holdout.load_manifest(MANIFEST)
    report = holdout.evaluate_manifest(manifest, digest, repeat=2, repo_root=ROOT)
    metrics = report["metrics"]
    assert metrics["case_count"] == 68
    assert metrics["passed_count"] == 68
    assert metrics["failed_count"] == 0
    assert metrics["fn"] == 0
    assert metrics["fp"] == 0
    assert metrics["recall"] == 1.0
    assert metrics["specificity"] == 1.0
    assert report["repeat"]["exact"] is True
    rendered = holdout.canonical_json_bytes(report).decode("utf-8")
    assert "901225-1234563" not in rendered


def test_pinned_manifest_digest_rejects_case_and_oracle_drift(tmp_path: Path) -> None:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    payload["cases"][0]["text"] = payload["cases"][0]["text"] + " drift"
    changed = tmp_path / "case-drift.cjson"
    changed.write_bytes(holdout.canonical_json_bytes(payload))
    with pytest.raises(holdout.HoldoutError, match="frozen evaluator digest"):
        holdout.load_manifest(changed)

    oracle = json.loads(MANIFEST.read_text(encoding="utf-8"))
    oracle["oracle"]["negative_prose"] = "drifted oracle text"
    oracle_path = tmp_path / "oracle-drift.cjson"
    oracle_path.write_bytes(holdout.canonical_json_bytes(oracle))
    with pytest.raises(holdout.HoldoutError, match="frozen evaluator digest"):
        holdout.load_manifest(oracle_path)


def test_dirty_source_binding_fails_closed_while_keeping_case_metrics(monkeypatch: pytest.MonkeyPatch) -> None:
    real_binding = holdout._source_binding

    def dirty(repo_root: Path) -> dict:
        binding = real_binding(repo_root)
        binding["working_package_tree_matches_head"] = False
        binding["working_source_files_match_head"] = False
        for item in binding["source_files"]:
            item["working_matches_head"] = False
        return binding

    monkeypatch.setattr(holdout, "_source_binding", dirty)
    manifest, digest = holdout.load_manifest(MANIFEST)
    report = holdout.evaluate_manifest(manifest, digest, repeat=2, repo_root=ROOT)
    assert report["metrics"]["passed_count"] == 68
    assert report["metrics"]["fn"] == 0
    assert report["metrics"]["fp"] == 0
    assert report["repeat"]["exact"] is True
    assert report["passed"] is False


def test_default_cli_is_nonzero_when_report_is_not_passed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def failing_evaluate(*args, **kwargs):
        return {
            "passed": False,
            "metrics": {"case_count": 68, "failed_count": 1},
            "manifest": {"sha256": holdout.MANIFEST_SHA256},
            "repeat": {"exact": True},
            "raw_returned": False,
        }

    monkeypatch.setattr(holdout, "evaluate_manifest", failing_evaluate)
    monkeypatch.setattr(holdout, "load_manifest", lambda path: ({"case_count": 68, "cases": []}, holdout.MANIFEST_SHA256))
    output = tmp_path / "fail.json"
    returncode = holdout.main(["--manifest", str(MANIFEST), "--repeat", "1", "--output", str(output)])
    assert returncode == 1
    assert json.loads(output.read_text(encoding="utf-8"))["passed"] is False


def test_report_passed_true_requires_source_files_and_package_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    real_binding = holdout._source_binding

    def bound(repo_root: Path) -> dict:
        binding = real_binding(repo_root)
        binding["working_package_tree_matches_head"] = True
        binding["working_source_files_match_head"] = True
        for item in binding["source_files"]:
            item["working_matches_head"] = True
        return binding

    monkeypatch.setattr(holdout, "_source_binding", bound)
    manifest, digest = holdout.load_manifest(MANIFEST)
    report = holdout.evaluate_manifest(manifest, digest, repeat=2, repo_root=ROOT)
    assert report["metrics"]["passed_count"] == 68
    assert report["repeat"]["exact"] is True
    assert report["passed"] is True
