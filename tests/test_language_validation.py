from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

import pytest

import k_guard_mcp.analyzers as analyzers
import k_guard_mcp.language_validation as language_validation
from k_guard_mcp.analyzers import (
    DEFAULT_SEMGREP_PROFILE,
    AnalyzerAdapter,
    AnalyzerFinding,
    AnalyzerRun,
    SemgrepAnalyzerAdapter,
)
from k_guard_mcp.language_validation import run_language_validation_pack
from k_guard_mcp.language_validation import DEFAULT_LANGUAGE_VALIDATION_PACK
from k_guard_mcp.provenance import verify_evidence_bundle


ROOT = Path(__file__).resolve().parents[1]
PACK = DEFAULT_LANGUAGE_VALIDATION_PACK
RAW_MARKER = "SOURCE_OR_DIAGNOSTIC_MUST_NOT_BE_RETURNED_84f90a"


def _expectations(pack: Path = PACK) -> dict:
    return json.loads((pack / "expectations.json").read_text(encoding="utf-8"))


class _FakeAdapter(AnalyzerAdapter):
    def __init__(
        self,
        *,
        missing: set[str] | None = None,
        false_positives: set[str] | None = None,
        repeat_drift: bool = False,
        incomplete_calls: set[int] | None = None,
        raise_calls: set[int] | None = None,
        invalid_return_calls: set[int] | None = None,
        run_overrides: dict[int, dict[str, Any]] | None = None,
        control_errors_by_call: dict[int, tuple[str, ...]] | None = None,
        extra_findings_by_call: dict[int, tuple[AnalyzerFinding, ...]] | None = None,
    ) -> None:
        self.missing = missing or set()
        self.false_positives = false_positives or set()
        self.repeat_drift = repeat_drift
        self.incomplete_calls = incomplete_calls or set()
        self.raise_calls = raise_calls or set()
        self.invalid_return_calls = invalid_return_calls or set()
        self.run_overrides = run_overrides or {}
        self.control_errors_by_call = control_errors_by_call or {}
        self.extra_findings_by_call = extra_findings_by_call or {}
        self.calls: list[tuple[Path, Path | None]] = []
        manifest = json.loads((PACK / "pack.json").read_text(encoding="utf-8"))
        self.profile_sha256 = manifest["profile"]["sha256"]
        self.rules_sha256 = manifest["profile"]["rules_sha256"]
        self.executable_version = manifest["analyzer"]["executable_version"]
        target_paths = tuple(sorted(case["file"] for case in _expectations()["cases"]))
        self.target_count = len(target_paths)
        self.target_path_set_sha256 = analyzers._path_set_sha256(target_paths)

    @property
    def analyzer_subtype(self) -> str:
        return "fake-intrafile"

    def analyze(self, workspace: str | Path, *, profile_path: str | Path | None = None) -> AnalyzerRun:
        call_index = len(self.calls)
        self.calls.append((Path(workspace), Path(profile_path) if profile_path is not None else None))
        if call_index in self.raise_calls:
            raise RuntimeError(RAW_MARKER)
        if call_index in self.invalid_return_calls:
            return object()  # type: ignore[return-value]
        incomplete = call_index in self.incomplete_calls
        findings: list[AnalyzerFinding] = []
        if not incomplete:
            for case in _expectations()["cases"]:
                wanted = case["expected"] == "vulnerable" and case["case_id"] not in self.missing
                wanted = wanted or case["case_id"] in self.false_positives
                if wanted:
                    salt = ":repeat-drift" if self.repeat_drift and call_index == 1 else ""
                    fingerprint = hashlib.sha256((case["case_id"] + salt).encode("ascii")).hexdigest()
                    findings.append(
                        AnalyzerFinding(
                            rule_id=case["rule_id"],
                            severity="high",
                            confidence="high",
                            cwe=("CWE-20",),
                            file=case["file"],
                            line_start=1,
                            line_end=1,
                            message=RAW_MARKER,
                            recommendation=RAW_MARKER,
                            analyzer_subtype=self.analyzer_subtype,
                            fingerprint=fingerprint,
                        )
                    )
        findings.extend(self.extra_findings_by_call.get(call_index, ()))
        values: dict[str, Any] = {
            "complete": not incomplete,
            "control_errors": self.control_errors_by_call.get(
                call_index,
                ("fake_analyzer_incomplete",) if incomplete else (),
            ),
            "findings": tuple(findings),
            "analyzer": "fake-analyzer",
            "analyzer_subtype": self.analyzer_subtype,
            "executable_version": self.executable_version,
            "adapter_version": "1.0.0",
            "profile_name": DEFAULT_SEMGREP_PROFILE.name,
            "adapter_sha256": "a" * 64,
            "profile_sha256": self.profile_sha256,
            "rules_sha256": self.rules_sha256,
            "command_contract_sha256": "b" * 64,
            "input_snapshot": (
                {}
                if incomplete
                else {
                    "schema": "k_guard_source_tree_snapshot.v1",
                    "complete": True,
                    "tree_sha256": "c" * 64,
                }
            ),
            "counts": {
                "eligible_target_count": self.target_count,
                "scanned_target_count": self.target_count,
            },
            "target_coverage": analyzers._target_coverage(
                result="exact",
                eligible_count=self.target_count,
                scanned_count=self.target_count,
                eligible_path_set_sha256=self.target_path_set_sha256,
                scanned_path_set_sha256=self.target_path_set_sha256,
            ),
        }
        values.update(self.run_overrides.get(call_index, {}))
        return AnalyzerRun(**values)


def _copy_pack(tmp_path: Path) -> Path:
    target = tmp_path / "pack"
    shutil.copytree(PACK, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"))
    return target


def _write_expectations_and_repin(pack: Path, value: dict) -> None:
    content = (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    (pack / "expectations.json").write_bytes(content)
    manifest = json.loads((pack / "pack.json").read_text(encoding="utf-8"))
    manifest["expectations"]["sha256"] = hashlib.sha256(content).hexdigest()
    (pack / "pack.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def _write_expectations_bytes_and_repin(pack: Path, content: bytes) -> None:
    (pack / "expectations.json").write_bytes(content)
    manifest = json.loads((pack / "pack.json").read_text(encoding="utf-8"))
    manifest["expectations"]["sha256"] = hashlib.sha256(content).hexdigest()
    (pack / "pack.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def _write_manifest(pack: Path, value: Any) -> None:
    (pack / "pack.json").write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _finding(*, file: str, rule_id: str, seed: str) -> AnalyzerFinding:
    return AnalyzerFinding(
        rule_id=rule_id,
        severity="high",
        confidence="high",
        cwe=("CWE-20",),
        file=file,
        line_start=1,
        line_end=1,
        message=RAW_MARKER,
        recommendation=RAW_MARKER,
        analyzer_subtype="fake-intrafile",
        fingerprint=hashlib.sha256(seed.encode("ascii")).hexdigest(),
    )


def test_pack_is_balanced_immutable_and_fake_adapter_is_ready() -> None:
    expectations = _expectations()
    cases = expectations["cases"]
    assert expectations["immutable"] is True
    assert len(cases) == 90
    assert len({case["case_id"] for case in cases}) == 90
    assert len({case["file"] for case in cases}) == 90
    for language in language_validation.REQUIRED_LANGUAGES:
        selected = [case for case in cases if case["language"] == language]
        assert sum(case["expected"] == "vulnerable" for case in selected) == 5
        assert sum(case["expected"] == "clean" for case in selected) == 5
        for expected in ("vulnerable", "clean"):
            assert {case["category"] for case in selected if case["expected"] == expected} == {
                "sql-injection",
                "command-injection",
                "path-traversal",
                "ssrf",
                "authorization-review",
            }

    adapter = _FakeAdapter()
    report = run_language_validation_pack(PACK, adapter)

    assert report["complete"] is True
    assert report["ready"] is True
    assert report["status"] == "development_validation_ready"
    assert report["metrics"]["overall"] == {
        "confusion_matrix": {"tp": 45, "fn": 0, "fp": 0, "tn": 45},
        "recall": 1.0,
        "specificity": 1.0,
        "precision": 1.0,
    }
    for language in language_validation.REQUIRED_LANGUAGES:
        assert report["metrics"]["by_language"][language]["confusion_matrix"] == {
            "tp": 5,
            "fn": 0,
            "fp": 0,
            "tn": 5,
        }
    assert report["repeat"]["exact"] is True
    assert report["repeat"]["primary_finding_count"] == 45
    assert report["repeat"]["primary_fingerprint_multiset"] == report["repeat"]["repeat_fingerprint_multiset"]
    assert report["unmapped_findings"] == []
    assert report["pack"]["analyzer"] == {
        "name": "semgrep",
        "executable_version": "1.174.0",
    }
    assert all(run["target_coverage"]["result"] == "exact" for run in report["analyzer_runs"])
    assert len(adapter.calls) == 2
    assert all(profile == DEFAULT_SEMGREP_PROFILE for _, profile in adapter.calls)
    assert all(workspace == (PACK / "fixtures").resolve() for workspace, _ in adapter.calls)
    assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in report["hashes"].values())
    assert verify_evidence_bundle(report["evidence_bundle"]) is True
    rendered = json.dumps(report, sort_keys=True)
    assert RAW_MARKER not in rendered
    assert str(PACK.resolve()) not in rendered
    assert report["claim_boundary"]["claim"] == "development_validation_not_field_accuracy"
    assert report["claim_boundary"]["field_accuracy_claimed"] is False
    assert report["claim_boundary"]["analysis_scope"] == "semgrep_ce_intrafile"
    assert report["claim_boundary"]["interfile_dataflow_claimed"] is False
    assert report["claim_boundary"]["framework_authorization_proof_claimed"] is False
    assert report["requirements"]["all_nine_languages"] is True


def test_case_level_scoring_counts_false_negative_and_clean_false_positive() -> None:
    adapter = _FakeAdapter(
        missing={"java-sql-vulnerable"},
        false_positives={"java-command-clean"},
    )
    report = run_language_validation_pack(PACK, adapter)

    assert report["complete"] is True
    assert report["ready"] is False
    assert report["metrics"]["overall"]["confusion_matrix"] == {"tp": 44, "fn": 1, "fp": 1, "tn": 44}
    assert report["metrics"]["overall"]["recall"] == pytest.approx(44 / 45, abs=1e-6)
    assert report["metrics"]["overall"]["specificity"] == pytest.approx(44 / 45, abs=1e-6)
    assert report["metrics"]["overall"]["precision"] == pytest.approx(44 / 45, abs=1e-6)
    assert report["requirements"]["all_expected_positives_found"] is False
    assert report["requirements"]["zero_clean_case_false_positives"] is False


def test_repeat_fingerprint_drift_blocks_readiness() -> None:
    report = run_language_validation_pack(PACK, _FakeAdapter(repeat_drift=True))

    assert report["complete"] is True
    assert report["metrics"]["overall"]["confusion_matrix"] == {"tp": 45, "fn": 0, "fp": 0, "tn": 45}
    assert report["repeat"]["exact"] is False
    assert report["ready"] is False
    assert report["requirements"]["exact_repeat_fingerprint_multiset"] is False


def test_incomplete_analyzer_fails_closed_after_both_runs() -> None:
    adapter = _FakeAdapter(incomplete_calls={0})
    report = run_language_validation_pack(PACK, adapter)

    assert len(adapter.calls) == 2
    assert report["complete"] is False
    assert report["ready"] is False
    assert report["metrics"] is None
    assert report["case_results"] == []
    assert "analyzer_run_incomplete" in report["control_errors"]
    assert "fake_analyzer_incomplete" in report["control_errors"]
    assert report["repeat"]["exact"] is False


def test_invalid_api_inputs_fail_closed_without_running_analyzer() -> None:
    adapter = _FakeAdapter()

    invalid_repeat = run_language_validation_pack(PACK, adapter, repeat=1)  # type: ignore[arg-type]
    invalid_adapter = run_language_validation_pack(PACK, object())  # type: ignore[arg-type]

    assert invalid_repeat["control_errors"] == ["repeat_option_invalid"]
    assert invalid_adapter["control_errors"] == ["analyzer_adapter_invalid"]
    assert adapter.calls == []
    assert verify_evidence_bundle(invalid_repeat["evidence_bundle"]) is True
    assert verify_evidence_bundle(invalid_adapter["evidence_bundle"]) is True


@pytest.mark.parametrize("failure_kind", ["exception-first", "exception-repeat", "invalid-first", "invalid-repeat"])
def test_adapter_failures_are_raw_free_and_fail_closed(failure_kind: str) -> None:
    call_index = 1 if failure_kind.endswith("repeat") else 0
    adapter = _FakeAdapter(
        raise_calls={call_index} if failure_kind.startswith("exception") else set(),
        invalid_return_calls={call_index} if failure_kind.startswith("invalid") else set(),
    )

    report = run_language_validation_pack(PACK, adapter)

    expected = "analyzer_adapter_exception" if failure_kind.startswith("exception") else "analyzer_run_contract_invalid"
    assert report["control_errors"] == [expected]
    assert report["complete"] is False
    assert report["ready"] is False
    assert len(report["analyzer_runs"]) == call_index
    assert RAW_MARKER not in json.dumps(report, sort_keys=True)


@pytest.mark.parametrize(
    ("overrides", "expected_error"),
    [
        ({0: {"profile_name": "other.yml"}, 1: {"profile_name": "other.yml"}}, "analyzer_profile_contract_mismatch"),
        ({0: {"profile_sha256": "d" * 64}, 1: {"profile_sha256": "d" * 64}}, "analyzer_profile_contract_mismatch"),
        ({0: {"rules_sha256": "d" * 64}, 1: {"rules_sha256": "d" * 64}}, "analyzer_profile_contract_mismatch"),
        ({0: {"adapter_sha256": ""}, 1: {"adapter_sha256": ""}}, "analyzer_identity_incomplete"),
        (
            {0: {"command_contract_sha256": ""}, 1: {"command_contract_sha256": ""}},
            "analyzer_identity_incomplete",
        ),
        ({1: {"executable_version": "2.0.0"}}, "analyzer_contract_drift"),
        (
            {
                1: {
                    "input_snapshot": {
                        "schema": "k_guard_source_tree_snapshot.v1",
                        "complete": True,
                        "tree_sha256": "d" * 64,
                    }
                }
            },
            "analyzer_contract_drift",
        ),
    ],
)
def test_profile_identity_and_repeat_contract_mismatch_fail_closed(
    overrides: dict[int, dict[str, Any]],
    expected_error: str,
) -> None:
    report = run_language_validation_pack(PACK, _FakeAdapter(run_overrides=overrides))

    assert expected_error in report["control_errors"]
    assert report["complete"] is False
    assert report["ready"] is False
    assert report["metrics"] is None


@pytest.mark.parametrize("version", ["", "2.0.0"], ids=("missing", "drift-from-pin"))
def test_missing_or_drifted_semgrep_version_fails_pack_application(version: str) -> None:
    overrides = {
        0: {"executable_version": version},
        1: {"executable_version": version},
    }

    report = run_language_validation_pack(PACK, _FakeAdapter(run_overrides=overrides))

    assert report["complete"] is False
    assert report["ready"] is False
    assert "analyzer_executable_version_mismatch" in report["control_errors"]
    assert report["metrics"] is None


def test_missing_target_coverage_proof_fails_pack_application() -> None:
    overrides = {0: {"target_coverage": {}}, 1: {"target_coverage": {}}}

    report = run_language_validation_pack(PACK, _FakeAdapter(run_overrides=overrides))

    assert report["complete"] is False
    assert "analyzer_target_coverage_mismatch" in report["control_errors"]


def test_untrusted_control_errors_are_normalized_and_raw_free() -> None:
    adapter = _FakeAdapter(
        incomplete_calls={0, 1},
        control_errors_by_call={0: (RAW_MARKER,), 1: ("bounded_failure",)},
    )

    report = run_language_validation_pack(PACK, adapter)

    assert report["control_errors"] == [
        "analyzer_run_incomplete",
        "analyzer_control_error",
        "bounded_failure",
    ]
    assert RAW_MARKER not in json.dumps(report, sort_keys=True)


def test_single_run_cannot_claim_repeat_readiness_and_sanitizes_versions() -> None:
    adapter = _FakeAdapter(run_overrides={0: {"adapter_version": "bad version"}})

    report = run_language_validation_pack(PACK, adapter, repeat=False)

    assert report["complete"] is True
    assert report["ready"] is False
    assert report["repeat"] == {
        "requested": False,
        "performed": False,
        "exact": False,
        "primary_finding_count": 45,
        "repeat_finding_count": 0,
        "primary_fingerprint_multiset": report["repeat"]["primary_fingerprint_multiset"],
        "repeat_fingerprint_multiset": [],
        "primary_fingerprint_multiset_sha256": report["repeat"]["primary_fingerprint_multiset_sha256"],
        "repeat_fingerprint_multiset_sha256": "",
    }
    assert report["analyzer_runs"][0]["executable_version"] == "1.174.0"
    assert report["analyzer_runs"][0]["adapter_version"] == ""


def test_current_language_contract_is_complete_and_fails_closed_on_loader_error(monkeypatch) -> None:
    current = language_validation.current_language_validation_contract()

    assert current["complete"] is True
    assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in current["hashes"].values())
    assert current["analyzer"] == {"name": "semgrep", "executable_version": "1.174.0"}
    assert current["raw_free"] is True

    def _raise_loader_error(_value):
        raise RuntimeError(RAW_MARKER)

    monkeypatch.setattr(language_validation, "_load_pack", _raise_loader_error)
    failed = language_validation.current_language_validation_contract()
    assert failed["complete"] is False
    assert set(failed["hashes"].values()) == {""}
    assert failed["analyzer"] == {"name": "", "executable_version": ""}
    assert RAW_MARKER not in json.dumps(failed)


def test_expectations_and_fixture_tampering_fail_before_analysis(tmp_path: Path) -> None:
    expectation_tamper = _copy_pack(tmp_path / "expectation")
    with (expectation_tamper / "expectations.json").open("ab") as handle:
        handle.write(b" ")
    adapter = _FakeAdapter()
    report = run_language_validation_pack(expectation_tamper, adapter)
    assert report["control_errors"] == ["expectations_hash_mismatch"]
    assert adapter.calls == []

    fixture_tamper = _copy_pack(tmp_path / "fixture")
    fixture = fixture_tamper / "fixtures" / "java" / "JavaSqlVulnerable.java"
    fixture.write_text(fixture.read_text(encoding="utf-8") + "// changed\n", encoding="utf-8")
    report = run_language_validation_pack(fixture_tamper, adapter)
    assert report["control_errors"] == ["fixture_hash_mismatch"]
    assert adapter.calls == []


def test_pack_json_file_path_is_accepted_but_other_files_and_missing_paths_are_rejected(tmp_path: Path) -> None:
    pack = _copy_pack(tmp_path)

    accepted = run_language_validation_pack(pack / "pack.json", _FakeAdapter())
    wrong_file = run_language_validation_pack(pack / "expectations.json", _FakeAdapter())
    missing = run_language_validation_pack(tmp_path / "missing", _FakeAdapter())
    empty = run_language_validation_pack("", _FakeAdapter())

    assert accepted["complete"] is True
    assert wrong_file["control_errors"] == ["pack_path_invalid"]
    assert missing["control_errors"] == ["pack_path_invalid"]
    assert empty["control_errors"] == ["pack_path_invalid"]


def test_installed_wheel_bytecode_does_not_change_fixture_inventory(tmp_path: Path) -> None:
    pack = _copy_pack(tmp_path)
    cache = pack / "fixtures" / "python" / "__pycache__"
    cache.mkdir()
    (cache / "python_sql_clean.cpython-311.pyc").write_bytes(b"compiled-fixture-bytecode")

    report = run_language_validation_pack(pack, _FakeAdapter())

    assert report["complete"] is True
    assert report["ready"] is True


@pytest.mark.parametrize(
    ("content", "expected_error"),
    [
        (b"", "pack_manifest_size_invalid"),
        (b" " * (64 * 1024 + 1), "pack_manifest_size_invalid"),
        (b'{"schema":', "pack_manifest_json_invalid"),
        (b'{"schema":"a","schema":"b"}', "pack_manifest_duplicate_json_key"),
        (b"[]", "pack_manifest_schema_invalid"),
        (b"\xff", "pack_manifest_json_invalid"),
    ],
    ids=("empty", "oversized", "json", "duplicate-key", "non-object", "utf8"),
)
def test_malformed_pack_manifest_fails_before_analysis(
    tmp_path: Path,
    content: bytes,
    expected_error: str,
) -> None:
    pack = _copy_pack(tmp_path)
    (pack / "pack.json").write_bytes(content)
    adapter = _FakeAdapter()

    report = run_language_validation_pack(pack, adapter)

    assert report["control_errors"] == [expected_error]
    assert adapter.calls == []


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ("extra-key", "pack_manifest_schema_invalid"),
        ("schema", "pack_manifest_schema_invalid"),
        ("pack-id", "pack_id_invalid"),
        ("languages", "pack_languages_invalid"),
        ("claim", "pack_claim_boundary_invalid"),
        ("fixture-root-escape", "fixture_root_invalid"),
        ("fixture-root-missing", "fixture_root_invalid"),
        ("expectations-shape", "expectations_reference_invalid"),
        ("expectations-path", "expectations_reference_invalid"),
        ("expectations-hash", "expectations_reference_invalid"),
        ("profile-shape", "profile_reference_invalid"),
        ("profile-name", "profile_reference_invalid"),
        ("profile-rule-count", "profile_reference_invalid"),
        ("profile-hash-format", "profile_reference_invalid"),
        ("profile-hash-mismatch", "profile_hash_mismatch"),
        ("analyzer-shape", "analyzer_reference_invalid"),
        ("analyzer-name", "analyzer_reference_invalid"),
        ("analyzer-version", "semgrep_version_reference_invalid"),
    ],
)
def test_manifest_contract_variants_fail_closed(
    tmp_path: Path,
    mutation: str,
    expected_error: str,
) -> None:
    pack = _copy_pack(tmp_path)
    manifest = json.loads((pack / "pack.json").read_text(encoding="utf-8"))
    if mutation == "extra-key":
        manifest["unexpected"] = True
    elif mutation == "schema":
        manifest["schema"] = "wrong"
    elif mutation == "pack-id":
        manifest["pack_id"] = "!"
    elif mutation == "languages":
        manifest["languages"] = ["go", "java", "kotlin"]
    elif mutation == "claim":
        manifest["raw_free"] = False
    elif mutation == "fixture-root-escape":
        manifest["fixture_root"] = "../fixtures"
    elif mutation == "fixture-root-missing":
        manifest["fixture_root"] = "missing"
    elif mutation == "expectations-shape":
        manifest["expectations"] = None
    elif mutation == "expectations-path":
        manifest["expectations"]["path"] = "other.json"
    elif mutation == "expectations-hash":
        manifest["expectations"]["sha256"] = "not-a-hash"
    elif mutation == "profile-shape":
        manifest["profile"] = None
    elif mutation == "profile-name":
        manifest["profile"]["name"] = "other.yml"
    elif mutation == "profile-rule-count":
        manifest["profile"]["rule_count"] = 39
    elif mutation == "profile-hash-format":
        manifest["profile"]["rules_sha256"] = "bad"
    elif mutation == "profile-hash-mismatch":
        manifest["profile"]["sha256"] = "0" * 64
    elif mutation == "analyzer-shape":
        manifest["analyzer"] = None
    elif mutation == "analyzer-name":
        manifest["analyzer"]["name"] = "other"
    else:
        manifest["analyzer"]["executable_version"] = "1.163.0"
    _write_manifest(pack, manifest)
    adapter = _FakeAdapter()

    report = run_language_validation_pack(pack, adapter)

    assert report["control_errors"] == [expected_error]
    assert adapter.calls == []


@pytest.mark.parametrize(
    ("content", "expected_error"),
    [
        (b"", "expectations_size_invalid"),
        (b" " * (1024 * 1024 + 1), "expectations_size_invalid"),
        (b'{"schema":', "expectations_json_invalid"),
        (b'{"schema":"a","schema":"b"}', "expectations_duplicate_json_key"),
        (b"[]", "expectations_schema_invalid"),
        (b"\xff", "expectations_json_invalid"),
    ],
    ids=("empty", "oversized", "json", "duplicate-key", "non-object", "utf8"),
)
def test_malformed_expectations_fail_before_analysis(
    tmp_path: Path,
    content: bytes,
    expected_error: str,
) -> None:
    pack = _copy_pack(tmp_path)
    _write_expectations_bytes_and_repin(pack, content)
    adapter = _FakeAdapter()

    report = run_language_validation_pack(pack, adapter)

    assert report["control_errors"] == [expected_error]
    assert adapter.calls == []


def test_missing_expectations_file_fails_closed(tmp_path: Path) -> None:
    pack = _copy_pack(tmp_path)
    (pack / "expectations.json").unlink()

    report = run_language_validation_pack(pack, _FakeAdapter())

    assert report["control_errors"] == ["expectations_path_invalid"]


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ("duplicate", "duplicate_case_id"),
        ("escape", "case_file_invalid"),
    ],
)
def test_unique_cases_and_path_containment_are_enforced(
    tmp_path: Path,
    mutation: str,
    expected_error: str,
) -> None:
    pack = _copy_pack(tmp_path)
    expectations = _expectations(pack)
    if mutation == "duplicate":
        expectations["cases"].append(dict(expectations["cases"][0]))
    else:
        expectations["cases"][0]["file"] = "../outside.java"
    _write_expectations_and_repin(pack, expectations)

    adapter = _FakeAdapter()
    report = run_language_validation_pack(pack, adapter)
    assert report["complete"] is False
    assert report["control_errors"] == [expected_error]
    assert adapter.calls == []
    assert str(pack.resolve()) not in json.dumps(report)


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ("expectations-extra-key", "expectations_schema_invalid"),
        ("expectations-schema", "expectations_schema_invalid"),
        ("expectations-pack", "expectations_schema_invalid"),
        ("expectations-mutable", "expectations_schema_invalid"),
        ("expectations-raw", "expectations_schema_invalid"),
        ("cases-not-list", "expectations_schema_invalid"),
        ("cases-empty", "expectations_cases_empty"),
        ("case-missing-key", "case_schema_invalid"),
        ("case-id", "case_id_invalid"),
        ("case-taxonomy", "case_taxonomy_invalid"),
        ("case-outcome", "case_expected_outcome_invalid"),
        ("case-rule-id", "case_rule_id_invalid"),
        ("case-rule-contract", "case_rule_contract_invalid"),
        ("case-file-language", "case_file_language_mismatch"),
        ("case-file-duplicate", "duplicate_case_file"),
        ("case-source-hash", "case_source_hash_invalid"),
    ],
)
def test_expectation_and_case_contract_variants_fail_closed(
    tmp_path: Path,
    mutation: str,
    expected_error: str,
) -> None:
    pack = _copy_pack(tmp_path)
    expectations = _expectations(pack)
    first = expectations["cases"][0]
    if mutation == "expectations-extra-key":
        expectations["unexpected"] = True
    elif mutation == "expectations-schema":
        expectations["schema"] = "wrong"
    elif mutation == "expectations-pack":
        expectations["pack_id"] = "other-pack"
    elif mutation == "expectations-mutable":
        expectations["immutable"] = False
    elif mutation == "expectations-raw":
        expectations["raw_free"] = False
    elif mutation == "cases-not-list":
        expectations["cases"] = {}
    elif mutation == "cases-empty":
        expectations["cases"] = []
    elif mutation == "case-missing-key":
        first.pop("category")
    elif mutation == "case-id":
        first["case_id"] = "!"
    elif mutation == "case-taxonomy":
        first["language"] = "rust"
    elif mutation == "case-outcome":
        first["expected"] = "unknown"
    elif mutation == "case-rule-id":
        first["rule_id"] = "!"
    elif mutation == "case-rule-contract":
        first["rule_id"] = "k-guard.java.http-to-sql"
        if first["category"] == "sql-injection":
            first["rule_id"] = "k-guard.java.http-to-command"
    elif mutation == "case-file-language":
        first["file"] = "wrong.kt"
    elif mutation == "case-file-duplicate":
        first["file"] = expectations["cases"][1]["file"]
        first["source_sha256"] = expectations["cases"][1]["source_sha256"]
    else:
        first["source_sha256"] = "bad"
    _write_expectations_and_repin(pack, expectations)
    adapter = _FakeAdapter()

    report = run_language_validation_pack(pack, adapter)

    assert report["control_errors"] == [expected_error]
    assert adapter.calls == []


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ("missing-language", "case_language_coverage_invalid"),
        ("missing-category", "case_category_coverage_invalid"),
        ("extra-fixture", "fixture_inventory_mismatch"),
        ("missing-fixture", "case_file_invalid"),
        ("empty-fixture", "fixture_size_invalid"),
    ],
)
def test_pack_coverage_and_fixture_inventory_fail_closed(
    tmp_path: Path,
    mutation: str,
    expected_error: str,
) -> None:
    pack = _copy_pack(tmp_path)
    expectations = _expectations(pack)
    if mutation == "missing-language":
        expectations["cases"] = [case for case in expectations["cases"] if case["language"] != "go"]
        _write_expectations_and_repin(pack, expectations)
    elif mutation == "missing-category":
        case = next(
            item
            for item in expectations["cases"]
            if item["language"] == "java" and item["category"] == "sql-injection" and item["expected"] == "clean"
        )
        case["category"] = "command-injection"
        case["rule_id"] = "k-guard.java.http-to-command"
        _write_expectations_and_repin(pack, expectations)
    elif mutation == "extra-fixture":
        (pack / "fixtures" / "java" / "Unregistered.java").write_text("class Unregistered {}\n", encoding="utf-8")
    else:
        case = expectations["cases"][0]
        fixture = pack / "fixtures" / case["file"]
        if mutation == "missing-fixture":
            fixture.unlink()
        else:
            fixture.write_bytes(b"")
    adapter = _FakeAdapter()

    report = run_language_validation_pack(pack, adapter)

    assert report["control_errors"] == [expected_error]
    assert adapter.calls == []


@pytest.mark.parametrize("language", language_validation.REQUIRED_LANGUAGES)
def test_each_of_nine_languages_is_mandatory(language: str, tmp_path: Path) -> None:
    pack = _copy_pack(tmp_path)
    expectations = _expectations(pack)
    expectations["cases"] = [case for case in expectations["cases"] if case["language"] != language]
    _write_expectations_and_repin(pack, expectations)

    adapter = _FakeAdapter()
    report = run_language_validation_pack(pack, adapter)

    assert report["complete"] is False
    assert report["ready"] is False
    assert report["control_errors"] == ["case_language_coverage_invalid"]
    assert adapter.calls == []


@pytest.mark.parametrize("profile_variant", ["missing", "too-few-rules", "missing-required-rules"])
def test_bundled_profile_integrity_failures_are_detected(
    tmp_path: Path,
    monkeypatch,
    profile_variant: str,
) -> None:
    profile = tmp_path / "semgrep-deep.yml"
    if profile_variant == "too-few-rules":
        profile.write_text("rules:\n  - id: only.one\n", encoding="utf-8")
    elif profile_variant == "missing-required-rules":
        profile.write_text(
            "rules:\n" + "".join(f"  - id: dummy.rule.{index}\n" for index in range(40)),
            encoding="utf-8",
        )
    monkeypatch.setattr(language_validation, "DEFAULT_SEMGREP_PROFILE", profile)

    report = run_language_validation_pack(PACK, _FakeAdapter())

    assert report["control_errors"] == ["bundled_profile_invalid"]


def test_zero_findings_exercises_zero_rate_boundaries_without_false_success() -> None:
    vulnerable_ids = {
        case["case_id"] for case in _expectations()["cases"] if case["expected"] == "vulnerable"
    }

    report = run_language_validation_pack(PACK, _FakeAdapter(missing=vulnerable_ids))

    assert report["metrics"]["overall"] == {
        "confusion_matrix": {"tp": 0, "fn": 45, "fp": 0, "tn": 45},
        "recall": 0.0,
        "specificity": 1.0,
        "precision": 0.0,
    }
    assert report["repeat"]["exact"] is True
    assert report["ready"] is False


def test_unmapped_findings_block_readiness_without_exposing_guidance() -> None:
    wrong_rule = _finding(
        file="java/JavaSqlVulnerable.java",
        rule_id="k-guard.java.http-to-command",
        seed="wrong-rule",
    )
    unknown_file = _finding(
        file="outside/Unknown.java",
        rule_id="k-guard.java.http-to-sql",
        seed="unknown-file",
    )
    extras = (wrong_rule, unknown_file)

    report = run_language_validation_pack(
        PACK,
        _FakeAdapter(extra_findings_by_call={0: extras, 1: extras}),
    )

    assert report["complete"] is True
    assert report["repeat"]["exact"] is True
    assert report["requirements"]["all_findings_mapped"] is False
    assert report["ready"] is False
    assert len(report["unmapped_findings"]) == 2
    assert RAW_MARKER not in json.dumps(report, sort_keys=True)


@pytest.mark.skipif(not os.getenv("K_GUARD_SEMGREP_EXECUTABLE"), reason="real Semgrep executable not configured")
def test_real_semgrep_164_pack_is_ready() -> None:
    adapter = SemgrepAnalyzerAdapter(executable=os.environ["K_GUARD_SEMGREP_EXECUTABLE"], timeout_seconds=180)
    report = run_language_validation_pack(PACK, adapter)

    assert report["complete"] is True
    assert report["ready"] is True
    assert report["metrics"]["overall"]["confusion_matrix"] == {"tp": 45, "fn": 0, "fp": 0, "tn": 45}
    assert report["repeat"]["exact"] is True
    assert [run["executable_version"] for run in report["analyzer_runs"]] == ["1.174.0", "1.174.0"]
    assert [run["target_coverage"]["eligible_target_count"] for run in report["analyzer_runs"]] == [90, 90]
    assert all(run["target_coverage"]["result"] == "exact" for run in report["analyzer_runs"])
