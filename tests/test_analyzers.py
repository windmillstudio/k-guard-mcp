from __future__ import annotations

import io
import json
import re
import subprocess
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

import k_guard_mcp.analyzers as analyzers
from k_guard_mcp import cli, server
from k_guard_mcp.analyzers import AnalyzerAdapter, AnalyzerFinding, AnalyzerRun, SemgrepAnalyzerAdapter
from k_guard_mcp.hashing import EVIDENCE_HMAC_ENV
from k_guard_mcp.provenance import verify_evidence_bundle


RAW_MATCH = "RAW_MATCHED_CODE_do_not_publish_7f84b2"


def test_common_analyzer_contract_is_not_semgrep_hardcoded() -> None:
    finding = AnalyzerFinding(
        rule_id="other.rule",
        severity="medium",
        confidence="medium",
        cwe=("CWE-20",),
        file="src/app.go",
        line_start=1,
        line_end=1,
        message="Normalized finding.",
        recommendation="Review the normalized finding.",
        analyzer_subtype="other-engine-intrafile",
        fingerprint="a" * 64,
    )
    run = AnalyzerRun(
        complete=True,
        control_errors=(),
        findings=(finding,),
        analyzer="other-engine",
        analyzer_subtype="other-engine-intrafile",
        executable_version="1.0.0",
        adapter_version="1.0.0",
        profile_name="other-profile",
        adapter_sha256="b" * 64,
        profile_sha256="c" * 64,
        rules_sha256="d" * 64,
        command_contract_sha256="e" * 64,
        input_snapshot={
            "schema": "k_guard_source_tree_snapshot.v1",
            "tree_sha256": "f" * 64,
            "complete": True,
            "raw_returned": False,
        },
    )

    assert run.complete is True
    assert run.findings[0].analyzer_subtype == "other-engine-intrafile"


def test_deep_analyze_cli_writes_report_and_uses_fail_closed_exit_codes(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install_fake_semgrep(monkeypatch, scan_stdout=json.dumps(_payload([_finding_row(workspace)])).encode("utf-8"))
    output = tmp_path / "deep-report.json"

    assert cli.main(["deep-analyze", str(workspace), "--output", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    summary = json.loads(capsys.readouterr().out)

    assert report["complete"] is True
    assert report["counts"]["finding_count"] == 1
    assert summary["complete"] is True
    assert summary["analyzer_subtype"] == "semgrep-ce-intrafile"

    monkeypatch.setattr(analyzers.shutil, "which", lambda executable: None)
    failed = tmp_path / "deep-failed.json"
    assert cli.main(["deep-analyze", str(workspace), "--output", str(failed)]) == 3
    assert json.loads(failed.read_text(encoding="utf-8"))["control_errors"] == ["semgrep_executable_missing"]


def test_mcp_deep_analyzer_tool_does_not_turn_missing_engine_into_a_pass(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("K_GUARD_SEMGREP_EXECUTABLE", "definitely-missing-semgrep")
    monkeypatch.setattr(analyzers.shutil, "which", lambda executable: None)

    report = server.deep_analyzer_audit(str(workspace))

    assert report["complete"] is False
    assert report["control_errors"] == ["semgrep_executable_missing"]
    assert report["experience"]["details"]["presentation"]["verdict"] != "SHIP"


class _FakeProcess:
    def __init__(
        self,
        stdout: bytes = b"",
        *,
        stderr: bytes = b"",
        returncode: int = 0,
        running: bool = False,
    ) -> None:
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode: int | None = None if running else returncode
        self._final_returncode = returncode

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            if timeout is not None:
                raise subprocess.TimeoutExpired("fake-semgrep", timeout)
            self.returncode = self._final_returncode
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    source = root / "src" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text(f"query = '{RAW_MATCH}'\n", encoding="utf-8")
    return root


def _finding_row(
    workspace: Path,
    *,
    path: str | None = None,
    line_start: int = 7,
    line_end: int = 8,
    summary: str = "Untrusted HTTP input reaches a SQL execution API.",
    recommendation: str = "Bind query values separately from SQL text.",
) -> dict[str, Any]:
    return {
        "check_id": "k-guard.python.http-to-sql",
        "path": path if path is not None else str(workspace / "src" / "app.py"),
        "start": {"line": line_start, "col": 3},
        "end": {"line": line_end, "col": 20},
        "extra": {
            "severity": "ERROR",
            "message": f"Rendered metavariable: {RAW_MATCH}",
            "lines": f"cursor.execute({RAW_MATCH})",
            "metavars": {
                "$VALUE": {
                    "abstract_content": RAW_MATCH,
                    "match": RAW_MATCH,
                }
            },
            "dataflow_trace": {"taint_source": {"content": RAW_MATCH}},
            "fingerprint": RAW_MATCH,
            "metadata": {
                "cwe": ["CWE-89: SQL Injection", "CWE_20"],
                "confidence": "HIGH",
                "k_guard_severity": "critical",
                "summary": summary,
                "recommendation": recommendation,
                "ignored_raw_field": RAW_MATCH,
            },
        },
    }


def _payload(
    results: list[dict[str, Any]] | None = None,
    *,
    errors: list[Any] | None = None,
    skipped: list[Any] | None = None,
    scanned: list[Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "version": "1.99.0",
        "results": results or [],
        "errors": errors or [],
        "paths": {
            "scanned": ["src/app.py"] if scanned is None else scanned,
            "skipped": skipped or [],
        },
    }
    payload.update(extra)
    return payload


def _install_fake_semgrep(
    monkeypatch: pytest.MonkeyPatch,
    *,
    scan_stdout: bytes,
    scan_stderr: bytes = b"",
    scan_returncode: int = 0,
    scan_running: bool = False,
    version_stdout: bytes = b"semgrep 1.99.0\n",
    version_returncode: int = 0,
) -> list[tuple[list[str], dict[str, Any]]]:
    calls: list[tuple[list[str], dict[str, Any]]] = []
    monkeypatch.setattr(analyzers.shutil, "which", lambda executable: "semgrep-local")

    def fake_popen(argv: list[str], **kwargs: Any) -> _FakeProcess:
        calls.append((list(argv), kwargs))
        if "--version" in argv:
            return _FakeProcess(version_stdout, returncode=version_returncode)
        staging = Path(kwargs["cwd"])
        assert (staging / ".semgrepignore").is_file()
        assert any(path.is_file() and path.name != ".semgrepignore" for path in staging.rglob("*"))
        return _FakeProcess(
            scan_stdout,
            stderr=scan_stderr,
            returncode=scan_returncode,
            running=scan_running,
        )

    monkeypatch.setattr(analyzers.subprocess, "Popen", fake_popen)
    return calls


def _run_payload(
    monkeypatch: pytest.MonkeyPatch,
    workspace: Path,
    payload: dict[str, Any],
    **adapter_options: Any,
):
    calls = _install_fake_semgrep(monkeypatch, scan_stdout=json.dumps(payload).encode("utf-8"))
    run = SemgrepAnalyzerAdapter(**adapter_options).analyze(workspace)
    return run, calls


def _assert_incomplete_without_raw(run: analyzers.AnalyzerRun, expected_error: str) -> None:
    assert run.complete is False
    assert expected_error in run.control_errors
    assert run.findings == ()
    assert run.raw_free is True
    assert RAW_MATCH not in json.dumps(run.to_dict(), sort_keys=True)


def test_success_normalizes_findings_enforces_offline_contract_and_signs_raw_free_report(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SEMGREP_APP_TOKEN", RAW_MATCH)
    monkeypatch.delenv(EVIDENCE_HMAC_ENV, raising=False)
    run, calls = _run_payload(monkeypatch, workspace, _payload([_finding_row(workspace)]))

    assert isinstance(SemgrepAnalyzerAdapter(), AnalyzerAdapter)
    assert run.complete is True
    assert run.control_errors == ()
    assert run.executable_version == "1.99.0"
    assert run.adapter_version == "1.2.0"
    assert run.profile_name == "semgrep-deep.yml"
    assert len(run.findings) == 1
    finding = run.findings[0]
    assert finding.rule_id == "k-guard.python.http-to-sql"
    assert finding.severity == "critical"
    assert finding.confidence == "high"
    assert finding.cwe == ("CWE-20", "CWE-89")
    assert finding.file == "src/app.py"
    assert (finding.line_start, finding.line_end) == (7, 8)
    assert finding.message == "Untrusted HTTP input reaches a SQL execution API."
    assert finding.recommendation == "Bind query values separately from SQL text."
    assert finding.analyzer_subtype == "semgrep-ce-intrafile"
    assert re.fullmatch(r"[0-9a-f]{64}", finding.fingerprint)
    assert set(finding.to_dict()) == {
        "rule_id",
        "severity",
        "confidence",
        "cwe",
        "file",
        "line_start",
        "line_end",
        "message",
        "recommendation",
        "analyzer_subtype",
        "fingerprint",
        "raw_free",
    }

    assert len(calls) == 2
    version_argv, version_kwargs = calls[0]
    scan_argv, scan_kwargs = calls[1]
    assert version_argv == ["semgrep-local", "--version"]
    assert scan_argv[-1] == "."
    assert str(workspace) not in scan_argv
    assert "--json" in scan_argv
    assert "--metrics=off" in scan_argv
    assert "--disable-version-check" in scan_argv
    assert "--no-git-ignore" in scan_argv
    assert "--oss-only" in scan_argv
    assert "--jobs=1" in scan_argv
    assert "--strict" in scan_argv
    assert scan_argv[scan_argv.index("--config") + 1] == str(analyzers.DEFAULT_SEMGREP_PROFILE.resolve())
    assert version_kwargs["shell"] is False and scan_kwargs["shell"] is False
    assert scan_kwargs["cwd"] != str(workspace.resolve())
    assert Path(scan_kwargs["cwd"]).name.startswith("k-guard-semgrep-")
    assert scan_kwargs["env"]["SEMGREP_SEND_METRICS"] == "off"
    assert scan_kwargs["env"]["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
    assert "SEMGREP_APP_TOKEN" not in scan_kwargs["env"]

    assert run.counts["result_count"] == 1
    assert run.counts["finding_count"] == 1
    assert run.counts["eligible_target_count"] == 1
    assert run.counts["scanned_target_count"] == 1
    assert run.target_coverage["result"] == "exact"
    assert run.target_coverage["eligible_path_set_sha256"] == run.target_coverage["scanned_path_set_sha256"]
    assert re.fullmatch(r"[0-9a-f]{64}", run.target_coverage["eligible_path_set_sha256"])
    assert run.input_snapshot["complete"] is True
    assert re.fullmatch(r"[0-9a-f]{64}", str(run.input_snapshot["tree_sha256"]))
    assert run.timings["total_ms"] >= 0
    assert all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in (
        run.adapter_sha256,
        run.profile_sha256,
        run.rules_sha256,
        run.command_contract_sha256,
    ))
    limitation = " ".join(run.limitations).casefold()
    assert "intrafile only" in limitation
    assert "does not establish interfile" in limitation

    report = run.to_report()
    rendered = json.dumps(report, sort_keys=True)
    assert report["raw_free"] is True
    assert RAW_MATCH not in rendered
    assert str(workspace) not in rendered
    assert report["evidence_bundle"]["signature"]["key_mode"] == "public-default-key"
    assert verify_evidence_bundle(report["evidence_bundle"])

    with pytest.raises(FrozenInstanceError):
        finding.severity = "low"  # type: ignore[misc]
    with pytest.raises(TypeError):
        run.counts["finding_count"] = 99  # type: ignore[index]


def test_tainted_metadata_guidance_is_replaced_not_returned(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = _finding_row(workspace, summary=RAW_MATCH, recommendation=RAW_MATCH)
    run, _ = _run_payload(monkeypatch, workspace, _payload([row]))

    assert run.complete is True
    finding = run.findings[0]
    assert finding.message == "Semgrep rule k-guard.python.http-to-sql matched a security-sensitive pattern."
    assert finding.recommendation == "Review the reported line and apply a context-appropriate secure implementation."
    assert RAW_MATCH not in json.dumps(run.to_dict())


def test_missing_executable_fails_closed_without_launch(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(analyzers.shutil, "which", lambda executable: None)
    monkeypatch.setattr(
        analyzers.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("Popen must not run when the executable is missing"),
    )

    run = SemgrepAnalyzerAdapter().run(workspace)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_EXECUTABLE_MISSING)


def test_executable_lookup_exception_fails_closed_without_launch(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_lookup(executable: str) -> str | None:
        raise OSError("synthetic executable lookup failure")

    monkeypatch.setattr(analyzers.shutil, "which", fail_lookup)
    monkeypatch.setattr(
        analyzers.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("Popen must not run after executable lookup failure"),
    )

    run = SemgrepAnalyzerAdapter().analyze(workspace)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_EXECUTABLE_MISSING)


def test_timeout_fails_closed(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_semgrep(monkeypatch, scan_stdout=b"", scan_running=True)

    run = SemgrepAnalyzerAdapter(timeout_seconds=0.01).analyze(workspace)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_TIMEOUT)


def test_nonzero_exit_fails_closed_and_drops_diagnostics(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_semgrep(
        monkeypatch,
        scan_stdout=b"",
        scan_stderr=f"fatal diagnostic {RAW_MATCH}".encode(),
        scan_returncode=2,
    )

    run = SemgrepAnalyzerAdapter().analyze(workspace)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_NONZERO_EXIT)


def test_nonzero_exit_keeps_specific_bounded_json_error_classification(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _payload(errors=[{"type": "ParseError", "message": f"parse error near {RAW_MATCH}"}])
    _install_fake_semgrep(
        monkeypatch,
        scan_stdout=json.dumps(payload).encode("utf-8"),
        scan_returncode=2,
    )

    run = SemgrepAnalyzerAdapter().analyze(workspace)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_NONZERO_EXIT)
    assert analyzers.CONTROL_ERRORS_ARRAY in run.control_errors
    assert analyzers.CONTROL_PARSE_ERRORS in run.control_errors
    assert run.counts["error_count"] == 1


@pytest.mark.parametrize(
    "malformed",
    [b'{"results":[', b"not-json", b"\xff\xfe"],
)
def test_malformed_or_truncated_json_fails_closed(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    malformed: bytes,
) -> None:
    _install_fake_semgrep(monkeypatch, scan_stdout=malformed)

    run = SemgrepAnalyzerAdapter().analyze(workspace)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_JSON_MALFORMED)


def test_nonempty_errors_array_fails_closed_without_raw_error_text(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _payload(
        [_finding_row(workspace)],
        errors=[{"type": "SemgrepError", "message": f"engine failed near {RAW_MATCH}"}],
    )

    run, _ = _run_payload(monkeypatch, workspace, payload)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_ERRORS_ARRAY)
    assert run.counts["error_count"] == 1


@pytest.mark.parametrize(
    ("payload", "expected_error"),
    [
        (
            _payload(skipped=[{"path": RAW_MATCH, "reason": "max_target_bytes"}]),
            analyzers.CONTROL_SKIPPED,
        ),
        (
            _payload(errors=[{"type": "Unsupported", "message": f"unsupported language {RAW_MATCH}"}]),
            analyzers.CONTROL_UNSUPPORTED,
        ),
        (
            _payload(errors=[{"type": "ParseError", "message": f"parse error near {RAW_MATCH}"}]),
            analyzers.CONTROL_PARSE_ERRORS,
        ),
    ],
    ids=["skipped", "unsupported", "parse-error"],
)
def test_skipped_unsupported_and_parse_families_fail_closed(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, Any],
    expected_error: str,
) -> None:
    run, _ = _run_payload(monkeypatch, workspace, payload)

    _assert_incomplete_without_raw(run, expected_error)


def test_result_count_limit_fails_closed_before_mapping(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = [
        _finding_row(workspace, line_start=1, line_end=1),
        _finding_row(workspace, line_start=2, line_end=2),
    ]

    run, _ = _run_payload(monkeypatch, workspace, _payload(results), max_results=1)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_RESULT_LIMIT)
    assert run.counts["result_count"] == 2


def test_output_limit_is_enforced_by_bounded_subprocess_reader(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_semgrep(monkeypatch, scan_stdout=b"x" * 4096)

    run = SemgrepAnalyzerAdapter(max_output_bytes=128).analyze(workspace)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_OUTPUT_LIMIT)
    assert run.counts["stdout_bytes"] == 4096


def test_result_path_escape_fails_closed_instead_of_returning_absolute_or_parent_path(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _payload([_finding_row(workspace, path="../outside.py")])

    run, _ = _run_payload(monkeypatch, workspace, payload)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_RESULT_SCHEMA)


def test_zero_effective_semgrep_coverage_fails_closed_with_raw_free_set_proof(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, _ = _run_payload(monkeypatch, workspace, _payload(scanned=[]))

    _assert_incomplete_without_raw(run, analyzers.CONTROL_TARGET_COVERAGE)
    assert run.counts["eligible_target_count"] == 1
    assert run.counts["scanned_target_count"] == 0
    assert run.target_coverage["result"] == "mismatch"
    assert run.target_coverage["eligible_path_set_sha256"] != run.target_coverage["scanned_path_set_sha256"]
    assert "src/app.py" not in json.dumps(run.to_dict(), sort_keys=True)


def test_semgrep_scanned_set_must_exactly_match_all_eligible_targets(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (workspace / "src" / "other.py").write_text("pass\n", encoding="utf-8")

    run, _ = _run_payload(monkeypatch, workspace, _payload(scanned=["src/app.py"]))

    _assert_incomplete_without_raw(run, analyzers.CONTROL_TARGET_COVERAGE)
    assert run.counts["eligible_target_count"] == 2
    assert run.counts["scanned_target_count"] == 1
    assert run.target_coverage["result"] == "mismatch"


@pytest.mark.parametrize(
    ("scanned", "expected_error"),
    [
        ([7], analyzers.CONTROL_SCANNED_TARGETS_INVALID),
        ([f"../{RAW_MATCH}.py"], analyzers.CONTROL_SCANNED_TARGET_ESCAPE),
        (["src/app.py", "./src/app.py"], analyzers.CONTROL_SCANNED_TARGET_DUPLICATE),
    ],
    ids=("malformed", "escape", "normalized-duplicate"),
)
def test_semgrep_scanned_paths_reject_malformed_escape_and_duplicate_entries(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    scanned: list[Any],
    expected_error: str,
) -> None:
    run, _ = _run_payload(monkeypatch, workspace, _payload(scanned=scanned))

    _assert_incomplete_without_raw(run, expected_error)
    assert run.target_coverage["result"] == "invalid"
    assert run.counts["scanned_target_count"] == len(scanned)


def test_workspace_with_no_eligible_targets_completes_without_launching_semgrep(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "README.txt").write_text("not a bundled language\n", encoding="utf-8")
    monkeypatch.setattr(
        analyzers.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("Semgrep must not launch without eligible targets"),
    )

    run = SemgrepAnalyzerAdapter().analyze(workspace)

    assert run.complete is True
    assert run.control_errors == ()
    assert run.findings == ()
    assert run.executable_version == ""
    assert run.target_coverage["result"] == "no_eligible_targets"
    assert run.counts["eligible_target_count"] == 0
    assert run.counts["scanned_target_count"] == 0
    assert run.target_coverage["eligible_path_set_sha256"] == run.target_coverage["scanned_path_set_sha256"]


def test_eligible_target_enumeration_rejects_symlinks_before_process_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "source.py"
    source.write_text("pass\n", encoding="utf-8")
    link = workspace / "linked.py"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("File symlinks are unavailable in this environment")
    monkeypatch.setattr(
        analyzers.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("Semgrep must not launch after a symlink is found"),
    )

    run = SemgrepAnalyzerAdapter().analyze(workspace)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_TARGET_SYMLINK)


def test_eligible_target_enumeration_is_count_bounded_before_process_launch(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (workspace / "src" / "other.py").write_text("pass\n", encoding="utf-8")
    monkeypatch.setattr(
        analyzers.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("Semgrep must not launch after discovery exceeds its bound"),
    )

    run = SemgrepAnalyzerAdapter(max_target_count=1).analyze(workspace)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_TARGET_ENUMERATION_LIMIT)


def test_workspace_and_profile_paths_are_validated_before_process_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace_file = tmp_path / "workspace.py"
    workspace_file.write_text("pass\n", encoding="utf-8")
    invalid_profile = tmp_path / "profile.txt"
    invalid_profile.write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr(
        analyzers.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("Popen must not run for invalid paths"),
    )

    bad_workspace = SemgrepAnalyzerAdapter().analyze(workspace_file)
    bad_profile = SemgrepAnalyzerAdapter(profile_path=invalid_profile).analyze(tmp_path)

    _assert_incomplete_without_raw(bad_workspace, "workspace_path_not_directory")
    _assert_incomplete_without_raw(bad_profile, "profile_path_extension_invalid")


def test_bundled_profile_has_cross_language_security_and_authorization_review_coverage() -> None:
    profile = analyzers.DEFAULT_SEMGREP_PROFILE
    text = profile.read_text(encoding="utf-8")
    rule_ids = re.findall(r"^\s*- id:\s*([^\s]+)", text, re.MULTILINE)

    assert len(rule_ids) == 40
    assert len(set(rule_ids)) == 40
    for language in ("javascript", "typescript", "python", "java", "kotlin", "go", "php", "ruby", "csharp"):
        assert language in text
    for category in ("sql-injection", "command-injection", "path-traversal", "ssrf", "authorization-review"):
        assert text.count(f"category: {category}") == 8
    assert text.count("ce_interfile: false") == 40
    assert "intrafile only" in analyzers.SEMGREP_CE_LIMITATION
    assert "does not establish interfile" in analyzers.SEMGREP_CE_LIMITATION
    contract, errors = analyzers._validated_profile(profile, 2 * 1024 * 1024)
    assert errors == ()
    assert contract is not None
    assert re.fullmatch(r"[0-9a-f]{64}", contract.profile_sha256)
    assert re.fullmatch(r"[0-9a-f]{64}", contract.rules_sha256)


@pytest.mark.parametrize(
    "name",
    [
        "app.cjs",
        "App.cs",
        "app.go",
        "App.java",
        "app.js",
        "app.jsx",
        "App.kt",
        "script.kts",
        "module.ktm",
        "app.mjs",
        "index.php",
        "app.py",
        "types.pyi",
        "worker.rb",
        "app.ts",
        "app.tsx",
    ],
)
def test_bundled_profile_target_suffix_contract_accepts_semgrep_164_extensions(name: str) -> None:
    assert analyzers._has_eligible_target_suffix(name) is True


@pytest.mark.parametrize("name", ["types.d.ts", "bundle.min.js", "app.PY"])
def test_bundled_profile_target_suffix_contract_rejects_semgrep_164_non_targets(name: str) -> None:
    assert analyzers._has_eligible_target_suffix(name) is False


@pytest.mark.parametrize("name", ["app.cts", "app.mts", "component.vue", "component.svelte"])
def test_bundled_profile_target_suffix_contract_accepts_modern_js_ts_targets(name: str) -> None:
    assert analyzers._has_eligible_target_suffix(name) is True


def test_extensionless_bundled_language_shebang_is_an_independently_eligible_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    script = workspace / "tool"
    script.write_text("#!/usr/bin/env python3\nprint('ok')\n", encoding="utf-8")
    script.chmod(0o755)
    _install_fake_semgrep(monkeypatch, scan_stdout=json.dumps(_payload(scanned=["tool"])).encode("utf-8"))

    run = SemgrepAnalyzerAdapter().analyze(workspace)

    assert run.complete is True
    assert run.target_coverage["result"] == "exact"
    assert run.counts["eligible_target_count"] == 1


def test_extensionless_shebang_detection_is_bounded_before_process_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    script = workspace / "tool"
    script.write_bytes(b"#!" + b" " * (analyzers._MAX_TARGET_SHEBANG_BYTES + 1))
    script.chmod(0o755)
    monkeypatch.setattr(
        analyzers.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("Semgrep must not launch after the shebang bound is exceeded"),
    )

    run = SemgrepAnalyzerAdapter().analyze(workspace)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_TARGET_ENUMERATION_LIMIT)


def _valid_finding_kwargs() -> dict[str, Any]:
    return {
        "rule_id": "k-guard.test.rule",
        "severity": "high",
        "confidence": "medium",
        "cwe": ("CWE-20",),
        "file": "src/app.py",
        "line_start": 1,
        "line_end": 2,
        "message": "Review this finding.",
        "recommendation": "Apply a safe implementation.",
        "analyzer_subtype": analyzers.ANALYZER_SUBTYPE,
        "fingerprint": "a" * 64,
        "raw_free": True,
    }


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("rule_id", "bad rule id"),
        ("severity", "urgent"),
        ("confidence", "certain"),
        ("cwe", ("CWE-invalid",)),
        ("file", "../outside.py"),
        ("line_start", 0),
        ("line_end", 0),
        ("message", " "),
        ("recommendation", ""),
        ("analyzer_subtype", "Bad subtype"),
        ("fingerprint", "not-a-digest"),
        ("raw_free", False),
    ],
)
def test_analyzer_finding_rejects_every_non_normalized_contract_field(
    field_name: str,
    invalid_value: Any,
) -> None:
    values = _valid_finding_kwargs()
    values[field_name] = invalid_value

    with pytest.raises(ValueError):
        AnalyzerFinding(**values)


def _valid_run_kwargs() -> dict[str, Any]:
    return {
        "complete": True,
        "control_errors": (),
        "findings": (),
        "analyzer": "semgrep",
        "analyzer_subtype": analyzers.ANALYZER_SUBTYPE,
        "executable_version": "1.99.0",
        "adapter_version": "1.0.0",
        "profile_name": "semgrep-deep.yml",
        "adapter_sha256": "a" * 64,
        "profile_sha256": "b" * 64,
        "rules_sha256": "c" * 64,
        "command_contract_sha256": "d" * 64,
        "input_snapshot": {
            "schema": "k_guard_source_tree_snapshot.v1",
            "tree_sha256": "e" * 64,
            "complete": True,
            "raw_returned": False,
        },
        "timings": {"total_ms": 1.0},
        "counts": {
            "finding_count": 0,
            "eligible_target_count": 1,
            "scanned_target_count": 1,
        },
        "target_coverage": analyzers._target_coverage(
            result="exact",
            eligible_count=1,
            scanned_count=1,
            eligible_path_set_sha256=analyzers._path_set_sha256(("src/app.py",)),
            scanned_path_set_sha256=analyzers._path_set_sha256(("src/app.py",)),
        ),
        "raw_free": True,
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {"control_errors": ("unexpected_error",)},
        {"complete": False, "control_errors": ()},
        {"analyzer": "Bad analyzer"},
        {"analyzer_subtype": "Bad subtype"},
        {"adapter_sha256": "bad-hash"},
        {"timings": {"total_ms": -0.1}},
        {"counts": {"finding_count": -1}},
        {"target_coverage": {}},
        {
            "counts": {
                "finding_count": 0,
                "eligible_target_count": 1,
                "scanned_target_count": 0,
            }
        },
        {"raw_free": False},
        {"input_snapshot": {"schema": "wrong", "complete": True, "tree_sha256": "e" * 64}},
        {
            "input_snapshot": {
                "schema": "k_guard_source_tree_snapshot.v1",
                "complete": False,
                "tree_sha256": "e" * 64,
            }
        },
        {
            "input_snapshot": {
                "schema": "k_guard_source_tree_snapshot.v1",
                "complete": True,
                "tree_sha256": "not-a-digest",
            }
        },
    ],
)
def test_analyzer_run_rejects_inconsistent_or_unattested_state(overrides: dict[str, Any]) -> None:
    values = _valid_run_kwargs()
    values.update(overrides)

    with pytest.raises(ValueError):
        AnalyzerRun(**values)


def test_abstract_adapter_contract_and_semgrep_subtype_are_explicit(workspace: Path) -> None:
    assert AnalyzerAdapter.analyzer_subtype.fget is not None
    with pytest.raises(NotImplementedError):
        AnalyzerAdapter.analyzer_subtype.fget(object())
    with pytest.raises(NotImplementedError):
        AnalyzerAdapter.analyze(object(), workspace)
    assert SemgrepAnalyzerAdapter().analyzer_subtype == analyzers.ANALYZER_SUBTYPE


def test_workspace_validation_rejects_blank_missing_and_resolution_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert analyzers._validated_workspace("")[1] == ("workspace_path_invalid",)
    assert analyzers._validated_workspace("bad\x00path")[1] == ("workspace_path_invalid",)
    assert analyzers._validated_workspace(tmp_path / "missing")[1] == ("workspace_path_not_found",)

    def fail_resolve(self: Path, strict: bool = False) -> Path:
        raise OSError("synthetic resolution failure")

    monkeypatch.setattr(Path, "resolve", fail_resolve)
    assert analyzers._validated_workspace(tmp_path)[1] == ("workspace_path_invalid",)


def test_profile_validation_rejects_path_shape_size_encoding_and_rule_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert analyzers._validated_profile(Path("bad\x00profile.yml"), 1024)[1] == ("profile_path_invalid",)
    assert analyzers._validated_profile(tmp_path / "missing.yml", 1024)[1] == ("profile_path_not_found",)

    directory = tmp_path / "directory.yml"
    directory.mkdir()
    assert analyzers._validated_profile(directory, 1024)[1] == ("profile_path_not_file",)

    empty = tmp_path / "empty.yml"
    empty.write_bytes(b"")
    assert analyzers._validated_profile(empty, 1024)[1] == ("profile_empty",)

    oversized = tmp_path / "oversized.yml"
    oversized.write_text("rules:\n  - id: valid.rule\n", encoding="utf-8")
    assert analyzers._validated_profile(oversized, 1)[1] == ("profile_size_limit_exceeded",)

    invalid_encoding = tmp_path / "encoding.yml"
    invalid_encoding.write_bytes(b"\xff\xfe")
    assert analyzers._validated_profile(invalid_encoding, 1024)[1] == ("profile_encoding_invalid",)

    no_rules = tmp_path / "no-rules.yml"
    no_rules.write_text("metadata: {}\n", encoding="utf-8")
    assert analyzers._validated_profile(no_rules, 1024)[1] == ("profile_rules_invalid",)

    duplicate_rules = tmp_path / "duplicate.yml"
    duplicate_rules.write_text("rules:\n  - id: same.rule\n  - id: same.rule\n", encoding="utf-8")
    assert analyzers._validated_profile(duplicate_rules, 1024)[1] == ("profile_rules_invalid",)

    valid = tmp_path / "valid.yml"
    valid.write_text("rules:\n  - id: valid.rule\n", encoding="utf-8")
    original_read_bytes = Path.read_bytes

    def fail_read_bytes(self: Path) -> bytes:
        if self == valid:
            raise OSError("synthetic read failure")
        return original_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", fail_read_bytes)
    assert analyzers._validated_profile(valid, 1024)[1] == ("profile_path_invalid",)


def test_profile_validation_rejects_symlink_without_reading_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile.yml"
    profile.write_text("rules:\n  - id: valid.rule\n", encoding="utf-8")
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == profile or original_is_symlink(self))

    contract, errors = analyzers._validated_profile(profile, 1024)

    assert contract is None
    assert errors == ("profile_path_symlink_disallowed",)


@pytest.mark.parametrize(
    ("launch_error", "expected_error"),
    [
        (FileNotFoundError("synthetic missing executable"), analyzers.CONTROL_EXECUTABLE_MISSING),
        (PermissionError("synthetic launch denial"), analyzers.CONTROL_EXECUTABLE_LAUNCH_FAILED),
    ],
)
def test_version_process_launch_failures_are_fail_closed(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    launch_error: OSError,
    expected_error: str,
) -> None:
    monkeypatch.setattr(analyzers.shutil, "which", lambda executable: "semgrep-local")

    def fail_popen(*args: Any, **kwargs: Any) -> _FakeProcess:
        raise launch_error

    monkeypatch.setattr(analyzers.subprocess, "Popen", fail_popen)

    run = SemgrepAnalyzerAdapter().analyze(workspace)

    _assert_incomplete_without_raw(run, expected_error)
    assert analyzers.CONTROL_VERSION_UNAVAILABLE in run.control_errors


@pytest.mark.parametrize("version_stdout", [b"semgrep unknown\n", b"\xff\xfe"])
def test_unparseable_or_non_utf8_version_is_fail_closed(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    version_stdout: bytes,
) -> None:
    _install_fake_semgrep(monkeypatch, scan_stdout=b"{}", version_stdout=version_stdout)

    run = SemgrepAnalyzerAdapter().analyze(workspace)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_VERSION_UNAVAILABLE)


def test_initial_incomplete_source_snapshot_prevents_process_launch(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        analyzers,
        "source_tree_snapshot",
        lambda root: {"schema": "k_guard_source_tree_snapshot.v1", "complete": False, "raw_returned": False},
    )
    monkeypatch.setattr(
        analyzers.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("Popen must not run after an incomplete source snapshot"),
    )

    run = SemgrepAnalyzerAdapter().analyze(workspace)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_WORKSPACE_SNAPSHOT)


@pytest.mark.parametrize(
    "final_snapshot",
    [
        {"schema": "k_guard_source_tree_snapshot.v1", "complete": False, "tree_sha256": "a" * 64},
        {"schema": "k_guard_source_tree_snapshot.v1", "complete": True, "tree_sha256": "b" * 64},
    ],
    ids=["final-snapshot-incomplete", "tree-hash-changed"],
)
def test_workspace_snapshot_drift_discards_otherwise_valid_findings(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    final_snapshot: dict[str, Any],
) -> None:
    snapshots = iter(
        [
            {"schema": "k_guard_source_tree_snapshot.v1", "complete": True, "tree_sha256": "a" * 64},
            final_snapshot,
        ]
    )
    monkeypatch.setattr(analyzers, "source_tree_snapshot", lambda root: next(snapshots))
    _install_fake_semgrep(monkeypatch, scan_stdout=json.dumps(_payload([_finding_row(workspace)])).encode("utf-8"))

    run = SemgrepAnalyzerAdapter().analyze(workspace)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_WORKSPACE_CHANGED)
    assert run.counts["finding_count"] == 1


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"results": [], "errors": {}},
        {"results": [], "errors": [], "paths": []},
        {"results": [], "errors": [], "paths": {"skipped": "not-a-list"}},
        {"results": [], "errors": [], "skipped": "not-a-list"},
        {"results": [], "errors": [], "skipped_rules": {}},
    ],
)
def test_payload_schema_variants_fail_closed_before_result_mapping(payload: Any) -> None:
    errors, rows, counts = analyzers._inspect_payload(payload)

    assert errors == (analyzers.CONTROL_JSON_SCHEMA,)
    assert rows == []
    assert counts["finding_count"] == 0


def test_payload_accepts_explicit_none_skip_list_but_rejects_truthy_unsupported_markers() -> None:
    errors, rows, counts = analyzers._inspect_payload(
        {"results": [], "errors": [], "paths": {"skipped": []}, "skipped": None}
    )
    assert errors == ()
    assert rows == []
    assert counts["skipped_count"] == 0

    for key in ("unsupported", "unsupported_languages", "unsupported_rules"):
        errors, _, _ = analyzers._inspect_payload({"results": [], "errors": [], key: ["synthetic"]})
        assert analyzers.CONTROL_UNSUPPORTED in errors


@pytest.mark.parametrize(
    "case",
    [
        "row-not-object",
        "invalid-rule-id",
        "reversed-line-range",
        "extra-not-object",
        "metadata-not-object",
        "empty-path",
        "workspace-root-path",
        "location-not-object",
        "line-is-bool",
    ],
)
def test_invalid_result_shapes_are_all_converted_to_fail_closed_control_errors(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    row: Any = _finding_row(workspace)
    if case == "row-not-object":
        row = None
    elif case == "invalid-rule-id":
        row["check_id"] = "bad rule id"
    elif case == "reversed-line-range":
        row["end"] = {"line": 1}
    elif case == "extra-not-object":
        row["extra"] = []
    elif case == "metadata-not-object":
        row["extra"]["metadata"] = []
    elif case == "empty-path":
        row["path"] = ""
    elif case == "workspace-root-path":
        row["path"] = str(workspace)
    elif case == "location-not-object":
        row["start"] = []
    elif case == "line-is-bool":
        row["start"] = {"line": True}

    payload = _payload()
    payload["results"] = [row]
    run, _ = _run_payload(monkeypatch, workspace, payload)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_RESULT_SCHEMA)


def test_finding_normalization_uses_bounded_defaults_for_untrusted_metadata(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = _finding_row(workspace)
    metadata = row["extra"]["metadata"]
    metadata.pop("k_guard_severity")
    metadata["severity"] = "WARNING"
    metadata["confidence"] = "certain"
    metadata["cwe"] = "CWE 7"
    metadata["summary"] = None
    metadata["recommendation"] = None

    fallback_row = _finding_row(workspace, line_start=20, line_end=20)
    fallback_metadata = fallback_row["extra"]["metadata"]
    fallback_metadata.pop("k_guard_severity")
    fallback_metadata.pop("severity", None)
    fallback_row["extra"]["severity"] = "INFO"
    fallback_metadata["cwe"] = [None, "CWE_00020"]

    run, _ = _run_payload(monkeypatch, workspace, _payload([row, fallback_row]))

    assert run.complete is True
    by_line = {finding.line_start: finding for finding in run.findings}
    assert by_line[7].severity == "medium"
    assert by_line[7].confidence == "medium"
    assert by_line[7].cwe == ("CWE-7",)
    assert by_line[7].message.startswith("Semgrep rule")
    assert by_line[7].recommendation.startswith("Review the reported line")
    assert by_line[20].severity == "low"
    assert by_line[20].cwe == ("CWE-20",)
    assert analyzers._normalized_cwe(None) == ()


def test_diagnostic_string_collection_is_depth_and_cardinality_bounded() -> None:
    output: set[str] = set()
    analyzers._collect_strings("", output, depth=0)
    analyzers._collect_strings([RAW_MATCH, 7], output, depth=0)
    analyzers._collect_strings({"nested": {"deeper": RAW_MATCH}}, output, depth=7)
    assert output == {RAW_MATCH}

    full = {f"item-{index}" for index in range(256)}
    analyzers._collect_strings("must-not-be-added", full, depth=0)
    assert len(full) == 256


@pytest.mark.parametrize("value", ["", "../outside.py", "C:/absolute.py", "bad\nname.py"])
def test_safe_relative_file_rejects_ambiguous_or_escaping_values(value: str) -> None:
    assert analyzers._is_safe_relative_file(value) is False


def test_adapter_hash_falls_back_to_versioned_contract_when_source_is_unreadable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable = tmp_path / "unreadable.py"
    monkeypatch.setattr(Path, "read_bytes", lambda self: (_ for _ in ()).throw(OSError("synthetic")))

    digest = analyzers._sha256_file_or_contract(unreadable)

    assert digest == analyzers.hashlib.sha256(
        f"k_guard_mcp.analyzers:{analyzers.ADAPTER_VERSION}".encode("ascii")
    ).hexdigest()


@pytest.mark.parametrize("value", [True, "1", 0, -1])
def test_positive_number_rejects_boolean_non_numeric_and_non_positive_values(value: Any) -> None:
    with pytest.raises(ValueError):
        analyzers._positive_number(value, "limit")


@pytest.mark.parametrize("value", [True, 1.5, "1", 0, -1])
def test_positive_integer_rejects_boolean_non_integer_and_non_positive_values(value: Any) -> None:
    with pytest.raises(ValueError):
        analyzers._positive_int(value, "limit")


class _ReadFailureStream(io.BytesIO):
    def read(self, size: int = -1) -> bytes:
        raise OSError("synthetic reader failure")


def test_reader_os_error_is_reported_as_output_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess()
    process.stdout = _ReadFailureStream()
    monkeypatch.setattr(analyzers.subprocess, "Popen", lambda *args, **kwargs: process)

    result = analyzers._run_process_bounded(
        ["fake"], cwd=tmp_path, env={}, timeout_seconds=1.0, max_output_bytes=1024
    )

    assert result.output_limited is True
    assert analyzers._process_errors(result, version_stage=False) == (analyzers.CONTROL_OUTPUT_LIMIT,)


def test_output_limit_terminates_a_still_running_process(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_semgrep(monkeypatch, scan_stdout=b"x" * 4096, scan_running=True)

    run = SemgrepAnalyzerAdapter(max_output_bytes=128).analyze(workspace)

    _assert_incomplete_without_raw(run, analyzers.CONTROL_OUTPUT_LIMIT)


class _WaitRequiresKill(_FakeProcess):
    def __init__(self) -> None:
        super().__init__()
        self.killed = False

    def wait(self, timeout: float | None = None) -> int:
        if timeout is not None and not self.killed:
            raise subprocess.TimeoutExpired("fake", timeout)
        return int(self.returncode or 0)

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


def test_process_wait_timeout_escalates_to_kill(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _WaitRequiresKill()
    monkeypatch.setattr(analyzers.subprocess, "Popen", lambda *args, **kwargs: process)

    result = analyzers._run_process_bounded(
        ["fake"], cwd=tmp_path, env={}, timeout_seconds=1.0, max_output_bytes=1024
    )

    assert process.killed is True
    assert result.returncode == -9


class _SyntheticThread:
    alive = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def start(self) -> None:
        pass

    def join(self, timeout: float | None = None) -> None:
        pass

    def is_alive(self) -> bool:
        return self.alive


def test_missing_pipe_objects_are_closed_conditionally(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess()
    process.stdout = None
    process.stderr = None
    monkeypatch.setattr(analyzers.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(analyzers.threading, "Thread", _SyntheticThread)

    result = analyzers._run_process_bounded(
        ["fake"], cwd=tmp_path, env={}, timeout_seconds=1.0, max_output_bytes=1024
    )

    assert result.output_limited is False


def test_incomplete_reader_threads_force_fail_closed_output_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess()

    class StuckThread(_SyntheticThread):
        alive = True

    monkeypatch.setattr(analyzers.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(analyzers.threading, "Thread", StuckThread)

    result = analyzers._run_process_bounded(
        ["fake"], cwd=tmp_path, env={}, timeout_seconds=1.0, max_output_bytes=1024
    )

    assert result.output_limited is True


@pytest.mark.parametrize("kill_raises", [False, True])
def test_terminate_process_falls_back_to_kill_and_tolerates_kill_failure(kill_raises: bool) -> None:
    class TerminationFailure:
        def __init__(self) -> None:
            self.kill_called = False

        def terminate(self) -> None:
            raise OSError("synthetic terminate failure")

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def kill(self) -> None:
            self.kill_called = True
            if kill_raises:
                raise OSError("synthetic kill failure")

    process = TerminationFailure()

    analyzers._terminate_process(process)  # type: ignore[arg-type]

    assert process.kill_called is True
