from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

import k_guard_mcp.sca as sca
from k_guard_mcp.provenance import verify_evidence_bundle
from k_guard_mcp.sca import (
    CONTROL_MANIFEST_LIMIT,
    CONTROL_MANIFEST_OVERSIZED,
    CONTROL_MANIFEST_SYMLINK,
    CONTROL_MANIFEST_UNREADABLE,
    CONTROL_SNAPSHOT_DRIFT,
    ProcessResult,
    SoftwareCompositionAnalyzer,
)


RAW_PACKAGE = "internal-secret-package-7f42"
RAW_VERSION = "91.82.73-private"


class ScriptedRunner:
    def __init__(
        self,
        audits: Mapping[str, ProcessResult | Sequence[ProcessResult]],
        *,
        versions: Mapping[str, ProcessResult] | None = None,
        on_audit: Callable[[str], None] | None = None,
    ) -> None:
        self.audits = {
            engine: list(value) if isinstance(value, (list, tuple)) else [value]
            for engine, value in audits.items()
        }
        self.versions = dict(
            versions
            or {
                "pip-audit": ProcessResult(0, b"pip-audit 2.9.0\n"),
                "npm": ProcessResult(0, b"10.8.2\n"),
                "govulncheck": ProcessResult(0, b"govulncheck@v1.1.4\n"),
            }
        )
        self.on_audit = on_audit
        self.calls: list[dict[str, Any]] = []
        self.normalized_python_inputs: list[str] = []

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: float,
        max_output_bytes: int,
        shell: bool,
    ) -> ProcessResult:
        call = {
            "argv": list(argv),
            "cwd": cwd,
            "env": env,
            "timeout_seconds": timeout_seconds,
            "max_output_bytes": max_output_bytes,
            "shell": shell,
        }
        self.calls.append(call)
        assert shell is False
        engine = Path(argv[0]).name
        if list(argv[1:]) in (["--version"], ["-version"]):
            return self.versions[engine]
        if engine == "pip-audit" and "-r" in argv:
            requirement_path = Path(argv[argv.index("-r") + 1])
            if requirement_path.is_absolute():
                self.normalized_python_inputs.append(requirement_path.read_text(encoding="utf-8"))
        if self.on_audit is not None:
            self.on_audit(engine)
        responses = self.audits.get(engine)
        if not responses:
            raise AssertionError(f"unexpected audit invocation: {argv!r}")
        return responses.pop(0)


def _python_workspace(root: Path, content: str = "demo-package==1.2.3\n") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "requirements.txt").write_text(content, encoding="utf-8")
    return root


def _python_payload(*vulnerabilities: dict[str, Any]) -> bytes:
    return json.dumps(
        {
            "dependencies": [
                {
                    "name": RAW_PACKAGE,
                    "version": RAW_VERSION,
                    "vulns": list(vulnerabilities),
                }
            ]
        }
    ).encode("utf-8")


def _clean_python_payload() -> bytes:
    return json.dumps(
        {"dependencies": [{"name": "demo-package", "version": "1.2.3", "vulns": []}]}
    ).encode("utf-8")


def _npm_workspace(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": "fixture", "dependencies": {RAW_PACKAGE: RAW_VERSION}}),
        encoding="utf-8",
    )
    (root / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "fixture", "version": "1.0.0"},
                    f"node_modules/{RAW_PACKAGE}": {
                        "name": RAW_PACKAGE,
                        "version": RAW_VERSION,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    return root


def _clean_npm_payload() -> bytes:
    return json.dumps({"auditReportVersion": 2, "vulnerabilities": {}}).encode("utf-8")


def _pep621_workspace(root: Path, lock_lines: list[str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text(
        "[project]\n"
        "name = 'pep621-fixture'\n"
        "version = '1.0.0'\n"
        "dependencies = [\n"
        "  'Core_Pkg>=1',\n"
        "  'direct-url @ https://example.invalid/direct.whl',\n"
        "]\n"
        "[project.optional-dependencies]\n"
        "dev = [\"Optional.Pkg[security]>=2; python_version >= '3.11'\"]\n",
        encoding="utf-8",
    )
    (root / "requirements.lock").write_text("".join(f"{line}\n" for line in lock_lines), encoding="utf-8")
    return root


def test_clean_python_audit_uses_common_bounded_no_shell_contract(tmp_path: Path) -> None:
    workspace = _python_workspace(tmp_path / "workspace")
    runner = ScriptedRunner({"pip-audit": ProcessResult(0, _clean_python_payload())})

    run = SoftwareCompositionAnalyzer(process_runner=runner).run(workspace)

    assert run.complete is True
    assert run.passed is True
    assert run.control_errors == ()
    assert run.requested_ecosystems == ("python",)
    assert run.audited_ecosystems == ("python",)
    assert run.findings == ()
    assert run.inventory["manifest_count"] == 1
    assert run.inventory["lock_count"] == 1
    assert run.inventory["uncovered_manifest_count"] == 0
    assert run.input_snapshot["complete"] is True
    assert run.input_snapshot["file_count"] == 1

    adapter = run.adapters[0]
    assert adapter.complete is True
    assert adapter.engine_name == "pip-audit"
    assert adapter.engine_version == "2.9.0"
    assert adapter.counts["invocation_count"] == 2
    assert adapter.counts["stdout_bytes"] == len(_clean_python_payload())
    assert adapter.counts["stderr_bytes"] == 0
    assert adapter.counts["result_count"] == 0
    assert adapter.command_contract["shell"] is False
    assert adapter.command_contract["success_requires_valid_complete_json"] is True

    assert runner.calls[1]["argv"] == [
        "pip-audit",
        "--format=json",
        "--progress-spinner=off",
        "--strict",
        "-r",
        "requirements.txt",
    ]
    assert runner.calls[1]["cwd"] == workspace.resolve()
    assert all(call["shell"] is False for call in runner.calls)

    report = run.to_report()
    assert report["complete"] is True
    assert report["raw_free"] is True
    assert verify_evidence_bundle(report["evidence_bundle"])


def test_python_vulnerability_exit_is_complete_and_raw_free(tmp_path: Path) -> None:
    workspace = _python_workspace(tmp_path / "workspace")
    vulnerable = _python_payload(
        {
            "id": "CVE-2026-12345",
            "severity": "HIGH",
            "fix_versions": ["100.0.0"],
        }
    )
    runner = ScriptedRunner({"pip-audit": ProcessResult(1, vulnerable)})

    run = SoftwareCompositionAnalyzer(process_runner=runner).run(workspace)
    report = run.to_report()
    rendered = json.dumps(report, sort_keys=True)

    assert run.complete is True
    assert run.passed is False
    assert len(run.findings) == 1
    finding = run.findings[0]
    assert finding.vulnerability_id == "CVE-2026-12345"
    assert finding.severity == "high"
    assert finding.fixed_version_present is True
    assert finding.package_ref not in {RAW_PACKAGE, RAW_VERSION}
    assert finding.installed_version_ref not in {RAW_PACKAGE, RAW_VERSION}
    assert RAW_PACKAGE not in rendered
    assert RAW_VERSION not in rendered
    assert "100.0.0" not in rendered
    assert "package_ref" in report["findings"][0]
    assert "installed_version_ref" in report["findings"][0]
    assert report["findings"][0]["raw_free"] is True


def test_npm_vulnerability_uses_package_lock_version_without_returning_it(tmp_path: Path) -> None:
    workspace = _npm_workspace(tmp_path / "workspace")
    audit = json.dumps(
        {
            "auditReportVersion": 2,
            "vulnerabilities": {
                RAW_PACKAGE: {
                    "name": RAW_PACKAGE,
                    "severity": "critical",
                    "via": [
                        {
                            "source": 98765,
                            "severity": "high",
                            "url": "https://github.com/advisories/GHSA-2345-6789-CFGH",
                        }
                    ],
                    "nodes": [f"node_modules/{RAW_PACKAGE}"],
                    "fixAvailable": {"name": RAW_PACKAGE, "version": "100.0.0"},
                }
            },
        }
    ).encode("utf-8")
    runner = ScriptedRunner({"npm": ProcessResult(1, audit)})

    report = SoftwareCompositionAnalyzer(process_runner=runner).run(workspace).to_report()
    rendered = json.dumps(report, sort_keys=True)

    assert report["complete"] is True
    assert report["passed"] is False
    assert report["findings"][0]["vulnerability_id"] == "GHSA-2345-6789-CFGH"
    assert report["findings"][0]["fixed_version_present"] is True
    assert runner.calls[1]["argv"] == ["npm", "audit", "--json", "--package-lock-only"]
    assert RAW_PACKAGE not in rendered
    assert RAW_VERSION not in rendered
    assert "100.0.0" not in rendered


def test_go_manifest_reports_missing_govulncheck_as_control_error(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "go.mod").write_text("module example.test/service\n\ngo 1.24\n", encoding="utf-8")
    (workspace / "go.sum").write_text("example.test/dependency v1.0.0 h1:abc\n", encoding="utf-8")
    runner = ScriptedRunner(
        {},
        versions={"govulncheck": ProcessResult(-1, launch_error="missing")},
    )

    run = SoftwareCompositionAnalyzer(process_runner=runner).run(workspace)

    assert run.complete is False
    assert run.passed is False
    assert "go_engine_missing" in run.control_errors
    assert "go_engine_version_unavailable" in run.control_errors
    assert run.audited_ecosystems == ()
    assert run.adapters[0].engine_name == "govulncheck"
    assert run.adapters[0].findings == ()


def test_go_vulnerability_is_normalized_from_bounded_json_stream(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "go.mod").write_text("module example.test/service\n\ngo 1.24\n", encoding="utf-8")
    (workspace / "go.sum").write_text("example.test/dependency v1.0.0 h1:abc\n", encoding="utf-8")
    output = (
        json.dumps({"config": {"protocol_version": "v1.0.0"}})
        + "\n"
        + json.dumps({"osv": {"id": "GO-2026-1234"}})
        + "\n"
        + json.dumps(
            {
                "finding": {
                    "osv": "GO-2026-1234",
                    "fixed_version": "v2.0.0",
                    "trace": [{"module": RAW_PACKAGE, "version": RAW_VERSION}],
                }
            }
        )
        + "\n"
    ).encode("utf-8")
    runner = ScriptedRunner({"govulncheck": ProcessResult(0, output)})

    report = SoftwareCompositionAnalyzer(process_runner=runner).run(workspace).to_report()
    rendered = json.dumps(report, sort_keys=True)

    assert report["complete"] is True
    assert report["passed"] is False
    assert report["findings"][0]["vulnerability_id"] == "GO-2026-1234"
    assert report["findings"][0]["severity"] == "unknown"
    assert report["findings"][0]["fixed_version_present"] is True
    assert runner.calls[0]["argv"] == ["govulncheck", "-version"]
    assert runner.calls[1]["argv"] == ["govulncheck", "-json", "./..."]
    assert RAW_PACKAGE not in rendered
    assert RAW_VERSION not in rendered


@pytest.mark.parametrize(
    ("result", "expected_error"),
    [
        (ProcessResult(2, _clean_python_payload()), "python_engine_nonzero_exit"),
        (ProcessResult(0, b"{not-json"), "python_engine_json_malformed"),
        (
            ProcessResult(0, _clean_python_payload() + b" " * 200),
            "python_engine_output_limit_exceeded",
        ),
    ],
)
def test_nonzero_malformed_and_oversized_output_fail_closed(
    tmp_path: Path,
    result: ProcessResult,
    expected_error: str,
) -> None:
    workspace = _python_workspace(tmp_path / "workspace")
    runner = ScriptedRunner({"pip-audit": result})
    max_output = 64 if expected_error.endswith("output_limit_exceeded") else 1024 * 1024

    run = SoftwareCompositionAnalyzer(process_runner=runner, max_output_bytes=max_output).run(workspace)

    assert run.complete is False
    assert run.passed is False
    assert expected_error in run.control_errors
    assert run.findings == ()
    assert run.adapters[0].complete is False
    assert run.adapters[0].counts["finding_count"] == 0


def test_result_count_limit_fails_closed_without_partial_findings(tmp_path: Path) -> None:
    workspace = _python_workspace(tmp_path / "workspace")
    payload = _python_payload(
        {"id": "CVE-2026-1111", "fix_versions": []},
        {"id": "CVE-2026-2222", "fix_versions": []},
    )
    runner = ScriptedRunner({"pip-audit": ProcessResult(1, payload)})

    run = SoftwareCompositionAnalyzer(process_runner=runner, max_results=1).run(workspace)

    assert run.complete is False
    assert "python_result_limit_exceeded" in run.control_errors
    assert run.findings == ()
    assert run.adapters[0].counts["result_count"] == 2


def test_manifest_without_lock_fails_before_engine_invocation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text(
        json.dumps({"name": "fixture", "dependencies": {"demo": "^1.0.0"}}),
        encoding="utf-8",
    )
    runner = ScriptedRunner({})

    run = SoftwareCompositionAnalyzer(process_runner=runner).run(workspace)

    assert run.complete is False
    assert "npm_manifest_without_lock" in run.control_errors
    assert run.inventory["manifest_count"] == 1
    assert run.inventory["lock_count"] == 0
    assert run.inventory["uncovered_manifest_count"] == 1
    assert runner.calls == []


def test_unpinned_python_requirements_are_an_uncovered_manifest(tmp_path: Path) -> None:
    workspace = _python_workspace(tmp_path / "workspace", "demo-package>=1\n")
    runner = ScriptedRunner({})

    run = SoftwareCompositionAnalyzer(process_runner=runner).run(workspace)

    assert run.complete is False
    assert "python_manifest_without_lock" in run.control_errors
    assert run.inventory["manifest_count"] == 1
    assert run.inventory["lock_count"] == 0
    assert runner.calls == []


def test_exact_constraints_cover_and_audit_ranged_requirements(tmp_path: Path) -> None:
    workspace = _python_workspace(
        tmp_path / "workspace",
        "-c constraints.txt\ndemo-package>=1\n",
    )
    (workspace / "constraints.txt").write_text("demo-package==1.2.3\n", encoding="utf-8")
    runner = ScriptedRunner(
        {
            "pip-audit": [
                ProcessResult(0, _clean_python_payload()),
                ProcessResult(0, _clean_python_payload()),
            ]
        }
    )

    run = SoftwareCompositionAnalyzer(process_runner=runner).run(workspace)

    assert run.complete is True
    assert run.inventory["manifest_count"] == 2
    assert run.inventory["lock_count"] == 1
    assert run.inventory["uncovered_manifest_count"] == 0
    audit_inputs = [call["argv"][-1] for call in runner.calls[1:]]
    assert audit_inputs == ["constraints.txt", "requirements.txt"]


def test_pep621_dependencies_and_optional_groups_accept_covering_pinned_lock(tmp_path: Path) -> None:
    workspace = _pep621_workspace(
        tmp_path / "workspace",
        [
            "core-pkg==1.4.0",
            "direct_url==2.0.0",
            "optional-pkg==3.1.0",
            "transitive-package==4.0.0",
        ],
    )
    runner = ScriptedRunner({"pip-audit": ProcessResult(0, _clean_python_payload())})

    run = SoftwareCompositionAnalyzer(process_runner=runner).run(workspace)

    assert run.complete is True
    assert run.control_errors == ()
    assert run.inventory["manifest_count"] == 2
    assert run.inventory["lock_count"] == 1
    assert run.inventory["uncovered_manifest_count"] == 0
    assert runner.calls[1]["argv"][-1] == "requirements.lock"


def test_pep621_lock_missing_one_optional_dependency_remains_fail_closed(tmp_path: Path) -> None:
    workspace = _pep621_workspace(
        tmp_path / "workspace",
        [
            "core-pkg==1.4.0",
            "direct-url==2.0.0",
        ],
    )
    runner = ScriptedRunner({})

    run = SoftwareCompositionAnalyzer(process_runner=runner).run(workspace)

    assert run.complete is False
    assert "python_manifest_without_lock" in run.control_errors
    assert run.inventory["uncovered_manifest_count"] == 1
    assert runner.calls == []


def test_malformed_pep621_optional_dependency_group_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "pyproject.toml").write_text(
        "[project]\n"
        "name = 'broken'\n"
        "version = '1.0.0'\n"
        "dependencies = ['demo>=1']\n"
        "[project.optional-dependencies]\n"
        "dev = 'not-a-list'\n",
        encoding="utf-8",
    )
    (workspace / "requirements.lock").write_text("demo==1.0.0\n", encoding="utf-8")

    run = SoftwareCompositionAnalyzer(process_runner=ScriptedRunner({})).run(workspace)

    assert run.complete is False
    assert "manifest_schema_invalid" in run.control_errors


def test_manifest_symlink_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside-requirements.txt"
    outside.write_text("demo-package==1.2.3\n", encoding="utf-8")
    link = workspace / "requirements.txt"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")

    run = SoftwareCompositionAnalyzer(process_runner=ScriptedRunner({})).run(workspace)

    assert run.complete is False
    assert CONTROL_MANIFEST_SYMLINK in run.control_errors
    assert run.input_snapshot["complete"] is False
    assert run.findings == ()


def test_unreadable_and_oversized_manifests_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable_workspace = _python_workspace(tmp_path / "unreadable")
    unreadable_path = unreadable_workspace / "requirements.txt"
    original_bounded_read = sca._read_manifest_bounded

    def guarded_read(path: Path, max_bytes: int) -> tuple[bytes, bool]:
        if path == unreadable_path:
            raise PermissionError("fixture unreadable")
        return original_bounded_read(path, max_bytes)

    monkeypatch.setattr(sca, "_read_manifest_bounded", guarded_read)
    unreadable = SoftwareCompositionAnalyzer(process_runner=ScriptedRunner({})).run(unreadable_workspace)
    monkeypatch.setattr(sca, "_read_manifest_bounded", original_bounded_read)

    oversized_workspace = _python_workspace(tmp_path / "oversized", "demo-package==1.2.3\n")
    oversized = SoftwareCompositionAnalyzer(
        process_runner=ScriptedRunner({}),
        max_manifest_bytes=8,
    ).run(oversized_workspace)

    assert CONTROL_MANIFEST_UNREADABLE in unreadable.control_errors
    assert unreadable.complete is False
    assert CONTROL_MANIFEST_OVERSIZED in oversized.control_errors
    assert oversized.complete is False


def test_candidate_count_is_bounded_before_manifest_parsing(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    for directory_name in ("a", "b"):
        directory = workspace / directory_name
        directory.mkdir(parents=True)
        (directory / "package.json").write_text(json.dumps({"name": directory_name}), encoding="utf-8")

    run = SoftwareCompositionAnalyzer(
        process_runner=ScriptedRunner({}),
        max_manifest_files=1,
    ).run(workspace)

    assert run.complete is False
    assert CONTROL_MANIFEST_LIMIT in run.control_errors
    assert run.input_snapshot["complete"] is False


def test_snapshot_drift_invalidates_completed_engine_output(tmp_path: Path) -> None:
    workspace = _python_workspace(tmp_path / "workspace")
    manifest = workspace / "requirements.txt"
    changed = False

    def mutate(_engine: str) -> None:
        nonlocal changed
        if not changed:
            manifest.write_text("demo-package==2.0.0\n", encoding="utf-8")
            changed = True

    runner = ScriptedRunner(
        {"pip-audit": ProcessResult(0, _clean_python_payload())},
        on_audit=mutate,
    )

    run = SoftwareCompositionAnalyzer(process_runner=runner).run(workspace)

    assert run.complete is False
    assert CONTROL_SNAPSHOT_DRIFT in run.control_errors
    assert run.audited_ecosystems == ()
    assert run.findings == ()
    assert run.adapters[0].complete is False
    assert CONTROL_SNAPSHOT_DRIFT in run.adapters[0].control_errors


def test_non_manifest_source_drift_is_bound_to_the_input_snapshot(tmp_path: Path) -> None:
    workspace = _python_workspace(tmp_path / "workspace")
    source = workspace / "app.py"
    source.write_text("print('before')\n", encoding="utf-8")
    changed = False

    def mutate(_engine: str) -> None:
        nonlocal changed
        if not changed:
            source.write_text("print('after')\n", encoding="utf-8")
            changed = True

    runner = ScriptedRunner(
        {"pip-audit": ProcessResult(0, _clean_python_payload())},
        on_audit=mutate,
    )

    run = SoftwareCompositionAnalyzer(runner=runner).run(workspace)

    assert run.complete is False
    assert CONTROL_SNAPSHOT_DRIFT in run.control_errors
    assert run.input_snapshot["schema"] == "k_guard_source_tree_snapshot.v1"
    assert len(run.input_snapshot["tree_sha256"]) == 64
    assert run.input_snapshot["file_count"] == 2
    assert run.audited_ecosystems == ()


def test_multi_ecosystem_partial_failure_never_becomes_a_pass(tmp_path: Path) -> None:
    workspace = _python_workspace(tmp_path / "workspace")
    _npm_workspace(workspace)
    runner = ScriptedRunner(
        {
            "pip-audit": ProcessResult(0, _clean_python_payload()),
            "npm": ProcessResult(2, json.dumps({"error": {"code": "EAUDIT"}}).encode("utf-8")),
        }
    )

    run = SoftwareCompositionAnalyzer(process_runner=runner).run(workspace)

    assert run.complete is False
    assert run.passed is False
    assert run.requested_ecosystems == ("python", "npm")
    assert run.audited_ecosystems == ("python",)
    assert "npm_engine_json_schema_invalid" in run.control_errors
    assert "npm_engine_nonzero_exit" in run.control_errors
    by_ecosystem = {adapter.ecosystem: adapter for adapter in run.adapters}
    assert by_ecosystem["python"].complete is True
    assert by_ecosystem["npm"].complete is False


def test_poetry_and_pipenv_locks_are_discovered_and_audited(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    poetry = workspace / "poetry-project"
    pipenv = workspace / "pipenv-project"
    poetry.mkdir(parents=True)
    pipenv.mkdir(parents=True)
    (poetry / "pyproject.toml").write_text(
        "[tool.poetry]\n"
        "name = 'fixture'\n"
        "version = '1.0.0'\n"
        "[tool.poetry.dependencies]\n"
        "python = '^3.11'\n"
        "demo = '1.0.0'\n",
        encoding="utf-8",
    )
    (poetry / "poetry.lock").write_text(
        "[[package]]\nname = 'demo'\nversion = '1.0.0'\n",
        encoding="utf-8",
    )
    (pipenv / "Pipfile").write_text("[packages]\ndemo = '==1.0.0'\n", encoding="utf-8")
    (pipenv / "Pipfile.lock").write_text(
        json.dumps({"default": {"demo": {"version": "==1.0.0"}}, "develop": {}}),
        encoding="utf-8",
    )
    runner = ScriptedRunner(
        {
            "pip-audit": [
                ProcessResult(0, _clean_python_payload()),
                ProcessResult(0, _clean_python_payload()),
            ]
        }
    )

    run = SoftwareCompositionAnalyzer(process_runner=runner).run(workspace)

    assert run.complete is True
    assert run.inventory["manifest_count"] == 2
    assert run.inventory["lock_count"] == 2
    assert run.adapters[0].counts["invocation_count"] == 3
    audit_calls = [call for call in runner.calls if call["argv"][1:] != ["--version"]]
    assert len(audit_calls) == 2
    assert all(call["argv"][-2] == "-r" for call in audit_calls)
    assert all(Path(call["argv"][-1]).is_absolute() for call in audit_calls)
    assert runner.normalized_python_inputs == ["demo==1.0.0\n", "demo==1.0.0\n"]
    assert all(not Path(call["argv"][-1]).exists() for call in audit_calls)


def test_unrepresentable_pipenv_lock_fails_before_audit(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "Pipfile").write_text("[packages]\ndemo = {git = 'https://example.invalid/repo'}\n", encoding="utf-8")
    (workspace / "Pipfile.lock").write_text(
        json.dumps({"default": {"demo": {"git": "https://example.invalid/repo"}}, "develop": {}}),
        encoding="utf-8",
    )
    runner = ScriptedRunner({})

    run = SoftwareCompositionAnalyzer(process_runner=runner).run(workspace)

    assert run.complete is False
    assert "python_lock_normalization_failed" in run.control_errors
    assert run.adapters[0].counts["invocation_count"] == 1
    assert len(runner.calls) == 1


@pytest.mark.parametrize("lock_name", ["yarn.lock", "pnpm-lock.yaml"])
def test_yarn_and_pnpm_locks_are_discovered_but_fail_closed_without_adapter(
    tmp_path: Path,
    lock_name: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text(json.dumps({"dependencies": {"demo": "1.0.0"}}), encoding="utf-8")
    (workspace / lock_name).write_text("lockfile fixture\n", encoding="utf-8")
    runner = ScriptedRunner({})

    run = SoftwareCompositionAnalyzer(process_runner=runner).run(workspace)

    assert run.complete is False
    assert "npm_lock_manager_unsupported" in run.control_errors
    assert run.inventory["lock_count"] == 1
    assert runner.calls == []


def test_report_content_is_deterministic_and_raw_free(tmp_path: Path) -> None:
    workspace = _python_workspace(tmp_path / "workspace")
    payload = _python_payload(
        {
            "id": "CVE-2026-55555",
            "severity": "medium",
            "fix_versions": [],
            "description": "private advisory narrative must not return",
        }
    )
    first = SoftwareCompositionAnalyzer(
        process_runner=ScriptedRunner({"pip-audit": ProcessResult(1, payload)})
    ).run(workspace)
    second = SoftwareCompositionAnalyzer(
        process_runner=ScriptedRunner({"pip-audit": ProcessResult(1, payload)})
    ).run(workspace)

    assert first.to_dict() == second.to_dict()
    assert first.to_report() == second.to_report()
    assert first.to_dict()["report_sha256"] == second.to_dict()["report_sha256"]
    report = first.to_report()
    rendered = json.dumps(report, sort_keys=True)
    assert verify_evidence_bundle(report["evidence_bundle"])
    assert RAW_PACKAGE not in rendered
    assert RAW_VERSION not in rendered
    assert "private advisory narrative" not in rendered
    assert str(workspace) not in rendered
    assert "requirements.txt" not in rendered


def test_noncanonical_vulnerability_id_is_replaced_with_a_hash_ref(tmp_path: Path) -> None:
    workspace = _python_workspace(tmp_path / "workspace")
    payload = _python_payload(
        {
            "id": RAW_PACKAGE.upper(),
            "severity": "low",
            "fix_versions": [],
        }
    )
    runner = ScriptedRunner({"pip-audit": ProcessResult(1, payload)})

    report = SoftwareCompositionAnalyzer(process_runner=runner).run(workspace).to_report()
    rendered = json.dumps(report, sort_keys=True)

    assert report["complete"] is True
    assert report["findings"][0]["vulnerability_id"].startswith("VULN-")
    assert RAW_PACKAGE not in rendered
    assert RAW_PACKAGE.upper() not in rendered
