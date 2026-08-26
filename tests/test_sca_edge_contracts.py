from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import k_guard_mcp.sca as sca


def _input_file(
    tmp_path: Path,
    *,
    name: str = "requirements.txt",
    ecosystem: str = "python",
    kind: str = "requirements",
    roles: tuple[str, ...] = ("manifest", "lock"),
    content: bytes = b"demo==1.0.0\n",
    package_names: frozenset[str] = frozenset({"demo"}),
) -> sca._InputFile:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return sca._InputFile(
        path=path.resolve(),
        relative=name.replace("\\", "/"),
        ecosystem=ecosystem,
        kind=kind,
        roles=roles,
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        package_names=package_names,
    )


def _valid_adapter(finding: sca.ScaFinding) -> sca.ScaAdapterRun:
    return sca.ScaAdapterRun(
        ecosystem="python",
        complete=True,
        control_errors=(),
        findings=(finding,),
        engine_name="pip-audit",
        engine_version="2.10.1",
        command_contract={},
        command_contract_sha256="0" * 64,
        input_snapshot={},
        inventory={},
        counts={"finding_count": 1},
        bounds={},
    )


@pytest.mark.parametrize(
    "field",
    [
        "max_manifest_files",
        "max_manifest_bytes",
        "max_manifest_total_bytes",
        "max_walk_entries",
        "max_source_files",
        "max_source_file_bytes",
        "max_source_total_bytes",
        "max_output_bytes",
        "max_results",
    ],
)
def test_sca_bounds_reject_non_positive_integer_limits(field: str) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        sca.ScaBounds(**{field: 0})
    with pytest.raises(ValueError, match="positive integer"):
        sca.ScaBounds(**{field: True})


@pytest.mark.parametrize("field", ["timeout_seconds", "version_timeout_seconds"])
def test_sca_bounds_reject_non_positive_time_limits(field: str) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        sca.ScaBounds(**{field: 0.0})
    with pytest.raises(ValueError, match="must be positive"):
        sca.ScaBounds(**{field: True})


def test_sca_value_objects_reject_forged_states() -> None:
    result = sca.ProcessResult(0, stdout="ok", stderr="hidden")
    assert result.stdout == b"ok"
    assert result.stderr == b"hidden"
    with pytest.raises(ValueError, match="non-negative"):
        sca.ProcessResult(0, stdout_bytes=-1)

    finding = sca._finding("python", "CVE-2026-12345", "demo", "1.0", "high", True)
    invalid_findings = (
        {"ecosystem": "rust"},
        {"vulnerability_id": "not-normalized"},
        {"package_ref": "short"},
        {"installed_version_ref": "short"},
        {"severity": "urgent"},
        {"fixed_version_present": 1},
        {"fingerprint": "short"},
        {"raw_free": False},
    )
    for changes in invalid_findings:
        with pytest.raises(ValueError):
            replace(finding, **changes)

    adapter = _valid_adapter(finding)
    assert adapter.passed is False
    go_finding = sca._finding("go", "GO-2026-1234", "demo", "1.0", "low", False)
    invalid_adapters = (
        {"ecosystem": "rust"},
        {"control_errors": ("unexpected",)},
        {"complete": False},
        {"counts": {"finding_count": -1}},
        {"command_contract_sha256": "short"},
        {"findings": (go_finding,)},
        {"raw_free": False},
    )
    for changes in invalid_adapters:
        with pytest.raises(ValueError):
            replace(adapter, **changes)

    run = sca.ScaRun(
        complete=True,
        control_errors=(),
        findings=(finding,),
        requested_ecosystems=("python",),
        audited_ecosystems=("python",),
        adapters=(adapter,),
        input_snapshot={},
        inventory={},
        counts={"finding_count": 1},
    )
    assert run.passed is False
    for changes in (
        {"control_errors": ("unexpected",)},
        {"complete": False},
        {"audited_ecosystems": ("npm",)},
        {"counts": {"finding_count": -1}},
        {"raw_free": False},
    ):
        with pytest.raises(ValueError):
            replace(run, **changes)


def test_manifest_name_classification_is_explicit() -> None:
    expected = {
        "requirements.in": ("python", "requirements_in"),
        "requirements-prod.txt": ("python", "requirements"),
        "constraints.lock": ("python", "constraints"),
        "pyproject.toml": ("python", "pyproject"),
        "poetry.lock": ("python", "poetry_lock"),
        "Pipfile": ("python", "pipfile"),
        "Pipfile.lock": ("python", "pipfile_lock"),
        "package.json": ("npm", "package_manifest"),
        "package-lock.json": ("npm", "package_lock"),
        "npm-shrinkwrap.json": ("npm", "npm_shrinkwrap"),
        "yarn.lock": ("npm", "yarn_lock"),
        "pnpm-lock.yaml": ("npm", "pnpm_lock"),
        "go.mod": ("go", "go_mod"),
        "go.sum": ("go", "go_sum"),
    }
    assert {name: sca._candidate_kind(name) for name in expected} == expected
    assert sca._candidate_kind("Cargo.lock") is None


def test_requirement_and_pyproject_parsers_cover_strict_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    exact, names = sca._requirement_pins(
        b"# comment\n--hash=sha256:abc\nDemo_Pkg==1.0 \\\n+          --hash=sha256:def\n-r other.txt\nLoose>=2\n--index-url https://example.invalid\n"
    )
    assert exact is False
    assert names == frozenset({"demo-pkg", "loose"})
    pending_exact, pending_names = sca._requirement_pins(b"demo==1.0\\")
    assert pending_exact is True
    assert pending_names == frozenset({"demo"})

    assert sca._pep508_direct_name("Demo_Pkg[security]>=1; python_version >= '3.11'") == "demo-pkg"
    for invalid in (None, "", "bad\nname", "not a valid requirement ???"):
        with pytest.raises(ValueError):
            sca._pep508_direct_name(invalid)
    with pytest.raises(ValueError):
        sca._pep508_direct_name("a" * (sca._MAX_PEP508_REQUIREMENT_BYTES + 1))

    monkeypatch.setattr(sca, "Requirement", None)
    assert sca._pep508_direct_name("Fallback_Name>=1") == "fallback-name"
    with pytest.raises(ValueError):
        sca._pep508_direct_name("???")

    declared, poetry = sca._pyproject_contract(
        b"[project]\ndependencies=['demo>=1']\n[tool.poetry]\nname='fixture'\n"
    )
    assert declared == frozenset({"demo"})
    assert poetry is True

    for payload in (
        {"project": []},
        {"project": {"dependencies": "bad"}},
        {"project": {"optional-dependencies": []}},
        {"project": {"optional-dependencies": {"dev": "bad"}}},
        {"tool": []},
        {"tool": {"poetry": "bad"}},
    ):
        monkeypatch.setattr(sca.tomllib, "loads", lambda _text, value=payload: value)
        with pytest.raises(ValueError):
            sca._pyproject_contract(b"ignored")

    refs = sca._requirement_file_references(
        b"-r local.txt\n--constraint=constraints.lock\n-r ../escape.txt\n-r C:/absolute.txt\n"
    )
    assert refs == ("constraints.lock", "local.txt")


@pytest.mark.parametrize(
    ("ecosystem", "kind", "content", "roles"),
    [
        ("python", "requirements_in", b"demo>=1\n", ("manifest",)),
        ("python", "requirements", b"demo>=1\n", ("manifest",)),
        ("python", "pyproject", b"[project]\ndependencies=[]\n", ()),
        ("python", "poetry_lock", b"[[package]]\nname='demo'\nversion='1.0'\n", ("lock",)),
        ("python", "pipfile", b"[packages]\ndemo='==1.0'\n", ("manifest",)),
        ("python", "pipfile_lock", b'{"default":{"demo":{"version":"==1.0"}}}', ("lock",)),
        ("npm", "package_manifest", b"{}", ("manifest",)),
        ("npm", "package_lock", b"{}", ("lock",)),
        ("npm", "npm_shrinkwrap", b"{}", ("lock",)),
        ("npm", "yarn_lock", b"fixture\n", ("lock",)),
        ("npm", "pnpm_lock", b"fixture\n", ("lock",)),
        ("go", "go_mod", b"module example.test/app\n", ("manifest",)),
        ("go", "go_sum", b"example.test/mod v1.0 h1:abc\n", ("lock",)),
    ],
)
def test_manifest_schema_classification_covers_each_supported_kind(
    ecosystem: str,
    kind: str,
    content: bytes,
    roles: tuple[str, ...],
) -> None:
    classified_roles, _names, errors = sca._validate_and_classify(ecosystem, kind, content)
    assert classified_roles == roles
    assert errors == ()


@pytest.mark.parametrize(
    ("kind", "content", "error"),
    [
        ("package_manifest", b"[]", sca.CONTROL_MANIFEST_SCHEMA),
        ("pipfile_lock", b"[]", sca.CONTROL_MANIFEST_SCHEMA),
        ("poetry_lock", b"package='bad'", sca.CONTROL_MANIFEST_SCHEMA),
        ("go_mod", b"go 1.24\n", sca.CONTROL_MANIFEST_SCHEMA),
        ("unknown", b"{}", sca.CONTROL_MANIFEST_SCHEMA),
        ("yarn_lock", b"\xff", sca.CONTROL_MANIFEST_ENCODING),
    ],
)
def test_manifest_schema_classification_fails_closed(kind: str, content: bytes, error: str) -> None:
    roles, _names, errors = sca._validate_and_classify("python", kind, content)
    assert roles == ()
    assert errors == (error,)


def test_discovery_rejects_invalid_targets_and_snapshot_limits(tmp_path: Path) -> None:
    assert sca.CONTROL_TARGET_INVALID in sca._discover("", sca.ScaBounds()).errors
    assert sca.CONTROL_TARGET_NOT_FOUND in sca._discover(tmp_path / "missing", sca.ScaBounds()).errors
    target_file = tmp_path / "plain.txt"
    target_file.write_text("x", encoding="ascii")
    assert sca.CONTROL_TARGET_NOT_DIRECTORY in sca._discover(target_file, sca.ScaBounds()).errors

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "requirements.txt").write_text("demo==1.0\n", encoding="ascii")
    (workspace / "extra.py").write_text("print('x')\n", encoding="ascii")
    limited = sca._discover(workspace, sca.ScaBounds(max_source_files=1))
    assert sca.CONTROL_SOURCE_SNAPSHOT in limited.errors
    assert limited.snapshot["complete"] is False

    walk_limited = sca._discover(workspace, sca.ScaBounds(max_walk_entries=1))
    assert sca.CONTROL_DISCOVERY_LIMIT in walk_limited.errors

    total_limited = sca._discover(
        workspace,
        sca.ScaBounds(max_manifest_bytes=64, max_manifest_total_bytes=4),
    )
    assert sca.CONTROL_MANIFEST_TOTAL_OVERSIZED in total_limited.errors


def test_discovery_detects_manifest_change_during_bounded_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manifest = workspace / "requirements.txt"
    manifest.write_text("demo==1.0\n", encoding="ascii")
    original = sca._read_manifest_bounded

    def changed(path: Path, maximum: int) -> tuple[bytes, bool]:
        content, limited = original(path, maximum)
        path.write_text("demo==2.00\n", encoding="ascii")
        return content, limited

    monkeypatch.setattr(sca, "_read_manifest_bounded", changed)
    state = sca._discover(workspace, sca.ScaBounds())
    assert sca.CONTROL_MANIFEST_CHANGED in state.errors


def test_python_manifest_coverage_rules_are_explicit(tmp_path: Path) -> None:
    lock = _input_file(tmp_path, name="constraints.lock", kind="constraints")
    requirements = _input_file(
        tmp_path,
        name="requirements.txt",
        roles=("manifest",),
        content=b"-c constraints.lock\ndemo>=1\n",
    )
    assert sca._python_manifest_is_covered(requirements, [lock]) is True

    requirement_in = _input_file(
        tmp_path,
        name="dev.in",
        kind="requirements_in",
        roles=("manifest",),
        content=b"demo>=1\n",
    )
    dev_lock = _input_file(tmp_path, name="dev.lock")
    assert sca._python_manifest_is_covered(requirement_in, [dev_lock]) is True
    assert sca._python_manifest_is_covered(requirement_in, []) is False

    constraints = _input_file(
        tmp_path,
        name="constraints.in",
        kind="constraints",
        roles=("manifest",),
        content=b"demo>=1\n",
    )
    assert sca._python_manifest_is_covered(constraints, [lock]) is False

    pipfile = _input_file(tmp_path, name="Pipfile", kind="pipfile", roles=("manifest",))
    pipfile_lock = _input_file(tmp_path, name="Pipfile.lock", kind="pipfile_lock", roles=("lock",))
    assert sca._python_manifest_is_covered(pipfile, [pipfile_lock]) is True

    empty = replace(requirements, package_names=frozenset())
    assert sca._python_manifest_is_covered(empty, [lock]) is True
    assert sca._bounded_source_snapshot(None, sca.ScaBounds())["complete"] is False


def test_audit_unit_planning_handles_missing_and_lock_only_states(tmp_path: Path) -> None:
    snapshot = {"complete": True}
    inventory = sca._inventory_projection([], {name: 0 for name in sca.SUPPORTED_ECOSYSTEMS})
    empty = sca._InventoryState(tmp_path, (), (), (), snapshot, inventory, {name: 0 for name in sca.SUPPORTED_ECOSYSTEMS})
    assert sca._audit_units("python", empty)[1] == ("python_manifest_missing",)

    go_sum = _input_file(
        tmp_path,
        name="go.sum",
        ecosystem="go",
        kind="go_sum",
        roles=("lock",),
        package_names=frozenset(),
    )
    lock_only = replace(empty, files=(go_sum,))
    _units, errors = sca._audit_units("go", lock_only)
    assert "go_manifest_missing" in errors

    manifest_only = _input_file(
        tmp_path,
        name="go.mod",
        ecosystem="go",
        kind="go_mod",
        roles=("manifest",),
        package_names=frozenset(),
    )
    no_lock = replace(empty, files=(manifest_only,))
    _units, errors = sca._audit_units("go", no_lock)
    assert "go_auditable_lock_missing" in errors


def test_local_process_runner_enforces_shell_timeout_and_output_bounds(tmp_path: Path) -> None:
    runner = sca._LocalProcessRunner()
    common = {
        "cwd": tmp_path,
        "env": dict(os.environ),
        "max_output_bytes": 64,
    }
    assert runner([sys.executable, "-c", "print('x')"], timeout_seconds=1, shell=True, **common).launch_error == "shell_disallowed"
    assert runner(["missing-k-guard-command-xyz"], timeout_seconds=1, shell=False, **common).launch_error == "missing"

    success = runner([sys.executable, "-c", "print('ok')"], timeout_seconds=5, shell=False, **common)
    assert success.returncode == 0
    assert success.stdout == b"ok\r\n" or success.stdout == b"ok\n"

    limited = runner(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 4096)"],
        # This case measures output bounding; timeout behavior is tested below.
        timeout_seconds=5,
        shell=False,
        **common,
    )
    assert limited.output_limited is True
    assert limited.stdout_bytes is not None and limited.stdout_bytes > 64

    timed_out = runner(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout_seconds=0.05,
        shell=False,
        **common,
    )
    assert timed_out.timed_out is True


def test_process_result_coercion_and_error_normalization() -> None:
    mapping = sca._coerce_process_result(
        {"returncode": 2, "stdout": "abcdef", "stderr": "hidden", "stdout_bytes": 20},
        4,
    )
    assert mapping.stdout == b"abcd"
    assert mapping.stderr == b""
    assert mapping.output_limited is True

    completed = subprocess.CompletedProcess(["tool"], 0, stdout=b"ok", stderr=b"")
    assert sca._coerce_process_result(completed, 10).returncode == 0
    assert sca._coerce_process_result(sca.ProcessResult(0, b"ok"), 10).stdout == b"ok"

    errors = sca._process_errors(
        "python",
        sca.ProcessResult(-1, launch_error="os_error", timed_out=True, output_limited=True),
        version=True,
    )
    assert errors == [
        "python_engine_launch_failed",
        "python_engine_timeout",
        "python_engine_output_limit_exceeded",
        "python_engine_version_unavailable",
    ]
    assert sca._process_errors("npm", sca.ProcessResult(2), version=True) == [
        "npm_engine_nonzero_exit",
        "npm_engine_version_unavailable",
    ]

    assert sca._normalize_engine_version("go", b"govulncheck@v1.1.4\n") == "1.1.4"
    assert sca._normalize_engine_version("python", b"tool without a version") == ""
    assert sca._normalize_engine_version("python", b"\xff") == ""


def test_identifier_and_severity_normalizers_cover_supported_shapes() -> None:
    assert sca._normalize_vulnerability_id(123, prefix="NPM-") == "NPM-123"
    assert sca._normalize_vulnerability_id("123", prefix="NPM-") == "NPM-123"
    assert sca._normalize_vulnerability_id(None) == ""
    assert sca._normalize_vulnerability_id("contains spaces") == ""
    assert sca._normalize_vulnerability_id("private-id").startswith("VULN-")
    assert [sca._normalize_severity(value) for value in (9.0, 7.0, 4.0, 0.1, 0, None)] == [
        "critical",
        "high",
        "medium",
        "low",
        "unknown",
        "unknown",
    ]
    assert sca._normalize_severity("moderate") == "medium"
    assert sca._normalize_severity("nonsense") == "unknown"
    with pytest.raises(ValueError, match="package and version"):
        sca._finding("python", "CVE-2026-12345", "", "1.0", "high", False)


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        ([], "schema"),
        ({"error": "failed", "dependencies": []}, "schema"),
        ({}, "schema"),
        ({"dependencies": ["bad"]}, "schema"),
        ({"dependencies": [{"name": "", "version": "1", "vulns": []}]}, "schema"),
        ({"dependencies": [{"name": "p", "version": "1", "vulns": {}}]}, "schema"),
        ({"dependencies": [{"name": "p", "version": "1", "vulns": ["bad"]}]}, "schema"),
        ({"dependencies": [{"name": "p", "version": "1", "vulns": [{"id": None}]}]}, "schema"),
        ({"dependencies": [{"name": "p", "version": "1", "vulns": [{"id": "CVE-2026-12345", "fix_versions": {}}]}]}, "schema"),
    ],
)
def test_python_audit_schema_errors_are_fail_closed(payload: Any, error: str) -> None:
    findings, _count, observed = sca._python_findings(payload, 10)
    assert findings == []
    assert observed == error


def test_python_audit_alias_and_database_severity_are_normalized() -> None:
    payload = {
        "dependencies": [
            {
                "name": "Demo_Pkg",
                "version": "1.0",
                "vulns": [
                    {
                        "id": None,
                        "aliases": ["bad alias", "CVE-2026-12345"],
                        "database_specific": {"severity": "critical"},
                        "fix_versions": [],
                    }
                ],
            }
        ]
    }
    findings, count, error = sca._python_findings(payload, 1)
    assert (count, error) == (1, "")
    assert findings[0].vulnerability_id == "CVE-2026-12345"
    assert findings[0].severity == "critical"
    assert sca._python_findings(payload, 0)[2] == "limit"


def test_locked_python_requirements_reject_malformed_lock_shapes(tmp_path: Path) -> None:
    poetry = _input_file(
        tmp_path,
        name="poetry.lock",
        kind="poetry_lock",
        roles=("lock",),
        content=b"[[package]]\nname='demo'\nversion='1.0'\n",
    )
    assert sca._locked_python_requirements(poetry) == b"demo==1.0\n"

    pipfile = _input_file(
        tmp_path,
        name="Pipfile.lock",
        kind="pipfile_lock",
        roles=("lock",),
        content=b'{"default":{"demo":{"version":"==1.0"}},"develop":{}}',
    )
    assert sca._locked_python_requirements(pipfile) == b"demo==1.0\n"

    invalid = (
        replace(poetry, content=b"package='bad'"),
        replace(poetry, content=b"package=['bad']"),
        replace(poetry, content=b"[[package]]\nname=1\nversion='1'\n"),
        replace(pipfile, content=b"[]"),
        replace(pipfile, content=b'{"default":[],"develop":{}}'),
        replace(pipfile, content=b'{"default":{"demo":"bad"},"develop":{}}'),
        replace(pipfile, content=b'{"default":{"demo":{"version":"1.0"}},"develop":{}}'),
        replace(poetry, kind="unsupported"),
        replace(poetry, content=b"[[package]]\nname='bad name'\nversion='1.0'\n"),
    )
    for source in invalid:
        with pytest.raises((ValueError, TypeError)):
            sca._locked_python_requirements(source)


def _npm_source(tmp_path: Path) -> sca._InputFile:
    content = json.dumps(
        {
            "packages": {
                "node_modules/demo": {"name": "demo", "version": "1.0.0"},
                "node_modules/derived": {"version": "2.0.0"},
                "ignored": {"version": ""},
            },
            "dependencies": {"legacy": {"version": "3.0.0"}},
        }
    ).encode("utf-8")
    return _input_file(
        tmp_path,
        name="package-lock.json",
        ecosystem="npm",
        kind="package_lock",
        roles=("lock",),
        content=content,
        package_names=frozenset(),
    )


def test_npm_lock_and_both_audit_formats_are_normalized(tmp_path: Path) -> None:
    source = _npm_source(tmp_path)
    by_name, by_node = sca._npm_lock_versions(source)
    assert by_name["demo"] == ("1.0.0",)
    assert by_name["derived"] == ("2.0.0",)
    assert by_name["legacy"] == ("3.0.0",)
    assert by_node["node_modules/demo"] == "1.0.0"

    modern = {
        "vulnerabilities": {
            "demo": {
                "name": "demo",
                "severity": "high",
                "nodes": ["node_modules/demo"],
                "via": ["transitive-only"],
                "source": 123,
                "fixAvailable": True,
            }
        }
    }
    findings, count, error = sca._npm_findings(modern, 10, source)
    assert (count, error) == (1, "")
    assert findings[0].vulnerability_id == "NPM-123"

    legacy = {
        "advisories": {
            "44": {
                "module_name": "legacy",
                "severity": "moderate",
                "patched_versions": ">=4",
                "findings": [{"version": "3.1.0"}],
                "cves": ["CVE-2026-44444"],
            }
        }
    }
    findings, count, error = sca._npm_findings(legacy, 10, source)
    assert (count, error) == (1, "")
    assert {finding.vulnerability_id for finding in findings} == {"CVE-2026-44444"}
    assert len(findings) == 2
    assert all(finding.fixed_version_present for finding in findings)


def test_npm_advisory_and_schema_edges_fail_closed(tmp_path: Path) -> None:
    source = _npm_source(tmp_path)
    assert sca._npm_advisory_id({"id": "CVE-2026-11111"}, "x") == "CVE-2026-11111"
    assert sca._npm_advisory_id({"cves": [None, "CVE-2026-22222"]}, "x") == "CVE-2026-22222"
    assert sca._npm_advisory_id({"url": "https://x/GHSA-2345-6789-CFGH"}, "x") == "GHSA-2345-6789-CFGH"
    assert sca._npm_advisory_id({}, "fallback").startswith("NPM-")
    assert sca._npm_versions_for_row("demo", {"version": "9.0"}, {}, {}) == ("9.0",)
    assert sca._npm_versions_for_row("demo", {}, {"demo": ("1.0",)}, {}) == ("1.0",)

    malformed_source = replace(source, content=b"[]")
    cases = (
        ([], source, "schema"),
        ({"error": {"code": "EAUDIT"}}, source, "schema"),
        ({"vulnerabilities": []}, source, "schema"),
        ({"vulnerabilities": {1: {}}}, source, "schema"),
        ({"vulnerabilities": {"demo": {"name": "", "via": []}}}, source, "schema"),
        ({"vulnerabilities": {"missing": {"via": []}}}, source, "schema"),
        ({"vulnerabilities": {"demo": {"via": {}}}}, source, "schema"),
        ({"advisories": []}, source, "schema"),
        ({"advisories": {"1": "bad"}}, source, "schema"),
        ({"advisories": {"1": {"module_name": "missing"}}}, source, "schema"),
        ({}, source, "schema"),
        ({"vulnerabilities": {}}, malformed_source, "schema"),
    )
    for payload, lock, expected in cases:
        findings, _count, error = sca._npm_findings(payload, 10, lock)
        assert findings == []
        assert error == expected
    assert sca._npm_findings({"advisories": {"1": {}}}, 0, source)[2] == "limit"


def test_go_json_stream_schema_and_findings_are_bounded() -> None:
    assert sca._go_payload(b"\xff")[1] == "malformed"
    assert sca._go_payload(b"not-json\n")[1] == "malformed"
    assert sca._go_payload(b"[]\n")[1] == "schema"
    assert sca._go_payload(b"\n")[1] == "malformed"
    pretty_stream = (
        json.dumps({"config": {"protocol_version": "v1.0.0"}}, indent=2)
        + "\n"
        + json.dumps({"progress": {"message": "complete"}}, indent=2)
    ).encode("utf-8")
    pretty_rows, pretty_error = sca._go_payload(pretty_stream)
    assert pretty_error == ""
    assert len(pretty_rows) == 2
    assert sca._go_payload(pretty_stream + b" trailing-garbage")[1] == "malformed"

    valid = "\n".join(
        [
            json.dumps({"config": {"protocol_version": "v1.0.0"}}),
            json.dumps({"osv": {"id": "GO-2026-1234", "database_specific": {"severity": "HIGH"}}}),
            json.dumps(
                {
                    "finding": {
                        "osv": "GO-2026-1234",
                        "trace": ["skip", {"module": "example/mod", "version": "v1.0.0"}],
                        "fixed_version": "v1.1.0",
                    }
                }
            ),
        ]
    ).encode("utf-8")
    findings, count, error = sca._go_findings(valid, 1)
    assert (count, error) == (1, "")
    assert findings[0].severity == "high"
    assert findings[0].fixed_version_present is True
    assert sca._go_findings(valid, 0)[2] == "limit"

    invalid_rows = (
        [{"config": {"protocol_version": "v0"}}],
        [{"config": {"protocol_version": "v1.0.0"}}, {"config": {"protocol_version": "v1.0.0"}}],
        [{"config": {"protocol_version": "v1.0.0"}, "extra": True}],
        [{"config": {"protocol_version": "v1.0.0"}}, {"finding": {"osv": "bad", "trace": []}}],
        [{"config": {"protocol_version": "v1.0.0"}}, {"finding": {"osv": "GO-2026-1234", "trace": {}}}],
        [{"config": {"protocol_version": "v1.0.0"}}, {"finding": {"osv": "GO-2026-1234", "trace": []}}],
    )
    for rows in invalid_rows:
        payload = "\n".join(json.dumps(row) for row in rows).encode("utf-8")
        assert sca._go_findings(payload, 10)[2] == "schema"


def test_analyzer_constructor_request_aliases_and_runner_failures(tmp_path: Path) -> None:
    runner = lambda *args, **kwargs: sca.ProcessResult(0)  # noqa: E731
    with pytest.raises(ValueError, match="only one"):
        sca.SoftwareCompositionAnalyzer(process_runner=runner, runner=runner)

    assert sca._requested_ecosystems(None, ("python",)) == (("python",), ())
    requested, errors = sca._requested_ecosystems(["pip", "nodejs", "golang", 1, "rust"], ())
    assert requested == ("python", "npm", "go")
    assert errors == ("requested_ecosystem_invalid",)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "requirements.txt").write_text("demo==1.0\n", encoding="ascii")
    missing = sca.SoftwareCompositionAnalyzer(executable_resolver=lambda _name: None).run(workspace)
    assert "python_engine_missing" in missing.control_errors

    def resolver_failure(_name: str) -> str | None:
        raise OSError("resolver failed")

    failed = sca.SoftwareCompositionAnalyzer(process_runner=runner, executable_resolver=resolver_failure).run(workspace)
    assert "python_engine_missing" in failed.control_errors

    for error_type, expected in (
        (FileNotFoundError, "python_engine_missing"),
        (OSError, "python_engine_launch_failed"),
        (RuntimeError, "python_engine_launch_failed"),
    ):
        def raising(*_args: Any, exception: type[Exception] = error_type, **_kwargs: Any) -> Any:
            raise exception("runner failed")

        run = sca.SoftwareCompositionAnalyzer(process_runner=raising).run(workspace)
        assert expected in run.control_errors


def test_public_sca_wrapper_and_audit_argv_contract(tmp_path: Path) -> None:
    source = _input_file(tmp_path)
    unit = sca._AuditUnit("python", "locked_project", tmp_path, source)
    with pytest.raises(ValueError, match="normalized lock"):
        sca.SoftwareCompositionAnalyzer._audit_argv("python", "pip-audit", unit)
    assert sca.SoftwareCompositionAnalyzer._audit_argv("npm", "npm", unit) == [
        "npm",
        "audit",
        "--json",
        "--package-lock-only",
    ]
    assert sca.SoftwareCompositionAnalyzer._audit_argv("go", "govulncheck", unit) == [
        "govulncheck",
        "-json",
        "./...",
    ]

    report = sca.analyze_software_composition(
        tmp_path,
        ecosystems="rust",
        process_runner=lambda *args, **kwargs: sca.ProcessResult(0),
    )
    assert report["complete"] is False
    assert report["control_errors"] == ["requested_ecosystem_invalid"]


def test_repository_sca_does_not_trust_test_fixture_paths_as_an_exclusion(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    fixture = repository / "tests" / "fixtures" / "go-case"
    fixture.mkdir(parents=True)
    (fixture / "go.mod").write_text("module example.test/fixture\n\ngo 1.24\n", encoding="utf-8")
    (fixture / "go.sum").write_text("example.test/demo v1.0.0 h1:test\n", encoding="utf-8")

    repository_state = sca._discover(repository, sca.ScaBounds())
    direct_state = sca._discover(fixture, sca.ScaBounds())

    assert repository_state.detected_ecosystems == ("go",)
    assert repository_state.inventory["excluded_test_fixture_manifest_count"] == 0
    assert repository_state.inventory["manifest_count"] == 1
    assert repository_state.inventory["lock_count"] == 1
    assert direct_state.detected_ecosystems == ("go",)
    assert direct_state.inventory["excluded_test_fixture_manifest_count"] == 0


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("Cargo.toml", "[package]\nname='demo'\nversion='0.1.0'\n"),
        ("pom.xml", "<project/>\n"),
        ("composer.lock", "{}\n"),
        ("Demo.csproj", "<Project/>\n"),
    ],
)
def test_unsupported_dependency_ecosystem_fails_closed(tmp_path: Path, name: str, content: str) -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")

    report = sca.analyze_software_composition(
        tmp_path,
        process_runner=lambda *args, **kwargs: sca.ProcessResult(0),
    )

    assert report["complete"] is False
    assert sca.CONTROL_UNSUPPORTED_ECOSYSTEM in report["control_errors"]
    assert report["inventory"]["unsupported_manifest_count"] == 1
