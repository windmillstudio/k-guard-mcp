from __future__ import annotations

import json
from pathlib import Path

from scripts import dependency_audit


def _audit_result(*, label: str, requirements_file: str, returncode: int | None = 0) -> dict[str, object]:
    return {
        "label": label,
        "requirements_file": requirements_file,
        "skipped": False,
        "returncode": returncode,
        "pip_audit_stdout_json": {"dependencies": []},
        "pip_audit_stderr": "",
        "vulnerability_count": 0,
        "output_valid": True,
    }


def _prepare_main(monkeypatch, tmp_path: Path) -> None:
    for _, requirements_file in dependency_audit.ACTIVE_REQUIREMENTS_LOCKS:
        (tmp_path / requirements_file).write_text("example==1.0\n", encoding="utf-8")
    monkeypatch.setattr(dependency_audit, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(
        dependency_audit,
        "declared_dependency_scope",
        lambda _root: {"runtime": ["example>=1"], "optional": {}},
    )
    monkeypatch.setattr(dependency_audit, "evidence_lock_report", lambda _root: {"valid": True})
    monkeypatch.chdir(tmp_path)


def test_dependency_audit_aggregates_all_active_locks(monkeypatch, tmp_path: Path) -> None:
    _prepare_main(monkeypatch, tmp_path)
    calls: list[tuple[Path, str, str]] = []

    def fake_audit(path: Path, *, label: str, requirements_file: str) -> dict[str, object]:
        calls.append((path, label, requirements_file))
        return _audit_result(label=label, requirements_file=requirements_file)

    monkeypatch.setattr(dependency_audit, "_audit_lock", fake_audit)

    assert dependency_audit.main() == 0
    report = json.loads((tmp_path / "audit-report.json").read_text(encoding="utf-8"))
    assert [(label, name) for _, label, name in calls] == list(dependency_audit.ACTIVE_REQUIREMENTS_LOCKS)
    assert report["scope"] == "pinned_release_evidence_dependency_closure"
    assert report["audit_scope"] == "all_active_requirements_locks"
    assert report["required_lock_count"] == 4
    assert report["locks_present"] is True
    assert report["vulnerability_count"] == 0
    assert report["passed"] is True


def test_dependency_audit_fails_closed_on_invalid_output(monkeypatch, tmp_path: Path) -> None:
    _prepare_main(monkeypatch, tmp_path)

    def fake_audit(path: Path, *, label: str, requirements_file: str) -> dict[str, object]:
        result = _audit_result(label=label, requirements_file=requirements_file)
        if requirements_file == "requirements-semgrep.lock":
            result["output_valid"] = False
        return result

    monkeypatch.setattr(dependency_audit, "_audit_lock", fake_audit)

    assert dependency_audit.main() == 1
    report = json.loads((tmp_path / "audit-report.json").read_text(encoding="utf-8"))
    assert report["pip_audit_available"] is True
    assert report["passed"] is False


def test_dependency_audit_sums_vulnerabilities_across_locks(monkeypatch, tmp_path: Path) -> None:
    _prepare_main(monkeypatch, tmp_path)
    counts = {
        "requirements-evidence.lock": 1,
        "requirements-semgrep.lock": 2,
        "requirements-pip-audit.lock": 3,
        "requirements-build.lock": 4,
    }

    def fake_audit(path: Path, *, label: str, requirements_file: str) -> dict[str, object]:
        result = _audit_result(label=label, requirements_file=requirements_file, returncode=1)
        result["vulnerability_count"] = counts[requirements_file]
        return result

    monkeypatch.setattr(dependency_audit, "_audit_lock", fake_audit)

    assert dependency_audit.main() == 1
    report = json.loads((tmp_path / "audit-report.json").read_text(encoding="utf-8"))
    assert report["vulnerability_count"] == 10
    assert report["passed"] is False


def test_dependency_audit_reports_unavailable_auditor(monkeypatch, tmp_path: Path) -> None:
    _prepare_main(monkeypatch, tmp_path)

    def fake_audit(path: Path, *, label: str, requirements_file: str) -> dict[str, object]:
        return _audit_result(
            label=label,
            requirements_file=requirements_file,
            returncode=None if requirements_file == "requirements-pip-audit.lock" else 0,
        )

    monkeypatch.setattr(dependency_audit, "_audit_lock", fake_audit)

    assert dependency_audit.main() == 2
    report = json.loads((tmp_path / "audit-report.json").read_text(encoding="utf-8"))
    assert report["pip_audit_available"] is False
    assert report["passed"] is False


def test_audit_lock_missing_is_labeled_and_fails_closed(tmp_path: Path) -> None:
    result = dependency_audit._audit_lock(
        tmp_path / "requirements-build.lock",
        label="release_build_lock",
        requirements_file="requirements-build.lock",
    )

    assert result["label"] == "release_build_lock"
    assert result["requirements_file"] == "requirements-build.lock"
    assert result["returncode"] == 2
    assert result["output_valid"] is False
    assert result["pip_audit_stderr"] == "requirements-build.lock missing"
