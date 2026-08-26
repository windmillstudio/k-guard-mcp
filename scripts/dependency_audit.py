from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from k_guard_mcp.dependency_evidence import (
    EVIDENCE_LOCK_NAME,
    declared_dependency_scope,
    evidence_lock_report,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ACTIVE_REQUIREMENTS_LOCKS = (
    ("release_evidence_lock", EVIDENCE_LOCK_NAME),
    ("semgrep_tool_lock", "requirements-semgrep.lock"),
    ("pip_audit_tool_lock", "requirements-pip-audit.lock"),
    ("release_build_lock", "requirements-build.lock"),
)


def main() -> int:
    report_path = Path("audit-report.json")
    dependency_scope = declared_dependency_scope(PROJECT_ROOT)
    lock_report = evidence_lock_report(PROJECT_ROOT)
    audit_runs = [
        _audit_lock(PROJECT_ROOT / requirements_file, label=label, requirements_file=requirements_file)
        for label, requirements_file in ACTIVE_REQUIREMENTS_LOCKS
    ]
    report = {
        "scope": "pinned_release_evidence_dependency_closure",
        "audit_scope": "all_active_requirements_locks",
        "direct_runtime_dependencies": dependency_scope["runtime"],
        "optional_dependency_groups": dependency_scope["optional"],
        "evidence_lock": lock_report,
        "required_locks": [requirements_file for _, requirements_file in ACTIVE_REQUIREMENTS_LOCKS],
        "required_lock_count": len(ACTIVE_REQUIREMENTS_LOCKS),
        "locks_present": all((PROJECT_ROOT / requirements_file).is_file() for _, requirements_file in ACTIVE_REQUIREMENTS_LOCKS),
        "audit_runs": audit_runs,
    }
    report["pip_audit_available"] = all(run["returncode"] is not None for run in audit_runs)
    report["vulnerability_count"] = sum(int(run["vulnerability_count"]) for run in audit_runs)
    report["passed"] = (
        bool(lock_report["valid"])
        and report["locks_present"]
        and report["pip_audit_available"]
        and report["vulnerability_count"] == 0
        and all(run["returncode"] == 0 for run in audit_runs)
        and all(run["output_valid"] is True for run in audit_runs)
    )
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if not report["pip_audit_available"]:
        return 2
    return 0 if report["passed"] else 1


def _audit_lock(requirements_path: Path, *, label: str, requirements_file: str) -> dict[str, object]:
    if not requirements_path.is_file():
        return {
            "label": label,
            "requirements_file": requirements_file,
            "skipped": False,
            "returncode": 2,
            "vulnerability_count": 0,
            "pip_audit_stdout_json": {"dependencies": []},
            "pip_audit_stderr": f"{requirements_file} missing",
            "output_valid": False,
        }
    pip_audit_result = _run(
        [
            sys.executable,
            "-m",
            "pip_audit",
            "--requirement",
            str(requirements_path),
            "--format",
            "json",
        ]
    )
    audit_json = _try_json(pip_audit_result["stdout"]) or {}
    output_valid = isinstance(audit_json, dict) and isinstance(audit_json.get("dependencies"), list)
    return {
        "label": label,
        "requirements_file": requirements_file,
        "skipped": False,
        "returncode": pip_audit_result["returncode"],
        "pip_audit_stdout_json": audit_json,
        "pip_audit_stderr": pip_audit_result["stderr"][-4000:],
        "vulnerability_count": _count_vulnerabilities(audit_json) if output_valid else 0,
        "output_valid": output_valid,
    }


def _run(args: list[str]) -> dict[str, object]:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=180, check=False)
        return {"returncode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}
    except FileNotFoundError as exc:
        return {"returncode": None, "stdout": "", "stderr": str(exc)}
    except subprocess.TimeoutExpired as exc:
        return {"returncode": 124, "stdout": exc.stdout or "", "stderr": exc.stderr or "timeout"}


def _try_json(value: str):
    try:
        return json.loads(value)
    except Exception:
        return None


def _count_vulnerabilities(audit_json) -> int:
    count = 0
    for dependency in audit_json.get("dependencies", []):
        count += len(dependency.get("vulns", []))
    return count


if __name__ == "__main__":
    raise SystemExit(main())
