from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "run_regression_attestation.py"
SPEC = importlib.util.spec_from_file_location("run_regression_attestation_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
attestation = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = attestation
SPEC.loader.exec_module(attestation)


class _Process:
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode
        self.killed = False
        self.pid = 12345

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return self.returncode

    def kill(self) -> None:
        self.killed = True


def _target(_: Path) -> dict[str, str]:
    return {
        "head_git_oid": "a" * 40,
        "dirty_path_set_sha256": "b" * 64,
        "dirty_worktree_sha256": "c" * 64,
    }


def _runner(argv, _cwd, stdout, stderr):
    junit = next(Path(value.split("=", 1)[1]) for value in argv if value.startswith("--junitxml="))
    junit.write_text(
        '<testsuites tests="4" failures="0" errors="0" skipped="1"><testsuite /></testsuites>',
        encoding="utf-8",
    )
    stdout.write(b"raw stdout is not retained")
    stderr.write(b"")
    return _Process()


def _launch(directory: Path, selectors: tuple[str, ...] = ()) -> None:
    binding = attestation.selector_binding(selectors)
    (directory / attestation.LAUNCH_NAME).write_text(
        json.dumps(
            {
                "schema": attestation.LAUNCH_SCHEMA,
                "pid": 12345,
                "selector_binding": binding,
                "raw_returned": False,
            }
        ),
        encoding="utf-8",
    )


def test_junit_summary_rejects_impossible_counts(tmp_path: Path) -> None:
    report = tmp_path / "results.xml"
    report.write_text('<testsuites tests="2" failures="3" errors="0" skipped="0" />', encoding="utf-8")

    with pytest.raises(attestation.RegressionAttestationError, match="junit_summary_invalid"):
        attestation.junit_summary(report)


def test_junit_summary_reads_pytest_suite_counts_when_root_is_only_a_container(tmp_path: Path) -> None:
    report = tmp_path / "results.xml"
    report.write_text(
        '<testsuites><testsuite tests="4" failures="0" errors="1" skipped="1" /></testsuites>',
        encoding="utf-8",
    )

    assert attestation.junit_summary(report) == {
        "total": 4,
        "passed": 2,
        "failed": 0,
        "errors": 1,
        "skipped": 1,
    }


def test_run_worker_writes_raw_free_complete_receipt(tmp_path: Path) -> None:
    run_directory = tmp_path / "regression"
    run_directory.mkdir()
    _launch(run_directory)

    receipt = attestation.run_worker(run_directory, (), runner=_runner, target_capturer=_target)

    assert receipt["status"] == "COMPLETE"
    assert receipt["complete"] is True
    assert receipt["test_run"]["summary"] == {
        "total": 4,
        "passed": 3,
        "failed": 0,
        "errors": 0,
        "skipped": 1,
    }
    assert receipt["test_run"]["all_tests_passed"] is True
    assert receipt["claim_boundary"]["release_gate_passed"] is False
    assert "raw stdout is not retained" not in json.dumps(receipt, sort_keys=True)
    assert (run_directory / attestation.RECEIPT_NAME).is_file()


def test_run_worker_holds_when_target_changes(tmp_path: Path) -> None:
    run_directory = tmp_path / "regression"
    run_directory.mkdir()
    _launch(run_directory)
    targets = iter(
        (
            _target(ROOT),
            {
                "head_git_oid": "a" * 40,
                "dirty_path_set_sha256": "d" * 64,
                "dirty_worktree_sha256": "e" * 64,
            },
        )
    )

    receipt = attestation.run_worker(run_directory, (), runner=_runner, target_capturer=lambda _: next(targets))

    assert receipt["status"] == "CONTROL_HOLD"
    assert receipt["test_run"]["all_tests_passed"] is False
    assert receipt["control_errors"] == ["target_changed_during_regression"]


def test_selector_and_run_directory_boundaries_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(attestation.RegressionAttestationError, match="test_selector_invalid"):
        attestation.normalize_selectors(("--collect-only",))
    with pytest.raises(attestation.RegressionAttestationError, match="run_directory_must_be_outside_repository"):
        attestation._prepare_run_directory(ROOT / "tmp" / "attestation")

    outside = tmp_path / "external"
    prepared = attestation._prepare_run_directory(outside)
    assert prepared == outside.resolve()
    with pytest.raises(attestation.RegressionAttestationError, match="run_directory_already_exists"):
        attestation._prepare_run_directory(outside)


def test_start_persists_selector_binding_before_worker_launch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_directory = tmp_path / "background"
    observed: dict[str, object] = {}

    class _LaunchedProcess:
        pid = 45678

    def fake_popen(_argv, **_kwargs):
        launch = json.loads((run_directory / attestation.LAUNCH_NAME).read_text(encoding="utf-8"))
        observed["pid_before_worker"] = launch["pid"]
        observed["binding"] = launch["selector_binding"]
        return _LaunchedProcess()

    monkeypatch.setattr(attestation.subprocess, "Popen", fake_popen)

    launch = attestation.start_run(run_directory, ())

    assert observed["pid_before_worker"] == 0
    assert observed["binding"] == attestation.selector_binding(())
    assert launch["pid"] == 45678
    assert json.loads((run_directory / attestation.LAUNCH_NAME).read_text(encoding="utf-8"))["pid"] == 45678


def test_prepare_run_writes_a_foreground_launch_receipt(tmp_path: Path) -> None:
    run_directory = tmp_path / "foreground"

    directory, launch = attestation.prepare_run(run_directory, ())

    assert directory == run_directory.resolve()
    assert launch["pid"] == 0
    assert attestation.status(run_directory)["status"] == "QUEUED"


def test_cli_exposes_start_worker_and_status_without_raw_log_arguments() -> None:
    completed = __import__("subprocess").run(
        [sys.executable, str(SCRIPT), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "start" in completed.stdout
    assert "run" in completed.stdout
    assert "worker" in completed.stdout
    assert "status" in completed.stdout
    assert "--raw-log" not in completed.stdout
