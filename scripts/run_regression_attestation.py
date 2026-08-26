from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as element_tree
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from capture_supervisor_target import capture_target


SCHEMA = "k_guard_regression_attestation.v1"
LAUNCH_SCHEMA = "k_guard_regression_attestation_launch.v1"
RECEIPT_NAME = "regression-attestation.json"
LAUNCH_NAME = "regression-attestation-launch.json"
MAX_TIMEOUT_SECONDS = 90 * 60
MAX_SELECTORS = 128
MAX_SELECTOR_LENGTH = 512
MAX_JUNIT_BYTES = 16 * 1024 * 1024
MAX_LOG_BYTES = 16 * 1024 * 1024


class RegressionAttestationError(ValueError):
    pass


ProcessRunner = Callable[[Sequence[str], Path, Any, Any], subprocess.Popen[bytes]]
TargetCapturer = Callable[[Path], Mapping[str, str]]


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("ascii")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(_canonical_bytes(payload))
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)


def _outside_repository(path: Path) -> Path:
    rendered = str(path)
    if not rendered or "\x00" in rendered:
        raise RegressionAttestationError("run_directory_invalid")
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        return resolved
    raise RegressionAttestationError("run_directory_must_be_outside_repository")


def _prepare_run_directory(value: str | Path) -> Path:
    directory = _outside_repository(Path(value))
    try:
        directory.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise RegressionAttestationError("run_directory_already_exists") from exc
    except OSError as exc:
        raise RegressionAttestationError("run_directory_unavailable") from exc
    return directory.resolve(strict=True)


def _existing_run_directory(value: str | Path) -> Path:
    directory = _outside_repository(Path(value))
    if not directory.is_dir() or directory.is_symlink():
        raise RegressionAttestationError("run_directory_unavailable")
    return directory.resolve(strict=True)


def _validate_selector(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_SELECTOR_LENGTH or "\x00" in value:
        raise RegressionAttestationError("test_selector_invalid")
    if value.startswith("-") or "\\" in value:
        raise RegressionAttestationError("test_selector_invalid")
    file_part = value.split("::", 1)[0]
    relative = Path(file_part)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise RegressionAttestationError("test_selector_invalid")
    candidate = (ROOT / relative).resolve(strict=False)
    try:
        candidate.relative_to(ROOT.resolve(strict=True))
    except ValueError as exc:
        raise RegressionAttestationError("test_selector_invalid") from exc
    if candidate.suffix != ".py" or not candidate.is_file() or candidate.is_symlink():
        raise RegressionAttestationError("test_selector_invalid")
    return value


def normalize_selectors(values: Sequence[str]) -> tuple[str, ...]:
    if len(values) > MAX_SELECTORS:
        raise RegressionAttestationError("test_selector_count_exceeded")
    normalized = tuple(_validate_selector(value) for value in values)
    if len(set(normalized)) != len(normalized):
        raise RegressionAttestationError("test_selector_duplicate")
    return normalized


def selector_binding(selectors: Sequence[str]) -> dict[str, Any]:
    normalized = normalize_selectors(selectors)
    return {
        "scope": "full" if not normalized else "focused",
        "selector_count": len(normalized),
        "selector_sha256": _sha256_bytes("\n".join(normalized).encode("utf-8")),
    }


def _require_launch(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema", "pid", "selector_binding", "raw_returned"}:
        raise RegressionAttestationError("launch_receipt_invalid")
    if value["schema"] != LAUNCH_SCHEMA or value["raw_returned"] is not False:
        raise RegressionAttestationError("launch_receipt_invalid")
    if not isinstance(value["pid"], int) or value["pid"] < 0:
        raise RegressionAttestationError("launch_receipt_invalid")
    binding = value["selector_binding"]
    if not isinstance(binding, dict) or set(binding) != {"scope", "selector_count", "selector_sha256"}:
        raise RegressionAttestationError("launch_receipt_invalid")
    if binding["scope"] not in {"full", "focused"}:
        raise RegressionAttestationError("launch_receipt_invalid")
    if not isinstance(binding["selector_count"], int) or not 0 <= binding["selector_count"] <= MAX_SELECTORS:
        raise RegressionAttestationError("launch_receipt_invalid")
    if not isinstance(binding["selector_sha256"], str) or len(binding["selector_sha256"]) != 64:
        raise RegressionAttestationError("launch_receipt_invalid")
    return value


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegressionAttestationError("receipt_unreadable") from exc


def _read_launch(directory: Path) -> dict[str, Any]:
    path = directory / LAUNCH_NAME
    if not path.is_file() or path.is_symlink():
        raise RegressionAttestationError("launch_receipt_unavailable")
    return _require_launch(_read_json(path))


def _bounded_size(path: Path, maximum: int, *, label: str) -> tuple[int, str]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise RegressionAttestationError(f"{label}_unavailable") from exc
    if size < 0 or size > maximum:
        raise RegressionAttestationError(f"{label}_size_limit_exceeded")
    return size, _sha256_file(path)


def _integer_attribute(element: element_tree.Element, name: str) -> int:
    raw = element.attrib.get(name, "0")
    try:
        value = int(raw)
    except ValueError as exc:
        raise RegressionAttestationError("junit_summary_invalid") from exc
    if value < 0 or value > 10_000_000:
        raise RegressionAttestationError("junit_summary_invalid")
    return value


def junit_summary(path: Path) -> dict[str, int]:
    _bounded_size(path, MAX_JUNIT_BYTES, label="junit")
    try:
        root = element_tree.parse(path).getroot()
    except (OSError, element_tree.ParseError) as exc:
        raise RegressionAttestationError("junit_summary_invalid") from exc
    if root.tag not in {"testsuites", "testsuite"}:
        raise RegressionAttestationError("junit_summary_invalid")
    if root.tag == "testsuites" and "tests" not in root.attrib:
        suites = [item for item in root if item.tag == "testsuite"]
        if not suites:
            raise RegressionAttestationError("junit_summary_invalid")
        total = sum(_integer_attribute(item, "tests") for item in suites)
        failures = sum(_integer_attribute(item, "failures") for item in suites)
        errors = sum(_integer_attribute(item, "errors") for item in suites)
        skipped = sum(_integer_attribute(item, "skipped") for item in suites)
    else:
        total = _integer_attribute(root, "tests")
        failures = _integer_attribute(root, "failures")
        errors = _integer_attribute(root, "errors")
        skipped = _integer_attribute(root, "skipped")
    if failures + errors + skipped > total:
        raise RegressionAttestationError("junit_summary_invalid")
    return {
        "total": total,
        "passed": total - failures - errors - skipped,
        "failed": failures,
        "errors": errors,
        "skipped": skipped,
    }


def _default_process_runner(argv: Sequence[str], cwd: Path, stdout: Any, stderr: Any) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        list(argv),
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=stderr,
        shell=False,
    )


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    try:
        process.kill()
    except OSError:
        pass
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=20,
            )
        except (OSError, subprocess.SubprocessError):
            pass


def _receipt_hash(payload: Mapping[str, Any]) -> str:
    return _sha256_bytes(_canonical_bytes({key: value for key, value in payload.items() if key != "receipt_sha256"}))


def _build_receipt(
    *,
    binding: Mapping[str, Any],
    target_before: Mapping[str, str],
    target_after: Mapping[str, str],
    duration_ms: int,
    process_returncode: int | None,
    process_timed_out: bool,
    stdout_size: int,
    stdout_sha256: str,
    stderr_size: int,
    stderr_sha256: str,
    junit_size: int | None,
    junit_sha256: str | None,
    summary: Mapping[str, int] | None,
    control_errors: Sequence[str],
) -> dict[str, Any]:
    errors = sorted(set(control_errors))
    tests_passed = (
        not errors
        and process_returncode == 0
        and summary is not None
        and summary["failed"] == 0
        and summary["errors"] == 0
    )
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "COMPLETE" if tests_passed else "CONTROL_HOLD",
        "complete": process_returncode is not None and not process_timed_out,
        "selector_binding": dict(binding),
        "target_before": dict(target_before),
        "target_after": dict(target_after),
        "test_run": {
            "duration_ms": duration_ms,
            "process_returncode": process_returncode,
            "process_timed_out": process_timed_out,
            "stdout_byte_count": stdout_size,
            "stdout_sha256": stdout_sha256,
            "stderr_byte_count": stderr_size,
            "stderr_sha256": stderr_sha256,
            "junit_byte_count": junit_size,
            "junit_sha256": junit_sha256,
            "summary": dict(summary) if summary is not None else None,
            "all_tests_passed": tests_passed,
        },
        "control_errors": errors,
        "claim_boundary": {
            "product_accuracy_proven": False,
            "release_gate_passed": False,
            "raw_returned": False,
        },
        "raw_returned": False,
    }
    payload["receipt_sha256"] = _receipt_hash(payload)
    return payload


def run_worker(
    directory: Path,
    selectors: Sequence[str],
    *,
    runner: ProcessRunner = _default_process_runner,
    target_capturer: TargetCapturer = capture_target,
    timeout_seconds: float = MAX_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    if timeout_seconds <= 0 or timeout_seconds > MAX_TIMEOUT_SECONDS:
        raise RegressionAttestationError("timeout_invalid")
    run_directory = _existing_run_directory(directory)
    normalized = normalize_selectors(selectors)
    binding = selector_binding(normalized)
    launch = _read_launch(run_directory)
    if launch["selector_binding"] != binding:
        raise RegressionAttestationError("launch_selector_binding_mismatch")

    target_before = dict(target_capturer(ROOT))
    running_payload = {
        "schema": SCHEMA,
        "status": "RUNNING",
        "complete": False,
        "selector_binding": binding,
        "target_before": target_before,
        "raw_returned": False,
    }
    _atomic_write_json(run_directory / RECEIPT_NAME, running_payload)

    started = time.monotonic()
    process_returncode: int | None = None
    process_timed_out = False
    control_errors: list[str] = []
    summary: dict[str, int] | None = None
    junit_size: int | None = None
    junit_sha256: str | None = None

    with tempfile.TemporaryDirectory(prefix="k-guard-regression-") as temporary_name:
        temporary = Path(temporary_name)
        junit_path = temporary / "results.xml"
        stdout_path = temporary / "stdout.bin"
        stderr_path = temporary / "stderr.bin"
        argv = [sys.executable, "-m", "pytest", "-q", *normalized, f"--junitxml={junit_path}"]
        try:
            with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                process = runner(argv, ROOT, stdout, stderr)
                try:
                    process_returncode = int(process.wait(timeout=timeout_seconds))
                except subprocess.TimeoutExpired:
                    process_timed_out = True
                    control_errors.append("pytest_timeout")
                    _terminate_process_tree(process)
                    process_returncode = int(process.wait())
        except (OSError, subprocess.SubprocessError, ValueError):
            control_errors.append("pytest_launch_or_execution_failed")

        try:
            stdout_size, stdout_sha256 = _bounded_size(stdout_path, MAX_LOG_BYTES, label="stdout")
        except RegressionAttestationError as exc:
            control_errors.append(str(exc))
            stdout_size, stdout_sha256 = 0, _sha256_bytes(b"")
        try:
            stderr_size, stderr_sha256 = _bounded_size(stderr_path, MAX_LOG_BYTES, label="stderr")
        except RegressionAttestationError as exc:
            control_errors.append(str(exc))
            stderr_size, stderr_sha256 = 0, _sha256_bytes(b"")
        try:
            junit_size, junit_sha256 = _bounded_size(junit_path, MAX_JUNIT_BYTES, label="junit")
            summary = junit_summary(junit_path)
        except RegressionAttestationError as exc:
            control_errors.append(str(exc))

    target_after = dict(target_capturer(ROOT))
    if target_before != target_after:
        control_errors.append("target_changed_during_regression")
    if process_returncode is None:
        control_errors.append("pytest_returncode_unavailable")
    elif process_returncode != 0:
        control_errors.append("pytest_nonzero_exit")
    if summary is not None and (summary["failed"] or summary["errors"]):
        control_errors.append("junit_reported_failure")
    if summary is None:
        control_errors.append("junit_summary_unavailable")

    receipt = _build_receipt(
        binding=binding,
        target_before=target_before,
        target_after=target_after,
        duration_ms=round((time.monotonic() - started) * 1000),
        process_returncode=process_returncode,
        process_timed_out=process_timed_out,
        stdout_size=stdout_size,
        stdout_sha256=stdout_sha256,
        stderr_size=stderr_size,
        stderr_sha256=stderr_sha256,
        junit_size=junit_size,
        junit_sha256=junit_sha256,
        summary=summary,
        control_errors=control_errors,
    )
    _atomic_write_json(run_directory / RECEIPT_NAME, receipt)
    return receipt


def prepare_run(directory_value: str | Path, selectors: Sequence[str]) -> tuple[Path, dict[str, Any]]:
    normalized = normalize_selectors(selectors)
    binding = selector_binding(normalized)
    directory = _prepare_run_directory(directory_value)
    launch = {
        "schema": LAUNCH_SCHEMA,
        "pid": 0,
        "selector_binding": binding,
        "raw_returned": False,
    }
    # The worker validates this binding before it starts pytest, so persist it before execution.
    _atomic_write_json(directory / LAUNCH_NAME, launch)
    return directory, launch


def start_run(directory_value: str | Path, selectors: Sequence[str]) -> dict[str, Any]:
    directory, launch = prepare_run(directory_value, selectors)
    normalized = normalize_selectors(selectors)
    worker_argv = [sys.executable, str(Path(__file__).resolve()), "worker", "--run-dir", str(directory)]
    for selector in normalized:
        worker_argv.extend(("--test", selector))
    popen_kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "cwd": str(ROOT),
        "shell": False,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    try:
        process = subprocess.Popen(worker_argv, **popen_kwargs)
    except OSError as exc:
        (directory / LAUNCH_NAME).unlink(missing_ok=True)
        directory.rmdir()
        raise RegressionAttestationError("worker_launch_failed") from exc
    launch["pid"] = int(process.pid)
    _atomic_write_json(directory / LAUNCH_NAME, launch)
    return launch


def run_foreground(directory_value: str | Path, selectors: Sequence[str]) -> dict[str, Any]:
    directory, _ = prepare_run(directory_value, selectors)
    return run_worker(directory, selectors)


def status(directory_value: str | Path) -> dict[str, Any]:
    directory = _existing_run_directory(directory_value)
    receipt_path = directory / RECEIPT_NAME
    if receipt_path.is_file() and not receipt_path.is_symlink():
        value = _read_json(receipt_path)
        if isinstance(value, dict):
            return value
        raise RegressionAttestationError("receipt_unreadable")
    launch = _read_launch(directory)
    return {
        "schema": SCHEMA,
        "status": "QUEUED",
        "complete": False,
        "selector_binding": launch["selector_binding"],
        "raw_returned": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run pytest in a durable, raw-free regression-attestation carrier."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("start", "run", "worker"):
        command = subparsers.add_parser(name)
        command.add_argument("--run-dir", required=True)
        command.add_argument("--test", action="append", default=[])
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--run-dir", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "start":
            payload = start_run(args.run_dir, args.test)
        elif args.command == "run":
            payload = run_foreground(args.run_dir, args.test)
        elif args.command == "worker":
            payload = run_worker(Path(args.run_dir), args.test)
        else:
            payload = status(args.run_dir)
    except RegressionAttestationError as exc:
        print(json.dumps({"status": "CONTROL_HOLD", "control_errors": [str(exc)], "raw_returned": False}, sort_keys=True))
        return 2
    print(json.dumps(payload, ensure_ascii=True, sort_keys=True))
    if args.command == "start" or payload.get("status") in {"COMPLETE", "QUEUED", "RUNNING"}:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
