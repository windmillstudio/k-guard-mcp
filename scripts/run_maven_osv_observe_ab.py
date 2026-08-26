from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from capture_supervisor_target import capture_target
from seal_current_baseline import _load_canonical_receipt, validate_current_baseline


SCHEMA = "k_guard_maven_osv_observe_ab.v1"
HYPOTHESIS_ID = "H5A"
DEFAULT_EXPECTED_CVE = "CVE-2013-7285"
DEFAULT_OLD_VERSION = "1.4.5"
DEFAULT_NEW_VERSION = "1.4.7"
MAX_POM_BYTES = 2 * 1024 * 1024
MAX_ENGINE_BYTES = 256 * 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 300.0
VERSION_RE = re.compile(r"(?m)^osv-scanner version:\s*([0-9]+\.[0-9]+\.[0-9]+)\s*$")
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class ObservationError(ValueError):
    pass


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_bytes: int
    stderr_bytes: int
    timed_out: bool = False
    output_limited: bool = False
    launch_error: str = ""


ProcessRunner = Callable[[Sequence[str], Path, float, int], ProcessResult]


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("ascii")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _safe_regular_file(value: str | Path, *, label: str, maximum_bytes: int) -> Path:
    rendered = str(value)
    if not rendered or "\x00" in rendered:
        raise ObservationError(f"{label}_path_invalid")
    path = Path(rendered)
    try:
        if path.is_symlink() or not path.is_file():
            raise ObservationError(f"{label}_not_regular_file")
        resolved = path.resolve(strict=True)
        if resolved.is_symlink() or not resolved.is_file():
            raise ObservationError(f"{label}_not_regular_file")
        if resolved.stat().st_size > maximum_bytes:
            raise ObservationError(f"{label}_size_limit_exceeded")
    except OSError as exc:
        raise ObservationError(f"{label}_unavailable") from exc
    return resolved


def _read_bounded(path: Path, *, label: str, maximum_bytes: int) -> bytes:
    try:
        before = path.stat()
        if before.st_size > maximum_bytes:
            raise ObservationError(f"{label}_size_limit_exceeded")
        with path.open("rb") as stream:
            raw = stream.read(maximum_bytes + 1)
        after = path.stat()
    except OSError as exc:
        raise ObservationError(f"{label}_unavailable") from exc
    if len(raw) > maximum_bytes:
        raise ObservationError(f"{label}_size_limit_exceeded")
    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        raise ObservationError(f"{label}_changed_during_read")
    return raw


def _file_ref(path: Path, raw: bytes) -> dict[str, Any]:
    return {
        "sha256": _sha256_bytes(raw),
        "byte_count": len(raw),
        "raw_returned": False,
    }


def _run_process(argv: Sequence[str], cwd: Path, timeout_seconds: float, maximum_bytes: int) -> ProcessResult:
    if not argv or timeout_seconds <= 0 or timeout_seconds > MAX_TIMEOUT_SECONDS:
        raise ObservationError("process_contract_invalid")
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                process = subprocess.Popen(
                    list(argv),
                    cwd=str(cwd),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    shell=False,
                )
            except FileNotFoundError:
                return ProcessResult(-1, b"", b"", 0, 0, launch_error="missing")
            except OSError:
                return ProcessResult(-1, b"", b"", 0, 0, launch_error="os_error")
            timed_out = False
            try:
                returncode = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                returncode = process.wait()
            stdout.seek(0, os.SEEK_END)
            stdout_bytes = stdout.tell()
            stderr.seek(0, os.SEEK_END)
            stderr_bytes = stderr.tell()
            stdout.seek(0)
            stderr.seek(0)
            output_limited = stdout_bytes > maximum_bytes or stderr_bytes > maximum_bytes
            return ProcessResult(
                int(returncode),
                stdout.read(maximum_bytes + 1)[:maximum_bytes],
                stderr.read(maximum_bytes + 1)[:maximum_bytes],
                stdout_bytes,
                stderr_bytes,
                timed_out=timed_out,
                output_limited=output_limited,
            )
    except OSError as exc:
        raise ObservationError("process_execution_failed") from exc


def _require_success(result: ProcessResult, *, label: str) -> None:
    if result.launch_error:
        raise ObservationError(f"{label}_engine_{result.launch_error}")
    if result.timed_out:
        raise ObservationError(f"{label}_timed_out")
    if result.output_limited:
        raise ObservationError(f"{label}_output_limit_exceeded")
    if result.returncode != 0:
        raise ObservationError(f"{label}_nonzero_exit")


def _engine_version(binary: Path, runner: ProcessRunner, timeout_seconds: float) -> str:
    result = runner((str(binary), "--version"), binary.parent, min(timeout_seconds, 30.0), 64 * 1024)
    _require_success(result, label="engine_version")
    try:
        text = result.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ObservationError("engine_version_encoding_invalid") from exc
    match = VERSION_RE.search(text)
    if not match:
        raise ObservationError("engine_version_unavailable")
    return match.group(1)


def _safe_string(value: Any, *, label: str, maximum_length: int = 1024) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > maximum_length:
        raise ObservationError(f"osv_{label}_invalid")
    return value


def _normalized_severity(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    normalized = value.strip().casefold()
    if normalized == "critical":
        return "critical"
    if normalized == "high":
        return "high"
    if normalized in {"moderate", "medium"}:
        return "medium"
    if normalized == "low":
        return "low"
    return "unknown"


def _observed_severity(vulnerability: dict[str, Any]) -> str:
    database = vulnerability.get("database_specific")
    if isinstance(database, dict):
        return _normalized_severity(database.get("severity"))
    return "unknown"


def _parse_osv_output(raw: bytes, *, expected_cve: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ObservationError("osv_json_invalid") from exc
    if not isinstance(payload, dict) or set(payload) - {"experimental_config", "results"}:
        raise ObservationError("osv_root_schema_invalid")
    results = payload.get("results")
    if not isinstance(results, list):
        raise ObservationError("osv_results_schema_invalid")

    expected_matches: list[dict[str, str]] = []
    package_count = 0
    vulnerability_count = 0
    for result in results:
        if not isinstance(result, dict) or set(result) - {"source", "packages", "groups"}:
            raise ObservationError("osv_result_schema_invalid")
        packages = result.get("packages", [])
        if not isinstance(packages, list):
            raise ObservationError("osv_packages_schema_invalid")
        for package_row in packages:
            if not isinstance(package_row, dict) or set(package_row) - {"package", "vulnerabilities", "groups"}:
                raise ObservationError("osv_package_schema_invalid")
            package = package_row.get("package")
            vulnerabilities = package_row.get("vulnerabilities", [])
            if not isinstance(package, dict) or not isinstance(vulnerabilities, list):
                raise ObservationError("osv_package_schema_invalid")
            name = _safe_string(package.get("name"), label="package_name")
            version = _safe_string(package.get("version"), label="package_version")
            ecosystem = _safe_string(package.get("ecosystem"), label="package_ecosystem")
            package_count += 1
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    raise ObservationError("osv_vulnerability_schema_invalid")
                identifier = _safe_string(vulnerability.get("id"), label="vulnerability_id")
                aliases = vulnerability.get("aliases", [])
                if not isinstance(aliases, list) or any(not isinstance(item, str) for item in aliases):
                    raise ObservationError("osv_alias_schema_invalid")
                vulnerability_count += 1
                identifiers = {identifier.upper(), *(item.upper() for item in aliases)}
                if expected_cve not in identifiers:
                    continue
                expected_matches.append(
                    {
                        "package_ref_sha256": _sha256_text(name),
                        "version_ref_sha256": _sha256_text(version),
                        "ecosystem_ref_sha256": _sha256_text(ecosystem),
                        "severity": _observed_severity(vulnerability),
                    }
                )

    expected_matches.sort(
        key=lambda item: (
            item["package_ref_sha256"],
            item["version_ref_sha256"],
            item["ecosystem_ref_sha256"],
            item["severity"],
        )
    )
    return {
        "result_count": len(results),
        "package_count": package_count,
        "vulnerability_count": vulnerability_count,
        "expected_cve_match_count": len(expected_matches),
        "expected_cve_matches": expected_matches,
        "raw_returned": False,
    }


def _scan_projection(
    binary: Path,
    pom: Path,
    config: Path,
    expected_cve: str,
    runner: ProcessRunner,
    timeout_seconds: float,
) -> dict[str, Any]:
    argv = (
        str(binary),
        "scan",
        "source",
        "--format",
        "json",
        "--no-resolve",
        "--lockfile",
        str(pom),
        "--config",
        str(config),
        "--verbosity",
        "error",
    )
    result = runner(argv, config.parent, timeout_seconds, MAX_OUTPUT_BYTES)
    if result.launch_error:
        raise ObservationError(f"osv_scan_engine_{result.launch_error}")
    if result.timed_out:
        raise ObservationError("osv_scan_timed_out")
    if result.output_limited:
        raise ObservationError("osv_scan_output_limit_exceeded")
    if result.returncode not in {0, 1}:
        raise ObservationError("osv_scan_unexpected_exit")
    parsed = _parse_osv_output(result.stdout, expected_cve=expected_cve)
    return {
        "exit_code": result.returncode,
        "stdout_sha256": _sha256_bytes(result.stdout),
        "stdout_byte_count": result.stdout_bytes,
        "stderr_sha256": _sha256_bytes(result.stderr),
        "stderr_byte_count": result.stderr_bytes,
        **parsed,
        "raw_returned": False,
    }


def _derive_negative_pom(positive: bytes, *, old_version: str, new_version: str) -> tuple[bytes, dict[str, Any]]:
    if not SEMVER_RE.fullmatch(old_version) or not SEMVER_RE.fullmatch(new_version) or old_version == new_version:
        raise ObservationError("version_mutation_contract_invalid")
    needle = f"<xstream.version>{old_version}</xstream.version>".encode("ascii")
    replacement = f"<xstream.version>{new_version}</xstream.version>".encode("ascii")
    occurrence_count = positive.count(needle)
    if occurrence_count != 1:
        raise ObservationError("positive_pom_expected_xstream_property_not_exactly_once")
    negative = positive.replace(needle, replacement, 1)
    return negative, {
        "kind": "single_exact_xstream_property_replacement",
        "old_version_ref_sha256": _sha256_text(old_version),
        "new_version_ref_sha256": _sha256_text(new_version),
        "occurrence_count": occurrence_count,
        "raw_returned": False,
    }


def _semantic_projection(run: dict[str, Any]) -> dict[str, Any]:
    return {
        "positive": {
            key: run["positive"][key]
            for key in (
                "exit_code",
                "result_count",
                "package_count",
                "vulnerability_count",
                "expected_cve_match_count",
                "expected_cve_matches",
            )
        },
        "negative": {
            key: run["negative"][key]
            for key in (
                "exit_code",
                "result_count",
                "package_count",
                "vulnerability_count",
                "expected_cve_match_count",
                "expected_cve_matches",
            )
        },
    }


def _control_hold(reason: str, *, expected_cve: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "hypothesis": {
            "id": HYPOTHESIS_ID,
            "stage": "observe",
            "warning_promotion_admitted": False,
            "blocking_promotion_admitted": False,
        },
        "expected_cve": expected_cve,
        "complete": False,
        "status": "CONTROL_HOLD",
        "control_errors": [reason],
        "claim_boundary": {
            "machine_oracle_pair_ready": False,
            "k_guard_maven_sca_added": False,
            "guardian_policy_changed": False,
            "product_precision_or_recall_claimed": False,
            "release_gate_passed": False,
            "raw_returned": False,
        },
        "raw_returned": False,
    }


def _outside_repository(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT.resolve(strict=True))
    except ValueError:
        return True
    return False


def measure_h5a(
    positive_pom: str | Path,
    scanner: str | Path,
    *,
    expected_positive_sha256: str,
    expected_cve: str = DEFAULT_EXPECTED_CVE,
    old_version: str = DEFAULT_OLD_VERSION,
    new_version: str = DEFAULT_NEW_VERSION,
    timeout_seconds: float = 120.0,
    runner: ProcessRunner = _run_process,
) -> dict[str, Any]:
    normalized_cve = str(expected_cve).upper()
    if not CVE_RE.fullmatch(normalized_cve):
        return _control_hold("expected_cve_invalid", expected_cve=normalized_cve)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_positive_sha256):
        return _control_hold("expected_positive_sha256_invalid", expected_cve=normalized_cve)
    if timeout_seconds <= 0 or timeout_seconds > MAX_TIMEOUT_SECONDS:
        return _control_hold("timeout_contract_invalid", expected_cve=normalized_cve)
    try:
        binary = _safe_regular_file(scanner, label="scanner", maximum_bytes=MAX_ENGINE_BYTES)
        source = _safe_regular_file(positive_pom, label="positive_pom", maximum_bytes=MAX_POM_BYTES)
        positive_raw = _read_bounded(source, label="positive_pom", maximum_bytes=MAX_POM_BYTES)
        positive_ref = _file_ref(source, positive_raw)
        if positive_ref["sha256"] != expected_positive_sha256:
            raise ObservationError("positive_pom_sha256_mismatch")
        binary_raw = _read_bounded(binary, label="scanner", maximum_bytes=MAX_ENGINE_BYTES)
        negative_raw, mutation = _derive_negative_pom(
            positive_raw,
            old_version=old_version,
            new_version=new_version,
        )
        version = _engine_version(binary, runner, timeout_seconds)
        with tempfile.TemporaryDirectory(prefix="k-guard-h5a-") as temporary:
            root = Path(temporary)
            config = root / "k-guard-observer.toml"
            config.write_bytes(b"# fixed empty observer configuration\n")
            negative = root / "pom.xml"
            negative.write_bytes(negative_raw)
            runs: list[dict[str, Any]] = []
            for run_index in range(1, 3):
                runs.append(
                    {
                        "run_index": run_index,
                        "positive": _scan_projection(
                            binary,
                            source,
                            config,
                            normalized_cve,
                            runner,
                            timeout_seconds,
                        ),
                        "negative": _scan_projection(
                            binary,
                            negative,
                            config,
                            normalized_cve,
                            runner,
                            timeout_seconds,
                        ),
                        "raw_returned": False,
                    }
                )
        semantics = [_semantic_projection(run) for run in runs]
        raw_output_exact = (
            runs[0]["positive"]["stdout_sha256"] == runs[1]["positive"]["stdout_sha256"]
            and runs[0]["negative"]["stdout_sha256"] == runs[1]["negative"]["stdout_sha256"]
        )
        semantic_exact = semantics[0] == semantics[1]
        positive_exactly_once = all(run["positive"]["expected_cve_match_count"] == 1 for run in runs)
        negative_absent = all(run["negative"]["expected_cve_match_count"] == 0 for run in runs)
        oracle_pair_admitted = semantic_exact and positive_exactly_once and negative_absent
        return {
            "schema": SCHEMA,
            "hypothesis": {
                "id": HYPOTHESIS_ID,
                "stage": "observe",
                "warning_promotion_admitted": False,
                "blocking_promotion_admitted": False,
            },
            "expected_cve": normalized_cve,
            "engine": {
                "name": "osv-scanner",
                "version": version,
                "binary_sha256": _sha256_bytes(binary_raw),
                "binary_byte_count": len(binary_raw),
                "command_contract": [
                    "{engine}",
                    "scan",
                    "source",
                    "--format",
                    "json",
                    "--no-resolve",
                    "--lockfile",
                    "{pom}",
                    "--config",
                    "{controlled-empty-config}",
                    "--verbosity",
                    "error",
                ],
                "transitive_resolution": False,
                "raw_returned": False,
            },
            "inputs": {
                "positive_pom": positive_ref,
                "negative_pom": _file_ref(Path("pom.xml"), negative_raw),
                "negative_derivation": mutation,
                "observer_sha256": _sha256_bytes(Path(__file__).read_bytes()),
                "raw_returned": False,
            },
            "runs": runs,
            "repeat": {
                "semantic_exact": semantic_exact,
                "raw_output_exact": raw_output_exact,
                "projection_sha256": _sha256_bytes(_canonical_bytes(semantics)),
                "raw_returned": False,
            },
            "oracle": {
                "positive_expected_cve_exactly_once": positive_exactly_once,
                "negative_expected_cve_absent": negative_absent,
                "pair_admitted": oracle_pair_admitted,
                "raw_returned": False,
            },
            "complete": True,
            "status": "MEASURED_HOLD",
            "control_errors": [],
            "claim_boundary": {
                "machine_oracle_pair_ready": oracle_pair_admitted,
                "k_guard_maven_sca_added": False,
                "guardian_policy_changed": False,
                "product_precision_or_recall_claimed": False,
                "release_gate_passed": False,
                "raw_returned": False,
            },
            "raw_returned": False,
        }
    except ObservationError as exc:
        return _control_hold(str(exc), expected_cve=normalized_cve)


def _write_new(path: Path, payload: dict[str, Any]) -> None:
    target = Path(path)
    if not target.is_absolute():
        raise ObservationError("output_path_must_be_absolute")
    target.parent.mkdir(parents=True, exist_ok=True)
    raw = _canonical_bytes(payload)
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ObservationError("output_path_already_exists") from exc
    except OSError as exc:
        raise ObservationError("output_path_unavailable") from exc
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Measure one source-bound Maven XStream CVE oracle pair without promoting K-Guard or Guardian."
    )
    parser.add_argument("--positive-pom", type=Path, required=True)
    parser.add_argument("--scanner", type=Path, required=True)
    parser.add_argument("--baseline-receipt", type=Path, required=True)
    parser.add_argument("--expected-positive-sha256", required=True)
    parser.add_argument("--expected-cve", default=DEFAULT_EXPECTED_CVE)
    parser.add_argument("--old-version", default=DEFAULT_OLD_VERSION)
    parser.add_argument("--new-version", default=DEFAULT_NEW_VERSION)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    normalized_cve = str(args.expected_cve).upper()
    target: dict[str, Any] | None = None
    try:
        if not _outside_repository(args.baseline_receipt):
            raise ObservationError("baseline_receipt_must_be_external")
        if not _outside_repository(args.output):
            raise ObservationError("output_path_must_be_external")
        receipt = _load_canonical_receipt(args.baseline_receipt)
        validate_current_baseline(ROOT, receipt)
        target = capture_target(ROOT)
        report = measure_h5a(
            args.positive_pom,
            args.scanner,
            expected_positive_sha256=args.expected_positive_sha256,
            expected_cve=normalized_cve,
            old_version=args.old_version,
            new_version=args.new_version,
            timeout_seconds=args.timeout_seconds,
        )
        if capture_target(ROOT) != target:
            raise ObservationError("target_changed_during_measurement")
        report["execution_binding"] = {
            "baseline_receipt_sha256": receipt["receipt_sha256"],
            "target": target,
            "raw_returned": False,
        }
    except (ObservationError, OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        report = _control_hold(str(exc), expected_cve=normalized_cve)
    try:
        _write_new(args.output, report)
    except ObservationError as exc:
        print(json.dumps({"status": "CONTROL_HOLD", "error": str(exc), "raw_returned": False}, sort_keys=True))
        return 3
    print(
        json.dumps(
            {
                "status": report["status"],
                "complete": report["complete"],
                "pair_admitted": report.get("oracle", {}).get("pair_admitted", False),
                "report_sha256": _sha256_bytes(_canonical_bytes(report)),
                "raw_returned": False,
            },
            sort_keys=True,
        )
    )
    return 0 if report["complete"] is True and report.get("oracle", {}).get("pair_admitted") is True else 3


if __name__ == "__main__":
    raise SystemExit(main())
