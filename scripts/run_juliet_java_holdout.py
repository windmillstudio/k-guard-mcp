from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from k_guard_mcp.java_flow import JavaFlowParseError, scan_java_sql_flows  # noqa: E402


PREREG_SCHEMA = "k_guard_public_holdout_preregistration.v1"
REPORT_SCHEMA = "k_guard_juliet_java_holdout_result.v1"
WORKER_SCHEMA = "k_guard_juliet_java_holdout_worker.v1"
ARCHIVE_SHA256 = "d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60"
SOURCE_FAMILIES = ("getCookies_Servlet", "getParameter_Servlet", "getQueryString_Servlet")
SINK_FAMILIES = ("execute", "executeBatch", "executeQuery", "executeUpdate", "prepareStatement")
FLOW_VARIANTS = ("01", "02", "03", "04", "05", "06", "07", "08", "15", "16", "17", "31", "41", "42")
CASE_RE = re.compile(
    r"^CWE89_SQL_Injection__(?P<source>getCookies_Servlet|getParameter_Servlet|getQueryString_Servlet)_"
    r"(?P<sink>executeBatch|executeQuery|executeUpdate|prepareStatement|execute)_"
    r"(?P<variant>01|02|03|04|05|06|07|08|15|16|17|31|41|42)\.java$"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "git command failed")
    return completed.stdout.strip()


def _selected_members(archive: zipfile.ZipFile) -> list[tuple[str, re.Match[str]]]:
    selected: list[tuple[str, re.Match[str]]] = []
    for member in archive.namelist():
        path = PurePosixPath(member.replace("\\", "/"))
        if "CWE89_SQL_Injection" not in path.parts:
            continue
        match = CASE_RE.fullmatch(path.name)
        if match is not None:
            selected.append((member, match))
    return sorted(selected, key=lambda item: item[0])


def _worker(archive_path: Path, output_path: Path) -> int:
    if _sha256(archive_path) != ARCHIVE_SHA256:
        raise RuntimeError("Juliet archive SHA-256 does not match the preregistered NIST artifact")
    units: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    with zipfile.ZipFile(archive_path) as archive:
        selected = _selected_members(archive)
        for member, match in selected:
            raw = archive.read(member)
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                errors.append({"case_ref": hashlib.sha256(member.encode()).hexdigest()[:20], "error": "decode_failed"})
                continue
            member_ref = hashlib.sha256(member.encode("utf-8")).hexdigest()[:20]
            for entrypoint, expected in (("bad", "vulnerable"), ("good", "clean")):
                try:
                    flows = scan_java_sql_flows(text, entrypoint_names={entrypoint})
                except JavaFlowParseError:
                    errors.append({"case_ref": member_ref, "error": f"parse_failed:{entrypoint}"})
                    continue
                units.append(
                    {
                        "unit_id": f"{member_ref}:{entrypoint}",
                        "source_family": match.group("source"),
                        "sink_family": match.group("sink"),
                        "flow_variant": match.group("variant"),
                        "entrypoint": entrypoint,
                        "expected": expected,
                        "predicted": "vulnerable" if flows else "clean",
                        "finding_count": len(flows),
                        "finding_refs": [
                            hashlib.sha256(f"{flow.line}|{flow.subtype}".encode("utf-8")).hexdigest()[:20]
                            for flow in flows
                        ],
                        "raw_returned": False,
                    }
                )
    payload = {
        "schema": WORKER_SCHEMA,
        "archive_sha256": ARCHIVE_SHA256,
        "selected_file_count": len({unit["unit_id"].split(":", 1)[0] for unit in units}),
        "units": sorted(units, key=lambda unit: unit["unit_id"]),
        "errors": sorted(errors, key=lambda error: (error["case_ref"], error["error"])),
        "raw_returned": False,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0 if not errors else 2


def _wilson_lower(successes: int, total: int, z: float = 1.959963984540054) -> float:
    if total <= 0:
        return 0.0
    observed = successes / total
    denominator = 1 + z * z / total
    centre = observed + z * z / (2 * total)
    margin = z * math.sqrt((observed * (1 - observed) + z * z / (4 * total)) / total)
    return round((centre - margin) / denominator, 6)


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _score(units: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    confusion: Counter[str] = Counter()
    cases: list[dict[str, Any]] = []
    for unit in units:
        expected = unit["expected"] == "vulnerable"
        predicted = unit["predicted"] == "vulnerable"
        outcome = "tp" if expected and predicted else "fn" if expected else "fp" if predicted else "tn"
        confusion[outcome] += 1
        cases.append({**unit, "outcome": outcome})
    tp, fp, fn, tn = (confusion[name] for name in ("tp", "fp", "fn", "tn"))
    metrics = {
        "total_units": len(units),
        "vulnerable_units": tp + fn,
        "clean_units": tn + fp,
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "precision": _ratio(tp, tp + fp),
        "precision_wilson_95_lower": _wilson_lower(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
        "recall_wilson_95_lower": _wilson_lower(tp, tp + fn),
        "specificity": _ratio(tn, tn + fp),
        "specificity_wilson_95_lower": _wilson_lower(tn, tn + fp),
    }
    return metrics, cases


def _threshold_checks(metrics: dict[str, Any], thresholds: dict[str, Any]) -> dict[str, bool]:
    mapping = {
        "minimum_total_units": "total_units",
        "minimum_vulnerable_units": "vulnerable_units",
        "minimum_clean_units": "clean_units",
        "minimum_precision": "precision",
        "minimum_precision_wilson_95_lower": "precision_wilson_95_lower",
        "minimum_recall": "recall",
        "minimum_recall_wilson_95_lower": "recall_wilson_95_lower",
        "minimum_specificity": "specificity",
        "minimum_specificity_wilson_95_lower": "specificity_wilson_95_lower",
    }
    return {name: float(metrics[metric]) >= float(thresholds[name]) for name, metric in mapping.items()}


def run(preregistration: Path, archive_path: Path, output_dir: Path) -> dict[str, Any]:
    prereg = _read_json(preregistration)
    if prereg.get("schema") != PREREG_SCHEMA or prereg.get("status") != "locked_before_download_and_scan":
        raise ValueError("Juliet holdout preregistration is not locked")
    if prereg.get("source", {}).get("archive_sha256") != ARCHIVE_SHA256 or _sha256(archive_path) != ARCHIVE_SHA256:
        raise RuntimeError("Juliet archive integrity check failed")
    registered_scanner = str(prereg.get("scanner_revision") or "")
    scanner_clean = not _git("status", "--porcelain")
    scanner_source_unchanged = subprocess.run(
        ["git", "-C", str(ROOT), "diff", "--quiet", registered_scanner, "HEAD", "--", "src/k_guard_mcp"],
        check=False,
    ).returncode == 0
    if not scanner_clean or not scanner_source_unchanged:
        raise RuntimeError("scanner worktree or registered source integrity check failed")

    output_dir.mkdir(parents=True, exist_ok=True)
    run_records: list[dict[str, Any]] = []
    worker_payloads: list[dict[str, Any]] = []
    for number in (1, 2):
        worker_path = output_dir / f"juliet-worker-{number}.json"
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = "0"
        env["PYTHONPATH"] = str(ROOT / "src")
        started = time.monotonic()
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--worker", "--archive", str(archive_path), "--output", str(worker_path)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if completed.returncode != 0 or not worker_path.is_file():
            raise RuntimeError(f"Juliet worker {number} failed closed with exit {completed.returncode}")
        payload = _read_json(worker_path)
        if payload.get("schema") != WORKER_SCHEMA or payload.get("errors"):
            raise RuntimeError(f"Juliet worker {number} returned incomplete evidence")
        worker_hash = _sha256(worker_path)
        run_records.append(
            {
                "run": number,
                "exit_code": completed.returncode,
                "duration_seconds": round(time.monotonic() - started, 3),
                "worker_sha256": worker_hash,
            }
        )
        worker_payloads.append(payload)

    exact_repeat = run_records[0]["worker_sha256"] == run_records[1]["worker_sha256"]
    units = list(worker_payloads[0]["units"])
    metrics, cases = _score(units)
    thresholds = dict(prereg.get("locked_thresholds") or {})
    threshold_checks = _threshold_checks(metrics, thresholds)
    strata = {
        "source_families": sorted({case["source_family"] for case in cases}),
        "sink_families": sorted({case["sink_family"] for case in cases}),
        "flow_variants": sorted({case["flow_variant"] for case in cases}),
    }
    selection = prereg.get("locked_selection", {})
    integrity = {
        "preregistration_locked": True,
        "archive_sha256_matches": True,
        "scanner_worktree_clean": scanner_clean,
        "scanner_source_unchanged_since_registration": scanner_source_unchanged,
        "two_fresh_process_runs": len(run_records) == 2,
        "exact_worker_repeat": exact_repeat,
        "no_worker_errors": not worker_payloads[0].get("errors") and not worker_payloads[1].get("errors"),
        "source_strata_complete": strata["source_families"] == sorted(selection.get("source_families") or []),
        "sink_strata_complete": strata["sink_families"] == sorted(selection.get("sink_families") or []),
        "flow_variants_complete": strata["flow_variants"] == sorted(selection.get("flow_variants") or []),
        "paired_units_complete": metrics["vulnerable_units"] == metrics["clean_units"],
        "raw_source_not_returned": True,
    }
    passed = all(integrity.values()) and all(threshold_checks.values())
    result = {
        "schema": REPORT_SCHEMA,
        "holdout_id": prereg.get("holdout_id"),
        "verdict": "pass" if passed else "hold",
        "passed": passed,
        "scanner_revision": registered_scanner,
        "execution_revision": _git("rev-parse", "HEAD"),
        "source": prereg.get("source"),
        "preregistration_sha256": _sha256(preregistration),
        "runs": run_records,
        "integrity": integrity,
        "strata": strata,
        "metrics": metrics,
        "thresholds": thresholds,
        "threshold_checks": threshold_checks,
        "cases": cases,
        "claim_boundary": prereg.get("claim_boundary"),
        "raw_returned": False,
    }
    result_path = output_dir / "holdout-result.json"
    result_path.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the preregistered NIST Juliet Java CWE-89 component holdout.")
    parser.add_argument("--preregistration", type=Path)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.worker:
        if args.output is None:
            parser.error("--worker requires --output")
        return _worker(args.archive.resolve(), args.output.resolve())
    if args.preregistration is None or args.output_dir is None:
        parser.error("holdout mode requires --preregistration and --output-dir")
    result = run(args.preregistration.resolve(), args.archive.resolve(), args.output_dir.resolve())
    print(json.dumps({"holdout_id": result["holdout_id"], "verdict": result["verdict"], "metrics": result["metrics"]}, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
