from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

from k_guard_mcp.provenance import (
    RELEASE_SNAPSHOT_EXCLUDED_TREES,
    evidence_bundle,
    object_artifact,
    source_tree_snapshot,
)
from k_guard_mcp.redaction import redact_text


ADAPTER_VERSION = "1.2.0"
ANALYZER_SUBTYPE = "semgrep-ce-intrafile"
DEFAULT_SEMGREP_PROFILE = Path(__file__).with_name("analyzer_profiles") / "semgrep-deep.yml"
TARGET_COVERAGE_SCHEMA = "k_guard_analyzer_target_coverage.v1"
PATH_SET_SCHEMA = "k_guard_normalized_path_set.v1"
SEMGREP_CE_LIMITATION = (
    "Semgrep Community Edition analysis in this adapter is intrafile only; "
    "it does not establish interfile data flow or authorization correctness."
)

CONTROL_EXECUTABLE_MISSING = "semgrep_executable_missing"
CONTROL_EXECUTABLE_LAUNCH_FAILED = "semgrep_executable_launch_failed"
CONTROL_VERSION_UNAVAILABLE = "semgrep_executable_version_unavailable"
CONTROL_TIMEOUT = "semgrep_timeout"
CONTROL_NONZERO_EXIT = "semgrep_nonzero_exit"
CONTROL_OUTPUT_LIMIT = "semgrep_output_limit_exceeded"
CONTROL_JSON_MALFORMED = "semgrep_json_malformed_or_truncated"
CONTROL_JSON_SCHEMA = "semgrep_json_schema_invalid"
CONTROL_ERRORS_ARRAY = "semgrep_errors_array_nonempty"
CONTROL_SKIPPED = "semgrep_skipped_targets"
CONTROL_UNSUPPORTED = "semgrep_unsupported_analysis"
CONTROL_PARSE_ERRORS = "semgrep_parse_errors"
CONTROL_RESULT_LIMIT = "semgrep_result_limit_exceeded"
CONTROL_RESULT_SCHEMA = "semgrep_result_schema_invalid"
CONTROL_WORKSPACE_SNAPSHOT = "workspace_snapshot_incomplete"
CONTROL_WORKSPACE_CHANGED = "workspace_changed_during_analysis"
CONTROL_TARGET_ENUMERATION = "eligible_target_enumeration_failed"
CONTROL_TARGET_ENUMERATION_LIMIT = "eligible_target_enumeration_limit_exceeded"
CONTROL_TARGET_SYMLINK = "eligible_target_symlink_disallowed"
CONTROL_SCANNED_TARGETS_INVALID = "semgrep_scanned_targets_invalid"
CONTROL_SCANNED_TARGET_ESCAPE = "semgrep_scanned_target_escape"
CONTROL_SCANNED_TARGET_SYMLINK = "semgrep_scanned_target_symlink_disallowed"
CONTROL_SCANNED_TARGET_DUPLICATE = "semgrep_scanned_target_duplicate"
CONTROL_SCANNED_TARGET_LIMIT = "semgrep_scanned_target_limit_exceeded"
CONTROL_TARGET_COVERAGE = "semgrep_target_coverage_mismatch"
CONTROL_TARGET_STAGING = "semgrep_target_staging_failed"

_RULE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}\Z")
_ANALYZER_ID_RE = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,127}\Z")
_PROFILE_RULE_ID_RE = re.compile(
    r"^\s*-\s+id:\s*['\"]?([A-Za-z0-9][A-Za-z0-9_.:/-]{0,255})['\"]?\s*(?:#.*)?$",
    re.MULTILINE,
)
_CWE_RE = re.compile(r"CWE[-_ ]?(\d{1,5})", re.IGNORECASE)
_VERSION_RE = re.compile(r"(?<![A-Za-z0-9])v?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)")
_TARGET_SUFFIXES = frozenset(
    {
        ".cjs",
        ".cts",
        ".cs",
        ".go",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".kts",
        ".ktm",
        ".mjs",
        ".mts",
        ".php",
        ".py",
        ".pyi",
        ".rb",
        ".ts",
        ".tsx",
        ".vue",
        ".svelte",
    }
)
_TARGET_EXCLUDED_SUFFIXES = (".d.ts", ".min.js")
_TARGET_SHEBANG_COMMANDS = frozenset(
    {b"js", b"node", b"nodejs", b"php", b"python", b"python2", b"python3", b"ruby", b"ts-node"}
)
_MAX_TARGET_SHEBANG_BYTES = 4096
_TARGET_LANGUAGES = ("csharp", "go", "java", "javascript", "kotlin", "php", "python", "ruby", "typescript")
_TARGET_COVERAGE_RESULTS = frozenset(
    {"exact", "invalid", "mismatch", "no_eligible_targets", "unverified"}
)
_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "error": "high",
    "medium": "medium",
    "warning": "medium",
    "warn": "medium",
    "low": "low",
    "info": "low",
    "informational": "info",
    "inventory": "info",
    "experiment": "info",
}
_CONFIDENCE = {"high", "medium", "low"}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_DEFAULT_COUNTS = {
    "result_count": 0,
    "finding_count": 0,
    "error_count": 0,
    "skipped_count": 0,
    "stdout_bytes": 0,
    "stderr_bytes": 0,
    "version_stdout_bytes": 0,
    "version_stderr_bytes": 0,
    "eligible_target_count": 0,
    "scanned_target_count": 0,
}


@dataclass(frozen=True, slots=True)
class AnalyzerFinding:
    rule_id: str
    severity: str
    confidence: str
    cwe: tuple[str, ...]
    file: str
    line_start: int
    line_end: int
    message: str
    recommendation: str
    analyzer_subtype: str
    fingerprint: str
    raw_free: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "cwe", tuple(self.cwe))
        if not _RULE_ID_RE.fullmatch(self.rule_id):
            raise ValueError("Analyzer finding rule_id is invalid.")
        if self.severity not in _SEVERITY_ORDER:
            raise ValueError("Analyzer finding severity is not normalized.")
        if self.confidence not in _CONFIDENCE:
            raise ValueError("Analyzer finding confidence is not normalized.")
        if any(not re.fullmatch(r"CWE-\d{1,5}", item) for item in self.cwe):
            raise ValueError("Analyzer finding CWE values are not normalized.")
        if not _is_safe_relative_file(self.file):
            raise ValueError("Analyzer finding file must be a safe relative path.")
        if self.line_start < 1 or self.line_end < self.line_start:
            raise ValueError("Analyzer finding line range is invalid.")
        if not self.message.strip() or not self.recommendation.strip():
            raise ValueError("Analyzer finding guidance must not be empty.")
        if not _ANALYZER_ID_RE.fullmatch(self.analyzer_subtype):
            raise ValueError("Analyzer finding subtype is invalid.")
        if not re.fullmatch(r"[0-9a-f]{64}", self.fingerprint):
            raise ValueError("Analyzer finding fingerprint is invalid.")
        if self.raw_free is not True:
            raise ValueError("Analyzer findings must be raw-free.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "cwe": list(self.cwe),
            "file": self.file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "message": self.message,
            "recommendation": self.recommendation,
            "analyzer_subtype": self.analyzer_subtype,
            "fingerprint": self.fingerprint,
            "raw_free": True,
        }


@dataclass(frozen=True, slots=True)
class AnalyzerRun:
    complete: bool
    control_errors: tuple[str, ...]
    findings: tuple[AnalyzerFinding, ...]
    analyzer: str
    analyzer_subtype: str
    executable_version: str
    adapter_version: str
    profile_name: str
    adapter_sha256: str
    profile_sha256: str
    rules_sha256: str
    command_contract_sha256: str
    input_snapshot: Mapping[str, Any]
    timings: Mapping[str, float] = field(default_factory=dict)
    counts: Mapping[str, int] = field(default_factory=dict)
    target_coverage: Mapping[str, Any] = field(default_factory=dict)
    limitations: tuple[str, ...] = (SEMGREP_CE_LIMITATION,)
    raw_free: bool = True
    schema: str = "k_guard_analyzer_run.v1"

    def __post_init__(self) -> None:
        errors = tuple(dict.fromkeys(str(item) for item in self.control_errors if str(item)))
        findings = tuple(self.findings)
        timings = {str(key): round(float(value), 3) for key, value in self.timings.items()}
        counts = {str(key): int(value) for key, value in self.counts.items()}
        target_coverage = dict(self.target_coverage)
        input_snapshot = dict(self.input_snapshot)
        limitations = tuple(str(item) for item in self.limitations if str(item))
        object.__setattr__(self, "control_errors", errors)
        object.__setattr__(self, "findings", findings)
        object.__setattr__(self, "timings", MappingProxyType(timings))
        object.__setattr__(self, "counts", MappingProxyType(counts))
        object.__setattr__(self, "target_coverage", MappingProxyType(target_coverage))
        object.__setattr__(self, "input_snapshot", MappingProxyType(input_snapshot))
        object.__setattr__(self, "limitations", limitations)
        if self.complete and errors:
            raise ValueError("A complete analyzer run cannot contain control errors.")
        if not self.complete and not errors:
            raise ValueError("An incomplete analyzer run requires a control error.")
        if not _ANALYZER_ID_RE.fullmatch(self.analyzer) or not _ANALYZER_ID_RE.fullmatch(self.analyzer_subtype):
            raise ValueError("Analyzer run identity is invalid.")
        for digest in (
            self.adapter_sha256,
            self.profile_sha256,
            self.rules_sha256,
            self.command_contract_sha256,
        ):
            if digest and not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("Analyzer run hash is invalid.")
        if any(value < 0 for value in timings.values()) or any(value < 0 for value in counts.values()):
            raise ValueError("Analyzer timings and counts must be non-negative.")
        if target_coverage and not _valid_target_coverage(target_coverage):
            raise ValueError("Analyzer target coverage is invalid.")
        if self.analyzer == "semgrep":
            if not target_coverage:
                raise ValueError("Semgrep analyzer runs require target coverage proof.")
            if counts.get("eligible_target_count") != target_coverage["eligible_target_count"]:
                raise ValueError("Analyzer eligible target counts do not agree.")
            if counts.get("scanned_target_count") != target_coverage["scanned_target_count"]:
                raise ValueError("Analyzer scanned target counts do not agree.")
            if self.complete and target_coverage["result"] not in {"exact", "no_eligible_targets"}:
                raise ValueError("A complete Semgrep run requires exact target coverage.")
            if self.complete and target_coverage["result"] == "exact" and not self.executable_version:
                raise ValueError("A scanned Semgrep run requires an executable version.")
        if self.raw_free is not True:
            raise ValueError("Analyzer runs must be raw-free.")
        if self.complete and (
            input_snapshot.get("schema") != "k_guard_source_tree_snapshot.v1"
            or input_snapshot.get("complete") is not True
            or not re.fullmatch(r"[0-9a-f]{64}", str(input_snapshot.get("tree_sha256") or ""))
        ):
            raise ValueError("A complete analyzer run requires a complete source snapshot.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "complete": self.complete,
            "control_errors": list(self.control_errors),
            "findings": [finding.to_dict() for finding in self.findings],
            "analyzer": self.analyzer,
            "analyzer_subtype": self.analyzer_subtype,
            "executable_version": self.executable_version,
            "adapter_version": self.adapter_version,
            "profile_name": self.profile_name,
            "adapter_sha256": self.adapter_sha256,
            "profile_sha256": self.profile_sha256,
            "rules_sha256": self.rules_sha256,
            "command_contract_sha256": self.command_contract_sha256,
            "input_snapshot": dict(self.input_snapshot),
            "timings": dict(self.timings),
            "counts": dict(self.counts),
            "target_coverage": dict(self.target_coverage),
            "limitations": list(self.limitations),
            "raw_free": True,
        }

    def to_report(self) -> dict[str, Any]:
        return build_analyzer_report(self)


class AnalyzerAdapter(ABC):
    @property
    @abstractmethod
    def analyzer_subtype(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def analyze(
        self,
        workspace: str | Path,
        *,
        profile_path: str | Path | None = None,
    ) -> AnalyzerRun:
        raise NotImplementedError

    def run(
        self,
        workspace: str | Path,
        *,
        profile_path: str | Path | None = None,
    ) -> AnalyzerRun:
        return self.analyze(workspace, profile_path=profile_path)


@dataclass(frozen=True, slots=True)
class _ProfileContract:
    path: Path
    name: str
    profile_sha256: str
    rules_sha256: str


@dataclass(frozen=True, slots=True)
class _TargetInventory:
    paths: tuple[str, ...]
    path_set_sha256: str


@dataclass(frozen=True, slots=True)
class _ScannedTargetProof:
    paths: tuple[str, ...]
    reported_count: int
    path_set_sha256: str
    errors: tuple[str, ...]


class _TargetPathError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class _BoundedProcessResult:
    returncode: int
    stdout: bytes = b""
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    timed_out: bool = False
    output_limited: bool = False
    launch_error: str = ""
    duration_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class _StagedSemgrepResult:
    process: _BoundedProcessResult | None
    payload: Any | None
    scanned_proof: _ScannedTargetProof | None
    errors: tuple[str, ...]


class SemgrepAnalyzerAdapter(AnalyzerAdapter):
    def __init__(
        self,
        executable: str | Path = "semgrep",
        *,
        profile_path: str | Path = DEFAULT_SEMGREP_PROFILE,
        timeout_seconds: float = 120.0,
        version_timeout_seconds: float = 10.0,
        rule_timeout_seconds: int = 10,
        max_output_bytes: int = 8 * 1024 * 1024,
        max_results: int = 10_000,
        max_target_bytes: int = 2 * 1024 * 1024,
        max_profile_bytes: int = 2 * 1024 * 1024,
        max_target_entries: int = 50_000,
        max_target_count: int = 50_000,
        max_target_path_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        self.executable = str(executable)
        self.profile_path = Path(profile_path)
        self.timeout_seconds = _positive_number(timeout_seconds, "timeout_seconds")
        self.version_timeout_seconds = _positive_number(version_timeout_seconds, "version_timeout_seconds")
        self.rule_timeout_seconds = _positive_int(rule_timeout_seconds, "rule_timeout_seconds")
        self.max_output_bytes = _positive_int(max_output_bytes, "max_output_bytes")
        self.max_results = _positive_int(max_results, "max_results")
        self.max_target_bytes = _positive_int(max_target_bytes, "max_target_bytes")
        self.max_profile_bytes = _positive_int(max_profile_bytes, "max_profile_bytes")
        self.max_target_entries = _positive_int(max_target_entries, "max_target_entries")
        self.max_target_count = _positive_int(max_target_count, "max_target_count")
        self.max_target_path_bytes = _positive_int(max_target_path_bytes, "max_target_path_bytes")
        self._adapter_sha256 = _sha256_file_or_contract(Path(__file__))
        self._command_contract_sha256 = self._command_contract_hash()

    @property
    def analyzer_subtype(self) -> str:
        return ANALYZER_SUBTYPE

    def analyze(
        self,
        workspace: str | Path,
        *,
        profile_path: str | Path | None = None,
    ) -> AnalyzerRun:
        started = time.perf_counter()
        timings: dict[str, float] = {"version_ms": 0.0, "analysis_ms": 0.0}
        counts = dict(_DEFAULT_COUNTS)
        workspace_path, workspace_errors = _validated_workspace(workspace)
        if workspace_errors:
            return self._finish(
                started,
                complete=False,
                control_errors=workspace_errors,
                findings=(),
                timings=timings,
                counts=counts,
            )

        selected_profile = Path(profile_path) if profile_path is not None else self.profile_path
        profile, profile_errors = _validated_profile(selected_profile, self.max_profile_bytes)
        if profile_errors:
            return self._finish(
                started,
                complete=False,
                control_errors=profile_errors,
                findings=(),
                timings=timings,
                counts=counts,
            )

        inventory, inventory_errors = _enumerate_eligible_targets(
            workspace_path,
            max_entries=self.max_target_entries,
            max_targets=self.max_target_count,
            max_path_bytes=self.max_target_path_bytes,
        )
        if inventory_errors or inventory is None:
            return self._finish(
                started,
                complete=False,
                control_errors=inventory_errors or (CONTROL_TARGET_ENUMERATION,),
                findings=(),
                timings=timings,
                counts=counts,
                profile=profile,
            )
        counts["eligible_target_count"] = len(inventory.paths)
        target_coverage = _target_coverage(
            result="unverified",
            eligible_count=len(inventory.paths),
            scanned_count=0,
            eligible_path_set_sha256=inventory.path_set_sha256,
            scanned_path_set_sha256="",
        )
        workspace_snapshot = source_tree_snapshot(workspace_path)
        if workspace_snapshot.get("complete") is not True:
            return self._finish(
                started,
                complete=False,
                control_errors=(CONTROL_WORKSPACE_SNAPSHOT,),
                findings=(),
                timings=timings,
                counts=counts,
                profile=profile,
                workspace_snapshot=workspace_snapshot,
                target_coverage=target_coverage,
            )
        confirmed_inventory, confirmed_inventory_errors = _enumerate_eligible_targets(
            workspace_path,
            max_entries=self.max_target_entries,
            max_targets=self.max_target_count,
            max_path_bytes=self.max_target_path_bytes,
        )
        if confirmed_inventory_errors or confirmed_inventory is None:
            return self._finish(
                started,
                complete=False,
                control_errors=confirmed_inventory_errors or (CONTROL_TARGET_ENUMERATION,),
                findings=(),
                timings=timings,
                counts=counts,
                profile=profile,
                workspace_snapshot=workspace_snapshot,
                target_coverage=target_coverage,
            )
        if confirmed_inventory != inventory:
            return self._finish(
                started,
                complete=False,
                control_errors=(CONTROL_WORKSPACE_CHANGED,),
                findings=(),
                timings=timings,
                counts=counts,
                profile=profile,
                workspace_snapshot=workspace_snapshot,
                target_coverage=target_coverage,
            )
        if not inventory.paths:
            target_coverage = _target_coverage(
                result="no_eligible_targets",
                eligible_count=0,
                scanned_count=0,
                eligible_path_set_sha256=inventory.path_set_sha256,
                scanned_path_set_sha256=inventory.path_set_sha256,
            )
            final_workspace_snapshot = source_tree_snapshot(workspace_path)
            if (
                final_workspace_snapshot.get("complete") is not True
                or final_workspace_snapshot.get("tree_sha256") != workspace_snapshot.get("tree_sha256")
            ):
                return self._finish(
                    started,
                    complete=False,
                    control_errors=(CONTROL_WORKSPACE_CHANGED,),
                    findings=(),
                    timings=timings,
                    counts=counts,
                    profile=profile,
                    workspace_snapshot=workspace_snapshot,
                    target_coverage=target_coverage,
                )
            return self._finish(
                started,
                complete=True,
                control_errors=(),
                findings=(),
                timings=timings,
                counts=counts,
                profile=profile,
                workspace_snapshot=workspace_snapshot,
                target_coverage=target_coverage,
            )

        try:
            executable = shutil.which(self.executable)
        except (OSError, ValueError):
            executable = None
        if not executable:
            return self._finish(
                started,
                complete=False,
                control_errors=(CONTROL_EXECUTABLE_MISSING,),
                findings=(),
                timings=timings,
                counts=counts,
                profile=profile,
                workspace_snapshot=workspace_snapshot,
                target_coverage=target_coverage,
            )

        environment = self._offline_environment()
        version_result = _run_process_bounded(
            [executable, "--version"],
            cwd=workspace_path,
            env=environment,
            timeout_seconds=self.version_timeout_seconds,
            max_output_bytes=min(self.max_output_bytes, 64 * 1024),
        )
        timings["version_ms"] = version_result.duration_ms
        counts["version_stdout_bytes"] = version_result.stdout_bytes
        counts["version_stderr_bytes"] = version_result.stderr_bytes
        version_errors = _process_errors(version_result, version_stage=True)
        if version_errors:
            return self._finish(
                started,
                complete=False,
                control_errors=version_errors,
                findings=(),
                timings=timings,
                counts=counts,
                profile=profile,
                workspace_snapshot=workspace_snapshot,
                target_coverage=target_coverage,
            )
        executable_version = _normalized_version(version_result.stdout)
        if not executable_version:
            return self._finish(
                started,
                complete=False,
                control_errors=(CONTROL_VERSION_UNAVAILABLE,),
                findings=(),
                timings=timings,
                counts=counts,
                profile=profile,
                workspace_snapshot=workspace_snapshot,
                target_coverage=target_coverage,
            )

        staged_scan = _run_semgrep_staged(
            workspace=workspace_path,
            inventory=inventory,
            argv=self._scan_arguments(executable, profile.path),
            environment=environment,
            timeout_seconds=self.timeout_seconds,
            max_output_bytes=self.max_output_bytes,
            max_target_bytes=self.max_target_bytes,
            max_entries=self.max_target_entries,
            max_targets=self.max_target_count,
            max_path_bytes=self.max_target_path_bytes,
        )
        if staged_scan.errors:
            return self._finish(
                started,
                complete=False,
                control_errors=staged_scan.errors,
                findings=(),
                timings=timings,
                counts=counts,
                profile=profile,
                executable_version=executable_version,
                workspace_snapshot=workspace_snapshot,
                target_coverage=target_coverage,
            )
        scan_result = staged_scan.process
        if scan_result is None:
            return self._finish(
                started,
                complete=False,
                control_errors=(CONTROL_TARGET_STAGING,),
                findings=(),
                timings=timings,
                counts=counts,
                profile=profile,
                executable_version=executable_version,
                workspace_snapshot=workspace_snapshot,
                target_coverage=target_coverage,
            )
        timings["analysis_ms"] = scan_result.duration_ms
        counts["stdout_bytes"] = scan_result.stdout_bytes
        counts["stderr_bytes"] = scan_result.stderr_bytes
        scan_errors = _process_errors(scan_result, version_stage=False)
        if scan_errors:
            classified_errors, classified_counts = _classify_bounded_json_diagnostics(scan_result.stdout)
            counts.update(classified_counts)
            return self._finish(
                started,
                complete=False,
                control_errors=(*scan_errors, *classified_errors),
                findings=(),
                timings=timings,
                counts=counts,
                profile=profile,
                executable_version=executable_version,
                workspace_snapshot=workspace_snapshot,
                target_coverage=target_coverage,
            )

        payload = staged_scan.payload
        scanned_proof = staged_scan.scanned_proof
        if payload is None or scanned_proof is None:
            return self._finish(
                started,
                complete=False,
                control_errors=(CONTROL_JSON_MALFORMED,),
                findings=(),
                timings=timings,
                counts=counts,
                profile=profile,
                executable_version=executable_version,
                workspace_snapshot=workspace_snapshot,
                target_coverage=target_coverage,
            )

        payload_errors, result_rows, payload_counts = _inspect_payload(payload)
        counts.update(
            {
                key: payload_counts[key]
                for key in ("result_count", "error_count", "skipped_count")
            }
        )
        counts["scanned_target_count"] = scanned_proof.reported_count
        coverage_errors = list(scanned_proof.errors)
        if not coverage_errors and scanned_proof.paths != inventory.paths:
            coverage_errors.append(CONTROL_TARGET_COVERAGE)
        if coverage_errors:
            coverage_result = "invalid" if scanned_proof.errors else "mismatch"
        else:
            coverage_result = "exact"
        target_coverage = _target_coverage(
            result=coverage_result,
            eligible_count=len(inventory.paths),
            scanned_count=scanned_proof.reported_count,
            eligible_path_set_sha256=inventory.path_set_sha256,
            scanned_path_set_sha256=scanned_proof.path_set_sha256,
        )
        control_errors = tuple(dict.fromkeys((*payload_errors, *coverage_errors)))
        if control_errors:
            return self._finish(
                started,
                complete=False,
                control_errors=control_errors,
                findings=(),
                timings=timings,
                counts=counts,
                profile=profile,
                executable_version=executable_version,
                workspace_snapshot=workspace_snapshot,
                target_coverage=target_coverage,
            )
        if len(result_rows) > self.max_results:
            return self._finish(
                started,
                complete=False,
                control_errors=(CONTROL_RESULT_LIMIT,),
                findings=(),
                timings=timings,
                counts=counts,
                profile=profile,
                executable_version=executable_version,
                workspace_snapshot=workspace_snapshot,
                target_coverage=target_coverage,
            )

        normalized: dict[str, AnalyzerFinding] = {}
        scanned_target_paths = set(scanned_proof.paths)
        try:
            for row in result_rows:
                finding = _normalized_finding(row, workspace_path, profile.rules_sha256)
                if finding.file not in scanned_target_paths:
                    raise ValueError("Result path was not present in the scanned target proof.")
                normalized.setdefault(finding.fingerprint, finding)
        except (OSError, TypeError, ValueError):
            return self._finish(
                started,
                complete=False,
                control_errors=(CONTROL_RESULT_SCHEMA,),
                findings=(),
                timings=timings,
                counts=counts,
                profile=profile,
                executable_version=executable_version,
                workspace_snapshot=workspace_snapshot,
                target_coverage=target_coverage,
            )

        findings = tuple(
            sorted(
                normalized.values(),
                key=lambda item: (
                    _SEVERITY_ORDER[item.severity],
                    item.file.casefold(),
                    item.line_start,
                    item.line_end,
                    item.rule_id,
                    item.fingerprint,
                ),
            )
        )
        counts["finding_count"] = len(findings)
        final_workspace_snapshot = source_tree_snapshot(workspace_path)
        if (
            final_workspace_snapshot.get("complete") is not True
            or final_workspace_snapshot.get("tree_sha256") != workspace_snapshot.get("tree_sha256")
        ):
            return self._finish(
                started,
                complete=False,
                control_errors=(CONTROL_WORKSPACE_CHANGED,),
                findings=(),
                timings=timings,
                counts=counts,
                profile=profile,
                executable_version=executable_version,
                workspace_snapshot=workspace_snapshot,
                target_coverage=target_coverage,
            )
        return self._finish(
            started,
            complete=True,
            control_errors=(),
            findings=findings,
            timings=timings,
            counts=counts,
            profile=profile,
            executable_version=executable_version,
            workspace_snapshot=workspace_snapshot,
            target_coverage=target_coverage,
        )

    def _scan_arguments(self, executable: str, profile: Path) -> list[str]:
        return [
            executable,
            "scan",
            "--config",
            str(profile),
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--oss-only",
            "--jobs=1",
            "--strict",
            "--no-rewrite-rule-ids",
            f"--timeout={self.rule_timeout_seconds}",
            "--timeout-threshold=1",
            f"--max-target-bytes={self.max_target_bytes}",
            ".",
        ]

    def _offline_environment(self) -> dict[str, str]:
        environment = dict(os.environ)
        environment.pop("SEMGREP_APP_TOKEN", None)
        environment.update(
            {
                "SEMGREP_SEND_METRICS": "off",
                "SEMGREP_ENABLE_VERSION_CHECK": "0",
            }
        )
        return environment

    def _command_contract_hash(self) -> str:
        contract = {
            "schema": "k_guard_semgrep_command_contract.v1",
            "version_argv": ["{semgrep}", "--version"],
            "scan_argv": self._scan_arguments("{semgrep}", Path("{local-profile}")),
            "cwd": "{validated-workspace}",
            "environment": {
                "SEMGREP_APP_TOKEN": "removed",
                "SEMGREP_ENABLE_VERSION_CHECK": "0",
                "SEMGREP_SEND_METRICS": "off",
            },
            "limits": {
                "max_output_bytes": self.max_output_bytes,
                "max_results": self.max_results,
                "max_target_bytes": self.max_target_bytes,
                "max_target_count": self.max_target_count,
                "max_target_entries": self.max_target_entries,
                "max_target_path_bytes": self.max_target_path_bytes,
                "rule_timeout_seconds": self.rule_timeout_seconds,
                "timeout_seconds": self.timeout_seconds,
                "version_timeout_seconds": self.version_timeout_seconds,
            },
            "network_config_source": "validated-local-profile-only",
            "target_discovery": {
                "eligible_languages": list(_TARGET_LANGUAGES),
                "eligible_suffixes": sorted(_TARGET_SUFFIXES),
                "excluded_suffixes": list(_TARGET_EXCLUDED_SUFFIXES),
                "excluded_trees": sorted(RELEASE_SNAPSHOT_EXCLUDED_TREES),
                "extensionless_shebang_commands": sorted(
                    command.decode("ascii") for command in _TARGET_SHEBANG_COMMANDS
                ),
                "max_shebang_bytes": _MAX_TARGET_SHEBANG_BYTES,
                "path_set_schema": PATH_SET_SCHEMA,
                "pre_scan_inventory_passes": 2,
                "required_semgrep_field": "paths.scanned",
                "require_exact_normalized_set": True,
                "execution_root": "private-temporary-copy-of-exact-eligible-target-set",
                "ignore_policy": "staging-root-comment-only-semgrepignore",
                "source_copy": "bounded-restat-and-content-hash-verified",
                "symlinks": "rejected",
            },
            "raw_free": True,
        }
        rendered = json.dumps(contract, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(rendered.encode("utf-8")).hexdigest()

    def _finish(
        self,
        started: float,
        *,
        complete: bool,
        control_errors: Sequence[str],
        findings: Sequence[AnalyzerFinding],
        timings: Mapping[str, float],
        counts: Mapping[str, int],
        profile: _ProfileContract | None = None,
        executable_version: str = "",
        workspace_snapshot: Mapping[str, Any] | None = None,
        target_coverage: Mapping[str, Any] | None = None,
    ) -> AnalyzerRun:
        final_timings = dict(timings)
        final_timings["total_ms"] = max(0.0, (time.perf_counter() - started) * 1000.0)
        coverage = dict(target_coverage) if target_coverage is not None else _target_coverage(
            result="unverified",
            eligible_count=int(counts.get("eligible_target_count", 0)),
            scanned_count=int(counts.get("scanned_target_count", 0)),
            eligible_path_set_sha256="",
            scanned_path_set_sha256="",
        )
        return AnalyzerRun(
            complete=complete,
            control_errors=tuple(control_errors),
            findings=tuple(findings),
            analyzer="semgrep",
            analyzer_subtype=ANALYZER_SUBTYPE,
            executable_version=executable_version,
            adapter_version=ADAPTER_VERSION,
            profile_name=profile.name if profile else "",
            adapter_sha256=self._adapter_sha256,
            profile_sha256=profile.profile_sha256 if profile else "",
            rules_sha256=profile.rules_sha256 if profile else "",
            command_contract_sha256=self._command_contract_sha256,
            input_snapshot=dict(workspace_snapshot or {}),
            timings=final_timings,
            counts=counts,
            target_coverage=coverage,
        )


def build_analyzer_report(run: AnalyzerRun) -> dict[str, Any]:
    payload = run.to_dict()
    payload["evidence_bundle"] = evidence_bundle(
        subject="normalized-local-analyzer-run",
        producer=f"k_guard_mcp.analyzers:{run.adapter_version}",
        artifacts=[
            object_artifact("analyzer-run", payload, role="analysis"),
            object_artifact("input-snapshot", payload.get("input_snapshot", {}), role="input"),
        ],
    )
    return payload


def _validated_workspace(value: str | Path) -> tuple[Path | None, tuple[str, ...]]:
    text = str(value)
    if not text.strip() or "\x00" in text:
        return None, ("workspace_path_invalid",)
    candidate = Path(value)
    try:
        if not candidate.exists():
            return None, ("workspace_path_not_found",)
        if _is_link_like(candidate):
            return None, ("workspace_path_symlink_disallowed",)
        if not candidate.is_dir():
            return None, ("workspace_path_not_directory",)
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None, ("workspace_path_invalid",)
    return resolved, ()


def _validated_profile(value: Path, max_bytes: int) -> tuple[_ProfileContract | None, tuple[str, ...]]:
    text = str(value)
    if not text.strip() or "\x00" in text:
        return None, ("profile_path_invalid",)
    try:
        if value.is_symlink():
            return None, ("profile_path_symlink_disallowed",)
        if not value.exists():
            return None, ("profile_path_not_found",)
        if not value.is_file():
            return None, ("profile_path_not_file",)
        if value.suffix.casefold() not in {".yml", ".yaml"}:
            return None, ("profile_path_extension_invalid",)
        resolved = value.resolve(strict=True)
        size = resolved.stat().st_size
        if size <= 0:
            return None, ("profile_empty",)
        if size > max_bytes:
            return None, ("profile_size_limit_exceeded",)
        content = resolved.read_bytes()
        profile_text = content.decode("utf-8")
    except UnicodeDecodeError:
        return None, ("profile_encoding_invalid",)
    except (OSError, RuntimeError, ValueError):
        return None, ("profile_path_invalid",)
    if not re.search(r"^\s*rules\s*:\s*$", profile_text, re.MULTILINE):
        return None, ("profile_rules_invalid",)
    rule_ids = _PROFILE_RULE_ID_RE.findall(profile_text)
    if not rule_ids or len(set(rule_ids)) != len(rule_ids):
        return None, ("profile_rules_invalid",)
    profile_sha256 = hashlib.sha256(content).hexdigest()
    rules_contract = json.dumps(
        {"profile_sha256": profile_sha256, "rule_ids": sorted(rule_ids)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    rules_sha256 = hashlib.sha256(rules_contract.encode("ascii")).hexdigest()
    return (
        _ProfileContract(
            path=resolved,
            name=resolved.name,
            profile_sha256=profile_sha256,
            rules_sha256=rules_sha256,
        ),
        (),
    )


def _enumerate_eligible_targets(
    workspace: Path,
    *,
    max_entries: int,
    max_targets: int,
    max_path_bytes: int,
) -> tuple[_TargetInventory | None, tuple[str, ...]]:
    if min(max_entries, max_targets, max_path_bytes) <= 0:
        return None, (CONTROL_TARGET_ENUMERATION_LIMIT,)
    excluded = {name.casefold() for name in RELEASE_SNAPSHOT_EXCLUDED_TREES}
    eligible: list[str] = []
    entry_count = 0
    path_bytes = 0

    def raise_walk_error(error: OSError) -> None:
        raise error

    try:
        for current, directory_names, file_names in os.walk(
            workspace,
            topdown=True,
            followlinks=False,
            onerror=raise_walk_error,
        ):
            current_path = Path(current)
            current_resolved = current_path.resolve(strict=True)
            if not current_resolved.is_relative_to(workspace):
                raise _TargetPathError(CONTROL_TARGET_ENUMERATION)

            kept_directories: list[str] = []
            for name in sorted(directory_names, key=lambda item: (item.casefold(), item)):
                entry_count += 1
                candidate = current_path / name
                if _is_link_like(candidate):
                    raise _TargetPathError(CONTROL_TARGET_SYMLINK)
                relative = _inventory_relative_path(candidate, workspace)
                path_bytes += len(relative.encode("utf-8", errors="surrogatepass"))
                if entry_count > max_entries or path_bytes > max_path_bytes:
                    raise _TargetPathError(CONTROL_TARGET_ENUMERATION_LIMIT)
                if not candidate.is_dir():
                    raise _TargetPathError(CONTROL_TARGET_ENUMERATION)
                if name.casefold() not in excluded:
                    kept_directories.append(name)
            directory_names[:] = kept_directories

            for name in sorted(file_names, key=lambda item: (item.casefold(), item)):
                entry_count += 1
                candidate = current_path / name
                if _is_link_like(candidate):
                    raise _TargetPathError(CONTROL_TARGET_SYMLINK)
                relative = _inventory_relative_path(candidate, workspace)
                path_bytes += len(relative.encode("utf-8", errors="surrogatepass"))
                if entry_count > max_entries or path_bytes > max_path_bytes:
                    raise _TargetPathError(CONTROL_TARGET_ENUMERATION_LIMIT)
                if not candidate.is_file():
                    raise _TargetPathError(CONTROL_TARGET_ENUMERATION)
                if _is_eligible_source_target(candidate):
                    eligible.append(relative)
                    if len(eligible) > max_targets:
                        raise _TargetPathError(CONTROL_TARGET_ENUMERATION_LIMIT)
    except _TargetPathError as exc:
        return None, (exc.code,)
    except (OSError, RuntimeError, ValueError):
        return None, (CONTROL_TARGET_ENUMERATION,)

    normalized = tuple(sorted(eligible))
    if len(set(normalized)) != len(normalized):
        return None, (CONTROL_TARGET_ENUMERATION,)
    return _TargetInventory(paths=normalized, path_set_sha256=_path_set_sha256(normalized)), ()


def _run_semgrep_staged(
    *,
    workspace: Path,
    inventory: _TargetInventory,
    argv: Sequence[str],
    environment: Mapping[str, str],
    timeout_seconds: float,
    max_output_bytes: int,
    max_target_bytes: int,
    max_entries: int,
    max_targets: int,
    max_path_bytes: int,
) -> _StagedSemgrepResult:
    try:
        with tempfile.TemporaryDirectory(prefix="k-guard-semgrep-") as temporary_directory:
            staging = Path(temporary_directory).resolve(strict=True)
            staging_errors = _stage_eligible_targets(
                workspace,
                staging,
                inventory,
                max_target_bytes=max_target_bytes,
                max_entries=max_entries,
                max_targets=max_targets,
                max_path_bytes=max_path_bytes,
            )
            if staging_errors:
                return _StagedSemgrepResult(None, None, None, staging_errors)
            process = _run_process_bounded(
                argv,
                cwd=staging,
                env=environment,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
            )
            if _process_errors(process, version_stage=False):
                return _StagedSemgrepResult(process, None, None, ())
            try:
                payload = json.loads(process.stdout.decode("utf-8-sig"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return _StagedSemgrepResult(process, None, None, (CONTROL_JSON_MALFORMED,))
            proof = _scanned_target_proof(payload, staging, max_targets=max_targets)
            return _StagedSemgrepResult(process, payload, proof, ())
    except (OSError, RuntimeError, ValueError):
        return _StagedSemgrepResult(None, None, None, (CONTROL_TARGET_STAGING,))


def _stage_eligible_targets(
    workspace: Path,
    staging: Path,
    inventory: _TargetInventory,
    *,
    max_target_bytes: int,
    max_entries: int,
    max_targets: int,
    max_path_bytes: int,
) -> tuple[str, ...]:
    try:
        _write_staged_file(
            staging / ".semgrepignore",
            b"# K-Guard staging contains only the independently enumerated target set.\n",
            executable=False,
        )
        for relative in inventory.paths:
            pure = PurePosixPath(relative)
            if not _is_safe_relative_file(relative) or ".." in pure.parts:
                raise _TargetPathError(CONTROL_TARGET_STAGING)
            source = workspace.joinpath(*pure.parts)
            current = workspace
            for part in pure.parts:
                current = current / part
                if _is_link_like(current):
                    raise _TargetPathError(CONTROL_TARGET_SYMLINK)
            before = source.stat()
            if not source.is_file() or before.st_size > max_target_bytes:
                raise _TargetPathError(CONTROL_TARGET_COVERAGE)
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(source, flags)
            try:
                opened = os.fstat(descriptor)
                chunks: list[bytes] = []
                remaining = max_target_bytes + 1
                while remaining:
                    chunk = os.read(descriptor, min(64 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                content = b"".join(chunks)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            if (
                len(content) > max_target_bytes
                or before.st_size != opened.st_size
                or before.st_mtime_ns != opened.st_mtime_ns
                or opened.st_size != after.st_size
                or opened.st_mtime_ns != after.st_mtime_ns
                or len(content) != after.st_size
                or source.resolve(strict=True).relative_to(workspace).as_posix() != relative
            ):
                raise _TargetPathError(CONTROL_WORKSPACE_CHANGED)
            destination = staging.joinpath(*pure.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            _write_staged_file(destination, content, executable=bool(before.st_mode & 0o111))
            if hashlib.sha256(destination.read_bytes()).digest() != hashlib.sha256(content).digest():
                raise _TargetPathError(CONTROL_TARGET_STAGING)
        staged_inventory, staged_errors = _enumerate_eligible_targets(
            staging,
            max_entries=max_entries + 1,
            max_targets=max_targets,
            max_path_bytes=max_path_bytes + len(".semgrepignore"),
        )
        if staged_errors or staged_inventory != inventory:
            raise _TargetPathError(CONTROL_TARGET_STAGING)
    except _TargetPathError as exc:
        return (exc.code,)
    except (OSError, RuntimeError, ValueError):
        return (CONTROL_TARGET_STAGING,)
    return ()


def _write_staged_file(path: Path, content: bytes, *, executable: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o700 if executable else 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short staging write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _inventory_relative_path(candidate: Path, workspace: Path) -> str:
    try:
        resolved = candidate.resolve(strict=True)
        relative = resolved.relative_to(workspace).as_posix()
    except (OSError, RuntimeError, ValueError) as exc:
        raise _TargetPathError(CONTROL_TARGET_ENUMERATION) from exc
    if "\\" in relative or not _is_safe_relative_file(relative):
        raise _TargetPathError(CONTROL_TARGET_ENUMERATION)
    return relative


def _has_eligible_target_suffix(name: str) -> bool:
    return (
        not any(name.endswith(suffix) for suffix in _TARGET_EXCLUDED_SUFFIXES)
        and any(name.endswith(suffix) for suffix in _TARGET_SUFFIXES)
    )


def _is_eligible_source_target(candidate: Path) -> bool:
    if _has_eligible_target_suffix(candidate.name):
        return True
    if "." in candidate.name:
        return False
    try:
        mode = candidate.stat().st_mode
        if os.name != "nt" and mode & 0o111 == 0:
            return False
        with candidate.open("rb") as handle:
            first_block = handle.read(_MAX_TARGET_SHEBANG_BYTES + 1)
    except OSError as exc:
        raise _TargetPathError(CONTROL_TARGET_ENUMERATION) from exc
    first_line, separator, _rest = first_block.partition(b"\n")
    if not separator and len(first_block) > _MAX_TARGET_SHEBANG_BYTES:
        raise _TargetPathError(CONTROL_TARGET_ENUMERATION_LIMIT)
    return _shebang_command(first_line.rstrip(b"\r")) in _TARGET_SHEBANG_COMMANDS


def _shebang_command(first_line: bytes) -> bytes:
    match = re.fullmatch(rb"#![ \t]*([^ \t]*)(?:[ \t]*([^ \t].*)?)?", first_line)
    if match is None:
        return b""
    command = match.group(1)
    argument = match.group(2) or b""
    if command == b"/usr/bin/env":
        if argument.startswith(b"-S"):
            split_arguments = argument[2:].split()
            return split_arguments[0] if split_arguments else b""
        return argument
    return command.rsplit(b"/", 1)[-1]


def _scanned_target_proof(
    payload: Any,
    workspace: Path,
    *,
    max_targets: int,
) -> _ScannedTargetProof:
    if not isinstance(payload, dict):
        return _ScannedTargetProof((), 0, "", (CONTROL_SCANNED_TARGETS_INVALID,))
    paths = payload.get("paths")
    if not isinstance(paths, dict) or "scanned" not in paths:
        return _ScannedTargetProof((), 0, "", (CONTROL_SCANNED_TARGETS_INVALID,))
    scanned = paths.get("scanned")
    if not isinstance(scanned, list):
        return _ScannedTargetProof((), 0, "", (CONTROL_SCANNED_TARGETS_INVALID,))
    reported_count = len(scanned)
    if reported_count > max_targets:
        return _ScannedTargetProof((), reported_count, "", (CONTROL_SCANNED_TARGET_LIMIT,))

    normalized: list[str] = []
    identities: set[str] = set()
    try:
        for value in scanned:
            relative = _normalized_scanned_target(value, workspace)
            identity = os.path.normcase(relative)
            if identity in identities:
                raise _TargetPathError(CONTROL_SCANNED_TARGET_DUPLICATE)
            identities.add(identity)
            normalized.append(relative)
    except _TargetPathError as exc:
        return _ScannedTargetProof((), reported_count, "", (exc.code,))
    except (OSError, RuntimeError, ValueError):
        return _ScannedTargetProof((), reported_count, "", (CONTROL_SCANNED_TARGETS_INVALID,))

    result = tuple(sorted(normalized))
    return _ScannedTargetProof(result, reported_count, _path_set_sha256(result), ())


def _normalized_scanned_target(value: Any, workspace: Path) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\x00" in value
        or "\n" in value
        or "\r" in value
    ):
        raise _TargetPathError(CONTROL_SCANNED_TARGETS_INVALID)
    portable = value.replace("\\", "/")
    pure = PurePosixPath(portable)
    if ".." in pure.parts or re.match(r"^[A-Za-z]:", portable) and os.name != "nt":
        raise _TargetPathError(CONTROL_SCANNED_TARGET_ESCAPE)

    native = Path(portable)
    lexical = native if native.is_absolute() else workspace.joinpath(*pure.parts)
    try:
        lexical_relative = lexical.relative_to(workspace)
    except ValueError as exc:
        raise _TargetPathError(CONTROL_SCANNED_TARGET_ESCAPE) from exc
    current = workspace
    try:
        for part in lexical_relative.parts:
            current = current / part
            if _is_link_like(current):
                raise _TargetPathError(CONTROL_SCANNED_TARGET_SYMLINK)
        resolved = lexical.resolve(strict=True)
        relative = resolved.relative_to(workspace).as_posix()
        if not resolved.is_file():
            raise _TargetPathError(CONTROL_SCANNED_TARGETS_INVALID)
    except _TargetPathError:
        raise
    except ValueError as exc:
        raise _TargetPathError(CONTROL_SCANNED_TARGET_ESCAPE) from exc
    except (OSError, RuntimeError) as exc:
        raise _TargetPathError(CONTROL_SCANNED_TARGETS_INVALID) from exc
    if "\\" in relative or not _is_safe_relative_file(relative):
        raise _TargetPathError(CONTROL_SCANNED_TARGETS_INVALID)
    return relative


def _is_link_like(path: Path) -> bool:
    if path.is_symlink():
        return True
    junction_check = getattr(path, "is_junction", None)
    return bool(junction_check()) if callable(junction_check) else False


def _path_set_sha256(paths: Sequence[str]) -> str:
    rendered = json.dumps(
        {"schema": PATH_SET_SCHEMA, "paths": sorted(paths)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(rendered.encode("ascii")).hexdigest()


def _target_coverage(
    *,
    result: str,
    eligible_count: int,
    scanned_count: int,
    eligible_path_set_sha256: str,
    scanned_path_set_sha256: str,
) -> dict[str, Any]:
    return {
        "schema": TARGET_COVERAGE_SCHEMA,
        "result": result,
        "eligible_target_count": eligible_count,
        "scanned_target_count": scanned_count,
        "eligible_path_set_sha256": eligible_path_set_sha256,
        "scanned_path_set_sha256": scanned_path_set_sha256,
        "raw_free": True,
    }


def _valid_target_coverage(value: Mapping[str, Any]) -> bool:
    if set(value) != {
        "schema",
        "result",
        "eligible_target_count",
        "scanned_target_count",
        "eligible_path_set_sha256",
        "scanned_path_set_sha256",
        "raw_free",
    }:
        return False
    eligible_count = value.get("eligible_target_count")
    scanned_count = value.get("scanned_target_count")
    eligible_sha256 = value.get("eligible_path_set_sha256")
    scanned_sha256 = value.get("scanned_path_set_sha256")
    if (
        value.get("schema") != TARGET_COVERAGE_SCHEMA
        or value.get("result") not in _TARGET_COVERAGE_RESULTS
        or value.get("raw_free") is not True
        or isinstance(eligible_count, bool)
        or not isinstance(eligible_count, int)
        or eligible_count < 0
        or isinstance(scanned_count, bool)
        or not isinstance(scanned_count, int)
        or scanned_count < 0
        or not isinstance(eligible_sha256, str)
        or not isinstance(scanned_sha256, str)
        or eligible_sha256 and not re.fullmatch(r"[0-9a-f]{64}", eligible_sha256)
        or scanned_sha256 and not re.fullmatch(r"[0-9a-f]{64}", scanned_sha256)
    ):
        return False
    if value["result"] == "exact":
        return (
            eligible_count > 0
            and scanned_count == eligible_count
            and bool(eligible_sha256)
            and eligible_sha256 == scanned_sha256
        )
    if value["result"] == "no_eligible_targets":
        return (
            eligible_count == 0
            and scanned_count == 0
            and bool(eligible_sha256)
            and eligible_sha256 == scanned_sha256
        )
    if value["result"] == "mismatch":
        return (
            eligible_count > 0
            and bool(eligible_sha256)
            and bool(scanned_sha256)
            and (eligible_count != scanned_count or eligible_sha256 != scanned_sha256)
        )
    return True


def _process_errors(result: _BoundedProcessResult, *, version_stage: bool) -> tuple[str, ...]:
    errors: list[str] = []
    if result.launch_error == "missing":
        errors.append(CONTROL_EXECUTABLE_MISSING)
    elif result.launch_error:
        errors.append(CONTROL_EXECUTABLE_LAUNCH_FAILED)
    if result.timed_out:
        errors.append(CONTROL_TIMEOUT)
    if result.output_limited:
        errors.append(CONTROL_OUTPUT_LIMIT)
    if not result.launch_error and not result.timed_out and not result.output_limited and result.returncode != 0:
        errors.append(CONTROL_NONZERO_EXIT)
    if errors and version_stage:
        errors.append(CONTROL_VERSION_UNAVAILABLE)
    return tuple(errors)


def _classify_bounded_json_diagnostics(stdout: bytes) -> tuple[tuple[str, ...], dict[str, int]]:
    try:
        payload = json.loads(stdout.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ((CONTROL_JSON_MALFORMED,) if stdout else ()), {}
    control_errors, _results, counts = _inspect_payload(payload)
    return control_errors, {
        key: counts[key]
        for key in ("result_count", "error_count", "skipped_count")
    }


def _inspect_payload(payload: Any) -> tuple[tuple[str, ...], list[Any], dict[str, int]]:
    counts = dict(_DEFAULT_COUNTS)
    if not isinstance(payload, dict):
        return (CONTROL_JSON_SCHEMA,), [], counts
    results = payload.get("results")
    errors = payload.get("errors")
    if not isinstance(results, list) or not isinstance(errors, list):
        return (CONTROL_JSON_SCHEMA,), [], counts
    counts["result_count"] = len(results)
    counts["error_count"] = len(errors)

    skipped: list[Any] = []
    paths = payload.get("paths")
    if paths is not None:
        if not isinstance(paths, dict):
            return (CONTROL_JSON_SCHEMA,), [], counts
        path_skipped = paths.get("skipped", [])
        if not isinstance(path_skipped, list):
            return (CONTROL_JSON_SCHEMA,), [], counts
        skipped.extend(path_skipped)
    for key in ("skipped", "skipped_rules"):
        value = payload.get(key, [])
        if value is None:
            continue
        if not isinstance(value, list):
            return (CONTROL_JSON_SCHEMA,), [], counts
        skipped.extend(value)
    counts["skipped_count"] = len(skipped)

    control_errors: list[str] = []
    if errors:
        control_errors.append(CONTROL_ERRORS_ARRAY)
    if skipped:
        control_errors.append(CONTROL_SKIPPED)
    diagnostic_text = _bounded_diagnostic_text([*errors, *skipped])
    if _has_parse_diagnostic(diagnostic_text):
        control_errors.append(CONTROL_PARSE_ERRORS)
    if _has_unsupported_diagnostic(diagnostic_text) or _truthy_unsupported_marker(payload):
        control_errors.append(CONTROL_UNSUPPORTED)
    return tuple(control_errors), results, counts


def _normalized_finding(row: Any, workspace: Path, rules_sha256: str) -> AnalyzerFinding:
    if not isinstance(row, dict):
        raise ValueError("Result row is not an object.")
    rule_id = row.get("check_id")
    if not isinstance(rule_id, str) or not _RULE_ID_RE.fullmatch(rule_id):
        raise ValueError("Result rule id is invalid.")
    relative_file = _relative_result_file(row.get("path"), workspace)
    line_start = _result_line(row.get("start"))
    line_end = _result_line(row.get("end"))
    if line_end < line_start:
        raise ValueError("Result line range is invalid.")
    extra = row.get("extra")
    if not isinstance(extra, dict):
        raise ValueError("Result extra field is invalid.")
    metadata = extra.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("Result metadata is invalid.")

    severity = _normalized_severity(metadata.get("k_guard_severity"))
    if not severity:
        severity = _normalized_severity(metadata.get("severity"))
    if not severity:
        severity = _normalized_severity(extra.get("severity")) or "medium"
    confidence_value = metadata.get("confidence")
    confidence = str(confidence_value).strip().casefold() if isinstance(confidence_value, str) else "medium"
    if confidence not in _CONFIDENCE:
        confidence = "medium"
    cwe = _normalized_cwe(metadata.get("cwe"))
    match_material = _match_material(extra)
    message = _safe_guidance(
        metadata.get("summary", metadata.get("k_guard_message", metadata.get("message"))),
        fallback=f"Semgrep rule {rule_id} matched a security-sensitive pattern.",
        match_material=match_material,
    )
    recommendation = _safe_guidance(
        metadata.get("recommendation", metadata.get("fix")),
        fallback="Review the reported line and apply a context-appropriate secure implementation.",
        match_material=match_material,
    )
    fingerprint_payload = json.dumps(
        {
            "analyzer_subtype": ANALYZER_SUBTYPE,
            "file": relative_file,
            "line_end": line_end,
            "line_start": line_start,
            "rule_id": rule_id,
            "rules_sha256": rules_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    fingerprint = hashlib.sha256(fingerprint_payload.encode("utf-8")).hexdigest()
    return AnalyzerFinding(
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        cwe=cwe,
        file=relative_file,
        line_start=line_start,
        line_end=line_end,
        message=message,
        recommendation=recommendation,
        analyzer_subtype=ANALYZER_SUBTYPE,
        fingerprint=fingerprint,
    )


def _relative_result_file(value: Any, workspace: Path) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError("Result path is invalid.")
    native_value = value.replace("\\", os.sep).replace("/", os.sep)
    candidate = Path(native_value)
    resolved = candidate.resolve(strict=False) if candidate.is_absolute() else (workspace / candidate).resolve(strict=False)
    try:
        relative = resolved.relative_to(workspace)
    except ValueError as error:
        raise ValueError("Result path escaped the workspace.") from error
    rendered = relative.as_posix()
    if not _is_safe_relative_file(rendered):
        raise ValueError("Result path is not a safe relative path.")
    return rendered


def _result_line(value: Any) -> int:
    if not isinstance(value, dict):
        raise ValueError("Result location is invalid.")
    line = value.get("line")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        raise ValueError("Result line is invalid.")
    return line


def _normalized_severity(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return _SEVERITY.get(value.strip().casefold(), "")


def _normalized_cwe(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        values: Sequence[Any] = (value,)
    elif isinstance(value, (list, tuple)):
        values = value
    else:
        values = ()
    normalized: set[str] = set()
    for item in values:
        if not isinstance(item, str):
            continue
        for match in _CWE_RE.finditer(item):
            normalized.add(f"CWE-{int(match.group(1))}")
    return tuple(sorted(normalized, key=lambda item: int(item.split("-", 1)[1])))


def _safe_guidance(value: Any, *, fallback: str, match_material: Sequence[str]) -> str:
    if not isinstance(value, str):
        return fallback
    normalized = re.sub(r"\s+", " ", value).strip()
    if not normalized or len(normalized) > 600 or any(fragment in normalized for fragment in match_material):
        return fallback
    redacted = redact_text(normalized)
    return redacted if redacted.strip() else fallback


def _match_material(extra: Mapping[str, Any]) -> tuple[str, ...]:
    fragments: set[str] = set()
    _collect_strings(extra.get("lines"), fragments, depth=0)
    _collect_strings(extra.get("metavars"), fragments, depth=0)
    _collect_strings(extra.get("dataflow_trace"), fragments, depth=0)
    return tuple(sorted((item for item in fragments if 4 <= len(item) <= 4096), key=len, reverse=True))


def _collect_strings(value: Any, output: set[str], *, depth: int) -> None:
    if depth > 6 or len(output) >= 256:
        return
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            output.add(stripped)
        return
    if isinstance(value, dict):
        for item in list(value.values())[:256]:
            _collect_strings(item, output, depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for item in value[:256]:
            _collect_strings(item, output, depth=depth + 1)


def _bounded_diagnostic_text(values: Sequence[Any]) -> str:
    fragments: set[str] = set()
    _collect_strings(list(values)[:256], fragments, depth=0)
    return " ".join(sorted(fragments))[:64_000].casefold()


def _has_parse_diagnostic(value: str) -> bool:
    return any(
        marker in value
        for marker in (
            "parse error",
            "parse_error",
            "parser error",
            "parser_or_internal_error",
            "syntax error",
            "partially parsed",
        )
    )


def _has_unsupported_diagnostic(value: str) -> bool:
    return any(
        marker in value
        for marker in (
            "unsupported",
            "not supported",
            "unknown language",
            "language not found",
            "missing plugin",
        )
    )


def _truthy_unsupported_marker(payload: Mapping[str, Any]) -> bool:
    for key in ("unsupported", "unsupported_languages", "unsupported_rules"):
        marker = payload.get(key)
        if marker not in (None, False, (), [], {}):
            return True
    return False


def _normalized_version(stdout: bytes) -> str:
    try:
        value = stdout.decode("utf-8-sig")
    except UnicodeDecodeError:
        return ""
    match = _VERSION_RE.search(value[:4096])
    return match.group(1) if match else ""


def _is_safe_relative_file(value: str) -> bool:
    if not value or "\x00" in value or "\n" in value or "\r" in value or re.match(r"^[A-Za-z]:", value):
        return False
    path = PurePosixPath(value.replace("\\", "/"))
    return not path.is_absolute() and path.name not in {"", ".", ".."} and ".." not in path.parts


def _sha256_file_or_contract(path: Path) -> str:
    try:
        content = path.read_bytes()
    except OSError:
        content = f"k_guard_mcp.analyzers:{ADAPTER_VERSION}".encode("ascii")
    return hashlib.sha256(content).hexdigest()


def _positive_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ValueError(f"{label} must be positive.")
    return float(value)


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer.")
    return value


def _run_process_bounded(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: float,
    max_output_bytes: int,
) -> _BoundedProcessResult:
    started = time.perf_counter()
    try:
        process = subprocess.Popen(
            list(argv),
            cwd=str(cwd),
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except FileNotFoundError:
        return _BoundedProcessResult(
            returncode=-1,
            launch_error="missing",
            duration_ms=(time.perf_counter() - started) * 1000.0,
        )
    except OSError:
        return _BoundedProcessResult(
            returncode=-1,
            launch_error="os_error",
            duration_ms=(time.perf_counter() - started) * 1000.0,
        )

    stdout_buffer = bytearray()
    state = {"stdout_bytes": 0, "stderr_bytes": 0, "total_bytes": 0}
    lock = threading.Lock()
    output_limited = threading.Event()

    def drain(stream: Any, *, keep: bool, counter: str) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                with lock:
                    before = state["total_bytes"]
                    state[counter] += len(chunk)
                    state["total_bytes"] += len(chunk)
                    if keep and before < max_output_bytes:
                        stdout_buffer.extend(chunk[: max_output_bytes - before])
                    if state["total_bytes"] > max_output_bytes:
                        output_limited.set()
        except OSError:
            output_limited.set()

    stdout_thread = threading.Thread(
        target=drain,
        args=(process.stdout,),
        kwargs={"keep": True, "counter": "stdout_bytes"},
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=drain,
        args=(process.stderr,),
        kwargs={"keep": False, "counter": "stderr_bytes"},
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    deadline = started + timeout_seconds
    timed_out = False
    while process.poll() is None:
        if output_limited.is_set():
            _terminate_process(process)
            break
        if time.perf_counter() >= deadline:
            timed_out = True
            _terminate_process(process)
            break
        time.sleep(0.01)

    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    stdout_thread.join(timeout=1.0)
    stderr_thread.join(timeout=1.0)
    readers_incomplete = stdout_thread.is_alive() or stderr_thread.is_alive()
    if process.stdout is not None:
        process.stdout.close()
    if process.stderr is not None:
        process.stderr.close()
    if readers_incomplete:
        output_limited.set()
        stdout_thread.join(timeout=0.2)
        stderr_thread.join(timeout=0.2)
    return _BoundedProcessResult(
        returncode=int(process.returncode if process.returncode is not None else -1),
        stdout=bytes(stdout_buffer),
        stdout_bytes=state["stdout_bytes"],
        stderr_bytes=state["stderr_bytes"],
        timed_out=timed_out,
        output_limited=output_limited.is_set(),
        duration_ms=(time.perf_counter() - started) * 1000.0,
    )


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    try:
        process.terminate()
        process.wait(timeout=0.5)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except OSError:
            pass
