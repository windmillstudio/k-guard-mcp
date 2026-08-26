from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import tomllib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

try:
    from packaging.requirements import InvalidRequirement, Requirement
except ImportError:
    InvalidRequirement = ValueError  # type: ignore[assignment,misc]
    Requirement = None  # type: ignore[assignment,misc]

from k_guard_mcp.hashing import active_evidence_key, evidence_hash, evidence_hash_scheme
from k_guard_mcp.provenance import (
    RELEASE_SNAPSHOT_EXCLUDED_TREES,
    canonical_json,
    evidence_bundle,
    object_artifact,
    source_tree_snapshot,
)


SCA_SCHEMA = "k_guard_sca_run.v1"
SCA_ADAPTER_SCHEMA = "k_guard_sca_adapter_run.v1"
SCA_FINDING_SCHEMA = "k_guard_sca_finding.v1"
SCA_INPUT_SNAPSHOT_SCHEMA = "k_guard_sca_input_snapshot.v1"
SCA_INVENTORY_SCHEMA = "k_guard_sca_inventory.v1"
SCA_COMMAND_CONTRACT_SCHEMA = "k_guard_sca_command_contract.v1"
ADAPTER_VERSION = "1.0.0"

CONTROL_TARGET_INVALID = "target_path_invalid"
CONTROL_TARGET_NOT_FOUND = "target_path_not_found"
CONTROL_TARGET_NOT_DIRECTORY = "target_path_not_directory"
CONTROL_TARGET_SYMLINK = "target_path_symlink_disallowed"
CONTROL_DISCOVERY_LIMIT = "manifest_discovery_limit_exceeded"
CONTROL_MANIFEST_LIMIT = "manifest_count_limit_exceeded"
CONTROL_MANIFEST_SYMLINK = "manifest_symlink_disallowed"
CONTROL_MANIFEST_UNREADABLE = "manifest_unreadable"
CONTROL_MANIFEST_OVERSIZED = "manifest_size_limit_exceeded"
CONTROL_MANIFEST_TOTAL_OVERSIZED = "manifest_total_size_limit_exceeded"
CONTROL_MANIFEST_CHANGED = "manifest_changed_during_snapshot"
CONTROL_MANIFEST_SCHEMA = "manifest_schema_invalid"
CONTROL_MANIFEST_ENCODING = "manifest_encoding_invalid"
CONTROL_SOURCE_SNAPSHOT = "source_snapshot_incomplete"
CONTROL_SNAPSHOT_DRIFT = "input_snapshot_drift"
CONTROL_INVENTORY_INCOMPLETE = "input_inventory_incomplete"
CONTROL_UNSUPPORTED_ECOSYSTEM = "unsupported_ecosystem_manifest_detected"

SUPPORTED_ECOSYSTEMS = ("python", "npm", "go")
_ECOSYSTEM_ORDER = {name: index for index, name in enumerate(SUPPORTED_ECOSYSTEMS)}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
_EXCLUDED_TREES = frozenset(name.casefold() for name in RELEASE_SNAPSHOT_EXCLUDED_TREES)
_REQUIREMENTS_NAME = re.compile(r"^requirements?(?:[-_.][a-z0-9_.-]+)?\.(?:txt|in|lock)$", re.IGNORECASE)
_CONSTRAINTS_NAME = re.compile(r"^constraints?(?:[-_.][a-z0-9_.-]+)?\.(?:txt|in|lock)$", re.IGNORECASE)
_PYTHON_LOCK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,255}\Z")
_PYTHON_LOCK_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,255}\Z")
_PEP508_DIRECT_NAME = re.compile(
    r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?=\s*(?:\[|@|[<>=!~;]|\Z))"
)
_MAX_PEP508_REQUIREMENT_BYTES = 16 * 1024
_VULNERABILITY_ID = re.compile(r"[A-Z0-9][A-Z0-9._:+-]{0,127}\Z")
_CANONICAL_VULNERABILITY_ID = re.compile(
    r"(?:CVE|PYSEC|GO|RUSTSEC)-\d{4}-\d+"
    r"|GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}"
    r"|NPM-(?:\d+|[A-F0-9]{16})"
    r"|VULN-[A-F0-9]{16}"
)
_VERSION = re.compile(r"(?<![A-Za-z0-9])v?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)")
_GHSA_IN_TEXT = re.compile(
    r"GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}",
    re.IGNORECASE,
)
_CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_UNSUPPORTED_MANIFEST_NAMES = {
    "cargo.lock": "rust",
    "cargo.toml": "rust",
    "pom.xml": "java-maven",
    "build.gradle": "java-gradle",
    "build.gradle.kts": "java-gradle",
    "gradle.lockfile": "java-gradle",
    "composer.json": "php",
    "composer.lock": "php",
    "gemfile": "ruby",
    "gemfile.lock": "ruby",
    "packages.lock.json": "dotnet",
    "paket.lock": "dotnet",
    "package.swift": "swift",
    "package.resolved": "swift",
    "pubspec.yaml": "dart",
    "pubspec.lock": "dart",
    "mix.exs": "elixir",
    "mix.lock": "elixir",
}


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _positive_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ValueError(f"{label} must be positive")
    return float(value)


@dataclass(frozen=True, slots=True)
class ScaBounds:
    max_manifest_files: int = 256
    max_manifest_bytes: int = 8 * 1024 * 1024
    max_manifest_total_bytes: int = 32 * 1024 * 1024
    max_walk_entries: int = 100_000
    max_source_files: int = 50_000
    max_source_file_bytes: int = 64 * 1024 * 1024
    max_source_total_bytes: int = 1024 * 1024 * 1024
    max_output_bytes: int = 8 * 1024 * 1024
    max_results: int = 10_000
    timeout_seconds: float = 120.0
    version_timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        for name in (
            "max_manifest_files",
            "max_manifest_bytes",
            "max_manifest_total_bytes",
            "max_walk_entries",
            "max_source_files",
            "max_source_file_bytes",
            "max_source_total_bytes",
            "max_output_bytes",
            "max_results",
        ):
            _positive_int(getattr(self, name), name)
        _positive_number(self.timeout_seconds, "timeout_seconds")
        _positive_number(self.version_timeout_seconds, "version_timeout_seconds")

    def to_dict(self) -> dict[str, int | float]:
        return {
            "max_manifest_files": self.max_manifest_files,
            "max_manifest_bytes": self.max_manifest_bytes,
            "max_manifest_total_bytes": self.max_manifest_total_bytes,
            "max_walk_entries": self.max_walk_entries,
            "max_source_files": self.max_source_files,
            "max_source_file_bytes": self.max_source_file_bytes,
            "max_source_total_bytes": self.max_source_total_bytes,
            "max_output_bytes": self.max_output_bytes,
            "max_results": self.max_results,
            "timeout_seconds": self.timeout_seconds,
            "version_timeout_seconds": self.version_timeout_seconds,
        }


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Bounded process-runner result accepted by every ecosystem adapter."""

    returncode: int
    stdout: bytes | str = b""
    stderr: bytes | str = b""
    stdout_bytes: int | None = None
    stderr_bytes: int | None = None
    timed_out: bool = False
    output_limited: bool = False
    launch_error: str = ""

    def __post_init__(self) -> None:
        stdout = self.stdout.encode("utf-8") if isinstance(self.stdout, str) else bytes(self.stdout)
        stderr = self.stderr.encode("utf-8") if isinstance(self.stderr, str) else bytes(self.stderr)
        stdout_bytes = len(stdout) if self.stdout_bytes is None else int(self.stdout_bytes)
        stderr_bytes = len(stderr) if self.stderr_bytes is None else int(self.stderr_bytes)
        if stdout_bytes < 0 or stderr_bytes < 0:
            raise ValueError("process byte counts must be non-negative")
        object.__setattr__(self, "stdout", stdout)
        object.__setattr__(self, "stderr", stderr)
        object.__setattr__(self, "stdout_bytes", stdout_bytes)
        object.__setattr__(self, "stderr_bytes", stderr_bytes)
        object.__setattr__(self, "launch_error", str(self.launch_error or ""))


class ProcessRunner(Protocol):
    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: float,
        max_output_bytes: int,
        shell: bool,
    ) -> ProcessResult | subprocess.CompletedProcess[bytes]: ...


def _ref(value: str) -> dict[str, Any]:
    return {
        "hash": evidence_hash(value),
        "hash_scheme": evidence_hash_scheme(),
        "raw_returned": False,
    }


@dataclass(frozen=True, slots=True)
class ScaFinding:
    ecosystem: str
    vulnerability_id: str
    package_ref: str
    installed_version_ref: str
    severity: str
    fixed_version_present: bool
    fingerprint: str
    raw_free: bool = True
    schema: str = SCA_FINDING_SCHEMA

    def __post_init__(self) -> None:
        if self.ecosystem not in SUPPORTED_ECOSYSTEMS:
            raise ValueError("finding ecosystem is invalid")
        if not _CANONICAL_VULNERABILITY_ID.fullmatch(self.vulnerability_id):
            raise ValueError("vulnerability id is not normalized")
        if not re.fullmatch(r"[0-9a-f]{16}", self.package_ref):
            raise ValueError("package reference is invalid")
        if not re.fullmatch(r"[0-9a-f]{16}", self.installed_version_ref):
            raise ValueError("installed version reference is invalid")
        if self.severity not in _SEVERITY_ORDER:
            raise ValueError("severity is not normalized")
        if not isinstance(self.fixed_version_present, bool):
            raise ValueError("fixed version presence must be boolean")
        if not re.fullmatch(r"[0-9a-f]{64}", self.fingerprint):
            raise ValueError("finding fingerprint is invalid")
        if self.raw_free is not True:
            raise ValueError("SCA findings must be raw-free")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "ecosystem": self.ecosystem,
            "vulnerability_id": self.vulnerability_id,
            "package_ref": {
                "hash": self.package_ref,
                "hash_scheme": evidence_hash_scheme(),
                "raw_returned": False,
            },
            "installed_version_ref": {
                "hash": self.installed_version_ref,
                "hash_scheme": evidence_hash_scheme(),
                "raw_returned": False,
            },
            "severity": self.severity,
            "fixed_version_present": self.fixed_version_present,
            "fingerprint": self.fingerprint,
            "raw_free": True,
        }


@dataclass(frozen=True, slots=True)
class ScaAdapterRun:
    ecosystem: str
    complete: bool
    control_errors: tuple[str, ...]
    findings: tuple[ScaFinding, ...]
    engine_name: str
    engine_version: str
    command_contract: Mapping[str, Any]
    command_contract_sha256: str
    input_snapshot: Mapping[str, Any]
    inventory: Mapping[str, Any]
    counts: Mapping[str, int]
    bounds: Mapping[str, int | float]
    raw_free: bool = True
    schema: str = SCA_ADAPTER_SCHEMA

    def __post_init__(self) -> None:
        errors = tuple(dict.fromkeys(str(item) for item in self.control_errors if str(item)))
        findings = tuple(self.findings)
        counts = {str(key): int(value) for key, value in self.counts.items()}
        if self.ecosystem not in SUPPORTED_ECOSYSTEMS:
            raise ValueError("adapter ecosystem is invalid")
        if self.complete and errors:
            raise ValueError("a complete adapter cannot have control errors")
        if not self.complete and not errors:
            raise ValueError("an incomplete adapter requires a control error")
        if any(value < 0 for value in counts.values()):
            raise ValueError("adapter counts must be non-negative")
        if not re.fullmatch(r"[0-9a-f]{64}", self.command_contract_sha256):
            raise ValueError("command contract hash is invalid")
        if any(finding.ecosystem != self.ecosystem for finding in findings):
            raise ValueError("adapter finding ecosystem mismatch")
        if self.raw_free is not True:
            raise ValueError("SCA adapter reports must be raw-free")
        object.__setattr__(self, "control_errors", errors)
        object.__setattr__(self, "findings", findings)
        object.__setattr__(self, "command_contract", MappingProxyType(dict(self.command_contract)))
        object.__setattr__(self, "input_snapshot", MappingProxyType(dict(self.input_snapshot)))
        object.__setattr__(self, "inventory", MappingProxyType(dict(self.inventory)))
        object.__setattr__(self, "counts", MappingProxyType(counts))
        object.__setattr__(self, "bounds", MappingProxyType(dict(self.bounds)))

    @property
    def passed(self) -> bool:
        return self.complete and not self.findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "ecosystem": self.ecosystem,
            "complete": self.complete,
            "passed": self.passed,
            "control_errors": list(self.control_errors),
            "findings": [finding.to_dict() for finding in self.findings],
            "engine": {
                "name": self.engine_name,
                "version": self.engine_version,
                "command_contract": dict(self.command_contract),
                "command_contract_sha256": self.command_contract_sha256,
                "raw_returned": False,
            },
            "input_snapshot": dict(self.input_snapshot),
            "inventory": dict(self.inventory),
            "counts": dict(self.counts),
            "bounds": dict(self.bounds),
            "raw_free": True,
        }


@dataclass(frozen=True, slots=True)
class ScaRun:
    complete: bool
    control_errors: tuple[str, ...]
    findings: tuple[ScaFinding, ...]
    requested_ecosystems: tuple[str, ...]
    audited_ecosystems: tuple[str, ...]
    adapters: tuple[ScaAdapterRun, ...]
    input_snapshot: Mapping[str, Any]
    inventory: Mapping[str, Any]
    counts: Mapping[str, int]
    raw_free: bool = True
    schema: str = SCA_SCHEMA

    def __post_init__(self) -> None:
        errors = tuple(dict.fromkeys(str(item) for item in self.control_errors if str(item)))
        findings = tuple(self.findings)
        requested = tuple(sorted(set(self.requested_ecosystems), key=_ECOSYSTEM_ORDER.__getitem__))
        audited = tuple(sorted(set(self.audited_ecosystems), key=_ECOSYSTEM_ORDER.__getitem__))
        adapters = tuple(sorted(self.adapters, key=lambda item: _ECOSYSTEM_ORDER[item.ecosystem]))
        counts = {str(key): int(value) for key, value in self.counts.items()}
        if self.complete and errors:
            raise ValueError("a complete SCA run cannot have control errors")
        if not self.complete and not errors:
            raise ValueError("an incomplete SCA run requires a control error")
        if set(audited) - set(requested):
            raise ValueError("audited ecosystems must be requested")
        if any(value < 0 for value in counts.values()):
            raise ValueError("SCA counts must be non-negative")
        if self.raw_free is not True:
            raise ValueError("SCA runs must be raw-free")
        object.__setattr__(self, "control_errors", errors)
        object.__setattr__(self, "findings", findings)
        object.__setattr__(self, "requested_ecosystems", requested)
        object.__setattr__(self, "audited_ecosystems", audited)
        object.__setattr__(self, "adapters", adapters)
        object.__setattr__(self, "input_snapshot", MappingProxyType(dict(self.input_snapshot)))
        object.__setattr__(self, "inventory", MappingProxyType(dict(self.inventory)))
        object.__setattr__(self, "counts", MappingProxyType(counts))

    @property
    def passed(self) -> bool:
        return self.complete and not self.findings

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": self.schema,
            "complete": self.complete,
            "passed": self.passed,
            "control_errors": list(self.control_errors),
            "requested_ecosystems": list(self.requested_ecosystems),
            "audited_ecosystems": list(self.audited_ecosystems),
            "findings": [finding.to_dict() for finding in self.findings],
            "adapters": [adapter.to_dict() for adapter in self.adapters],
            "input_snapshot": dict(self.input_snapshot),
            "inventory": dict(self.inventory),
            "counts": dict(self.counts),
            "raw_free": True,
        }
        payload["report_sha256"] = _sha256_json(payload)
        return payload

    def to_report(self) -> dict[str, Any]:
        return build_sca_report(self)


@dataclass(frozen=True, slots=True)
class _InputFile:
    path: Path
    relative: str
    ecosystem: str
    kind: str
    roles: tuple[str, ...]
    content: bytes = field(repr=False)
    sha256: str
    package_names: frozenset[str] = frozenset()


@dataclass(slots=True)
class _InventoryState:
    root: Path | None
    files: tuple[_InputFile, ...]
    errors: tuple[str, ...]
    detected_ecosystems: tuple[str, ...]
    snapshot: dict[str, Any]
    inventory: dict[str, Any]
    uncovered: dict[str, int]


@dataclass(frozen=True, slots=True)
class _AuditUnit:
    ecosystem: str
    kind: str
    cwd: Path
    source: _InputFile


def _sha256_json(value: Any) -> str:
    rendered = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(rendered.encode("ascii")).hexdigest()


def _candidate_kind(name: str) -> tuple[str, str] | None:
    lower = name.casefold()
    if _REQUIREMENTS_NAME.fullmatch(lower):
        suffix = Path(lower).suffix
        return "python", "requirements_in" if suffix == ".in" else "requirements"
    if _CONSTRAINTS_NAME.fullmatch(lower):
        return "python", "constraints"
    if lower == "pyproject.toml":
        return "python", "pyproject"
    if lower == "poetry.lock":
        return "python", "poetry_lock"
    if lower == "pipfile":
        return "python", "pipfile"
    if lower == "pipfile.lock":
        return "python", "pipfile_lock"
    if lower == "package.json":
        return "npm", "package_manifest"
    if lower == "package-lock.json":
        return "npm", "package_lock"
    if lower == "npm-shrinkwrap.json":
        return "npm", "npm_shrinkwrap"
    if lower == "yarn.lock":
        return "npm", "yarn_lock"
    if lower == "pnpm-lock.yaml":
        return "npm", "pnpm_lock"
    if lower == "go.mod":
        return "go", "go_mod"
    if lower == "go.sum":
        return "go", "go_sum"
    return None


def _unsupported_manifest_ecosystem(name: str) -> str | None:
    lower = name.casefold()
    if lower.endswith(('.csproj', '.fsproj', '.vbproj')):
        return "dotnet"
    return _UNSUPPORTED_MANIFEST_NAMES.get(lower)


def _decode_manifest(content: bytes) -> str:
    return content.decode("utf-8-sig")


def _requirement_pins(content: bytes) -> tuple[bool, frozenset[str]]:
    text = _decode_manifest(content)
    logical_lines: list[str] = []
    pending = ""
    for physical in text.splitlines():
        stripped = physical.strip()
        if pending:
            pending += stripped
        else:
            pending = stripped
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        logical_lines.append(pending)
        pending = ""
    if pending:
        logical_lines.append(pending)

    names: set[str] = set()
    saw_requirement = False
    exact = True
    for line in logical_lines:
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        if not line or line.startswith("#") or line.startswith("--hash="):
            continue
        if line.startswith(("-r", "--requirement", "-c", "--constraint")):
            exact = False
            continue
        if line.startswith("-"):
            continue
        requirement = line.split(";", 1)[0].strip()
        match = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*(===|==)\s*([^,\s]+)",
            requirement,
        )
        saw_requirement = True
        if not match or "*" in match.group(3):
            exact = False
            loose_name = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)", requirement)
            if loose_name:
                names.add(_normalize_python_package(loose_name.group(1)))
            continue
        names.add(_normalize_python_package(match.group(1)))
    return saw_requirement and exact, frozenset(names)


def _normalize_python_package(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value.strip().casefold())


def _pep508_direct_name(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or any(character in value for character in "\x00\r\n"):
        raise ValueError
    if len(value.encode("utf-8")) > _MAX_PEP508_REQUIREMENT_BYTES:
        raise ValueError
    if Requirement is not None:
        try:
            return _normalize_python_package(Requirement(value).name)
        except InvalidRequirement as error:
            raise ValueError from error
    match = _PEP508_DIRECT_NAME.match(value)
    if not match:
        raise ValueError
    return _normalize_python_package(match.group(1))


def _pyproject_contract(content: bytes) -> tuple[frozenset[str], bool]:
    payload = tomllib.loads(_decode_manifest(content))
    if not isinstance(payload, dict):
        raise ValueError
    project = payload.get("project", {})
    if not isinstance(project, dict):
        raise ValueError
    dependencies = project.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValueError
    optional = project.get("optional-dependencies", {})
    if not isinstance(optional, dict):
        raise ValueError
    declared: list[Any] = list(dependencies)
    for group_dependencies in optional.values():
        if not isinstance(group_dependencies, list):
            raise ValueError
        declared.extend(group_dependencies)

    tool = payload.get("tool", {})
    if not isinstance(tool, dict):
        raise ValueError
    poetry_project = "poetry" in tool
    if poetry_project and not isinstance(tool.get("poetry"), dict):
        raise ValueError
    return frozenset(_pep508_direct_name(item) for item in declared), poetry_project


def _requirement_file_references(content: bytes) -> tuple[str, ...]:
    text = _decode_manifest(content)
    references: set[str] = set()
    for raw_line in text.splitlines():
        line = re.split(r"\s+#", raw_line, maxsplit=1)[0].strip()
        match = re.match(r"^(?:-c|--constraint|-r|--requirement)(?:\s+|=)(\S+)$", line)
        if not match:
            continue
        rendered = match.group(1).replace("\\", "/")
        candidate = Path(rendered)
        if candidate.is_absolute() or ".." in candidate.parts:
            continue
        references.add(rendered.casefold())
    return tuple(sorted(references))


def _validate_and_classify(
    ecosystem: str,
    kind: str,
    content: bytes,
) -> tuple[tuple[str, ...], frozenset[str], tuple[str, ...]]:
    errors: list[str] = []
    names: frozenset[str] = frozenset()
    roles: tuple[str, ...]
    try:
        if kind in {"requirements", "requirements_in", "constraints"}:
            exact, names = _requirement_pins(content)
            if kind == "requirements_in":
                roles = ("manifest",)
            elif exact:
                roles = ("manifest", "lock")
            else:
                roles = ("manifest",)
        elif kind == "pyproject":
            names, poetry_project = _pyproject_contract(content)
            roles = ("manifest",) if names or poetry_project else ()
        elif kind == "poetry_lock":
            payload = tomllib.loads(_decode_manifest(content))
            packages = payload.get("package", [])
            if not isinstance(packages, list):
                raise ValueError
            names = frozenset(
                _normalize_python_package(str(row.get("name")))
                for row in packages
                if isinstance(row, dict) and row.get("name")
            )
            roles = ("lock",)
        elif kind == "pipfile":
            payload = tomllib.loads(_decode_manifest(content))
            if not isinstance(payload, dict):
                raise ValueError
            declared = {
                _normalize_python_package(str(name))
                for group in ("packages", "dev-packages")
                for name in (payload.get(group, {}) if isinstance(payload.get(group, {}), dict) else {})
            }
            names = frozenset(declared)
            roles = ("manifest",)
        elif kind == "pipfile_lock":
            payload = json.loads(_decode_manifest(content))
            if not isinstance(payload, dict):
                raise ValueError
            locked = {
                _normalize_python_package(str(name))
                for group in ("default", "develop")
                for name in (payload.get(group, {}) if isinstance(payload.get(group, {}), dict) else {})
            }
            names = frozenset(locked)
            roles = ("lock",)
        elif kind in {"package_manifest", "package_lock", "npm_shrinkwrap"}:
            payload = json.loads(_decode_manifest(content))
            if not isinstance(payload, dict):
                raise ValueError
            roles = ("manifest",) if kind == "package_manifest" else ("lock",)
        elif kind in {"yarn_lock", "pnpm_lock"}:
            _decode_manifest(content)
            roles = ("lock",)
        elif kind == "go_mod":
            text = _decode_manifest(content)
            if not re.search(r"(?m)^\s*module\s+\S+", text):
                raise ValueError
            roles = ("manifest",)
        elif kind == "go_sum":
            _decode_manifest(content)
            roles = ("lock",)
        else:
            raise ValueError
    except UnicodeDecodeError:
        errors.append(CONTROL_MANIFEST_ENCODING)
        roles = ()
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, TypeError, ValueError):
        errors.append(CONTROL_MANIFEST_SCHEMA)
        roles = ()
    return roles, names, tuple(errors)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _read_manifest_bounded(path: Path, max_bytes: int) -> tuple[bytes, bool]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        content = stream.read(max_bytes + 1)
    return content[:max_bytes], len(content) > max_bytes


def _discover(root_value: str | Path, bounds: ScaBounds) -> _InventoryState:
    errors: list[str] = []
    detected: set[str] = set()
    files: list[_InputFile] = []
    root: Path | None = None
    total_bytes = 0
    walk_entries = 0
    candidate_count = 0
    unsupported_manifest_counts: dict[str, int] = {}
    text = str(root_value)
    candidate = Path(root_value)
    if not text.strip() or "\x00" in text:
        errors.append(CONTROL_TARGET_INVALID)
    else:
        try:
            if candidate.is_symlink():
                errors.append(CONTROL_TARGET_SYMLINK)
            elif not candidate.exists():
                errors.append(CONTROL_TARGET_NOT_FOUND)
            elif not candidate.is_dir():
                errors.append(CONTROL_TARGET_NOT_DIRECTORY)
            else:
                root = candidate.resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            errors.append(CONTROL_TARGET_INVALID)

    stop = bool(errors)
    if root is not None and not stop:
        def walk_error(_error: OSError) -> None:
            errors.append(CONTROL_MANIFEST_UNREADABLE)

        for current, directory_names, file_names in os.walk(
            root,
            topdown=True,
            followlinks=False,
            onerror=walk_error,
        ):
            directory_names.sort(key=str.casefold)
            file_names.sort(key=str.casefold)
            kept_directories: list[str] = []
            for name in directory_names:
                walk_entries += 1
                if walk_entries > bounds.max_walk_entries:
                    errors.append(CONTROL_DISCOVERY_LIMIT)
                    stop = True
                    break
                directory = Path(current) / name
                if name.casefold() in _EXCLUDED_TREES:
                    continue
                try:
                    if directory.is_symlink():
                        errors.append(CONTROL_MANIFEST_SYMLINK)
                        continue
                except OSError:
                    errors.append(CONTROL_MANIFEST_UNREADABLE)
                    continue
                kept_directories.append(name)
            directory_names[:] = kept_directories
            if stop:
                break
            for name in file_names:
                walk_entries += 1
                if walk_entries > bounds.max_walk_entries:
                    errors.append(CONTROL_DISCOVERY_LIMIT)
                    stop = True
                    break
                path = Path(current) / name
                try:
                    if path.is_symlink():
                        errors.append(CONTROL_MANIFEST_SYMLINK)
                        continue
                except OSError:
                    errors.append(CONTROL_MANIFEST_UNREADABLE)
                    continue
                classification = _candidate_kind(name)
                if classification is None:
                    unsupported = _unsupported_manifest_ecosystem(name)
                    if unsupported:
                        unsupported_manifest_counts[unsupported] = unsupported_manifest_counts.get(unsupported, 0) + 1
                        errors.append(CONTROL_UNSUPPORTED_ECOSYSTEM)
                    continue
                ecosystem, kind = classification
                detected.add(ecosystem)
                candidate_count += 1
                if candidate_count > bounds.max_manifest_files:
                    errors.append(CONTROL_MANIFEST_LIMIT)
                    stop = True
                    break
                try:
                    before = path.stat()
                    if not path.is_file():
                        errors.append(CONTROL_MANIFEST_UNREADABLE)
                        continue
                    if before.st_size > bounds.max_manifest_bytes:
                        errors.append(CONTROL_MANIFEST_OVERSIZED)
                        continue
                    if total_bytes + before.st_size > bounds.max_manifest_total_bytes:
                        errors.append(CONTROL_MANIFEST_TOTAL_OVERSIZED)
                        stop = True
                        break
                    resolved_before = path.resolve(strict=True)
                    if not _is_relative_to(resolved_before, root):
                        errors.append(CONTROL_MANIFEST_SYMLINK)
                        continue
                    remaining_total_bytes = bounds.max_manifest_total_bytes - total_bytes
                    content, read_limited = _read_manifest_bounded(
                        path,
                        min(bounds.max_manifest_bytes, remaining_total_bytes),
                    )
                    if read_limited:
                        if remaining_total_bytes <= bounds.max_manifest_bytes:
                            errors.append(CONTROL_MANIFEST_TOTAL_OVERSIZED)
                            stop = True
                            break
                        errors.append(CONTROL_MANIFEST_OVERSIZED)
                        continue
                    after = path.stat()
                    if (
                        path.is_symlink()
                        or len(content) != before.st_size
                        or before.st_size != after.st_size
                        or before.st_mtime_ns != after.st_mtime_ns
                    ):
                        errors.append(CONTROL_MANIFEST_CHANGED)
                        continue
                    resolved = path.resolve(strict=True)
                    if not _is_relative_to(resolved, root):
                        errors.append(CONTROL_MANIFEST_SYMLINK)
                        continue
                    relative = resolved.relative_to(root).as_posix()
                except (OSError, RuntimeError, ValueError):
                    errors.append(CONTROL_MANIFEST_UNREADABLE)
                    continue
                total_bytes += len(content)
                roles, package_names, validation_errors = _validate_and_classify(ecosystem, kind, content)
                errors.extend(validation_errors)
                if not roles:
                    continue
                files.append(
                    _InputFile(
                        path=resolved,
                        relative=relative,
                        ecosystem=ecosystem,
                        kind=kind,
                        roles=roles,
                        content=content,
                        sha256=hashlib.sha256(content).hexdigest(),
                        package_names=package_names,
                    )
                )
            if stop:
                break

    files.sort(key=lambda item: (item.relative.casefold(), item.kind, item.sha256))
    uncovered = _uncovered_manifest_counts(root, files)
    source_snapshot = _bounded_source_snapshot(root, bounds)
    if root is not None and source_snapshot.get("complete") is not True:
        errors.append(CONTROL_SOURCE_SNAPSHOT)
    snapshot = _snapshot_projection(
        root,
        files,
        errors,
        total_bytes,
        walk_entries,
        bounds,
        source_snapshot,
    )
    inventory = _inventory_projection(files, uncovered)
    unsupported_count = sum(unsupported_manifest_counts.values())
    unsupported_refs = [evidence_hash(name) for name in sorted(unsupported_manifest_counts)]
    snapshot["excluded_test_fixture_manifest_count"] = 0
    snapshot["unsupported_manifest_count"] = unsupported_count
    snapshot["unsupported_ecosystem_refs"] = unsupported_refs
    inventory["excluded_test_fixture_manifest_count"] = 0
    inventory["unsupported_manifest_count"] = unsupported_count
    inventory["unsupported_ecosystem_refs"] = unsupported_refs
    return _InventoryState(
        root=root,
        files=tuple(files),
        errors=tuple(dict.fromkeys(errors)),
        detected_ecosystems=tuple(sorted(detected, key=_ECOSYSTEM_ORDER.__getitem__)),
        snapshot=snapshot,
        inventory=inventory,
        uncovered=uncovered,
    )


def _same_or_ancestor(candidate: Path, directory: Path) -> bool:
    return candidate == directory or _is_relative_to(directory, candidate)


def _python_manifest_is_covered(manifest: _InputFile, locks: Sequence[_InputFile]) -> bool:
    if "lock" in manifest.roles:
        return True
    same_directory = [lock for lock in locks if lock.path.parent == manifest.path.parent]
    if manifest.kind == "pyproject":
        try:
            declared_names, poetry_project = _pyproject_contract(manifest.content)
        except (UnicodeDecodeError, tomllib.TOMLDecodeError, TypeError, ValueError):
            return False
        if poetry_project:
            return any(lock.kind == "poetry_lock" for lock in same_directory)
        compatible = [
            lock
            for lock in same_directory
            if lock.kind in {"requirements", "constraints"}
        ]
        return bool(declared_names) and any(
            declared_names.issubset(lock.package_names)
            for lock in compatible
        )
    if manifest.kind == "pipfile":
        return any(lock.kind == "pipfile_lock" for lock in same_directory)
    compatible = [lock for lock in same_directory if lock.kind in {"requirements", "constraints"}]
    if not compatible:
        if manifest.kind != "requirements":
            return False
    if manifest.kind == "requirements":
        references = _requirement_file_references(manifest.content)
        compatible = [
            lock
            for lock in locks
            if lock.kind in {"requirements", "constraints"}
            if any(
                (manifest.path.parent / reference).resolve(strict=False) == lock.path
                for reference in references
            )
        ]
        if not compatible:
            return False
    elif manifest.kind == "requirements_in":
        expected_names = {
            f"{manifest.path.stem}.txt".casefold(),
            f"{manifest.path.stem}.lock".casefold(),
        }
        compatible = [lock for lock in compatible if lock.path.name.casefold() in expected_names]
        if not compatible:
            return False
    elif manifest.kind == "constraints":
        return False
    if not manifest.package_names:
        return True
    return any(manifest.package_names.issubset(lock.package_names) for lock in compatible)


def _uncovered_manifest_counts(root: Path | None, files: Sequence[_InputFile]) -> dict[str, int]:
    del root
    uncovered = {ecosystem: 0 for ecosystem in SUPPORTED_ECOSYSTEMS}
    for ecosystem in SUPPORTED_ECOSYSTEMS:
        manifests = [item for item in files if item.ecosystem == ecosystem and "manifest" in item.roles]
        locks = [item for item in files if item.ecosystem == ecosystem and "lock" in item.roles]
        for manifest in manifests:
            if ecosystem == "python":
                covered = _python_manifest_is_covered(manifest, locks)
            elif ecosystem == "npm":
                covered = any(_same_or_ancestor(lock.path.parent, manifest.path.parent) for lock in locks)
            else:
                covered = any(lock.kind == "go_sum" and lock.path.parent == manifest.path.parent for lock in locks)
            if not covered:
                uncovered[ecosystem] += 1
    return uncovered


def _snapshot_projection(
    root: Path | None,
    files: Sequence[_InputFile],
    errors: Sequence[str],
    total_bytes: int,
    walk_entries: int,
    bounds: ScaBounds,
    source_snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    rows = [
        {
            "relative": item.relative,
            "ecosystem": item.ecosystem,
            "kind": item.kind,
            "roles": list(item.roles),
            "sha256": item.sha256,
            "byte_count": len(item.content),
        }
        for item in files
    ]
    projection = dict(source_snapshot)
    projection.update(
        {
        "root_ref": _ref(str(root or "")),
        "snapshot_sha256": _sha256_json(rows),
        "manifest_file_set_sha256": _sha256_json([row["relative"] for row in rows]),
        "manifest_file_count": len(files),
        "manifest_byte_count": total_bytes,
        "walk_entry_count": walk_entries,
        "manifest_inventory_complete": not errors,
        "complete": source_snapshot.get("complete") is True and not errors,
        "limit_exceeded": source_snapshot.get("limit_exceeded") is True
        or any("limit_exceeded" in error for error in errors),
        "manifest_bounds": {
            "max_manifest_files": bounds.max_manifest_files,
            "max_manifest_bytes": bounds.max_manifest_bytes,
            "max_manifest_total_bytes": bounds.max_manifest_total_bytes,
            "max_walk_entries": bounds.max_walk_entries,
        },
        "raw_returned": False,
        }
    )
    return projection


def _bounded_source_snapshot(root: Path | None, bounds: ScaBounds) -> dict[str, Any]:
    if root is None:
        return {
            "schema": "k_guard_source_tree_snapshot.v1",
            "collector": "bounded_independent_release_snapshot.v1",
            "tree_sha256": hashlib.sha256().hexdigest(),
            "file_count": 0,
            "hashed_file_count": 0,
            "unreadable_file_count": 0,
            "oversized_file_count": 0,
            "skipped_symlink_tree_count": 0,
            "byte_count": 0,
            "complete": False,
            "limit_exceeded": False,
            "bounds": {
                "max_files": bounds.max_source_files,
                "max_file_bytes": bounds.max_source_file_bytes,
                "max_total_bytes": bounds.max_source_total_bytes,
            },
            "raw_returned": False,
        }
    return source_tree_snapshot(
        root,
        max_files=bounds.max_source_files,
        max_file_bytes=bounds.max_source_file_bytes,
        max_total_bytes=bounds.max_source_total_bytes,
    )


def _inventory_projection(files: Sequence[_InputFile], uncovered: Mapping[str, int]) -> dict[str, Any]:
    manifest_rows: list[dict[str, str]] = []
    lock_rows: list[dict[str, str]] = []
    ecosystem_counts: dict[str, dict[str, Any]] = {}
    for ecosystem in SUPPORTED_ECOSYSTEMS:
        ecosystem_files = [item for item in files if item.ecosystem == ecosystem]
        manifests = [item for item in ecosystem_files if "manifest" in item.roles]
        locks = [item for item in ecosystem_files if "lock" in item.roles]
        kinds: dict[str, int] = {}
        for item in locks:
            kinds[item.kind] = kinds.get(item.kind, 0) + 1
        ecosystem_counts[ecosystem] = {
            "file_count": len(ecosystem_files),
            "manifest_count": len(manifests),
            "lock_count": len(locks),
            "uncovered_manifest_count": int(uncovered.get(ecosystem, 0)),
            "lock_kind_counts": dict(sorted(kinds.items())),
        }
        manifest_rows.extend(
            {"relative": item.relative, "sha256": item.sha256, "kind": item.kind}
            for item in manifests
        )
        lock_rows.extend(
            {"relative": item.relative, "sha256": item.sha256, "kind": item.kind}
            for item in locks
        )
    all_rows = sorted([*manifest_rows, *lock_rows], key=lambda row: (row["relative"], row["kind"], row["sha256"]))
    return {
        "schema": SCA_INVENTORY_SCHEMA,
        "file_count": len(files),
        "manifest_count": len(manifest_rows),
        "lock_count": len(lock_rows),
        "uncovered_manifest_count": sum(int(value) for value in uncovered.values()),
        "manifest_set_sha256": _sha256_json(sorted(manifest_rows, key=lambda row: (row["relative"], row["kind"]))),
        "lock_set_sha256": _sha256_json(sorted(lock_rows, key=lambda row: (row["relative"], row["kind"]))),
        "inventory_set_sha256": _sha256_json(all_rows),
        "ecosystems": ecosystem_counts,
        "raw_returned": False,
    }


def _ecosystem_inventory(inventory: Mapping[str, Any], ecosystem: str) -> dict[str, Any]:
    ecosystems = inventory.get("ecosystems", {})
    counts = ecosystems.get(ecosystem, {}) if isinstance(ecosystems, Mapping) else {}
    return {
        "schema": SCA_INVENTORY_SCHEMA,
        "ecosystem": ecosystem,
        "file_count": int(counts.get("file_count", 0)),
        "manifest_count": int(counts.get("manifest_count", 0)),
        "lock_count": int(counts.get("lock_count", 0)),
        "uncovered_manifest_count": int(counts.get("uncovered_manifest_count", 0)),
        "lock_kind_counts": dict(counts.get("lock_kind_counts", {})),
        "inventory_set_sha256": str(inventory.get("inventory_set_sha256", "")),
        "raw_returned": False,
    }


def _ecosystem_snapshot(snapshot: Mapping[str, Any], inventory: Mapping[str, Any], ecosystem: str) -> dict[str, Any]:
    projected_inventory = _ecosystem_inventory(inventory, ecosystem)
    return {
        "schema": SCA_INPUT_SNAPSHOT_SCHEMA,
        "snapshot_sha256": str(snapshot.get("snapshot_sha256", "")),
        "tree_sha256": str(snapshot.get("tree_sha256", "")),
        "manifest_file_set_sha256": str(snapshot.get("manifest_file_set_sha256", "")),
        "file_count": projected_inventory["file_count"],
        "source_file_count": int(snapshot.get("file_count", 0)),
        "source_byte_count": int(snapshot.get("byte_count", 0)),
        "complete": snapshot.get("complete") is True,
        "raw_returned": False,
    }


def _command_contract(ecosystem: str, bounds: ScaBounds) -> dict[str, Any]:
    if ecosystem == "python":
        engine = "pip-audit"
        audit_argv: Any = {
            "requirements": [
                "{engine}",
                "--format=json",
                "--progress-spinner=off",
                "--strict",
                "-r",
                "{lock}",
            ],
            "locked_project": [
                "{engine}",
                "--format=json",
                "--progress-spinner=off",
                "--strict",
                "--disable-pip",
                "--no-deps",
                "-r",
                "{normalized-temporary-lock-requirements}",
            ],
        }
        accepted_vulnerability_exit_codes = [1]
    elif ecosystem == "npm":
        engine = "npm"
        audit_argv = ["{engine}", "audit", "--json", "--package-lock-only"]
        accepted_vulnerability_exit_codes = [1]
    else:
        engine = "govulncheck"
        audit_argv = ["{engine}", "-json", "./..."]
        accepted_vulnerability_exit_codes = []
    version_argv = ["{engine}", "-version"] if ecosystem == "go" else ["{engine}", "--version"]
    return {
        "schema": SCA_COMMAND_CONTRACT_SCHEMA,
        "engine": engine,
        "version_argv": version_argv,
        "audit_argv": audit_argv,
        "cwd": "{validated-manifest-directory}",
        "shell": False,
        "accepted_vulnerability_exit_codes": accepted_vulnerability_exit_codes,
        "success_requires_valid_complete_json": True,
        "temporary_input_policy": "ephemeral-normalized-lock-file" if ecosystem == "python" else "none",
        "limits": {
            "max_output_bytes": bounds.max_output_bytes,
            "max_results": bounds.max_results,
            "timeout_seconds": bounds.timeout_seconds,
            "version_timeout_seconds": bounds.version_timeout_seconds,
        },
        "raw_returned": False,
    }


def _engine_name(ecosystem: str) -> str:
    return {"python": "pip-audit", "npm": "npm", "go": "govulncheck"}[ecosystem]


def _version_argv(ecosystem: str, executable: str) -> list[str]:
    return [executable, "-version" if ecosystem == "go" else "--version"]


def _default_counts(inventory: Mapping[str, Any]) -> dict[str, int]:
    return {
        "manifest_count": int(inventory.get("manifest_count", 0)),
        "lock_count": int(inventory.get("lock_count", 0)),
        "uncovered_manifest_count": int(inventory.get("uncovered_manifest_count", 0)),
        "invocation_count": 0,
        "version_stdout_bytes": 0,
        "version_stderr_bytes": 0,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "result_count": 0,
        "finding_count": 0,
    }


def _audit_units(ecosystem: str, state: _InventoryState) -> tuple[list[_AuditUnit], tuple[str, ...]]:
    files = [item for item in state.files if item.ecosystem == ecosystem]
    manifests = [item for item in files if "manifest" in item.roles]
    locks = [item for item in files if "lock" in item.roles]
    errors: list[str] = []
    if not files:
        return [], (f"{ecosystem}_manifest_missing",)
    if not manifests:
        errors.append(f"{ecosystem}_manifest_missing")
    if state.uncovered.get(ecosystem, 0):
        errors.append(f"{ecosystem}_manifest_without_lock")
    units: list[_AuditUnit] = []
    if ecosystem == "python":
        for lock in locks:
            if lock.kind in {"requirements", "constraints"}:
                units.append(_AuditUnit(ecosystem, "requirements", lock.path.parent, lock))
            elif lock.kind in {"poetry_lock", "pipfile_lock"}:
                units.append(_AuditUnit(ecosystem, "locked_project", lock.path.parent, lock))
        for manifest in manifests:
            if (
                manifest.kind == "requirements"
                and "lock" not in manifest.roles
                and _python_manifest_is_covered(manifest, locks)
            ):
                units.append(_AuditUnit(ecosystem, "requirements", manifest.path.parent, manifest))
        units = _dedupe_units(units)
    elif ecosystem == "npm":
        unsupported = [lock for lock in locks if lock.kind in {"yarn_lock", "pnpm_lock"}]
        if unsupported:
            errors.append("npm_lock_manager_unsupported")
        for lock in locks:
            if lock.kind in {"package_lock", "npm_shrinkwrap"}:
                units.append(_AuditUnit(ecosystem, lock.kind, lock.path.parent, lock))
        units = _dedupe_units(units)
    else:
        sums = {item.path.parent: item for item in locks if item.kind == "go_sum"}
        for manifest in manifests:
            source = sums.get(manifest.path.parent)
            if source is not None:
                units.append(_AuditUnit(ecosystem, "go_module", manifest.path.parent, source))
        if locks and not manifests:
            errors.append("go_manifest_missing")
        units = _dedupe_units(units)
    if not units and not errors:
        errors.append(f"{ecosystem}_auditable_lock_missing")
    return units, tuple(dict.fromkeys(errors))


def _dedupe_units(units: Sequence[_AuditUnit]) -> list[_AuditUnit]:
    unique: dict[tuple[str, str], _AuditUnit] = {}
    for unit in units:
        key = (unit.source.relative.casefold(), unit.kind)
        unique.setdefault(key, unit)
    return sorted(
        unique.values(),
        key=lambda unit: (str(unit.cwd).casefold(), unit.kind, unit.source.relative.casefold()),
    )


class _LocalProcessRunner:
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
        if shell:
            return ProcessResult(-1, launch_error="shell_disallowed")
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
            return ProcessResult(-1, launch_error="missing")
        except OSError:
            return ProcessResult(-1, launch_error="os_error")

        stdout_buffer = bytearray()
        state = {"stdout": 0, "stderr": 0, "total": 0}
        state_lock = threading.Lock()
        output_limited = threading.Event()

        def drain(stream: Any, counter: str, keep: bool) -> None:
            try:
                while True:
                    chunk = stream.read(64 * 1024)
                    if not chunk:
                        return
                    with state_lock:
                        available = max(0, max_output_bytes - state["total"])
                        state[counter] = min(max_output_bytes + 1, state[counter] + len(chunk))
                        state["total"] = min(max_output_bytes + 1, state["total"] + len(chunk))
                        if keep and available:
                            stdout_buffer.extend(chunk[:available])
                        if state["total"] > max_output_bytes:
                            output_limited.set()
            except OSError:
                output_limited.set()

        stdout_thread = threading.Thread(target=drain, args=(process.stdout, "stdout", True), daemon=True)
        stderr_thread = threading.Thread(target=drain, args=(process.stderr, "stderr", False), daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        deadline = time.monotonic() + timeout_seconds
        timed_out = False
        while process.poll() is None:
            if output_limited.is_set():
                _terminate_process(process)
                break
            if time.monotonic() >= deadline:
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
        if stdout_thread.is_alive() or stderr_thread.is_alive():
            output_limited.set()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        return ProcessResult(
            int(process.returncode if process.returncode is not None else -1),
            stdout=bytes(stdout_buffer),
            stdout_bytes=state["stdout"],
            stderr_bytes=state["stderr"],
            timed_out=timed_out,
            output_limited=output_limited.is_set(),
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


def _coerce_process_result(value: Any, max_output_bytes: int) -> ProcessResult:
    if isinstance(value, ProcessResult):
        result = value
    elif isinstance(value, Mapping):
        result = ProcessResult(
            returncode=int(value.get("returncode", -1)),
            stdout=value.get("stdout", b""),
            stderr=value.get("stderr", b""),
            stdout_bytes=value.get("stdout_bytes"),
            stderr_bytes=value.get("stderr_bytes"),
            timed_out=bool(value.get("timed_out", False)),
            output_limited=bool(value.get("output_limited", False)),
            launch_error=str(value.get("launch_error", "") or ""),
        )
    else:
        result = ProcessResult(
            returncode=int(getattr(value, "returncode", -1)),
            stdout=getattr(value, "stdout", b"") or b"",
            stderr=getattr(value, "stderr", b"") or b"",
            stdout_bytes=getattr(value, "stdout_bytes", None),
            stderr_bytes=getattr(value, "stderr_bytes", None),
            timed_out=bool(getattr(value, "timed_out", False)),
            output_limited=bool(getattr(value, "output_limited", False)),
            launch_error=str(getattr(value, "launch_error", "") or ""),
        )
    stdout = bytes(result.stdout)
    stderr = bytes(result.stderr)
    stdout_count = max(len(stdout), int(result.stdout_bytes or 0))
    stderr_count = max(len(stderr), int(result.stderr_bytes or 0))
    limited = result.output_limited or stdout_count + stderr_count > max_output_bytes
    return ProcessResult(
        result.returncode,
        stdout=stdout[:max_output_bytes],
        stderr=b"",
        stdout_bytes=min(stdout_count, max_output_bytes + 1),
        stderr_bytes=min(stderr_count, max_output_bytes + 1),
        timed_out=result.timed_out,
        output_limited=limited,
        launch_error=result.launch_error,
    )


def _process_errors(ecosystem: str, result: ProcessResult, *, version: bool) -> list[str]:
    errors: list[str] = []
    if result.launch_error == "missing":
        errors.append(f"{ecosystem}_engine_missing")
    elif result.launch_error:
        errors.append(f"{ecosystem}_engine_launch_failed")
    if result.timed_out:
        errors.append(f"{ecosystem}_engine_timeout")
    if result.output_limited:
        errors.append(f"{ecosystem}_engine_output_limit_exceeded")
    if version and not errors and result.returncode != 0:
        errors.append(f"{ecosystem}_engine_nonzero_exit")
    if version and errors:
        errors.append(f"{ecosystem}_engine_version_unavailable")
    return errors


def _normalize_engine_version(ecosystem: str, stdout: bytes) -> str:
    try:
        text = stdout.decode("utf-8-sig")[:4096]
    except UnicodeDecodeError:
        return ""
    if ecosystem == "go":
        scanner = re.search(
            r"govulncheck(?:@|\s+)(?:v)?([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][0-9A-Za-z.-]+)?)",
            text,
            re.IGNORECASE,
        )
        if scanner:
            return scanner.group(1)
    match = _VERSION.search(text)
    return match.group(1) if match else ""


def _normalize_vulnerability_id(value: Any, *, prefix: str = "") -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        value = f"{prefix}{value}"
    if not isinstance(value, str):
        return ""
    candidate = value.strip().upper()
    if candidate.isdigit() and prefix:
        candidate = f"{prefix}{candidate}"
    if not _VULNERABILITY_ID.fullmatch(candidate):
        return ""
    if _CANONICAL_VULNERABILITY_ID.fullmatch(candidate):
        return candidate
    digest = hashlib.sha256(candidate.encode("ascii", errors="ignore")).hexdigest()[:16].upper()
    return f"VULN-{digest}"


def _normalize_severity(value: Any) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        score = float(value)
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
        return "unknown"
    if not isinstance(value, str):
        return "unknown"
    candidate = value.strip().casefold()
    aliases = {
        "critical": "critical",
        "high": "high",
        "moderate": "medium",
        "medium": "medium",
        "low": "low",
        "info": "low",
        "informational": "low",
        "unknown": "unknown",
    }
    return aliases.get(candidate, "unknown")


def _finding(
    ecosystem: str,
    vulnerability_id: str,
    package: str,
    version: str,
    severity: str,
    fixed_version_present: bool,
) -> ScaFinding:
    if not package.strip() or not version.strip():
        raise ValueError("finding package and version are required")
    package_ref = evidence_hash(package)
    version_ref = evidence_hash(version)
    fingerprint = _sha256_json(
        {
            "ecosystem": ecosystem,
            "fixed_version_present": fixed_version_present,
            "installed_version_ref": version_ref,
            "package_ref": package_ref,
            "severity": severity,
            "vulnerability_id": vulnerability_id,
        }
    )
    return ScaFinding(
        ecosystem=ecosystem,
        vulnerability_id=vulnerability_id,
        package_ref=package_ref,
        installed_version_ref=version_ref,
        severity=severity,
        fixed_version_present=fixed_version_present,
        fingerprint=fingerprint,
    )


def _python_findings(payload: Any, max_results: int) -> tuple[list[ScaFinding], int, str]:
    if not isinstance(payload, dict) or payload.get("error") not in (None, "", [], {}):
        return [], 0, "schema"
    dependencies = payload.get("dependencies")
    if not isinstance(dependencies, list):
        return [], 0, "schema"
    result_count = 0
    findings: list[ScaFinding] = []
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            return [], result_count, "schema"
        package = dependency.get("name")
        version = dependency.get("version")
        vulnerabilities = dependency.get("vulns")
        if not isinstance(package, str) or not package.strip() or not isinstance(version, str) or not version.strip():
            return [], result_count, "schema"
        if not isinstance(vulnerabilities, list):
            return [], result_count, "schema"
        result_count += len(vulnerabilities)
        if result_count > max_results:
            return [], result_count, "limit"
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                return [], result_count, "schema"
            vulnerability_id = _normalize_vulnerability_id(vulnerability.get("id"))
            if not vulnerability_id:
                aliases = vulnerability.get("aliases", [])
                if isinstance(aliases, list):
                    vulnerability_id = next(
                        (
                            normalized
                            for alias in aliases
                            if (normalized := _normalize_vulnerability_id(alias))
                        ),
                        "",
                    )
            if not vulnerability_id:
                return [], result_count, "schema"
            severity_value = vulnerability.get("severity")
            if severity_value is None and isinstance(vulnerability.get("database_specific"), dict):
                severity_value = vulnerability["database_specific"].get("severity")
            fixed = vulnerability.get("fix_versions", [])
            if not isinstance(fixed, list):
                return [], result_count, "schema"
            findings.append(
                _finding(
                    "python",
                    vulnerability_id,
                    _normalize_python_package(package),
                    version,
                    _normalize_severity(severity_value),
                    bool(fixed),
                )
            )
    return findings, result_count, ""


def _locked_python_requirements(source: _InputFile) -> bytes:
    rows: list[tuple[str, str]] = []
    if source.kind == "poetry_lock":
        payload = tomllib.loads(_decode_manifest(source.content))
        packages = payload.get("package", []) if isinstance(payload, dict) else []
        if not isinstance(packages, list):
            raise ValueError
        for package in packages:
            if not isinstance(package, dict):
                raise ValueError
            name = package.get("name")
            version = package.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                raise ValueError
            rows.append((name, version))
    elif source.kind == "pipfile_lock":
        payload = json.loads(_decode_manifest(source.content))
        if not isinstance(payload, dict):
            raise ValueError
        for group in ("default", "develop"):
            packages = payload.get(group, {})
            if not isinstance(packages, dict):
                raise ValueError
            for name, package in packages.items():
                if not isinstance(name, str) or not isinstance(package, dict):
                    raise ValueError
                version = package.get("version")
                if not isinstance(version, str) or not version.startswith("=="):
                    raise ValueError
                rows.append((name, version[2:]))
    else:
        raise ValueError

    requirements: set[str] = set()
    for name, version in rows:
        if not _PYTHON_LOCK_NAME.fullmatch(name) or not _PYTHON_LOCK_VERSION.fullmatch(version):
            raise ValueError
        requirements.add(f"{name}=={version}")
    rendered = "".join(f"{requirement}\n" for requirement in sorted(requirements, key=str.casefold))
    return rendered.encode("utf-8")


def _npm_lock_versions(source: _InputFile) -> tuple[dict[str, tuple[str, ...]], dict[str, str]]:
    payload = json.loads(_decode_manifest(source.content))
    if not isinstance(payload, dict):
        raise ValueError
    by_name: dict[str, set[str]] = {}
    by_node: dict[str, str] = {}
    packages = payload.get("packages", {})
    if isinstance(packages, dict):
        for node, row in packages.items():
            if not isinstance(node, str) or not isinstance(row, dict):
                continue
            version = row.get("version")
            if not isinstance(version, str) or not version:
                continue
            normalized_node = node.replace("\\", "/").strip("/")
            name = row.get("name")
            if not isinstance(name, str) or not name:
                name = normalized_node.rsplit("node_modules/", 1)[-1] if "node_modules/" in normalized_node else ""
            if name:
                by_name.setdefault(name.casefold(), set()).add(version)
            by_node[normalized_node] = version
    dependencies = payload.get("dependencies", {})
    if isinstance(dependencies, dict):
        for name, row in dependencies.items():
            if isinstance(name, str) and isinstance(row, dict) and isinstance(row.get("version"), str):
                by_name.setdefault(name.casefold(), set()).add(row["version"])
    return {name: tuple(sorted(versions)) for name, versions in by_name.items()}, by_node


def _npm_advisory_id(value: Mapping[str, Any], fallback: str) -> str:
    for key in ("id", "cve"):
        candidate = _normalize_vulnerability_id(value.get(key), prefix="NPM-")
        if candidate:
            return candidate
    cves = value.get("cves", [])
    if isinstance(cves, list):
        for cve in cves:
            candidate = _normalize_vulnerability_id(cve)
            if candidate:
                return candidate
    url = value.get("url")
    if isinstance(url, str):
        match = _GHSA_IN_TEXT.search(url) or _CVE_IN_TEXT.search(url)
        if match:
            return match.group(0).upper()
    candidate = _normalize_vulnerability_id(value.get("source"), prefix="NPM-")
    if candidate:
        return candidate
    return f"NPM-{hashlib.sha256(fallback.encode('utf-8', errors='ignore')).hexdigest()[:16].upper()}"


def _npm_versions_for_row(
    package: str,
    row: Mapping[str, Any],
    by_name: Mapping[str, tuple[str, ...]],
    by_node: Mapping[str, str],
) -> tuple[str, ...]:
    versions: set[str] = set()
    direct = row.get("version")
    if isinstance(direct, str) and direct:
        versions.add(direct)
    nodes = row.get("nodes", [])
    if isinstance(nodes, list):
        for node in nodes:
            if isinstance(node, str):
                normalized = node.replace("\\", "/").strip("/")
                if normalized in by_node:
                    versions.add(by_node[normalized])
    if not versions:
        versions.update(by_name.get(package.casefold(), ()))
    return tuple(sorted(versions))


def _npm_findings(
    payload: Any,
    max_results: int,
    source: _InputFile,
) -> tuple[list[ScaFinding], int, str]:
    if not isinstance(payload, dict) or payload.get("error") not in (None, "", [], {}):
        return [], 0, "schema"
    try:
        by_name, by_node = _npm_lock_versions(source)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return [], 0, "schema"
    findings: list[ScaFinding] = []
    result_count = 0
    vulnerabilities = payload.get("vulnerabilities")
    advisories = payload.get("advisories")
    if vulnerabilities is not None:
        if not isinstance(vulnerabilities, dict):
            return [], 0, "schema"
        if any(not isinstance(package_key, str) for package_key in vulnerabilities):
            return [], 0, "schema"
        for package_key in sorted(vulnerabilities, key=str.casefold):
            row = vulnerabilities[package_key]
            if not isinstance(row, dict):
                return [], result_count, "schema"
            package = row.get("name", package_key)
            if not isinstance(package, str) or not package.strip():
                return [], result_count, "schema"
            versions = _npm_versions_for_row(package, row, by_name, by_node)
            if not versions:
                return [], result_count, "schema"
            via = row.get("via", [])
            if not isinstance(via, list):
                return [], result_count, "schema"
            advisory_rows = [item for item in via if isinstance(item, dict)]
            if not advisory_rows:
                advisory_rows = [row]
            result_count += len(advisory_rows)
            if result_count > max_results:
                return [], result_count, "limit"
            fixed_marker = row.get("fixAvailable")
            fixed_present = fixed_marker not in (None, False, {}, [])
            for index, advisory in enumerate(advisory_rows):
                vulnerability_id = _npm_advisory_id(advisory, f"{package_ref_seed(package)}:{index}")
                severity = _normalize_severity(advisory.get("severity", row.get("severity")))
                if len(findings) + len(versions) > max_results:
                    return [], result_count, "limit"
                for version in versions:
                    findings.append(
                        _finding(
                            "npm",
                            vulnerability_id,
                            package.casefold(),
                            version,
                            severity,
                            fixed_present,
                        )
                    )
        return findings, result_count, ""
    if advisories is not None:
        if not isinstance(advisories, dict):
            return [], 0, "schema"
        if any(not isinstance(advisory_key, str) for advisory_key in advisories):
            return [], 0, "schema"
        result_count = len(advisories)
        if result_count > max_results:
            return [], result_count, "limit"
        for advisory_key in sorted(advisories, key=str.casefold):
            advisory = advisories[advisory_key]
            if not isinstance(advisory, dict):
                return [], result_count, "schema"
            package = advisory.get("module_name")
            if not isinstance(package, str) or not package:
                return [], result_count, "schema"
            versions: set[str] = set(by_name.get(package.casefold(), ()))
            old_findings = advisory.get("findings", [])
            if isinstance(old_findings, list):
                versions.update(
                    row["version"]
                    for row in old_findings
                    if isinstance(row, dict) and isinstance(row.get("version"), str) and row["version"]
                )
            if not versions:
                return [], result_count, "schema"
            vulnerability_id = _npm_advisory_id(advisory, str(advisory_key))
            patched = advisory.get("patched_versions")
            fixed_present = (
                isinstance(patched, str)
                and bool(patched.strip())
                and patched.strip() not in {"<0.0.0", "<0.0.0-0"}
            )
            if len(findings) + len(versions) > max_results:
                return [], result_count, "limit"
            for version in sorted(versions):
                findings.append(
                    _finding(
                        "npm",
                        vulnerability_id,
                        package.casefold(),
                        version,
                        _normalize_severity(advisory.get("severity")),
                        fixed_present,
                    )
                )
        return findings, result_count, ""
    return [], 0, "schema"


def package_ref_seed(package: str) -> str:
    return evidence_hash(package)


def _go_payload(stdout: bytes) -> tuple[list[Mapping[str, Any]], str]:
    try:
        text = stdout.decode("utf-8-sig")
    except UnicodeDecodeError:
        return [], "malformed"
    decoder = json.JSONDecoder()
    rows: list[Mapping[str, Any]] = []
    offset = 0
    length = len(text)
    while offset < length:
        while offset < length and text[offset].isspace():
            offset += 1
        if offset >= length:
            break
        try:
            row, offset = decoder.raw_decode(text, offset)
        except json.JSONDecodeError:
            return [], "malformed"
        if not isinstance(row, dict):
            return [], "schema"
        rows.append(row)
    return (rows, "") if rows else ([], "malformed")


def _go_findings(stdout: bytes, max_results: int) -> tuple[list[ScaFinding], int, str]:
    rows, payload_error = _go_payload(stdout)
    if payload_error:
        return [], 0, payload_error
    config = rows[0].get("config") if rows else None
    if not isinstance(config, dict) or config.get("protocol_version") != "v1.0.0":
        return [], 0, "schema"
    osv_severity: dict[str, str] = {}
    finding_rows: list[Mapping[str, Any]] = []
    allowed_message_keys = {"config", "progress", "SBOM", "osv", "finding"}
    for index, row in enumerate(rows):
        populated = [key for key in allowed_message_keys if key in row and row[key] is not None]
        if len(populated) != 1 or any(key not in allowed_message_keys for key in row):
            return [], 0, "schema"
        if populated[0] == "config" and index != 0:
            return [], 0, "schema"
        osv = row.get("osv")
        if isinstance(osv, dict):
            vulnerability_id = _normalize_vulnerability_id(osv.get("id"))
            if vulnerability_id:
                database_specific = osv.get("database_specific", {})
                severity = database_specific.get("severity") if isinstance(database_specific, dict) else None
                osv_severity[vulnerability_id] = _normalize_severity(severity)
        finding = row.get("finding")
        if isinstance(finding, dict):
            finding_rows.append(finding)
    if len(finding_rows) > max_results:
        return [], len(finding_rows), "limit"
    findings: list[ScaFinding] = []
    for row in finding_rows:
        vulnerability_id = _normalize_vulnerability_id(row.get("osv"))
        if not vulnerability_id:
            return [], len(finding_rows), "schema"
        trace = row.get("trace", [])
        if not isinstance(trace, list):
            return [], len(finding_rows), "schema"
        package = ""
        version = ""
        for frame in trace:
            if not isinstance(frame, dict):
                continue
            module = frame.get("module")
            installed = frame.get("version")
            if isinstance(module, str) and module and isinstance(installed, str) and installed:
                package = module
                version = installed
                break
        if not package or not version:
            return [], len(finding_rows), "schema"
        fixed = row.get("fixed_version")
        findings.append(
            _finding(
                "go",
                vulnerability_id,
                package,
                version,
                osv_severity.get(vulnerability_id, "unknown"),
                isinstance(fixed, str) and bool(fixed.strip()),
            )
        )
    return findings, len(finding_rows), ""


def _parse_audit_result(
    ecosystem: str,
    result: ProcessResult,
    unit: _AuditUnit,
    max_results: int,
) -> tuple[list[ScaFinding], int, str]:
    if ecosystem == "go":
        return _go_findings(bytes(result.stdout), max_results)
    try:
        payload = json.loads(bytes(result.stdout).decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return [], 0, "malformed"
    if ecosystem == "python":
        return _python_findings(payload, max_results)
    return _npm_findings(payload, max_results, unit.source)


class SoftwareCompositionAnalyzer:
    """Bounded, fail-closed local SCA orchestrator for later Guardian integration."""

    def __init__(
        self,
        *,
        process_runner: ProcessRunner | None = None,
        runner: ProcessRunner | None = None,
        executable_resolver: Callable[[str], str | None] | None = None,
        bounds: ScaBounds | None = None,
        max_manifest_files: int | None = None,
        max_manifest_bytes: int | None = None,
        max_manifest_total_bytes: int | None = None,
        max_walk_entries: int | None = None,
        max_source_files: int | None = None,
        max_source_file_bytes: int | None = None,
        max_source_total_bytes: int | None = None,
        max_output_bytes: int | None = None,
        max_results: int | None = None,
        timeout_seconds: float | None = None,
        version_timeout_seconds: float | None = None,
    ) -> None:
        if process_runner is not None and runner is not None:
            raise ValueError("provide only one process runner")
        selected_runner = process_runner or runner
        active = bounds or ScaBounds()
        overrides = {
            "max_manifest_files": max_manifest_files,
            "max_manifest_bytes": max_manifest_bytes,
            "max_manifest_total_bytes": max_manifest_total_bytes,
            "max_walk_entries": max_walk_entries,
            "max_source_files": max_source_files,
            "max_source_file_bytes": max_source_file_bytes,
            "max_source_total_bytes": max_source_total_bytes,
            "max_output_bytes": max_output_bytes,
            "max_results": max_results,
            "timeout_seconds": timeout_seconds,
            "version_timeout_seconds": version_timeout_seconds,
        }
        if any(value is not None for value in overrides.values()):
            values = active.to_dict()
            values.update({key: value for key, value in overrides.items() if value is not None})
            active = ScaBounds(**values)
        self.bounds = active
        self._runner: ProcessRunner = selected_runner or _LocalProcessRunner()
        if executable_resolver is not None:
            self._resolver = executable_resolver
        elif selected_runner is None:
            self._resolver = shutil.which
        else:
            self._resolver = lambda executable: executable

    def run(
        self,
        target: str | Path,
        *,
        ecosystems: Iterable[str] | str | None = None,
    ) -> ScaRun:
        return self.analyze(target, ecosystems=ecosystems)

    def analyze(
        self,
        target: str | Path,
        *,
        ecosystems: Iterable[str] | str | None = None,
    ) -> ScaRun:
        initial = _discover(target, self.bounds)
        requested, request_errors = _requested_ecosystems(ecosystems, initial.detected_ecosystems)
        global_errors = [*initial.errors, *request_errors]
        adapters: list[ScaAdapterRun] = []
        if initial.root is not None:
            for ecosystem in requested:
                if initial.errors or request_errors:
                    adapters.append(self._incomplete_adapter(ecosystem, initial, (CONTROL_INVENTORY_INCOMPLETE,)))
                else:
                    adapters.append(self._audit_adapter(ecosystem, initial))

        if initial.root is not None and not initial.errors and not request_errors:
            final = _discover(initial.root, self.bounds)
            if (
                final.errors
                or final.snapshot.get("tree_sha256") != initial.snapshot.get("tree_sha256")
                or final.snapshot.get("snapshot_sha256") != initial.snapshot.get("snapshot_sha256")
                or final.inventory.get("inventory_set_sha256") != initial.inventory.get("inventory_set_sha256")
            ):
                global_errors.append(CONTROL_SNAPSHOT_DRIFT)
                adapters = [
                    replace(
                        adapter,
                        complete=False,
                        control_errors=(*adapter.control_errors, CONTROL_SNAPSHOT_DRIFT),
                        findings=(),
                        counts={**dict(adapter.counts), "finding_count": 0},
                    )
                    for adapter in adapters
                ]

        adapter_errors = [error for adapter in adapters for error in adapter.control_errors]
        all_errors = tuple(dict.fromkeys([*global_errors, *adapter_errors]))
        complete = not all_errors and len(adapters) == len(requested) and all(adapter.complete for adapter in adapters)
        findings = tuple(
            sorted(
                (finding for adapter in adapters if adapter.complete for finding in adapter.findings),
                key=lambda item: (
                    _ECOSYSTEM_ORDER[item.ecosystem],
                    _SEVERITY_ORDER[item.severity],
                    item.vulnerability_id,
                    item.package_ref,
                    item.installed_version_ref,
                    item.fingerprint,
                ),
            )
        )
        audited = tuple(adapter.ecosystem for adapter in adapters if adapter.complete)
        counts = {
            "manifest_count": int(initial.inventory.get("manifest_count", 0)),
            "lock_count": int(initial.inventory.get("lock_count", 0)),
            "requested_ecosystem_count": len(requested),
            "audited_ecosystem_count": len(audited),
            "adapter_count": len(adapters),
            "result_count": sum(int(adapter.counts.get("result_count", 0)) for adapter in adapters),
            "finding_count": len(findings),
            "stdout_bytes": sum(int(adapter.counts.get("stdout_bytes", 0)) for adapter in adapters),
            "stderr_bytes": sum(int(adapter.counts.get("stderr_bytes", 0)) for adapter in adapters),
        }
        return ScaRun(
            complete=complete,
            control_errors=all_errors,
            findings=findings,
            requested_ecosystems=requested,
            audited_ecosystems=audited,
            adapters=tuple(adapters),
            input_snapshot=initial.snapshot,
            inventory=initial.inventory,
            counts=counts,
        )

    def _incomplete_adapter(
        self,
        ecosystem: str,
        state: _InventoryState,
        errors: Sequence[str],
    ) -> ScaAdapterRun:
        inventory = _ecosystem_inventory(state.inventory, ecosystem)
        contract = _command_contract(ecosystem, self.bounds)
        return ScaAdapterRun(
            ecosystem=ecosystem,
            complete=False,
            control_errors=tuple(errors),
            findings=(),
            engine_name=_engine_name(ecosystem),
            engine_version="",
            command_contract=contract,
            command_contract_sha256=_sha256_json(contract),
            input_snapshot=_ecosystem_snapshot(state.snapshot, state.inventory, ecosystem),
            inventory=inventory,
            counts=_default_counts(inventory),
            bounds=self.bounds.to_dict(),
        )

    def _execute(self, argv: Sequence[str], cwd: Path, timeout: float, max_output: int) -> ProcessResult:
        try:
            value = self._runner(
                tuple(str(item) for item in argv),
                cwd=cwd,
                env=dict(os.environ),
                timeout_seconds=timeout,
                max_output_bytes=max_output,
                shell=False,
            )
        except FileNotFoundError:
            value = ProcessResult(-1, launch_error="missing")
        except OSError:
            value = ProcessResult(-1, launch_error="os_error")
        except Exception:
            value = ProcessResult(-1, launch_error="runner_error")
        return _coerce_process_result(value, max_output)

    def _audit_adapter(self, ecosystem: str, state: _InventoryState) -> ScaAdapterRun:
        inventory = _ecosystem_inventory(state.inventory, ecosystem)
        counts = _default_counts(inventory)
        contract = _command_contract(ecosystem, self.bounds)
        contract_sha256 = _sha256_json(contract)
        units, unit_errors = _audit_units(ecosystem, state)
        if unit_errors:
            return ScaAdapterRun(
                ecosystem=ecosystem,
                complete=False,
                control_errors=unit_errors,
                findings=(),
                engine_name=_engine_name(ecosystem),
                engine_version="",
                command_contract=contract,
                command_contract_sha256=contract_sha256,
                input_snapshot=_ecosystem_snapshot(state.snapshot, state.inventory, ecosystem),
                inventory=inventory,
                counts=counts,
                bounds=self.bounds.to_dict(),
            )
        engine_name = _engine_name(ecosystem)
        try:
            executable = self._resolver(engine_name)
        except (OSError, ValueError):
            executable = None
        if not executable:
            return self._adapter_result(
                ecosystem,
                state,
                inventory,
                counts,
                contract,
                (f"{ecosystem}_engine_missing",),
            )

        version_result = self._execute(
            _version_argv(ecosystem, str(executable)),
            units[0].cwd,
            self.bounds.version_timeout_seconds,
            min(self.bounds.max_output_bytes, 64 * 1024),
        )
        counts["invocation_count"] += 1
        counts["version_stdout_bytes"] += int(version_result.stdout_bytes or 0)
        counts["version_stderr_bytes"] += int(version_result.stderr_bytes or 0)
        errors = _process_errors(ecosystem, version_result, version=True)
        version = _normalize_engine_version(ecosystem, bytes(version_result.stdout)) if not errors else ""
        if not errors and not version:
            errors.append(f"{ecosystem}_engine_version_unavailable")
        if errors:
            return self._adapter_result(ecosystem, state, inventory, counts, contract, tuple(errors))

        normalized: dict[str, ScaFinding] = {}
        for unit in units:
            result, input_error = self._execute_audit_unit(ecosystem, str(executable), unit)
            if input_error:
                errors.append(input_error)
                break
            assert result is not None
            counts["invocation_count"] += 1
            counts["stdout_bytes"] += int(result.stdout_bytes or 0)
            counts["stderr_bytes"] += int(result.stderr_bytes or 0)
            process_errors = _process_errors(ecosystem, result, version=False)
            parsed: list[ScaFinding] = []
            result_count = 0
            parse_error = ""
            if not process_errors:
                parsed, result_count, parse_error = _parse_audit_result(
                    ecosystem,
                    result,
                    unit,
                    max(
                        0,
                        min(
                            self.bounds.max_results - counts["result_count"],
                            self.bounds.max_results - len(normalized),
                        ),
                    ),
                )
                counts["result_count"] += result_count
            errors.extend(process_errors)
            if parse_error == "malformed":
                errors.append(f"{ecosystem}_engine_json_malformed")
            elif parse_error == "schema":
                errors.append(f"{ecosystem}_engine_json_schema_invalid")
            elif parse_error == "limit":
                errors.append(f"{ecosystem}_result_limit_exceeded")
            accepted_vulnerability_code = result.returncode in contract["accepted_vulnerability_exit_codes"]
            valid_payload = not process_errors and not parse_error
            if result.returncode != 0:
                if not (accepted_vulnerability_code and valid_payload and parsed):
                    errors.append(f"{ecosystem}_engine_nonzero_exit")
            if valid_payload:
                for finding in parsed:
                    normalized.setdefault(finding.fingerprint, finding)
            if errors:
                break

        findings = tuple(
            sorted(
                normalized.values(),
                key=lambda item: (
                    _SEVERITY_ORDER[item.severity],
                    item.vulnerability_id,
                    item.package_ref,
                    item.installed_version_ref,
                    item.fingerprint,
                ),
            )
        )
        if errors:
            findings = ()
        counts["finding_count"] = len(findings)
        return self._adapter_result(
            ecosystem,
            state,
            inventory,
            counts,
            contract,
            tuple(dict.fromkeys(errors)),
            findings=findings,
            engine_version=version,
        )

    def _adapter_result(
        self,
        ecosystem: str,
        state: _InventoryState,
        inventory: Mapping[str, Any],
        counts: Mapping[str, int],
        contract: Mapping[str, Any],
        errors: Sequence[str],
        *,
        findings: Sequence[ScaFinding] = (),
        engine_version: str = "",
    ) -> ScaAdapterRun:
        return ScaAdapterRun(
            ecosystem=ecosystem,
            complete=not errors,
            control_errors=tuple(errors),
            findings=tuple(findings),
            engine_name=_engine_name(ecosystem),
            engine_version=engine_version,
            command_contract=contract,
            command_contract_sha256=_sha256_json(contract),
            input_snapshot=_ecosystem_snapshot(state.snapshot, state.inventory, ecosystem),
            inventory=inventory,
            counts=counts,
            bounds=self.bounds.to_dict(),
        )

    def _execute_audit_unit(
        self,
        ecosystem: str,
        executable: str,
        unit: _AuditUnit,
    ) -> tuple[ProcessResult | None, str]:
        if ecosystem != "python" or unit.kind != "locked_project":
            argv = self._audit_argv(ecosystem, executable, unit)
            return (
                self._execute(
                    argv,
                    unit.cwd,
                    self.bounds.timeout_seconds,
                    self.bounds.max_output_bytes,
                ),
                "",
            )
        try:
            content = _locked_python_requirements(unit.source)
        except (UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError, TypeError, ValueError):
            return None, "python_lock_normalization_failed"
        if len(content) > self.bounds.max_manifest_bytes:
            return None, "python_normalized_input_size_limit_exceeded"
        try:
            with tempfile.TemporaryDirectory(prefix="k-guard-sca-") as temporary_directory:
                path = Path(temporary_directory) / "locked-requirements.txt"
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                argv = self._audit_argv(ecosystem, executable, unit, normalized_lock=path)
                return (
                    self._execute(
                        argv,
                        unit.cwd,
                        self.bounds.timeout_seconds,
                        self.bounds.max_output_bytes,
                    ),
                    "",
                )
        except OSError:
            return None, "python_temporary_input_failed"

    @staticmethod
    def _audit_argv(
        ecosystem: str,
        executable: str,
        unit: _AuditUnit,
        *,
        normalized_lock: Path | None = None,
    ) -> list[str]:
        if ecosystem == "python":
            common = [
                executable,
                "--format=json",
                "--progress-spinner=off",
                "--strict",
            ]
            if unit.kind == "locked_project":
                if normalized_lock is None:
                    raise ValueError("a normalized lock input is required")
                return [*common, "--disable-pip", "--no-deps", "-r", str(normalized_lock)]
            return [*common, "-r", unit.source.path.name]
        if ecosystem == "npm":
            return [executable, "audit", "--json", "--package-lock-only"]
        return [executable, "-json", "./..."]


def _requested_ecosystems(
    value: Iterable[str] | str | None,
    detected: Sequence[str],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if value is None:
        return tuple(detected), ()
    values = [value] if isinstance(value, str) else list(value)
    aliases = {
        "python": "python",
        "pip": "python",
        "poetry": "python",
        "pipenv": "python",
        "npm": "npm",
        "node": "npm",
        "nodejs": "npm",
        "javascript": "npm",
        "yarn": "npm",
        "pnpm": "npm",
        "go": "go",
        "golang": "go",
    }
    requested: set[str] = set()
    errors: list[str] = []
    for item in values:
        if not isinstance(item, str):
            errors.append("requested_ecosystem_invalid")
            continue
        normalized = aliases.get(item.strip().casefold())
        if normalized is None:
            errors.append("requested_ecosystem_invalid")
        else:
            requested.add(normalized)
    return tuple(sorted(requested, key=_ECOSYSTEM_ORDER.__getitem__)), tuple(dict.fromkeys(errors))


def build_sca_report(run: ScaRun) -> dict[str, Any]:
    payload = run.to_dict()
    payload["evidence_bundle"] = _content_deterministic_evidence_bundle(
        subject="bounded-software-composition-analysis",
        producer=f"k_guard_mcp.sca:{ADAPTER_VERSION}",
        artifacts=[
            object_artifact("sca-run", payload, role="analysis"),
            object_artifact("sca-input-snapshot", payload["input_snapshot"], role="input"),
            object_artifact("sca-manifest-lock-inventory", payload["inventory"], role="inventory"),
        ],
    )
    return payload


def _content_deterministic_evidence_bundle(
    subject: str,
    producer: str,
    artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    bundle = evidence_bundle(subject=subject, producer=producer, artifacts=artifacts)
    bundle.pop("generated_at", None)
    bundle.pop("bundle_sha256", None)
    signature = dict(bundle.pop("signature", {}))
    bundle_sha256 = hashlib.sha256(canonical_json(bundle).encode("utf-8")).hexdigest()
    signature["signature_sha256"] = hmac.new(
        active_evidence_key().encode("utf-8"),
        bundle_sha256.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    bundle["bundle_sha256"] = bundle_sha256
    bundle["signature"] = signature
    return bundle


def analyze_software_composition(
    target: str | Path,
    *,
    ecosystems: Iterable[str] | str | None = None,
    process_runner: ProcessRunner | None = None,
    runner: ProcessRunner | None = None,
    executable_resolver: Callable[[str], str | None] | None = None,
    bounds: ScaBounds | None = None,
) -> dict[str, Any]:
    analyzer = SoftwareCompositionAnalyzer(
        process_runner=process_runner,
        runner=runner,
        executable_resolver=executable_resolver,
        bounds=bounds,
    )
    return analyzer.run(target, ecosystems=ecosystems).to_report()


# Explicit acronym aliases keep the integration surface unsurprising.
SCAAnalyzer = SoftwareCompositionAnalyzer
SCAFinding = ScaFinding
SCAAdapterRun = ScaAdapterRun
SCARun = ScaRun


__all__ = [
    "ADAPTER_VERSION",
    "CONTROL_DISCOVERY_LIMIT",
    "CONTROL_INVENTORY_INCOMPLETE",
    "CONTROL_MANIFEST_CHANGED",
    "CONTROL_MANIFEST_ENCODING",
    "CONTROL_MANIFEST_LIMIT",
    "CONTROL_MANIFEST_OVERSIZED",
    "CONTROL_MANIFEST_SCHEMA",
    "CONTROL_MANIFEST_SYMLINK",
    "CONTROL_MANIFEST_TOTAL_OVERSIZED",
    "CONTROL_MANIFEST_UNREADABLE",
    "CONTROL_SOURCE_SNAPSHOT",
    "CONTROL_SNAPSHOT_DRIFT",
    "CONTROL_TARGET_INVALID",
    "CONTROL_TARGET_NOT_DIRECTORY",
    "CONTROL_TARGET_NOT_FOUND",
    "CONTROL_TARGET_SYMLINK",
    "ProcessResult",
    "ProcessRunner",
    "SCAAdapterRun",
    "SCAAnalyzer",
    "SCAFinding",
    "SCARun",
    "SUPPORTED_ECOSYSTEMS",
    "ScaAdapterRun",
    "ScaBounds",
    "ScaFinding",
    "ScaRun",
    "SoftwareCompositionAnalyzer",
    "analyze_software_composition",
    "build_sca_report",
]
