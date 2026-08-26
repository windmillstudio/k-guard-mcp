from __future__ import annotations

import hashlib
import importlib.metadata
from pathlib import Path
import re
import tomllib
from typing import Any

try:
    from packaging.requirements import InvalidRequirement, Requirement
except ImportError:
    InvalidRequirement = ValueError  # type: ignore[assignment,misc]
    Requirement = None  # type: ignore[assignment,misc]


EVIDENCE_LOCK_NAME = "requirements-evidence.lock"
_HASH_OPTION_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})\Z")


def declared_dependency_scope(project_root: Path) -> dict[str, Any]:
    payload = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    project = payload.get("project", {})
    runtime = [str(item) for item in project.get("dependencies", [])]
    optional = {
        str(group): [str(item) for item in requirements]
        for group, requirements in dict(project.get("optional-dependencies", {})).items()
    }
    all_requirements = runtime + [
        requirement
        for requirements in optional.values()
        for requirement in requirements
    ]
    return {
        "runtime": runtime,
        "optional": optional,
        "all_requirements": all_requirements,
    }


def installed_dependency_closure(requirements: list[str]) -> tuple[set[str], set[str]]:
    if Requirement is None:
        return set(), {"packaging_parser_unavailable"}

    pending: list[tuple[str, frozenset[str]]] = [
        (requirement, frozenset({""})) for requirement in requirements
    ]
    allowed: set[str] = set()
    unresolved: set[str] = set()
    requested_extras: dict[str, set[str]] = {}
    processed_states: set[tuple[str, frozenset[str]]] = set()

    while pending:
        requirement_text, parent_extras = pending.pop()
        parsed = _active_requirement(requirement_text, parent_extras)
        if parsed is None:
            continue
        name = normalize_name(parsed.name)
        if not name:
            continue
        extras = requested_extras.setdefault(name, set())
        extras.update(str(extra) for extra in parsed.extras)
        active_extras = frozenset(extras or {""})
        state_key = (name, active_extras)
        if state_key in processed_states:
            continue
        processed_states.add(state_key)
        allowed.add(name)
        try:
            dist = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError:
            unresolved.add(name)
            continue
        for child_requirement in dist.requires or []:
            pending.append((child_requirement, active_extras))

    return allowed, unresolved


def evidence_lock_report(project_root: Path) -> dict[str, Any]:
    path = project_root / EVIDENCE_LOCK_NAME
    if not path.is_file():
        return {
            "path": EVIDENCE_LOCK_NAME,
            "sha256": "",
            "active_versions": {},
            "active_entry_count": 0,
            "entry_count": 0,
            "hashed_entry_count": 0,
            "hash_count": 0,
            "all_entries_hashed": False,
            "errors": ["evidence_lock_missing"],
            "valid": False,
        }
    raw = path.read_bytes()
    active_versions: dict[str, str] = {}
    errors: list[str] = []
    entry_count = 0
    hashed_entry_count = 0
    hash_count = 0
    if Requirement is None:
        errors.append("packaging_parser_unavailable")
    else:
        entries, logical_errors = _logical_lock_entries(raw)
        errors.extend(logical_errors)
        entry_count = len(entries)
        for line_number, line in entries:
            requirement_text, hashes, hash_error = _split_hashed_requirement(line)
            hash_count += len(hashes)
            if hash_error:
                errors.append(f"{hash_error}:{line_number}")
                continue
            else:
                hashed_entry_count += 1
            try:
                parsed = Requirement(requirement_text)
            except InvalidRequirement:
                errors.append(f"invalid_requirement_line:{line_number}")
                continue
            specifiers = list(parsed.specifier)
            if (
                len(specifiers) != 1
                or specifiers[0].operator != "=="
                or "*" in specifiers[0].version
            ):
                errors.append(f"non_exact_pin_line:{line_number}")
                continue
            if parsed.marker and not parsed.marker.evaluate({"extra": ""}):
                continue
            name = normalize_name(parsed.name)
            if name in active_versions:
                errors.append(f"duplicate_pin:{name}")
                continue
            active_versions[name] = specifiers[0].version
    return {
        "path": EVIDENCE_LOCK_NAME,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "active_versions": dict(sorted(active_versions.items())),
        "active_entry_count": len(active_versions),
        "entry_count": entry_count,
        "hashed_entry_count": hashed_entry_count,
        "hash_count": hash_count,
        "all_entries_hashed": entry_count > 0 and hashed_entry_count == entry_count,
        "errors": errors,
        "valid": not errors,
    }


def _logical_lock_entries(raw: bytes) -> tuple[list[tuple[int, str]], list[str]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return [], ["lock_encoding_invalid"]

    entries: list[tuple[int, str]] = []
    errors: list[str] = []
    parts: list[str] = []
    start_line = 0
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not parts and (not stripped or stripped.startswith("#")):
            continue
        if parts and (not stripped or stripped.startswith("#")):
            errors.append(f"invalid_continuation_line:{line_number}")
            continue
        if not parts:
            start_line = line_number
        continued = stripped.endswith("\\")
        segment = stripped[:-1].strip() if continued else stripped
        if segment:
            parts.append(segment)
        if not continued:
            entries.append((start_line, " ".join(parts)))
            parts = []
            start_line = 0
    if parts:
        errors.append(f"truncated_continuation_line:{start_line}")
    return entries, errors


def _split_hashed_requirement(line: str) -> tuple[str, list[str], str | None]:
    tokens = line.split()
    first_hash = next(
        (index for index, token in enumerate(tokens) if token.startswith("--hash=")),
        None,
    )
    if first_hash is None:
        return line, [], "missing_hash_line"

    requirement_text = " ".join(tokens[:first_hash]).strip()
    hash_tokens = tokens[first_hash:]
    hashes: list[str] = []
    for token in hash_tokens:
        matched = _HASH_OPTION_RE.fullmatch(token)
        if matched is None:
            return requirement_text, hashes, "invalid_hash_line"
        hashes.append(matched.group(1))
    if not requirement_text or not hashes:
        return requirement_text, hashes, "invalid_hash_line"
    return requirement_text, hashes, None


def dependency_lock_mismatches(
    allowed_names: set[str],
    component_versions: dict[str, str],
    lock_report: dict[str, Any],
) -> list[dict[str, str]]:
    locked_versions = {
        normalize_name(str(name)): str(version)
        for name, version in dict(lock_report.get("active_versions", {})).items()
    }
    mismatches: list[dict[str, str]] = []
    for name in sorted(allowed_names):
        expected = locked_versions.get(name)
        actual = component_versions.get(name)
        if expected is None:
            mismatches.append({"name": name, "reason": "dependency_not_pinned"})
        elif actual is None:
            mismatches.append(
                {"name": name, "reason": "dependency_not_installed", "expected": expected}
            )
        elif actual != expected:
            mismatches.append(
                {
                    "name": name,
                    "reason": "installed_version_mismatch",
                    "expected": expected,
                    "actual": actual,
                }
            )
    for name in sorted(set(locked_versions) - allowed_names):
        mismatches.append(
            {
                "name": name,
                "reason": "stale_or_out_of_scope_pin",
                "expected": locked_versions[name],
            }
        )
    return mismatches


def normalize_name(value: str) -> str:
    return value.strip().lower().replace("_", "-").replace(".", "-")


def _active_requirement(
    requirement_text: str,
    parent_extras: frozenset[str],
):
    if Requirement is None:
        return None
    try:
        parsed = Requirement(requirement_text)
    except InvalidRequirement:
        return None
    contexts = parent_extras or frozenset({""})
    if parsed.marker and not any(
        parsed.marker.evaluate({"extra": extra}) for extra in contexts
    ):
        return None
    return parsed
