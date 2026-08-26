from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme


FIELD_APP_ROSTER_FIELDS = (
    "app_id",
    "target_id",
    "stratum",
    "source_revision",
    "scope_basis",
    "scope_assertion_ref",
    "recruitment_status",
    "authorization_status",
    "scan_consent",
    "aggregate_consent",
)
FIELD_CAMPAIGN_ROSTER_FIELDS = FIELD_APP_ROSTER_FIELDS
REQUIRED_STRATA = ("top", "mid", "long_tail")
SCOPE_BASES = ("owned", "partner")
MIN_APP_COUNT = 12
MAX_APP_COUNT = 20

_OPAQUE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SOURCE_REVISION = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_ASSERTION_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/?#%+=@~-]{2,511}\Z")
_EMAIL = re.compile(r"(?i)(?:^|[^A-Z0-9._%+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?:$|[^A-Z0-9.-])")
_CONTACT_URI = re.compile(r"(?i)(?:^|\s)(?:mailto|tel):")
_PLACEHOLDER = re.compile(
    r"(?i)(?:^|[-_:/<\s])(?:todo|tbd|placeholder|changeme|replace[-_]?me|"
    r"your[-_][a-z0-9_-]+|example|sample)(?:$|[-_:/>\s])"
)
_PLACEHOLDER_VALUES = {
    "-",
    "?",
    "n/a",
    "na",
    "none",
    "null",
    "unknown",
    "xxx",
    "owned-or-partner",
    "partner-scope-ticket-or-immutable-dataset-ref",
}
_CONTACT_HEADER_PARTS = {"contact", "email", "phone", "telephone", "mobile", "person", "name"}


class FieldCampaignRosterError(ValueError):
    """Raised when a field-app roster does not satisfy the readiness contract."""

    def __init__(self, blockers: list[str]) -> None:
        self.blockers = tuple(blockers)
        super().__init__("Field campaign roster is not ready: " + ", ".join(blockers))


def write_field_app_roster_template(path: str | Path) -> None:
    """Write the exact field-app roster header without example or placeholder rows."""

    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle, lineterminator="\n").writerow(FIELD_APP_ROSTER_FIELDS)


def load_field_app_roster(path: str | Path) -> list[dict[str, str | bool]]:
    """Load a roster only when every structural and readiness check passes."""

    inspection = _inspect_roster(Path(path))
    blockers = sorted(inspection["blocker_counts"])
    if blockers:
        raise FieldCampaignRosterError(blockers)
    return [_public_row(row) for row in inspection["rows"]]


def evaluate_field_campaign_readiness(path: str | Path) -> dict[str, Any]:
    """Return a raw-free readiness report for a roster, including malformed input."""

    inspection = _inspect_roster(Path(path))
    blocker_counts = dict(sorted(inspection["blocker_counts"].items()))
    blockers = list(blocker_counts)
    rows = inspection["rows"]
    stratum_counts = {stratum: inspection["stratum_counts"].get(stratum, 0) for stratum in REQUIRED_STRATA}
    app_count = len(inspection["app_ids"])
    target_count = len(inspection["target_ids"])
    ready = not blockers
    content_sha256 = inspection["content_sha256"]
    return {
        "schema": "k_guard_field_campaign_readiness.v1",
        "content_sha256": content_sha256,
        "roster_content_sha256": content_sha256,
        "row_count": inspection["row_count"],
        "app_count": app_count,
        "target_count": target_count,
        "stratum_count": sum(count > 0 for count in stratum_counts.values()),
        "stratum_counts": stratum_counts,
        "blockers": blockers,
        "blocker_counts": blocker_counts,
        "passed": ready,
        "ready": ready,
        "roster_refs": [_sanitized_row_ref(row) for row in rows if _row_is_reference_safe(row)],
        "raw_returned": False,
    }


def write_field_campaign_status_report(
    roster_path: str | Path,
    output_path: str | Path,
) -> dict[str, Any]:
    """Evaluate a roster and write its sanitized readiness report as JSON."""

    roster = Path(roster_path)
    output = Path(output_path)
    if roster.resolve(strict=False) == output.resolve(strict=False):
        raise ValueError("Roster input and status-report output must be different files.")
    report = evaluate_field_campaign_readiness(roster)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def _inspect_roster(path: Path) -> dict[str, Any]:
    blocker_counts: Counter[str] = Counter()
    rows: list[dict[str, str]] = []
    row_count = 0
    try:
        content = path.read_bytes()
    except FileNotFoundError:
        blocker_counts["roster_not_found"] += 1
        return _inspection_result(b"", rows, row_count, blocker_counts)
    except OSError:
        blocker_counts["roster_unreadable"] += 1
        return _inspection_result(b"", rows, row_count, blocker_counts)

    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        blocker_counts["invalid_utf8"] += 1
        return _inspection_result(content, rows, row_count, blocker_counts)

    try:
        records = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except csv.Error:
        blocker_counts["malformed_csv"] += 1
        return _inspection_result(content, rows, row_count, blocker_counts)

    if not records:
        blocker_counts["malformed_headers"] += 1
        return _inspection_result(content, rows, row_count, blocker_counts)

    header = records[0]
    if tuple(header) != FIELD_APP_ROSTER_FIELDS:
        blocker_counts["malformed_headers"] += 1
        if _has_contact_header(header):
            blocker_counts["personal_contact_field_forbidden"] += 1
        return _inspection_result(content, rows, max(0, len(records) - 1), blocker_counts)

    for record in records[1:]:
        row_count += 1
        if len(record) != len(FIELD_APP_ROSTER_FIELDS) or any(_has_control_character(value) for value in record):
            blocker_counts["malformed_row"] += 1
            continue
        row = {field: value.strip() for field, value in zip(FIELD_APP_ROSTER_FIELDS, record, strict=True)}
        rows.append(row)
        _validate_row(row, blocker_counts)

    _validate_collection(rows, row_count, blocker_counts)
    return _inspection_result(content, rows, row_count, blocker_counts)


def _validate_row(row: dict[str, str], blockers: Counter[str]) -> None:
    missing_fields = [field for field in FIELD_APP_ROSTER_FIELDS if not row[field]]
    if missing_fields:
        blockers["missing_required_value"] += 1
    if any(_is_placeholder(value) for value in row.values() if value):
        blockers["placeholder_value"] += 1
    if not _OPAQUE_ID.fullmatch(row["app_id"]):
        blockers["invalid_app_id"] += 1
    if not _OPAQUE_ID.fullmatch(row["target_id"]):
        blockers["invalid_target_id"] += 1
    if row["stratum"].lower() not in REQUIRED_STRATA:
        blockers["invalid_stratum"] += 1
    if not _SOURCE_REVISION.fullmatch(row["source_revision"]):
        blockers["invalid_source_revision"] += 1
    if row["scope_basis"].lower() not in SCOPE_BASES:
        blockers["invalid_scope_basis"] += 1
    if not row["scope_assertion_ref"]:
        blockers["missing_scope_assertion_ref"] += 1
    elif not _ASSERTION_REF.fullmatch(row["scope_assertion_ref"]):
        blockers["invalid_scope_assertion_ref"] += 1
    if row["recruitment_status"].lower() != "accepted":
        blockers["recruitment_not_accepted"] += 1
    if row["authorization_status"].lower() != "approved":
        blockers["authorization_not_approved"] += 1
    _validate_required_true(row["scan_consent"], "scan_consent", blockers)
    _validate_required_true(row["aggregate_consent"], "aggregate_consent", blockers)
    if any(_contains_personal_contact(row[field]) for field in ("app_id", "target_id", "scope_assertion_ref")):
        blockers["personal_contact_value_forbidden"] += 1


def _validate_required_true(value: str, field: str, blockers: Counter[str]) -> None:
    normalized = value.lower()
    if normalized not in {"true", "false"}:
        blockers[f"invalid_{field}"] += 1
    elif normalized != "true":
        blockers[f"{field}_not_true"] += 1


def _validate_collection(rows: list[dict[str, str]], row_count: int, blockers: Counter[str]) -> None:
    app_ids = [row["app_id"].casefold() for row in rows if row["app_id"]]
    target_ids = [row["target_id"].casefold() for row in rows if row["target_id"]]
    duplicate_apps = len(app_ids) - len(set(app_ids))
    duplicate_targets = len(target_ids) - len(set(target_ids))
    if duplicate_apps:
        blockers["duplicate_app_id"] += duplicate_apps
    if duplicate_targets:
        blockers["duplicate_target_id"] += duplicate_targets

    app_count = len(set(app_ids))
    if row_count == 0:
        blockers["roster_empty"] += 1
    if not MIN_APP_COUNT <= row_count <= MAX_APP_COUNT:
        blockers["row_count_out_of_range"] += 1
    if not MIN_APP_COUNT <= app_count <= MAX_APP_COUNT:
        blockers["app_count_out_of_range"] += 1

    present_strata = {row["stratum"].lower() for row in rows if row["stratum"].lower() in REQUIRED_STRATA}
    missing_strata = set(REQUIRED_STRATA) - present_strata
    if missing_strata:
        blockers["missing_strata"] += len(missing_strata)


def _inspection_result(
    content: bytes,
    rows: list[dict[str, str]],
    row_count: int,
    blocker_counts: Counter[str],
) -> dict[str, Any]:
    app_ids = {row["app_id"].casefold() for row in rows if row["app_id"]}
    target_ids = {row["target_id"].casefold() for row in rows if row["target_id"]}
    stratum_counts = Counter(
        row["stratum"].lower() for row in rows if row["stratum"].lower() in REQUIRED_STRATA
    )
    return {
        "content_sha256": hashlib.sha256(content).hexdigest() if content or not blocker_counts.get("roster_not_found") else "",
        "rows": rows,
        "row_count": row_count,
        "app_ids": app_ids,
        "target_ids": target_ids,
        "stratum_counts": stratum_counts,
        "blocker_counts": blocker_counts,
    }


def _public_row(row: dict[str, str]) -> dict[str, str | bool]:
    return {
        "app_id": row["app_id"],
        "target_id": row["target_id"],
        "stratum": row["stratum"].lower(),
        "source_revision": row["source_revision"].lower(),
        "scope_basis": row["scope_basis"].lower(),
        "scope_assertion_ref": row["scope_assertion_ref"],
        "recruitment_status": "accepted",
        "authorization_status": "approved",
        "scan_consent": True,
        "aggregate_consent": True,
    }


def _sanitized_row_ref(row: dict[str, str]) -> dict[str, Any]:
    return {
        "app_ref": _hashed_ref(row["app_id"]),
        "target_ref": _hashed_ref(row["target_id"]),
        "source_revision_ref": _hashed_ref(row["source_revision"]),
        "scope_assertion_ref": _hashed_ref(row["scope_assertion_ref"]),
        "raw_returned": False,
    }


def _hashed_ref(value: str) -> dict[str, Any]:
    return {
        "hash": evidence_hash(value),
        "hash_scheme": evidence_hash_scheme(),
        "raw_returned": False,
    }


def _row_is_reference_safe(row: dict[str, str]) -> bool:
    values = (row["app_id"], row["target_id"], row["source_revision"], row["scope_assertion_ref"])
    return all(values) and not any(_is_placeholder(value) for value in values) and not any(
        _contains_personal_contact(value) for value in (row["app_id"], row["target_id"], row["scope_assertion_ref"])
    )


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().casefold()
    return normalized in _PLACEHOLDER_VALUES or _PLACEHOLDER.search(normalized) is not None


def _contains_personal_contact(value: str) -> bool:
    return _EMAIL.search(value) is not None or _CONTACT_URI.search(value) is not None


def _has_contact_header(header: list[str]) -> bool:
    for field in header:
        parts = {part for part in re.split(r"[^a-z0-9]+", field.casefold()) if part}
        if parts & _CONTACT_HEADER_PARTS:
            return True
    return False


def _has_control_character(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


# Descriptive aliases for callers that use campaign-centric naming.
write_field_campaign_roster_template = write_field_app_roster_template
load_field_campaign_roster = load_field_app_roster
build_field_campaign_status_report = evaluate_field_campaign_readiness
emit_field_campaign_status_report = write_field_campaign_status_report
