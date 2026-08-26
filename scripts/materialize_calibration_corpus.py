from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any


PLAN_REQUEST_SCHEMA = "k_guard_l3_campaign_plan_request.v1"
PLAN_SCHEMA = "k_guard_l3_campaign_plan.v1"
EVENT_REQUEST_SCHEMA = "k_guard_l3_campaign_event_request.v1"
EVENT_SCHEMA = "k_guard_l3_campaign_event.v1"
LABEL_REQUEST_SCHEMA = "k_guard_l3_label_commitment_request.v1"
LABEL_SCHEMA = "k_guard_l3_label_commitment.v1"
STATUS_SCHEMA = "k_guard_l3_campaign_status.v1"
ADMISSION_RECEIPT_SCHEMA = "k_guard_l3_admission_receipt.v1"

PLANES = ("site", "api", "data", "operations")
SEVERITIES = frozenset({"high", "critical"})
SUPPORTED_LANGUAGES = frozenset({"javascript", "typescript", "python", "java", "kotlin", "go"})
REQUIRED_COVERAGE_TAGS = frozenset(
    {"nextjs", "express", "supabase", "firebase", "sql-rls", "mcp-proxy", "gha-docker-iac", "korean-privacy"}
)
SCENARIO_FAMILIES = frozenset(
    {"source-flow", "auth-rls-db", "dependency-sca", "gha-docker-iac", "policy-kpriv"}
)
PATCH_POLICY_BY_FAMILY = {
    "source-flow": "bounded-causal-patch.source-flow.v1",
    "auth-rls-db": "bounded-causal-patch.auth-rls-db.v1",
    "dependency-sca": "bounded-causal-patch.dependency-sca.v1",
    "gha-docker-iac": "bounded-causal-patch.gha-docker-iac.v1",
    "policy-kpriv": "bounded-causal-patch.policy-kpriv.v1",
}
PATCH_LIMITS = {
    "source-flow": (2, 25, frozenset({"ast-call", "ast-guard", "ast-sanitizer"})),
    "auth-rls-db": (2, 40, frozenset({"middleware", "policy", "migration"})),
    "dependency-sca": (2, 400, frozenset({"manifest-entry", "lockfile-hunk"})),
    "gha-docker-iac": (1, 40, frozenset({"workflow-step", "resource-stanza"})),
    "policy-kpriv": (2, 40, frozenset({"config-key", "policy-field"})),
}
TRUTH = {"vulnerable": "present", "fixed": "absent", "negative_control": "absent"}
ZERO_SHA256 = "0" * 64

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_CWE_RE = re.compile(r"^CWE-[1-9][0-9]*$")
_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
_EVIDENCE_KEY_RE = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SPDX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*(?:\s+(?:AND|OR)\s+[A-Za-z0-9][A-Za-z0-9.+-]*)*$")
_DECIMAL_RE = re.compile(r"^(?:0|1|2)(?:\.\d{1,3})?$")
_CVSS_SCORE_RE = re.compile(r"^(?:10\.0|[0-9](?:\.\d)?)$")
CVSS_V4_BASE_ORDER = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
CVSS_V4_BASE_VALUES = {
    "AV": frozenset({"N", "A", "L", "P"}),
    "AC": frozenset({"L", "H"}),
    "AT": frozenset({"N", "P"}),
    "PR": frozenset({"N", "L", "H"}),
    "UI": frozenset({"N", "P", "A"}),
    "VC": frozenset({"H", "L", "N"}),
    "VI": frozenset({"H", "L", "N"}),
    "VA": frozenset({"H", "L", "N"}),
    "SC": frozenset({"H", "L", "N"}),
    "SI": frozenset({"H", "L", "N"}),
    "SA": frozenset({"H", "L", "N"}),
}

_STAGE_BY_STATUS = {
    "reserved": "reservation",
    "materializing": "materialization",
    "admitted": "verification",
    "rejected": "verification",
    "replaced": "replacement",
    "finalized": "finalization",
}
_LEGAL_NEXT = {
    None: frozenset({"reserved"}),
    "reserved": frozenset({"materializing"}),
    "materializing": frozenset({"admitted", "rejected"}),
    "admitted": frozenset({"finalized"}),
    "rejected": frozenset({"replaced"}),
    "replaced": frozenset({"materializing"}),
    "finalized": frozenset(),
}


def canonical_json_bytes(value: object, *, line: bool = False) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":") if line else None,
            indent=None if line else 2,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("value is not canonical-JSON serializable") from exc
    return (rendered + "\n").encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _domain_hash(domain: bytes, value: object) -> str:
    return sha256_bytes(domain + canonical_json_bytes(value, line=True).rstrip(b"\n"))


def _require_mapping(value: object, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(message)
    return value


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = ",".join(sorted(expected - actual)) or "none"
        extra = ",".join(sorted(actual - expected)) or "none"
        raise ValueError(f"{context} keys invalid; missing={missing}; extra={extra}")


def _require_id(value: object, context: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise ValueError(f"{context} must be a bounded lowercase identifier")
    return value


def _require_text(value: object, context: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise ValueError(f"{context} must be bounded non-empty text")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{context} contains a control character")
    return value


def _require_sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{context} must be a lowercase SHA-256 digest")
    return value


def _require_utc(value: object, context: str) -> str:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise ValueError(f"{context} must be an RFC3339 UTC second")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError(f"{context} is not a real UTC timestamp") from exc
    return value


def _quota_cell(slot: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "coverage_tags": list(slot["coverage_tags"]),
        "cwe": str(slot["cwe"]),
        "family": str(slot["family"]),
        "framework": str(slot["framework"]),
        "generator_family": str(slot["generator_family"]),
        "language": str(slot["language"]),
        "plane": str(slot["plane"]),
        "severity": str(slot["severity"]),
    }


def _quota_cell_sha256(cell: Mapping[str, Any]) -> str:
    return _domain_hash(b"k_guard_l3_quota_cell.v1\0", cell)


def _language_group(language: str) -> str:
    if language in {"javascript", "typescript"}:
        return "js_ts"
    if language == "python":
        return "python"
    if language in {"java", "kotlin"}:
        return "java_kotlin"
    if language == "go":
        return "go"
    raise ValueError(f"unsupported language: {language}")


def _normalize_sampling(value: object, context: str) -> dict[str, str]:
    sampling = _require_mapping(value, f"{context} must be an object")
    _require_exact_keys(sampling, {"strategy", "temperature"}, context)
    strategy = _require_id(sampling["strategy"], f"{context}.strategy")
    temperature = sampling["temperature"]
    if not isinstance(temperature, str) or _DECIMAL_RE.fullmatch(temperature) is None:
        raise ValueError(f"{context}.temperature must be a deterministic decimal string")
    try:
        decimal_temperature = Decimal(temperature)
    except InvalidOperation as exc:
        raise ValueError(f"{context}.temperature invalid") from exc
    if not Decimal("0") <= decimal_temperature <= Decimal("2"):
        raise ValueError(f"{context}.temperature outside 0..2")
    return {"strategy": strategy, "temperature": temperature}


def _normalize_candidate(
    value: object,
    *,
    context: str,
    quota_cell_sha256: str,
    reserve_order: int,
    generator_family: str,
) -> dict[str, Any]:
    candidate = _require_mapping(value, f"{context} must be an object")
    _require_exact_keys(
        candidate,
        {"lineage_id", "template_identity_sha256", "source_identity_sha256", "generator"},
        context,
    )
    lineage_id = _require_id(candidate["lineage_id"], f"{context}.lineage_id")
    template_sha256 = _require_sha256(candidate["template_identity_sha256"], f"{context}.template_identity_sha256")
    source_sha256 = _require_sha256(candidate["source_identity_sha256"], f"{context}.source_identity_sha256")
    raw_generator = _require_mapping(candidate["generator"], f"{context}.generator must be an object")
    _require_exact_keys(
        raw_generator,
        {
            "family",
            "model",
            "version",
            "prompt_sha256",
            "seed",
            "sampling",
            "generator_commit",
            "dependency_sha256",
            "license_spdx",
            "license_content_sha256",
            "scanner_output_absent_at_seal",
            "provenance_sha256",
        },
        f"{context}.generator",
    )
    family = _require_id(raw_generator["family"], f"{context}.generator.family")
    if family != generator_family:
        raise ValueError(f"{context}.generator family differs from quota cell")
    model = _require_text(raw_generator["model"], f"{context}.generator.model")
    version = _require_text(raw_generator["version"], f"{context}.generator.version")
    prompt_sha256 = _require_sha256(raw_generator["prompt_sha256"], f"{context}.generator.prompt_sha256")
    seed = raw_generator["seed"]
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ValueError(f"{context}.generator.seed invalid")
    sampling = _normalize_sampling(raw_generator["sampling"], f"{context}.generator.sampling")
    generator_commit = raw_generator["generator_commit"]
    if not isinstance(generator_commit, str) or _COMMIT_RE.fullmatch(generator_commit) is None:
        raise ValueError(f"{context}.generator.generator_commit invalid")
    dependency_sha256 = _require_sha256(raw_generator["dependency_sha256"], f"{context}.generator.dependency_sha256")
    license_spdx = raw_generator["license_spdx"]
    if not isinstance(license_spdx, str) or _SPDX_RE.fullmatch(license_spdx) is None:
        raise ValueError(f"{context}.generator.license_spdx invalid")
    license_content_sha256 = _require_sha256(
        raw_generator["license_content_sha256"], f"{context}.generator.license_content_sha256"
    )
    if raw_generator["scanner_output_absent_at_seal"] is not True:
        raise ValueError(f"{context}.generator was not sealed before scanner output")
    generator_without_hash = {
        "dependency_sha256": dependency_sha256,
        "family": family,
        "generator_commit": generator_commit,
        "license_content_sha256": license_content_sha256,
        "license_spdx": license_spdx,
        "model": model,
        "prompt_sha256": prompt_sha256,
        "sampling": sampling,
        "scanner_output_absent_at_seal": True,
        "seed": seed,
        "version": version,
    }
    subject = {
        "generator": generator_without_hash,
        "lineage_id": lineage_id,
        "quota_cell_sha256": quota_cell_sha256,
        "source_identity_sha256": source_sha256,
        "template_identity_sha256": template_sha256,
    }
    expected_provenance = _domain_hash(b"k_guard_l3_generator_provenance.v1\0", subject)
    supplied_provenance = _require_sha256(
        raw_generator["provenance_sha256"], f"{context}.generator.provenance_sha256"
    )
    if supplied_provenance != expected_provenance:
        raise ValueError(f"{context}.generator provenance hash mismatch")
    return {
        "generator": {**generator_without_hash, "provenance_sha256": supplied_provenance},
        "lineage_id": lineage_id,
        "quota_cell_sha256": quota_cell_sha256,
        "reserve_order": reserve_order,
        "source_identity_sha256": source_sha256,
        "template_identity_sha256": template_sha256,
    }


def build_plan(specification: object) -> dict[str, Any]:
    spec = _require_mapping(specification, "plan specification must be an object")
    _require_exact_keys(
        spec,
        {"schema", "detector_artifact_sha256", "cvss_calculator", "scanner_output_absent_at_seal", "slots"},
        "plan specification",
    )
    if spec["schema"] != PLAN_REQUEST_SCHEMA:
        raise ValueError("plan request schema invalid")
    detector_sha256 = _require_sha256(spec["detector_artifact_sha256"], "detector_artifact_sha256")
    calculator = _require_mapping(spec["cvss_calculator"], "cvss_calculator must be an object")
    _require_exact_keys(calculator, {"id", "artifact_sha256"}, "cvss_calculator")
    calculator_id = _require_text(calculator["id"], "cvss_calculator.id")
    calculator_sha256 = _require_sha256(calculator["artifact_sha256"], "cvss_calculator.artifact_sha256")
    if spec["scanner_output_absent_at_seal"] is not True:
        raise ValueError("scanner_output_absent_at_seal must be true")
    slots = spec["slots"]
    if not isinstance(slots, list) or len(slots) != 60:
        raise ValueError("plan must contain exactly 60 slots")

    normalized_slots: list[dict[str, Any]] = []
    plane_counts = {plane: 0 for plane in PLANES}
    language_group_counts = {group: 0 for group in ("js_ts", "python", "java_kotlin", "go")}
    coverage_union: set[str] = set()
    generator_family_counts: Counter[str] = Counter()
    slot_ids: set[str] = set()
    lineages: set[str] = set()
    templates: set[str] = set()
    sources: set[str] = set()

    for index, raw_slot in enumerate(slots):
        slot = _require_mapping(raw_slot, f"slots[{index}] must be an object")
        _require_exact_keys(
            slot,
            {
                "slot_id",
                "plane",
                "language",
                "framework",
                "family",
                "generator_family",
                "coverage_tags",
                "cwe",
                "severity",
                "candidates",
            },
            f"slots[{index}]",
        )
        slot_id = _require_id(slot["slot_id"], f"slots[{index}].slot_id")
        if slot_id in slot_ids:
            raise ValueError(f"duplicate slot_id: {slot_id}")
        slot_ids.add(slot_id)
        plane = slot["plane"]
        if plane not in PLANES:
            raise ValueError(f"slots[{index}].plane invalid")
        plane_counts[str(plane)] += 1
        language = _require_id(slot["language"], f"slots[{index}].language")
        if language not in SUPPORTED_LANGUAGES:
            raise ValueError(f"slots[{index}].language is not declared supported")
        language_group_counts[_language_group(language)] += 1
        framework = _require_id(slot["framework"], f"slots[{index}].framework")
        family = _require_id(slot["family"], f"slots[{index}].family")
        if family not in SCENARIO_FAMILIES:
            raise ValueError(f"slots[{index}].family invalid")
        generator_family = _require_id(slot["generator_family"], f"slots[{index}].generator_family")
        generator_family_counts[generator_family] += 1
        coverage_tags = slot["coverage_tags"]
        if not isinstance(coverage_tags, list) or not coverage_tags:
            raise ValueError(f"slots[{index}].coverage_tags missing")
        normalized_tags = sorted({_require_id(tag, f"slots[{index}].coverage_tags") for tag in coverage_tags})
        if len(normalized_tags) != len(coverage_tags) or not set(normalized_tags) <= REQUIRED_COVERAGE_TAGS:
            raise ValueError(f"slots[{index}].coverage_tags invalid or duplicated")
        coverage_union.update(normalized_tags)
        cwe = slot["cwe"]
        if not isinstance(cwe, str) or _CWE_RE.fullmatch(cwe) is None:
            raise ValueError(f"slots[{index}].cwe invalid")
        severity = slot["severity"]
        if severity not in SEVERITIES:
            raise ValueError(f"slots[{index}].severity invalid")
        candidates = slot["candidates"]
        if not isinstance(candidates, list) or not candidates:
            raise ValueError(f"slots[{index}] must contain a primary candidate")

        cell = {
            "coverage_tags": normalized_tags,
            "cwe": cwe,
            "family": family,
            "framework": framework,
            "generator_family": generator_family,
            "language": language,
            "plane": plane,
            "severity": severity,
        }
        cell_sha256 = _quota_cell_sha256(cell)
        normalized_candidates: list[dict[str, Any]] = []
        for rank, raw_candidate in enumerate(candidates):
            candidate = _normalize_candidate(
                raw_candidate,
                context=f"slots[{index}].candidates[{rank}]",
                quota_cell_sha256=cell_sha256,
                reserve_order=rank,
                generator_family=generator_family,
            )
            lineage_id = candidate["lineage_id"]
            template_sha256 = candidate["template_identity_sha256"]
            source_sha256 = candidate["source_identity_sha256"]
            if lineage_id in lineages:
                raise ValueError(f"duplicate lineage identity: {lineage_id}")
            if template_sha256 in templates:
                raise ValueError(f"duplicate template identity: {template_sha256}")
            if source_sha256 in sources:
                raise ValueError(f"duplicate source identity: {source_sha256}")
            lineages.add(lineage_id)
            templates.add(template_sha256)
            sources.add(source_sha256)
            normalized_candidates.append(candidate)
        normalized_slots.append(
            {
                **cell,
                "candidates": normalized_candidates,
                "quota_cell_sha256": cell_sha256,
                "slot_id": slot_id,
            }
        )

    if plane_counts != {plane: 15 for plane in PLANES}:
        raise ValueError(f"plane quota drift: {plane_counts}")
    missing_language_groups = sorted(group for group, count in language_group_counts.items() if count == 0)
    if missing_language_groups:
        raise ValueError(f"language group coverage missing: {','.join(missing_language_groups)}")
    missing_coverage = sorted(REQUIRED_COVERAGE_TAGS - coverage_union)
    if missing_coverage:
        raise ValueError(f"required ecosystem coverage missing: {','.join(missing_coverage)}")
    overrepresented = sorted(family for family, count in generator_family_counts.items() if count > 24)
    if overrepresented:
        raise ValueError(f"generator family share exceeds 40%: {','.join(overrepresented)}")
    normalized_slots.sort(key=lambda row: row["slot_id"])
    plan: dict[str, Any] = {
        "coverage_tags": sorted(coverage_union),
        "cvss_calculator": {"artifact_sha256": calculator_sha256, "id": calculator_id},
        "detector_artifact_sha256": detector_sha256,
        "generator_family_counts": dict(sorted(generator_family_counts.items())),
        "language_group_counts": language_group_counts,
        "plane_counts": plane_counts,
        "scanner_output_absent_at_seal": True,
        "schema": PLAN_SCHEMA,
        "slot_count": 60,
        "slots": normalized_slots,
    }
    plan["plan_sha256"] = _domain_hash(b"k_guard_l3_campaign_plan.v1\0", plan)
    return plan


def validate_plan(plan: object) -> dict[str, Any]:
    value = _require_mapping(plan, "plan must be an object")
    _require_exact_keys(
        value,
        {
            "schema",
            "coverage_tags",
            "cvss_calculator",
            "detector_artifact_sha256",
            "generator_family_counts",
            "language_group_counts",
            "scanner_output_absent_at_seal",
            "slot_count",
            "plane_counts",
            "slots",
            "plan_sha256",
        },
        "plan",
    )
    digest = _require_sha256(value["plan_sha256"], "plan.plan_sha256")
    unsigned = dict(value)
    unsigned.pop("plan_sha256")
    expected = _domain_hash(b"k_guard_l3_campaign_plan.v1\0", unsigned)
    if digest != expected:
        raise ValueError("plan hash mismatch")
    try:
        rebuilt = build_plan(
            {
                "schema": PLAN_REQUEST_SCHEMA,
                "detector_artifact_sha256": value["detector_artifact_sha256"],
                "cvss_calculator": value["cvss_calculator"],
                "scanner_output_absent_at_seal": value["scanner_output_absent_at_seal"],
                "slots": [
                    {
                        **_quota_cell(slot),
                        "slot_id": slot["slot_id"],
                        "candidates": [
                            {
                                "lineage_id": candidate["lineage_id"],
                                "template_identity_sha256": candidate["template_identity_sha256"],
                                "source_identity_sha256": candidate["source_identity_sha256"],
                                "generator": candidate["generator"],
                            }
                            for candidate in slot["candidates"]
                        ],
                    }
                    for slot in value["slots"]
                ],
            }
        )
    except (KeyError, TypeError) as exc:
        raise ValueError("plan nested structure invalid") from exc
    if rebuilt != dict(value):
        raise ValueError("plan canonical structure mismatch")
    return dict(value)


def _load_json(path: Path, *, canonical: bool, maximum_bytes: int = 20 * 1024 * 1024) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"JSON artifact is not a regular file: {path}")
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read JSON artifact: {path}") from exc
    if not raw or len(raw) > maximum_bytes:
        raise ValueError(f"JSON artifact size invalid: {path}")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"JSON artifact invalid: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be an object: {path}")
    if canonical and canonical_json_bytes(value) != raw:
        raise ValueError(f"JSON artifact is not canonical: {path}")
    return value


def _write_new(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError as exc:
        raise ValueError(f"refusing to overwrite artifact: {path}") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def write_plan(specification: object, output_path: Path) -> dict[str, Any]:
    plan = build_plan(specification)
    _write_new(output_path, canonical_json_bytes(plan))
    return plan


def load_plan(path: Path) -> dict[str, Any]:
    return validate_plan(_load_json(path, canonical=True))


def _plan_index(plan: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(slot["slot_id"]): dict(slot) for slot in plan["slots"]}


def _event_hash(event_without_hash: Mapping[str, Any]) -> str:
    return _domain_hash(b"k_guard_l3_campaign_event.v1\0", event_without_hash)


def load_ledger(path: Path, plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file():
        raise ValueError("ledger is not a regular file")
    raw = path.read_bytes()
    if len(raw) > 100 * 1024 * 1024:
        raise ValueError("ledger exceeds size limit")
    if raw and not raw.endswith(b"\n"):
        raise ValueError("ledger has a truncated final record")
    events: list[dict[str, Any]] = []
    previous = ZERO_SHA256
    for line_number, raw_line in enumerate(raw.splitlines(keepends=True), start=1):
        try:
            value = json.loads(raw_line.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"ledger line {line_number} invalid") from exc
        if not isinstance(value, dict) or canonical_json_bytes(value, line=True) != raw_line:
            raise ValueError(f"ledger line {line_number} is not canonical")
        _require_exact_keys(
            value,
            {
                "schema",
                "sequence",
                "previous_event_sha256",
                "event_sha256",
                "plan_sha256",
                "slot_id",
                "candidate_lineage_id",
                "stage",
                "status",
                "evidence_hashes",
                "admission_receipt",
                "replacement_lineage_id",
            },
            f"ledger line {line_number}",
        )
        if value["schema"] != EVENT_SCHEMA:
            raise ValueError(f"ledger line {line_number} schema invalid")
        if value["sequence"] != line_number:
            raise ValueError(f"ledger line {line_number} sequence invalid")
        if value["previous_event_sha256"] != previous:
            raise ValueError(f"ledger line {line_number} chain mismatch")
        if value["plan_sha256"] != plan["plan_sha256"]:
            raise ValueError(f"ledger line {line_number} plan mismatch")
        supplied_hash = _require_sha256(value["event_sha256"], f"ledger line {line_number} event hash")
        unsigned = dict(value)
        unsigned.pop("event_sha256")
        if supplied_hash != _event_hash(unsigned):
            raise ValueError(f"ledger line {line_number} event hash mismatch")
        previous = supplied_hash
        events.append(value)
    _replay(plan, events)
    return events


def _initial_states(plan: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(slot["slot_id"]): {
            "candidate_index": 0,
            "candidate_lineage_id": slot["candidates"][0]["lineage_id"],
            "status": None,
            "event_count": 0,
            "admission_receipt": None,
        }
        for slot in plan["slots"]
    }


def _validate_evidence_hashes(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError("event evidence_hashes must be a non-empty object")
    result: dict[str, str] = {}
    for key, digest in value.items():
        if not isinstance(key, str) or _EVIDENCE_KEY_RE.fullmatch(key) is None:
            raise ValueError("event evidence hash key invalid")
        result[key] = _require_sha256(digest, f"event evidence_hashes.{key}")
    return dict(sorted(result.items()))


def _canonical_cvss_v4(vector: object, context: str) -> str:
    if not isinstance(vector, str):
        raise ValueError(f"{context} must be a CVSS v4.0 vector")
    parts = vector.split("/")
    if not parts or parts[0] != "CVSS:4.0":
        raise ValueError(f"{context} must start with CVSS:4.0")
    components: dict[str, str] = {}
    for component in parts[1:]:
        if component.count(":") != 1:
            raise ValueError(f"{context} component invalid")
        metric, metric_value = component.split(":", 1)
        if metric in components or metric not in CVSS_V4_BASE_VALUES:
            raise ValueError(f"{context} metric invalid or duplicated")
        if metric_value not in CVSS_V4_BASE_VALUES[metric]:
            raise ValueError(f"{context} metric value invalid")
        components[metric] = metric_value
    if tuple(components) != CVSS_V4_BASE_ORDER:
        raise ValueError(f"{context} must contain canonical complete base metrics")
    return vector


def _normalize_cvss_v4(
    value: object,
    *,
    context: str,
    expected_severity: str,
    calculator: Mapping[str, Any],
) -> dict[str, str]:
    cvss = _require_mapping(value, f"{context} must be an object")
    _require_exact_keys(
        cvss,
        {"vector", "score", "severity", "calculator_id", "calculator_artifact_sha256", "result_sha256"},
        context,
    )
    vector = _canonical_cvss_v4(cvss["vector"], f"{context}.vector")
    score = cvss["score"]
    if not isinstance(score, str) or _CVSS_SCORE_RE.fullmatch(score) is None:
        raise ValueError(f"{context}.score must be a deterministic one-decimal string")
    decimal_score = Decimal(score)
    bucket = "critical" if decimal_score >= Decimal("9.0") else "high" if decimal_score >= Decimal("7.0") else None
    if bucket != expected_severity or cvss["severity"] != expected_severity:
        raise ValueError(f"{context} result/severity mismatch")
    if cvss["calculator_id"] != calculator["id"]:
        raise ValueError(f"{context} calculator id mismatch")
    if cvss["calculator_artifact_sha256"] != calculator["artifact_sha256"]:
        raise ValueError(f"{context} calculator artifact mismatch")
    result_sha256 = _require_sha256(cvss["result_sha256"], f"{context}.result_sha256")
    return {
        "calculator_artifact_sha256": calculator["artifact_sha256"],
        "calculator_id": calculator["id"],
        "result_sha256": result_sha256,
        "score": score,
        "severity": expected_severity,
        "vector": vector,
    }


def _normalize_execution(
    value: object,
    *,
    context: str,
    outcome_key: str,
    expected_outcome: bool,
) -> dict[str, Any]:
    execution = _require_mapping(value, f"{context} must be an object")
    _require_exact_keys(
        execution,
        {"executed", "harness_passed", "command_sha256", "result_sha256", outcome_key, "receipt_sha256"},
        context,
    )
    if (
        execution["executed"] is not True
        or execution["harness_passed"] is not True
        or execution[outcome_key] is not expected_outcome
    ):
        raise ValueError(f"{context} semantic outcome invalid")
    return {
        "command_sha256": _require_sha256(execution["command_sha256"], f"{context}.command_sha256"),
        "executed": True,
        "harness_passed": True,
        outcome_key: expected_outcome,
        "receipt_sha256": _require_sha256(execution["receipt_sha256"], f"{context}.receipt_sha256"),
        "result_sha256": _require_sha256(execution["result_sha256"], f"{context}.result_sha256"),
    }


def _normalize_validator(
    value: object,
    *,
    context: str,
    expected_id: str,
) -> dict[str, Any]:
    validator = _require_mapping(value, f"{context} must be an object")
    _require_exact_keys(validator, {"validator_id", "validator_sha256", "receipt_sha256", "passed"}, context)
    if validator["validator_id"] != expected_id or validator["passed"] is not True:
        raise ValueError(f"{context} validator identity or result invalid")
    return {
        "passed": True,
        "receipt_sha256": _require_sha256(validator["receipt_sha256"], f"{context}.receipt_sha256"),
        "validator_id": expected_id,
        "validator_sha256": _require_sha256(validator["validator_sha256"], f"{context}.validator_sha256"),
    }


def _normalize_patch_validator(value: object, *, family: str) -> dict[str, Any]:
    context = "admission_receipt.bounded_causal_patch"
    validator = _require_mapping(value, f"{context} must be an object")
    _require_exact_keys(
        validator,
        {
            "validator_id",
            "validator_sha256",
            "receipt_sha256",
            "passed",
            "production_file_count",
            "logical_changed_lines",
            "change_kinds",
            "invariants_unchanged",
        },
        context,
    )
    max_files, max_lines, allowed_kinds = PATCH_LIMITS[family]
    file_count = validator["production_file_count"]
    changed_lines = validator["logical_changed_lines"]
    if (
        isinstance(file_count, bool)
        or not isinstance(file_count, int)
        or not 1 <= file_count <= max_files
        or isinstance(changed_lines, bool)
        or not isinstance(changed_lines, int)
        or not 1 <= changed_lines <= max_lines
    ):
        raise ValueError(f"{context} exceeds family patch bounds")
    change_kinds = validator["change_kinds"]
    if not isinstance(change_kinds, list) or not change_kinds:
        raise ValueError(f"{context} change kinds missing")
    normalized_kinds = sorted({_require_id(item, f"{context}.change_kinds") for item in change_kinds})
    if len(normalized_kinds) != len(change_kinds) or not set(normalized_kinds) <= allowed_kinds:
        raise ValueError(f"{context} change kinds violate family policy")
    if family == "dependency-sca" and "manifest-entry" not in normalized_kinds:
        raise ValueError(f"{context} dependency manifest entry missing")
    if validator["validator_id"] != PATCH_POLICY_BY_FAMILY[family] or validator["passed"] is not True:
        raise ValueError(f"{context} validator identity or result invalid")
    if validator["invariants_unchanged"] is not True:
        raise ValueError(f"{context} unrelated invariants changed")
    return {
        "change_kinds": normalized_kinds,
        "invariants_unchanged": True,
        "logical_changed_lines": changed_lines,
        "passed": True,
        "production_file_count": file_count,
        "receipt_sha256": _require_sha256(validator["receipt_sha256"], f"{context}.receipt_sha256"),
        "validator_id": PATCH_POLICY_BY_FAMILY[family],
        "validator_sha256": _require_sha256(validator["validator_sha256"], f"{context}.validator_sha256"),
    }


def _admission_receipt_hash(value: Mapping[str, Any]) -> str:
    unsigned = dict(value)
    unsigned.pop("receipt_sha256", None)
    return _domain_hash(b"k_guard_l3_admission_receipt.v1\0", unsigned)


def _normalize_admission_receipt(
    value: object,
    *,
    status: str,
    slot: Mapping[str, Any],
    candidate: Mapping[str, Any],
    calculator: Mapping[str, Any],
) -> dict[str, Any]:
    receipt = _require_mapping(value, "admission_receipt must be an object")
    if status == "rejected":
        _require_exact_keys(
            receipt,
            {
                "schema",
                "lineage_id",
                "admission_passed",
                "failure_codes",
                "provenance_sha256",
                "scanner_output_absent_at_seal",
                "receipt_sha256",
            },
            "rejected admission_receipt",
        )
        if receipt["schema"] != ADMISSION_RECEIPT_SCHEMA or receipt["lineage_id"] != candidate["lineage_id"]:
            raise ValueError("rejected admission receipt identity invalid")
        if receipt["admission_passed"] is not False or receipt["scanner_output_absent_at_seal"] is not True:
            raise ValueError("rejected admission receipt disposition invalid")
        failures = receipt["failure_codes"]
        if not isinstance(failures, list) or not failures:
            raise ValueError("rejected admission receipt must retain failure codes")
        normalized_failures = sorted({_require_id(item, "admission failure code") for item in failures})
        if len(normalized_failures) != len(failures):
            raise ValueError("admission failure codes duplicated")
        if receipt["provenance_sha256"] != candidate["generator"]["provenance_sha256"]:
            raise ValueError("rejected admission provenance mismatch")
        normalized = {
            "admission_passed": False,
            "failure_codes": normalized_failures,
            "lineage_id": candidate["lineage_id"],
            "provenance_sha256": candidate["generator"]["provenance_sha256"],
            "scanner_output_absent_at_seal": True,
            "schema": ADMISSION_RECEIPT_SCHEMA,
        }
    else:
        _require_exact_keys(
            receipt,
            {
                "schema",
                "lineage_id",
                "admission_passed",
                "expected_disposition",
                "scanner_output_absent_at_seal",
                "vulnerable_tree_sha256",
                "fixed_tree_sha256",
                "negative_control_tree_sha256",
                "exploit_vulnerable",
                "exploit_fixed",
                "negative_control",
                "fixed_functional",
                "bounded_causal_patch",
                "ast_config_diff",
                "build_result",
                "functional_snapshot",
                "license_provenance",
                "oracle_bundle_sha256",
                "cvss_v4",
                "receipt_sha256",
            },
            "admitted admission_receipt",
        )
        if receipt["schema"] != ADMISSION_RECEIPT_SCHEMA or receipt["lineage_id"] != candidate["lineage_id"]:
            raise ValueError("admitted admission receipt identity invalid")
        if receipt["admission_passed"] is not True or receipt["scanner_output_absent_at_seal"] is not True:
            raise ValueError("admitted admission receipt disposition invalid")
        disposition = receipt["expected_disposition"]
        if disposition not in {"block", "review"} or (slot["severity"] == "critical" and disposition != "block"):
            raise ValueError("admitted expected disposition invalid")
        trees = {
            name: _require_sha256(receipt[name], f"admission_receipt.{name}")
            for name in ("vulnerable_tree_sha256", "fixed_tree_sha256", "negative_control_tree_sha256")
        }
        if len(set(trees.values())) != 3:
            raise ValueError("admission source trees must be distinct")
        exploit_vulnerable = _normalize_execution(
            receipt["exploit_vulnerable"],
            context="admission_receipt.exploit_vulnerable",
            outcome_key="exploit_succeeded",
            expected_outcome=True,
        )
        exploit_fixed = _normalize_execution(
            receipt["exploit_fixed"],
            context="admission_receipt.exploit_fixed",
            outcome_key="exploit_succeeded",
            expected_outcome=False,
        )
        if exploit_vulnerable["command_sha256"] != exploit_fixed["command_sha256"]:
            raise ValueError("exploit vulnerable/fixed command mismatch")
        if exploit_vulnerable["result_sha256"] == exploit_fixed["result_sha256"]:
            raise ValueError("exploit vulnerable/fixed results are not differential")
        negative_control = _normalize_execution(
            receipt["negative_control"],
            context="admission_receipt.negative_control",
            outcome_key="control_triggered",
            expected_outcome=False,
        )
        fixed_functional = _normalize_execution(
            receipt["fixed_functional"],
            context="admission_receipt.fixed_functional",
            outcome_key="passed",
            expected_outcome=True,
        )
        patch = _normalize_patch_validator(receipt["bounded_causal_patch"], family=slot["family"])
        ast_diff = _normalize_validator(
            receipt["ast_config_diff"],
            context="admission_receipt.ast_config_diff",
            expected_id=f"ast-config-diff.{slot['family']}.v1",
        )
        build_result = _normalize_execution(
            receipt["build_result"],
            context="admission_receipt.build_result",
            outcome_key="passed",
            expected_outcome=True,
        )
        snapshot = _require_mapping(receipt["functional_snapshot"], "functional_snapshot must be an object")
        _require_exact_keys(snapshot, {"before_sha256", "after_sha256", "equal", "receipt_sha256"}, "functional_snapshot")
        before = _require_sha256(snapshot["before_sha256"], "functional_snapshot.before_sha256")
        after = _require_sha256(snapshot["after_sha256"], "functional_snapshot.after_sha256")
        if snapshot["equal"] is not True or before != after:
            raise ValueError("functional snapshot mismatch")
        normalized_snapshot = {
            "after_sha256": after,
            "before_sha256": before,
            "equal": True,
            "receipt_sha256": _require_sha256(snapshot["receipt_sha256"], "functional_snapshot.receipt_sha256"),
        }
        license_value = _require_mapping(receipt["license_provenance"], "license_provenance must be an object")
        _require_exact_keys(
            license_value,
            {"verified", "license_spdx", "license_content_sha256", "provenance_sha256", "receipt_sha256"},
            "license_provenance",
        )
        generator = candidate["generator"]
        if (
            license_value["verified"] is not True
            or license_value["license_spdx"] != generator["license_spdx"]
            or license_value["license_content_sha256"] != generator["license_content_sha256"]
            or license_value["provenance_sha256"] != generator["provenance_sha256"]
        ):
            raise ValueError("license/provenance receipt mismatch")
        normalized_license = {
            "license_content_sha256": generator["license_content_sha256"],
            "license_spdx": generator["license_spdx"],
            "provenance_sha256": generator["provenance_sha256"],
            "receipt_sha256": _require_sha256(license_value["receipt_sha256"], "license_provenance.receipt_sha256"),
            "verified": True,
        }
        cvss = _normalize_cvss_v4(
            receipt["cvss_v4"], context="admission_receipt.cvss_v4", expected_severity=slot["severity"], calculator=calculator
        )
        normalized = {
            "admission_passed": True,
            "ast_config_diff": ast_diff,
            "bounded_causal_patch": patch,
            "build_result": build_result,
            "cvss_v4": cvss,
            "expected_disposition": disposition,
            "exploit_fixed": exploit_fixed,
            "exploit_vulnerable": exploit_vulnerable,
            "fixed_functional": fixed_functional,
            "fixed_tree_sha256": trees["fixed_tree_sha256"],
            "functional_snapshot": normalized_snapshot,
            "license_provenance": normalized_license,
            "lineage_id": candidate["lineage_id"],
            "negative_control_tree_sha256": trees["negative_control_tree_sha256"],
            "negative_control": negative_control,
            "oracle_bundle_sha256": _require_sha256(receipt["oracle_bundle_sha256"], "oracle_bundle_sha256"),
            "scanner_output_absent_at_seal": True,
            "schema": ADMISSION_RECEIPT_SCHEMA,
            "vulnerable_tree_sha256": trees["vulnerable_tree_sha256"],
        }
    supplied = _require_sha256(receipt["receipt_sha256"], "admission_receipt.receipt_sha256")
    if supplied != _admission_receipt_hash(normalized):
        raise ValueError("admission receipt hash mismatch")
    return {**normalized, "receipt_sha256": supplied}


def _apply_event(
    plan: Mapping[str, Any],
    states: dict[str, dict[str, Any]],
    event: Mapping[str, Any],
) -> None:
    plan_index = _plan_index(plan)
    slot_id = event["slot_id"]
    if slot_id not in states:
        raise ValueError(f"event references unknown slot: {slot_id}")
    state = states[slot_id]
    slot = plan_index[slot_id]
    status = event["status"]
    if status not in _STAGE_BY_STATUS:
        raise ValueError(f"event status invalid: {status}")
    if event["stage"] != _STAGE_BY_STATUS[status]:
        raise ValueError(f"event stage does not match status: {status}")
    if status not in _LEGAL_NEXT[state["status"]]:
        raise ValueError(f"illegal transition for {slot_id}: {state['status']}->{status}")
    if event["candidate_lineage_id"] != state["candidate_lineage_id"]:
        raise ValueError(f"candidate lineage drift for {slot_id}")
    evidence_hashes = _validate_evidence_hashes(event["evidence_hashes"])
    candidate = slot["candidates"][state["candidate_index"]]
    admission_receipt = event["admission_receipt"]
    if status in {"admitted", "rejected"}:
        normalized_receipt = _normalize_admission_receipt(
            admission_receipt,
            status=status,
            slot=slot,
            candidate=candidate,
            calculator=plan["cvss_calculator"],
        )
        expected_evidence = {"admission_receipt_sha256": normalized_receipt["receipt_sha256"]}
        if evidence_hashes != expected_evidence:
            raise ValueError("admission event evidence does not bind the structured receipt")
    elif admission_receipt is not None:
        raise ValueError("admission_receipt is allowed only for admitted or rejected events")
    else:
        normalized_receipt = None
    if status == "finalized" and (
        not isinstance(state["admission_receipt"], Mapping)
        or state["admission_receipt"].get("admission_passed") is not True
    ):
        raise ValueError(f"cannot finalize {slot_id} without a valid admitted receipt")

    replacement = event["replacement_lineage_id"]
    if status == "replaced":
        next_index = state["candidate_index"] + 1
        candidates = slot["candidates"]
        if next_index >= len(candidates):
            raise ValueError(f"reserve exhausted for {slot_id}")
        expected = candidates[next_index]
        if replacement != expected["lineage_id"]:
            raise ValueError(f"replacement order or quota cell invalid for {slot_id}")
        if expected["quota_cell_sha256"] != slot["quota_cell_sha256"]:
            raise ValueError(f"replacement quota cell drift for {slot_id}")
        state["candidate_index"] = next_index
        state["candidate_lineage_id"] = replacement
        state["admission_receipt"] = None
    elif replacement is not None:
        raise ValueError("replacement_lineage_id is allowed only for replaced events")
    if status in {"admitted", "rejected"}:
        state["admission_receipt"] = normalized_receipt
    state["status"] = status
    state["event_count"] += 1


def _replay(plan: Mapping[str, Any], events: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    states = _initial_states(plan)
    for event in events:
        _apply_event(plan, states, event)
    return states


def append_event(
    plan_path: Path,
    ledger_path: Path,
    request: object,
) -> dict[str, Any]:
    plan = load_plan(plan_path)
    value = _require_mapping(request, "event request must be an object")
    allowed = {
        "schema",
        "slot_id",
        "candidate_lineage_id",
        "stage",
        "status",
        "evidence_hashes",
        "admission_receipt",
        "replacement_lineage_id",
    }
    _require_exact_keys(value, allowed, "event request")
    if value["schema"] != EVENT_REQUEST_SCHEMA:
        raise ValueError("event request schema invalid")
    slot_id = _require_id(value["slot_id"], "event.slot_id")
    candidate = _require_id(value["candidate_lineage_id"], "event.candidate_lineage_id")
    status = value["status"]
    if status not in _STAGE_BY_STATUS:
        raise ValueError("event status invalid")
    stage = value["stage"]
    if stage != _STAGE_BY_STATUS[status]:
        raise ValueError("event stage does not match status")
    replacement = value["replacement_lineage_id"]
    if replacement is not None:
        replacement = _require_id(replacement, "event.replacement_lineage_id")
    evidence_hashes = _validate_evidence_hashes(value["evidence_hashes"])
    admission_receipt = value["admission_receipt"]

    lock_path = ledger_path.with_name(ledger_path.name + ".lock")
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise ValueError("ledger append lock already exists") from exc
    try:
        os.close(lock_fd)
        events = load_ledger(ledger_path, plan)
        previous = events[-1]["event_sha256"] if events else ZERO_SHA256
        event: dict[str, Any] = {
            "candidate_lineage_id": candidate,
            "admission_receipt": admission_receipt,
            "evidence_hashes": evidence_hashes,
            "plan_sha256": plan["plan_sha256"],
            "previous_event_sha256": previous,
            "replacement_lineage_id": replacement,
            "schema": EVENT_SCHEMA,
            "sequence": len(events) + 1,
            "slot_id": slot_id,
            "stage": stage,
            "status": status,
        }
        _apply_event(plan, _replay(plan, events), event)
        event["event_sha256"] = _event_hash(event)
        with ledger_path.open("ab") as output:
            output.write(canonical_json_bytes(event, line=True))
            output.flush()
            os.fsync(output.fileno())
        load_ledger(ledger_path, plan)
        return event
    finally:
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def _validate_label(
    raw_label: object,
    slot: Mapping[str, Any],
    state: Mapping[str, Any],
    detector_sha256: str,
    calculator: Mapping[str, Any],
    index: int,
) -> dict[str, Any]:
    label = _require_mapping(raw_label, f"labels[{index}] must be an object")
    expected_keys = {
        "slot_id",
        "lineage_id",
        "scenario_id",
        "oracle_id",
        "plane",
        "language",
        "framework",
        "family",
        "generator_family",
        "coverage_tags",
        "cwe",
        "cvss_v4",
        "severity",
        "expected_disposition",
        "vulnerable_truth",
        "fixed_truth",
        "negative_control_truth",
        "oracle_bundle_sha256",
        "vulnerable_tree_sha256",
        "fixed_tree_sha256",
        "negative_control_tree_sha256",
        "provenance_sha256",
        "admission_receipt_sha256",
        "detector_artifact_sha256",
        "scanner_output_absent_at_seal",
    }
    _require_exact_keys(label, expected_keys, f"labels[{index}]")
    slot_id = _require_id(label["slot_id"], f"labels[{index}].slot_id")
    if slot_id != slot["slot_id"]:
        raise ValueError(f"label slot order or identity drift at index {index}")
    lineage_id = _require_id(label["lineage_id"], f"labels[{index}].lineage_id")
    if lineage_id != state["candidate_lineage_id"]:
        raise ValueError(f"label lineage drift for {slot_id}")
    scenario_id = _require_id(label["scenario_id"], f"labels[{index}].scenario_id")
    oracle_id = _require_id(label["oracle_id"], f"labels[{index}].oracle_id")
    for field in ("plane", "language", "framework", "family", "generator_family", "cwe", "severity"):
        if label[field] != slot[field]:
            raise ValueError(f"label quota drift for {slot_id}: {field}")
    if label["coverage_tags"] != slot["coverage_tags"]:
        raise ValueError(f"label quota drift for {slot_id}: coverage_tags")
    cvss = _normalize_cvss_v4(
        label["cvss_v4"],
        context=f"labels[{index}].cvss_v4",
        expected_severity=slot["severity"],
        calculator=calculator,
    )
    disposition = label["expected_disposition"]
    if disposition not in {"block", "review"}:
        raise ValueError(f"label disposition invalid for {slot_id}")
    if label["severity"] == "critical" and disposition != "block":
        raise ValueError(f"Critical label must block for {slot_id}")
    if label["vulnerable_truth"] != TRUTH["vulnerable"]:
        raise ValueError(f"vulnerable truth invalid for {slot_id}")
    if label["fixed_truth"] != TRUTH["fixed"]:
        raise ValueError(f"fixed truth invalid for {slot_id}")
    if label["negative_control_truth"] != TRUTH["negative_control"]:
        raise ValueError(f"negative-control truth invalid for {slot_id}")
    for field in (
        "oracle_bundle_sha256",
        "vulnerable_tree_sha256",
        "fixed_tree_sha256",
        "negative_control_tree_sha256",
    ):
        _require_sha256(label[field], f"labels[{index}].{field}")
    if len(
        {
            label["vulnerable_tree_sha256"],
            label["fixed_tree_sha256"],
            label["negative_control_tree_sha256"],
        }
    ) != 3:
        raise ValueError(f"source tree hashes must be distinct for {slot_id}")
    receipt = state.get("admission_receipt")
    if not isinstance(receipt, Mapping) or receipt.get("admission_passed") is not True:
        raise ValueError(f"label lacks admitted machine receipt for {slot_id}")
    candidate = slot["candidates"][state["candidate_index"]]
    expected_bindings = {
        "admission_receipt_sha256": receipt["receipt_sha256"],
        "expected_disposition": receipt["expected_disposition"],
        "fixed_tree_sha256": receipt["fixed_tree_sha256"],
        "negative_control_tree_sha256": receipt["negative_control_tree_sha256"],
        "oracle_bundle_sha256": receipt["oracle_bundle_sha256"],
        "provenance_sha256": candidate["generator"]["provenance_sha256"],
        "vulnerable_tree_sha256": receipt["vulnerable_tree_sha256"],
    }
    for field, expected in expected_bindings.items():
        if label[field] != expected:
            raise ValueError(f"label admission binding mismatch for {slot_id}: {field}")
    if cvss != receipt["cvss_v4"]:
        raise ValueError(f"label CVSS result differs from admitted receipt for {slot_id}")
    if label["detector_artifact_sha256"] != detector_sha256:
        raise ValueError(f"detector artifact drift for {slot_id}")
    if label["scanner_output_absent_at_seal"] is not True:
        raise ValueError(f"scanner output was present before label seal for {slot_id}")
    return {
        **dict(label),
        "cvss_v4": cvss,
        "oracle_id": oracle_id,
        "scenario_id": scenario_id,
        "slot_id": slot_id,
        "lineage_id": lineage_id,
    }


def build_label_commitment(
    plan: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    request: object,
) -> dict[str, Any]:
    value = _require_mapping(request, "label commitment request must be an object")
    _require_exact_keys(
        value,
        {"schema", "sealed_at", "detector_artifact_sha256", "scanner_output_absent_at_seal", "labels"},
        "label commitment request",
    )
    if value["schema"] != LABEL_REQUEST_SCHEMA:
        raise ValueError("label commitment request schema invalid")
    sealed_at = _require_utc(value["sealed_at"], "sealed_at")
    detector_sha256 = _require_sha256(value["detector_artifact_sha256"], "detector_artifact_sha256")
    if detector_sha256 != plan["detector_artifact_sha256"]:
        raise ValueError("label detector artifact does not match plan")
    if value["scanner_output_absent_at_seal"] is not True:
        raise ValueError("scanner output must be absent when labels are sealed")
    states = _replay(plan, events)
    incomplete = sorted(slot_id for slot_id, state in states.items() if state["status"] != "finalized")
    if incomplete:
        raise ValueError(f"cannot seal labels before all slots are finalized: {','.join(incomplete)}")
    labels = value["labels"]
    if not isinstance(labels, list) or len(labels) != 60:
        raise ValueError("label commitment must contain exactly 60 labels")
    slots = plan["slots"]
    normalized_labels = [
        _validate_label(
            labels[index],
            slots[index],
            states[slots[index]["slot_id"]],
            detector_sha256,
            plan["cvss_calculator"],
            index,
        )
        for index in range(60)
    ]
    scenarios = [label["scenario_id"] for label in normalized_labels]
    oracles = [label["oracle_id"] for label in normalized_labels]
    if len(set(scenarios)) != 60:
        raise ValueError("duplicate scenario_id in label commitment")
    if len(set(oracles)) != 60:
        raise ValueError("duplicate oracle_id in label commitment")
    ledger_head = events[-1]["event_sha256"] if events else ZERO_SHA256
    commitment: dict[str, Any] = {
        "admission_receipt_count": 60,
        "cvss_calculator": plan["cvss_calculator"],
        "detector_artifact_sha256": detector_sha256,
        "label_count": 60,
        "labels": normalized_labels,
        "ledger_event_count": len(events),
        "plan_sha256": plan["plan_sha256"],
        "prior_ledger_sha256": ledger_head,
        "scanner_output_absent_at_seal": True,
        "schema": LABEL_SCHEMA,
        "sealed_at": sealed_at,
    }
    commitment["commitment_sha256"] = _domain_hash(b"k_guard_l3_label_commitment.v1\0", commitment)
    return commitment


def seal_labels(plan_path: Path, ledger_path: Path, request: object, output_path: Path) -> dict[str, Any]:
    plan = load_plan(plan_path)
    events = load_ledger(ledger_path, plan)
    commitment = build_label_commitment(plan, events, request)
    _write_new(output_path, canonical_json_bytes(commitment))
    return commitment


def load_label_commitment(
    path: Path,
    plan: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    value = _load_json(path, canonical=True)
    if value.get("schema") != LABEL_SCHEMA:
        raise ValueError("label commitment schema invalid")
    supplied = _require_sha256(value.get("commitment_sha256"), "commitment_sha256")
    unsigned = dict(value)
    unsigned.pop("commitment_sha256", None)
    if supplied != _domain_hash(b"k_guard_l3_label_commitment.v1\0", unsigned):
        raise ValueError("label commitment hash mismatch")
    rebuilt = build_label_commitment(
        plan,
        events,
        {
            "schema": LABEL_REQUEST_SCHEMA,
            "sealed_at": value.get("sealed_at"),
            "detector_artifact_sha256": value.get("detector_artifact_sha256"),
            "scanner_output_absent_at_seal": value.get("scanner_output_absent_at_seal"),
            "labels": value.get("labels"),
        },
    )
    if rebuilt != value:
        raise ValueError("label commitment canonical structure mismatch")
    return value


def campaign_status(
    plan: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    commitment: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    states = _replay(plan, events)
    slots = _plan_index(plan)
    counts = {status: 0 for status in (*_STAGE_BY_STATUS, "unreserved")}
    reserve_exhausted: list[str] = []
    for slot_id, state in states.items():
        counts[state["status"] or "unreserved"] += 1
        if state["status"] == "rejected" and state["candidate_index"] + 1 >= len(slots[slot_id]["candidates"]):
            reserve_exhausted.append(slot_id)
    all_finalized = counts["finalized"] == 60
    fully_admitted = sum(
        state["status"] == "finalized"
        and isinstance(state["admission_receipt"], Mapping)
        and state["admission_receipt"].get("admission_passed") is True
        for state in states.values()
    )
    commitment_valid = False
    if commitment is not None:
        required_commitment = {
            "schema": LABEL_SCHEMA,
            "admission_receipt_count": 60,
            "cvss_calculator": plan["cvss_calculator"],
            "plan_sha256": plan["plan_sha256"],
            "prior_ledger_sha256": events[-1]["event_sha256"] if events else ZERO_SHA256,
            "ledger_event_count": len(events),
            "label_count": 60,
            "detector_artifact_sha256": plan["detector_artifact_sha256"],
            "scanner_output_absent_at_seal": True,
        }
        for field, expected in required_commitment.items():
            if commitment.get(field) != expected:
                raise ValueError(f"status label commitment mismatch: {field}")
        supplied = _require_sha256(commitment.get("commitment_sha256"), "commitment_sha256")
        unsigned = dict(commitment)
        unsigned.pop("commitment_sha256", None)
        if supplied != _domain_hash(b"k_guard_l3_label_commitment.v1\0", unsigned):
            raise ValueError("status label commitment hash mismatch")
        rebuilt = build_label_commitment(
            plan,
            events,
            {
                "schema": LABEL_REQUEST_SCHEMA,
                "sealed_at": commitment.get("sealed_at"),
                "detector_artifact_sha256": commitment.get("detector_artifact_sha256"),
                "scanner_output_absent_at_seal": commitment.get("scanner_output_absent_at_seal"),
                "labels": commitment.get("labels"),
            },
        )
        if rebuilt != dict(commitment):
            raise ValueError("status label commitment canonical structure mismatch")
        commitment_valid = True
    reasons: list[str] = []
    if reserve_exhausted:
        reasons.append("reserve_exhausted")
    if not all_finalized:
        reasons.append("slots_not_finalized")
    if fully_admitted != 60:
        reasons.append("machine_admission_receipts_incomplete")
    if not commitment_valid:
        reasons.append("labels_not_sealed")
    disposition = "READY_TO_SCAN" if not reasons else "HOLD"
    return {
        "commitment_sha256": commitment.get("commitment_sha256") if commitment else None,
        "disposition": disposition,
        "fully_admitted_finalized_count": fully_admitted,
        "event_count": len(events),
        "ledger_head_sha256": events[-1]["event_sha256"] if events else ZERO_SHA256,
        "plan_sha256": plan["plan_sha256"],
        "reasons": reasons,
        "reserve_exhausted_slots": sorted(reserve_exhausted),
        "schema": STATUS_SCHEMA,
        "slot_status_counts": counts,
    }


def status_from_paths(plan_path: Path, ledger_path: Path, commitment_path: Path | None = None) -> dict[str, Any]:
    plan = load_plan(plan_path)
    events = load_ledger(ledger_path, plan)
    commitment = load_label_commitment(commitment_path, plan, events) if commitment_path else None
    return campaign_status(plan, events, commitment)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Materialize deterministic L3 calibration campaign metadata.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan")
    plan.add_argument("--spec", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    append = subparsers.add_parser("append-event")
    append.add_argument("--plan", type=Path, required=True)
    append.add_argument("--ledger", type=Path, required=True)
    append.add_argument("--event", type=Path, required=True)
    seal = subparsers.add_parser("seal-labels")
    seal.add_argument("--plan", type=Path, required=True)
    seal.add_argument("--ledger", type=Path, required=True)
    seal.add_argument("--labels", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)
    status = subparsers.add_parser("status")
    status.add_argument("--plan", type=Path, required=True)
    status.add_argument("--ledger", type=Path, required=True)
    status.add_argument("--commitment", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "plan":
            result = write_plan(_load_json(args.spec, canonical=False), args.output)
        elif args.command == "append-event":
            result = append_event(args.plan, args.ledger, _load_json(args.event, canonical=False))
        elif args.command == "seal-labels":
            result = seal_labels(args.plan, args.ledger, _load_json(args.labels, canonical=False), args.output)
        else:
            result = status_from_paths(args.plan, args.ledger, args.commitment)
        sys.stdout.buffer.write(canonical_json_bytes(result))
        return 0 if result.get("disposition") != "HOLD" else 1
    except (OSError, ValueError) as exc:
        print(f"materialize_calibration_corpus: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
