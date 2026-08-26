from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
MATERIALIZER_PATH = REPOSITORY_ROOT / "scripts" / "materialize_calibration_corpus.py"
SCHEMA = "k_guard_l3_generated_pair_blueprint.v1"
VERSION = "1.0.0"
PLANES = ("site", "api", "data", "operations")
FAMILIES = frozenset(
    {"source-flow", "auth-rls-db", "dependency-sca", "gha-docker-iac", "policy-kpriv"}
)
LANGUAGES = frozenset({"javascript", "typescript", "python", "java", "kotlin", "go"})
REQUIRED_COVERAGE_TAGS = frozenset(
    {"nextjs", "express", "supabase", "firebase", "sql-rls", "mcp-proxy", "gha-docker-iac", "korean-privacy"}
)
SEVERITIES = frozenset({"high", "critical"})
SLOT_ID_RE = re.compile(r"^(site|api|data|operations)-(?:0[1-9]|1[0-5])$")
SCENARIO_ID_RE = re.compile(r"^dev-[a-z0-9][a-z0-9-]{2,95}$")
ORACLE_ID_RE = re.compile(r"^l3-gen-[a-z0-9][a-z0-9-]{2,95}$")
ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

GENERATOR_PROFILES: dict[str, dict[str, Any]] = {
    "deterministic-template-v1": {
        "kind": "local-deterministic-template",
        "network_allowed": False,
        "scanner_output_absent_at_seal": True,
        "version": "1.0.0",
    },
    "deterministic-transform-v1": {
        "kind": "local-deterministic-transform",
        "network_allowed": False,
        "scanner_output_absent_at_seal": True,
        "version": "1.0.0",
    },
    "deterministic-fixture-v1": {
        "kind": "local-deterministic-fixture",
        "network_allowed": False,
        "scanner_output_absent_at_seal": True,
        "version": "1.0.0",
    },
}

ORACLE_CONTRACT = {
    "schema": "k_guard_l3_generated_pair_oracle_contract.v1",
    "vulnerable_expected": "exploit_succeeds",
    "fixed_expected": "exploit_fails_and_functional_test_passes",
    "negative_control_expected": "exploit_fails_without_target_condition",
    "isolated_execution_required": True,
    "network_disabled_required": True,
    "source_triplet_required": True,
}

REQUIRED_EVIDENCE_KEYS = (
    "candidate_provenance_sha256",
    "license_content_sha256",
    "negative_control_tree_sha256",
    "fixed_tree_sha256",
    "vulnerable_tree_sha256",
    "exploit_vulnerable_receipt_sha256",
    "exploit_fixed_receipt_sha256",
    "fixed_functional_receipt_sha256",
    "negative_control_receipt_sha256",
    "bounded_patch_receipt_sha256",
    "invariants_receipt_sha256",
)

# family, language, framework, coverage tag, CWE, severity, stable scenario suffix
SLOT_ROWS: dict[str, tuple[tuple[str, str, str, str, str, str, str], ...]] = {
    "site": (
        ("source-flow", "typescript", "nextjs", "nextjs", "CWE-79", "high", "xss-render"),
        ("source-flow", "javascript", "express", "express", "CWE-89", "high", "sqli-query"),
        ("source-flow", "javascript", "express", "express", "CWE-78", "critical", "command-exec"),
        ("source-flow", "typescript", "nextjs", "nextjs", "CWE-22", "high", "path-traversal"),
        ("source-flow", "typescript", "nextjs", "nextjs", "CWE-601", "high", "untrusted-redirect"),
        ("source-flow", "javascript", "express", "express", "CWE-918", "high", "ssrf-fetch"),
        ("source-flow", "typescript", "nextjs", "nextjs", "CWE-1321", "high", "prototype-pollution"),
        ("source-flow", "javascript", "express", "express", "CWE-502", "critical", "unsafe-deserialize"),
        ("source-flow", "typescript", "nextjs", "nextjs", "CWE-798", "critical", "client-secret"),
        ("source-flow", "javascript", "express", "express", "CWE-942", "high", "cors-origin"),
        ("source-flow", "python", "django", "express", "CWE-79", "high", "template-xss"),
        ("source-flow", "python", "flask", "express", "CWE-22", "high", "file-read"),
        ("source-flow", "java", "spring", "express", "CWE-89", "high", "jdbc-query"),
        ("source-flow", "kotlin", "ktor", "express", "CWE-79", "high", "html-response"),
        ("source-flow", "go", "chi", "express", "CWE-89", "critical", "sql-builder"),
    ),
    "api": (
        ("auth-rls-db", "javascript", "express", "express", "CWE-862", "high", "route-idor"),
        ("auth-rls-db", "typescript", "nextjs", "nextjs", "CWE-639", "high", "service-idor"),
        ("auth-rls-db", "typescript", "supabase", "supabase", "CWE-284", "critical", "rls-missing"),
        ("auth-rls-db", "typescript", "firebase", "firebase", "CWE-284", "critical", "rule-open"),
        ("auth-rls-db", "typescript", "nextjs", "nextjs", "CWE-285", "critical", "admin-boundary"),
        ("auth-rls-db", "javascript", "express", "express", "CWE-915", "high", "mass-assignment"),
        ("auth-rls-db", "typescript", "supabase", "supabase", "CWE-798", "critical", "service-role-key"),
        ("auth-rls-db", "typescript", "firebase", "firebase", "CWE-284", "high", "storage-read"),
        ("auth-rls-db", "python", "fastapi", "express", "CWE-862", "high", "dependency-auth"),
        ("auth-rls-db", "python", "django-rest", "express", "CWE-639", "high", "object-owner"),
        ("auth-rls-db", "python", "flask", "express", "CWE-285", "high", "role-guard"),
        ("auth-rls-db", "java", "spring", "express", "CWE-862", "high", "method-auth"),
        ("auth-rls-db", "kotlin", "ktor", "express", "CWE-639", "high", "resource-owner"),
        ("auth-rls-db", "go", "chi", "express", "CWE-639", "high", "handler-bola"),
        ("auth-rls-db", "go", "gin", "express", "CWE-862", "high", "middleware-auth"),
    ),
    "data": (
        ("auth-rls-db", "typescript", "supabase", "sql-rls", "CWE-284", "critical", "postgres-rls-disabled"),
        ("auth-rls-db", "typescript", "prisma", "sql-rls", "CWE-732", "high", "broad-grant"),
        ("source-flow", "typescript", "prisma", "sql-rls", "CWE-89", "high", "raw-query"),
        ("policy-kpriv", "typescript", "nextjs", "korean-privacy", "CWE-532", "high", "pii-log"),
        ("policy-kpriv", "typescript", "nextjs", "korean-privacy", "CWE-200", "critical", "cross-border-flow"),
        ("policy-kpriv", "python", "django", "korean-privacy", "CWE-200", "high", "data-minimization"),
        ("source-flow", "python", "fastapi", "sql-rls", "CWE-89", "high", "parameterized-query"),
        ("policy-kpriv", "python", "fastapi", "korean-privacy", "CWE-200", "high", "retention-gap"),
        ("source-flow", "java", "spring", "sql-rls", "CWE-89", "high", "jdbc-concat"),
        ("auth-rls-db", "java", "spring", "sql-rls", "CWE-284", "critical", "tenant-policy"),
        ("policy-kpriv", "java", "spring", "korean-privacy", "CWE-311", "high", "backup-plaintext"),
        ("auth-rls-db", "kotlin", "ktor", "sql-rls", "CWE-284", "high", "row-filter"),
        ("policy-kpriv", "kotlin", "ktor", "korean-privacy", "CWE-200", "high", "erasure-gap"),
        ("source-flow", "go", "pgx", "sql-rls", "CWE-89", "high", "query-format"),
        ("policy-kpriv", "go", "gin", "korean-privacy", "CWE-200", "critical", "object-storage-public"),
    ),
    "operations": (
        ("gha-docker-iac", "typescript", "nextjs", "gha-docker-iac", "CWE-250", "critical", "docker-socket"),
        ("gha-docker-iac", "typescript", "nextjs", "gha-docker-iac", "CWE-829", "high", "mutable-action"),
        ("gha-docker-iac", "javascript", "express", "gha-docker-iac", "CWE-269", "high", "workflow-permissions"),
        ("gha-docker-iac", "typescript", "nextjs", "gha-docker-iac", "CWE-250", "high", "container-root"),
        ("dependency-sca", "python", "fastapi", "gha-docker-iac", "CWE-1104", "high", "pypi-vulnerable"),
        ("dependency-sca", "python", "django", "gha-docker-iac", "CWE-1104", "high", "python-lock-drift"),
        ("dependency-sca", "java", "spring", "gha-docker-iac", "CWE-1104", "high", "maven-vulnerable"),
        ("dependency-sca", "java", "spring", "gha-docker-iac", "CWE-1104", "high", "maven-version-range"),
        ("dependency-sca", "java", "spring", "gha-docker-iac", "CWE-1104", "high", "gradle-vulnerable"),
        ("dependency-sca", "java", "spring", "gha-docker-iac", "CWE-1104", "high", "lockfile-mismatch"),
        ("dependency-sca", "kotlin", "ktor", "gha-docker-iac", "CWE-1104", "high", "kotlin-gradle"),
        ("gha-docker-iac", "kotlin", "ktor", "mcp-proxy", "CWE-284", "critical", "mcp-tool-boundary"),
        ("gha-docker-iac", "kotlin", "ktor", "mcp-proxy", "CWE-306", "high", "mcp-auth-missing"),
        ("gha-docker-iac", "kotlin", "ktor", "mcp-proxy", "CWE-798", "critical", "workflow-secret"),
        ("gha-docker-iac", "go", "gin", "gha-docker-iac", "CWE-200", "critical", "artifact-exposure"),
    ),
}


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("ascii")


def _domain_hash(domain: bytes, value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return hashlib.sha256(domain + encoded).hexdigest()


def _language_group(language: str) -> str:
    if language in {"javascript", "typescript"}:
        return "js_ts"
    if language == "python":
        return "python"
    if language in {"java", "kotlin"}:
        return "java_kotlin"
    if language == "go":
        return "go"
    raise ValueError("blueprint_language_invalid")


def build_blueprint() -> dict[str, Any]:
    slots: list[dict[str, Any]] = []
    absolute_index = 0
    profile_ids = tuple(sorted(GENERATOR_PROFILES))
    for plane in PLANES:
        rows = SLOT_ROWS[plane]
        if len(rows) != 15:
            raise ValueError("blueprint_plane_row_count_invalid")
        for index, (family, language, framework, coverage_tag, cwe, severity, suffix) in enumerate(rows, start=1):
            profile_id = profile_ids[absolute_index % len(profile_ids)]
            slot_id = f"{plane}-{index:02d}"
            slots.append(
                {
                    "slot_id": slot_id,
                    "scenario_id": f"dev-{plane}-{index:02d}-{suffix}",
                    "oracle_id": f"l3-gen-{plane}-{index:02d}-{suffix}",
                    "plane": plane,
                    "family": family,
                    "language": language,
                    "framework": framework,
                    "coverage_tags": [coverage_tag],
                    "cwe": cwe,
                    "severity": severity,
                    "generator_profile": profile_id,
                    "scanner_output_absent_at_seal": True,
                }
            )
            absolute_index += 1

    blueprint: dict[str, Any] = {
        "schema": SCHEMA,
        "version": VERSION,
        "candidate_materialization": {
            "primary_candidates_per_slot": 1,
            "pre_registered_reserves_per_slot": 1,
            "unadmitted_slot_policy": "hold",
            "replacement_policy": "same_slot_fixed_reserve_order_only",
        },
        "claim_boundary": {
            "scanner_output_observed": False,
            "source_triplets_materialized": False,
            "execution_oracles_proved": False,
            "eligible_for_tp_fp_fn": False,
            "eligible_for_h100": False,
            "release_gate_passed": False,
            "raw_source_returned": False,
        },
        "generator_profiles": GENERATOR_PROFILES,
        "oracle_contract": ORACLE_CONTRACT,
        "required_evidence_keys": list(REQUIRED_EVIDENCE_KEYS),
        "slot_count": 60,
        "plane_counts": {plane: 15 for plane in PLANES},
        "slots": slots,
    }
    blueprint["blueprint_sha256"] = _domain_hash(b"k_guard_l3_generated_pair_blueprint.v1\0", blueprint)
    return blueprint


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], context: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{context}_keys_invalid")


def _require_id(value: object, context: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise ValueError(f"{context}_invalid")
    return value


def _require_cwe(value: object, context: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"CWE-[1-9][0-9]*", value) is None:
        raise ValueError(f"{context}_invalid")
    return value


def validate_blueprint(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("blueprint_not_object")
    _require_exact_keys(
        value,
        {
            "schema",
            "version",
            "candidate_materialization",
            "claim_boundary",
            "generator_profiles",
            "oracle_contract",
            "required_evidence_keys",
            "slot_count",
            "plane_counts",
            "slots",
            "blueprint_sha256",
        },
        "blueprint",
    )
    if value["schema"] != SCHEMA or value["version"] != VERSION:
        raise ValueError("blueprint_schema_or_version_invalid")
    supplied_hash = value["blueprint_sha256"]
    if not isinstance(supplied_hash, str) or SHA256_RE.fullmatch(supplied_hash) is None:
        raise ValueError("blueprint_hash_invalid")
    unsigned = dict(value)
    unsigned.pop("blueprint_sha256")
    if supplied_hash != _domain_hash(b"k_guard_l3_generated_pair_blueprint.v1\0", unsigned):
        raise ValueError("blueprint_hash_mismatch")

    materialization = value["candidate_materialization"]
    if not isinstance(materialization, Mapping):
        raise ValueError("candidate_materialization_invalid")
    _require_exact_keys(
        materialization,
        {
            "primary_candidates_per_slot",
            "pre_registered_reserves_per_slot",
            "unadmitted_slot_policy",
            "replacement_policy",
        },
        "candidate_materialization",
    )
    if materialization != {
        "primary_candidates_per_slot": 1,
        "pre_registered_reserves_per_slot": 1,
        "unadmitted_slot_policy": "hold",
        "replacement_policy": "same_slot_fixed_reserve_order_only",
    }:
        raise ValueError("candidate_materialization_contract_invalid")

    boundary = value["claim_boundary"]
    expected_boundary = {
        "scanner_output_observed": False,
        "source_triplets_materialized": False,
        "execution_oracles_proved": False,
        "eligible_for_tp_fp_fn": False,
        "eligible_for_h100": False,
        "release_gate_passed": False,
        "raw_source_returned": False,
    }
    if not isinstance(boundary, Mapping) or dict(boundary) != expected_boundary:
        raise ValueError("claim_boundary_invalid")

    profiles = value["generator_profiles"]
    if not isinstance(profiles, Mapping) or dict(profiles) != GENERATOR_PROFILES:
        raise ValueError("generator_profiles_invalid")
    oracle_contract = value["oracle_contract"]
    if not isinstance(oracle_contract, Mapping) or dict(oracle_contract) != ORACLE_CONTRACT:
        raise ValueError("oracle_contract_invalid")
    evidence_keys = value["required_evidence_keys"]
    if not isinstance(evidence_keys, list) or tuple(evidence_keys) != REQUIRED_EVIDENCE_KEYS:
        raise ValueError("required_evidence_keys_invalid")
    if value["slot_count"] != 60 or value["plane_counts"] != {plane: 15 for plane in PLANES}:
        raise ValueError("blueprint_quota_invalid")

    slots = value["slots"]
    if not isinstance(slots, list) or len(slots) != 60:
        raise ValueError("blueprint_slots_invalid")
    ids: set[str] = set()
    scenarios: set[str] = set()
    oracles: set[str] = set()
    plane_counts: Counter[str] = Counter()
    critical_counts: Counter[str] = Counter()
    language_groups: Counter[str] = Counter()
    generator_counts: Counter[str] = Counter()
    coverage_tags: set[str] = set()
    families: set[str] = set()
    expected_slot_ids = {f"{plane}-{index:02d}" for plane in PLANES for index in range(1, 16)}
    for slot in slots:
        if not isinstance(slot, Mapping):
            raise ValueError("blueprint_slot_not_object")
        _require_exact_keys(
            slot,
            {
                "slot_id",
                "scenario_id",
                "oracle_id",
                "plane",
                "family",
                "language",
                "framework",
                "coverage_tags",
                "cwe",
                "severity",
                "generator_profile",
                "scanner_output_absent_at_seal",
            },
            "blueprint_slot",
        )
        slot_id = slot["slot_id"]
        if not isinstance(slot_id, str) or SLOT_ID_RE.fullmatch(slot_id) is None or slot_id in ids:
            raise ValueError("blueprint_slot_id_invalid")
        ids.add(slot_id)
        scenario_id = slot["scenario_id"]
        oracle_id = slot["oracle_id"]
        if not isinstance(scenario_id, str) or SCENARIO_ID_RE.fullmatch(scenario_id) is None or scenario_id in scenarios:
            raise ValueError("blueprint_scenario_id_invalid")
        if not isinstance(oracle_id, str) or ORACLE_ID_RE.fullmatch(oracle_id) is None or oracle_id in oracles:
            raise ValueError("blueprint_oracle_id_invalid")
        scenarios.add(scenario_id)
        oracles.add(oracle_id)
        plane = slot["plane"]
        if plane not in PLANES or not slot_id.startswith(f"{plane}-"):
            raise ValueError("blueprint_plane_invalid")
        family = slot["family"]
        if family not in FAMILIES:
            raise ValueError("blueprint_family_invalid")
        language = slot["language"]
        if language not in LANGUAGES:
            raise ValueError("blueprint_language_invalid")
        _require_id(slot["framework"], "blueprint_framework")
        tags = slot["coverage_tags"]
        if not isinstance(tags, list) or not tags or len(tags) != len(set(tags)) or not set(tags) <= REQUIRED_COVERAGE_TAGS:
            raise ValueError("blueprint_coverage_tags_invalid")
        _require_cwe(slot["cwe"], "blueprint_cwe")
        if slot["severity"] not in SEVERITIES:
            raise ValueError("blueprint_severity_invalid")
        profile_id = slot["generator_profile"]
        if profile_id not in GENERATOR_PROFILES:
            raise ValueError("blueprint_generator_profile_invalid")
        if slot["scanner_output_absent_at_seal"] is not True:
            raise ValueError("blueprint_scanner_output_present")
        plane_counts[str(plane)] += 1
        critical_counts[str(plane)] += int(slot["severity"] == "critical")
        language_groups[_language_group(str(language))] += 1
        generator_counts[str(profile_id)] += 1
        coverage_tags.update(tags)
        families.add(str(family))

    if ids != expected_slot_ids or plane_counts != Counter({plane: 15 for plane in PLANES}):
        raise ValueError("blueprint_plane_quota_drift")
    if critical_counts != Counter({plane: 4 for plane in PLANES}):
        raise ValueError("blueprint_critical_quota_drift")
    if set(language_groups) != {"js_ts", "python", "java_kotlin", "go"}:
        raise ValueError("blueprint_language_group_missing")
    if coverage_tags != REQUIRED_COVERAGE_TAGS:
        raise ValueError("blueprint_coverage_tag_drift")
    if families != FAMILIES:
        raise ValueError("blueprint_family_coverage_drift")
    if set(generator_counts) != set(GENERATOR_PROFILES) or any(count > 24 for count in generator_counts.values()):
        raise ValueError("blueprint_generator_concentration_invalid")
    return dict(value)


def _reject_duplicate_keys(pairs: Iterable[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError("blueprint_duplicate_json_key")
        result[key] = item
    return result


def load_blueprint(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("blueprint_input_path_invalid")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("blueprint_input_json_invalid") from exc
    if canonical_json_bytes(value) != raw:
        raise ValueError("blueprint_input_not_canonical")
    return validate_blueprint(value)


def _is_within_repository(path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(REPOSITORY_ROOT.resolve(strict=True))
        return True
    except ValueError:
        return False


def write_blueprint(output: Path) -> dict[str, Any]:
    if not output.is_absolute() or _is_within_repository(output):
        raise ValueError("blueprint_output_must_be_external")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing_to_overwrite_blueprint")
    blueprint = build_blueprint()
    validate_blueprint(blueprint)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as stream:
            stream.write(canonical_json_bytes(blueprint))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("refusing_to_overwrite_blueprint") from exc
    return blueprint


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build or validate the P2.4A raw-free generated-pair blueprint.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        blueprint = write_blueprint(args.output) if args.command == "build" else load_blueprint(args.input)
    except (OSError, ValueError) as exc:
        print(f"build_l3_generated_pair_blueprint: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"blueprint_sha256": blueprint["blueprint_sha256"], "slot_count": 60, "raw_source_returned": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
