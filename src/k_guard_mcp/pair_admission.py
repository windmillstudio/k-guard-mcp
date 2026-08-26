from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from datetime import date
from hashlib import sha256
from typing import Any


PAIR_ADMISSION_SCHEMA = "k_guard_generated_pair_admission.v1"
PAIR_ADMISSION_RESULT_SCHEMA = "k_guard_generated_pair_admission_result.v2"
KPRIV_SCHEMA = "KPRIV-v1"
PAIR_VERIFICATION_SCHEMA = "k_guard_pair_evidence_verification.v2"
PLANES = frozenset({"site", "api", "data", "operations"})

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SPDX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*(?:\s+(?:AND|OR)\s+[A-Za-z0-9][A-Za-z0-9.+-]*)*$")
_IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DIGEST_REF_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")

KPRIV_REQUIRED_FIELDS = (
    "collection_minimization",
    "purpose_consent_or_legal_basis",
    "sensitive_or_unique_identifiers",
    "retention_and_deletion",
    "third_party_sharing",
    "cross_border_transfer",
    "access_control",
    "access_logs",
    "encryption",
    "backup",
    "log_analytics_exposure",
    "data_subject_request",
    "ai_input_training_opt_out",
)

_KPRIV_OBSERVABLE_TYPES = {
    "code_flow",
    "config_key",
    "database_policy",
    "policy_field",
    "retention_job",
    "deletion_job",
    "schema_field",
    "test_assertion",
}

_COMMON_INVARIANTS = (
    "route_inventory_unchanged",
    "public_api_shape_unchanged",
    "schema_unchanged",
    "unrelated_dependencies_unchanged",
    "feature_flags_unchanged",
    "logging_unchanged",
    "build_options_unchanged",
    "build_passed",
    "functional_snapshot_equal",
)

FAMILY_POLICIES: dict[str, dict[str, Any]] = {
    "source_flow": {
        "max_files": 2,
        "max_lines": 25,
        "allowed_roles": {"production"},
        "allowed_kinds": {"argument", "call", "comparison", "guard", "sanitizer"},
        "selector_prefixes": ("ast.call.", "ast.guard.", "ast.sanitizer.", "ast.source_sink."),
    },
    "auth_rls_db": {
        "max_files": 2,
        "max_lines": 40,
        "allowed_roles": {"production", "policy", "migration"},
        "allowed_kinds": {
            "authorization_guard",
            "ddl_policy_statement",
            "middleware_call",
            "policy_predicate",
            "query_filter",
            "role_check",
        },
        "selector_prefixes": ("ast.auth.", "ast.middleware.", "config.auth.", "ddl.policy.", "ddl.rls."),
    },
    "dependency_sca": {
        "max_files": 2,
        "max_lines": 400,
        "allowed_roles": {"manifest", "lockfile"},
        "allowed_kinds": {"lockfile_dependency_hunk", "manifest_entry"},
        "selector_prefixes": ("dependency.manifest.", "dependency.lockfile."),
    },
    "gha_docker_iac": {
        "max_files": 1,
        "max_lines": 40,
        "allowed_roles": {"infrastructure", "workflow"},
        "allowed_kinds": {"resource_stanza", "workflow_step"},
        "selector_prefixes": ("config.docker.", "config.iac.", "config.workflow."),
    },
    "policy_kpriv": {
        "max_files": 2,
        "max_lines": 40,
        "allowed_roles": {"config", "policy"},
        "allowed_kinds": {"config_key", "policy_field"},
        "selector_prefixes": tuple(f"kpriv.{field}." for field in KPRIV_REQUIRED_FIELDS),
    },
}


def validate_pair_admission(
    manifest: object, *, expected_verifier_sha256: str
) -> dict[str, Any]:
    """Validate a pair manifest schema without proving a live pair replay."""

    errors: list[str] = []
    if not isinstance(manifest, Mapping):
        return _result("", ["manifest:not_object"])

    schema = manifest.get("schema")
    if schema != PAIR_ADMISSION_SCHEMA:
        errors.append("manifest:schema_invalid")
    family = manifest.get("family")
    if not isinstance(family, str) or family not in FAMILY_POLICIES:
        errors.append("manifest:family_invalid")
        family = ""

    _require_nonempty_text(manifest, "lineage_id", errors, "manifest")
    if manifest.get("label_locked_before_scanner_output") is not True:
        errors.append("manifest:label_not_prelocked")

    _validate_provenance(manifest.get("provenance"), errors)
    _validate_hashes(manifest.get("hashes"), errors)
    _validate_executions(manifest.get("executions"), manifest.get("hashes"), errors)
    if family:
        _validate_diff(manifest.get("diff"), family, errors)
    _validate_invariants(manifest.get("invariants"), errors)
    _validate_test_oracle_files(manifest.get("test_oracle_files"), errors)
    _validate_evidence_verification(manifest, expected_verifier_sha256, errors)

    kpriv = manifest.get("kpriv")
    if family == "policy_kpriv" or kpriv is not None:
        kpriv_result = validate_kpriv_manifest(kpriv)
        errors.extend(f"kpriv:{error}" for error in kpriv_result["errors"])

    return _result(family, errors)


def validate_kpriv_manifest(manifest: object) -> dict[str, Any]:
    """Validate the machine-observable KPRIV-v1 risk-signal contract."""

    errors: list[str] = []
    if not isinstance(manifest, Mapping):
        return _kpriv_result(["manifest:not_object"])
    if manifest.get("schema") != KPRIV_SCHEMA:
        errors.append("manifest:schema_invalid")
    if manifest.get("legal_inconclusive") is not False:
        errors.append("manifest:legal_inconclusive")

    boundary = manifest.get("claim_boundary")
    if not isinstance(boundary, Mapping):
        errors.append("claim_boundary:not_object")
    else:
        expected = {
            "risk_signals_only": True,
            "legal_compliance_proved": False,
            "legal_advice": False,
        }
        for key, value in expected.items():
            if boundary.get(key) is not value:
                errors.append(f"claim_boundary:{key}_invalid")

    sources = manifest.get("legal_sources")
    if not _is_nonempty_sequence(sources):
        errors.append("legal_sources:missing")
    else:
        for index, source in enumerate(sources):
            prefix = f"legal_sources[{index}]"
            if not isinstance(source, Mapping):
                errors.append(f"{prefix}:not_object")
                continue
            _require_nonempty_text(source, "authority", errors, prefix)
            _require_iso_date(source.get("effective_date"), errors, f"{prefix}:effective_date_invalid")
            _require_sha256(source.get("content_sha256"), errors, f"{prefix}:content_sha256_invalid")
            _require_sha256(source.get("source_url_sha256"), errors, f"{prefix}:source_url_sha256_invalid")

    required = manifest.get("required_fields")
    if not isinstance(required, Mapping):
        errors.append("required_fields:not_object")
    else:
        observed = set(required)
        expected = set(KPRIV_REQUIRED_FIELDS)
        for field in sorted(expected - observed):
            errors.append(f"required_fields:{field}:missing")
        for field in sorted(observed - expected):
            errors.append(f"required_fields:{field}:unknown")
        for field in KPRIV_REQUIRED_FIELDS:
            if field in required:
                _validate_kpriv_field(field, required[field], errors)

    contradictions = manifest.get("forbidden_contradictions")
    if not isinstance(contradictions, list) or contradictions:
        errors.append("forbidden_contradictions:not_empty_list")
    if manifest.get("source_to_policy_consistent") is not True:
        errors.append("source_to_policy_consistent:not_true")
    for name in ("retention_evidence", "deletion_evidence", "config_evidence"):
        _validate_observable_evidence_list(manifest.get(name), errors, name)

    return _kpriv_result(errors)


def canonical_admission_result(result: Mapping[str, Any]) -> str:
    return json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def pair_subject_sha256(manifest: Mapping[str, Any]) -> str:
    """Hash the verifier subject while excluding its non-recursive receipt."""

    subject = dict(manifest)
    subject.pop("verification", None)
    try:
        encoded = json.dumps(
            subject,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("pair manifest is not canonical-JSON serializable") from exc
    return sha256(b"k_guard_pair_evidence_subject.v1\0" + encoded).hexdigest()


def _validate_provenance(value: object, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append("provenance:not_object")
        return
    for key in ("model", "version", "framework", "language", "plane", "cwe"):
        _require_nonempty_text(value, key, errors, "provenance")
    if value.get("plane") not in PLANES:
        errors.append("provenance:plane_invalid")
    cwe = value.get("cwe")
    if not isinstance(cwe, str) or re.fullmatch(r"CWE-[1-9][0-9]*", cwe) is None:
        errors.append("provenance:cwe_invalid")
    for key in ("prompt_sha256", "dependency_sha256"):
        _require_sha256(value.get(key), errors, f"provenance:{key}_invalid")
    if not isinstance(value.get("generator_commit"), str) or not _COMMIT_RE.fullmatch(value["generator_commit"]):
        errors.append("provenance:generator_commit_invalid")
    if not _is_int(value.get("seed")) or value["seed"] < 0:
        errors.append("provenance:seed_invalid")
    sampling = value.get("sampling")
    if not isinstance(sampling, Mapping):
        errors.append("provenance:sampling_not_object")
    else:
        temperature = sampling.get("temperature")
        if isinstance(temperature, bool) or not isinstance(temperature, (int, float)) or not 0 <= temperature <= 2:
            errors.append("provenance:sampling_temperature_invalid")
        _require_nonempty_text(sampling, "strategy", errors, "provenance:sampling")
    license_spdx = value.get("license_spdx")
    if not isinstance(license_spdx, str) or not _SPDX_RE.fullmatch(license_spdx):
        errors.append("provenance:license_spdx_invalid")
    source = value.get("source")
    if not isinstance(source, Mapping):
        errors.append("provenance:source_not_object")
    else:
        if source.get("kind") != "generated":
            errors.append("provenance:source_kind_invalid")
        _require_sha256(source.get("identity_sha256"), errors, "provenance:source_identity_sha256_invalid")


def _validate_evidence_verification(
    manifest: Mapping[str, Any],
    expected_verifier_sha256: str,
    errors: list[str],
) -> None:
    value = manifest.get("verification")
    if not isinstance(value, Mapping):
        errors.append("verification:not_object")
        return
    expected_fields = {
        "schema",
        "verified",
        "verifier_id",
        "verifier_version",
        "verifier_sha256",
        "runtime_image_reference",
        "runtime_image_id",
        "plan_sha256",
        "evidence_bundle_sha256",
        "subject_sha256",
        "source_receipts_sha256",
        "execution_receipts_sha256",
        "diff_receipt_sha256",
        "invariants_receipt_sha256",
        "files_rehashed",
        "commands_executed",
        "diff_recomputed",
        "invariants_recomputed",
        "isolated_execution",
        "network_disabled",
        "snapshot_replayed",
        "raw_sensitive_output_returned",
    }
    if set(value) != expected_fields:
        errors.append("verification:fields_invalid")
    if value.get("schema") != PAIR_VERIFICATION_SCHEMA:
        errors.append("verification:schema_invalid")
    if value.get("verified") is not True:
        errors.append("verification:not_verified")
    for field in ("verifier_id", "verifier_version"):
        _require_nonempty_text(value, field, errors, "verification")
    for field in (
        "verifier_sha256",
        "plan_sha256",
        "evidence_bundle_sha256",
        "subject_sha256",
        "source_receipts_sha256",
        "execution_receipts_sha256",
        "diff_receipt_sha256",
        "invariants_receipt_sha256",
    ):
        _require_sha256(value.get(field), errors, f"verification:{field}_invalid")
    image_reference = value.get("runtime_image_reference")
    if not isinstance(image_reference, str) or _DIGEST_REF_RE.fullmatch(image_reference) is None:
        errors.append("verification:runtime_image_reference_invalid")
    image_id = value.get("runtime_image_id")
    if not isinstance(image_id, str) or _IMAGE_ID_RE.fullmatch(image_id) is None:
        errors.append("verification:runtime_image_id_invalid")
    if not _is_sha256(expected_verifier_sha256):
        errors.append("verification:expected_verifier_sha256_invalid")
    elif value.get("verifier_sha256") != expected_verifier_sha256:
        errors.append("verification:verifier_not_preregistered")
    for field in (
        "files_rehashed",
        "commands_executed",
        "diff_recomputed",
        "invariants_recomputed",
        "isolated_execution",
        "network_disabled",
        "snapshot_replayed",
    ):
        if value.get(field) is not True:
            errors.append(f"verification:{field}_not_true")
    if value.get("raw_sensitive_output_returned") is not False:
        errors.append("verification:raw_sensitive_output_returned_not_false")
    try:
        expected_subject = pair_subject_sha256(manifest)
    except ValueError:
        errors.append("verification:subject_not_canonical_json")
    else:
        if value.get("subject_sha256") != expected_subject:
            errors.append("verification:subject_hash_mismatch")


def _validate_hashes(value: object, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append("hashes:not_object")
        return
    required = (
        "vulnerable_source_sha256",
        "fixed_source_sha256",
        "exploit_command_sha256",
        "regression_command_sha256",
        "negative_control_command_sha256",
        "diff_command_sha256",
        "invariants_command_sha256",
    )
    for key in required:
        _require_sha256(value.get(key), errors, f"hashes:{key}_invalid")
    vulnerable = value.get("vulnerable_source_sha256")
    fixed = value.get("fixed_source_sha256")
    if _is_sha256(vulnerable) and vulnerable == fixed:
        errors.append("hashes:source_pair_identical")


def _validate_executions(value: object, hashes: object, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append("executions:not_object")
        return
    hash_map = hashes if isinstance(hashes, Mapping) else {}
    contracts = {
        "exploit_vulnerable": ("exploit_command_sha256", "exploit_succeeded", True),
        "exploit_fixed": ("exploit_command_sha256", "exploit_succeeded", False),
        "fixed_functional": ("regression_command_sha256", "functional_passed", True),
        "negative_control": ("negative_control_command_sha256", "control_triggered", False),
    }
    for name, (command_key, outcome_key, outcome) in contracts.items():
        receipt = value.get(name)
        prefix = f"executions:{name}"
        if not isinstance(receipt, Mapping):
            errors.append(f"{prefix}:not_object")
            continue
        if receipt.get("executed") is not True:
            errors.append(f"{prefix}:not_executed")
        if receipt.get("harness_passed") is not True:
            errors.append(f"{prefix}:harness_failed")
        if not _is_int(receipt.get("exit_code")) or receipt["exit_code"] != 0:
            errors.append(f"{prefix}:exit_code_invalid")
        if receipt.get(outcome_key) is not outcome:
            errors.append(f"{prefix}:{outcome_key}_invalid")
        _require_sha256(receipt.get("result_sha256"), errors, f"{prefix}:result_sha256_invalid")
        command_sha256 = receipt.get("command_sha256")
        _require_sha256(command_sha256, errors, f"{prefix}:command_sha256_invalid")
        if _is_sha256(command_sha256) and command_sha256 != hash_map.get(command_key):
            errors.append(f"{prefix}:command_hash_mismatch")


def _validate_diff(value: object, family: str, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append("diff:not_object")
        return
    changes = value.get("production_changes")
    if not _is_nonempty_sequence(changes):
        errors.append("diff:production_changes_missing")
        return
    policy = FAMILY_POLICIES[family]
    paths: set[str] = set()
    total_lines = 0
    kinds: list[str] = []
    for index, change in enumerate(changes):
        prefix = f"diff:production_changes[{index}]"
        if not isinstance(change, Mapping):
            errors.append(f"{prefix}:not_object")
            continue
        path = change.get("path")
        if not _is_safe_relative_path(path):
            errors.append(f"{prefix}:path_invalid")
        elif path in paths:
            errors.append(f"{prefix}:duplicate_path")
        else:
            paths.add(path)
        lines = change.get("logical_changed_lines")
        if not _is_int(lines) or lines <= 0:
            errors.append(f"{prefix}:logical_changed_lines_invalid")
        else:
            total_lines += lines
        role = change.get("role")
        if role not in policy["allowed_roles"]:
            errors.append(f"{prefix}:role_not_allowed")
        kind = change.get("change_kind")
        if kind not in policy["allowed_kinds"]:
            errors.append(f"{prefix}:change_kind_not_allowed")
        elif isinstance(kind, str):
            kinds.append(kind)
        selector = change.get("selector")
        if not isinstance(selector, str) or not any(selector.startswith(item) and len(selector) > len(item) for item in policy["selector_prefixes"]):
            errors.append(f"{prefix}:selector_not_allowlisted")
        _require_nonempty_text(change, "root_cause_ref", errors, prefix)
        _require_sha256(change.get("before_sha256"), errors, f"{prefix}:before_sha256_invalid")
        _require_sha256(change.get("after_sha256"), errors, f"{prefix}:after_sha256_invalid")
        if _is_sha256(change.get("before_sha256")) and change.get("before_sha256") == change.get("after_sha256"):
            errors.append(f"{prefix}:content_unchanged")

    if len(paths) > policy["max_files"]:
        errors.append(f"diff:file_limit_exceeded:{len(paths)}>{policy['max_files']}")
    if total_lines > policy["max_lines"]:
        errors.append(f"diff:line_limit_exceeded:{total_lines}>{policy['max_lines']}")
    _validate_family_shape(family, changes, kinds, errors)


def _validate_family_shape(family: str, changes: Sequence[object], kinds: list[str], errors: list[str]) -> None:
    if family == "dependency_sca":
        if kinds.count("manifest_entry") != 1:
            errors.append("diff:dependency_manifest_entry_count_invalid")
        if kinds.count("lockfile_dependency_hunk") > 1:
            errors.append("diff:dependency_lockfile_hunk_count_invalid")
        for index, change in enumerate(changes):
            if isinstance(change, Mapping) and change.get("change_kind") == "lockfile_dependency_hunk" and change.get("deterministically_generated") is not True:
                errors.append(f"diff:production_changes[{index}]:lockfile_not_deterministic")
    elif family == "gha_docker_iac":
        if len(changes) != 1 or len(kinds) != 1:
            errors.append("diff:infrastructure_root_change_count_invalid")
        elif not _is_nonempty_string_list(changes[0].get("connected_config_keys") if isinstance(changes[0], Mapping) else None):
            errors.append("diff:production_changes[0]:connected_config_keys_missing")
    elif family == "policy_kpriv":
        for index, change in enumerate(changes):
            if not isinstance(change, Mapping) or change.get("kpriv_field") not in KPRIV_REQUIRED_FIELDS:
                errors.append(f"diff:production_changes[{index}]:kpriv_field_invalid")
            elif not str(change.get("selector", "")).startswith(f"kpriv.{change['kpriv_field']}."):
                errors.append(f"diff:production_changes[{index}]:kpriv_selector_mismatch")


def _validate_invariants(value: object, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append("invariants:not_object")
        return
    for name in _COMMON_INVARIANTS:
        if value.get(name) is not True:
            errors.append(f"invariants:{name}_not_true")


def _validate_test_oracle_files(value: object, errors: list[str]) -> None:
    if not _is_nonempty_sequence(value):
        errors.append("test_oracle_files:missing")
        return
    paths: set[str] = set()
    roles: set[str] = set()
    for index, row in enumerate(value):
        prefix = f"test_oracle_files[{index}]"
        if not isinstance(row, Mapping):
            errors.append(f"{prefix}:not_object")
            continue
        path = row.get("path")
        if not _is_safe_relative_path(path):
            errors.append(f"{prefix}:path_invalid")
        elif path in paths:
            errors.append(f"{prefix}:duplicate_path")
        else:
            paths.add(path)
        _require_sha256(row.get("content_sha256"), errors, f"{prefix}:content_sha256_invalid")
        if row.get("role") not in {"exploit", "negative_control", "oracle", "regression"}:
            errors.append(f"{prefix}:role_invalid")
        else:
            roles.add(str(row["role"]))
    for role in ("exploit", "negative_control", "oracle", "regression"):
        if role not in roles:
            errors.append(f"test_oracle_files:{role}_missing")


def _validate_kpriv_field(field: str, value: object, errors: list[str]) -> None:
    prefix = f"required_fields:{field}"
    if not isinstance(value, Mapping):
        errors.append(f"{prefix}:not_object")
        return
    if value.get("outcome") != "pass":
        errors.append(f"{prefix}:outcome_not_pass")
    _validate_observable_evidence_list(value.get("evidence"), errors, f"{prefix}:evidence")


def _validate_observable_evidence_list(value: object, errors: list[str], prefix: str) -> None:
    if not _is_nonempty_sequence(value):
        errors.append(f"{prefix}:missing")
        return
    for index, evidence in enumerate(value):
        item_prefix = f"{prefix}[{index}]"
        if not isinstance(evidence, Mapping):
            errors.append(f"{item_prefix}:not_object")
            continue
        if evidence.get("observable_type") not in _KPRIV_OBSERVABLE_TYPES:
            errors.append(f"{item_prefix}:observable_type_invalid")
        if not _is_safe_relative_path(evidence.get("path")):
            errors.append(f"{item_prefix}:path_invalid")
        _require_nonempty_text(evidence, "selector", errors, item_prefix)
        _require_sha256(evidence.get("content_sha256"), errors, f"{item_prefix}:content_sha256_invalid")


def _result(family: str, errors: list[str]) -> dict[str, Any]:
    normalized = sorted(set(errors))
    schema_valid = not normalized
    return {
        "schema": PAIR_ADMISSION_RESULT_SCHEMA,
        "schema_valid": schema_valid,
        "live_replay_proved": False,
        "status": "schema_valid_pending_live_replay" if schema_valid else "rejected_fail_closed",
        "family": family,
        "error_count": len(normalized),
        "errors": normalized,
        "claim_boundary": {
            "schema_contract_only": True,
            "live_replay_proved": False,
            "machine_oracle_only": True,
            "human_review_proved": False,
            "legal_compliance_proved": False,
        },
    }


def _kpriv_result(errors: list[str]) -> dict[str, Any]:
    normalized = sorted(set(errors))
    return {
        "schema": "KPRIV-v1.validation",
        "passed": not normalized,
        "status": "pass" if not normalized else "inconclusive_fail_closed",
        "error_count": len(normalized),
        "errors": normalized,
    }


def _require_nonempty_text(value: Mapping[str, Any], key: str, errors: list[str], prefix: str) -> None:
    candidate = value.get(key)
    try:
        valid = (
            isinstance(candidate, str)
            and bool(candidate.strip())
            and len(candidate.encode("utf-8")) <= 4096
        )
    except UnicodeEncodeError:
        valid = False
    if not valid:
        errors.append(f"{prefix}:{key}_invalid")


def _require_sha256(value: object, errors: list[str], code: str) -> None:
    if not _is_sha256(value):
        errors.append(code)


def _require_iso_date(value: object, errors: list[str], code: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        errors.append(code)
        return
    try:
        date.fromisoformat(value)
    except ValueError:
        errors.append(code)


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_nonempty_sequence(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)) and len(value) > 0


def _is_nonempty_string_list(value: object) -> bool:
    return _is_nonempty_sequence(value) and all(isinstance(item, str) and bool(item.strip()) for item in value)


def _is_safe_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        return False
    try:
        if len(value.encode("utf-8")) > 4096:
            return False
    except UnicodeEncodeError:
        return False
    if any(ord(character) < 32 for character in value):
        return False
    parts = value.split("/")
    return all(part not in {"", ".", ".."} and ":" not in part for part in parts)
