from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
SCHEMA = "k_guard_l2_execution_oracle_aggregate.v1"
SOURCE_REGISTRY_SCHEMA = "k_guard_l2_source_materialization.v3"
EXPECTED_COMPONENT_ROLES = ("positive", "negative", "supervisor")
SHA256_LENGTH = 64


APP_SPECS: dict[str, dict[str, Any]] = {
    "crapi": {
        "source_tree_sha256": "f76c89d35f9b7d34c3b12c6b2f64177e0845957f85fab52613bbc18354925d52",
        "source_receipt_sha256": "d86a9985f9eda5e391112a26a092f7a5273bde393c386ae8968f91399df7429b",
        "components": {
            "positive": {
                "path": "phase2-p23b5-crapi-vehicle-bola-20260723-r5/positive-r1-r2-comparison.json",
                "schema": "k_guard_l2_crapi_vehicle_bola_execution_repeat_comparison.v1",
            },
            "negative": {
                "path": "phase2-p23b5-crapi-vehicle-bola-20260723-r5/negative-r1-r2-comparison.json",
                "schema": "k_guard_l2_crapi_vehicle_bola_negative_control_repeat_comparison.v1",
            },
            "supervisor": {
                "path": "phase2-p23b5-crapi-vehicle-bola-20260723-r5/supervisor-review-r1-r2-comparison.json",
                "schema": "k_guard_supervisor_repeat_comparison.v1",
                "field_id": "p2.3b.5-crapi-vehicle-bola",
            },
        },
    },
    "juice-shop": {
        "source_tree_sha256": "9a109ac9217946774a0c5d356d2a9836c06153d4ae1fe21de92aa71556525fae",
        "source_receipt_sha256": "4ed955ad49e650a12139a21e8fc0491a102fd346e4920ca771668e3cf0f9a93a",
        "components": {
            "positive": {
                "path": "phase2-p23b2-juice-shop-bola-development-20260723-r3-r4-positive-comparison.json",
                "schema": "k_guard_l2_juice_shop_bola_execution_repeat_comparison.v1",
            },
            "negative": {
                "path": "phase2-p23b2-juice-shop-bola-development-20260723-r3-r4-negative-comparison.json",
                "schema": "k_guard_l2_juice_shop_bola_negative_control_repeat_comparison.v1",
            },
            "supervisor": {
                "path": "phase2-p23b2-supervisor-review-20260723-r1-r2-comparison.json",
                "schema": "k_guard_supervisor_repeat_comparison.v1",
                "field_id": "p2.3b2-juice-shop-bola",
            },
        },
    },
    "nodegoat": {
        "source_tree_sha256": "352404981579791fafc18f70649c772a03f304b8895c4f239fbd9863ef5f8a52",
        "source_receipt_sha256": "d3ad5d453bb7d35580f3bf21dfcbab1bbf53555b7144f94da917cd6513ee21ab",
        "components": {
            "positive": {
                "path": "phase2-p23b3-nodegoat-allocations-idor-development-20260723-r7-r8-positive-comparison.json",
                "schema": "k_guard_l2_nodegoat_allocations_idor_execution_repeat_comparison.v1",
            },
            "negative": {
                "path": "phase2-p23b3-nodegoat-allocations-idor-development-20260723-r9-r10-negative-comparison.json",
                "schema": "k_guard_l2_nodegoat_allocations_idor_negative_control_repeat_comparison.v1",
            },
            "supervisor": {
                "path": "phase2-p23b3-supervisor-review-20260723-r1-r2-comparison.json",
                "schema": "k_guard_supervisor_repeat_comparison.v1",
                "field_id": "p2.3b3-nodegoat-allocations-idor",
            },
        },
    },
    "pygoat": {
        "source_tree_sha256": "156486b1531432930bf9df68f2886a20531c28a7aeffe95c9f095286eee3821c",
        "source_receipt_sha256": "0bf2824174f6e979893bda964f87e394c3689db69a3825cab646880156f2fa5c",
        "components": {
            "positive": {
                "path": "phase2-p23b4-pygoat-sensitive-data-development-20260723-r2-r3-positive-comparison.json",
                "schema": "k_guard_l2_pygoat_sensitive_data_execution_repeat_comparison.v1",
            },
            "negative": {
                "path": "phase2-p23b4-pygoat-sensitive-data-development-20260723-r4-r5-negative-comparison.json",
                "schema": "k_guard_l2_pygoat_sensitive_data_negative_control_repeat_comparison.v1",
            },
            "supervisor": {
                "path": "phase2-p23b4-supervisor-review-20260723-r3-r4-comparison.json",
                "schema": "k_guard_supervisor_repeat_comparison.v1",
                "field_id": "p2.3b4-pygoat-sensitive-data",
            },
        },
    },
    "webgoat": {
        "source_tree_sha256": "0b2193e30038f4366715986e939645d7851e647c6188b992311639dd7564da3c",
        "source_receipt_sha256": "7755ce29a5450b9803f46effb6f42fe7624e39b317c99546eb74624a3380b83b",
        "components": {
            "positive": {
                "path": "phase2-p23b1-webgoat-idor-positive-20260723-r5-r6-comparison.json",
                "schema": "k_guard_l2_execution_contract_repeat_comparison.v1",
            },
            "negative": {
                "path": "phase2-p23b1-webgoat-idor-negative-20260723-r5-r6-comparison.json",
                "schema": "k_guard_l2_webgoat_idor_negative_control_repeat_comparison.v2",
            },
            "supervisor": {
                "path": "phase2-p23b1-supervisor-review-20260723-r1-r2-comparison.json",
                "schema": "k_guard_supervisor_repeat_comparison.v1",
                "field_id": "p2.3b1-webgoat-idor-rebind",
            },
        },
    },
    "wrongsecrets": {
        "source_tree_sha256": "9b85876c204c995d056206a292ba45e48731ce2a71124fc5e43f4cdea6eeff80",
        "source_receipt_sha256": "58509e4ad992c66e1b230a66d9f7e18c6c080aea07fb110e07b08d4295455485",
        "components": {
            "positive": {
                "path": "phase2-p23b7-six-app-aggregate-20260723-r1/wrongsecrets-positive-authority-v2.json",
                "schema": "k_guard_l2_wrongsecrets_challenge1_execution_repeat_comparison.v1",
            },
            "negative": {
                "path": "phase2-p23b7-six-app-aggregate-20260723-r1/wrongsecrets-negative-authority-v2.json",
                "schema": "k_guard_l2_wrongsecrets_challenge1_negative_control_repeat_comparison.v1",
            },
            "supervisor": {
                "path": "phase2-p23b6-wrongsecrets-challenge1-javac-20260723-r1/supervisor-review-r1-retry-900-r2-comparison.json",
                "schema": "k_guard_supervisor_repeat_comparison.v1",
                "field_id": "p2.3b.6a-wrongsecrets-challenge1-javac-harness",
            },
        },
    },
}
EXPECTED_APP_IDS = tuple(sorted(APP_SPECS))
FORBIDDEN_RAW_KEYS = frozenset(
    {
        "absolute_path",
        "credential_value",
        "file_contents",
        "raw_source",
        "request_body",
        "response_body",
        "response_headers",
        "scanner_output",
        "secret_value",
        "source_bytes",
        "token_value",
    }
)


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def sha256_bytes(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _sha256_raw(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except ValueError:
        return False


def _require_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or len(value) != SHA256_LENGTH:
        raise ValueError(f"{label}_sha256_invalid")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{label}_sha256_invalid") from exc
    return value.lower()


def _assert_raw_free(value: object, *, label: str) -> None:
    if isinstance(value, Mapping):
        if value.get("raw_returned") not in {None, False}:
            raise ValueError(f"{label}_raw_boundary_invalid")
        if FORBIDDEN_RAW_KEYS.intersection(value):
            raise ValueError(f"{label}_contains_raw_content")
        for nested in value.values():
            _assert_raw_free(nested, label=label)
    elif isinstance(value, list):
        for nested in value:
            _assert_raw_free(nested, label=label)


def _load_canonical(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label}_path_invalid")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError(f"{label}_not_canonical")
    _assert_raw_free(payload, label=label)
    return payload, raw


def _resolve_under_evidence_root(evidence_root: Path, path: Path, *, label: str) -> tuple[Path, str]:
    try:
        root = evidence_root.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label}_path_invalid") from exc
    if path.is_symlink() or not resolved.is_file() or not _is_within(resolved, root):
        raise ValueError(f"{label}_outside_evidence_root")
    return resolved, resolved.relative_to(root).as_posix()


def _validate_authority(value: object, *, label: str) -> None:
    if not isinstance(value, Mapping) or (
        value.get("may_mark_field_fix") is not True
        or value.get("may_affect_oracle_labels") is not False
        or value.get("may_affect_performance_metrics") is not False
        or value.get("may_affect_h100_or_release") is not False
    ):
        raise ValueError(f"{label}_authority_invalid")


def _semantic_pair(payload: Mapping[str, Any], *, label: str) -> str:
    pairs = (
        ("first_semantic_fingerprint_sha256", "second_semantic_fingerprint_sha256"),
        ("first_semantic_sha256", "second_semantic_sha256"),
    )
    for first_name, second_name in pairs:
        first = payload.get(first_name)
        second = payload.get(second_name)
        if first is None and second is None:
            continue
        first_hash = _require_sha256(first, label=f"{label}_{first_name}")
        second_hash = _require_sha256(second, label=f"{label}_{second_name}")
        if first_hash != second_hash:
            raise ValueError(f"{label}_semantic_repeat_mismatch")
        return first_hash
    raise ValueError(f"{label}_semantic_pair_missing")


def _validate_component(
    evidence_root: Path,
    *,
    app_id: str,
    role: str,
    spec: Mapping[str, Any],
) -> dict[str, Any]:
    configured_path = spec.get("path")
    if not isinstance(configured_path, str) or not configured_path:
        raise ValueError(f"{app_id}_{role}_path_invalid")
    candidate = evidence_root / Path(configured_path)
    path, relative_path = _resolve_under_evidence_root(
        evidence_root, candidate, label=f"{app_id}_{role}"
    )
    payload, raw = _load_canonical(path, label=f"{app_id}_{role}")
    if (
        payload.get("schema") != spec.get("schema")
        or payload.get("status") != "FIX"
        or payload.get("repeat_exact") is not True
        or payload.get("raw_returned") is not False
    ):
        raise ValueError(f"{app_id}_{role}_comparison_invalid")
    _validate_authority(payload.get("authority"), label=f"{app_id}_{role}")
    semantic_sha256 = _semantic_pair(payload, label=f"{app_id}_{role}")
    if role == "supervisor":
        if payload.get("field_id") != spec.get("field_id") or payload.get("run_count") != 2:
            raise ValueError(f"{app_id}_supervisor_binding_invalid")
    return {
        "role": role,
        "evidence_path": relative_path,
        "sha256": _sha256_raw(raw),
        "schema": payload["schema"],
        "semantic_fingerprint_sha256": semantic_sha256,
        "status": "FIX",
        "repeat_exact": True,
        "raw_returned": False,
    }


def _validate_source_registry(evidence_root: Path, registry_path: Path) -> dict[str, Any]:
    path, relative_path = _resolve_under_evidence_root(
        evidence_root, registry_path, label="source_registry"
    )
    payload, raw = _load_canonical(path, label="source_registry")
    if (
        payload.get("schema") != SOURCE_REGISTRY_SCHEMA
        or payload.get("expected_app_count") != len(EXPECTED_APP_IDS)
        or payload.get("materialized_app_count") != len(EXPECTED_APP_IDS)
        or payload.get("source_license_admission") != "PASS"
        or payload.get("isolation_contract_declared") != "PASS"
        or payload.get("phase_2_status") != "HOLD"
        or payload.get("release_gate_passed") is not False
        or payload.get("raw_returned") is not False
    ):
        raise ValueError("source_registry_claim_boundary_invalid")
    apps = payload.get("apps")
    if not isinstance(apps, list) or len(apps) != len(EXPECTED_APP_IDS):
        raise ValueError("source_registry_app_set_invalid")
    by_id: dict[str, Mapping[str, Any]] = {}
    for app in apps:
        if not isinstance(app, Mapping) or not isinstance(app.get("app_id"), str):
            raise ValueError("source_registry_app_invalid")
        app_id = app["app_id"]
        if app_id in by_id:
            raise ValueError("source_registry_app_duplicate")
        by_id[app_id] = app
    if tuple(sorted(by_id)) != EXPECTED_APP_IDS:
        raise ValueError("source_registry_app_set_invalid")
    bindings: list[dict[str, Any]] = []
    for app_id in EXPECTED_APP_IDS:
        app = by_id[app_id]
        expected = APP_SPECS[app_id]
        source_tree_sha256 = _require_sha256(
            app.get("source_tree_sha256"), label=f"{app_id}_source_tree"
        )
        source_receipt_sha256 = _require_sha256(
            app.get("receipt_sha256"), label=f"{app_id}_source_receipt"
        )
        if (
            source_tree_sha256 != expected["source_tree_sha256"]
            or source_receipt_sha256 != expected["source_receipt_sha256"]
            or app.get("source_license_admission") != "PASS"
        ):
            raise ValueError(f"{app_id}_source_registry_binding_invalid")
        bindings.append(
            {
                "app_id": app_id,
                "source_tree_sha256": source_tree_sha256,
                "source_receipt_sha256": source_receipt_sha256,
            }
        )
    return {
        "evidence_path": relative_path,
        "sha256": _sha256_raw(raw),
        "schema": SOURCE_REGISTRY_SCHEMA,
        "app_source_bindings": bindings,
        "raw_returned": False,
    }


def build_aggregate(evidence_root: Path, source_registry: Path) -> dict[str, Any]:
    root = evidence_root.resolve(strict=True)
    if not root.is_dir() or _is_within(root, REPOSITORY_ROOT):
        raise ValueError("evidence_root_must_be_external_directory")
    registry = _validate_source_registry(root, source_registry)
    apps: list[dict[str, Any]] = []
    for app_id in EXPECTED_APP_IDS:
        app_spec = APP_SPECS[app_id]
        components = app_spec.get("components")
        if not isinstance(components, Mapping) or set(components) != set(EXPECTED_COMPONENT_ROLES):
            raise ValueError(f"{app_id}_component_spec_invalid")
        component_rows = [
            _validate_component(
                root,
                app_id=app_id,
                role=role,
                spec=components[role],
            )
            for role in EXPECTED_COMPONENT_ROLES
        ]
        apps.append(
            {
                "app_id": app_id,
                "source_binding": {
                    "source_tree_sha256": app_spec["source_tree_sha256"],
                    "source_receipt_sha256": app_spec["source_receipt_sha256"],
                },
                "comparators": component_rows,
                "raw_returned": False,
            }
        )
    materializer_sha256 = _sha256_raw(Path(__file__).resolve(strict=True).read_bytes())
    return {
        "schema": SCHEMA,
        "status": "MEASURED",
        "aggregate_ready": True,
        "source_registry": registry,
        "apps": apps,
        "coverage": {
            "expected_app_ids": list(EXPECTED_APP_IDS),
            "expected_app_count": len(EXPECTED_APP_IDS),
            "included_app_ids": list(EXPECTED_APP_IDS),
            "included_app_count": len(EXPECTED_APP_IDS),
            "excluded_app_ids": [],
            "excluded_app_count": 0,
            "missing_app_ids": [],
            "missing_app_count": 0,
            "component_count_per_app": len(EXPECTED_COMPONENT_ROLES),
            "total_component_count": len(EXPECTED_APP_IDS) * len(EXPECTED_COMPONENT_ROLES),
        },
        "tool_provenance": {
            "materializer_sha256": materializer_sha256,
        },
        "claim_boundary": {
            "historical_component_comparators_revalidated": True,
            "fresh_app_execution_proven": False,
            "detector_accuracy_proven": False,
            "tp_fp_fn_admitted": False,
            "guardian_or_h100_admitted": False,
            "release_gate_admitted": False,
        },
        "release_gate_passed": False,
        "raw_returned": False,
    }


def validate_measurement(payload: Mapping[str, Any]) -> None:
    expected_keys = {
        "aggregate_ready",
        "apps",
        "claim_boundary",
        "coverage",
        "raw_returned",
        "release_gate_passed",
        "schema",
        "source_registry",
        "status",
        "tool_provenance",
    }
    if set(payload) != expected_keys:
        raise ValueError("aggregate_measurement_shape_invalid")
    _assert_raw_free(payload, label="aggregate_measurement")
    if (
        payload.get("schema") != SCHEMA
        or payload.get("status") != "MEASURED"
        or payload.get("aggregate_ready") is not True
        or payload.get("release_gate_passed") is not False
        or payload.get("raw_returned") is not False
    ):
        raise ValueError("aggregate_measurement_claim_boundary_invalid")
    coverage = payload.get("coverage")
    if not isinstance(coverage, Mapping) or coverage != {
        "expected_app_ids": list(EXPECTED_APP_IDS),
        "expected_app_count": len(EXPECTED_APP_IDS),
        "included_app_ids": list(EXPECTED_APP_IDS),
        "included_app_count": len(EXPECTED_APP_IDS),
        "excluded_app_ids": [],
        "excluded_app_count": 0,
        "missing_app_ids": [],
        "missing_app_count": 0,
        "component_count_per_app": len(EXPECTED_COMPONENT_ROLES),
        "total_component_count": len(EXPECTED_APP_IDS) * len(EXPECTED_COMPONENT_ROLES),
    }:
        raise ValueError("aggregate_coverage_invalid")
    source_registry = payload.get("source_registry")
    if not isinstance(source_registry, Mapping) or source_registry.get("schema") != SOURCE_REGISTRY_SCHEMA:
        raise ValueError("aggregate_source_registry_invalid")
    _require_sha256(source_registry.get("sha256"), label="aggregate_source_registry")
    bindings = source_registry.get("app_source_bindings")
    if not isinstance(bindings, list) or [item.get("app_id") for item in bindings if isinstance(item, Mapping)] != list(EXPECTED_APP_IDS):
        raise ValueError("aggregate_source_bindings_invalid")
    apps = payload.get("apps")
    if not isinstance(apps, list) or [item.get("app_id") for item in apps if isinstance(item, Mapping)] != list(EXPECTED_APP_IDS):
        raise ValueError("aggregate_app_set_invalid")
    for app in apps:
        if not isinstance(app, Mapping):
            raise ValueError("aggregate_app_invalid")
        app_id = app.get("app_id")
        if app_id not in APP_SPECS or app.get("raw_returned") is not False:
            raise ValueError("aggregate_app_invalid")
        source_binding = app.get("source_binding")
        if source_binding != {
            "source_tree_sha256": APP_SPECS[app_id]["source_tree_sha256"],
            "source_receipt_sha256": APP_SPECS[app_id]["source_receipt_sha256"],
        }:
            raise ValueError("aggregate_app_source_binding_invalid")
        components = app.get("comparators")
        if not isinstance(components, list) or [item.get("role") for item in components if isinstance(item, Mapping)] != list(EXPECTED_COMPONENT_ROLES):
            raise ValueError("aggregate_component_set_invalid")
        for component in components:
            if not isinstance(component, Mapping):
                raise ValueError("aggregate_component_invalid")
            if (
                component.get("status") != "FIX"
                or component.get("repeat_exact") is not True
                or component.get("raw_returned") is not False
            ):
                raise ValueError("aggregate_component_invalid")
            _require_sha256(component.get("sha256"), label="aggregate_component")
            _require_sha256(
                component.get("semantic_fingerprint_sha256"), label="aggregate_component_semantic"
            )
    tool_provenance = payload.get("tool_provenance")
    if not isinstance(tool_provenance, Mapping):
        raise ValueError("aggregate_tool_provenance_invalid")
    _require_sha256(tool_provenance.get("materializer_sha256"), label="aggregate_materializer")
    if payload.get("claim_boundary") != {
        "historical_component_comparators_revalidated": True,
        "fresh_app_execution_proven": False,
        "detector_accuracy_proven": False,
        "tp_fp_fn_admitted": False,
        "guardian_or_h100_admitted": False,
        "release_gate_admitted": False,
    }:
        raise ValueError("aggregate_claim_boundary_invalid")


def write_measurement(output: Path, payload: Mapping[str, Any]) -> None:
    if not output.is_absolute() or _is_within(output, REPOSITORY_ROOT):
        raise ValueError("aggregate_output_must_be_external")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing_to_overwrite_aggregate_output")
    validate_measurement(payload)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(payload)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("refusing_to_overwrite_aggregate_output") from exc


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Materialize a raw-free six-app historical execution-oracle aggregate."
    )
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--source-registry", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    aggregate = build_aggregate(args.evidence_root, args.source_registry)
    write_measurement(args.output, aggregate)
    print(
        json.dumps(
            {
                "status": aggregate["status"],
                "included_app_count": aggregate["coverage"]["included_app_count"],
                "release_gate_passed": False,
                "raw_returned": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
