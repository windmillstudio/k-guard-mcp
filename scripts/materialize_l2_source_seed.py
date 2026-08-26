from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
MATERIALIZER_PATH = REPOSITORY_ROOT / "scripts" / "materialize_l2_sources.py"
SEED_BUILD_SCHEMA = "k_guard_l2_source_seed_build.v1"
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except ValueError:
        return False


def _load_materializer_with_hash() -> tuple[Any, str]:
    raw_before = MATERIALIZER_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location(
        "k_guard_l2_source_seed_materializer", MATERIALIZER_PATH
    )
    if spec is None or spec.loader is None:
        raise ValueError("l2_source_materializer_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if MATERIALIZER_PATH.read_bytes() != raw_before:
        raise ValueError("l2_source_materializer_changed_while_loading")
    return module, sha256_bytes(raw_before)


def _safe_name(value: str, *, label: str, suffix: str | None = None) -> str:
    if (
        not isinstance(value, str)
        or NAME_RE.fullmatch(value) is None
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or (suffix is not None and not value.endswith(suffix))
    ):
        raise ValueError(f"{label}_invalid")
    return value


def _source_root(path: Path) -> Path:
    root = path.resolve(strict=True)
    if not root.is_dir() or root.is_symlink() or _is_within(root, REPOSITORY_ROOT):
        raise ValueError("source_root_must_be_an_external_regular_directory")
    return root


def _external_summary(path: Path, source_root: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("summary_must_be_absolute_external_path")
    resolved = path.resolve(strict=False)
    if _is_within(resolved, REPOSITORY_ROOT) or _is_within(resolved, source_root):
        raise ValueError("summary_must_be_outside_repository_and_source_root")
    if resolved.exists() or resolved.is_symlink():
        raise FileExistsError("refusing_to_overwrite_source_seed_summary")
    return resolved


def _license_binding(
    checkout: Path, identity: Mapping[str, Any], materializer: Any
) -> dict[str, Any]:
    locked = identity["license"]
    if not isinstance(locked, Mapping):
        raise ValueError("locked_license_binding_invalid")
    path = locked["path"]
    if not isinstance(path, str):
        raise ValueError("locked_license_path_invalid")
    license_path = checkout / path
    if (
        license_path.parent != checkout
        or license_path.is_symlink()
        or not license_path.is_file()
    ):
        raise ValueError("locked_root_license_missing")
    raw = license_path.read_bytes()
    expected = {
        "path": path,
        "spdx": locked["spdx"],
        "sha256": locked["sha256"],
        "byte_count": locked["byte_count"],
    }
    observed = {
        "path": path,
        "spdx": locked["spdx"],
        "sha256": materializer.sha256_bytes(raw),
        "byte_count": len(raw),
    }
    if observed != expected:
        raise ValueError("locked_root_license_content_mismatch")
    return expected


def _verify_identity(
    app_id: str,
    checkout: Path,
    identity: Mapping[str, Any],
    materializer: Any,
    verifier: Any,
) -> tuple[dict[str, Any], dict[str, Any], bytes, str, str]:
    if checkout.is_symlink() or not checkout.is_dir():
        raise ValueError("source_checkout_missing_or_linked")
    receipt = verifier.build_git_materialization_receipt(
        checkout,
        expected_repository_id=identity["repository_id"],
        expected_commit=identity["commit"],
        expected_tree=identity["commit_tree"],
    )
    receipt_raw = materializer.canonical_json_bytes(receipt)
    observed_receipt_sha256 = materializer.sha256_bytes(receipt_raw)
    observed_semantic_sha256 = materializer._source_receipt_semantic_sha256(receipt)
    locked_semantic_sha256 = identity.get("receipt_semantic_sha256")
    if not isinstance(locked_semantic_sha256, str):
        raise ValueError("immutable_source_receipt_semantic_identity_missing")
    if observed_receipt_sha256 == identity["receipt_sha256"]:
        receipt_equivalence = "exact_raw_receipt"
    elif observed_semantic_sha256 == locked_semantic_sha256:
        receipt_equivalence = "informational_porcelain_variance"
    else:
        raise ValueError("source_receipt_hash_differs_from_immutable_identity")
    required_identity = {
        "repository_id": identity["repository_id"],
        "commit": identity["commit"],
        "commit_tree": identity["commit_tree"],
        "source_tree_sha256": identity["source_tree_sha256"],
    }
    observed_identity = {
        field: receipt.get(field) for field in required_identity
    }
    if observed_identity != required_identity:
        raise ValueError("source_identity_differs_from_immutable_identity")
    license_binding = _license_binding(checkout, identity, materializer)
    return (
        receipt,
        license_binding,
        receipt_raw,
        observed_semantic_sha256,
        receipt_equivalence,
    )


def build_seed_bundle(
    source_root: Path,
    *,
    seed_name: str,
    receipts_dir_name: str,
) -> dict[str, Any]:
    builder_path = Path(__file__).resolve(strict=True)
    builder_raw = builder_path.read_bytes()
    root = _source_root(source_root)
    seed_name = _safe_name(seed_name, label="seed_name", suffix=".json")
    receipts_dir_name = _safe_name(receipts_dir_name, label="receipts_dir_name")
    materializer, materializer_sha256 = _load_materializer_with_hash()
    verifier, verifier_sha256 = materializer._load_source_materialization_with_hash()
    expected_apps = frozenset(materializer.EXPECTED_APPS)
    identities = materializer.EXPECTED_IDENTITIES
    if len(expected_apps) != 6 or set(identities) != expected_apps:
        raise ValueError("immutable_six_app_identity_registry_invalid")

    seed_apps: list[dict[str, Any]] = []
    summary_apps: list[dict[str, Any]] = []
    receipts: dict[str, dict[str, Any]] = {}
    for app_id in sorted(expected_apps):
        identity = identities[app_id]
        checkout = root / app_id
        (
            receipt,
            license_binding,
            receipt_raw,
            receipt_semantic_sha256,
            receipt_equivalence,
        ) = _verify_identity(
            app_id, checkout, identity, materializer, verifier
        )
        receipt_relative = f"{receipts_dir_name}/{app_id}.json"
        receipt_sha256 = materializer.sha256_bytes(receipt_raw)
        seed_apps.append(
            {
                "app_id": app_id,
                "repository_id": identity["repository_id"],
                "commit": identity["commit"],
                "commit_tree": identity["commit_tree"],
                "source_tree_sha256": identity["source_tree_sha256"],
                "lineage_id": materializer.compute_lineage_id(
                    app_id,
                    identity["repository_id"],
                    identity["commit"],
                    identity["commit_tree"],
                    identity["source_tree_sha256"],
                ),
                "checkout_root": app_id,
                "receipt_path": receipt_relative,
                "receipt_sha256": receipt_sha256,
                "receipt_semantic_sha256": receipt_semantic_sha256,
                "receipt_equivalence": receipt_equivalence,
                "license": license_binding,
                "isolation": {
                    field: True for field in materializer.ISOLATION_FIELDS
                },
                "machine_oracles": [],
            }
        )
        receipts[receipt_relative] = receipt
        summary_apps.append(
            {
                "app_id": app_id,
                "repository_id": identity["repository_id"],
                "commit": identity["commit"],
                "commit_tree": identity["commit_tree"],
                "source_tree_sha256": identity["source_tree_sha256"],
                "receipt_sha256": identity["receipt_sha256"],
                "observed_receipt_sha256": receipt_sha256,
                "receipt_semantic_sha256": receipt_semantic_sha256,
                "receipt_equivalence": receipt_equivalence,
                "license": license_binding,
                "file_count": receipt["file_count"],
                "total_bytes": receipt["total_bytes"],
            }
        )
    seed = {"schema": materializer.SEED_SCHEMA, "apps": seed_apps}
    seed_raw = materializer.canonical_json_bytes(seed)
    if builder_path.read_bytes() != builder_raw:
        raise RuntimeError("source_seed_builder_changed_while_building")
    return {
        "seed": seed,
        "seed_raw": seed_raw,
        "receipts": receipts,
        "summary": {
            "schema": SEED_BUILD_SCHEMA,
            "seed": {
                "schema": materializer.SEED_SCHEMA,
                "sha256": materializer.sha256_bytes(seed_raw),
                "app_count": 6,
                "location": "external_local_source_root",
            },
            "source_license_registry": {
                "expected_app_count": 6,
                "materialized_app_count": 6,
                "source_license_admission": "PASS",
                "apps": summary_apps,
            },
            "runtime_allowance": {
                "declaration_only": True,
                "required_isolation_fields": list(materializer.ISOLATION_FIELDS),
                "runtime_evidence_observed": False,
                "runtime_gate": "HOLD",
            },
            "machine_oracles": {
                "declared_count": 0,
                "machine_oracle_gate": "HOLD",
            },
            "scanner_output_observed": False,
            "tool_provenance": {
                "seed_builder_artifact": builder_path.name,
                "seed_builder_sha256": sha256_bytes(builder_raw),
                "materializer_artifact": MATERIALIZER_PATH.name,
                "materializer_sha256": materializer_sha256,
                "verifier_artifact": "holdout_source_materialization.py",
                "verifier_sha256": verifier_sha256,
            },
            "claim_boundary": {
                "source_provenance_only": True,
                "runtime_isolation_proven": False,
                "machine_oracle_proven": False,
                "scanner_accuracy_proven": False,
                "performance_metrics_proven": False,
                "release_gate_admitted": False,
            },
            "raw_returned": False,
        },
    }


def _write_new(path: Path, payload: bytes, *, label: str) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing_to_overwrite_{label}")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise FileExistsError(f"refusing_to_overwrite_{label}") from exc


def write_seed_bundle(
    source_root: Path,
    bundle: Mapping[str, Any],
    *,
    seed_name: str,
    receipts_dir_name: str,
    summary_path: Path,
) -> tuple[Path, Path]:
    root = _source_root(source_root)
    seed_name = _safe_name(seed_name, label="seed_name", suffix=".json")
    receipts_dir_name = _safe_name(receipts_dir_name, label="receipts_dir_name")
    seed_path = root / seed_name
    receipts_root = root / receipts_dir_name
    summary = _external_summary(summary_path, root)
    if seed_path.exists() or seed_path.is_symlink():
        raise FileExistsError("refusing_to_overwrite_source_seed")
    if receipts_root.exists() or receipts_root.is_symlink():
        raise FileExistsError("refusing_to_overwrite_source_receipt_directory")
    receipts_root.mkdir(parents=False, exist_ok=False)
    receipts = bundle["receipts"]
    if not isinstance(receipts, Mapping):
        raise ValueError("seed_bundle_receipts_invalid")
    for relative, receipt in sorted(receipts.items()):
        target = root / str(relative)
        try:
            target.relative_to(receipts_root)
        except ValueError as exc:
            raise ValueError("seed_bundle_receipt_path_escapes_sidecar") from exc
        _write_new(
            target,
            canonical_json_bytes(receipt),
            label="source_receipt",
        )
    seed_raw = bundle["seed_raw"]
    if not isinstance(seed_raw, bytes):
        raise ValueError("seed_bundle_seed_invalid")
    _write_new(seed_path, seed_raw, label="source_seed")
    _write_new(
        summary,
        canonical_json_bytes(bundle["summary"]),
        label="source_seed_summary",
    )
    return seed_path, summary


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a fail-closed six-app L2 source seed without scanner execution."
    )
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--seed-name", required=True)
    parser.add_argument("--receipts-dir-name", required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args(argv)
    bundle = build_seed_bundle(
        args.source_root,
        seed_name=args.seed_name,
        receipts_dir_name=args.receipts_dir_name,
    )
    write_seed_bundle(
        args.source_root,
        bundle,
        seed_name=args.seed_name,
        receipts_dir_name=args.receipts_dir_name,
        summary_path=args.summary,
    )
    print(
        json.dumps(
            {
                "source_license_admission": "PASS",
                "seed_sha256": bundle["summary"]["seed"]["sha256"],
                "runtime_gate": "HOLD",
                "machine_oracle_gate": "HOLD",
                "raw_returned": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
