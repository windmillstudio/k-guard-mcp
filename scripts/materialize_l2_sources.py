from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any


SEED_SCHEMA = "k_guard_l2_source_seed.v2"
OUTPUT_SCHEMA = "k_guard_l2_source_materialization.v3"
SOURCE_RECEIPT_SCHEMA = "k_guard_git_source_materialization.v2"
EXPECTED_IDENTITIES: Mapping[str, Mapping[str, Any]] = MappingProxyType(
    {
        "crapi": MappingProxyType(
            {
                "repository_id": "owasp/crapi",
                "commit": "73d309cc8f28bbdeed31dbb35f05dba8354de3c9",
                "commit_tree": "86d22e42ca8f8e3c903f30146ad0df51483b8df0",
                "source_tree_sha256": "f76c89d35f9b7d34c3b12c6b2f64177e0845957f85fab52613bbc18354925d52",
                "receipt_sha256": "d86a9985f9eda5e391112a26a092f7a5273bde393c386ae8968f91399df7429b",
                "receipt_semantic_sha256": "e284ea288d5a36a07661f279690c6e62bdd62e5905c2e2b3d733022efb64daaf",
                "license": MappingProxyType(
                    {
                        "path": "LICENSE.md",
                        "spdx": "Apache-2.0",
                        "sha256": "c98881e3c37ee7331ff667bc0ae59415e5405ea18974c50fa44cd0308623415c",
                        "byte_count": 11311,
                    }
                ),
            }
        ),
        "juice-shop": MappingProxyType(
            {
                "repository_id": "juice-shop/juice-shop",
                "commit": "33518f5a0911e25d9df747b1e70fb7af279a755c",
                "commit_tree": "d503a1d2f1a8864ba596fbf3f6d23dfa02cf45a6",
                "source_tree_sha256": "9a109ac9217946774a0c5d356d2a9836c06153d4ae1fe21de92aa71556525fae",
                "receipt_sha256": "4ed955ad49e650a12139a21e8fc0491a102fd346e4920ca771668e3cf0f9a93a",
                "receipt_semantic_sha256": "16bdfe32da401e75ad16aac3f219758371c2e8bd9a20086c306c22923c5feffa",
                "license": MappingProxyType(
                    {
                        "path": "LICENSE",
                        "spdx": "MIT",
                        "sha256": "fa4ca6d61009e537c953f1c0b8455dd66d69f810888546c48db8ea05f0713093",
                        "byte_count": 1101,
                    }
                ),
            }
        ),
        "nodegoat": MappingProxyType(
            {
                "repository_id": "owasp/nodegoat",
                "commit": "c5cb68a7084e4ae7dcc60e6a98768720a81841e8",
                "commit_tree": "839d7b6856ec6da992d649b2423d5f9fcefdcf1f",
                "source_tree_sha256": "352404981579791fafc18f70649c772a03f304b8895c4f239fbd9863ef5f8a52",
                "receipt_sha256": "d3ad5d453bb7d35580f3bf21dfcbab1bbf53555b7144f94da917cd6513ee21ab",
                "receipt_semantic_sha256": "6b190b395c99e735e3ddbaa1e2d2ea8a7daaba5d514e0469e3ab7d3250eaaafa",
                "license": MappingProxyType(
                    {
                        "path": "LICENSE",
                        "spdx": "Apache-2.0",
                        "sha256": "73ba74dfaa520b49a401b5d21459a8523a146f3b7518a833eea5efa85130bf68",
                        "byte_count": 10273,
                    }
                ),
            }
        ),
        "pygoat": MappingProxyType(
            {
                "repository_id": "adeyosemanputra/pygoat",
                "commit": "19d17cc8874861142b330636d068bbde54e86b85",
                "commit_tree": "1ee82a01f5ac80df289327eca929c9f5aff2a9c4",
                "source_tree_sha256": "156486b1531432930bf9df68f2886a20531c28a7aeffe95c9f095286eee3821c",
                "receipt_sha256": "0bf2824174f6e979893bda964f87e394c3689db69a3825cab646880156f2fa5c",
                "receipt_semantic_sha256": "29b7f1119840084e6022732d7aeb2b07e6402ae3a96fa74819e8470f200eb44a",
                "license": MappingProxyType(
                    {
                        "path": "LICENSE.md",
                        "spdx": "MIT",
                        "sha256": "f3e0249f489c8823e83c5f6e4a65795e624ef9024381722f21592134dcab611f",
                        "byte_count": 1063,
                    }
                ),
            }
        ),
        "webgoat": MappingProxyType(
            {
                "repository_id": "webgoat/webgoat",
                "commit": "5142935bf7c279882c3b0fc0ecec42c447de6fd5",
                "commit_tree": "6c45e60db0995416a5bbe5977657a78d5084dcf7",
                "source_tree_sha256": "0b2193e30038f4366715986e939645d7851e647c6188b992311639dd7564da3c",
                "receipt_sha256": "7755ce29a5450b9803f46effb6f42fe7624e39b317c99546eb74624a3380b83b",
                "receipt_semantic_sha256": "4b518fc464fcbc9eed993895c3aa628958828a3c8a6f6733e24739c84628dded",
                "license": MappingProxyType(
                    {
                        "path": "LICENSE.txt",
                        "spdx": "GPL-2.0-or-later",
                        "sha256": "2fea812568866fdb6ff99671ad70465bfc25ab77f86129795d08d961c30d2ca1",
                        "byte_count": 1092,
                    }
                ),
            }
        ),
        "wrongsecrets": MappingProxyType(
            {
                "repository_id": "owasp/wrongsecrets",
                "commit": "25bdda3c380c7b16bdd2a528c9fff3700fa2b801",
                "commit_tree": "4946781597334bc73adb26d97d84f2677264f9d1",
                "source_tree_sha256": "9b85876c204c995d056206a292ba45e48731ce2a71124fc5e43f4cdea6eeff80",
                "receipt_sha256": "58509e4ad992c66e1b230a66d9f7e18c6c080aea07fb110e07b08d4295455485",
                "receipt_semantic_sha256": "06f9b90faa43039cd5093b577fb63f98d855134e852ab35bc40c331d423c2bba",
                "license": MappingProxyType(
                    {
                        "path": "LICENSE",
                        "spdx": "AGPL-3.0-only",
                        "sha256": "a3c8862ad142ce7c8a915663dc397c2fb56bbc61a1d1ba9dfebb55b0931c37d6",
                        "byte_count": 34479,
                    }
                ),
            }
        ),
    }
)
EXPECTED_APPS = frozenset(EXPECTED_IDENTITIES)
ISOLATION_FIELDS = (
    "loopback_only",
    "external_egress_denied",
    "isolated_container",
    "cap_drop_all",
    "no_new_privileges",
    "read_only_root",
)
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.-]+$")
SPDX_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9.+-]*(?:\s+(?:AND|OR)\s+[A-Za-z0-9][A-Za-z0-9.+-]*)*$"
)
LICENSE_PATH_RE = re.compile(
    r"^(?:LICENSE|COPYING)(?:[._-][A-Za-z0-9._-]+)?$", re.IGNORECASE
)
ORACLE_STATUSES = frozenset({"present", "missing", "uncertain"})
RECEIPT_EQUIVALENCES = frozenset(
    {"exact_raw_receipt", "informational_porcelain_variance"}
)


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _source_receipt_semantic_sha256(receipt: dict[str, Any]) -> str:
    """Bind every source proof except the informational porcelain flag."""

    porcelain_clean = receipt.get("git_porcelain_clean")
    if not isinstance(porcelain_clean, bool):
        raise ValueError("source receipt git_porcelain_clean must be boolean")
    semantic = dict(receipt)
    del semantic["git_porcelain_clean"]
    return sha256_bytes(canonical_json_bytes(semantic))


def _load_source_materialization_with_hash() -> tuple[Any, str]:
    path = Path(__file__).with_name("holdout_source_materialization.py")
    raw_before = path.read_bytes()
    spec = importlib.util.spec_from_file_location(
        "k_guard_l2_holdout_source_materialization", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("source materialization verifier could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    raw_after = path.read_bytes()
    if raw_after != raw_before:
        raise RuntimeError("source materialization verifier changed while loading")
    return module, sha256_bytes(raw_before)


def _load_source_materialization() -> Any:
    return _load_source_materialization_with_hash()[0]


def _load_canonical_object(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError(f"{label} must be a canonical JSON object")
    return payload, raw


def _exact_keys(value: dict[str, Any], expected: set[str], *, label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise ValueError(f"{label} fields differ; missing={missing}; extra={extra}")


def _safe_relative_input(base: Path, value: Any, *, label: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{label} must be a non-empty relative path")
    relative = Path(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(f"{label} must be a normalized relative path")
    base_resolved = base.resolve(strict=True)
    resolved = (base_resolved / relative).resolve(strict=True)
    try:
        resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError(f"{label} escapes the seed directory") from exc
    return resolved


def compute_lineage_id(
    app_id: str,
    repository_id: str,
    commit: str,
    commit_tree: str,
    source_tree_sha256: str,
) -> str:
    fields = (app_id, repository_id, commit, commit_tree, source_tree_sha256)
    return sha256_bytes(("k_guard_l2_lineage.v1\0" + "\0".join(fields)).encode("utf-8"))


def _validate_license(
    app: dict[str, Any], root: Path, receipt: dict[str, Any]
) -> dict[str, Any]:
    license_value = app["license"]
    if not isinstance(license_value, dict):
        raise ValueError("license must be an object")
    _exact_keys(
        license_value,
        {"path", "spdx", "sha256", "byte_count"},
        label="license",
    )
    relative = license_value["path"]
    spdx = license_value["spdx"]
    expected_hash = license_value["sha256"]
    expected_bytes = license_value["byte_count"]
    if not isinstance(relative, str) or LICENSE_PATH_RE.fullmatch(relative) is None:
        raise ValueError("license path must name a root LICENSE or COPYING file")
    if not isinstance(spdx, str) or SPDX_RE.fullmatch(spdx) is None:
        raise ValueError("license SPDX expression is invalid")
    if not isinstance(expected_hash, str) or SHA256_RE.fullmatch(expected_hash) is None:
        raise ValueError("license SHA-256 must be full lowercase hex")
    if not isinstance(expected_bytes, int) or isinstance(expected_bytes, bool) or expected_bytes < 1:
        raise ValueError("license byte_count must be a positive integer")
    target = root / relative
    if target.parent != root or target.is_symlink() or not target.is_file():
        raise ValueError("license must be an actual regular file at repository root")
    raw = target.read_bytes()
    if len(raw) != expected_bytes or sha256_bytes(raw) != expected_hash:
        raise ValueError("license content differs from the seed binding")
    receipt_rows = {
        row.get("path"): row for row in receipt.get("files", []) if isinstance(row, dict)
    }
    row = receipt_rows.get(relative)
    if (
        not isinstance(row, dict)
        or row.get("sha256") != expected_hash
        or row.get("byte_count") != expected_bytes
    ):
        raise ValueError("license is not bound by the source receipt")
    return {
        "path": relative,
        "spdx": spdx,
        "sha256": expected_hash,
        "byte_count": expected_bytes,
        "root_file_verified": True,
        "source_receipt_bound": True,
    }


def _validate_isolation(value: Any) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise ValueError("isolation must be an object")
    _exact_keys(value, set(ISOLATION_FIELDS), label="isolation")
    if any(value[field] is not True for field in ISOLATION_FIELDS):
        raise ValueError("every L2 isolation declaration must be exactly true")
    return {field: True for field in ISOLATION_FIELDS}


def _validate_oracles(value: Any) -> tuple[list[dict[str, str]], dict[str, int]]:
    if not isinstance(value, list):
        raise ValueError("machine_oracles ledger must be present as an array")
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    counts = {status: 0 for status in sorted(ORACLE_STATUSES)}
    for index, row in enumerate(value):
        if not isinstance(row, dict):
            raise ValueError(f"machine_oracles[{index}] must be an object")
        _exact_keys(row, {"scenario_id", "status", "reason"}, label="machine oracle")
        scenario_id, status, reason = row["scenario_id"], row["status"], row["reason"]
        if (
            not isinstance(scenario_id, str)
            or not scenario_id
            or len(scenario_id.encode("utf-8")) > 200
            or any(character in scenario_id for character in "\x00\r\n")
            or scenario_id in seen
        ):
            raise ValueError("machine oracle scenario_id is invalid or duplicated")
        if status not in ORACLE_STATUSES:
            raise ValueError("machine oracle status must be present, missing, or uncertain")
        if not isinstance(reason, str) or not reason or len(reason.encode("utf-8")) > 1000:
            raise ValueError("machine oracle reason must be explicit and bounded")
        if status == "present" and reason != "machine_oracle_declared_not_executed":
            raise ValueError("unexecuted present oracle must use the locked reason")
        seen.add(scenario_id)
        counts[status] += 1
        rows.append({"scenario_id": scenario_id, "status": status, "reason": reason})
    rows.sort(key=lambda row: row["scenario_id"])
    return rows, counts


def _validate_app(
    app: dict[str, Any], seed_directory: Path, verifier: Any
) -> dict[str, Any]:
    _exact_keys(
        app,
        {
            "app_id",
            "repository_id",
            "commit",
            "commit_tree",
            "source_tree_sha256",
            "lineage_id",
            "checkout_root",
            "receipt_path",
            "receipt_sha256",
            "receipt_semantic_sha256",
            "receipt_equivalence",
            "license",
            "isolation",
            "machine_oracles",
        },
        label="app",
    )
    app_id = app["app_id"]
    repository_id = app["repository_id"]
    commit = app["commit"]
    commit_tree = app["commit_tree"]
    source_tree = app["source_tree_sha256"]
    lineage_id = app["lineage_id"]
    if app_id not in EXPECTED_APPS:
        raise ValueError("app_id is not in the locked six-app set")
    locked = EXPECTED_IDENTITIES[app_id]
    locked_identity = {
        "repository_id": locked["repository_id"],
        "commit": locked["commit"],
        "commit_tree": locked["commit_tree"],
        "source_tree_sha256": locked["source_tree_sha256"],
        "license": dict(locked["license"]),
    }
    observed_identity = {
        "repository_id": repository_id,
        "commit": commit,
        "commit_tree": commit_tree,
        "source_tree_sha256": source_tree,
        "license": app["license"],
    }
    if observed_identity != locked_identity:
        raise ValueError(f"{app_id} identity differs from immutable preregistration")
    if not isinstance(repository_id, str) or REPOSITORY_RE.fullmatch(repository_id) is None:
        raise ValueError("repository_id must be a normalized lowercase owner/name")
    if not isinstance(commit, str) or REVISION_RE.fullmatch(commit) is None:
        raise ValueError("commit must be a full lowercase SHA-1")
    if not isinstance(commit_tree, str) or REVISION_RE.fullmatch(commit_tree) is None:
        raise ValueError("commit_tree must be a full lowercase SHA-1")
    if not isinstance(source_tree, str) or SHA256_RE.fullmatch(source_tree) is None:
        raise ValueError("source_tree_sha256 must be full lowercase hex")
    expected_lineage = compute_lineage_id(
        app_id, repository_id, commit, commit_tree, source_tree
    )
    if lineage_id != expected_lineage:
        raise ValueError("lineage_id does not bind the app source identity")
    receipt_hash = app["receipt_sha256"]
    if not isinstance(receipt_hash, str) or SHA256_RE.fullmatch(receipt_hash) is None:
        raise ValueError("receipt_sha256 must be full lowercase hex")
    receipt_semantic_sha256 = app["receipt_semantic_sha256"]
    if (
        not isinstance(receipt_semantic_sha256, str)
        or SHA256_RE.fullmatch(receipt_semantic_sha256) is None
    ):
        raise ValueError("receipt_semantic_sha256 must be full lowercase hex")
    if app["receipt_equivalence"] not in RECEIPT_EQUIVALENCES:
        raise ValueError("receipt_equivalence is invalid")
    locked_semantic_sha256 = locked.get("receipt_semantic_sha256")
    if (
        not isinstance(locked_semantic_sha256, str)
        or SHA256_RE.fullmatch(locked_semantic_sha256) is None
    ):
        raise ValueError("immutable receipt_semantic_sha256 is invalid")

    root = _safe_relative_input(seed_directory, app["checkout_root"], label="checkout_root")
    if not root.is_dir():
        raise ValueError("checkout_root must be a directory")
    receipt_path = _safe_relative_input(
        seed_directory, app["receipt_path"], label="receipt_path"
    )
    receipt, receipt_raw = _load_canonical_object(receipt_path, label="source receipt")
    if sha256_bytes(receipt_raw) != receipt_hash:
        raise ValueError("source receipt byte hash differs from seed binding")
    if receipt.get("schema") != SOURCE_RECEIPT_SCHEMA or receipt.get("passed") is not True:
        raise ValueError("source receipt schema or pass state is invalid")
    recomputed = verifier.build_git_materialization_receipt(
        root,
        expected_repository_id=repository_id,
        expected_commit=commit,
        expected_tree=commit_tree,
    )
    if recomputed != receipt:
        raise ValueError("source receipt differs from the clean checkout verification")
    observed_semantic_sha256 = _source_receipt_semantic_sha256(receipt)
    if observed_semantic_sha256 != receipt_semantic_sha256:
        raise ValueError("source receipt semantic hash differs from seed binding")
    if receipt_hash == locked["receipt_sha256"]:
        receipt_equivalence = "exact_raw_receipt"
    elif observed_semantic_sha256 == locked_semantic_sha256:
        receipt_equivalence = "informational_porcelain_variance"
    else:
        raise ValueError("source receipt differs from immutable preregistration")
    if app["receipt_equivalence"] != receipt_equivalence:
        raise ValueError("source receipt equivalence differs from seed binding")
    if receipt.get("source_tree_sha256") != source_tree:
        raise ValueError("source tree differs from the seed binding")
    required_receipt_truths = (
        "source_worktree_clean",
        "origin_repository_match",
        "commit_match",
        "commit_object_hash_match",
        "commit_tree_match",
        "tree_object_reconstruction_match",
        "index_tree_match",
        "physical_bytes_match_git_blobs",
        "git_fsck_strict_passed",
    )
    if any(receipt.get(field) is not True for field in required_receipt_truths):
        raise ValueError("source receipt does not prove a complete clean checkout")
    if receipt.get("git_repository_layout") != "ordinary_non_shallow_standalone_clone":
        raise ValueError("source receipt does not prove a full standalone clone")

    license_result = _validate_license(app, root, receipt)
    isolation = _validate_isolation(app["isolation"])
    oracle_rows, oracle_counts = _validate_oracles(app["machine_oracles"])
    oracle_missing = not oracle_rows or oracle_counts["missing"] > 0
    oracle_uncertain = oracle_counts["uncertain"] > 0
    return {
        "app_id": app_id,
        "repository_id": repository_id,
        "commit": commit,
        "commit_tree": commit_tree,
        "source_tree_sha256": source_tree,
        "lineage_id": lineage_id,
        "receipt_sha256": locked["receipt_sha256"],
        "observed_receipt_sha256": receipt_hash,
        "receipt_semantic_sha256": observed_semantic_sha256,
        "receipt_equivalence": receipt_equivalence,
        "file_count": receipt["file_count"],
        "total_bytes": receipt["total_bytes"],
        "source_license_admission": "PASS",
        "license": license_result,
        "isolation_contract": {
            "declarations": isolation,
            "declared_status": "PASS",
            "runtime_evidence_observed": False,
            "runtime_gate": "HOLD",
        },
        "machine_oracles": oracle_rows,
        "oracle_counts": oracle_counts,
        "oracle_missing": oracle_missing,
        "oracle_uncertain": oracle_uncertain,
        "oracle_gate_status": "HOLD",
        "scanner_output_observed": False,
    }


def materialize_l2_sources(seed_path: Path) -> dict[str, Any]:
    materializer_path = Path(__file__).resolve(strict=True)
    materializer_raw = materializer_path.read_bytes()
    seed_path = seed_path.resolve(strict=True)
    seed, seed_raw = _load_canonical_object(seed_path, label="L2 seed")
    _exact_keys(seed, {"schema", "apps"}, label="L2 seed")
    if seed["schema"] != SEED_SCHEMA or not isinstance(seed["apps"], list):
        raise ValueError("L2 seed schema or apps collection is invalid")
    if len(seed["apps"]) != len(EXPECTED_APPS):
        raise ValueError("L2 seed must contain exactly six apps")
    verifier, verifier_sha256 = _load_source_materialization_with_hash()
    results = [_validate_app(row, seed_path.parent, verifier) for row in seed["apps"]]
    app_ids = [row["app_id"] for row in results]
    if set(app_ids) != EXPECTED_APPS or len(app_ids) != len(set(app_ids)):
        raise ValueError("L2 seed app set is missing or duplicated")
    for field in (
        "repository_id",
        "commit_tree",
        "source_tree_sha256",
        "lineage_id",
    ):
        values = [row[field] for row in results]
        if len(values) != len(set(values)):
            raise ValueError(f"L2 app {field} values must be unique")
    results.sort(key=lambda row: row["app_id"])
    totals = {
        status: sum(row["oracle_counts"][status] for row in results)
        for status in sorted(ORACLE_STATUSES)
    }
    if materializer_path.read_bytes() != materializer_raw:
        raise RuntimeError("L2 materializer changed while evidence was produced")
    return {
        "schema": OUTPUT_SCHEMA,
        "seed_sha256": sha256_bytes(seed_raw),
        "tool_provenance": {
            "materializer_artifact": materializer_path.name,
            "materializer_sha256": sha256_bytes(materializer_raw),
            "verifier_artifact": "holdout_source_materialization.py",
            "verifier_sha256": verifier_sha256,
        },
        "expected_app_count": 6,
        "materialized_app_count": 6,
        "source_license_admission": "PASS",
        "isolation_contract_declared": "PASS",
        "runtime_isolation_gate": "HOLD",
        "runtime_isolation_gate_reason": "docker_runtime_receipts_not_observed",
        "machine_oracle_totals": totals,
        "machine_oracle_gate": "HOLD",
        "machine_oracle_gate_reason": "oracle_count_and_replay_gate_not_executed",
        "phase_2_status": "HOLD",
        "release_gate_passed": False,
        "scanner_output_observed": False,
        "apps": results,
        "raw_returned": False,
    }


def write_new_output(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite L2 materialization: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(canonical_json_bytes(payload))
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise FileExistsError(
                f"refusing to overwrite L2 materialization: {path}"
            ) from exc
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail-closed L2 source, license, and isolation admission."
    )
    parser.add_argument("--seed", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite L2 materialization: {args.output}")
    payload = materialize_l2_sources(args.seed)
    write_new_output(args.output, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
