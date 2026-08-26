from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Iterable, Mapping


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
MATERIALIZER_PATH = REPOSITORY_ROOT / "scripts" / "materialize_l2_sources.py"
SCHEMA = "k_guard_l2_clean_source_root.v1"
GIT_TIMEOUT_SECONDS = 300
MAX_GIT_OUTPUT_BYTES = 4 * 1024 * 1024


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _load_materializer_with_hash() -> tuple[Any, str]:
    raw_before = MATERIALIZER_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location(
        "k_guard_l2_clean_source_materializer", MATERIALIZER_PATH
    )
    if spec is None or spec.loader is None:
        raise ValueError("l2_source_materializer_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if MATERIALIZER_PATH.read_bytes() != raw_before:
        raise ValueError("l2_source_materializer_changed_while_loading")
    return module, sha256_bytes(raw_before)


def _git_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for key in list(environment):
        normalized = key.upper()
        if normalized in {
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_CEILING_DIRECTORIES",
            "GIT_DISCOVERY_ACROSS_FILESYSTEM",
            "GIT_CONFIG",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_TEMPLATE_DIR",
        } or normalized.startswith("GIT_CONFIG_"):
            environment.pop(key, None)
    environment["GIT_TERMINAL_PROMPT"] = "0"
    return environment


def _run(command: list[str], *, cwd: Path, label: str) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
            env=_git_environment(),
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"{label}_timed_out") from exc
    if len(completed.stdout) > MAX_GIT_OUTPUT_BYTES or len(completed.stderr) > MAX_GIT_OUTPUT_BYTES:
        raise ValueError(f"{label}_output_exceeded_budget")
    if completed.returncode != 0:
        detail = hashlib.sha256(completed.stderr).hexdigest()[:20]
        raise ValueError(f"{label}_failed:{detail}")
    return completed


def _run_git(root: Path, *arguments: str, label: str) -> subprocess.CompletedProcess[bytes]:
    return _run(
        [
            "git",
            "--no-replace-objects",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.longpaths=true",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-C",
            str(root),
            *arguments,
        ],
        cwd=root,
        label=label,
    )


def _external_output_root(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("output_root_must_be_absolute")
    root = path.resolve(strict=False)
    if _is_within(root, REPOSITORY_ROOT):
        raise ValueError("output_root_must_be_external")
    if root.exists() or root.is_symlink():
        raise FileExistsError("refusing_to_overwrite_clean_source_root")
    parent = root.parent.resolve(strict=True)
    if not parent.is_dir() or parent.is_symlink():
        raise ValueError("output_root_parent_invalid")
    return root


def _external_summary(path: Path, output_root: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("summary_must_be_absolute_external_path")
    resolved = path.resolve(strict=False)
    if _is_within(resolved, REPOSITORY_ROOT) or _is_within(resolved, output_root):
        raise ValueError("summary_must_be_outside_repository_and_output_root")
    if resolved.exists() or resolved.is_symlink():
        raise FileExistsError("refusing_to_overwrite_clean_source_summary")
    return resolved


def _canonical_origin(repository_id: str) -> str:
    return f"https://github.com/{repository_id}.git"


def _materialize_app(
    destination: Path,
    *,
    app_id: str,
    identity: Mapping[str, Any],
    materializer: Any,
    verifier: Any,
    transport_source: str,
) -> tuple[dict[str, Any], bytes, int, str, str]:
    if destination.exists() or destination.is_symlink():
        raise ValueError("clean_source_app_destination_exists")
    _run(["git", "init", "--quiet", str(destination)], cwd=destination.parent, label=f"{app_id}_init")
    _run_git(destination, "config", "--local", "core.autocrlf", "false", label=f"{app_id}_autocrlf")
    _run_git(
        destination,
        "remote",
        "add",
        "origin",
        _canonical_origin(identity["repository_id"]),
        label=f"{app_id}_origin",
    )
    _run_git(
        destination,
        "fetch",
        "--no-tags",
        "--no-recurse-submodules",
        transport_source,
        identity["commit"],
        label=f"{app_id}_fetch",
    )
    _run_git(
        destination,
        "checkout",
        "--detach",
        "--force",
        identity["commit"],
        label=f"{app_id}_checkout",
    )
    raw_blob_rewrite_count = verifier.materialize_git_blob_exact_worktree(
        destination,
        expected_repository_id=identity["repository_id"],
        expected_commit=identity["commit"],
        expected_tree=identity["commit_tree"],
        confirm_disposable_worktree=True,
    )
    receipt = verifier.build_git_materialization_receipt(
        destination,
        expected_repository_id=identity["repository_id"],
        expected_commit=identity["commit"],
        expected_tree=identity["commit_tree"],
    )
    if receipt.get("source_tree_sha256") != identity["source_tree_sha256"]:
        raise ValueError("clean_source_tree_differs_from_immutable_identity")
    receipt_raw = canonical_json_bytes(receipt)
    observed_receipt_sha256 = sha256_bytes(receipt_raw)
    observed_semantic_sha256 = materializer._source_receipt_semantic_sha256(receipt)
    locked_semantic_sha256 = identity.get("receipt_semantic_sha256")
    if not isinstance(locked_semantic_sha256, str):
        raise ValueError("clean_source_semantic_identity_missing")
    if observed_receipt_sha256 == identity["receipt_sha256"]:
        receipt_equivalence = "exact_raw_receipt"
    elif observed_semantic_sha256 == locked_semantic_sha256:
        receipt_equivalence = "informational_porcelain_variance"
    else:
        raise ValueError("clean_source_receipt_differs_from_immutable_identity")
    return (
        receipt,
        receipt_raw,
        raw_blob_rewrite_count,
        observed_semantic_sha256,
        receipt_equivalence,
    )


def materialize_clean_sources(
    output_root: Path,
    summary_path: Path,
    *,
    transport_sources: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    script_path = Path(__file__).resolve(strict=True)
    script_raw = script_path.read_bytes()
    root = _external_output_root(output_root)
    summary = _external_summary(summary_path, root)
    materializer, materializer_sha256 = _load_materializer_with_hash()
    verifier, verifier_sha256 = materializer._load_source_materialization_with_hash()
    expected_apps = frozenset(materializer.EXPECTED_APPS)
    if len(expected_apps) != 6 or set(materializer.EXPECTED_IDENTITIES) != expected_apps:
        raise ValueError("immutable_six_app_identity_registry_invalid")
    if transport_sources is not None and set(transport_sources) != expected_apps:
        raise ValueError("transport_source_set_must_match_six_apps")

    temporary = root.parent / f".{root.name}.partial-{uuid.uuid4().hex}"
    if temporary.exists() or temporary.is_symlink():
        raise FileExistsError("clean_source_temporary_path_exists")
    temporary.mkdir()
    records: list[dict[str, Any]] = []
    try:
        for app_id in sorted(expected_apps):
            identity = materializer.EXPECTED_IDENTITIES[app_id]
            transport = (
                transport_sources[app_id]
                if transport_sources is not None
                else _canonical_origin(identity["repository_id"])
            )
            (
                receipt,
                receipt_raw,
                raw_blob_rewrite_count,
                receipt_semantic_sha256,
                receipt_equivalence,
            ) = _materialize_app(
                temporary / app_id,
                app_id=app_id,
                identity=identity,
                materializer=materializer,
                verifier=verifier,
                transport_source=transport,
            )
            records.append(
                {
                    "app_id": app_id,
                    "repository_id": identity["repository_id"],
                    "commit": identity["commit"],
                    "commit_tree": identity["commit_tree"],
                    "source_tree_sha256": identity["source_tree_sha256"],
                    "receipt_sha256": identity["receipt_sha256"],
                    "observed_receipt_sha256": sha256_bytes(receipt_raw),
                    "receipt_semantic_sha256": receipt_semantic_sha256,
                    "receipt_equivalence": receipt_equivalence,
                    "license": dict(identity["license"]),
                    "file_count": receipt["file_count"],
                    "total_bytes": receipt["total_bytes"],
                    "raw_git_blob_rewrite_count": raw_blob_rewrite_count,
                }
            )
        if script_path.read_bytes() != script_raw:
            raise RuntimeError("clean_source_materializer_changed_while_building")
        result = {
            "schema": SCHEMA,
            "expected_app_count": 6,
            "materialized_app_count": 6,
            "source_license_admission": "PASS",
            "source_acquisition": "direct_github_no_filter_fetch_at_pinned_commit_plus_raw_blob_worktree",
            "ordinary_non_shallow_clone_verified": True,
            "network_fetch_performed": True,
            "scanner_output_observed": False,
            "runtime_evidence_observed": False,
            "machine_oracle_evidence_observed": False,
            "release_gate_passed": False,
            "apps": records,
            "tool_provenance": {
                "clean_source_materializer_artifact": script_path.name,
                "clean_source_materializer_sha256": sha256_bytes(script_raw),
                "identity_materializer_artifact": MATERIALIZER_PATH.name,
                "identity_materializer_sha256": materializer_sha256,
                "verifier_artifact": "holdout_source_materialization.py",
                "verifier_sha256": verifier_sha256,
            },
            "claim_boundary": {
                "source_acquisition_only": True,
                "runtime_isolation_proven": False,
                "machine_oracle_proven": False,
                "scanner_accuracy_proven": False,
                "performance_metrics_proven": False,
                "release_gate_admitted": False,
            },
            "raw_returned": False,
        }
        os.replace(temporary, root)
        summary.parent.mkdir(parents=True, exist_ok=True)
        with summary.open("xb") as stream:
            stream.write(canonical_json_bytes(result))
            stream.flush()
            os.fsync(stream.fileno())
        return result
    except Exception as exc:
        if temporary.exists() and temporary.is_dir() and temporary.parent == root.parent:
            try:
                shutil.rmtree(temporary)
            except OSError:
                raise RuntimeError(
                    "clean_source_materialization_failed_and_partial_cleanup_required"
                ) from exc
        raise


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Materialize six pinned public sources as ordinary full Git clones."
    )
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args(argv)
    result = materialize_clean_sources(args.output_root, args.summary)
    print(
        json.dumps(
            {
                "source_license_admission": result["source_license_admission"],
                "materialized_app_count": result["materialized_app_count"],
                "network_fetch_performed": result["network_fetch_performed"],
                "release_gate_passed": result["release_gate_passed"],
                "raw_returned": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
