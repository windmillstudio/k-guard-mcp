from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

import k_guard_mcp.public_lineage as public_lineage_module

from k_guard_mcp.public_lineage import (
    MAX_SOURCE_VERIFIER_BYTES,
    MAX_MANIFEST_BYTES,
    BoundSourceVerifier,
    PublicPoolContractError,
    build_l4_public_selection,
    canonical_json_bytes,
    compile_source_verifier_bytes,
    seal_candidate_pool_bytes,
)


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def load_prefetched_pool(path: Path, *, expected_sha256: str):
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise PublicPoolContractError("candidate input is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
    ):
        raise PublicPoolContractError("candidate input must be a regular file")
    size = metadata.st_size
    if size <= 0 or size > MAX_MANIFEST_BYTES:
        raise PublicPoolContractError("candidate input size is invalid")
    raw = path.read_bytes()
    after = os.lstat(path)
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(metadata, field, None) != getattr(after, field, None) for field in stable):
        raise PublicPoolContractError("candidate input changed during read")
    return seal_candidate_pool_bytes(raw, expected_manifest_sha256=expected_sha256)


def write_selection(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite L4 selection: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(canonical_json_bytes(payload))
    except FileExistsError as exc:
        raise FileExistsError(f"refusing to overwrite L4 selection: {path}") from exc


def load_source_verifier(
    path: Path, *, expected_sha256: str
) -> BoundSourceVerifier:
    if _SHA256_RE.fullmatch(expected_sha256) is None:
        raise PublicPoolContractError("expected source verifier SHA-256 is invalid")
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise PublicPoolContractError("source verifier is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
        or metadata.st_size <= 0
        or metadata.st_size > MAX_SOURCE_VERIFIER_BYTES
    ):
        raise PublicPoolContractError("source verifier must be a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PublicPoolContractError("source verifier could not be opened") from exc
    try:
        before = os.fstat(descriptor)
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_SOURCE_VERIFIER_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(metadata, field, None) != getattr(before, field, None) for field in stable):
        raise PublicPoolContractError("source verifier changed before read")
    if any(getattr(before, field, None) != getattr(after, field, None) for field in stable):
        raise PublicPoolContractError("source verifier changed during read")
    if len(raw) != metadata.st_size or len(raw) > MAX_SOURCE_VERIFIER_BYTES:
        raise PublicPoolContractError("source verifier changed during read")
    return compile_source_verifier_bytes(
        raw,
        expected_sha256=expected_sha256,
        filename=str(path),
    )


def implementation_sha256(path: Path) -> str:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise PublicPoolContractError("selection implementation is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
        or metadata.st_size <= 0
        or metadata.st_size > MAX_SOURCE_VERIFIER_BYTES
    ):
        raise PublicPoolContractError(
            "selection implementation must be a bounded regular file"
        )
    raw = path.read_bytes()
    after = os.lstat(path)
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(metadata, field, None) != getattr(after, field, None) for field in stable):
        raise PublicPoolContractError("selection implementation changed during read")
    return hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build the deterministic 59-app natural-public L4 population from "
            "pre-fetched metadata without importing a detector or using a network."
        )
    )
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--expected-candidate-manifest-sha256", required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--source-verifier", type=Path, required=True)
    parser.add_argument("--expected-source-verifier-sha256", required=True)
    parser.add_argument("--seed-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    pool = load_prefetched_pool(
        args.candidates,
        expected_sha256=args.expected_candidate_manifest_sha256,
    )
    source_verifier = load_source_verifier(
        args.source_verifier,
        expected_sha256=args.expected_source_verifier_sha256,
    )
    result = build_l4_public_selection(
        pool,
        seed_sha256=args.seed_sha256,
        artifact_root=args.artifact_root,
        source_verifier=source_verifier,
        selection_implementation_sha256=implementation_sha256(
            Path(public_lineage_module.__file__)
        ),
        selection_cli_sha256=implementation_sha256(Path(__file__)),
    )
    write_selection(args.output, result)
    print(
        json.dumps(
            {
                "schema": result["schema"],
                "selected_count": result["selection"]["selected_count"],
                "stratum_counts": result["selection"]["stratum_counts"],
                "scanner_output_observed": False,
                "network_accessed": False,
                "source_verifier_sha256": result["bindings"]["source_verifier_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
