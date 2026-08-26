from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from k_guard_mcp.collector import DEFAULT_EXCLUDES, is_excluded_scan_directory
from k_guard_mcp.hashing import EVIDENCE_HMAC_ENV, active_evidence_key, evidence_hash, evidence_hash_scheme, operator_evidence_key_is_valid
from k_guard_mcp.redaction import sanitize_any


RELEASE_SNAPSHOT_MAX_FILES = 50_000
RELEASE_SNAPSHOT_MAX_FILE_BYTES = 64 * 1024 * 1024
RELEASE_SNAPSHOT_MAX_TOTAL_BYTES = 1024 * 1024 * 1024
RELEASE_SNAPSHOT_EXCLUDED_TREES = set(DEFAULT_EXCLUDES)


def canonical_json(value: Any) -> str:
    return json.dumps(sanitize_any(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def object_artifact(label: str, value: Any, *, role: str = "evidence") -> dict[str, Any]:
    rendered = canonical_json(value)
    return {
        "label": label,
        "role": role,
        "hash": evidence_hash(rendered),
        "hash_scheme": evidence_hash_scheme(),
        "byte_count": len(rendered.encode("utf-8")),
        "raw_returned": False,
    }


def path_artifact(label: str, path: str | Path, *, role: str = "input") -> dict[str, Any]:
    text = str(path or "")
    try:
        candidate = Path(text)
        exists = candidate.exists() if text else False
        is_file = candidate.is_file() if exists else False
        content = candidate.read_bytes() if is_file else b""
    except OSError:
        exists = False
        is_file = False
        content = b""
    return {
        "label": label,
        "role": role,
        "hash": evidence_hash(text),
        "hash_scheme": evidence_hash_scheme(),
        "exists_at_bundle_time": exists,
        "content_sha256": hashlib.sha256(content).hexdigest() if is_file else "",
        "byte_count": len(content),
        "raw_returned": False,
    }


def source_tree_snapshot(
    path: str | Path,
    *,
    max_files: int = RELEASE_SNAPSHOT_MAX_FILES,
    max_file_bytes: int = RELEASE_SNAPSHOT_MAX_FILE_BYTES,
    max_total_bytes: int = RELEASE_SNAPSHOT_MAX_TOTAL_BYTES,
) -> dict[str, Any]:
    root = Path(path).resolve()
    files, collection_limited, skipped_symlink_trees = _collect_release_snapshot_files(root, max_files=max_files)
    digest = hashlib.sha256()
    total_bytes = 0
    unreadable = 0
    oversized = 0
    total_bytes_limited = False
    hashed_file_count = 0
    for file_path in files:
        try:
            relative = str(file_path.absolute().relative_to(root if root.is_dir() else root.parent)).replace("\\", "/")
            if file_path.is_symlink():
                content = os.readlink(file_path).encode("utf-8", errors="surrogatepass")
                content_kind = b"symlink"
            else:
                size = file_path.stat().st_size
                if size > max_file_bytes:
                    oversized += 1
                    continue
                if total_bytes + size > max_total_bytes:
                    total_bytes_limited = True
                    break
                content = file_path.read_bytes()
                content_kind = b"file"
        except (OSError, ValueError):
            unreadable += 1
            continue
        relative_bytes = relative.encode("utf-8", errors="ignore")
        digest.update(len(relative_bytes).to_bytes(8, "big"))
        digest.update(relative_bytes)
        digest.update(content_kind)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
        total_bytes += len(content)
        hashed_file_count += 1
    complete = not any((collection_limited, total_bytes_limited, unreadable, oversized, skipped_symlink_trees))
    return {
        "schema": "k_guard_source_tree_snapshot.v1",
        "collector": "bounded_independent_release_snapshot.v1",
        "tree_sha256": digest.hexdigest(),
        "file_count": len(files),
        "hashed_file_count": hashed_file_count,
        "unreadable_file_count": unreadable,
        "oversized_file_count": oversized,
        "skipped_symlink_tree_count": skipped_symlink_trees,
        "byte_count": total_bytes,
        "complete": complete,
        "limit_exceeded": collection_limited or total_bytes_limited or oversized > 0,
        "bounds": {
            "max_files": max_files,
            "max_file_bytes": max_file_bytes,
            "max_total_bytes": max_total_bytes,
        },
        "raw_returned": False,
    }


def _collect_release_snapshot_files(root: Path, *, max_files: int) -> tuple[list[Path], bool, int]:
    if max_files <= 0:
        return [], True, 0
    if root.is_file():
        return [root], False, 0
    if not root.is_dir():
        return [], False, 0

    files: list[Path] = []
    limited = False
    skipped_symlink_trees = 0
    for current, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        kept_directories: list[str] = []
        for name in sorted(directory_names, key=str.casefold):
            candidate = Path(current) / name
            if is_excluded_scan_directory(root, Path(current), name):
                continue
            if candidate.is_symlink():
                skipped_symlink_trees += 1
                continue
            kept_directories.append(name)
        directory_names[:] = kept_directories
        for name in sorted(file_names, key=str.casefold):
            files.append(Path(current) / name)
            if len(files) > max_files:
                files.pop()
                limited = True
                return files, limited, skipped_symlink_trees
    files.sort(key=lambda item: str(item.relative_to(root)).replace("\\", "/").casefold())
    return files, limited, skipped_symlink_trees


def evidence_bundle(subject: str, producer: str, artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    payload = {
        "schema": "k_guard_evidence_bundle.v1",
        "subject": subject,
        "producer": producer,
        "generated_at": datetime.now(UTC).isoformat(),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "hash_scheme": evidence_hash_scheme(),
        "raw_returned": False,
    }
    canonical = canonical_json(payload)
    bundle_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    key = active_evidence_key()
    operator_keyed = operator_evidence_key_is_valid()
    signature_sha256 = hmac.new(key.encode("utf-8"), bundle_sha256.encode("utf-8"), hashlib.sha256).hexdigest()
    payload["bundle_sha256"] = bundle_sha256
    payload["signature"] = {
        "algorithm": "hmac-sha256",
        "signature_sha256": signature_sha256,
        "key_mode": "operator-keyed" if operator_keyed else "public-default-key",
        "key_env": EVIDENCE_HMAC_ENV,
        "tamper_resistant_with_operator_secret": operator_keyed,
        "raw_returned": False,
    }
    return sanitize_any(payload)


def verify_evidence_bundle(value: object, *, require_operator_key: bool = False) -> bool:
    if not isinstance(value, dict):
        return False
    signature = value.get("signature", {})
    if not isinstance(signature, dict):
        return False
    if value.get("schema") != "k_guard_evidence_bundle.v1" or value.get("raw_returned") is not False:
        return False
    if not isinstance(value.get("artifacts"), list) or not value.get("artifacts"):
        return False
    try:
        artifact_count = int(value.get("artifact_count", -1))
    except (TypeError, ValueError):
        return False
    if artifact_count != len(value.get("artifacts", [])):
        return False
    if signature.get("algorithm") != "hmac-sha256":
        return False
    if require_operator_key and not operator_evidence_key_is_valid():
        return False
    if require_operator_key and (signature.get("key_mode") != "operator-keyed" or signature.get("tamper_resistant_with_operator_secret") is not True):
        return False
    payload = dict(value)
    expected_bundle_sha256 = str(payload.pop("bundle_sha256", "") or "")
    payload.pop("signature", None)
    if not expected_bundle_sha256:
        return False
    canonical = canonical_json(payload)
    actual_bundle_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(actual_bundle_sha256, expected_bundle_sha256):
        return False
    key = active_evidence_key()
    actual_signature = hmac.new(key.encode("utf-8"), expected_bundle_sha256.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(actual_signature, str(signature.get("signature_sha256") or ""))
