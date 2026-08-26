"""Raw-free HMAC-chained runtime mediation receipts shared by HTTP and stdio proxies."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from k_guard_mcp.hashing import (
    DEFAULT_EVIDENCE_KEY,
    EVIDENCE_HMAC_ENV,
    active_evidence_key,
    operator_evidence_key_is_valid,
    operator_evidence_key_value_is_valid,
)


RECEIPT_SCHEMA = "k_guard_runtime_mediation_receipt.v1"
CHAIN_SCHEMA = "k_guard_runtime_mediation_receipt_chain.v1"
TAMPER_REPORT_SCHEMA = "k_guard_runtime_mediation_receipt_tamper_report.v1"
HMAC_DOMAIN = b"k-guard-runtime-mediation-receipt-v1"
INITIAL_SHA256 = "0" * 64
ACTIONS = frozenset({"allow", "redact", "block", "deny"})
DIRECTIONS = frozenset({"client_to_upstream", "upstream_to_client"})
TRANSPORTS = frozenset({"jsonl", "streamable_http"})
MESSAGE_KINDS = frozenset({"request", "response", "notification"})
RECEIPT_FIELDS = (
    "schema",
    "sequence",
    "recorded_at",
    "transaction_id",
    "transport",
    "direction",
    "message_kind",
    "message_ref",
    "action",
    "finding_refs",
    "rule_ids",
    "access_reason",
    "policy_ref",
    "toolchain_ref",
    "original_forwarded",
    "safe_replacement_forwarded",
    "previous_sha256",
    "entry_sha256",
    "chain_hmac_sha256",
    "raw_free",
    "raw_returned",
)
RECEIPT_FIELD_SET = frozenset(RECEIPT_FIELDS)
UNSIGNED_RECEIPT_FIELDS = frozenset({"entry_sha256", "chain_hmac_sha256"})
MAX_RECEIPTS = 100_000
MAX_RECEIPT_LINE_BYTES = 64 * 1024
_HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_FORBIDDEN_MESSAGE_KEYS = frozenset(
    {
        "arguments",
        "content",
        "params",
        "payload",
        "principal",
        "result",
        "secret",
        "token",
        "path",
        "url",
        "uri",
    }
)


class RuntimeMediationReceiptError(RuntimeError):
    """Fail-closed receipt construction or persistence error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def new_transaction_id() -> str:
    """Return a non-reversible random transaction reference."""

    return hashlib.sha256(secrets.token_bytes(32)).hexdigest()


def jsonrpc_message_kind(message: Mapping[str, Any]) -> str:
    if not isinstance(message, Mapping):
        raise RuntimeMediationReceiptError("receipt_message_invalid")
    if "method" in message:
        return "request" if "id" in message else "notification"
    return "response"


def message_ref_for(
    message: Mapping[str, Any],
    *,
    hmac_key: str | bytes | bytearray | memoryview | None = None,
) -> str:
    kind = jsonrpc_message_kind(message)
    method = message.get("method") if isinstance(message.get("method"), str) else ""
    if "id" in message:
        id_digest = hashlib.sha256(_canonical_json({"id": message.get("id")})).hexdigest()
        id_present = True
    else:
        id_digest = INITIAL_SHA256
        id_present = False
    return _opaque_ref(
        b"message-ref",
        {
            "id_digest": id_digest,
            "id_present": id_present,
            "kind": kind,
            "method": method,
        },
        hmac_key=hmac_key,
    )


def finding_refs_for(
    findings: Iterable[Any] | None,
    *,
    hmac_key: str | bytes | bytearray | memoryview | None = None,
) -> list[str]:
    refs: list[str] = []
    seen: set[str] = set()
    for finding in findings or ():
        finding_id = ""
        rule_id = ""
        if hasattr(finding, "id") and hasattr(finding, "rule_id"):
            finding_id = str(getattr(finding, "id") or "")
            rule_id = str(getattr(finding, "rule_id") or "")
        elif isinstance(finding, Mapping):
            finding_id = str(finding.get("id") or finding.get("finding_ref") or "")
            rule_id = str(finding.get("rule_id") or "")
        digest = _opaque_ref(
            b"finding-ref",
            {"id": finding_id, "rule_id": rule_id},
            hmac_key=hmac_key,
        )
        if digest not in seen:
            seen.add(digest)
            refs.append(digest)
    return refs


def rule_ids_for(findings: Iterable[Any] | None, extra: Iterable[str] | None = None) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for finding in findings or ():
        rule_id = ""
        if hasattr(finding, "rule_id"):
            rule_id = str(getattr(finding, "rule_id") or "")
        elif isinstance(finding, Mapping):
            rule_id = str(finding.get("rule_id") or "")
        if rule_id and rule_id not in seen:
            seen.add(rule_id)
            values.append(rule_id)
    for rule_id in extra or ():
        item = str(rule_id or "")
        if item and item not in seen:
            seen.add(item)
            values.append(item)
    return values


def policy_ref_for(policy_source_sha256: str | None = None) -> str:
    material = (
        f"k-guard-access-policy:{policy_source_sha256}"
        if isinstance(policy_source_sha256, str) and policy_source_sha256
        else "k-guard-content-policy-only"
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def receipt_persist_path_for_report(report_path: str | Path | None) -> Path | None:
    if report_path is None:
        return None
    path = Path(report_path)
    return path.with_name(path.name + ".receipts.jsonl")


def hmac_key_metadata(key: str | bytes | bytearray | memoryview | None = None) -> dict[str, Any]:
    material = _normalize_key(key)
    mode, tamper_resistant = _key_mode(material)
    return {
        "algorithm": "hmac-sha256",
        "key_mode": mode,
        "key_env": EVIDENCE_HMAC_ENV,
        "tamper_resistant_with_operator_secret": tamper_resistant,
        "raw_returned": False,
    }


def forwarding_contract(*, action: str, forwarded: object | None) -> tuple[bool, bool]:
    if action == "allow" and forwarded is not None:
        return True, False
    if forwarded is not None and action in {"redact", "block", "deny"}:
        return False, True
    return False, False


def receipt_semantic_projection(receipts: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    projection: list[dict[str, Any]] = []
    for item in receipts:
        if not isinstance(item, Mapping):
            continue
        projection.append(
            {
                "access_reason": item.get("access_reason", ""),
                "action": item.get("action"),
                "direction": item.get("direction"),
                "message_kind": item.get("message_kind"),
                "original_forwarded": item.get("original_forwarded"),
                "raw_free": item.get("raw_free"),
                "raw_returned": item.get("raw_returned"),
                "rule_ids": list(item.get("rule_ids") or []),
                "safe_replacement_forwarded": item.get("safe_replacement_forwarded"),
            }
        )
    return projection


class RuntimeMediationReceiptChain:
    """In-memory HMAC-chained receipts with optional fail-closed JSONL persistence."""

    def __init__(
        self,
        *,
        transport: str,
        toolchain_ref: str,
        policy_ref: str | None = None,
        persist_path: str | Path | None = None,
        hmac_key: str | bytes | bytearray | memoryview | None = None,
    ) -> None:
        if transport not in TRANSPORTS:
            raise RuntimeMediationReceiptError("receipt_transport_invalid")
        if not isinstance(toolchain_ref, str) or not _HEX_64_RE.fullmatch(toolchain_ref):
            raise RuntimeMediationReceiptError("receipt_toolchain_ref_invalid")
        resolved_policy_ref = policy_ref or policy_ref_for()
        if not isinstance(resolved_policy_ref, str) or not _HEX_64_RE.fullmatch(resolved_policy_ref):
            raise RuntimeMediationReceiptError("receipt_policy_ref_invalid")
        self.transport = transport
        self.toolchain_ref = toolchain_ref
        self.policy_ref = resolved_policy_ref
        self.persist_path = Path(persist_path) if persist_path is not None else None
        self._key = _normalize_key(hmac_key)
        self._derived = _derive_chain_key(self._key)
        self._lock = threading.Lock()
        self._receipts: list[dict[str, Any]] = []
        self._last_sha256 = INITIAL_SHA256

    def record(
        self,
        *,
        direction: str,
        action: str,
        message: Mapping[str, Any] | None = None,
        message_kind: str | None = None,
        message_ref: str | None = None,
        findings: Iterable[Any] | None = None,
        rule_ids: Iterable[str] | None = None,
        access_reason: str = "",
        policy_ref: str | None = None,
        transaction_id: str | None = None,
        recorded_at: str | None = None,
        original_forwarded: bool = False,
        safe_replacement_forwarded: bool = False,
        forwarded: object | None = None,
    ) -> dict[str, Any]:
        kind = message_kind or (jsonrpc_message_kind(message) if message is not None else "")
        ref = message_ref or (message_ref_for(message, hmac_key=self._key) if message is not None else "")
        receipt_policy_ref = policy_ref or self.policy_ref
        timestamp = recorded_at or datetime.now(UTC).isoformat()
        txn = transaction_id or new_transaction_id()
        refs = finding_refs_for(findings, hmac_key=self._key)
        rules = rule_ids_for(findings, rule_ids)
        if forwarded is not None:
            original_forwarded, safe_replacement_forwarded = forwarding_contract(action=action, forwarded=forwarded)
        with self._lock:
            if len(self._receipts) >= MAX_RECEIPTS:
                raise RuntimeMediationReceiptError("receipt_capacity_exceeded")
            payload = {
                "schema": RECEIPT_SCHEMA,
                "sequence": len(self._receipts) + 1,
                "recorded_at": timestamp,
                "transaction_id": txn,
                "transport": self.transport,
                "direction": direction,
                "message_kind": kind,
                "message_ref": ref,
                "action": action,
                "finding_refs": list(refs),
                "rule_ids": list(rules),
                "access_reason": access_reason or "",
                "policy_ref": receipt_policy_ref,
                "toolchain_ref": self.toolchain_ref,
                "original_forwarded": bool(original_forwarded),
                "safe_replacement_forwarded": bool(safe_replacement_forwarded),
                "previous_sha256": self._last_sha256,
                "raw_free": True,
                "raw_returned": False,
            }
            _validate_unsigned_receipt(payload)
            canonical = _canonical_json(payload)
            entry_sha256 = hashlib.sha256(canonical).hexdigest()
            chain_hmac = _chain_hmac(self._derived, entry_sha256, self._last_sha256)
            record = {
                **payload,
                "entry_sha256": entry_sha256,
                "chain_hmac_sha256": chain_hmac,
            }
            _validate_signed_receipt(record)
            line = _canonical_json(record) + b"\n"
            if len(line) > MAX_RECEIPT_LINE_BYTES:
                raise RuntimeMediationReceiptError("receipt_line_too_large")
            if self.persist_path is not None:
                _append_receipt_line(self.persist_path, line)
            self._receipts.append(record)
            self._last_sha256 = entry_sha256
            return dict(record)

    def receipts(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._receipts]

    def export(self) -> dict[str, Any]:
        with self._lock:
            receipts = [dict(item) for item in self._receipts]
            last_sha256 = self._last_sha256
        metadata = hmac_key_metadata(self._key)
        return {
            "schema": CHAIN_SCHEMA,
            "transport": self.transport,
            "count": len(receipts),
            "toolchain_ref": self.toolchain_ref,
            "policy_ref": self.policy_ref,
            "last_entry_sha256": last_sha256,
            "hmac": metadata,
            "receipts": receipts,
            "raw_free": True,
            "raw_returned": False,
        }


def verify_runtime_mediation_receipts(
    receipts: Sequence[Mapping[str, Any]] | None,
    *,
    hmac_key: str | bytes | bytearray | memoryview | None = None,
    require_operator_key: bool = False,
) -> bool:
    try:
        _inspect_receipts(receipts or (), hmac_key=hmac_key, require_operator_key=require_operator_key)
    except RuntimeMediationReceiptError:
        return False
    return True


def verify_runtime_mediation_receipt_chain(
    chain: Mapping[str, Any] | None,
    *,
    hmac_key: str | bytes | bytearray | memoryview | None = None,
    require_operator_key: bool = False,
) -> bool:
    if not isinstance(chain, Mapping):
        return False
    if chain.get("schema") != CHAIN_SCHEMA or chain.get("raw_free") is not True or chain.get("raw_returned") is not False:
        return False
    receipts = chain.get("receipts")
    if not isinstance(receipts, list):
        return False
    try:
        count = int(chain.get("count", -1))
    except (TypeError, ValueError):
        return False
    if count != len(receipts):
        return False
    metadata = chain.get("hmac")
    if not isinstance(metadata, Mapping) or metadata.get("algorithm") != "hmac-sha256":
        return False
    if metadata.get("raw_returned") is not False:
        return False
    key = _normalize_key(hmac_key)
    mode, tamper_resistant = _key_mode(key)
    if metadata.get("key_mode") != mode:
        return False
    if metadata.get("tamper_resistant_with_operator_secret") is not tamper_resistant:
        return False
    if mode == "public-default-key" and metadata.get("tamper_resistant_with_operator_secret") is True:
        return False
    if require_operator_key and not tamper_resistant:
        return False
    if chain.get("transport") not in TRANSPORTS:
        return False
    try:
        last_sha256 = _inspect_receipts(receipts, hmac_key=key, require_operator_key=require_operator_key)
    except RuntimeMediationReceiptError:
        return False
    expected_last = chain.get("last_entry_sha256")
    if expected_last != last_sha256:
        return False
    return True


def inspect_runtime_mediation_receipt_tamper(
    receipts: Sequence[Mapping[str, Any]] | None,
    *,
    hmac_key: str | bytes | bytearray | memoryview | None = None,
) -> dict[str, Any]:
    key = _normalize_key(hmac_key)
    mode, tamper_resistant = _key_mode(key)
    failed_sequence = None
    valid = True
    try:
        _inspect_receipts(receipts or (), hmac_key=key, require_operator_key=False)
    except RuntimeMediationReceiptError as exc:
        valid = False
        match = re.search(r"sequence=(\d+)", str(exc))
        if match:
            failed_sequence = int(match.group(1))
    return {
        "schema": TAMPER_REPORT_SCHEMA,
        "valid": valid,
        "tampered": not valid,
        "failed_sequence": failed_sequence,
        "key_mode": mode,
        "tamper_resistant_with_operator_secret": tamper_resistant,
        "raw_free": True,
        "raw_returned": False,
    }


def verify_proxy_report_receipts(
    report: Mapping[str, Any] | None,
    *,
    hmac_key: str | bytes | bytearray | memoryview | None = None,
    require_operator_key: bool = False,
) -> bool:
    if not isinstance(report, Mapping):
        return False
    return verify_runtime_mediation_receipt_chain(
        report.get("mediation_receipts") if isinstance(report.get("mediation_receipts"), Mapping) else None,
        hmac_key=hmac_key,
        require_operator_key=require_operator_key,
    )


def _inspect_receipts(
    receipts: Sequence[Mapping[str, Any]],
    *,
    hmac_key: str | bytes | bytearray | memoryview | None,
    require_operator_key: bool,
) -> str:
    key = _normalize_key(hmac_key)
    mode, tamper_resistant = _key_mode(key)
    if require_operator_key and not tamper_resistant:
        raise RuntimeMediationReceiptError("receipt_operator_key_required")
    derived = _derive_chain_key(key)
    previous = INITIAL_SHA256
    for index, record in enumerate(receipts, start=1):
        if not isinstance(record, Mapping):
            raise RuntimeMediationReceiptError(f"receipt_record_invalid sequence={index}")
        try:
            _validate_signed_receipt(record)
        except RuntimeMediationReceiptError as exc:
            raise RuntimeMediationReceiptError(f"{exc.code} sequence={index}") from exc
        if record.get("sequence") != index:
            raise RuntimeMediationReceiptError(f"receipt_sequence_invalid sequence={index}")
        if record.get("previous_sha256") != previous:
            raise RuntimeMediationReceiptError(f"receipt_chain_invalid sequence={index}")
        payload = {key_name: record[key_name] for key_name in record if key_name not in UNSIGNED_RECEIPT_FIELDS}
        actual_sha256 = hashlib.sha256(_canonical_json(payload)).hexdigest()
        if not hmac.compare_digest(actual_sha256, str(record["entry_sha256"])):
            raise RuntimeMediationReceiptError(f"receipt_digest_mismatch sequence={index}")
        actual_hmac = _chain_hmac(derived, str(record["entry_sha256"]), previous)
        if not hmac.compare_digest(actual_hmac, str(record["chain_hmac_sha256"])):
            raise RuntimeMediationReceiptError(f"receipt_hmac_mismatch sequence={index}")
        previous = str(record["entry_sha256"])
        _ = mode
    return previous


def _validate_unsigned_receipt(record: Mapping[str, Any]) -> None:
    if set(record) != RECEIPT_FIELD_SET - UNSIGNED_RECEIPT_FIELDS:
        raise RuntimeMediationReceiptError("receipt_fields_invalid")
    if record.get("schema") != RECEIPT_SCHEMA:
        raise RuntimeMediationReceiptError("receipt_schema_invalid")
    if record.get("raw_free") is not True or record.get("raw_returned") is not False:
        raise RuntimeMediationReceiptError("receipt_raw_contract_invalid")
    if not isinstance(record.get("sequence"), int) or isinstance(record.get("sequence"), bool) or record["sequence"] < 1:
        raise RuntimeMediationReceiptError("receipt_sequence_invalid")
    if not isinstance(record.get("recorded_at"), str) or not record["recorded_at"]:
        raise RuntimeMediationReceiptError("receipt_timestamp_invalid")
    for name in ("transaction_id", "message_ref", "policy_ref", "toolchain_ref", "previous_sha256"):
        value = record.get(name)
        if not isinstance(value, str) or not _HEX_64_RE.fullmatch(value):
            raise RuntimeMediationReceiptError("receipt_digest_invalid")
    if record.get("transport") not in TRANSPORTS or record.get("direction") not in DIRECTIONS:
        raise RuntimeMediationReceiptError("receipt_route_invalid")
    if record.get("message_kind") not in MESSAGE_KINDS or record.get("action") not in ACTIONS:
        raise RuntimeMediationReceiptError("receipt_action_invalid")
    finding_refs = record.get("finding_refs")
    rule_ids = record.get("rule_ids")
    if not isinstance(finding_refs, list) or any(
        not isinstance(item, str) or not _HEX_64_RE.fullmatch(item) for item in finding_refs
    ):
        raise RuntimeMediationReceiptError("receipt_finding_refs_invalid")
    if not isinstance(rule_ids, list) or any(not isinstance(item, str) or not _TOKEN_RE.fullmatch(item) for item in rule_ids):
        raise RuntimeMediationReceiptError("receipt_rule_ids_invalid")
    access_reason = record.get("access_reason")
    if not isinstance(access_reason, str):
        raise RuntimeMediationReceiptError("receipt_access_reason_invalid")
    if access_reason and not _TOKEN_RE.fullmatch(access_reason):
        raise RuntimeMediationReceiptError("receipt_access_reason_invalid")
    if not isinstance(record.get("original_forwarded"), bool) or not isinstance(record.get("safe_replacement_forwarded"), bool):
        raise RuntimeMediationReceiptError("receipt_forwarding_flags_invalid")
    if record.get("original_forwarded") and record.get("safe_replacement_forwarded"):
        raise RuntimeMediationReceiptError("receipt_forwarding_flags_invalid")
    if record.get("action") == "allow" and record.get("original_forwarded") is not True:
        raise RuntimeMediationReceiptError("receipt_forwarding_flags_invalid")
    if record.get("action") in {"block", "deny"} and record.get("original_forwarded") is True:
        raise RuntimeMediationReceiptError("receipt_forwarding_flags_invalid")
    if any(key in record for key in _FORBIDDEN_MESSAGE_KEYS):
        raise RuntimeMediationReceiptError("receipt_forbidden_field")


def _validate_signed_receipt(record: Mapping[str, Any]) -> None:
    if set(record) != RECEIPT_FIELD_SET:
        raise RuntimeMediationReceiptError("receipt_fields_invalid")
    payload = {key: record[key] for key in record if key not in UNSIGNED_RECEIPT_FIELDS}
    _validate_unsigned_receipt(payload)
    for name in ("entry_sha256", "chain_hmac_sha256"):
        value = record.get(name)
        if not isinstance(value, str) or not _HEX_64_RE.fullmatch(value):
            raise RuntimeMediationReceiptError("receipt_digest_invalid")


def _append_receipt_line(path: Path, line: bytes) -> None:
    try:
        if path.exists() and (path.is_symlink() or not path.is_file()):
            raise RuntimeMediationReceiptError("receipt_persist_path_invalid")
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            view = memoryview(line)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short receipt write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except RuntimeMediationReceiptError:
        raise
    except OSError as exc:
        raise RuntimeMediationReceiptError("receipt_persist_failed") from exc


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise RuntimeMediationReceiptError("receipt_canonical_json_invalid") from exc


def _opaque_ref(
    domain: bytes,
    value: object,
    *,
    hmac_key: str | bytes | bytearray | memoryview | None = None,
) -> str:
    key = _normalize_key(hmac_key)
    return hmac.new(key, HMAC_DOMAIN + b"\0" + domain + b"\0" + _canonical_json(value), hashlib.sha256).hexdigest()


def _derive_chain_key(key: bytes) -> bytes:
    return hmac.new(key, HMAC_DOMAIN + b"\0chain", hashlib.sha256).digest()


def _chain_hmac(key: bytes, entry_sha256: str, previous_sha256: str) -> str:
    message = HMAC_DOMAIN + b"\0" + previous_sha256.encode("ascii") + b"\0" + entry_sha256.encode("ascii")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _normalize_key(key: str | bytes | bytearray | memoryview | None) -> bytes:
    if key is None:
        return active_evidence_key().encode("utf-8")
    if isinstance(key, (bytes, bytearray, memoryview)):
        material = bytes(key)
    else:
        material = str(key).encode("utf-8")
    if not material:
        raise RuntimeMediationReceiptError("receipt_hmac_key_invalid")
    return material


def _key_mode(key: bytes) -> tuple[str, bool]:
    try:
        text = key.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if text and hmac.compare_digest(text, DEFAULT_EVIDENCE_KEY):
        return "public-default-key", False
    if text and operator_evidence_key_value_is_valid(text):
        return "operator-keyed", True
    if operator_evidence_key_is_valid() and hmac.compare_digest(key, active_evidence_key().encode("utf-8")):
        return "operator-keyed", True
    return "public-default-key", False


__all__ = [
    "ACTIONS",
    "CHAIN_SCHEMA",
    "DIRECTIONS",
    "MESSAGE_KINDS",
    "RECEIPT_FIELDS",
    "RECEIPT_SCHEMA",
    "TAMPER_REPORT_SCHEMA",
    "TRANSPORTS",
    "RuntimeMediationReceiptChain",
    "RuntimeMediationReceiptError",
    "finding_refs_for",
    "forwarding_contract",
    "hmac_key_metadata",
    "inspect_runtime_mediation_receipt_tamper",
    "jsonrpc_message_kind",
    "message_ref_for",
    "new_transaction_id",
    "policy_ref_for",
    "receipt_persist_path_for_report",
    "receipt_semantic_projection",
    "rule_ids_for",
    "verify_proxy_report_receipts",
    "verify_runtime_mediation_receipt_chain",
    "verify_runtime_mediation_receipts",
]
