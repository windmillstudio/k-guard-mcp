from __future__ import annotations

import hashlib
import hmac
import math
import os
from collections import Counter


EVIDENCE_HMAC_ENV = "K_GUARD_EVIDENCE_HMAC_KEY"
DEFAULT_EVIDENCE_KEY = "k-guard-public-evidence-v1"
MIN_OPERATOR_KEY_BYTES = 32
MIN_OPERATOR_KEY_ESTIMATED_BITS = 128.0


def operator_evidence_key_is_valid() -> bool:
    return operator_evidence_key_value_is_valid(os.environ.get(EVIDENCE_HMAC_ENV, ""))


def operator_evidence_key_value_is_valid(value: str) -> bool:
    encoded = value.encode("utf-8")
    if len(encoded) < MIN_OPERATOR_KEY_BYTES or hmac.compare_digest(value, DEFAULT_EVIDENCE_KEY):
        return False
    counts = Counter(encoded)
    entropy_per_byte = -sum((count / len(encoded)) * math.log2(count / len(encoded)) for count in counts.values())
    return entropy_per_byte * len(encoded) >= MIN_OPERATOR_KEY_ESTIMATED_BITS


def active_evidence_key() -> str:
    return os.environ[EVIDENCE_HMAC_ENV] if operator_evidence_key_is_valid() else DEFAULT_EVIDENCE_KEY


def evidence_hash(value: str, length: int = 16) -> str:
    key = active_evidence_key().encode("utf-8")
    digest = hmac.new(key, value.strip().encode("utf-8", errors="ignore"), hashlib.sha256).hexdigest()
    return digest[:length]


def evidence_hash_scheme() -> str:
    mode = "operator-keyed" if operator_evidence_key_is_valid() else "public-default-key"
    return f"hmac-sha256:{mode}:len16"


def uses_public_evidence_key() -> bool:
    return not operator_evidence_key_is_valid()
