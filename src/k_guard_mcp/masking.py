from __future__ import annotations

import hashlib
import re

from k_guard_mcp.redaction import redaction_token


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


def mask_value(label: str, value: str) -> str:
    value = value.strip()
    upper = label.upper()
    if not value:
        return ""
    if upper in {"PRIVATE_KEY"}:
        return redaction_token("PRIVATE_KEY", value)
    if upper in {"JWT"}:
        return redaction_token("JWT", value)
    if upper in {"API_KEY", "GITHUB_PAT", "AWS_ACCESS_KEY", "SECRET", "DB_URL"}:
        return redaction_token(upper, value)
    if upper in {"RRN", "FRN", "RRN_VALID", "FRN_VALID"}:
        token_label = "RRN" if upper.startswith("RRN") else "FRN"
        return redaction_token(token_label, value)
    if upper == "PHONE":
        return redaction_token("PHONE", value)
    if upper == "EMAIL":
        return redaction_token("EMAIL", value)
    if upper == "PERSON":
        return redaction_token("PERSON", value)
    if upper == "ADDRESS":
        return redaction_token("ADDRESS", value)
    if upper in {
        "PASSPORT",
        "DRIVER_LICENSE",
        "PERSONAL_CUSTOMS_CODE",
        "BANK_ACCOUNT",
        "VEHICLE_NUMBER",
        "BIRTHDATE",
        "TIMESTAMP",
        "LOCATION",
        "ORDER_ID",
        "ACCOUNT_ID",
        "PATIENT_ID",
        "HEALTH_INSURANCE_ID",
        "DEVICE_ID",
        "CI",
        "DI",
        "IP_ADDRESS",
        "BUSINESS_REGISTRATION",
        "CORPORATE_REGISTRATION",
    }:
        return redaction_token(upper, value)
    if upper == "CREDIT_CARD":
        digits = re.sub(r"\D", "", value)
        if len(digits) >= 10:
            return redaction_token("CREDIT_CARD", value)
    if len(value) <= 4:
        return value[0] + "*" * max(0, len(value) - 1)
    return f"{value[:3]}****{value[-3:]}"


def _mask_secret(value: str) -> str:
    if "://" in value and "@" in value:
        return re.sub(r":([^:@/]+)@", r":****@", value)
    if len(value) <= 8:
        return value[:2] + "****"
    return f"{value[:4]}****{value[-4:]}"


def _mask_email(value: str) -> str:
    if "@" not in value:
        return _mask_secret(value)
    local, domain = value.split("@", 1)
    if len(local) <= 2:
        masked = local[0] + "*"
    else:
        masked = local[0] + "*" * max(1, len(local) - 2) + local[-1]
    return f"{masked}@{domain}"


def _mask_person(value: str) -> str:
    if len(value) <= 1:
        return "*"
    if len(value) == 2:
        return value[0] + "*"
    return value[0] + "*" * (len(value) - 2) + value[-1]


def _mask_address(value: str) -> str:
    parts = value.split()
    if len(parts) <= 2:
        return value[:3] + " ***"
    return " ".join(parts[:3]) + " ***"
