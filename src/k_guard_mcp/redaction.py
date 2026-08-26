from __future__ import annotations

import csv
import dataclasses
import hashlib
import io
import re
import unicodedata
from datetime import date
from collections.abc import Mapping
from typing import Any

from k_guard_mcp.sensitive_vocabulary import normalize_header_label

ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
UNTRUSTED_DATA_INSTRUCTION = re.compile(
    r"(?:"
    r"\b(?:ignore|disregard|forget|override|bypass)\b.{0,80}"
    r"\b(?:previous|prior|above|system|developer|user|tool|instructions?|rules?|prompt)\b|"
    r"\b(?:follow|obey|execute)\b.{0,40}\b(?:these|the\s+following|my)\b.{0,20}\binstructions?\b|"
    r"\byou\s+are\s+now\b|\bsystem[\s._:/-]+prompt\b|\bdeveloper[\s._:/-]+message\b|"
    r"\bdo[\s._:/-]+not[\s._:/-]+reveal\b|(?:\A|[\r\n])\s*(?:assistant|developer|system|tool)\s*:|"
    r"<\s*/?\s*(?:assistant|developer|system|tool)(?:\s+[^>]*)?>|"
    r"<\|(?:assistant|developer|system|tool)\|>|"
    r"(?:이전|위|시스템|개발자).{0,30}지시.{0,30}(?:무시|재정의|우회)|"
    r"(?:다음|아래|이).{0,20}지시.{0,20}(?:따르|실행|준수)|"
    r"지시.{0,10}따르"
    r")",
    re.IGNORECASE | re.DOTALL,
)
# Backwards-compatible name for callers that only sanitize locators.
UNTRUSTED_LOCATOR_INSTRUCTION = UNTRUSTED_DATA_INSTRUCTION
DISALLOWED_OUTPUT_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

MCP_LOCATOR_FIELDS = frozenset(
    {
        "endpoint",
        "endpoints",
        "file",
        "files",
        "locator",
        "locators",
        "manifest",
        "path",
        "paths",
        "session_file",
        "uri",
        "uris",
        "url",
        "urls",
        "workspace",
        "workspace_path",
    }
)
MCP_LOCATOR_SUFFIXES = (
    "_endpoint",
    "_endpoints",
    "_file",
    "_files",
    "_locator",
    "_locators",
    "_path",
    "_paths",
    "_uri",
    "_uris",
    "_url",
    "_urls",
)
MCP_MESSAGE_FIELDS = frozenset(
    {
        "content",
        "description",
        "detail",
        "error",
        "evidence",
        "fix_verification",
        "label",
        "limitations",
        "message",
        "note",
        "notes",
        "recommendation",
        "summary_line",
        "text",
        "title",
        "why",
        "why_it_matters",
    }
)
MCP_MESSAGE_SUFFIXES = (
    "_content",
    "_description",
    "_detail",
    "_error",
    "_evidence",
    "_label",
    "_message",
    "_note",
    "_notes",
    "_recommendation",
    "_text",
    "_title",
)
SAFE_DETECTOR_SUBTYPE = re.compile(r"\bdetector_subtype\s*[=:]\s*([A-Za-z0-9_.-]{1,64})\b", re.IGNORECASE)
SAFE_OUTPUT_FINGERPRINT = re.compile(
    r"\b((?:response|body|header|content|evidence|object|value|request)_(?:hash|ref)|fingerprint)"
    r"\s*[=:]\s*([A-Fa-f0-9]{8,128})\b",
    re.IGNORECASE,
)


def stable_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


# Field-bound organization identifiers are redacted before generic RRN when the
# value is not a plausible natural-person RRN/FRN. Privacy-first: a plausible
# person ID always wins over an org label. Label context is same-line only.
CONTEXT_BOUND_REDACTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "CORPORATE_REGISTRATION",
        re.compile(
            r"(?:법인[^\S\r\n]*등록[^\S\r\n]*번호|법인[^\S\r\n]*번호|법인번호|"
            r"corporate(?:[_ -]?registration)?(?:[_ -]?(?:no|num(?:ber)?))?|"
            r"corp[_ -]?(?:reg(?:istration)?|no|num(?:ber)?)|\bcrn\b)"
            r"[^\S\r\n]*[\"'\t :=#-]*[\"']?(?P<value>(?<!\d)(?:\d{6}[- ]?\d{7}|\d{13})(?!\d))",
            re.IGNORECASE,
        ),
    ),
    (
        "BUSINESS_REGISTRATION",
        re.compile(
            r"(?:사업자[^\S\r\n]*등록[^\S\r\n]*번호|사업자[^\S\r\n]*번호|사업자번호|"
            r"biz[_ -]?(?:reg(?:istration)?|no|number)|\bbrn\b|"
            r"business[_ -]?registration(?:[_ -]?(?:no|num(?:ber)?))?)"
            r"[^\S\r\n]*[\"'\t :=#-]*[\"']?(?P<value>(?<!\d)(?:\d{3}[- ]\d{2}[- ]\d{5}|\d{10})(?!\d))",
            re.IGNORECASE,
        ),
    ),
)
_SPLIT_JSON_ORG_KEY = re.compile(r"^[\[{,]?\s*[\"'](?P<key>[^\"']+)[\"']\s*:\s*[\"']?\s*$")
_SPLIT_JSON_CORP_VALUE = re.compile(r"(?P<value>(?<!\d)(?:\d{6}[- ]?\d{7}|\d{13})(?!\d))")
_SPLIT_JSON_BIZ_VALUE = re.compile(r"(?P<value>(?<!\d)(?:\d{3}[- ]\d{2}[- ]\d{5}|\d{10})(?!\d))")
_CORP_REDACT_HEADERS = frozenset(
    {
        "법인등록번호",
        "법인번호",
        "crn",
        "corp_reg",
        "corporate_registration",
        "corporate_registration_number",
        "corporate_registration_no",
    }
)
_BIZ_REDACT_HEADERS = frozenset(
    {
        "사업자등록번호",
        "사업자번호",
        "biz_no",
        "biz_number",
        "brn",
        "business_registration",
        "business_registration_number",
        "business_registration_no",
    }
)
def _compact_redact_header(header: str) -> str:
    return re.sub(r"[_-]+", "", normalize_header_label(header))


_NORMALIZED_CORP_REDACT_HEADERS = frozenset(_compact_redact_header(name) for name in _CORP_REDACT_HEADERS)
_NORMALIZED_BIZ_REDACT_HEADERS = frozenset(_compact_redact_header(name) for name in _BIZ_REDACT_HEADERS)

REDACTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----")),
    ("DB_URL", re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^)\s'\"`]+")),
    ("GITHUB_PAT", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    ("API_KEY", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("API_KEY_SPLIT", re.compile(r"\bsk-[A-Za-z0-9_\-\s]{20,}\b")),
    ("RRN", re.compile(r"\b\d{6}[- ]?[1-8]\d{6}\b")),
    ("CORPORATE_REGISTRATION", re.compile(r"\b\d{6}[- ]?\d{7}\b")),
    ("BUSINESS_REGISTRATION", re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{5}\b")),
    ("PHONE", re.compile(r"\b(?:010|011|016|017|018|019|02|0[3-6][1-6]|070|080)[- ]?\d{3,4}[- ]?\d{4}\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("PASSPORT", re.compile(r"\b[MSROD][0-9]{8}\b")),
    ("CUSTOMS", re.compile(r"\bP\d{12}\b")),
    ("CI", re.compile(r"(?:\bci\b|connecting[_ -]?info(?:rmation)?|연계정보)[\"'\s:=]+[\"']?[A-Za-z0-9+/=_-]{20,}", re.IGNORECASE)),
    ("DI", re.compile(r"(?:\bdi\b|duplication[_ -]?info(?:rmation)?|중복가입확인정보)[\"'\s:=]+[\"']?[A-Za-z0-9+/=_-]{20,}", re.IGNORECASE)),
    ("HEALTH_INSURANCE_ID", re.compile(r"(?:health[_ -]?insurance[_ -]?(?:id|no|number)|건강보험(?:증)?번호|보험증번호)[\"'\s:=#-]+[A-Za-z0-9_.-]{6,}", re.IGNORECASE)),
    ("PATIENT_ID", re.compile(r"(?:patient[_ -]?(?:id|no|number)|medical[_ -]?record[_ -]?(?:id|no|number)|환자번호|차트번호|진료번호|의무기록번호|병록번호)[\"'\s:=#-]+[A-Za-z0-9_.-]{4,}", re.IGNORECASE)),
    ("ACCOUNT_ID", re.compile(r"(?:student[_ -]?id|employee[_ -]?id|member[_ -]?(?:id|no|number)|customer[_ -]?(?:no|number)|학번|사번|회원번호|회원ID|고객번호|수험번호)[\"'\s:=#-]+[A-Za-z0-9_.-]{4,}", re.IGNORECASE)),
    ("DEVICE_ID", re.compile(r"(?:device[_ -]?id|deviceId|idfa|gaid|adid|advertising[_ -]?id|firebase[_ -]?installation[_ -]?id|installation[_ -]?id|기기ID|기기식별자)[\"'\s:=]+[A-Za-z0-9_.:-]{12,}", re.IGNORECASE)),
    ("PERSON", re.compile(r"\b(?:name|user_name|customer_name|full_name|이름|성명|고객명|사용자명)[\"'\s:=]+[\"']?[가-힣]{2,4}", re.IGNORECASE)),
    ("ADDRESS", re.compile(r"\b(?:address|addr|주소)[\"'\s:=]+[\"']?[가-힣A-Za-z0-9\s\-]+(?:시|도|구|군|동|로|길)[가-힣A-Za-z0-9\s\-]*", re.IGNORECASE)),
)

ENCODED_SENSITIVE_LABELS = frozenset(
    {
        "PRIVATE_KEY",
        "DB_URL",
        "GITHUB_PAT",
        "AWS_ACCESS_KEY",
        "JWT",
        "API_KEY",
        "API_KEY_SPLIT",
        "RRN",
        "CORPORATE_REGISTRATION",
        "BUSINESS_REGISTRATION",
        "PHONE",
        "EMAIL",
        "CREDIT_CARD",
        "PASSPORT",
        "CUSTOMS",
        "CI",
        "DI",
        "HEALTH_INSURANCE_ID",
        "PATIENT_ID",
        "ACCOUNT_ID",
        "DEVICE_ID",
        "PERSON",
        "ADDRESS",
    }
)
ENCODED_REDACTION_PATTERNS = tuple((label, pattern) for label, pattern in REDACTION_PATTERNS if label in ENCODED_SENSITIVE_LABELS)


def redact_text(value: str) -> str:
    redacted = ZERO_WIDTH.sub("", value)
    redacted = unicodedata.normalize("NFKC", redacted)
    redacted = re.sub(r"\|\s*([가-힣]{2,4})\s*\|", lambda match: f"| {redaction_token('PERSON', match.group(1))} |", redacted)
    redacted = _redact_encoded_tokens(redacted)
    redacted = _redact_context_bound_identifiers(redacted)
    redacted = _redact_split_json_org_identifiers(redacted)
    redacted = _redact_csv_header_bound_identifiers(redacted)
    for label, pattern in REDACTION_PATTERNS:
        redacted = pattern.sub(lambda match, bound=label: _replace_generic_identifier(match, bound), redacted)
    return redacted


def _redact_context_bound_identifiers(value: str) -> str:
    redacted = value
    for label, pattern in CONTEXT_BOUND_REDACTION_PATTERNS:
        redacted = pattern.sub(lambda match, bound=label: _replace_bound_identifier(match, bound), redacted)
    return redacted


def _replace_bound_identifier(match: re.Match[str], label: str) -> str:
    raw = match.group("value")
    digits = re.sub(r"\D", "", raw)
    if label == "CORPORATE_REGISTRATION" and _person_identity_digits(digits):
        return match.group(0)
    if label == "BUSINESS_REGISTRATION" and len(digits) != 10:
        return match.group(0)
    return match.group(0).replace(raw, redaction_token(label, raw), 1)


def _person_identity_digits(digits: str) -> bool:
    if not re.fullmatch(r"\d{13}", digits) or digits[6] not in {"1", "2", "3", "4", "5", "6", "7", "8"}:
        return False
    century = 1900 if digits[6] in {"1", "2", "5", "6"} else 2000
    try:
        date(century + int(digits[:2]), int(digits[2:4]), int(digits[4:6]))
    except ValueError:
        return False
    return True


def _replace_generic_identifier(match: re.Match[str], label: str) -> str:
    raw = match.group(0)
    digits = re.sub(r"\D", "", raw)
    if label == "RRN":
        if _person_identity_digits(digits):
            return redaction_token("RRN" if digits[6] in {"1", "2", "3", "4"} else "FRN", raw)
        return raw
    if label == "CORPORATE_REGISTRATION":
        if _historical_corporate_checksum_valid(digits) and not _person_identity_digits(digits):
            return redaction_token(label, raw)
        return raw
    if label == "BUSINESS_REGISTRATION":
        if _business_checksum_valid(digits):
            return redaction_token(label, raw)
        return raw
    return redaction_token(label, raw)


def _historical_corporate_checksum_valid(digits: str) -> bool:
    if not re.fullmatch(r"\d{13}", digits):
        return False
    weights = (1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2)
    total = sum(int(digits[index]) * weights[index] for index in range(12))
    return (10 - (total % 10)) % 10 == int(digits[12])


def _business_checksum_valid(digits: str) -> bool:
    if not re.fullmatch(r"\d{10}", digits):
        return False
    weights = [1, 3, 7, 1, 3, 7, 1, 3, 5]
    total = sum(int(digits[index]) * weights[index] for index in range(9))
    total += (int(digits[8]) * 5) // 10
    return (10 - (total % 10)) % 10 == int(digits[9])


def _redact_split_json_org_identifiers(value: str) -> str:
    lines = value.splitlines(keepends=True)
    if len(lines) < 2:
        return value
    pending: str | None = None
    rebuilt: list[str] = []
    for line in lines:
        body, newline = _split_line_ending(line)
        if pending is not None:
            pattern = _SPLIT_JSON_CORP_VALUE if pending == "CORPORATE_REGISTRATION" else _SPLIT_JSON_BIZ_VALUE
            match = pattern.search(body)
            if match is not None:
                raw = match.group("value")
                digits = re.sub(r"\D", "", raw)
                skip_org = pending == "CORPORATE_REGISTRATION" and _person_identity_digits(digits)
                if not skip_org:
                    body = body[: match.start("value")] + redaction_token(pending, raw) + body[match.end("value") :]
            pending = None
        key_match = _SPLIT_JSON_ORG_KEY.match(body.strip().rstrip(","))
        if key_match is not None:
            compact = _compact_redact_header(key_match.group("key"))
            if compact in _NORMALIZED_CORP_REDACT_HEADERS:
                pending = "CORPORATE_REGISTRATION"
            elif compact in _NORMALIZED_BIZ_REDACT_HEADERS:
                pending = "BUSINESS_REGISTRATION"
        rebuilt.append(body + newline)
    return "".join(rebuilt)


def _redact_csv_header_bound_identifiers(value: str) -> str:
    lines = value.splitlines(keepends=True)
    if len(lines) < 2:
        return value
    header_raw = lines[0]
    header_line = header_raw.splitlines()[0]
    stripped = header_line.lstrip("\ufeff").strip()
    if not stripped or stripped.endswith((":", "=")):
        return value
    delimiter = "\t" if "\t" in header_line and "," not in header_line else ","
    try:
        header_row = next(csv.reader(io.StringIO(header_line), delimiter=delimiter))
    except (csv.Error, StopIteration):
        header_row = [stripped]
    headers = [_compact_redact_header(item) for item in header_row]
    corp_cols = {index for index, name in enumerate(headers) if name in _NORMALIZED_CORP_REDACT_HEADERS}
    biz_cols = {index for index, name in enumerate(headers) if name in _NORMALIZED_BIZ_REDACT_HEADERS}
    if not corp_cols and not biz_cols:
        return value
    rebuilt = [header_raw]
    for line in lines[1:]:
        body, newline = _split_line_ending(line)
        try:
            row = next(csv.reader(io.StringIO(body), delimiter=delimiter))
        except (csv.Error, StopIteration):
            rebuilt.append(line)
            continue
        occupied: list[tuple[int, int]] = []
        redacted_body = body
        for col_idx, cell in enumerate(row):
            if col_idx in corp_cols:
                label = "CORPORATE_REGISTRATION"
            elif col_idx in biz_cols:
                label = "BUSINESS_REGISTRATION"
            else:
                continue
            cell_value = cell.strip()
            digits = re.sub(r"\D", "", cell_value)
            if label == "CORPORATE_REGISTRATION" and (not re.fullmatch(r"\d{13}", digits) or _person_identity_digits(digits)):
                continue
            if label == "BUSINESS_REGISTRATION" and not re.fullmatch(r"\d{10}", digits):
                continue
            token = redaction_token(label, cell_value)
            found_at = _unoccupied_index(redacted_body, cell_value, occupied)
            if found_at is None and cell_value != digits:
                found_at = _unoccupied_index(redacted_body, digits, occupied)
                cell_value = digits if found_at is not None else cell_value
            if found_at is None:
                continue
            redacted_body = redacted_body[:found_at] + token + redacted_body[found_at + len(cell_value) :]
            occupied.append((found_at, found_at + len(token)))
        rebuilt.append(redacted_body + newline)
    return "".join(rebuilt)


def _split_line_ending(line: str) -> tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n"):
        return line[:-1], "\n"
    if line.endswith("\r"):
        return line[:-1], "\r"
    return line, ""


def _unoccupied_index(text: str, needle: str, occupied: list[tuple[int, int]]) -> int | None:
    if not needle:
        return None
    start = 0
    while True:
        index = text.find(needle, start)
        if index < 0:
            return None
        span = (index, index + len(needle))
        if not any(not (span[1] <= left or span[0] >= right) for left, right in occupied):
            return index
        start = index + 1


def redaction_token(label: str, value: str) -> str:
    return f"<redacted:{label}:{stable_fingerprint(value)}>"


def sanitize_untrusted_locator(value: str | None, kind: str = "locator") -> str | None:
    if value is None:
        return None
    cleaned = redact_text(str(value)).replace("\r", " ").replace("\n", " ")
    if UNTRUSTED_DATA_INSTRUCTION.search(cleaned) or DISALLOWED_OUTPUT_CONTROL.search(cleaned):
        return _untrusted_output_ref(cleaned, kind)
    return cleaned


def sanitize_untrusted_text(value: str | None, kind: str = "message") -> str | None:
    """Quarantine instruction-shaped untrusted text while retaining stable triage references."""
    if value is None:
        return None
    cleaned = redact_text(str(value))
    if UNTRUSTED_DATA_INSTRUCTION.search(cleaned) or DISALLOWED_OUTPUT_CONTROL.search(cleaned):
        return _untrusted_output_ref(cleaned, kind, preserve_fingerprints=True)
    return cleaned


def sanitize_mcp_response(value: Any) -> Any:
    """Sanitize every source-controlled string at the MCP serialization boundary."""
    try:
        return _sanitize_mcp_response(value, field_name="", depth=0, active=set())
    except Exception:
        return "<mcp-output-sanitization-failed>"


def _structural_digest(field_name: str, value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9_]+", "_", field_name.strip().casefold()).strip("_")
    digest_field = (
        normalized in {"hash", "fingerprint"}
        or normalized.endswith("_sha256")
        or normalized.endswith("_hash")
        or normalized.endswith("_fingerprint")
    )
    return digest_field and re.fullmatch(r"[0-9a-f]{8,128}", value) is not None


def sanitize_any(value: Any, *, _field_name: str = "") -> Any:
    if isinstance(value, str):
        if _structural_digest(_field_name, value):
            return value
        return redact_text(value)
    if dataclasses.is_dataclass(value):
        return sanitize_any(dataclasses.asdict(value), _field_name=_field_name)
    if isinstance(value, dict):
        return {
            key: sanitize_any(item, _field_name=str(key) if isinstance(key, str) else "")
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_any(item, _field_name=_field_name) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_any(item, _field_name=_field_name) for item in value)
    return value


def _sanitize_mcp_response(
    value: Any,
    *,
    field_name: str,
    depth: int,
    active: set[int],
) -> Any:
    if depth > 64:
        return "<mcp-output-depth-limit>"
    if isinstance(value, str):
        field_kind = _mcp_field_kind(field_name)
        if field_kind == "locator":
            return sanitize_untrusted_locator(value, _locator_kind(field_name))
        return sanitize_untrusted_text(value, field_kind)
    if isinstance(value, (bytes, bytearray, memoryview)):
        decoded = bytes(value).decode("utf-8", errors="replace")
        return _untrusted_output_ref(redact_text(decoded), "binary")
    if dataclasses.is_dataclass(value):
        try:
            return _sanitize_mcp_response(
                dataclasses.asdict(value),
                field_name=field_name,
                depth=depth + 1,
                active=active,
            )
        except Exception:
            return "<mcp-output-dataclass-sanitization-failed>"
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            return "<mcp-output-cycle>"
        active.add(identity)
        try:
            sanitized: dict[Any, Any] = {}
            for key, item in value.items():
                original_key = str(key) if isinstance(key, str) else ""
                safe_key = sanitize_untrusted_text(key, "field-name") if isinstance(key, str) else key
                sanitized[safe_key] = _sanitize_mcp_response(
                    item,
                    field_name=original_key,
                    depth=depth + 1,
                    active=active,
                )
            return sanitized
        finally:
            active.remove(identity)
    if isinstance(value, (list, tuple, set, frozenset)):
        identity = id(value)
        if identity in active:
            return "<mcp-output-cycle>"
        active.add(identity)
        try:
            sanitized_items = [
                _sanitize_mcp_response(
                    item,
                    field_name=field_name,
                    depth=depth + 1,
                    active=active,
                )
                for item in value
            ]
            return tuple(sanitized_items) if isinstance(value, tuple) else sanitized_items
        finally:
            active.remove(identity)
    return value


def _mcp_field_kind(field_name: str) -> str:
    normalized = re.sub(r"[^a-z0-9_]+", "_", str(field_name).strip().lower()).strip("_")
    if normalized in MCP_LOCATOR_FIELDS or normalized.endswith(MCP_LOCATOR_SUFFIXES):
        return "locator"
    if normalized in MCP_MESSAGE_FIELDS or normalized.endswith(MCP_MESSAGE_SUFFIXES):
        return "message"
    return "value"


def _locator_kind(field_name: str) -> str:
    normalized = re.sub(r"[^a-z0-9_-]", "", str(field_name).strip().lower())
    if "url" in normalized or "uri" in normalized or "endpoint" in normalized:
        return "url"
    if "file" in normalized or "path" in normalized or "workspace" in normalized or "manifest" in normalized:
        return "path"
    return "locator"


def _untrusted_output_ref(value: str, kind: str, *, preserve_fingerprints: bool = False) -> str:
    safe_kind = re.sub(r"[^a-z0-9_-]", "", kind.lower()) or "value"
    marker = f"<untrusted-{safe_kind}-ref:{stable_fingerprint(value)}>"
    if not preserve_fingerprints:
        return marker
    retained = _retained_fingerprints(value)
    return marker if not retained else f"{marker} retained_fingerprints={' '.join(retained)}"


def _retained_fingerprints(value: str) -> list[str]:
    retained: list[str] = []
    for match in SAFE_DETECTOR_SUBTYPE.finditer(value):
        retained.append(f"detector_subtype={match.group(1)}")
    for match in SAFE_OUTPUT_FINGERPRINT.finditer(value):
        retained.append(f"{match.group(1).lower()}={match.group(2).lower()}")
    return list(dict.fromkeys(retained))[:6]


def _redact_encoded_tokens(value: str) -> str:
    value = re.sub(r"\b[A-Fa-f0-9]{32,}\b", _redact_hex_if_sensitive, value)
    value = re.sub(r"\b[A-Za-z0-9+/]{16,}={0,2}\b", _redact_base64_if_sensitive, value)
    return value


def _redact_base64_if_sensitive(match: re.Match[str]) -> str:
    import base64

    token = match.group(0)
    try:
        decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=False).decode("utf-8", errors="ignore")
    except Exception:
        return token
    if _looks_sensitive(decoded):
        return redaction_token("ENCODED", token)
    return token


def _redact_hex_if_sensitive(match: re.Match[str]) -> str:
    token = match.group(0)
    try:
        decoded = bytes.fromhex(token).decode("utf-8", errors="ignore")
    except Exception:
        return token
    if _looks_sensitive(decoded):
        return redaction_token("ENCODED", token)
    return token


def _looks_sensitive(decoded: str) -> bool:
    return any(pattern.search(decoded) for _, pattern in ENCODED_REDACTION_PATTERNS)
