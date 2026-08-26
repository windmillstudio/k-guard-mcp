from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Portions Copyright 2026 Josh Waldrep
# Modifications Copyright 2026 K-Guard MCP Contributors

import base64
import html
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass


# Adapted from Pipelock's Apache-2.0 normalization pipeline. This bounded Python
# implementation and its modifications are recorded in THIRD_PARTY_NOTICES.md.
MAX_SEGMENT_CHARS = 32 * 1024
MAX_DECODED_CHARS = 16 * 1024
MAX_BASE64_TOKENS_PER_SEGMENT = 8
MAX_ROLLING_LINES = 3

_BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/-]{24,8192}={0,2}(?![A-Za-z0-9_+/=-])")
_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})")
_STRING_JOIN = re.compile(r"(?P<quote>['\"])\s*\+\s*(?P=quote)")
_BLOCK_COMMENT = re.compile(r"/\*[^*]{0,256}(?:\*(?!/)[^*]{0,256})*\*/")
_ASCII_REQUIRES_NORMALIZATION = re.compile(r"[^\x09\x0A\x0D\x20-\x7E]")
_LEET_TRANSLATION = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

# Deliberately small: only high-frequency cross-script lookalikes needed by the
# English security phrases in this detector. NFKC already handles full-width and
# presentation forms.
_CONFUSABLE_TRANSLATION = str.maketrans(
    {
        "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J",
        "К": "K", "М": "M", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X",
        "а": "a", "е": "e", "і": "i", "ј": "j", "о": "o", "р": "p", "с": "c",
        "ѕ": "s", "х": "x", "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K",
        "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "α": "a",
        "ε": "e", "ι": "i", "κ": "k", "ο": "o", "Ø": "O", "ø": "o", "Ł": "L",
        "ł": "l", "Đ": "D", "đ": "d",
    }
)


@dataclass(frozen=True)
class ThreatScanCandidate:
    text: str
    line_start: int
    line_end: int
    source_text: str
    transformations: tuple[str, ...] = ()

    @property
    def mode(self) -> str:
        return "+".join(self.transformations) if self.transformations else "direct"


def iter_threat_scan_candidates(text: str) -> list[ThreatScanCandidate]:
    """Return bounded direct and normalized candidates with source line mapping."""

    lines = text.splitlines() or [text]
    candidates: list[ThreatScanCandidate] = []
    seen: set[tuple[int, int, str]] = set()

    for line_no, line in enumerate(lines, start=1):
        _append_segment_candidates(candidates, seen, line, line_no, line_no)

    for width in range(2, MAX_ROLLING_LINES + 1):
        for offset in range(0, max(0, len(lines) - width + 1)):
            segment = " ".join(lines[offset : offset + width])
            if len(segment) > MAX_SEGMENT_CHARS:
                continue
            _append_segment_candidates(candidates, seen, segment, offset + 1, offset + width, rolling=True)
    return candidates


def _append_segment_candidates(
    output: list[ThreatScanCandidate],
    seen: set[tuple[int, int, str]],
    segment: str,
    line_start: int,
    line_end: int,
    *,
    rolling: bool = False,
) -> None:
    if len(segment) > MAX_SEGMENT_CHARS:
        chunks = _bounded_chunks(segment)
    else:
        chunks = [segment]
    for chunk in chunks:
        variants: list[tuple[str, tuple[str, ...]]] = [(chunk, ("rolling_window",) if rolling else ())]

        unicode_text = normalize_for_threat_matching(chunk)
        if unicode_text != chunk:
            variants.append((unicode_text, (("rolling_window",) if rolling else ()) + ("unicode",)))

        decoded = _decode_text_escapes(chunk)
        if decoded != chunk:
            variants.append(
                (
                    normalize_for_threat_matching(decoded),
                    (("rolling_window",) if rolling else ()) + ("escaped_text", "unicode"),
                )
            )

        fragmented = _collapse_fragments(chunk)
        if fragmented != chunk:
            variants.append(
                (
                    normalize_for_threat_matching(fragmented),
                    (("rolling_window",) if rolling else ()) + ("code_fragment", "unicode"),
                )
            )

        normalized_base = unicode_text
        leet = normalized_base.translate(_LEET_TRANSLATION)
        if leet != normalized_base:
            variants.append((leet, (("rolling_window",) if rolling else ()) + ("unicode", "leetspeak")))

        for decoded_base64 in _decode_base64_variants(chunk):
            variants.append(
                (
                    normalize_for_threat_matching(decoded_base64),
                    (("rolling_window",) if rolling else ()) + ("base64", "unicode"),
                )
            )

        for candidate_text, transformations in variants:
            if not candidate_text or len(candidate_text) > MAX_SEGMENT_CHARS * 2:
                continue
            key = (line_start, line_end, candidate_text)
            if key in seen:
                continue
            seen.add(key)
            output.append(
                ThreatScanCandidate(
                    text=candidate_text,
                    line_start=line_start,
                    line_end=line_end,
                    source_text=chunk,
                    transformations=transformations,
                )
            )


def normalize_for_threat_matching(value: str) -> str:
    if value.isascii() and _ASCII_REQUIRES_NORMALIZATION.search(value) is None:
        return value
    value = unicodedata.normalize("NFKC", value)
    output: list[str] = []
    for character in value:
        codepoint = ord(character)
        category = unicodedata.category(character)
        if category == "Cf" or 0xFE00 <= codepoint <= 0xFE0F or 0xE0000 <= codepoint <= 0xE007F:
            continue
        if category in {"Cc", "Cs"} and character not in "\t\r\n":
            continue
        if category.startswith("Z"):
            output.append(" ")
            continue
        output.append(character)
    return "".join(output).translate(_CONFUSABLE_TRANSLATION)


def _decode_text_escapes(value: str) -> str:
    decoded = _UNICODE_ESCAPE.sub(_unicode_escape_replacement, value)
    if "&" in decoded:
        decoded = html.unescape(decoded)
    if "%" in decoded:
        for _ in range(2):
            next_value = urllib.parse.unquote(decoded)
            if next_value == decoded or len(next_value) > MAX_DECODED_CHARS:
                break
            decoded = next_value
    return decoded


def _unicode_escape_replacement(match: re.Match[str]) -> str:
    try:
        return chr(int(match.group(1) or match.group(2), 16))
    except (TypeError, ValueError, OverflowError):
        return match.group(0)


def _collapse_fragments(value: str) -> str:
    collapsed = _STRING_JOIN.sub("", value)
    return _BLOCK_COMMENT.sub("", collapsed)


def _decode_base64_variants(value: str) -> list[str]:
    variants: list[str] = []
    for index, match in enumerate(_BASE64_TOKEN.finditer(value)):
        if index >= MAX_BASE64_TOKENS_PER_SEGMENT:
            break
        token = match.group(0)
        try:
            padded = token + "=" * (-len(token) % 4)
            raw = base64.b64decode(padded, altchars=b"-_", validate=True)
            decoded = raw.decode("utf-8", errors="strict")
        except (ValueError, UnicodeError):
            continue
        if not 8 <= len(decoded) <= MAX_DECODED_CHARS or _printable_ratio(decoded) < 0.90:
            continue
        variants.append(value[: match.start()] + decoded + value[match.end() :])
    return variants


def _printable_ratio(value: str) -> float:
    if not value:
        return 0.0
    printable = sum(character.isprintable() or character in "\r\n\t" for character in value)
    return printable / len(value)


def _bounded_chunks(value: str) -> list[str]:
    overlap = 256
    chunks: list[str] = []
    offset = 0
    while offset < len(value):
        chunks.append(value[offset : offset + MAX_SEGMENT_CHARS])
        offset += MAX_SEGMENT_CHARS - overlap
    return chunks
