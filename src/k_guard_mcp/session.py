from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from k_guard_mcp.collector import is_unsafe_link, read_text


MAX_SESSION_FILE_BYTES = 64 * 1024
MAX_SESSION_LIFETIME = timedelta(hours=24)
SESSION_HEADER_NAMES = {
    "api-key",
    "apikey",
    "authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "x-session-token",
}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class SessionMaterial:
    headers: dict[str, str]
    identity_assertion: dict[str, object] | None
    origin: str
    expires_at: str


def load_session_material(
    path_value: str | Path,
    *,
    base_dir: str | Path,
    target_url: str,
) -> SessionMaterial:
    base = Path(base_dir).resolve(strict=True)
    candidate = Path(path_value)
    if not candidate.is_absolute():
        candidate = base / candidate
    if is_unsafe_link(candidate):
        raise ValueError("session_file links are not allowed")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError("session_file must stay inside the approved workspace boundary") from exc
    if not resolved.is_file():
        raise ValueError("session_file must be a regular file")
    text = read_text(resolved, max_bytes=MAX_SESSION_FILE_BYTES)
    if text is None:
        raise ValueError("session_file is unreadable or exceeds the bounded size")
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValueError("session_file must contain valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("session_file must contain a JSON object")

    origin = _normalized_origin(str(payload.get("origin") or ""), require_origin_only=True)
    target_origin = _normalized_origin(target_url, require_origin_only=False)
    if origin is None or target_origin is None or origin != target_origin:
        raise ValueError("session_file origin must exactly match the probe target origin")

    expires_at = _valid_expiry(payload.get("expires_at"))
    headers = _valid_headers(payload.get("headers"))
    identity_assertion = _valid_identity_assertion(payload.get("identity_assertion"))
    return SessionMaterial(
        headers=headers,
        identity_assertion=identity_assertion,
        origin=_render_origin(origin),
        expires_at=expires_at.isoformat(),
    )


def _normalized_origin(value: str, *, require_origin_only: bool) -> tuple[str, str, int] | None:
    try:
        parsed = urllib.parse.urlparse(str(value or ""))
        scheme = parsed.scheme.casefold()
        host = (parsed.hostname or "").casefold()
        if scheme not in {"http", "https"} or not host or parsed.username is not None or parsed.password is not None:
            return None
        if require_origin_only and (parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
            return None
        port = parsed.port or (443 if scheme == "https" else 80)
        return scheme, host, port
    except (TypeError, ValueError):
        return None


def _render_origin(origin: tuple[str, str, int]) -> str:
    scheme, host, port = origin
    default = 443 if scheme == "https" else 80
    suffix = "" if port == default else f":{port}"
    return f"{scheme}://{host}{suffix}"


def _valid_expiry(value: object) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise ValueError("session_file expires_at is required")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("session_file expires_at must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("session_file expires_at must include a timezone")
    expires = parsed.astimezone(UTC)
    now = datetime.now(UTC)
    if expires <= now:
        raise ValueError("session_file is expired")
    if expires - now > MAX_SESSION_LIFETIME:
        raise ValueError("session_file lifetime must not exceed 24 hours")
    return expires


def _valid_headers(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("session_file headers must be a JSON object")
    headers: dict[str, str] = {}
    for raw_name, raw_value in value.items():
        name = str(raw_name).strip()
        content = str(raw_value)
        if (
            name.casefold() not in SESSION_HEADER_NAMES
            or not content.strip()
            or "\r" in name
            or "\n" in name
            or "\r" in content
            or "\n" in content
        ):
            raise ValueError("session_file contains an unsupported or malformed header")
        headers[name] = content
    if not headers:
        raise ValueError("session_file contains no authentication headers")
    return headers


def _valid_identity_assertion(value: object) -> dict[str, object] | None:
    if value is None or value == "":
        return None
    if not isinstance(value, dict):
        raise ValueError("identity_assertion must be a JSON object")
    path = str(value.get("path") or "")
    expected_hash = str(value.get("expected_body_sha256") or "").casefold()
    try:
        expected_status = int(value.get("expected_status", 200))
    except (TypeError, ValueError) as exc:
        raise ValueError("identity_assertion expected_status is invalid") from exc
    if not _safe_literal_path(path):
        raise ValueError("identity_assertion path is invalid")
    if not 200 <= expected_status < 300:
        raise ValueError("identity_assertion expected_status must be 2xx")
    if _SHA256.fullmatch(expected_hash) is None:
        raise ValueError("identity_assertion expected_body_sha256 is invalid")
    return {
        "path": path,
        "expected_status": expected_status,
        "expected_body_sha256": expected_hash,
    }


def _safe_literal_path(path: str) -> bool:
    return (
        bool(path)
        and len(path) <= 256
        and path.startswith("/")
        and not any(token in path for token in ("{", "}", "?", "#", "\\", "%", ".."))
        and all(ord(char) >= 32 for char in path)
    )
