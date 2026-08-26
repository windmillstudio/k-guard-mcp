from __future__ import annotations

import base64
import json
import math
import re
import time
from dataclasses import dataclass

from k_guard_mcp.ids import IdFactory
from k_guard_mcp.masking import mask_value
from k_guard_mcp.models import Finding


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    label: str
    pattern: re.Pattern[str]
    title: str
    severity: str
    confidence: str
    recommendation: str


class SecretDetector:
    def __init__(self, id_factory: IdFactory | None = None) -> None:
        self.ids = id_factory or IdFactory()
        self.rules = [
            SecretRule(
                "SECRET_PRIVATE_KEY",
                "PRIVATE_KEY",
                re.compile(
                    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[ \t]*\r?\n"
                    r"(?:[A-Za-z0-9+/=]{3,}[ \t]*\r?\n)+"
                    r"-----END [A-Z ]*PRIVATE KEY-----"
                ),
                "Private key block exposed",
                "critical",
                "high",
                "Remove the key, rotate it, and use a secret manager or environment injection.",
            ),
            SecretRule(
                "SECRET_GITHUB_PAT",
                "GITHUB_PAT",
                re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
                "GitHub personal access token exposed",
                "critical",
                "high",
                "Revoke the token and move it to a secret manager.",
            ),
            SecretRule(
                "SECRET_AWS_ACCESS_KEY",
                "AWS_ACCESS_KEY",
                re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
                "AWS access key id exposed",
                "critical",
                "high",
                "Rotate the credential and remove it from source control.",
            ),
            SecretRule(
                "SECRET_JWT",
                "JWT",
                re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
                "JWT token exposed",
                "high",
                "medium",
                "Avoid storing JWTs in code, logs, or fixtures.",
            ),
            SecretRule(
                "SECRET_DB_URL",
                "DB_URL",
                re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^)\s'\"`]+"),
                "Database URL with password exposed",
                "critical",
                "high",
                "Rotate the password and inject the URL through server-side environment variables.",
            ),
            SecretRule(
                "SECRET_DB_URL",
                "DB_URL",
                re.compile(
                    r"\bjdbc:(?:postgresql|mysql|mariadb|sqlserver)://[^\s'\"`]+?"
                    r"(?:\?|&)(?:[^\s'\"`&]+&)*password=[^\s'\"`&]+",
                    re.IGNORECASE,
                ),
                "JDBC database URL with password exposed",
                "critical",
                "high",
                "Rotate the password and inject the JDBC URL through a server-side secret provider.",
            ),
            SecretRule(
                "SECRET_OPENAI_STYLE_KEY",
                "API_KEY",
                re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
                "OpenAI-style API key exposed",
                "critical",
                "medium",
                "Rotate the key if real and keep it out of client-side code and committed files.",
            ),
            SecretRule(
                "SECRET_WEBHOOK_URL",
                "SECRET",
                re.compile(r"https://hooks\.(?:slack|discord)\.com/[^\s'\"`]+"),
                "Webhook URL exposed",
                "high",
                "medium",
                "Rotate the webhook and remove it from source control.",
            ),
        ]

    def scan_text(self, text: str, file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            for match in rule.pattern.finditer(text):
                value = match.group(0)
                if rule.rule_id == "SECRET_DB_URL" and _db_url_password_is_placeholder(value):
                    continue
                line = text.count("\n", 0, match.start()) + 1
                rule_id = rule.rule_id
                confidence = rule.confidence
                severity = rule.severity
                title = rule.title
                why = "A leaked credential can allow unauthorized access or data exfiltration."
                recommendation = rule.recommendation
                evidence = mask_value(rule.label, value)
                if rule.rule_id == "SECRET_DB_URL" and _db_url_is_explicitly_simulated(value, text, match.start()):
                    rule_id = "SECRET_SIMULATED_DB_URL"
                    severity = "info"
                    confidence = "high"
                    title = "Non-routable simulated database credential is present"
                    why = "The reserved example host and nearby simulation statement show this is not a live database credential, but the pattern can still normalize unsafe examples."
                    recommendation = "Keep the example clearly marked and use an unmistakable placeholder password unless the unsafe pattern is the subject of a training fixture."
                    evidence = f"detector_subtype=simulated_non_routable_db_credential {evidence}"
                if rule.rule_id == "SECRET_WEBHOOK_URL" and _webhook_url_is_placeholder(value):
                    rule_id = "SECRET_SIMULATED_WEBHOOK_URL"
                    severity = "info"
                    confidence = "high"
                    title = "Non-live placeholder webhook URL is present"
                    why = "The webhook path is structurally a documented all-zero or repeated placeholder and cannot establish a live credential exposure."
                    recommendation = "Keep the value visibly synthetic and inject real webhook credentials only through an approved secret provider."
                    evidence = f"detector_subtype=simulated_webhook_placeholder {evidence}"
                if rule.label == "API_KEY" and _entropy(value) < 3.2:
                    confidence = "low"
                if rule.rule_id == "SECRET_JWT" and _jwt_is_expired(value):
                    severity = "medium"
                    confidence = "high"
                    title = "Expired JWT remains in a repository artifact"
                    why = "An expired token is not a live credential, but committed auth fixtures can still expose identities, claims, and unsafe handling patterns."
                    recommendation = "Replace the token with a clearly synthetic fixture and keep live session material out of repository artifacts."
                findings.append(
                    Finding(
                        id=self.ids.next(),
                        source="static",
                        rule_id=rule_id,
                        severity=severity,
                        confidence=confidence,
                        title=title,
                        file=file,
                        line_start=line,
                        line_end=line,
                        evidence=evidence,
                        why_it_matters=why,
                        recommendation=recommendation,
                    )
                )
        return findings


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _jwt_is_expired(value: str, now: float | None = None) -> bool:
    try:
        payload = value.split(".", 2)[1]
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        claims = json.loads(decoded.decode("utf-8"))
        expires = claims.get("exp")
        cutoff = time.time() if now is None else now
        return isinstance(expires, (int, float)) and not isinstance(expires, bool) and expires <= cutoff
    except (IndexError, ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        return False


def _db_url_password_is_placeholder(value: str) -> bool:
    uri = re.match(r"^[a-z]+://[^:@/\s]+:(?P<password>[^@/\s]+)@", value, re.IGNORECASE)
    jdbc = re.search(r"[?&]password=(?P<password>[^&\s'\"`]+)", value, re.IGNORECASE)
    match = uri or jdbc
    if match is None:
        return False
    password = match.group("password").strip()
    return bool(
        re.fullmatch(
            r"(?:%[a-z]|\{+[^{}]+\}+|\$\{[^{}]+\}|<[^<>]+>|(?:your[_-]?)?password|changeme)",
            password,
            re.IGNORECASE,
        )
    )


def _db_url_is_explicitly_simulated(value: str, text: str, start: int) -> bool:
    host_match = re.search(
        r"(?:jdbc:[a-z0-9+.-]+|[a-z0-9+.-]+)://(?:[^@/\s]+@)?(?P<host>\[[^\]]+\]|[^/:?#\s]+)",
        value,
        re.IGNORECASE,
    )
    if host_match is None:
        return False
    host = host_match.group("host").strip("[]").lower().rstrip(".")
    if not _is_reserved_example_host(host):
        return False
    context = text[max(0, start - 600) : min(len(text), start + len(value) + 600)]
    return bool(
        re.search(
            r"\b(?:simulat(?:e|ed|es|ing|ion)|demonstrat(?:e|es|ing|ion)|"
            r"no\s+real\s+database|non[- ]?routable|intentionally\s+(?:fake|invalid)|"
            r"dummy\s+database|training\s+(?:fixture|example))\b",
            context,
            re.IGNORECASE,
        )
    )


def _is_reserved_example_host(host: str) -> bool:
    return host in {"example.com", "example.net", "example.org"} or host.endswith(
        (".example.com", ".example.net", ".example.org", ".example", ".invalid", ".test")
    )


def _webhook_url_is_placeholder(value: str) -> bool:
    slack = re.fullmatch(
        r"https://hooks\.slack\.com/services/(?P<team>[^/]+)/(?P<channel>[^/]+)/(?P<token>[^/?#]+)",
        value,
        re.IGNORECASE,
    )
    if slack:
        parts = (slack.group("team"), slack.group("channel"), slack.group("token"))
        return all(re.fullmatch(r"(?:T?0+|B?0+|X+|x+|placeholder|example)", part, re.IGNORECASE) for part in parts)
    discord = re.fullmatch(r"https://hooks\.discord\.com/api/webhooks/(?P<id>0+)/(?P<token>[Xx]+)", value, re.IGNORECASE)
    return discord is not None
