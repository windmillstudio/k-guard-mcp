from __future__ import annotations

import json
import re
import shlex
import tomllib
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.ids import IdFactory
from k_guard_mcp.mcp_normalization import ThreatScanCandidate, iter_threat_scan_candidates, normalize_for_threat_matching
from k_guard_mcp.models import Finding


@dataclass(frozen=True)
class McpThreatRule:
    rule_id: str
    severity: str
    confidence: str
    title: str
    pattern: re.Pattern[str]
    why: str
    recommendation: str


RULES = [
    McpThreatRule(
        "MCP_TOOL_POISONING",
        "critical",
        "high",
        "MCP tool poisoning directive",
        re.compile(
            r"(description|tool|inputSchema|schema|prompt|resource).{0,120}"
            r"(ignore (all )?(previous|prior) instructions|do not tell (the )?user|"
            r"hidden instruction|system prompt|developer message|exfiltrat|"
            r"이전 지시.*무시|사용자에게.*말하지|숨겨진 지시)",
            re.IGNORECASE,
        ),
        "A tool description, schema, prompt, or resource appears to include instructions that can poison agent behavior.",
        "Disable the MCP server until the tool metadata is transparent, minimal, and reviewed.",
    ),
    McpThreatRule(
        "MCP_HIDDEN_INSTRUCTION",
        "critical",
        "high",
        "Hidden instruction or prompt-injection directive",
        re.compile(
            r"(ignore (all )?(previous|prior) instructions|do not tell (the )?user|"
            r"hidden instruction|system prompt|developer message|silently|secretly|"
            r"이전 지시.*무시|사용자에게.*말하지|숨겨진 지시|시스템 프롬프트)",
            re.IGNORECASE,
        ),
        "MCP tool metadata, prompts, or bundled docs can poison an agent before the user sees the real intent.",
        "Remove hidden instructions from MCP metadata/prompts and keep tool descriptions behaviorally transparent.",
    ),
    McpThreatRule(
        "MCP_EXFILTRATION_INTENT",
        "critical",
        "high",
        "MCP exfiltration intent",
        re.compile(
            r"(exfiltrat|send.*(secret|token|cookie|credential|env|\.ssh|개인정보|토큰)|"
            r"\b(curl|wget|nc|netcat|scp|ftp|Invoke-WebRequest|iwr)\b.*(token|secret|env|cookie|\.ssh|http)|"
            r"(fetch|axios|requests\.|httpx\.).*(process\.env|os\.environ|cookie|localStorage|sessionStorage)|"
            r"forward[_ -]?(?:env|environment)?.{0,100}(?:full\s+output|environment\s+(?:data|variables?)|env\b))",
            re.IGNORECASE,
        ),
        "A tool or prompt appears to move secrets, cookies, environment data, or personal data outside the trusted boundary.",
        "Block the tool until the outbound data purpose is documented, minimized, and explicitly approved.",
    ),
    McpThreatRule(
        "MCP_DANGEROUS_COMMAND",
        "high",
        "medium",
        "Dangerous MCP command surface",
        re.compile(
            r"(powershell\s+.*-enc|bash\s+-c\s+.*(curl|wget|nc)|cmd\.exe\s+/c\s+.*(curl|powershell)|"
            r"rm\s+-rf\s+[/~]|chmod\s+777|docker\s+run\s+.*--privileged)",
            re.IGNORECASE,
        ),
        "MCP server launch commands can become a local execution bridge for an agent.",
        "Avoid opaque shell wrappers and privileged commands in MCP configs; pin reviewed binaries and arguments.",
    ),
    McpThreatRule(
        "MCP_OVERBROAD_FILE_ACCESS",
        "high",
        "medium",
        "Overbroad filesystem access in MCP setup",
        re.compile(
            r"(--allow-all|--dangerously|/Users/|C:\\\\Users\\\\|~[/\\\\]|/home/|/var/run/docker\.sock|"
            r"\.ssh[/\\\\]|\.aws[/\\\\]|\.config[/\\\\])",
            re.IGNORECASE,
        ),
        "Broad filesystem access lets a compromised or poisoned MCP server read developer secrets and project data.",
        "Scope MCP file access to the project directory and exclude home, SSH, cloud, browser, and Docker socket paths.",
    ),
    McpThreatRule(
        "MCP_TOOL_SHADOWING_ADVISORY",
        "info",
        "low",
        "Possible tool shadowing or trust spoofing advisory",
        re.compile(
            r"(official|trusted|safe|secure|verified|공식|신뢰|안전|검증).{0,80}"
            r"(read_file|write_file|shell|browser|gmail|drive|slack|파일|쉘|브라우저|메일)",
            re.IGNORECASE,
        ),
        "A malicious tool can imitate trusted capabilities or overstate trust in its name/description.",
        "Verify the server package source, tool descriptions, and command path before enabling it. This advisory does not block CI by default.",
    ),
    McpThreatRule(
        "AGENT_SKILL_REMOTE_EXECUTION",
        "critical",
        "high",
        "Agent skill downloads content directly into a command interpreter",
        re.compile(
            r"(?:\b(?:curl|wget)\b[^\n\r|]{0,240}\|\s*(?:sudo\s+)?(?:bash|sh|zsh|pwsh|powershell)\b|"
            r"\b(?:iwr|Invoke-WebRequest)\b[^\n\r|]{0,240}\|\s*(?:iex|Invoke-Expression)\b|"
            r"\b(?:eval|exec|Invoke-Expression|iex)\s*\([^\n\r]{0,240}(?:curl|wget|requests\.|httpx\.|fetch\())",
            re.IGNORECASE,
        ),
        "A skill or agent instruction can turn mutable remote content into local code before the user can review it.",
        "Download to a bounded file, verify an immutable digest or signature, and execute only the reviewed artifact with explicit approval.",
    ),
    McpThreatRule(
        "AGENT_SKILL_CREDENTIAL_ACCESS",
        "high",
        "high",
        "Agent skill requests access to developer credential stores",
        re.compile(
            r"(?:read|copy|collect|upload|send|inspect|export|cat|type|Get-Content|읽|복사|수집|전송).{0,120}"
            r"(?:\.ssh[/\\]|\.aws[/\\]|\.kube[/\\]|credentials(?:\.json)?|id_rsa|id_ed25519|"
            r"browser\s+(?:cookies?|profiles?)|keychain|credential\s+manager|토큰|자격\s*증명)",
            re.IGNORECASE,
        ),
        "Agent instructions that reach credential stores can expose accounts far beyond the project being reviewed.",
        "Remove credential-store access, use a narrowly scoped secret reference, and require a separate operator-approved capability when access is unavoidable.",
    ),
]


MCP_FILE_HINT = re.compile(r"(mcp|claude|cursor|windsurf|gemini|cline|codex|grok|antigravity)", re.IGNORECASE)
MCP_CONTEXT_DIRECTORIES = {
    ".mcp", ".claude", ".cursor", ".windsurf", ".gemini", ".cline", ".codex", ".grok",
    "antigravity", "tools", "prompts", "skills", "agents",
}
AGENT_INSTRUCTION_NAMES = {"skill.md", "agents.md", "copilot-instructions.md"}
AGENT_CLIENT_DIRECTORIES = {".claude", ".cursor", ".gemini", ".codex", ".grok", ".agents", "antigravity"}
MAX_STRUCTURED_DEPTH = 8
MAX_STRUCTURED_SERVER_ENTRIES = 256
MAX_STRUCTURED_NAMED_VALUES = 1024
ACTIVATION_DEPENDENT_RULES = frozenset(
    {
        "MCP_AUTOMATIC_TOOL_APPROVAL",
        "MCP_INSECURE_REMOTE_TRANSPORT",
        "MCP_MUTABLE_GIT_SOURCE",
        "MCP_OVERBROAD_FILESYSTEM_SCOPE",
        "MCP_PRIVILEGED_CONTAINER_SURFACE",
        "MCP_SHELL_WRAPPER_EXECUTION",
        "MCP_UNPINNED_PACKAGE_EXECUTION",
    }
)
MCP_DOCUMENT_CONTEXT = re.compile(
    r'(?:'
    r'["\']mcpServers["\']\s*:|'
    r'\[?\bmcp_servers(?:\.|\])|'
    r'\bmodelcontextprotocol\b|'
    r'\bFastMCP\s*\(|'
    r'@mcp\.(?:tool|prompt|resource)\b|'
    r'\b(?:registerTool|registerPrompt|registerResource)\s*\(|'
    r'\b(?:tools|prompts|resources)/(?:list|get|call|read)\b|'
    r'["\']inputSchema["\']\s*:|'
    r'\bClientSession\s*\([^\n]{0,160}\b(?:stdio|sse|streamable)|'
    r'\bStdioServerParameters\s*\('
    r')',
    re.IGNORECASE,
)


class McpThreatDetector:
    def __init__(self, id_factory: IdFactory | None = None) -> None:
        self.ids = id_factory or IdFactory()

    def scan_text(self, text: str, file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        if not is_mcp_adjacent_text(file, text):
            return findings
        seen: set[tuple[str, int]] = set()
        matched_lines: dict[str, set[int]] = {}
        for candidate in iter_threat_scan_candidates(text):
            if _comment_only_candidate(candidate.source_text):
                continue
            for rule in RULES:
                if not rule.pattern.search(candidate.text):
                    continue
                covered_lines = set(range(candidate.line_start, candidate.line_end + 1))
                if "rolling_window" in candidate.transformations and matched_lines.get(rule.rule_id, set()).intersection(covered_lines):
                    continue
                key = (rule.rule_id, candidate.line_start)
                if key in seen:
                    continue
                seen.add(key)
                matched_lines.setdefault(rule.rule_id, set()).update(covered_lines)
                confidence = _candidate_confidence(rule.confidence, candidate)
                findings.append(
                    Finding(
                        id=self.ids.next(),
                        source="mcp-threat",
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        confidence=confidence,
                        title=rule.title,
                        file=file,
                        line_start=candidate.line_start,
                        line_end=candidate.line_end,
                        method=f"normalized-text:{candidate.mode}",
                        evidence=(
                            f"segment_hash={evidence_hash(candidate.source_text)} scheme={evidence_hash_scheme()} "
                            f"matched={rule.rule_id} detector_subtype={_candidate_subtype(candidate)} "
                            f"normalization={candidate.mode} raw_returned=false"
                        ),
                        why_it_matters=rule.why,
                        recommendation=rule.recommendation,
                        audit_depth=3 if candidate.transformations else 2,
                        inspected_scope="MCP-adjacent text was scanned with direct, bounded Unicode/encoding normalization, split-fragment, and rolling-window no-exec passes.",
                        not_inspected="This static check does not execute the MCP server, prove semantic intent, or decode arbitrary encrypted/compressed payloads.",
                    )
                )
        findings.extend(self._scan_structured_config(text, file))
        return findings

    def _scan_structured_config(
        self,
        text: str,
        file: str | None,
    ) -> list[Finding]:
        document = _parse_config_document(text, file)
        if document is None:
            return []
        findings: list[Finding] = []
        coverage_gaps = _structured_config_coverage_gaps(document)
        if coverage_gaps:
            findings.append(
                Finding(
                    id=self.ids.next(),
                    source="mcp-config-structure",
                    rule_id="MCP_CONFIG_STRUCTURE_INCOMPLETE",
                    severity="high",
                    confidence="high",
                    title="MCP configuration structure exceeded a reviewed bound",
                    file=file,
                    line_start=1,
                    line_end=1,
                    method="structured-config-coverage",
                    evidence=(
                        f"gap_refs={','.join(evidence_hash(item) for item in coverage_gaps)} "
                        f"server_limit={MAX_STRUCTURED_SERVER_ENTRIES} value_limit={MAX_STRUCTURED_NAMED_VALUES} "
                        f"depth_limit={MAX_STRUCTURED_DEPTH} scheme={evidence_hash_scheme()} raw_returned=false"
                    ),
                    why_it_matters="A release gate cannot clear an MCP configuration when server entries or nested permission fields were omitted by a parser bound.",
                    recommendation="Split the configuration or raise the reviewed bounds, then rerun until the structured coverage finding is absent.",
                    audit_depth=4,
                    inspected_scope="The parsed JSON/TOML tree was counted before bounded server and field checks ran.",
                    not_inspected="Entries beyond the reported structural bound were not classified; this finding intentionally fails closed.",
                )
            )
        structured_seen: set[tuple[str, int, str]] = set()
        for server_name, server in _iter_server_entries(document):
            line = _server_line(text, server_name)
            checks = _structured_server_checks(server)
            for rule_id, severity, confidence, title, subtype, why, recommendation in checks:
                server_name_hash = evidence_hash(server_name)
                key = (rule_id, line, server_name_hash)
                if key in structured_seen:
                    continue
                structured_seen.add(key)
                findings.append(
                    Finding(
                        id=self.ids.next(),
                        source="mcp-config-structure",
                        rule_id=rule_id,
                        severity=severity,
                        confidence=confidence,
                        title=title,
                        file=file,
                        line_start=line,
                        line_end=line,
                        method="structured-json",
                        evidence=(
                            f"server_name_hash={server_name_hash} config_hash={evidence_hash(text)} "
                            f"activation_state={'disabled' if _server_is_explicitly_disabled(server) else 'enabled_or_unspecified'} "
                            f"scheme={evidence_hash_scheme()} detector_subtype={subtype} raw_returned=false"
                        ),
                        why_it_matters=why,
                        recommendation=recommendation,
                        audit_depth=4,
                        inspected_scope="The MCP JSON server map, command, arguments, transport URL, headers, and environment shape were parsed without executing the server.",
                        not_inspected="Package contents, registry ownership, remote TLS identity, and runtime behavior were not verified by this static config pass.",
                    )
                )
        return findings


def _mcp_file_hint(file: str | None) -> bool:
    parts = [part for part in str(file or "").replace("\\", "/").split("/") if part]
    if not parts:
        return False
    lowered = [part.casefold() for part in parts]
    return (
        MCP_FILE_HINT.search(parts[-1]) is not None
        or lowered[-1] in AGENT_INSTRUCTION_NAMES
        or any(part in AGENT_CLIENT_DIRECTORIES for part in lowered[:-1])
        or (len(parts) > 1 and lowered[-2] in MCP_CONTEXT_DIRECTORIES)
    )


def is_mcp_adjacent_text(file: str | None, text: str) -> bool:
    """Return true only for active MCP paths or text with MCP protocol structure."""
    if _mcp_file_hint(file) or MCP_DOCUMENT_CONTEXT.search(text) is not None:
        return True
    normalized = normalize_for_threat_matching(text)
    return normalized != text and MCP_DOCUMENT_CONTEXT.search(normalized) is not None


def _candidate_confidence(default: str, candidate: ThreatScanCandidate) -> str:
    if {"base64", "leetspeak", "code_fragment"}.intersection(candidate.transformations):
        return "medium" if default == "high" else default
    return default


def _candidate_subtype(candidate: ThreatScanCandidate) -> str:
    if not candidate.transformations:
        return "direct_mcp_text"
    return "normalized_mcp_evasion"


def _comment_only_candidate(value: str) -> bool:
    stripped = value.lstrip()
    if not stripped:
        return False
    if stripped.startswith(("#", "//", "*", ";")):
        return True
    if stripped.startswith("/*"):
        closing = stripped.find("*/", 2)
        return closing < 0 or not stripped[closing + 2 :].strip()
    if stripped.startswith("<!--"):
        closing = stripped.find("-->", 4)
        return closing < 0 or not stripped[closing + 3 :].strip()
    return False


def _iter_server_entries(value: Any, depth: int = 0) -> list[tuple[str, dict[str, Any]]]:
    if depth > MAX_STRUCTURED_DEPTH:
        return []
    entries: list[tuple[str, dict[str, Any]]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"mcpServers", "mcp_servers", "servers"} and isinstance(child, dict):
                entries.extend((str(name), server) for name, server in child.items() if isinstance(server, dict))
            else:
                entries.extend(_iter_server_entries(child, depth + 1))
    elif isinstance(value, list):
        for child in value[:MAX_STRUCTURED_SERVER_ENTRIES]:
            entries.extend(_iter_server_entries(child, depth + 1))
    return entries[:MAX_STRUCTURED_SERVER_ENTRIES]


def _structured_config_coverage_gaps(value: Any) -> tuple[str, ...]:
    gaps: set[str] = set()
    server_count = 0
    named_value_count = 0

    def walk(node: Any, depth: int) -> None:
        nonlocal server_count, named_value_count
        if depth > MAX_STRUCTURED_DEPTH:
            gaps.add("depth_limit")
            return
        if isinstance(node, dict):
            named_value_count += len(node)
            if len(node) > MAX_STRUCTURED_SERVER_ENTRIES:
                gaps.add("container_entry_limit")
            if named_value_count > MAX_STRUCTURED_NAMED_VALUES:
                gaps.add("named_value_limit")
            for key, child in node.items():
                if key in {"mcpServers", "mcp_servers", "servers"} and isinstance(child, dict):
                    server_count += sum(1 for server in child.values() if isinstance(server, dict))
                    if server_count > MAX_STRUCTURED_SERVER_ENTRIES:
                        gaps.add("server_entry_limit")
                walk(child, depth + 1)
        elif isinstance(node, list):
            named_value_count += len(node)
            if len(node) > MAX_STRUCTURED_SERVER_ENTRIES or named_value_count > MAX_STRUCTURED_NAMED_VALUES:
                gaps.add("named_value_limit")
            for child in node:
                walk(child, depth + 1)

    walk(value, 0)
    return tuple(sorted(gaps))


def _structured_server_checks(server: dict[str, Any]) -> list[tuple[str, str, str, str, str, str, str]]:
    checks: list[tuple[str, str, str, str, str, str, str]] = []
    command = str(server.get("command") or "").strip()
    args_value = server.get("args")
    args = [str(item) for item in args_value] if isinstance(args_value, list) else []
    command_name = _normalized_executable_name(command)

    if command_name in {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"} and any(
        arg.casefold() in {"-c", "/c", "-command", "-encodedcommand", "-enc"} for arg in args
    ):
        checks.append(
            (
                "MCP_SHELL_WRAPPER_EXECUTION",
                "high",
                "high",
                "MCP server is launched through a general-purpose shell",
                "structured_shell_wrapper",
                "Shell wrappers enlarge the execution surface and make the effective MCP command harder to review or pin.",
                "Launch a reviewed executable directly with a fixed argument vector and remove command-string shell interpretation.",
            )
        )

    package = _launcher_package(command_name, args)
    if package and _registry_package_requires_pin(package):
        checks.append(
            (
                "MCP_UNPINNED_PACKAGE_EXECUTION",
                "high",
                "high",
                "MCP server package is executed without an immutable version",
                "structured_unpinned_registry_launcher",
                "A mutable registry tag can change the code an MCP client executes between reviews.",
                "Pin the MCP package to an exact reviewed version or immutable commit and verify its lockfile or provenance before enabling it.",
            )
        )

    for url_value in _server_urls(server):
        parsed = urlparse(url_value)
        host = (parsed.hostname or "").casefold()
        if parsed.scheme.casefold() == "http" and host not in {"localhost", "127.0.0.1", "::1"}:
            checks.append(
                (
                    "MCP_INSECURE_REMOTE_TRANSPORT",
                    "high",
                    "high",
                    "Remote MCP transport does not use TLS",
                    "structured_plaintext_remote_transport",
                    "Plain HTTP can expose MCP requests, tool results, credentials, and personal data to interception or modification.",
                    "Use HTTPS with a reviewed endpoint identity, or bind plain HTTP strictly to loopback behind a trusted local proxy.",
                )
            )
            break

    if _has_static_credential(server):
        checks.append(
            (
                "MCP_STATIC_CREDENTIAL_IN_CONFIG",
                "high",
                "high",
                "MCP configuration appears to contain a fixed credential",
                "structured_static_credential",
                "Credentials stored directly in MCP configuration are easily copied into backups, logs, support bundles, or source control.",
                "Move the credential to a scoped secret store or environment reference, rotate the exposed value, and keep it out of committed config.",
            )
        )
    if _has_auto_approval(server):
        checks.append(
            (
                "MCP_AUTOMATIC_TOOL_APPROVAL",
                "critical",
                "high",
                "MCP server tools are configured for automatic approval",
                "structured_automatic_tool_approval",
                "Automatic approval removes the user decision point before an MCP tool can read data or perform actions.",
                "Disable automatic approval and allow only individually reviewed read-only tools; require explicit approval for every state-changing capability.",
            )
        )
    if _has_overbroad_filesystem_scope(server):
        checks.append(
            (
                "MCP_OVERBROAD_FILESYSTEM_SCOPE",
                "high",
                "high",
                "MCP server receives an overbroad filesystem scope",
                "structured_overbroad_filesystem_scope",
                "Home, root, credential directories, or the Docker socket expose data and execution surfaces outside the reviewed project.",
                "Bind the server to the single reviewed project directory and explicitly deny home, credential, browser, cloud, and container-runtime paths.",
            )
        )
    if _has_privileged_container_surface(command_name, args):
        checks.append(
            (
                "MCP_PRIVILEGED_CONTAINER_SURFACE",
                "critical",
                "high",
                "MCP server launcher grants host-level container privileges",
                "structured_privileged_container_surface",
                "Privileged containers, host namespaces, root mounts, or Docker socket access can turn an MCP tool into host control.",
                "Remove privileged and host namespace flags, use a read-only project mount, drop capabilities, and keep the container runtime socket unavailable.",
            )
        )
    if _has_mutable_git_source(server):
        checks.append(
            (
                "MCP_MUTABLE_GIT_SOURCE",
                "high",
                "high",
                "MCP server source is fetched from a mutable Git reference",
                "structured_mutable_git_source",
                "A branch, tag, or unqualified repository URL can execute different code after the review without changing local configuration.",
                "Pin the source to a full immutable commit, verify the fetched tree digest, and retain that provenance in the release evidence bundle.",
            )
        )
    if not _server_is_explicitly_disabled(server):
        return checks
    return [
        (
            rule_id,
            severity,
            "medium" if confidence == "high" and rule_id in ACTIVATION_DEPENDENT_RULES else confidence,
            title,
            subtype,
            why,
            recommendation,
        )
        for rule_id, severity, confidence, title, subtype, why, recommendation in checks
    ]


def _iter_named_values(value: Any, depth: int = 0) -> list[tuple[str, Any]]:
    if depth > MAX_STRUCTURED_DEPTH:
        return []
    rows: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in list(value.items())[:MAX_STRUCTURED_SERVER_ENTRIES]:
            rows.append((str(key), child))
            rows.extend(_iter_named_values(child, depth + 1))
    elif isinstance(value, list):
        for child in value[:MAX_STRUCTURED_SERVER_ENTRIES]:
            rows.extend(_iter_named_values(child, depth + 1))
    return rows[:MAX_STRUCTURED_NAMED_VALUES]


def _has_auto_approval(server: dict[str, Any]) -> bool:
    approval_keys = {
        "autoapprove",
        "auto_approve",
        "alwaysallow",
        "always_allow",
        "dangerouslyskippermissions",
        "dangerously_skip_permissions",
        "skipapproval",
        "skip_approval",
    }
    for key, value in _iter_named_values(server):
        if key.casefold() not in approval_keys:
            continue
        if value is True or isinstance(value, (list, dict)) and bool(value):
            return True
        if isinstance(value, str) and value.strip().casefold() in {"true", "all", "always", "*"}:
            return True
    return False


def _server_is_explicitly_disabled(server: dict[str, Any]) -> bool:
    disabled = server.get("disabled")
    enabled = server.get("enabled")
    disabled_true = disabled is True or disabled == 1 or (
        isinstance(disabled, str) and disabled.strip().casefold() in {"true", "yes", "1"}
    )
    enabled_false = enabled is False or enabled == 0 or (
        isinstance(enabled, str) and enabled.strip().casefold() in {"false", "no", "0"}
    )
    return disabled_true or enabled_false


def _has_overbroad_filesystem_scope(server: dict[str, Any]) -> bool:
    scope_keys = {
        "roots",
        "root",
        "directories",
        "alloweddirectories",
        "allowed_directories",
        "workspacepaths",
        "workspace_paths",
        "mounts",
        "volumes",
        "filesystem",
    }
    candidates: list[str] = []
    for key, value in _iter_named_values(server):
        if key.casefold() in scope_keys:
            candidates.extend(_flatten_string_values(value))
    args = server.get("args")
    if isinstance(args, list):
        candidates.extend(str(item) for item in args)
    rendered_args = " ".join(str(item) for item in args).replace("\\", "/").casefold() if isinstance(args, list) else ""
    root_mount = bool(
        re.search(r"(?:^|\s)(?:-v|--volume)(?:=|\s+)/:(?:/|[^\s]+)", rendered_args)
        or re.search(r"(?:^|\s)--mount(?:=|\s+)[^\s]*(?:^|,)type=bind(?:,|$)[^\s]*(?:^|,)(?:src|source)=/(?:,|$)", rendered_args)
    )
    return root_mount or any(_overbroad_path_value(value) for value in candidates)


def _flatten_string_values(value: Any, depth: int = 0) -> list[str]:
    if depth > 5:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in list(value.values())[:128] for item in _flatten_string_values(child, depth + 1)]
    if isinstance(value, list):
        return [item for child in value[:128] for item in _flatten_string_values(child, depth + 1)]
    return []


def _overbroad_path_value(value: str) -> bool:
    normalized = str(value or "").strip().replace("\\", "/").casefold()
    if not normalized:
        return False
    if normalized in {"/", "~", "~/", "/home", "/users", "c:/users"}:
        return True
    return any(
        marker in normalized
        for marker in (
            "/.ssh",
            "/.aws",
            "/.kube",
            "/var/run/docker.sock",
            "//var/run/docker.sock",
            ":/var/run/docker.sock",
        )
    ) or bool(re.fullmatch(r"[a-z]:/users/[^/]+/?", normalized))


def _has_privileged_container_surface(command_name: str, args: list[str]) -> bool:
    if not _container_launcher_present(command_name, args):
        return False
    rendered = " ".join((command_name, *args)).replace("\\", "/").casefold()
    if any(
        marker in rendered
        for marker in (
            "--privileged",
            "--pid=host",
            "--pid host",
            "--network=host",
            "--network host",
            "--ipc=host",
            "--ipc host",
            "--userns=host",
            "--userns host",
            "--uts=host",
            "--uts host",
            "--cgroupns=host",
            "--cgroupns host",
            "--cap-add=all",
            "--cap-add all",
            "--cap-add=sys_admin",
            "--cap-add sys_admin",
            "--device=",
            "--device ",
            "seccomp=unconfined",
            "apparmor=unconfined",
            "/var/run/docker.sock",
            "-v /:/",
            "--volume /:/",
        )
    ):
        return True
    mount_values: list[str] = []
    for index, arg in enumerate(args):
        lowered = arg.replace("\\", "/").casefold()
        if lowered == "--mount" and index + 1 < len(args):
            mount_values.append(args[index + 1].replace("\\", "/").casefold())
        elif lowered.startswith("--mount="):
            mount_values.append(lowered.split("=", 1)[1])
    return any(
        "type=bind" in value
        and re.search(r"(?:^|,)(?:src|source)=/(?:,|$)", value) is not None
        for value in mount_values
    )


def _container_launcher_present(command_name: str, args: list[str]) -> bool:
    return _container_command_tokens_present([command_name, *args], depth=0)


def _container_command_tokens_present(tokens: list[str], *, depth: int) -> bool:
    if not tokens or depth > 4:
        return False
    tools = {"docker", "docker.exe", "docker-compose", "docker-compose.exe", "podman", "podman.exe", "nerdctl", "nerdctl.exe"}
    wrappers = {
        "chrt",
        "command",
        "command.exe",
        "env",
        "env.exe",
        "ionice",
        "nice",
        "nohup",
        "setsid",
        "sudo",
        "sudo.exe",
        "timeout",
    }
    shells = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
    command = _normalized_executable_name(tokens[0])
    if command in tools:
        return True
    if command in shells:
        for index, token in enumerate(tokens[1:], start=1):
            if str(token).casefold() not in {"-c", "/c", "-command", "-encodedcommand", "-enc"} or index + 1 >= len(tokens):
                continue
            try:
                nested = shlex.split(str(tokens[index + 1]), posix=True)
            except ValueError:
                nested = str(tokens[index + 1]).replace('"', " ").replace("'", " ").split()
            if _container_command_tokens_present(nested, depth=depth + 1):
                return True
        rendered = " ".join(str(item) for item in tokens[1:]).replace("\\", "/").casefold()
        return _container_tool_text_present(rendered)
    if command not in wrappers:
        return False
    for index, token in enumerate(tokens[1:], start=1):
        normalized = _normalized_executable_name(token)
        if normalized in tools:
            return True
        if normalized in shells or normalized in wrappers:
            if _container_command_tokens_present([normalized, *tokens[index + 1 :]], depth=depth + 1):
                return True
    return _container_tool_text_present(" ".join(str(item) for item in tokens[1:]).replace("\\", "/").casefold())


def _container_tool_text_present(value: str) -> bool:
    return re.search(
        r"(?:^|[\s;&|`'\"(])(?:\$\([^)]*\s+)?(?:[a-z]:)?(?:/[^\s;&|`'\"()]+/)?"
        r"(?:docker|docker-compose|podman|nerdctl)(?:\.exe)?(?:[\s;&|`'\")]|$)",
        value,
    ) is not None


def _normalized_executable_name(value: object) -> str:
    normalized = str(value or "").strip().strip("'\"").replace("\\", "/").rstrip("/")
    return normalized.rsplit("/", 1)[-1].casefold()


def _has_mutable_git_source(server: dict[str, Any]) -> bool:
    values = _flatten_string_values(server)
    for value in values:
        lowered = value.casefold()
        if not any(marker in lowered for marker in ("git+", "github:", "github.com/", "gitlab.com/", "bitbucket.org/")):
            continue
        fragments = re.findall(r"(?:@|#)([0-9a-z._/-]+)", lowered)
        if not fragments or not any(re.fullmatch(r"[0-9a-f]{40,64}", fragment) for fragment in fragments):
            return True
    return False


def _launcher_package(command_name: str, args: list[str]) -> str | None:
    if command_name not in {"npx", "npx.cmd", "uvx", "pipx", "bunx", "pnpx"}:
        return None
    package_value_flags = {
        "npx": {"--package", "-p"},
        "npx.cmd": {"--package", "-p"},
        "uvx": {"--from"},
        "pipx": {"--spec"},
    }.get(command_name, set())
    option_value_flags = {
        "npx": {
            "--cache", "--loglevel", "--node-options", "--prefix", "--registry",
            "--script-shell", "--userconfig", "--workspace", "-w",
        },
        "npx.cmd": {
            "--cache", "--loglevel", "--node-options", "--prefix", "--registry",
            "--script-shell", "--userconfig", "--workspace", "-w",
        },
        "uvx": {
            "--config-file", "--default-index", "--directory", "--exclude-newer",
            "--extra-index-url", "--find-links", "--index", "--index-url", "--keyring-provider",
            "--project", "--python", "--python-downloads", "--python-platform",
            "--python-preference", "--python-version", "--refresh-package", "--resolution", "-p",
        },
        "pipx": {"--fetch-missing-python", "--index-url", "--pip-args", "--python", "--suffix"},
    }.get(command_name, set())
    command_value_flags = {"--call", "-c"} if command_name in {"npx", "npx.cmd"} else set()

    index = 0
    skipped_pipx_subcommand = False
    while index < len(args):
        arg = args[index]
        lowered = arg.casefold()
        if lowered in package_value_flags:
            return args[index + 1] if index + 1 < len(args) else None
        package_prefix = next((f"{flag}=" for flag in package_value_flags if lowered.startswith(f"{flag}=")), None)
        if package_prefix is not None:
            return arg.split("=", 1)[1]
        if lowered in command_value_flags or any(lowered.startswith(f"{flag}=") for flag in command_value_flags):
            return None
        if lowered in option_value_flags:
            index += 2
            continue
        if any(lowered.startswith(f"{flag}=") for flag in option_value_flags):
            index += 1
            continue
        if arg.startswith("-"):
            index += 1
            continue
        if command_name == "pipx" and not skipped_pipx_subcommand and lowered in {"run", "runpip"}:
            skipped_pipx_subcommand = True
            index += 1
            continue
        return arg
    return None


def _package_is_pinned(package: str) -> bool:
    lowered = package.casefold()
    if any(marker in lowered for marker in ("git+", "github:", "github.com/", "gitlab.com/", "bitbucket.org/")):
        fragments = re.findall(r"(?:@|#)([0-9a-f]{40,64})(?:\b|$)", lowered)
        return bool(fragments)
    if lowered in {".", ".."} or (
        "/" in package and (package.startswith(("./", "../", "/")) or ":/" in package)
    ):
        return False
    if "==" in package:
        return _immutable_version(package.rsplit("==", 1)[-1])
    if package.startswith("@"):
        separator = package.rfind("@")
        return separator > package.find("/") and _immutable_version(package[separator + 1 :])
    if "@" in package:
        return _immutable_version(package.rsplit("@", 1)[-1])
    return False


def _registry_package_requires_pin(package: str) -> bool:
    lowered = package.casefold().strip()
    if any(marker in lowered for marker in ("git+", "github:", "github.com/", "gitlab.com/", "bitbucket.org/")):
        return False
    if lowered in {".", ".."} or lowered.startswith(("./", "../", "/", "file:", "link:", "workspace:")):
        return False
    if ":/" in lowered or re.fullmatch(r"v?\d+(?:\.\d+){1,3}", lowered):
        return False
    npm_spec = re.fullmatch(
        r"(?:@[a-z0-9._-]+/[a-z0-9._-]+|[a-z0-9][a-z0-9._-]*)(?:@[^\s/]+|==[^\s/]+)?",
        lowered,
    )
    python_spec = re.fullmatch(
        r"[a-z0-9][a-z0-9._-]*(?:\[[a-z0-9,._-]+\])?"
        r"(?:(?:===|==|~=|!=|<=|>=|<|>)[^\s/]+)?",
        lowered,
    )
    return (npm_spec is not None or python_spec is not None) and not _package_is_pinned(package)


def _immutable_version(value: str) -> bool:
    lowered = value.casefold().strip()
    exact_release = re.fullmatch(r"v?\d+(?:\.\d+){1,3}(?:-[0-9a-z.-]+)?(?:\+[0-9a-z.-]+)?", lowered)
    return exact_release is not None


def _server_urls(server: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    url_keys = {"url", "serverurl", "server_url", "endpoint"}
    for key, value in _iter_named_values(server):
        if key.casefold() in url_keys and isinstance(value, str) and value:
            urls.append(value)
    return urls


def _has_static_credential(server: dict[str, Any]) -> bool:
    credential_name = re.compile(r"(?:authorization|api[_-]?key|access[_-]?token|client[_-]?secret|password)", re.IGNORECASE)
    reference = re.compile(r"(?:\$\{|\$env:|process\.env|os\.environ|secret://|env://)", re.IGNORECASE)
    for key, value in _iter_named_values(server):
        if (
            credential_name.search(str(key))
            and isinstance(value, str)
            and value.strip()
            and not reference.search(value)
            and not _credential_placeholder(value)
        ):
            return True
    return False


def _credential_placeholder(value: str) -> bool:
    candidate = value.strip().strip('"\'').strip()
    candidate = re.sub(r"^(?:bearer|basic|token)\s+", "", candidate, flags=re.IGNORECASE).strip()
    if not candidate:
        return True
    if re.fullmatch(r"<[^<>]{1,96}>", candidate):
        return True
    normalized = re.sub(r"[\s.-]+", "_", candidate.casefold()).strip("_")
    normalized_core = re.sub(r"_(?:here|value)$", "", normalized)
    if normalized_core in {
        "api_key",
        "api_key_here",
        "changeme",
        "change_me",
        "client_secret",
        "dummy",
        "example",
        "insert_here",
        "password",
        "paste_here",
        "placeholder",
        "replace_me",
        "secret",
        "token",
        "token_here",
        "xxx",
        "xxxxx",
    }:
        return True
    if normalized_core.startswith(("your_", "example_", "sample_", "dummy_", "fake_")) and re.search(
        r"(?:api_?key|access_?token|personal_?access_?token|client_?secret|password|secret|token|key)$",
        normalized_core,
    ):
        return True
    return bool(
        re.fullmatch(
            r"(?:your|replace|insert|enter|paste|example|sample|dummy|fake|placeholder|changeme)_?"
            r"(?:api_?key|access_?token|personal_?access_?token|client_?secret|password|secret|token|key|value)?",
            normalized_core,
        )
    )


def _server_line(text: str, server_name: str) -> int:
    quoted = json.dumps(server_name, ensure_ascii=False)
    for line_no, line in enumerate(text.splitlines(), start=1):
        if quoted in line or server_name in line:
            return line_no
    return 1


def _parse_config_document(text: str, file: str | None) -> Any | None:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    if str(file or "").lower().endswith(".toml") or "mcp_servers" in text.casefold():
        try:
            return tomllib.loads(text)
        except (tomllib.TOMLDecodeError, TypeError, ValueError):
            return None
    return None
