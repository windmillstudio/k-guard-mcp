from __future__ import annotations

import json
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from k_guard_mcp.detectors import McpThreatDetector, PiiDetector, SecretDetector
from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.ids import IdFactory
from k_guard_mcp.models import Finding, ScanResult
from k_guard_mcp.privacy_taxonomy import metadata_for_labels
from k_guard_mcp.redaction import redact_text, sanitize_any


RECENT_SENSITIVE_MAX_EVENT_DISTANCE = 4
RECENT_SENSITIVE_MAX_AGE_SECONDS = 30.0
DEFAULT_MAX_RUNTIME_SESSIONS = 256
DEFAULT_RUNTIME_SESSION_IDLE_SECONDS = 300.0


@dataclass(frozen=True)
class SensitiveRuntimeEvent:
    index: int
    tool: str
    labels: Counter[str]
    content_hash: str
    observed_at: float
    correlation_keys: frozenset[str]


@dataclass
class RuntimeSessionState:
    event_count: int = 0
    recent_sensitive: list[SensitiveRuntimeEvent] = field(default_factory=list)
    last_seen_at: float = field(default_factory=time.monotonic)


class McpRuntimeObserver:
    def __init__(
        self,
        id_factory: IdFactory | None = None,
        *,
        max_sessions: int = DEFAULT_MAX_RUNTIME_SESSIONS,
        session_idle_seconds: float = DEFAULT_RUNTIME_SESSION_IDLE_SECONDS,
    ) -> None:
        self.ids = id_factory or IdFactory()
        self.pii_detector = PiiDetector(self.ids)
        self.secret_detector = SecretDetector(self.ids)
        self.mcp_threat_detector = McpThreatDetector(self.ids)
        self.max_sessions = max(1, int(max_sessions))
        self.session_idle_seconds = max(1.0, float(session_idle_seconds))
        self.stream_states: dict[str, RuntimeSessionState] = {}

    def observe_text(self, text: str, label: str = "mcp-runtime-events") -> ScanResult:
        findings: list[Finding] = []
        decisions: list[dict[str, Any]] = []
        events, parse_errors = _parse_events(text)
        if parse_errors:
            findings.append(
                Finding(
                    id=self.ids.next(),
                    source="mcp-runtime",
                    rule_id="RUNTIME_MCP_EVENT_PARSE_ERROR",
                    severity="info",
                    confidence="high",
                    title="Some MCP runtime events could not be parsed",
                    file=label,
                    evidence=f"parse_errors={parse_errors}",
                    why_it_matters="Malformed observer logs reduce runtime audit coverage.",
                    recommendation="Export runtime events as JSON array or JSONL records with event/type and content/result/arguments fields.",
                    audit_depth=2,
                    inspected_scope="Runtime observer input was parsed locally; invalid records were counted but not echoed.",
                    not_inspected="Unparseable event bodies were not inspected for PII or tool flow.",
                )
            )
        recent_sensitive: list[SensitiveRuntimeEvent] = []
        for index, event in enumerate(events, start=1):
            self._observe_event(event, index, label, recent_sensitive, findings, decisions)
            recent_sensitive = recent_sensitive[-8:]
        result = ScanResult(findings=findings, metadata={"runtime_policy": _runtime_policy_metadata("batch", decisions, len(events), parse_errors)}).finalize()
        return result

    def enforce_text(self, text: str, label: str = "mcp-runtime-events") -> tuple[ScanResult, list[dict[str, Any]]]:
        findings: list[Finding] = []
        decisions: list[dict[str, Any]] = []
        events, parse_errors = _parse_events(text)
        if parse_errors:
            findings.append(
                Finding(
                    id=self.ids.next(),
                    source="mcp-runtime",
                    rule_id="RUNTIME_MCP_EVENT_PARSE_ERROR",
                    severity="info",
                    confidence="high",
                    title="Some MCP runtime events could not be parsed",
                    file=label,
                    evidence=f"parse_errors={parse_errors}",
                    why_it_matters="Malformed observer logs reduce runtime audit coverage.",
                    recommendation="Export runtime events as JSON array or JSONL records with event/type and content/result/arguments fields.",
                    audit_depth=2,
                    inspected_scope="Runtime interceptor input was parsed locally; invalid records were counted but not echoed.",
                    not_inspected="Unparseable event bodies were not forwarded by this batch interceptor.",
                )
            )
        recent_sensitive: list[SensitiveRuntimeEvent] = []
        for index, event in enumerate(events, start=1):
            self._observe_event(event, index, label, recent_sensitive, findings, decisions)
            recent_sensitive = recent_sensitive[-8:]
        forwarded_events, interceptor_metadata = _enforce_events(events, decisions)
        policy = _runtime_policy_metadata("interceptor", decisions, len(events), parse_errors)
        policy.update(interceptor_metadata)
        policy["enforcement"] = "forwarded_events_applied_for_callers_that_consume_forwarded_stream"
        policy["contract"] = "This report includes interceptor decisions; the returned forwarded_events stream is where block/redact changes are applied. MCP report-only wrappers do not forward event content."
        result = ScanResult(findings=findings, metadata={"runtime_policy": policy}).finalize()
        return result, forwarded_events

    def observe_event(self, text: str, session_id: str = "default", label: str = "mcp-runtime-event") -> ScanResult:
        findings: list[Finding] = []
        decisions: list[dict[str, Any]] = []
        events, parse_errors = _parse_events(text)
        now = time.monotonic()
        evicted_session_count = self._prune_stream_states(now)
        normalized_session_id = session_id or "default"
        if normalized_session_id not in self.stream_states and len(self.stream_states) >= self.max_sessions:
            oldest_session_id = min(
                self.stream_states,
                key=lambda item: self.stream_states[item].last_seen_at,
            )
            del self.stream_states[oldest_session_id]
            evicted_session_count += 1
        state = self.stream_states.setdefault(
            normalized_session_id,
            RuntimeSessionState(last_seen_at=now),
        )
        state.last_seen_at = now
        if parse_errors or not events:
            findings.append(
                Finding(
                    id=self.ids.next(),
                    source="mcp-runtime",
                    rule_id="RUNTIME_MCP_EVENT_PARSE_ERROR",
                    severity="info",
                    confidence="high",
                    title="MCP runtime event could not be parsed",
                    file=label,
                    evidence=f"parse_errors={parse_errors or 1}",
                    why_it_matters="Malformed observer events reduce runtime policy coverage.",
                    recommendation="Send one JSON object event or JSONL record with event/type and content/result/arguments fields.",
                    audit_depth=2,
                    inspected_scope="Runtime event input was parsed locally; invalid records were counted but not echoed.",
                    not_inspected="Unparseable event bodies were not inspected for PII or tool flow.",
                )
            )
        for event in events:
            state.event_count += 1
            self._observe_event(event, state.event_count, label, state.recent_sensitive, findings, decisions)
            state.recent_sensitive = state.recent_sensitive[-8:]
        result = ScanResult(
            findings=findings,
            metadata={
                "runtime_policy": _runtime_policy_metadata(
                    "stream",
                    decisions,
                    len(events),
                    parse_errors,
                    session_hash=evidence_hash(session_id or "default"),
                    retained_sensitive_context_count=len(state.recent_sensitive),
                )
            },
        ).finalize()
        result.metadata["runtime_policy"].update(
            {
                "active_session_count": len(self.stream_states),
                "max_session_count": self.max_sessions,
                "session_idle_seconds": self.session_idle_seconds,
                "evicted_session_count": evicted_session_count,
            }
        )
        return result

    def _prune_stream_states(self, now: float) -> int:
        expired = [
            session_id
            for session_id, state in self.stream_states.items()
            if now - state.last_seen_at > self.session_idle_seconds
        ]
        for session_id in expired:
            del self.stream_states[session_id]
        return len(expired)

    def _observe_event(
        self,
        event: dict[str, Any],
        index: int,
        label: str,
        recent_sensitive: list[SensitiveRuntimeEvent],
        findings: list[Finding],
        decisions: list[dict[str, Any]],
    ) -> None:
        content = _event_text(event)
        event_type = _event_type(event)
        tool = _event_tool(event)
        content_hash = evidence_hash(content)
        observed_at = time.monotonic()
        correlation_keys = _event_correlation_keys(event)
        _prune_sensitive_context(recent_sensitive, index, observed_at)

        if _is_jsonrpc_response(event) and not _is_valid_jsonrpc_response(event):
            rule_id = "RUNTIME_MCP_INVALID_JSONRPC_RESPONSE"
            findings.append(
                Finding(
                    id=self.ids.next(),
                    source="mcp-runtime",
                    rule_id=rule_id,
                    severity="high",
                    confidence="high",
                    title="Runtime JSON-RPC response has a contradictory payload shape",
                    file=label,
                    evidence=f"event_index={index} content_hash={content_hash} result_and_error=true raw_returned=false",
                    why_it_matters="A response containing both result and error is invalid and can bypass policy paths that assume exactly one payload.",
                    recommendation="Block the response and fix the upstream server to emit exactly one of result or error.",
                    audit_depth=5,
                    inspected_scope="The JSON-RPC response envelope and both payload fields were inspected before forwarding.",
                    not_inspected="K-Guard did not infer which contradictory payload the upstream intended.",
                )
            )
            decisions.append(
                _policy_decision(
                    index,
                    "block",
                    rule_id,
                    "contradictory_jsonrpc_response_shape",
                    "high",
                    content_hash,
                )
            )

        threat_rules = {finding.rule_id for finding in self.mcp_threat_detector.scan_text(content, f"{label}:mcp-runtime")}
        if threat_rules and _is_tool_result_event(event_type):
            rule_id = "RUNTIME_MCP_HIDDEN_INSTRUCTION_IN_TOOL_RESULT"
            findings.append(
                Finding(
                    id=self.ids.next(),
                    source="mcp-runtime",
                    rule_id=rule_id,
                    severity="critical",
                    confidence="high",
                    title="Runtime MCP tool result contains hidden instruction markers",
                    file=label,
                    evidence=f"event_index={index} tool_hash={evidence_hash(tool)} content_hash={content_hash} matched={','.join(sorted(threat_rules))} scheme={evidence_hash_scheme()}",
                    why_it_matters="Tool results can inject instructions into the agent's next reasoning step even when tool metadata looked clean.",
                    recommendation="Block or sanitize this tool result before it is passed to an agent or LLM context.",
                    audit_depth=5,
                    inspected_scope="Runtime MCP event content was observed and scanned without storing raw result values.",
                    not_inspected="This observer emits policy decisions; enforcement requires wiring the decision into the MCP client or proxy.",
                )
            )
            decisions.append(_policy_decision(index, "block", rule_id, "hidden_instruction_in_tool_result", "high", content_hash))

        pii_labels = Counter(entity.label for entity in self.pii_detector.detect_entities(content, label))
        secret_rules = Counter(finding.rule_id for finding in self.secret_detector.scan_text(content, label))
        if _is_tool_result_event(event_type) and pii_labels:
            rule_id = "RUNTIME_MCP_TOOL_RESULT_PII"
            meta = metadata_for_labels(pii_labels.keys(), audit_depth=5)
            recent_sensitive.append(SensitiveRuntimeEvent(index, tool, pii_labels, content_hash, observed_at, correlation_keys))
            findings.append(
                Finding(
                    id=self.ids.next(),
                    source="mcp-runtime",
                    rule_id=rule_id,
                    severity="medium",
                    confidence="medium",
                    title="Runtime MCP tool result contains personal data",
                    file=label,
                    evidence=f"event_index={index} tool_hash={evidence_hash(tool)} pii_counts={_format_counts(pii_labels)} content_hash={content_hash}",
                    why_it_matters="Tool results containing personal data can be forwarded into prompts, logs, or later tool calls.",
                    recommendation="Minimize tool results and mask personal data before returning it to the agent.",
                    privacy_class=str(meta["privacy_class"]),
                    pipc_basis=str(meta["pipc_basis"]),
                    audit_depth=int(meta["audit_depth"]),
                    inspected_scope="Runtime MCP tool result was classified locally with count-only PII evidence.",
                    not_inspected="The observer did not verify the original database/API authorization behind the tool result.",
                )
            )
            decisions.append(_policy_decision(index, "redact", rule_id, "pii_in_tool_result", "medium", content_hash, pii_counts=_format_counts(pii_labels)))
        if _is_tool_result_event(event_type) and secret_rules:
            rule_id = "RUNTIME_MCP_TOOL_RESULT_SECRET"
            findings.append(
                Finding(
                    id=self.ids.next(),
                    source="mcp-runtime",
                    rule_id=rule_id,
                    severity="critical",
                    confidence="medium",
                    title="Runtime MCP tool result contains secret-like data",
                    file=label,
                    evidence=f"event_index={index} tool_hash={evidence_hash(tool)} secret_counts={_format_counts(secret_rules)} content_hash={content_hash}",
                    why_it_matters="Secrets returned by tools can be copied into agent context or exfiltrated by later tool calls.",
                    recommendation="Stop returning secrets through MCP tools; rotate the credential if real.",
                    audit_depth=5,
                    inspected_scope="Runtime MCP tool result was scanned for secret patterns without storing raw values.",
                    not_inspected="The observer did not validate credential liveness.",
                )
            )
            decisions.append(_policy_decision(index, "block", rule_id, "secret_in_tool_result", "medium", content_hash, secret_counts=_format_counts(secret_rules)))

        sink_kind = None if _is_tool_result_event(event_type) else _sink_kind(event_type, tool, event)
        source_event = _correlated_sensitive_event(recent_sensitive, index, observed_at, correlation_keys) if sink_kind else None
        if sink_kind and source_event:
            rule_id = "RUNTIME_MCP_PII_TO_AGENTIC_OR_EXTERNAL_SINK"
            meta = metadata_for_labels(source_event.labels.keys(), audit_depth=5)
            findings.append(
                Finding(
                    id=self.ids.next(),
                    source="mcp-runtime",
                    rule_id=rule_id,
                    severity="critical" if sink_kind in {"llm", "mcp_tool"} else "high",
                    confidence="medium",
                    title="Runtime personal data may flow from MCP result to an agentic or external sink",
                    file=label,
                    evidence=(
                        f"source_event={source_event.index} sink_event={index} sink_kind={sink_kind} "
                        f"source_tool_hash={evidence_hash(source_event.tool)} sink_tool_hash={evidence_hash(tool)} "
                        f"pii_counts={_format_counts(source_event.labels)} source_hash={source_event.content_hash} sink_hash={content_hash}"
                    ),
                    why_it_matters="This is runtime observer evidence that personal data returned by one tool may be sent onward to a model, MCP tool, or external service.",
                    recommendation="Add a policy gate that redacts or blocks personal data before this sink unless an approved purpose is documented.",
                    privacy_class=str(meta["privacy_class"]),
                    pipc_basis=str(meta["pipc_basis"]),
                    audit_depth=int(meta["audit_depth"]),
                    inspected_scope="Runtime event order was analyzed to link a sensitive MCP result to a later sink without storing raw values.",
                    not_inspected="The observer infers event-to-event flow by order; proxy wiring can enforce this policy before forwarding.",
                )
            )
            decisions.append(
                _policy_decision(
                    index,
                    "block",
                    rule_id,
                    f"pii_to_{sink_kind}",
                    "medium",
                    content_hash,
                    source_event=source_event.index,
                    pii_counts=_format_counts(source_event.labels),
                )
            )
            recent_sensitive.remove(source_event)


def _parse_events(text: str) -> tuple[list[dict[str, Any]], int]:
    value = text.strip()
    if not value:
        return [], 0
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            events = [item for item in parsed if isinstance(item, dict)]
            errors = sum(1 for item in parsed if not isinstance(item, dict))
            return events, errors
        if isinstance(parsed, dict):
            return [parsed], 0
    except json.JSONDecodeError:
        pass
    events: list[dict[str, Any]] = []
    errors = 0
    for line in value.splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            errors += 1
            continue
        if isinstance(parsed, dict):
            events.append(parsed)
        else:
            errors += 1
    return events, errors


def _event_text(event: dict[str, Any]) -> str:
    keys = ("content", "result", "error", "response", "arguments", "args", "input", "prompt", "message", "data", "payload")
    parts: list[str] = []
    for key in keys:
        if key not in event:
            continue
        value = event[key]
        if isinstance(value, str):
            parts.append(value)
        else:
            parts.append(json.dumps(value, ensure_ascii=False, default=str))
    if not parts:
        parts.append(json.dumps(event, ensure_ascii=False, default=str))
    return "\n".join(parts)


def _event_type(event: dict[str, Any]) -> str:
    explicit = str(event.get("event") or event.get("type") or "").strip().lower()
    if explicit:
        return explicit
    if _is_jsonrpc_response(event):
        return "mcp.result.jsonrpc"
    if event.get("jsonrpc") == "2.0" and isinstance(event.get("method"), str):
        return "mcp.call.jsonrpc"
    return ""


def _event_tool(event: dict[str, Any]) -> str:
    explicit = event.get("tool") or event.get("name") or event.get("server") or event.get("provider")
    if explicit:
        return str(explicit)
    method = event.get("method")
    params = event.get("params")
    if isinstance(params, dict) and params.get("name"):
        return str(params["name"])
    return str(method or "unknown")


def _is_jsonrpc_response(event: dict[str, Any]) -> bool:
    return (
        event.get("jsonrpc") == "2.0"
        and "id" in event
        and ("result" in event or "error" in event)
    )


def _is_valid_jsonrpc_response(event: dict[str, Any]) -> bool:
    return _is_jsonrpc_response(event) and (("result" in event) ^ ("error" in event))


def _is_tool_result_event(event_type: str) -> bool:
    return any(term in event_type for term in ("tool_result", "tool.result", "result", "mcp.result"))


def _sink_kind(event_type: str, tool: str, event: dict[str, Any]) -> str | None:
    combined = " ".join([event_type, tool, str(event.get("url") or ""), str(event.get("provider") or "")]).lower()
    if any(term in combined for term in ("llm", "openai", "anthropic", "gemini", "chat.completions", "responses.create", "model_request")):
        return "llm"
    if any(term in combined for term in ("tool_call", "tool.call", "call_tool", "mcp.call")):
        return "mcp_tool"
    if any(term in combined for term in ("http", "webhook", "fetch", "external_request", "requests.")):
        return "external_http"
    return None


def _event_correlation_keys(event: dict[str, Any]) -> frozenset[str]:
    keys: set[str] = set()
    field_names = {
        "correlation_id",
        "correlationid",
        "request_id",
        "requestid",
        "trace_id",
        "traceid",
        "conversation_id",
        "conversationid",
        "session_id",
        "sessionid",
    }
    containers = [event]
    for name in ("metadata", "context"):
        value = event.get(name)
        if isinstance(value, dict):
            containers.append(value)
    for container in containers:
        for name, value in container.items():
            normalized = str(name).replace("-", "").replace("_", "").lower()
            if normalized not in {item.replace("_", "") for item in field_names} or value in (None, ""):
                continue
            keys.add(evidence_hash(f"{normalized}:{value}"))
    if _is_jsonrpc_response(event):
        keys.add(evidence_hash(f"jsonrpc_id:{event.get('id')}"))
    return frozenset(keys)


def _prune_sensitive_context(recent_sensitive: list[SensitiveRuntimeEvent], index: int, observed_at: float) -> None:
    recent_sensitive[:] = [
        item
        for item in recent_sensitive
        if 0 < index - item.index <= RECENT_SENSITIVE_MAX_EVENT_DISTANCE
        and 0.0 <= observed_at - item.observed_at <= RECENT_SENSITIVE_MAX_AGE_SECONDS
    ]


def _correlated_sensitive_event(
    recent_sensitive: list[SensitiveRuntimeEvent],
    index: int,
    observed_at: float,
    sink_keys: frozenset[str],
) -> SensitiveRuntimeEvent | None:
    _prune_sensitive_context(recent_sensitive, index, observed_at)
    for source in reversed(recent_sensitive):
        if source.correlation_keys or sink_keys:
            if source.correlation_keys & sink_keys:
                return source
            continue
        return source
    return None


def _policy_decision(event_index: int, action: str, rule_id: str, reason: str, confidence: str, content_hash: str, **extra: Any) -> dict[str, Any]:
    return {
        "event_index": event_index,
        "action": action,
        "rule_id": rule_id,
        "reason": reason,
        "confidence": confidence,
        "content_hash": content_hash,
        **{key: value for key, value in extra.items() if value not in (None, "")},
    }


def _runtime_policy_metadata(
    mode: str,
    decisions: list[dict[str, Any]],
    event_count: int,
    parse_errors: int,
    session_hash: str | None = None,
    retained_sensitive_context_count: int | None = None,
) -> dict[str, Any]:
    action_counts = Counter(str(decision.get("action", "unknown")) for decision in decisions)
    metadata: dict[str, Any] = {
        "mode": mode,
        "enforcement": "advisory_decision_output",
        "event_count": event_count,
        "parse_error_count": parse_errors,
        "decision_count": len(decisions),
        "block_decision_count": action_counts.get("block", 0),
        "redact_decision_count": action_counts.get("redact", 0),
        "actions": dict(sorted(action_counts.items())),
        "decisions": decisions,
        "sensitive_context_max_event_distance": RECENT_SENSITIVE_MAX_EVENT_DISTANCE,
        "sensitive_context_max_age_seconds": RECENT_SENSITIVE_MAX_AGE_SECONDS,
        "contract": "MCP clients or proxies can enforce block/redact actions before forwarding tool results or sink calls.",
    }
    if session_hash:
        metadata["session_hash"] = session_hash
    if retained_sensitive_context_count is not None:
        metadata["retained_sensitive_context_count"] = retained_sensitive_context_count
    return metadata


def _enforce_events(events: list[dict[str, Any]], decisions: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    grouped: dict[int, list[dict[str, Any]]] = {}
    for decision in decisions:
        try:
            index = int(decision.get("event_index", 0))
        except (TypeError, ValueError):
            continue
        grouped.setdefault(index, []).append(decision)
    forwarded: list[dict[str, Any]] = []
    enforced_summaries: list[dict[str, Any]] = []
    action_counts: Counter[str] = Counter()
    for index, event in enumerate(events, start=1):
        event_decisions = grouped.get(index, [])
        action = _effective_action(event_decisions)
        action_counts[action] += 1
        forwarded_event = _forwarded_event(index, event, action, event_decisions)
        forwarded.append(forwarded_event)
        enforced_summaries.append(
            {
                "event_index": index,
                "action": action,
                "content_hash": evidence_hash(_event_text(event)),
                "rule_ids": sorted({str(decision.get("rule_id")) for decision in event_decisions if decision.get("rule_id")}),
                "raw_returned_in_report": False,
            }
        )
    return sanitize_any(forwarded), {
        "interceptor": {
            "mode": "block_or_redact_before_forward",
            "event_count": len(events),
            "forwarded_count": action_counts.get("allow", 0) + action_counts.get("redact", 0),
            "blocked_count": action_counts.get("block", 0),
            "redacted_count": action_counts.get("redact", 0),
            "output_event_count": len(forwarded),
            "actions": dict(sorted(action_counts.items())),
            "enforced_events": enforced_summaries,
            "report_raw_free": True,
            "forwarded_stream_policy": "blocked events are replaced with block stubs; redacted events have sensitive string fields redacted before forwarding; allowed events are preserved for transport use.",
        }
    }


def _effective_action(decisions: list[dict[str, Any]]) -> str:
    actions = {str(decision.get("action") or "allow") for decision in decisions}
    if "block" in actions:
        return "block"
    if "redact" in actions:
        return "redact"
    return "allow"


def _forwarded_event(index: int, event: dict[str, Any], action: str, decisions: list[dict[str, Any]]) -> dict[str, Any]:
    content_hash = evidence_hash(_event_text(event))
    rule_ids = sorted({str(decision.get("rule_id")) for decision in decisions if decision.get("rule_id")})
    reasons = sorted({str(decision.get("reason")) for decision in decisions if decision.get("reason")})
    if _is_jsonrpc_response(event):
        if not _is_valid_jsonrpc_response(event):
            return {
                "jsonrpc": "2.0",
                "id": event.get("id"),
                "error": {
                    "code": -32002,
                    "message": "K-Guard blocked an invalid upstream response",
                    "data": {
                        "rule_ids": ["RUNTIME_MCP_INVALID_JSONRPC_RESPONSE"],
                        "raw_content_forwarded": False,
                    },
                },
            }
        if action == "block":
            return {
                "jsonrpc": "2.0",
                "id": event.get("id"),
                "error": {
                    "code": -32001,
                    "message": "K-Guard blocked an unsafe MCP response",
                    "data": {"rule_ids": rule_ids, "raw_content_forwarded": False},
                },
            }
        if action == "redact":
            forwarded_response = dict(event)
            payload_key = "result" if "result" in event else "error"
            forwarded_response[payload_key] = _redact_event(event.get(payload_key))
            return forwarded_response
        return dict(event)
    if action == "block":
        return {
            "event_index": index,
            "interceptor_action": "block",
            "blocked": True,
            "redacted": False,
            "content_hash": content_hash,
            "rule_ids": rule_ids,
            "reasons": reasons,
            "raw_content_forwarded": False,
        }
    forwarded = _redact_event(event) if action == "redact" else dict(event)
    forwarded["event_index"] = index
    forwarded["interceptor_action"] = action
    forwarded["blocked"] = False
    forwarded["redacted"] = action == "redact"
    forwarded["content_hash"] = content_hash
    if rule_ids:
        forwarded["rule_ids"] = rule_ids
    return forwarded


def _redact_event(value: Any) -> Any:
    if isinstance(value, str):
        redacted = redact_text(value)
        if PiiDetector().detect_entities(redacted):
            return f"<redacted:MCP_PII:{evidence_hash(value)}>"
        return redacted
    if isinstance(value, (dict, list)):
        serialized = json.dumps(value, ensure_ascii=False, default=str)
        redacted = redact_text(serialized)
        if PiiDetector().detect_entities(redacted):
            return {"redacted": True, "reason": "k_guard_pii_policy", "raw_content_forwarded": False}
        try:
            return json.loads(redacted)
        except json.JSONDecodeError:
            return {"redacted": True, "reason": "k_guard_serialization_policy", "raw_content_forwarded": False}
    return value


def _format_counts(counts: Counter[str]) -> str:
    return ",".join(f"{key}={counts[key]}" for key in sorted(counts))


def observe_mcp_events_file(path: str | Path) -> ScanResult:
    event_path = Path(path)
    return McpRuntimeObserver().observe_text(event_path.read_text(encoding="utf-8"), str(event_path))
