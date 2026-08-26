from __future__ import annotations

import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any, TextIO

from k_guard_mcp.access_policy import AccessPolicyController
from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.mcp_runtime import McpRuntimeObserver
from k_guard_mcp.provenance import evidence_bundle, object_artifact
from k_guard_mcp.redaction import redact_text, sanitize_any
from k_guard_mcp.runtime_mediation_receipts import (
    RuntimeMediationReceiptChain,
    RuntimeMediationReceiptError,
    forwarding_contract,
    new_transaction_id,
    policy_ref_for,
    receipt_persist_path_for_report,
)


DEFAULT_MAX_LINE_BYTES = 1024 * 1024
DEFAULT_MAX_STREAM_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_MESSAGES = 100_000
_PROTOCOL_VERSION_PLACEHOLDER = "mcp-negotiated-version"
_SAFE_ENV_NAMES = frozenset(
    {
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
)


class _DuplicateJsonKey(ValueError):
    pass


def mcp_stdio_proxy_toolchain_contract() -> dict[str, Any]:
    package_root = Path(__file__).resolve().parent
    paths = [
        package_root / "access_policy.py",
        package_root / "mcp_proxy.py",
        package_root / "mcp_runtime.py",
        package_root / "redaction.py",
        package_root / "hashing.py",
        package_root / "detectors" / "mcp_threat.py",
        package_root / "runtime_mediation_receipts.py",
    ]
    digest = hashlib.sha256()
    hashed = 0
    for path in paths:
        try:
            relative = path.relative_to(package_root).as_posix().encode("utf-8")
            content = path.read_bytes()
        except (OSError, ValueError):
            continue
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
        hashed += 1
    return {
        "schema": "k_guard_mcp_stdio_proxy_toolchain.v1",
        "sha256": digest.hexdigest(),
        "expected_file_count": len(paths),
        "hashed_file_count": hashed,
        "complete": hashed == len(paths),
        "raw_returned": False,
    }


def run_stdio_proxy(
    upstream_argv: list[str],
    *,
    report_path: str | Path | None = None,
    client_input: TextIO | None = None,
    protocol_output: TextIO | None = None,
    diagnostic_output: TextIO | None = None,
    response_timeout_seconds: float = 30.0,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
    max_messages: int = DEFAULT_MAX_MESSAGES,
    allowed_environment_names: tuple[str, ...] = (),
    access_controller: AccessPolicyController | None = None,
    access_token: str | None = None,
    receipt_log_path: str | Path | None = None,
) -> int:
    client_input = client_input or sys.stdin
    protocol_output = protocol_output or sys.stdout
    diagnostic_output = diagnostic_output or sys.stderr
    argv = [str(item) for item in upstream_argv]
    if argv[:1] == ["--"]:
        argv = argv[1:]
    if not argv or any(not item or "\x00" in item for item in argv):
        _diagnostic(diagnostic_output, "mcp-proxy requires a non-empty upstream argv after '--'.")
        _write_report(report_path, _empty_report(argv, "invalid_upstream_argv"), diagnostic_output)
        return 2
    if (access_controller is None) != (access_token is None):
        _diagnostic(diagnostic_output, "mcp-proxy access policy requires both a controller and a grant token.")
        _write_report(report_path, _empty_report(argv, "access_policy_configuration_invalid"), diagnostic_output)
        return 2

    toolchain_contract = mcp_stdio_proxy_toolchain_contract()
    persist_path = Path(receipt_log_path) if receipt_log_path is not None else receipt_persist_path_for_report(report_path)
    receipt_chain = RuntimeMediationReceiptChain(
        transport="jsonl",
        toolchain_ref=str(toolchain_contract.get("sha256") or ("0" * 64)),
        policy_ref=policy_ref_for(
            access_controller.policy.source_sha256 if access_controller is not None else None
        ),
        persist_path=persist_path,
    )
    stats: Counter[str] = Counter()
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    pending_upstream: dict[str, dict[str, Any]] = {}
    pending_client: dict[str, dict[str, Any]] = {}
    pending_lock = threading.Lock()
    output_lock = threading.Lock()
    upstream_write_lock = threading.Lock()
    observer_lock = threading.Lock()
    input_activity_lock = threading.Lock()
    input_stop = threading.Event()
    watchdog_stop = threading.Event()
    response_timeout = max(0.1, float(response_timeout_seconds))
    if min(int(max_line_bytes), int(max_stream_bytes), int(max_messages)) <= 0:
        _diagnostic(diagnostic_output, "mcp-proxy resource limits must be positive.")
        _write_report(
            report_path,
            _empty_report(argv, "invalid_resource_limits", receipt_chain=receipt_chain, toolchain_contract=toolchain_contract),
            diagnostic_output,
        )
        return 2
    observer = McpRuntimeObserver()
    process_group_options: dict[str, Any]
    if os.name == "nt":
        process_group_options = {
            "creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        }
    else:
        process_group_options = {"start_new_session": True}

    try:
        upstream_environment = _minimal_upstream_environment(allowed_environment_names)
    except ValueError as exc:
        _record_error(errors, "invalid_environment_allowlist", exc)
        _write_report(
            report_path,
            _proxy_report(
                argv,
                stats,
                findings,
                errors,
                2,
                receipt_chain=receipt_chain,
                toolchain_contract=toolchain_contract,
            ),
            diagnostic_output,
        )
        return 2

    if report_path is not None and not _write_report(
        report_path,
        _empty_report(
            argv,
            "proxy_starting_fail_closed",
            receipt_chain=receipt_chain,
            toolchain_contract=toolchain_contract,
        ),
        diagnostic_output,
    ):
        return 2

    try:
        process = subprocess.Popen(
            argv,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=upstream_environment,
            **process_group_options,
        )
    except OSError as exc:
        _record_error(errors, "spawn_failed", exc)
        _diagnostic(diagnostic_output, f"upstream spawn failed: {exc}")
        _write_report(
            report_path,
            _proxy_report(
                argv,
                stats,
                findings,
                errors,
                127,
                receipt_chain=receipt_chain,
                toolchain_contract=toolchain_contract,
            ),
            diagnostic_output,
        )
        return 127

    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    _attach_windows_kill_job(process)

    input_thread = threading.Thread(
        target=_forward_client_input,
        args=(
            client_input,
            process.stdin,
            pending_upstream,
            pending_lock,
            stats,
            errors,
            diagnostic_output,
            observer,
            findings,
            protocol_output,
            output_lock,
            observer_lock,
            pending_client,
            process,
            upstream_write_lock,
            input_stop,
            input_activity_lock,
            int(max_line_bytes),
            int(max_stream_bytes),
            int(max_messages),
            access_controller,
            access_token,
            receipt_chain,
        ),
        name="k-guard-mcp-proxy-input",
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_forward_upstream_stderr,
        args=(process.stderr, diagnostic_output),
        name="k-guard-mcp-proxy-stderr",
        daemon=True,
    )
    watchdog_thread = threading.Thread(
        target=_watch_pending_requests,
        args=(
            process,
            pending_upstream,
            pending_client,
            pending_lock,
            response_timeout,
            watchdog_stop,
            stats,
            errors,
            diagnostic_output,
        ),
        name="k-guard-mcp-proxy-watchdog",
        daemon=True,
    )
    input_thread.start()
    stderr_thread.start()
    watchdog_thread.start()

    interrupted = False
    upstream_total_bytes = 0
    upstream_message_count = 0
    try:
        for raw_line in process.stdout:
            if not raw_line.strip():
                continue
            upstream_line_bytes = len(raw_line.encode("utf-8", errors="replace"))
            upstream_total_bytes += upstream_line_bytes
            upstream_message_count += 1
            if (
                upstream_line_bytes > max_line_bytes
                or upstream_total_bytes > max_stream_bytes
                or upstream_message_count > max_messages
            ):
                kind = (
                    "upstream_line_limit_exceeded"
                    if upstream_line_bytes > max_line_bytes
                    else "upstream_stream_limit_exceeded"
                    if upstream_total_bytes > max_stream_bytes
                    else "upstream_message_limit_exceeded"
                )
                stats[kind] += 1
                _record_error(errors, kind, RuntimeError(kind))
                _diagnostic(diagnostic_output, "upstream protocol resource limit exceeded; stopping the mediated process.")
                _terminate_process_tree(process, force=True)
                break
            try:
                message = _strict_json_loads(raw_line)
            except (json.JSONDecodeError, _DuplicateJsonKey, ValueError) as exc:
                stats["malformed_upstream_lines"] += 1
                _record_error(errors, "malformed_upstream_json", exc)
                _diagnostic(diagnostic_output, "blocked a non-JSON line written by the upstream process to protocol stdout.")
                _terminate_process_tree(process, force=True)
                break

            if not isinstance(message, dict):
                stats["invalid_upstream_message_shapes"] += 1
                _record_error(errors, "invalid_upstream_message_shape", TypeError("upstream JSON-RPC message must be an object"))
                _diagnostic(diagnostic_output, "blocked a non-object JSON value written by the upstream process to protocol stdout.")
                _terminate_process_tree(process, force=True)
                break

            is_response = _is_jsonrpc_response_candidate(message)
            if not is_response and not _is_valid_jsonrpc_request(message):
                stats["invalid_upstream_message_shapes"] += 1
                _record_error(
                    errors,
                    "invalid_upstream_jsonrpc_shape",
                    RuntimeError("upstream JSON-RPC request or notification has an invalid envelope"),
                )
                _diagnostic(diagnostic_output, "blocked an invalid JSON-RPC request or notification from upstream.")
                if _is_jsonrpc_request_candidate(message):
                    wrote = _write_upstream_message(
                        process.stdin,
                        _invalid_upstream_request_response(message.get("id")),
                        upstream_write_lock,
                    )
                    if not wrote:
                        _record_error(
                            errors,
                            "invalid_upstream_request_response_failed",
                            BrokenPipeError("upstream stdin unavailable"),
                        )
                        _terminate_process_tree(process, force=True)
                _terminate_process_tree(process, force=True)
                break

            invalid_response = is_response and not _is_valid_jsonrpc_response(message)
            uncorrelated_response = False
            pending_context: dict[str, Any] | None = None
            if is_response:
                stats["responses_inspected"] += 1
                with pending_lock:
                    pending_context = pending_upstream.pop(_rpc_id_key(message.get("id")), None)
                if pending_context is None:
                    uncorrelated_response = True
                    stats["uncorrelated_upstream_responses"] += 1
                    _record_error(
                        errors,
                        "uncorrelated_upstream_response",
                        RuntimeError("upstream response has no pending client request"),
                    )
                if invalid_response:
                    stats["invalid_response_shapes"] += 1
                    _record_error(
                        errors,
                        "invalid_jsonrpc_response_shape",
                        RuntimeError("JSON-RPC response has an invalid envelope"),
                    )
                if pending_context:
                    stats["responses_correlated"] += 1
            else:
                stats["upstream_messages_inspected"] += 1

            related_method = str(pending_context.get("method") or "") if pending_context else ""
            with observer_lock:
                result, transformed, action = _enforce_upstream_message(
                    observer,
                    message,
                    is_response=is_response,
                    related_method=related_method,
                )
            if (
                access_controller is not None
                and access_token is not None
                and is_response
                and related_method == "tools/list"
                and transformed is not None
            ):
                filtered = access_controller.filter_tools_list_response(access_token, transformed)
                if filtered != transformed:
                    action = "redact"
                    stats["access_tool_lists_filtered"] += 1
                transformed = filtered
            if uncorrelated_response:
                transformed = None
                action = "block"
            elif invalid_response:
                transformed = _blocked_parse_response(message.get("id"))
                action = "block"
            findings.extend(finding.to_dict() for finding in result.findings)
            prefix = "responses" if is_response else "upstream_messages"
            stats[f"{prefix}_{action}"] += 1
            if action != "allow":
                message_ref = message.get("id") if "id" in message else message.get("method", "notification")
                _diagnostic(diagnostic_output, f"upstream message policy action={action} message_ref={evidence_hash(str(message_ref))}")
            transaction_id = ""
            if pending_context:
                transaction_id = str(pending_context.get("transaction_id") or "")
            transaction_id = transaction_id or new_transaction_id()
            original_forwarded, safe_replacement_forwarded = forwarding_contract(action=action, forwarded=transformed)
            if not _record_stdio_receipt(
                receipt_chain,
                errors,
                direction="upstream_to_client",
                action=action,
                message=message,
                findings=result.findings,
                access_reason="",
                transaction_id=transaction_id,
                original_forwarded=original_forwarded,
                safe_replacement_forwarded=safe_replacement_forwarded,
            ):
                _terminate_process_tree(process, force=True)
                break
            if transformed is None:
                stats["upstream_messages_dropped"] += 1
                if not is_response and _is_jsonrpc_request_candidate(message):
                    wrote = _write_upstream_message(
                        process.stdin,
                        _blocked_upstream_request_response(message.get("id"), [finding.rule_id for finding in result.findings]),
                        upstream_write_lock,
                    )
                    if not wrote:
                        _record_error(errors, "blocked_upstream_request_response_failed", BrokenPipeError("upstream stdin unavailable"))
                        _terminate_process_tree(process, force=True)
                continue
            if not is_response:
                if _is_jsonrpc_request_candidate(transformed):
                    request_key = _rpc_id_key(transformed.get("id"))
                    with pending_lock:
                        duplicate = request_key in pending_client
                        if duplicate:
                            pending_client.pop(request_key, None)
                        else:
                            pending_client[request_key] = {
                                "method_ref": evidence_hash(str(transformed.get("method"))),
                                "started_at": time.monotonic(),
                                "transaction_id": transaction_id,
                            }
                    if duplicate:
                        stats["duplicate_upstream_request_ids"] += 1
                        _record_error(errors, "duplicate_upstream_request_id", RuntimeError("duplicate outstanding upstream request id"))
                        _write_upstream_message(
                            process.stdin,
                            _duplicate_request_response(transformed.get("id")),
                            upstream_write_lock,
                        )
                        _terminate_process_tree(process, force=True)
                        continue
                stats["upstream_messages_forwarded"] += 1

            _write_protocol_message(protocol_output, transformed, output_lock)
    except KeyboardInterrupt:
        interrupted = True
        stats["interruptions"] += 1
        _diagnostic(diagnostic_output, "mcp-proxy interrupted; stopping the upstream process.")
        _terminate_process_tree(process, force=True)
    except (BrokenPipeError, OSError, ValueError) as exc:
        _record_error(errors, "protocol_output_failed", exc)
        _diagnostic(diagnostic_output, f"protocol output failed: {exc}")
        _terminate_process_tree(process, force=True)
    finally:
        input_stop.set()
        watchdog_stop.set()
        try:
            return_code = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(process, force=True)
            return_code = process.wait(timeout=5)
        with input_activity_lock:
            pass
        input_thread.join(timeout=1)
        stderr_thread.join(timeout=1)
        watchdog_thread.join(timeout=1)
        _close_windows_kill_job(process)

    with pending_lock:
        pending_upstream_count = len(pending_upstream)
        pending_client_count = len(pending_client)
    stats["pending_upstream_response_count"] = pending_upstream_count
    stats["pending_client_response_count"] = pending_client_count
    stats["pending_request_count"] = pending_upstream_count + pending_client_count
    if pending_upstream_count or pending_client_count:
        errors.append(
            {
                "kind": "unanswered_requests",
                "type": "RuntimeError",
                "detail_ref": evidence_hash(
                    f"pending_upstream={pending_upstream_count};pending_client={pending_client_count}"
                ),
            }
        )
    report = _proxy_report(
        argv,
        stats,
        findings,
        errors,
        return_code,
        access_summary=access_controller.summary() if access_controller is not None else None,
        receipt_chain=receipt_chain,
        toolchain_contract=toolchain_contract,
    )
    report_written = _write_report(report_path, report, diagnostic_output)
    if interrupted:
        return 130
    if report_path is not None and not report_written:
        return 3
    if errors:
        return 3
    return return_code if return_code >= 0 else 1


def _forward_client_input(
    source: TextIO,
    destination: TextIO,
    pending_upstream: dict[str, dict[str, Any]],
    pending_lock: threading.Lock,
    stats: Counter[str],
    errors: list[dict[str, str]],
    diagnostic_output: TextIO,
    observer: McpRuntimeObserver | None = None,
    findings: list[dict[str, Any]] | None = None,
    protocol_output: TextIO | None = None,
    output_lock: threading.Lock | None = None,
    observer_lock: threading.Lock | None = None,
    pending_client: dict[str, dict[str, Any]] | None = None,
    process: subprocess.Popen[str] | None = None,
    upstream_write_lock: threading.Lock | None = None,
    stop: threading.Event | None = None,
    activity_lock: threading.Lock | None = None,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
    max_messages: int = DEFAULT_MAX_MESSAGES,
    access_controller: AccessPolicyController | None = None,
    access_token: str | None = None,
    receipt_chain: RuntimeMediationReceiptChain | None = None,
) -> None:
    observer = observer or McpRuntimeObserver()
    finding_sink = findings if findings is not None else []
    write_lock = output_lock or threading.Lock()
    runtime_lock = observer_lock or threading.Lock()
    upstream_lock = upstream_write_lock or threading.Lock()
    client_pending = pending_client if pending_client is not None else {}
    stop_event = stop or threading.Event()
    active_lock = activity_lock or threading.Lock()
    total_bytes = 0
    message_count = 0
    try:
        for raw_line in source:
            if stop_event.is_set():
                break
            with active_lock:
                if stop_event.is_set():
                    break
                if not raw_line.strip():
                    continue
                line_bytes = len(raw_line.encode("utf-8", errors="replace"))
                total_bytes += line_bytes
                message_count += 1
                if line_bytes > max_line_bytes or total_bytes > max_stream_bytes or message_count > max_messages:
                    kind = (
                        "client_line_limit_exceeded"
                        if line_bytes > max_line_bytes
                        else "client_stream_limit_exceeded"
                        if total_bytes > max_stream_bytes
                        else "client_message_limit_exceeded"
                    )
                    stats[kind] += 1
                    _record_error(errors, kind, RuntimeError(kind))
                    _diagnostic(diagnostic_output, "client protocol resource limit exceeded; closing the mediated process.")
                    if process is not None:
                        _terminate_process_tree(process, force=True)
                    break
                keep_open = _process_client_line(
                    raw_line,
                    destination,
                    pending_upstream,
                    client_pending,
                    pending_lock,
                    stats,
                    errors,
                    diagnostic_output,
                    observer,
                    finding_sink,
                    protocol_output,
                    write_lock,
                    runtime_lock,
                    process,
                    upstream_lock,
                    access_controller,
                    access_token,
                    receipt_chain,
                )
                if not keep_open:
                    if process is not None:
                        _terminate_process_tree(process, force=True)
                    break
    except (BrokenPipeError, OSError) as exc:
        with active_lock:
            if not stop_event.is_set():
                _record_error(errors, "upstream_stdin_failed", exc)
                _diagnostic(diagnostic_output, f"upstream stdin closed: {exc}")
    finally:
        try:
            destination.close()
        except OSError:
            pass


def _process_client_line(
    raw_line: str,
    destination: TextIO,
    pending_upstream: dict[str, dict[str, Any]],
    pending_client: dict[str, dict[str, Any]],
    pending_lock: threading.Lock,
    stats: Counter[str],
    errors: list[dict[str, str]],
    diagnostic_output: TextIO,
    observer: McpRuntimeObserver,
    finding_sink: list[dict[str, Any]],
    protocol_output: TextIO | None,
    output_lock: threading.Lock,
    observer_lock: threading.Lock,
    process: subprocess.Popen[str] | None,
    upstream_write_lock: threading.Lock,
    access_controller: AccessPolicyController | None = None,
    access_token: str | None = None,
    receipt_chain: RuntimeMediationReceiptChain | None = None,
) -> bool:
    try:
        message = _strict_json_loads(raw_line)
    except (json.JSONDecodeError, _DuplicateJsonKey, ValueError) as exc:
        stats["malformed_client_lines"] += 1
        _record_error(errors, "malformed_client_json", exc)
        _diagnostic(diagnostic_output, "blocked a non-JSON line from the MCP client.")
        return False
    if not isinstance(message, dict):
        stats["invalid_client_message_shapes"] += 1
        _record_error(errors, "invalid_client_message_shape", TypeError("client JSON-RPC message must be an object"))
        _diagnostic(diagnostic_output, "blocked a non-object JSON value from the MCP client.")
        return False
    if not _is_valid_jsonrpc_client_message(message):
        stats["invalid_client_jsonrpc_shapes"] += 1
        _record_error(errors, "invalid_client_jsonrpc_shape", RuntimeError("invalid client JSON-RPC envelope"))
        _diagnostic(diagnostic_output, "blocked an invalid JSON-RPC envelope from the MCP client.")
        if protocol_output is not None and _is_jsonrpc_request_candidate(message):
            _write_protocol_message(protocol_output, _invalid_client_response(message.get("id")), output_lock)
        return False

    is_response = _is_jsonrpc_response_candidate(message)
    message_key = _rpc_id_key(message.get("id")) if "id" in message else ""
    pending_context: dict[str, Any] | None = None
    if is_response:
        with pending_lock:
            pending_context = pending_client.pop(message_key, None)
        if pending_context is None:
            stats["uncorrelated_client_responses"] += 1
            _record_error(errors, "uncorrelated_client_response", RuntimeError("client response has no pending upstream request"))
            _diagnostic(diagnostic_output, f"blocked an unsolicited client response id_ref={evidence_hash(message_key)}")
            return False
        stats["client_responses_correlated"] += 1
    elif _is_jsonrpc_request_candidate(message):
        with pending_lock:
            duplicate = message_key in pending_upstream
            if duplicate:
                pending_upstream.pop(message_key, None)
        if duplicate:
            stats["duplicate_client_request_ids"] += 1
            _record_error(errors, "duplicate_client_request_id", RuntimeError("duplicate outstanding client request id"))
            _diagnostic(diagnostic_output, f"blocked duplicate client request id_ref={evidence_hash(message_key)}")
            if protocol_output is not None:
                _write_protocol_message(protocol_output, _duplicate_request_response(message.get("id")), output_lock)
            if process is not None:
                _terminate_process_tree(process, force=True)
            return False

    transaction_id = str((pending_context or {}).get("transaction_id") or "") or new_transaction_id()
    if access_controller is not None and access_token is not None and "method" in message:
        decision = access_controller.authorize_client_message(
            access_token,
            message,
            transaction_ref=transaction_id,
        )
        stats[f"access_decisions_{decision.action}"] += 1
        stats[f"access_reason_{decision.reason}"] += 1
        if not decision.allowed:
            stats["client_messages_access_denied"] += 1
            if not _record_stdio_receipt(
                receipt_chain,
                errors,
                direction="client_to_upstream",
                action="deny",
                message=message,
                access_reason=decision.reason,
                transaction_id=transaction_id,
                original_forwarded=False,
                safe_replacement_forwarded=False,
            ):
                return False
            if protocol_output is not None and _is_jsonrpc_request_candidate(message):
                _write_protocol_message(
                    protocol_output,
                    _blocked_access_response(message.get("id"), decision.reason),
                    output_lock,
                )
            return True

    stats["client_messages_inspected"] += 1
    with observer_lock:
        client_findings, transformed, action, rule_ids = _enforce_client_message(observer, message)
    finding_sink.extend(finding.to_dict() for finding in client_findings)
    stats[f"client_messages_{action}"] += 1
    if action != "allow":
        message_ref = message.get("id") if "id" in message else message.get("method", "response")
        _diagnostic(diagnostic_output, f"client message policy action={action} message_ref={evidence_hash(str(message_ref))}")
    original_forwarded, safe_replacement_forwarded = forwarding_contract(action=action, forwarded=transformed)
    if not _record_stdio_receipt(
        receipt_chain,
        errors,
        direction="client_to_upstream",
        action=action,
        message=message,
        findings=client_findings,
        rule_ids=rule_ids,
        transaction_id=transaction_id,
        original_forwarded=original_forwarded,
        safe_replacement_forwarded=safe_replacement_forwarded,
    ):
        return False
    if transformed is None:
        stats["client_messages_dropped"] += 1
        if is_response:
            wrote = _write_upstream_message(
                destination,
                _blocked_upstream_request_response(message.get("id"), rule_ids),
                upstream_write_lock,
            )
            if not wrote:
                raise BrokenPipeError("upstream stdin unavailable for blocked client response")
        elif protocol_output is not None and _is_jsonrpc_request_candidate(message):
            _write_protocol_message(
                protocol_output,
                _blocked_client_response(message.get("id"), rule_ids),
                output_lock,
            )
        return True

    if _is_jsonrpc_request_candidate(transformed):
        context = {
            "method": str(transformed.get("method") or ""),
            "method_ref": evidence_hash(str(transformed.get("method"))),
            "tool_ref": evidence_hash(str(transformed.get("params", {}).get("name", ""))) if isinstance(transformed.get("params"), dict) else evidence_hash(""),
            "started_at": time.monotonic(),
            "transaction_id": transaction_id,
        }
        with pending_lock:
            pending_upstream[_rpc_id_key(transformed.get("id"))] = context
    if not _write_upstream_message(destination, transformed, upstream_write_lock):
        raise BrokenPipeError("upstream stdin unavailable")
    stats["client_lines_forwarded"] += 1
    return True


def _forward_upstream_stderr(source: TextIO, destination: TextIO) -> None:
    for line in source:
        cleaned = redact_text(line.rstrip("\r\n"))
        destination.write(f"[mcp-proxy upstream] {cleaned}\n")
        destination.flush()


def _watch_pending_requests(
    process: subprocess.Popen[str],
    pending_upstream: dict[str, dict[str, Any]],
    pending_client: dict[str, dict[str, Any]],
    pending_lock: threading.Lock,
    response_timeout: float,
    stop: threading.Event,
    stats: Counter[str],
    errors: list[dict[str, str]],
    diagnostic_output: TextIO,
) -> None:
    interval = min(0.25, max(0.02, response_timeout / 4))
    while not stop.wait(interval):
        now = time.monotonic()
        with pending_lock:
            expired_upstream = [
                request_id
                for request_id, context in pending_upstream.items()
                if now - float(context.get("started_at", now)) >= response_timeout
            ]
            expired_client = [
                request_id
                for request_id, context in pending_client.items()
                if now - float(context.get("started_at", now)) >= response_timeout
            ]
            for request_id in expired_upstream:
                pending_upstream.pop(request_id, None)
            for request_id in expired_client:
                pending_client.pop(request_id, None)
        if not expired_upstream and not expired_client:
            continue
        stats["response_timeouts"] += len(expired_upstream) + len(expired_client)
        stats["upstream_response_timeouts"] += len(expired_upstream)
        stats["client_response_timeouts"] += len(expired_client)
        if expired_upstream:
            errors.append(
                {
                    "kind": "upstream_response_timeout",
                    "type": "TimeoutError",
                    "detail_ref": evidence_hash(f"expired_request_count={len(expired_upstream)}"),
                }
            )
        if expired_client:
            errors.append(
                {
                    "kind": "client_response_timeout",
                    "type": "TimeoutError",
                    "detail_ref": evidence_hash(f"expired_request_count={len(expired_client)}"),
                }
            )
        _diagnostic(
            diagnostic_output,
            (
                "response timeout; stopped process after "
                f"upstream_wait={len(expired_upstream)} client_wait={len(expired_client)} pending request(s)."
            ),
        )
        _terminate_process_tree(process, force=True)
        return


def _valid_jsonrpc_id(value: Any) -> bool:
    return value is None or (
        isinstance(value, (str, int, float))
        and not isinstance(value, bool)
        and (not isinstance(value, float) or math.isfinite(value))
    )


def _strict_json_loads(value: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise _DuplicateJsonKey(key)
            result[key] = item
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    return json.loads(value, object_pairs_hook=reject_duplicates, parse_constant=reject_constant)


def _minimal_upstream_environment(allowed_names: tuple[str, ...]) -> dict[str, str]:
    requested = set(_SAFE_ENV_NAMES)
    for raw_name in allowed_names:
        name = str(raw_name or "").strip()
        if (
            not name
            or len(name) > 128
            or any(character in name for character in "\x00\r\n=")
            or not all(character.isalnum() or character == "_" for character in name)
        ):
            raise ValueError("allowed environment name is invalid")
        requested.add(name)
    return {name: os.environ[name] for name in sorted(requested) if name in os.environ}


def _is_jsonrpc_request_candidate(message: dict[str, Any]) -> bool:
    return (
        message.get("jsonrpc") == "2.0"
        and isinstance(message.get("method"), str)
        and "id" in message
    )


def _is_jsonrpc_response_candidate(message: dict[str, Any]) -> bool:
    return (
        message.get("jsonrpc") == "2.0"
        and "id" in message
        and "method" not in message
    )


def _is_valid_jsonrpc_response(message: dict[str, Any]) -> bool:
    if not _is_jsonrpc_response_candidate(message) or not _valid_jsonrpc_id(message.get("id")):
        return False
    if not (("result" in message) ^ ("error" in message)):
        return False
    if "error" not in message:
        return True
    error = message.get("error")
    return (
        isinstance(error, dict)
        and isinstance(error.get("code"), int)
        and not isinstance(error.get("code"), bool)
        and isinstance(error.get("message"), str)
    )


def _is_valid_jsonrpc_request(message: dict[str, Any]) -> bool:
    if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str) or not message.get("method"):
        return False
    if "result" in message or "error" in message:
        return False
    if "id" in message and not _valid_jsonrpc_id(message.get("id")):
        return False
    return "params" not in message or isinstance(message.get("params"), (dict, list))


def _is_valid_jsonrpc_client_message(message: dict[str, Any]) -> bool:
    return _is_valid_jsonrpc_request(message) or _is_valid_jsonrpc_response(message)


def _enforce_client_message(
    observer: McpRuntimeObserver,
    message: dict[str, Any],
) -> tuple[list[Any], dict[str, Any] | None, str, list[str]]:
    policy_message, protocol_version = _shield_protocol_version(
        message,
        payload_key="params",
        method=str(message.get("method") or ""),
    )
    payload_key = (
        "params"
        if "method" in policy_message
        else "result"
        if "result" in policy_message
        else "error"
    )
    payload = policy_message.get(payload_key, {})
    serialized = json.dumps(payload, ensure_ascii=False, default=str)
    label = "mcp-proxy:client-request" if "method" in message else "mcp-proxy:client-response"
    secret_findings = observer.secret_detector.scan_text(serialized, label)
    pii_findings, pii_entities = observer.pii_detector.scan_text(serialized, label)
    threat_findings = observer.mcp_threat_detector.scan_text(serialized, label)
    detected = [*secret_findings, *pii_findings, *threat_findings]
    rule_ids = sorted({str(finding.rule_id) for finding in detected})
    if secret_findings or any(finding.severity in {"critical", "high"} for finding in threat_findings):
        return detected, None, "block", rule_ids
    if not pii_entities:
        return detected, _restore_protocol_version(dict(policy_message), payload_key, protocol_version), "allow", rule_ids
    transformed = dict(policy_message)
    transformed_payload = sanitize_any(payload)
    sanitized_text = json.dumps(transformed_payload, ensure_ascii=False, default=str)
    if observer.pii_detector.detect_entities(sanitized_text, label):
        transformed_payload = {
            "redacted": True,
            "reason": "k_guard_pii_policy",
            "raw_content_forwarded": False,
        }
    transformed[payload_key] = transformed_payload
    return detected, _restore_protocol_version(transformed, payload_key, protocol_version), "redact", rule_ids


def _enforce_upstream_message(
    observer: McpRuntimeObserver,
    message: dict[str, Any],
    *,
    is_response: bool,
    related_method: str = "",
) -> tuple[Any, dict[str, Any] | None, str]:
    policy_message, protocol_version = _shield_protocol_version(
        message,
        payload_key="result" if is_response else "params",
        method=related_method or str(message.get("method") or ""),
    )
    label = "mcp-proxy:upstream-response" if is_response else "mcp-proxy:upstream-message"
    serialized = json.dumps(policy_message, ensure_ascii=False)
    result, forwarded = observer.enforce_text(serialized, label)
    policy = result.metadata.get("runtime_policy", {})
    interceptor = policy.get("interceptor", {}) if isinstance(policy, dict) else {}
    actions = interceptor.get("actions", {}) if isinstance(interceptor, dict) else {}
    action = "block" if int(actions.get("block", 0)) else ("redact" if int(actions.get("redact", 0)) else "allow")
    if not is_response:
        threat_findings = observer.mcp_threat_detector.scan_text(serialized, label)
        result.findings.extend(threat_findings)
        result.finalize()
        if any(finding.severity in {"critical", "high"} for finding in threat_findings):
            action = "block"
    if not forwarded:
        return result, (_blocked_parse_response(message.get("id")) if is_response else None), "block"
    candidate = forwarded[0]
    if not isinstance(candidate, dict):
        return result, (_blocked_parse_response(message.get("id")) if is_response else None), "block"
    if is_response:
        return result, _restore_protocol_version(candidate, "result", protocol_version), action
    if action == "block":
        return result, None, action
    transformed = {key: candidate[key] for key in message if key in candidate}
    if transformed != message:
        action = "redact"
    return result, _restore_protocol_version(transformed, "params", protocol_version), action


def _shield_protocol_version(
    message: dict[str, Any],
    *,
    payload_key: str,
    method: str,
) -> tuple[dict[str, Any], str | None]:
    if method != "initialize":
        return dict(message), None
    payload = message.get(payload_key)
    if not isinstance(payload, dict):
        return dict(message), None
    protocol_version = payload.get("protocolVersion")
    if not isinstance(protocol_version, str) or not protocol_version:
        return dict(message), None
    transformed = dict(message)
    transformed_payload = dict(payload)
    transformed_payload["protocolVersion"] = _PROTOCOL_VERSION_PLACEHOLDER
    transformed[payload_key] = transformed_payload
    return transformed, protocol_version


def _restore_protocol_version(
    message: dict[str, Any],
    payload_key: str,
    protocol_version: str | None,
) -> dict[str, Any]:
    if protocol_version is None:
        return message
    payload = message.get(payload_key)
    if not isinstance(payload, dict):
        return message
    transformed = dict(message)
    transformed_payload = dict(payload)
    if transformed_payload.get("protocolVersion") == _PROTOCOL_VERSION_PLACEHOLDER:
        transformed_payload["protocolVersion"] = protocol_version
    transformed[payload_key] = transformed_payload
    return transformed


def _terminate_process_tree(process: subprocess.Popen[str], *, force: bool) -> None:
    if os.name == "nt":
        job_handle = getattr(process, "_k_guard_job_handle", None)
        if job_handle:
            try:
                import ctypes
                from ctypes import wintypes

                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
                kernel32.TerminateJobObject.restype = wintypes.BOOL
                if kernel32.TerminateJobObject(job_handle, 1):
                    _close_windows_kill_job(process)
                    return
            except OSError:
                pass
        command = ["taskkill", "/PID", str(process.pid), "/T"]
        if force:
            command.append("/F")
        try:
            completed = subprocess.run(
                command,
                shell=False,
                check=False,
                capture_output=True,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if completed.returncode == 0:
                return
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
            return
        except (OSError, ProcessLookupError):
            pass
    if process.poll() is not None:
        return
    try:
        process.kill() if force else process.terminate()
    except OSError:
        pass


def _attach_windows_kill_job(process: subprocess.Popen[str]) -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        from ctypes import wintypes

        class JobObjectBasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_uint64),
                ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64),
                ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64),
                ("OtherTransferCount", ctypes.c_uint64),
            ]

        class JobObjectExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JobObjectBasicLimitInformation),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        job_handle = kernel32.CreateJobObjectW(None, None)
        if not job_handle:
            return
        information = JobObjectExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = 0x00002000
        configured = kernel32.SetInformationJobObject(
            job_handle,
            9,
            ctypes.byref(information),
            ctypes.sizeof(information),
        )
        assigned = configured and kernel32.AssignProcessToJobObject(
            job_handle,
            wintypes.HANDLE(process._handle),  # type: ignore[attr-defined]
        )
        if not assigned:
            kernel32.CloseHandle(job_handle)
            return
        setattr(process, "_k_guard_job_handle", job_handle)
    except (AttributeError, OSError, TypeError):
        return


def _close_windows_kill_job(process: subprocess.Popen[str]) -> None:
    job_handle = getattr(process, "_k_guard_job_handle", None)
    if not job_handle:
        return
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle(job_handle)
    except OSError:
        pass
    setattr(process, "_k_guard_job_handle", None)


def _rpc_id_key(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _blocked_parse_response(request_id: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32002,
            "message": "K-Guard blocked an invalid or unsafe upstream response",
            "data": {"raw_content_forwarded": False},
        },
    }


def _blocked_client_response(request_id: Any, rule_ids: list[str]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32003,
            "message": "K-Guard blocked an unsafe MCP request",
            "data": {"rule_ids": rule_ids, "raw_content_forwarded": False},
        },
    }


def _blocked_access_response(request_id: Any, reason: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32003,
            "message": "K-Guard access policy denied the request",
            "data": {
                "reason": reason,
                "retryable": False,
                "raw_returned": False,
            },
        },
    }


def _blocked_upstream_request_response(request_id: Any, rule_ids: list[str]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32004,
            "message": "K-Guard blocked an unsafe server-initiated MCP request or client response",
            "data": {"rule_ids": sorted(set(rule_ids)), "raw_content_forwarded": False},
        },
    }


def _duplicate_request_response(request_id: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32600,
            "message": "K-Guard blocked a duplicate outstanding JSON-RPC request id",
            "data": {"raw_content_forwarded": False},
        },
    }


def _invalid_upstream_request_response(request_id: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32600,
            "message": "K-Guard blocked an invalid server-initiated MCP request",
            "data": {"raw_content_forwarded": False},
        },
    }


def _invalid_client_response(request_id: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32600,
            "message": "K-Guard blocked an invalid MCP request",
            "data": {"raw_content_forwarded": False},
        },
    }


def _write_protocol_message(destination: TextIO, message: dict[str, Any], lock: threading.Lock) -> None:
    with lock:
        destination.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
        destination.flush()


def _write_upstream_message(destination: TextIO, message: dict[str, Any], lock: threading.Lock) -> bool:
    try:
        with lock:
            destination.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
            destination.flush()
    except (BrokenPipeError, OSError, ValueError):
        return False
    return True


def _record_error(errors: list[dict[str, str]], kind: str, exc: BaseException) -> None:
    errors.append({"kind": kind, "type": type(exc).__name__, "detail_ref": evidence_hash(str(exc))})


def _diagnostic(destination: TextIO, message: str) -> None:
    destination.write("[mcp-proxy] " + redact_text(message) + "\n")
    destination.flush()


def _record_stdio_receipt(
    chain: RuntimeMediationReceiptChain | None,
    errors: list[dict[str, str]],
    **kwargs: Any,
) -> bool:
    if chain is None:
        return True
    try:
        chain.record(**kwargs)
    except RuntimeMediationReceiptError as exc:
        _record_error(errors, "mediation_receipt_persist_failed", exc)
        return False
    return True


def _empty_report(
    argv: list[str],
    status: str,
    *,
    receipt_chain: RuntimeMediationReceiptChain | None = None,
    toolchain_contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _proxy_report(
        argv,
        Counter(),
        [],
        [{"kind": status, "type": "ValueError", "detail_ref": evidence_hash(status)}],
        2,
        receipt_chain=receipt_chain,
        toolchain_contract=toolchain_contract,
    )


def _proxy_report(
    argv: list[str],
    stats: Counter[str],
    findings: list[dict[str, Any]],
    errors: list[dict[str, str]],
    upstream_return_code: int,
    *,
    access_summary: dict[str, Any] | None = None,
    receipt_chain: RuntimeMediationReceiptChain | None = None,
    toolchain_contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    passed = not errors and upstream_return_code == 0
    toolchain = toolchain_contract or mcp_stdio_proxy_toolchain_contract()
    payload = {
        "schema": "k_guard_mcp_stdio_proxy_report.v1",
        "raw_free": True,
        "passed": passed,
        "control_status": "completed" if passed else "failed_closed",
        "mode": "stdio_jsonl_live_proxy",
        "transport": "jsonl",
        "toolchain_contract": toolchain,
        "enforcement_contract": {
            "client_to_upstream": "inspect_block_or_redact_before_forward",
            "upstream_to_client": "inspect_block_or_redact_before_forward",
            "invalid_jsonrpc": "fail_closed",
            "request_enforcement": True,
            "response_enforcement": True,
            "notification_enforcement": True,
            "receipt_persist_before_forward": True,
            "raw_returned": False,
        },
        "access_control": access_summary
        or {
            "enabled": False,
            "default_action": "content-policy-only",
            "raw_free": True,
            "raw_returned": False,
        },
        "upstream": {
            "shell": False,
            "argv_count": len(argv),
            "argv_refs": [evidence_hash(item) for item in argv],
            "hash_scheme": evidence_hash_scheme(),
            "return_code": upstream_return_code,
        },
        "stats": dict(sorted(stats.items())),
        "finding_count": len(findings),
        "findings": findings,
        "errors": errors,
    }
    sanitized = sanitize_any(payload)
    chain = receipt_chain or RuntimeMediationReceiptChain(
        transport="jsonl",
        toolchain_ref=str(toolchain.get("sha256") or ("0" * 64)),
    )
    sanitized["mediation_receipts"] = chain.export()
    sanitized["evidence_bundle"] = evidence_bundle(
        subject="mcp_stdio_jsonl_runtime",
        producer="k_guard_mcp.mcp_proxy",
        artifacts=[object_artifact("runtime-report", sanitized, role="runtime")],
    )
    return sanitized


def _write_report(report_path: str | Path | None, report: dict[str, Any], diagnostic_output: TextIO) -> bool:
    if report_path is None:
        return True
    try:
        path = Path(report_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
    except OSError as exc:
        _diagnostic(diagnostic_output, f"could not write proxy report: {exc}")
        try:
            Path(report_path).with_name(Path(report_path).name + ".tmp").unlink(missing_ok=True)
        except OSError:
            pass
        return False
    return True
