from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "execute_supervisor_review.py"
SPEC = importlib.util.spec_from_file_location("execute_supervisor_review_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)


TARGET = {
    "head_git_oid": "a" * 40,
    "dirty_path_set_sha256": "b" * 64,
    "dirty_worktree_sha256": "c" * 64,
}
MANIFEST = "d" * 64
PACKET = "e" * 64


def _terminal(provider: str, verdict: str = "GO") -> dict[str, object]:
    return {
        "verdict": verdict,
        "blocker_count": 0 if verdict != "HOLD" else 1,
        "nonblocking_count": 0,
        "claim_boundary_confirmed": verdict != "BLOCKED",
        "blocker_codes": [] if verdict != "HOLD" else ["CLAIM_BOUNDARY_GAP"],
        "nonblocking_codes": [],
        "finding_summary": "DIRECT_FILES_READ: reviewed listed files" if provider == "claude" else "packet reviewed",
    }


def _wrapped(provider: str, verdict: str = "GO", *, direct_path: str = "a.py") -> bytes:
    text = json.dumps(_terminal(provider, verdict), separators=(",", ":"))
    if provider == "claude":
        return "\n".join(
            (
                json.dumps(
                    {
                        "type": "assistant",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_use",
                                    "id": "read-1",
                                    "name": "Read",
                                    "input": {"file_path": direct_path},
                                }
                            ]
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "user",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_result",
                                    "tool_use_id": "read-1",
                                    "content": "discarded",
                                }
                            ]
                        },
                    }
                ),
                json.dumps({"type": "result", "is_error": False, "subtype": "success", "result": text}),
            )
        ).encode("utf-8")
    if provider == "grok":
        return json.dumps({"text": text}).encode("utf-8")
    return "\n".join(
        (
            json.dumps({"type": "agent_event", "event": {"type": "content_start", "contentType": "reasoning"}}),
            json.dumps({"type": "run_result", "text": text}),
        )
    ).encode("utf-8")


def _approved_payload_manifest(
    tmp_path: Path,
    *,
    root: Path,
    direct_files: list[str],
    claim_boundary: str,
    external_direct_files: list[dict[str, object]] | None = None,
) -> tuple[Path, str]:
    external_direct_files = external_direct_files or []
    repository_entries = []
    total = 0
    for relative in direct_files:
        digest, byte_count = review._sha256_file(root / relative)
        repository_entries.append({"path": relative, "byte_count": byte_count, "sha256": digest})
        total += byte_count
    external_entries = [
        {
            "label": str(item["label"]),
            "path": Path(item["_path"]).relative_to(tmp_path).as_posix(),
            "byte_count": item["byte_count"],
            "sha256": item["sha256"],
        }
        for item in external_direct_files
    ]
    total += sum(int(item["byte_count"]) for item in external_entries)
    direct_ids = direct_files + [str(item["id"]) for item in external_direct_files]
    payload = {
        "schema": review.APPROVED_PAYLOAD_MANIFEST_SCHEMA,
        "claim_boundary": claim_boundary,
        "target": review._capture_target(root),
        "repository_direct_files": repository_entries,
        "external_direct_files": external_entries,
        "direct_file_count": len(direct_ids),
        "direct_file_total_byte_count": total,
        "direct_file_set_sha256": review._direct_file_binding(direct_ids)["sha256"],
        "claude": {
            "model": "claude-opus-5",
            "effort": "max",
            "permission_mode": "plan",
            "tools": ["Read"],
        },
        "grok": {
            "model": "grok-4.6",
            "reasoning_effort": "xhigh",
            "review_scope": "sanitized-packet",
            "subagents": False,
            "web_search": False,
        },
        "raw_credentials_included": False,
        "raw_environment_included": False,
        "transmission_authorized": False,
    }
    path = tmp_path / "approved-payload-manifest.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    digest, _ = review._sha256_file(path)
    return path, digest


def test_provider_commands_pin_exact_models_and_correct_glm_model_form(monkeypatch: pytest.MonkeyPatch) -> None:
    packet = {"schema": "test", "raw_returned": False}
    executables = {"claude": "claude.exe", "grok": "grok.exe", "glm": "cline.exe"}
    schema = review._terminal_schema()
    resolved = {
        "claude.exe": "C:/tools/claude.cmd",
        "grok.exe": "C:/tools/grok.exe",
        "cline.exe": "C:/tools/cline.cmd",
    }
    monkeypatch.setattr(review, "resolve_supervisor_executable", lambda value, **_: resolved[value])

    claude = review._provider_command("claude", executables=executables, packet=packet, direct_files=["a.py"], terminal_schema=schema, output_dir=Path("C:/evidence"), timeout_seconds=30)
    grok = review._provider_command("grok", executables=executables, packet=packet, direct_files=["a.py"], terminal_schema=schema, output_dir=Path("C:/evidence"), timeout_seconds=30)
    glm = review._provider_command("glm", executables=executables, packet=packet, direct_files=["a.py"], terminal_schema=schema, output_dir=Path("C:/evidence"), timeout_seconds=30)

    assert "claude-opus-5" in claude
    assert claude[0] == "C:/tools/claude.cmd"
    assert claude[claude.index("--allowedTools") + 1] == "Read"
    assert claude[claude.index("--max-turns") + 1] == "100"
    assert claude[claude.index("--output-format") + 1] == "stream-json"
    assert "--verbose" in claude
    assert "grok-4.6" in grok and "--tools" in grok
    assert grok[grok.index("--reasoning-effort") + 1] == "xhigh"
    assert grok[0] == "C:/tools/grok.exe"
    assert "cline-pass/glm-5.2" in glm
    assert glm[0] == "C:/tools/cline.cmd"
    assert "-P" not in glm
    assert glm[glm.index("--auto-approve") + 1] == "false"
    assert "--plan" not in glm


def test_long_review_packet_uses_native_executable_not_cmd_shim(monkeypatch: pytest.MonkeyPatch) -> None:
    packet = {"schema": "test", "raw_returned": False, "payload": "x" * 12_000}
    monkeypatch.setattr(
        review,
        "resolve_supervisor_executable",
        lambda value, **_: "C:/tools/claude.exe" if value == "claude" else "C:/tools/cline.exe",
    )

    claude = review._provider_command(
        "claude",
        executables={"claude": "claude", "grok": "grok", "glm": "cline"},
        packet=packet,
        direct_files=["a.py"],
        terminal_schema=review._terminal_schema(),
        output_dir=Path("C:/evidence"),
        timeout_seconds=30,
    )
    glm = review._provider_command(
        "glm",
        executables={"claude": "claude", "grok": "grok", "glm": "cline"},
        packet=packet,
        direct_files=["a.py"],
        terminal_schema=review._terminal_schema(),
        output_dir=Path("C:/evidence"),
        timeout_seconds=30,
    )

    assert claude[0].endswith(".exe")
    assert glm[0].endswith(".exe")
    assert max(len(value) for value in [*claude, *glm]) > 8_191


def test_terminal_parsers_accept_only_provider_terminal_envelopes() -> None:
    for provider in ("claude", "grok", "glm"):
        terminal = review.parse_terminal(provider, _wrapped(provider))
        assert terminal is not None
        assert terminal["verdict"] == "GO"

    ambiguous_glm = _wrapped("glm") + b"\n" + json.dumps(
        {"type": "run_result", "text": json.dumps(_terminal("glm"))}
    ).encode("utf-8")
    assert review.parse_terminal("glm", ambiguous_glm) is None
    assert review.parse_terminal("grok", b'{"text":"not-json"}') is None
    assert review.parse_terminal_with_reason("grok", b'{"text":"not-json"}')[1] == "terminal_json"


def test_claude_stream_prefers_a_successful_structured_output_tool_result() -> None:
    terminal = _terminal("claude")
    raw = "\n".join(
        (
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "structured-1",
                                "name": "StructuredOutput",
                                "input": terminal,
                            }
                        ]
                    },
                }
            ),
            json.dumps(
                {
                    "type": "user",
                    "message": {
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": "structured-1",
                                "content": "discarded",
                            }
                        ]
                    },
                }
            ),
            json.dumps({"type": "result", "is_error": False, "subtype": "success", "result": "not-json"}),
        )
    ).encode("utf-8")
    parsed = review.parse_terminal("claude", raw)
    assert parsed is not None
    assert parsed["verdict"] == "GO"


def test_terminal_parser_accepts_one_fenced_terminal_json_but_not_trailing_text() -> None:
    terminal = json.dumps(_terminal("grok"), separators=(",", ":"))
    wrapped = json.dumps({"text": "```json\n" + terminal + "\n```"}).encode("utf-8")
    assert review.parse_terminal("grok", wrapped) is not None
    trailing = json.dumps({"text": terminal + "\nextra"}).encode("utf-8")
    assert review.parse_terminal("grok", trailing) is None
    prefixed = json.dumps({"text": "Here is the result: " + terminal}).encode("utf-8")
    assert review.parse_terminal("grok", prefixed) is None


def test_claude_stream_recovers_one_embedded_terminal_but_rejects_two() -> None:
    terminal = json.dumps(_terminal("claude"), separators=(",", ":"))
    one = "direct review narration\n" + terminal + "\nend"
    one_raw = "\n".join(
        (
            json.dumps({"type": "result", "is_error": False, "subtype": "success", "result": one}),
        )
    ).encode("utf-8")
    assert review.parse_terminal("claude", one_raw) is not None

    two = terminal + "\n" + terminal
    two_raw = "\n".join(
        (
            json.dumps({"type": "result", "is_error": False, "subtype": "success", "result": two}),
        )
    ).encode("utf-8")
    assert review.parse_terminal("claude", two_raw) is None


def test_terminal_parser_ignores_advisory_summary_size_and_extra_fields() -> None:
    accepted = _terminal("grok")
    accepted["finding_summary"] = "x" * 2001
    accepted["provider_note"] = "ignored"
    accepted_raw = json.dumps({"text": json.dumps(accepted)}).encode("utf-8")
    assert review.parse_terminal("grok", accepted_raw) is not None

    rejected = dict(accepted)
    del rejected["claim_boundary_confirmed"]
    rejected_raw = json.dumps({"text": json.dumps(rejected)}).encode("utf-8")
    assert review.parse_terminal("grok", rejected_raw) is None
    assert review.parse_terminal_with_reason("grok", rejected_raw)[1] == "terminal_decision_fields"


def test_claude_max_turns_is_recorded_without_provider_raw_text() -> None:
    raw = json.dumps({"is_error": True, "subtype": "error_max_turns", "result": "discarded"}).encode("utf-8")
    assert review.parse_terminal_with_reason("claude", raw) == (None, "claude_error_max_turns")


def test_terminal_codes_must_match_counts_and_are_retained_in_sanitized_summary() -> None:
    terminal = _terminal("grok", "HOLD")
    raw = json.dumps({"text": json.dumps(terminal)}).encode("utf-8")
    parsed = review.parse_terminal("grok", raw)
    assert parsed is not None
    assert parsed["blocker_codes"] == ["CLAIM_BOUNDARY_GAP"]

    terminal["blocker_codes"] = []
    invalid = json.dumps({"text": json.dumps(terminal)}).encode("utf-8")
    assert review.parse_terminal_with_reason("grok", invalid)[1] == "terminal_code_counts"


def test_terminal_codes_may_repeat_for_distinct_defects_in_one_category() -> None:
    terminal = _terminal("grok", "HOLD")
    terminal["blocker_count"] = 2
    terminal["blocker_codes"] = ["CLAIM_BOUNDARY_GAP", "CLAIM_BOUNDARY_GAP"]
    raw = json.dumps({"text": json.dumps(terminal)}).encode("utf-8")
    parsed = review.parse_terminal("grok", raw)
    assert parsed is not None
    assert parsed["blocker_codes"] == ["CLAIM_BOUNDARY_GAP", "CLAIM_BOUNDARY_GAP"]


def test_every_provider_prompt_contains_the_terminal_contract() -> None:
    packet = {"schema": "test", "raw_returned": False}
    executables = {"claude": "claude.exe", "grok": "grok.exe", "glm": "cline.exe"}
    schema = review._terminal_schema()
    commands: dict[str, list[str]] = {}
    for provider in ("claude", "grok", "glm"):
        command = review._provider_command(
            provider,
            executables=executables,
            packet=packet,
            direct_files=["a.py"],
            terminal_schema=schema,
            output_dir=Path("C:/evidence"),
            timeout_seconds=30,
        )
        commands[provider] = command
        assert any("A code may repeat when distinct defects share a category." in value for value in command)
    assert any("independent raw-free evidence auditor" in value for value in commands["grok"])


def test_error_classifier_does_not_misread_authority_as_authentication() -> None:
    assert review._blocked_reason(b"invalid authority evidence", b"") == "BLOCKED_PROVIDER"


def test_invalid_claude_terminal_is_provider_blocked_even_if_stream_has_a_rate_event(tmp_path: Path) -> None:
    raw = b'{"type":"rate_limit_event"}\n{"type":"result","is_error":false,"result":"not-json"}\n'

    def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(command, 0, stdout=raw, stderr=b"")

    receipt, _ = review.review_provider(
        "claude",
        executables={"claude": "claude.exe", "grok": "grok.exe", "glm": "cline.exe"},
        repo_root=tmp_path,
        output_dir=tmp_path,
        target=TARGET,
        evidence_manifest_sha256=MANIFEST,
        review_packet_sha256=PACKET,
        packet={"schema": "test", "raw_returned": False},
        direct_files=["a.py"],
        direct_file_binding=review._direct_file_binding(["a.py"]),
        terminal_schema=review._terminal_schema(),
        timeout_seconds=30,
        runner=runner,
    )
    assert receipt["blocked_reason"] == "BLOCKED_PROVIDER"


def test_review_provider_discards_raw_output_and_requires_claude_tool_attestation(tmp_path: Path) -> None:
    def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
        provider = "claude" if "claude-opus-5" in command else "grok" if "grok-4.6" in command else "glm"
        return subprocess.CompletedProcess(command, 0, stdout=_wrapped(provider), stderr=b"")

    (tmp_path / "a.py").write_text("pass\n", encoding="utf-8")
    binding = review._direct_file_binding(["a.py"])
    receipt, summary = review.review_provider(
        "claude",
        executables={"claude": "claude.exe", "grok": "grok.exe", "glm": "cline.exe"},
        repo_root=tmp_path,
        output_dir=tmp_path,
        target=TARGET,
        evidence_manifest_sha256=MANIFEST,
        review_packet_sha256=PACKET,
        packet={"schema": "test", "raw_returned": False},
        direct_files=["a.py"],
        direct_file_binding=binding,
        terminal_schema=review._terminal_schema(),
        timeout_seconds=30,
        runner=runner,
    )

    assert receipt["review_scope"] == "direct-files"
    assert receipt["verdict"] == "GO"
    assert receipt["direct_file_attestation"] == {
        "schema": "k_guard_direct_file_tool_attestation.v1",
        "file_count": 1,
        "file_set_sha256": binding["sha256"],
        "raw_returned": False,
    }
    assert summary["summary"] == review.TRANSPORT_SUMMARY
    assert "DIRECT_FILES_READ" not in json.dumps(receipt)


def test_claude_read_tool_use_without_successful_tool_result_is_blocked(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("pass\n", encoding="utf-8")
    terminal = json.dumps(_terminal("claude"), separators=(",", ":"))
    raw = "\n".join(
        (
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "read-1",
                                "name": "Read",
                                "input": {"file_path": "a.py"},
                            }
                        ]
                    },
                }
            ),
            json.dumps({"type": "result", "is_error": False, "subtype": "success", "result": terminal}),
        )
    ).encode("utf-8")

    def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(command, 0, stdout=raw, stderr=b"")

    receipt, summary = review.review_provider(
        "claude",
        executables={"claude": "claude.exe", "grok": "grok.exe", "glm": "cline.exe"},
        repo_root=tmp_path,
        output_dir=tmp_path,
        target=TARGET,
        evidence_manifest_sha256=MANIFEST,
        review_packet_sha256=PACKET,
        packet={"schema": "test", "raw_returned": False},
        direct_files=["a.py"],
        direct_file_binding=review._direct_file_binding(["a.py"]),
        terminal_schema=review._terminal_schema(),
        timeout_seconds=30,
        runner=runner,
    )

    assert receipt["verdict"] == "BLOCKED"
    assert summary["transport_status"] == "direct_file_tool_attestation_missing"


def test_execute_review_binds_verified_claude_tool_attestation_without_raw_output(tmp_path: Path) -> None:
    root = SCRIPT.parents[1]
    direct_file = "scripts/execute_supervisor_review.py"
    claim_boundary = "A fake transport test proves only receipt binding and never product performance."
    approved_manifest, approved_sha256 = _approved_payload_manifest(
        tmp_path,
        root=root,
        direct_files=[direct_file],
        claim_boundary=claim_boundary,
    )

    def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
        provider = "claude" if "claude-opus-5" in command else "grok" if "grok-4.6" in command else "glm"
        return subprocess.CompletedProcess(command, 0, stdout=_wrapped(provider, direct_path=direct_file), stderr=b"")

    artifacts = [review._parse_labeled_file("implementation=scripts/execute_supervisor_review.py", root)]
    output_dir = tmp_path / "review-evidence"
    decision = review.execute_review(
        repo_root=root,
        output_dir=output_dir,
        field_id="supervisor-tool-attestation-contract",
        claim_boundary=claim_boundary,
        review_questions=["Does the receipt bind a successful Claude Read event to the listed direct file?"],
        direct_files=[direct_file],
        artifacts=artifacts,
        test_attestation={
            "focused_passed": True,
            "full_regression_passed": True,
            "repeat_required": True,
            "repeat_exact": False,
            "raw_returned": False,
        },
        test_basis={"focused": "fake transport", "full_regression": "fake transport", "repeat": "fake transport"},
        executables={"claude": "claude.exe", "grok": "grok.exe", "glm": "cline.exe"},
        timeout_seconds=30,
        runner=runner,
        approved_payload_manifest=approved_manifest,
        operator_approved_manifest_sha256=approved_sha256,
    )

    receipts = json.loads((output_dir / "supervisor-receipts.json").read_text(encoding="utf-8"))
    packet = json.loads((output_dir / "review-packet.json").read_text(encoding="utf-8"))
    assert decision["status"] == "HOLD"
    assert "test_attestation_incomplete" in decision["failure_reasons"]
    assert receipts["schema"] == "k_guard_supervisor_review_receipts.v5"
    assert receipts["direct_file_count"] == 1
    assert receipts["receipts"][0]["direct_file_attestation"]["raw_returned"] is False
    assert packet["required_models"] == {"claude": "claude-opus-5", "grok": "grok-4.6"}
    assert set(packet["reviewer_roles"]) == {"claude", "grok"}
    assert packet["artifact_manifest"][0]["label"] == "implementation"
    assert packet["artifact_manifest"][0]["repository_path"] == direct_file
    assert packet["approved_payload_binding"]["manifest_sha256"] == approved_sha256
    assert packet["pre_promotion_contract"]["state"] == "unpromoted-baseline"
    assert packet["reviewer_roles"]["grok"].startswith("independent raw-free")
    assert "DIRECT_FILES_READ" not in (output_dir / "supervisor-receipts.json").read_text(encoding="utf-8")


def test_execute_review_rejects_self_attested_repeat_exactness(tmp_path: Path) -> None:
    root = SCRIPT.parents[1]
    artifact = review._parse_labeled_file("implementation=scripts/execute_supervisor_review.py", root)
    with pytest.raises(ValueError, match="repeat comparator"):
        review.execute_review(
            repo_root=root,
            output_dir=tmp_path / "review-evidence",
            field_id="self-attested-repeat-is-invalid",
            claim_boundary="Test only.",
            review_questions=["Test only."],
            direct_files=["scripts/execute_supervisor_review.py"],
            artifacts=[artifact],
            test_attestation={
                "focused_passed": True,
                "full_regression_passed": True,
                "repeat_required": True,
                "repeat_exact": True,
                "raw_returned": False,
            },
            test_basis={"focused": "test", "full_regression": "test", "repeat": "test"},
            executables={"claude": "claude.exe", "grok": "grok.exe", "glm": "cline.exe"},
            timeout_seconds=30,
        )


def test_execute_review_rejects_invalid_field_id_before_provider_invocation(tmp_path: Path) -> None:
    root = SCRIPT.parents[1]
    artifact = review._parse_labeled_file("implementation=scripts/execute_supervisor_review.py", root)

    def runner(*_: object, **__: object) -> subprocess.CompletedProcess[bytes]:
        raise AssertionError("provider must not be invoked for an invalid field id")

    with pytest.raises(ValueError, match="field_id is invalid"):
        review.execute_review(
            repo_root=root,
            output_dir=tmp_path / "review-evidence",
            field_id="Invalid-Uppercase-Field",
            claim_boundary="Test only.",
            review_questions=["Test only."],
            direct_files=["scripts/execute_supervisor_review.py"],
            artifacts=[artifact],
            test_attestation={
                "focused_passed": False,
                "full_regression_passed": False,
                "repeat_required": True,
                "repeat_exact": False,
                "raw_returned": False,
            },
            test_basis={"focused": "test", "full_regression": "test", "repeat": "test"},
            executables={"claude": "claude.exe", "grok": "grok.exe", "glm": "cline.exe"},
            timeout_seconds=30,
            runner=runner,
        )

    assert not (tmp_path / "review-evidence").exists()


def test_artifact_manifest_hides_paths_and_rechecks_content(tmp_path: Path) -> None:
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("one\n", encoding="utf-8")
    parsed = review._parse_labeled_file(f"proof={artifact}", tmp_path)
    manifest = review._artifact_manifest([parsed])

    assert manifest[0]["label"] == "proof"
    assert manifest[0]["repository_path"] == "evidence.txt"
    assert "_path" not in manifest[0]
    assert str(artifact) not in json.dumps(manifest)
    assert review._artifact_integrity([parsed]) is True
    artifact.write_text("two\n", encoding="utf-8")
    assert review._artifact_integrity([parsed]) is False


def test_approved_payload_binds_external_direct_evidence_without_packet_path_leak(tmp_path: Path) -> None:
    root = SCRIPT.parents[1]
    direct_file = "scripts/execute_supervisor_review.py"
    claim_boundary = "External receipt binding only."
    external_path = tmp_path / "gate-b-receipt.json"
    external_path.write_text('{"raw_returned":false}\n', encoding="utf-8")
    external = review._parse_external_direct_file(f"gate-b={external_path}", root)
    approved_manifest, approved_sha256 = _approved_payload_manifest(
        tmp_path,
        root=root,
        direct_files=[direct_file],
        claim_boundary=claim_boundary,
        external_direct_files=[external],
    )
    artifacts = [
        review._parse_labeled_file(f"implementation={root / direct_file}", root),
        review._parse_labeled_file(f"gate-b={external_path}", root),
    ]
    resolved_repository = [review._repo_relative_file(root, direct_file)]
    direct_binding = review._direct_file_binding([direct_file, "external:gate-b"])
    binding = review._load_approved_payload_binding(
        approved_manifest,
        operator_approved_sha256=approved_sha256,
        repo_root=root,
        target=review._capture_target(root),
        claim_boundary=claim_boundary,
        repository_direct=resolved_repository,
        external_direct=[external],
        artifact_manifest=review._artifact_manifest(artifacts),
        direct_file_binding=direct_binding,
    )

    assert binding["external_direct_file_count"] == 1
    assert binding["operator_approval_bound"] is True
    packet = review._build_packet(
        field_id="external-direct-binding",
        target=review._capture_target(root),
        manifest_sha256="a" * 64,
        claim_boundary=claim_boundary,
        review_questions=["Is external evidence bound without leaking its absolute path to Grok?"],
        direct_files=[direct_file, "external:gate-b"],
        direct_file_binding=direct_binding,
        artifact_manifest=review._artifact_manifest(artifacts),
        approved_payload_binding=binding,
        test_attestation={
            "focused_passed": True,
            "full_regression_passed": True,
            "repeat_required": True,
            "repeat_exact": False,
            "raw_returned": False,
        },
        test_basis={"focused": "test", "full_regression": "test", "repeat": "test"},
    )
    assert str(external_path) not in json.dumps(packet)
    assert packet["review_scope"]["claude_direct_file_ids"] == [direct_file, "external:gate-b"]
    assert review._matched_direct_files(
        [direct_file, str(external_path)],
        repo_root=root,
        direct_files=[direct_file, str(external_path)],
    )
