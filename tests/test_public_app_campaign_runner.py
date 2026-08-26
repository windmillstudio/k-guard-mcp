from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from k_guard_mcp.release_policy import AUTOMATIC_RELEASE_RULES


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "run_public_app_campaign",
    ROOT / "scripts" / "run_public_app_campaign.py",
)
assert SPEC and SPEC.loader
campaign_runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign_runner)


def test_campaign_runner_imports_analyzer_from_this_repository() -> None:
    assert campaign_runner.ANALYZER_PACKAGE_DIR == (
        ROOT / "src" / "k_guard_mcp"
    ).resolve()


def test_child_process_policy_contract_rejects_missing_or_forged_proof() -> None:
    policy = {
        "schema": "k_guard_windows_child_process_policy.v1",
        "policy_id": 13,
        "required_flags": 1,
        "before_flags": 0,
        "set_succeeded": True,
        "set_error": 0,
        "after_flags": 1,
        "disable_attempt_canary": {
            "blocked": True,
            "winerror": 5,
            "flags_after_attempt": 1,
        },
        "prebound_create_process_canary": {
            "api": "kernel32.CreateProcessW",
            "blocked": True,
            "winerror": 367,
            "unexpected_process_created": False,
        },
        "prebound_shell_execute_canary": {
            "api": "shell32.ShellExecuteW",
            "blocked": True,
            "result": 5,
            "winerror": 367,
        },
        "final_query_succeeded": True,
        "final_flags": 1,
        "passed": True,
        "raw_returned": False,
    }
    assert campaign_runner._child_process_policy_contract_valid(
        {"child_process_policy": policy}
    )

    for missing in (
        "final_flags",
        "set_error",
        "disable_attempt_canary",
        "prebound_create_process_canary",
        "prebound_shell_execute_canary",
    ):
        malformed = dict(policy)
        malformed.pop(missing)
        assert not campaign_runner._child_process_policy_contract_valid(
            {"child_process_policy": malformed}
        )
    forged = dict(policy)
    forged["final_flags"] = 0
    assert not campaign_runner._child_process_policy_contract_valid(
        {"child_process_policy": forged}
    )


def test_scorer_reuses_the_complete_runtime_monitor_contract() -> None:
    from scripts import public_field_effectiveness as scorer
    from scripts import run_public_app_campaign as canonical_runner

    assert scorer._runtime_monitor_contract_valid is canonical_runner._runtime_monitor_contract_valid

    incomplete_receipt = {
        "mutation_monitors": [
            {
                "root": root,
                "event_count": 0,
                "events": [],
                "error": None,
                "liveness": {"passed": True},
            }
            for root in ("scanner_prefix", "base_runtime", "protocol_repository")
        ],
        "mutation_canary_monitor": {
            "root": "monitor_canary",
            "event_count": 4,
            "events": [{"action": 1, "relative_path": str(index)} for index in range(4)],
            "error": None,
            "liveness": {"passed": True},
        },
    }
    assert scorer._runtime_monitor_contract_valid(incomplete_receipt) is False


def test_normalize_workspace_paths_redacts_only_the_workspace_prefix(tmp_path: Path) -> None:
    workspace = tmp_path / "Public App"
    value = {
        "root": str(workspace),
        "file": str(workspace / "src" / "app.py"),
        "svg": f'<text>{workspace}\\src\\app.py</text><text>{workspace}\\api.py</text>',
        "unrelated": str(tmp_path / "Public Application" / "src" / "app.py"),
    }

    normalized = campaign_runner._normalize_workspace_paths(value, workspace)

    assert normalized["root"] == "<workspace>"
    assert normalized["file"] == "<workspace>/src/app.py"
    assert normalized["svg"] == '<text><workspace>/src/app.py</text><text><workspace>/api.py</text>'
    assert normalized["unrelated"] == value["unrelated"]
    assert not campaign_runner._contains_workspace_path(normalized, workspace)


def test_normalize_workspace_paths_handles_scanner_redaction_before_persistence(tmp_path: Path) -> None:
    workspace = tmp_path / "k-guard-public-apps-20260714-064326" / "demo"
    scanner_redacted_path = campaign_runner.redact_text(str(workspace / "src" / "app.py"))

    normalized = campaign_runner._normalize_workspace_paths(
        {"file": scanner_redacted_path},
        workspace,
    )

    assert normalized == {"file": "<workspace>/src/app.py"}
    assert not campaign_runner._contains_workspace_path(normalized, workspace)
    assert not campaign_runner._contains_local_home_path(normalized)
    assert campaign_runner._contains_local_home_path(
        {"file": (Path.home() / "private" / "report.json").as_posix()}
    )


def test_candidate_rows_are_deterministic_redacted_and_automatic_release_blocking_only() -> None:
    report = {
        "findings": [
            {
                "rule_id": "WEB_UNTRUSTED_INPUT_TO_COMMAND",
                "severity": "critical",
                "confidence": "high",
                "file": "<workspace>/src/exec.js",
                "line_start": 12,
                "artifact_scope": "runtime_source",
                "evidence": "detector_subtype=request_to_command; value redacted",
                "source": "polyglot",
            },
            {
                "rule_id": "SECRET_API_KEY",
                "severity": "high",
                "confidence": "high",
                "file": "<workspace>/tests/fixture.py",
                "line_start": 7,
                "artifact_scope": "test_fixture",
                "evidence": "value redacted",
                "source": "secret",
            },
            {
                "rule_id": "SECRET_BUNDLED_SOURCE_MAP",
                "severity": "high",
                "confidence": "medium",
                "file": "<workspace>/dist/app.js.map",
                "line_start": 1,
                "artifact_scope": "deployable_artifact",
                "evidence": "value redacted",
                "source": "secret",
            },
            {
                "rule_id": "DOC_EXAMPLE",
                "severity": "critical",
                "confidence": "high",
                "file": "<workspace>/README.md",
                "line_start": 3,
                "artifact_scope": "documentation",
                "evidence": "example only",
            },
            {
                "rule_id": "LOW_SIGNAL",
                "severity": "medium",
                "file": "<workspace>/src/query.js",
                "line_start": 20,
                "artifact_scope": "runtime_source",
                "evidence": "review",
            },
        ]
    }

    first = campaign_runner._candidate_rows("demo", "a" * 64, report, limit=10)
    second = campaign_runner._candidate_rows("demo", "a" * 64, report, limit=10)

    assert first == second
    assert len(first) == 1
    assert first[0]["candidate_id"] == first[0]["redacted_fingerprint"].split(":", 1)[1]
    assert first[0]["detector_subtype"] == "request_to_command"
    assert first[0]["source_location"] == "src/exec.js:12"
    assert first[0]["location"] == {
        "kind": "source",
        "source": "src/exec.js:12",
        "body_or_header": None,
    }
    assert first[0]["evidence_refs"] == {}
    assert first[0]["response_hash"] is None
    assert first[0]["scan_report_sha256"] == "a" * 64
    assert first[0]["raw_returned"] is False
    assert "evidence" not in first[0]
    assert {(row["rule_id"], row["artifact_scope"]) for row in first} == {
        ("WEB_UNTRUSTED_INPUT_TO_COMMAND", "runtime_source"),
    }


def test_candidate_evidence_refs_keep_hashes_without_raw_evidence() -> None:
    refs = campaign_runner._redacted_evidence_refs(
        "detector_subtype=missing_rls object_ref=abc123456789 statement_ref=def987654321 "
        "body_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa raw_returned=false"
    )

    assert refs == {
        "body_sha256": "a" * 64,
        "object_ref": "abc123456789",
        "statement_ref": "def987654321",
    }


def test_candidate_rows_skip_findings_without_an_exact_source_line() -> None:
    report = {
        "findings": [
            {
                "rule_id": "CROSS_PLANE_KR_PII_TO_AGENTIC_SINK",
                "severity": "critical",
                "confidence": "high",
                "file": "<workspace>/routes/chat.ts",
                "line_start": None,
                "artifact_scope": "runtime_source",
                "evidence": "detector_subtype=cross-plane",
                "source": "cross-plane",
            },
            {
                "rule_id": "WEB_UNTRUSTED_INPUT_TO_COMMAND",
                "severity": "critical",
                "confidence": "high",
                "file": "<workspace>/routes/login.ts",
                "line_start": 34,
                "artifact_scope": "runtime_source",
                "evidence": "detector_subtype=direct_request_to_command",
                "source": "polyglot",
            },
        ]
    }

    rows = campaign_runner._candidate_rows("demo", "a" * 64, report, limit=3)

    assert [row["source_location"] for row in rows] == ["routes/login.ts:34"]


def test_candidate_sampling_prioritizes_distinct_rules_before_duplicate_lines() -> None:
    report = {
        "findings": [
            {
                "rule_id": "AUTH_JWT_DECODE_WITHOUT_VERIFY",
                "severity": "high",
                "confidence": "high",
                "file": "<workspace>/app.py",
                "line_start": line,
                "artifact_scope": "runtime_source",
                "evidence": f"line_hash={'a' * 16}{line}",
                "source": "test",
            }
            for line in (10, 11, 12)
        ]
        + [
            {
                "rule_id": "CONFIG_CSP_UNSAFE_EVAL",
                "severity": "high",
                "confidence": "high",
                "file": "<workspace>/config.py",
                "line_start": 20,
                "artifact_scope": "runtime_source",
                "evidence": "line_hash=bbbbbbbbbbbbbbbb",
                "source": "test",
            },
            {
                "rule_id": "WEB_UNTRUSTED_INPUT_TO_COMMAND",
                "severity": "high",
                "confidence": "high",
                "file": "<workspace>/route.py",
                "line_start": 30,
                "artifact_scope": "runtime_source",
                "evidence": "line_hash=cccccccccccccccc",
                "source": "test",
            },
        ]
    }

    rows = campaign_runner._candidate_rows("demo", "d" * 64, report, limit=3)

    assert [row["rule_id"] for row in rows] == [
        "AUTH_JWT_DECODE_WITHOUT_VERIFY",
        "CONFIG_CSP_UNSAFE_EVAL",
        "WEB_UNTRUSTED_INPUT_TO_COMMAND",
    ]


def test_candidate_census_keeps_every_locatable_release_blocker() -> None:
    automatic_rules = sorted(AUTOMATIC_RELEASE_RULES)
    report = {
        "findings": [
            {
                "rule_id": rule_id,
                "severity": "high",
                "confidence": "high",
                "file": f"<workspace>/src/{index}.py",
                "line_start": index,
                "artifact_scope": "runtime_source",
                "evidence": f"line_hash={index:016x}",
                "source": "test",
            }
            for index, rule_id in enumerate(automatic_rules, start=1)
        ]
        + [
            {
                "rule_id": automatic_rules[0],
                "severity": "high",
                "confidence": "high",
                "file": "<workspace>/src/unknown.py",
                "line_start": None,
                "artifact_scope": "runtime_source",
                "evidence": "coverage gap",
                "source": "test",
            }
        ]
    }

    rows = campaign_runner._candidate_rows("demo", "e" * 64, report, limit=None)

    assert len(rows) == len(automatic_rules)
    assert {row["rule_id"] for row in rows} == set(automatic_rules)
    assert len(campaign_runner._release_blocking_findings(report)) == len(automatic_rules) + 1
    assert len(campaign_runner._eligible_release_blocking_findings(report)) == len(automatic_rules)


def test_probe_result_requires_both_accepted_rule_and_oracle_file() -> None:
    probe = {
        "probe_id": "known-sql-injection",
        "app": "demo",
        "risk_domain": "sql_injection",
        "oracle_classification": "true_positive",
        "vulnerability": "Request input reaches raw SQL.",
        "oracle_refs": ["src/vulnerable.js:10-15"],
        "accepted_rule_ids": ["WEB_UNTRUSTED_INPUT_TO_SQL"],
    }
    wrong_file_report = {
        "findings": [
            {
                "rule_id": "WEB_UNTRUSTED_INPUT_TO_SQL",
                "file": "<workspace>/src/unrelated.js",
                "line_start": 10,
            }
        ]
    }
    oracle_report = {
        "findings": [
            {
                "rule_id": "WEB_UNTRUSTED_INPUT_TO_SQL",
                "file": "<workspace>/src/vulnerable.js",
                "line_start": 12,
            }
        ]
    }

    missed = campaign_runner._probe_result(probe, "b" * 64, wrong_file_report)
    detected = campaign_runner._probe_result(probe, "c" * 64, oracle_report)

    assert missed["result"] == "false_negative"
    assert missed["matching_findings"] == []
    assert detected["result"] == "detected"
    assert detected["matching_findings"][0]["source_location"] == "src/vulnerable.js:12"
    assert detected["oracle_classification"] == "true_positive"
    assert detected["raw_returned"] is False


def test_campaign_rejects_single_run_before_touching_evidence(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="at least two fresh-process runs"):
        campaign_runner.run_campaign(manifest, tmp_path, tmp_path / "output", runs=1)


def test_run_scan_times_out_fail_closed_and_removes_partial_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = tmp_path / "report.json"
    raw_output = output.with_suffix(".raw.json")
    raw_output.write_text("partial", encoding="utf-8")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(campaign_runner.subprocess, "run", timeout)

    with pytest.raises(campaign_runner.ScanTimeoutError, match="locked 1s timeout"):
        campaign_runner._run_scan(workspace, output, timeout_seconds=1)
    assert not raw_output.exists()


def test_run_scan_binds_nonisolated_child_to_repository_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = tmp_path / "report.json"
    observed: dict[str, object] = {}

    def complete(command, **kwargs):
        observed["command"] = command
        observed["env"] = kwargs["env"]
        raw_output = Path(command[command.index("--json") + 1])
        raw_output.write_text('{"findings": []}\n', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(campaign_runner.subprocess, "run", complete)
    monkeypatch.setenv("PYTHONPATH", "C:/attacker")
    monkeypatch.setenv("PYTHONHOME", "C:/attacker")

    exit_code, _duration, _digest, report = campaign_runner._run_scan(
        workspace,
        output,
    )

    assert exit_code == 0
    assert report == {"findings": []}
    assert observed["command"][1:4] == ["-I", "-B", "-c"]
    assert campaign_runner.NONISOLATED_SCANNER_EXECUTION_MODE in (
        "repo_src_isolated_bootstrap_v1",
    )
    assert "PYTHONPATH" not in observed["env"]
    assert "PYTHONHOME" not in observed["env"]


def test_run_scan_uses_bound_python_in_isolated_no_bytecode_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = tmp_path / "report.json"
    scanner = tmp_path / "scanner-python.exe"
    scanner.write_bytes(b"bound executable")
    launcher = tmp_path / "launcher.py"
    launcher.write_text("# bound launcher\n", encoding="utf-8")
    probe = tmp_path / "probe.py"
    probe.write_text("# bound probe\n", encoding="utf-8")
    source_probe = tmp_path / "source-probe.py"
    source_probe.write_text("# bound source probe\n", encoding="utf-8")
    expected_source_tree = "e" * 64
    expected_source_file_count = 2
    expected_runtime = tmp_path / "runtime.json"
    expected_runtime.write_text(
        json.dumps(
            {
                "prefix_tree": {
                    "files": [
                        {
                            "path": "Lib/site-packages/k_guard_mcp/cli.py",
                            "sha256": "a" * 64,
                            "byte_count": 1,
                        }
                    ]
                },
                "base_runtime_tree": {
                    "files": [
                        {"path": "python311.dll", "sha256": "b" * 64, "byte_count": 1}
                    ]
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    receipt_path = tmp_path / "receipt.json"
    observed: dict[str, object] = {}

    def complete(command, **kwargs):
        observed["command"] = command
        observed["env"] = kwargs["env"]
        raw_output = Path(command[command.index("--output") + 1])
        raw_output.write_text("{}", encoding="utf-8")
        expected_hash = command[command.index("--expected-runtime-sha256") + 1]
        source_tree_hash = command[command.index("--expected-source-tree-sha256") + 1]
        source_file_count = int(command[command.index("--expected-source-file-count") + 1])
        executed = [
            {
                "path": "<prefix>/Lib/site-packages/k_guard_mcp/cli.py",
                "sha256": "a" * 64,
                "event_kinds": ["exec"],
                "event_count": 1,
                "executed_code_sha256": ["c" * 64],
            }
        ]
        modules = [{"path": "<base_prefix>/python311.dll", "sha256": "b" * 64}]
        locked_native_files = [
            {"path": "<base_prefix>/python311.dll", "sha256": "b" * 64}
        ]
        def object_entry(
            path: str,
            kind: str,
            content_sha256: str | None,
        ) -> dict:
            basic_info = {
                "creation_time": 1,
                "last_write_time": 2,
                "change_time": 3,
                "file_attributes": 32,
            }
            payload = {
                "kind": kind,
                "basic_info": basic_info,
                "basic_sha256": hashlib.sha256(
                    json.dumps(
                        basic_info,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest(),
                "security_sha256": hashlib.sha256(
                    (path + ":security").encode()
                ).hexdigest(),
                "file_id_sha256": hashlib.sha256(
                    (path + ":file-id").encode()
                ).hexdigest(),
                "usn_record": {
                    "major_version": 2,
                    "minor_version": 0,
                    "file_reference": "01" * 8,
                    "parent_reference": "02" * 8,
                    "usn": "1",
                },
                "content_sha256": content_sha256,
            }
            attestation_sha256 = hashlib.sha256(
                json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            return {
                "path": path,
                "kind": kind,
                "expected_content_sha256": content_sha256,
                "checkpoints": [
                    {
                        "phase": phase,
                        **payload,
                        "attestation_sha256": attestation_sha256,
                    }
                    for phase in campaign_runner.RUNTIME_OBJECT_ATTESTATION_PHASES
                ],
            }

        object_entries = sorted(
            [
                object_entry(
                    "<base_prefix>/python311.dll",
                    "native_file",
                    "b" * 64,
                ),
                *[
                    object_entry(path, "directory", None)
                    for path in (
                        "<prefix>/Lib",
                        "<prefix>/Lib/site-packages",
                        "<prefix>/Lib/site-packages/k_guard_mcp",
                    )
                ],
            ],
            key=lambda row: row["path"],
        )
        receipt = {
            "schema": campaign_runner.RUNTIME_RECEIPT_SCHEMA,
            "passed": True,
            "raw_returned": False,
            "scanner_python_sha256": hashlib.sha256(scanner.read_bytes()).hexdigest(),
            "launcher_sha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
            "probe_sha256": hashlib.sha256(probe.read_bytes()).hexdigest(),
            "source_probe_sha256": hashlib.sha256(source_probe.read_bytes()).hexdigest(),
            "expected_source_tree_sha256": source_tree_hash,
            "pre_source_tree_sha256": source_tree_hash,
            "post_source_tree_sha256": source_tree_hash,
            "expected_source_file_count": source_file_count,
            "pre_source_file_count": source_file_count,
            "post_source_file_count": source_file_count,
            "pre_source_total_bytes": 24,
            "post_source_total_bytes": 24,
            "source_mutation_guard_canary": True,
            "source_mutation_observed": False,
            "source_mutation_monitor": {
                "root": "workspace_source",
                "guard": "windows_read_directory_changes_overlapped_v2",
                "canary_boundary": (
                    "temporary excluded root file created and deleted before pre-source capture"
                ),
                "measurement_boundary": (
                    "after canary drain through post-source capture and watcher termination"
                ),
                "canary_event_count": 2,
                "scan_event_count": 0,
                "events": [
                    {
                        "action": action,
                        "relative_path": ".k-guard-source-monitor.canary",
                    }
                    for action in (1, 2)
                ],
                "error": None,
                "liveness": {
                    "registration_count": 2,
                    "heartbeat_count": 2,
                    "drain_completed": True,
                    "stop_acknowledged": True,
                    "thread_terminated": True,
                    "passed": True,
                },
                "passed": True,
            },
            "scanner_exit_code": 0,
            "loaded_module_set_sha256": "5" * 64,
            "loaded_module_file_count": 1,
            "runtime_mutation_observed": False,
            "notification_event_count": 0,
            "accepted_native_load_metadata_event_count": 0,
            "unclassified_notification_count": 0,
            "mutation_event_count": 0,
            "mutation_monitor_errors": [],
            "mutation_guard": "windows_read_directory_changes_overlapped_v2",
            "runtime_notification_classifier": (
                campaign_runner.RUNTIME_NOTIFICATION_CLASSIFIER
            ),
            "runtime_notification_classifier_errors": [],
                "native_runtime_lock_guard": campaign_runner.NATIVE_RUNTIME_LOCK_GUARD,
                "native_runtime_prewarm_guard": (
                    campaign_runner.NATIVE_RUNTIME_PREWARM_GUARD
                ),
                "runtime_object_attestation_guard": (
                campaign_runner.RUNTIME_OBJECT_ATTESTATION_GUARD
            ),
            "mutation_monitor_liveness_passed": True,
            "mutation_guard_canary": {
                "before_scan": True,
                "after_scan": True,
                "cleanup_passed": True,
            },
            "mutation_monitors": [
                {
                    "root": root,
                    "notification_event_count": 0,
                    "notification_events": [],
                    "accepted_native_load_metadata_event_count": 0,
                    "accepted_native_load_metadata_events": [],
                    "accepted_stable_directory_metadata_event_count": 0,
                    "accepted_stable_directory_metadata_events": [],
                    "unclassified_notification_count": 0,
                    "event_count": 0,
                    "events": [],
                    "error": None,
                    "liveness": {
                        "registration_count": 1,
                        "heartbeat_count": 1,
                        "drain_completed": True,
                        "stop_acknowledged": True,
                        "thread_terminated": True,
                        "passed": True,
                    },
                }
                for root in ("scanner_prefix", "base_runtime", "protocol_repository")
            ],
            "accepted_stable_directory_metadata_event_count": 0,
                "native_runtime_lock": {
                "schema": campaign_runner.NATIVE_RUNTIME_LOCK_SCHEMA,
                "guard": campaign_runner.NATIVE_RUNTIME_LOCK_GUARD,
                "expected_file_count": 1,
                "locked_file_count": 1,
                "released_file_count": 1,
                "file_set_sha256": hashlib.sha256(
                    campaign_runner.NATIVE_RUNTIME_LOCK_SCHEMA.encode("ascii")
                    + b"\0"
                    + json.dumps(
                        locked_native_files,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest(),
                "files": locked_native_files,
                "read_open_canary": {
                    "path": "<base_prefix>/python311.dll",
                    "succeeded": True,
                    "winerror": 0,
                },
                "write_open_canary": {
                    "path": "<base_prefix>/python311.dll",
                    "blocked": True,
                    "winerror": 32,
                },
                "delete_open_canary": {
                    "path": "<base_prefix>/python311.dll",
                    "blocked": True,
                    "winerror": 32,
                },
                "metadata_access_canaries": [
                    {
                        "path": "<base_prefix>/python311.dll",
                        "access": access,
                        "opened": opened,
                        "winerror": 0 if opened else 5,
                    }
                    for access, opened in (
                        ("file_write_attributes", True),
                        ("write_dac", True),
                        ("write_owner", True),
                        ("access_system_security", False),
                    )
                ],
                "metadata_integrity_guard": (
                    campaign_runner.RUNTIME_OBJECT_ATTESTATION_GUARD
                ),
                "classification_completed_while_active": True,
                "errors": [],
                "activated": True,
                "released": True,
                "passed": True,
                    "raw_returned": False,
                },
                "native_runtime_prewarm": {
                    "schema": campaign_runner.NATIVE_RUNTIME_PREWARM_SCHEMA,
                    "guard": campaign_runner.NATIVE_RUNTIME_PREWARM_GUARD,
                    "method": (
                        "CreateFileMappingW(PAGE_READONLY|SEC_IMAGE)"
                        "+MapViewOfFile(FILE_MAP_READ)"
                    ),
                    "measurement_boundary": (
                        "after native runtime lock activation and pre-prewarm object "
                        "snapshot; before runtime mutation watchers, image-load "
                        "monitoring, and scanner import"
                    ),
                    "expected_file_count": 1,
                    "file_count": 1,
                    "mapped_file_count": 1,
                    "policy_blocked_file_count": 0,
                    "file_set_sha256": hashlib.sha256(
                        campaign_runner.NATIVE_RUNTIME_PREWARM_SCHEMA.encode("ascii")
                        + b"\0"
                        + json.dumps(
                            [
                                {
                                    "path": "<base_prefix>/python311.dll",
                                    "sha256": "b" * 64,
                                    "outcome": "mapped",
                                    "winerror": 0,
                                }
                            ],
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode()
                    ).hexdigest(),
                    "files": [
                        {
                            "path": "<base_prefix>/python311.dll",
                            "sha256": "b" * 64,
                            "outcome": "mapped",
                            "winerror": 0,
                        }
                    ],
                    "native_lock_active": True,
                    "errors": [],
                    "completed": True,
                    "passed": True,
                    "raw_returned": False,
                },
                "runtime_object_attestation": {
                "schema": campaign_runner.RUNTIME_OBJECT_ATTESTATION_SCHEMA,
                "guard": campaign_runner.RUNTIME_OBJECT_ATTESTATION_GUARD,
                "security_descriptor_scope": "owner_group_dacl",
                "sacl_requires_elevated_security_privilege": True,
                "usn_required": True,
                "checkpoint_phases": (
                    campaign_runner.RUNTIME_OBJECT_ATTESTATION_PHASES
                ),
                    "measurement_boundary": (
                        "pre-prewarm snapshot under the active native lock; controlled "
                        "SEC_IMAGE prewarm transition; post-prewarm through "
                        "post-classification must remain object-identical before "
                        "handle release"
                    ),
                    "prewarm_transition_policy": {
                        "native_file_mutable_fields": [
                            "basic_info.change_time",
                            "usn_record.usn",
                        ],
                        "native_file_immutable_fields": [
                            "basic_info.creation_time",
                            "basic_info.last_write_time",
                            "basic_info.file_attributes",
                            "security_sha256",
                            "file_id_sha256",
                            "content_sha256",
                            "usn_record.major_version",
                            "usn_record.minor_version",
                            "usn_record.file_reference",
                            "usn_record.parent_reference",
                        ],
                        "directory_mutable_fields": [],
                    },
                    "prewarm_transition_passed": True,
                "expected_entry_count": len(object_entries),
                "entry_count": len(object_entries),
                "native_file_count": 1,
                "directory_count": 3,
                "entry_set_sha256": hashlib.sha256(
                    campaign_runner.RUNTIME_OBJECT_ATTESTATION_SCHEMA.encode(
                        "ascii"
                    )
                    + b"\0"
                    + json.dumps(
                        object_entries,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                    ).hexdigest(),
                    "entries": object_entries,
                    "prewarm_changed_entry_count": 0,
                    "prewarm_changed_entries": [],
                    "changed_entry_count": 0,
                "changed_entries": [],
                "errors": [],
                "passed": True,
                "raw_returned": False,
            },
            "mutation_canary_monitor": {
                "root": "monitor_canary",
                "event_count": 4,
                "events": [{"action": 1, "relative_path": f"canary-{index}"} for index in range(4)],
                "error": None,
                "liveness": {
                    "registration_count": 2,
                    "heartbeat_count": 2,
                    "drain_completed": True,
                    "stop_acknowledged": True,
                    "thread_terminated": True,
                    "passed": True,
                },
            },
            "image_load_monitor": {
                "schema": "k_guard_windows_image_load_monitor.v1",
                "guard": "ntdll_ldr_dll_notification_v1",
                "registered": True,
                "unregistered": True,
                "canaries": [
                    {
                        "phase": phase,
                        "load_succeeded": True,
                        "load_error": 0,
                        "free_succeeded": True,
                        "free_error": 0,
                        "load_notification_seen": True,
                        "unload_notification_seen": True,
                        "passed": True,
                    }
                    for phase in ("before-scan", "after-scan")
                ],
                "scan_event_count": 0,
                "scan_load_count": 0,
                "scan_unload_count": 0,
                "event_set_sha256": hashlib.sha256(
                    b"k_guard_windows_image_load_monitor.v1\0[]"
                ).hexdigest(),
                "events": [],
                "outside_image_events": [],
                "callback_errors": [],
                "proof_boundary": "windows_loader_managed_images",
                "passed": True,
                "raw_returned": False,
            },
            "child_process_policy": {
                "schema": "k_guard_windows_child_process_policy.v1",
                "policy_id": 13,
                "required_flags": 1,
                "before_flags": 0,
                "set_succeeded": True,
                "set_error": 0,
                "after_flags": 1,
                "disable_attempt_canary": {
                    "blocked": True,
                    "winerror": 5,
                    "flags_after_attempt": 1,
                },
                "prebound_create_process_canary": {
                    "api": "kernel32.CreateProcessW",
                    "blocked": True,
                    "winerror": 367,
                    "unexpected_process_created": False,
                },
                "prebound_shell_execute_canary": {
                    "api": "shell32.ShellExecuteW",
                    "blocked": True,
                    "result": 5,
                    "winerror": 367,
                },
                "final_query_succeeded": True,
                "final_flags": 1,
                "passed": True,
                "raw_returned": False,
            },
            "execution_audit": {
                "schema": "k_guard_python_execution_audit.v3",
                "event_count": 1,
                "executed_file_count": 1,
                "executed_file_set_sha256": hashlib.sha256(
                    b"k_guard_python_execution_audit.v3\0"
                    + json.dumps(executed, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest(),
                "executed_files": executed,
                "outside_executed_code": [],
                "dynamic_executed_code": [],
                "dynamic_exec_events": [],
                "audit_errors": [],
                "process_creation_events": [],
                "code_object_control_events": [],
                "native_symbol_resolution_events": [],
                "passed": True,
                "raw_returned": False,
            },
            "native_module_receipt": {
                "schema": "k_guard_windows_native_module_receipt.v1",
                "module_count": 1,
                "module_set_sha256": hashlib.sha256(
                    b"k_guard_windows_native_module_receipt.v1\0"
                    + json.dumps(modules, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest(),
                "modules": modules,
                "outside_native_modules": [],
                "passed": True,
                "raw_returned": False,
            },
            "outside_loaded_modules": [],
            "pre_runtime_sha256": expected_hash,
            "post_runtime_sha256": expected_hash,
            "output_sha256": hashlib.sha256(raw_output.read_bytes()).hexdigest(),
        }
        observed["receipt"] = receipt
        Path(command[command.index("--receipt") + 1]).write_text(
            json.dumps(receipt, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(campaign_runner.subprocess, "run", complete)
    monkeypatch.setenv("PYTHONPATH", "C:/attacker")
    monkeypatch.setenv("PYTHONHOME", "C:/attacker")

    exit_code, _duration, _digest, _report = campaign_runner._run_scan(
        workspace,
        output,
        python_executable=scanner,
        isolated=True,
        runtime_launcher=launcher,
        runtime_probe=probe,
        source_probe=source_probe,
        expected_source_tree_sha256=expected_source_tree,
        expected_source_file_count=expected_source_file_count,
        expected_runtime=expected_runtime,
        execution_receipt=receipt_path,
    )

    assert exit_code == 0
    assert observed["command"][:4] == [str(scanner.resolve()), "-I", "-B", "-S"]
    assert "PYTHONPATH" not in observed["env"]
    assert "PYTHONHOME" not in observed["env"]

    for allowed, reason in ((False, None), (True, "unregistered_code_path")):
        forged_receipt = json.loads(json.dumps(observed["receipt"]))
        forged_receipt["execution_audit"]["event_count"] = 2
        forged_receipt["execution_audit"]["code_object_control_events"] = [
            {
                "event": "function.__new__",
                "payload_sha256": "d" * 64,
                "previous_code_sha256": None,
                "caller_path": "<prefix>/Lib/site-packages/k_guard_mcp/cli.py",
                "caller_function": "main",
                "caller_frames": [],
                "allowed": allowed,
                "allowed_reason": reason,
                "event_count": 1,
            }
        ]
        assert not campaign_runner._runtime_execution_contract_valid(
            forged_receipt,
            expected_runtime=json.loads(expected_runtime.read_text(encoding="utf-8")),
            launcher_sha256=hashlib.sha256(launcher.read_bytes()).hexdigest(),
            probe_sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),
        )

    for monitor_mutation in ("missing", "still_registered", "outside_event"):
        forged_receipt = json.loads(json.dumps(observed["receipt"]))
        if monitor_mutation == "missing":
            forged_receipt.pop("image_load_monitor")
        elif monitor_mutation == "still_registered":
            forged_receipt["image_load_monitor"]["unregistered"] = False
        else:
            forged_receipt["image_load_monitor"]["outside_image_events"] = [
                {"sequence": 1, "action": "load", "path_sha256": "e" * 20}
            ]
        assert not campaign_runner._runtime_execution_contract_valid(
            forged_receipt,
            expected_runtime=json.loads(expected_runtime.read_text(encoding="utf-8")),
            launcher_sha256=hashlib.sha256(launcher.read_bytes()).hexdigest(),
            probe_sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),
        )

    for runtime_forgery in (
        "classifier",
        "lock_guard",
        "lock_hash",
        "lock_omission",
        "prewarm_guard",
        "prewarm_hash",
        "prewarm_outcome",
        "metadata_guard",
        "object_security",
        "object_usn",
        "partition",
    ):
        forged_receipt = json.loads(json.dumps(observed["receipt"]))
        if runtime_forgery == "classifier":
            forged_receipt["runtime_notification_classifier"] = "forged"
        elif runtime_forgery == "lock_guard":
            forged_receipt["native_runtime_lock"]["guard"] = "forged"
        elif runtime_forgery == "lock_hash":
            forged_receipt["native_runtime_lock"]["files"][0]["sha256"] = "0" * 64
        elif runtime_forgery == "lock_omission":
            forged_receipt["native_runtime_lock"]["files"] = []
            forged_receipt["native_runtime_lock"]["expected_file_count"] = 0
            forged_receipt["native_runtime_lock"]["locked_file_count"] = 0
            forged_receipt["native_runtime_lock"]["released_file_count"] = 0
            forged_receipt["native_runtime_lock"]["file_set_sha256"] = hashlib.sha256(
                campaign_runner.NATIVE_RUNTIME_LOCK_SCHEMA.encode("ascii")
                + b"\0"
                + b"[]"
            ).hexdigest()
        elif runtime_forgery == "prewarm_guard":
            forged_receipt["native_runtime_prewarm"]["guard"] = "forged"
        elif runtime_forgery == "prewarm_hash":
            forged_receipt["native_runtime_prewarm"]["files"][0]["sha256"] = (
                "0" * 64
            )
        elif runtime_forgery == "prewarm_outcome":
            forged_receipt["native_runtime_prewarm"]["files"][0]["outcome"] = (
                "ignored"
            )
        elif runtime_forgery == "metadata_guard":
            forged_receipt["native_runtime_lock"]["metadata_integrity_guard"] = (
                "forged"
            )
        elif runtime_forgery == "object_security":
            forged_receipt["runtime_object_attestation"]["entries"][0][
                "checkpoints"
            ][-1]["security_sha256"] = "0" * 64
        elif runtime_forgery == "object_usn":
            forged_receipt["runtime_object_attestation"]["entries"][0][
                "checkpoints"
            ][-1]["usn_record"]["usn"] = "2"
        else:
            forged_receipt["notification_event_count"] = 1
        assert campaign_runner._runtime_monitor_contract_valid(forged_receipt) is False

    path_bound_receipt = json.loads(json.dumps(observed["receipt"]))
    native_entry = next(
        row
        for row in path_bound_receipt["runtime_object_attestation"]["entries"]
        if row["path"] == "<base_prefix>/python311.dll"
    )
    path_bound_receipt["image_load_monitor"]["events"] = [
        {
            "action": "load",
            "path": "<base_prefix>/python311.dll",
            "sha256": "b" * 64,
        }
    ]
    base_monitor = next(
        row
        for row in path_bound_receipt["mutation_monitors"]
        if row["root"] == "base_runtime"
    )
    raw_event = {"action": 3, "relative_path": "python311.dll"}
    accepted_event = {
        **raw_event,
        "attested_path": "<base_prefix>/python311.dll",
        "sha256": "b" * 64,
        "attestation_sha256": native_entry["checkpoints"][0][
            "attestation_sha256"
        ],
        "reason": "attested_write_locked_unchanged_native_notification",
    }
    base_monitor["notification_event_count"] = 1
    base_monitor["notification_events"] = [raw_event]
    base_monitor["accepted_native_load_metadata_event_count"] = 1
    base_monitor["accepted_native_load_metadata_events"] = [accepted_event]
    path_bound_receipt["notification_event_count"] = 1
    path_bound_receipt["accepted_native_load_metadata_event_count"] = 1
    assert campaign_runner._runtime_monitor_contract_valid(path_bound_receipt) is False

    laundered_receipt = json.loads(json.dumps(path_bound_receipt))
    laundered_base_monitor = next(
        row
        for row in laundered_receipt["mutation_monitors"]
        if row["root"] == "base_runtime"
    )
    laundered_base_monitor["notification_events"][0]["relative_path"] = "evil.py"
    laundered_base_monitor["accepted_native_load_metadata_events"][0][
        "relative_path"
    ] = "evil.py"
    assert campaign_runner._runtime_monitor_contract_valid(laundered_receipt) is False

    runtime_with_unlocked_native = json.loads(expected_runtime.read_text(encoding="utf-8"))
    runtime_with_unlocked_native["base_runtime_tree"]["files"].append(
        {"path": "unlocked.pyd", "sha256": "f" * 64, "byte_count": 1}
    )
    assert not campaign_runner._runtime_execution_contract_valid(
        observed["receipt"],
        expected_runtime=runtime_with_unlocked_native,
        launcher_sha256=hashlib.sha256(launcher.read_bytes()).hexdigest(),
        probe_sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),
        source_probe_sha256=hashlib.sha256(source_probe.read_bytes()).hexdigest(),
    )


def test_cli_resolves_paths_before_campaign_changes_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Path] = {}

    def fake_run_campaign(
        manifest: Path,
        apps_root: Path,
        output_dir: Path,
        runs: int,
        candidates_per_app: int,
    ) -> dict[str, dict[str, object]]:
        captured.update(manifest=manifest, apps_root=apps_root, output_dir=output_dir)
        assert runs == 2
        assert candidates_per_app == 3
        return {
            "campaign": {"campaign_id": "relative-path-test", "apps": []},
            "candidates": {"candidates": []},
            "probes": {"metrics": {}},
        }

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(campaign_runner, "run_campaign", fake_run_campaign)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_public_app_campaign.py",
            "--manifest",
            "manifest.json",
            "--apps-root",
            "apps",
            "--output-dir",
            "evidence",
        ],
    )

    assert campaign_runner.main() == 0
    assert captured == {
        "manifest": (tmp_path / "manifest.json").resolve(),
        "apps_root": (tmp_path / "apps").resolve(),
        "output_dir": (tmp_path / "evidence").resolve(),
    }


def test_supported_file_count_reads_review_inventory() -> None:
    report = {"metadata": {"review_coverage": {"inventory": {"supported_file_count": 37}}}}

    assert campaign_runner._supported_file_count(report) == 37


def test_manifest_contract_requires_full_commits_strata_and_bound_probes() -> None:
    manifest = {
        "schema": campaign_runner.MANIFEST_SCHEMA,
        "apps": [
            {
                "app": "demo",
                "local_dir": "demo",
                "stratum": "mid",
                "repository": "https://example.test/demo.git",
                "commit": "a" * 40,
            }
        ],
        "probes": [
            {
                "probe_id": "demo-probe",
                "app": "demo",
                "oracle_refs": ["src/app.py:1"],
                "accepted_rule_ids": ["DEMO_RULE"],
            }
        ],
    }

    campaign_runner._validate_manifest(manifest)

    manifest["apps"][0]["commit"] = "short"
    with pytest.raises(ValueError, match="full lowercase SHA-1"):
        campaign_runner._validate_manifest(manifest)
