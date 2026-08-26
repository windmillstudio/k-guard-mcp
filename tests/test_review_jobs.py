from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from k_guard_mcp.review_jobs import ReviewJobRegistry, ReviewQueueFull


def _release_args(review_id: str, workspace: str = ".") -> dict[str, object]:
    return {
        "initial_review_id": review_id,
        "workspace_path": workspace,
        "app_id": "demo-app",
        "business_purpose": "owned demo service",
        "data_classes": "public_content",
        "user_scope": "public users",
        "scope_proof_ref": "operator-owned fixture",
    }


def _await_review(server, review_id: str, *, timeout_seconds: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout_seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            pytest.fail(f"review {review_id} did not finish within {timeout_seconds} seconds")
        result = server.continue_review(review_id, wait_seconds=min(4.0, remaining))
        state = result.get("review_job", {}).get("state")
        if state not in {"queued", "running"}:
            return result


def test_registry_deduplicates_active_work_fails_closed_when_full_and_evicts_completed() -> None:
    registry = ReviewJobRegistry(max_jobs=1, max_workers=1)
    release = threading.Event()
    try:
        review_id, reused = registry.submit(
            kind="workspace",
            dedupe_key="same",
            work=lambda: (release.wait(2), {"status": "done"})[1],
        )
        same_id, same_reused = registry.submit(kind="workspace", dedupe_key="same", work=lambda: {})

        assert reused is False
        assert same_reused is True and same_id == review_id
        assert registry.inspect(review_id)["state"] in {"queued", "running"}
        assert registry.inspect(review_id, wait_seconds=0.01)["state"] in {"queued", "running"}
        with pytest.raises(ReviewQueueFull):
            registry.submit(kind="workspace", dedupe_key="different", work=lambda: {})

        release.set()
        completed = registry.inspect(review_id, wait_seconds=1)
        assert completed["state"] == "completed"
        assert completed["result"] == {"status": "done"}
        completed["result"]["status"] = "mutated"
        assert registry.inspect(review_id)["result"] == {"status": "done"}

        replacement_id, replacement_reused = registry.submit(
            kind="workspace",
            dedupe_key="different",
            work=lambda: {"status": "replacement"},
        )
        assert replacement_reused is False and replacement_id != review_id
    finally:
        release.set()
        registry.shutdown()


def test_registry_returns_raw_free_failure_and_rejects_invalid_results() -> None:
    registry = ReviewJobRegistry(max_jobs=2, max_workers=1)
    try:
        def fail() -> dict:
            raise RuntimeError("private failure value")

        failed_id, _ = registry.submit(kind="workspace", dedupe_key="failed", work=lambda: (time.sleep(0.01), fail())[1])
        failed = registry.inspect(failed_id, wait_seconds=1)
        assert failed["state"] == "failed"
        assert failed["error_type"] == "RuntimeError"
        assert "private failure value" not in str(failed)

        invalid_id, _ = registry.submit(kind="workspace", dedupe_key="invalid", work=lambda: ["bad"])  # type: ignore[arg-type,return-value]
        invalid = registry.inspect(invalid_id, wait_seconds=1)
        assert invalid["state"] == "failed"
        assert invalid["error_type"] == "InvalidReviewResult"
        assert registry.inspect("missing")["state"] == "not_found"
        registry._mark_completed("missing")
    finally:
        registry.shutdown()


def test_registry_validates_limits() -> None:
    with pytest.raises(ValueError):
        ReviewJobRegistry(max_jobs=0)
    with pytest.raises(ValueError):
        ReviewJobRegistry(max_workers=0)


def test_check_my_app_acknowledges_quickly_but_finishes_full_review(tmp_path: Path, monkeypatch) -> None:
    from k_guard_mcp import server

    (tmp_path / "app.ts").write_text("export const ready = true\n", encoding="utf-8")
    registry = ReviewJobRegistry(max_jobs=2, max_workers=1)
    monkeypatch.setattr(server, "review_jobs", registry)
    started = threading.Event()
    release = threading.Event()
    original = server._complete_check_my_app

    def deliberately_slow(path: str, include_flow: bool) -> dict:
        started.set()
        release.wait(2)
        return original(path, include_flow)

    monkeypatch.setattr(server, "_complete_check_my_app", deliberately_slow)
    try:
        before = time.perf_counter()
        first = server.check_my_app(str(tmp_path), include_flow=True)
        elapsed = time.perf_counter() - before

        assert elapsed < 0.5
        assert first["review_job"]["state"] == "running"
        assert first["review_job"]["scope_reduction_for_client_timeout"] is False
        assert first["experience"]["verdict"]["code"] == "review_in_progress"
        assert first["review_job"]["no_release_before_complete"] is True
        assert started.wait(1)

        duplicate = server.check_my_app(str(tmp_path), include_flow=True)
        assert duplicate["review_job"]["review_id"] == first["review_job"]["review_id"]
        assert duplicate["review_job"]["reused_active_review"] is True

        running = server.continue_review(first["review_job"]["review_id"], wait_seconds=0)
        assert running["experience"]["verdict"]["code"] == "review_in_progress"

        release.set()
        completed = _await_review(server, first["review_job"]["review_id"])
        assert completed["review_job"]["state"] == "completed"
        assert completed["method"] == "check_my_app"
        assert completed["primary_workflow"]["mode"] == "exhaustive_workspace_review"
        assert completed["primary_workflow"]["release_review_eligible"] is completed["review_receipt"]["eligible_for_release_review"]
        assert completed["primary_workflow"]["scope_reduction_for_client_timeout"] is False
        assert completed["review_coverage"]["status"] == "available_declared_scope"
        assert completed["review_coverage"]["coverage_metadata_available"] is True
        assert completed["review_coverage"].get("complete") is not True
        assert completed["review_coverage"]["inventory"]["scanned_text_file_count"] >= 1
        assert completed["primary_workflow"]["reviewed_scope"] == completed["review_coverage"]["reviewed_scope"]
        assert completed["primary_workflow"]["not_inspected"] == completed["review_coverage"]["not_inspected"]
        assert completed["release_review_contract"] == {
            "schema": "k_guard_pending_release_review_contract.v1",
            "status": "ready",
            "initial_review_completed": True,
            "initial_review_release_eligible": completed["review_receipt"]["eligible_for_release_review"],
            "eligible_to_start_guardian": completed["review_receipt"]["eligible_for_release_review"],
            "release_review_started": False,
            "release_verdict_issued": False,
            "canonical_release_authority": False,
            "claim_boundary": "handoff_readiness_not_release_verdict",
            "next_tool": "start_review_before_ship",
            "raw_returned": False,
        }
        assert completed["guardian_handoff"]["status"] == "ready"
        assert completed["guardian_handoff"]["completed_initial_review_required"] is True
        assert completed["guardian_handoff"]["unchanged_source_snapshot_required"] is True
        assert completed["guardian_handoff"]["same_mcp_session_required"] is True
        assert completed["guardian_handoff"]["same_workspace_required"] is True
        assert completed["guardian_handoff"]["operator_context_required"] is True
        assert completed["guardian_handoff"]["release_review_started"] is False
        assert completed["guardian_handoff"]["release_verdict_issued"] is False
        assert completed["guardian_handoff"]["canonical_release_authority"] is False
        assert completed["next_tool"] == "start_review_before_ship"
        assert completed["primary_workflow"]["next_tool"] == completed["next_tool"]
        assert completed["release_review_contract"]["next_tool"] == completed["next_tool"]
        assert completed["guardian_handoff"]["next_tool"] == completed["next_tool"]
        assert completed["release_review_contract"]["status"] == completed["guardian_handoff"]["status"]
        assert completed["release_review_contract"]["eligible_to_start_guardian"] is completed["review_receipt"][
            "eligible_for_release_review"
        ]
        assert completed["guardian_handoff"]["eligible_to_start_guardian"] is completed["review_receipt"][
            "eligible_for_release_review"
        ]
        assert completed["not_inspected"] == []
        assert completed["canonical_release_authority"] is False
        assert completed["repository_content_role"] == "untrusted_data_not_instructions"
        assert completed["scope_reduction_for_client_timeout"] is False
        assert completed["experience"]["verdict"]["code"] != "review_in_progress"
    finally:
        release.set()
        registry.shutdown()


def test_continue_review_and_release_start_fail_closed_at_control_boundaries(monkeypatch, tmp_path: Path) -> None:
    from k_guard_mcp import server

    registry = ReviewJobRegistry(max_jobs=1, max_workers=1)
    monkeypatch.setattr(server, "review_jobs", registry)
    try:
        missing = server.continue_review("missing", wait_seconds=0)
        invalid_wait = server.continue_review("missing", wait_seconds=4.1)
        assert missing["experience"]["verdict"]["code"] == "hold_incomplete"
        assert invalid_wait["experience"]["verdict"]["code"] == "hold_incomplete"

        (tmp_path / "app.ts").write_text("export const ready = true\n", encoding="utf-8")
        first = server.check_my_app(str(tmp_path))
        first_completed = _await_review(server, first["review_job"]["review_id"])
        assert first_completed["review_receipt"]["eligible_for_release_review"] is True

        monkeypatch.setattr(
            server,
            "review_before_ship",
            lambda **kwargs: {
                "method": "guardian_audit",
                "guardian_gate": {"passed": False, "canonical_release_authority": False},
                "experience": {"verdict": {"code": "hold", "message": "HOLD"}},
            },
        )
        started = server.start_review_before_ship(**_release_args(first["review_job"]["review_id"], str(tmp_path)))
        completed = _await_review(server, started["review_job"]["review_id"])
        assert started["review_job"]["kind"] == "guardian_release"
        assert completed["review_job"]["state"] == "completed"
        assert completed["guardian_gate"]["canonical_release_authority"] is False
    finally:
        registry.shutdown()


def test_complete_check_my_app_missing_scanner_coverage_is_explicitly_not_inspected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from k_guard_mcp import server

    (tmp_path / "app.py").write_text("print('ready')\n", encoding="utf-8")
    monkeypatch.setattr(
        server,
        "_run_security_gate",
        lambda *_args, **_kwargs: {
            "method": "security_gate",
            "findings": [],
            "security_gate": {"passed": False, "control_status": "scan_failed"},
            "raw_returned": False,
        },
    )

    completed = server._complete_check_my_app(str(tmp_path), include_flow=False)

    assert completed["review_coverage"] == {
        "capability": "korean_senior_pre_release_v1",
        "source_kind": "workspace",
        "status": "unavailable_fail_closed",
        "complete": False,
        "coverage_metadata_available": False,
        "flow_analysis_executed": False,
        "inventory_available": False,
        "inventory": None,
        "reviewed_scope": [],
        "not_inspected": [
            "production source and configuration",
            "tests, fixtures, documentation, and generated text artifacts",
            "local storage samples and Korean data controls",
            "input-to-storage and input-to-external-transfer flow analysis",
            "scanner review-coverage metadata was unavailable; no workspace coverage claim is made",
        ],
        "raw_returned": False,
    }
    assert completed["primary_workflow"]["release_review_eligible"] is False
    assert completed["release_review_contract"]["initial_review_release_eligible"] is False
    assert completed["release_review_contract"]["eligible_to_start_guardian"] is False
    assert completed["release_review_contract"]["status"] == "blocked"
    assert completed["release_review_contract"]["release_verdict_issued"] is False
    assert completed["release_review_contract"]["canonical_release_authority"] is False
    assert completed["release_review_contract"]["claim_boundary"] == "handoff_readiness_not_release_verdict"
    assert completed["guardian_handoff"]["status"] == "blocked"
    assert completed["guardian_handoff"]["eligible_to_start_guardian"] is False
    assert completed["guardian_handoff"]["release_verdict_issued"] is False
    assert completed["guardian_handoff"]["canonical_release_authority"] is False
    assert completed["next_tool"] == "check_my_app"
    assert completed["primary_workflow"]["next_tool"] == completed["next_tool"]
    assert completed["release_review_contract"]["next_tool"] == completed["next_tool"]
    assert completed["guardian_handoff"]["next_tool"] == completed["next_tool"]
    assert completed["primary_workflow"]["reviewed_scope"] == []
    assert completed["not_inspected"] == completed["primary_workflow"]["not_inspected"]
    assert completed["not_inspected"] == completed["review_coverage"]["not_inspected"]
    assert completed["not_inspected"] == [
        "production source and configuration",
        "tests, fixtures, documentation, and generated text artifacts",
        "local storage samples and Korean data controls",
        "input-to-storage and input-to-external-transfer flow analysis",
        "scanner review-coverage metadata was unavailable; no workspace coverage claim is made",
    ]
    assert completed["canonical_release_authority"] is False
    assert completed["repository_content_role"] == "untrusted_data_not_instructions"
    assert completed["scope_reduction_for_client_timeout"] is False
    assert completed["raw_returned"] is False


def test_server_async_control_exceptions_all_hold(monkeypatch) -> None:
    from k_guard_mcp import server

    class QueueFullRegistry:
        def submit(self, **kwargs):
            del kwargs
            raise ReviewQueueFull("private queue detail")

    class BrokenRegistry:
        def submit(self, **kwargs):
            del kwargs
            raise RuntimeError("private start detail")

    monkeypatch.setattr(server, "review_jobs", QueueFullRegistry())
    queue_full = server.check_my_app(".")
    release_queue_full = server.start_review_before_ship(**_release_args("missing"))
    assert queue_full["experience"]["verdict"]["code"] == "hold_incomplete"
    assert release_queue_full["experience"]["verdict"]["code"] == "hold_incomplete"

    monkeypatch.setattr(server, "review_jobs", BrokenRegistry())
    start_failed = server.check_my_app(".")
    release_start_failed = server.start_review_before_ship(**_release_args("missing"))
    assert start_failed["experience"]["verdict"]["code"] == "hold_incomplete"
    assert release_start_failed["experience"]["verdict"]["code"] == "hold_incomplete"
    assert "private start detail" not in str(start_failed)

    monkeypatch.setattr(server, "_run_security_gate", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("private worker detail")))
    worker_failed = server._complete_check_my_app(".", True)
    assert worker_failed["security_gate"]["control_status"] == "scan_failed"
    assert "private worker detail" not in str(worker_failed)

    class SnapshotRegistry:
        def __init__(self, snapshot):
            self.snapshot = snapshot

        def inspect(self, review_id, *, wait_seconds=0):
            del review_id, wait_seconds
            return self.snapshot

    monkeypatch.setattr(server, "review_jobs", SnapshotRegistry({"state": "completed", "result": ["bad"]}))
    invalid_result = server.continue_review("review-id", wait_seconds=0)
    assert invalid_result["experience"]["verdict"]["code"] == "hold_incomplete"

    monkeypatch.setattr(
        server,
        "review_jobs",
        SnapshotRegistry(
            {
                "state": "failed",
                "review_id": "review-id",
                "kind": "workspace_exhaustive",
                "error_type": "RuntimeError",
                "error_ref": "redacted-ref",
                "hash_scheme": "hmac-sha256",
            }
        ),
    )
    failed_result = server.continue_review("review-id", wait_seconds=0)
    assert failed_result["review_job"]["state"] == "failed"
    assert failed_result["experience"]["verdict"]["code"] == "hold_incomplete"

    class ExplodingInspectRegistry:
        def inspect(self, review_id, *, wait_seconds=0):
            del review_id, wait_seconds
            raise RuntimeError("private@example.com sk-private-inspection-value")

    monkeypatch.setattr(server, "review_jobs", ExplodingInspectRegistry())
    inspection_failed = server.continue_review("review-id", wait_seconds=0)
    serialized = str(inspection_failed)
    assert inspection_failed["experience"]["verdict"]["code"] == "hold_incomplete"
    assert inspection_failed["review_control"]["passed"] is False
    assert inspection_failed["review_control"]["fail_closed"] is True
    assert "private@example.com" not in serialized
    assert "sk-private-inspection-value" not in serialized


def test_installed_workspace_binding_rejects_escape_and_returns_raw_free_identity(tmp_path: Path, monkeypatch) -> None:
    from k_guard_mcp import server

    workspace = tmp_path / "selected-app"
    outside = tmp_path / "other-app"
    workspace.mkdir()
    outside.mkdir()
    (workspace / "app.ts").write_text("export const ready = true\n", encoding="utf-8")
    (outside / "app.ts").write_text("export const wrong = true\n", encoding="utf-8")
    registry = ReviewJobRegistry(max_jobs=4, max_workers=1)
    monkeypatch.setattr(server, "review_jobs", registry)
    monkeypatch.setenv(server.WORKSPACE_ROOT_ENV, str(workspace))
    try:
        started = server.check_my_app(".")
        completed = _await_review(server, started["review_job"]["review_id"])
        escaped = server.check_my_app(str(outside))
        quick_escape = server.security_gate(str(outside))
    finally:
        registry.shutdown()

    assert completed["review_receipt"]["eligible_for_release_review"] is True
    assert completed["review_receipt"]["source_snapshot_complete"] is True
    assert started["workspace_binding"]["bound"] is True
    assert started["workspace_binding"]["workspace_name"] == "selected-app"
    assert {item["rule_id"] for item in escaped["findings"]} == {"MCP_WORKSPACE_SCOPE_MISMATCH"}
    assert escaped["experience"]["verdict"]["code"] == "hold_incomplete"
    assert quick_escape["security_gate"]["passed"] is False
    assert quick_escape["security_gate"]["control_status"] == "workspace_scope_mismatch"
    serialized = str({"started": started, "completed": completed, "escaped": escaped})
    assert str(workspace) not in serialized
    assert str(outside) not in serialized


def test_release_start_requires_same_completed_source_snapshot(tmp_path: Path, monkeypatch) -> None:
    from k_guard_mcp import server

    source = tmp_path / "app.ts"
    source.write_text("export const version = 1\n", encoding="utf-8")
    registry = ReviewJobRegistry(max_jobs=4, max_workers=1)
    monkeypatch.setattr(server, "review_jobs", registry)
    try:
        missing = server.start_review_before_ship(**_release_args("missing", str(tmp_path)))
        first = server.check_my_app(str(tmp_path))
        first_done = _await_review(server, first["review_job"]["review_id"])
        source.write_text("export const version = 2\n", encoding="utf-8")
        drifted = server.start_review_before_ship(**_release_args(first["review_job"]["review_id"], str(tmp_path)))

        second = server.check_my_app(str(tmp_path))
        second_done = _await_review(server, second["review_job"]["review_id"])
        monkeypatch.setattr(
            server,
            "review_before_ship",
            lambda **kwargs: {
                "method": "guardian_audit",
                "guardian_gate": {"passed": False, "canonical_release_authority": False},
                "experience": {"verdict": {"code": "hold_qualification", "message": "HOLD"}},
            },
        )
        release = server.start_review_before_ship(**_release_args(second["review_job"]["review_id"], str(tmp_path)))
        release_done = _await_review(server, release["review_job"]["review_id"])
    finally:
        registry.shutdown()

    assert missing["experience"]["verdict"]["code"] == "hold_incomplete"
    assert {item["rule_id"] for item in missing["findings"]} == {"MCP_INITIAL_REVIEW_REQUIRED"}
    assert first_done["review_receipt"]["review_id"] == first["review_job"]["review_id"]
    assert {item["rule_id"] for item in drifted["findings"]} == {"MCP_INITIAL_REVIEW_SOURCE_DRIFT"}
    assert second_done["review_receipt"]["source_tree_sha256"] != first_done["review_receipt"]["source_tree_sha256"]
    assert release["release_review_contract"]["source_snapshot_validated_at_queue"] is True
    assert release["release_review_contract"]["source_snapshot_bound"] is False
    assert release["release_review_contract"]["initial_review_receipt"]["validated_for_release_start"] is True
    assert release_done["review_job"]["state"] == "completed"
    assert release_done["release_review_contract"]["source_snapshot_bound"] is True
    assert release_done["release_review_contract"]["worker_source_binding"]["worker_start_match"] is True
    assert release_done["release_review_contract"]["worker_source_binding"]["worker_end_match"] is True


def test_first_review_without_flow_is_never_release_eligible(tmp_path: Path, monkeypatch) -> None:
    from k_guard_mcp import server

    (tmp_path / "app.ts").write_text("export const ready = true\n", encoding="utf-8")
    registry = ReviewJobRegistry(max_jobs=4, max_workers=1)
    monkeypatch.setattr(server, "review_jobs", registry)
    try:
        started = server.check_my_app(str(tmp_path), include_flow=False)
        completed = _await_review(server, started["review_job"]["review_id"])
        release = server.start_review_before_ship(**_release_args(started["review_job"]["review_id"], str(tmp_path)))
    finally:
        registry.shutdown()

    assert completed["review_receipt"]["eligible_for_release_review"] is False
    assert completed["review_receipt"]["include_flow"] is False
    assert completed["review_receipt"]["reason_codes"] == ["flow_analysis_required_for_release"]
    assert completed["primary_workflow"]["release_review_eligible"] is False
    assert completed["primary_workflow"]["not_inspected"] == [
        "input-to-storage and input-to-external-transfer flow analysis"
    ]
    assert {item["rule_id"] for item in release["findings"]} == {"MCP_INITIAL_REVIEW_INCOMPLETE"}


def test_release_worker_rejects_source_drift_after_queue_validation(tmp_path: Path, monkeypatch) -> None:
    from k_guard_mcp import server

    source = tmp_path / "app.ts"
    source.write_text("export const version = 1\n", encoding="utf-8")
    registry = ReviewJobRegistry(max_jobs=8, max_workers=1)
    monkeypatch.setattr(server, "review_jobs", registry)
    blocker_started = threading.Event()
    unblock = threading.Event()
    guardian_called = threading.Event()
    try:
        first = server.check_my_app(str(tmp_path))
        first_done = _await_review(server, first["review_job"]["review_id"])

        def block_worker():
            blocker_started.set()
            assert unblock.wait(timeout=5)
            return {"ok": True}

        registry.submit(kind="test_blocker", dedupe_key="blocker", work=block_worker)
        assert blocker_started.wait(timeout=2)
        monkeypatch.setattr(server, "review_before_ship", lambda **kwargs: guardian_called.set() or {"method": "guardian_audit"})
        release = server.start_review_before_ship(**_release_args(first_done["review_job"]["review_id"], str(tmp_path)))
        source.write_text("export const version = 2\n", encoding="utf-8")
        unblock.set()
        release_done = _await_review(server, release["review_job"]["review_id"])
    finally:
        unblock.set()
        registry.shutdown()

    assert guardian_called.is_set() is False
    assert release_done["review_job"]["state"] == "completed"
    assert {item["rule_id"] for item in release_done["findings"]} == {"MCP_RELEASE_REVIEW_SOURCE_DRIFT"}
    assert release_done["guardian_gate"]["passed"] is False
    assert release_done["release_review_contract"]["source_snapshot_bound"] is False
    assert release_done["release_review_contract"]["worker_source_binding"]["worker_start_match"] is False


def test_workspace_binding_rejects_invalid_roots_and_accepts_only_nested_directories(
    tmp_path: Path, monkeypatch
) -> None:
    from k_guard_mcp import server

    monkeypatch.setenv(server.WORKSPACE_ROOT_ENV, "")
    empty_binding = server.check_my_app(".")
    assert {item["rule_id"] for item in empty_binding["findings"]} == {"MCP_WORKSPACE_BINDING_INVALID"}
    empty_gate = server.security_gate(".")
    assert empty_gate["security_gate"]["control_status"] == "workspace_binding_invalid"

    monkeypatch.setenv(server.WORKSPACE_ROOT_ENV, "relative/project")
    relative = server.check_my_app(".")
    assert {item["rule_id"] for item in relative["findings"]} == {"MCP_WORKSPACE_BINDING_INVALID"}

    missing = tmp_path / "missing"
    monkeypatch.setenv(server.WORKSPACE_ROOT_ENV, str(missing))
    unavailable = server.check_my_app(".")
    assert {item["rule_id"] for item in unavailable["findings"]} == {"MCP_WORKSPACE_BINDING_INVALID"}

    workspace = tmp_path / "workspace"
    nested = workspace / "packages" / "web"
    nested.mkdir(parents=True)
    file_path = workspace / "not-a-directory.ts"
    file_path.write_text("export const nope = true\n", encoding="utf-8")
    monkeypatch.setenv(server.WORKSPACE_ROOT_ENV, str(workspace))

    resolved, identity, finding = server._resolve_bound_workspace("packages/web")
    assert Path(resolved) == nested.resolve()
    assert identity["requested_path_within_binding"] is True
    assert finding is None

    root_resolved, root_identity, root_finding = server._resolve_bound_workspace(
        str(workspace), require_bound_root=True
    )
    assert Path(root_resolved) == workspace.resolve()
    assert root_identity["requested_path_is_root"] is True
    assert root_finding is None

    _child_resolved, child_identity, child_finding = server._resolve_bound_workspace(
        "packages/web", require_bound_root=True
    )
    assert child_finding is not None
    assert child_finding.rule_id == "MCP_WORKSPACE_ROOT_REQUIRED"
    assert child_identity["workspace_name"] == "workspace"
    assert child_identity["accepted_path_forms"] == [".", "exact absolute installed workspace path"]
    rejected = server.check_my_app("packages/web")
    assert {item["rule_id"] for item in rejected["findings"]} == {"MCP_WORKSPACE_ROOT_REQUIRED"}
    scoped_gate = server.security_gate("packages/web", fail_on="high", include_flow=True)
    assert "MCP_WORKSPACE_ROOT_REQUIRED" not in {item["rule_id"] for item in scoped_gate["findings"]}

    _resolved_file, _identity, file_finding = server._resolve_bound_workspace("not-a-directory.ts")
    assert file_finding is not None
    assert file_finding.rule_id == "MCP_WORKSPACE_SCOPE_MISMATCH"

    monkeypatch.setattr(server, "is_unsafe_link", lambda path: Path(path) == workspace)
    _resolved_link, _identity, link_finding = server._resolve_bound_workspace(".")
    assert link_finding is not None
    assert link_finding.rule_id == "MCP_WORKSPACE_BINDING_INVALID"


def test_continue_review_compacts_and_pages_without_mutating_full_registry(monkeypatch) -> None:
    from k_guard_mcp import server

    registry = ReviewJobRegistry(max_jobs=2, max_workers=1)
    monkeypatch.setattr(server, "review_jobs", registry)
    full_findings = [
        {
            "id": f"finding-{index:04d}",
            "rule_id": f"RULE_{index:02d}",
            "severity": "medium",
            "recommendation": "fix then rerun",
            "evidence": "x" * 900,
        }
        for index in range(24)
    ]
    full_report = {
        "method": "check_my_app",
        "experience": {
            "verdict": {"code": "hold_fix", "message": "HOLD"},
            "why": "blocking findings remain",
            "next_actions": ["fix first finding"],
        },
        "findings": full_findings,
        "review_receipt": {
            "eligible_for_release_review": True,
            "source_tree_sha256": "a" * 64,
            "source_snapshot_complete": True,
        },
        "primary_workflow": {"release_review_eligible": True},
        "release_review_contract": {"source_snapshot_bound": True},
        "guardian_handoff": {"latest_completed_review_required": True},
    }
    try:
        review_id, _ = registry.submit(
            kind="workspace_exhaustive",
            dedupe_key="compact",
            work=lambda: full_report,
        )
        first = server.continue_review(review_id, wait_seconds=4)
        encoded = json.dumps(first, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        assert len(encoded) <= server.MAX_COMPACT_CONTINUE_REVIEW_BYTES
        assert first["method"] == "check_my_app"
        assert first["review_job"]["state"] == "completed"
        assert first["review_receipt"]["source_tree_sha256"] == "a" * 64
        assert first["release_review_contract"]["source_snapshot_bound"] is True
        assert first["guardian_handoff"]["latest_completed_review_required"] is True
        assert first["findings_page"] == {
            "offset": 0,
            "requested_limit": 8,
            "returned_count": 8,
            "total_count": 24,
            "has_more": True,
            "next_offset": 8,
            "full_result_retained_in_review_registry": True,
            "raw_returned": False,
        }

        second = server.continue_review(review_id, wait_seconds=0, finding_offset=8, finding_limit=8)
        assert [item["rule_id"] for item in second["findings"]] == [f"RULE_{index:02d}" for index in range(8, 16)]
        assert second["findings_page"]["next_offset"] == 16

        full = server.continue_review(review_id, wait_seconds=0, response_mode="full")
        assert len(full["findings"]) == 24
        assert len(registry.inspect(review_id)["result"]["findings"]) == 24
    finally:
        registry.shutdown()


def test_suggest_fix_includes_canonical_recheck_and_release_flow() -> None:
    from k_guard_mcp import server

    result = server.suggest_fix("WEB_UNTRUSTED_INPUT_TO_SQL", framework="python")
    flow = result["canonical_recheck_flow"]

    assert [step.get("tool") for step in flow] == [
        "check_my_app",
        "continue_review",
        None,
        "start_review_before_ship",
    ]
    assert flow[0]["arguments"] == {"path": ".", "include_flow": True}
    assert flow[1]["repeat_until"] == ["completed", "failed"]
    assert flow[1]["finding_pages"] == {
        "start_offset": 0,
        "follow": "findings_page.next_offset",
        "until": "findings_page.has_more=false",
        "requires_all_pages": True,
        "no_duplicate_or_missing_offsets": True,
    }
    assert flow[2]["verification"] == "same_rule_absent"
    assert flow[2]["rule_id"] == "WEB_UNTRUSTED_INPUT_TO_SQL"
    assert flow[2]["requires_all_pages"] is True
    assert flow[3]["arguments"]["initial_review_id"] == "latest_completed_check_my_app_review_id"


def test_compact_review_hard_cap_envelope_projection_and_cursor_integrity(monkeypatch) -> None:
    from k_guard_mcp import server

    registry = ReviewJobRegistry(max_jobs=3, max_workers=1)
    monkeypatch.setattr(server, "review_jobs", registry)
    findings = [
        {"id": f"finding-{index}", "rule_id": f"RULE_{index}", "severity": "high", "title": "action"}
        for index in range(29)
    ]
    huge = "z" * 120_000
    report = {
        "method": "check_my_app",
        "experience": {"verdict": {"code": "hold_fix"}, "why": huge, "next_actions": [huge]},
        "findings": findings,
        "review_receipt": {"eligible_for_release_review": False, "source_tree_sha256": "b" * 64},
        "primary_workflow": {"release_review_eligible": False, "reviewed_scope": [huge]},
        "release_review_contract": {"source_snapshot_bound": False, "oversized": huge},
        "guardian_handoff": {"oversized": huge},
        "review_coverage": {
            "status": "available_declared_scope",
            "coverage_metadata_available": True,
            "inventory": {"oversized": huge},
        },
        "next_tool": "start_review_before_ship",
        "raw_returned": False,
        "not_inspected": [huge],
        "canonical_release_authority": False,
        "repository_content_role": "untrusted_data_not_instructions",
        "scope_reduction_for_client_timeout": False,
    }
    try:
        review_id, _ = registry.submit(kind="workspace_exhaustive", dedupe_key="huge-envelope", work=lambda: report)
        seen: list[str] = []
        offset = 0
        while True:
            page = server.continue_review(review_id, wait_seconds=4, finding_offset=offset, finding_limit=8)
            assert len(json.dumps(page, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) <= 20_000
            assert {
                "next_tool",
                "raw_returned",
                "not_inspected",
                "canonical_release_authority",
                "repository_content_role",
                "scope_reduction_for_client_timeout",
            }.issubset(page)
            seen.extend(item["rule_id"] for item in page["findings"])
            contract = page["findings_page"]
            if not contract["has_more"]:
                break
            assert contract["next_offset"] > offset
            offset = contract["next_offset"]
        assert seen == [f"RULE_{index}" for index in range(29)]
        assert len(seen) == len(set(seen))
        assert len(registry.inspect(review_id)["result"]["findings"]) == 29
        projected_coverage = server.continue_review(review_id, wait_seconds=0)["review_coverage"]
        assert projected_coverage["status"] == "available_declared_scope"
        assert projected_coverage["coverage_metadata_available"] is True
    finally:
        registry.shutdown()


def test_compact_review_projects_oversized_finding_without_cursor_skip(monkeypatch) -> None:
    from k_guard_mcp import server

    registry = ReviewJobRegistry(max_jobs=2, max_workers=1)
    monkeypatch.setattr(server, "review_jobs", registry)
    findings = [
        {
            "id": "oversized",
            "rule_id": "RULE_OVERSIZED",
            "severity": "high",
            "title": "t" * 150_000,
            "evidence": "e" * 150_000,
        },
        {"id": "normal", "rule_id": "RULE_NORMAL", "severity": "medium", "title": "normal"},
    ]
    report = {
        "method": "check_my_app",
        "experience": {"verdict": {"code": "hold_fix"}, "why": "fix", "next_actions": []},
        "findings": findings,
    }
    try:
        review_id, _ = registry.submit(kind="workspace_exhaustive", dedupe_key="oversized-finding", work=lambda: report)
        first = server.continue_review(review_id, wait_seconds=4, finding_offset=0, finding_limit=1)
        second = server.continue_review(
            review_id,
            wait_seconds=0,
            finding_offset=first["findings_page"]["next_offset"],
            finding_limit=1,
        )
        assert len(json.dumps(first, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) <= 20_000
        assert [item["rule_id"] for item in first["findings"]] == ["RULE_OVERSIZED"]
        assert first["findings_page"]["next_offset"] == 1
        assert [item["rule_id"] for item in second["findings"]] == ["RULE_NORMAL"]
        assert second["findings_page"]["has_more"] is False
    finally:
        registry.shutdown()


def test_compact_review_envelope_capacity_exhaustion_advances_every_cursor(monkeypatch) -> None:
    from k_guard_mcp import server

    registry = ReviewJobRegistry(max_jobs=2, max_workers=1)
    monkeypatch.setattr(server, "review_jobs", registry)
    findings = [
        {
            "id": f"finding-{index:04d}",
            "rule_id": f"RULE_{index:02d}",
            "severity": "high",
            "title": "action",
        }
        for index in range(17)
    ]
    padding = "bounded-envelope-value-" + ("z" * 1_700)
    report = {
        "method": "check_my_app",
        "experience": {"detail": padding},
        "findings": findings,
        "review_receipt": {"detail": padding},
        "primary_workflow": {"detail": padding},
        "release_review_contract": {"detail": padding},
        "guardian_handoff": {"detail": padding},
        "guardian_gate": {"detail": padding},
        "application_assurance": {"detail": padding},
        "auditor_qualification": {"detail": padding},
        "workspace_binding": {"detail": padding},
        "security_gate": {"detail": padding},
        "summary": {"detail": padding},
        "review_control": {"detail": padding},
        "source_snapshot": {"detail": padding},
        "source_tree_snapshot": {"detail": padding},
        "scan_inventory_consistency": {"detail": padding},
        "review_coverage": {
            "status": "available_declared_scope",
            "coverage_metadata_available": True,
            "detail": padding,
        },
        "raw_returned": False,
    }
    try:
        review_id, _ = registry.submit(
            kind="workspace_exhaustive",
            dedupe_key="envelope-capacity-cursor",
            work=lambda: report,
        )
        seen: list[str] = []
        offset = 0
        while True:
            page = server.continue_review(
                review_id,
                wait_seconds=4,
                finding_offset=offset,
                finding_limit=8,
            )
            encoded = json.dumps(page, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            assert len(encoded) <= server.MAX_COMPACT_CONTINUE_REVIEW_BYTES
            assert b"bounded-envelope-value" not in encoded
            assert page["raw_returned"] is False
            contract = page["findings_page"]
            assert contract["offset"] == offset
            assert contract["requested_limit"] == 8
            assert contract["total_count"] == 17
            assert contract["returned_count"] == len(page["findings"])
            assert contract["returned_count"] == 1
            assert contract["limited_by_byte_budget"] is True
            assert contract["envelope_capacity_exhausted"] is True
            assert page["response_contract"]["cursor_advanced"] is True
            assert page["findings"][0]["raw_returned"] is False
            assert page["review_coverage"] == {
                "status": "available_declared_scope",
                "coverage_metadata_available": True,
                "raw_returned": False,
            }
            seen.extend(item["rule_id"] for item in page["findings"])
            if not contract["has_more"]:
                assert contract["next_offset"] is None
                break
            assert contract["next_offset"] > offset
            offset = contract["next_offset"]

        assert seen == [f"RULE_{index:02d}" for index in range(17)]
        assert len(seen) == len(set(seen))
        assert len(registry.inspect(review_id)["result"]["findings"]) == 17
    finally:
        registry.shutdown()


def test_initial_review_receipt_validation_failures_remain_raw_free(tmp_path: Path, monkeypatch) -> None:
    from k_guard_mcp import server

    private_detail = "private@example.com sk-private-snapshot-value"
    monkeypatch.setattr(
        server,
        "source_tree_snapshot",
        lambda _path: (_ for _ in ()).throw(RuntimeError(private_detail)),
    )
    receipt = server._initial_review_receipt(
        str(tmp_path),
        {"security_gate": {"control_status": "scan_failed"}},
    )
    assert receipt["eligible_for_release_review"] is False
    assert receipt["reason_codes"] == [
        "initial_review_control_incomplete",
        "source_snapshot_incomplete",
        "flow_analysis_required_for_release",
    ]
    assert private_detail not in str(receipt)

    oversized, oversized_finding = server._validated_initial_review("x" * 100_000, str(tmp_path))
    assert oversized is None
    assert oversized_finding is not None

    class Registry:
        snapshot: dict | None = None
        error: Exception | None = None

        def inspect(self, review_id, *, wait_seconds=0):
            del review_id, wait_seconds
            if self.error is not None:
                raise self.error
            return self.snapshot

    registry = Registry()
    registry.error = RuntimeError(private_detail)
    monkeypatch.setattr(server, "review_jobs", registry)
    validated, finding = server._validated_initial_review("review-id", str(tmp_path))
    assert validated is None and finding is not None
    assert finding.rule_id == "MCP_INITIAL_REVIEW_RECEIPT_UNAVAILABLE"
    assert private_detail not in finding.evidence

    registry.error = None
    registry.snapshot = {"state": "completed", "kind": "workspace_exhaustive", "result": {}}
    validated, finding = server._validated_initial_review("review-id", str(tmp_path))
    assert validated is None and finding is not None
    assert finding.rule_id == "MCP_INITIAL_REVIEW_INCOMPLETE"

    registry.snapshot = {
        "state": "completed",
        "kind": "workspace_exhaustive",
        "result": {
            "review_receipt": {
                "eligible_for_release_review": True,
                "workspace_ref": "wrong-workspace",
                "source_tree_sha256": "source-a",
            }
        },
    }
    validated, finding = server._validated_initial_review("review-id", str(tmp_path))
    assert validated is None and finding is not None
    assert finding.rule_id == "MCP_INITIAL_REVIEW_WORKSPACE_MISMATCH"

    registry.snapshot["result"]["review_receipt"]["workspace_ref"] = server._raw_free_ref(
        server._canonical_review_path(str(tmp_path)), "workspace"
    )
    validated, finding = server._validated_initial_review("review-id", str(tmp_path))
    assert validated is None and finding is not None
    assert finding.rule_id == "MCP_INITIAL_REVIEW_SOURCE_UNAVAILABLE"


def test_release_start_fails_closed_when_queue_or_worker_start_breaks(tmp_path: Path, monkeypatch) -> None:
    from k_guard_mcp import server

    tree_hash = "a" * 64
    workspace_ref = server._raw_free_ref(server._canonical_review_path(str(tmp_path)), "workspace")
    completed_snapshot = {
        "state": "completed",
        "kind": "workspace_exhaustive",
        "result": {
            "review_receipt": {
                "schema": "k_guard_initial_review_receipt.v1",
                "eligible_for_release_review": True,
                "workspace_ref": workspace_ref,
                "source_tree_sha256": tree_hash,
            }
        },
    }
    monkeypatch.setattr(
        server,
        "source_tree_snapshot",
        lambda _path: {"complete": True, "tree_sha256": tree_hash},
    )

    class FailingRegistry:
        def __init__(self, error: Exception) -> None:
            self.error = error

        def inspect(self, review_id, *, wait_seconds=0):
            del review_id, wait_seconds
            return completed_snapshot

        def submit(self, **kwargs):
            del kwargs
            raise self.error

    monkeypatch.setattr(server, "review_jobs", FailingRegistry(ReviewQueueFull("private queue")))
    queue_full = server.start_review_before_ship(**_release_args("review-id", str(tmp_path)))
    assert {item["rule_id"] for item in queue_full["findings"]} == {"MCP_REVIEW_QUEUE_FULL"}

    monkeypatch.setattr(server, "review_jobs", FailingRegistry(RuntimeError("private start")))
    start_failed = server.start_review_before_ship(**_release_args("review-id", str(tmp_path)))
    assert {item["rule_id"] for item in start_failed["findings"]} == {"MCP_RELEASE_REVIEW_START_FAILED"}
    assert "private start" not in str(start_failed)


def test_internal_guardian_engine_is_not_an_mcp_tool_and_sdk_absence_is_explicit(monkeypatch) -> None:
    from k_guard_mcp import server

    monkeypatch.setattr(server, "_PromptIsolatedFastMCP", None)
    with pytest.raises(RuntimeError, match="MCP Python SDK"):
        server.create_mcp_server()
