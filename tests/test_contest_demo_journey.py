from __future__ import annotations

import importlib.util
from io import StringIO
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEMO_ROOT = ROOT / "examples" / "contest-demo" / "v1"
SUBMISSION_ROOT = ROOT / "submission" / "demo"


def _load_demo_module():
    spec = importlib.util.spec_from_file_location("contest_demo_journey", DEMO_ROOT / "demo.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


demo = _load_demo_module()


def test_contest_demo_stage_order_matches_checked_in_dry_run_transcript() -> None:
    expected_order = (
        "vulnerable_fixture",
        "first_review_hold",
        "first_actionable_blocker",
        "visible_safe_patch",
        "guardian_rerun",
        "bounded_result",
    )
    assert demo.STAGE_ORDER == expected_order

    generated = demo.build_dry_run_transcript()
    checked_in = (SUBMISSION_ROOT / "dry-run-transcript.txt").read_text(encoding="utf-8")
    assert generated == checked_in

    positions = [
        generated.index(f"[{index}/6] {demo.STAGE_TITLES[stage_id]}")
        for index, stage_id in enumerate(expected_order, 1)
    ]
    assert positions == sorted(positions)


def test_contest_demo_dry_run_is_truthful_and_has_no_execution_side_effects(monkeypatch) -> None:
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("dry-run attempted an execution side effect")

    monkeypatch.setattr(demo, "prepare", fail_if_called)
    monkeypatch.setattr(demo, "build_server", fail_if_called)
    monkeypatch.setattr(demo.subprocess, "Popen", fail_if_called)
    stream = StringIO()

    scorecard = demo.run_dry_run(stream)

    assert scorecard == json.loads((SUBMISSION_ROOT / "dry-run-scorecard.json").read_text(encoding="utf-8"))
    assert scorecard["mode"] == "dry_run_contract"
    assert scorecard["scan_executed"] is False
    assert scorecard["http_requests_sent"] is False
    assert scorecard["patch_applied"] is False
    assert "실행 결과를 주장하지 않습니다" in stream.getvalue()
    assert "증거가 아닙니다" in scorecard["claim_boundary"]
    assert scorecard["safety_contract"] == {
        "targets": "local_workspace_and_127.0.0.1_only",
        "public_targets_allowed": False,
        "execution_surface": "local_cli",
        "mcp_client_exercised": False,
        "award_evidence_claimed": False,
        "release_authority_claimed": False,
    }


def test_contest_demo_enforces_local_targets_and_runtime_budget(tmp_path: Path) -> None:
    demo.prepare("hold", tmp_path)
    manifest = demo.write_runtime_manifest(tmp_path, 43210)

    assert demo.runtime_manifest_is_local_only(manifest, tmp_path) is True
    assert "http://127.0.0.1:43210" in manifest.read_text(encoding="utf-8")
    assert demo.RUNTIME_BUDGET_SECONDS == 180
    assert 2 * demo.GUARDIAN_STEP_TIMEOUT_SECONDS + demo.SHUTDOWN_RESERVE_SECONDS <= demo.RUNTIME_BUDGET_SECONDS

    public_manifest = tmp_path / "public-target.csv"
    public_manifest.write_text(
        manifest.read_text(encoding="utf-8").replace("http://127.0.0.1:43210", "https://example.com"),
        encoding="utf-8",
    )
    assert demo.runtime_manifest_is_local_only(public_manifest, tmp_path) is False


def test_contest_demo_actual_run_streams_korean_journey_and_keeps_claim_boundary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "K_GUARD_EVIDENCE_HMAC_KEY",
        "contest-demo-test-operator-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    )
    stream = StringIO()

    scorecard = demo.run_demo(tmp_path, stream=stream)

    output = stream.getvalue()
    stage_positions = [output.index(f"[{index}/6]") for index in range(1, 7)]
    assert stage_positions == sorted(stage_positions)
    assert "[제품 CLI] 출력 수신: verdict=hold_fix, 전체 gate=HOLD" in output
    assert "보고서 순서상 첫 blocker: DYN_UNAUTH_API_JSON" in output
    assert "--- a/app.py" in output
    assert "애플리케이션 위험: CLEAR (clear_in_reviewed_scope, 검수 범위 한정)" in output
    assert "제품 qualification: HOLD (hold_qualification)" in output
    assert "canonical release authority: 부여되지 않음" in output

    assert scorecard["passed"] is True
    assert scorecard["stage_order"] == list(demo.STAGE_ORDER)
    assert scorecard["transition"] == ["hold_fix", "hold_qualification"]
    assert scorecard["application_transition"] == ["risk_blocked", "clear_in_reviewed_scope"]
    assert all(scorecard["checks"].values())
    assert scorecard["public_targets_called"] is False
    assert scorecard["mcp_client_exercised"] is False
    assert scorecard["award_evidence_claimed"] is False
    assert scorecard["release_authority_claimed"] is False

    transcript = (tmp_path / "evidence" / "demo-transcript.txt").read_text(encoding="utf-8")
    persisted_scorecard = json.loads((tmp_path / "evidence" / "demo-scorecard.json").read_text(encoding="utf-8"))
    assert transcript in output
    assert persisted_scorecard == scorecard
