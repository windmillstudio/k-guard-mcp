from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "contest-demo" / "runtime-attack" / "demo.py"
GUARDIAN = ROOT / "examples" / "contest-demo" / "v1"


def _load_demo():
    spec = importlib.util.spec_from_file_location("runtime_attack_demo", DEMO)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_guardian_contest_demo_is_preserved() -> None:
    metadata = json.loads((GUARDIAN / "demo-metadata.json").read_text(encoding="utf-8"))
    assert (GUARDIAN / "demo.py").is_file()
    assert metadata["schema"] == "k_guard_contest_demo.v2"
    assert metadata["mcp_client_exercised"] is False
    assert metadata["execution_surface"] == "local_cli"
    assert metadata["real_app_validation"] is False


def test_official_mcp_client_attack_demo_blocks_before_malicious_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("mcp")
    monkeypatch.setenv(
        "K_GUARD_EVIDENCE_HMAC_KEY",
        "runtime-attack-demo-operator-key-20260826-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789",
    )
    demo = _load_demo()
    scorecard = demo.run_attack_demo(tmp_path)
    assert scorecard["real_app_validation"] is False
    assert scorecard["checks"]["attack_blocked_before_upstream"] is True
    assert scorecard["checks"]["attack_invoked_via_official_client"] is True
    assert scorecard["checks"]["block_observed_by_official_client"] is True
    assert scorecard["upstream_steal_calls"] == 0
    assert scorecard["checks"]["benign_echo_allowed"] is True
    assert scorecard["checks"]["secret_absent_from_report"] is True
    assert scorecard["checks"]["pii_absent_from_report"] is True
    assert scorecard["checks"]["finding_action_transaction_linked"] is True
    assert scorecard["checks"]["receipts_operator_keyed"] is True
    assert scorecard["checks"]["receipts_verified_with_operator_key"] is True
    assert scorecard["checks"]["persisted_receipts_verified_with_operator_key"] is True
    assert scorecard["checks"]["tampered_receipt_rejected"] is True
    assert scorecard["checks"]["evidence_bundle_verified_with_operator_key"] is True
    assert len(scorecard["attack_transaction_id"]) == 64
    assert scorecard["attack_finding_refs"]
    assert scorecard["passed"] is True
    assert "증거가 아닙니다" in scorecard["claim_boundary"]
    assert "canonical release authority" in scorecard["claim_boundary"]

    with pytest.raises(FileExistsError, match="must be new"):
        demo.run_attack_demo(tmp_path)
