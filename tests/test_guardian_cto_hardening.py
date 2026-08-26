from __future__ import annotations

import json

from k_guard_mcp.guardian import run_guardian_audit
from k_guard_mcp.experience import apply_guardian_experience
from k_guard_mcp.hashing import DEFAULT_EVIDENCE_KEY, uses_public_evidence_key
from k_guard_mcp.provenance import evidence_bundle, object_artifact, source_tree_snapshot, verify_evidence_bundle


def test_release_snapshot_includes_deployable_build_and_js_module_outputs(tmp_path):
    files = [
        tmp_path / "dist" / "app.js",
        tmp_path / "build" / "server.mjs",
        tmp_path / "bundle.cjs",
    ]
    for path in files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("export const release = 'one';\n", encoding="utf-8")

    before = source_tree_snapshot(tmp_path)
    files[1].write_text("export const release = 'two';\n", encoding="utf-8")
    after = source_tree_snapshot(tmp_path)

    assert before["complete"] is True
    assert before["hashed_file_count"] == 3
    assert before["tree_sha256"] != after["tree_sha256"]


def test_release_snapshot_includes_scanned_vendor_source(tmp_path):
    vendor_source = tmp_path / "vendor" / "runtime.py"
    vendor_source.parent.mkdir(parents=True)
    vendor_source.write_text("TOKEN = 'first'\n", encoding="utf-8")

    before = source_tree_snapshot(tmp_path)
    vendor_source.write_text("TOKEN = 'second'\n", encoding="utf-8")
    after = source_tree_snapshot(tmp_path)

    assert before["complete"] is True
    assert before["hashed_file_count"] == 1
    assert before["tree_sha256"] != after["tree_sha256"]


def test_guardian_scans_deployable_build_outputs_and_binds_candidate_inventory(tmp_path):
    workspace = tmp_path / "app"
    build = workspace / "build"
    build.mkdir(parents=True)
    (workspace / "route.ts").write_text("export const GET = () => new Response('ok');\n", encoding="utf-8")
    (build / "client.js").write_text(
        "const OPENAI_API_KEY = 'sk-thisisaverylongfakeapikey000';\n",
        encoding="utf-8",
    )
    manifest = tmp_path / "guardian.csv"
    manifest.write_text(
        "target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,notes\n"
        "workspace-01,workspace,app,true,local project,false,,true,high,team,build output review\n",
        encoding="utf-8",
    )

    report = run_guardian_audit(manifest, fail_on_override="high")

    target = report["targets"][0]
    inventory = target["review_evidence"]["review_coverage"]["inventory"]
    consistency = target["review_evidence"]["scan_inventory_consistency"]
    assert inventory["supported_file_count"] == 2
    assert inventory["scanned_text_file_count"] == 2
    assert consistency["matched"] is True
    assert any("build" in str(item.get("file", "")) for item in target["findings"])
    assert target["gate"]["passed"] is False


def test_guardian_fails_closed_on_oversized_deployable_candidate(tmp_path):
    workspace = tmp_path / "app"
    bundle = workspace / "dist" / "bundle.js"
    bundle.parent.mkdir(parents=True)
    bundle.write_bytes(b"x" * (5 * 1024 * 1024 + 1))
    manifest = tmp_path / "guardian.csv"
    manifest.write_text(
        "target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,notes\n"
        "workspace-01,workspace,app,true,local project,false,,true,high,team,oversized output review\n",
        encoding="utf-8",
    )

    report = run_guardian_audit(manifest, fail_on_override="high")

    target = report["targets"][0]
    inventory = target["review_evidence"]["review_coverage"]["inventory"]
    assert inventory["supported_file_count"] == 1
    assert inventory["scanned_text_file_count"] == 0
    assert inventory["oversized_candidate_count"] == 1
    assert target["review_evidence"]["scan_inventory_consistency"]["matched"] is False
    assert "GUARDIAN_SCAN_INVENTORY_MISMATCH" in {finding["rule_id"] for finding in target["findings"]}
    assert target["gate"]["passed"] is False


def test_guardian_target_exception_never_returns_raw_error_text(tmp_path):
    workspace = tmp_path / "app"
    workspace.mkdir()
    (workspace / "app.py").write_text("print('ready')\n", encoding="utf-8")
    manifest = tmp_path / "guardian.csv"
    manifest.write_text(
        "target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,notes\n"
        "workspace-01,workspace,app,true,local project,false,,true,high,team,error review\n",
        encoding="utf-8",
    )
    sentinel = "private-user@example.com sk-thisisaverylongfakeapikey999"

    class FailingScanner:
        def scan_workspace(self, *args, **kwargs):
            raise RuntimeError(sentinel)

    report = run_guardian_audit(manifest, scanner=FailingScanner(), fail_on_override="high")
    payload = json.dumps(report, ensure_ascii=False)

    assert "GUARDIAN_TARGET_FAILED" in {finding["rule_id"] for finding in report["targets"][0]["findings"]}
    assert sentinel not in payload
    assert "private-user@example.com" not in payload
    assert "sk-thisisaverylongfakeapikey999" not in payload
    assert "raw_returned=false" in report["targets"][0]["findings"][0]["evidence"]


def test_only_high_override_can_hold_canonical_guardian_release_authority(tmp_path):
    workspace = tmp_path / "app"
    workspace.mkdir()
    (workspace / "app.py").write_text("def ready():\n    return True\n", encoding="utf-8")
    manifest = tmp_path / "guardian.csv"
    manifest.write_text(
        "target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,notes\n"
        "workspace-01,workspace,app,true,local project,false,,true,medium,team,noncanonical review\n",
        encoding="utf-8",
    )

    report = run_guardian_audit(manifest, fail_on_override="medium")

    assert report["execution_contract"]["mode"] == "report"
    assert report["review_contract"]["release_gate_enabled"] is False
    assert report["review_contract"]["canonical_release_authority"] is False
    assert "guardian_gate" not in report


def test_public_default_evidence_key_can_never_produce_ship(monkeypatch):
    monkeypatch.delenv("K_GUARD_EVIDENCE_HMAC_KEY", raising=False)
    report = {
        "summary": {"blocking_target_count": 0, "coverage_gap_target_count": 0},
        "review_contract": {
            "profile": "korean_senior",
            "strict_domain_enforcement": True,
            "canonical_release_authority": True,
            "release_authority": "canonical",
            "single_app_scope": True,
            "app_id": "primary-app",
            "passed": True,
        },
        "guardian_gate": {"passed": True, "fail_on": "high"},
        "evidence_bundle": evidence_bundle(
            "guardian_audit",
            "test",
            [object_artifact("release", {"passed": True}, role="gate")],
        ),
    }

    apply_guardian_experience(report)

    assert report["guardian_gate"]["passed"] is False
    assert report["guardian_gate"]["canonical_release_authority"] is False
    assert "operator_keyed_evidence_required" in report["guardian_gate"]["authority_blockers"]
    assert report["experience"]["verdict_code"] == "hold_authority"


def test_default_short_and_low_entropy_evidence_keys_never_become_operator_keys(monkeypatch):
    for weak_key in (DEFAULT_EVIDENCE_KEY, "short-key", "A" * 64):
        monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", weak_key)
        bundle = evidence_bundle("weak-key-check", "test", [object_artifact("value", {"ready": True})])

        assert uses_public_evidence_key() is True
        assert bundle["signature"]["key_mode"] == "public-default-key"
        assert bundle["signature"]["tamper_resistant_with_operator_secret"] is False
        assert verify_evidence_bundle(bundle, require_operator_key=True) is False


def test_unknown_guardian_kind_is_fixed_and_raw_free(tmp_path):
    sentinel = "private-kind-user@example.com-sk-thisisaverylongfakeapikey333"
    manifest = tmp_path / "guardian.csv"
    manifest.write_text(
        "target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,notes\n"
        f"target-01,{sentinel},.,true,local,false,,true,high,team,unknown kind\n",
        encoding="utf-8",
    )

    report = run_guardian_audit(manifest, fail_on_override="high")
    payload = json.dumps(report, ensure_ascii=False)

    assert report["targets"][0]["kind"] == "unknown"
    assert report["targets"][0]["kind_ref"]["raw_returned"] is False
    assert "GUARDIAN_TARGET_KIND_UNKNOWN" in {finding["rule_id"] for finding in report["targets"][0]["findings"]}
    assert sentinel not in payload
    assert "private-kind-user@example.com" not in payload
    assert "sk-thisisaverylongfakeapikey333" not in payload
