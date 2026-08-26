from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from k_guard_mcp.hashing import EVIDENCE_HMAC_ENV
from scripts.mcp_config_development_calibration import PublicSource, SOURCES, build_calibration, write_calibration


def _blob_sha1(payload: bytes) -> str:
    prefix = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(prefix + payload, usedforsecurity=False).hexdigest()


def test_public_source_manifest_is_unique_and_content_bound() -> None:
    assert len(SOURCES) == 29
    assert len({source.repository for source in SOURCES}) == len(SOURCES)
    assert len({(source.repository, source.commit, source.path) for source in SOURCES}) == len(SOURCES)
    assert all(len(source.commit) == 40 for source in SOURCES)
    assert all(len(source.blob_sha1) == 40 for source in SOURCES)


def test_calibration_is_raw_free_and_marks_example_configs_as_supporting() -> None:
    payload = b'{"mcpServers":{"demo":{"command":"npx","args":["demo-server"]}}}'
    source = PublicSource(
        repository="example/project",
        commit="a" * 40,
        path="mcp.example.json",
        blob_sha1=_blob_sha1(payload),
        discovery_query="mcpServers npx language:JSON",
    )

    result = build_calibration((source,), fetcher=lambda _: payload)

    assert result["rows"][0]["rule_id"] == "MCP_UNPINNED_PACKAGE_EXECUTION"
    assert result["rows"][0]["artifact_scope"] == "example"
    assert result["rows"][0]["release_lane"] == "supporting_review"
    assert result["rows"][0]["manual_label"] == "unreviewed"
    assert result["claim_boundary"]["qualifies_release_policy"] is False
    assert result["raw_returned"] is False
    assert payload.decode("utf-8") not in str(result)


def test_calibration_rejects_changed_source_blob() -> None:
    source = PublicSource(
        repository="example/project",
        commit="a" * 40,
        path="mcp.json",
        blob_sha1="b" * 40,
        discovery_query="mcpServers npx language:JSON",
    )

    with pytest.raises(ValueError, match="Git blob mismatch"):
        build_calibration((source,), fetcher=lambda _: b"{}")


def test_candidate_identity_is_stable_across_operator_hmac_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = (
        b'{"mcpServers":{"one":{"command":"npx","args":["server"]},'
        b'"two":{"command":"npx","args":["server"]}}}'
    )
    source = PublicSource(
        repository="example/project",
        commit="a" * 40,
        path="mcp.json",
        blob_sha1=_blob_sha1(payload),
        discovery_query="mcpServers npx language:JSON",
    )

    monkeypatch.setenv(EVIDENCE_HMAC_ENV, "first-operator-evidence-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    first = build_calibration((source,), fetcher=lambda _: payload)
    monkeypatch.setenv(EVIDENCE_HMAC_ENV, "second-operator-evidence-key-9876543210-ZYXWVUTSRQPONMLKJIHGFEDCBA")
    second = build_calibration((source,), fetcher=lambda _: payload)

    assert len(first["rows"]) == 2
    assert first["rows"] == second["rows"]
    assert len({row["candidate_id"] for row in first["rows"]}) == 2


def test_calibration_writer_uses_canonical_utf8_lf(tmp_path: Path) -> None:
    output = tmp_path / "nested" / "calibration.json"

    write_calibration(output, {"schema": "fixture", "rows": []})

    raw = output.read_bytes()
    assert raw.endswith(b"\n")
    assert b"\r\n" not in raw
