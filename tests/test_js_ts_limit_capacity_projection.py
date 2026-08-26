from __future__ import annotations

from pathlib import Path

import pytest

from scripts.project_js_ts_limit_capacity import (
    _finding_record,
    write_projection,
)


def _finding(rule_id: str, evidence: str) -> dict:
    return {
        "artifact_scope": "repository_asset",
        "confidence": "low",
        "evidence": evidence,
        "file": "<workspace>",
        "line_start": None,
        "rule_id": rule_id,
        "severity": "medium",
        "source": "retention",
    }


def test_retention_aggregate_identity_survives_count_evidence_change(
    tmp_path: Path,
) -> None:
    before = _finding_record(
        _finding(
            "RETENTION_POLICY_MISSING_FOR_PERSONAL_DATA",
            "finding_count=20 raw_returned=false",
        ),
        app="fixture",
        app_root=tmp_path,
    )
    after = _finding_record(
        _finding(
            "RETENTION_POLICY_MISSING_FOR_PERSONAL_DATA",
            "finding_count=28 raw_returned=false",
        ),
        app="fixture",
        app_root=tmp_path,
    )

    assert before["semantic_key"] == after["semantic_key"]
    assert before["content_sha256"] != after["content_sha256"]
    assert before["evidence_sha256"] != after["evidence_sha256"]


def test_nonaggregate_finding_identity_includes_evidence(
    tmp_path: Path,
) -> None:
    before = _finding_record(
        _finding(
            "JS_TS_TAINT_PII_TO_RESPONSE",
            "source_hash=1111 sink_hash=2222",
        ),
        app="fixture",
        app_root=tmp_path,
    )
    after = _finding_record(
        _finding(
            "JS_TS_TAINT_PII_TO_RESPONSE",
            "source_hash=3333 sink_hash=4444",
        ),
        app="fixture",
        app_root=tmp_path,
    )

    assert before["semantic_key"] != after["semantic_key"]


def test_limit_projection_refuses_to_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "projection.json"
    output.write_text("{}\n", encoding="utf-8")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        write_projection(output, {"schema": "fixture"})
