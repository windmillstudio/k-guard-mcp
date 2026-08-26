from __future__ import annotations

from pathlib import Path

from k_guard_mcp.models import Finding
from k_guard_mcp.retention import RetentionDeletionAnalyzer


def test_executable_retention_and_erasure_paths_satisfy_privacy_review(tmp_path: Path) -> None:
    (tmp_path / "account.py").write_text(
        "RETENTION_DAYS = 30\n"
        "def delete_user(user_id):\n"
        "    return storage.delete(user_id)\n",
        encoding="utf-8",
    )
    privacy_finding = Finding(
        id="privacy-1",
        source="fixture",
        rule_id="PII_EMAIL",
        severity="high",
        confidence="high",
        title="Personal data",
        evidence="raw_returned=false",
        why_it_matters="fixture",
        recommendation="fixture",
    )
    analyzer = RetentionDeletionAnalyzer()

    counts, hashes = analyzer._markers(tmp_path)
    findings = analyzer.scan(tmp_path, [privacy_finding])

    assert counts == {"retention": 1, "deletion": 1}
    assert set(hashes) == {"retention", "deletion"}
    assert findings == []
