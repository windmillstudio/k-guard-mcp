from __future__ import annotations

from pathlib import Path

from scripts.submission_artifacts import build_manifest, normalize_text_artifacts, validate_manifest


def test_submission_manifest_binds_every_artifact_exactly(tmp_path: Path) -> None:
    submission = tmp_path / "submission"
    (submission / "report").mkdir(parents=True)
    (submission / "demo").mkdir()
    (submission / "report" / "report.html").write_text("report", encoding="utf-8")
    (submission / "demo" / "demo.mp4").write_bytes(b"video")

    manifest = submission / "SHA256SUMS"
    manifest.write_text(build_manifest(tmp_path), encoding="utf-8")

    assert validate_manifest(tmp_path) == []
    (submission / "demo" / "demo.mp4").write_bytes(b"changed")
    assert validate_manifest(tmp_path) == ["submission_manifest_content_mismatch"]


def test_submission_text_normalization_never_changes_binary_artifacts(tmp_path: Path) -> None:
    submission = tmp_path / "submission"
    submission.mkdir()
    text = submission / "attestation.json"
    binary = submission / "demo.mp4"
    text.write_bytes(b'{\r\n  "valid": true\r\n}\r\n')
    binary.write_bytes(b"video\r\nbytes")

    assert normalize_text_artifacts(tmp_path) == 1
    assert text.read_bytes() == b'{\n  "valid": true\n}\n'
    assert binary.read_bytes() == b"video\r\nbytes"


def test_submission_manifest_binds_the_distributed_brand_source(tmp_path: Path) -> None:
    (tmp_path / "submission").mkdir()
    hero = tmp_path / "src" / "k_guard_mcp" / "assets" / "glasses-senpai-hero.png"
    hero.parent.mkdir(parents=True)
    hero.write_bytes(b"project-created image")

    manifest = build_manifest(tmp_path)

    assert "src/k_guard_mcp/assets/glasses-senpai-hero.png" in manifest
