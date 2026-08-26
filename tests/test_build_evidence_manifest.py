from __future__ import annotations

from pathlib import Path

import pytest

from scripts.build_evidence_manifest import artifact_paths, build_manifest, main, validate_manifest


def test_builder_binds_every_artifact_without_rewriting_bytes(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    (evidence / "qualification").mkdir(parents=True)
    text = evidence / "qualification" / "report.json"
    binary = evidence / "sample.bin"
    text.write_bytes(b'{\r\n  "valid": true\r\n}\r\n')
    binary.write_bytes(b"binary\r\nbytes")

    before = {path: path.read_bytes() for path in (text, binary)}
    assert main(["--root", str(tmp_path)]) == 0

    assert validate_manifest(tmp_path) == []
    assert {path: path.read_bytes() for path in (text, binary)} == before
    assert set(artifact_paths(tmp_path)) == {binary, text}
    assert (evidence / "SHA256SUMS").read_bytes().endswith(b"\n")


def test_builder_detects_artifact_drift(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    artifact = evidence / "report.json"
    artifact.write_bytes(b'{"valid":true}\n')
    (evidence / "SHA256SUMS").write_bytes(build_manifest(tmp_path).encode("utf-8"))

    assert validate_manifest(tmp_path) == []
    artifact.write_bytes(b'{"valid":false}\n')
    assert validate_manifest(tmp_path) == ["evidence_manifest_content_mismatch"]


def test_builder_binds_nested_manifest_name_as_ordinary_evidence(tmp_path: Path) -> None:
    nested = tmp_path / "evidence" / "lane" / "SHA256SUMS"
    nested.parent.mkdir(parents=True)
    nested.write_bytes(b"nested evidence\n")

    rendered = build_manifest(tmp_path)

    assert "evidence/lane/SHA256SUMS" in rendered


def test_builder_rejects_evidence_symlinks(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"{}\n")
    link = evidence / "linked.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"file symlink unavailable: {exc}")

    with pytest.raises(ValueError, match="evidence symlink"):
        build_manifest(tmp_path)
