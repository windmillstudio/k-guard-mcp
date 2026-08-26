from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts.preregister_baseline import (
    SCHEMA,
    build_preregistration,
    canonical_json_bytes,
    load_preregistration,
    main,
    verify_preregistration,
)


CONSENSUS = """# Test consensus

## 1. 판정과 증명 경계
boundary

## 3. 정답 오라클 위계
oracle

### 3.1 Severity 계약
severity

## 4. 라벨 계약
labels

## 5. 분리된 코퍼스 레인
lanes

## 6. H100 표본 합격수
denominator

## 9. Finding review 방법

### 9.1 기계 matching
matching

### 9.4 결정론적 app PASS 함수
app pass

## 12. 즉시 중단·rollback 조건
stop

## 13. 잠긴 제품 게이트
gates

## 14. 허용 주장과 금지 주장
claims
"""


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _repository(tmp_path: Path) -> tuple[Path, Path, bytes, bytes]:
    root = tmp_path / "repo"
    (root / "src" / "k_guard_mcp" / "detectors").mkdir(parents=True)
    (root / "src" / "k_guard_mcp" / "analyzer_profiles").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "src" / "k_guard_mcp" / "detectors" / "sample.py").write_text("RULE = 'x'\n", encoding="utf-8")
    (root / "src" / "k_guard_mcp" / "release_policy.py").write_text("POLICY = 'block'\n", encoding="utf-8")
    (root / "src" / "k_guard_mcp" / "taint.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "src" / "k_guard_mcp" / "analyzer_profiles" / "deep.yml").write_text("rules: []\n", encoding="utf-8")
    (root / "requirements-evidence.lock").write_text("pytest==8.0.0\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        """[project]
name = "fixture"
version = "0.0.1"
dependencies = ["packaging>=24"]

[project.optional-dependencies]
dev = ["pytest>=8"]
""",
        encoding="utf-8",
    )
    protected_test = root / "tests" / "test_python_security_taint.py"
    protected_test.write_text("EXPECTED = 1\n", encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "K-Guard Test")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "fixture")
    protected_source = root / "src" / "k_guard_mcp" / "taint.py"
    protected_source.write_text("VALUE = 2\n", encoding="utf-8")
    protected_test.write_text("EXPECTED = 2\n", encoding="utf-8")
    consensus = tmp_path / "candidate-consensus.md"
    consensus.write_text(CONSENSUS, encoding="utf-8")
    return root, consensus, protected_source.read_bytes(), protected_test.read_bytes()


def test_build_and_verify_hashes_dirty_files_without_changing_them(tmp_path: Path) -> None:
    root, consensus, source_before, test_before = _repository(tmp_path)
    manifest = tmp_path / "evidence" / "phase-0-1.json"

    assert main(["create", "--repo", str(root), "--consensus", str(consensus), "--manifest", str(manifest)]) == 0
    payload = verify_preregistration(root, consensus, manifest)

    assert payload["schema"] == SCHEMA
    assert payload["git"]["dirty_path_count"] == 2
    assert {row["path"] for row in payload["git"]["dirty_paths"]} == {
        "src/k_guard_mcp/taint.py",
        "tests/test_python_security_taint.py",
    }
    assert payload["fingerprints"]["rules"]["sha256"]
    assert payload["fingerprints"]["config"]["sha256"]
    assert payload["fingerprints"]["dependencies"]["sha256"]
    assert payload["fingerprints"]["runtime"]["sha256"]
    assert set(payload["consensus_plan"]["references"]) == {
        "canonicalization",
        "claim",
        "denominator",
        "oracle",
        "severity",
        "stop",
    }
    assert (root / "src" / "k_guard_mcp" / "taint.py").read_bytes() == source_before
    assert (root / "tests" / "test_python_security_taint.py").read_bytes() == test_before


def test_verification_fails_closed_when_dirty_content_or_contract_changes(tmp_path: Path) -> None:
    root, consensus, _, _ = _repository(tmp_path)
    manifest = tmp_path / "phase-0-1.json"
    manifest.write_bytes(canonical_json_bytes(build_preregistration(root, consensus)))

    (root / "src" / "k_guard_mcp" / "taint.py").write_text("VALUE = 3\n", encoding="utf-8")
    with pytest.raises(ValueError, match="changed after freeze"):
        verify_preregistration(root, consensus, manifest)

    (root / "src" / "k_guard_mcp" / "taint.py").write_text("VALUE = 2\n", encoding="utf-8")
    consensus.write_text(CONSENSUS.replace("claims\n", "changed claims\n"), encoding="utf-8")
    with pytest.raises(ValueError, match="changed after freeze"):
        verify_preregistration(root, consensus, manifest)


def test_missing_contract_and_tampered_manifest_are_rejected(tmp_path: Path) -> None:
    root, consensus, _, _ = _repository(tmp_path)
    consensus.write_text(CONSENSUS.replace("## 13. 잠긴 제품 게이트", "## missing"), encoding="utf-8")
    with pytest.raises(ValueError, match="missing or duplicated"):
        build_preregistration(root, consensus)

    consensus.write_text(CONSENSUS, encoding="utf-8")
    manifest = tmp_path / "phase-0-1.json"
    payload = build_preregistration(root, consensus)
    manifest.write_bytes(canonical_json_bytes(payload))
    tampered = json.loads(manifest.read_text(encoding="utf-8"))
    tampered["git"]["head_tree"] = "0" * 40
    manifest.write_bytes(canonical_json_bytes(tampered))
    with pytest.raises(ValueError, match="hash mismatch"):
        load_preregistration(manifest)


def test_cli_rejects_manifest_inside_repository(tmp_path: Path) -> None:
    root, consensus, _, _ = _repository(tmp_path)
    manifest = root / "phase-0-1.json"
    assert main(["create", "--repo", str(root), "--consensus", str(consensus), "--manifest", str(manifest)]) == 2
    assert not manifest.exists()
