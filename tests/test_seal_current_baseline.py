from __future__ import annotations

import importlib.util
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "seal_current_baseline.py"
SPEC = importlib.util.spec_from_file_location("seal_current_baseline_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
baseline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(baseline)


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "src" / "k_guard_mcp").mkdir(parents=True)
    (root / "src" / "k_guard_mcp" / "scanner.py").write_text("RULE = 'one'\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname = 'baseline-test'\n", encoding="utf-8")
    (root / "requirements-build.lock").write_text("build==1\n", encoding="utf-8")
    (root / "requirements-evidence.lock").write_text("evidence==1\n", encoding="utf-8")
    _git(root, "init")
    _git(root, "config", "user.email", "tests@example.invalid")
    _git(root, "config", "user.name", "K-Guard Tests")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "baseline")
    return root


def _toolchain() -> dict[str, str]:
    return {
        "python": "3.11.9",
        "git": "git version test",
        "pytest": "pytest 8.0.0",
        "docker": "Docker version test",
    }


def _dependencies() -> dict[str, str]:
    return {name: "1.0.0" for name in baseline.DEPENDENCY_NAMES}


def _receipt(root: Path) -> dict:
    return baseline.build_baseline_receipt(
        root,
        toolchain=_toolchain(),
        dependency_versions=_dependencies(),
    )


def test_same_target_produces_byte_exact_raw_free_baseline_receipt(tmp_path: Path) -> None:
    root = _repository(tmp_path)

    first = _receipt(root)
    second = _receipt(root)

    assert baseline.canonical_json_bytes(first) == baseline.canonical_json_bytes(second)
    assert first["raw_returned"] is False
    assert first["claim_boundary"]["product_accuracy_proven"] is False
    assert first["release_gate_passed"] is False
    baseline.validate_baseline_receipt(first)


def test_analyzer_change_requires_a_new_baseline_receipt(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    first = _receipt(root)

    assert (
        baseline.validate_current_baseline(
            root,
            first,
            toolchain=_toolchain(),
            dependency_versions=_dependencies(),
        )["receipt_sha256"]
        == first["receipt_sha256"]
    )

    (root / "src" / "k_guard_mcp" / "scanner.py").write_text("RULE = 'two'\n", encoding="utf-8")
    second = _receipt(root)

    assert first["analyzer"]["package_tree_sha256"] != second["analyzer"]["package_tree_sha256"]
    assert first["target"]["dirty_worktree_sha256"] != second["target"]["dirty_worktree_sha256"]
    assert first["receipt_sha256"] != second["receipt_sha256"]
    with pytest.raises(baseline.BaselineSealError, match="baseline_not_current"):
        baseline.validate_current_baseline(
            root,
            first,
            toolchain=_toolchain(),
            dependency_versions=_dependencies(),
        )


def test_untracked_content_change_invalidates_target_without_relabeling_analyzer(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    first = _receipt(root)

    (root / "operator-note.txt").write_text("first note\n", encoding="utf-8")
    second = _receipt(root)

    assert first["analyzer"]["package_tree_sha256"] == second["analyzer"]["package_tree_sha256"]
    assert first["target"]["dirty_path_set_sha256"] != second["target"]["dirty_path_set_sha256"]
    assert first["target"]["dirty_worktree_sha256"] != second["target"]["dirty_worktree_sha256"]
    assert first["receipt_sha256"] != second["receipt_sha256"]


def test_validation_rejects_claim_promotion_missing_tool_and_hash_tampering(tmp_path: Path) -> None:
    receipt = _receipt(_repository(tmp_path))

    promoted = deepcopy(receipt)
    promoted["claim_boundary"]["product_accuracy_proven"] = True
    with pytest.raises(baseline.BaselineSealError, match="claim_boundary_invalid"):
        baseline.validate_baseline_receipt(promoted)

    missing_tool = deepcopy(receipt)
    del missing_tool["toolchain"]["docker"]
    with pytest.raises(baseline.BaselineSealError, match="toolchain_keys_invalid"):
        baseline.validate_baseline_receipt(missing_tool)

    tampered = deepcopy(receipt)
    tampered["repository"]["pyproject_sha256"] = "0" * 64
    with pytest.raises(baseline.BaselineSealError, match="receipt_hash_invalid"):
        baseline.validate_baseline_receipt(tampered)


def test_receipt_can_only_be_written_outside_the_repository_and_never_overwritten(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    receipt = _receipt(root)
    external = tmp_path / "evidence" / "baseline.json"

    baseline.write_baseline_receipt(root, external, receipt)

    assert baseline._load_canonical_receipt(external)["receipt_sha256"] == receipt["receipt_sha256"]
    with pytest.raises(baseline.BaselineSealError, match="receipt_output_already_exists"):
        baseline.write_baseline_receipt(root, external, receipt)
    with pytest.raises(baseline.BaselineSealError, match="receipt_output_must_be_outside_repository"):
        baseline.write_baseline_receipt(root, root / "baseline.json", receipt)
