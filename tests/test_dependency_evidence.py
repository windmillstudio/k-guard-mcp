from __future__ import annotations

import importlib.metadata
from pathlib import Path
from unittest.mock import patch

from k_guard_mcp import dependency_evidence as de


def test_release_evidence_lock_matches_installed_declared_closure() -> None:
    root = Path(__file__).resolve().parents[1]
    scope = de.declared_dependency_scope(root)
    names, unresolved = de.installed_dependency_closure(scope["all_requirements"])
    lock = de.evidence_lock_report(root)
    versions = {name: importlib.metadata.version(name) for name in names}

    assert scope["runtime"] == [
        "mcp>=1.28.1,<2",
        "httpx>=0.28.1,<1",
        "pydantic>=2.7,<3",
        "PyYAML>=6.0.2,<7",
        "PyJWT>=2.13.0",
        "sqlglot>=30.12.0,<31",
        "tree-sitter==0.26.0",
        "tree-sitter-java==0.23.5",
    ]
    assert {"dev", "mcp"}.issubset(scope["optional"])
    assert not unresolved
    assert lock["valid"] is True
    assert lock["active_entry_count"] == len(names)
    assert lock["entry_count"] == lock["hashed_entry_count"] == 41
    assert lock["hash_count"] > lock["entry_count"]
    assert lock["all_entries_hashed"] is True
    assert de.dependency_lock_mismatches(names, versions, lock) == []


def test_dependency_closure_propagates_requested_extras_and_missing_packages() -> None:
    class FakeDistribution:
        def __init__(self, requirements: list[str]) -> None:
            self.requires = requirements

    distributions = {
        "parent": FakeDistribution(
            [
                "base>=1",
                "crypto-child>=1; extra == 'crypto'",
                "ignored>=1; extra == 'other'",
            ]
        ),
        "base": FakeDistribution([]),
        "crypto-child": FakeDistribution([]),
    }

    def distribution(name: str):
        normalized = de.normalize_name(name)
        if normalized not in distributions:
            raise importlib.metadata.PackageNotFoundError(name)
        return distributions[normalized]

    with patch.object(de.importlib.metadata, "distribution", side_effect=distribution):
        names, unresolved = de.installed_dependency_closure(
            ["parent[crypto]>=1", "missing-package>=1", "broken requirement ???"]
        )

    assert names == {"parent", "base", "crypto-child", "missing-package"}
    assert unresolved == {"missing-package"}


def test_evidence_lock_parser_fails_closed_on_missing_invalid_and_duplicate_rows(tmp_path: Path) -> None:
    missing = de.evidence_lock_report(tmp_path)
    assert missing["valid"] is False
    assert missing["errors"] == ["evidence_lock_missing"]

    valid_hash = "a" * 64
    lock_path = tmp_path / de.EVIDENCE_LOCK_NAME
    lock_path.write_text(
        f"valid-name==1.2.3 --hash=sha256:{valid_hash}\n"
        f"valid_name==1.2.3 --hash=sha256:{valid_hash}\n"
        f"range-name>=1 --hash=sha256:{valid_hash}\n"
        f"wildcard-name==1.* --hash=sha256:{valid_hash}\n"
        f"not a requirement ??? --hash=sha256:{valid_hash}\n"
        f"inactive-name==1; python_version < '1' --hash=sha256:{valid_hash}\n"
        "missing-hash==1\n"
        "invalid-hash==1 --hash=sha256:not-a-digest\n",
        encoding="utf-8",
    )
    report = de.evidence_lock_report(tmp_path)

    assert report["valid"] is False
    assert report["active_versions"] == {"valid-name": "1.2.3"}
    assert any(error.startswith("duplicate_pin:") for error in report["errors"])
    assert any(error.startswith("non_exact_pin_line:") for error in report["errors"])
    assert any(error.startswith("invalid_requirement_line:") for error in report["errors"])
    assert any(error.startswith("missing_hash_line:") for error in report["errors"])
    assert any(error.startswith("invalid_hash_line:") for error in report["errors"])
    assert report["all_entries_hashed"] is False

    with patch.object(de, "Requirement", None):
        parser_missing = de.evidence_lock_report(tmp_path)
        names, unresolved = de.installed_dependency_closure(["anything==1"])
    assert parser_missing["errors"] == ["packaging_parser_unavailable"]
    assert names == set() and unresolved == {"packaging_parser_unavailable"}


def test_evidence_lock_parser_joins_continuations_and_rejects_truncation(tmp_path: Path) -> None:
    valid_hash = "b" * 64
    lock_path = tmp_path / de.EVIDENCE_LOCK_NAME
    lock_path.write_text(
        "joined-name==2.0 \\\n"
        f"    --hash=sha256:{valid_hash}\n"
        "truncated-name==1 \\\n",
        encoding="utf-8",
    )

    report = de.evidence_lock_report(tmp_path)

    assert report["active_versions"] == {"joined-name": "2.0"}
    assert report["hash_count"] == 1
    assert any(error.startswith("truncated_continuation_line:") for error in report["errors"])
    assert report["valid"] is False


def test_dependency_lock_mismatch_reasons_are_explicit() -> None:
    lock = {
        "active_versions": {
            "versioned": "2.0",
            "missing": "1.0",
            "stale": "4.0",
        }
    }
    mismatches = de.dependency_lock_mismatches(
        {"versioned", "missing", "unpinned"},
        {"versioned": "1.0"},
        lock,
    )
    by_name = {item["name"]: item for item in mismatches}

    assert by_name["versioned"]["reason"] == "installed_version_mismatch"
    assert by_name["missing"]["reason"] == "dependency_not_installed"
    assert by_name["unpinned"]["reason"] == "dependency_not_pinned"
    assert by_name["stale"]["reason"] == "stale_or_out_of_scope_pin"
    assert de.normalize_name("My_Package.Name") == "my-package-name"


def test_declared_dependency_scope_reads_all_optional_groups(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        "name = 'fixture'\n"
        "version = '1.0'\n"
        "dependencies = ['runtime-one>=1']\n"
        "[project.optional-dependencies]\n"
        "dev = ['dev-one>=1']\n"
        "mcp = ['mcp-one>=1']\n",
        encoding="utf-8",
    )

    scope = de.declared_dependency_scope(tmp_path)

    assert scope["runtime"] == ["runtime-one>=1"]
    assert scope["optional"] == {"dev": ["dev-one>=1"], "mcp": ["mcp-one>=1"]}
    assert scope["all_requirements"] == ["runtime-one>=1", "dev-one>=1", "mcp-one>=1"]


def test_evidence_lock_parser_rejects_invalid_encoding_and_interrupted_rows(
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / de.EVIDENCE_LOCK_NAME
    lock_path.write_bytes(b"\xff\xfe")

    report = de.evidence_lock_report(tmp_path)

    assert report["valid"] is False
    assert report["errors"] == ["lock_encoding_invalid"]

    entries, errors = de._logical_lock_entries(
        b"package==1 \\\n# comments cannot interrupt a continued requirement\n"
    )
    assert entries == []
    assert errors == ["invalid_continuation_line:2", "truncated_continuation_line:1"]


def test_dependency_parser_rejects_hash_without_requirement_and_missing_parser() -> None:
    requirement, hashes, error = de._split_hashed_requirement(f"--hash=sha256:{'a' * 64}")

    assert requirement == ""
    assert hashes == ["a" * 64]
    assert error == "invalid_hash_line"

    with patch.object(de, "Requirement", None):
        assert de._active_requirement("package==1", frozenset({""})) is None
