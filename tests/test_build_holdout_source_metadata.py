from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_holdout_source_metadata.py"
SPEC = importlib.util.spec_from_file_location("build_holdout_source_metadata_test", SCRIPT)
assert SPEC and SPEC.loader
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def _seed(tmp_path: Path) -> Path:
    path = tmp_path / "seed.json"
    path.write_text(
        json.dumps(
            {
                "apps": [
                    {
                        "repository": "https://github.com/Owner/Repo.git",
                        "commit": "a" * 40,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


def test_builder_is_structural_preflight_and_binds_github_identity(tmp_path: Path, monkeypatch) -> None:
    assert "k_guard_mcp" not in SCRIPT.read_text(encoding="utf-8")

    def fake_github(url: str, _token: str | None):
        if url.endswith("/git/commits/" + "a" * 40):
            return {"sha": "a" * 40, "tree": {"sha": "b" * 40}}
        if "/git/trees/" in url:
            return {
                "sha": "b" * 40,
                "truncated": False,
                "tree": [
                    {
                        "path": "src",
                        "mode": "040000",
                        "type": "tree",
                        "sha": "c" * 40,
                    },
                    {
                        "path": "src/app.ts",
                        "mode": "100644",
                        "type": "blob",
                        "sha": "d" * 40,
                    },
                ],
            }
        return {
            "full_name": "Owner/Repo",
            "node_id": "R_repo",
            "default_branch": "main",
            "fork": False,
            "archived": False,
            "stargazers_count": 42,
            "language": "TypeScript",
            "license": {"spdx_id": "MIT"},
        }

    monkeypatch.setattr(builder, "_github_json", fake_github)
    payload = builder.build_source_metadata(_seed(tmp_path))

    row = payload["repositories"][0]
    assert row["repository_id"] == "owner/repo"
    assert row["github_node_id"] == "R_repo"
    assert row["commit_tree"] == "b" * 40
    assert row["git_tree_entry_count"] == 2
    assert row["git_tree_mode_counts"] == {"040000": 1, "100644": 1}
    assert row["git_tree_recursive_truncated"] is False
    assert len(row["git_tree_structure_sha256"]) == 64
    assert payload["schema"] == "k_guard_holdout_source_metadata.v2"
    assert payload["all_source_trees_structurally_eligible"] is True
    assert payload["selection_boundary"]["scanner_output_observed"] is False
    assert payload["selection_boundary"]["git_tree_entry_modes_verified"] is True


@pytest.mark.parametrize(("field", "value", "message"), [("fork", True, "fork"), ("archived", True, "archived")])
def test_builder_rejects_ineligible_repository_metadata(
    tmp_path: Path,
    monkeypatch,
    field: str,
    value: bool,
    message: str,
) -> None:
    def fake_github(url: str, _token: str | None):
        if "/git/commits/" in url:
            return {"sha": "a" * 40, "tree": {"sha": "b" * 40}}
        if "/git/trees/" in url:
            return {
                "sha": "b" * 40,
                "truncated": False,
                "tree": [
                    {
                        "path": "app.py",
                        "mode": "100644",
                        "type": "blob",
                        "sha": "c" * 40,
                    }
                ],
            }
        payload = {
            "full_name": "owner/repo",
            "node_id": "R_repo",
            "default_branch": "main",
            "fork": False,
            "archived": False,
            "stargazers_count": 1,
            "language": None,
            "license": None,
        }
        payload[field] = value
        return payload

    monkeypatch.setattr(builder, "_github_json", fake_github)
    with pytest.raises(ValueError, match=message):
        builder.build_source_metadata(_seed(tmp_path))


@pytest.mark.parametrize(
    ("tree_payload", "message"),
    [
        (
            {
                "sha": "b" * 40,
                "truncated": False,
                "tree": [
                    {
                        "path": "linked.py",
                        "mode": "120000",
                        "type": "blob",
                        "sha": "c" * 40,
                    }
                ],
            },
            "symlink, submodule",
        ),
        (
            {
                "sha": "b" * 40,
                "truncated": False,
                "tree": [
                    {
                        "path": "vendor",
                        "mode": "160000",
                        "type": "commit",
                        "sha": "c" * 40,
                    }
                ],
            },
            "symlink, submodule",
        ),
        (
            {
                "sha": "b" * 40,
                "truncated": True,
                "tree": [],
            },
            "truncated",
        ),
    ],
)
def test_builder_rejects_unsupported_or_incomplete_recursive_git_trees(
    tmp_path: Path,
    monkeypatch,
    tree_payload: dict,
    message: str,
) -> None:
    def fake_github(url: str, _token: str | None):
        if "/git/commits/" in url:
            return {"sha": "a" * 40, "tree": {"sha": "b" * 40}}
        if "/git/trees/" in url:
            return tree_payload
        return {
            "full_name": "owner/repo",
            "node_id": "R_repo",
            "default_branch": "main",
            "fork": False,
            "archived": False,
            "stargazers_count": 1,
            "language": "Python",
            "license": {"spdx_id": "MIT"},
        }

    monkeypatch.setattr(builder, "_github_json", fake_github)
    with pytest.raises(ValueError, match=message):
        builder.build_source_metadata(_seed(tmp_path))
