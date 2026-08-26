from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "prepare_holdout_runtime.py"
SPEC = importlib.util.spec_from_file_location("prepare_holdout_runtime_test", SCRIPT)
assert SPEC and SPEC.loader
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def test_seal_install_report_binds_exact_artifact_set_and_root_wheel(tmp_path: Path) -> None:
    wheel_hash = "a" * 64
    path = tmp_path / "report.json"
    path.write_text(
        json.dumps(
            {
                "version": "1",
                "pip_version": "24.0",
                "install": [
                    {
                        "download_info": {
                            "archive_info": {"hashes": {"sha256": wheel_hash}}
                        },
                        "requested": True,
                        "metadata": {"name": "K_Guard.MCP", "version": "0.1.0"},
                    },
                    {
                        "download_info": {
                            "archive_info": {"hashes": {"sha256": "b" * 64}}
                        },
                        "requested": False,
                        "metadata": {"name": "Dependency", "version": "1.0"},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    payload = runtime.seal_install_report(path, wheel_hash)

    expected_rows = [
        {"name": "dependency", "version": "1.0", "sha256": "b" * 64},
        {"name": "k-guard-mcp", "version": "0.1.0", "sha256": wheel_hash},
    ]
    expected = hashlib.sha256(
        json.dumps(expected_rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert payload["k_guard_install_artifact_set_sha256"] == expected
    assert path.read_bytes().endswith(b"\n")


def test_seal_install_report_rejects_unbound_or_duplicate_root(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    row = {
        "download_info": {"archive_info": {"hashes": {"sha256": "b" * 64}}},
        "requested": True,
        "metadata": {"name": "k-guard-mcp", "version": "0.1.0"},
    }
    path.write_text(json.dumps({"version": "1", "install": [row]}), encoding="utf-8")
    with pytest.raises(ValueError, match="rooted"):
        runtime.seal_install_report(path, "a" * 64)
