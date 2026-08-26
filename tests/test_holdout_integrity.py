from __future__ import annotations

import copy
import base64
import hashlib
import importlib.util
import json
import subprocess
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


integrity = _load("holdout_integrity", ROOT / "scripts" / "holdout_integrity.py")
builder = _load("build_holdout_exclusions", ROOT / "scripts" / "build_holdout_exclusions.py")
runner = _load("run_public_field_campaign_v4", ROOT / "scripts" / "run_public_field_campaign.py")
scorer = _load("public_field_effectiveness_v4", ROOT / "scripts" / "public_field_effectiveness.py")
assembler = _load("assemble_public_field_labels_v4", ROOT / "scripts" / "assemble_public_field_labels.py")
protocol = _load("holdout_protocol_v4", ROOT / "scripts" / "holdout_protocol.py")


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")


def test_structural_source_metadata_requires_complete_regular_git_tree_contract(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "source-metadata-v2.json"
    repository_id = "owner/repo"
    payload = {
        "schema": protocol.STRUCTURAL_SOURCE_METADATA_SCHEMA,
        "metadata_source": "github_api_v3",
        "retrieved_at": "2026-07-16T00:00:00Z",
        "selection_boundary": {
            "k_guard_imported": False,
            "scanner_output_observed": False,
            "github_metadata_cryptographically_attested": False,
            "git_tree_entry_modes_verified": True,
        },
        "git_tree_entry_policy": protocol.SOURCE_METADATA_GIT_TREE_ENTRY_POLICY,
        "all_source_trees_structurally_eligible": True,
        "repository_count": 1,
        "repository_set_sha256": protocol._repository_set_sha256([repository_id]),
        "repositories": [
            {
                "repository": f"https://github.com/{repository_id}.git",
                "repository_id": repository_id,
                "github_node_id": "R_repo",
                "default_branch": "main",
                "is_fork": False,
                "fork_parent_repository_id": None,
                "archived": False,
                "commit": "a" * 40,
                "commit_tree": "b" * 40,
                "stars_at_registration": 1,
                "language": "Python",
                "license_spdx": "MIT",
                "git_tree_entry_count": 1,
                "git_tree_mode_counts": {"100644": 1},
                "git_tree_recursive_truncated": False,
                "git_tree_structure_sha256": "c" * 64,
            }
        ],
        "raw_returned": False,
    }
    _write(source_path, payload)

    assert protocol.load_source_metadata(source_path) == payload

    payload["repositories"][0]["git_tree_mode_counts"] = {"120000": 1}
    _write(source_path, payload)
    with pytest.raises(ValueError, match="Git tree eligibility"):
        protocol.load_source_metadata(source_path)


def test_protocol_file_sets_are_versioned_without_rewriting_v1() -> None:
    legacy_rows = [
        {"path": path, "sha256": hashlib.sha256(path.encode()).hexdigest()}
        for path in protocol.LEGACY_REQUIRED_PROTOCOL_FILES
    ]
    source_bound_rows = [
        {"path": path, "sha256": hashlib.sha256(path.encode()).hexdigest()}
        for path in protocol.SOURCE_BOUND_REQUIRED_PROTOCOL_FILES
    ]
    preexecution_rows = [
        {"path": path, "sha256": hashlib.sha256(path.encode()).hexdigest()}
        for path in protocol.PREEXECUTION_REQUIRED_PROTOCOL_FILES
    ]
    structural_rows = [
        {"path": path, "sha256": hashlib.sha256(path.encode()).hexdigest()}
        for path in protocol.STRUCTURAL_REQUIRED_PROTOCOL_FILES
    ]
    current_rows = [
        {"path": path, "sha256": hashlib.sha256(path.encode()).hexdigest()}
        for path in protocol.REQUIRED_PROTOCOL_FILES
    ]

    assert set(
        protocol._validate_protocol_files(legacy_rows, protocol.LEGACY_PROTOCOL_SCHEMA)
    ) == set(protocol.LEGACY_REQUIRED_PROTOCOL_FILES)
    assert set(
        protocol._validate_protocol_files(
            source_bound_rows,
            protocol.SOURCE_BOUND_PROTOCOL_SCHEMA,
        )
    ) == set(protocol.SOURCE_BOUND_REQUIRED_PROTOCOL_FILES)
    assert set(
        protocol._validate_protocol_files(
            preexecution_rows,
            protocol.PREEXECUTION_PROTOCOL_SCHEMA,
        )
    ) == set(protocol.PREEXECUTION_REQUIRED_PROTOCOL_FILES)
    assert set(
        protocol._validate_protocol_files(
            structural_rows,
            protocol.STRUCTURAL_PROTOCOL_SCHEMA,
        )
    ) == set(protocol.STRUCTURAL_REQUIRED_PROTOCOL_FILES)
    assert set(protocol._validate_protocol_files(current_rows, protocol.PROTOCOL_SCHEMA)) == set(
        protocol.REQUIRED_PROTOCOL_FILES
    )
    with pytest.raises(ValueError, match="required file set"):
        protocol._validate_protocol_files(current_rows, protocol.LEGACY_PROTOCOL_SCHEMA)
    with pytest.raises(ValueError, match="required file set"):
        protocol._validate_protocol_files(current_rows, protocol.SOURCE_BOUND_PROTOCOL_SCHEMA)
    with pytest.raises(ValueError, match="required file set"):
        protocol._validate_protocol_files(current_rows, protocol.PREEXECUTION_PROTOCOL_SCHEMA)


def _runtime_execution_receipts(expected_runtime: dict) -> dict:
    executed = [
        {
            "path": "<prefix>/Lib/site-packages/k_guard_mcp/cli.py",
            "sha256": "a" * 64,
            "event_kinds": ["exec"],
            "event_count": 1,
            "executed_code_sha256": ["c" * 64],
        }
    ]
    modules = [{"path": "<base_prefix>/python311.dll", "sha256": "b" * 64}]
    locked_native_files = [
        {"path": "<base_prefix>/python311.dll", "sha256": "b" * 64}
    ]
    directory_paths: set[str] = set()
    for tree_name, normalized_root in (
        ("prefix_tree", "<prefix>"),
        ("base_runtime_tree", "<base_prefix>"),
    ):
        for file_row in expected_runtime[tree_name]["files"]:
            parent = Path(file_row["path"]).parent
            while parent != Path("."):
                directory_paths.add(normalized_root + "/" + parent.as_posix())
                parent = parent.parent
    def object_entry(
        path: str,
        kind: str,
        content_sha256: str | None,
    ) -> dict:
        basic_info = {
            "creation_time": 1,
            "last_write_time": 2,
            "change_time": 3,
            "file_attributes": 32,
        }
        payload = {
            "kind": kind,
            "basic_info": basic_info,
            "basic_sha256": hashlib.sha256(
                json.dumps(
                    basic_info,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
            "security_sha256": hashlib.sha256((path + ":security").encode()).hexdigest(),
            "file_id_sha256": hashlib.sha256((path + ":file-id").encode()).hexdigest(),
            "usn_record": {
                "major_version": 2,
                "minor_version": 0,
                "file_reference": "01" * 8,
                "parent_reference": "02" * 8,
                "usn": "1",
            },
            "content_sha256": content_sha256,
        }
        attestation_sha256 = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return {
            "path": path,
            "kind": kind,
            "expected_content_sha256": content_sha256,
            "checkpoints": [
                {
                    "phase": phase,
                    **payload,
                    "attestation_sha256": attestation_sha256,
                }
                for phase in (
                    "pre_prewarm",
                    "post_prewarm",
                    "pre_scan",
                    "post_scan",
                    "post_drain",
                    "post_stop",
                    "post_classification",
                )
            ],
        }

    object_entries = sorted(
        [
            *[
                object_entry(row["path"], "native_file", row["sha256"])
                for row in locked_native_files
            ],
            *[
                object_entry(path, "directory", None)
                for path in sorted(directory_paths)
            ],
        ],
        key=lambda row: row["path"],
    )
    return {
        "image_load_monitor": {
            "schema": "k_guard_windows_image_load_monitor.v1",
            "guard": "ntdll_ldr_dll_notification_v1",
            "registered": True,
            "unregistered": True,
            "canaries": [
                {
                    "phase": phase,
                    "load_succeeded": True,
                    "load_error": 0,
                    "free_succeeded": True,
                    "free_error": 0,
                    "load_notification_seen": True,
                    "unload_notification_seen": True,
                    "passed": True,
                }
                for phase in ("before-scan", "after-scan")
            ],
            "scan_event_count": 0,
            "scan_load_count": 0,
            "scan_unload_count": 0,
            "event_set_sha256": hashlib.sha256(
                b"k_guard_windows_image_load_monitor.v1\0[]"
            ).hexdigest(),
            "events": [],
            "outside_image_events": [],
            "callback_errors": [],
            "proof_boundary": "windows_loader_managed_images",
            "passed": True,
            "raw_returned": False,
        },
        "child_process_policy": {
            "schema": "k_guard_windows_child_process_policy.v1",
            "policy_id": 13,
            "required_flags": 1,
            "before_flags": 0,
            "set_succeeded": True,
            "set_error": 0,
            "after_flags": 1,
            "disable_attempt_canary": {
                "blocked": True,
                "winerror": 5,
                "flags_after_attempt": 1,
            },
            "prebound_create_process_canary": {
                "api": "kernel32.CreateProcessW",
                "blocked": True,
                "winerror": 367,
                "unexpected_process_created": False,
            },
            "prebound_shell_execute_canary": {
                "api": "shell32.ShellExecuteW",
                "blocked": True,
                "result": 5,
                "winerror": 367,
            },
            "final_query_succeeded": True,
            "final_flags": 1,
            "passed": True,
            "raw_returned": False,
        },
        "execution_audit": {
            "schema": "k_guard_python_execution_audit.v3",
            "event_count": 1,
            "executed_file_count": 1,
            "executed_file_set_sha256": hashlib.sha256(
                b"k_guard_python_execution_audit.v3\0"
                + json.dumps(executed, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            "executed_files": executed,
            "outside_executed_code": [],
            "dynamic_executed_code": [],
            "dynamic_exec_events": [],
            "audit_errors": [],
            "process_creation_events": [],
            "code_object_control_events": [],
            "native_symbol_resolution_events": [],
            "passed": True,
            "raw_returned": False,
        },
        "native_module_receipt": {
            "schema": "k_guard_windows_native_module_receipt.v1",
            "module_count": 1,
            "module_set_sha256": hashlib.sha256(
                b"k_guard_windows_native_module_receipt.v1\0"
                + json.dumps(modules, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            "modules": modules,
            "outside_native_modules": [],
            "passed": True,
            "raw_returned": False,
        },
        "native_runtime_lock": {
            "schema": "k_guard_windows_native_runtime_lock.v1",
            "guard": protocol.NATIVE_RUNTIME_LOCK_GUARD,
            "expected_file_count": 1,
            "locked_file_count": 1,
            "released_file_count": 1,
            "file_set_sha256": hashlib.sha256(
                b"k_guard_windows_native_runtime_lock.v1\0"
                + json.dumps(
                    locked_native_files,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
            "files": locked_native_files,
            "read_open_canary": {
                "path": "<base_prefix>/python311.dll",
                "succeeded": True,
                "winerror": 0,
            },
            "write_open_canary": {
                "path": "<base_prefix>/python311.dll",
                "blocked": True,
                "winerror": 32,
            },
            "delete_open_canary": {
                "path": "<base_prefix>/python311.dll",
                "blocked": True,
                "winerror": 32,
            },
            "metadata_access_canaries": [
                {
                    "path": "<base_prefix>/python311.dll",
                    "access": access,
                    "opened": opened,
                    "winerror": 0 if opened else 5,
                }
                for access, opened in (
                    ("file_write_attributes", True),
                    ("write_dac", True),
                    ("write_owner", True),
                    ("access_system_security", False),
                )
            ],
            "metadata_integrity_guard": protocol.RUNTIME_OBJECT_ATTESTATION_GUARD,
            "classification_completed_while_active": True,
            "errors": [],
            "activated": True,
            "released": True,
            "passed": True,
            "raw_returned": False,
        },
        "native_runtime_prewarm": {
            "schema": "k_guard_windows_native_runtime_prewarm.v1",
            "guard": protocol.NATIVE_RUNTIME_PREWARM_GUARD,
            "method": (
                "CreateFileMappingW(PAGE_READONLY|SEC_IMAGE)"
                "+MapViewOfFile(FILE_MAP_READ)"
            ),
            "measurement_boundary": (
                "after native runtime lock activation and pre-prewarm object snapshot; "
                "before runtime mutation watchers, image-load monitoring, and scanner import"
            ),
            "expected_file_count": len(locked_native_files),
            "file_count": len(locked_native_files),
            "mapped_file_count": len(locked_native_files),
            "policy_blocked_file_count": 0,
            "file_set_sha256": hashlib.sha256(
                b"k_guard_windows_native_runtime_prewarm.v1\0"
                + json.dumps(
                    [
                        {
                            **row,
                            "outcome": "mapped",
                            "winerror": 0,
                        }
                        for row in locked_native_files
                    ],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
            "files": [
                {
                    **row,
                    "outcome": "mapped",
                    "winerror": 0,
                }
                for row in locked_native_files
            ],
            "native_lock_active": True,
            "errors": [],
            "completed": True,
            "passed": True,
            "raw_returned": False,
        },
        "runtime_object_attestation": {
            "schema": "k_guard_windows_runtime_object_attestation.v2",
            "guard": protocol.RUNTIME_OBJECT_ATTESTATION_GUARD,
            "security_descriptor_scope": "owner_group_dacl",
            "sacl_requires_elevated_security_privilege": True,
            "usn_required": True,
            "checkpoint_phases": [
                "pre_prewarm",
                "post_prewarm",
                "pre_scan",
                "post_scan",
                "post_drain",
                "post_stop",
                "post_classification",
            ],
            "measurement_boundary": (
                "pre-prewarm snapshot under the active native lock; controlled SEC_IMAGE "
                "prewarm transition; post-prewarm through post-classification must remain "
                "object-identical before handle release"
            ),
            "prewarm_transition_policy": {
                "native_file_mutable_fields": [
                    "basic_info.change_time",
                    "usn_record.usn",
                ],
                "native_file_immutable_fields": [
                    "basic_info.creation_time",
                    "basic_info.last_write_time",
                    "basic_info.file_attributes",
                    "security_sha256",
                    "file_id_sha256",
                    "content_sha256",
                    "usn_record.major_version",
                    "usn_record.minor_version",
                    "usn_record.file_reference",
                    "usn_record.parent_reference",
                ],
                "directory_mutable_fields": [],
            },
            "prewarm_transition_passed": True,
            "expected_entry_count": len(object_entries),
            "entry_count": len(object_entries),
            "native_file_count": len(locked_native_files),
            "directory_count": len(directory_paths),
            "entry_set_sha256": hashlib.sha256(
                b"k_guard_windows_runtime_object_attestation.v2\0"
                + json.dumps(
                    object_entries,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
            "entries": object_entries,
            "prewarm_changed_entry_count": 0,
            "prewarm_changed_entries": [],
            "changed_entry_count": 0,
            "changed_entries": [],
            "errors": [],
            "passed": True,
            "raw_returned": False,
        },
    }


def _snapshot(tmp_path: Path) -> tuple[Path, dict]:
    repository_ids = ["prior/one", "prior/two"]
    payload = {
        "schema": integrity.HOLDOUT_EXCLUSION_SCHEMA,
        "source_revision": "a" * 40,
        "repository_count": len(repository_ids),
        "repository_set_sha256": integrity.repository_set_sha256(repository_ids),
        "repositories": [
            {"repository_id": value, "evidence_paths": ["evidence/public/prior.json"]}
            for value in repository_ids
        ],
        "raw_returned": False,
    }
    path = tmp_path / "prior-exclusions.json"
    _write(path, payload)
    return path, payload


def _protocol_artifacts(tmp_path: Path, apps: list[dict]) -> tuple[str, dict]:
    wheel_path = tmp_path / "k_guard_mcp-0.1.0-py3-none-any.whl"
    members = {
        "k_guard_mcp/__init__.py": b"__version__ = '0.1.0'\n",
        "k_guard_mcp-0.1.0.dist-info/METADATA": (
            b"Metadata-Version: 2.1\nName: k-guard-mcp\nVersion: 0.1.0\n"
            b"Requires-Python: >=3.11\n\n"
        ),
        "k_guard_mcp-0.1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
        ),
    }
    record_name = "k_guard_mcp-0.1.0.dist-info/RECORD"
    record_lines = []
    for name, payload in sorted(members.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode("ascii").rstrip("=")
        record_lines.append(f"{name},sha256={digest},{len(payload)}\n")
    record_lines.append(f"{record_name},,\n")
    members[record_name] = "".join(record_lines).encode("utf-8")
    with zipfile.ZipFile(wheel_path, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    wheel_contract = protocol.wheel_qualification_contract(wheel_path)
    runtime_path = tmp_path / "runtime-environment.json"
    scanner_python_hash = "e" * 64
    distribution_set_hash = "f" * 64
    scanner_scaffold_hash = hashlib.sha256(
        (protocol.SCANNER_SCAFFOLD_SCHEMA + "\0").encode("ascii") + b"[]"
    ).hexdigest()
    _write(
        runtime_path,
        {
            "schema": protocol.RUNTIME_ENVIRONMENT_SCHEMA,
            "python": {
                "implementation": "CPython",
                "version": "3.11.9",
                "executable_sha256": scanner_python_hash,
                "prefix_is_virtual_environment": True,
                "isolated_flag": 1,
                "ignore_environment_flag": 1,
                "no_user_site_flag": 1,
                "dont_write_bytecode_flag": 1,
                "safe_path_flag": 1,
                "no_site_flag": 1,
                "user_site_enabled": False,
                "include_system_site_packages": False,
                "manual_site_bootstrap": True,
            },
            "platform": {"system": "Windows"},
            "install_scheme": {
                "purelib": "<prefix>/Lib/site-packages",
                "platlib": "<prefix>/Lib/site-packages",
                "scripts": "<prefix>/Scripts",
                "data": "<prefix>/.",
                "include": "<prefix>/Include",
            },
            "k_guard": {
                "package_tree_sha256": wheel_contract["package_contract"][
                    "package_tree_sha256"
                ]
            },
            "installed_distributions": [
                {
                    "name": "k-guard-mcp",
                    "version": "0.1.0",
                    "installed_tree_sha256": "6" * 64,
                    "installed_files": [
                        {
                            "path": f"Lib/site-packages/{name}",
                            "sha256": hashlib.sha256(payload).hexdigest(),
                            "byte_count": len(payload),
                        }
                        for name, payload in sorted(members.items())
                    ]
                    + [
                        {
                            "path": "Lib/site-packages/k_guard_mcp-0.1.0.dist-info/INSTALLER",
                            "sha256": hashlib.sha256(b"pip\n").hexdigest(),
                            "byte_count": 4,
                        },
                        {
                            "path": "Lib/site-packages/k_guard_mcp-0.1.0.dist-info/REQUESTED",
                            "sha256": hashlib.sha256(b"").hexdigest(),
                            "byte_count": 0,
                        },
                        {
                            "path": "Lib/site-packages/k_guard_mcp-0.1.0.dist-info/direct_url.json",
                            "sha256": "7" * 64,
                            "byte_count": 2,
                        },
                    ],
                }
            ],
            "installed_distribution_set_sha256": distribution_set_hash,
            "duplicate_distribution_names": [],
            "shared_distribution_files": [],
            "unowned_site_package_files": [],
            "scanner_scaffold": {
                "schema": protocol.SCANNER_SCAFFOLD_SCHEMA,
                "tree_sha256": scanner_scaffold_hash,
                "file_count": 0,
                "files": [],
                "raw_returned": False,
            },
            "scaffold_distribution_overlaps": [],
            "unowned_prefix_files": [],
            "missing_prefix_files": [],
            "modified_scaffold_files": [],
            "outside_import_search_paths": [],
            "base_site_package_import_paths": [],
            "prefix_tree": {
                "sha256": "1" * 64,
                "files": [
                    {
                        "path": "Lib/site-packages/k_guard_mcp/cli.py",
                        "sha256": "a" * 64,
                        "byte_count": 1,
                    }
                ],
            },
            "base_runtime_tree": {
                "sha256": "2" * 64,
                "files": [
                    {"path": "python311.dll", "sha256": "b" * 64, "byte_count": 1}
                ],
            },
            "attestation_errors": [],
            "attestation_passed": True,
            "raw_returned": False,
        },
    )
    install_report_path = tmp_path / "pip-install-report.json"
    wheel_hash = protocol.sha256_file(wheel_path)
    artifact_rows = [{"name": "k-guard-mcp", "version": "0.1.0", "sha256": wheel_hash}]
    artifact_set_hash = hashlib.sha256(
        json.dumps(artifact_rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    _write(
        install_report_path,
        {
            "version": "1",
            "pip_version": "test",
            "install": [
                {
                    "download_info": {
                        "url": wheel_path.as_uri(),
                        "archive_info": {"hashes": {"sha256": wheel_hash}},
                    },
                    "is_direct": True,
                    "is_yanked": False,
                    "requested": True,
                    "metadata": {"name": "k-guard-mcp", "version": "0.1.0"},
                }
            ],
            "k_guard_install_artifact_set_sha256": artifact_set_hash,
        },
    )
    wheelhouse_manifest_path = tmp_path / "wheelhouse-manifest.json"
    wheelhouse_payload = protocol.build_wheelhouse_manifest(tmp_path, tmp_path)
    _write(wheelhouse_manifest_path, wheelhouse_payload)
    source_path = tmp_path / "source-metadata.json"
    source_rows = sorted(
        [
            {
                **{
                    field: app.get(field)
                    for field in (
                        "repository",
                        "repository_id",
                        "github_node_id",
                        "default_branch",
                        "is_fork",
                        "fork_parent_repository_id",
                        "archived",
                        "commit",
                        "commit_tree",
                        "stars_at_registration",
                        "language",
                        "license_spdx",
                    )
                },
                "git_tree_entry_count": 1,
                "git_tree_mode_counts": {"100644": 1},
                "git_tree_recursive_truncated": False,
                "git_tree_structure_sha256": hashlib.sha256(
                    str(app["repository_id"]).encode()
                ).hexdigest(),
            }
            for app in apps
        ],
        key=lambda row: row["repository_id"],
    )
    repository_ids = [row["repository_id"] for row in source_rows]
    _write(
        source_path,
        {
            "schema": protocol.STRUCTURAL_SOURCE_METADATA_SCHEMA,
            "metadata_source": "github_api_v3",
            "retrieved_at": "2026-07-15T00:00:00Z",
            "selection_boundary": {
                "k_guard_imported": False,
                "scanner_output_observed": False,
                "github_metadata_cryptographically_attested": False,
                "git_tree_entry_modes_verified": True,
            },
            "git_tree_entry_policy": protocol.SOURCE_METADATA_GIT_TREE_ENTRY_POLICY,
            "all_source_trees_structurally_eligible": True,
            "repository_count": len(source_rows),
            "repository_set_sha256": protocol._repository_set_sha256(repository_ids),
            "repositories": source_rows,
            "raw_returned": False,
        },
    )
    manifest_path = tmp_path / "holdout-protocol.json"
    manifest = {
        "schema": protocol.PROTOCOL_SCHEMA,
        "implementation_revision": "d" * 40,
        "package_tree_hash_schema": protocol.TREE_HASH_SCHEMA,
        "analyzer_package_tree_sha256": wheel_contract["package_contract"][
            "package_tree_sha256"
        ],
        "release_blocking_policy": runner.RELEASE_BLOCKING_POLICY,
        "automatic_release_rule_ids": sorted(protocol.AUTOMATIC_RELEASE_RULES),
        "execution_package_source": "isolated_venv_installed_from_bound_wheel",
        "protocol_files": [
            {"path": value, "sha256": hashlib.sha256(value.encode()).hexdigest()}
            for value in protocol.REQUIRED_PROTOCOL_FILES
        ],
        "wheel": {
            "artifact_path": wheel_path.name,
            "sha256": wheel_hash,
            "qualification_contract": wheel_contract,
        },
        "runtime_environment": {
            "artifact_path": runtime_path.name,
            "sha256": protocol.sha256_file(runtime_path),
            "schema": protocol.RUNTIME_ENVIRONMENT_SCHEMA,
            "scanner_python_sha256": scanner_python_hash,
            "installed_distribution_set_sha256": distribution_set_hash,
            "prefix_tree_sha256": "1" * 64,
            "base_runtime_tree_sha256": "2" * 64,
            "scanner_scaffold_tree_sha256": scanner_scaffold_hash,
            "runtime_mutation_guard": "windows_read_directory_changes_overlapped_v2",
            "runtime_notification_classifier": protocol.RUNTIME_NOTIFICATION_CLASSIFIER,
            "native_runtime_lock_guard": protocol.NATIVE_RUNTIME_LOCK_GUARD,
            "native_runtime_prewarm_guard": protocol.NATIVE_RUNTIME_PREWARM_GUARD,
            "runtime_object_attestation_guard": (
                protocol.RUNTIME_OBJECT_ATTESTATION_GUARD
            ),
            "pip_install_report": {
                "artifact_path": install_report_path.name,
                "sha256": protocol.sha256_file(install_report_path),
                "artifact_set_sha256": artifact_set_hash,
            },
            "wheelhouse": {
                "manifest_path": wheelhouse_manifest_path.name,
                "manifest_sha256": protocol.sha256_file(wheelhouse_manifest_path),
                "artifact_set_sha256": wheelhouse_payload["artifact_set_sha256"],
            },
            "bootstrap_distributions": [],
        },
        "source_materialization": {
            "schema": "k_guard_git_source_materialization.v2",
            "cleanliness_method": "git_blob_sha256_file_set_plus_index_tree_v2",
            "git_porcelain_clean_required": False,
            "direct_git_blob_sha256_required": True,
            "runtime_receipt_schema": protocol.RUNTIME_RECEIPT_SCHEMA,
            "mutation_guard": "windows_read_directory_changes_overlapped_v2",
            "required_scan_event_count": 0,
        },
        "independent_git_verification": {
            "schema": "k_guard_independent_git_verification.v3",
            "artifact_path": "independent-git-verification.json",
            "mirror_layout": "one_unlinked_full_bare_sha1_input_mirror_per_app",
            "verification_method": "verifier_owned_no_local_snapshot_and_raw_object_reconstruction",
            "byte_binding": "git_sha1_graph_plus_independent_sha256_file_bytes",
            "storage_binding": "pre_post_sha256_manifest_plus_file_identity",
            "path_policy": "windows_ntfs_materialization_fail_closed_v1",
            "execution_provenance": "unsigned_local_replay_receipt",
            "external_signed_provenance_required_for_contest_go": True,
            "source_contents_embedded": False,
        },
        "source_metadata": {
            "artifact_path": source_path.name,
            "sha256": protocol.sha256_file(source_path),
            "schema": protocol.STRUCTURAL_SOURCE_METADATA_SCHEMA,
        },
        "raw_returned": False,
    }
    _write(manifest_path, manifest)
    return manifest_path.name, manifest


def _fixture_git_object_sha1(kind: str, raw: bytes) -> str:
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"{kind} {len(raw)}\0".encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _fixture_git_source(index: int) -> dict[str, object]:
    content = f"name: fixture-{index}\nuses: owner/action@main\n".encode("utf-8")
    blob = _fixture_git_object_sha1("blob", content)

    def tree(mode: str, name: bytes, oid: str) -> str:
        raw = mode.encode("ascii") + b" " + name + b"\0" + bytes.fromhex(oid)
        return _fixture_git_object_sha1("tree", raw)

    workflows = tree("100644", b"ci.yml", blob)
    github = tree("40000", b"workflows", workflows)
    root_tree = tree("40000", b".github", github)
    commit_raw = (
        f"tree {root_tree}\n"
        "author Fixture <fixture@example.com> 0 +0000\n"
        "committer Fixture <fixture@example.com> 0 +0000\n"
        f"\nfixture {index}\n"
    ).encode("utf-8")
    return {
        "path": ".github/workflows/ci.yml",
        "content": content,
        "blob": blob,
        "sha256": hashlib.sha256(content).hexdigest(),
        "byte_count": len(content),
        "tree": root_tree,
        "commit": _fixture_git_object_sha1("commit", commit_raw),
        "commit_raw": commit_raw,
    }


def _selection_artifacts(tmp_path: Path, apps: list[dict]) -> dict[str, str]:
    rule_ids = (
        "AUTH_JWT_DECODE_WITHOUT_VERIFY",
        "CONFIG_CSP_UNSAFE_EVAL",
        "MCP_STATIC_CREDENTIAL_IN_CONFIG",
        "WEB_UNTRUSTED_INPUT_TO_COMMAND",
    )
    discovery_rows = []
    rule_counts: dict[str, int] = {rule_id: 0 for rule_id in rule_ids}
    for index, app in enumerate(apps):
        rule_id = rule_ids[index % len(rule_ids)]
        rule_counts[rule_id] += 5
        discovery_rows.append(
            {
                "bytes_read": 100 + index,
                "estimated_candidate_count": 5,
                "estimated_rule_counts": {rule_id: 5},
                "files_read": 1,
                "repository_id": app["repository_id"],
                "stars": index,
                "stratum": app["stratum"],
            }
        )
    discovery_rows.sort(key=lambda row: row["repository_id"])
    discovery_path = tmp_path / "structural-preflight.json"
    discovery = {
        "schema": integrity.DISCOVERY_POOL_SCHEMA,
        "population_role": integrity.DISCOVERY_POOL_ROLE,
        "qualification_authority": False,
        "qualification_thresholds_apply": False,
        "qualification_population_artifact": "selected-corpus.json",
        "apps": discovery_rows,
        "candidate_repository_count": len(discovery_rows),
        "estimated_apps_with_candidates": len(discovery_rows),
        "estimated_candidate_count": sum(rule_counts.values()),
        "estimated_distinct_rule_count": len(rule_counts),
        "estimated_maximum_single_rule_share": 0.25,
        "estimated_rule_counts": rule_counts,
        "fingerprints": [],
        "independence": {
            "generic_mechanisms_only": True,
            "k_guard_executed": False,
            "k_guard_imported": False,
            "not_a_k_guard_result": True,
            "scanner_output_observed": False,
        },
        "method": "fixture structural preflight",
        "raw_returned": False,
    }
    _write(discovery_path, discovery)
    discovery_hash = integrity.sha256_file(discovery_path)

    repository_ids = [app["repository_id"] for app in apps]
    qualification_path = tmp_path / "selected-corpus.json"
    qualification = {
        "schema": integrity.QUALIFICATION_POPULATION_SCHEMA,
        "population_role": integrity.QUALIFICATION_POPULATION_ROLE,
        "qualification_authority": True,
        "qualification_thresholds_apply": True,
        "discovery_population_artifact": discovery_path.name,
        "apps": [
            {
                key: app.get(key)
                for key in (
                    "app",
                    "local_dir",
                    "stratum",
                    "repository",
                    "repository_id",
                    "commit",
                )
            }
            for app in apps
        ],
        "bindings": {
            "structural_preflight_sha256": discovery_hash,
        },
        "independence": {
            "k_guard_executed": False,
            "k_guard_imported": False,
            "not_a_k_guard_result": True,
            "scanner_output_observed": False,
            "selection_locked_before_scanner_execution": True,
        },
        "preflight_only_expected_population": {
            "estimated_apps_with_candidates": len(apps),
            "estimated_candidate_count": sum(rule_counts.values()),
            "estimated_distinct_rule_count": len(rule_counts),
            "estimated_maximum_single_rule_share": 0.25,
            "estimated_rule_counts": rule_counts,
            "estimated_strata_with_candidates": ["long_tail", "mid", "top"],
            "not_a_k_guard_result": True,
        },
        "repository_count": len(repository_ids),
        "repository_set_sha256": integrity.repository_set_sha256(repository_ids),
        "selection": {
            "not_random_sample": True,
            "risk_enriched_challenge_set": True,
        },
        "raw_returned": False,
    }
    _write(qualification_path, qualification)
    return {
        "discovery_name": discovery_path.name,
        "discovery_sha256": discovery_hash,
        "qualification_name": qualification_path.name,
        "qualification_sha256": integrity.sha256_file(qualification_path),
    }


def _v4_preregistration(tmp_path: Path) -> tuple[Path, dict]:
    snapshot_path, snapshot = _snapshot(tmp_path)
    strata = ["top"] * 7 + ["mid"] * 6 + ["long_tail"] * 7
    apps = []
    for index, stratum in enumerate(strata):
        source = _fixture_git_source(index)
        apps.append({
            "app": f"app-{index}",
            "local_dir": f"app-{index}",
            "stratum": stratum,
            "repository": f"https://github.com/fresh-owner/app-{index}.git",
            "repository_id": f"fresh-owner/app-{index}",
            "commit": source["commit"],
            "commit_tree": source["tree"],
            "github_node_id": f"R_test_{index:04d}",
            "default_branch": "main",
            "is_fork": False,
            "fork_parent_repository_id": None,
            "archived": False,
            "stars_at_registration": index,
            "language": "Python",
            "license_spdx": "MIT",
        })
    repository_ids = [row["repository_id"] for row in apps]
    manifest_name, manifest = _protocol_artifacts(tmp_path, apps)
    selection_artifacts = _selection_artifacts(tmp_path, apps)
    payload = {
        "schema": runner.PREREGISTRATION_SCHEMA,
        "campaign_id": "fresh-v4",
        "status": "locked_before_scanner_execution",
        "qualification_contract": "release_blocker_actionability_v4",
        "analyzer_package_tree_sha256": manifest["analyzer_package_tree_sha256"],
        "holdout_protocol": {
            "manifest_path": manifest_name,
            "manifest_sha256": protocol.sha256_file(tmp_path / manifest_name),
        },
        "locked_execution": {
            "candidate_selection_mode": "all_eligible_release_blockers",
            "release_blocking_policy": runner.RELEASE_BLOCKING_POLICY,
            "exact_fresh_process_runs_per_app": 2,
            "retry_count": 0,
            "per_scan_timeout_seconds": 900,
        },
        "locked_thresholds": {
            "minimum_app_count": 20,
            "minimum_stratum_count": 6,
            "minimum_blocker_candidates": 100,
            "minimum_blocker_actionability": 0.9,
            "minimum_blocker_actionability_wilson_95_lower": 0.8,
            "required_exact_repeat_rate": 1.0,
            "required_candidate_sample_coverage": 1.0,
            "required_candidate_label_coverage": 1.0,
            "maximum_unlocatable_release_blockers": 0,
            "minimum_distinct_blocker_rule_ids": 4,
            "minimum_apps_with_blocker_candidates": 20,
            "minimum_strata_with_blocker_candidates": 3,
            "maximum_single_rule_candidate_share": 0.5,
            "minimum_fully_actionable_app_rate": 0.9,
            "minimum_fully_actionable_app_wilson_95_lower": 0.8,
            "minimum_reviewer_unanimous_rate": 0.9,
            "maximum_inconclusive_rate": 0.0,
            "maximum_individual_inconclusive_rate": 0.0,
        },
        "locked_review": {
            "required_reviewer_count": 3,
            "required_vendors": ["anthropic", "openai", "xai"],
            "independent_sessions": True,
            "individual_inconclusive_allowed": False,
            "review_method": "external_ai_source_context_review",
        },
        "holdout_integrity": {
            "source_selection_locked_before_scanner_execution": True,
            "scanner_output_seen_during_selection": False,
            "k_guard_imported_by_preflight": False,
            "development_or_prior_campaign_overlap_allowed": False,
            "repository_overlap_count": 0,
            "exclusion_snapshot_path": snapshot_path.name,
            "exclusion_snapshot_sha256": integrity.sha256_file(snapshot_path),
            "prior_evidence_source_revision": snapshot["source_revision"],
            "repository_count": len(repository_ids),
            "repository_set_sha256": integrity.repository_set_sha256(repository_ids),
        },
        "selection": {
            "discovery_population_artifact": selection_artifacts["discovery_name"],
            "discovery_population_sha256": selection_artifacts["discovery_sha256"],
            "discovery_pool_has_no_qualification_authority": True,
            "estimated_population_artifact": selection_artifacts["qualification_name"],
            "qualification_population_artifact": selection_artifacts["qualification_name"],
            "qualification_population_sha256": selection_artifacts["qualification_sha256"],
            "qualification_thresholds_apply_only_to": selection_artifacts[
                "qualification_name"
            ],
        },
        "apps": apps,
        "claim_boundary": {
            "public_repositories_only": True,
            "owned_or_partner_scope": False,
            "commercial_release_authority": False,
            "field_prevalence_estimate": False,
            "risk_enriched_challenge_set": True,
            "static_source_actionability_only": True,
            "full_app_recall_measured": False,
            "runtime_exploitability_measured": False,
            "pristine_blind_holdout": False,
            "cross_vendor_ai_review": True,
            "not_human_review": True,
            "independent_git_execution_attested": False,
            "external_signed_git_provenance_required_for_contest_go": True,
        },
        "raw_returned": False,
    }
    path = tmp_path / "preregistration.json"
    _write(path, payload)
    return path, payload


def _mark_protocol_recovery_replay(
    path: Path,
    payload: dict,
) -> dict:
    manifest = {
        "schema": integrity.PRIOR_EXECUTION_MANIFEST_SCHEMA,
        "source_campaign_id": payload["campaign_id"],
        "target_campaign_id": f"{payload['campaign_id']}-recovery",
        "source_population_reused": True,
        "source_repository_set_sha256": payload["holdout_integrity"][
            "repository_set_sha256"
        ],
        "app_count": len(payload["apps"]),
        "prior_scanner_execution": True,
        "prior_scanner_output_seen": True,
        "prior_candidate_content_exposure_assumed": True,
        "candidate_labels_created": False,
        "effectiveness_status_created": False,
        "analyzer_change_informed_by_prior_execution": True,
        "detector_rules_changed_after_observation": False,
        "release_policy_changed_after_observation": False,
        "attempt_count": 2,
        "attempts": [
            {
                "attempt_id": "r1",
                "output_tree_sha256": "1" * 64,
                "artifact_inventory_sha256": "2" * 64,
                "report_count": 1,
                "source_receipt_count": len(payload["apps"]),
                "runtime_receipt_count": 1,
                "candidate_labels_present": False,
                "effectiveness_status_present": False,
                "raw_returned": False,
            },
            {
                "attempt_id": "r2",
                "output_tree_sha256": "3" * 64,
                "artifact_inventory_sha256": "4" * 64,
                "report_count": len(payload["apps"]) * 2,
                "source_receipt_count": len(payload["apps"]),
                "runtime_receipt_count": len(payload["apps"]) * 2,
                "candidate_labels_present": False,
                "effectiveness_status_present": False,
                "raw_returned": False,
            },
        ],
        "aggregate": {
            "report_count": 1 + len(payload["apps"]) * 2,
            "source_receipt_count": len(payload["apps"]) * 2,
            "runtime_receipt_count": 1 + len(payload["apps"]) * 2,
            "scanner_output_observed": True,
            "candidate_labels_present": False,
            "effectiveness_status_present": False,
        },
        "raw_returned": False,
    }
    manifest_path = path.parent / "prior-execution-manifest.json"
    _write(manifest_path, manifest)
    payload["campaign_id"] = manifest["target_campaign_id"]
    payload["status"] = integrity.PROTOCOL_RECOVERY_REPLAY_STATUS
    payload["replay_provenance"] = {
        "schema": integrity.PROTOCOL_RECOVERY_REPLAY_SCHEMA,
        "mode": "protocol_recovery_replay",
        "qualifying_holdout": False,
        "release_claim_allowed": False,
        "evidence_use": "development_baseline_only",
        "source_population_reused": True,
        "prior_scanner_execution": True,
        "prior_scanner_output_seen": True,
        "prior_candidate_content_exposure_assumed": True,
        "candidate_labels_created": False,
        "effectiveness_status_created": False,
        "analyzer_change_informed_by_prior_execution": True,
        "detector_rules_changed_after_observation": False,
        "release_policy_changed_after_observation": False,
        "final_unseen_holdout_required_for_go": True,
        "superseded_campaign_id": manifest["source_campaign_id"],
        "prior_execution_manifest_path": manifest_path.name,
        "prior_execution_manifest_sha256": integrity.sha256_file(manifest_path),
        "raw_returned": False,
    }
    _write(path, payload)
    return manifest


def _v4_evidence(
    tmp_path: Path,
    *,
    individual_inconclusive: bool = False,
    protocol_recovery_replay: bool = False,
    perfect_metrics: bool = False,
) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    preregistration_path, preregistration = _v4_preregistration(tmp_path)
    if protocol_recovery_replay:
        _mark_protocol_recovery_replay(
            preregistration_path,
            preregistration,
        )
    bound_protocol = protocol.validate_bound_protocol(preregistration, preregistration_path)
    qualification_boundary = (
        integrity.protocol_recovery_qualification_boundary(preregistration)
    )
    evidence = tmp_path / "campaign-evidence"
    reports = evidence / "reports"
    reports.mkdir(parents=True)
    runtime_receipts = evidence / "runtime-receipts"
    runtime_receipts.mkdir()
    source_receipts = evidence / "source-receipts"
    source_receipts.mkdir()
    source_revision = "c" * 40
    app_rows = []
    candidates = []
    source_contracts: dict[str, dict] = {}
    for index, app in enumerate(preregistration["apps"]):
        name = app["app"]
        source = _fixture_git_source(index)
        source_rows = [
            {
                "path": source["path"],
                "mode": "100644",
                "git_blob_sha1": source["blob"],
                "sha256": source["sha256"],
                "byte_count": source["byte_count"],
            }
        ]
        source_tree_sha256 = scorer._source_tree_sha256(source_rows)
        source_receipt = {
            "schema": "k_guard_git_source_materialization.v2",
            "passed": True,
            "repository_id": app["repository_id"],
            "origin_repository_id": app["repository_id"],
            "origin_repository_match": True,
            "commit": app["commit"],
            "commit_match": True,
            "commit_object_hash_match": True,
            "commit_tree": app["commit_tree"],
            "commit_tree_match": True,
            "tree_object_reconstruction_match": True,
            "git_object_format": "sha1",
            "git_repository_layout": "ordinary_non_shallow_standalone_clone",
            "source_worktree_clean": True,
            "source_worktree_clean_method": (
                "git_blob_sha256_file_set_plus_index_tree_v2"
            ),
            "git_porcelain_clean": index % 2 == 0,
            "index_tree_match": True,
            "physical_bytes_match_git_blobs": True,
            "git_fsck_strict_passed": True,
            "git_fsck_output_sha256": hashlib.sha256(f"source-fsck-{index}".encode()).hexdigest(),
            "scanner_visible_tree_contract": (
                "regular-file paths and raw Git blob bytes; "
                "Git modes remain commit-bound metadata"
            ),
            "source_tree_schema": "k_guard_materialized_source_tree.v1",
            "source_tree_sha256": source_tree_sha256,
            "file_count": 1,
            "total_bytes": source["byte_count"],
            "files": source_rows,
            "raw_returned": False,
        }
        source_receipt_path = source_receipts / f"{name}.json"
        _write(source_receipt_path, source_receipt)
        source_receipt_hash = hashlib.sha256(source_receipt_path.read_bytes()).hexdigest()
        source_contracts[name] = {
            "source": source,
            "rows": source_rows,
            "tree_sha256": source_tree_sha256,
            "receipt_path": source_receipt_path.relative_to(evidence).as_posix(),
            "receipt_sha256": source_receipt_hash,
            "receipt": source_receipt,
        }
        rule_ids = (
            sorted(protocol.AUTOMATIC_RELEASE_RULES)
            if perfect_metrics
            else ["CONFIG_CSP_UNSAFE_EVAL"]
        )
        findings = [
            {
                "rule_id": rule_id,
                "severity": "high",
                "confidence": "high",
                "file": f"<workspace>/src/finding-{position}.py",
                "line_start": index * len(rule_ids) + position + 1,
                "artifact_scope": "configuration",
                "evidence": (
                    f"detector_subtype=fixture-{position} "
                    f"line_hash={index * len(rule_ids) + position + 1:016x} "
                    "raw_returned=false"
                ),
                "source": "config",
            }
            for position, rule_id in enumerate(rule_ids)
        ]
        report = {
            "findings": findings,
            "metadata": {"review_coverage": {"inventory": {"supported_file_count": 1}}},
        }
        runs = []
        for run_number in (1, 2):
            report_path = reports / f"{name}-run{run_number}.json"
            report_hash = runner._write_report(report_path, report)
            receipt_path = runtime_receipts / f"{name}-run{run_number}.json"
            _write(
                receipt_path,
                {
                    "schema": protocol.RUNTIME_RECEIPT_SCHEMA,
                    "expected_runtime_sha256": bound_protocol["manifest"]["runtime_environment"][
                        "sha256"
                    ],
                    "scanner_python_sha256": bound_protocol["manifest"]["runtime_environment"][
                        "scanner_python_sha256"
                    ],
                    "launcher_sha256": bound_protocol["protocol_files"][
                        "scripts/holdout_scan_launcher.py"
                    ],
                    "probe_sha256": bound_protocol["protocol_files"][
                        "scripts/holdout_runtime_probe.py"
                    ],
                    "source_probe_sha256": bound_protocol["protocol_files"][
                        "scripts/holdout_source_materialization.py"
                    ],
                    "mutation_guard": "windows_read_directory_changes_overlapped_v2",
                    "runtime_notification_classifier": (
                        protocol.RUNTIME_NOTIFICATION_CLASSIFIER
                    ),
                    "runtime_notification_classifier_errors": [],
                    "native_runtime_lock_guard": protocol.NATIVE_RUNTIME_LOCK_GUARD,
                    "native_runtime_prewarm_guard": (
                        protocol.NATIVE_RUNTIME_PREWARM_GUARD
                    ),
                    "runtime_object_attestation_guard": (
                        protocol.RUNTIME_OBJECT_ATTESTATION_GUARD
                    ),
                    "pre_runtime_sha256": bound_protocol["manifest"]["runtime_environment"][
                        "sha256"
                    ],
                    "post_runtime_sha256": bound_protocol["manifest"]["runtime_environment"][
                        "sha256"
                    ],
                    "scanner_exit_code": 0,
                    "loaded_module_set_sha256": "5" * 64,
                    "loaded_module_file_count": 1,
                    "outside_loaded_modules": [],
                    "notification_event_count": 0,
                    "accepted_native_load_metadata_event_count": 0,
                    "accepted_stable_directory_metadata_event_count": 0,
                    "unclassified_notification_count": 0,
                    "mutation_event_count": 0,
                    "mutation_monitor_errors": [],
                    "mutation_monitor_liveness_passed": True,
                    "mutation_guard_canary": {
                        "before_scan": True,
                        "after_scan": True,
                        "cleanup_passed": True,
                    },
                    "mutation_monitors": [
                        {
                            "root": root,
                            "notification_event_count": 0,
                            "notification_events": [],
                            "accepted_native_load_metadata_event_count": 0,
                            "accepted_native_load_metadata_events": [],
                            "accepted_stable_directory_metadata_event_count": 0,
                            "accepted_stable_directory_metadata_events": [],
                            "unclassified_notification_count": 0,
                            "event_count": 0,
                            "events": [],
                            "error": None,
                            "liveness": {
                                "registration_count": 1,
                                "heartbeat_count": 1,
                                "drain_completed": True,
                                "stop_acknowledged": True,
                                "thread_terminated": True,
                                "passed": True,
                            },
                        }
                        for root in ("scanner_prefix", "base_runtime", "protocol_repository")
                    ],
                    "mutation_canary_monitor": {
                        "root": "monitor_canary",
                        "event_count": 4,
                        "events": [
                            {"action": 1, "relative_path": f"canary-{index}"}
                            for index in range(4)
                        ],
                        "error": None,
                        "liveness": {
                            "registration_count": 2,
                            "heartbeat_count": 2,
                            "drain_completed": True,
                            "stop_acknowledged": True,
                            "thread_terminated": True,
                            "passed": True,
                        },
                    },
                    "expected_source_tree_sha256": source_tree_sha256,
                    "pre_source_tree_sha256": source_tree_sha256,
                    "post_source_tree_sha256": source_tree_sha256,
                    "expected_source_file_count": 1,
                    "pre_source_file_count": 1,
                    "post_source_file_count": 1,
                    "pre_source_total_bytes": source["byte_count"],
                    "post_source_total_bytes": source["byte_count"],
                    "source_mutation_guard_canary": True,
                    "source_mutation_observed": False,
                    "source_mutation_monitor": {
                        "root": "workspace_source",
                        "guard": "windows_read_directory_changes_overlapped_v2",
                        "canary_boundary": (
                            "temporary excluded root file created and deleted before pre-source capture"
                        ),
                        "measurement_boundary": (
                            "after canary drain through post-source capture and watcher termination"
                        ),
                        "canary_event_count": 2,
                        "scan_event_count": 0,
                        "events": [
                            {
                                "action": action,
                                "relative_path": ".k-guard-source-monitor.canary-fixture",
                            }
                            for action in (1, 2)
                        ],
                        "error": None,
                        "liveness": {
                            "registration_count": 2,
                            "heartbeat_count": 1,
                            "drain_completed": True,
                            "stop_acknowledged": True,
                            "thread_terminated": True,
                            "passed": True,
                        },
                        "passed": True,
                    },
                    **_runtime_execution_receipts(
                        bound_protocol["runtime_environment"]
                    ),
                    "runtime_mutation_observed": False,
                    "output_sha256": report_hash,
                    "passed": True,
                    "raw_returned": False,
                },
            )
            artifact_path, artifact_hash = runner._compress_report_artifact(report_path)
            runs.append(
                {
                    "run": run_number,
                    "exit_code": 0,
                    "duration_seconds": 0.01,
                    "report_sha256": report_hash,
                    "report_artifact_path": artifact_path.relative_to(evidence).as_posix(),
                    "report_artifact_sha256": artifact_hash,
                    "report_artifact_encoding": "canonical-json+gzip-mtime-zero",
                    "runtime_receipt_path": receipt_path.relative_to(evidence).as_posix(),
                    "runtime_receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                    "runtime_mutation_guard": "windows_read_directory_changes_overlapped_v2",
                    "runtime_notification_classifier": (
                        protocol.RUNTIME_NOTIFICATION_CLASSIFIER
                    ),
                    "native_runtime_lock_guard": protocol.NATIVE_RUNTIME_LOCK_GUARD,
                    "native_runtime_prewarm_guard": (
                        protocol.NATIVE_RUNTIME_PREWARM_GUARD
                    ),
                    "runtime_object_attestation_guard": (
                        protocol.RUNTIME_OBJECT_ATTESTATION_GUARD
                    ),
                    "source_tree_sha256": source_tree_sha256,
                    "source_mutation_observed": False,
                    "raw_report_sha256": report_hash,
                }
            )
        app_candidates = runner._candidate_rows(name, runs[0]["report_sha256"], report, None)
        candidates.extend(app_candidates)
        lane_counts = runner.release_hold_counts(findings, "high")
        lane_counts["supporting_review_high_critical_count"] = 0
        app_rows.append(
            {
                "app": name,
                "stratum": app["stratum"],
                "language": app.get("language"),
                "stars_at_registration": app.get("stars_at_registration"),
                "repository": app["repository"],
                "repository_id": app["repository_id"],
                "origin_repository_id": app["repository_id"],
                "origin_repository_match": True,
                "github_node_id": app["github_node_id"],
                "default_branch": app["default_branch"],
                "is_fork": app["is_fork"],
                "fork_parent_repository_id": app["fork_parent_repository_id"],
                "archived": app["archived"],
                "commit": app["commit"],
                "commit_tree": app["commit_tree"],
                "commit_tree_match": True,
                "license_spdx": app["license_spdx"],
                "source_worktree_clean": True,
                "source_materialization_receipt_path": source_contracts[name]["receipt_path"],
                "source_materialization_receipt_sha256": source_receipt_hash,
                "source_materialization_schema": "k_guard_git_source_materialization.v2",
                "source_tree_sha256": source_tree_sha256,
                "source_total_bytes": source["byte_count"],
                "tracked_files": 1,
                "supported_files": 1,
                "finding_counts": runner._finding_counts(report),
                "available_release_blocking_findings": len(findings),
                "eligible_release_blocking_findings": len(findings),
                "unlocatable_release_blocking_findings": 0,
                "sampled_release_blocking_candidates": len(findings),
                "release_lane_counts": lane_counts,
                "runs": runs,
                "exact_repeat": True,
            }
        )

    snapshot = evidence / "preregistration.snapshot.json"
    snapshot.write_bytes(preregistration_path.read_bytes())
    protocol_execution = {
        "holdout_protocol_schema": bound_protocol["manifest"]["schema"],
        "implementation_revision": bound_protocol["manifest"]["implementation_revision"],
        "execution_revision": source_revision,
        "protocol_manifest_sha256": bound_protocol["manifest_sha256"],
        "analyzer_package_tree_sha256": preregistration["analyzer_package_tree_sha256"],
        "wheel_sha256": bound_protocol["manifest"]["wheel"]["sha256"],
        "runtime_environment_sha256": bound_protocol["manifest"]["runtime_environment"]["sha256"],
        "scanner_python_sha256": bound_protocol["manifest"]["runtime_environment"][
            "scanner_python_sha256"
        ],
        "runtime_launcher_sha256": bound_protocol["protocol_files"][
            "scripts/holdout_scan_launcher.py"
        ],
        "runtime_probe_sha256": bound_protocol["protocol_files"][
            "scripts/holdout_runtime_probe.py"
        ],
        "source_materialization_probe_sha256": bound_protocol["protocol_files"][
            "scripts/holdout_source_materialization.py"
        ],
        "independent_git_verifier_sha256": bound_protocol["protocol_files"][
            "scripts/verify_holdout_git_sources.py"
        ],
        "installed_distribution_set_sha256": bound_protocol["manifest"][
            "runtime_environment"
        ]["installed_distribution_set_sha256"],
        "prefix_tree_sha256": bound_protocol["manifest"]["runtime_environment"][
            "prefix_tree_sha256"
        ],
        "base_runtime_tree_sha256": bound_protocol["manifest"]["runtime_environment"][
            "base_runtime_tree_sha256"
        ],
        "scanner_scaffold_tree_sha256": bound_protocol["manifest"]["runtime_environment"][
            "scanner_scaffold_tree_sha256"
        ],
        "runtime_mutation_guard": "windows_read_directory_changes_overlapped_v2",
        "runtime_notification_classifier": protocol.RUNTIME_NOTIFICATION_CLASSIFIER,
        "native_runtime_lock_guard": protocol.NATIVE_RUNTIME_LOCK_GUARD,
        "native_runtime_prewarm_guard": protocol.NATIVE_RUNTIME_PREWARM_GUARD,
        "runtime_object_attestation_guard": (
            protocol.RUNTIME_OBJECT_ATTESTATION_GUARD
        ),
        "pip_install_report_sha256": bound_protocol["manifest"]["runtime_environment"][
            "pip_install_report"
        ]["sha256"],
        "pip_install_artifact_set_sha256": bound_protocol["manifest"][
            "runtime_environment"
        ]["pip_install_report"]["artifact_set_sha256"],
        "wheelhouse_manifest_sha256": bound_protocol["manifest"]["runtime_environment"][
            "wheelhouse"
        ]["manifest_sha256"],
        "wheelhouse_artifact_set_sha256": bound_protocol["manifest"][
            "runtime_environment"
        ]["wheelhouse"]["artifact_set_sha256"],
        "source_metadata_sha256": bound_protocol["manifest"]["source_metadata"]["sha256"],
        "release_blocking_policy": runner.RELEASE_BLOCKING_POLICY,
        "automatic_release_rule_ids": sorted(protocol.AUTOMATIC_RELEASE_RULES),
        "tracked_artifacts_committed_at_execution_head": [
            {"path": f"artifact-{index}", "sha256": digest}
            for index, digest in enumerate(
                (
                    hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                    bound_protocol["manifest_sha256"],
                    bound_protocol["manifest"]["wheel"]["sha256"],
                    bound_protocol["manifest"]["runtime_environment"]["sha256"],
                    bound_protocol["manifest"]["runtime_environment"]["pip_install_report"][
                        "sha256"
                    ],
                    bound_protocol["manifest"]["runtime_environment"]["wheelhouse"][
                        "manifest_sha256"
                    ],
                    bound_protocol["manifest"]["source_metadata"]["sha256"],
                    preregistration["holdout_integrity"]["exclusion_snapshot_sha256"],
                    preregistration["selection"]["discovery_population_sha256"],
                    preregistration["selection"]["qualification_population_sha256"],
                )
            )
        ],
        "raw_returned": False,
    }
    if qualification_boundary:
        protocol_execution["tracked_artifacts_committed_at_execution_head"].append(
            {
                "path": preregistration["replay_provenance"][
                    "prior_execution_manifest_path"
                ],
                "sha256": preregistration["replay_provenance"][
                    "prior_execution_manifest_sha256"
                ],
            }
        )
    campaign = {
        "schema": scorer.CAMPAIGN_SCHEMA,
        "campaign_id": preregistration["campaign_id"],
        "source_revision": source_revision,
        "analyzer_package_tree_sha256": preregistration["analyzer_package_tree_sha256"],
        "preregistration_path": snapshot.name,
        "preregistration_sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
        "holdout_protocol": protocol_execution,
        "execution_boundary": {
            "scanner_python_isolated": True,
            "python_no_site_startup": True,
            "scanner_python_sha256": protocol_execution["scanner_python_sha256"],
            "post_execution_runtime_verified": True,
            "runtime_mutation_guard": "windows_read_directory_changes_overlapped_v2",
            "runtime_notification_classifier": protocol.RUNTIME_NOTIFICATION_CLASSIFIER,
            "native_runtime_lock_guard": protocol.NATIVE_RUNTIME_LOCK_GUARD,
            "native_runtime_prewarm_guard": protocol.NATIVE_RUNTIME_PREWARM_GUARD,
            "runtime_object_attestation_guard": (
                protocol.RUNTIME_OBJECT_ATTESTATION_GUARD
            ),
            "runtime_actual_mutation_event_count_required": 0,
            "runtime_launcher_sha256": protocol_execution["runtime_launcher_sha256"],
            "runtime_probe_sha256": protocol_execution["runtime_probe_sha256"],
            "source_materialization_probe_sha256": protocol_execution[
                "source_materialization_probe_sha256"
            ],
            "git_blob_exact_materialization_required": True,
            "source_pre_post_tree_match_required": True,
            "source_mutation_event_count_required": 0,
            "independent_git_verifier_sha256": protocol_execution[
                "independent_git_verifier_sha256"
            ],
            "independent_git_verification_post_campaign_required": True,
        },
        "release_decision_contract": {
            "blocking_policy": runner.RELEASE_BLOCKING_POLICY,
            "release_qualification_allowed": not bool(
                qualification_boundary
            ),
        },
        "apps": app_rows,
        "claim_boundary": preregistration["claim_boundary"],
        "qualification_boundary": qualification_boundary,
        "raw_returned": False,
    }
    available = {
        row["app"]: row["eligible_release_blocking_findings"]
        for row in app_rows
    }
    queue = {
        "schema": scorer.QUEUE_SCHEMA,
        "campaign_id": preregistration["campaign_id"],
        "source_revision": source_revision,
        "analyzer_package_tree_sha256": preregistration["analyzer_package_tree_sha256"],
        "holdout_protocol_manifest_sha256": bound_protocol["manifest_sha256"],
        "candidate_population": {
            "blocking_policy": runner.RELEASE_BLOCKING_POLICY,
            "lane": "release_blocking",
            "excluded_holds_still_fail_closed": True,
            "release_qualification_allowed": not bool(
                qualification_boundary
            ),
        },
        "sampling": {
            "mode": "all_eligible_release_blockers",
            "target_per_app": None,
            "available_by_app": available,
            "all_release_blockers_by_app": available,
            "unlocatable_by_app": {name: 0 for name in available},
            "sampled_by_app": available,
        },
        "candidates": candidates,
        "claim_boundary": preregistration["claim_boundary"],
        "qualification_boundary": qualification_boundary,
        "raw_returned": False,
    }
    _write(evidence / "campaign.json", campaign)
    independent_apps = []
    for app in preregistration["apps"]:
        name = app["app"]
        contract = source_contracts[name]
        source = contract["source"]
        rows = contract["rows"]
        independent_apps.append(
            {
                "app": name,
                "repository_id": app["repository_id"],
                "origin_repository_id": app["repository_id"],
                "origin_repository_match": True,
                "commit": app["commit"],
                "commit_object_base64": base64.b64encode(source["commit_raw"]).decode("ascii"),
                "commit_object_hash_match": True,
                "commit_tree": app["commit_tree"],
                "tree_object_reconstruction_match": True,
                "git_object_format": "sha1",
                "git_repository_layout": (
                    "verifier_owned_unlinked_full_bare_sha1_mirror_snapshot"
                ),
                "git_fsck_strict_passed": True,
                "git_fsck_output_sha256": hashlib.sha256(
                    f"mirror-fsck-{name}".encode()
                ).hexdigest(),
                "input_mirror_storage_manifest_sha256": hashlib.sha256(
                    f"input-storage-{name}".encode()
                ).hexdigest(),
                "private_snapshot_method": "git_clone_mirror_no_local",
                "private_snapshot_storage_manifest_sha256": hashlib.sha256(
                    f"private-storage-{name}".encode()
                ).hexdigest(),
                "storage_stable": True,
                "source_materialization_receipt_path": contract["receipt_path"],
                "source_materialization_receipt_sha256": contract["receipt_sha256"],
                "source_tree_sha256": contract["tree_sha256"],
                "file_set_sha256": scorer._independent_file_set_sha256(rows),
                "file_count": len(rows),
                "total_bytes": sum(row["byte_count"] for row in rows),
                "files": rows,
                "raw_returned": False,
            }
        )
    independent_verification = {
        "schema": "k_guard_independent_git_verification.v3",
        "campaign_id": preregistration["campaign_id"],
        "preregistration_sha256": hashlib.sha256(preregistration_path.read_bytes()).hexdigest(),
        "campaign_sha256": hashlib.sha256((evidence / "campaign.json").read_bytes()).hexdigest(),
        "holdout_protocol_manifest_sha256": bound_protocol["manifest_sha256"],
        "independent_git_verifier_sha256": bound_protocol["protocol_files"][
            "scripts/verify_holdout_git_sources.py"
        ],
        "verification_method": (
            "verifier_owned_no_local_mirror_snapshot_raw_git_object_reconstruction"
        ),
        "byte_binding": "git_sha1_graph_plus_independent_sha256_file_bytes",
        "storage_binding": "pre_post_sha256_manifest_plus_file_identity",
        "path_policy": "windows_ntfs_materialization_fail_closed_v1",
        "execution_provenance": "unsigned_local_replay_receipt",
        "external_signed_provenance_required_for_contest_go": True,
        "acquisition_boundary": (
            "input origin is configuration metadata; an unlinked verifier-owned no-local mirror "
            "snapshot is storage-manifested before and after content-addressed reconstruction"
        ),
        "source_contents_embedded": False,
        "app_count": len(independent_apps),
        "apps": independent_apps,
        "raw_returned": False,
    }
    _write(evidence / "independent-git-verification.json", independent_verification)
    queue_path = evidence / "candidate-queue.json"
    _write(queue_path, queue)
    artifacts = evidence / "review-artifacts"
    reviews_dir = evidence / "reviews"
    artifacts.mkdir()
    reviews_dir.mkdir()
    prompt = artifacts / "review-prompt.txt"
    prompt.write_text("Review every candidate against its pinned source context.", encoding="utf-8")
    review_paths = []
    binding_hash = assembler.candidate_bindings_sha256(candidates)
    queue_hash = hashlib.sha256(queue_path.read_bytes()).hexdigest()
    for alias, vendor in (("one", "openai"), ("two", "anthropic"), ("three", "xai")):
        response = artifacts / f"{vendor}-response.json"
        response.write_text(
            json.dumps({"session_id": f"session-{alias}", "response_id": f"response-{alias}"}),
            encoding="utf-8",
        )
        review = {
            "schema": assembler.REVIEW_SCHEMA,
            "campaign_id": preregistration["campaign_id"],
            "source_revision": source_revision,
            "analyzer_package_tree_sha256": preregistration["analyzer_package_tree_sha256"],
            "holdout_protocol_manifest_sha256": bound_protocol["manifest_sha256"],
            "reviewer_alias": alias,
            "reviewer_kind": "external_ai_source_context_review",
            "vendor": vendor,
            "model": f"{vendor}-test-model",
            "session_id": f"session-{alias}",
            "response_id": f"response-{alias}",
            "prompt_artifact_path": prompt.relative_to(evidence).as_posix(),
            "prompt_sha256": hashlib.sha256(prompt.read_bytes()).hexdigest(),
            "response_artifact_path": response.relative_to(evidence).as_posix(),
            "response_sha256": hashlib.sha256(response.read_bytes()).hexdigest(),
            "candidate_queue_sha256": queue_hash,
            "candidate_bindings_sha256": binding_hash,
            "candidates": [
                {
                    "candidate_id": candidate["candidate_id"],
                    "label": (
                        "inconclusive"
                        if individual_inconclusive and vendor == "xai" and position == 0
                        else "true_positive"
                    ),
                    "rationale": "source context checked",
                }
                for position, candidate in enumerate(candidates)
            ],
            "raw_returned": False,
        }
        review_path = reviews_dir / f"{vendor}.json"
        _write(review_path, review)
        review_paths.append(review_path)
    labels = assembler.build_labels(queue_path, review_paths)
    _write(evidence / "candidate-labels.json", labels)
    return evidence, preregistration_path


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://github.com/Owner/Repo.git", "owner/repo"),
        ("git@github.com:Owner/Repo.git", "owner/repo"),
        ("OWNER/REPO", "owner/repo"),
        ("https://example.com/owner/repo", None),
        ("https://github.com/owner/repo/tree/main", None),
    ],
)
def test_normalize_github_repository(value: str, expected: str | None) -> None:
    assert integrity.normalize_github_repository(value) == expected


def test_prior_evidence_snapshot_is_deterministic_and_includes_explicit_development_exclusions() -> None:
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()

    first = builder.build_snapshot(ROOT, revision)
    second = builder.build_snapshot(ROOT, revision)
    repository_ids = {row["repository_id"] for row in first["repositories"]}

    assert first == second
    assert first["repository_count"] == len(repository_ids)
    assert "gpustack/gpustack" in repository_ids
    assert "aegntic/dailydoco" in repository_ids


def test_checked_in_exclusion_snapshot_replays_from_its_bound_revision() -> None:
    path = ROOT / "evidence" / "public" / "holdout" / "prior-corpus-exclusions-3b102ab-v1.json"
    checked_in = json.loads(path.read_text(encoding="utf-8"))

    assert integrity.load_exclusion_snapshot(path) == checked_in
    assert builder.build_snapshot(ROOT, checked_in["source_revision"]) == checked_in


def test_checked_in_v6_preregistration_migrates_without_changing_selection() -> None:
    v5_root = (
        ROOT
        / "evidence"
        / "public"
        / "holdout"
        / "k-guard-public-apps-41-v5-20260716"
    )
    v6_root = (
        ROOT
        / "evidence"
        / "public"
        / "holdout"
        / "k-guard-public-apps-41-v6-20260716"
    )
    v5_path = v5_root / "preregistration.json"
    v6_path = v6_root / "preregistration.json"
    v5 = json.loads(v5_path.read_text(encoding="utf-8"))
    v6 = json.loads(v6_path.read_text(encoding="utf-8"))

    runner._validate_preregistration(v6, v6_path)

    assert [
        (row["repository_id"], row["commit"], row["stratum"])
        for row in v6["apps"]
    ] == [
        (row["repository_id"], row["commit"], row["stratum"])
        for row in v5["apps"]
    ]
    assert v6["locked_thresholds"] == v5["locked_thresholds"]
    assert v6["locked_review"] == v5["locked_review"]
    migration = v6["registration_migration"]
    assert migration["superseded_preregistration_sha256"] == integrity.sha256_file(
        v5_path
    )
    assert migration["scanner_execution_before_migration"] is False
    assert migration["scanner_output_seen_before_migration"] is False
    assert migration["source_selection_changed"] is False
    assert migration["repository_set_changed"] is False
    assert migration["locked_thresholds_changed"] is False
    assert migration["locked_review_changed"] is False


def test_checked_in_v7_preregistration_migrates_without_changing_selection() -> None:
    v6_root = (
        ROOT
        / "evidence"
        / "public"
        / "holdout"
        / "k-guard-public-apps-41-v6-20260716"
    )
    v7_root = (
        ROOT
        / "evidence"
        / "public"
        / "holdout"
        / "k-guard-public-apps-41-v7-20260716"
    )
    v6_path = v6_root / "preregistration.json"
    v7_path = v7_root / "preregistration.json"
    v6 = json.loads(v6_path.read_text(encoding="utf-8"))
    v7 = json.loads(v7_path.read_text(encoding="utf-8"))

    runner._validate_preregistration(v7, v7_path)

    assert v7["apps"] == v6["apps"]
    assert v7["locked_thresholds"] == v6["locked_thresholds"]
    assert v7["locked_review"] == v6["locked_review"]
    assert v7["selection"] == v6["selection"]
    assert v7["holdout_integrity"] == v6["holdout_integrity"]
    assert v7["analyzer_package_tree_sha256"] == v6["analyzer_package_tree_sha256"]
    migration = v7["registration_migration"]
    assert migration["superseded_preregistration_sha256"] == integrity.sha256_file(
        v6_path
    )
    assert migration["scanner_execution_before_migration"] is False
    assert migration["scanner_output_seen_before_migration"] is False
    assert migration["source_selection_changed"] is False
    assert migration["repository_set_changed"] is False
    assert migration["locked_thresholds_changed"] is False
    assert migration["locked_review_changed"] is False


def test_checked_in_v8_preregistration_replaces_only_git_tree_ineligible_sources() -> None:
    v7_root = (
        ROOT
        / "evidence"
        / "public"
        / "holdout"
        / "k-guard-public-apps-41-v7-20260716"
    )
    v8_root = (
        ROOT
        / "evidence"
        / "public"
        / "holdout"
        / "k-guard-public-apps-41-v8-20260716"
    )
    v7 = json.loads((v7_root / "preregistration.json").read_text(encoding="utf-8"))
    v8_path = v8_root / "preregistration.json"
    v8 = json.loads(v8_path.read_text(encoding="utf-8"))
    selected = json.loads((v8_root / "selected-corpus.json").read_text(encoding="utf-8"))
    source = json.loads((v8_root / "source-metadata.json").read_text(encoding="utf-8"))
    manifest = json.loads((v8_root / "holdout-protocol.json").read_text(encoding="utf-8"))

    runner._validate_preregistration(v8, v8_path)

    previous_ids = {row["repository_id"] for row in v7["apps"]}
    current_ids = {row["repository_id"] for row in v8["apps"]}
    assert previous_ids - current_ids == {
        "naryal2580/vfapi",
        "robinmoretti/mamankim",
        "vkottler/vtelem",
    }
    assert current_ids - previous_ids == {
        "0x00c0ff33/medicare-portal-owasp",
        "0xhunterr/hackademy",
        "ahmetak4n/vuln-netframework",
    }
    assert v8["locked_thresholds"] == v7["locked_thresholds"]
    assert v8["locked_review"] == v7["locked_review"]
    assert v8["locked_execution"] == v7["locked_execution"]
    assert v8["label_contract"] == v7["label_contract"]
    assert v8["claim_boundary"] == v7["claim_boundary"]
    assert v8["selection"]["stratum_counts"] == v7["selection"]["stratum_counts"]

    migration = v8["registration_migration"]
    assert migration["schema"] == integrity.STRUCTURAL_REPLACEMENT_MIGRATION_SCHEMA
    assert migration["replacement_policy"] == integrity.STRUCTURAL_REPLACEMENT_POLICY
    assert migration["scanner_execution_before_migration"] is False
    assert migration["scanner_output_seen_before_migration"] is False
    assert migration["replacement_count"] == 3
    assert selected["selection_migration"] == migration

    assert source["schema"] == protocol.STRUCTURAL_SOURCE_METADATA_SCHEMA
    assert source["all_source_trees_structurally_eligible"] is True
    assert source["repository_set_sha256"] == v8["holdout_integrity"][
        "repository_set_sha256"
    ]
    assert all(
        set(row["git_tree_mode_counts"]).issubset(
            protocol.SOURCE_METADATA_GIT_TREE_MODES
        )
        and row["git_tree_recursive_truncated"] is False
        for row in source["repositories"]
    )
    assert manifest["schema"] == protocol.STRUCTURAL_PROTOCOL_SCHEMA
    assert manifest["source_materialization"]["schema"] == (
        "k_guard_git_source_materialization.v1"
    )
    assert manifest["source_metadata"]["schema"] == protocol.STRUCTURAL_SOURCE_METADATA_SCHEMA


def test_checked_in_v9_preregistration_strengthens_only_source_protocol_before_execution() -> None:
    v8_root = (
        ROOT
        / "evidence"
        / "public"
        / "holdout"
        / "k-guard-public-apps-41-v8-20260716"
    )
    v9_root = (
        ROOT
        / "evidence"
        / "public"
        / "holdout"
        / "k-guard-public-apps-41-v9-20260716"
    )
    v8_path = v8_root / "preregistration.json"
    v9_path = v9_root / "preregistration.json"
    v8 = json.loads(v8_path.read_text(encoding="utf-8"))
    v9 = json.loads(v9_path.read_text(encoding="utf-8"))

    runner._validate_preregistration(v9, v9_path)
    bound = protocol.validate_bound_protocol(v9, v9_path)

    for field in (
        "apps",
        "analyzer_package_tree_sha256",
        "claim_boundary",
        "holdout_integrity",
        "label_contract",
        "locked_execution",
        "locked_review",
        "locked_thresholds",
        "qualification_contract",
        "registration_migration",
        "selection",
    ):
        assert v9[field] == v8[field]
    assert v9["campaign_id"] == "k-guard-public-apps-41-v9-20260716"
    assert bound["manifest"]["schema"] == protocol.BLOB_EXACT_PROTOCOL_SCHEMA
    assert bound["manifest"]["source_materialization"] == {
        "schema": "k_guard_git_source_materialization.v2",
        "cleanliness_method": "git_blob_sha256_file_set_plus_index_tree_v2",
        "git_porcelain_clean_required": False,
        "direct_git_blob_sha256_required": True,
        "runtime_receipt_schema": "k_guard_holdout_scan_runtime_receipt.v3",
        "mutation_guard": "windows_read_directory_changes_overlapped_v2",
        "required_scan_event_count": 0,
    }

    migration = v9["protocol_migration"]
    assert migration["schema"] == "k_guard_preexecution_protocol_migration.v1"
    assert migration["supersedes_campaign_id"] == v8["campaign_id"]
    assert migration["superseded_preregistration_sha256"] == integrity.sha256_file(
        v8_path
    )
    assert migration["superseded_protocol_sha256"] == integrity.sha256_file(
        v8_root / "holdout-protocol.json"
    )
    assert migration["new_evidence_contract_revision"] == bound["manifest"][
        "implementation_revision"
    ]
    assert migration["scanner_execution_before_migration"] is False
    assert migration["scanner_output_seen_before_migration"] is False
    assert migration["review_output_seen_before_migration"] is False
    assert migration["source_selection_changed"] is False
    assert migration["repository_set_changed"] is False
    assert migration["locked_thresholds_changed"] is False
    assert migration["locked_review_changed"] is False
    assert migration["locked_execution_changed"] is False
    assert migration["analyzer_package_tree_changed"] is False
    assert migration["source_materialization_strengthened"] is True
    assert migration["git_porcelain_is_observational_only"] is True
    assert migration["windows_extended_length_paths_required"] is True
    assert not any(
        (v9_root / name).exists()
        for name in (
            "campaign-report.json",
            "candidate-queue.json",
            "source-receipts",
            "runtime-receipts",
            "reports",
            "reviews",
        )
    )


def test_checked_in_v10_preregistration_strengthens_only_runtime_protocol_before_execution() -> None:
    v9_root = (
        ROOT
        / "evidence"
        / "public"
        / "holdout"
        / "k-guard-public-apps-41-v9-20260716"
    )
    v10_root = (
        ROOT
        / "evidence"
        / "public"
        / "holdout"
        / "k-guard-public-apps-41-v10-20260717"
    )
    v9_path = v9_root / "preregistration.json"
    v10_path = v10_root / "preregistration.json"
    v9 = json.loads(v9_path.read_text(encoding="utf-8"))
    v10 = json.loads(v10_path.read_text(encoding="utf-8"))

    runner._validate_preregistration(v10, v10_path)
    bound = protocol.validate_bound_protocol(v10, v10_path)

    for field in (
        "apps",
        "analyzer_package_tree_sha256",
        "claim_boundary",
        "holdout_integrity",
        "label_contract",
        "locked_execution",
        "locked_review",
        "locked_thresholds",
        "qualification_contract",
        "registration_migration",
        "selection",
    ):
        assert v10[field] == v9[field]
    assert v10["campaign_id"] == "k-guard-public-apps-41-v10-20260717"
    assert bound["manifest"]["schema"] == protocol.PROTOCOL_SCHEMA
    assert bound["manifest"]["source_materialization"] == {
        "schema": "k_guard_git_source_materialization.v2",
        "cleanliness_method": "git_blob_sha256_file_set_plus_index_tree_v2",
        "git_porcelain_clean_required": False,
        "direct_git_blob_sha256_required": True,
        "runtime_receipt_schema": protocol.RUNTIME_RECEIPT_SCHEMA,
        "mutation_guard": "windows_read_directory_changes_overlapped_v2",
        "required_scan_event_count": 0,
    }
    assert bound["manifest"]["runtime_environment"][
        "runtime_notification_classifier"
    ] == protocol.RUNTIME_NOTIFICATION_CLASSIFIER
    assert bound["manifest"]["runtime_environment"][
        "native_runtime_prewarm_guard"
    ] == protocol.NATIVE_RUNTIME_PREWARM_GUARD
    assert bound["manifest"]["runtime_environment"][
        "runtime_object_attestation_guard"
    ] == protocol.RUNTIME_OBJECT_ATTESTATION_GUARD

    review = v10["implementation_review"]
    assert review["quorum_passed"] is True
    assert review["may_preregister_v10"] is True
    assert review["implementation_revision"] == bound["manifest"][
        "implementation_revision"
    ]
    assert review["qualification_authority"].startswith(
        "structural implementation review only"
    )
    for artifact_key, digest_key in (
        ("artifact_path", "artifact_sha256"),
        ("quorum_artifact_path", "quorum_sha256"),
    ):
        assert integrity.sha256_file(v10_root / review[artifact_key]) == review[digest_key]

    migration = v10["protocol_migration"]
    assert migration["schema"] == "k_guard_preexecution_protocol_migration.v2"
    assert migration["supersedes_campaign_id"] == v9["campaign_id"]
    assert migration["superseded_preregistration_sha256"] == integrity.sha256_file(
        v9_path
    )
    assert migration["superseded_protocol_sha256"] == integrity.sha256_file(
        v9_root / "holdout-protocol.json"
    )
    assert migration["new_evidence_contract_revision"] == bound["manifest"][
        "implementation_revision"
    ]
    assert migration["scanner_execution_before_migration"] is False
    assert migration["scanner_output_seen_before_migration"] is False
    assert migration["candidate_review_output_seen_before_migration"] is False
    assert migration["implementation_review_seen_before_migration"] is True
    assert migration["source_selection_changed"] is False
    assert migration["repository_set_changed"] is False
    assert migration["locked_thresholds_changed"] is False
    assert migration["locked_review_changed"] is False
    assert migration["locked_execution_changed"] is False
    assert migration["analyzer_package_tree_changed"] is False
    assert migration["source_materialization_strengthened"] is False
    assert migration["runtime_attestation_strengthened"] is True
    assert migration["runtime_receipt_schema"] == protocol.RUNTIME_RECEIPT_SCHEMA
    assert migration["runtime_notification_classifier"] == (
        protocol.RUNTIME_NOTIFICATION_CLASSIFIER
    )
    assert migration["native_runtime_prewarm_guard"] == (
        protocol.NATIVE_RUNTIME_PREWARM_GUARD
    )
    assert migration["runtime_object_attestation_guard"] == (
        protocol.RUNTIME_OBJECT_ATTESTATION_GUARD
    )
    assert migration["implementation_review_quorum_bound"] is True
    assert not any(
        (v10_root / name).exists()
        for name in (
            "campaign-report.json",
            "candidate-queue.json",
            "source-receipts",
            "runtime-receipts",
            "reports",
            "reviews",
        )
    )


def test_checked_in_v11_preregistration_is_nonqualifying_protocol_recovery_only() -> None:
    v10_root = (
        ROOT
        / "evidence"
        / "public"
        / "holdout"
        / "k-guard-public-apps-41-v10-20260717"
    )
    v11_root = (
        ROOT
        / "evidence"
        / "public"
        / "holdout"
        / "k-guard-public-apps-41-v11-20260717"
    )
    v10_path = v10_root / "preregistration.json"
    v11_path = v11_root / "preregistration.json"
    v10 = json.loads(v10_path.read_text(encoding="utf-8"))
    v11 = json.loads(v11_path.read_text(encoding="utf-8"))

    runner._validate_preregistration(v11, v11_path)
    bound = protocol.validate_bound_protocol(v11, v11_path)
    validated = integrity.validate_v4_preregistration(v11, v11_path)

    for field in (
        "apps",
        "claim_boundary",
        "holdout_integrity",
        "label_contract",
        "locked_execution",
        "locked_review",
        "locked_thresholds",
        "qualification_contract",
        "registration_migration",
        "selection",
    ):
        assert v11[field] == v10[field]
    assert v11["campaign_id"] == "k-guard-public-apps-41-v11-20260717"
    assert v11["status"] == integrity.PROTOCOL_RECOVERY_REPLAY_STATUS
    assert v11["analyzer_package_tree_sha256"] == bound["manifest"][
        "analyzer_package_tree_sha256"
    ]

    replay = v11["replay_provenance"]
    assert replay["superseded_campaign_id"] == v10["campaign_id"]
    assert replay["source_population_reused"] is True
    assert replay["prior_scanner_execution"] is True
    assert replay["prior_scanner_output_seen"] is True
    assert replay["prior_candidate_content_exposure_assumed"] is True
    assert replay["candidate_labels_created"] is False
    assert replay["effectiveness_status_created"] is False
    assert replay["qualifying_holdout"] is False
    assert replay["release_claim_allowed"] is False
    assert replay["evidence_use"] == "development_baseline_only"
    assert replay["final_unseen_holdout_required_for_go"] is True
    assert integrity.sha256_file(
        v11_root / replay["prior_execution_manifest_path"]
    ) == replay["prior_execution_manifest_sha256"]

    boundary = validated["qualification_boundary"]
    assert boundary["qualification_eligible"] is False
    assert boundary["release_claim_allowed"] is False
    assert boundary["fresh_unseen_holdout_required_for_go"] is True

    review = v11["implementation_review"]
    assert review["quorum_passed"] is True
    assert review["may_run_recovery_baseline"] is True
    assert review["may_use_recovery_for_go"] is False
    assert integrity.sha256_file(v11_root / review["artifact_path"]) == review[
        "artifact_sha256"
    ]
    assert integrity.sha256_file(
        v11_root / review["quorum_artifact_path"]
    ) == review["quorum_sha256"]
    provenance = json.loads(
        (v11_root / review["artifact_path"]).read_text(encoding="utf-8")
    )
    quorum = json.loads(
        (v11_root / review["quorum_artifact_path"]).read_text(encoding="utf-8")
    )
    assert quorum["artifact_canonicalization"][
        "checked_in_line_endings"
    ] == "lf"
    assert quorum["artifact_canonicalization"]["json_semantics_changed"] is False
    for row in provenance["reviews"]:
        artifact = v11_root / row["artifact_path"]
        assert b"\r" not in artifact.read_bytes()
        assert integrity.sha256_file(artifact) == row["sha256"]
        reviewer = row["reviewer"]
        assert quorum["reviewer_artifacts"][reviewer][
            "verdict_sha256"
        ] == row["sha256"]
        assert quorum["reviewer_artifacts"][reviewer][
            "source_verdict_sha256"
        ]
    assert not any(
        (v11_root / name).exists()
        for name in (
            "campaign-report.json",
            "candidate-queue.json",
            "independent-git-verification.json",
            "candidate-labels.json",
            "effectiveness-status.json",
        )
    )


def test_v4_preregistration_accepts_only_disjoint_hash_bound_sources(tmp_path: Path) -> None:
    path, payload = _v4_preregistration(tmp_path)

    runner._validate_preregistration(payload, path)

    overlap = copy.deepcopy(payload)
    overlap["apps"][0]["repository"] = "https://github.com/prior/one.git"
    overlap["apps"][0]["repository_id"] = "prior/one"
    overlap_ids = [row["repository_id"] for row in overlap["apps"]]
    overlap["holdout_integrity"]["repository_set_sha256"] = integrity.repository_set_sha256(overlap_ids)
    with pytest.raises(ValueError, match="overlaps prior evidence"):
        runner._validate_preregistration(overlap, path)

    duplicate = copy.deepcopy(payload)
    duplicate["apps"][1]["repository"] = duplicate["apps"][0]["repository"]
    duplicate["apps"][1]["repository_id"] = duplicate["apps"][0]["repository_id"]
    duplicate_ids = [row["repository_id"] for row in duplicate["apps"]]
    duplicate["holdout_integrity"]["repository_set_sha256"] = integrity.repository_set_sha256(duplicate_ids)
    with pytest.raises(ValueError, match="must be unique"):
        runner._validate_preregistration(duplicate, path)

    overclaimed = copy.deepcopy(payload)
    overclaimed["claim_boundary"]["independent_git_execution_attested"] = True
    with pytest.raises(ValueError, match="claim boundary"):
        runner._validate_preregistration(overclaimed, path)


def test_v4_protocol_recovery_replay_requires_explicit_nonqualifying_provenance(
    tmp_path: Path,
) -> None:
    path, payload = _v4_preregistration(tmp_path)

    unexpected = copy.deepcopy(payload)
    unexpected["replay_provenance"] = {}
    with pytest.raises(ValueError, match="cannot carry protocol recovery"):
        runner._validate_preregistration(unexpected, path)

    manifest = _mark_protocol_recovery_replay(path, payload)
    validated = integrity.validate_v4_preregistration(payload, path)

    assert validated["replay_manifest"] == manifest
    assert validated["qualification_boundary"]["qualification_eligible"] is False
    assert validated["qualification_boundary"]["release_claim_allowed"] is False
    assert (
        validated["qualification_boundary"]["fresh_unseen_holdout_required_for_go"]
        is True
    )

    overclaimed = copy.deepcopy(payload)
    overclaimed["replay_provenance"]["qualifying_holdout"] = True
    with pytest.raises(ValueError, match="qualifying_holdout"):
        runner._validate_preregistration(overclaimed, path)


def test_v4_protocol_recovery_replay_rejects_prior_execution_manifest_tampering(
    tmp_path: Path,
) -> None:
    path, payload = _v4_preregistration(tmp_path)
    _mark_protocol_recovery_replay(path, payload)
    manifest_path = tmp_path / payload["replay_provenance"][
        "prior_execution_manifest_path"
    ]
    manifest_path.write_text(
        manifest_path.read_text(encoding="utf-8") + " ",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="prior execution manifest hash"):
        runner._validate_preregistration(payload, path)


def test_v4_wheelhouse_rejects_record_owned_extra_runtime_file(tmp_path: Path) -> None:
    preregistration_path, preregistration = _v4_preregistration(tmp_path)
    bound = protocol.validate_bound_protocol(preregistration, preregistration_path)
    runtime = json.loads(json.dumps(bound["runtime_environment"]))
    runtime["installed_distributions"][0]["installed_files"].append(
        {
            "path": "Lib/site-packages/bootstrap.pth",
            "sha256": "9" * 64,
            "byte_count": 12,
        }
    )
    binding = bound["manifest"]["runtime_environment"]["wheelhouse"]

    with pytest.raises(ValueError, match="not exactly wheel-derived"):
        protocol.load_wheelhouse_manifest(
            tmp_path,
            binding,
            runtime_environment=runtime,
            install_report=bound["install_report"],
        )


def test_v4_wheelhouse_rejects_case_colliding_archive_paths(tmp_path: Path) -> None:
    wheel = tmp_path / "case_collision-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("package/Module.py", b"one\n")
        archive.writestr("package/module.py", b"two\n")

    with pytest.raises(ValueError, match="unsafe member"):
        protocol._generic_wheel_artifact(wheel)


def test_v4_install_report_rejects_unreported_bootstrap_distribution(tmp_path: Path) -> None:
    preregistration_path, preregistration = _v4_preregistration(tmp_path)
    bound = protocol.validate_bound_protocol(preregistration, preregistration_path)
    runtime = json.loads(json.dumps(bound["runtime_environment"]))
    runtime["installed_distributions"].append(
        {"name": "bootstrap-payload", "version": "1.0", "installed_files": []}
    )

    with pytest.raises(ValueError, match="absent from the wheel installation report"):
        protocol.load_install_report(
            bound["install_report_path"],
            wheel_sha256=bound["manifest"]["wheel"]["sha256"],
            runtime_environment=runtime,
        )

def test_v4_preregistration_rejects_snapshot_or_selection_tampering(tmp_path: Path) -> None:
    path, payload = _v4_preregistration(tmp_path)
    snapshot_path = tmp_path / payload["holdout_integrity"]["exclusion_snapshot_path"]
    snapshot_path.write_text(snapshot_path.read_text(encoding="utf-8") + " ", encoding="utf-8")

    with pytest.raises(ValueError, match="snapshot hash"):
        runner._validate_preregistration(payload, path)

    path, payload = _v4_preregistration(tmp_path)
    payload["holdout_integrity"]["scanner_output_seen_during_selection"] = True
    with pytest.raises(ValueError, match="scanner_output_seen_during_selection"):
        runner._validate_preregistration(payload, path)

    path, payload = _v4_preregistration(tmp_path)
    selected_path = tmp_path / payload["selection"]["qualification_population_artifact"]
    selected_path.write_text(
        selected_path.read_text(encoding="utf-8") + " ",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="qualification population hash"):
        runner._validate_preregistration(payload, path)


def test_v4_preregistration_enforces_population_roles_and_locked_app_count(
    tmp_path: Path,
) -> None:
    path, payload = _v4_preregistration(tmp_path)
    discovery_path = tmp_path / payload["selection"]["discovery_population_artifact"]
    discovery = json.loads(discovery_path.read_text(encoding="utf-8"))
    discovery["qualification_authority"] = True
    _write(discovery_path, discovery)
    payload["selection"]["discovery_population_sha256"] = integrity.sha256_file(discovery_path)

    with pytest.raises(ValueError, match="discovery population authority"):
        runner._validate_preregistration(payload, path)

    path, payload = _v4_preregistration(tmp_path)
    payload["locked_thresholds"]["minimum_app_count"] = 21
    with pytest.raises(ValueError, match="minimum_app_count"):
        runner._validate_preregistration(payload, path)


def test_v4_preregistration_recomputes_selected_population_projection(
    tmp_path: Path,
) -> None:
    path, payload = _v4_preregistration(tmp_path)
    selected_path = tmp_path / payload["selection"]["qualification_population_artifact"]
    selected = json.loads(selected_path.read_text(encoding="utf-8"))
    selected["preflight_only_expected_population"]["estimated_candidate_count"] = 101
    _write(selected_path, selected)
    payload["selection"]["qualification_population_sha256"] = integrity.sha256_file(
        selected_path
    )

    with pytest.raises(ValueError, match="projection is inconsistent"):
        runner._validate_preregistration(payload, path)

    path, payload = _v4_preregistration(tmp_path)
    discovery_path = tmp_path / payload["selection"]["discovery_population_artifact"]
    discovery = json.loads(discovery_path.read_text(encoding="utf-8"))
    selected_repository = payload["apps"][0]["repository_id"]
    next(
        row for row in discovery["apps"] if row["repository_id"] == selected_repository
    )["stratum"] = "long_tail"
    _write(discovery_path, discovery)
    discovery_hash = integrity.sha256_file(discovery_path)
    payload["selection"]["discovery_population_sha256"] = discovery_hash
    selected_path = tmp_path / payload["selection"]["qualification_population_artifact"]
    selected = json.loads(selected_path.read_text(encoding="utf-8"))
    selected["bindings"]["structural_preflight_sha256"] = discovery_hash
    _write(selected_path, selected)
    payload["selection"]["qualification_population_sha256"] = integrity.sha256_file(
        selected_path
    )

    with pytest.raises(ValueError, match="stratum projection is inconsistent"):
        runner._validate_preregistration(payload, path)


def test_v4_preregistration_compares_rule_share_without_rounding_slack(
    tmp_path: Path,
) -> None:
    path, payload = _v4_preregistration(tmp_path)
    discovery_path = tmp_path / payload["selection"]["discovery_population_artifact"]
    discovery = json.loads(discovery_path.read_text(encoding="utf-8"))
    rows_by_rule: dict[str, list[dict]] = {}
    for row in discovery["apps"]:
        rule_id = next(iter(row["estimated_rule_counts"]))
        rows_by_rule.setdefault(rule_id, []).append(row)
    target_rule = "AUTH_JWT_DECODE_WITHOUT_VERIFY"
    other_primary_rule = "CONFIG_CSP_UNSAFE_EVAL"
    target_counts = [1_249_997, 1, 1, 1, 1]
    other_primary_counts = [1_249_985, 1, 1, 1, 1]
    for row, count in zip(rows_by_rule[target_rule], target_counts, strict=True):
        row["estimated_candidate_count"] = count
        row["estimated_rule_counts"] = {target_rule: count}
    for row, count in zip(
        rows_by_rule[other_primary_rule],
        other_primary_counts,
        strict=True,
    ):
        row["estimated_candidate_count"] = count
        row["estimated_rule_counts"] = {other_primary_rule: count}
    for rule_id, rows in rows_by_rule.items():
        if rule_id in {target_rule, other_primary_rule}:
            continue
        for row in rows:
            row["estimated_candidate_count"] = 1
            row["estimated_rule_counts"] = {rule_id: 1}

    rule_counts = {
        rule_id: sum(row["estimated_candidate_count"] for row in rows)
        for rule_id, rows in rows_by_rule.items()
    }
    candidate_count = sum(rule_counts.values())
    discovery.update(
        {
            "estimated_apps_with_candidates": len(discovery["apps"]),
            "estimated_candidate_count": candidate_count,
            "estimated_distinct_rule_count": len(rule_counts),
            "estimated_maximum_single_rule_share": 0.5,
            "estimated_rule_counts": rule_counts,
        }
    )
    assert rule_counts[target_rule] / candidate_count > 0.5
    assert round(rule_counts[target_rule] / candidate_count, 6) == 0.5
    _write(discovery_path, discovery)
    discovery_hash = integrity.sha256_file(discovery_path)
    payload["selection"]["discovery_population_sha256"] = discovery_hash

    selected_path = tmp_path / payload["selection"]["qualification_population_artifact"]
    selected = json.loads(selected_path.read_text(encoding="utf-8"))
    selected["bindings"]["structural_preflight_sha256"] = discovery_hash
    selected["preflight_only_expected_population"].update(
        {
            "estimated_apps_with_candidates": len(discovery["apps"]),
            "estimated_candidate_count": candidate_count,
            "estimated_distinct_rule_count": len(rule_counts),
            "estimated_maximum_single_rule_share": 0.5,
            "estimated_rule_counts": rule_counts,
        }
    )
    _write(selected_path, selected)
    payload["selection"]["qualification_population_sha256"] = integrity.sha256_file(
        selected_path
    )

    with pytest.raises(ValueError, match="maximum_single_rule_candidate_share"):
        runner._validate_preregistration(payload, path)


def test_v4_campaign_origin_must_bind_to_the_preregistered_repository() -> None:
    row = {
        "repository_id": "owner/app",
        "origin_repository_id": "owner/app",
        "origin_repository_match": True,
    }

    assert scorer._v4_origin_binding_valid(row, "owner/app") is True
    assert scorer._v4_origin_binding_valid(row, "other/app") is False
    assert scorer._v4_origin_binding_valid({**row, "origin_repository_match": False}, "owner/app") is False


def test_v4_effectiveness_rebuilds_candidate_census_from_raw_reports(tmp_path: Path) -> None:
    evidence, preregistration = _v4_evidence(tmp_path)

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is True
    assert status["metrics"]["candidate_count"] == 20
    assert status["qualified"] is False


def test_v4_protocol_recovery_replay_is_integrity_valid_but_never_qualifies(
    tmp_path: Path,
) -> None:
    evidence, preregistration = _v4_evidence(
        tmp_path,
        protocol_recovery_replay=True,
        perfect_metrics=True,
    )

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is True
    assert status["qualified"] is False
    assert status["verdict"] == "hold"
    assert status["blockers"] == ["protocol_recovery_replay_nonqualifying"]
    assert status["metrics"]["candidate_count"] == 100
    assert status["metrics"]["blocker_actionability"] == 1.0
    assert status["metrics"]["fully_actionable_blocker_app_rate"] == 1.0
    assert status["qualification_boundary"]["qualification_eligible"] is False
    assert status["qualification_boundary"]["release_claim_allowed"] is False


def test_v4_protocol_recovery_replay_rejects_boundary_or_commit_binding_tampering(
    tmp_path: Path,
) -> None:
    evidence, preregistration = _v4_evidence(
        tmp_path,
        protocol_recovery_replay=True,
    )
    queue_path = evidence / "candidate-queue.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["qualification_boundary"]["release_claim_allowed"] = True
    _write(queue_path, queue)

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is False
    assert "v4_recovery_qualification_boundary_invalid" in status[
        "validation_errors"
    ]

    evidence, preregistration = _v4_evidence(
        tmp_path / "authority-tamper",
        protocol_recovery_replay=True,
    )
    campaign_path = evidence / "campaign.json"
    campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    campaign["release_decision_contract"][
        "release_qualification_allowed"
    ] = True
    _write(campaign_path, campaign)

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is False
    assert "v4_recovery_release_authority_invalid" in status[
        "validation_errors"
    ]

    evidence, preregistration = _v4_evidence(
        tmp_path / "queue-authority-tamper",
        protocol_recovery_replay=True,
    )
    queue_path = evidence / "candidate-queue.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["candidate_population"]["release_qualification_allowed"] = True
    _write(queue_path, queue)

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is False
    assert "v4_recovery_release_authority_invalid" in status[
        "validation_errors"
    ]

    evidence, preregistration = _v4_evidence(
        tmp_path / "missing-commit-binding",
        protocol_recovery_replay=True,
    )
    preregistration_payload = json.loads(
        preregistration.read_text(encoding="utf-8")
    )
    prior_hash = preregistration_payload["replay_provenance"][
        "prior_execution_manifest_sha256"
    ]
    campaign_path = evidence / "campaign.json"
    campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    execution = campaign["holdout_protocol"]
    execution["tracked_artifacts_committed_at_execution_head"] = [
        row
        for row in execution["tracked_artifacts_committed_at_execution_head"]
        if row["sha256"] != prior_hash
    ]
    _write(campaign_path, campaign)

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is False
    assert "v4_holdout_protocol_committed_artifact_set_incomplete" in status[
        "validation_errors"
    ]


def test_v4_effectiveness_rejects_queue_or_report_tampering(tmp_path: Path) -> None:
    evidence, preregistration = _v4_evidence(tmp_path)
    queue_path = evidence / "candidate-queue.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["candidates"][0]["rule_id"] = "MCP_STATIC_CREDENTIAL_IN_CONFIG"
    _write(queue_path, queue)

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is False
    assert "v4_candidate_census_mismatch:app-0" in status["validation_errors"]

    evidence, preregistration = _v4_evidence(tmp_path / "report-tamper")
    report_path = next((evidence / "reports").glob("*.json.gz"))
    report_path.write_bytes(report_path.read_bytes() + b"tampered")

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is False
    assert any(value.startswith("v4_report_artifact_invalid:") for value in status["validation_errors"])


def test_v4_effectiveness_requires_population_artifacts_in_execution_receipt(
    tmp_path: Path,
) -> None:
    evidence, preregistration_path = _v4_evidence(tmp_path)
    preregistration = json.loads(preregistration_path.read_text(encoding="utf-8"))
    campaign_path = evidence / "campaign.json"
    campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    qualification_hash = preregistration["selection"]["qualification_population_sha256"]
    execution = campaign["holdout_protocol"]
    execution["tracked_artifacts_committed_at_execution_head"] = [
        row
        for row in execution["tracked_artifacts_committed_at_execution_head"]
        if row["sha256"] != qualification_hash
    ]
    _write(campaign_path, campaign)

    status = scorer.build_status(evidence, preregistration_path)

    assert status["integrity_passed"] is False
    assert "v4_holdout_protocol_committed_artifact_set_incomplete" in status[
        "validation_errors"
    ]


def test_v4_individual_inconclusive_blocks_even_when_majority_is_true_positive(
    tmp_path: Path,
) -> None:
    evidence, preregistration = _v4_evidence(tmp_path, individual_inconclusive=True)

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is True
    assert status["metrics"]["inconclusive_rate"] == 0.0
    assert status["metrics"]["individual_review_label_counts"]["inconclusive"] == 1
    assert status["metrics"]["individual_inconclusive_rate"] > 0.0
    assert "individual_inconclusive_rate_above_locked_maximum" in status["blockers"]


def test_v4_effectiveness_rejects_review_artifact_tampering(tmp_path: Path) -> None:
    evidence, preregistration = _v4_evidence(tmp_path)
    response = evidence / "review-artifacts" / "openai-response.json"
    response.write_text("tampered", encoding="utf-8")

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is False
    assert "v4_reviewer_artifact_invalid:openai:response_artifact_path" in status["validation_errors"]


def test_v4_effectiveness_requires_independent_git_verification_artifact(tmp_path: Path) -> None:
    evidence, preregistration = _v4_evidence(tmp_path)
    (evidence / "independent-git-verification.json").unlink()

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is False
    assert "v4_independent_git_verification_artifact_invalid" in status["validation_errors"]


def test_v4_effectiveness_recomputes_independent_git_file_rows(tmp_path: Path) -> None:
    evidence, preregistration = _v4_evidence(tmp_path)
    path = evidence / "independent-git-verification.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["apps"][0]["files"][0]["sha256"] = "f" * 64
    _write(path, payload)

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is False
    assert "v4_independent_git_verification_app_invalid:app-0" in status["validation_errors"]


def test_v4_source_row_validator_rejects_windows_prefix_collisions() -> None:
    rows = [
        {
            "path": "A/x.py",
            "mode": "100644",
            "git_blob_sha1": "1" * 40,
            "sha256": "2" * 64,
            "byte_count": 1,
        },
        {
            "path": "a/y.py",
            "mode": "100644",
            "git_blob_sha1": "3" * 40,
            "sha256": "4" * 64,
            "byte_count": 1,
        },
    ]

    with pytest.raises(ValueError, match="prefix collision"):
        scorer._validated_source_file_rows(rows)


def test_v4_source_row_validator_rejects_windows_aliases() -> None:
    row = {
        "path": "src/NUL.txt",
        "mode": "100644",
        "git_blob_sha1": "1" * 40,
        "sha256": "2" * 64,
        "byte_count": 1,
    }

    with pytest.raises(ValueError, match="reserved Windows"):
        scorer._validated_source_file_rows([row])


def test_v4_independent_verification_requires_explicit_path_policy(tmp_path: Path) -> None:
    evidence, preregistration = _v4_evidence(tmp_path)
    path = evidence / "independent-git-verification.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload.pop("path_policy")
    _write(path, payload)

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is False
    assert "v4_independent_git_verification_binding_invalid" in status["validation_errors"]


def test_v4_effectiveness_rejects_extra_source_receipt(tmp_path: Path) -> None:
    evidence, preregistration = _v4_evidence(tmp_path)
    _write(evidence / "source-receipts" / "extra.json", {"raw_returned": False})

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is False
    assert "v4_source_receipt_artifact_set_mismatch" in status["validation_errors"]


def test_v4_effectiveness_rejects_nested_source_receipt_directory(tmp_path: Path) -> None:
    evidence, preregistration = _v4_evidence(tmp_path)
    (evidence / "source-receipts" / "nested").mkdir()

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is False
    assert "v4_source_receipt_directory_invalid" in status["validation_errors"]


def test_v4_effectiveness_checks_runtime_source_watcher_against_receipt(tmp_path: Path) -> None:
    evidence, preregistration = _v4_evidence(tmp_path)
    receipt_path = evidence / "runtime-receipts" / "app-0-run1.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["post_source_tree_sha256"] = "f" * 64
    _write(receipt_path, receipt)

    campaign_path = evidence / "campaign.json"
    campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    campaign["apps"][0]["runs"][0]["runtime_receipt_sha256"] = hashlib.sha256(
        receipt_path.read_bytes()
    ).hexdigest()
    _write(campaign_path, campaign)

    verification_path = evidence / "independent-git-verification.json"
    verification = json.loads(verification_path.read_text(encoding="utf-8"))
    verification["campaign_sha256"] = hashlib.sha256(campaign_path.read_bytes()).hexdigest()
    _write(verification_path, verification)

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is False
    assert "v4_runtime_receipt_contract_invalid:app-0:run1" in status["validation_errors"]
