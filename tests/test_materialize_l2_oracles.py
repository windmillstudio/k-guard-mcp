from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "materialize_l2_oracles.py"
SPEC = importlib.util.spec_from_file_location("materialize_l2_oracles_test", SCRIPT)
assert SPEC and SPEC.loader
l2 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(l2)

_FIXTURE_IDENTITIES: dict[str, dict] = {}


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _git_bytes(root: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", *args], cwd=root, stdin=subprocess.DEVNULL, capture_output=True, check=True
    ).stdout


def _fixture_receipt(
    root: Path,
    *,
    repository_id: str,
    commit: str,
    commit_tree: str,
    porcelain_clean: bool | None = None,
) -> dict:
    paths = sorted(
        value.decode("utf-8")
        for value in _git_bytes(root, "ls-tree", "-r", "--name-only", "-z", "HEAD").split(b"\0")
        if value
    )
    files = []
    exact = True
    for relative in paths:
        raw_blob = _git_bytes(root, "show", f"HEAD:{relative}")
        physical = (root / relative).read_bytes()
        exact = exact and raw_blob == physical
        files.append(
            {
                "path": relative,
                "sha256": l2.sha256_bytes(raw_blob),
                "byte_count": len(raw_blob),
            }
        )
    source_tree = l2.sha256_bytes(l2.canonical_json_bytes({"files": files}))
    if porcelain_clean is None:
        porcelain_clean = _git_bytes(root, "status", "--porcelain=v1", "-z") == b""
    return {
        "schema": l2.SOURCE_RECEIPT_SCHEMA,
        "passed": exact,
        "repository_id": repository_id,
        "origin_repository_id": repository_id,
        "origin_repository_match": True,
        "commit": commit,
        "commit_match": True,
        "commit_object_hash_match": True,
        "commit_tree": commit_tree,
        "commit_tree_match": True,
        "tree_object_reconstruction_match": True,
        "index_tree_match": True,
        "source_worktree_clean": exact,
        "source_worktree_clean_method": "git_blob_sha256_file_set_plus_index_tree_v2",
        "physical_bytes_match_git_blobs": exact,
        "git_porcelain_clean": porcelain_clean,
        "git_repository_layout": "ordinary_non_shallow_standalone_clone",
        "git_object_format": "sha1",
        "git_fsck_strict_passed": True,
        "git_fsck_output_sha256": l2.sha256_bytes(b""),
        "source_tree_schema": "k_guard_materialized_source_tree.v1",
        "source_tree_sha256": source_tree,
        "scanner_visible_tree_contract": "regular-file paths and raw Git blob bytes",
        "file_count": len(files),
        "total_bytes": sum(row["byte_count"] for row in files),
        "files": files,
        "raw_returned": False,
    }


class _FixtureVerifier:
    @staticmethod
    def build_git_materialization_receipt(
        root: Path, *, expected_repository_id: str, expected_commit: str, expected_tree: str
    ) -> dict:
        return _fixture_receipt(
            root,
            repository_id=expected_repository_id,
            commit=expected_commit,
            commit_tree=expected_tree,
        )


def _app_files(app_id: str) -> dict[str, str]:
    if app_id == "juice-shop":
        return {
            "data/static/challenges.yml": """---
-
  name: 'Fixture API Challenge'
  category: 'Broken Access Control'
  description: 'Exploit an API authorization boundary.'
  difficulty: 3
  key: fixtureApiChallenge
"""
        }
    if app_id == "webgoat":
        return {
            "src/it/java/org/owasp/webgoat/integration/IDORIntegrationTest.java": """package org.owasp.webgoat.integration;
import org.junit.jupiter.api.Test;
class IDORIntegrationTest {
  @Test
  void exploitAnotherProfile() { /* official executable lesson test */ }
}
""",
            "src/it/java/org/owasp/webgoat/integration/AccessControlIntegrationTest.java": """package org.owasp.webgoat.integration;
import org.junit.jupiter.api.Test;
class AccessControlIntegrationTest {
  @Test
  void testLesson() { /* official executable lesson test */ }
}
""",
        }
    if app_id == "nodegoat":
        return {
            "app/views/tutorial/a7.html": """{% block title %}Missing Function Access Control{% endblock %}
<p>This vulnerable route lets a non-admin access an admin function.</p>
"""
        }
    if app_id == "pygoat":
        return {
            "challenge/challenge.json": json.dumps(
                [{"name": "do-it-fast", "description": "login and obtain the flag"}],
                indent=2,
            )
            + "\n"
        }
    if app_id == "crapi":
        return {
            "docs/challenges.md": """# Challenges

## BOLA Vulnerabilities

### Challenge 1 - Access another user's vehicle

Exploit the API to read another user's vehicle.
"""
        }
    if app_id == "wrongsecrets":
        return {
            "src/test/java/org/owasp/wrongsecrets/challenges/docker/Challenge1Test.java": """package org.owasp.wrongsecrets.challenges.docker;
import org.junit.jupiter.api.Test;
class Challenge1Test {
  @Test
  void rightAnswerShouldSolveChallenge() { /* official executable challenge test */ }
}
"""
        }
    raise AssertionError(app_id)


@pytest.fixture(scope="module")
def corpus(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, Path]:
    tmp_path = tmp_path_factory.mktemp("l2-oracle-corpus")
    sources = tmp_path / "sources"
    for app_id in l2.EXPECTED_APPS:
        root = sources / app_id
        root.mkdir(parents=True)
        _git(root, "init", "--initial-branch=main")
        _git(root, "config", "user.email", "l2@example.invalid")
        _git(root, "config", "user.name", "L2 Fixture")
        _git(root, "config", "core.autocrlf", "false")
        _git(root, "remote", "add", "origin", f"https://github.com/k-guard-fixtures/{app_id}.git")
        for relative, content in _app_files(app_id).items():
            _write(root / relative, content)
        _write(root / "LICENSE", f"fixture license for {app_id}\n")
        _git(root, "add", "--all")
        _git(root, "commit", "-m", f"bind {app_id}")
    receipt_dir = tmp_path / "source-receipts"
    receipt_dir.mkdir()
    admission_rows = []
    _FIXTURE_IDENTITIES.clear()
    for app_id in l2.EXPECTED_APPS:
        root = sources / app_id
        repository_id = f"k-guard-fixtures/{app_id}"
        commit = _git(root, "rev-parse", "HEAD")
        commit_tree = _git(root, "rev-parse", "HEAD^{tree}")
        receipt = _fixture_receipt(
            root,
            repository_id=repository_id,
            commit=commit,
            commit_tree=commit_tree,
        )
        receipt_raw = l2.canonical_json_bytes(receipt)
        receipt_sha256 = l2.sha256_bytes(receipt_raw)
        (receipt_dir / f"{app_id}.json").write_bytes(receipt_raw)
        license_raw = (root / "LICENSE").read_bytes()
        license_binding = {
            "path": "LICENSE",
            "spdx": "MIT",
            "sha256": l2.sha256_bytes(license_raw),
            "byte_count": len(license_raw),
        }
        identity = {
            "repository_id": repository_id,
            "commit": commit,
            "commit_tree": commit_tree,
            "source_tree_sha256": receipt["source_tree_sha256"],
            "receipt_sha256": receipt_sha256,
            "receipt_semantic_sha256": l2._source_receipt_semantic_sha256(receipt),
            "license": license_binding,
        }
        _FIXTURE_IDENTITIES[app_id] = identity
        lineage_id = l2.sha256_bytes(
            ("k_guard_l2_lineage.v1\0" + "\0".join(
                (app_id, repository_id, commit, commit_tree, receipt["source_tree_sha256"])
            )).encode("utf-8")
        )
        admission_rows.append(
            {
                "app_id": app_id,
                **identity,
                "lineage_id": lineage_id,
                "source_admission": "PASS",
                "scanner_output_observed": False,
            }
        )
    admission = {
        "schema": "k_guard_l2_source_materialization.v1",
        "apps": admission_rows,
        "scanner_output_observed": False,
    }
    (tmp_path / "source-admission.json").write_bytes(l2.canonical_json_bytes(admission))
    calculator = tmp_path / "calculator"
    calculator.mkdir()
    _git(calculator, "init", "--initial-branch=main")
    _git(calculator, "config", "user.email", "calculator@example.invalid")
    _git(calculator, "config", "user.name", "Calculator Fixture")
    _git(calculator, "config", "core.autocrlf", "false")
    _git(
        calculator,
        "remote",
        "add",
        "origin",
        "https://github.com/k-guard-fixtures/cvss-v4-calculator.git",
    )
    for name in l2.LOCKED_CALCULATOR_CORE_FILES:
        _write(calculator / name, f"export const fixture_{name.replace('.', '_')} = true;\n")
    _write(calculator / "LICENSE", "fixture calculator license\n")
    _git(calculator, "add", "--all")
    _git(calculator, "commit", "-m", "bind calculator")
    calculator_receipt = _fixture_receipt(
        calculator,
        repository_id="k-guard-fixtures/cvss-v4-calculator",
        commit=_git(calculator, "rev-parse", "HEAD"),
        commit_tree=_git(calculator, "rev-parse", "HEAD^{tree}"),
    )
    calculator_receipt_path = tmp_path / "calculator-receipt.json"
    calculator_receipt_path.write_bytes(l2.canonical_json_bytes(calculator_receipt))
    return sources, calculator, calculator_receipt_path


@pytest.fixture(scope="module", autouse=True)
def bind_fixture_source_contract(corpus: tuple[Path, Path, Path]) -> None:
    patcher = pytest.MonkeyPatch()
    sources, calculator, calculator_receipt_path = corpus
    contract = SimpleNamespace(EXPECTED_IDENTITIES=_FIXTURE_IDENTITIES)
    patcher.setattr(
        l2,
        "LOCKED_SOURCE_ADMISSION_SHA256",
        l2.sha256_bytes((sources.parent / "source-admission.json").read_bytes()),
    )
    patcher.setattr(l2, "LOCKED_SOURCE_CONTRACT_SHA256", "c" * 64)
    patcher.setattr(l2, "LOCKED_SOURCE_VERIFIER_SHA256", "d" * 64)
    patcher.setattr(
        l2,
        "_load_authoritative_source_modules",
        lambda: (contract, _FixtureVerifier, "c" * 64, "d" * 64),
    )
    calculator_receipt = json.loads(calculator_receipt_path.read_text(encoding="utf-8"))
    calculator_files = calculator_receipt["files"]
    calculator_files_by_path = {row["path"]: row for row in calculator_files}
    patcher.setattr(
        l2,
        "LOCKED_CALCULATOR_REPOSITORY_ID",
        "k-guard-fixtures/cvss-v4-calculator",
    )
    patcher.setattr(l2, "LOCKED_CALCULATOR_COMMIT", calculator_receipt["commit"])
    patcher.setattr(l2, "LOCKED_CALCULATOR_TREE", calculator_receipt["commit_tree"])
    patcher.setattr(
        l2,
        "LOCKED_CALCULATOR_SOURCE_TREE_SHA256",
        calculator_receipt["source_tree_sha256"],
    )
    patcher.setattr(
        l2,
        "LOCKED_CALCULATOR_RECEIPT_SHA256",
        l2.sha256_bytes(calculator_receipt_path.read_bytes()),
    )
    patcher.setattr(
        l2,
        "LOCKED_CALCULATOR_FILE_MANIFEST_SHA256",
        l2.sha256_bytes(l2.canonical_json_bytes({"files": calculator_files})),
    )
    patcher.setattr(l2, "LOCKED_CALCULATOR_FILE_COUNT", len(calculator_files))
    patcher.setattr(
        l2,
        "LOCKED_CALCULATOR_TOTAL_BYTES",
        sum(row["byte_count"] for row in calculator_files),
    )
    license_row = calculator_files_by_path["LICENSE"]
    patcher.setattr(
        l2,
        "LOCKED_CALCULATOR_LICENSE",
        {
            "path": "LICENSE",
            "spdx": "MIT",
            "sha256": license_row["sha256"],
            "byte_count": license_row["byte_count"],
        },
    )
    patcher.setattr(
        l2,
        "LOCKED_CALCULATOR_CORE_FILES",
        {
            name: calculator_files_by_path[name]["sha256"]
            for name in l2.LOCKED_CALCULATOR_CORE_FILES
        },
    )
    yield
    patcher.undo()


_PAYLOAD_CACHE: dict[str, dict] = {}


def _materialize(corpus: tuple[Path, Path, Path]) -> dict:
    sources, calculator, calculator_receipt = corpus
    key = str(sources)
    if key not in _PAYLOAD_CACHE:
        _PAYLOAD_CACHE[key] = l2.materialize_l2_oracles(
            sources, calculator, calculator_receipt
        )
    return copy.deepcopy(_PAYLOAD_CACHE[key])


def _materialize_direct(corpus: tuple[Path, Path, Path]) -> dict:
    sources, calculator, calculator_receipt = corpus
    return l2.materialize_l2_oracles(sources, calculator, calculator_receipt)


def _webgoat_candidate(payload: dict, test_class: str = "IDORIntegrationTest") -> dict:
    return next(
        row
        for row in payload["retained_candidates"]
        if row["app_id"] == "webgoat" and test_class in row["root_cause"]
    )


def _validate(
    payload: dict,
    corpus: tuple[Path, Path, Path],
    *,
    execution_evidence_path: Path | None = None,
    cwe_evidence_path: Path | None = None,
    cvss_evidence_path: Path | None = None,
    state_reset_evidence_path: Path | None = None,
    state_reset_positive_receipt_path: Path | None = None,
    state_reset_negative_receipt_path: Path | None = None,
    missing_function_ac_execution_evidence_path: Path | None = None,
    missing_function_ac_cwe_evidence_path: Path | None = None,
    missing_function_ac_cvss_evidence_path: Path | None = None,
    missing_function_ac_state_reset_evidence_path: Path | None = None,
    missing_function_ac_state_reset_positive_receipt_path: Path | None = None,
    missing_function_ac_state_reset_negative_receipt_path: Path | None = None,
) -> None:
    sources, calculator, calculator_receipt = corpus
    l2.validate_registry(
        payload,
        sources,
        calculator,
        calculator_receipt,
        execution_evidence_path=execution_evidence_path,
        cwe_evidence_path=cwe_evidence_path,
        cvss_evidence_path=cvss_evidence_path,
        state_reset_evidence_path=state_reset_evidence_path,
        state_reset_positive_receipt_path=state_reset_positive_receipt_path,
        state_reset_negative_receipt_path=state_reset_negative_receipt_path,
        missing_function_ac_execution_evidence_path=missing_function_ac_execution_evidence_path,
        missing_function_ac_cwe_evidence_path=missing_function_ac_cwe_evidence_path,
        missing_function_ac_cvss_evidence_path=missing_function_ac_cvss_evidence_path,
        missing_function_ac_state_reset_evidence_path=(
            missing_function_ac_state_reset_evidence_path
        ),
        missing_function_ac_state_reset_positive_receipt_path=(
            missing_function_ac_state_reset_positive_receipt_path
        ),
        missing_function_ac_state_reset_negative_receipt_path=(
            missing_function_ac_state_reset_negative_receipt_path
        ),
    )


def _complete_command(name: str) -> dict:
    digest = l2.sha256_bytes(name.encode("utf-8"))
    return {
        "argv": ["python", "-m", "pytest", name],
        "cwd": ".",
        "kind": "http",
        "network_policy": "offline",
        "expected_exit_code": 0,
        "expected_http_status": 200,
        "expected_body_sha256": digest,
        "expected_result_sha256": digest,
    }


def _complete_process_command(name: str, *, exit_code: int = 0) -> dict:
    digest = l2.sha256_bytes(name.encode("utf-8"))
    return {
        "argv": ["python", "-m", "pytest", name],
        "cwd": ".",
        "kind": "process",
        "network_policy": "offline",
        "expected_exit_code": exit_code,
        "expected_http_status": None,
        "expected_body_sha256": None,
        "expected_result_sha256": digest,
    }


def _write_execution_evidence(
    corpus: tuple[Path, Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, dict]:
    baseline = _materialize(corpus)
    candidate = _webgoat_candidate(baseline)
    receipt = next(row for row in baseline["source_receipts"] if row["app_id"] == "webgoat")
    adapter_sha256 = "a" * 64
    replay_sha256 = "b" * 64
    monkeypatch.setattr(
        l2,
        "_load_webgoat_execution_evidence_adapter",
        lambda: (SimpleNamespace(validate_execution_evidence=lambda _payload: None), adapter_sha256, replay_sha256),
    )
    source = candidate["official_source"]
    selector = {
        "root_cause": candidate["root_cause"],
        "source_path": source["path"],
        "source_line": source["line"],
        "source_content_sha256": source["content_sha256"],
        "source_root_cause_identity": candidate["source_root_cause_identity"],
        "scenario_id": candidate["scenario_id"],
        "raw_returned": False,
    }
    payload = {
        "schema": l2.WEBGOAT_EXECUTION_EVIDENCE_SCHEMA,
        "tool_provenance": {
            "adapter_sha256": adapter_sha256,
            "replay_contract_sha256": replay_sha256,
            "raw_returned": False,
        },
        "source": {
            "app_id": "webgoat",
            "repository_id": receipt["repository_id"],
            "commit": receipt["commit"],
            "commit_tree": receipt["commit_tree"],
            "source_tree_sha256": receipt["source_tree_sha256"],
            "source_receipt_sha256": receipt["receipt_sha256"],
            "lineage_id": receipt["lineage_id"],
            "selector": selector,
            "raw_returned": False,
        },
        "oracle": _complete_process_command("webgoat-positive"),
        "negative_control": _complete_process_command("webgoat-negative", exit_code=1),
        "state_reset_evidence": {"registry_state_reset_admitted": False, "raw_returned": False},
        "claim_boundary": {
            "execution_result_pair_proven": True,
            "source_bound_execution_selector_proven": True,
            "process_oracle_contract_proven": True,
            "state_reset_evidence_proven": True,
            "registry_state_reset_admitted": False,
            "generated_control_pair_only": True,
            "independent_upstream_fixed_revision_proven": False,
            "scanner_accuracy_proven": False,
            "severity_or_cwe_admitted": False,
            "tp_fp_fn_admitted": False,
            "registry_evidence_integrated": False,
            "l2_gate_admitted": False,
            "release_gate_admitted": False,
            "raw_returned": False,
        },
        "raw_returned": False,
    }
    path = tmp_path / "webgoat-execution-evidence.json"
    path.write_bytes(l2.canonical_json_bytes(payload))
    return path, payload


def _write_missing_function_ac_evidence(
    corpus: tuple[Path, Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, dict, dict]:
    baseline = _materialize(corpus)
    candidate = _webgoat_candidate(baseline, "AccessControlIntegrationTest")
    receipt = next(row for row in baseline["source_receipts"] if row["app_id"] == "webgoat")
    execution_adapter_sha256 = "1" * 64
    replay_sha256 = "2" * 64
    cwe_adapter_sha256 = "3" * 64
    monkeypatch.setattr(
        l2,
        "_load_webgoat_missing_function_ac_execution_evidence_adapter",
        lambda: (
            SimpleNamespace(validate_execution_evidence=lambda _payload: None),
            execution_adapter_sha256,
            replay_sha256,
        ),
    )
    monkeypatch.setattr(
        l2,
        "_load_webgoat_missing_function_ac_cwe_evidence_adapter",
        lambda: (SimpleNamespace(validate_cwe_evidence=lambda _payload: None), cwe_adapter_sha256),
    )
    source = candidate["official_source"]
    selector = {
        "root_cause": candidate["root_cause"],
        "source_path": source["path"],
        "source_line": source["line"],
        "source_content_sha256": source["content_sha256"],
        "source_root_cause_identity": candidate["source_root_cause_identity"],
        "scenario_id": candidate["scenario_id"],
        "raw_returned": False,
    }
    evidence_source = {
        "app_id": "webgoat",
        "repository_id": receipt["repository_id"],
        "commit": receipt["commit"],
        "commit_tree": receipt["commit_tree"],
        "source_tree_sha256": receipt["source_tree_sha256"],
        "source_receipt_sha256": receipt["observed_receipt_sha256"],
        "source_receipt_semantic_sha256": receipt["receipt_semantic_sha256"],
        "lineage_id": receipt["lineage_id"],
        "selector": selector,
        "raw_returned": False,
    }
    execution = {
        "schema": l2.WEBGOAT_MISSING_FUNCTION_AC_EXECUTION_EVIDENCE_SCHEMA,
        "tool_provenance": {
            "adapter_sha256": execution_adapter_sha256,
            "replay_contract_sha256": replay_sha256,
            "raw_returned": False,
        },
        "source": copy.deepcopy(evidence_source),
        "execution_pair": {"fixture": "pair", "raw_returned": False},
        "oracle": _complete_process_command("missing-function-ac-positive"),
        "negative_control": _complete_process_command("missing-function-ac-negative", exit_code=1),
        "state_reset_evidence": {
            "registry_state_reset_admitted": False,
            "raw_returned": False,
        },
        "claim_boundary": {
            "execution_result_pair_proven": True,
            "source_bound_execution_selector_proven": True,
            "process_oracle_contract_proven": True,
            "state_reset_cleanup_chain_proven": True,
            "generated_control_pair_only": True,
            "independent_upstream_fixed_revision_proven": False,
            "scanner_accuracy_proven": False,
            "severity_or_cwe_admitted": False,
            "tp_fp_fn_admitted": False,
            "registry_evidence_integrated": False,
            "l2_gate_admitted": False,
            "release_gate_admitted": False,
            "raw_returned": False,
        },
        "admission_blockers": ["fixture"],
        "adapter_status": "EXECUTION_EVIDENCE_PASS",
        "release_gate_passed": False,
        "raw_returned": False,
    }
    cwe = {
        "schema": l2.WEBGOAT_MISSING_FUNCTION_AC_CWE_EVIDENCE_SCHEMA,
        "tool_provenance": {
            "adapter_sha256": cwe_adapter_sha256,
            "raw_returned": False,
        },
        "source": copy.deepcopy(evidence_source),
        "classification": {
            "cwe": {
                "id": "CWE-266",
                "reference_url": "https://cwe.example.invalid/266",
                "mapping_scope": "pinned_webgoat_benchmark_scenario",
                "raw_returned": False,
            },
            "mechanism_truth": "present",
            "cvss_v4": None,
            "expected_disposition": None,
            "severity_status": "DEFERRED_NO_SOURCE_BOUND_CVSS_PROFILE",
            "source_evidence": {
                "test": {
                    "path": selector["source_path"],
                    "content_sha256": selector["source_content_sha256"],
                    "anchor_ids": ["fixture-test"],
                    "raw_returned": False,
                },
                "implementation": {
                    "path": "fixture/implementation.java",
                    "content_sha256": "4" * 64,
                    "anchor_ids": ["fixture-implementation"],
                    "raw_returned": False,
                },
                "raw_returned": False,
            },
            "raw_returned": False,
        },
        "claim_boundary": {
            "source_bound_cwe_mapping_supported": True,
            "source_bound_mechanism_truth_supported": True,
            "source_bound_cvss_profile_proven": False,
            "customer_deployment_severity_admitted": False,
            "scanner_accuracy_proven": False,
            "tp_fp_fn_admitted": False,
            "registry_evidence_integrated": False,
            "l2_gate_admitted": False,
            "release_gate_admitted": False,
            "raw_returned": False,
        },
        "admission_blockers": ["fixture"],
        "adapter_status": "CWE_MECHANISM_EVIDENCE_PASS",
        "release_gate_passed": False,
        "raw_returned": False,
    }
    execution_path = tmp_path / "missing-function-ac-execution-evidence.json"
    cwe_path = tmp_path / "missing-function-ac-cwe-evidence.json"
    execution_path.write_bytes(l2.canonical_json_bytes(execution))
    cwe_path.write_bytes(l2.canonical_json_bytes(cwe))
    return execution_path, cwe_path, execution, cwe


def _write_missing_function_ac_state_reset_evidence(
    corpus: tuple[Path, Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, Path, Path, Path, dict, dict]:
    execution_path, cwe_path, execution, _cwe = _write_missing_function_ac_evidence(
        corpus, tmp_path, monkeypatch
    )
    positive_path = tmp_path / "missing-function-ac-positive-receipt.json"
    positive_path.write_bytes(
        l2.canonical_json_bytes({"fixture": "positive", "raw_returned": False})
    )
    negative_path = tmp_path / "missing-function-ac-negative-receipt.json"
    negative_path.write_bytes(
        l2.canonical_json_bytes({"fixture": "negative", "raw_returned": False})
    )
    adapter_sha256 = "4" * 64
    registry_sha256 = l2.sha256_bytes((ROOT / "scripts" / "materialize_l2_oracles.py").read_bytes())
    state_reset = {
        "argv": ["python", "scripts/verify-missing-function-ac-reset.py"],
        "cwd": ".",
        "kind": "process",
        "network_policy": "offline",
        "expected_exit_code": 0,
        "expected_http_status": None,
        "expected_body_sha256": None,
        "expected_result_sha256": "5" * 64,
    }
    state_evidence = {
        "schema": l2.WEBGOAT_MISSING_FUNCTION_AC_STATE_RESET_EVIDENCE_SCHEMA,
        "tool_provenance": {
            "adapter_sha256": adapter_sha256,
            "execution_adapter_sha256": "1" * 64,
            "replay_contract_sha256": "2" * 64,
            "registry_contract_sha256": registry_sha256,
            "raw_returned": False,
        },
        "source": copy.deepcopy(execution["source"]),
        "inputs": {
            "execution_evidence_sha256": l2.sha256_bytes(execution_path.read_bytes()),
            "positive_execution_receipt_sha256": l2.sha256_bytes(positive_path.read_bytes()),
            "negative_control_receipt_sha256": l2.sha256_bytes(negative_path.read_bytes()),
            "raw_returned": False,
        },
        "reset_proof": {"fixture": "reset", "raw_returned": False},
        "state_reset": state_reset,
        "claim_boundary": {
            "state_reset_cleanup_chain_proven": True,
            "registry_state_reset_admitted": False,
            "registry_scenario_admitted": False,
            "scanner_accuracy_proven": False,
            "severity_or_cwe_admitted": False,
            "tp_fp_fn_admitted": False,
            "l2_gate_admitted": False,
            "release_gate_admitted": False,
            "raw_returned": False,
        },
        "admission_blockers": ["fixture"],
        "adapter_status": "STATE_RESET_EVIDENCE_PASS",
        "release_gate_passed": False,
        "raw_returned": False,
    }
    state_path = tmp_path / "missing-function-ac-state-reset-evidence.json"
    state_path.write_bytes(l2.canonical_json_bytes(state_evidence))
    fake_adapter = SimpleNamespace(
        derive_state_reset_evidence=lambda *_args: copy.deepcopy(state_evidence),
        validate_state_reset_evidence=lambda _payload: None,
    )
    monkeypatch.setattr(
        l2,
        "_load_webgoat_missing_function_ac_state_reset_evidence_adapter",
        lambda: (fake_adapter, adapter_sha256),
    )
    return execution_path, cwe_path, state_path, positive_path, negative_path, execution, state_evidence


def _write_missing_function_ac_cvss_evidence_for_paths(
    corpus: tuple[Path, Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    execution_path: Path,
    cwe_path: Path,
) -> tuple[Path, dict]:
    baseline = _materialize(corpus)
    candidate = _webgoat_candidate(baseline, "AccessControlIntegrationTest")
    _sources, calculator, calculator_receipt = corpus
    calculator_binding = l2._verify_calculator_source(calculator, calculator_receipt)
    calculator_binding_sha256 = l2.sha256_bytes(l2.canonical_json_bytes(calculator_binding))
    source = candidate["official_source"]
    selector = {
        "root_cause": candidate["root_cause"],
        "source_path": source["path"],
        "source_line": source["line"],
        "source_content_sha256": source["content_sha256"],
        "source_root_cause_identity": candidate["source_root_cause_identity"],
        "scenario_id": candidate["scenario_id"],
        "raw_returned": False,
    }
    adapter_sha256 = "6" * 64
    payload = {
        "schema": l2.WEBGOAT_MISSING_FUNCTION_AC_CVSS_EVIDENCE_SCHEMA,
        "tool_provenance": {
            "adapter_sha256": adapter_sha256,
            "registry_contract_sha256": l2.sha256_bytes(Path(l2.__file__).read_bytes()),
            "raw_returned": False,
        },
        "source": {
            "selector": selector,
            "cwe_evidence_sha256": l2.sha256_bytes(cwe_path.read_bytes()),
            "cwe_adapter_sha256": "3" * 64,
            "execution_evidence_sha256": l2.sha256_bytes(execution_path.read_bytes()),
            "execution_adapter_sha256": "1" * 64,
            "raw_returned": False,
        },
        "cvss_profile": {
            "scope": "pinned_webgoat_benchmark_scenario",
            "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
            "score": "7.1",
            "severity": "high",
            "expected_disposition": "warn",
            "metric_evidence": {},
            "calculator": {
                "id": l2.DEFAULT_CALCULATOR_ID,
                "binding_sha256": calculator_binding_sha256,
                "source_receipt_sha256": l2.LOCKED_CALCULATOR_RECEIPT_SHA256,
                "raw_returned": False,
            },
            "raw_returned": False,
        },
        "claim_boundary": {
            "benchmark_cvss_profile_proven": True,
            "customer_deployment_severity_admitted": False,
            "registry_evidence_integrated": False,
            "scanner_accuracy_proven": False,
            "tp_fp_fn_admitted": False,
            "l2_gate_admitted": False,
            "release_gate_admitted": False,
            "raw_returned": False,
        },
        "admission_blockers": ["registry_evidence_integration_missing"],
        "adapter_status": "CVSS_PROFILE_EVIDENCE_PASS",
        "release_gate_passed": False,
        "raw_returned": False,
    }
    fake_adapter = SimpleNamespace(
        derive_cvss_evidence=lambda *_args: copy.deepcopy(payload),
        validate_cvss_evidence=lambda _payload: None,
    )
    monkeypatch.setattr(
        l2,
        "_load_webgoat_missing_function_ac_cvss_evidence_adapter",
        lambda: (fake_adapter, adapter_sha256),
    )
    path = tmp_path / "missing-function-ac-cvss-evidence.json"
    path.write_bytes(l2.canonical_json_bytes(payload))
    return path, payload


def _write_missing_function_ac_cvss_evidence(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, Path, dict, dict]:
    execution_path, cwe_path, execution, cwe = _write_missing_function_ac_evidence(
        corpus, tmp_path, monkeypatch
    )
    cvss_path, cvss = _write_missing_function_ac_cvss_evidence_for_paths(
        corpus, tmp_path, monkeypatch, execution_path, cwe_path
    )
    return execution_path, cwe_path, cvss_path, execution, cvss


def _write_cvss_evidence(
    corpus: tuple[Path, Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, Path, dict]:
    execution_path, _execution = _write_execution_evidence(corpus, tmp_path, monkeypatch)
    baseline = _materialize(corpus)
    candidate = _webgoat_candidate(baseline)
    sources, calculator, calculator_receipt = corpus
    calculator_binding = l2._verify_calculator_source(calculator, calculator_receipt)
    calculator_binding_sha256 = l2.sha256_bytes(l2.canonical_json_bytes(calculator_binding))
    source = candidate["official_source"]
    selector = {
        "root_cause": candidate["root_cause"],
        "source_path": source["path"],
        "source_line": source["line"],
        "source_content_sha256": source["content_sha256"],
        "source_root_cause_identity": candidate["source_root_cause_identity"],
        "scenario_id": candidate["scenario_id"],
        "raw_returned": False,
    }
    cwe_path = tmp_path / "webgoat-cwe-evidence.json"
    cwe_path.write_bytes(l2.canonical_json_bytes({"fixture": "cwe", "raw_returned": False}))
    cwe_sha256 = l2.sha256_bytes(cwe_path.read_bytes())
    adapter_sha256 = "e" * 64
    payload = {
        "schema": l2.WEBGOAT_CVSS_EVIDENCE_SCHEMA,
        "tool_provenance": {
            "adapter_sha256": adapter_sha256,
            "registry_contract_sha256": l2.sha256_bytes(Path(l2.__file__).read_bytes()),
            "raw_returned": False,
        },
        "source": {
            "selector": selector,
            "cwe_evidence_sha256": cwe_sha256,
            "cwe_adapter_sha256": "f" * 64,
            "execution_evidence_sha256": l2.sha256_bytes(execution_path.read_bytes()),
            "execution_adapter_sha256": "a" * 64,
            "raw_returned": False,
        },
        "cvss_profile": {
            "scope": "pinned_webgoat_benchmark_scenario",
            "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
            "score": "7.1",
            "severity": "high",
            "expected_disposition": "warn",
            "metric_evidence": {},
            "calculator": {
                "id": l2.DEFAULT_CALCULATOR_ID,
                "binding_sha256": calculator_binding_sha256,
                "source_receipt_sha256": l2.LOCKED_CALCULATOR_RECEIPT_SHA256,
                "raw_returned": False,
            },
            "raw_returned": False,
        },
        "claim_boundary": {
            "benchmark_cvss_profile_proven": True,
            "customer_deployment_severity_admitted": False,
            "registry_evidence_integrated": False,
            "scanner_accuracy_proven": False,
            "tp_fp_fn_admitted": False,
            "l2_gate_admitted": False,
            "release_gate_admitted": False,
            "raw_returned": False,
        },
        "admission_blockers": [
            "registry_evidence_integration_missing",
            "negative_control_missing",
            "state_reset_missing",
        ],
        "adapter_status": "CVSS_PROFILE_EVIDENCE_PASS",
        "release_gate_passed": False,
        "raw_returned": False,
    }
    expected_payload = copy.deepcopy(payload)
    cwe_payload = {
        "classification": {
            "cwe": {"id": "CWE-639"},
            "mechanism_truth": "present",
        }
    }
    adapter = SimpleNamespace(
        validate_cvss_evidence=lambda _payload: None,
        derive_cvss_evidence=lambda *_args: copy.deepcopy(expected_payload),
        _load_cwe_evidence=lambda _path: (copy.deepcopy(cwe_payload), cwe_sha256, "f" * 64),
    )
    monkeypatch.setattr(
        l2,
        "_load_webgoat_cvss_evidence_adapter",
        lambda: (adapter, adapter_sha256),
    )
    cvss_path = tmp_path / "webgoat-cvss-evidence.json"
    cvss_path.write_bytes(l2.canonical_json_bytes(payload))
    return execution_path, cwe_path, cvss_path, payload


def _write_state_reset_evidence(
    corpus: tuple[Path, Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, Path, Path, Path, Path, dict]:
    execution_path, cwe_path, cvss_path, _cvss = _write_cvss_evidence(
        corpus, tmp_path, monkeypatch
    )
    baseline = _materialize(corpus)
    candidate = _webgoat_candidate(baseline)
    receipt = next(row for row in baseline["source_receipts"] if row["app_id"] == "webgoat")
    source = candidate["official_source"]
    selector = {
        "root_cause": candidate["root_cause"],
        "source_path": source["path"],
        "source_line": source["line"],
        "source_content_sha256": source["content_sha256"],
        "source_root_cause_identity": candidate["source_root_cause_identity"],
        "scenario_id": candidate["scenario_id"],
        "raw_returned": False,
    }
    positive_path = tmp_path / "webgoat-positive-receipt.json"
    positive_path.write_bytes(l2.canonical_json_bytes({"fixture": "positive", "raw_returned": False}))
    negative_path = tmp_path / "webgoat-negative-receipt.json"
    negative_path.write_bytes(l2.canonical_json_bytes({"fixture": "negative", "raw_returned": False}))
    adapter_sha256 = "c" * 64
    payload = {
        "schema": l2.WEBGOAT_STATE_RESET_EVIDENCE_SCHEMA,
        "tool_provenance": {
            "adapter_sha256": adapter_sha256,
            "execution_adapter_sha256": "a" * 64,
            "replay_contract_sha256": "b" * 64,
            "registry_contract_sha256": l2.sha256_bytes(Path(l2.__file__).read_bytes()),
            "raw_returned": False,
        },
        "source": {
            "app_id": "webgoat",
            "repository_id": receipt["repository_id"],
            "commit": receipt["commit"],
            "commit_tree": receipt["commit_tree"],
            "source_tree_sha256": receipt["source_tree_sha256"],
            "source_receipt_sha256": receipt["receipt_sha256"],
            "lineage_id": receipt["lineage_id"],
            "selector": selector,
            "raw_returned": False,
        },
        "inputs": {
            "execution_evidence_sha256": l2.sha256_bytes(execution_path.read_bytes()),
            "positive_execution_receipt_sha256": l2.sha256_bytes(positive_path.read_bytes()),
            "negative_control_receipt_sha256": l2.sha256_bytes(negative_path.read_bytes()),
            "raw_returned": False,
        },
        "reset_proof": {"fixture": "cleanup", "raw_returned": False},
        "state_reset": _complete_process_command("webgoat-state-reset"),
        "claim_boundary": {
            "state_reset_cleanup_chain_proven": True,
            "registry_state_reset_admitted": False,
            "registry_scenario_admitted": False,
            "scanner_accuracy_proven": False,
            "severity_or_cwe_admitted": False,
            "tp_fp_fn_admitted": False,
            "l2_gate_admitted": False,
            "release_gate_admitted": False,
            "raw_returned": False,
        },
        "admission_blockers": ["evidence_signature_missing"],
        "adapter_status": "STATE_RESET_EVIDENCE_PASS",
        "release_gate_passed": False,
        "raw_returned": False,
    }
    expected_payload = copy.deepcopy(payload)
    adapter = SimpleNamespace(
        validate_state_reset_evidence=lambda _payload: None,
        derive_state_reset_evidence=lambda *_args: copy.deepcopy(expected_payload),
    )
    monkeypatch.setattr(
        l2,
        "_load_webgoat_state_reset_evidence_adapter",
        lambda: (adapter, adapter_sha256),
    )
    state_reset_path = tmp_path / "webgoat-state-reset-evidence.json"
    state_reset_path.write_bytes(l2.canonical_json_bytes(payload))
    return (
        execution_path,
        cwe_path,
        cvss_path,
        state_reset_path,
        positive_path,
        negative_path,
        payload,
    )


def test_materialization_is_deterministic_and_fail_closed(corpus: tuple[Path, Path, Path]) -> None:
    first = _materialize_direct(corpus)
    second = _materialize_direct(corpus)

    assert l2.canonical_json_bytes(first) == l2.canonical_json_bytes(second)
    assert first["phase_2_l2_status"] == "HOLD"
    assert first["release_gate_passed"] is False
    assert first["inventory_gate"] == "HOLD"
    assert first["oracle_replay"]["executed"] is False
    assert first["oracle_replay"]["status"] == "HOLD"
    assert first["claim_boundary"]["source_candidate_inventory_only"] is True
    assert first["claim_boundary"]["proves_machine_oracle_replay"] is False
    assert first["scanner_output_observed"] is False
    assert first["summary"]["candidate_count"] == 7
    assert first["summary"]["admitted_high_critical_scenario_count"] == 0
    assert first["summary"]["critical_scenario_count"] == 0
    assert first["summary"]["admitted_apps"] == []
    assert first["scenarios"] == []
    assert {row["app_id"] for row in first["retained_candidates"]} == set(l2.EXPECTED_APPS)
    assert all(row["scanner_output_observed"] is False for row in first["retained_candidates"])
    assert all(row["admission"] == "HOLD" and row["deficits"] for row in first["retained_candidates"])


def test_executable_test_rows_still_hold_without_result_and_negative_control(
    corpus: tuple[Path, Path, Path],
) -> None:
    payload = _materialize(corpus)
    rows = {row["app_id"]: row for row in payload["retained_candidates"] if row["app_id"] != "webgoat"}
    webgoat = _webgoat_candidate(payload)

    for row in (webgoat, rows["wrongsecrets"]):
        assert row["official_source"]["kind"] == "upstream_executable_test"
        assert row["oracle"]["kind"] == "process"
        assert row["oracle"]["network_policy"] == "isolated_loopback"
        assert "oracle_expected_result_sha256_missing" in row["deficits"]
        assert "oracle_expected_status_missing" not in row["deficits"]
        assert "oracle_expected_body_sha256_missing" not in row["deficits"]
        assert "negative_control_missing" in row["deficits"]
        assert "state_reset_missing" in row["deficits"]
    assert rows["wrongsecrets"]["mechanism_truth"] is None
    assert "mechanism_truth_not_present" in rows["wrongsecrets"]["deficits"]


def test_webgoat_execution_evidence_attaches_only_the_bound_process_pair(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    evidence_path, evidence = _write_execution_evidence(corpus, tmp_path, monkeypatch)

    payload = l2.materialize_l2_oracles(
        sources,
        calculator,
        calculator_receipt,
        execution_evidence_path=evidence_path,
    )

    row = _webgoat_candidate(payload)
    assert payload["execution_evidence"]["status"] == "ATTACHED"
    assert payload["execution_evidence"]["scenario_id"] == row["scenario_id"]
    assert row["oracle"] == evidence["oracle"]
    assert row["negative_control"] == evidence["negative_control"]
    assert row["state_reset"] is None
    assert "oracle_expected_result_sha256_missing" not in row["deficits"]
    assert "negative_control_missing" not in row["deficits"]
    assert "state_reset_missing" in row["deficits"]
    assert row["admission"] == "HOLD"
    assert payload["phase_2_l2_status"] == "HOLD"
    assert payload["release_gate_passed"] is False
    _validate(payload, corpus, execution_evidence_path=evidence_path)


def test_missing_function_ac_evidence_attaches_a_second_webgoat_scenario(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    execution_path, cwe_path, execution, cwe = _write_missing_function_ac_evidence(
        corpus, tmp_path, monkeypatch
    )

    payload = l2.materialize_l2_oracles(
        sources,
        calculator,
        calculator_receipt,
        missing_function_ac_execution_evidence_path=execution_path,
        missing_function_ac_cwe_evidence_path=cwe_path,
    )

    row = _webgoat_candidate(payload, "AccessControlIntegrationTest")
    idor = _webgoat_candidate(payload)
    attachment = payload["missing_function_ac_evidence"]
    assert attachment["status"] == "ATTACHED"
    assert attachment["execution_evidence_sha256"] == l2.sha256_bytes(execution_path.read_bytes())
    assert attachment["cwe_evidence_sha256"] == l2.sha256_bytes(cwe_path.read_bytes())
    assert attachment["scenario_id"] == row["scenario_id"]
    assert attachment["source_root_cause_identity"] == row["source_root_cause_identity"]
    assert attachment["registry_execution_attached"] is True
    assert attachment["registry_classification_attached"] is True
    assert attachment["registry_scenario_admitted"] is False
    assert row["oracle"] == execution["oracle"]
    assert row["negative_control"] == execution["negative_control"]
    assert row["cwe"] == "CWE-266"
    assert row["mechanism_truth"] == "present"
    assert row["expected_disposition"] is None
    assert row["state_reset"] is None
    assert row["deficits"] == [
        "cvss_v4_high_critical_missing",
        "expected_disposition_missing",
        "state_reset_missing",
    ]
    assert row["admission"] == "HOLD"
    assert idor["cwe"] is None
    assert idor["oracle"]["expected_result_sha256"] is None
    assert payload["scenarios"] == []
    assert payload["phase_2_l2_status"] == "HOLD"
    assert payload["release_gate_passed"] is False
    _validate(
        payload,
        corpus,
        missing_function_ac_execution_evidence_path=execution_path,
        missing_function_ac_cwe_evidence_path=cwe_path,
    )


def test_missing_function_ac_state_reset_evidence_removes_only_the_bound_reset_deficit(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    (
        execution_path,
        cwe_path,
        state_reset_path,
        positive_receipt_path,
        negative_receipt_path,
        _execution,
        state_reset,
    ) = _write_missing_function_ac_state_reset_evidence(corpus, tmp_path, monkeypatch)

    payload = l2.materialize_l2_oracles(
        sources,
        calculator,
        calculator_receipt,
        missing_function_ac_execution_evidence_path=execution_path,
        missing_function_ac_cwe_evidence_path=cwe_path,
        missing_function_ac_state_reset_evidence_path=state_reset_path,
        missing_function_ac_state_reset_positive_receipt_path=positive_receipt_path,
        missing_function_ac_state_reset_negative_receipt_path=negative_receipt_path,
    )

    row = _webgoat_candidate(payload, "AccessControlIntegrationTest")
    attachment = payload["missing_function_ac_evidence"]
    assert attachment["registry_execution_attached"] is True
    assert attachment["registry_classification_attached"] is True
    assert attachment["registry_state_reset_attached"] is True
    assert attachment["state_reset_evidence_sha256"] == l2.sha256_bytes(state_reset_path.read_bytes())
    assert attachment["state_reset_positive_execution_receipt_sha256"] == l2.sha256_bytes(
        positive_receipt_path.read_bytes()
    )
    assert attachment["state_reset_negative_control_receipt_sha256"] == l2.sha256_bytes(
        negative_receipt_path.read_bytes()
    )
    assert row["state_reset"] == state_reset["state_reset"]
    assert row["deficits"] == ["cvss_v4_high_critical_missing", "expected_disposition_missing"]
    assert row["admission"] == "HOLD"
    assert payload["phase_2_l2_status"] == "HOLD"
    assert payload["release_gate_passed"] is False
    _validate(
        payload,
        corpus,
        missing_function_ac_execution_evidence_path=execution_path,
        missing_function_ac_cwe_evidence_path=cwe_path,
        missing_function_ac_state_reset_evidence_path=state_reset_path,
        missing_function_ac_state_reset_positive_receipt_path=positive_receipt_path,
        missing_function_ac_state_reset_negative_receipt_path=negative_receipt_path,
    )


def test_missing_function_ac_cvss_evidence_removes_only_cvss_and_disposition_deficits(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    execution_path, cwe_path, cvss_path, _execution, cvss = _write_missing_function_ac_cvss_evidence(
        corpus, tmp_path, monkeypatch
    )

    payload = l2.materialize_l2_oracles(
        sources,
        calculator,
        calculator_receipt,
        missing_function_ac_execution_evidence_path=execution_path,
        missing_function_ac_cwe_evidence_path=cwe_path,
        missing_function_ac_cvss_evidence_path=cvss_path,
    )

    row = _webgoat_candidate(payload, "AccessControlIntegrationTest")
    attachment = payload["missing_function_ac_evidence"]
    assert attachment["registry_cvss_attached"] is True
    assert attachment["cvss_evidence_sha256"] == l2.sha256_bytes(cvss_path.read_bytes())
    assert row["cvss_v4"] == {
        "vector": cvss["cvss_profile"]["vector"],
        "score": "7.1",
        "severity": "high",
        "calculator_id": l2.DEFAULT_CALCULATOR_ID,
        "calculator_binding_sha256": payload["calculator"]["binding_sha256"],
        "source": "source_bound_benchmark_profile",
    }
    assert row["expected_disposition"] == "warn"
    assert row["state_reset"] is None
    assert row["deficits"] == ["state_reset_missing"]
    assert row["admission"] == "HOLD"
    assert payload["scenarios"] == []
    assert payload["phase_2_l2_status"] == "HOLD"
    assert payload["release_gate_passed"] is False
    _validate(
        payload,
        corpus,
        missing_function_ac_execution_evidence_path=execution_path,
        missing_function_ac_cwe_evidence_path=cwe_path,
        missing_function_ac_cvss_evidence_path=cvss_path,
    )


def test_missing_function_ac_cvss_and_state_reset_admit_only_the_bound_candidate(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    (
        execution_path,
        cwe_path,
        state_reset_path,
        positive_receipt_path,
        negative_receipt_path,
        _execution,
        state_reset,
    ) = _write_missing_function_ac_state_reset_evidence(corpus, tmp_path, monkeypatch)
    cvss_path, _cvss = _write_missing_function_ac_cvss_evidence_for_paths(
        corpus, tmp_path, monkeypatch, execution_path, cwe_path
    )

    payload = l2.materialize_l2_oracles(
        sources,
        calculator,
        calculator_receipt,
        missing_function_ac_execution_evidence_path=execution_path,
        missing_function_ac_cwe_evidence_path=cwe_path,
        missing_function_ac_cvss_evidence_path=cvss_path,
        missing_function_ac_state_reset_evidence_path=state_reset_path,
        missing_function_ac_state_reset_positive_receipt_path=positive_receipt_path,
        missing_function_ac_state_reset_negative_receipt_path=negative_receipt_path,
    )

    row = _webgoat_candidate(payload, "AccessControlIntegrationTest")
    idor = _webgoat_candidate(payload)
    assert row["state_reset"] == state_reset["state_reset"]
    assert row["deficits"] == []
    assert row["admission"] == "PASS"
    assert payload["scenarios"] == [row]
    assert idor["admission"] == "HOLD"
    assert payload["phase_2_l2_status"] == "HOLD"
    assert payload["release_gate_passed"] is False
    _validate(
        payload,
        corpus,
        missing_function_ac_execution_evidence_path=execution_path,
        missing_function_ac_cwe_evidence_path=cwe_path,
        missing_function_ac_cvss_evidence_path=cvss_path,
        missing_function_ac_state_reset_evidence_path=state_reset_path,
        missing_function_ac_state_reset_positive_receipt_path=positive_receipt_path,
        missing_function_ac_state_reset_negative_receipt_path=negative_receipt_path,
    )


def test_missing_function_ac_cvss_evidence_requires_the_same_input_chain_to_revalidate(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    execution_path, cwe_path, cvss_path, _execution, _cvss = _write_missing_function_ac_cvss_evidence(
        corpus, tmp_path, monkeypatch
    )
    payload = l2.materialize_l2_oracles(
        sources,
        calculator,
        calculator_receipt,
        missing_function_ac_execution_evidence_path=execution_path,
        missing_function_ac_cwe_evidence_path=cwe_path,
        missing_function_ac_cvss_evidence_path=cvss_path,
    )

    with pytest.raises(ValueError, match="MissingFunctionAC evidence attachment is not reproducible"):
        _validate(
            payload,
            corpus,
            missing_function_ac_execution_evidence_path=execution_path,
            missing_function_ac_cwe_evidence_path=cwe_path,
        )


def test_missing_function_ac_state_reset_evidence_requires_every_bound_input(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    execution_path, cwe_path, state_reset_path, positive_receipt_path, _negative_receipt_path, _execution, _state_reset = (
        _write_missing_function_ac_state_reset_evidence(corpus, tmp_path, monkeypatch)
    )

    with pytest.raises(ValueError, match="requires bound positive and negative receipts"):
        l2.materialize_l2_oracles(
            sources,
            calculator,
            calculator_receipt,
            missing_function_ac_execution_evidence_path=execution_path,
            missing_function_ac_cwe_evidence_path=cwe_path,
            missing_function_ac_state_reset_evidence_path=state_reset_path,
            missing_function_ac_state_reset_positive_receipt_path=positive_receipt_path,
        )


def test_missing_function_ac_state_reset_attachment_requires_the_same_inputs_to_revalidate(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    (
        execution_path,
        cwe_path,
        state_reset_path,
        positive_receipt_path,
        negative_receipt_path,
        _execution,
        _state_reset,
    ) = _write_missing_function_ac_state_reset_evidence(corpus, tmp_path, monkeypatch)
    payload = l2.materialize_l2_oracles(
        sources,
        calculator,
        calculator_receipt,
        missing_function_ac_execution_evidence_path=execution_path,
        missing_function_ac_cwe_evidence_path=cwe_path,
        missing_function_ac_state_reset_evidence_path=state_reset_path,
        missing_function_ac_state_reset_positive_receipt_path=positive_receipt_path,
        missing_function_ac_state_reset_negative_receipt_path=negative_receipt_path,
    )

    with pytest.raises(ValueError, match="MissingFunctionAC evidence attachment is not reproducible"):
        _validate(
            payload,
            corpus,
            missing_function_ac_execution_evidence_path=execution_path,
            missing_function_ac_cwe_evidence_path=cwe_path,
        )


def test_missing_function_ac_evidence_requires_both_bound_inputs(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    execution_path, cwe_path, _execution, _cwe = _write_missing_function_ac_evidence(
        corpus, tmp_path, monkeypatch
    )

    with pytest.raises(ValueError, match="requires both execution and CWE evidence"):
        l2.materialize_l2_oracles(
            sources,
            calculator,
            calculator_receipt,
            missing_function_ac_execution_evidence_path=execution_path,
        )
    with pytest.raises(ValueError, match="requires both execution and CWE evidence"):
        l2.materialize_l2_oracles(
            sources,
            calculator,
            calculator_receipt,
            missing_function_ac_cwe_evidence_path=cwe_path,
        )


def test_missing_function_ac_evidence_rejects_cross_scenario_binding(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    execution_path, cwe_path, _execution, cwe = _write_missing_function_ac_evidence(
        corpus, tmp_path, monkeypatch
    )
    cwe["source"]["selector"] = {
        **cwe["source"]["selector"],
        "scenario_id": _webgoat_candidate(_materialize(corpus))["scenario_id"],
    }
    cwe_path.write_bytes(l2.canonical_json_bytes(cwe))

    with pytest.raises(ValueError, match="must bind one exact source selector"):
        l2.materialize_l2_oracles(
            sources,
            calculator,
            calculator_receipt,
            missing_function_ac_execution_evidence_path=execution_path,
            missing_function_ac_cwe_evidence_path=cwe_path,
        )


def test_attached_missing_function_ac_registry_requires_the_same_inputs_to_revalidate(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    execution_path, cwe_path, _execution, _cwe = _write_missing_function_ac_evidence(
        corpus, tmp_path, monkeypatch
    )
    payload = l2.materialize_l2_oracles(
        sources,
        calculator,
        calculator_receipt,
        missing_function_ac_execution_evidence_path=execution_path,
        missing_function_ac_cwe_evidence_path=cwe_path,
    )

    with pytest.raises(ValueError, match="MissingFunctionAC evidence attachment is not reproducible"):
        _validate(payload, corpus)


def test_missing_function_ac_source_receipt_accepts_only_observed_semantic_equivalence(
    corpus: tuple[Path, Path, Path]
) -> None:
    payload = _materialize(corpus)
    receipt = next(row for row in payload["source_receipts"] if row["app_id"] == "webgoat")
    candidate = _webgoat_candidate(payload, "AccessControlIntegrationTest")
    selector = {
        "root_cause": candidate["root_cause"],
        "source_path": candidate["official_source"]["path"],
        "source_line": candidate["official_source"]["line"],
        "source_content_sha256": candidate["official_source"]["content_sha256"],
        "source_root_cause_identity": candidate["source_root_cause_identity"],
        "scenario_id": candidate["scenario_id"],
        "raw_returned": False,
    }
    alternate = copy.deepcopy(receipt)
    alternate["observed_receipt_sha256"] = "5" * 64
    source = {
        "app_id": "webgoat",
        "repository_id": receipt["repository_id"],
        "commit": receipt["commit"],
        "commit_tree": receipt["commit_tree"],
        "source_tree_sha256": receipt["source_tree_sha256"],
        "source_receipt_sha256": "5" * 64,
        "source_receipt_semantic_sha256": receipt["receipt_semantic_sha256"],
        "lineage_id": receipt["lineage_id"],
        "selector": selector,
        "raw_returned": False,
    }
    _selector, equivalence = l2._webgoat_semantic_source_equivalence(
        source, alternate, label="fixture"
    )
    assert equivalence == "informational_porcelain_variance"
    source["source_receipt_sha256"] = "6" * 64
    with pytest.raises(ValueError, match="not an authoritative registry receipt"):
        l2._webgoat_semantic_source_equivalence(source, alternate, label="fixture")


def test_webgoat_cvss_evidence_attaches_one_classification_but_cannot_admit_it(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    execution_path, cwe_path, cvss_path, _cvss = _write_cvss_evidence(corpus, tmp_path, monkeypatch)

    payload = l2.materialize_l2_oracles(
        sources,
        calculator,
        calculator_receipt,
        execution_evidence_path=execution_path,
        cwe_evidence_path=cwe_path,
        cvss_evidence_path=cvss_path,
    )

    row = _webgoat_candidate(payload)
    assert payload["cvss_evidence"]["status"] == "ATTACHED"
    assert payload["cvss_evidence"]["registry_classification_attached"] is True
    assert payload["cvss_evidence"]["registry_scenario_admitted"] is False
    assert row["cwe"] == "CWE-639"
    assert row["cvss_v4"]["score"] == "7.1"
    assert row["cvss_v4"]["source"] == "source_bound_benchmark_profile"
    assert row["mechanism_truth"] == "present"
    assert row["expected_disposition"] == "warn"
    assert row["deficits"] == ["state_reset_missing"]
    assert row["admission"] == "HOLD"
    assert payload["scenarios"] == []
    assert payload["phase_2_l2_status"] == "HOLD"
    assert payload["release_gate_passed"] is False
    _validate(
        payload,
        corpus,
        execution_evidence_path=execution_path,
        cwe_evidence_path=cwe_path,
        cvss_evidence_path=cvss_path,
    )


def test_webgoat_state_reset_evidence_attaches_only_the_bound_execution_scenario(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    (
        execution_path,
        cwe_path,
        cvss_path,
        state_reset_path,
        positive_path,
        negative_path,
        state_reset,
    ) = _write_state_reset_evidence(corpus, tmp_path, monkeypatch)

    payload = l2.materialize_l2_oracles(
        sources,
        calculator,
        calculator_receipt,
        execution_evidence_path=execution_path,
        cwe_evidence_path=cwe_path,
        cvss_evidence_path=cvss_path,
        state_reset_evidence_path=state_reset_path,
        state_reset_positive_receipt_path=positive_path,
        state_reset_negative_receipt_path=negative_path,
    )

    row = _webgoat_candidate(payload)
    assert payload["state_reset_evidence"]["status"] == "ATTACHED"
    assert payload["state_reset_evidence"]["registry_state_reset_attached"] is True
    assert payload["state_reset_evidence"]["registry_scenario_admitted"] is False
    assert payload["state_reset_evidence"]["scenario_id"] == row["scenario_id"]
    assert row["state_reset"] == state_reset["state_reset"]
    assert row["deficits"] == []
    assert row["admission"] == "PASS"
    assert payload["scenarios"] == [row]
    assert payload["phase_2_l2_status"] == "HOLD"
    assert payload["release_gate_passed"] is False
    _validate(
        payload,
        corpus,
        execution_evidence_path=execution_path,
        cwe_evidence_path=cwe_path,
        cvss_evidence_path=cvss_path,
        state_reset_evidence_path=state_reset_path,
        state_reset_positive_receipt_path=positive_path,
        state_reset_negative_receipt_path=negative_path,
    )


def test_independent_webgoat_idor_and_missing_function_ac_oracles_coexist(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two complete chains must admit only their separately bound candidates."""

    sources, calculator, calculator_receipt = corpus
    (
        idor_execution_path,
        idor_cwe_path,
        idor_cvss_path,
        idor_state_reset_path,
        idor_positive_path,
        idor_negative_path,
        _idor_state_reset,
    ) = _write_state_reset_evidence(corpus, tmp_path, monkeypatch)
    (
        missing_execution_path,
        missing_cwe_path,
        missing_state_reset_path,
        missing_positive_path,
        missing_negative_path,
        _missing_execution,
        _missing_state_reset,
    ) = _write_missing_function_ac_state_reset_evidence(corpus, tmp_path, monkeypatch)
    missing_cvss_path, _missing_cvss = _write_missing_function_ac_cvss_evidence_for_paths(
        corpus, tmp_path, monkeypatch, missing_execution_path, missing_cwe_path
    )

    payload = l2.materialize_l2_oracles(
        sources,
        calculator,
        calculator_receipt,
        execution_evidence_path=idor_execution_path,
        cwe_evidence_path=idor_cwe_path,
        cvss_evidence_path=idor_cvss_path,
        state_reset_evidence_path=idor_state_reset_path,
        state_reset_positive_receipt_path=idor_positive_path,
        state_reset_negative_receipt_path=idor_negative_path,
        missing_function_ac_execution_evidence_path=missing_execution_path,
        missing_function_ac_cwe_evidence_path=missing_cwe_path,
        missing_function_ac_cvss_evidence_path=missing_cvss_path,
        missing_function_ac_state_reset_evidence_path=missing_state_reset_path,
        missing_function_ac_state_reset_positive_receipt_path=missing_positive_path,
        missing_function_ac_state_reset_negative_receipt_path=missing_negative_path,
    )

    idor = _webgoat_candidate(payload)
    missing = _webgoat_candidate(payload, "AccessControlIntegrationTest")
    assert idor["admission"] == "PASS"
    assert missing["admission"] == "PASS"
    assert idor["scenario_id"] != missing["scenario_id"]
    assert {row["scenario_id"] for row in payload["scenarios"]} == {
        idor["scenario_id"],
        missing["scenario_id"],
    }
    assert payload["summary"]["admitted_high_critical_scenario_count"] == 2
    assert payload["phase_2_l2_status"] == "HOLD"
    assert payload["release_gate_passed"] is False
    _validate(
        payload,
        corpus,
        execution_evidence_path=idor_execution_path,
        cwe_evidence_path=idor_cwe_path,
        cvss_evidence_path=idor_cvss_path,
        state_reset_evidence_path=idor_state_reset_path,
        state_reset_positive_receipt_path=idor_positive_path,
        state_reset_negative_receipt_path=idor_negative_path,
        missing_function_ac_execution_evidence_path=missing_execution_path,
        missing_function_ac_cwe_evidence_path=missing_cwe_path,
        missing_function_ac_cvss_evidence_path=missing_cvss_path,
        missing_function_ac_state_reset_evidence_path=missing_state_reset_path,
        missing_function_ac_state_reset_positive_receipt_path=missing_positive_path,
        missing_function_ac_state_reset_negative_receipt_path=missing_negative_path,
    )


def test_webgoat_state_reset_evidence_requires_all_three_bound_inputs(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    (
        execution_path,
        _cwe_path,
        _cvss_path,
        state_reset_path,
        positive_path,
        negative_path,
        _state_reset,
    ) = _write_state_reset_evidence(corpus, tmp_path, monkeypatch)

    with pytest.raises(ValueError, match="requires bound execution, positive, and negative inputs"):
        l2.materialize_l2_oracles(
            sources,
            calculator,
            calculator_receipt,
            execution_evidence_path=execution_path,
            state_reset_evidence_path=state_reset_path,
        )
    with pytest.raises(ValueError, match="state-reset receipts require a state-reset evidence attachment"):
        l2.materialize_l2_oracles(
            sources,
            calculator,
            calculator_receipt,
            state_reset_positive_receipt_path=positive_path,
            state_reset_negative_receipt_path=negative_path,
        )


def test_attached_state_reset_registry_requires_the_same_input_chain_to_revalidate(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    (
        execution_path,
        cwe_path,
        cvss_path,
        state_reset_path,
        positive_path,
        negative_path,
        _state_reset,
    ) = _write_state_reset_evidence(corpus, tmp_path, monkeypatch)
    payload = l2.materialize_l2_oracles(
        sources,
        calculator,
        calculator_receipt,
        execution_evidence_path=execution_path,
        cwe_evidence_path=cwe_path,
        cvss_evidence_path=cvss_path,
        state_reset_evidence_path=state_reset_path,
        state_reset_positive_receipt_path=positive_path,
        state_reset_negative_receipt_path=negative_path,
    )

    with pytest.raises(ValueError, match="state-reset evidence attachment is not reproducible"):
        _validate(
            payload,
            corpus,
            execution_evidence_path=execution_path,
            cwe_evidence_path=cwe_path,
            cvss_evidence_path=cvss_path,
        )


def test_webgoat_cvss_evidence_rejects_a_changed_or_missing_bound_input(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    execution_path, cwe_path, cvss_path, cvss = _write_cvss_evidence(corpus, tmp_path, monkeypatch)
    cvss["source"]["execution_evidence_sha256"] = "0" * 64
    cvss_path.write_bytes(l2.canonical_json_bytes(cvss))

    with pytest.raises(ValueError, match="does not reproduce"):
        l2.materialize_l2_oracles(
            sources,
            calculator,
            calculator_receipt,
            execution_evidence_path=execution_path,
            cwe_evidence_path=cwe_path,
            cvss_evidence_path=cvss_path,
        )

    with pytest.raises(ValueError, match="requires the bound CWE and execution evidence inputs"):
        l2.materialize_l2_oracles(
            sources,
            calculator,
            calculator_receipt,
            cvss_evidence_path=cvss_path,
        )


def test_attached_cvss_registry_requires_the_same_input_chain_to_revalidate(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    execution_path, cwe_path, cvss_path, _cvss = _write_cvss_evidence(corpus, tmp_path, monkeypatch)
    payload = l2.materialize_l2_oracles(
        sources,
        calculator,
        calculator_receipt,
        execution_evidence_path=execution_path,
        cwe_evidence_path=cwe_path,
        cvss_evidence_path=cvss_path,
    )

    with pytest.raises(ValueError, match="CVSS evidence attachment is not reproducible"):
        _validate(payload, corpus, execution_evidence_path=execution_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cwe", "CWE-862"),
        (
            "cvss_v4",
            {
                "vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
                "score": "4.8",
                "severity": "medium",
                "source": "official_source_text",
            },
        ),
    ],
)
def test_webgoat_cvss_evidence_cannot_replace_an_existing_classification(
    corpus: tuple[Path, Path, Path],
    field: str,
    value: object,
) -> None:
    candidate = _webgoat_candidate(_materialize(corpus))
    source = candidate["official_source"]
    candidate[field] = copy.deepcopy(value)
    attachment = {
        "selector": {
            "root_cause": candidate["root_cause"],
            "source_path": source["path"],
            "source_line": source["line"],
            "source_content_sha256": source["content_sha256"],
            "source_root_cause_identity": candidate["source_root_cause_identity"],
            "scenario_id": candidate["scenario_id"],
            "raw_returned": False,
        },
        "cwe": "CWE-639",
        "cvss_v4": {
            "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
            "score": "7.1",
            "severity": "high",
            "calculator_id": l2.DEFAULT_CALCULATOR_ID,
            "calculator_binding_sha256": "c" * 64,
            "source": "source_bound_benchmark_profile",
        },
        "mechanism_truth": "present",
        "expected_disposition": "warn",
    }

    with pytest.raises(ValueError, match="cannot replace an existing source classification"):
        l2._apply_cvss_evidence([candidate], attachment)


def test_execution_evidence_selector_must_match_exactly_one_webgoat_candidate(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    evidence_path, evidence = _write_execution_evidence(corpus, tmp_path, monkeypatch)
    evidence["source"]["selector"]["scenario_id"] = "webgoat:forged:0" * 4
    evidence_path.write_bytes(l2.canonical_json_bytes(evidence))

    with pytest.raises(ValueError, match="does not select exactly one"):
        l2.materialize_l2_oracles(
            sources,
            calculator,
            calculator_receipt,
            execution_evidence_path=evidence_path,
        )


def test_execution_evidence_rejects_self_admitted_state_reset(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    evidence_path, evidence = _write_execution_evidence(corpus, tmp_path, monkeypatch)
    evidence["state_reset_evidence"]["registry_state_reset_admitted"] = True
    evidence_path.write_bytes(l2.canonical_json_bytes(evidence))

    with pytest.raises(ValueError, match="cannot self-admit registry state reset"):
        l2.materialize_l2_oracles(
            sources,
            calculator,
            calculator_receipt,
            execution_evidence_path=evidence_path,
        )


def test_attached_registry_requires_the_same_evidence_input_to_revalidate(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    evidence_path, _evidence = _write_execution_evidence(corpus, tmp_path, monkeypatch)
    payload = l2.materialize_l2_oracles(
        sources,
        calculator,
        calculator_receipt,
        execution_evidence_path=evidence_path,
    )

    with pytest.raises(ValueError, match="execution evidence attachment is not reproducible"):
        _validate(payload, corpus)


def test_execution_evidence_rejects_wrong_tool_provenance(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, calculator, calculator_receipt = corpus
    evidence_path, evidence = _write_execution_evidence(corpus, tmp_path, monkeypatch)
    evidence["tool_provenance"]["adapter_sha256"] = "c" * 64
    evidence_path.write_bytes(l2.canonical_json_bytes(evidence))

    with pytest.raises(ValueError, match="tool provenance is not current"):
        l2.materialize_l2_oracles(
            sources,
            calculator,
            calculator_receipt,
            execution_evidence_path=evidence_path,
        )


def test_metadata_only_rows_retain_explicit_oracle_gap(corpus: tuple[Path, Path, Path]) -> None:
    payload = _materialize(corpus)
    rows = {row["app_id"]: row for row in payload["retained_candidates"]}

    for app_id in ("crapi", "juice-shop", "nodegoat", "pygoat"):
        assert rows[app_id]["oracle"] is None
        assert "oracle_missing" in rows[app_id]["deficits"]
    assert payload["summary"]["oracle_missing_candidate_count"] == 7
    assert payload["summary"]["gates"]["no_oracle_missing_or_uncertain"] is False


def test_process_command_requires_only_a_normalized_result_hash() -> None:
    incomplete = _complete_process_command("oracle")
    incomplete["expected_result_sha256"] = None
    assert l2._command_deficits(incomplete, label="oracle") == [
        "oracle_expected_result_sha256_missing"
    ]

    complete = _complete_process_command("oracle")
    assert l2._command_deficits(complete, label="oracle") == []


def test_process_negative_control_can_expect_a_nonzero_rejection_exit() -> None:
    rejected = _complete_process_command("negative", exit_code=1)
    assert l2._command_deficits(rejected, label="negative_control") == []
    assert l2._command_deficits(rejected, label="oracle") == ["oracle_expected_exit_missing"]


def test_process_command_rejects_http_only_fields() -> None:
    malformed = _complete_process_command("oracle")
    malformed["expected_http_status"] = 200
    assert l2._command_deficits(malformed, label="oracle") == ["oracle_malformed"]


def test_negative_control_must_have_a_distinct_expected_outcome(
    corpus: tuple[Path, Path, Path],
) -> None:
    payload = _materialize(corpus)
    row = _webgoat_candidate(payload)
    row["oracle"] = _complete_process_command("same-result")
    row["negative_control"] = _complete_process_command("same-result")
    row["state_reset"] = _complete_process_command("reset")

    assert "negative_control_not_distinguishing" in l2._candidate_deficits(row)

    row["negative_control"] = _complete_process_command("negative-result", exit_code=1)
    assert "negative_control_not_distinguishing" not in l2._candidate_deficits(row)


def test_calculator_artifact_must_match_preregistered_hash(
    corpus: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(l2, "LOCKED_CALCULATOR_RECEIPT_SHA256", "0" * 64)
    with pytest.raises(ValueError, match="source receipt hash"):
        _materialize_direct(corpus)


def test_calculator_identity_is_locked_with_the_artifact_hash(corpus: tuple[Path, Path, Path]) -> None:
    sources, calculator, calculator_receipt = corpus
    with pytest.raises(ValueError, match="locked calculator identity"):
        l2.materialize_l2_oracles(
            sources,
            calculator,
            calculator_receipt,
            calculator_id="attacker-renamed-calculator",
        )


def test_validator_rejects_unpinned_calculator(corpus: tuple[Path, Path, Path]) -> None:
    payload = _materialize(corpus)
    payload["calculator"]["binding_sha256"] = "f" * 64

    with pytest.raises(ValueError, match="not bound"):
        _validate(payload, corpus)


@pytest.mark.parametrize("bad_path", ["../escape.md", "/absolute.md", "a\\b.md", "./same.md"])
def test_validator_rejects_malformed_official_paths(
    corpus: tuple[Path, Path, Path], bad_path: str
) -> None:
    payload = _materialize(corpus)
    payload["retained_candidates"][0]["official_source"]["path"] = bad_path

    with pytest.raises(ValueError, match="official source path"):
        _validate(payload, corpus)


def test_validator_rejects_missing_official_source(corpus: tuple[Path, Path, Path]) -> None:
    payload = _materialize(corpus)
    row = payload["retained_candidates"][0]
    row["official_source"]["path"] = "missing/official.md"

    with pytest.raises(ValueError, match="official source does not exist"):
        _validate(payload, corpus)


def test_validator_rejects_duplicate_scenario_and_source_root_identity(
    corpus: tuple[Path, Path, Path],
) -> None:
    payload = _materialize(corpus)
    payload["retained_candidates"][1]["source_root_cause_identity"] = payload["retained_candidates"][0][
        "source_root_cause_identity"
    ]

    with pytest.raises(ValueError, match="identity is malformed or duplicated"):
        _validate(payload, corpus)


def test_validator_rejects_a_v2_registry_under_the_process_contract(
    corpus: tuple[Path, Path, Path],
) -> None:
    payload = _materialize(corpus)
    payload["schema"] = "k_guard_l2_oracle_registry.v2"

    with pytest.raises(ValueError, match="schema or top-level fields"):
        _validate(payload, corpus)


def test_validator_rejects_unsafe_command_and_network_policy(corpus: tuple[Path, Path, Path]) -> None:
    payload = _materialize(corpus)
    row = next(row for row in payload["retained_candidates"] if row["oracle"] is not None)
    row["oracle"]["argv"] = ["curl", "https://example.invalid/exploit"]
    row["oracle"]["network_policy"] = "unrestricted"

    with pytest.raises(ValueError, match="command or network policy is unsafe"):
        _validate(payload, corpus)


def test_validator_rejects_non_allowlisted_command_without_a_url(corpus: tuple[Path, Path, Path]) -> None:
    payload = _materialize(corpus)
    row = next(row for row in payload["retained_candidates"] if row["oracle"] is not None)
    row["oracle"]["argv"] = ["powershell", "-EncodedCommand", "AAAA"]

    with pytest.raises(ValueError, match="command or network policy is unsafe"):
        _validate(payload, corpus)


def test_validator_rejects_malformed_cvss_v4_even_for_retained_candidate(
    corpus: tuple[Path, Path, Path],
) -> None:
    payload = _materialize(corpus)
    row = payload["retained_candidates"][0]
    row["cvss_v4"]["vector"] = "CVSS:4.0/AV:N"
    row["cvss_v4"]["source"] = "official_source_text"

    with pytest.raises(ValueError, match="complete and canonical"):
        _validate(payload, corpus)


def test_validator_rejects_forged_app_lineage(corpus: tuple[Path, Path, Path]) -> None:
    payload = _materialize(corpus)
    payload["retained_candidates"][0]["app_lineage"]["commit"] = "0" * 40

    with pytest.raises(ValueError, match="app lineage binding"):
        _validate(payload, corpus)


def test_validator_rejects_fabricated_pass_and_summary(corpus: tuple[Path, Path, Path]) -> None:
    payload = _materialize(corpus)
    row = payload["retained_candidates"][0]
    row["admission"] = "PASS"
    row["deficits"] = []
    payload["scenarios"] = [row]

    with pytest.raises(ValueError, match="deficit ledger is not reproducible"):
        _validate(payload, corpus)


def test_candidate_inventory_can_never_claim_replay_or_release(
    corpus: tuple[Path, Path, Path],
) -> None:
    payload = _materialize(corpus)
    payload["oracle_replay"] = {
        "executed": True,
        "passed_scenario_count": 120,
        "receipt_count": 120,
        "status": "PASS",
        "blocker": None,
    }
    payload["phase_2_l2_status"] = "PASS"
    payload["release_gate_passed"] = True

    with pytest.raises(ValueError, match="replay boundary|remain HOLD|release authority"):
        _validate(payload, corpus)


def test_validator_reextracts_semantics_and_rejects_forged_complete_candidate(
    corpus: tuple[Path, Path, Path],
) -> None:
    payload = _materialize(corpus)
    row = next(row for row in payload["retained_candidates"] if row["app_id"] == "nodegoat")
    row["cwe"] = "CWE-862"
    row["cvss_v4"] = {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "score": "9.3",
        "severity": "critical",
        "calculator_id": payload["calculator"]["id"],
        "calculator_binding_sha256": payload["calculator"]["binding_sha256"],
        "source": "official_source_text",
    }
    row["mechanism_truth"] = "present"
    row["expected_disposition"] = "block"
    row["oracle"] = _complete_command("oracle")
    row["negative_control"] = _complete_command("negative")
    row["state_reset"] = _complete_command("reset")
    row["deficits"] = []
    row["admission"] = "PASS"
    payload["scenarios"] = [row]
    payload["summary"] = l2._summary(payload["retained_candidates"], payload["source_receipts"])

    with pytest.raises(ValueError, match="do not exactly match deterministic source re-extraction"):
        _validate(payload, corpus)


def test_integer_official_cvss_score_is_canonicalized_without_crashing() -> None:
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    digest = "a" * 64
    cvss = l2._cvss_from_official_text(f"{vector} CVSS score: 9", "fixture", digest)

    assert cvss["score"] == "9.0"
    assert cvss["severity"] == "critical"
    l2._validate_cvss_v4(cvss, digest)

    maximum = l2._cvss_from_official_text(f"{vector} score: 10", "fixture", digest)
    assert maximum["score"] == "10.0"
    l2._validate_cvss_v4(maximum, digest)


def test_cwe_is_extracted_from_the_entire_bound_semantic_window() -> None:
    text = "\n".join(["context"] * 40 + ["explicit CWE-862 evidence"])
    assert l2._unique_explicit_cwe(text) == "CWE-862"


def test_source_change_is_rejected_before_candidate_extraction(corpus: tuple[Path, Path, Path]) -> None:
    sources, _calculator, _calculator_receipt = corpus
    challenge = sources / "crapi" / "docs" / "challenges.md"
    original = challenge.read_bytes()
    try:
        challenge.write_bytes(original + b"\nlocal change\n")
        with pytest.raises(ValueError, match="no longer matches raw Git blobs and index"):
            _materialize_direct(corpus)
    finally:
        challenge.write_bytes(original)


def test_output_is_canonical_non_overwriting_and_validatable(
    corpus: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    payload = _materialize(corpus)
    output = tmp_path / "registry.json"

    l2.write_new_output(output, payload)
    assert output.read_bytes() == l2.canonical_json_bytes(payload)
    loaded = l2._load_canonical(output)
    _validate(loaded, corpus)
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        l2.write_new_output(output, payload)


def test_loader_rejects_noncanonical_json(corpus: tuple[Path, Path, Path], tmp_path: Path) -> None:
    payload = _materialize(corpus)
    path = tmp_path / "noncanonical.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="canonical JSON"):
        l2._load_canonical(path)


def test_cli_writes_hold_registry_and_returns_two(
    corpus: tuple[Path, Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sources, calculator, calculator_receipt = corpus
    output = tmp_path / "cli-registry.json"

    result = l2.main(
        [
            "materialize",
            "--sources-root",
            str(sources),
            "--calculator-root",
            str(calculator),
            "--calculator-receipt",
            str(calculator_receipt),
            "--source-admission",
            str(sources.parent / "source-admission.json"),
            "--source-receipts-dir",
            str(sources.parent / "source-receipts"),
            "--output",
            str(output),
        ]
    )

    assert result == 2
    assert output.is_file()
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "HOLD"
    assert report["registry_path"] == str(output.resolve())
    assert report["registry_sha256"] == l2.sha256_bytes(output.read_bytes())
    assert report["evaluation"] == {
        "exit_code": 2,
        "exit_contract": "0=phase_2_l2_pass;2=validated_hold_not_release",
        "phase_2_l2_status": "HOLD",
        "registry_contract_valid": True,
    }


def test_cli_validate_reports_a_structurally_valid_hold_with_exit_two(
    corpus: tuple[Path, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sources, calculator, calculator_receipt = corpus
    evidence_path, _evidence = _write_execution_evidence(corpus, tmp_path, monkeypatch)
    payload = l2.materialize_l2_oracles(
        sources,
        calculator,
        calculator_receipt,
        execution_evidence_path=evidence_path,
    )
    output = tmp_path / "attached-registry.json"
    l2.write_new_output(output, payload)

    result = l2.main(
        [
            "validate",
            "--sources-root",
            str(sources),
            "--registry",
            str(output),
            "--calculator-root",
            str(calculator),
            "--calculator-receipt",
            str(calculator_receipt),
            "--source-admission",
            str(sources.parent / "source-admission.json"),
            "--source-receipts-dir",
            str(sources.parent / "source-receipts"),
            "--execution-evidence",
            str(evidence_path),
        ]
    )

    assert result == 2
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "HOLD"
    assert report["evaluation"] == {
        "exit_code": 2,
        "exit_contract": "0=phase_2_l2_pass;2=validated_hold_not_release",
        "phase_2_l2_status": "HOLD",
        "registry_contract_valid": True,
    }


def test_validator_detects_source_content_change_after_materialization(
    corpus: tuple[Path, Path, Path],
) -> None:
    sources, _calculator, _calculator_receipt = corpus
    payload = _materialize(corpus)
    path = sources / "nodegoat" / "app" / "views" / "tutorial" / "a7.html"
    original = path.read_bytes()
    try:
        path.write_bytes(b"changed after registry\n")
        with pytest.raises(ValueError, match="source receipt no longer matches"):
            _validate(payload, corpus)
    finally:
        path.write_bytes(original)


def test_validator_detects_unrelated_tracked_file_change_via_source_receipt(
    corpus: tuple[Path, Path, Path],
) -> None:
    sources, _calculator, _calculator_receipt = corpus
    payload = _materialize(corpus)
    path = sources / "webgoat" / "LICENSE"
    original = path.read_bytes()
    try:
        path.write_bytes(original + b"changed\n")
        with pytest.raises(ValueError, match="source receipt no longer matches"):
            _validate(payload, corpus)
    finally:
        path.write_bytes(original)


def test_sources_root_requires_exact_six_apps(corpus: tuple[Path, Path, Path]) -> None:
    sources, _calculator, _calculator_receipt = corpus
    extra = sources / "seventh-app"
    extra.mkdir()
    try:
        with pytest.raises(ValueError, match="exactly the locked six"):
            _materialize_direct(corpus)
    finally:
        shutil.rmtree(extra)


def test_windows_autocrlf_porcelain_noise_is_informational(
    corpus: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, _calculator, _calculator_receipt = corpus
    receipt_path = sources.parent / "source-receipts" / "crapi.json"
    admission_path = sources.parent / "source-admission.json"
    original_receipt = receipt_path.read_bytes()
    original_admission = admission_path.read_bytes()
    original_hash = _FIXTURE_IDENTITIES["crapi"]["receipt_sha256"]

    class PorcelainNoiseVerifier(_FixtureVerifier):
        @staticmethod
        def build_git_materialization_receipt(
            root: Path, *, expected_repository_id: str, expected_commit: str, expected_tree: str
        ) -> dict:
            value = _FixtureVerifier.build_git_materialization_receipt(
                root,
                expected_repository_id=expected_repository_id,
                expected_commit=expected_commit,
                expected_tree=expected_tree,
            )
            if root.name == "crapi":
                value["git_porcelain_clean"] = False
            return value

    try:
        receipt = json.loads(original_receipt.decode("utf-8"))
        receipt["git_porcelain_clean"] = False
        receipt_path.write_bytes(l2.canonical_json_bytes(receipt))
        new_hash = l2.sha256_bytes(receipt_path.read_bytes())
        contract = SimpleNamespace(EXPECTED_IDENTITIES=_FIXTURE_IDENTITIES)
        monkeypatch.setattr(
            l2,
            "_load_authoritative_source_modules",
            lambda: (contract, PorcelainNoiseVerifier, "c" * 64, "d" * 64),
        )

        payload = _materialize_direct(corpus)
        crapi = next(row for row in payload["source_receipts"] if row["app_id"] == "crapi")
        assert crapi["git_porcelain_clean"] is False
        assert crapi["git_porcelain_is_informational"] is True
        assert crapi["receipt_sha256"] == original_hash
        assert crapi["observed_receipt_sha256"] == new_hash
        assert crapi["receipt_equivalence"] == "informational_porcelain_variance"
        assert crapi["source_worktree_clean"] is True
        assert payload["summary"]["gates"]["all_source_receipts_blob_exact"] is True
        assert all(
            "source_receipt_not_clean" not in row["deficits"]
            for row in payload["retained_candidates"]
        )
    finally:
        receipt_path.write_bytes(original_receipt)
        admission_path.write_bytes(original_admission)


def test_source_receipt_semantic_fingerprint_ignores_only_porcelain_status() -> None:
    receipt = {
        "schema": l2.SOURCE_RECEIPT_SCHEMA,
        "git_porcelain_clean": True,
        "source_tree_sha256": "a" * 64,
        "physical_bytes_match_git_blobs": True,
    }
    fingerprint = l2._source_receipt_semantic_sha256(receipt)

    porcelain_variant = copy.deepcopy(receipt)
    porcelain_variant["git_porcelain_clean"] = False
    source_variant = copy.deepcopy(receipt)
    source_variant["source_tree_sha256"] = "b" * 64

    assert l2._source_receipt_semantic_sha256(porcelain_variant) == fingerprint
    assert l2._source_receipt_semantic_sha256(source_variant) != fingerprint
    with pytest.raises(ValueError, match="git_porcelain_clean must be boolean"):
        l2._source_receipt_semantic_sha256({"git_porcelain_clean": "true"})


def test_swapped_checkout_directories_are_rejected(corpus: tuple[Path, Path, Path]) -> None:
    sources, _calculator, _calculator_receipt = corpus
    crapi = sources / "crapi"
    juice = sources / "juice-shop"
    temporary = sources / "swap-temporary"
    crapi.rename(temporary)
    juice.rename(crapi)
    temporary.rename(juice)
    try:
        with pytest.raises(ValueError, match="source receipt no longer matches raw Git blobs and index"):
            _materialize_direct(corpus)
    finally:
        crapi.rename(temporary)
        juice.rename(crapi)
        temporary.rename(juice)


def test_arbitrary_six_repo_identity_is_rejected(corpus: tuple[Path, Path, Path]) -> None:
    sources, _calculator, _calculator_receipt = corpus
    admission_path = sources.parent / "source-admission.json"
    original = admission_path.read_bytes()
    try:
        admission = json.loads(original.decode("utf-8"))
        admission["apps"][0]["repository_id"] = "arbitrary/repository"
        admission_path.write_bytes(l2.canonical_json_bytes(admission))
        with pytest.raises(ValueError, match="admission artifact hash is not preregistered"):
            _materialize_direct(corpus)
    finally:
        admission_path.write_bytes(original)


def test_payload_never_contains_scanner_derived_truth(corpus: tuple[Path, Path, Path]) -> None:
    payload = _materialize(corpus)
    encoded = l2.canonical_json_bytes(payload).decode("utf-8")

    assert '"scanner_output_observed": false' in encoded
    assert "scanner_finding" not in encoded
    assert "detector_rule" not in encoded
    assert payload["summary"]["status"] == "HOLD"
