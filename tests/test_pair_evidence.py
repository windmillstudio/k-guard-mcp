from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from k_guard_mcp import pair_evidence
from k_guard_mcp.pair_admission import pair_subject_sha256


IMAGE_REFERENCE = "kguard/pair-verifier@sha256:" + "1" * 64
IMAGE_ID = "sha256:" + "2" * 64
LIVE_BUSYBOX_REFERENCE = (
    "busybox@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028"
)
LIVE_BUSYBOX_ID = "sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028"


def _domain_hash(domain: bytes, value: object) -> str:
    return hashlib.sha256(domain + pair_evidence.canonical_json_bytes(value)).hexdigest()


def _result(case_id: str, outcome_name: str, value: bool) -> bytes:
    payload = {
        "schema": pair_evidence.ORACLE_RESULT_SCHEMA,
        "case_id": case_id,
        "harness_passed": True,
        "outcome": {"name": outcome_name, "value": value},
    }
    payload["evidence_sha256"] = _domain_hash(
        b"k_guard_pair_oracle_result.v1\0", payload
    )
    return pair_evidence.canonical_json_bytes(payload)


def _structured_result(
    schema: str, case_id: str, payload_key: str, payload_value: object
) -> bytes:
    payload = {
        "schema": schema,
        "case_id": case_id,
        "passed": True,
        payload_key: payload_value,
    }
    payload["evidence_sha256"] = _domain_hash(
        (schema + "\0").encode("ascii"), payload
    )
    return pair_evidence.canonical_json_bytes(payload)


class QueueRunner:
    def __init__(self, outputs: list[pair_evidence.ProcessResult]) -> None:
        self.outputs = list(outputs)
        self.calls: list[tuple[list[str], int]] = []

    def run(self, argv, *, timeout_seconds: int) -> pair_evidence.ProcessResult:
        self.calls.append((list(argv), timeout_seconds))
        if not self.outputs:
            raise AssertionError("unexpected process call")
        return self.outputs.pop(0)


def _process(raw: bytes) -> pair_evidence.ProcessResult:
    return pair_evidence.ProcessResult(0, raw, b"")


def test_verifier_artifact_hash_binds_replay_and_admission_code() -> None:
    artifact = Path(pair_evidence.__file__)
    expected = _domain_hash(
        b"k_guard_pair_verifier_artifacts.v1\0",
        {
            artifact.name: pair_evidence.sha256_bytes(artifact.read_bytes()),
            "pair_admission.py": pair_evidence.sha256_bytes(
                artifact.with_name("pair_admission.py").read_bytes()
            ),
        },
    )

    assert pair_evidence.verifier_artifact_sha256() == expected


def _build_bundle(tmp_path: Path) -> tuple[Path, dict, dict, QueueRunner, list[bytes]]:
    root = tmp_path / "pair"
    vulnerable = root / "vulnerable"
    fixed = root / "fixed"
    oracle = root / "oracle"
    vulnerable.mkdir(parents=True)
    fixed.mkdir()
    oracle.mkdir()
    (vulnerable / "app.py").write_text(
        "def render(value):\n    return value\n", encoding="utf-8"
    )
    (fixed / "app.py").write_text(
        "def render(value):\n    return escape(value)\n", encoding="utf-8"
    )
    oracle_roles = {
        "exploit.py": "exploit",
        "regression.py": "regression",
        "negative.py": "negative_control",
        "diff.py": "oracle",
        "invariants.py": "oracle",
    }
    for name in oracle_roles:
        (oracle / name).write_text(f"# {name}\n", encoding="ascii")

    commands = {
        "exploit": {
            "argv": ["/usr/local/bin/python", "/oracle/exploit.py"],
            "timeout_seconds": 30,
        },
        "regression": {
            "argv": ["/usr/local/bin/python", "/oracle/regression.py"],
            "timeout_seconds": 30,
        },
        "negative_control": {
            "argv": ["/usr/local/bin/python", "/oracle/negative.py"],
            "timeout_seconds": 30,
        },
        "diff": {
            "argv": ["/usr/local/bin/python", "/oracle/diff.py"],
            "timeout_seconds": 30,
        },
        "invariants": {
            "argv": ["/usr/local/bin/python", "/oracle/invariants.py"],
            "timeout_seconds": 30,
        },
    }
    vulnerable_receipt = pair_evidence.regular_tree_receipt(vulnerable.resolve())
    fixed_receipt = pair_evidence.regular_tree_receipt(fixed.resolve())
    physical_diff = pair_evidence._physical_diff(vulnerable.resolve(), fixed.resolve())
    change = {
        **physical_diff[0],
        "role": "production",
        "change_kind": "guard",
        "selector": "ast.guard.request_input",
        "root_cause_ref": "scenario-xss-001",
    }
    invariants = {
        "route_inventory_unchanged": True,
        "public_api_shape_unchanged": True,
        "schema_unchanged": True,
        "unrelated_dependencies_unchanged": True,
        "feature_flags_unchanged": True,
        "logging_unchanged": True,
        "build_options_unchanged": True,
        "build_passed": True,
        "functional_snapshot_equal": True,
    }
    outputs = [
        _result("exploit_vulnerable", "exploit_succeeded", True),
        _result("exploit_fixed", "exploit_succeeded", False),
        _result("fixed_functional", "functional_passed", True),
        _result("negative_control", "control_triggered", False),
        _structured_result(
            pair_evidence.DIFF_RESULT_SCHEMA,
            "diff",
            "production_changes",
            [change],
        ),
        _structured_result(
            pair_evidence.INVARIANT_RESULT_SCHEMA,
            "invariants",
            "invariants",
            invariants,
        ),
    ]
    execution_specs = {
        "exploit_vulnerable": ("exploit", "exploit_succeeded", True, outputs[0]),
        "exploit_fixed": ("exploit", "exploit_succeeded", False, outputs[1]),
        "fixed_functional": ("regression", "functional_passed", True, outputs[2]),
        "negative_control": ("negative_control", "control_triggered", False, outputs[3]),
    }
    executions = {}
    for case_id, (command_id, outcome_name, outcome, raw) in execution_specs.items():
        executions[case_id] = {
            "executed": True,
            "harness_passed": True,
            "exit_code": 0,
            "command_sha256": pair_evidence.command_sha256(commands[command_id]),
            "result_sha256": pair_evidence.sha256_bytes(raw),
            outcome_name: outcome,
        }
    manifest = {
        "schema": "k_guard_generated_pair_admission.v1",
        "family": "source_flow",
        "lineage_id": "generated-source-flow-001",
        "label_locked_before_scanner_output": True,
        "provenance": {
            "model": "deterministic-template",
            "version": "1.0.0",
            "prompt_sha256": "3" * 64,
            "seed": 7,
            "sampling": {"temperature": 0, "strategy": "deterministic"},
            "generator_commit": "4" * 40,
            "dependency_sha256": "5" * 64,
            "framework": "fixture",
            "language": "python",
            "plane": "site",
            "cwe": "CWE-79",
            "license_spdx": "MIT",
            "source": {"kind": "generated", "identity_sha256": "6" * 64},
        },
        "hashes": {
            "vulnerable_source_sha256": vulnerable_receipt["tree_sha256"],
            "fixed_source_sha256": fixed_receipt["tree_sha256"],
            "exploit_command_sha256": pair_evidence.command_sha256(commands["exploit"]),
            "regression_command_sha256": pair_evidence.command_sha256(commands["regression"]),
            "negative_control_command_sha256": pair_evidence.command_sha256(
                commands["negative_control"]
            ),
            "diff_command_sha256": pair_evidence.command_sha256(commands["diff"]),
            "invariants_command_sha256": pair_evidence.command_sha256(
                commands["invariants"]
            ),
        },
        "executions": executions,
        "diff": {"production_changes": [change]},
        "invariants": invariants,
        "test_oracle_files": [
            {
                "path": f"oracle/{name}",
                "content_sha256": pair_evidence.sha256_bytes((oracle / name).read_bytes()),
                "role": role,
            }
            for name, role in oracle_roles.items()
        ],
    }
    plan = {
        "schema": pair_evidence.PLAN_SCHEMA,
        "lineage_id": manifest["lineage_id"],
        "bundle_root": str(root.resolve()),
        "manifest_subject_sha256": pair_subject_sha256(manifest),
        "verifier_sha256": pair_evidence.verifier_artifact_sha256(),
        "runtime_image": {
            "reference": IMAGE_REFERENCE,
            "expected_image_id": IMAGE_ID,
        },
        "isolation": {
            "network": "none",
            "read_only_root": True,
            "cap_drop": "ALL",
            "no_new_privileges": True,
            "user": "65532:65532",
            "pids_limit": 64,
            "memory_bytes": 256 * 1024 * 1024,
            "nano_cpus": 500_000_000,
            "tmpfs_bytes": 16 * 1024 * 1024,
        },
        "paths": {"vulnerable": "vulnerable", "fixed": "fixed", "oracle": "oracle"},
        "commands": commands,
    }
    inspect = json.dumps([{"Id": IMAGE_ID, "RepoDigests": [IMAGE_REFERENCE]}]).encode()
    runner = QueueRunner([_process(inspect), *[_process(raw) for raw in outputs]])
    return root, manifest, plan, runner, outputs


def test_pair_replay_rehashes_and_runs_all_cases_in_locked_docker(tmp_path: Path) -> None:
    root, manifest, plan, runner, _outputs = _build_bundle(tmp_path)

    result = pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)

    assert result["status"] == "PASS"
    assert result["pair_admission"] == "LIVE_REPLAY_PASS"
    assert result["release_gate_passed"] is False
    receipt = result["verification_receipt"]
    assert receipt["schema"] == "k_guard_pair_evidence_verification.v2"
    assert receipt["network_disabled"] is True
    assert receipt["snapshot_replayed"] is True
    assert receipt["raw_sensitive_output_returned"] is False
    assert len(runner.calls) == 7
    assert runner.calls[0][0][:3] == ["docker", "image", "inspect"]
    for argv, _timeout in runner.calls[1:]:
        assert argv[:2] == ["docker", "run"]
        assert "none" == argv[argv.index("--network") + 1]
        assert "--read-only" in argv
        assert "ALL" == argv[argv.index("--cap-drop") + 1]
        assert "no-new-privileges=true" == argv[argv.index("--security-opt") + 1]
        assert "--entrypoint" in argv
        assert all("docker.sock" not in item for item in argv)
    assert runner.outputs == []


def test_physical_source_tamper_fails_before_any_container_runs(tmp_path: Path) -> None:
    root, manifest, plan, runner, _outputs = _build_bundle(tmp_path)
    (root / "fixed" / "app.py").write_text("tampered\n", encoding="ascii")

    with pytest.raises(pair_evidence.PairEvidenceError, match="fixed source tree hash"):
        pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)

    assert runner.calls == []


def test_source_mutation_during_snapshot_fails_before_any_container_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, manifest, plan, runner, _outputs = _build_bundle(tmp_path)
    original = pair_evidence._copy_tree_snapshot

    def mutate_before_copy(source_root, expected_receipt, snapshot_root):
        if source_root.name == "fixed":
            (source_root / "app.py").write_text("mutated during snapshot\n", encoding="ascii")
        return original(source_root, expected_receipt, snapshot_root)

    monkeypatch.setattr(pair_evidence, "_copy_tree_snapshot", mutate_before_copy)

    with pytest.raises(pair_evidence.PairEvidenceError, match="source changed while snapshotting"):
        pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)

    assert runner.calls == []


def test_weakened_isolation_or_command_shell_is_rejected(tmp_path: Path) -> None:
    root, manifest, plan, runner, _outputs = _build_bundle(tmp_path)
    plan["isolation"]["network"] = "bridge"
    with pytest.raises(pair_evidence.PairEvidenceError, match="isolation profile"):
        pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)

    root, manifest, plan, runner, _outputs = _build_bundle(tmp_path / "shell")
    plan["commands"]["exploit"]["argv"] = ["/bin/sh", "-c", "true"]
    with pytest.raises(pair_evidence.PairEvidenceError, match="non-shell"):
        pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)


@pytest.mark.parametrize("executable", ["/bin/ash", "/bin/busybox", "/usr/bin/env"])
def test_shell_equivalent_executables_are_not_allowlisted(
    tmp_path: Path, executable: str
) -> None:
    root, manifest, plan, runner, _outputs = _build_bundle(tmp_path)
    plan["commands"]["exploit"]["argv"] = [executable, "sh", "-c", "true"]

    with pytest.raises(pair_evidence.PairEvidenceError, match="allowlisted non-shell"):
        pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)


def test_diff_and_invariant_commands_are_bound_by_manifest_hashes(tmp_path: Path) -> None:
    root, manifest, plan, runner, _outputs = _build_bundle(tmp_path)
    plan["commands"]["diff"] = {
        "argv": ["/bin/cat", "/oracle/invariants.py"],
        "timeout_seconds": 30,
    }

    with pytest.raises(pair_evidence.PairEvidenceError, match="command hash"):
        pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)

    assert runner.calls == []


def test_wrong_image_identity_is_fail_closed(tmp_path: Path) -> None:
    root, manifest, plan, _runner, outputs = _build_bundle(tmp_path)
    inspect = json.dumps(
        [{"Id": "sha256:" + "9" * 64, "RepoDigests": [IMAGE_REFERENCE]}]
    ).encode()
    runner = QueueRunner([_process(inspect), *[_process(raw) for raw in outputs]])

    with pytest.raises(pair_evidence.PairEvidenceError, match="image ID"):
        pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)


def test_oracle_outcome_and_noncanonical_output_cannot_be_rebound(tmp_path: Path) -> None:
    root, manifest, plan, _runner, outputs = _build_bundle(tmp_path)
    bad = _result("exploit_fixed", "exploit_succeeded", True)
    inspect = json.dumps([{"Id": IMAGE_ID, "RepoDigests": [IMAGE_REFERENCE]}]).encode()
    runner = QueueRunner(
        [_process(inspect), _process(outputs[0]), _process(bad), *[_process(raw) for raw in outputs[2:]]]
    )
    with pytest.raises(pair_evidence.PairEvidenceError, match="oracle outcome"):
        pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)

    root, manifest, plan, _runner, outputs = _build_bundle(tmp_path / "noncanonical")
    noncanonical = json.dumps(json.loads(outputs[0])).encode("ascii")
    runner = QueueRunner(
        [_process(inspect), _process(noncanonical), *[_process(raw) for raw in outputs[1:]]]
    )
    with pytest.raises(pair_evidence.PairEvidenceError, match="not canonical"):
        pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)


def test_semantic_diff_must_match_both_manifest_and_physical_diff(tmp_path: Path) -> None:
    root, manifest, plan, _runner, outputs = _build_bundle(tmp_path)
    changed = copy.deepcopy(manifest["diff"]["production_changes"])
    changed[0]["selector"] = "ast.guard.unrelated"
    outputs[4] = _structured_result(
        pair_evidence.DIFF_RESULT_SCHEMA,
        "diff",
        "production_changes",
        changed,
    )
    inspect = json.dumps([{"Id": IMAGE_ID, "RepoDigests": [IMAGE_REFERENCE]}]).encode()
    runner = QueueRunner([_process(inspect), *[_process(raw) for raw in outputs]])

    with pytest.raises(pair_evidence.PairEvidenceError, match="semantic diff"):
        pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)

    root, manifest, plan, runner, _outputs = _build_bundle(tmp_path / "physical")
    manifest["diff"]["production_changes"][0]["logical_changed_lines"] += 1
    plan["manifest_subject_sha256"] = pair_subject_sha256(manifest)
    with pytest.raises(pair_evidence.PairEvidenceError, match="logical_changed_lines"):
        pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)


def test_supplied_verified_true_receipt_is_replayed_not_trusted(tmp_path: Path) -> None:
    root, manifest, plan, runner, _outputs = _build_bundle(tmp_path)
    first = pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)
    forged = copy.deepcopy(first["manifest"])
    forged["verification"]["evidence_bundle_sha256"] = "f" * 64
    _root, _manifest, _plan, fresh_runner, _outputs = _build_bundle(tmp_path / "fresh")
    fresh_plan = copy.deepcopy(plan)
    fresh_plan["bundle_root"] = str(_root.resolve())
    fresh_plan["manifest_subject_sha256"] = pair_subject_sha256(forged)

    with pytest.raises(pair_evidence.PairEvidenceError, match="supplied verification"):
        pair_evidence.verify_pair_evidence(_root.resolve(), forged, fresh_plan, runner=fresh_runner)


def test_timeout_and_output_truncation_fail_closed(tmp_path: Path) -> None:
    root, manifest, plan, _runner, outputs = _build_bundle(tmp_path)
    inspect = json.dumps([{"Id": IMAGE_ID, "RepoDigests": [IMAGE_REFERENCE]}]).encode()
    runner = QueueRunner(
        [
            _process(inspect),
            pair_evidence.ProcessResult(124, b"", b"", timed_out=True),
            *[_process(raw) for raw in outputs[1:]],
        ]
    )
    with pytest.raises(pair_evidence.PairEvidenceError, match="timed out"):
        pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)

    root, manifest, plan, _runner, outputs = _build_bundle(tmp_path / "truncated")
    runner = QueueRunner(
        [
            _process(inspect),
            pair_evidence.ProcessResult(0, outputs[0], b"", output_truncated=True),
            *[_process(raw) for raw in outputs[1:]],
        ]
    )
    with pytest.raises(pair_evidence.PairEvidenceError, match="output bound"):
        pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)

    root, manifest, plan, _runner, outputs = _build_bundle(tmp_path / "oversized")
    runner = QueueRunner(
        [
            _process(inspect),
            pair_evidence.ProcessResult(
                0,
                b"x" * (pair_evidence.MAX_OUTPUT_BYTES + 1),
                b"",
            ),
            *[_process(raw) for raw in outputs[1:]],
        ]
    )
    with pytest.raises(pair_evidence.PairEvidenceError, match="output bound"):
        pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)


def test_oracle_tree_symlink_is_rejected_when_supported(tmp_path: Path) -> None:
    root, manifest, plan, runner, _outputs = _build_bundle(tmp_path)
    target = root / "outside.py"
    target.write_text("secret\n", encoding="ascii")
    try:
        os.symlink(target, root / "oracle" / "linked.py")
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(pair_evidence.PairEvidenceError, match="link or reparse"):
        pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan, runner=runner)


def test_subprocess_runner_never_invokes_a_host_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    class FakeProcess:
        def __init__(self, argv, **kwargs):
            observed["argv"] = argv
            observed.update(kwargs)

        def wait(self, timeout=None):
            observed["timeout"] = timeout
            return 0

        def kill(self):
            raise AssertionError("successful process must not be killed")

    monkeypatch.setattr(pair_evidence.subprocess, "Popen", FakeProcess)
    result = pair_evidence.SubprocessDockerRunner().run(
        ["docker", "version"], timeout_seconds=5
    )

    assert result.returncode == 0
    assert observed["shell"] is False
    assert observed["stdin"] is pair_evidence.subprocess.DEVNULL


def test_docker_environment_drops_remote_endpoint_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DOCKER_HOST", "tcp://remote.example:2376")
    monkeypatch.setenv("DOCKER_CONTEXT", "remote-context")

    environment = pair_evidence._docker_environment()

    assert "DOCKER_HOST" not in environment
    assert "DOCKER_CONTEXT" not in environment


@pytest.mark.skipif(
    os.environ.get("K_GUARD_L3_LIVE_DOCKER") != "1",
    reason="requires an explicitly requested local Docker transport smoke run",
)
def test_live_docker_transport_smoke_is_not_a_semantic_pair_oracle(tmp_path: Path) -> None:
    root, manifest, plan, _runner, outputs = _build_bundle(tmp_path)
    (root / "vulnerable" / "app.py").write_bytes(
        outputs[0] + b"def render(value):\n    return value\n"
    )
    (root / "fixed" / "app.py").write_bytes(
        outputs[1] + b"def render(value):\n    return escape(value)\n"
    )
    (root / "oracle" / "regression.py").write_bytes(outputs[2])
    (root / "oracle" / "negative.py").write_bytes(outputs[3])
    (root / "oracle" / "invariants.py").write_bytes(outputs[5])
    physical_diff = pair_evidence._physical_diff(
        (root / "vulnerable").resolve(), (root / "fixed").resolve()
    )
    manifest["hashes"]["vulnerable_source_sha256"] = pair_evidence.regular_tree_receipt(
        (root / "vulnerable").resolve()
    )["tree_sha256"]
    manifest["hashes"]["fixed_source_sha256"] = pair_evidence.regular_tree_receipt(
        (root / "fixed").resolve()
    )["tree_sha256"]
    manifest["diff"]["production_changes"][0].update(physical_diff[0])
    outputs[4] = _structured_result(
        pair_evidence.DIFF_RESULT_SCHEMA,
        "diff",
        "production_changes",
        manifest["diff"]["production_changes"],
    )
    (root / "oracle" / "diff.py").write_bytes(outputs[4])
    for row in manifest["test_oracle_files"]:
        row["content_sha256"] = pair_evidence.sha256_bytes(
            (root / row["path"]).read_bytes()
        )
    plan["commands"] = {
        "exploit": {
            "argv": ["/bin/grep", "^{", "/workspace/app.py"],
            "timeout_seconds": 30,
        },
        "regression": {
            "argv": ["/bin/cat", "/oracle/regression.py"],
            "timeout_seconds": 30,
        },
        "negative_control": {
            "argv": ["/bin/cat", "/oracle/negative.py"],
            "timeout_seconds": 30,
        },
        "diff": {
            "argv": ["/bin/cat", "/oracle/diff.py"],
            "timeout_seconds": 30,
        },
        "invariants": {
            "argv": ["/bin/cat", "/oracle/invariants.py"],
            "timeout_seconds": 30,
        },
    }
    manifest["hashes"].update(
        {
            "exploit_command_sha256": pair_evidence.command_sha256(plan["commands"]["exploit"]),
            "regression_command_sha256": pair_evidence.command_sha256(plan["commands"]["regression"]),
            "negative_control_command_sha256": pair_evidence.command_sha256(
                plan["commands"]["negative_control"]
            ),
            "diff_command_sha256": pair_evidence.command_sha256(plan["commands"]["diff"]),
            "invariants_command_sha256": pair_evidence.command_sha256(
                plan["commands"]["invariants"]
            ),
        }
    )
    manifest["executions"]["exploit_vulnerable"]["command_sha256"] = manifest["hashes"][
        "exploit_command_sha256"
    ]
    manifest["executions"]["exploit_fixed"]["command_sha256"] = manifest["hashes"][
        "exploit_command_sha256"
    ]
    manifest["executions"]["fixed_functional"]["command_sha256"] = manifest["hashes"][
        "regression_command_sha256"
    ]
    manifest["executions"]["negative_control"]["command_sha256"] = manifest["hashes"][
        "negative_control_command_sha256"
    ]
    plan["runtime_image"] = {
        "reference": LIVE_BUSYBOX_REFERENCE,
        "expected_image_id": LIVE_BUSYBOX_ID,
    }
    plan["manifest_subject_sha256"] = pair_subject_sha256(manifest)

    result = pair_evidence.verify_pair_evidence(root.resolve(), manifest, plan)

    assert result["status"] == "PASS"
    assert result["claim_boundary"]["scanner_accuracy_proved"] is False
    assert result["release_gate_passed"] is False
