from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "materialize_l2_runtime.py"
SPEC = importlib.util.spec_from_file_location("materialize_l2_runtime_test", SCRIPT)
assert SPEC and SPEC.loader
runtime = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runtime
SPEC.loader.exec_module(runtime)


class QueueRunner:
    def __init__(self, results: list[runtime.CommandResult]) -> None:
        self.results = list(results)
        self.calls: list[tuple[list[str], int]] = []

    def run(self, argv: list[str], *, timeout: int) -> runtime.CommandResult:
        self.calls.append((list(argv), timeout))
        if not self.results:
            raise AssertionError(f"unexpected command: {argv}")
        return self.results.pop(0)


def _runtime_settings() -> dict:
    return {
        "container_name": "kguard-l2-nodegoat-r1",
        "network_name": "kguard-l2-nodegoat-net-r1",
        "container_port": 4000,
        "run_as": "1000:1000",
        "tmpfs": [{"path": "/tmp", "size_bytes": 4 * 1024 * 1024}],
        "health_probe": {
            "path": "/health",
            "expected_status": [200],
            "timeout_seconds": 2,
            "attempts": 1,
            "interval_seconds": 0,
        },
    }


def _container(settings: dict | None = None) -> dict:
    settings = settings or _runtime_settings()
    port_key = f"{settings['container_port']}/tcp"
    return {
        "Id": "c" * 64,
        "Image": "sha256:" + "a" * 64,
        "Config": {
            "User": settings["run_as"],
            "Labels": {
                "io.k-guard.app-id": "nodegoat",
                "io.k-guard.runtime-contract": "v1",
            },
        },
        "HostConfig": {
            "NetworkMode": settings["network_name"],
            "PortBindings": {port_key: None},
            "ReadonlyRootfs": True,
            "Tmpfs": {
                row["path"]: runtime._tmpfs_option(row).split(":", 1)[1]
                for row in settings["tmpfs"]
            },
            "Binds": None,
            "Mounts": None,
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": runtime.PIDS_LIMIT,
            "Memory": runtime.MEMORY_BYTES,
            "NanoCpus": runtime.NANO_CPUS,
            "Privileged": False,
            "PidMode": "",
            "IpcMode": "private",
            "UTSMode": "",
            "UsernsMode": "private",
            "Devices": [],
            "DeviceRequests": None,
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
        },
        "Mounts": [],
        "NetworkSettings": {
            "Networks": {settings["network_name"]: {"Aliases": ["nodegoat"]}},
            "Ports": {port_key: None},
        },
    }


def _image(reference: str, image_id: str = "sha256:" + "b" * 64) -> dict:
    return {
        "Id": image_id,
        "RepoDigests": [reference],
        "RootFS": {"Type": "layers", "Layers": ["sha256:" + "c" * 64]},
        "Config": {
            "User": "65534:65534",
            "WorkingDir": "/app",
            "Entrypoint": ["/entrypoint"],
            "Cmd": ["serve", "--token", "not-for-receipt"],
            "Env": ["PATH=/usr/bin", "PASSWORD=raw-secret"],
            "ExposedPorts": {"8080/tcp": {}},
            "Labels": {},
        },
    }


def _fake_source_module() -> object:
    identities = {}
    for index, app_id in enumerate(sorted(runtime.APP_IDS)):
        identities[app_id] = {
            "repository_id": f"owner/{app_id}",
            "commit": f"{index + 1:040x}",
            "commit_tree": f"{index + 11:040x}",
            "source_tree_sha256": f"{index + 21:064x}",
            "receipt_sha256": f"{index + 31:064x}",
        }
    return type(
        "SourceModule",
        (),
        {
            "EXPECTED_IDENTITIES": identities,
            "_load_source_materialization_with_hash": staticmethod(
                lambda: (object(), "e" * 64)
            ),
        },
    )()


def _source_admission(module: object, tool_hash: str = "d" * 64) -> dict:
    apps = []
    for app_id in sorted(runtime.APP_IDS):
        locked = module.EXPECTED_IDENTITIES[app_id]
        apps.append(
            {
                "app_id": app_id,
                **locked,
                "source_license_admission": "PASS",
            }
        )
    return {
        "schema": runtime.SOURCE_SCHEMA,
        "source_license_admission": "PASS",
        "runtime_isolation_gate": "HOLD",
        "release_gate_passed": False,
        "tool_provenance": {
            "materializer_artifact": "materialize_l2_sources.py",
            "materializer_sha256": tool_hash,
            "verifier_artifact": "holdout_source_materialization.py",
            "verifier_sha256": "e" * 64,
        },
        "apps": apps,
    }


def _app_plan(app_id: str) -> dict:
    return {
        "app_id": app_id,
        "checkout_relative": app_id,
        "build": {
            "source": {
                "mode": "inspect_existing",
                "image_reference": f"kguard-l2/{app_id}:locked",
                "dockerfile_relative": "Dockerfile",
                "context_relative": ".",
            },
            "adapter": None,
        },
        "runtime": {
            **_runtime_settings(),
            "container_name": f"kguard-l2-{app_id}-r1",
            "network_name": f"kguard-l2-{app_id}-net-r1",
        },
    }


def _plan(source_root: Path, admission_hash: str) -> dict:
    return {
        "schema": runtime.PLAN_SCHEMA,
        "source_admission_sha256": admission_hash,
        "source_root": str(source_root),
        "helper": {
            "image_reference": "library/busybox@sha256:" + "e" * 64,
            "expected_image_id": "sha256:" + "f" * 64,
        },
        "apps": [_app_plan(app_id) for app_id in sorted(runtime.APP_IDS)],
    }


def _write(path: Path, value: object) -> None:
    path.write_bytes(runtime.canonical_json_bytes(value))


def test_container_projection_accepts_only_complete_hardening() -> None:
    projection, checks = runtime._container_projection(
        _container(), _runtime_settings(), "sha256:" + "a" * 64, "nodegoat"
    )

    assert all(checks.values())
    assert projection["privileged"] is False
    assert "PASSWORD" not in json.dumps(projection)


def test_container_projection_rejects_any_host_port_publish() -> None:
    value = _container()
    port_key = "4000/tcp"
    value["HostConfig"]["PortBindings"][port_key] = [
        {"HostIp": "127.0.0.1", "HostPort": "49153"}
    ]
    value["NetworkSettings"]["Ports"][port_key] = [
        {"HostIp": "127.0.0.1", "HostPort": "49153"}
    ]

    _projection, checks = runtime._container_projection(
        value,
        _runtime_settings(),
        "sha256:" + "a" * 64,
        "nodegoat",
    )

    assert checks["no_host_port_publish"] is False


def test_container_projection_requires_the_expected_internal_alias() -> None:
    value = _container()
    value["NetworkSettings"]["Networks"]["kguard-l2-nodegoat-net-r1"]["Aliases"] = []

    _projection, checks = runtime._container_projection(
        value, _runtime_settings(), "sha256:" + "a" * 64, "nodegoat"
    )

    assert checks["network_alias_present"] is False


def test_container_creation_uses_internal_alias_without_host_publish() -> None:
    settings = _runtime_settings()
    runner = QueueRunner(
        [
            runtime.CommandResult(1, b"", b"not found"),
            runtime.CommandResult(0, b"c" * 64 + b"\n", b""),
            runtime.CommandResult(0, json.dumps([_container()]).encode(), b""),
        ]
    )
    created = {"container": None}

    receipt = runtime._create_container(
        runner,
        "nodegoat",
        settings,
        "sha256:" + "a" * 64,
        created,
    )

    argv = runner.calls[1][0]
    assert receipt["passed"] is True
    assert "--publish" not in argv
    assert "-p" not in argv
    assert "-P" not in argv
    assert argv[argv.index("--network-alias") + 1] == "nodegoat"


def test_runtime_plan_keeps_legacy_tmpfs_and_allows_nonroot_uid_with_root_group() -> None:
    legacy = runtime._validate_runtime_plan(_runtime_settings())
    assert legacy["tmpfs"] == [{"path": "/tmp", "size_bytes": 4 * 1024 * 1024}]

    owned = _runtime_settings()
    owned["run_as"] = "65532:0"
    owned["tmpfs"] = [
        {
            "path": "/tmp",
            "size_bytes": 4 * 1024 * 1024,
            "uid": 65532,
            "gid": 0,
            "mode": "0770",
        }
    ]

    assert runtime._validate_runtime_plan(owned)["tmpfs"] == owned["tmpfs"]


@pytest.mark.parametrize("run_as", ["0:0", "65532:4294967296"])
def test_runtime_plan_rejects_root_or_out_of_range_runtime_identity(run_as: str) -> None:
    settings = _runtime_settings()
    settings["run_as"] = run_as

    with pytest.raises(runtime.RuntimeContractError):
        runtime._validate_runtime_plan(settings)


@pytest.mark.parametrize(
    "row",
    [
        {"path": "/tmp", "size_bytes": 4096, "uid": 65532},
        {"path": "/tmp", "size_bytes": 4096, "uid": 65532, "gid": 0},
        {
            "path": "/tmp",
            "size_bytes": 4096,
            "uid": 65532,
            "gid": 0,
            "mode": "0777",
        },
        {
            "path": "/tmp",
            "size_bytes": 4096,
            "uid": 65532,
            "gid": 0,
            "mode": "075",
        },
    ],
)
def test_runtime_plan_rejects_partial_or_world_accessible_tmpfs_ownership(row: dict) -> None:
    settings = _runtime_settings()
    settings["run_as"] = "65532:0"
    settings["tmpfs"] = [row]

    with pytest.raises(runtime.RuntimeContractError):
        runtime._validate_runtime_plan(settings)


def test_runtime_plan_rejects_tmpfs_owner_that_differs_from_runtime_user() -> None:
    settings = _runtime_settings()
    settings["run_as"] = "65532:0"
    settings["tmpfs"] = [
        {
            "path": "/tmp",
            "size_bytes": 4096,
            "uid": 1000,
            "gid": 0,
            "mode": "0770",
        }
    ]

    with pytest.raises(runtime.RuntimeContractError, match="exactly match"):
        runtime._validate_runtime_plan(settings)


def test_tmpfs_option_and_projection_bind_declared_owner_mode() -> None:
    settings = _runtime_settings()
    settings["run_as"] = "65532:0"
    settings["tmpfs"] = [
        {
            "path": "/tmp",
            "size_bytes": 4 * 1024 * 1024,
            "uid": 65532,
            "gid": 0,
            "mode": "0770",
        }
    ]

    assert runtime._tmpfs_option(settings["tmpfs"][0]) == (
        "/tmp:rw,noexec,nosuid,nodev,size=4194304,uid=65532,gid=0,mode=0770"
    )
    _projection, checks = runtime._container_projection(
        _container(settings), settings, "sha256:" + "a" * 64, "nodegoat"
    )

    assert all(checks.values())


@pytest.mark.parametrize(
    "actual_options",
    [
        "rw,noexec,nosuid,nodev,size=4194304,uid=65532,gid=0",
        "rw,noexec,nosuid,nodev,size=4194304,uid=0,gid=0,mode=0770",
        "rw,noexec,nosuid,nodev,size=4194304,uid=65532,gid=0,mode=0777",
        "rw,exec,nosuid,nodev,size=4194304,uid=65532,gid=0,mode=0770",
        "rw,noexec,nosuid,nodev,size=4194304,uid=65532,gid=0,mode=0770,uid=0",
    ],
)
def test_container_projection_rejects_missing_or_forged_tmpfs_owner_mode(
    actual_options: str,
) -> None:
    settings = _runtime_settings()
    settings["run_as"] = "65532:0"
    settings["tmpfs"] = [
        {
            "path": "/tmp",
            "size_bytes": 4 * 1024 * 1024,
            "uid": 65532,
            "gid": 0,
            "mode": "0770",
        }
    ]
    value = _container(settings)
    value["HostConfig"]["Tmpfs"]["/tmp"] = actual_options

    _projection, checks = runtime._container_projection(
        value, settings, "sha256:" + "a" * 64, "nodegoat"
    )

    assert checks["tmpfs_options_hardened"] is False


def test_container_creation_serializes_declared_tmpfs_owner_and_mode() -> None:
    settings = _runtime_settings()
    settings["run_as"] = "65532:0"
    settings["tmpfs"] = [
        {
            "path": "/tmp",
            "size_bytes": 4 * 1024 * 1024,
            "uid": 65532,
            "gid": 0,
            "mode": "0770",
        }
    ]
    runner = QueueRunner(
        [
            runtime.CommandResult(1, b"", b"not found"),
            runtime.CommandResult(0, b"c" * 64 + b"\n", b""),
            runtime.CommandResult(0, json.dumps([_container(settings)]).encode(), b""),
        ]
    )

    receipt = runtime._create_container(
        runner,
        "nodegoat",
        settings,
        "sha256:" + "a" * 64,
        {"container": None},
    )

    argv = runner.calls[1][0]
    assert receipt["passed"] is True
    assert argv[argv.index("--tmpfs") + 1] == (
        "/tmp:rw,noexec,nosuid,nodev,size=4194304,uid=65532,gid=0,mode=0770"
    )


@pytest.mark.parametrize(
    ("mutate", "failed_check"),
    [
        (lambda value: value["HostConfig"].update(NetworkMode="bridge"), "network_mode_exact"),
        (lambda value: value["NetworkSettings"].update(Networks={"bridge": {}}), "single_internal_network"),
        (lambda value: value["HostConfig"].update(Privileged=True), "not_privileged"),
        (lambda value: value["HostConfig"].update(CapDrop=[]), "cap_drop_all"),
        (lambda value: value["HostConfig"].update(CapAdd=["SYS_ADMIN"]), "cap_drop_all"),
        (lambda value: value["HostConfig"].update(SecurityOpt=[]), "no_new_privileges"),
        (lambda value: value["HostConfig"].update(ReadonlyRootfs=False), "read_only_rootfs"),
        (lambda value: value["HostConfig"].update(Binds=["/:/host:ro"]), "no_bind_or_volume_mounts"),
        (lambda value: value.update(Mounts=[{"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}]), "docker_socket_absent"),
        (lambda value: value["HostConfig"].update(PidsLimit=0), "pids_bounded"),
        (lambda value: value["HostConfig"].update(Memory=0), "memory_bounded"),
        (lambda value: value["HostConfig"].update(NanoCpus=0), "cpu_bounded"),
        (lambda value: value["HostConfig"].update(PidMode="host"), "no_host_pid"),
        (lambda value: value["HostConfig"].update(IpcMode="host"), "no_host_ipc"),
        (lambda value: value["HostConfig"].update(UTSMode="host"), "no_host_uts"),
        (lambda value: value["HostConfig"].update(UsernsMode="host"), "no_host_userns"),
        (lambda value: value["Config"].update(User="0:0"), "non_root_user"),
    ],
)
def test_container_projection_fails_closed_on_forged_or_unsafe_inspect(
    mutate, failed_check: str
) -> None:
    value = _container()
    mutate(value)

    _projection, checks = runtime._container_projection(
        value, _runtime_settings(), "sha256:" + "a" * 64, "nodegoat"
    )

    assert checks[failed_check] is False


def test_wrong_image_and_app_labels_do_not_pass() -> None:
    value = _container()
    value["Image"] = "sha256:" + "9" * 64
    value["Config"]["Labels"]["io.k-guard.app-id"] = "crapi"

    _projection, checks = runtime._container_projection(
        value, _runtime_settings(), "sha256:" + "a" * 64, "nodegoat"
    )

    assert checks["image_id_exact"] is False
    assert checks["app_label_exact"] is False


def test_image_projection_redacts_commands_and_environment_values() -> None:
    projection = runtime._image_projection(
        _image("library/busybox@sha256:" + "e" * 64)
    )
    rendered = json.dumps(projection, sort_keys=True)

    assert "raw-secret" not in rendered
    assert "not-for-receipt" not in rendered
    assert projection["config"]["env_names"] == ["PASSWORD", "PATH"]
    assert len(projection["config"]["cmd_sha256"]) == 64


def test_existing_image_labels_are_observation_not_build_proof(tmp_path: Path) -> None:
    checkout = tmp_path / "nodegoat"
    checkout.mkdir()
    (checkout / "Dockerfile").write_text("FROM scratch\n", encoding="ascii")
    source_row = {
        "commit": "1" * 40,
        "source_tree_sha256": "2" * 64,
    }
    app = _app_plan("nodegoat")
    dockerfile_hash = runtime.sha256_bytes((checkout / "Dockerfile").read_bytes())
    image = _image("kguard-l2/nodegoat@sha256:" + "3" * 64)
    image["Config"]["Labels"] = runtime._source_labels(
        "nodegoat", source_row, dockerfile_hash
    )
    runner = QueueRunner(
        [runtime.CommandResult(0, json.dumps([image]).encode(), b"")]
    )

    result, _image_id = runtime._prepare_images(
        runner, "nodegoat", app, checkout, source_row, tmp_path
    )

    assert all(result["source"]["label_checks"].values())
    assert result["source"]["passed"] is False
    assert result["source"]["claim_boundary"] == "existing_image_observed_not_proven"


def test_adapter_must_extend_the_exact_source_image_layers(tmp_path: Path) -> None:
    source_root = tmp_path / "sources"
    checkout = source_root / "nodegoat"
    checkout.mkdir(parents=True)
    (checkout / "Dockerfile").write_text("FROM scratch\n", encoding="ascii")
    adapter_root = tmp_path / "adapter"
    adapter_root.mkdir()
    (adapter_root / "Dockerfile").write_text(
        "ARG SOURCE_IMAGE\nFROM ${SOURCE_IMAGE}\n", encoding="ascii"
    )
    source_row = {"commit": "1" * 40, "source_tree_sha256": "2" * 64}
    app = _app_plan("nodegoat")
    app["build"]["adapter"] = {
        "root": str(adapter_root),
        "image_reference": "kguard-l2/nodegoat-adapter:locked",
        "dockerfile_relative": "Dockerfile",
        "context_relative": ".",
    }
    source_image = _image("kguard-l2/nodegoat@sha256:" + "3" * 64)
    source_image["Config"]["Labels"] = runtime._source_labels(
        "nodegoat",
        source_row,
        runtime.sha256_bytes((checkout / "Dockerfile").read_bytes()),
    )
    adapter_tree = runtime._regular_tree_receipt(adapter_root)
    adapter_image = _image(
        "kguard-l2/nodegoat-adapter@sha256:" + "4" * 64,
        "sha256:" + "5" * 64,
    )
    adapter_image["RootFS"]["Layers"] = ["sha256:" + "9" * 64]
    adapter_image["Config"]["Labels"] = {
        "io.k-guard.adapter-tree-sha256": adapter_tree["tree_sha256"],
        "io.k-guard.app-id": "nodegoat",
        "io.k-guard.source-image-id": source_image["Id"],
        "io.k-guard.source-tree-sha256": source_row["source_tree_sha256"],
    }
    runner = QueueRunner(
        [
            runtime.CommandResult(0, json.dumps([source_image]).encode(), b""),
            runtime.CommandResult(0, b"adapter build", b""),
            runtime.CommandResult(0, json.dumps([source_image]).encode(), b""),
            runtime.CommandResult(0, json.dumps([adapter_image]).encode(), b""),
        ]
    )

    result, _image_id = runtime._prepare_images(
        runner, "nodegoat", app, checkout, source_row, source_root
    )

    assert result["adapter"]["label_checks"]["source_layers_are_prefix"] is False
    assert result["adapter"]["passed"] is False
    assert "SOURCE_IMAGE=kguard-l2/nodegoat:locked" in runner.calls[1][0]


def test_adapter_rejects_source_tag_rebound_after_build(tmp_path: Path) -> None:
    source_root = tmp_path / "sources"
    checkout = source_root / "nodegoat"
    checkout.mkdir(parents=True)
    (checkout / "Dockerfile").write_text("FROM scratch\n", encoding="ascii")
    adapter_root = tmp_path / "adapter"
    adapter_root.mkdir()
    (adapter_root / "Dockerfile").write_text(
        "ARG SOURCE_IMAGE\nFROM ${SOURCE_IMAGE}\n", encoding="ascii"
    )
    source_row = {"commit": "1" * 40, "source_tree_sha256": "2" * 64}
    app = _app_plan("nodegoat")
    app["build"]["adapter"] = {
        "root": str(adapter_root),
        "image_reference": "kguard-l2/nodegoat-adapter:locked",
        "dockerfile_relative": "Dockerfile",
        "context_relative": ".",
    }
    source_image = _image("kguard-l2/nodegoat@sha256:" + "3" * 64)
    source_image["Config"]["Labels"] = runtime._source_labels(
        "nodegoat",
        source_row,
        runtime.sha256_bytes((checkout / "Dockerfile").read_bytes()),
    )
    rebound_source = copy.deepcopy(source_image)
    rebound_source["Id"] = "sha256:" + "6" * 64
    rebound_source["RootFS"]["Layers"] = ["sha256:" + "7" * 64]
    adapter_tree = runtime._regular_tree_receipt(adapter_root)
    adapter_image = _image(
        "kguard-l2/nodegoat-adapter@sha256:" + "4" * 64,
        "sha256:" + "5" * 64,
    )
    adapter_image["RootFS"]["Layers"] = list(source_image["RootFS"]["Layers"]) + [
        "sha256:" + "8" * 64
    ]
    adapter_image["Config"]["Labels"] = {
        "io.k-guard.adapter-tree-sha256": adapter_tree["tree_sha256"],
        "io.k-guard.app-id": "nodegoat",
        "io.k-guard.source-image-id": source_image["Id"],
        "io.k-guard.source-tree-sha256": source_row["source_tree_sha256"],
    }
    runner = QueueRunner(
        [
            runtime.CommandResult(0, json.dumps([source_image]).encode(), b""),
            runtime.CommandResult(0, b"adapter build", b""),
            runtime.CommandResult(0, json.dumps([rebound_source]).encode(), b""),
            runtime.CommandResult(0, json.dumps([adapter_image]).encode(), b""),
        ]
    )

    result, _image_id = runtime._prepare_images(
        runner, "nodegoat", app, checkout, source_row, source_root
    )

    assert result["adapter"]["label_checks"]["source_reference_unchanged"] is False
    assert result["adapter"]["passed"] is False


def test_adapter_tree_is_size_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = tmp_path / "adapter"
    adapter.mkdir()
    (adapter / "large.bin").write_bytes(b"12345")
    monkeypatch.setattr(runtime, "MAX_ADAPTER_FILE_BYTES", 4)

    with pytest.raises(runtime.RuntimeContractError, match="size limit"):
        runtime._regular_tree_receipt(adapter)


def test_source_admission_rejects_wrong_commit_even_when_pass_booleans_are_forged() -> None:
    module = _fake_source_module()
    admission = _source_admission(module)
    admission["apps"][0]["commit"] = "0" * 40

    with pytest.raises(runtime.RuntimeContractError, match="source identity"):
        runtime._validate_source_admission(
            admission, runtime.canonical_json_bytes(admission), module, "d" * 64
        )


def test_source_admission_requires_runtime_gate_to_remain_hold() -> None:
    module = _fake_source_module()
    admission = _source_admission(module)
    admission["runtime_isolation_gate"] = "PASS"

    with pytest.raises(runtime.RuntimeContractError, match="improperly claims"):
        runtime._validate_source_admission(
            admission, runtime.canonical_json_bytes(admission), module, "d" * 64
        )


def test_source_admission_rejects_stale_git_verifier_provenance() -> None:
    module = _fake_source_module()
    admission = _source_admission(module)
    admission["tool_provenance"]["verifier_sha256"] = "0" * 64

    with pytest.raises(runtime.RuntimeContractError, match="provenance"):
        runtime._validate_source_admission(
            admission, runtime.canonical_json_bytes(admission), module, "d" * 64
        )


def test_source_admission_exact_six_app_identity_passes() -> None:
    module = _fake_source_module()
    admission = _source_admission(module)

    indexed = runtime._validate_source_admission(
        admission, runtime.canonical_json_bytes(admission), module, "d" * 64
    )

    assert set(indexed) == runtime.APP_IDS


def test_helper_requires_digest_and_immutable_image_id() -> None:
    with pytest.raises(runtime.RuntimeContractError, match="pinned"):
        runtime._validate_helper_plan(
            {"image_reference": "busybox:latest", "expected_image_id": "sha256:" + "a" * 64}
        )
    with pytest.raises(runtime.RuntimeContractError, match="immutable"):
        runtime._validate_helper_plan(
            {
                "image_reference": "library/busybox@sha256:" + "a" * 64,
                "expected_image_id": "busybox:latest",
            }
        )


def test_egress_probe_passes_only_for_exact_pinned_helper_and_denied_request() -> None:
    reference = "library/busybox@sha256:" + "e" * 64
    image_id = "sha256:" + "f" * 64
    runner = QueueRunner(
        [
            runtime.CommandResult(0, json.dumps([_image(reference, image_id)]).encode(), b""),
            runtime.CommandResult(0, b"BusyBox wget", b""),
            runtime.CommandResult(1, b"", b"network unreachable"),
        ]
    )

    receipt = runtime._egress_probe(
        runner,
        {"image_reference": reference, "expected_image_id": image_id},
        "kguard-l2-nodegoat-net-r1",
    )

    assert receipt["passed"] is True
    assert receipt["command"]["raw_returned"] is False
    assert all(call[0][0] == "docker" for call in runner.calls)


def test_egress_probe_rejects_mutable_or_wrong_helper_identity() -> None:
    reference = "library/busybox@sha256:" + "e" * 64
    runner = QueueRunner(
        [
            runtime.CommandResult(
                0,
                json.dumps([_image(reference, "sha256:" + "1" * 64)]).encode(),
                b"",
            ),
            runtime.CommandResult(0, b"BusyBox wget", b""),
            runtime.CommandResult(1, b"", b"denied"),
        ]
    )

    receipt = runtime._egress_probe(
        runner,
        {"image_reference": reference, "expected_image_id": "sha256:" + "2" * 64},
        "kguard-l2-nodegoat-net-r1",
    )

    assert receipt["passed"] is False
    assert receipt["checks"]["helper_image_id_exact"] is False


def test_network_evidence_requires_actual_internal_local_bridge() -> None:
    network_id = "a" * 64
    network = {
        "Id": network_id,
        "Driver": "bridge",
        "Internal": False,
        "Ingress": False,
        "Scope": "local",
        "Labels": {
            "io.k-guard.app-id": "nodegoat",
            "io.k-guard.runtime-contract": "v1",
        },
    }
    runner = QueueRunner(
        [
            runtime.CommandResult(1, b"", b"not found"),
            runtime.CommandResult(0, f"{network_id}\n".encode("ascii"), b""),
            runtime.CommandResult(0, json.dumps([network]).encode(), b""),
        ]
    )
    created = {"container": None, "network": None}

    receipt = runtime._create_network(
        runner, "nodegoat", "kguard-l2-nodegoat-net-r1", created
    )

    assert receipt["passed"] is False
    assert receipt["checks"]["internal_true"] is False
    assert created["network"] == network_id


def test_cleanup_removes_only_the_exact_object_created_by_this_run() -> None:
    name = "kguard-l2-nodegoat-observe-r1"
    object_id = "c" * 64
    inspect = {
        "Id": object_id,
        "Config": {
            "Labels": {
                "io.k-guard.app-id": "nodegoat",
                "io.k-guard.runtime-contract": "v1",
            }
        },
    }
    runner = QueueRunner(
        [
            runtime.CommandResult(0, f"{name}\t{object_id[:12]}\n".encode(), b""),
            runtime.CommandResult(0, json.dumps([inspect]).encode(), b""),
            runtime.CommandResult(0, f"{object_id}\n".encode(), b""),
            runtime.CommandResult(0, b"", b""),
        ]
    )

    receipt = runtime._cleanup_owned_object(
        runner,
        kind="container",
        name=name,
        app_id="nodegoat",
        expected_object_id=object_id,
    )

    assert receipt["passed"] is True
    assert receipt["ownership_verified"] is True
    assert receipt["removed"] is True
    assert receipt["absent_after"] is True
    assert runner.calls[2][0] == ["docker", "container", "rm", "--force", name]


def test_cleanup_never_removes_an_unexpected_preexisting_object() -> None:
    name = "kguard-l2-nodegoat-observe-r1"
    object_id = "d" * 64
    runner = QueueRunner(
        [
            runtime.CommandResult(0, f"{name}\t{object_id[:12]}\n".encode(), b""),
        ]
    )

    receipt = runtime._cleanup_owned_object(
        runner,
        kind="container",
        name=name,
        app_id="nodegoat",
        expected_object_id=None,
    )

    assert receipt["passed"] is False
    assert receipt["removed"] is False
    assert receipt["blocker"] == "cleanup_unexpected_preexisting_object"
    assert len(runner.calls) == 1


def test_cleanup_rejects_id_or_label_swap_without_removing() -> None:
    name = "kguard-l2-nodegoat-net-r1"
    expected_id = "e" * 64
    actual_id = "f" * 64
    inspect = {
        "Id": actual_id,
        "Labels": {
            "io.k-guard.app-id": "juice-shop",
            "io.k-guard.runtime-contract": "v1",
        },
    }
    runner = QueueRunner(
        [
            runtime.CommandResult(0, f"{name}\t{actual_id[:12]}\n".encode(), b""),
            runtime.CommandResult(0, json.dumps([inspect]).encode(), b""),
        ]
    )

    receipt = runtime._cleanup_owned_object(
        runner,
        kind="network",
        name=name,
        app_id="nodegoat",
        expected_object_id=expected_id,
    )

    assert receipt["passed"] is False
    assert receipt["removed"] is False
    assert receipt["blocker"] == "cleanup_ownership_mismatch"
    assert len(runner.calls) == 2


def test_post_start_container_must_be_same_running_hardened_object() -> None:
    value = _container()
    value["State"] = {
        "Status": "running",
        "Running": True,
        "Paused": False,
        "Restarting": False,
        "OOMKilled": False,
        "Dead": False,
        "ExitCode": 0,
        "Error": "",
    }
    runner = QueueRunner(
        [runtime.CommandResult(0, json.dumps([value]).encode(), b"")]
    )

    receipt = runtime._observe_container_after_start(
        runner,
        "nodegoat",
        _runtime_settings(),
        "sha256:" + "a" * 64,
        "c" * 64,
    )

    assert receipt["passed"] is True
    assert receipt["state"]["raw_error_returned"] is False


def test_post_start_exited_or_replaced_container_is_hold() -> None:
    value = _container()
    value["Id"] = "d" * 64
    value["State"] = {
        "Status": "exited",
        "Running": False,
        "Paused": False,
        "Restarting": False,
        "OOMKilled": False,
        "Dead": False,
        "ExitCode": 1,
        "Error": "sensitive runtime error",
    }
    runner = QueueRunner(
        [runtime.CommandResult(0, json.dumps([value]).encode(), b"")]
    )

    receipt = runtime._observe_container_after_start(
        runner,
        "nodegoat",
        _runtime_settings(),
        "sha256:" + "a" * 64,
        "c" * 64,
    )

    assert receipt["passed"] is False
    assert receipt["checks"]["same_container_id"] is False
    assert receipt["checks"]["running"] is False
    assert "sensitive runtime error" not in json.dumps(receipt)


def test_post_runtime_network_rejects_external_or_extra_container() -> None:
    expected = "c" * 64
    network = {
        "Id": "n" * 64,
        "Driver": "bridge",
        "Internal": True,
        "Ingress": False,
        "Scope": "local",
        "Labels": {
            "io.k-guard.app-id": "nodegoat",
            "io.k-guard.runtime-contract": "v1",
        },
        "Containers": {expected: {}, "d" * 64: {}},
    }
    runner = QueueRunner(
        [runtime.CommandResult(0, json.dumps([network]).encode(), b"")]
    )

    receipt = runtime._observe_network_after_runtime(
        runner, "nodegoat", "kguard-l2-nodegoat-net-r1", expected
    )

    assert receipt["passed"] is False
    assert receipt["checks"]["only_expected_container_attached"] is False


def test_plan_rejects_duplicate_objects_wrong_app_and_wrong_source_binding(tmp_path: Path) -> None:
    admission_hash = "a" * 64
    plan = _plan(tmp_path, admission_hash)
    plan["apps"][1]["runtime"]["network_name"] = plan["apps"][0]["runtime"]["container_name"]
    with pytest.raises(runtime.RuntimeContractError, match="globally unique"):
        runtime._validate_plan(plan, admission_hash, tmp_path.resolve())

    plan = _plan(tmp_path, admission_hash)
    plan["source_admission_sha256"] = "b" * 64
    with pytest.raises(runtime.RuntimeContractError, match="not bound"):
        runtime._validate_plan(plan, admission_hash, tmp_path.resolve())

    plan = _plan(tmp_path, admission_hash)
    plan["apps"][0]["app_id"] = "unknown"
    with pytest.raises(runtime.RuntimeContractError, match="outside"):
        runtime._validate_plan(plan, admission_hash, tmp_path.resolve())


def test_path_traversal_and_symlink_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    child = root / "child"
    child.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(runtime.RuntimeContractError, match="normalized"):
        runtime._safe_relative(root.resolve(), "../outside", label="checkout")

    link = root / "linked"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(runtime.RuntimeContractError, match="link or reparse"):
        runtime._safe_relative(root.resolve(), "linked", label="checkout")


def test_adapter_tree_rejects_symlink(tmp_path: Path) -> None:
    root = tmp_path / "adapter"
    root.mkdir()
    (root / "Dockerfile").write_text("FROM scratch\n", encoding="ascii")
    target = tmp_path / "secret"
    target.write_text("secret", encoding="ascii")
    try:
        os.symlink(target, root / "link")
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(runtime.RuntimeContractError, match="link or reparse"):
        runtime._regular_tree_receipt(root)


def _wget_help_with_server_response_flag() -> runtime.CommandResult:
    return runtime.CommandResult(0, b"\t-S \t Show server response\n", b"")


def test_internal_health_probe_uses_pinned_helper_and_redacts_headers() -> None:
    reference = "library/busybox@sha256:" + "e" * 64
    runner = QueueRunner(
        [
            runtime.CommandResult(
                0,
                json.dumps([_image(reference, "sha256:" + "f" * 64)]).encode(),
                b"",
            ),
            _wget_help_with_server_response_flag(),
            runtime.CommandResult(
                0,
                b"",
                b"  HTTP/1.1 200 OK\r\n  X-Test: secret-header-value\r\n",
            ),
        ]
    )

    receipt = runtime._internal_health_probe(
        runner,
        _plan(Path.cwd(), "a" * 64)["helper"],
        "kguard-l2-nodegoat-net-r1",
        "nodegoat",
        _runtime_settings(),
    )

    rendered = json.dumps(receipt, sort_keys=True)
    assert receipt["passed"] is True
    assert receipt["status"] == 200
    assert "secret-header-value" not in rendered
    assert runner.calls[2][0][-1] == "http://nodegoat:4000/health"
    assert "--network" in runner.calls[2][0]


def test_internal_health_probe_fails_closed_when_wget_does_not_emit_status() -> None:
    reference = "library/busybox@sha256:" + "e" * 64
    runner = QueueRunner(
        [
            runtime.CommandResult(
                0,
                json.dumps([_image(reference, "sha256:" + "f" * 64)]).encode(),
                b"",
            ),
            _wget_help_with_server_response_flag(),
            runtime.CommandResult(0, b"", b"unstructured helper output"),
        ]
    )

    receipt = runtime._internal_health_probe(
        runner,
        _plan(Path.cwd(), "a" * 64)["helper"],
        "kguard-l2-nodegoat-net-r1",
        "nodegoat",
        _runtime_settings(),
    )

    assert receipt["passed"] is False
    assert receipt["checks"]["response_status_observed"] is False


@pytest.mark.parametrize(
    ("helper", "image", "failed_check"),
    [
        (
            {
                "image_reference": "library/busybox@sha256:" + "e" * 64,
                "expected_image_id": "sha256:" + "f" * 64,
            },
            _image(
                "library/busybox@sha256:" + "e" * 64,
                "sha256:" + "a" * 64,
            ),
            "helper_image_id_exact",
        ),
        (
            {
                "image_reference": "library/busybox:latest",
                "expected_image_id": "sha256:" + "f" * 64,
            },
            _image("library/busybox:latest", "sha256:" + "f" * 64),
            "helper_reference_digest_pinned",
        ),
    ],
)
def test_internal_health_probe_fails_closed_on_untrusted_helper(
    helper: dict, image: dict, failed_check: str
) -> None:
    runner = QueueRunner(
        [
            runtime.CommandResult(0, json.dumps([image]).encode(), b""),
        ]
    )

    receipt = runtime._internal_health_probe(
        runner,
        helper,
        "kguard-l2-nodegoat-net-r1",
        "nodegoat",
        _runtime_settings(),
    )

    assert receipt["passed"] is False
    assert receipt["checks"][failed_check] is False
    assert receipt["checks"]["probe_executed"] is False
    assert len(runner.calls) == 1


@pytest.mark.parametrize(
    ("probe", "failed_check"),
    [
        (
            runtime.CommandResult(0, b"", b"  HTTP/1.1 500 Internal Server Error\r\n"),
            "response_status_expected",
        ),
        (
            runtime.CommandResult(1, b"", b"  HTTP/1.1 200 OK\r\n"),
            "request_succeeded",
        ),
        (
            runtime.CommandResult(0, b"", b"", timed_out=True),
            "probe_executed",
        ),
        (
            runtime.CommandResult(0, b"", b"", output_truncated=True),
            "probe_executed",
        ),
    ],
)
def test_internal_health_probe_fails_closed_on_bad_result(
    probe: runtime.CommandResult, failed_check: str
) -> None:
    reference = "library/busybox@sha256:" + "e" * 64
    runner = QueueRunner(
        [
            runtime.CommandResult(
                0,
                json.dumps([_image(reference, "sha256:" + "f" * 64)]).encode(),
                b"",
            ),
            _wget_help_with_server_response_flag(),
            probe,
        ]
    )

    receipt = runtime._internal_health_probe(
        runner,
        _plan(Path.cwd(), "a" * 64)["helper"],
        "kguard-l2-nodegoat-net-r1",
        "nodegoat",
        _runtime_settings(),
    )

    assert receipt["passed"] is False
    assert receipt["checks"][failed_check] is False


def test_internal_health_probe_refuses_helper_without_server_response_flag() -> None:
    reference = "library/busybox@sha256:" + "e" * 64
    runner = QueueRunner(
        [
            runtime.CommandResult(
                0,
                json.dumps([_image(reference, "sha256:" + "f" * 64)]).encode(),
                b"",
            ),
            runtime.CommandResult(0, b"wget help without status flag\n", b""),
        ]
    )

    receipt = runtime._internal_health_probe(
        runner,
        _plan(Path.cwd(), "a" * 64)["helper"],
        "kguard-l2-nodegoat-net-r1",
        "nodegoat",
        _runtime_settings(),
    )

    assert receipt["passed"] is False
    assert receipt["checks"]["helper_server_response_supported"] is False
    assert receipt["checks"]["probe_executed"] is False
    assert len(runner.calls) == 2


def test_internal_health_status_parser_uses_the_first_helper_status_line() -> None:
    fixture = (
        b"Connecting to nodegoat (172.20.0.2:4000)\n"
        b"  HTTP/1.1 200 OK\r\n"
        b"  X-Test: value\r\n"
        b"HTTP/1.1 500 injected\r\n"
    )
    reference = "library/busybox@sha256:" + "e" * 64
    runner = QueueRunner(
        [
            runtime.CommandResult(
                0,
                json.dumps([_image(reference, "sha256:" + "f" * 64)]).encode(),
                b"",
            ),
            _wget_help_with_server_response_flag(),
            runtime.CommandResult(0, b"", fixture),
        ]
    )

    assert runtime.HTTP_STATUS_RE.findall(fixture) == [b"200", b"500"]
    receipt = runtime._internal_health_probe(
        runner,
        _plan(Path.cwd(), "a" * 64)["helper"],
        "kguard-l2-nodegoat-net-r1",
        "nodegoat",
        _runtime_settings(),
    )
    assert receipt["passed"] is True
    assert receipt["status"] == 200


def test_internal_health_probe_rejects_later_forged_success_status() -> None:
    fixture = (
        b"  HTTP/1.1 500 Internal Server Error\r\n"
        b"  X-Test: value\r\n"
        b"HTTP/1.1 200 injected\r\n"
    )
    reference = "library/busybox@sha256:" + "e" * 64
    runner = QueueRunner(
        [
            runtime.CommandResult(
                0,
                json.dumps([_image(reference, "sha256:" + "f" * 64)]).encode(),
                b"",
            ),
            _wget_help_with_server_response_flag(),
            runtime.CommandResult(1, b"", fixture),
        ]
    )

    receipt = runtime._internal_health_probe(
        runner,
        _plan(Path.cwd(), "a" * 64)["helper"],
        "kguard-l2-nodegoat-net-r1",
        "nodegoat",
        _runtime_settings(),
    )

    assert receipt["passed"] is False
    assert receipt["status"] == 500
    assert receipt["checks"]["response_status_expected"] is False


def test_health_plan_rejects_statuses_wget_cannot_treat_as_success() -> None:
    value = _runtime_settings()["health_probe"]
    value["expected_status"] = [500]

    with pytest.raises(runtime.RuntimeContractError, match="expected_status"):
        runtime._validate_health_plan(value)


@pytest.mark.parametrize(
    ("post_health", "expected_state", "replacement"),
    [
        ({"passed": False, "state": {"status": "exited"}}, "exited", False),
        (
            {
                "passed": False,
                "state": {"status": "running"},
                "checks": {"same_container_id": False},
            },
            "running",
            True,
        ),
    ],
)
def test_materialize_app_holds_when_post_health_observation_is_unsafe(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    post_health: dict,
    expected_state: str,
    replacement: bool,
) -> None:
    app = _app_plan("nodegoat")
    (tmp_path / "nodegoat").mkdir()
    source_snapshot = {"tree": "locked"}
    events: list[str] = []
    observations = iter(
        [
            {"passed": True, "state": {"status": "running"}},
            post_health,
        ]
    )

    monkeypatch.setattr(runtime, "_verify_checkout", lambda *_args: source_snapshot)
    monkeypatch.setattr(
        runtime,
        "_prepare_images",
        lambda *_args: (
            {"source": {"passed": True}, "adapter": None},
            "sha256:" + "a" * 64,
        ),
    )
    monkeypatch.setattr(runtime, "_create_network", lambda *_args: {"passed": True})
    monkeypatch.setattr(
        runtime,
        "_create_container",
        lambda *_args: {"id": "c" * 64, "passed": True},
    )
    monkeypatch.setattr(
        runtime,
        "_docker",
        lambda *_args, **_kwargs: runtime.CommandResult(0, b"", b""),
    )

    def observe(*_args: object) -> dict:
        events.append("observe")
        return next(observations)

    def health(*_args: object) -> dict:
        events.append("health")
        return {"executed": True, "passed": True, "status": 200, "raw_returned": False}

    monkeypatch.setattr(runtime, "_observe_container_after_start", observe)
    monkeypatch.setattr(runtime, "_internal_health_probe", health)
    monkeypatch.setattr(runtime, "_egress_probe", lambda *_args: {"passed": True})
    monkeypatch.setattr(
        runtime, "_observe_network_after_runtime", lambda *_args: {"passed": True}
    )

    result = runtime._materialize_app(
        QueueRunner([]),
        "nodegoat",
        app,
        {"repository_id": "owner/nodegoat", "commit": "1" * 40, "source_tree_sha256": "2" * 64},
        object(),
        tmp_path,
        _plan(tmp_path, "a" * 64)["helper"],
        {"container": None, "network": None},
    )

    assert events == ["observe", "health", "observe"]
    assert result["container"]["post_health"]["state"]["status"] == expected_state
    if replacement:
        assert result["container"]["post_health"]["checks"]["same_container_id"] is False
    assert result["checks"]["container_isolation"] is False
    assert result["status"] == "HOLD"


def test_materialize_app_skips_health_when_container_start_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    app = _app_plan("nodegoat")
    (tmp_path / "nodegoat").mkdir()
    source_snapshot = {"tree": "locked"}

    monkeypatch.setattr(runtime, "_verify_checkout", lambda *_args: source_snapshot)
    monkeypatch.setattr(
        runtime,
        "_prepare_images",
        lambda *_args: (
            {"source": {"passed": True}, "adapter": None},
            "sha256:" + "a" * 64,
        ),
    )
    monkeypatch.setattr(runtime, "_create_network", lambda *_args: {"passed": True})
    monkeypatch.setattr(
        runtime,
        "_create_container",
        lambda *_args: {"id": "c" * 64, "passed": True},
    )
    monkeypatch.setattr(
        runtime,
        "_docker",
        lambda *_args, **_kwargs: runtime.CommandResult(1, b"", b"start failed"),
    )
    monkeypatch.setattr(
        runtime,
        "_observe_container_after_start",
        lambda *_args: {"passed": True, "state": {"status": "created"}},
    )
    monkeypatch.setattr(
        runtime,
        "_internal_health_probe",
        lambda *_args: pytest.fail("health probe must not run after failed start"),
    )
    monkeypatch.setattr(runtime, "_egress_probe", lambda *_args: {"passed": True})
    monkeypatch.setattr(
        runtime, "_observe_network_after_runtime", lambda *_args: {"passed": True}
    )

    result = runtime._materialize_app(
        QueueRunner([]),
        "nodegoat",
        app,
        {"repository_id": "owner/nodegoat", "commit": "1" * 40, "source_tree_sha256": "2" * 64},
        object(),
        tmp_path,
        _plan(tmp_path, "a" * 64)["helper"],
        {"container": None, "network": None},
    )

    assert result["health_probe"]["executed"] is False
    assert result["container"]["post_health"] is None
    assert result["status"] == "HOLD"


def _receipt(status: str = "HOLD", run_nonce_sha256: str = "c" * 64) -> dict:
    source_module, source_materializer_sha256 = runtime._load_source_module()
    _verifier, source_verifier_sha256 = (
        source_module._load_source_materialization_with_hash()
    )
    statuses = {app_id: status for app_id in sorted(runtime.APP_IDS)}
    apps = [
        {"app_id": app_id, "status": status, "blockers": ["not_observed"]}
        for app_id in sorted(runtime.APP_IDS)
    ]
    value = {
        "schema": runtime.RECEIPT_SCHEMA,
        "run_nonce_sha256": run_nonce_sha256,
        "source_admission_sha256": "a" * 64,
        "runtime_plan_sha256": "b" * 64,
        "tool_provenance": {
            "runtime_materializer_sha256": runtime.sha256_bytes(SCRIPT.read_bytes()),
            "source_materializer_sha256": source_materializer_sha256,
            "source_verifier_sha256": source_verifier_sha256,
        },
        "app_status": statuses,
        "runtime_isolation_gate": status,
        "release_gate_passed": False,
        "apps": apps,
    }
    projection = {
        "schema": value["schema"],
        "run_nonce_sha256": value["run_nonce_sha256"],
        "source_admission_sha256": value["source_admission_sha256"],
        "runtime_plan_sha256": value["runtime_plan_sha256"],
        "tool_provenance": value["tool_provenance"],
        "app_status": statuses,
        "runtime_isolation_gate": status,
    }
    value["validation_projection_sha256"] = runtime._canonical_sha256(projection)
    value["receipt_sha256"] = runtime._canonical_sha256(value)
    return value


def test_receipt_replay_contract_detects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "receipt.json"
    receipt = _receipt()
    _write(path, receipt)
    assert runtime.verify_runtime_receipt(path)["runtime_isolation_gate"] == "HOLD"

    receipt["apps"][0]["status"] = "PASS"
    receipt["receipt_sha256"] = runtime._canonical_sha256(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    )
    _write(path, receipt)
    with pytest.raises(runtime.RuntimeContractError, match="inconsistent"):
        runtime.verify_runtime_receipt(path)


def test_noncanonical_receipt_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(_receipt()), encoding="utf-8")
    with pytest.raises(runtime.RuntimeContractError, match="canonical"):
        runtime.verify_runtime_receipt(path)


def test_output_is_canonical_and_non_overwriting(tmp_path: Path) -> None:
    path = tmp_path / "receipt.json"
    payload = _receipt()

    runtime.write_new_output(path, payload)
    assert path.read_bytes() == runtime.canonical_json_bytes(payload)
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        runtime.write_new_output(path, payload)


def test_runtime_replay_comparison_requires_equal_decision_projection(
    tmp_path: Path,
) -> None:
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    first = _receipt()
    second = _receipt(run_nonce_sha256="d" * 64)
    _write(first_path, first)
    _write(second_path, second)

    comparison = runtime.compare_runtime_replays(first_path, second_path)

    assert comparison["replay_gate"] == "PASS"
    assert comparison["runtime_plan_equal"] is True
    assert comparison["decision_projection_equal"] is True
    assert comparison["distinct_run_nonce"] is True
    assert comparison["distinct_receipt"] is True
    assert comparison["release_gate_passed"] is False

    second["apps"][0]["blockers"] = ["different_blocker"]
    second["receipt_sha256"] = runtime._canonical_sha256(
        {key: value for key, value in second.items() if key != "receipt_sha256"}
    )
    _write(second_path, second)

    comparison = runtime.compare_runtime_replays(first_path, second_path)

    assert comparison["replay_gate"] == "HOLD"
    assert comparison["decision_projection_equal"] is False


def test_runtime_replay_comparison_rejects_copied_receipt_nonce(tmp_path: Path) -> None:
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    receipt = _receipt()
    _write(first_path, receipt)
    _write(second_path, copy.deepcopy(receipt))

    comparison = runtime.compare_runtime_replays(first_path, second_path)

    assert comparison["replay_gate"] == "HOLD"
    assert comparison["distinct_run_nonce"] is False
    assert comparison["distinct_receipt"] is False


def test_runtime_replay_comparison_rejects_one_receipt_used_twice(tmp_path: Path) -> None:
    path = tmp_path / "receipt.json"
    _write(path, _receipt())

    with pytest.raises(runtime.RuntimeContractError, match="two distinct"):
        runtime.compare_runtime_replays(path, path)


def test_docker_runner_never_uses_a_host_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict = {}

    class FakeProcess:
        def __init__(self, argv, **kwargs):
            observed["argv"] = argv
            observed.update(kwargs)

        def wait(self, *, timeout=None):
            observed["timeout"] = timeout
            return 0

        def kill(self):
            raise AssertionError("process should not be killed")

    monkeypatch.setattr(runtime.subprocess, "Popen", FakeProcess)
    result = runtime.SubprocessRunner().run(["docker", "version"], timeout=5)

    assert result.returncode == 0
    assert observed["argv"] == ["docker", "version"]
    assert observed["shell"] is False


def test_missing_docker_environment_keeps_all_six_apps_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    module = _fake_source_module()
    admission = _source_admission(module)
    admission_path = tmp_path / "source.json"
    _write(admission_path, admission)
    plan_path = tmp_path / "plan.json"
    plan = _plan(source_root, runtime.sha256_bytes(admission_path.read_bytes()))
    _write(plan_path, plan)

    monkeypatch.setattr(runtime, "_load_source_module", lambda: (module, "d" * 64))
    runner = QueueRunner([runtime.CommandResult(1, b"", b"docker unavailable")])
    receipt = runtime.materialize_l2_runtime(admission_path, plan_path, runner=runner)

    assert receipt["runtime_isolation_gate"] == "HOLD"
    assert receipt["release_gate_passed"] is False
    assert set(receipt["app_status"]) == runtime.APP_IDS
    assert set(receipt["app_status"].values()) == {"HOLD"}
    assert all(
        row["blockers"] == ["docker_environment_unavailable"]
        for row in receipt["apps"]
    )


def test_build_command_uses_bounded_argv_and_hash_only_receipt(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\n", encoding="ascii")
    runner = QueueRunner([runtime.CommandResult(0, b"build details", b"warning")])

    receipt = runtime._build_image(
        runner,
        reference="kguard-l2/nodegoat:locked",
        dockerfile=dockerfile,
        context=tmp_path,
        labels={"io.k-guard.app-id": "nodegoat"},
    )

    argv, timeout = runner.calls[0]
    assert argv[:2] == ["docker", "build"]
    assert timeout == runtime.MAX_COMMAND_SECONDS
    assert "build details" not in json.dumps(receipt)
    assert receipt["stdout_sha256"] == runtime.sha256_bytes(b"build details")
