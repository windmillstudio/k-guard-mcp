from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import secrets
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


SCHEMA = "k_guard_l2_nodegoat_allocations_idor_execution_contract.v1"
NEGATIVE_CONTROL_SCHEMA = "k_guard_l2_nodegoat_allocations_idor_negative_control.v1"
DRIVER_RESULT_SCHEMA = "k_guard_l2_nodegoat_allocations_idor_driver_result.v1"
SEED_RESULT_SCHEMA = "k_guard_l2_nodegoat_allocations_seed_result.v1"
APP_ID = "nodegoat"
REPOSITORY_ID = "owasp/nodegoat"
SOURCE_COMMIT = "c5cb68a7084e4ae7dcc60e6a98768720a81841e8"
SOURCE_TREE = "839d7b6856ec6da992d649b2423d5f9fcefdcf1f"
SOURCE_TREE_SHA256 = "352404981579791fafc18f70649c772a03f304b8895c4f239fbd9863ef5f8a52"
P23A_APP_RECEIPT_SHA256 = "d3ad5d453bb7d35580f3bf21dfcbab1bbf53555b7144f94da917cd6513ee21ab"
P23A_APP_SEMANTIC_SHA256 = "6b190b395c99e735e3ddbaa1e2d2ea8a7daaba5d514e0469e3ab7d3250eaaafa"
SOURCE_IMAGE_REF = "kguard-l2/nodegoat:c5cb68a7"
SOURCE_IMAGE_ID = "sha256:0b25b431d05093835f50099d7281fc25553f45802e75f4686e31fee6ffafc71b"
MONGO_IMAGE_REF = "mongo@sha256:7250955b2354cc6ad3548b428628e441e34625caa39dd64906e85adf369e1942"
MONGO_IMAGE_ID = "sha256:7250955b2354cc6ad3548b428628e441e34625caa39dd64906e85adf369e1942"
ROUTE_PATH = "app/routes/allocations.js"
SEED_PATH = "artifacts/db-reset.js"
EXECUTION_CONTRACT_LABEL = "nodegoat-allocations-idor-v1"
NEGATIVE_CONTROL_LABEL = "nodegoat-allocations-idor-negative-control-v1"
NEGATIVE_CONTROL_PATCH_ID = "use-session-user-id.v1"
RESULT_MARKER = "K_GUARD_NODEGOAT_IDOR_RESULT:"
SEED_RESULT_MARKER = "K_GUARD_NODEGOAT_SEED_RESULT:"
NETWORK_POLICY = "internal_bridge_loopback_driver_v1"
APP_USER = "node"
MONGO_USER = "mongodb"
APP_MEMORY_BYTES = 512 * 1024 * 1024
MONGO_MEMORY_BYTES = 768 * 1024 * 1024
NANO_CPUS = 1_000_000_000
APP_PIDS_LIMIT = 256
MONGO_PIDS_LIMIT = 256
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
OBJECT_ID_RE = re.compile(r"^[0-9a-f]{64}$")

ADMISSION_BLOCKERS = tuple(
    sorted(
        {
            "evidence_signature_missing",
            "independent_upstream_fixed_revision_missing",
            "scanner_finding_mapping_missing",
            "source_bound_severity_rubric_missing",
        }
    )
)
NEGATIVE_CONTROL_ADMISSION_BLOCKERS = ADMISSION_BLOCKERS

APP_TMPFS = {
    "/tmp": "rw,noexec,nosuid,nodev,size=33554432,uid=1000,gid=1000,mode=0700",
}
MONGO_TMPFS = {
    "/data/db": "rw,noexec,nosuid,nodev,size=268435456,uid=999,gid=999,mode=0700",
    "/data/configdb": "rw,noexec,nosuid,nodev,size=33554432,uid=999,gid=999,mode=0700",
    "/tmp": "rw,noexec,nosuid,nodev,size=33554432,uid=999,gid=999,mode=0700",
}


# The driver only emits boolean outcomes. Login material, cookies, response HTML,
# and seeded names stay in the transient application container.
DRIVER_SCRIPT = r'''"use strict"

const http = require("http")

const marker = "K_GUARD_NODEGOAT_IDOR_RESULT:"
const schema = "k_guard_l2_nodegoat_allocations_idor_driver_result.v1"
const mode = process.env.KGUARD_MODE
const expectedStatus = Number(process.env.KGUARD_EXPECTED_STATUS)

function emit(value) {
  process.stdout.write(marker + JSON.stringify(value) + "\n")
}

function request(method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const content = body === undefined ? undefined : Buffer.from(body, "utf8")
    const requestHeaders = {
      ...headers,
      ...(content === undefined ? {} : {
        "content-type": "application/x-www-form-urlencoded",
        "content-length": String(content.length)
      })
    }
    const request = http.request({
      host: "127.0.0.1",
      port: 4000,
      path,
      method,
      headers: requestHeaders,
      timeout: 5000
    }, response => {
      const chunks = []
      let total = 0
      response.on("data", chunk => {
        total += chunk.length
        if (total <= 131072) chunks.push(chunk)
      })
      response.on("end", () => {
        if (total > 131072) return reject(new Error("response_too_large"))
        resolve({
          status: Number(response.statusCode || 0),
          headers: response.headers,
          body: Buffer.concat(chunks).toString("utf8")
        })
      })
    })
    request.on("timeout", () => request.destroy(new Error("request_timeout")))
    request.on("error", reject)
    if (content !== undefined) request.write(content)
    request.end()
  })
}

async function waitForApplication() {
  const deadline = Date.now() + 90000
  while (Date.now() < deadline) {
    try {
      const response = await request("GET", "/login")
      if (response.status === 200) return
    } catch (_) {
      // The bounded retry loop intentionally reveals no application output.
    }
    await new Promise(resolve => setTimeout(resolve, 500))
  }
  throw new Error("application_not_ready")
}

function failed(code) {
  emit({
    schema,
    mode,
    expected_status: expectedStatus,
    observed_status: null,
    foreign_allocation_observed: false,
    own_allocation_observed: false,
    driver_error_code: code,
    passed: false,
    raw_returned: false
  })
  process.exit(81)
}

async function main() {
  if (!Number.isInteger(expectedStatus) || expectedStatus !== 200 || !["positive", "negative"].includes(mode)) {
    return failed("driver_contract_invalid")
  }
  try {
    await waitForApplication()
    const credentials = new URLSearchParams({
      userName: "user1",
      password: Buffer.from("VXNlcjFfMTIz", "base64").toString("utf8")
    }).toString()
    const login = await request("POST", "/login", credentials)
    const setCookie = login.headers["set-cookie"]
    const cookie = Array.isArray(setCookie) ? setCookie.map(value => value.split(";", 1)[0]).join("; ") : ""
    if (login.status !== 302 || !cookie) return failed("fixture_login_failed")
    const response = await request("GET", "/allocations/3", undefined, { cookie })
    const foreign = response.body.includes("Asset Allocations for Will Smith")
    const own = response.body.includes("Asset Allocations for John Doe")
    const passed = mode === "positive"
      ? response.status === 200 && foreign === true && own === false
      : response.status === 200 && foreign === false && own === true
    emit({
      schema,
      mode,
      expected_status: expectedStatus,
      observed_status: response.status,
      foreign_allocation_observed: foreign,
      own_allocation_observed: own,
      driver_error_code: null,
      passed,
      raw_returned: false
    })
    process.exit(passed ? 0 : 81)
  } catch (_) {
    failed("driver_runtime_failed")
  }
}

void main()
'''


# A fresh database can accept a local ping before its internal DNS alias is
# usable from a sibling container. The wrapper resets the whole source-owned
# seed process at most three times and emits only an attempt count/result.
SEED_WRAPPER_SCRIPT = r'''"use strict"

const { spawn } = require("child_process")

const marker = "K_GUARD_NODEGOAT_SEED_RESULT:"
const schema = "k_guard_l2_nodegoat_allocations_seed_result.v1"
const maxAttempts = 3

function emit(value) {
  process.stdout.write(marker + JSON.stringify(value) + "\n")
}

function wait(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds))
}

function resetOnce() {
  return new Promise(resolve => {
    const child = spawn("node", ["artifacts/db-reset.js"], {
      stdio: ["ignore", "ignore", "ignore"],
      env: process.env
    })
    child.once("error", () => resolve(127))
    child.once("exit", code => resolve(Number.isInteger(code) ? code : 1))
  })
}

async function main() {
  for (let attempts = 1; attempts <= maxAttempts; attempts += 1) {
    const code = await resetOnce()
    if (code === 0) {
      emit({ schema, attempts, max_attempts: maxAttempts, passed: true, raw_returned: false })
      process.exit(0)
    }
    if (attempts < maxAttempts) await wait(1000)
  }
  emit({ schema, attempts: maxAttempts, max_attempts: maxAttempts, passed: false, raw_returned: false })
  process.exit(81)
}

void main()
'''


class RuntimeContractError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_truncated: bool


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_sha256(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _command_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "DOCKER_CLI_HINTS": "false",
            "DOCKER_SCAN_SUGGEST": "false",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    return environment


def _run_bounded(argv: list[str], *, cwd: Path, timeout: int) -> CommandResult:
    with tempfile.SpooledTemporaryFile(max_size=MAX_OUTPUT_BYTES) as stdout, tempfile.SpooledTemporaryFile(
        max_size=MAX_OUTPUT_BYTES
    ) as stderr:
        process = subprocess.Popen(
            argv,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            shell=False,
            env=_command_environment(),
        )
        timed_out = False
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
            returncode = 124
        stdout.seek(0)
        stderr.seek(0)
        stdout_raw = stdout.read(MAX_OUTPUT_BYTES + 1)
        stderr_raw = stderr.read(MAX_OUTPUT_BYTES + 1)
    return CommandResult(
        returncode=returncode,
        stdout=stdout_raw[:MAX_OUTPUT_BYTES],
        stderr=stderr_raw[:MAX_OUTPUT_BYTES],
        timed_out=timed_out,
        output_truncated=len(stdout_raw) > MAX_OUTPUT_BYTES or len(stderr_raw) > MAX_OUTPUT_BYTES,
    )


def _docker(arguments: list[str], *, cwd: Path, timeout: int) -> CommandResult:
    return _run_bounded(["docker", *arguments], cwd=cwd, timeout=timeout)


def _expect_success(result: CommandResult, label: str) -> None:
    if result.returncode != 0 or result.timed_out or result.output_truncated:
        raise RuntimeContractError(f"{label}_failed")


def _load_json_stdout(result: CommandResult, label: str) -> Any:
    _expect_success(result, label)
    try:
        return json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError(f"{label}_not_json") from exc


def _command_receipt(result: CommandResult) -> dict[str, Any]:
    return {
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "output_truncated": result.output_truncated,
        "stdout_sha256": sha256_bytes(result.stdout),
        "stderr_sha256": sha256_bytes(result.stderr),
        "stdout_bytes": len(result.stdout),
        "stderr_bytes": len(result.stderr),
        "raw_returned": False,
    }


def _load_source_verifier() -> tuple[Any, str]:
    path = Path(__file__).with_name("holdout_source_materialization.py")
    raw_before = path.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l2_nodegoat_source_verifier", path)
    if spec is None or spec.loader is None:
        raise RuntimeContractError("source_verifier_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if path.read_bytes() != raw_before:
        raise RuntimeContractError("source_verifier_changed_while_loading")
    return module, sha256_bytes(raw_before)


def _load_p23a_registry(path: Path) -> tuple[dict[str, Any], str]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeContractError("p23a_registry_invalid_path")
    raw = path.read_bytes()
    try:
        registry = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError("p23a_registry_not_json") from exc
    if not isinstance(registry, dict) or canonical_json_bytes(registry) != raw:
        raise RuntimeContractError("p23a_registry_not_canonical")
    if (
        registry.get("schema") != "k_guard_l2_source_materialization.v3"
        or registry.get("seed_sha256") != "95f48fd53d3d411be9dbaa7b78a130a893d1fbf87bbc92f7ce40f1d6dbaf2fef"
        or registry.get("expected_app_count") != 6
        or registry.get("materialized_app_count") != 6
        or registry.get("source_license_admission") != "PASS"
        or registry.get("raw_returned") is not False
    ):
        raise RuntimeContractError("p23a_registry_contract_invalid")
    apps = registry.get("apps")
    if not isinstance(apps, list):
        raise RuntimeContractError("p23a_registry_apps_invalid")
    matches = [item for item in apps if isinstance(item, dict) and item.get("app_id") == APP_ID]
    if len(matches) != 1:
        raise RuntimeContractError("p23a_registry_nodegoat_missing")
    app = matches[0]
    expected = {
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
        "receipt_sha256": P23A_APP_RECEIPT_SHA256,
        "receipt_semantic_sha256": P23A_APP_SEMANTIC_SHA256,
        "source_license_admission": "PASS",
        "scanner_output_observed": False,
        "oracle_gate_status": "HOLD",
        "oracle_missing": True,
    }
    if any(app.get(key) != value for key, value in expected.items()):
        raise RuntimeContractError("p23a_registry_nodegoat_binding_invalid")
    return app, sha256_bytes(raw)


def _source_projection(
    receipt: Mapping[str, Any], *, p23a_app: Mapping[str, Any], p23a_registry_sha256: str
) -> dict[str, Any]:
    expected = {
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
    }
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise RuntimeContractError("source_identity_mismatch")
    required_truths = (
        "source_worktree_clean",
        "origin_repository_match",
        "commit_match",
        "commit_tree_match",
        "tree_object_reconstruction_match",
        "index_tree_match",
        "physical_bytes_match_git_blobs",
        "git_fsck_strict_passed",
    )
    if any(receipt.get(key) is not True for key in required_truths):
        raise RuntimeContractError("source_receipt_not_blob_exact")
    if any(receipt.get(key) != p23a_app.get(key) for key in ("file_count", "total_bytes")):
        raise RuntimeContractError("source_receipt_size_mismatch")
    return {
        **expected,
        "p23a_registry_sha256": p23a_registry_sha256,
        "p23a_app_receipt_sha256": P23A_APP_RECEIPT_SHA256,
        "p23a_app_receipt_semantic_sha256": P23A_APP_SEMANTIC_SHA256,
        "current_source_receipt_sha256": _canonical_sha256(dict(receipt)),
        "file_count": receipt.get("file_count"),
        "total_bytes": receipt.get("total_bytes"),
        "raw_returned": False,
    }


def verify_source_workspace(source_root: Path, p23a_registry: Path) -> tuple[dict[str, Any], Any, str]:
    if not source_root.is_absolute() or not source_root.is_dir():
        raise RuntimeContractError("source_root_invalid")
    p23a_app, p23a_registry_sha256 = _load_p23a_registry(p23a_registry)
    verifier, verifier_sha256 = _load_source_verifier()
    receipt = verifier.build_git_materialization_receipt(
        source_root,
        expected_repository_id=REPOSITORY_ID,
        expected_commit=SOURCE_COMMIT,
        expected_tree=SOURCE_TREE,
    )
    return _source_projection(receipt, p23a_app=p23a_app, p23a_registry_sha256=p23a_registry_sha256), verifier, verifier_sha256


def _read_image(ref: str, *, work_root: Path) -> dict[str, Any]:
    rows = _load_json_stdout(_docker(["image", "inspect", ref], cwd=work_root, timeout=60), "image_inspect")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise RuntimeContractError("image_inspect_shape_invalid")
    return rows[0]


def _labels(value: Mapping[str, Any]) -> Mapping[str, Any]:
    config = value.get("Config")
    labels = config.get("Labels") if isinstance(config, Mapping) else None
    if not isinstance(labels, Mapping):
        return {}
    return labels


def _rootfs_layers(value: Mapping[str, Any]) -> tuple[str, ...]:
    rootfs = value.get("RootFS")
    layers = rootfs.get("Layers") if isinstance(rootfs, Mapping) else None
    if not isinstance(layers, list) or not layers or not all(isinstance(item, str) and IMAGE_ID_RE.fullmatch(item) for item in layers):
        raise RuntimeContractError("image_rootfs_layers_invalid")
    return tuple(layers)


def _container_id(result: CommandResult, label: str) -> str:
    _expect_success(result, label)
    try:
        value = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise RuntimeContractError(f"{label}_id_invalid") from exc
    if OBJECT_ID_RE.fullmatch(value) is None:
        raise RuntimeContractError(f"{label}_id_invalid")
    return value


def _cleanup_container(
    *,
    work_root: Path,
    name: str,
    expected_id: str | None,
    nonce: str,
    contract_label: str,
    role: str,
) -> dict[str, Any]:
    inspected = _docker(["container", "inspect", name], cwd=work_root, timeout=60)
    if inspected.returncode != 0:
        return {
            "ownership_verified": expected_id is None,
            "removed": False,
            "absent_after": expected_id is None,
            "passed": expected_id is None,
            "raw_returned": False,
        }
    try:
        rows = json.loads(inspected.stdout.decode("utf-8"))
        row = rows[0] if isinstance(rows, list) and len(rows) == 1 else None
        labels = _labels(row) if isinstance(row, Mapping) else {}
        owned = (
            isinstance(row, Mapping)
            and row.get("Id") == expected_id
            and labels.get("io.k-guard.app-id") == APP_ID
            and labels.get("io.k-guard.execution-contract") == contract_label
            and labels.get("io.k-guard.run-nonce") == nonce
            and labels.get("io.k-guard.role") == role
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        owned = False
    removed = False
    if owned:
        deletion = _docker(["container", "rm", "--force", name], cwd=work_root, timeout=60)
        removed = deletion.returncode == 0 and not deletion.timed_out and not deletion.output_truncated
    post = _docker(["container", "inspect", name], cwd=work_root, timeout=60)
    absent_after = post.returncode != 0 and not post.timed_out and not post.output_truncated
    return {
        "ownership_verified": owned,
        "removed": removed,
        "absent_after": absent_after,
        "passed": owned and removed and absent_after,
        "raw_returned": False,
    }


def _cleanup_network(
    *, work_root: Path, name: str, expected_id: str | None, nonce: str, contract_label: str
) -> dict[str, Any]:
    inspected = _docker(["network", "inspect", name], cwd=work_root, timeout=60)
    if inspected.returncode != 0:
        return {
            "ownership_verified": expected_id is None,
            "removed": False,
            "absent_after": expected_id is None,
            "passed": expected_id is None,
            "raw_returned": False,
        }
    try:
        rows = json.loads(inspected.stdout.decode("utf-8"))
        row = rows[0] if isinstance(rows, list) and len(rows) == 1 else None
        labels = row.get("Labels") if isinstance(row, Mapping) and isinstance(row.get("Labels"), Mapping) else {}
        owned = (
            isinstance(row, Mapping)
            and row.get("Id") == expected_id
            and labels.get("io.k-guard.app-id") == APP_ID
            and labels.get("io.k-guard.execution-contract") == contract_label
            and labels.get("io.k-guard.run-nonce") == nonce
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        owned = False
    removed = False
    if owned:
        deletion = _docker(["network", "rm", name], cwd=work_root, timeout=60)
        removed = deletion.returncode == 0 and not deletion.timed_out and not deletion.output_truncated
    post = _docker(["network", "inspect", name], cwd=work_root, timeout=60)
    absent_after = post.returncode != 0 and not post.timed_out and not post.output_truncated
    return {
        "ownership_verified": owned,
        "removed": removed,
        "absent_after": absent_after,
        "passed": owned and removed and absent_after,
        "raw_returned": False,
    }


def _extract_image_file(
    *, work_root: Path, image_id: str, image_path: str, nonce: str, contract_label: str
) -> bytes:
    name = f"kguard-l2-nodegoat-extract-{nonce}"
    container_id: str | None = None
    try:
        created = _docker(
            [
                "container",
                "create",
                "--name",
                name,
                "--label",
                f"io.k-guard.app-id={APP_ID}",
                "--label",
                f"io.k-guard.execution-contract={contract_label}",
                "--label",
                f"io.k-guard.run-nonce={nonce}",
                "--label",
                "io.k-guard.role=source-extract",
                "--network",
                "none",
                "--entrypoint",
                "/bin/sh",
                image_id,
                "-c",
                "exit 0",
            ],
            cwd=work_root,
            timeout=60,
        )
        container_id = _container_id(created, "source_extract_container")
        destination = work_root / f"extracted-{sha256_bytes(image_path.encode('utf-8'))}.js"
        copied = _docker(["container", "cp", f"{name}:{image_path}", str(destination)], cwd=work_root, timeout=60)
        _expect_success(copied, "source_extract_copy")
        if not destination.is_file() or destination.is_symlink():
            raise RuntimeContractError("source_extract_file_invalid")
        raw = destination.read_bytes()
        if not raw or len(raw) > MAX_FILE_BYTES:
            raise RuntimeContractError("source_extract_file_size_invalid")
        return raw
    finally:
        cleanup = _cleanup_container(
            work_root=work_root,
            name=name,
            expected_id=container_id,
            nonce=nonce,
            contract_label=contract_label,
            role="source-extract",
        )
        if not cleanup["passed"]:
            raise RuntimeContractError("source_extract_cleanup_failed")


def _validate_base_images(source_root: Path, *, work_root: Path) -> tuple[dict[str, Any], bytes]:
    route_path = source_root / ROUTE_PATH
    seed_path = source_root / SEED_PATH
    dockerfile_path = source_root / "Dockerfile"
    if any(not path.is_file() or path.is_symlink() for path in (route_path, seed_path, dockerfile_path)):
        raise RuntimeContractError("source_file_missing")
    source = _read_image(SOURCE_IMAGE_REF, work_root=work_root)
    mongo = _read_image(MONGO_IMAGE_REF, work_root=work_root)
    source_labels = _labels(source)
    source_layers = _rootfs_layers(source)
    mongo_layers = _rootfs_layers(mongo)
    if source.get("Id") != SOURCE_IMAGE_ID or mongo.get("Id") != MONGO_IMAGE_ID:
        raise RuntimeContractError("base_image_id_mismatch")
    if source_labels.get("org.kguard.source-commit") != SOURCE_COMMIT:
        raise RuntimeContractError("source_image_commit_label_invalid")
    repo_digests = mongo.get("RepoDigests")
    if not isinstance(repo_digests, list) or MONGO_IMAGE_REF not in repo_digests:
        raise RuntimeContractError("mongo_digest_binding_missing")
    route = _extract_image_file(
        work_root=work_root,
        image_id=SOURCE_IMAGE_ID,
        image_path=f"/home/node/app/{ROUTE_PATH}",
        nonce=secrets.token_hex(16),
        contract_label=EXECUTION_CONTRACT_LABEL,
    )
    seed = _extract_image_file(
        work_root=work_root,
        image_id=SOURCE_IMAGE_ID,
        image_path=f"/home/node/app/{SEED_PATH}",
        nonce=secrets.token_hex(16),
        contract_label=EXECUTION_CONTRACT_LABEL,
    )
    expected_route = route_path.read_bytes()
    expected_seed = seed_path.read_bytes()
    if route != expected_route or seed != expected_seed:
        raise RuntimeContractError("source_image_file_binding_invalid")
    return {
        "source_image_id": SOURCE_IMAGE_ID,
        "source_image_ref": SOURCE_IMAGE_REF,
        "source_image_rootfs_layers_sha256": _canonical_sha256(source_layers),
        "source_image_commit_label": SOURCE_COMMIT,
        "mongo_image_id": MONGO_IMAGE_ID,
        "mongo_image_ref": MONGO_IMAGE_REF,
        "mongo_image_rootfs_layers_sha256": _canonical_sha256(mongo_layers),
        "source_dockerfile_sha256": sha256_bytes(dockerfile_path.read_bytes()),
        "route_source_sha256": sha256_bytes(route),
        "seed_source_sha256": sha256_bytes(seed),
        "source_image_current_source_provenance_only": True,
        "fresh_dependency_rebuild_proven": False,
        "mongo_runtime_supply_chain_proven": False,
        "raw_returned": False,
    }, route


def _negative_route_patch(route: bytes) -> tuple[bytes, dict[str, Any]]:
    ending = b"\r\n" if b"\r\n" in route else b"\n"
    marker = ending.join((b"        const {", b"            userId", b"        } = req.params;"))
    replacement = ending.join((b"        const {", b"            userId", b"        } = req.session;"))
    if route.count(marker) != 1 or route.count(replacement) != 0:
        raise RuntimeContractError("negative_control_patch_anchor_invalid")
    patched = route.replace(marker, replacement, 1)
    if patched == route or patched.count(marker) != 0 or patched.count(replacement) != 1:
        raise RuntimeContractError("negative_control_patch_not_single")
    return patched, {
        "patch_id": NEGATIVE_CONTROL_PATCH_ID,
        "source_path": ROUTE_PATH,
        "original_file_sha256": sha256_bytes(route),
        "patched_file_sha256": sha256_bytes(patched),
        "patch_sha256": sha256_bytes(replacement),
        "marker_count": 1,
        "replacement_count": 1,
        "source_checkout_mutated": False,
        "raw_returned": False,
    }


def _dockerfile_template() -> str:
    return f"""ARG BASE_SOURCE={SOURCE_IMAGE_REF}
FROM ${{BASE_SOURCE}}
USER root
RUN mkdir -p /opt/kguard
COPY allocations.js /home/node/app/{ROUTE_PATH}
COPY driver.js /opt/kguard/driver.js
COPY seed.js /opt/kguard/seed.js
RUN chown node:node /home/node/app/{ROUTE_PATH} /opt/kguard/driver.js /opt/kguard/seed.js
USER node
"""


def _build_contract_sha256(*, variant: str, base_images: Mapping[str, Any], route: Mapping[str, Any]) -> str:
    return _canonical_sha256(
        {
            "base_source_image_id": base_images["source_image_id"],
            "base_source_image_ref": base_images["source_image_ref"],
            "build_network": "none",
            "dockerfile_sha256": sha256_bytes(_dockerfile_template().encode("utf-8")),
            "driver_sha256": sha256_bytes(DRIVER_SCRIPT.encode("utf-8")),
            "seed_wrapper_sha256": sha256_bytes(SEED_WRAPPER_SCRIPT.encode("utf-8")),
            "no_cache": True,
            "pull": False,
            "route_original_file_sha256": route["original_file_sha256"],
            "route_patched_file_sha256": route.get("patched_file_sha256"),
            "variant": variant,
        }
    )


def _build_replay_image(
    *,
    work_root: Path,
    timeout: int,
    base_images: Mapping[str, Any],
    route: bytes,
    route_projection: Mapping[str, Any],
    variant: str,
) -> tuple[dict[str, Any], str]:
    if variant not in {"positive", "negative"}:
        raise RuntimeContractError("replay_variant_invalid")
    context = work_root / f"build-{variant}"
    context.mkdir()
    (context / "allocations.js").write_bytes(route)
    (context / "driver.js").write_text(DRIVER_SCRIPT, encoding="utf-8", newline="\n")
    (context / "seed.js").write_text(SEED_WRAPPER_SCRIPT, encoding="utf-8", newline="\n")
    dockerfile = _dockerfile_template()
    dockerfile_path = context / "Dockerfile.kguard"
    dockerfile_path.write_text(dockerfile, encoding="utf-8", newline="\n")
    nonce = secrets.token_hex(16)
    tag = f"kguard-l2-nodegoat-{variant}-{nonce}"
    contract_label = EXECUTION_CONTRACT_LABEL if variant == "positive" else NEGATIVE_CONTROL_LABEL
    build = _docker(
        [
            "build",
            "--no-cache",
            "--pull=false",
            "--network",
            "none",
            "--build-arg",
            f"BASE_SOURCE={base_images['source_image_ref']}",
            "--label",
            f"io.k-guard.app-id={APP_ID}",
            "--label",
            f"io.k-guard.execution-contract={contract_label}",
            "--label",
            f"io.k-guard.source-image-id={base_images['source_image_id']}",
            "--label",
            f"io.k-guard.build-nonce={nonce}",
            "--file",
            str(dockerfile_path),
            "--tag",
            tag,
            str(context),
        ],
        cwd=work_root,
        timeout=timeout,
    )
    _expect_success(build, "replay_image_build")
    image = _read_image(tag, work_root=work_root)
    image_id = image.get("Id")
    labels = _labels(image)
    layers = _rootfs_layers(image)
    base = _read_image(SOURCE_IMAGE_ID, work_root=work_root)
    base_layers = _rootfs_layers(base)
    if not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None:
        raise RuntimeContractError("replay_image_id_invalid")
    if (
        labels.get("io.k-guard.app-id") != APP_ID
        or labels.get("io.k-guard.execution-contract") != contract_label
        or labels.get("io.k-guard.source-image-id") != base_images["source_image_id"]
        or labels.get("io.k-guard.build-nonce") != nonce
        or len(layers) <= len(base_layers)
        or layers[: len(base_layers)] != base_layers
    ):
        raise RuntimeContractError("replay_image_lineage_invalid")
    return {
        "image_id": image_id,
        "image_id_sha256": sha256_bytes(image_id.encode("ascii")),
        "base_source_image_id": base_images["source_image_id"],
        "contract_label": contract_label,
        "dockerfile_sha256": sha256_bytes(dockerfile.encode("utf-8")),
        "driver_sha256": sha256_bytes(DRIVER_SCRIPT.encode("utf-8")),
        "seed_wrapper_sha256": sha256_bytes(SEED_WRAPPER_SCRIPT.encode("utf-8")),
        "build_contract_sha256": _build_contract_sha256(
            variant=variant, base_images=base_images, route=route_projection
        ),
        "rootfs_lineage_sha256": _canonical_sha256(layers),
        "route": dict(route_projection),
        "source_derived": True,
        "build_network": "none",
        "fresh_dependency_rebuild_proven": False,
        "raw_returned": False,
    }, image_id


def _cleanup_image(image_id: str, *, work_root: Path, contract_label: str) -> dict[str, Any]:
    inspected = _docker(["image", "inspect", image_id], cwd=work_root, timeout=60)
    owned = False
    if inspected.returncode == 0 and not inspected.timed_out and not inspected.output_truncated:
        try:
            rows = json.loads(inspected.stdout.decode("utf-8"))
            row = rows[0] if isinstance(rows, list) and len(rows) == 1 else None
            labels = _labels(row) if isinstance(row, Mapping) else {}
            owned = (
                isinstance(row, Mapping)
                and labels.get("io.k-guard.app-id") == APP_ID
                and labels.get("io.k-guard.execution-contract") == contract_label
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            owned = False
    removed = False
    if owned:
        deletion = _docker(["image", "rm", "--force", image_id], cwd=work_root, timeout=120)
        removed = deletion.returncode == 0 and not deletion.timed_out and not deletion.output_truncated
    post = _docker(["image", "inspect", image_id], cwd=work_root, timeout=60)
    absent_after = post.returncode != 0 and not post.timed_out and not post.output_truncated
    return {
        "ownership_verified": owned,
        "removed": removed,
        "absent_after": absent_after,
        "passed": owned and removed and absent_after,
        "raw_returned": False,
    }


def _tmpfs_matches(actual: object, expected: Mapping[str, str]) -> bool:
    if not isinstance(actual, Mapping) or set(actual) != set(expected):
        return False
    for path, expected_value in expected.items():
        value = actual.get(path)
        if not isinstance(value, str):
            return False
        if not set(expected_value.split(",")).issubset(set(value.split(","))):
            return False
    return True


def _container_isolation(
    container: Mapping[str, Any],
    *,
    image_id: str,
    network_name: str,
    alias: str | None,
    expected_user: str,
    expected_tmpfs: Mapping[str, str],
    memory_bytes: int,
    pids_limit: int,
    nonce: str,
    contract_label: str,
    role: str,
) -> dict[str, Any]:
    host = container.get("HostConfig") if isinstance(container.get("HostConfig"), Mapping) else {}
    config = container.get("Config") if isinstance(container.get("Config"), Mapping) else {}
    labels = config.get("Labels") if isinstance(config.get("Labels"), Mapping) else {}
    network_settings = container.get("NetworkSettings") if isinstance(container.get("NetworkSettings"), Mapping) else {}
    networks = network_settings.get("Networks") if isinstance(network_settings.get("Networks"), Mapping) else {}
    attachment = networks.get(network_name) if isinstance(networks, Mapping) else None
    attachment_aliases = attachment.get("Aliases") if isinstance(attachment, Mapping) else []
    ports = network_settings.get("Ports")
    mounts = container.get("Mounts") if isinstance(container.get("Mounts"), list) else []
    security = {str(value).casefold() for value in host.get("SecurityOpt", []) if isinstance(value, str)}
    cap_drop = {str(value).upper() for value in host.get("CapDrop", []) if isinstance(value, str)}
    checks = {
        "exact_image": container.get("Image") == image_id,
        "contract_labels": labels.get("io.k-guard.app-id") == APP_ID
        and labels.get("io.k-guard.execution-contract") == contract_label
        and labels.get("io.k-guard.run-nonce") == nonce
        and labels.get("io.k-guard.role") == role,
        "single_internal_network": host.get("NetworkMode") == network_name and set(networks) == {network_name},
        "network_alias": alias is None or isinstance(attachment_aliases, list) and alias in attachment_aliases,
        "no_host_port_publish": host.get("PortBindings") in (None, {}) and ports in (None, {}),
        "read_only_root": host.get("ReadonlyRootfs") is True,
        "cap_drop_all": "ALL" in cap_drop and not host.get("CapAdd"),
        "no_new_privileges": any(value.startswith("no-new-privileges") for value in security),
        "pids_bounded": host.get("PidsLimit") == pids_limit,
        "memory_bounded": host.get("Memory") == memory_bytes,
        "cpu_bounded": host.get("NanoCpus") == NANO_CPUS,
        "non_root_user": config.get("User") == expected_user,
        "not_privileged": host.get("Privileged") is False,
        "no_bind_or_volume_mounts": not mounts and not host.get("Binds"),
        "hardened_tmpfs": _tmpfs_matches(host.get("Tmpfs"), expected_tmpfs),
    }
    return {"checks": checks, "passed": all(checks.values()), "raw_returned": False}


def _create_network(
    *, work_root: Path, name: str, nonce: str, contract_label: str
) -> tuple[dict[str, Any], str]:
    preexisting = _docker(["network", "inspect", name], cwd=work_root, timeout=60)
    if preexisting.returncode == 0 or preexisting.timed_out or preexisting.output_truncated:
        raise RuntimeContractError("network_preexisting_or_unavailable")
    created = _docker(
        [
            "network",
            "create",
            "--driver",
            "bridge",
            "--internal",
            "--label",
            f"io.k-guard.app-id={APP_ID}",
            "--label",
            f"io.k-guard.execution-contract={contract_label}",
            "--label",
            f"io.k-guard.run-nonce={nonce}",
            name,
        ],
        cwd=work_root,
        timeout=60,
    )
    network_id = _container_id(created, "network_create")
    inspected = _load_json_stdout(
        _docker(["network", "inspect", name], cwd=work_root, timeout=60), "network_inspect"
    )
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], Mapping):
        raise RuntimeContractError("network_inspect_shape_invalid")
    network = inspected[0]
    labels = network.get("Labels") if isinstance(network.get("Labels"), Mapping) else {}
    checks = {
        "created_id_exact": network.get("Id") == network_id,
        "bridge": network.get("Driver") == "bridge",
        "internal": network.get("Internal") is True,
        "ingress_false": network.get("Ingress") is False,
        "scope_local": network.get("Scope") == "local",
        "labels": labels.get("io.k-guard.app-id") == APP_ID
        and labels.get("io.k-guard.execution-contract") == contract_label
        and labels.get("io.k-guard.run-nonce") == nonce,
    }
    record = {
        "id_sha256": sha256_bytes(network_id.encode("ascii")),
        "checks": checks,
        "passed": all(checks.values()),
        "raw_returned": False,
    }
    if not record["passed"]:
        raise RuntimeContractError("network_isolation_invalid")
    return record, network_id


def _create_container(
    *,
    work_root: Path,
    name: str,
    image_id: str,
    command: tuple[str, ...],
    network_name: str,
    alias: str | None,
    user: str,
    tmpfs: Mapping[str, str],
    memory_bytes: int,
    pids_limit: int,
    environment: Mapping[str, str],
    nonce: str,
    contract_label: str,
    role: str,
) -> tuple[dict[str, Any], str]:
    preexisting = _docker(["container", "inspect", name], cwd=work_root, timeout=60)
    if preexisting.returncode == 0 or preexisting.timed_out or preexisting.output_truncated:
        raise RuntimeContractError("container_preexisting_or_unavailable")
    arguments = [
        "container",
        "create",
        "--name",
        name,
        "--label",
        f"io.k-guard.app-id={APP_ID}",
        "--label",
        f"io.k-guard.execution-contract={contract_label}",
        "--label",
        f"io.k-guard.run-nonce={nonce}",
        "--label",
        f"io.k-guard.role={role}",
        "--network",
        network_name,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--pids-limit",
        str(pids_limit),
        "--memory",
        str(memory_bytes),
        "--cpus",
        "1",
        "--user",
        user,
        "--restart",
        "no",
    ]
    if alias is not None:
        arguments.extend(["--network-alias", alias])
    for key, value in sorted(environment.items()):
        arguments.extend(["--env", f"{key}={value}"])
    for path, options in sorted(tmpfs.items()):
        arguments.extend(["--tmpfs", f"{path}:{options}"])
    arguments.extend([image_id, *command])
    created = _docker(arguments, cwd=work_root, timeout=60)
    container_id = _container_id(created, f"{role}_container_create")
    inspected = _load_json_stdout(
        _docker(["container", "inspect", name], cwd=work_root, timeout=60), f"{role}_container_inspect"
    )
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], Mapping):
        raise RuntimeContractError("container_inspect_shape_invalid")
    isolation = _container_isolation(
        inspected[0],
        image_id=image_id,
        network_name=network_name,
        alias=alias,
        expected_user=user,
        expected_tmpfs=tmpfs,
        memory_bytes=memory_bytes,
        pids_limit=pids_limit,
        nonce=nonce,
        contract_label=contract_label,
        role=role,
    )
    isolation["created_id_exact"] = inspected[0].get("Id") == container_id
    isolation["passed"] = isolation["passed"] is True and isolation["created_id_exact"] is True
    if not isolation["passed"]:
        raise RuntimeContractError(f"{role}_container_isolation_invalid")
    return isolation, container_id


def _start_container(
    *, work_root: Path, name: str, attached: bool, timeout: int
) -> tuple[dict[str, Any], bytes]:
    arguments = ["container", "start"]
    if attached:
        arguments.append("--attach")
    arguments.append(name)
    result = _docker(arguments, cwd=work_root, timeout=timeout)
    return _command_receipt(result), result.stdout


def _post_state(
    *, work_root: Path, name: str, expected_id: str, running: bool
) -> dict[str, Any]:
    rows = _load_json_stdout(
        _docker(["container", "inspect", name], cwd=work_root, timeout=60), "container_post_inspect"
    )
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], Mapping):
        raise RuntimeContractError("container_post_inspect_shape_invalid")
    state = rows[0].get("State") if isinstance(rows[0].get("State"), Mapping) else {}
    checks = {
        "same_container": rows[0].get("Id") == expected_id,
        "running": state.get("Running") is running,
        "exit_code": state.get("ExitCode") in (None, 0) if running else state.get("ExitCode") == 0,
        "not_oom_killed": state.get("OOMKilled") is False,
        "not_dead": state.get("Dead") is False,
    }
    return {"checks": checks, "passed": all(checks.values()), "raw_returned": False}


def _wait_for_mongo(*, work_root: Path, name: str, timeout: int) -> dict[str, Any]:
    deadline = time.monotonic() + min(timeout, 60)
    attempts = 0
    last: CommandResult | None = None
    while time.monotonic() < deadline:
        attempts += 1
        last = _docker(
            ["container", "exec", "--user", MONGO_USER, name, "mongo", "--quiet", "--eval", "db.adminCommand({ping:1}).ok"],
            cwd=work_root,
            timeout=10,
        )
        if (
            last.returncode == 0
            and not last.timed_out
            and not last.output_truncated
            and last.stdout.strip() == b"1"
        ):
            return {"attempts": attempts, "last_command": _command_receipt(last), "passed": True, "raw_returned": False}
        time.sleep(0.5)
    return {
        "attempts": attempts,
        "last_command": _command_receipt(last) if last is not None else None,
        "passed": False,
        "raw_returned": False,
    }


def _parse_driver_result(output: bytes, *, mode: str) -> dict[str, Any]:
    try:
        lines = output.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise RuntimeContractError("driver_output_not_utf8") from exc
    markers = [line[len(RESULT_MARKER) :] for line in lines if line.startswith(RESULT_MARKER)]
    if len(markers) != 1:
        raise RuntimeContractError("driver_result_marker_invalid")
    try:
        result = json.loads(markers[0])
    except json.JSONDecodeError as exc:
        raise RuntimeContractError("driver_result_not_json") from exc
    expected_keys = {
        "schema",
        "mode",
        "expected_status",
        "observed_status",
        "foreign_allocation_observed",
        "own_allocation_observed",
        "driver_error_code",
        "passed",
        "raw_returned",
    }
    foreign = mode == "positive"
    own = mode == "negative"
    if (
        not isinstance(result, Mapping)
        or set(result) != expected_keys
        or result.get("schema") != DRIVER_RESULT_SCHEMA
        or result.get("mode") != mode
        or result.get("expected_status") != 200
        or result.get("observed_status") != 200
        or result.get("foreign_allocation_observed") is not foreign
        or result.get("own_allocation_observed") is not own
        or result.get("driver_error_code") is not None
        or result.get("passed") is not True
        or result.get("raw_returned") is not False
    ):
        raise RuntimeContractError("driver_result_outcome_invalid")
    return {
        "schema": DRIVER_RESULT_SCHEMA,
        "mode": mode,
        "expected_status": 200,
        "observed_status": 200,
        "foreign_allocation_observed": foreign,
        "own_allocation_observed": own,
        "passed": True,
        "raw_returned": False,
    }


def _parse_seed_result(output: bytes) -> dict[str, Any]:
    try:
        lines = output.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise RuntimeContractError("seed_output_not_utf8") from exc
    markers = [line[len(SEED_RESULT_MARKER) :] for line in lines if line.startswith(SEED_RESULT_MARKER)]
    if len(markers) != 1:
        raise RuntimeContractError("seed_result_marker_invalid")
    try:
        result = json.loads(markers[0])
    except json.JSONDecodeError as exc:
        raise RuntimeContractError("seed_result_not_json") from exc
    expected = {
        "schema": SEED_RESULT_SCHEMA,
        "attempts": result.get("attempts") if isinstance(result, Mapping) else None,
        "max_attempts": 3,
        "passed": True,
        "raw_returned": False,
    }
    if (
        not isinstance(result, Mapping)
        or set(result) != set(expected)
        or not isinstance(result.get("attempts"), int)
        or not 1 <= result["attempts"] <= result.get("max_attempts", 0)
        or dict(result) != expected
    ):
        raise RuntimeContractError("seed_result_outcome_invalid")
    return dict(expected)


def _network_post_state(
    *, work_root: Path, name: str, expected_id: str, database_id: str, app_id: str, nonce: str, contract_label: str
) -> dict[str, Any]:
    rows = _load_json_stdout(
        _docker(["network", "inspect", name], cwd=work_root, timeout=60), "network_post_inspect"
    )
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], Mapping):
        raise RuntimeContractError("network_post_inspect_shape_invalid")
    network = rows[0]
    labels = network.get("Labels") if isinstance(network.get("Labels"), Mapping) else {}
    containers = network.get("Containers") if isinstance(network.get("Containers"), Mapping) else {}
    checks = {
        "same_network": network.get("Id") == expected_id,
        "internal_bridge": network.get("Driver") == "bridge" and network.get("Internal") is True and network.get("Ingress") is False,
        "labels": labels.get("io.k-guard.app-id") == APP_ID
        and labels.get("io.k-guard.execution-contract") == contract_label
        and labels.get("io.k-guard.run-nonce") == nonce,
        "only_database_and_application": set(containers) == {database_id, app_id},
    }
    return {"checks": checks, "passed": all(checks.values()), "raw_returned": False}


def _live_run(image_id: str, *, work_root: Path, timeout: int, variant: str) -> dict[str, Any]:
    if variant not in {"positive", "negative"}:
        raise RuntimeContractError("live_variant_invalid")
    contract_label = EXECUTION_CONTRACT_LABEL if variant == "positive" else NEGATIVE_CONTROL_LABEL
    nonce = secrets.token_hex(16)
    prefix = f"kguard-l2-nodegoat-{variant}-{nonce}"
    names = {"network": prefix, "database": f"{prefix}-mongo", "seed": f"{prefix}-seed", "application": f"{prefix}-app"}
    identifiers: dict[str, str | None] = {key: None for key in names}
    cleanup: dict[str, Any] = {}
    result: dict[str, Any] = {
        "run_nonce_sha256": sha256_bytes(nonce.encode("ascii")),
        "image_id": image_id,
        "driver_sha256": sha256_bytes(DRIVER_SCRIPT.encode("utf-8")),
        "network_policy": NETWORK_POLICY,
        "expected_status": 200,
        "mode": variant,
        "isolation": None,
        "seed_execution": None,
        "application_start": None,
        "execution": None,
        "normalized_result": None,
        "cleanup": None,
        "failure_code": None,
        "passed": False,
        "raw_returned": False,
    }
    try:
        network, identifiers["network"] = _create_network(
            work_root=work_root, name=names["network"], nonce=nonce, contract_label=contract_label
        )
        database, identifiers["database"] = _create_container(
            work_root=work_root,
            name=names["database"],
            image_id=MONGO_IMAGE_ID,
            command=("mongod", "--bind_ip", "0.0.0.0", "--port", "27017", "--dbpath", "/data/db", "--quiet"),
            network_name=names["network"],
            alias="mongo",
            user=MONGO_USER,
            tmpfs=MONGO_TMPFS,
            memory_bytes=MONGO_MEMORY_BYTES,
            pids_limit=MONGO_PIDS_LIMIT,
            environment={},
            nonce=nonce,
            contract_label=contract_label,
            role="database",
        )
        database_start, _database_stdout = _start_container(work_root=work_root, name=names["database"], attached=False, timeout=60)
        if database_start["returncode"] != 0:
            raise RuntimeContractError("database_start_failed")
        mongo_ready = _wait_for_mongo(work_root=work_root, name=names["database"], timeout=timeout)
        if not mongo_ready["passed"]:
            raise RuntimeContractError("database_not_ready")
        seed, identifiers["seed"] = _create_container(
            work_root=work_root,
            name=names["seed"],
            image_id=image_id,
            command=("node", "/opt/kguard/seed.js"),
            network_name=names["network"],
            alias=None,
            user=APP_USER,
            tmpfs=APP_TMPFS,
            memory_bytes=APP_MEMORY_BYTES,
            pids_limit=APP_PIDS_LIMIT,
            environment={"MONGODB_URI": "mongodb://mongo:27017/nodegoat"},
            nonce=nonce,
            contract_label=contract_label,
            role="seed",
        )
        seed_start, seed_stdout = _start_container(work_root=work_root, name=names["seed"], attached=True, timeout=timeout)
        seed_state = _post_state(work_root=work_root, name=names["seed"], expected_id=identifiers["seed"] or "", running=False)
        seed_result = _parse_seed_result(seed_stdout)
        result["seed_execution"] = {
            "start": seed_start,
            "state": seed_state,
            "mongo_ready": mongo_ready,
            "normalized_result": seed_result,
            "passed": seed_start["returncode"] == 0 and seed_state["passed"] is True and seed_result["passed"] is True,
            "raw_returned": False,
        }
        if not result["seed_execution"]["passed"]:
            raise RuntimeContractError("seed_execution_failed")
        cleanup["seed"] = _cleanup_container(
            work_root=work_root,
            name=names["seed"],
            expected_id=identifiers["seed"],
            nonce=nonce,
            contract_label=contract_label,
            role="seed",
        )
        if not cleanup["seed"]["passed"]:
            raise RuntimeContractError("seed_cleanup_failed")
        application, identifiers["application"] = _create_container(
            work_root=work_root,
            name=names["application"],
            image_id=image_id,
            command=("node", "server.js"),
            network_name=names["network"],
            alias="nodegoat-app",
            user=APP_USER,
            tmpfs=APP_TMPFS,
            memory_bytes=APP_MEMORY_BYTES,
            pids_limit=APP_PIDS_LIMIT,
            environment={"MONGODB_URI": "mongodb://mongo:27017/nodegoat", "PORT": "4000"},
            nonce=nonce,
            contract_label=contract_label,
            role="application",
        )
        application_start, _application_stdout = _start_container(work_root=work_root, name=names["application"], attached=False, timeout=60)
        result["application_start"] = application_start
        if application_start["returncode"] != 0:
            raise RuntimeContractError("application_start_failed")
        driver = _docker(
            [
                "container",
                "exec",
                "--user",
                APP_USER,
                "--env",
                f"KGUARD_MODE={variant}",
                "--env",
                "KGUARD_EXPECTED_STATUS=200",
                names["application"],
                "node",
                "/opt/kguard/driver.js",
            ],
            cwd=work_root,
            timeout=timeout,
        )
        result["execution"] = _command_receipt(driver)
        if driver.returncode != 0 or driver.timed_out or driver.output_truncated:
            raise RuntimeContractError("driver_execution_failed")
        result["normalized_result"] = _parse_driver_result(driver.stdout, mode=variant)
        application_state = _post_state(
            work_root=work_root,
            name=names["application"],
            expected_id=identifiers["application"] or "",
            running=True,
        )
        network_state = _network_post_state(
            work_root=work_root,
            name=names["network"],
            expected_id=identifiers["network"] or "",
            database_id=identifiers["database"] or "",
            app_id=identifiers["application"] or "",
            nonce=nonce,
            contract_label=contract_label,
        )
        result["isolation"] = {
            "network": network,
            "database": database,
            "seed": seed,
            "application": application,
            "application_post_state": application_state,
            "network_post_state": network_state,
            "passed": all(
                item.get("passed") is True
                for item in (network, database, seed, application, application_state, network_state)
            ),
            "raw_returned": False,
        }
        if not result["isolation"]["passed"]:
            raise RuntimeContractError("runtime_isolation_failed")
    except RuntimeContractError as exc:
        result["failure_code"] = str(exc)
    finally:
        if "seed" not in cleanup:
            cleanup["seed"] = _cleanup_container(
                work_root=work_root,
                name=names["seed"],
                expected_id=identifiers["seed"],
                nonce=nonce,
                contract_label=contract_label,
                role="seed",
            )
        cleanup["application"] = _cleanup_container(
            work_root=work_root,
            name=names["application"],
            expected_id=identifiers["application"],
            nonce=nonce,
            contract_label=contract_label,
            role="application",
        )
        cleanup["database"] = _cleanup_container(
            work_root=work_root,
            name=names["database"],
            expected_id=identifiers["database"],
            nonce=nonce,
            contract_label=contract_label,
            role="database",
        )
        cleanup["network"] = _cleanup_network(
            work_root=work_root,
            name=names["network"],
            expected_id=identifiers["network"],
            nonce=nonce,
            contract_label=contract_label,
        )
        cleanup["passed"] = all(item.get("passed") is True for key, item in cleanup.items() if key != "passed")
        cleanup["raw_returned"] = False
        result["cleanup"] = cleanup
    result["passed"] = (
        isinstance(result["isolation"], Mapping)
        and result["isolation"].get("passed") is True
        and isinstance(result["seed_execution"], Mapping)
        and result["seed_execution"].get("passed") is True
        and isinstance(result["application_start"], Mapping)
        and result["application_start"].get("returncode") == 0
        and isinstance(result["execution"], Mapping)
        and result["execution"].get("returncode") == 0
        and isinstance(result["normalized_result"], Mapping)
        and result["normalized_result"].get("passed") is True
        and isinstance(result["cleanup"], Mapping)
        and result["cleanup"].get("passed") is True
        and result["failure_code"] is None
    )
    return result


def _isolation_consensus_projection(value: object) -> object:
    if not isinstance(value, Mapping):
        return value
    projected: dict[str, Any] = {
        "passed": value.get("passed"),
        "raw_returned": value.get("raw_returned"),
    }
    for key in (
        "network",
        "database",
        "seed",
        "application",
        "application_post_state",
        "network_post_state",
    ):
        nested = value.get(key)
        if not isinstance(nested, Mapping):
            projected[key] = nested
            continue
        projected[key] = {
            "checks": nested.get("checks"),
            "created_id_exact": nested.get("created_id_exact"),
            "passed": nested.get("passed"),
            "raw_returned": nested.get("raw_returned"),
        }
    return projected


def _consensus_projection(run: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "driver_sha256": run.get("driver_sha256"),
        "network_policy": run.get("network_policy"),
        "expected_status": run.get("expected_status"),
        "mode": run.get("mode"),
        # Object identity is retained in each raw-free receipt. It is not an
        # execution semantic because every fresh internal network gets a new ID.
        "isolation": _isolation_consensus_projection(run.get("isolation")),
        "normalized_result": run.get("normalized_result"),
        "passed": run.get("passed"),
    }


def _claim_boundary(*, negative: bool) -> dict[str, bool]:
    return {
        "execution_oracle_only": True,
        "source_mutated_negative_control": negative,
        "scanner_accuracy_proven": False,
        "severity_or_cwe_admitted": False,
        "tp_fp_fn_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }


def _tool_provenance(verifier_sha256: str) -> dict[str, Any]:
    return {
        "runner_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "source_verifier_sha256": verifier_sha256,
        "driver_sha256": sha256_bytes(DRIVER_SCRIPT.encode("utf-8")),
        "seed_wrapper_sha256": sha256_bytes(SEED_WRAPPER_SCRIPT.encode("utf-8")),
        "source_image_id": SOURCE_IMAGE_ID,
        "mongo_image_id": MONGO_IMAGE_ID,
        "raw_returned": False,
    }


def _expected_positive_execution_tool_provenance() -> dict[str, Any]:
    _verifier, verifier_sha256 = _load_source_verifier()
    return _tool_provenance(verifier_sha256)


def _execute(
    source_root: Path,
    p23a_registry: Path,
    *,
    timeout: int,
    variant: str,
    positive_reference: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    source, _verifier, verifier_sha256 = verify_source_workspace(source_root.resolve(), p23a_registry.resolve())
    contract_label = EXECUTION_CONTRACT_LABEL if variant == "positive" else NEGATIVE_CONTROL_LABEL
    image: dict[str, Any] | None = None
    image_id: str | None = None
    image_cleanup: dict[str, Any] | None = None
    route_projection: dict[str, Any] | None = None
    base_images: dict[str, Any] | None = None
    runs: list[dict[str, Any]] = []
    failure: str | None = None
    with tempfile.TemporaryDirectory(prefix=f"kguard-l2-nodegoat-{variant}-") as temporary:
        work_root = Path(temporary)
        try:
            base_images, route = _validate_base_images(source_root.resolve(), work_root=work_root)
            if variant == "negative":
                route, route_projection = _negative_route_patch(route)
            elif variant == "positive":
                route_projection = {
                    "source_path": ROUTE_PATH,
                    "original_file_sha256": sha256_bytes(route),
                    "source_checkout_mutated": False,
                    "raw_returned": False,
                }
            else:
                raise RuntimeContractError("execution_variant_invalid")
            image, image_id = _build_replay_image(
                work_root=work_root,
                timeout=timeout,
                base_images=base_images,
                route=route,
                route_projection=route_projection,
                variant=variant,
            )
            runs = [_live_run(image_id, work_root=work_root, timeout=timeout, variant=variant) for _ in range(2)]
        except RuntimeContractError as exc:
            failure = str(exc)
        finally:
            if image_id is not None:
                image_cleanup = _cleanup_image(image_id, work_root=work_root, contract_label=contract_label)
    projections = [_consensus_projection(run) for run in runs]
    consensus_passed = len(projections) == 2 and projections[0] == projections[1] and all(run.get("passed") is True for run in runs)
    if failure is None and not consensus_passed:
        failure = "execution_repeatability_or_runtime_failed"
    status = "EXECUTION_CONTRACT_PASS" if variant == "positive" else "NEGATIVE_CONTROL_PASS"
    passed = (
        failure is None
        and base_images is not None
        and image is not None
        and image_cleanup is not None
        and image_cleanup.get("passed") is True
        and consensus_passed
    )
    common = {
        "tool_provenance": _tool_provenance(verifier_sha256),
        "source": source,
        "base_images": base_images,
        "image": image,
        "runs": runs,
        "consensus": {
            "run_count": len(runs),
            "two_runs_byte_equivalent_after_normalization": consensus_passed,
            "projection_sha256": _canonical_sha256(projections) if projections else None,
            "raw_returned": False,
        },
        "image_cleanup": image_cleanup,
        "release_gate_passed": False,
        "failure_code": None if passed else failure or "execution_contract_incomplete",
        "raw_returned": False,
    }
    if variant == "positive":
        receipt = {
            "schema": SCHEMA,
            **common,
            "claim_boundary": _claim_boundary(negative=False),
            "admission_blockers": list(ADMISSION_BLOCKERS),
            "execution_contract_status": status if passed else "HOLD",
        }
        validate_receipt(receipt)
        return receipt
    if positive_reference is None or route_projection is None:
        raise RuntimeContractError("negative_control_reference_missing")
    receipt = {
        "schema": NEGATIVE_CONTROL_SCHEMA,
        **common,
        "positive_execution_contract": dict(positive_reference),
        "negative_control": route_projection,
        "claim_boundary": _claim_boundary(negative=True),
        "admission_blockers": list(NEGATIVE_CONTROL_ADMISSION_BLOCKERS),
        "negative_control_status": status if passed else "HOLD",
    }
    validate_negative_control_receipt(receipt)
    return receipt


def execute_contract(source_root: Path, p23a_registry: Path, *, timeout: int) -> dict[str, Any]:
    return _execute(source_root, p23a_registry, timeout=timeout, variant="positive")


def _load_positive_execution_contract(path: Path, *, source: Mapping[str, Any]) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeContractError("positive_execution_receipt_invalid_path")
    raw = path.read_bytes()
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError("positive_execution_receipt_not_json") from exc
    if not isinstance(receipt, dict) or canonical_json_bytes(receipt) != raw:
        raise RuntimeContractError("positive_execution_receipt_not_canonical")
    validate_receipt(receipt)
    if receipt.get("execution_contract_status") != "EXECUTION_CONTRACT_PASS":
        raise RuntimeContractError("positive_execution_receipt_not_passed")
    if receipt.get("tool_provenance") != _expected_positive_execution_tool_provenance():
        raise RuntimeContractError("positive_execution_tool_provenance_mismatch")
    positive_source = receipt.get("source")
    if not isinstance(positive_source, Mapping) or any(
        positive_source.get(key) != source.get(key)
        for key in (
            "repository_id",
            "commit",
            "commit_tree",
            "source_tree_sha256",
            "p23a_registry_sha256",
            "p23a_app_receipt_sha256",
            "p23a_app_receipt_semantic_sha256",
            "current_source_receipt_sha256",
        )
    ):
        raise RuntimeContractError("positive_execution_source_mismatch")
    return {
        "receipt_sha256": sha256_bytes(raw),
        "source_receipt_sha256": source["current_source_receipt_sha256"],
        "execution_contract_status": "EXECUTION_CONTRACT_PASS",
        "raw_returned": False,
    }


def execute_negative_control(
    source_root: Path, p23a_registry: Path, positive_receipt: Path, *, timeout: int
) -> dict[str, Any]:
    source, _verifier, _verifier_sha256 = verify_source_workspace(source_root.resolve(), p23a_registry.resolve())
    positive_reference = _load_positive_execution_contract(positive_receipt, source=source)
    return _execute(source_root, p23a_registry, timeout=timeout, variant="negative", positive_reference=positive_reference)


def _assert_raw_free(value: object) -> None:
    if isinstance(value, Mapping):
        if "raw_returned" in value and value["raw_returned"] is not False:
            raise RuntimeContractError("raw_boundary_invalid")
        for nested in value.values():
            _assert_raw_free(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_raw_free(nested)


def _validate_source(source: object) -> None:
    if not isinstance(source, Mapping):
        raise RuntimeContractError("receipt_source_invalid")
    expected = {
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
        "p23a_app_receipt_sha256": P23A_APP_RECEIPT_SHA256,
        "p23a_app_receipt_semantic_sha256": P23A_APP_SEMANTIC_SHA256,
        "raw_returned": False,
    }
    if any(source.get(key) != value for key, value in expected.items()):
        raise RuntimeContractError("receipt_source_binding_invalid")
    for key in ("p23a_registry_sha256", "current_source_receipt_sha256"):
        if not isinstance(source.get(key), str) or SHA256_RE.fullmatch(source[key]) is None:
            raise RuntimeContractError("receipt_source_hash_invalid")


def _validate_tool(tool: object) -> None:
    if not isinstance(tool, Mapping) or tool.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_tool_invalid")
    for key in ("runner_sha256", "source_verifier_sha256", "driver_sha256", "seed_wrapper_sha256"):
        if not isinstance(tool.get(key), str) or SHA256_RE.fullmatch(tool[key]) is None:
            raise RuntimeContractError("receipt_tool_hash_invalid")
    if tool.get("source_image_id") != SOURCE_IMAGE_ID or tool.get("mongo_image_id") != MONGO_IMAGE_ID:
        raise RuntimeContractError("receipt_tool_image_binding_invalid")


def _validate_base_images_receipt(base: object) -> None:
    if not isinstance(base, Mapping) or base.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_base_images_invalid")
    if (
        base.get("source_image_id") != SOURCE_IMAGE_ID
        or base.get("mongo_image_id") != MONGO_IMAGE_ID
        or base.get("source_image_ref") != SOURCE_IMAGE_REF
        or base.get("mongo_image_ref") != MONGO_IMAGE_REF
        or base.get("source_image_current_source_provenance_only") is not True
        or base.get("fresh_dependency_rebuild_proven") is not False
        or base.get("mongo_runtime_supply_chain_proven") is not False
    ):
        raise RuntimeContractError("receipt_base_images_binding_invalid")
    for key in (
        "source_image_rootfs_layers_sha256",
        "mongo_image_rootfs_layers_sha256",
        "source_dockerfile_sha256",
        "route_source_sha256",
        "seed_source_sha256",
    ):
        if not isinstance(base.get(key), str) or SHA256_RE.fullmatch(base[key]) is None:
            raise RuntimeContractError("receipt_base_images_hash_invalid")


def _validate_image(image: object, *, variant: str) -> None:
    if not isinstance(image, Mapping) or image.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_image_invalid")
    expected_label = EXECUTION_CONTRACT_LABEL if variant == "positive" else NEGATIVE_CONTROL_LABEL
    if (
        image.get("base_source_image_id") != SOURCE_IMAGE_ID
        or image.get("contract_label") != expected_label
        or image.get("source_derived") is not True
        or image.get("build_network") != "none"
        or image.get("fresh_dependency_rebuild_proven") is not False
    ):
        raise RuntimeContractError("receipt_image_binding_invalid")
    for key in ("image_id", "image_id_sha256", "dockerfile_sha256", "driver_sha256", "seed_wrapper_sha256", "build_contract_sha256", "rootfs_lineage_sha256"):
        if not isinstance(image.get(key), str):
            raise RuntimeContractError("receipt_image_hash_invalid")
    route = image.get("route")
    if not isinstance(route, Mapping) or route.get("source_path") != ROUTE_PATH or route.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_image_route_invalid")


def _validate_run(run: object, *, variant: str) -> None:
    if not isinstance(run, Mapping) or run.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_run_invalid")
    normalized = run.get("normalized_result")
    seed_execution = run.get("seed_execution") if isinstance(run, Mapping) else None
    seed_result = seed_execution.get("normalized_result") if isinstance(seed_execution, Mapping) else None
    if (
        run.get("network_policy") != NETWORK_POLICY
        or run.get("expected_status") != 200
        or run.get("mode") != variant
        or run.get("passed") is not True
        or not isinstance(run.get("isolation"), Mapping)
        or run["isolation"].get("passed") is not True
        or not isinstance(seed_execution, Mapping)
        or seed_execution.get("passed") is not True
        or not isinstance(seed_result, Mapping)
        or seed_result.get("schema") != SEED_RESULT_SCHEMA
        or not isinstance(seed_result.get("attempts"), int)
        or not 1 <= seed_result["attempts"] <= 3
        or seed_result.get("max_attempts") != 3
        or seed_result.get("passed") is not True
        or seed_result.get("raw_returned") is not False
        or not isinstance(run.get("application_start"), Mapping)
        or run["application_start"].get("returncode") != 0
        or not isinstance(run.get("execution"), Mapping)
        or run["execution"].get("returncode") != 0
        or not isinstance(normalized, Mapping)
        or normalized.get("passed") is not True
        or normalized.get("mode") != variant
        or not isinstance(run.get("cleanup"), Mapping)
        or run["cleanup"].get("passed") is not True
        or run.get("failure_code") is not None
    ):
        raise RuntimeContractError("receipt_run_contract_invalid")


def _validate_common_receipt(receipt: Mapping[str, Any], *, variant: str) -> None:
    _assert_raw_free(receipt)
    _validate_tool(receipt.get("tool_provenance"))
    _validate_source(receipt.get("source"))
    if receipt.get("release_gate_passed") is not False:
        raise RuntimeContractError("receipt_release_promotion_invalid")
    _validate_base_images_receipt(receipt.get("base_images"))
    status_key = "execution_contract_status" if variant == "positive" else "negative_control_status"
    passed_status = "EXECUTION_CONTRACT_PASS" if variant == "positive" else "NEGATIVE_CONTROL_PASS"
    status = receipt.get(status_key)
    if status not in {passed_status, "HOLD"}:
        raise RuntimeContractError("receipt_status_invalid")
    if status == passed_status:
        runs = receipt.get("runs")
        consensus = receipt.get("consensus")
        _validate_image(receipt.get("image"), variant=variant)
        if (
            not isinstance(runs, list)
            or len(runs) != 2
            or not all(isinstance(run, Mapping) for run in runs)
            or not isinstance(consensus, Mapping)
            or consensus.get("run_count") != 2
            or consensus.get("two_runs_byte_equivalent_after_normalization") is not True
            or not isinstance(receipt.get("image_cleanup"), Mapping)
            or receipt["image_cleanup"].get("passed") is not True
            or receipt.get("failure_code") is not None
        ):
            raise RuntimeContractError("receipt_pass_incomplete")
        for run in runs:
            _validate_run(run, variant=variant)
    elif receipt.get("failure_code") is None:
        raise RuntimeContractError("receipt_hold_without_failure")


def validate_receipt(receipt: dict[str, Any]) -> None:
    required = {
        "schema",
        "tool_provenance",
        "source",
        "base_images",
        "image",
        "runs",
        "consensus",
        "image_cleanup",
        "claim_boundary",
        "admission_blockers",
        "execution_contract_status",
        "release_gate_passed",
        "failure_code",
        "raw_returned",
    }
    if set(receipt) != required or receipt.get("schema") != SCHEMA or receipt.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_schema_invalid")
    if receipt.get("claim_boundary") != _claim_boundary(negative=False):
        raise RuntimeContractError("receipt_claim_boundary_invalid")
    if tuple(receipt.get("admission_blockers", ())) != ADMISSION_BLOCKERS:
        raise RuntimeContractError("receipt_admission_blockers_invalid")
    _validate_common_receipt(receipt, variant="positive")


def validate_negative_control_receipt(receipt: dict[str, Any]) -> None:
    required = {
        "schema",
        "tool_provenance",
        "source",
        "base_images",
        "image",
        "runs",
        "consensus",
        "image_cleanup",
        "positive_execution_contract",
        "negative_control",
        "claim_boundary",
        "admission_blockers",
        "negative_control_status",
        "release_gate_passed",
        "failure_code",
        "raw_returned",
    }
    if set(receipt) != required or receipt.get("schema") != NEGATIVE_CONTROL_SCHEMA or receipt.get("raw_returned") is not False:
        raise RuntimeContractError("negative_control_receipt_schema_invalid")
    if receipt.get("claim_boundary") != _claim_boundary(negative=True):
        raise RuntimeContractError("negative_control_claim_boundary_invalid")
    if tuple(receipt.get("admission_blockers", ())) != NEGATIVE_CONTROL_ADMISSION_BLOCKERS:
        raise RuntimeContractError("negative_control_admission_blockers_invalid")
    positive = receipt.get("positive_execution_contract")
    control = receipt.get("negative_control")
    if not isinstance(positive, Mapping) or not isinstance(control, Mapping):
        raise RuntimeContractError("negative_control_reference_invalid")
    if (
        not isinstance(positive.get("receipt_sha256"), str)
        or SHA256_RE.fullmatch(positive["receipt_sha256"]) is None
        or positive.get("execution_contract_status") != "EXECUTION_CONTRACT_PASS"
        or positive.get("raw_returned") is not False
        or control.get("patch_id") != NEGATIVE_CONTROL_PATCH_ID
        or control.get("source_path") != ROUTE_PATH
        or control.get("marker_count") != 1
        or control.get("replacement_count") != 1
        or control.get("source_checkout_mutated") is not False
        or control.get("raw_returned") is not False
    ):
        raise RuntimeContractError("negative_control_reference_invalid")
    for key in ("original_file_sha256", "patched_file_sha256", "patch_sha256"):
        if not isinstance(control.get(key), str) or SHA256_RE.fullmatch(control[key]) is None:
            raise RuntimeContractError("negative_control_patch_hash_invalid")
    if control["original_file_sha256"] == control["patched_file_sha256"]:
        raise RuntimeContractError("negative_control_patch_unchanged")
    _validate_common_receipt(receipt, variant="negative")


def _write_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise RuntimeContractError("refusing_to_overwrite_execution_evidence")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical_json_bytes(dict(receipt)))
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replay one source-bound NodeGoat allocations IDOR pair without detector or release promotion."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    positive = subparsers.add_parser("positive")
    positive.add_argument("--source-root", type=Path, required=True)
    positive.add_argument("--p23a-registry", type=Path, required=True)
    positive.add_argument("--output", type=Path, required=True)
    positive.add_argument("--timeout-seconds", type=int, default=240)
    negative = subparsers.add_parser("negative-control")
    negative.add_argument("--source-root", type=Path, required=True)
    negative.add_argument("--p23a-registry", type=Path, required=True)
    negative.add_argument("--positive-receipt", type=Path, required=True)
    negative.add_argument("--output", type=Path, required=True)
    negative.add_argument("--timeout-seconds", type=int, default=240)
    verify_positive = subparsers.add_parser("verify-positive")
    verify_positive.add_argument("--receipt", type=Path, required=True)
    verify_negative = subparsers.add_parser("verify-negative-control")
    verify_negative.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-positive":
            raw = args.receipt.read_bytes()
            receipt = json.loads(raw.decode("utf-8"))
            if canonical_json_bytes(receipt) != raw:
                raise RuntimeContractError("receipt_not_canonical")
            validate_receipt(receipt)
            print(json.dumps({"status": receipt["execution_contract_status"], "raw_returned": False}, sort_keys=True))
            return 0 if receipt["execution_contract_status"] == "EXECUTION_CONTRACT_PASS" else 2
        if args.command == "verify-negative-control":
            raw = args.receipt.read_bytes()
            receipt = json.loads(raw.decode("utf-8"))
            if canonical_json_bytes(receipt) != raw:
                raise RuntimeContractError("negative_control_receipt_not_canonical")
            validate_negative_control_receipt(receipt)
            print(json.dumps({"status": receipt["negative_control_status"], "raw_returned": False}, sort_keys=True))
            return 0 if receipt["negative_control_status"] == "NEGATIVE_CONTROL_PASS" else 2
        if args.timeout_seconds < 60:
            raise RuntimeContractError("timeout_seconds_too_small")
        if args.command == "positive":
            receipt = execute_contract(args.source_root, args.p23a_registry, timeout=args.timeout_seconds)
            _write_receipt(args.output, receipt)
            print(json.dumps({"status": receipt["execution_contract_status"], "raw_returned": False}, sort_keys=True))
            return 0 if receipt["execution_contract_status"] == "EXECUTION_CONTRACT_PASS" else 2
        receipt = execute_negative_control(
            args.source_root, args.p23a_registry, args.positive_receipt, timeout=args.timeout_seconds
        )
        _write_receipt(args.output, receipt)
        print(json.dumps({"status": receipt["negative_control_status"], "raw_returned": False}, sort_keys=True))
        return 0 if receipt["negative_control_status"] == "NEGATIVE_CONTROL_PASS" else 2
    except (OSError, json.JSONDecodeError, RuntimeContractError) as exc:
        print(json.dumps({"status": "HOLD", "failure_code": str(exc), "raw_returned": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
