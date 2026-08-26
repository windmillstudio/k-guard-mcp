from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


SCHEMA = "k_guard_l2_juice_shop_bola_execution_contract.v1"
NEGATIVE_CONTROL_SCHEMA = "k_guard_l2_juice_shop_bola_negative_control.v1"
DRIVER_RESULT_SCHEMA = "k_guard_l2_juice_shop_bola_driver_result.v1"
APP_ID = "juice-shop"
REPOSITORY_ID = "juice-shop/juice-shop"
SOURCE_COMMIT = "33518f5a0911e25d9df747b1e70fb7af279a755c"
SOURCE_TREE = "d503a1d2f1a8864ba596fbf3f6d23dfa02cf45a6"
SOURCE_TREE_SHA256 = "9a109ac9217946774a0c5d356d2a9836c06153d4ae1fe21de92aa71556525fae"
P23A_APP_RECEIPT_SHA256 = "4ed955ad49e650a12139a21e8fc0491a102fd346e4920ca771668e3cf0f9a93a"
P23A_APP_SEMANTIC_SHA256 = "16bdfe32da401e75ad16aac3f219758371c2e8bd9a20086c306c22923c5feffa"
SOURCE_IMAGE_REF = "kguard-l2/juice-shop:33518f5a-r3"
SOURCE_IMAGE_ID = "sha256:b909b04bf3b38892966b971cddc54ea07677e994af9a84cf4c1b3abfa3f0513d"
ADAPTER_IMAGE_REF = "kguard-l2/juice-shop-adapter:33518f5a-r3"
ADAPTER_IMAGE_ID = "sha256:1fb0cae1cb14458c7654755ffbe4824014a1966fd418b6a546bf751e94d7774b"
ROUTE_PATH = "build/routes/basket.js"
EXECUTION_CONTRACT_LABEL = "juice-shop-basket-bola-v1"
NEGATIVE_CONTROL_LABEL = "juice-shop-basket-bola-negative-control-v1"
NEGATIVE_CONTROL_PATCH_ID = "deny-cross-basket-read.v1"
RUN_AS = "65532:0"
MEMORY_BYTES = 2 * 1024 * 1024 * 1024
NANO_CPUS = 2_000_000_000
PIDS_LIMIT = 256
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_ROUTE_BYTES = 2 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RESULT_MARKER = "K_GUARD_BOLA_RESULT:"

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

NEGATIVE_CONTROL_ADMISSION_BLOCKERS = tuple(
    sorted(
        {
            "evidence_signature_missing",
            "independent_upstream_fixed_revision_missing",
            "scanner_finding_mapping_missing",
            "source_bound_severity_rubric_missing",
        }
    )
)

TMPFS_PATHS = (
    "/tmp",
    "/juice-shop/.well-known",
    "/juice-shop/data",
    "/juice-shop/frontend/dist",
    "/juice-shop/ftp",
    "/juice-shop/i18n",
    "/juice-shop/logs",
)
TMPFS_OPTIONS = "rw,noexec,nosuid,nodev,size=268435456,uid=65532,gid=0,mode=0770"
RUNTIME_SEED_PATHS = (
    ".well-known",
    "frontend/dist",
    "ftp",
    "i18n",
)

SEED_SCRIPT = r'''"use strict"

const fs = require("node:fs")
const root = "/juice-shop-kguard-seed"
const paths = [".well-known", "frontend/dist", "ftp", "i18n"]

fs.mkdirSync(root, { recursive: true })
for (const relative of paths) {
  fs.cpSync("/juice-shop/" + relative, root + "/" + relative, { recursive: true, force: true })
}
'''

# This script deliberately emits only a compact marker JSON. Login material and
# response bodies stay in the transient container process and are never copied
# into an evidence receipt.
DRIVER_SCRIPT = r'''"use strict"

const http = require("node:http")
const fs = require("node:fs")

const resultMarker = "K_GUARD_BOLA_RESULT:"
const resultSchema = "k_guard_l2_juice_shop_bola_driver_result.v1"
const expectedStatus = Number(process.env.KGUARD_EXPECTED_STATUS)
const mode = process.env.KGUARD_MODE

function emit (value) {
  process.stdout.write(resultMarker + JSON.stringify(value) + "\n")
}

function boundedRequest (method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const requestBody = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8")
    const request = http.request({
      host: "127.0.0.1",
      port: 3000,
      method,
      path,
      headers: {
        ...(requestBody === undefined ? {} : { "content-type": "application/json", "content-length": String(requestBody.length) }),
        ...headers
      },
      timeout: 5000
    }, (response) => {
      const chunks = []
      let total = 0
      response.on("data", (chunk) => {
        total += chunk.length
        if (total <= 65536) chunks.push(chunk)
      })
      response.on("end", () => {
        if (total > 65536) return reject(new Error("response_too_large"))
        const raw = Buffer.concat(chunks).toString("utf8")
        let parsed = null
        try { parsed = raw ? JSON.parse(raw) : null } catch { parsed = null }
        resolve({ status: Number(response.statusCode || 0), body: parsed })
      })
    })
    request.on("timeout", () => request.destroy(new Error("request_timeout")))
    request.on("error", reject)
    if (requestBody !== undefined) request.write(requestBody)
    request.end()
  })
}

async function waitForApplication () {
  const deadline = Date.now() + 90000
  let lastError = null
  while (Date.now() < deadline) {
    try {
      const response = await boundedRequest("GET", "/", undefined)
      if (response.status >= 200 && response.status < 500) return
    } catch (error) {
      lastError = error
    }
    await new Promise(resolve => setTimeout(resolve, 500))
  }
  throw new Error(lastError instanceof Error ? "application_not_ready" : "application_timeout")
}

function failed (code) {
  emit({
    schema: resultSchema,
    mode,
    expected_status: expectedStatus,
    observed_status: null,
    expected_basket_id_observed: false,
    authorization_denied: false,
    driver_error_code: code,
    passed: false,
    raw_returned: false
  })
  process.exit(81)
}

async function main () {
  if (!Number.isInteger(expectedStatus) || ![200, 403].includes(expectedStatus) || !["positive", "negative"].includes(mode)) {
    return failed("driver_contract_invalid")
  }
  try {
    for (const relative of [".well-known", "frontend/dist", "ftp", "i18n"]) {
      fs.cpSync("/juice-shop-kguard-seed/" + relative, "/juice-shop/" + relative, { recursive: true, force: true })
    }
    require("/juice-shop/bootstrap.js")
    await waitForApplication()
    const login = await boundedRequest("POST", "/rest/user/login", {
      email: "bjoern.kimminich@gmail.com",
      password: Buffer.from("Ylc5akxteHBZVzFuUUdoamFXNXBiVzFwYXk1dWNtVnZhbUk9", "base64").toString("utf8")
    })
    const token = login.body && login.body.authentication && login.body.authentication.token
    if (login.status !== 200 || typeof token !== "string" || token.length < 16) return failed("fixture_login_failed")
    const response = await boundedRequest("GET", "/rest/basket/2", undefined, { Authorization: "Bearer " + token })
    const expectedBasket = response.body && response.body.data && response.body.data.id === 2
    const authorizationDenied = response.status === 403 && !expectedBasket
    const passed = mode === "positive"
      ? response.status === 200 && expectedBasket
      : authorizationDenied
    emit({
      schema: resultSchema,
      mode,
      expected_status: expectedStatus,
      observed_status: response.status,
      expected_basket_id_observed: expectedBasket === true,
      authorization_denied: authorizationDenied,
      driver_error_code: null,
      passed,
      raw_returned: false
    })
    process.exit(passed ? 0 : 81)
  } catch (_error) {
    failed("driver_runtime_failed")
  }
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


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))


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


def _load_source_verifier() -> tuple[Any, str]:
    path = Path(__file__).with_name("holdout_source_materialization.py")
    raw_before = path.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l2_juice_shop_source_verifier", path)
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
    candidates = [item for item in apps if isinstance(item, dict) and item.get("app_id") == APP_ID]
    if len(candidates) != 1:
        raise RuntimeContractError("p23a_registry_juice_shop_missing")
    app = candidates[0]
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
        raise RuntimeContractError("p23a_registry_juice_shop_binding_invalid")
    return app, sha256_bytes(raw)


def _source_projection(receipt: Mapping[str, Any], *, p23a_app: Mapping[str, Any], p23a_registry_sha256: str) -> dict[str, Any]:
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
    fields = ("file_count", "total_bytes")
    if any(receipt.get(key) != p23a_app.get(key) for key in fields):
        raise RuntimeContractError("source_receipt_size_mismatch")
    current_receipt_sha256 = _canonical_sha256(dict(receipt))
    return {
        **expected,
        "p23a_registry_sha256": p23a_registry_sha256,
        "p23a_app_receipt_sha256": P23A_APP_RECEIPT_SHA256,
        "p23a_app_receipt_semantic_sha256": P23A_APP_SEMANTIC_SHA256,
        "current_source_receipt_sha256": current_receipt_sha256,
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


def _labels(image: Mapping[str, Any]) -> Mapping[str, Any]:
    config = image.get("Config")
    labels = config.get("Labels") if isinstance(config, Mapping) else None
    if not isinstance(labels, Mapping):
        raise RuntimeContractError("image_labels_invalid")
    return labels


def _rootfs_layers(image: Mapping[str, Any]) -> tuple[str, ...]:
    rootfs = image.get("RootFS")
    layers = rootfs.get("Layers") if isinstance(rootfs, Mapping) else None
    if not isinstance(layers, list) or not layers or not all(isinstance(layer, str) and IMAGE_ID_RE.fullmatch(layer) for layer in layers):
        raise RuntimeContractError("image_rootfs_layers_invalid")
    return tuple(layers)


def _validate_base_images(source_root: Path, *, work_root: Path) -> dict[str, Any]:
    dockerfile = source_root / "Dockerfile"
    if not dockerfile.is_file() or dockerfile.is_symlink():
        raise RuntimeContractError("source_dockerfile_missing")
    dockerfile_sha256 = sha256_bytes(dockerfile.read_bytes())
    source = _read_image(SOURCE_IMAGE_REF, work_root=work_root)
    adapter = _read_image(ADAPTER_IMAGE_REF, work_root=work_root)
    source_labels = _labels(source)
    adapter_labels = _labels(adapter)
    source_id = source.get("Id")
    adapter_id = adapter.get("Id")
    if source_id != SOURCE_IMAGE_ID or adapter_id != ADAPTER_IMAGE_ID:
        raise RuntimeContractError("base_image_id_mismatch")
    common_expected = {
        "io.k-guard.app-id": APP_ID,
        "io.k-guard.source-tree-sha256": SOURCE_TREE_SHA256,
        "io.k-guard.dockerfile-sha256": dockerfile_sha256,
        "org.opencontainers.image.revision": SOURCE_COMMIT,
        "org.opencontainers.image.source": "https://github.com/juice-shop/juice-shop",
    }
    if any(source_labels.get(key) != value for key, value in common_expected.items()):
        raise RuntimeContractError("source_image_provenance_mismatch")
    if any(adapter_labels.get(key) != value for key, value in common_expected.items()):
        raise RuntimeContractError("adapter_image_provenance_mismatch")
    if adapter_labels.get("io.k-guard.source-image-id") != SOURCE_IMAGE_ID:
        raise RuntimeContractError("adapter_source_image_mismatch")
    source_layers = _rootfs_layers(source)
    adapter_layers = _rootfs_layers(adapter)
    if len(adapter_layers) <= len(source_layers) or adapter_layers[: len(source_layers)] != source_layers:
        raise RuntimeContractError("adapter_rootfs_lineage_mismatch")
    adapter_digests = adapter.get("RepoDigests")
    expected_digest = f"kguard-l2/juice-shop-adapter@{ADAPTER_IMAGE_ID}"
    if not isinstance(adapter_digests, list) or expected_digest not in adapter_digests:
        raise RuntimeContractError("adapter_digest_binding_missing")
    return {
        "source_image_id": SOURCE_IMAGE_ID,
        "adapter_image_id": ADAPTER_IMAGE_ID,
        "adapter_image_ref": ADAPTER_IMAGE_REF,
        "source_image_rootfs_layers_sha256": _canonical_sha256(source_layers),
        "adapter_image_rootfs_layers_sha256": _canonical_sha256(adapter_layers),
        "adapter_digest": expected_digest,
        "source_dockerfile_sha256": dockerfile_sha256,
        "source_image_current_source_provenance_only": True,
        "fresh_dependency_rebuild_proven": False,
        "raw_returned": False,
    }


def _cleanup_container(
    *, work_root: Path, container_name: str, expected_container_id: str | None, nonce: str, contract_label: str
) -> dict[str, Any]:
    inspected = _docker(["container", "inspect", container_name], cwd=work_root, timeout=60)
    ownership_verified = expected_container_id is None
    removed = expected_container_id is None
    if inspected.returncode == 0 and not inspected.timed_out and not inspected.output_truncated:
        try:
            rows = json.loads(inspected.stdout.decode("utf-8"))
            row = rows[0] if isinstance(rows, list) and len(rows) == 1 else None
            labels = _labels(row) if isinstance(row, Mapping) else None
            ownership_verified = (
                isinstance(row, Mapping)
                and row.get("Id") == expected_container_id
                and labels.get("io.k-guard.execution-contract") == contract_label
                and labels.get("io.k-guard.run-nonce") == nonce
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RuntimeContractError):
            ownership_verified = False
        if ownership_verified:
            removed_result = _docker(["container", "rm", "--force", container_name], cwd=work_root, timeout=60)
            removed = (
                removed_result.returncode == 0
                and not removed_result.timed_out
                and not removed_result.output_truncated
            )
    elif inspected.returncode != 0:
        removed = expected_container_id is None
    post = _docker(["container", "inspect", container_name], cwd=work_root, timeout=60)
    absent_after = post.returncode != 0 and not post.timed_out and not post.output_truncated
    return {
        "ownership_verified": ownership_verified,
        "removed": removed,
        "absent_after": absent_after,
        "passed": ownership_verified and removed and absent_after,
        "raw_returned": False,
    }


def _extract_compiled_route(*, work_root: Path, timeout: int) -> tuple[bytes, dict[str, Any]]:
    nonce = secrets.token_hex(16)
    container_name = f"kguard-l2-juice-shop-route-{nonce}"
    container_id: str | None = None
    cleanup: dict[str, Any] | None = None
    try:
        created = _docker(
            [
                "container",
                "create",
                "--name",
                container_name,
                "--label",
                f"io.k-guard.execution-contract={EXECUTION_CONTRACT_LABEL}",
                "--label",
                f"io.k-guard.run-nonce={nonce}",
                "--network",
                "none",
                "--entrypoint",
                "/nodejs/bin/node",
                ADAPTER_IMAGE_ID,
                "-e",
                "process.exit(0)",
            ],
            cwd=work_root,
            timeout=60,
        )
        _expect_success(created, "compiled_route_container_create")
        try:
            container_id = created.stdout.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise RuntimeContractError("compiled_route_container_id_invalid") from exc
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise RuntimeContractError("compiled_route_container_id_invalid")
        copied_path = work_root / "compiled-route.js"
        copied = _docker(
            ["container", "cp", f"{container_name}:/juice-shop/{ROUTE_PATH}", str(copied_path)],
            cwd=work_root,
            timeout=timeout,
        )
        _expect_success(copied, "compiled_route_copy")
        if not copied_path.is_file() or copied_path.is_symlink():
            raise RuntimeContractError("compiled_route_copy_missing")
        route = copied_path.read_bytes()
        if not route or len(route) > MAX_ROUTE_BYTES:
            raise RuntimeContractError("compiled_route_size_invalid")
        return route, {
            "source_path": ROUTE_PATH,
            "original_file_sha256": sha256_bytes(route),
            "source_checkout_mutated": False,
            "extraction_container_network": "none",
            "raw_returned": False,
        }
    finally:
        cleanup = _cleanup_container(
            work_root=work_root,
            container_name=container_name,
            expected_container_id=container_id,
            nonce=nonce,
            contract_label=EXECUTION_CONTRACT_LABEL,
        )
        if not cleanup["passed"]:
            raise RuntimeContractError("compiled_route_cleanup_failed")


def _negative_route_patch(route: bytes) -> tuple[bytes, dict[str, Any]]:
    line_ending = b"\r\n" if b"\r\n" in route else b"\n"
    marker = b"            /* jshint eqeqeq:false */" + line_ending
    guard = line_ending.join(
        (
            b"            const authenticatedUser = security.authenticatedUsers.from(req);",
            b"            if (!authenticatedUser || !id || String(authenticatedUser.bid) !== String(id)) {",
            b"                return res.status(403).json({ error: 'Forbidden' });",
            b"            }",
        )
    ) + line_ending
    if route.count(marker) != 1:
        raise RuntimeContractError("negative_control_patch_anchor_invalid")
    patched = route.replace(marker, guard + marker, 1)
    if patched == route or patched.count(guard) != 1 or patched.count(marker) != 1:
        raise RuntimeContractError("negative_control_patch_not_single")
    return patched, {
        "patch_id": NEGATIVE_CONTROL_PATCH_ID,
        "source_path": ROUTE_PATH,
        "original_file_sha256": sha256_bytes(route),
        "patched_file_sha256": sha256_bytes(patched),
        "patch_sha256": sha256_bytes(guard),
        "marker_count": 1,
        "replacement_count": 1,
        "source_checkout_mutated": False,
        "raw_returned": False,
    }


def _dockerfile_template() -> str:
    return f"""ARG BASE_ADAPTER={ADAPTER_IMAGE_REF}\nFROM ${{BASE_ADAPTER}}\nUSER 0\nCOPY seed.js /opt/kguard/seed.js\nRUN [\"/nodejs/bin/node\", \"/opt/kguard/seed.js\"]\nCOPY driver.js /opt/kguard/driver.js\nUSER 65532:0\n"""


def _build_contract_sha256(*, variant: str, base_images: Mapping[str, Any], route: Mapping[str, Any]) -> str:
    return _canonical_sha256(
        {
            "base_adapter_digest": base_images["adapter_digest"],
            "base_adapter_image_id": base_images["adapter_image_id"],
            "base_adapter_image_ref": base_images["adapter_image_ref"],
            "build_network": "none",
            "docker_subcommand": "build",
            "dockerfile_sha256": sha256_bytes(_dockerfile_template().encode("utf-8")),
            "driver_sha256": sha256_bytes(DRIVER_SCRIPT.encode("utf-8")),
            "seed_sha256": sha256_bytes(SEED_SCRIPT.encode("utf-8")),
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
    context = work_root / f"build-{variant}"
    context.mkdir()
    (context / "driver.js").write_text(DRIVER_SCRIPT, encoding="utf-8", newline="\n")
    (context / "seed.js").write_text(SEED_SCRIPT, encoding="utf-8", newline="\n")
    dockerfile = _dockerfile_template()
    if variant == "negative":
        (context / "basket.js").write_bytes(route)
        dockerfile = dockerfile.replace("COPY driver.js /opt/kguard/driver.js", "COPY driver.js /opt/kguard/driver.js\nCOPY basket.js /juice-shop/build/routes/basket.js")
    elif variant != "positive":
        raise RuntimeContractError("replay_variant_invalid")
    dockerfile_path = context / "Dockerfile.kguard"
    dockerfile_path.write_text(dockerfile, encoding="utf-8", newline="\n")
    nonce = secrets.token_hex(16)
    tag = f"kguard-l2-juice-shop-{variant}-{nonce}"
    contract_label = EXECUTION_CONTRACT_LABEL if variant == "positive" else NEGATIVE_CONTROL_LABEL
    build_arguments = [
        "build",
        "--no-cache",
        "--pull=false",
        "--network",
        "none",
        "--build-arg",
        f"BASE_ADAPTER={base_images['adapter_image_ref']}",
        "--label",
        f"io.k-guard.execution-contract={contract_label}",
        "--label",
        f"io.k-guard.source-adapter-image-id={base_images['adapter_image_id']}",
        "--label",
        f"io.k-guard.build-nonce={nonce}",
        "--file",
        str(dockerfile_path),
        "--tag",
        tag,
        str(context),
    ]
    build = _docker(build_arguments, cwd=work_root, timeout=timeout)
    _expect_success(build, "replay_image_build")
    image = _read_image(tag, work_root=work_root)
    image_id = image.get("Id")
    labels = _labels(image)
    layers = _rootfs_layers(image)
    if not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None:
        raise RuntimeContractError("replay_image_id_invalid")
    if (
        labels.get("io.k-guard.execution-contract") != contract_label
        or labels.get("io.k-guard.source-adapter-image-id") != base_images["adapter_image_id"]
        or labels.get("io.k-guard.build-nonce") != nonce
    ):
        raise RuntimeContractError("replay_image_labels_invalid")
    base = _read_image(ADAPTER_IMAGE_ID, work_root=work_root)
    base_layers = _rootfs_layers(base)
    if len(layers) <= len(base_layers) or layers[: len(base_layers)] != base_layers:
        raise RuntimeContractError("replay_image_lineage_invalid")
    return {
        "image_id": image_id,
        "image_id_sha256": sha256_bytes(image_id.encode("ascii")),
        "base_adapter_image_id": base_images["adapter_image_id"],
        "contract_label": contract_label,
        "dockerfile_sha256": sha256_bytes(dockerfile.encode("utf-8")),
        "driver_sha256": sha256_bytes(DRIVER_SCRIPT.encode("utf-8")),
        "seed_sha256": sha256_bytes(SEED_SCRIPT.encode("utf-8")),
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


def _container_isolation(
    container: Mapping[str, Any], *, image_id: str, contract_label: str, expected_status: int, mode: str
) -> dict[str, Any]:
    host = container.get("HostConfig") if isinstance(container.get("HostConfig"), Mapping) else {}
    config = container.get("Config") if isinstance(container.get("Config"), Mapping) else {}
    labels = config.get("Labels") if isinstance(config.get("Labels"), Mapping) else {}
    network = container.get("NetworkSettings") if isinstance(container.get("NetworkSettings"), Mapping) else {}
    ports = network.get("Ports")
    mounts = container.get("Mounts") if isinstance(container.get("Mounts"), list) else []
    security = {str(value).casefold() for value in host.get("SecurityOpt", []) if isinstance(value, str)}
    cap_drop = {str(value).upper() for value in host.get("CapDrop", []) if isinstance(value, str)}
    tmpfs = host.get("Tmpfs") if isinstance(host.get("Tmpfs"), Mapping) else {}
    environment = {str(value).split("=", 1)[0]: str(value).split("=", 1)[1] for value in config.get("Env", []) if isinstance(value, str) and "=" in value}
    checks = {
        "exact_image": container.get("Image") == image_id,
        "contract_label": labels.get("io.k-guard.execution-contract") == contract_label,
        "network_none": host.get("NetworkMode") == "none",
        "no_host_port_publish": host.get("PortBindings") in (None, {}) and ports in (None, {}),
        "read_only_root": host.get("ReadonlyRootfs") is True,
        "cap_drop_all": "ALL" in cap_drop and not host.get("CapAdd"),
        "no_new_privileges": any(value.startswith("no-new-privileges") for value in security),
        "pids_bounded": host.get("PidsLimit") == PIDS_LIMIT,
        "memory_bounded": host.get("Memory") == MEMORY_BYTES,
        "cpu_bounded": host.get("NanoCpus") == NANO_CPUS,
        "non_root_user": config.get("User") == RUN_AS,
        "not_privileged": host.get("Privileged") is False,
        "no_bind_or_volume_mounts": not mounts and not host.get("Binds"),
        "driver_environment": environment.get("KGUARD_EXPECTED_STATUS") == str(expected_status)
        and environment.get("KGUARD_MODE") == mode,
        "hardened_tmpfs": all(
            isinstance(tmpfs.get(path), str)
            and all(token in tmpfs[path].split(",") for token in ("noexec", "nosuid", "nodev", "uid=65532", "gid=0", "mode=0770"))
            for path in TMPFS_PATHS
        )
        and len(tmpfs) == len(TMPFS_PATHS),
    }
    return {"checks": checks, "passed": all(checks.values()), "raw_returned": False}


def _parse_driver_result(output: bytes, *, expected_status: int, mode: str) -> dict[str, Any]:
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
        "expected_basket_id_observed",
        "authorization_denied",
        "driver_error_code",
        "passed",
        "raw_returned",
    }
    if not isinstance(result, dict) or set(result) != expected_keys:
        raise RuntimeContractError("driver_result_schema_invalid")
    if (
        result.get("schema") != DRIVER_RESULT_SCHEMA
        or result.get("mode") != mode
        or result.get("expected_status") != expected_status
        or result.get("observed_status") != expected_status
        or result.get("expected_basket_id_observed") is not (expected_status == 200)
        or result.get("authorization_denied") is not (expected_status == 403)
        or result.get("driver_error_code") is not None
        or result.get("passed") is not True
        or result.get("raw_returned") is not False
    ):
        raise RuntimeContractError("driver_result_outcome_invalid")
    return {
        "schema": DRIVER_RESULT_SCHEMA,
        "mode": mode,
        "expected_status": expected_status,
        "observed_status": expected_status,
        "expected_basket_id_observed": expected_status == 200,
        "authorization_denied": expected_status == 403,
        "passed": True,
        "raw_returned": False,
    }


def _offline_run(
    image_id: str, *, work_root: Path, timeout: int, variant: str
) -> dict[str, Any]:
    expected_status = 200 if variant == "positive" else 403
    contract_label = EXECUTION_CONTRACT_LABEL if variant == "positive" else NEGATIVE_CONTROL_LABEL
    nonce = secrets.token_hex(16)
    container_name = f"kguard-l2-juice-shop-{variant}-{nonce}"
    container_id: str | None = None
    result: dict[str, Any] = {
        "run_nonce_sha256": sha256_bytes(nonce.encode("ascii")),
        "image_id": image_id,
        "driver_sha256": sha256_bytes(DRIVER_SCRIPT.encode("utf-8")),
        "network_policy": "none",
        "expected_status": expected_status,
        "mode": variant,
        "isolation": None,
        "execution": None,
        "normalized_result": None,
        "cleanup": None,
        "failure_code": None,
        "passed": False,
        "raw_returned": False,
    }
    try:
        create_arguments = [
            "container",
            "create",
            "--name",
            container_name,
            "--label",
            f"io.k-guard.execution-contract={contract_label}",
            "--label",
            f"io.k-guard.run-nonce={nonce}",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            str(PIDS_LIMIT),
            "--memory",
            str(MEMORY_BYTES),
            "--cpus",
            "2",
            "--user",
            RUN_AS,
            "--env",
            f"KGUARD_EXPECTED_STATUS={expected_status}",
            "--env",
            f"KGUARD_MODE={variant}",
        ]
        for path in TMPFS_PATHS:
            create_arguments.extend(["--tmpfs", f"{path}:{TMPFS_OPTIONS}"])
        create_arguments.extend(["--entrypoint", "/nodejs/bin/node", image_id, "/opt/kguard/driver.js"])
        created = _docker(create_arguments, cwd=work_root, timeout=60)
        _expect_success(created, "offline_container_create")
        try:
            container_id = created.stdout.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise RuntimeContractError("offline_container_id_invalid") from exc
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise RuntimeContractError("offline_container_id_invalid")
        inspected = _load_json_stdout(
            _docker(["container", "inspect", container_name], cwd=work_root, timeout=60),
            "offline_container_inspect",
        )
        if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
            raise RuntimeContractError("offline_container_inspect_shape")
        isolation = _container_isolation(
            inspected[0], image_id=image_id, contract_label=contract_label, expected_status=expected_status, mode=variant
        )
        result["isolation"] = isolation
        if not isolation["passed"]:
            raise RuntimeContractError("offline_container_isolation_failed")
        started = _docker(["container", "start", "--attach", container_name], cwd=work_root, timeout=timeout)
        result["execution"] = _command_receipt(started)
        if started.returncode != 0 or started.timed_out or started.output_truncated:
            raise RuntimeContractError("offline_driver_failed")
        result["normalized_result"] = _parse_driver_result(
            started.stdout, expected_status=expected_status, mode=variant
        )
        post = _load_json_stdout(
            _docker(["container", "inspect", container_name], cwd=work_root, timeout=60),
            "offline_container_post_inspect",
        )
        if not isinstance(post, list) or len(post) != 1 or not isinstance(post[0], dict):
            raise RuntimeContractError("offline_container_post_shape")
        state = post[0].get("State") if isinstance(post[0].get("State"), Mapping) else {}
        if state.get("Running") is not False or state.get("ExitCode") != 0:
            raise RuntimeContractError("offline_container_exit_state_invalid")
    except RuntimeContractError as exc:
        result["failure_code"] = str(exc)
    finally:
        result["cleanup"] = _cleanup_container(
            work_root=work_root,
            container_name=container_name,
            expected_container_id=container_id,
            nonce=nonce,
            contract_label=contract_label,
        )
    result["passed"] = (
        isinstance(result["isolation"], Mapping)
        and result["isolation"].get("passed") is True
        and isinstance(result["execution"], Mapping)
        and result["execution"].get("returncode") == 0
        and isinstance(result["normalized_result"], Mapping)
        and result["failure_code"] is None
        and isinstance(result["cleanup"], Mapping)
        and result["cleanup"].get("passed") is True
    )
    return result


def _consensus_projection(run: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "driver_sha256": run.get("driver_sha256"),
        "network_policy": run.get("network_policy"),
        "expected_status": run.get("expected_status"),
        "mode": run.get("mode"),
        "isolation": run.get("isolation"),
        "normalized_result": run.get("normalized_result"),
        "passed": run.get("passed"),
    }


def _cleanup_image(image_id: str, *, work_root: Path, contract_label: str) -> dict[str, Any]:
    inspected = _docker(["image", "inspect", image_id], cwd=work_root, timeout=60)
    ownership_verified = False
    if inspected.returncode == 0 and not inspected.timed_out and not inspected.output_truncated:
        try:
            rows = json.loads(inspected.stdout.decode("utf-8"))
            row = rows[0] if isinstance(rows, list) and len(rows) == 1 else None
            labels = _labels(row) if isinstance(row, Mapping) else None
            ownership_verified = isinstance(row, Mapping) and labels.get("io.k-guard.execution-contract") == contract_label
        except (UnicodeDecodeError, json.JSONDecodeError, RuntimeContractError):
            ownership_verified = False
    removed = False
    if ownership_verified:
        removal = _docker(["image", "rm", "--force", image_id], cwd=work_root, timeout=120)
        removed = removal.returncode == 0 and not removal.timed_out and not removal.output_truncated
    post = _docker(["image", "inspect", image_id], cwd=work_root, timeout=60)
    absent_after = post.returncode != 0 and not post.timed_out and not post.output_truncated
    return {
        "ownership_verified": ownership_verified,
        "removed": removed,
        "absent_after": absent_after,
        "passed": ownership_verified and removed and absent_after,
        "raw_returned": False,
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
        "seed_sha256": sha256_bytes(SEED_SCRIPT.encode("utf-8")),
        "source_image_id": SOURCE_IMAGE_ID,
        "adapter_image_id": ADAPTER_IMAGE_ID,
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
    tool_provenance = _tool_provenance(verifier_sha256)
    contract_label = EXECUTION_CONTRACT_LABEL if variant == "positive" else NEGATIVE_CONTROL_LABEL
    with tempfile.TemporaryDirectory(prefix=f"kguard-l2-juice-shop-{variant}-") as temporary:
        work_root = Path(temporary)
        base_images = _validate_base_images(source_root.resolve(), work_root=work_root)
        image: dict[str, Any] | None = None
        image_id: str | None = None
        image_cleanup: dict[str, Any] | None = None
        runs: list[dict[str, Any]] = []
        route_projection: dict[str, Any] | None = None
        failure: str | None = None
        try:
            route, extraction = _extract_compiled_route(work_root=work_root, timeout=timeout)
            if variant == "negative":
                route, patch = _negative_route_patch(route)
                route_projection = {**extraction, **patch}
            else:
                route_projection = extraction
            image, image_id = _build_replay_image(
                work_root=work_root,
                timeout=timeout,
                base_images=base_images,
                route=route,
                route_projection=route_projection,
                variant=variant,
            )
            runs = [_offline_run(image_id, work_root=work_root, timeout=timeout, variant=variant) for _ in range(2)]
        except RuntimeContractError as exc:
            failure = str(exc)
        finally:
            if image_id is not None:
                image_cleanup = _cleanup_image(image_id, work_root=work_root, contract_label=contract_label)
    projections = [_consensus_projection(run) for run in runs]
    consensus_passed = (
        len(projections) == 2
        and projections[0] == projections[1]
        and all(run.get("passed") is True for run in runs)
    )
    if failure is None and not consensus_passed:
        failure = "execution_repeatability_or_runtime_failed"
    status = (
        "EXECUTION_CONTRACT_PASS" if variant == "positive" else "NEGATIVE_CONTROL_PASS"
    ) if failure is None and image is not None and image_cleanup is not None and image_cleanup.get("passed") is True and consensus_passed else "HOLD"
    common = {
        "tool_provenance": tool_provenance,
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
        "failure_code": failure,
        "raw_returned": False,
    }
    if variant == "positive":
        receipt = {
            "schema": SCHEMA,
            **common,
            "claim_boundary": _claim_boundary(negative=False),
            "admission_blockers": list(ADMISSION_BLOCKERS),
            "execution_contract_status": status,
        }
        validate_receipt(receipt)
        return receipt
    if positive_reference is None:
        raise RuntimeContractError("negative_control_positive_reference_missing")
    receipt = {
        "schema": NEGATIVE_CONTROL_SCHEMA,
        **common,
        "positive_execution_contract": dict(positive_reference),
        "negative_control": route_projection,
        "claim_boundary": _claim_boundary(negative=True),
        "admission_blockers": list(NEGATIVE_CONTROL_ADMISSION_BLOCKERS),
        "negative_control_status": status,
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
    return _execute(
        source_root,
        p23a_registry,
        timeout=timeout,
        variant="negative",
        positive_reference=positive_reference,
    )


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
    if not isinstance(source.get("file_count"), int) or not isinstance(source.get("total_bytes"), int):
        raise RuntimeContractError("receipt_source_size_invalid")


def _validate_tool(tool: object) -> None:
    if not isinstance(tool, Mapping) or tool.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_tool_invalid")
    for key in ("runner_sha256", "source_verifier_sha256", "driver_sha256", "seed_sha256"):
        if not isinstance(tool.get(key), str) or SHA256_RE.fullmatch(tool[key]) is None:
            raise RuntimeContractError("receipt_tool_hash_invalid")
    if tool.get("source_image_id") != SOURCE_IMAGE_ID or tool.get("adapter_image_id") != ADAPTER_IMAGE_ID:
        raise RuntimeContractError("receipt_tool_image_binding_invalid")


def _validate_run(run: object, *, variant: str) -> None:
    if not isinstance(run, Mapping) or run.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_run_invalid")
    expected_status = 200 if variant == "positive" else 403
    if (
        run.get("network_policy") != "none"
        or run.get("expected_status") != expected_status
        or run.get("mode") != variant
        or run.get("passed") is not True
        or not isinstance(run.get("isolation"), Mapping)
        or run["isolation"].get("passed") is not True
        or not isinstance(run.get("execution"), Mapping)
        or run["execution"].get("returncode") != 0
        or not isinstance(run.get("normalized_result"), Mapping)
        or run["normalized_result"].get("passed") is not True
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
    status_key = "execution_contract_status" if variant == "positive" else "negative_control_status"
    passed_status = "EXECUTION_CONTRACT_PASS" if variant == "positive" else "NEGATIVE_CONTROL_PASS"
    status = receipt.get(status_key)
    if status not in {passed_status, "HOLD"}:
        raise RuntimeContractError("receipt_status_invalid")
    if status == passed_status:
        runs = receipt.get("runs")
        consensus = receipt.get("consensus")
        if (
            not isinstance(runs, list)
            or len(runs) != 2
            or not all(isinstance(run, Mapping) for run in runs)
            or not isinstance(consensus, Mapping)
            or consensus.get("run_count") != 2
            or consensus.get("two_runs_byte_equivalent_after_normalization") is not True
            or not isinstance(receipt.get("image"), Mapping)
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
        description="Replay a source-bound Juice Shop basket BOLA execution pair without detector or release promotion."
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
