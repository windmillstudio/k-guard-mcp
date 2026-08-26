from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
MATERIALIZER_PATH = REPOSITORY_ROOT / "scripts" / "materialize_l2_sources.py"

SCHEMA = "k_guard_l2_crapi_vehicle_bola_execution_contract.v1"
NEGATIVE_CONTROL_SCHEMA = "k_guard_l2_crapi_vehicle_bola_negative_control.v1"
DRIVER_RESULT_SCHEMA = "k_guard_l2_crapi_vehicle_bola_driver_result.v1"

APP_ID = "crapi"
REPOSITORY_ID = "owasp/crapi"
SOURCE_COMMIT = "73d309cc8f28bbdeed31dbb35f05dba8354de3c9"
SOURCE_TREE = "86d22e42ca8f8e3c903f30146ad0df51483b8df0"
SOURCE_TREE_SHA256 = "f76c89d35f9b7d34c3b12c6b2f64177e0845957f85fab52613bbc18354925d52"
P23A_APP_RECEIPT_SHA256 = "d86a9985f9eda5e391112a26a092f7a5273bde393c386ae8968f91399df7429b"
P23A_APP_SEMANTIC_SHA256 = "e284ea288d5a36a07661f279690c6e62bdd62e5905c2e2b3d733022efb64daaf"

IDENTITY_SUBPROJECT = "services/identity"
CONTROLLER_PATH = (
    "services/identity/src/main/java/com/crapi/controller/VehicleController.java"
)
SOURCE_IMAGE_REF = "kguard-l2/crapi-identity:73d309cc-raw"
SOURCE_IMAGE_ID = "sha256:f9c4fa33439b7e89f09625cc58933d83e64fffa6c22dd7d9dad3e79ecae7ac95"
SOURCE_DOCKERFILE_SHA256 = "6ecdd3a650640d5b1ead281b0299cf5e3bd9764e62cd3b490ded246bfea782c0"
POSTGRES_IMAGE_REF = (
    "postgres@sha256:caf49e3b10d377aa2cfee478591d623808527beb27125d38797b418013f72d81"
)
PYTHON_DRIVER_IMAGE_REF = (
    "python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
)

SOURCE_FILES = {
    "services/identity/Dockerfile": SOURCE_DOCKERFILE_SHA256,
    "services/identity/entrypoint.sh": (
        "855332e32c5e8e7a55568a59c44fe0cc88f6608b8ba8fddd4dcf2105a07fd18f"
    ),
    "services/identity/build.gradle.kts": (
        "aff24988756aac240601f2874fcdc0239084db31cd0d9fa727db5354f97085cf"
    ),
    "services/identity/src/main/resources/application.properties": (
        "0a7805c942f360856f6a65a45db2b810ca56ce7015ba2d795694015b30368b26"
    ),
    CONTROLLER_PATH: (
        "c49f5ab14aab7b80386c5e309d6e493360ab86f21d41d939002f1d2961f78789"
    ),
    "services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java": (
        "1eadd6a4020699ea0e48e2ab3a245afc2618daf8e75ec97057f84a883d34a2c7"
    ),
    "services/identity/src/main/java/com/crapi/config/InitialDataConfig.java": (
        "9ac5f89ec9dd9c3397b66916f5998146c43ea1603d5b3fc1b6029425b088c9f4"
    ),
    "services/identity/src/main/java/com/crapi/constant/TestUsers.java": (
        "48a12a8a65695424def59cd21f4036ffe1af3201b6a933cca45f14dc8c80c369"
    ),
}

EXPECTED_SOURCE_IMAGE_LABELS = {
    "kguard.source.repository": REPOSITORY_ID,
    "kguard.source.commit": SOURCE_COMMIT,
    "kguard.source.tree": SOURCE_TREE,
    "kguard.source.tree-sha256": SOURCE_TREE_SHA256,
    "kguard.source.dockerfile-sha256": SOURCE_DOCKERFILE_SHA256,
}

EXECUTION_CONTRACT_LABEL = "crapi-identity-vehicle-bola-v1"
NEGATIVE_CONTROL_LABEL = "crapi-identity-vehicle-owner-guard-negative-control-v1"
NEGATIVE_CONTROL_PATCH_ID = "vehicle-location-current-owner-guard.v1"
NETWORK_POLICY = "internal_bridge_identity_postgres_driver_v1"

APP_USER = "10001:10001"
POSTGRES_USER = "999:999"
APP_MEMORY_BYTES = 768 * 1024 * 1024
POSTGRES_MEMORY_BYTES = 768 * 1024 * 1024
DRIVER_MEMORY_BYTES = 128 * 1024 * 1024
APP_NANO_CPUS = 1_000_000_000
POSTGRES_NANO_CPUS = 1_000_000_000
DRIVER_NANO_CPUS = 500_000_000
APP_PIDS_LIMIT = 256
POSTGRES_PIDS_LIMIT = 128
DRIVER_PIDS_LIMIT = 64
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_DRIVER_OUTPUT_BYTES = 64 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

APP_TMPFS = {
    "/tmp": "rw,noexec,nosuid,nodev,size=67108864,uid=10001,gid=10001,mode=0700",
}
POSTGRES_TMPFS = {
    "/var/lib/postgresql/data": (
        "rw,noexec,nosuid,nodev,size=536870912,uid=999,gid=999,mode=0700"
    ),
    "/var/run/postgresql": (
        "rw,noexec,nosuid,nodev,size=16777216,uid=999,gid=999,mode=0775"
    ),
    "/tmp": "rw,noexec,nosuid,nodev,size=67108864,uid=999,gid=999,mode=1777",
}
DRIVER_TMPFS = {
    "/tmp": "rw,noexec,nosuid,nodev,size=16777216,uid=10001,gid=10001,mode=0700",
}

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


# The driver deliberately keeps source fixture values, JWTs, response bytes, and
# HTTP headers inside the one-shot container. Its stdout contains only status and
# structural booleans.
DRIVER_SCRIPT = r'''from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any


MARKER = "K_GUARD_CRAPI_VEHICLE_BOLA_RESULT:"
SCHEMA = "k_guard_l2_crapi_vehicle_bola_driver_result.v1"
MAX_RESPONSE_BYTES = 131072

ACTOR_EMAIL = base64.b64decode("YWRhbTAwN0BleGFtcGxlLmNvbQ==").decode("ascii")
ACTOR_PASSWORD = base64.b64decode("YWRhbTAwNyExMjM=").decode("ascii")
TARGET_VEHICLE_ID = base64.b64decode(
    "Y2Q1MTVjMTItMGZjMS00OGFlLThiNjEtOTIzMGI3MGE4NDVi"
).decode("ascii")


def emit(payload: dict[str, Any]) -> None:
    print(MARKER + json.dumps(payload, sort_keys=True, separators=(",", ":")), flush=True)


def failed(mode: str, expected_status: int, code: str) -> int:
    emit(
        {
            "schema": SCHEMA,
            "mode": mode,
            "expected_status": expected_status,
            "observed_status": None,
            "token_present": False,
            "actor_target_distinct": True,
            "response_object_observed": False,
            "target_field_shape_observed": False,
            "target_location_field_observed": False,
            "target_full_name_field_observed": False,
            "target_email_field_observed": False,
            "target_response_absent": False,
            "driver_error_code": code,
            "passed": False,
            "raw_returned": False,
        }
    )
    return 81


def request(
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request_headers = dict(headers or {})
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        "http://identity:8080" + path,
        data=body,
        method=method,
        headers=request_headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_RESPONSE_BYTES:
                raise RuntimeError("response_too_large")
            return int(response.status), response_body
    except urllib.error.HTTPError as error:
        response_body = error.read(MAX_RESPONSE_BYTES + 1)
        if len(response_body) > MAX_RESPONSE_BYTES:
            raise RuntimeError("response_too_large")
        return int(error.code), response_body


def wait_for_application() -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            status, _ = request("/identity/health_check")
            if status == 200:
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError("application_not_ready")


def parse_json(raw: bytes) -> object:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def main() -> int:
    mode = os.environ.get("KGUARD_MODE", "")
    try:
        expected_status = int(os.environ.get("KGUARD_EXPECTED_STATUS", ""))
    except ValueError:
        return failed(mode, 0, "driver_contract_invalid")
    if (mode, expected_status) not in {("positive", 200), ("negative", 403)}:
        return failed(mode, expected_status, "driver_contract_invalid")
    try:
        wait_for_application()
        login_status, login_body = request(
            "/identity/api/auth/login",
            method="POST",
            payload={"email": ACTOR_EMAIL, "password": ACTOR_PASSWORD},
        )
        login = parse_json(login_body)
        token = login.get("token") if isinstance(login, dict) else None
        token_present = isinstance(token, str) and len(token) > 10
        if login_status != 200 or not token_present:
            return failed(mode, expected_status, "fixture_login_failed")
        observed_status, response_body = request(
            "/identity/api/v2/vehicle/" + TARGET_VEHICLE_ID + "/location",
            headers={"Authorization": "Bearer " + token},
        )
        parsed = parse_json(response_body)
        response_object = isinstance(parsed, dict)
        target_location = response_object and "vehicleLocation" in parsed
        target_name = response_object and "fullName" in parsed
        target_email = response_object and "email" in parsed
        target_car = response_object and "carId" in parsed
        field_shape = bool(target_location and target_name and target_email and target_car)
        # A 403 may legitimately use a generic JSON error envelope. The negative
        # control only requires absence of the target vehicle response shape, not
        # absence of every response object.
        target_response_absent = not field_shape
        passed = (
            observed_status == 200
            and token_present
            and response_object
            and field_shape
            and target_location
            and target_name
            and target_email
            if mode == "positive"
            else observed_status == 403
            and token_present
            and target_response_absent
            and not target_location
            and not target_name
            and not target_email
        )
        emit(
            {
                "schema": SCHEMA,
                "mode": mode,
                "expected_status": expected_status,
                "observed_status": observed_status,
                "token_present": token_present,
                "actor_target_distinct": True,
                "response_object_observed": response_object,
                "target_field_shape_observed": field_shape,
                "target_location_field_observed": bool(target_location),
                "target_full_name_field_observed": bool(target_name),
                "target_email_field_observed": bool(target_email),
                "target_response_absent": target_response_absent,
                "driver_error_code": None,
                "passed": passed,
                "raw_returned": False,
            }
        )
        return 0 if passed and observed_status == expected_status else 81
    except Exception:
        return failed(mode, expected_status, "driver_runtime_failed")


if __name__ == "__main__":
    raise SystemExit(main())
'''

ORIGINAL_CONTROLLER_METHOD = b'''  @GetMapping("/vehicle/{carId}/location")
  public ResponseEntity<?> getLocationBOLA(@PathVariable("carId") UUID carId) {
    VehicleLocationResponse vehicleDetails = vehicleService.getVehicleLocation(carId);
    if (vehicleDetails != null) return ResponseEntity.ok().body(vehicleDetails);
    else
      return ResponseEntity.status(HttpStatus.NOT_FOUND)
          .body(new CRAPIResponse(UserMessage.DID_NOT_GET_VEHICLE_FOR_USER));
  }
'''

PATCHED_CONTROLLER_METHOD = b'''  @GetMapping("/vehicle/{carId}/location")
  public ResponseEntity<?> getLocationBOLA(
      @PathVariable("carId") UUID carId, HttpServletRequest request) {
    boolean currentUserOwnsVehicle =
        vehicleService.getVehicleDetails(request).stream()
            .anyMatch(vehicle -> carId.equals(vehicle.getUuid()));
    if (!currentUserOwnsVehicle) {
      return ResponseEntity.status(HttpStatus.FORBIDDEN)
          .body(new CRAPIResponse(UserMessage.DID_NOT_GET_VEHICLE_FOR_USER, 403));
    }
    VehicleLocationResponse vehicleDetails = vehicleService.getVehicleLocation(carId);
    if (vehicleDetails != null) return ResponseEntity.ok().body(vehicleDetails);
    else
      return ResponseEntity.status(HttpStatus.NOT_FOUND)
          .body(new CRAPIResponse(UserMessage.DID_NOT_GET_VEHICLE_FOR_USER));
  }
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
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        + "\n"
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
        stdout_bytes = stdout.read(MAX_OUTPUT_BYTES + 1)
        stderr_bytes = stderr.read(MAX_OUTPUT_BYTES + 1)
    output_truncated = len(stdout_bytes) > MAX_OUTPUT_BYTES or len(stderr_bytes) > MAX_OUTPUT_BYTES
    if output_truncated:
        stdout_bytes = stdout_bytes[:MAX_OUTPUT_BYTES]
        stderr_bytes = stderr_bytes[:MAX_OUTPUT_BYTES]
    return CommandResult(
        returncode=returncode,
        stdout=stdout_bytes,
        stderr=stderr_bytes,
        timed_out=timed_out,
        output_truncated=output_truncated,
    )


def _docker(arguments: list[str], *, cwd: Path, timeout: int) -> CommandResult:
    return _run_bounded(["docker", *arguments], cwd=cwd, timeout=timeout)


def _command_receipt(result: CommandResult) -> dict[str, Any]:
    return {
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "output_truncated": result.output_truncated,
        "stdout_sha256": sha256_bytes(result.stdout),
        "stderr_sha256": sha256_bytes(result.stderr),
        "stdout_bytes": len(result.stdout),
        "stderr_bytes": len(result.stderr),
    }


def _expect_success(result: CommandResult, label: str) -> None:
    if result.returncode != 0 or result.timed_out or result.output_truncated:
        raise RuntimeContractError(f"{label}_failed")


def _load_json_stdout(result: CommandResult, label: str) -> Any:
    _expect_success(result, label)
    try:
        return json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError(f"{label}_not_json") from exc


def _load_source_verifier() -> tuple[Any, Any, str, str]:
    raw_before = MATERIALIZER_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location(
        "k_guard_l2_crapi_source_materializer", MATERIALIZER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeContractError("source_materializer_unavailable")
    materializer = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = materializer
    spec.loader.exec_module(materializer)
    if MATERIALIZER_PATH.read_bytes() != raw_before:
        raise RuntimeContractError("source_materializer_changed_while_loading")
    verifier, verifier_sha256 = materializer._load_source_materialization_with_hash()
    return materializer, verifier, sha256_bytes(raw_before), verifier_sha256


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _require_external_existing_directory(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise RuntimeContractError(f"{label}_must_be_absolute")
    resolved = path.resolve(strict=True)
    if resolved.is_symlink() or not resolved.is_dir():
        raise RuntimeContractError(f"{label}_invalid")
    if _is_within(resolved, REPOSITORY_ROOT):
        raise RuntimeContractError(f"{label}_must_be_external")
    return resolved


def _require_external_new_file(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise RuntimeContractError(f"{label}_must_be_absolute")
    resolved = path.resolve(strict=False)
    if _is_within(resolved, REPOSITORY_ROOT):
        raise RuntimeContractError(f"{label}_must_be_external")
    parent = resolved.parent.resolve(strict=True)
    if not parent.is_dir() or parent.is_symlink():
        raise RuntimeContractError(f"{label}_parent_invalid")
    if resolved.exists() or resolved.is_symlink():
        raise FileExistsError(f"{label}_already_exists")
    return resolved


def _safe_source_file(source_root: Path, relative: str) -> Path:
    candidate = source_root / relative
    resolved = candidate.resolve(strict=True)
    if candidate.is_symlink() or not resolved.is_file() or not _is_within(resolved, source_root):
        raise RuntimeContractError("source_file_invalid")
    return resolved


def _read_source_files(source_root: Path) -> dict[str, bytes]:
    values: dict[str, bytes] = {}
    for relative, expected_sha256 in SOURCE_FILES.items():
        raw = _safe_source_file(source_root, relative).read_bytes()
        if sha256_bytes(raw) != expected_sha256:
            raise RuntimeContractError("source_file_hash_mismatch")
        values[relative] = raw
    return values


def _load_p23a_registry(path: Path) -> tuple[dict[str, Any], str]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeContractError("p23a_registry_invalid")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError("p23a_registry_not_json") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise RuntimeContractError("p23a_registry_not_canonical")
    apps = payload.get("apps")
    if not isinstance(apps, list):
        raise RuntimeContractError("p23a_registry_apps_invalid")
    matches = [app for app in apps if isinstance(app, dict) and app.get("app_id") == APP_ID]
    if len(matches) != 1:
        raise RuntimeContractError("p23a_registry_crapi_missing")
    app = matches[0]
    expected = {
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
        "receipt_sha256": P23A_APP_RECEIPT_SHA256,
        "receipt_semantic_sha256": P23A_APP_SEMANTIC_SHA256,
        "source_license_admission": "PASS",
    }
    if any(app.get(field) != value for field, value in expected.items()):
        raise RuntimeContractError("p23a_registry_identity_mismatch")
    return app, sha256_bytes(raw)


def verify_source_workspace(source_root: Path, p23a_registry: Path) -> tuple[dict[str, Any], dict[str, bytes], str]:
    root = _require_external_existing_directory(source_root, "source_root")
    materializer, verifier, materializer_sha256, verifier_sha256 = _load_source_verifier()
    registry_app, registry_sha256 = _load_p23a_registry(p23a_registry)
    receipt = verifier.build_git_materialization_receipt(
        root,
        expected_repository_id=REPOSITORY_ID,
        expected_commit=SOURCE_COMMIT,
        expected_tree=SOURCE_TREE,
    )
    if receipt.get("source_tree_sha256") != SOURCE_TREE_SHA256:
        raise RuntimeContractError("source_tree_hash_mismatch")
    semantic_sha256 = materializer._source_receipt_semantic_sha256(receipt)
    if semantic_sha256 != P23A_APP_SEMANTIC_SHA256:
        raise RuntimeContractError("source_receipt_semantic_mismatch")
    if registry_app.get("receipt_semantic_sha256") != semantic_sha256:
        raise RuntimeContractError("source_registry_semantic_mismatch")
    source_files = _read_source_files(root)
    source_receipt_sha256 = sha256_bytes(canonical_json_bytes(receipt))
    return (
        {
            "repository_id": REPOSITORY_ID,
            "commit": SOURCE_COMMIT,
            "commit_tree": SOURCE_TREE,
            "source_tree_sha256": SOURCE_TREE_SHA256,
            "p23a_registry_sha256": registry_sha256,
            "p23a_app_receipt_sha256": P23A_APP_RECEIPT_SHA256,
            "p23a_app_receipt_semantic_sha256": P23A_APP_SEMANTIC_SHA256,
            "current_source_receipt_sha256": source_receipt_sha256,
            "current_source_receipt_semantic_sha256": semantic_sha256,
            "file_count": receipt.get("file_count"),
            "total_bytes": receipt.get("total_bytes"),
            "source_file_sha256": {
                relative: sha256_bytes(raw) for relative, raw in sorted(source_files.items())
            },
            "raw_returned": False,
        },
        source_files,
        verifier_sha256 + ":" + materializer_sha256,
    )


def _read_image(reference: str, *, work_root: Path) -> dict[str, Any]:
    value = _load_json_stdout(
        _docker(["image", "inspect", reference], cwd=work_root, timeout=60),
        "image_inspect",
    )
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise RuntimeContractError("image_inspect_shape_invalid")
    return value[0]


def _labels(image: Mapping[str, Any]) -> Mapping[str, Any]:
    config = image.get("Config")
    if not isinstance(config, Mapping):
        raise RuntimeContractError("image_config_invalid")
    labels = config.get("Labels")
    if not isinstance(labels, Mapping):
        raise RuntimeContractError("image_labels_invalid")
    return labels


def _image_id(image: Mapping[str, Any]) -> str:
    value = image.get("Id")
    if not isinstance(value, str) or not IMAGE_ID_RE.fullmatch(value):
        raise RuntimeContractError("image_id_invalid")
    return value


def _validate_base_source_image(*, work_root: Path) -> dict[str, Any]:
    image = _read_image(SOURCE_IMAGE_REF, work_root=work_root)
    image_id = _image_id(image)
    if image_id != SOURCE_IMAGE_ID:
        raise RuntimeContractError("source_image_id_mismatch")
    labels = _labels(image)
    if any(labels.get(key) != value for key, value in EXPECTED_SOURCE_IMAGE_LABELS.items()):
        raise RuntimeContractError("source_image_label_mismatch")
    return {
        "source_image_ref": SOURCE_IMAGE_REF,
        "source_image_id": image_id,
        "source_image_labels": dict(EXPECTED_SOURCE_IMAGE_LABELS),
        "source_dockerfile_sha256": SOURCE_DOCKERFILE_SHA256,
        "source_image_current_source_provenance_only": True,
        "fresh_dependency_rebuild_proven": False,
        "runtime_supply_chain_proven": False,
        "raw_returned": False,
    }


def _runtime_image_projection(reference: str, *, work_root: Path) -> dict[str, Any]:
    image = _read_image(reference, work_root=work_root)
    return {
        "reference": reference,
        "image_id": _image_id(image),
        "raw_returned": False,
    }


def _dockerfile_for_driver() -> str:
    return (
        f"FROM {PYTHON_DRIVER_IMAGE_REF}\n"
        "COPY driver.py /opt/kguard/driver.py\n"
        "ENTRYPOINT [\"python\", \"/opt/kguard/driver.py\"]\n"
    )


def _build_driver_image(*, work_root: Path) -> dict[str, Any]:
    driver_sha256 = sha256_bytes(DRIVER_SCRIPT.encode("utf-8"))
    dockerfile = _dockerfile_for_driver()
    dockerfile_sha256 = sha256_bytes(dockerfile.encode("utf-8"))
    image_ref = f"kguard-l2/crapi-bola-driver:{secrets.token_hex(10)}"
    with tempfile.TemporaryDirectory(prefix="kguard-crapi-driver-", dir=work_root) as temporary:
        context = Path(temporary)
        (context / "driver.py").write_text(DRIVER_SCRIPT, encoding="utf-8", newline="\n")
        (context / "Dockerfile").write_text(dockerfile, encoding="utf-8", newline="\n")
        result = _docker(
            [
                "build",
                "--quiet",
                "--pull=false",
                "--network=none",
                "--label",
                f"kguard.execution.driver-sha256={driver_sha256}",
                "--label",
                f"kguard.execution.dockerfile-sha256={dockerfile_sha256}",
                "-t",
                image_ref,
                str(context),
            ],
            cwd=work_root,
            timeout=300,
        )
        _expect_success(result, "driver_image_build")
    image = _read_image(image_ref, work_root=work_root)
    labels = _labels(image)
    if (
        labels.get("kguard.execution.driver-sha256") != driver_sha256
        or labels.get("kguard.execution.dockerfile-sha256") != dockerfile_sha256
    ):
        raise RuntimeContractError("driver_image_label_mismatch")
    return {
        "driver_image_ref": image_ref,
        "driver_image_id": _image_id(image),
        "driver_sha256": driver_sha256,
        "dockerfile_sha256": dockerfile_sha256,
        "driver_base_image": _runtime_image_projection(
            PYTHON_DRIVER_IMAGE_REF, work_root=work_root
        ),
        "raw_returned": False,
    }


def _cleanup_image(reference: str, *, work_root: Path) -> dict[str, Any]:
    result = _docker(["image", "rm", "-f", reference], cwd=work_root, timeout=60)
    _expect_success(result, "temporary_image_cleanup")
    return {"removed": True, "receipt": _command_receipt(result), "raw_returned": False}


def _negative_controller_patch(controller: bytes) -> tuple[bytes, dict[str, Any]]:
    marker_count = controller.count(ORIGINAL_CONTROLLER_METHOD)
    if marker_count != 1:
        raise RuntimeContractError("negative_patch_anchor_ambiguous")
    if b"currentUserOwnsVehicle" in controller:
        raise RuntimeContractError("negative_patch_marker_already_present")
    patched = controller.replace(ORIGINAL_CONTROLLER_METHOD, PATCHED_CONTROLLER_METHOD, 1)
    if patched.count(PATCHED_CONTROLLER_METHOD) != 1:
        raise RuntimeContractError("negative_patch_replacement_invalid")
    if b"getVehicleDetails(request).stream()" not in patched:
        raise RuntimeContractError("negative_patch_owner_guard_missing")
    patch_sha256 = sha256_bytes(PATCHED_CONTROLLER_METHOD)
    return (
        patched,
        {
            "patch_id": NEGATIVE_CONTROL_PATCH_ID,
            "source_path": CONTROLLER_PATH,
            "original_file_sha256": sha256_bytes(controller),
            "patched_file_sha256": sha256_bytes(patched),
            "patch_sha256": patch_sha256,
            "marker_count": marker_count,
            "replacement_count": 1,
            "source_checkout_mutated": False,
            "raw_returned": False,
        },
    )


def _build_negative_image(
    source_root: Path,
    source_files: Mapping[str, bytes],
    *,
    source_image: Mapping[str, Any],
    work_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    original = source_files.get(CONTROLLER_PATH)
    if not isinstance(original, bytes):
        raise RuntimeContractError("negative_controller_source_missing")
    patched, negative_control = _negative_controller_patch(original)
    image_ref = f"kguard-l2/crapi-identity-negative:{secrets.token_hex(10)}"
    with tempfile.TemporaryDirectory(prefix="kguard-crapi-negative-", dir=work_root) as temporary:
        temporary_root = Path(temporary)
        source_context = temporary_root / "identity"
        source_identity = _safe_source_file(source_root, "services/identity/Dockerfile").parent
        shutil.copytree(source_identity, source_context)
        copied_controller = source_context / "src/main/java/com/crapi/controller/VehicleController.java"
        if not copied_controller.is_file() or sha256_bytes(copied_controller.read_bytes()) != sha256_bytes(original):
            raise RuntimeContractError("negative_build_context_source_mismatch")
        copied_controller.write_bytes(patched)
        build_contract = {
            "contract_label": NEGATIVE_CONTROL_LABEL,
            "base_source_image_id": source_image["source_image_id"],
            "source_commit": SOURCE_COMMIT,
            "source_tree_sha256": SOURCE_TREE_SHA256,
            "negative_control": negative_control,
            "raw_returned": False,
        }
        build_contract_sha256 = _canonical_sha256(build_contract)
        result = _docker(
            [
                "build",
                "--quiet",
                "--pull=false",
                "--network=default",
                "--label",
                f"kguard.execution.contract={NEGATIVE_CONTROL_LABEL}",
                "--label",
                f"kguard.execution.build-contract-sha256={build_contract_sha256}",
                "--label",
                f"kguard.execution.base-source-image-id={source_image['source_image_id']}",
                "--label",
                f"kguard.execution.negative-patch-sha256={negative_control['patch_sha256']}",
                "-t",
                image_ref,
                str(source_context),
            ],
            cwd=work_root,
            timeout=900,
        )
        _expect_success(result, "negative_image_build")
    image = _read_image(image_ref, work_root=work_root)
    labels = _labels(image)
    if (
        labels.get("kguard.execution.contract") != NEGATIVE_CONTROL_LABEL
        or labels.get("kguard.execution.build-contract-sha256") != build_contract_sha256
        or labels.get("kguard.execution.base-source-image-id") != source_image["source_image_id"]
        or labels.get("kguard.execution.negative-patch-sha256") != negative_control["patch_sha256"]
    ):
        raise RuntimeContractError("negative_image_label_mismatch")
    return (
        {
            "app_image_ref": image_ref,
            "app_image_id": _image_id(image),
            "app_image_contract_sha256": build_contract_sha256,
            "contract_label": NEGATIVE_CONTROL_LABEL,
            "source_derived": True,
            "build_network": "default",
            "fresh_dependency_rebuild_proven": False,
            "raw_returned": False,
        },
        negative_control,
    )


def _source_image_contract(source_image: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "app_image_ref": source_image["source_image_ref"],
        "app_image_id": source_image["source_image_id"],
        "app_image_contract_sha256": _canonical_sha256(
            {
                "contract_label": EXECUTION_CONTRACT_LABEL,
                "source_image_id": source_image["source_image_id"],
                "source_dockerfile_sha256": source_image["source_dockerfile_sha256"],
                "raw_returned": False,
            }
        ),
        "contract_label": EXECUTION_CONTRACT_LABEL,
        "source_derived": True,
        "build_network": "prior_source_build",
        "fresh_dependency_rebuild_proven": False,
        "raw_returned": False,
    }


def _container_id(result: CommandResult, label: str) -> str:
    _expect_success(result, label)
    value = result.stdout.decode("ascii", errors="strict").strip()
    if not re.fullmatch(r"[0-9a-f]{12,64}", value):
        raise RuntimeContractError(f"{label}_id_invalid")
    return value


def _inspect_container(container_id: str, *, work_root: Path) -> Mapping[str, Any]:
    result = _docker(["inspect", container_id], cwd=work_root, timeout=60)
    value = _load_json_stdout(result, "container_inspect")
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], Mapping):
        raise RuntimeContractError("container_inspect_shape_invalid")
    return value[0]


def _tmpfs_satisfies(actual: object, expected: Mapping[str, str]) -> bool:
    if not isinstance(actual, Mapping):
        return False
    return all(actual.get(path) == options for path, options in expected.items())


def _container_isolation(
    inspect: Mapping[str, Any],
    *,
    expected_user: str,
    expected_tmpfs: Mapping[str, str],
    expected_memory: int,
    expected_nano_cpus: int,
    expected_pids_limit: int,
    expected_network: str,
) -> dict[str, Any]:
    host_config = inspect.get("HostConfig")
    config = inspect.get("Config")
    network_settings = inspect.get("NetworkSettings")
    mounts = inspect.get("Mounts")
    if not all(isinstance(value, Mapping) for value in (host_config, config, network_settings)):
        raise RuntimeContractError("container_isolation_shape_invalid")
    cap_drop = host_config.get("CapDrop")
    security_opt = host_config.get("SecurityOpt")
    networks = network_settings.get("Networks")
    host_port_bindings = host_config.get("PortBindings")
    # Docker reports a container-only exposed port as e.g. {"5432/tcp": null}
    # in NetworkSettings.Ports. HostConfig.PortBindings is the authoritative
    # host publication signal, so reject only a real host-side binding.
    no_host_ports = host_port_bindings in (None, {})
    no_mounts = host_config.get("Binds") in (None, []) and mounts == []
    network_attached = (
        isinstance(networks, Mapping)
        and set(networks) == {expected_network}
        and host_config.get("NetworkMode") == expected_network
    )
    security_values = {str(value) for value in security_opt or []}
    caps = {str(value).upper() for value in cap_drop or []}
    result = {
        "read_only_root": host_config.get("ReadonlyRootfs") is True,
        "non_root_user": config.get("User") == expected_user,
        "cap_drop_all": "ALL" in caps,
        "no_new_privileges": any("no-new-privileges" in value for value in security_values),
        "tmpfs_exact": _tmpfs_satisfies(host_config.get("Tmpfs"), expected_tmpfs),
        "memory_limited": host_config.get("Memory") == expected_memory,
        "cpu_limited": host_config.get("NanoCpus") == expected_nano_cpus,
        "pids_limited": host_config.get("PidsLimit") == expected_pids_limit,
        "no_host_ports": no_host_ports,
        "no_bind_or_volume_mount": no_mounts,
        "internal_network_only": network_attached,
        "privileged_false": host_config.get("Privileged") is False,
        "raw_returned": False,
    }
    result["passed"] = all(value for key, value in result.items() if key not in {"raw_returned", "passed"})
    return result


def _create_network(*, work_root: Path) -> tuple[str, dict[str, Any]]:
    name = f"kguard-crapi-bola-{secrets.token_hex(10)}"
    result = _docker(
        [
            "network",
            "create",
            "--internal",
            "--label",
            f"kguard.execution.contract={EXECUTION_CONTRACT_LABEL}",
            name,
        ],
        cwd=work_root,
        timeout=60,
    )
    network_id = _container_id(result, "network_create")
    try:
        inspect = _load_json_stdout(
            _docker(["network", "inspect", network_id], cwd=work_root, timeout=60),
            "network_inspect",
        )
        if not isinstance(inspect, list) or len(inspect) != 1 or not isinstance(inspect[0], Mapping):
            raise RuntimeContractError("network_inspect_shape_invalid")
        if inspect[0].get("Internal") is not True or inspect[0].get("Containers") not in ({}, None):
            raise RuntimeContractError("network_isolation_invalid")
        return name, {
            "internal": True,
            "driver": inspect[0].get("Driver") == "bridge",
            "empty_before_run": True,
            "raw_returned": False,
        }
    except Exception:
        try:
            _cleanup_network(name, work_root=work_root)
        except Exception as cleanup_error:
            raise RuntimeContractError("network_create_cleanup_failed") from cleanup_error
        raise


def _cleanup_container(container_id: str | None, *, work_root: Path, label: str) -> dict[str, Any]:
    if container_id is None:
        return {"attempted": False, "removed": True, "raw_returned": False}
    result = _docker(["rm", "-f", container_id], cwd=work_root, timeout=60)
    _expect_success(result, f"{label}_cleanup")
    return {
        "attempted": True,
        "removed": True,
        "receipt": _command_receipt(result),
        "raw_returned": False,
    }


def _cleanup_network(name: str | None, *, work_root: Path) -> dict[str, Any]:
    if name is None:
        return {"attempted": False, "removed": True, "raw_returned": False}
    result = _docker(["network", "rm", name], cwd=work_root, timeout=60)
    _expect_success(result, "network_cleanup")
    return {
        "attempted": True,
        "removed": True,
        "receipt": _command_receipt(result),
        "raw_returned": False,
    }


def _postgres_environment() -> tuple[str, dict[str, str]]:
    secret = secrets.token_hex(24)
    return secret, {
        "POSTGRES_DB": "crapi",
        "POSTGRES_USER": "admin",
        "POSTGRES_PASSWORD": secret,
    }


def _app_environment(database_secret: str) -> dict[str, str]:
    return {
        "DB_NAME": "crapi",
        "DB_USER": "admin",
        "DB_PASSWORD": database_secret,
        "DB_HOST": "postgresdb",
        "DB_PORT": "5432",
        "SERVER_PORT": "8080",
        "TLS_ENABLED": "false",
        "TLS_KEYSTORE_TYPE": "PKCS12",
        "TLS_KEYSTORE": "classpath:certs/server.p12",
        "TLS_KEYSTORE_PASSWORD": "placeholder",
        "TLS_KEY_PASSWORD": "placeholder",
        "TLS_KEY_ALIAS": "identity",
        "SMTP_FROM": "noreply@example.test",
        "SMTP_AUTH": "false",
        "SMTP_HOST": "mailhog",
        "SMTP_PORT": "1025",
        "SMTP_EMAIL": "identity@example.test",
        "SMTP_PASS": secrets.token_hex(24),
        "SMTP_STARTTLS": "false",
        "MAILHOG_HOST": "mailhog",
        "MAILHOG_PORT": "1025",
        "MAILHOG_DOMAIN": "example.test",
        "ENABLE_SHELL_INJECTION": "false",
        "API_GATEWAY_URL": "http://gateway.invalid",
        "JWT_EXPIRATION": "604800000",
        "LOG_LEVEL": "WARN",
    }


def _environment_arguments(values: Mapping[str, str]) -> list[str]:
    arguments: list[str] = []
    for key, value in sorted(values.items()):
        if not re.fullmatch(r"[A-Z0-9_]+", key) or not value or "\x00" in value:
            raise RuntimeContractError("runtime_environment_invalid")
        arguments.extend(["-e", f"{key}={value}"])
    return arguments


def _create_postgres_container(
    *, network: str, work_root: Path
) -> tuple[str, dict[str, Any], str]:
    name = f"kguard-crapi-postgres-{secrets.token_hex(10)}"
    secret, environment = _postgres_environment()
    arguments = [
        "run",
        "-d",
        "--pull=never",
        "--name",
        name,
        "--network",
        network,
        "--network-alias",
        "postgresdb",
        "--read-only",
        "--user",
        POSTGRES_USER,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(POSTGRES_PIDS_LIMIT),
        "--memory",
        str(POSTGRES_MEMORY_BYTES),
        "--cpus",
        "1",
    ]
    for path, options in POSTGRES_TMPFS.items():
        arguments.extend(["--tmpfs", f"{path}:{options}"])
    arguments.extend(_environment_arguments(environment))
    arguments.append(POSTGRES_IMAGE_REF)
    container_id: str | None = None
    try:
        container_id = _container_id(
            _docker(arguments, cwd=work_root, timeout=120), "postgres_create"
        )
        inspect = _inspect_container(container_id, work_root=work_root)
        isolation = _container_isolation(
            inspect,
            expected_user=POSTGRES_USER,
            expected_tmpfs=POSTGRES_TMPFS,
            expected_memory=POSTGRES_MEMORY_BYTES,
            expected_nano_cpus=POSTGRES_NANO_CPUS,
            expected_pids_limit=POSTGRES_PIDS_LIMIT,
            expected_network=network,
        )
        if not isolation["passed"]:
            raise RuntimeContractError("postgres_isolation_invalid")
        # The database password is generated once and stays in process memory only. It
        # It is passed directly to the paired identity container, never recovered from
        # an inspect response or written into the evidence receipt.
        return container_id, isolation, secret
    except Exception:
        if container_id is not None:
            try:
                _cleanup_container(container_id, work_root=work_root, label="postgres_create")
            except Exception as cleanup_error:
                raise RuntimeContractError("postgres_create_cleanup_failed") from cleanup_error
        raise


def _create_app_container(
    app_image: Mapping[str, Any],
    *,
    network: str,
    database_secret: str,
    work_root: Path,
) -> tuple[str, dict[str, Any]]:
    name = f"kguard-crapi-identity-{secrets.token_hex(10)}"
    arguments = [
        "run",
        "-d",
        "--pull=never",
        "--name",
        name,
        "--network",
        network,
        "--network-alias",
        "identity",
        "--read-only",
        "--user",
        APP_USER,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(APP_PIDS_LIMIT),
        "--memory",
        str(APP_MEMORY_BYTES),
        "--cpus",
        "1",
    ]
    for path, options in APP_TMPFS.items():
        arguments.extend(["--tmpfs", f"{path}:{options}"])
    arguments.extend(_environment_arguments(_app_environment(database_secret)))
    arguments.append(str(app_image["app_image_ref"]))
    container_id: str | None = None
    try:
        container_id = _container_id(_docker(arguments, cwd=work_root, timeout=120), "app_create")
        inspect = _inspect_container(container_id, work_root=work_root)
        isolation = _container_isolation(
            inspect,
            expected_user=APP_USER,
            expected_tmpfs=APP_TMPFS,
            expected_memory=APP_MEMORY_BYTES,
            expected_nano_cpus=APP_NANO_CPUS,
            expected_pids_limit=APP_PIDS_LIMIT,
            expected_network=network,
        )
        if not isolation["passed"]:
            raise RuntimeContractError("app_isolation_invalid")
        return container_id, isolation
    except Exception:
        if container_id is not None:
            try:
                _cleanup_container(container_id, work_root=work_root, label="app_create")
            except Exception as cleanup_error:
                raise RuntimeContractError("app_create_cleanup_failed") from cleanup_error
        raise


def _wait_for_postgres(container_id: str, *, work_root: Path, timeout: int) -> dict[str, Any]:
    deadline = time.monotonic() + min(timeout, 90)
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        inspect = _inspect_container(container_id, work_root=work_root)
        state = inspect.get("State")
        if not isinstance(state, Mapping) or state.get("Running") is not True:
            raise RuntimeContractError("postgres_exited_before_ready")
        result = _docker(
            ["exec", container_id, "pg_isready", "-U", "admin", "-d", "crapi"],
            cwd=work_root,
            timeout=15,
        )
        if result.returncode == 0 and not result.timed_out and not result.output_truncated:
            return {"ready": True, "attempts": attempts, "raw_returned": False}
        time.sleep(0.5)
    raise RuntimeContractError("postgres_not_ready")


def _wait_for_application(container_id: str, *, work_root: Path, timeout: int) -> dict[str, Any]:
    deadline = time.monotonic() + min(timeout, 180)
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        inspect = _inspect_container(container_id, work_root=work_root)
        state = inspect.get("State")
        if not isinstance(state, Mapping) or state.get("Running") is not True:
            raise RuntimeContractError("application_exited_before_ready")
        result = _docker(
            [
                "exec",
                container_id,
                "sh",
                "-c",
                "curl -fsS http://127.0.0.1:8080/identity/health_check >/dev/null",
            ],
            cwd=work_root,
            timeout=15,
        )
        if result.returncode == 0 and not result.timed_out and not result.output_truncated:
            return {"ready": True, "attempts": attempts, "raw_returned": False}
        time.sleep(0.5)
    raise RuntimeContractError("application_not_ready")


def _create_driver_container(
    driver_image: Mapping[str, Any],
    *,
    network: str,
    mode: str,
    expected_status: int,
    work_root: Path,
) -> tuple[str, dict[str, Any]]:
    if (mode, expected_status) not in {("positive", 200), ("negative", 403)}:
        raise RuntimeContractError("driver_mode_invalid")
    name = f"kguard-crapi-driver-{secrets.token_hex(10)}"
    arguments = [
        "create",
        "--name",
        name,
        "--network",
        network,
        "--read-only",
        "--user",
        APP_USER,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(DRIVER_PIDS_LIMIT),
        "--memory",
        str(DRIVER_MEMORY_BYTES),
        "--cpus",
        "0.5",
    ]
    for path, options in DRIVER_TMPFS.items():
        arguments.extend(["--tmpfs", f"{path}:{options}"])
    arguments.extend(["-e", f"KGUARD_MODE={mode}", "-e", f"KGUARD_EXPECTED_STATUS={expected_status}"])
    arguments.append(str(driver_image["driver_image_ref"]))
    container_id: str | None = None
    try:
        container_id = _container_id(
            _docker(arguments, cwd=work_root, timeout=120), "driver_create"
        )
        inspect = _inspect_container(container_id, work_root=work_root)
        isolation = _container_isolation(
            inspect,
            expected_user=APP_USER,
            expected_tmpfs=DRIVER_TMPFS,
            expected_memory=DRIVER_MEMORY_BYTES,
            expected_nano_cpus=DRIVER_NANO_CPUS,
            expected_pids_limit=DRIVER_PIDS_LIMIT,
            expected_network=network,
        )
        if not isolation["passed"]:
            raise RuntimeContractError("driver_isolation_invalid")
        return container_id, isolation
    except Exception:
        if container_id is not None:
            try:
                _cleanup_container(container_id, work_root=work_root, label="driver_create")
            except Exception as cleanup_error:
                raise RuntimeContractError("driver_create_cleanup_failed") from cleanup_error
        raise


def _parse_driver_result(output: bytes, *, mode: str, expected_status: int) -> dict[str, Any]:
    if len(output) > MAX_DRIVER_OUTPUT_BYTES:
        raise RuntimeContractError("driver_output_exceeded_budget")
    try:
        text = output.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeContractError("driver_output_not_utf8") from exc
    marker = "K_GUARD_CRAPI_VEHICLE_BOLA_RESULT:"
    lines = [line for line in text.splitlines() if line]
    if len(lines) != 1 or not lines[0].startswith(marker):
        raise RuntimeContractError("driver_marker_invalid")
    try:
        value = json.loads(lines[0][len(marker) :])
    except json.JSONDecodeError as exc:
        raise RuntimeContractError("driver_result_not_json") from exc
    expected_fields = {
        "schema",
        "mode",
        "expected_status",
        "observed_status",
        "token_present",
        "actor_target_distinct",
        "response_object_observed",
        "target_field_shape_observed",
        "target_location_field_observed",
        "target_full_name_field_observed",
        "target_email_field_observed",
        "target_response_absent",
        "driver_error_code",
        "passed",
        "raw_returned",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise RuntimeContractError("driver_result_shape_invalid")
    if (
        value.get("schema") != DRIVER_RESULT_SCHEMA
        or value.get("mode") != mode
        or value.get("expected_status") != expected_status
        or value.get("raw_returned") is not False
        or value.get("passed") is not True
        or value.get("driver_error_code") is not None
        or value.get("observed_status") != expected_status
        or value.get("token_present") is not True
        or value.get("actor_target_distinct") is not True
    ):
        raise RuntimeContractError("driver_result_contract_invalid")
    if mode == "positive":
        required_true = {
            "response_object_observed",
            "target_field_shape_observed",
            "target_location_field_observed",
            "target_full_name_field_observed",
            "target_email_field_observed",
        }
        if any(value.get(field) is not True for field in required_true) or value.get(
            "target_response_absent"
        ) is not False:
            raise RuntimeContractError("driver_positive_observation_invalid")
    else:
        required_false = {
            "target_field_shape_observed",
            "target_location_field_observed",
            "target_full_name_field_observed",
            "target_email_field_observed",
        }
        if not isinstance(value.get("response_object_observed"), bool):
            raise RuntimeContractError("driver_negative_response_object_invalid")
        if any(value.get(field) is not False for field in required_false) or value.get(
            "target_response_absent"
        ) is not True:
            raise RuntimeContractError("driver_negative_observation_invalid")
    return value


def _parse_driver_failure_code(output: bytes, *, mode: str, expected_status: int) -> str:
    """Extract one allowlisted, raw-free driver failure class from terminal output."""
    if len(output) > MAX_DRIVER_OUTPUT_BYTES:
        raise RuntimeContractError("driver_output_exceeded_budget")
    try:
        text = output.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeContractError("driver_output_not_utf8") from exc
    marker = "K_GUARD_CRAPI_VEHICLE_BOLA_RESULT:"
    lines = [line for line in text.splitlines() if line]
    if len(lines) != 1 or not lines[0].startswith(marker):
        raise RuntimeContractError("driver_failure_marker_invalid")
    try:
        value = json.loads(lines[0][len(marker) :])
    except json.JSONDecodeError as exc:
        raise RuntimeContractError("driver_failure_not_json") from exc
    if not isinstance(value, Mapping):
        raise RuntimeContractError("driver_failure_shape_invalid")
    if (
        value.get("schema") != DRIVER_RESULT_SCHEMA
        or value.get("mode") != mode
        or value.get("expected_status") != expected_status
        or value.get("raw_returned") is not False
        or value.get("passed") is not False
    ):
        raise RuntimeContractError("driver_failure_contract_invalid")
    code = value.get("driver_error_code")
    if code is not None:
        if not isinstance(code, str) or re.fullmatch(r"[a-z0-9_]{1,80}", code) is None:
            raise RuntimeContractError("driver_failure_code_invalid")
        return code
    observed_status = value.get("observed_status")
    if (
        isinstance(observed_status, int)
        and 100 <= observed_status <= 599
        and observed_status != expected_status
    ):
        return f"unexpected_status_{observed_status}"
    if observed_status == expected_status:
        observed_status = None
    if observed_status is not None:
        raise RuntimeContractError("driver_failure_status_invalid")
    if value.get("token_present") is not True:
        return "unexpected_token_absent"
    if value.get("actor_target_distinct") is not True:
        return "unexpected_identity_boundary"
    if any(
        value.get(field) is True
        for field in (
            "response_object_observed",
            "target_field_shape_observed",
            "target_location_field_observed",
            "target_full_name_field_observed",
            "target_email_field_observed",
        )
    ):
        return "unexpected_target_response_shape"
    if value.get("target_response_absent") is not True:
        return "unexpected_response_absence"
    return "unexpected_outcome"


def _app_logs_sha256(container_id: str, *, work_root: Path) -> str:
    result = _docker(["logs", container_id], cwd=work_root, timeout=60)
    _expect_success(result, "application_logs")
    return sha256_bytes(result.stdout + b"\n--stderr--\n" + result.stderr)


def _claim_boundary(*, negative: bool) -> dict[str, bool]:
    return {
        "source_bound_execution_oracle_only": True,
        "authenticated_cross_owner_vehicle_location_only": True,
        "source_mutated_negative_control_only": negative,
        "scanner_accuracy_proven": False,
        "severity_or_cwe_admitted": False,
        "tp_fp_fn_admitted": False,
        "korean_personal_data_accuracy_proven": False,
        "warning_or_block_admitted": False,
        "guardian_or_h100_admitted": False,
        "release_gate_admitted": False,
    }


def _tool_provenance(
    *,
    source_verifier_provenance: str,
    driver_image: Mapping[str, Any],
    postgres_image: Mapping[str, Any],
) -> dict[str, Any]:
    runner_sha256 = sha256_bytes(Path(__file__).read_bytes())
    return {
        "runner_sha256": runner_sha256,
        "source_verifier_provenance": source_verifier_provenance,
        "driver_sha256": driver_image["driver_sha256"],
        "driver_image_id": driver_image["driver_image_id"],
        "postgres_image_id": postgres_image["image_id"],
        "raw_returned": False,
    }


def _assert_raw_free(value: object) -> None:
    if isinstance(value, Mapping):
        if value.get("raw_returned") is not None and value.get("raw_returned") is not False:
            raise RuntimeContractError("raw_free_boundary_invalid")
        for nested in value.values():
            _assert_raw_free(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_raw_free(nested)


def _validate_hash(value: object, label: str) -> None:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise RuntimeContractError(f"{label}_invalid")


def _validate_image_id(value: object, label: str) -> None:
    if not isinstance(value, str) or not IMAGE_ID_RE.fullmatch(value):
        raise RuntimeContractError(f"{label}_invalid")


def _write_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    _require_external_new_file(path, "output")
    path.write_bytes(canonical_json_bytes(dict(receipt)))


def _failure_receipt(*, negative: bool, code: str) -> dict[str, Any]:
    safe_code = re.sub(r"[^a-z0-9_]", "_", code.lower())[:100] or "unknown"
    return {
        "schema": NEGATIVE_CONTROL_SCHEMA if negative else SCHEMA,
        "status": "HOLD",
        "failure_code": safe_code,
        "release_gate_passed": False,
        "raw_returned": False,
    }


def _load_canonical_positive_receipt(path: Path) -> tuple[dict[str, Any], str]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeContractError("positive_receipt_invalid")
    raw = path.read_bytes()
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError("positive_receipt_not_json") from exc
    if not isinstance(receipt, dict) or canonical_json_bytes(receipt) != raw:
        raise RuntimeContractError("positive_receipt_not_canonical")
    validate_receipt(receipt)
    return receipt, sha256_bytes(raw)


def _validate_source(value: object) -> None:
    if not isinstance(value, Mapping):
        raise RuntimeContractError("receipt_source_invalid")
    required = {
        "repository_id",
        "commit",
        "commit_tree",
        "source_tree_sha256",
        "p23a_registry_sha256",
        "p23a_app_receipt_sha256",
        "p23a_app_receipt_semantic_sha256",
        "current_source_receipt_sha256",
        "current_source_receipt_semantic_sha256",
        "file_count",
        "total_bytes",
        "source_file_sha256",
        "raw_returned",
    }
    if set(value) != required or value.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_source_shape_invalid")
    if (
        value.get("repository_id") != REPOSITORY_ID
        or value.get("commit") != SOURCE_COMMIT
        or value.get("commit_tree") != SOURCE_TREE
        or value.get("source_tree_sha256") != SOURCE_TREE_SHA256
        or value.get("p23a_app_receipt_sha256") != P23A_APP_RECEIPT_SHA256
        or value.get("p23a_app_receipt_semantic_sha256") != P23A_APP_SEMANTIC_SHA256
    ):
        raise RuntimeContractError("receipt_source_identity_invalid")
    for field in (
        "p23a_registry_sha256",
        "current_source_receipt_sha256",
        "current_source_receipt_semantic_sha256",
    ):
        _validate_hash(value.get(field), f"receipt_source_{field}")
    files = value.get("source_file_sha256")
    if not isinstance(files, Mapping) or set(files) != set(SOURCE_FILES):
        raise RuntimeContractError("receipt_source_files_invalid")
    if any(files.get(path) != expected for path, expected in SOURCE_FILES.items()):
        raise RuntimeContractError("receipt_source_file_hash_invalid")


def _validate_base_image(value: object) -> None:
    if not isinstance(value, Mapping):
        raise RuntimeContractError("receipt_base_image_invalid")
    required = {
        "source_image_ref",
        "source_image_id",
        "source_image_labels",
        "source_dockerfile_sha256",
        "source_image_current_source_provenance_only",
        "fresh_dependency_rebuild_proven",
        "runtime_supply_chain_proven",
        "raw_returned",
    }
    if set(value) != required or value.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_base_image_shape_invalid")
    if (
        value.get("source_image_ref") != SOURCE_IMAGE_REF
        or value.get("source_image_id") != SOURCE_IMAGE_ID
        or value.get("source_image_labels") != EXPECTED_SOURCE_IMAGE_LABELS
        or value.get("source_dockerfile_sha256") != SOURCE_DOCKERFILE_SHA256
        or value.get("source_image_current_source_provenance_only") is not True
        or value.get("fresh_dependency_rebuild_proven") is not False
        or value.get("runtime_supply_chain_proven") is not False
    ):
        raise RuntimeContractError("receipt_base_image_contract_invalid")


def _validate_driver_image(value: object) -> None:
    if not isinstance(value, Mapping):
        raise RuntimeContractError("receipt_driver_image_invalid")
    required = {
        "driver_image_ref",
        "driver_image_id",
        "driver_sha256",
        "dockerfile_sha256",
        "driver_base_image",
        "raw_returned",
    }
    if set(value) != required or value.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_driver_image_shape_invalid")
    _validate_image_id(value.get("driver_image_id"), "receipt_driver_image_id")
    _validate_hash(value.get("driver_sha256"), "receipt_driver_sha256")
    _validate_hash(value.get("dockerfile_sha256"), "receipt_driver_dockerfile_sha256")
    base = value.get("driver_base_image")
    if not isinstance(base, Mapping) or set(base) != {"reference", "image_id", "raw_returned"}:
        raise RuntimeContractError("receipt_driver_base_image_invalid")
    if base.get("reference") != PYTHON_DRIVER_IMAGE_REF or base.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_driver_base_image_contract_invalid")
    _validate_image_id(base.get("image_id"), "receipt_driver_base_image_id")


def _validate_run(value: object, *, negative: bool) -> None:
    if not isinstance(value, Mapping):
        raise RuntimeContractError("receipt_run_invalid")
    required = {
        "mode",
        "expected_status",
        "driver_sha256",
        "network_policy",
        "postgres_image",
        "app_image_id",
        "app_image_contract_sha256",
        "network",
        "isolation",
        "postgres_ready",
        "application_ready",
        "application_logs_sha256",
        "normalized_result",
        "passed",
        "cleanup",
        "raw_returned",
    }
    if set(value) != required or value.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_run_shape_invalid")
    expected_mode = "negative" if negative else "positive"
    expected_status = 403 if negative else 200
    if (
        value.get("mode") != expected_mode
        or value.get("expected_status") != expected_status
        or value.get("network_policy") != NETWORK_POLICY
        or value.get("passed") is not True
    ):
        raise RuntimeContractError("receipt_run_contract_invalid")
    _validate_hash(value.get("driver_sha256"), "receipt_run_driver_sha256")
    _validate_image_id(value.get("app_image_id"), "receipt_run_app_image_id")
    _validate_hash(value.get("app_image_contract_sha256"), "receipt_run_app_contract")
    _validate_hash(value.get("application_logs_sha256"), "receipt_run_logs")
    runtime_image = value.get("postgres_image")
    if not isinstance(runtime_image, Mapping) or runtime_image.get("reference") != POSTGRES_IMAGE_REF:
        raise RuntimeContractError("receipt_run_postgres_image_invalid")
    _validate_image_id(runtime_image.get("image_id"), "receipt_run_postgres_image_id")
    network = value.get("network")
    if not isinstance(network, Mapping) or network.get("internal") is not True or network.get(
        "driver"
    ) is not True:
        raise RuntimeContractError("receipt_run_network_invalid")
    isolation = value.get("isolation")
    if not isinstance(isolation, Mapping) or set(isolation) != {
        "postgres",
        "application",
        "driver",
        "all_passed",
        "raw_returned",
    }:
        raise RuntimeContractError("receipt_run_isolation_invalid")
    if (
        isolation.get("all_passed") is not True
        or isolation.get("raw_returned") is not False
        or not all(
            isinstance(isolation.get(name), Mapping) and isolation[name].get("passed") is True
            for name in ("postgres", "application", "driver")
        )
    ):
        raise RuntimeContractError("receipt_run_isolation_contract_invalid")
    for field in ("postgres_ready", "application_ready"):
        if not isinstance(value.get(field), Mapping) or value[field].get("ready") is not True:
            raise RuntimeContractError("receipt_run_readiness_invalid")
    result = value.get("normalized_result")
    if not isinstance(result, Mapping) or result.get("mode") != expected_mode or result.get(
        "expected_status"
    ) != expected_status or result.get("passed") is not True or result.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_run_result_invalid")
    cleanup = value.get("cleanup")
    if not isinstance(cleanup, Mapping) or cleanup.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_run_cleanup_invalid")
    if not all(
        isinstance(cleanup.get(name), Mapping) and cleanup[name].get("removed") is True
        for name in ("driver", "application", "postgres", "network")
    ):
        raise RuntimeContractError("receipt_run_cleanup_contract_invalid")


def _validate_tool(value: object) -> None:
    if not isinstance(value, Mapping):
        raise RuntimeContractError("receipt_tool_invalid")
    required = {
        "runner_sha256",
        "source_verifier_provenance",
        "driver_sha256",
        "driver_image_id",
        "postgres_image_id",
        "raw_returned",
    }
    if set(value) != required or value.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_tool_shape_invalid")
    for field in ("runner_sha256", "driver_sha256"):
        _validate_hash(value.get(field), f"receipt_tool_{field}")
    if not isinstance(value.get("source_verifier_provenance"), str) or ":" not in value.get(
        "source_verifier_provenance"
    ):
        raise RuntimeContractError("receipt_tool_verifier_invalid")
    _validate_image_id(value.get("driver_image_id"), "receipt_tool_driver_image")
    _validate_image_id(value.get("postgres_image_id"), "receipt_tool_postgres_image")


def validate_receipt(receipt: dict[str, Any]) -> None:
    required = {
        "schema",
        "source",
        "base_image",
        "driver_image",
        "image_contract",
        "runs",
        "execution_contract_status",
        "admission_blockers",
        "claim_boundary",
        "tool_provenance",
        "release_gate_passed",
        "raw_returned",
    }
    if set(receipt) != required or receipt.get("schema") != SCHEMA:
        raise RuntimeContractError("positive_receipt_shape_invalid")
    if (
        receipt.get("execution_contract_status") != "EXECUTION_CONTRACT_PASS"
        or receipt.get("release_gate_passed") is not False
        or receipt.get("raw_returned") is not False
        or tuple(receipt.get("admission_blockers", ())) != ADMISSION_BLOCKERS
    ):
        raise RuntimeContractError("positive_receipt_claim_invalid")
    _validate_source(receipt.get("source"))
    _validate_base_image(receipt.get("base_image"))
    _validate_driver_image(receipt.get("driver_image"))
    image = receipt.get("image_contract")
    if not isinstance(image, Mapping) or image.get("contract_label") != EXECUTION_CONTRACT_LABEL:
        raise RuntimeContractError("positive_image_contract_invalid")
    if image.get("app_image_id") != SOURCE_IMAGE_ID or image.get("source_derived") is not True:
        raise RuntimeContractError("positive_image_identity_invalid")
    runs = receipt.get("runs")
    if not isinstance(runs, list) or len(runs) != 2:
        raise RuntimeContractError("positive_runs_invalid")
    for run in runs:
        _validate_run(run, negative=False)
    if _normalized_run(runs[0]) != _normalized_run(runs[1]):
        raise RuntimeContractError("positive_internal_repeat_mismatch")
    _validate_tool(receipt.get("tool_provenance"))
    if receipt.get("claim_boundary") != _claim_boundary(negative=False):
        raise RuntimeContractError("positive_claim_boundary_invalid")
    _assert_raw_free(receipt)


def validate_negative_control_receipt(receipt: dict[str, Any]) -> None:
    required = {
        "schema",
        "source",
        "base_image",
        "driver_image",
        "image_contract",
        "negative_control",
        "positive_execution_receipt_sha256",
        "runs",
        "negative_control_status",
        "admission_blockers",
        "claim_boundary",
        "tool_provenance",
        "release_gate_passed",
        "raw_returned",
    }
    if set(receipt) != required or receipt.get("schema") != NEGATIVE_CONTROL_SCHEMA:
        raise RuntimeContractError("negative_receipt_shape_invalid")
    if (
        receipt.get("negative_control_status") != "NEGATIVE_CONTROL_PASS"
        or receipt.get("release_gate_passed") is not False
        or receipt.get("raw_returned") is not False
        or tuple(receipt.get("admission_blockers", ())) != ADMISSION_BLOCKERS
    ):
        raise RuntimeContractError("negative_receipt_claim_invalid")
    _validate_source(receipt.get("source"))
    _validate_base_image(receipt.get("base_image"))
    _validate_driver_image(receipt.get("driver_image"))
    image = receipt.get("image_contract")
    if (
        not isinstance(image, Mapping)
        or image.get("contract_label") != NEGATIVE_CONTROL_LABEL
        or image.get("source_derived") is not True
        or image.get("build_network") != "default"
    ):
        raise RuntimeContractError("negative_image_contract_invalid")
    control = receipt.get("negative_control")
    required_control = {
        "patch_id",
        "source_path",
        "original_file_sha256",
        "patched_file_sha256",
        "patch_sha256",
        "marker_count",
        "replacement_count",
        "source_checkout_mutated",
        "raw_returned",
    }
    if (
        not isinstance(control, Mapping)
        or set(control) != required_control
        or control.get("patch_id") != NEGATIVE_CONTROL_PATCH_ID
        or control.get("source_path") != CONTROLLER_PATH
        or control.get("original_file_sha256") != SOURCE_FILES[CONTROLLER_PATH]
        or control.get("marker_count") != 1
        or control.get("replacement_count") != 1
        or control.get("source_checkout_mutated") is not False
        or control.get("raw_returned") is not False
    ):
        raise RuntimeContractError("negative_control_invalid")
    for field in ("patched_file_sha256", "patch_sha256"):
        _validate_hash(control.get(field), f"negative_control_{field}")
    _validate_hash(
        receipt.get("positive_execution_receipt_sha256"),
        "negative_positive_execution_receipt",
    )
    runs = receipt.get("runs")
    if not isinstance(runs, list) or len(runs) != 2:
        raise RuntimeContractError("negative_runs_invalid")
    for run in runs:
        _validate_run(run, negative=True)
    if _normalized_run(runs[0]) != _normalized_run(runs[1]):
        raise RuntimeContractError("negative_internal_repeat_mismatch")
    _validate_tool(receipt.get("tool_provenance"))
    if receipt.get("claim_boundary") != _claim_boundary(negative=True):
        raise RuntimeContractError("negative_claim_boundary_invalid")
    _assert_raw_free(receipt)


def _normalized_run(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "mode": value["mode"],
        "expected_status": value["expected_status"],
        "driver_sha256": value["driver_sha256"],
        "network_policy": value["network_policy"],
        "postgres_image": value["postgres_image"],
        "app_image_contract_sha256": value["app_image_contract_sha256"],
        "network": value["network"],
        "isolation": value["isolation"],
        "normalized_result": value["normalized_result"],
        "passed": value["passed"],
        "raw_returned": False,
    }


def _live_run_bound(
    app_image: Mapping[str, Any],
    driver_image: Mapping[str, Any],
    postgres_image: Mapping[str, Any],
    *,
    mode: str,
    expected_status: int,
    work_root: Path,
    timeout: int,
) -> dict[str, Any]:
    network: str | None = None
    postgres_id: str | None = None
    app_id: str | None = None
    driver_id: str | None = None
    result: dict[str, Any] | None = None
    try:
        network, network_receipt = _create_network(work_root=work_root)
        postgres_id, postgres_isolation, database_secret = _create_postgres_container(
            network=network, work_root=work_root
        )
        postgres_ready = _wait_for_postgres(postgres_id, work_root=work_root, timeout=timeout)
        app_id, app_isolation = _create_app_container(
            app_image,
            network=network,
            database_secret=database_secret,
            work_root=work_root,
        )
        application_ready = _wait_for_application(app_id, work_root=work_root, timeout=timeout)
        driver_id, driver_isolation = _create_driver_container(
            driver_image,
            network=network,
            mode=mode,
            expected_status=expected_status,
            work_root=work_root,
        )
        start = _docker(["start", "-a", driver_id], cwd=work_root, timeout=timeout)
        if start.timed_out:
            raise RuntimeContractError("driver_start_timed_out")
        if start.output_truncated:
            raise RuntimeContractError("driver_start_output_truncated")
        if start.returncode != 0:
            raise RuntimeContractError(
                f"driver_{_parse_driver_failure_code(start.stdout, mode=mode, expected_status=expected_status)}"
            )
        normalized_result = _parse_driver_result(
            start.stdout, mode=mode, expected_status=expected_status
        )
        driver_inspect = _inspect_container(driver_id, work_root=work_root)
        driver_state = driver_inspect.get("State")
        if not isinstance(driver_state, Mapping) or driver_state.get("ExitCode") != 0:
            raise RuntimeContractError("driver_exit_invalid")
        result = {
            "mode": mode,
            "expected_status": expected_status,
            "driver_sha256": driver_image["driver_sha256"],
            "network_policy": NETWORK_POLICY,
            "postgres_image": postgres_image,
            "app_image_id": app_image["app_image_id"],
            "app_image_contract_sha256": app_image["app_image_contract_sha256"],
            "network": network_receipt,
            "isolation": {
                "postgres": postgres_isolation,
                "application": app_isolation,
                "driver": driver_isolation,
                "all_passed": (
                    postgres_isolation["passed"]
                    and app_isolation["passed"]
                    and driver_isolation["passed"]
                ),
                "raw_returned": False,
            },
            "postgres_ready": postgres_ready,
            "application_ready": application_ready,
            "application_logs_sha256": _app_logs_sha256(app_id, work_root=work_root),
            "normalized_result": normalized_result,
            "passed": True,
            "cleanup": {},
            "raw_returned": False,
        }
    finally:
        cleanup = {
            "driver": _cleanup_container(driver_id, work_root=work_root, label="driver"),
            "application": _cleanup_container(app_id, work_root=work_root, label="application"),
            "postgres": _cleanup_container(postgres_id, work_root=work_root, label="postgres"),
            "network": _cleanup_network(network, work_root=work_root),
            "raw_returned": False,
        }
        if any(
            value.get("removed") is not True
            for name, value in cleanup.items()
            if name != "raw_returned" and isinstance(value, Mapping)
        ):
            raise RuntimeContractError("runtime_cleanup_invalid")
        if result is not None:
            result["cleanup"] = cleanup
    if result is None:
        raise RuntimeContractError("runtime_result_missing")
    return result


def _execute(
    source_root: Path,
    p23a_registry: Path,
    *,
    work_root: Path,
    timeout: int,
    negative: bool,
    positive_receipt: Path | None,
) -> dict[str, Any]:
    source, source_files, source_verifier_provenance = verify_source_workspace(
        source_root, p23a_registry
    )
    source_image = _validate_base_source_image(work_root=work_root)
    postgres_image = _runtime_image_projection(POSTGRES_IMAGE_REF, work_root=work_root)
    driver_image = _build_driver_image(work_root=work_root)
    app_image: dict[str, Any] | None = None
    negative_control: dict[str, Any] | None = None
    temporary_images: list[str] = [str(driver_image["driver_image_ref"])]
    try:
        if negative:
            if positive_receipt is None:
                raise RuntimeContractError("negative_positive_receipt_required")
            positive, positive_sha256 = _load_canonical_positive_receipt(positive_receipt)
            if positive.get("source") != source:
                raise RuntimeContractError("negative_positive_source_mismatch")
            app_image, negative_control = _build_negative_image(
                source_root,
                source_files,
                source_image=source_image,
                work_root=work_root,
            )
            temporary_images.append(str(app_image["app_image_ref"]))
            mode = "negative"
            expected_status = 403
        else:
            app_image = _source_image_contract(source_image)
            positive_sha256 = None
            mode = "positive"
            expected_status = 200
        runs = [
            _live_run_bound(
                app_image,
                driver_image,
                postgres_image,
                mode=mode,
                expected_status=expected_status,
                work_root=work_root,
                timeout=timeout,
            )
            for _ in range(2)
        ]
        if _normalized_run(runs[0]) != _normalized_run(runs[1]):
            raise RuntimeContractError("internal_execution_repeat_mismatch")
        if _read_source_files(_require_external_existing_directory(source_root, "source_root")) != source_files:
            raise RuntimeContractError("source_workspace_mutated")
        tool = _tool_provenance(
            source_verifier_provenance=source_verifier_provenance,
            driver_image=driver_image,
            postgres_image=postgres_image,
        )
        if negative:
            if negative_control is None or positive_sha256 is None:
                raise RuntimeContractError("negative_internal_state_invalid")
            receipt = {
                "schema": NEGATIVE_CONTROL_SCHEMA,
                "source": source,
                "base_image": source_image,
                "driver_image": driver_image,
                "image_contract": app_image,
                "negative_control": negative_control,
                "positive_execution_receipt_sha256": positive_sha256,
                "runs": runs,
                "negative_control_status": "NEGATIVE_CONTROL_PASS",
                "admission_blockers": list(ADMISSION_BLOCKERS),
                "claim_boundary": _claim_boundary(negative=True),
                "tool_provenance": tool,
                "release_gate_passed": False,
                "raw_returned": False,
            }
            validate_negative_control_receipt(receipt)
        else:
            receipt = {
                "schema": SCHEMA,
                "source": source,
                "base_image": source_image,
                "driver_image": driver_image,
                "image_contract": app_image,
                "runs": runs,
                "execution_contract_status": "EXECUTION_CONTRACT_PASS",
                "admission_blockers": list(ADMISSION_BLOCKERS),
                "claim_boundary": _claim_boundary(negative=False),
                "tool_provenance": tool,
                "release_gate_passed": False,
                "raw_returned": False,
            }
            validate_receipt(receipt)
        return receipt
    finally:
        cleanup_errors: list[str] = []
        for reference in reversed(temporary_images):
            try:
                _cleanup_image(reference, work_root=work_root)
            except Exception as exc:
                cleanup_errors.append(type(exc).__name__)
        if cleanup_errors:
            raise RuntimeContractError("temporary_image_cleanup_failed")


def execute_contract(source_root: Path, p23a_registry: Path, *, timeout: int) -> dict[str, Any]:
    return _execute(
        source_root,
        p23a_registry,
        work_root=Path(tempfile.gettempdir()).resolve(strict=True),
        timeout=timeout,
        negative=False,
        positive_receipt=None,
    )


def execute_negative_control(
    source_root: Path,
    p23a_registry: Path,
    positive_receipt: Path,
    *,
    timeout: int,
) -> dict[str, Any]:
    return _execute(
        source_root,
        p23a_registry,
        work_root=Path(tempfile.gettempdir()).resolve(strict=True),
        timeout=timeout,
        negative=True,
        positive_receipt=positive_receipt,
    )


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replay the crAPI vehicle BOLA source-bound execution contract."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("positive", "negative"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--source-root", required=True, type=Path)
        subparser.add_argument("--p23a-registry", required=True, type=Path)
        subparser.add_argument("--output", required=True, type=Path)
        subparser.add_argument("--timeout", type=int, default=240)
        if command == "negative":
            subparser.add_argument("--positive-receipt", required=True, type=Path)
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.timeout < 60 or args.timeout > 900:
        parser.error("--timeout must be between 60 and 900 seconds")
    negative = args.command == "negative"
    output = _require_external_new_file(args.output, "output")
    try:
        if negative:
            receipt = execute_negative_control(
                args.source_root,
                args.p23a_registry,
                args.positive_receipt,
                timeout=args.timeout,
            )
        else:
            receipt = execute_contract(args.source_root, args.p23a_registry, timeout=args.timeout)
        _write_receipt(output, receipt)
        return 0
    except Exception as exc:
        failure_code = str(exc) if isinstance(exc, RuntimeContractError) else type(exc).__name__
        _write_receipt(output, _failure_receipt(negative=negative, code=failure_code))
        return 81


if __name__ == "__main__":
    raise SystemExit(main())
