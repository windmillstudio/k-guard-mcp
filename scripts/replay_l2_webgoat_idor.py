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
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable


SCHEMA = "k_guard_l2_webgoat_idor_execution_contract.v1"
RESULT_SCHEMA = "k_guard_l2_webgoat_idor_normalized_result.v1"
NEGATIVE_CONTROL_SCHEMA = "k_guard_l2_webgoat_idor_negative_control.v1"
NEGATIVE_CONTROL_RESULT_SCHEMA = "k_guard_l2_webgoat_idor_negative_control_result.v1"
APP_ID = "webgoat"
REPOSITORY_ID = "webgoat/webgoat"
SOURCE_COMMIT = "5142935bf7c279882c3b0fc0ecec42c447de6fd5"
SOURCE_TREE = "6c45e60db0995416a5bbe5977657a78d5084dcf7"
SOURCE_TREE_SHA256 = "0b2193e30038f4366715986e939645d7851e647c6188b992311639dd7564da3c"
BASE_IMAGE = "eclipse-temurin@sha256:201fbb8886b2d273218aa3a192f0afbf7b5ff65ee8cc6ef47f5dce2171f013ea"
TEST_CLASS = "org.owasp.webgoat.integration.IDORIntegrationTest"
EXPECTED_CASE_NAMES = ("testIDORLesson()[1]", "testIDORLesson()[2]")
SUCCESS_CASE_OUTCOMES = (("testIDORLesson()[1]", "pass"), ("testIDORLesson()[2]", "pass"))
NEGATIVE_CONTROL_CASE_OUTCOMES = (
    ("testIDORLesson", "failure"),
    ("testIDORLesson()[1]", "pass"),
    ("testIDORLesson()[2]", "failure"),
)
EXECUTION_CONTRACT_LABEL = "webgoat-idor-v1"
NEGATIVE_CONTROL_LABEL = "webgoat-idor-negative-control-v1"
NEGATIVE_CONTROL_SOURCE_PATH = Path(
    "src/main/java/org/owasp/webgoat/lessons/idor/IDOREditOtherProfile.java"
)
NEGATIVE_CONTROL_PATCH_ID = "reject-cross-profile-update.v2"
NEGATIVE_CONTROL_EXPECTED_EXIT_CODE = 1
# Historical P1.4B evidence keeps this reference. New P2.3B runs must instead
# bind a freshly verified positive receipt to the current execution toolchain.
POSITIVE_EXECUTION_RECEIPT_SHA256 = "f2afead44a548fd861c550acd2ee17dd52e3a3dae434f43bfc85f43ea74b0365"
RUN_AS = "65532:65532"
MEMORY_BYTES = 4 * 1024 * 1024 * 1024
NANO_CPUS = 2_000_000_000
PIDS_LIMIT = 512
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ADMISSION_BLOCKERS = tuple(
    sorted(
        {
            "source_bound_severity_rubric_missing",
            "negative_control_missing",
            "scanner_finding_mapping_missing",
            "evidence_signature_missing",
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

MAVEN_ARGUMENTS = (
    "/bin/sh ./mvnw -o -B -Dstyle.color=never -Pcleanall,start-server "
    "-Dtest=__kguard_no_unit__ -Dsurefire.failIfNoSpecifiedTests=false "
    f"-Dit.test={TEST_CLASS} verify"
)
RUNTIME_COMMAND = (
    "set +e; "
    f"{MAVEN_ARGUMENTS}; "
    "status=$?; "
    "if [ ! -d /workspace/target/failsafe-reports ]; then exit 97; fi; "
    "cp -R /workspace/target/failsafe-reports /evidence/ || exit 98; "
    "exit $status"
)
DOCKERFILE_TEMPLATE = f"""FROM {BASE_IMAGE}
WORKDIR /workspace
COPY source/ /workspace/
RUN groupadd --gid 65532 kguard && useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin kguard && mkdir -p /home/kguard/.m2 /evidence && chown -R 65532:65532 /workspace /home/kguard /evidence
USER 65532:65532
ENV HOME=/home/kguard
RUN /bin/sh ./mvnw -B -Dstyle.color=never -Pcleanall,start-server -Dtest=__kguard_no_unit__ -Dsurefire.failIfNoSpecifiedTests=false -Dit.test={TEST_CLASS} verify
LABEL io.k-guard.execution-contract={EXECUTION_CONTRACT_LABEL}
"""

NEGATIVE_CONTROL_DOCKERFILE_TEMPLATE = f"""FROM {BASE_IMAGE}
WORKDIR /workspace
COPY source/ /workspace/
RUN groupadd --gid 65532 kguard && useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin kguard && mkdir -p /home/kguard/.m2 /evidence && chown -R 65532:65532 /workspace /home/kguard /evidence
USER 65532:65532
ENV HOME=/home/kguard
RUN /bin/sh -lc 'set +e; /bin/sh ./mvnw -B -Dstyle.color=never -Pcleanall,start-server -Dtest=__kguard_no_unit__ -Dsurefire.failIfNoSpecifiedTests=false -Dit.test={TEST_CLASS} verify; status=$?; test -d /workspace/target/failsafe-reports || exit 97; exit 0'
LABEL io.k-guard.execution-contract={NEGATIVE_CONTROL_LABEL}
"""


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
    spec = importlib.util.spec_from_file_location("k_guard_l2_webgoat_source_verifier", path)
    if spec is None or spec.loader is None:
        raise RuntimeContractError("source_verifier_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if path.read_bytes() != raw_before:
        raise RuntimeContractError("source_verifier_changed_while_loading")
    return module, sha256_bytes(raw_before)


def _source_projection(receipt: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise RuntimeContractError(f"source_{key}_mismatch")
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
    receipt_sha256 = _canonical_sha256(receipt)
    return {
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
        "source_receipt_sha256": receipt_sha256,
        "file_count": receipt.get("file_count"),
        "total_bytes": receipt.get("total_bytes"),
        "raw_returned": False,
    }


def verify_source_workspace(source_root: Path) -> tuple[dict[str, Any], Any, str]:
    if not source_root.is_absolute() or not source_root.is_dir():
        raise RuntimeContractError("source_root_invalid")
    verifier, verifier_sha256 = _load_source_verifier()
    receipt = verifier.build_git_materialization_receipt(
        source_root,
        expected_repository_id=REPOSITORY_ID,
        expected_commit=SOURCE_COMMIT,
        expected_tree=SOURCE_TREE,
    )
    return _source_projection(receipt), verifier, verifier_sha256


def _copy_verified_source(source_root: Path, destination: Path, verifier: Any) -> None:
    shutil.copytree(source_root, destination, ignore=shutil.ignore_patterns(".git"), copy_function=shutil.copy2)
    copied = verifier.capture_materialized_tree(destination)
    if copied.get("tree_sha256") != SOURCE_TREE_SHA256:
        raise RuntimeContractError("copied_source_tree_mismatch")


def _source_line_ending(raw: bytes) -> bytes:
    return b"\r\n" if b"\r\n" in raw else b"\n"


def _apply_negative_control_patch(source_root: Path, verifier: Any) -> dict[str, Any]:
    target = source_root / NEGATIVE_CONTROL_SOURCE_PATH
    if not target.is_file():
        raise RuntimeContractError("negative_control_source_missing")
    original = target.read_bytes()
    line_ending = _source_line_ending(original)
    vulnerable_marker = line_ending.join(
        (
            b"    if (userSubmittedProfile.getUserId() != null",
            b"        && !userSubmittedProfile.getUserId().equals(authUserId)) {",
        )
    ) + line_ending
    vulnerable_replacement = line_ending.join(
        (
            b"    if (userSubmittedProfile.getUserId() != null",
            b"        && !userSubmittedProfile.getUserId().equals(authUserId)",
            b"        && Boolean.FALSE.booleanValue()) {",
        )
    ) + line_ending
    subsequent_marker = line_ending.join(
        (
            b"    } else if (userSubmittedProfile.getUserId() != null",
            b"        && userSubmittedProfile.getUserId().equals(authUserId)) {",
        )
    ) + line_ending
    subsequent_replacement = line_ending.join(
        (
            b"    } else if (userSubmittedProfile.getUserId() != null",
            b"        && !userSubmittedProfile.getUserId().equals(authUserId)) {",
            b"      return failed(this).feedback(\"idor.edit.profile.failure4\").build();",
            b"    } else if (userSubmittedProfile.getUserId() != null",
            b"        && userSubmittedProfile.getUserId().equals(authUserId)) {",
        )
    ) + line_ending
    if original.count(vulnerable_marker) != 1 or original.count(subsequent_marker) != 1:
        raise RuntimeContractError("negative_control_patch_anchor_invalid")
    patched = original.replace(vulnerable_marker, vulnerable_replacement, 1).replace(
        subsequent_marker, subsequent_replacement, 1
    )
    if patched == original:
        raise RuntimeContractError("negative_control_patch_not_applied")
    target.write_bytes(patched)
    variant = verifier.capture_materialized_tree(source_root)
    variant_tree_sha256 = variant.get("tree_sha256")
    if not isinstance(variant_tree_sha256, str) or SHA256_RE.fullmatch(variant_tree_sha256) is None:
        raise RuntimeContractError("negative_control_variant_tree_invalid")
    if variant_tree_sha256 == SOURCE_TREE_SHA256:
        raise RuntimeContractError("negative_control_variant_tree_unchanged")
    return {
        "patch_id": NEGATIVE_CONTROL_PATCH_ID,
        "source_path": NEGATIVE_CONTROL_SOURCE_PATH.as_posix(),
        "original_file_sha256": sha256_bytes(original),
        "patched_file_sha256": sha256_bytes(patched),
        "patch_sha256": sha256_bytes(vulnerable_replacement + b"\0" + subsequent_replacement),
        "variant_tree_sha256": variant_tree_sha256,
        "source_checkout_mutated": False,
        "raw_returned": False,
    }


def _dockerfile_sha256(template: str = DOCKERFILE_TEMPLATE) -> str:
    return sha256_bytes(template.encode("utf-8"))


def _build_contract_sha256(template: str = DOCKERFILE_TEMPLATE, *, contract_label: str = EXECUTION_CONTRACT_LABEL) -> str:
    """Bind stable build controls without treating nonce, temporary paths, or tags as semantics."""
    return _canonical_sha256(
        {
            "base_image": BASE_IMAGE,
            "build_network": "default",
            "contract_label": contract_label,
            "docker_subcommand": "build",
            "dockerfile_sha256": _dockerfile_sha256(template),
            "no_cache": True,
            "pull": False,
            "source_derived": True,
        }
    )


def _build_source_derived_image(
    source_root: Path,
    verifier: Any,
    *,
    work_root: Path,
    timeout: int,
    dockerfile_template: str = DOCKERFILE_TEMPLATE,
    contract_label: str = EXECUTION_CONTRACT_LABEL,
    source_mutator: Callable[[Path, Any], dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], str, str, dict[str, Any] | None]:
    context = work_root / "build-context"
    context.mkdir()
    _copy_verified_source(source_root, context / "source", verifier)
    source_variant = source_mutator(context / "source", verifier) if source_mutator is not None else None
    dockerfile = context / "Dockerfile.kguard"
    dockerfile.write_text(dockerfile_template, encoding="utf-8", newline="\n")
    nonce = secrets.token_hex(16)
    tag = f"kguard-l2-{contract_label}-{nonce}"
    build_arguments = [
        "build",
        "--no-cache",
        "--pull=false",
        "--network",
        "default",
        "--label",
        f"io.k-guard.execution-contract={contract_label}",
        "--label",
        f"io.k-guard.build-nonce={nonce}",
        "--file",
        str(dockerfile),
        "--tag",
        tag,
        str(context),
    ]
    build = _docker(build_arguments, cwd=work_root, timeout=timeout)
    _expect_success(build, "source_derived_image_build")
    inspect = _load_json_stdout(
        _docker(["image", "inspect", tag], cwd=work_root, timeout=60), "source_derived_image_inspect"
    )
    if not isinstance(inspect, list) or len(inspect) != 1 or not isinstance(inspect[0], dict):
        raise RuntimeContractError("source_derived_image_inspect_shape")
    image = inspect[0]
    image_id = image.get("Id")
    labels = image.get("Config", {}).get("Labels") if isinstance(image.get("Config"), dict) else None
    if not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None:
        raise RuntimeContractError("source_derived_image_id_invalid")
    if not isinstance(labels, dict) or labels.get("io.k-guard.execution-contract") != contract_label:
        raise RuntimeContractError("source_derived_image_label_missing")
    projection = {
        "base_image": BASE_IMAGE,
        "image_id": image_id,
        "image_id_sha256": sha256_bytes(image_id.encode("ascii")),
        "dockerfile_sha256": _dockerfile_sha256(dockerfile_template),
        "build_command_sha256": _canonical_sha256(build_arguments),
        "build_contract_sha256": _build_contract_sha256(
            dockerfile_template, contract_label=contract_label
        ),
        "build_output_sha256": sha256_bytes(build.stdout + build.stderr),
        "source_derived": True,
        "online_build_non_evidence": True,
        "raw_returned": False,
    }
    if source_variant is not None:
        projection["source_variant"] = source_variant
    return projection, image_id, tag, source_variant


def _safe_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise RuntimeContractError(f"{label}_invalid")
    try:
        converted = int(str(value))
    except (TypeError, ValueError) as exc:
        raise RuntimeContractError(f"{label}_invalid") from exc
    if converted < 0:
        raise RuntimeContractError(f"{label}_invalid")
    return converted


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _testcase_outcome(testcase: ET.Element) -> str:
    children = {_local_name(child.tag) for child in testcase}
    if "error" in children:
        return "error"
    if "failure" in children:
        return "failure"
    if "skipped" in children:
        return "skipped"
    return "pass"


def _parse_failsafe_reports(
    summary_path: Path, suite_path: Path
) -> tuple[dict[str, int], dict[str, int], tuple[tuple[str, str], ...], dict[str, str]]:
    if not summary_path.is_file() or not suite_path.is_file():
        raise RuntimeContractError("failsafe_report_missing")
    summary_raw = summary_path.read_bytes()
    suite_raw = suite_path.read_bytes()
    if not summary_raw or not suite_raw or len(summary_raw) > MAX_REPORT_BYTES or len(suite_raw) > MAX_REPORT_BYTES:
        raise RuntimeContractError("failsafe_report_size_invalid")
    if (
        b"<!DOCTYPE" in summary_raw.upper()
        or b"<!ENTITY" in summary_raw.upper()
        or b"<!DOCTYPE" in suite_raw.upper()
        or b"<!ENTITY" in suite_raw.upper()
    ):
        raise RuntimeContractError("failsafe_report_dtd_forbidden")
    try:
        summary = ET.fromstring(summary_raw)
        suite = ET.fromstring(suite_raw)
    except ET.ParseError as exc:
        raise RuntimeContractError("failsafe_report_xml_invalid") from exc
    if _local_name(summary.tag) != "failsafe-summary" or _local_name(suite.tag) != "testsuite":
        raise RuntimeContractError("failsafe_report_schema_invalid")
    summary_values = {
        key: _safe_int(next((child.text for child in summary if _local_name(child.tag) == key), None), key)
        for key in ("completed", "errors", "failures", "skipped", "flakes")
    }
    if summary.attrib.get("timeout") != "false":
        raise RuntimeContractError("failsafe_timeout_reported")
    suite_values = {
        key: _safe_int(suite.attrib.get(key), f"suite_{key}")
        for key in ("tests", "errors", "failures", "skipped", "flakes")
    }
    if suite.attrib.get("name") != TEST_CLASS:
        raise RuntimeContractError("failsafe_suite_mismatch")
    testcases = [child for child in suite if _local_name(child.tag) == "testcase"]
    case_outcomes = tuple(
        sorted((str(testcase.attrib.get("name") or ""), _testcase_outcome(testcase)) for testcase in testcases)
    )
    if any(not name for name, _outcome in case_outcomes) or len({name for name, _outcome in case_outcomes}) != len(case_outcomes):
        raise RuntimeContractError("failsafe_case_identity_invalid")
    return (
        summary_values,
        suite_values,
        case_outcomes,
        {"summary_sha256": sha256_bytes(summary_raw), "suite_sha256": sha256_bytes(suite_raw)},
    )


def summarize_failsafe_reports(summary_path: Path, suite_path: Path) -> tuple[dict[str, Any], dict[str, str]]:
    summary_values, suite_values, case_outcomes, hashes = _parse_failsafe_reports(summary_path, suite_path)
    return (
        {
            "test_class": TEST_CLASS,
            "failsafe": {**summary_values, "timeout": False},
            "suite": {**suite_values, "testcase_count": len(case_outcomes)},
            "case_outcomes": [
                {"name": name, "outcome": outcome} for name, outcome in case_outcomes
            ],
            "raw_returned": False,
        },
        hashes,
    )


def _normalize_failsafe_reports(
    summary_path: Path,
    suite_path: Path,
    *,
    result_schema: str,
    expected_summary: dict[str, int],
    expected_suite: dict[str, int],
    expected_cases: tuple[tuple[str, str], ...],
    control_triggered: bool,
) -> tuple[dict[str, Any], dict[str, str]]:
    summary_values, suite_values, case_outcomes, hashes = _parse_failsafe_reports(summary_path, suite_path)
    if len(case_outcomes) != len(expected_cases) or case_outcomes != expected_cases:
        raise RuntimeContractError("failsafe_case_outcome_invalid")
    if summary_values != expected_summary or suite_values != expected_suite:
        raise RuntimeContractError("failsafe_expected_outcome_mismatch")
    normalized = {
        "schema": result_schema,
        "test_class": TEST_CLASS,
        "failsafe": {**summary_values, "timeout": False},
        "suite": {
            **suite_values,
            "testcase_count": len(case_outcomes),
            "all_cases_passed": all(outcome == "pass" for _name, outcome in case_outcomes),
        },
        "raw_returned": False,
    }
    if control_triggered:
        normalized["control_triggered"] = True
        normalized["case_outcomes"] = [
            {"name": name, "outcome": outcome} for name, outcome in case_outcomes
        ]
    return (
        normalized,
        hashes,
    )


def normalize_failsafe_reports(summary_path: Path, suite_path: Path) -> tuple[dict[str, Any], dict[str, str]]:
    return _normalize_failsafe_reports(
        summary_path,
        suite_path,
        result_schema=RESULT_SCHEMA,
        expected_summary={"completed": 2, "errors": 0, "failures": 0, "skipped": 0, "flakes": 0},
        expected_suite={"tests": 2, "errors": 0, "failures": 0, "skipped": 0, "flakes": 0},
        expected_cases=SUCCESS_CASE_OUTCOMES,
        control_triggered=False,
    )


def normalize_negative_control_failsafe_reports(
    summary_path: Path, suite_path: Path
) -> tuple[dict[str, Any], dict[str, str]]:
    return _normalize_failsafe_reports(
        summary_path,
        suite_path,
        result_schema=NEGATIVE_CONTROL_RESULT_SCHEMA,
        expected_summary={"completed": 3, "errors": 0, "failures": 2, "skipped": 0, "flakes": 0},
        expected_suite={"tests": 3, "errors": 0, "failures": 2, "skipped": 0, "flakes": 0},
        expected_cases=NEGATIVE_CONTROL_CASE_OUTCOMES,
        control_triggered=True,
    )


def _container_isolation(
    container: dict[str, Any],
    *,
    image_id: str,
    cache_volume_name: str,
    report_volume_name: str,
    contract_label: str = EXECUTION_CONTRACT_LABEL,
) -> dict[str, Any]:
    host = container.get("HostConfig") if isinstance(container.get("HostConfig"), dict) else {}
    config = container.get("Config") if isinstance(container.get("Config"), dict) else {}
    labels = config.get("Labels") if isinstance(config.get("Labels"), dict) else {}
    network = container.get("NetworkSettings") if isinstance(container.get("NetworkSettings"), dict) else {}
    ports = network.get("Ports")
    mounts = container.get("Mounts") if isinstance(container.get("Mounts"), list) else []
    security = {str(value).casefold() for value in host.get("SecurityOpt", []) if isinstance(value, str)}
    cap_drop = {str(value).upper() for value in host.get("CapDrop", []) if isinstance(value, str)}
    volume_mounts = [row for row in mounts if isinstance(row, dict) and row.get("Type") == "volume"]
    tmpfs = host.get("Tmpfs") if isinstance(host.get("Tmpfs"), dict) else {}
    mount_by_destination = {
        row.get("Destination"): row.get("Name") for row in volume_mounts if isinstance(row.get("Destination"), str)
    }
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
        "no_bind_mounts": not host.get("Binds"),
        "owned_cache_volume": len(volume_mounts) == 2
        and mount_by_destination.get("/home/kguard/.m2") == cache_volume_name,
        "owned_report_volume": len(volume_mounts) == 2
        and mount_by_destination.get("/evidence") == report_volume_name,
        "hardened_tmpfs": all(
            isinstance(tmpfs.get(path), str)
            and all(token in tmpfs[path].split(",") for token in ("noexec", "nosuid", "nodev", "uid=65532", "gid=65532", "mode=0770"))
            for path in ("/tmp", "/workspace/target")
        ),
    }
    return {
        "checks": checks,
        "passed": all(checks.values()),
        "raw_returned": False,
    }


def _owned_cleanup(
    *,
    work_root: Path,
    container_name: str,
    volume_names: tuple[str, ...],
    expected_container_id: str | None,
    nonce: str,
    created_volume_names: set[str],
    contract_label: str = EXECUTION_CONTRACT_LABEL,
) -> dict[str, Any]:
    container_removed = False
    removed_volumes: dict[str, bool] = {name: False for name in volume_names}
    container_ownership_verified = expected_container_id is None
    inspected = _docker(["container", "inspect", container_name], cwd=work_root, timeout=30)
    if inspected.returncode == 0 and not inspected.timed_out and not inspected.output_truncated:
        try:
            rows = json.loads(inspected.stdout.decode("utf-8"))
            row = rows[0] if isinstance(rows, list) and len(rows) == 1 else None
            labels = row.get("Config", {}).get("Labels") if isinstance(row, dict) and isinstance(row.get("Config"), dict) else None
            container_ownership_verified = (
                isinstance(row, dict)
                and row.get("Id") == expected_container_id
                and isinstance(labels, dict)
                and labels.get("io.k-guard.execution-contract") == contract_label
                and labels.get("io.k-guard.run-nonce") == nonce
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            container_ownership_verified = False
        if container_ownership_verified:
            removed = _docker(["container", "rm", "--force", container_name], cwd=work_root, timeout=60)
            container_removed = removed.returncode == 0 and not removed.timed_out and not removed.output_truncated
    elif inspected.returncode != 0:
        container_removed = expected_container_id is None
    volumes_owned = True
    for volume_name in volume_names:
        volume_inspect = _docker(["volume", "inspect", volume_name], cwd=work_root, timeout=30)
        if volume_inspect.returncode == 0 and not volume_inspect.timed_out and not volume_inspect.output_truncated:
            try:
                rows = json.loads(volume_inspect.stdout.decode("utf-8"))
                row = rows[0] if isinstance(rows, list) and len(rows) == 1 else None
                labels = row.get("Labels") if isinstance(row, dict) else None
                volume_owned = (
                    isinstance(labels, dict)
                    and labels.get("io.k-guard.execution-contract") == contract_label
                    and labels.get("io.k-guard.run-nonce") == nonce
                )
            except (UnicodeDecodeError, json.JSONDecodeError):
                volume_owned = False
            volumes_owned = volumes_owned and volume_owned
            if volume_owned:
                removed = _docker(["volume", "rm", volume_name], cwd=work_root, timeout=60)
                removed_volumes[volume_name] = (
                    removed.returncode == 0 and not removed.timed_out and not removed.output_truncated
                )
        elif volume_inspect.returncode != 0:
            removed_volumes[volume_name] = volume_name not in created_volume_names
    return {
        "ownership_verified": container_ownership_verified and volumes_owned,
        "container_removed": container_removed,
        "volume_count": len(volume_names),
        "volumes_removed": all(removed_volumes.values()),
        "passed": container_ownership_verified and volumes_owned and container_removed and all(removed_volumes.values()),
        "raw_returned": False,
    }


def _offline_run(
    image_id: str,
    *,
    work_root: Path,
    timeout: int,
    contract_label: str = EXECUTION_CONTRACT_LABEL,
    expected_exit_code: int = 0,
    report_normalizer: Callable[[Path, Path], tuple[dict[str, Any], dict[str, str]]] = normalize_failsafe_reports,
) -> dict[str, Any]:
    nonce = secrets.token_hex(16)
    container_name = f"kguard-l2-{contract_label}-{nonce}"
    cache_volume_name = f"kguard-l2-webgoat-m2-{nonce}"
    report_volume_name = f"kguard-l2-webgoat-evidence-{nonce}"
    expected_container_id: str | None = None
    created_volume_names: set[str] = set()
    result: dict[str, Any] = {
        "run_nonce_sha256": sha256_bytes(nonce.encode("ascii")),
        "image_id": image_id,
        "maven_command_sha256": sha256_bytes(MAVEN_ARGUMENTS.encode("utf-8")),
        "runtime_command_sha256": sha256_bytes(RUNTIME_COMMAND.encode("utf-8")),
        "network_policy": "none",
        "expected_exit_code": expected_exit_code,
        "isolation": None,
        "execution": None,
        "normalized_result": None,
        "observed_result": None,
        "report_hashes": None,
        "cleanup": None,
        "failure_code": None,
        "passed": False,
        "raw_returned": False,
    }
    try:
        for volume_name in (cache_volume_name, report_volume_name):
            volume = _docker(
                [
                    "volume",
                    "create",
                    "--label",
                    f"io.k-guard.execution-contract={contract_label}",
                    "--label",
                    f"io.k-guard.run-nonce={nonce}",
                    volume_name,
                ],
                cwd=work_root,
                timeout=60,
            )
            _expect_success(volume, "owned_volume_create")
            created_volume_names.add(volume_name)
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
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=1073741824,uid=65532,gid=65532,mode=0770",
            "--tmpfs",
            "/workspace/target:rw,noexec,nosuid,nodev,size=1073741824,uid=65532,gid=65532,mode=0770",
            "--mount",
            f"type=volume,source={cache_volume_name},target=/home/kguard/.m2",
            "--mount",
            f"type=volume,source={report_volume_name},target=/evidence",
            image_id,
            "/bin/sh",
            "-lc",
            RUNTIME_COMMAND,
        ]
        created = _docker(create_arguments, cwd=work_root, timeout=60)
        _expect_success(created, "offline_container_create")
        try:
            expected_container_id = created.stdout.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise RuntimeContractError("offline_container_id_invalid") from exc
        if not re.fullmatch(r"[0-9a-f]{64}", expected_container_id):
            raise RuntimeContractError("offline_container_id_invalid")
        inspected = _load_json_stdout(
            _docker(["container", "inspect", container_name], cwd=work_root, timeout=60), "offline_container_inspect"
        )
        if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
            raise RuntimeContractError("offline_container_inspect_shape")
        isolation = _container_isolation(
            inspected[0],
            image_id=image_id,
            cache_volume_name=cache_volume_name,
            report_volume_name=report_volume_name,
            contract_label=contract_label,
        )
        result["isolation"] = isolation
        if not isolation["passed"]:
            raise RuntimeContractError("offline_container_isolation_failed")
        started = _docker(["container", "start", "--attach", container_name], cwd=work_root, timeout=timeout)
        result["execution"] = _command_receipt(started)
        if started.returncode != expected_exit_code or started.timed_out or started.output_truncated:
            raise RuntimeContractError("offline_test_command_failed")
        post = _load_json_stdout(
            _docker(["container", "inspect", container_name], cwd=work_root, timeout=60), "offline_container_post_inspect"
        )
        if not isinstance(post, list) or len(post) != 1 or not isinstance(post[0], dict):
            raise RuntimeContractError("offline_container_post_shape")
        state = post[0].get("State") if isinstance(post[0].get("State"), dict) else {}
        if state.get("Running") is not False or state.get("ExitCode") != expected_exit_code:
            raise RuntimeContractError("offline_container_exit_state_invalid")
        with tempfile.TemporaryDirectory(prefix="kguard-l2-webgoat-report-") as report_root:
            copied = _docker(
                ["container", "cp", f"{container_name}:/evidence/failsafe-reports", report_root],
                cwd=work_root,
                timeout=60,
            )
            _expect_success(copied, "offline_report_copy")
            reports = Path(report_root) / "failsafe-reports"
            summary_path = reports / "failsafe-summary.xml"
            suite_path = reports / f"TEST-{TEST_CLASS}.xml"
            try:
                normalized, hashes = report_normalizer(summary_path, suite_path)
            except RuntimeContractError:
                observed, hashes = summarize_failsafe_reports(summary_path, suite_path)
                result["observed_result"] = observed
                result["report_hashes"] = hashes
                raise
        result["normalized_result"] = normalized
        result["report_hashes"] = hashes
    except RuntimeContractError as exc:
        result["failure_code"] = str(exc)
    finally:
        result["cleanup"] = _owned_cleanup(
            work_root=work_root,
            container_name=container_name,
            volume_names=(cache_volume_name, report_volume_name),
            expected_container_id=expected_container_id,
            nonce=nonce,
            created_volume_names=created_volume_names,
            contract_label=contract_label,
        )
    result["passed"] = (
        isinstance(result["isolation"], dict)
        and result["isolation"].get("passed") is True
        and isinstance(result["execution"], dict)
        and result["execution"].get("returncode") == expected_exit_code
        and result["normalized_result"] is not None
        and result["failure_code"] is None
        and isinstance(result["cleanup"], dict)
        and result["cleanup"].get("passed") is True
    )
    return result


def _consensus_projection(run: dict[str, Any]) -> dict[str, Any]:
    return {
        "image_id": run.get("image_id"),
        "maven_command_sha256": run.get("maven_command_sha256"),
        "runtime_command_sha256": run.get("runtime_command_sha256"),
        "network_policy": run.get("network_policy"),
        "expected_exit_code": run.get("expected_exit_code"),
        "isolation": run.get("isolation"),
        "normalized_result": run.get("normalized_result"),
        "passed": run.get("passed"),
    }


def _cleanup_image(
    image_id: str, *, work_root: Path, contract_label: str = EXECUTION_CONTRACT_LABEL
) -> dict[str, Any]:
    inspected = _docker(["image", "inspect", image_id], cwd=work_root, timeout=60)
    ownership_verified = False
    if inspected.returncode == 0 and not inspected.timed_out and not inspected.output_truncated:
        try:
            rows = json.loads(inspected.stdout.decode("utf-8"))
            row = rows[0] if isinstance(rows, list) and len(rows) == 1 else None
            labels = row.get("Config", {}).get("Labels") if isinstance(row, dict) and isinstance(row.get("Config"), dict) else None
            ownership_verified = isinstance(labels, dict) and labels.get("io.k-guard.execution-contract") == contract_label
        except (UnicodeDecodeError, json.JSONDecodeError):
            ownership_verified = False
    removed = False
    if ownership_verified:
        result = _docker(["image", "rm", "--force", image_id], cwd=work_root, timeout=120)
        removed = result.returncode == 0 and not result.timed_out and not result.output_truncated
    post = _docker(["image", "inspect", image_id], cwd=work_root, timeout=60)
    absent = post.returncode != 0 and not post.timed_out and not post.output_truncated
    return {
        "ownership_verified": ownership_verified,
        "removed": removed,
        "absent_after": absent,
        "passed": ownership_verified and removed and absent,
        "raw_returned": False,
    }


def _claim_boundary() -> dict[str, bool]:
    return {
        "execution_contract_only": True,
        "scanner_accuracy_proven": False,
        "severity_or_cwe_admitted": False,
        "tp_fp_fn_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }


def execute_contract(source_root: Path, *, timeout: int) -> dict[str, Any]:
    source, verifier, verifier_sha256 = verify_source_workspace(source_root.resolve())
    image: dict[str, Any] | None = None
    image_id: str | None = None
    image_cleanup: dict[str, Any] | None = None
    runs: list[dict[str, Any]] = []
    failure: str | None = None
    with tempfile.TemporaryDirectory(prefix="kguard-l2-webgoat-idor-") as temporary:
        work_root = Path(temporary)
        try:
            image, image_id, _tag, _source_variant = _build_source_derived_image(
                source_root.resolve(), verifier, work_root=work_root, timeout=timeout
            )
            runs = [_offline_run(image_id, work_root=work_root, timeout=timeout) for _ in range(2)]
        except RuntimeContractError as exc:
            failure = str(exc)
        finally:
            if image_id is not None:
                image_cleanup = _cleanup_image(image_id, work_root=work_root)
    projections = [_consensus_projection(run) for run in runs]
    consensus_passed = len(projections) == 2 and projections[0] == projections[1] and all(run.get("passed") is True for run in runs)
    status = (
        "EXECUTION_CONTRACT_PASS"
        if failure is None and image is not None and image_cleanup is not None and image_cleanup["passed"] is True and consensus_passed
        else "HOLD"
    )
    receipt = {
        "schema": SCHEMA,
        "tool_provenance": {
            "runner_sha256": sha256_bytes(Path(__file__).read_bytes()),
            "source_verifier_sha256": verifier_sha256,
            "base_image": BASE_IMAGE,
            "raw_returned": False,
        },
        "source": source,
        "image": image,
        "runs": runs,
        "consensus": {
            "run_count": len(runs),
            "two_runs_byte_equivalent_after_normalization": consensus_passed,
            "projection_sha256": _canonical_sha256(projections) if projections else None,
            "raw_returned": False,
        },
        "image_cleanup": image_cleanup,
        "claim_boundary": _claim_boundary(),
        "admission_blockers": list(ADMISSION_BLOCKERS),
        "execution_contract_status": status,
        "release_gate_passed": False,
        "failure_code": failure,
        "raw_returned": False,
    }
    validate_receipt(receipt)
    return receipt


def validate_receipt(receipt: dict[str, Any]) -> None:
    required = {
        "schema", "tool_provenance", "source", "image", "runs", "consensus", "image_cleanup",
        "claim_boundary", "admission_blockers", "execution_contract_status", "release_gate_passed",
        "failure_code", "raw_returned",
    }
    if set(receipt) != required or receipt.get("schema") != SCHEMA or receipt.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_schema_invalid")
    boundary = receipt.get("claim_boundary")
    if boundary != _claim_boundary() or receipt.get("release_gate_passed") is not False:
        raise RuntimeContractError("receipt_claim_boundary_invalid")
    blockers = receipt.get("admission_blockers")
    if not isinstance(blockers, list) or tuple(blockers) != ADMISSION_BLOCKERS:
        raise RuntimeContractError("receipt_admission_blockers_invalid")
    status = receipt.get("execution_contract_status")
    if status not in {"EXECUTION_CONTRACT_PASS", "HOLD"}:
        raise RuntimeContractError("receipt_status_invalid")
    runs = receipt.get("runs")
    consensus = receipt.get("consensus")
    if not isinstance(runs, list) or not isinstance(consensus, dict):
        raise RuntimeContractError("receipt_run_shape_invalid")
    projections = [_consensus_projection(run) for run in runs if isinstance(run, dict)]
    expected_consensus = len(projections) == 2 and projections[0] == projections[1] and all(
        run.get("passed") is True for run in runs if isinstance(run, dict)
    )
    if consensus.get("two_runs_byte_equivalent_after_normalization") is not expected_consensus:
        raise RuntimeContractError("receipt_consensus_invalid")
    if status == "EXECUTION_CONTRACT_PASS":
        if receipt.get("failure_code") is not None or receipt.get("image") is None or receipt.get("image_cleanup", {}).get("passed") is not True or not expected_consensus:
            raise RuntimeContractError("receipt_pass_without_complete_evidence")
    elif receipt.get("failure_code") is None and expected_consensus:
        raise RuntimeContractError("receipt_hold_without_failure")


def _negative_control_claim_boundary() -> dict[str, bool]:
    return {
        "negative_control_execution_only": True,
        "independent_upstream_fixed_revision_proven": False,
        "scanner_accuracy_proven": False,
        "severity_or_cwe_admitted": False,
        "tp_fp_fn_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }


def _expected_positive_execution_tool_provenance() -> dict[str, object]:
    verifier_path = Path(__file__).with_name("holdout_source_materialization.py")
    return {
        "runner_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "source_verifier_sha256": sha256_bytes(verifier_path.read_bytes()),
        "base_image": BASE_IMAGE,
        "raw_returned": False,
    }


def _load_positive_execution_contract(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        receipt = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError("positive_execution_receipt_unreadable") from exc
    if not isinstance(receipt, dict) or canonical_json_bytes(receipt) != raw:
        raise RuntimeContractError("positive_execution_receipt_not_canonical")
    receipt_sha256 = sha256_bytes(raw)
    validate_receipt(receipt)
    if receipt.get("execution_contract_status") != "EXECUTION_CONTRACT_PASS":
        raise RuntimeContractError("positive_execution_contract_not_passed")
    if receipt.get("tool_provenance") != _expected_positive_execution_tool_provenance():
        raise RuntimeContractError("positive_execution_tool_provenance_mismatch")
    source = receipt.get("source")
    if not isinstance(source, dict):
        raise RuntimeContractError("positive_execution_source_invalid")
    expected_source = {
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
    }
    if any(source.get(key) != value for key, value in expected_source.items()):
        raise RuntimeContractError("positive_execution_source_mismatch")
    source_receipt_sha256 = source.get("source_receipt_sha256")
    if not isinstance(source_receipt_sha256, str) or SHA256_RE.fullmatch(source_receipt_sha256) is None:
        raise RuntimeContractError("positive_execution_source_receipt_invalid")
    return {
        "receipt_sha256": receipt_sha256,
        "source_receipt_sha256": source_receipt_sha256,
        "execution_contract_status": "EXECUTION_CONTRACT_PASS",
        "raw_returned": False,
    }


def execute_negative_control(
    source_root: Path, *, positive_receipt_path: Path, timeout: int
) -> dict[str, Any]:
    positive = _load_positive_execution_contract(positive_receipt_path)
    source, verifier, verifier_sha256 = verify_source_workspace(source_root.resolve())
    if source["source_receipt_sha256"] != positive["source_receipt_sha256"]:
        raise RuntimeContractError("positive_execution_source_receipt_mismatch")
    image: dict[str, Any] | None = None
    image_id: str | None = None
    source_variant: dict[str, Any] | None = None
    image_cleanup: dict[str, Any] | None = None
    runs: list[dict[str, Any]] = []
    failure: str | None = None
    with tempfile.TemporaryDirectory(prefix="kguard-l2-webgoat-idor-negative-control-") as temporary:
        work_root = Path(temporary)
        try:
            image, image_id, _tag, source_variant = _build_source_derived_image(
                source_root.resolve(),
                verifier,
                work_root=work_root,
                timeout=timeout,
                dockerfile_template=NEGATIVE_CONTROL_DOCKERFILE_TEMPLATE,
                contract_label=NEGATIVE_CONTROL_LABEL,
                source_mutator=_apply_negative_control_patch,
            )
            if source_variant is None:
                raise RuntimeContractError("negative_control_source_variant_missing")
            runs = [
                _offline_run(
                    image_id,
                    work_root=work_root,
                    timeout=timeout,
                    contract_label=NEGATIVE_CONTROL_LABEL,
                    expected_exit_code=NEGATIVE_CONTROL_EXPECTED_EXIT_CODE,
                    report_normalizer=normalize_negative_control_failsafe_reports,
                )
                for _ in range(2)
            ]
        except RuntimeContractError as exc:
            failure = str(exc)
        finally:
            if image_id is not None:
                image_cleanup = _cleanup_image(
                    image_id, work_root=work_root, contract_label=NEGATIVE_CONTROL_LABEL
                )
    projections = [_consensus_projection(run) for run in runs]
    consensus_passed = (
        len(projections) == 2
        and projections[0] == projections[1]
        and all(run.get("passed") is True for run in runs)
    )
    status = (
        "NEGATIVE_CONTROL_PASS"
        if (
            failure is None
            and image is not None
            and source_variant is not None
            and image_cleanup is not None
            and image_cleanup["passed"] is True
            and consensus_passed
        )
        else "HOLD"
    )
    receipt = {
        "schema": NEGATIVE_CONTROL_SCHEMA,
        "tool_provenance": {
            "runner_sha256": sha256_bytes(Path(__file__).read_bytes()),
            "source_verifier_sha256": verifier_sha256,
            "base_image": BASE_IMAGE,
            "raw_returned": False,
        },
        "source": source,
        "positive_execution_contract": positive,
        "negative_control": source_variant,
        "image": image,
        "runs": runs,
        "consensus": {
            "run_count": len(runs),
            "two_runs_byte_equivalent_after_normalization": consensus_passed,
            "projection_sha256": _canonical_sha256(projections) if projections else None,
            "raw_returned": False,
        },
        "image_cleanup": image_cleanup,
        "claim_boundary": _negative_control_claim_boundary(),
        "admission_blockers": list(NEGATIVE_CONTROL_ADMISSION_BLOCKERS),
        "negative_control_status": status,
        "release_gate_passed": False,
        "failure_code": failure,
        "raw_returned": False,
    }
    validate_negative_control_receipt(receipt)
    return receipt


def validate_negative_control_receipt(receipt: dict[str, Any]) -> None:
    required = {
        "schema",
        "tool_provenance",
        "source",
        "positive_execution_contract",
        "negative_control",
        "image",
        "runs",
        "consensus",
        "image_cleanup",
        "claim_boundary",
        "admission_blockers",
        "negative_control_status",
        "release_gate_passed",
        "failure_code",
        "raw_returned",
    }
    if (
        set(receipt) != required
        or receipt.get("schema") != NEGATIVE_CONTROL_SCHEMA
        or receipt.get("raw_returned") is not False
    ):
        raise RuntimeContractError("negative_control_receipt_schema_invalid")
    if receipt.get("claim_boundary") != _negative_control_claim_boundary() or receipt.get("release_gate_passed") is not False:
        raise RuntimeContractError("negative_control_claim_boundary_invalid")
    blockers = receipt.get("admission_blockers")
    if not isinstance(blockers, list) or tuple(blockers) != NEGATIVE_CONTROL_ADMISSION_BLOCKERS:
        raise RuntimeContractError("negative_control_admission_blockers_invalid")
    status = receipt.get("negative_control_status")
    if status not in {"NEGATIVE_CONTROL_PASS", "HOLD"}:
        raise RuntimeContractError("negative_control_status_invalid")
    incomplete_hold = status == "HOLD" and receipt.get("failure_code") is not None
    positive = receipt.get("positive_execution_contract")
    if not isinstance(positive, dict) or set(positive) != {
        "receipt_sha256", "source_receipt_sha256", "execution_contract_status", "raw_returned"
    }:
        raise RuntimeContractError("negative_control_positive_reference_invalid")
    if (
        positive.get("execution_contract_status") != "EXECUTION_CONTRACT_PASS"
        or positive.get("raw_returned") is not False
        or any(
            not isinstance(positive.get(field), str) or SHA256_RE.fullmatch(positive[field]) is None
            for field in ("receipt_sha256", "source_receipt_sha256")
        )
    ):
        raise RuntimeContractError("negative_control_positive_reference_invalid")
    source = receipt.get("source")
    if not isinstance(source, dict) or source.get("source_receipt_sha256") != positive["source_receipt_sha256"]:
        raise RuntimeContractError("negative_control_source_reference_invalid")
    control = receipt.get("negative_control")
    required_control = {
        "patch_id",
        "source_path",
        "original_file_sha256",
        "patched_file_sha256",
        "patch_sha256",
        "variant_tree_sha256",
        "source_checkout_mutated",
        "raw_returned",
    }
    if control is None:
        if not incomplete_hold:
            raise RuntimeContractError("negative_control_patch_invalid")
    else:
        if not isinstance(control, dict) or set(control) != required_control:
            raise RuntimeContractError("negative_control_patch_invalid")
        if (
            control.get("patch_id") != NEGATIVE_CONTROL_PATCH_ID
            or control.get("source_path") != NEGATIVE_CONTROL_SOURCE_PATH.as_posix()
            or control.get("source_checkout_mutated") is not False
            or control.get("raw_returned") is not False
            or any(
                not isinstance(control.get(field), str) or SHA256_RE.fullmatch(control[field]) is None
                for field in (
                    "original_file_sha256",
                    "patched_file_sha256",
                    "patch_sha256",
                    "variant_tree_sha256",
                )
            )
            or control["original_file_sha256"] == control["patched_file_sha256"]
            or control["variant_tree_sha256"] == SOURCE_TREE_SHA256
        ):
            raise RuntimeContractError("negative_control_patch_invalid")
    image = receipt.get("image")
    if control is None:
        if image is not None:
            raise RuntimeContractError("negative_control_image_variant_invalid")
    elif not isinstance(image, dict) or image.get("source_variant") != control:
        raise RuntimeContractError("negative_control_image_variant_invalid")
    runs = receipt.get("runs")
    consensus = receipt.get("consensus")
    if not isinstance(runs, list) or not isinstance(consensus, dict):
        raise RuntimeContractError("negative_control_run_shape_invalid")
    projections = [_consensus_projection(run) for run in runs if isinstance(run, dict)]
    expected_consensus = (
        len(runs) == 2
        and len(projections) == 2
        and projections[0] == projections[1]
        and all(run.get("passed") is True for run in runs if isinstance(run, dict))
        and all(
            run.get("expected_exit_code") == NEGATIVE_CONTROL_EXPECTED_EXIT_CODE
            and run.get("execution", {}).get("returncode") == NEGATIVE_CONTROL_EXPECTED_EXIT_CODE
            and run.get("normalized_result", {}).get("schema") == NEGATIVE_CONTROL_RESULT_SCHEMA
            and run.get("normalized_result", {}).get("control_triggered") is True
            and run.get("normalized_result", {}).get("suite", {}).get("all_cases_passed") is False
            for run in runs
            if isinstance(run, dict)
        )
    )
    if (
        consensus.get("run_count") != len(runs)
        or consensus.get("two_runs_byte_equivalent_after_normalization") is not expected_consensus
        or consensus.get("projection_sha256") != (_canonical_sha256(projections) if projections else None)
        or consensus.get("raw_returned") is not False
    ):
        raise RuntimeContractError("negative_control_consensus_invalid")
    if status == "NEGATIVE_CONTROL_PASS":
        if (
            receipt.get("failure_code") is not None
            or image is None
            or receipt.get("image_cleanup", {}).get("passed") is not True
            or not expected_consensus
        ):
            raise RuntimeContractError("negative_control_pass_without_complete_evidence")
    elif receipt.get("failure_code") is None and expected_consensus:
        raise RuntimeContractError("negative_control_hold_without_failure")


def _write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(receipt))


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay one WebGoat IDOR execution contract without admitting scanner accuracy.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--source-root", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--timeout-seconds", type=int, default=900)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--receipt", type=Path, required=True)
    negative_control = subparsers.add_parser("negative-control")
    negative_control.add_argument("--source-root", type=Path, required=True)
    negative_control.add_argument("--positive-receipt", type=Path, required=True)
    negative_control.add_argument("--output", type=Path, required=True)
    negative_control.add_argument("--timeout-seconds", type=int, default=900)
    verify_negative_control = subparsers.add_parser("verify-negative-control")
    verify_negative_control.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command == "verify":
        try:
            raw = args.receipt.read_bytes()
            receipt = json.loads(raw.decode("utf-8"))
            if canonical_json_bytes(receipt) != raw or not isinstance(receipt, dict):
                raise RuntimeContractError("receipt_not_canonical")
            validate_receipt(receipt)
        except (OSError, UnicodeError, json.JSONDecodeError, RuntimeContractError) as exc:
            raise SystemExit(f"HOLD: {exc}") from exc
        return 0
    if args.command == "verify-negative-control":
        try:
            raw = args.receipt.read_bytes()
            receipt = json.loads(raw.decode("utf-8"))
            if canonical_json_bytes(receipt) != raw or not isinstance(receipt, dict):
                raise RuntimeContractError("negative_control_receipt_not_canonical")
            validate_negative_control_receipt(receipt)
        except (OSError, UnicodeError, json.JSONDecodeError, RuntimeContractError) as exc:
            raise SystemExit(f"HOLD: {exc}") from exc
        return 0
    if args.timeout_seconds < 60 or args.timeout_seconds > 1800:
        raise SystemExit("HOLD: timeout_seconds_out_of_range")
    if args.command == "negative-control":
        receipt = execute_negative_control(
            args.source_root,
            positive_receipt_path=args.positive_receipt,
            timeout=args.timeout_seconds,
        )
        _write_receipt(args.output, receipt)
        return 0 if receipt["negative_control_status"] == "NEGATIVE_CONTROL_PASS" else 2
    receipt = execute_contract(args.source_root, timeout=args.timeout_seconds)
    _write_receipt(args.output, receipt)
    return 0 if receipt["execution_contract_status"] == "EXECUTION_CONTRACT_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
