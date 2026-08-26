from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import secrets
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "k_guard_l2_webgoat_missing_function_ac_execution_contract.v1"
RESULT_SCHEMA = "k_guard_l2_webgoat_missing_function_ac_normalized_result.v1"
NEGATIVE_CONTROL_SCHEMA = "k_guard_l2_webgoat_missing_function_ac_negative_control.v1"
NEGATIVE_CONTROL_RESULT_SCHEMA = "k_guard_l2_webgoat_missing_function_ac_negative_control_result.v1"
APP_ID = "webgoat"
REPOSITORY_ID = "webgoat/webgoat"
SOURCE_COMMIT = "5142935bf7c279882c3b0fc0ecec42c447de6fd5"
SOURCE_TREE = "6c45e60db0995416a5bbe5977657a78d5084dcf7"
SOURCE_TREE_SHA256 = "0b2193e30038f4366715986e939645d7851e647c6188b992311639dd7564da3c"
BASE_IMAGE = "eclipse-temurin@sha256:201fbb8886b2d273218aa3a192f0afbf7b5ff65ee8cc6ef47f5dce2171f013ea"
TEST_CLASS = "org.owasp.webgoat.integration.AccessControlIntegrationTest"
SUCCESS_CASE_OUTCOMES = (("testLesson", "pass"),)
NEGATIVE_CONTROL_CASE_OUTCOMES = (("testLesson", "failure"),)
EXECUTION_CONTRACT_LABEL = "webgoat-missing-function-ac-v1"
NEGATIVE_CONTROL_LABEL = "webgoat-missing-function-ac-negative-control-v1"
NEGATIVE_CONTROL_SOURCE_PATH = Path(
    "src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java"
)
NEGATIVE_CONTROL_PATCH_ID = "force-created-user-nonadmin.v1"
NEGATIVE_CONTROL_EXPECTED_EXIT_CODE = 1
RUN_AS = "65532:65532"
MEMORY_BYTES = 4 * 1024 * 1024 * 1024
NANO_CPUS = 2_000_000_000
PIDS_LIMIT = 512
MAX_REPORT_BYTES = 2 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

ADMISSION_BLOCKERS = tuple(
    sorted(
        {
            "evidence_signature_missing",
            "negative_control_missing",
            "registry_evidence_integration_missing",
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
            "registry_evidence_integration_missing",
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


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _load_shared_runtime() -> tuple[Any, str]:
    path = Path(__file__).resolve(strict=True).with_name("replay_l2_webgoat_idor.py")
    raw_before = path.read_bytes()
    name = "k_guard_l2_webgoat_missing_function_ac_shared_runtime"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("shared_runtime_unavailable")
    previous = sys.modules.get(name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    if path.read_bytes() != raw_before:
        raise RuntimeError("shared_runtime_changed_while_loading")
    return module, sha256_bytes(raw_before)


shared, SHARED_RUNTIME_SHA256 = _load_shared_runtime()
RuntimeContractError = shared.RuntimeContractError
if {
    "repository_id": shared.REPOSITORY_ID,
    "commit": shared.SOURCE_COMMIT,
    "commit_tree": shared.SOURCE_TREE,
    "source_tree_sha256": shared.SOURCE_TREE_SHA256,
    "base_image": shared.BASE_IMAGE,
} != {
    "repository_id": REPOSITORY_ID,
    "commit": SOURCE_COMMIT,
    "commit_tree": SOURCE_TREE,
    "source_tree_sha256": SOURCE_TREE_SHA256,
    "base_image": BASE_IMAGE,
}:
    raise RuntimeError("shared_runtime_source_identity_mismatch")


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _source_line_ending(raw: bytes) -> bytes:
    return b"\r\n" if b"\r\n" in raw else b"\n"


def _apply_negative_control_patch(source_root: Path, verifier: Any) -> dict[str, Any]:
    target = source_root / NEGATIVE_CONTROL_SOURCE_PATH
    if not target.is_file():
        raise RuntimeContractError("negative_control_source_missing")
    original = target.read_bytes()
    line_ending = _source_line_ending(original)
    marker = line_ending.join(
        (
            b"  public User addUser(@RequestBody User newUser) {",
            b"    try {",
            b"      userRepository.save(newUser);",
        )
    ) + line_ending
    replacement = line_ending.join(
        (
            b"  public User addUser(@RequestBody User newUser) {",
            b"    try {",
            b"      newUser.setAdmin(false);",
            b"      userRepository.save(newUser);",
        )
    ) + line_ending
    if original.count(marker) != 1:
        raise RuntimeContractError("negative_control_patch_anchor_invalid")
    patched = original.replace(marker, replacement, 1)
    if patched == original:
        raise RuntimeContractError("negative_control_patch_not_applied")
    target.write_bytes(patched)
    variant = verifier.capture_materialized_tree(source_root)
    variant_tree_sha256 = variant.get("tree_sha256")
    if not _is_sha256(variant_tree_sha256) or variant_tree_sha256 == SOURCE_TREE_SHA256:
        raise RuntimeContractError("negative_control_variant_tree_invalid")
    return {
        "patch_id": NEGATIVE_CONTROL_PATCH_ID,
        "source_path": NEGATIVE_CONTROL_SOURCE_PATH.as_posix(),
        "original_file_sha256": sha256_bytes(original),
        "patched_file_sha256": sha256_bytes(patched),
        "patch_sha256": sha256_bytes(replacement),
        "variant_tree_sha256": variant_tree_sha256,
        "source_checkout_mutated": False,
        "raw_returned": False,
    }


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
    if shared._local_name(summary.tag) != "failsafe-summary" or shared._local_name(suite.tag) != "testsuite":
        raise RuntimeContractError("failsafe_report_schema_invalid")
    summary_values = {
        key: shared._safe_int(
            next((child.text for child in summary if shared._local_name(child.tag) == key), None), key
        )
        for key in ("completed", "errors", "failures", "skipped", "flakes")
    }
    if summary.attrib.get("timeout") != "false":
        raise RuntimeContractError("failsafe_timeout_reported")
    suite_values = {
        key: shared._safe_int(suite.attrib.get(key), f"suite_{key}")
        for key in ("tests", "errors", "failures", "skipped", "flakes")
    }
    if suite.attrib.get("name") != TEST_CLASS:
        raise RuntimeContractError("failsafe_suite_mismatch")
    testcases = [child for child in suite if shared._local_name(child.tag) == "testcase"]
    case_outcomes = tuple(
        sorted((str(testcase.attrib.get("name") or ""), shared._testcase_outcome(testcase)) for testcase in testcases)
    )
    if any(not name for name, _outcome in case_outcomes) or len({name for name, _outcome in case_outcomes}) != len(case_outcomes):
        raise RuntimeContractError("failsafe_case_identity_invalid")
    return (
        summary_values,
        suite_values,
        case_outcomes,
        {"summary_sha256": sha256_bytes(summary_raw), "suite_sha256": sha256_bytes(suite_raw)},
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
    if case_outcomes != expected_cases or summary_values != expected_summary or suite_values != expected_suite:
        raise RuntimeContractError("failsafe_expected_outcome_mismatch")
    normalized: dict[str, Any] = {
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
    return normalized, hashes


def normalize_failsafe_reports(summary_path: Path, suite_path: Path) -> tuple[dict[str, Any], dict[str, str]]:
    return _normalize_failsafe_reports(
        summary_path,
        suite_path,
        result_schema=RESULT_SCHEMA,
        expected_summary={"completed": 1, "errors": 0, "failures": 0, "skipped": 0, "flakes": 0},
        expected_suite={"tests": 1, "errors": 0, "failures": 0, "skipped": 0, "flakes": 0},
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
        expected_summary={"completed": 1, "errors": 0, "failures": 1, "skipped": 0, "flakes": 0},
        expected_suite={"tests": 1, "errors": 0, "failures": 1, "skipped": 0, "flakes": 0},
        expected_cases=NEGATIVE_CONTROL_CASE_OUTCOMES,
        control_triggered=True,
    )


def summarize_failsafe_reports(summary_path: Path, suite_path: Path) -> tuple[dict[str, Any], dict[str, str]]:
    summary_values, suite_values, case_outcomes, hashes = _parse_failsafe_reports(summary_path, suite_path)
    return (
        {
            "test_class": TEST_CLASS,
            "failsafe": {**summary_values, "timeout": False},
            "suite": {**suite_values, "testcase_count": len(case_outcomes)},
            "case_outcomes": [{"name": name, "outcome": outcome} for name, outcome in case_outcomes],
            "raw_returned": False,
        },
        hashes,
    )


def _offline_run(
    image_id: str,
    *,
    work_root: Path,
    timeout: int,
    contract_label: str,
    expected_exit_code: int,
    report_normalizer: Any,
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
            volume = shared._docker(
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
            shared._expect_success(volume, "owned_volume_create")
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
        created = shared._docker(create_arguments, cwd=work_root, timeout=60)
        shared._expect_success(created, "offline_container_create")
        try:
            expected_container_id = created.stdout.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise RuntimeContractError("offline_container_id_invalid") from exc
        if re.fullmatch(r"[0-9a-f]{64}", expected_container_id) is None:
            raise RuntimeContractError("offline_container_id_invalid")
        inspected = shared._load_json_stdout(
            shared._docker(["container", "inspect", container_name], cwd=work_root, timeout=60),
            "offline_container_inspect",
        )
        if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
            raise RuntimeContractError("offline_container_inspect_shape")
        isolation = shared._container_isolation(
            inspected[0],
            image_id=image_id,
            cache_volume_name=cache_volume_name,
            report_volume_name=report_volume_name,
            contract_label=contract_label,
        )
        result["isolation"] = isolation
        if not isolation["passed"]:
            raise RuntimeContractError("offline_container_isolation_failed")
        started = shared._docker(["container", "start", "--attach", container_name], cwd=work_root, timeout=timeout)
        result["execution"] = shared._command_receipt(started)
        if started.returncode != expected_exit_code or started.timed_out or started.output_truncated:
            raise RuntimeContractError("offline_test_command_failed")
        post = shared._load_json_stdout(
            shared._docker(["container", "inspect", container_name], cwd=work_root, timeout=60),
            "offline_container_post_inspect",
        )
        if not isinstance(post, list) or len(post) != 1 or not isinstance(post[0], dict):
            raise RuntimeContractError("offline_container_post_shape")
        state = post[0].get("State") if isinstance(post[0].get("State"), dict) else {}
        if state.get("Running") is not False or state.get("ExitCode") != expected_exit_code:
            raise RuntimeContractError("offline_container_exit_state_invalid")
        with tempfile.TemporaryDirectory(prefix="kguard-l2-webgoat-missing-function-ac-report-") as report_root:
            copied = shared._docker(
                ["container", "cp", f"{container_name}:/evidence/failsafe-reports", report_root],
                cwd=work_root,
                timeout=60,
            )
            shared._expect_success(copied, "offline_report_copy")
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
        result["cleanup"] = shared._owned_cleanup(
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


def _claim_boundary() -> dict[str, bool]:
    return {
        "access_control_execution_pair_only": True,
        "generated_control_pair_only": True,
        "independent_upstream_fixed_revision_proven": False,
        "scanner_accuracy_proven": False,
        "severity_or_cwe_admitted": False,
        "tp_fp_fn_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }


def _negative_control_claim_boundary() -> dict[str, bool]:
    return {
        "admin_request_field_suppression_only": True,
        "independent_upstream_fixed_revision_proven": False,
        "scanner_accuracy_proven": False,
        "severity_or_cwe_admitted": False,
        "tp_fp_fn_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }


def _validate_source(source: object) -> None:
    if not isinstance(source, dict):
        raise RuntimeContractError("receipt_source_invalid")
    expected = {
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
    }
    if any(source.get(key) != value for key, value in expected.items()) or not _is_sha256(source.get("source_receipt_sha256")):
        raise RuntimeContractError("receipt_source_invalid")


def _validate_run(run: object, *, negative: bool) -> None:
    if not isinstance(run, dict) or run.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_run_invalid")
    expected_exit = NEGATIVE_CONTROL_EXPECTED_EXIT_CODE if negative else 0
    expected_schema = NEGATIVE_CONTROL_RESULT_SCHEMA if negative else RESULT_SCHEMA
    expected_failsafe = {"completed": 1, "errors": 0, "failures": 1 if negative else 0, "skipped": 0, "flakes": 0}
    expected_suite = {"tests": 1, "errors": 0, "failures": 1 if negative else 0, "skipped": 0, "flakes": 0}
    if (
        not _is_sha256(run.get("run_nonce_sha256"))
        or not isinstance(run.get("image_id"), str)
        or not run["image_id"].startswith("sha256:")
        or run.get("maven_command_sha256") != sha256_bytes(MAVEN_ARGUMENTS.encode("utf-8"))
        or run.get("runtime_command_sha256") != sha256_bytes(RUNTIME_COMMAND.encode("utf-8"))
        or run.get("network_policy") != "none"
        or run.get("expected_exit_code") != expected_exit
        or run.get("failure_code") is not None
        or run.get("passed") is not True
    ):
        raise RuntimeContractError("receipt_run_invalid")
    execution = run.get("execution")
    isolation = run.get("isolation")
    cleanup = run.get("cleanup")
    normalized = run.get("normalized_result")
    report_hashes = run.get("report_hashes")
    if (
        not isinstance(execution, dict)
        or execution.get("returncode") != expected_exit
        or not isinstance(isolation, dict)
        or isolation.get("passed") is not True
        or not isinstance(cleanup, dict)
        or cleanup.get("passed") is not True
        or not isinstance(normalized, dict)
        or normalized.get("schema") != expected_schema
        or normalized.get("test_class") != TEST_CLASS
        or normalized.get("failsafe") != {**expected_failsafe, "timeout": False}
        or not isinstance(normalized.get("suite"), dict)
        or {key: normalized["suite"].get(key) for key in expected_suite} != expected_suite
        or normalized["suite"].get("testcase_count") != 1
        or normalized["suite"].get("all_cases_passed") is not (not negative)
        or not isinstance(report_hashes, dict)
        or set(report_hashes) != {"summary_sha256", "suite_sha256"}
        or any(not _is_sha256(value) for value in report_hashes.values())
        or run.get("observed_result") is not None
    ):
        raise RuntimeContractError("receipt_run_invalid")
    suite_counts = {
        "errors": 0,
        "failures": 1 if negative else 0,
        "skipped": 0,
        "flakes": 0,
    }
    if any(normalized["suite"].get(key) != value for key, value in suite_counts.items()):
        raise RuntimeContractError("receipt_run_invalid")
    if negative:
        if normalized.get("control_triggered") is not True or normalized.get("case_outcomes") != [
            {"name": name, "outcome": outcome} for name, outcome in NEGATIVE_CONTROL_CASE_OUTCOMES
        ]:
            raise RuntimeContractError("receipt_run_invalid")
    elif set(normalized) != {"schema", "test_class", "failsafe", "suite", "raw_returned"}:
        raise RuntimeContractError("receipt_run_invalid")


def _validate_common_receipt(receipt: object, *, negative: bool, positive_reference: dict[str, Any] | None = None) -> None:
    if not isinstance(receipt, dict):
        raise RuntimeContractError("receipt_schema_invalid")
    if negative:
        required = {
            "schema", "tool_provenance", "source", "positive_execution_contract", "negative_control", "image", "runs", "consensus", "image_cleanup", "claim_boundary", "admission_blockers", "negative_control_status", "release_gate_passed", "failure_code", "raw_returned"
        }
        expected_schema = NEGATIVE_CONTROL_SCHEMA
        expected_status = "NEGATIVE_CONTROL_PASS"
        expected_boundary = _negative_control_claim_boundary()
        expected_blockers = NEGATIVE_CONTROL_ADMISSION_BLOCKERS
    else:
        required = {
            "schema", "tool_provenance", "source", "image", "runs", "consensus", "image_cleanup", "claim_boundary", "admission_blockers", "execution_contract_status", "release_gate_passed", "failure_code", "raw_returned"
        }
        expected_schema = SCHEMA
        expected_status = "EXECUTION_CONTRACT_PASS"
        expected_boundary = _claim_boundary()
        expected_blockers = ADMISSION_BLOCKERS
    if set(receipt) != required or receipt.get("schema") != expected_schema or receipt.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_schema_invalid")
    provenance = receipt.get("tool_provenance")
    if not isinstance(provenance, dict) or provenance != {
        "runner_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "shared_runtime_sha256": SHARED_RUNTIME_SHA256,
        "base_image": BASE_IMAGE,
        "raw_returned": False,
    }:
        raise RuntimeContractError("receipt_provenance_invalid")
    _validate_source(receipt.get("source"))
    if receipt.get("claim_boundary") != expected_boundary or receipt.get("release_gate_passed") is not False:
        raise RuntimeContractError("receipt_claim_boundary_invalid")
    blockers = receipt.get("admission_blockers")
    if not isinstance(blockers, list) or tuple(blockers) != expected_blockers:
        raise RuntimeContractError("receipt_admission_blockers_invalid")
    status_key = "negative_control_status" if negative else "execution_contract_status"
    status = receipt.get(status_key)
    if status not in {expected_status, "HOLD"}:
        raise RuntimeContractError("receipt_status_invalid")
    if status == "HOLD":
        failure = receipt.get("failure_code")
        if failure is not None and (not isinstance(failure, str) or not failure):
            raise RuntimeContractError("receipt_hold_failure_invalid")
        return
    image = receipt.get("image")
    if not isinstance(image, dict) or image.get("base_image") != BASE_IMAGE or image.get("source_derived") is not True or image.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_image_invalid")
    if negative:
        control = receipt.get("negative_control")
        if not isinstance(control, dict) or set(control) != {
            "patch_id", "source_path", "original_file_sha256", "patched_file_sha256", "patch_sha256", "variant_tree_sha256", "source_checkout_mutated", "raw_returned"
        }:
            raise RuntimeContractError("negative_control_patch_invalid")
        if (
            control.get("patch_id") != NEGATIVE_CONTROL_PATCH_ID
            or control.get("source_path") != NEGATIVE_CONTROL_SOURCE_PATH.as_posix()
            or control.get("source_checkout_mutated") is not False
            or control.get("raw_returned") is not False
            or any(not _is_sha256(control.get(key)) for key in ("original_file_sha256", "patched_file_sha256", "patch_sha256", "variant_tree_sha256"))
            or control.get("original_file_sha256") == control.get("patched_file_sha256")
            or control.get("variant_tree_sha256") == SOURCE_TREE_SHA256
            or image.get("source_variant") != control
        ):
            raise RuntimeContractError("negative_control_patch_invalid")
        positive = receipt.get("positive_execution_contract")
        if not isinstance(positive, dict) or set(positive) != {"receipt_sha256", "source_receipt_sha256", "execution_contract_status", "raw_returned"}:
            raise RuntimeContractError("negative_control_positive_reference_invalid")
        if (
            not _is_sha256(positive.get("receipt_sha256"))
            or not _is_sha256(positive.get("source_receipt_sha256"))
            or positive.get("execution_contract_status") != "EXECUTION_CONTRACT_PASS"
            or positive.get("raw_returned") is not False
            or positive["source_receipt_sha256"] != receipt["source"]["source_receipt_sha256"]
        ):
            raise RuntimeContractError("negative_control_positive_reference_invalid")
        if positive_reference is not None and positive != positive_reference:
            raise RuntimeContractError("negative_control_positive_reference_invalid")
    runs = receipt.get("runs")
    consensus = receipt.get("consensus")
    if not isinstance(runs, list) or len(runs) != 2 or not isinstance(consensus, dict):
        raise RuntimeContractError("receipt_run_shape_invalid")
    for run in runs:
        _validate_run(run, negative=negative)
    nonces = [run["run_nonce_sha256"] for run in runs]
    projections = [_consensus_projection(run) for run in runs]
    if len(set(nonces)) != 2 or projections[0] != projections[1]:
        raise RuntimeContractError("receipt_consensus_invalid")
    if consensus != {
        "run_count": 2,
        "two_runs_byte_equivalent_after_normalization": True,
        "projection_sha256": _canonical_sha256(projections),
        "raw_returned": False,
    }:
        raise RuntimeContractError("receipt_consensus_invalid")
    cleanup = receipt.get("image_cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("passed") is not True:
        raise RuntimeContractError("receipt_image_cleanup_invalid")
    if receipt.get("failure_code") is not None:
        raise RuntimeContractError("receipt_pass_with_failure")


def validate_receipt(receipt: dict[str, Any]) -> None:
    _validate_common_receipt(receipt, negative=False)


def validate_negative_control_receipt(
    receipt: dict[str, Any], *, positive_reference: dict[str, Any] | None = None
) -> None:
    _validate_common_receipt(receipt, negative=True, positive_reference=positive_reference)


def execute_contract(source_root: Path, *, timeout: int) -> dict[str, Any]:
    source, verifier, verifier_sha256 = shared.verify_source_workspace(source_root.resolve())
    image: dict[str, Any] | None = None
    image_id: str | None = None
    image_cleanup: dict[str, Any] | None = None
    runs: list[dict[str, Any]] = []
    failure: str | None = None
    with tempfile.TemporaryDirectory(prefix="kguard-l2-webgoat-missing-function-ac-") as temporary:
        work_root = Path(temporary)
        try:
            image, image_id, _tag, _source_variant = shared._build_source_derived_image(
                source_root.resolve(),
                verifier,
                work_root=work_root,
                timeout=timeout,
                dockerfile_template=DOCKERFILE_TEMPLATE,
                contract_label=EXECUTION_CONTRACT_LABEL,
            )
            runs = [
                _offline_run(
                    image_id,
                    work_root=work_root,
                    timeout=timeout,
                    contract_label=EXECUTION_CONTRACT_LABEL,
                    expected_exit_code=0,
                    report_normalizer=normalize_failsafe_reports,
                )
                for _ in range(2)
            ]
        except RuntimeContractError as exc:
            failure = str(exc)
        finally:
            if image_id is not None:
                image_cleanup = shared._cleanup_image(
                    image_id, work_root=work_root, contract_label=EXECUTION_CONTRACT_LABEL
                )
    projections = [_consensus_projection(run) for run in runs]
    consensus_passed = len(projections) == 2 and projections[0] == projections[1] and all(run.get("passed") is True for run in runs)
    status = (
        "EXECUTION_CONTRACT_PASS"
        if failure is None and image is not None and image_cleanup is not None and image_cleanup.get("passed") is True and consensus_passed
        else "HOLD"
    )
    receipt = {
        "schema": SCHEMA,
        "tool_provenance": {
            "runner_sha256": sha256_bytes(Path(__file__).read_bytes()),
            "shared_runtime_sha256": SHARED_RUNTIME_SHA256,
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


def _load_positive_execution_contract(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        receipt = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError("positive_execution_receipt_unreadable") from exc
    if not isinstance(receipt, dict) or canonical_json_bytes(receipt) != raw:
        raise RuntimeContractError("positive_execution_receipt_not_canonical")
    validate_receipt(receipt)
    if receipt.get("execution_contract_status") != "EXECUTION_CONTRACT_PASS":
        raise RuntimeContractError("positive_execution_contract_not_passed")
    source = receipt["source"]
    return {
        "receipt_sha256": sha256_bytes(raw),
        "source_receipt_sha256": source["source_receipt_sha256"],
        "execution_contract_status": "EXECUTION_CONTRACT_PASS",
        "raw_returned": False,
    }


def execute_negative_control(source_root: Path, *, positive_receipt_path: Path, timeout: int) -> dict[str, Any]:
    positive = _load_positive_execution_contract(positive_receipt_path)
    source, verifier, verifier_sha256 = shared.verify_source_workspace(source_root.resolve())
    if source["source_receipt_sha256"] != positive["source_receipt_sha256"]:
        raise RuntimeContractError("positive_execution_source_receipt_mismatch")
    image: dict[str, Any] | None = None
    image_id: str | None = None
    source_variant: dict[str, Any] | None = None
    image_cleanup: dict[str, Any] | None = None
    runs: list[dict[str, Any]] = []
    failure: str | None = None
    with tempfile.TemporaryDirectory(prefix="kguard-l2-webgoat-missing-function-ac-negative-control-") as temporary:
        work_root = Path(temporary)
        try:
            image, image_id, _tag, source_variant = shared._build_source_derived_image(
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
                image_cleanup = shared._cleanup_image(
                    image_id, work_root=work_root, contract_label=NEGATIVE_CONTROL_LABEL
                )
    projections = [_consensus_projection(run) for run in runs]
    consensus_passed = len(projections) == 2 and projections[0] == projections[1] and all(run.get("passed") is True for run in runs)
    status = (
        "NEGATIVE_CONTROL_PASS"
        if failure is None and image is not None and source_variant is not None and image_cleanup is not None and image_cleanup.get("passed") is True and consensus_passed
        else "HOLD"
    )
    receipt = {
        "schema": NEGATIVE_CONTROL_SCHEMA,
        "tool_provenance": {
            "runner_sha256": sha256_bytes(Path(__file__).read_bytes()),
            "shared_runtime_sha256": SHARED_RUNTIME_SHA256,
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
    validate_negative_control_receipt(receipt, positive_reference=positive)
    return receipt


def _write_new_output(path: Path, receipt: dict[str, Any]) -> None:
    if path.exists():
        raise RuntimeContractError("output_already_exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(receipt))


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replay the WebGoat missing-function access-control execution contract without admitting scanner accuracy."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--source-root", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--timeout-seconds", type=int, default=900)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--receipt", type=Path, required=True)
    negative = subparsers.add_parser("negative-control")
    negative.add_argument("--source-root", type=Path, required=True)
    negative.add_argument("--positive-receipt", type=Path, required=True)
    negative.add_argument("--output", type=Path, required=True)
    negative.add_argument("--timeout-seconds", type=int, default=900)
    verify_negative = subparsers.add_parser("verify-negative-control")
    verify_negative.add_argument("--receipt", type=Path, required=True)
    verify_negative.add_argument("--positive-receipt", type=Path, required=True)
    args = parser.parse_args(list(argv) if argv is not None else None)
    if getattr(args, "timeout_seconds", 60) < 60 or getattr(args, "timeout_seconds", 1800) > 1800:
        raise SystemExit("HOLD: timeout_seconds_out_of_range")
    try:
        if args.command == "verify":
            raw = args.receipt.read_bytes()
            receipt = json.loads(raw.decode("utf-8"))
            if not isinstance(receipt, dict) or canonical_json_bytes(receipt) != raw:
                raise RuntimeContractError("receipt_not_canonical")
            validate_receipt(receipt)
            return 0
        if args.command == "verify-negative-control":
            raw = args.receipt.read_bytes()
            receipt = json.loads(raw.decode("utf-8"))
            if not isinstance(receipt, dict) or canonical_json_bytes(receipt) != raw:
                raise RuntimeContractError("negative_control_receipt_not_canonical")
            positive = _load_positive_execution_contract(args.positive_receipt)
            validate_negative_control_receipt(receipt, positive_reference=positive)
            return 0
        if args.command == "run":
            receipt = execute_contract(args.source_root, timeout=args.timeout_seconds)
            _write_new_output(args.output, receipt)
            return 0 if receipt["execution_contract_status"] == "EXECUTION_CONTRACT_PASS" else 2
        receipt = execute_negative_control(
            args.source_root,
            positive_receipt_path=args.positive_receipt,
            timeout=args.timeout_seconds,
        )
        _write_new_output(args.output, receipt)
        return 0 if receipt["negative_control_status"] == "NEGATIVE_CONTROL_PASS" else 2
    except (OSError, UnicodeError, json.JSONDecodeError, RuntimeContractError) as exc:
        raise SystemExit(f"HOLD: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
