from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
SOURCE_VERIFIER_PATH = REPOSITORY_ROOT / "scripts" / "holdout_source_materialization.py"

SCHEMA = "k_guard_l2_wrongsecrets_challenge1_execution_contract.v1"
NEGATIVE_CONTROL_SCHEMA = "k_guard_l2_wrongsecrets_challenge1_negative_control.v1"
DRIVER_RESULT_SCHEMA = "k_guard_l2_wrongsecrets_challenge1_javac_driver_result.v1"

APP_ID = "wrongsecrets"
REPOSITORY_ID = "owasp/wrongsecrets"
SOURCE_COMMIT = "25bdda3c380c7b16bdd2a528c9fff3700fa2b801"
SOURCE_TREE = "4946781597334bc73adb26d97d84f2677264f9d1"
SOURCE_TREE_SHA256 = "9b85876c204c995d056206a292ba45e48731ce2a71124fc5e43f4cdea6eeff80"
P23A_OBSERVED_RECEIPT_SHA256 = (
    "a88dd137d957a2e2fb5ad01841369ee0fc2b5161c29d77c4d5087b4ff4bb4904"
)
P23A_APP_RECEIPT_SHA256 = (
    "58509e4ad992c66e1b230a66d9f7e18c6c080aea07fb110e07b08d4295455485"
)
P23A_APP_SEMANTIC_SHA256 = (
    "06f9b90faa43039cd5093b577fb63f98d855134e852ab35bc40c331d423c2bba"
)

TEST_CLASS = "org.owasp.wrongsecrets.challenges.docker.Challenge1Test"
TEST_METHOD = "rightAnswerShouldSolveChallenge"
TEST_SELECTOR = f"{TEST_CLASS}#{TEST_METHOD}"
TEST_REPORT = "target/surefire-reports/TEST-org.owasp.wrongsecrets.challenges.docker.Challenge1Test.xml"

BASE_IMAGE_REF = (
    "eclipse-temurin@sha256:201fbb8886b2d273218aa3a192f0afbf7b5ff65ee8cc6ef47f5dce2171f013ea"
)
BASE_IMAGE_ID = "sha256:201fbb8886b2d273218aa3a192f0afbf7b5ff65ee8cc6ef47f5dce2171f013ea"
EXPECTED_JAVA_VERSION = "jdk-25.0.3+9"

SOURCE_FILES = {
    "src/main/java/org/owasp/wrongsecrets/challenges/docker/Challenge1.java": (
        "c14a5c0b8fb931fb8e41d22277b0e1cf4ea905331fe3a1f24e7f19303abc0c51"
    ),
    "src/main/java/org/owasp/wrongsecrets/challenges/docker/WrongSecretsConstants.java": (
        "1b14d121a856828be326fa9b6551bd196d1414ea85e4e083cea467846272f808"
    ),
    "src/main/java/org/owasp/wrongsecrets/challenges/FixedAnswerChallenge.java": (
        "d33d249e8ca8850397380bc810fe99070bd51aae4aaad0607c06c67770e0b75e"
    ),
    "src/main/java/org/owasp/wrongsecrets/challenges/Challenge.java": (
        "b82b7e4be7b12dd4e4e9a3348ad44e90872a41e4a74b6bc227c24863dc272bc3"
    ),
    "src/main/java/org/owasp/wrongsecrets/challenges/Spoiler.java": (
        "326d64703cbc9b564b507fbb095d6bd9a88e7eba3afaf34e4a09dbcc485230d0"
    ),
    "src/test/java/org/owasp/wrongsecrets/challenges/docker/Challenge1Test.java": (
        "25a4a7c2bbb5beea0d8a41187da761e9055906b35043a59e25909d7f13f7bbad"
    ),
    "pom.xml": "aabd5452b4338823a29f86749c0da16f9d8df5ee867951c27c8ae68a8546ae50",
    "mvnw": "cae96cef89ebea3531221f4ae17c23cf8edf67d00eae8306d4186ae1bbed4d02",
    ".mvn/wrapper/maven-wrapper.properties": (
        "11cac19f3e77912a89bab9663fef29068d6aaad3776382909f41cd91766005be"
    ),
    "LICENSE": "a3c8862ad142ce7c8a915663dc397c2fb56bbc61a1d1ba9dfebb55b0931c37d6",
}

PATCH_ANCHOR = b"return WrongSecretsConstants.password;"
PATCH_REPLACEMENT = b'return "";'
NEGATIVE_PATCH_ID = "challenge1-answer-empty-derived-control.v1"
EXECUTION_CONTRACT_LABEL = "wrongsecrets-challenge1-process-v1"
NEGATIVE_CONTROL_LABEL = "wrongsecrets-challenge1-negative-control-v1"

APP_USER = "10001:10001"
APP_MEMORY_BYTES = 2 * 1024 * 1024 * 1024
APP_NANO_CPUS = 2_000_000_000
APP_PIDS_LIMIT = 256
APP_TMPFS = {
    "/tmp": "rw,noexec,nosuid,nodev,size=67108864,uid=10001,gid=10001,mode=0700",
    "/workspace/out": (
        "rw,noexec,nosuid,nodev,size=67108864,uid=10001,gid=10001,mode=0700"
    ),
}
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DRIVER_MARKER = "K_GUARD_WRONGSECRETS_CHALLENGE1_RESULT:"

ADMISSION_BLOCKERS = tuple(
    sorted(
        {
            "detector_finding_mapping_missing",
            "independent_upstream_fixed_revision_missing",
            "runtime_supply_chain_provenance_missing",
            "source_bound_severity_rubric_missing",
            "third_party_stub_semantics_not_generalized",
            "upstream_junit_execution_missing",
        }
    )
)


class RuntimeContractError(RuntimeError):
    """A fail-closed violation of the narrow execution-oracle contract."""


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


def _runner_sha256() -> str:
    return sha256_bytes(Path(__file__).read_bytes())


def _command_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "CI": "true",
            "DOCKER_CLI_HINTS": "false",
            "NO_COLOR": "1",
        }
    )
    return environment


def _run_bounded(
    argv: list[str],
    *,
    cwd: Path,
    timeout: int,
    input_bytes: bytes | None = None,
) -> CommandResult:
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd),
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            env=_command_environment(),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or b""
        stderr = exc.stderr or b""
        output_truncated = len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES
        return CommandResult(
            returncode=-1,
            stdout=stdout[:MAX_OUTPUT_BYTES],
            stderr=stderr[:MAX_OUTPUT_BYTES],
            timed_out=True,
            output_truncated=output_truncated,
        )
    output_truncated = (
        len(completed.stdout) > MAX_OUTPUT_BYTES or len(completed.stderr) > MAX_OUTPUT_BYTES
    )
    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout[:MAX_OUTPUT_BYTES],
        stderr=completed.stderr[:MAX_OUTPUT_BYTES],
        timed_out=False,
        output_truncated=output_truncated,
    )


def _docker(
    arguments: list[str], *, cwd: Path, timeout: int, input_bytes: bytes | None = None
) -> CommandResult:
    return _run_bounded(["docker", *arguments], cwd=cwd, timeout=timeout, input_bytes=input_bytes)


def _expect_success(result: CommandResult, label: str) -> None:
    if result.timed_out:
        raise RuntimeContractError(f"{label}_timed_out")
    if result.output_truncated:
        raise RuntimeContractError(f"{label}_output_truncated")
    if result.returncode != 0:
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
    before = SOURCE_VERIFIER_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location(
        "k_guard_l2_wrongsecrets_source_verifier", SOURCE_VERIFIER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeContractError("source_verifier_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if SOURCE_VERIFIER_PATH.read_bytes() != before:
        raise RuntimeContractError("source_verifier_changed_while_loading")
    return module, sha256_bytes(before)


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
    required_registry = {
        "schema": "k_guard_l2_source_materialization.v3",
        "seed_sha256": "95f48fd53d3d411be9dbaa7b78a130a893d1fbf87bbc92f7ce40f1d6dbaf2fef",
        "expected_app_count": 6,
        "materialized_app_count": 6,
        "source_license_admission": "PASS",
        "raw_returned": False,
    }
    if any(registry.get(key) != value for key, value in required_registry.items()):
        raise RuntimeContractError("p23a_registry_contract_invalid")
    apps = registry.get("apps")
    if not isinstance(apps, list):
        raise RuntimeContractError("p23a_registry_apps_invalid")
    candidates = [item for item in apps if isinstance(item, dict) and item.get("app_id") == APP_ID]
    if len(candidates) != 1:
        raise RuntimeContractError("p23a_registry_wrongsecrets_missing")
    app = candidates[0]
    required_app = {
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
        "observed_receipt_sha256": P23A_OBSERVED_RECEIPT_SHA256,
        "receipt_sha256": P23A_APP_RECEIPT_SHA256,
        "receipt_semantic_sha256": P23A_APP_SEMANTIC_SHA256,
        "source_license_admission": "PASS",
        "scanner_output_observed": False,
        "oracle_gate_status": "HOLD",
        "oracle_missing": True,
    }
    if any(app.get(key) != value for key, value in required_app.items()):
        raise RuntimeContractError("p23a_registry_wrongsecrets_binding_invalid")
    return app, sha256_bytes(raw)


def _source_projection(
    receipt: Mapping[str, Any], *, p23a_app: Mapping[str, Any], p23a_registry_sha256: str
) -> dict[str, Any]:
    identity = {
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
    }
    if any(receipt.get(key) != value for key, value in identity.items()):
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
        **identity,
        "p23a_registry_sha256": p23a_registry_sha256,
        "p23a_observed_receipt_sha256": P23A_OBSERVED_RECEIPT_SHA256,
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
    return (
        _source_projection(receipt, p23a_app=p23a_app, p23a_registry_sha256=p23a_registry_sha256),
        verifier,
        verifier_sha256,
    )


def _safe_source_file(source_root: Path, relative: str) -> Path:
    if not relative or "\\" in relative or relative.startswith("/") or ".." in Path(relative).parts:
        raise RuntimeContractError("source_relative_path_invalid")
    root = source_root.resolve(strict=True)
    path = (root / Path(relative)).resolve(strict=True)
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise RuntimeContractError("source_relative_path_escape") from exc
    if not path.is_file() or path.is_symlink():
        raise RuntimeContractError("source_file_invalid")
    return path


def _read_source_files(source_root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for relative, expected_sha256 in SOURCE_FILES.items():
        raw = _safe_source_file(source_root, relative).read_bytes()
        if sha256_bytes(raw) != expected_sha256:
            raise RuntimeContractError("source_file_hash_mismatch")
        files[relative] = raw
    return files


def _verify_base_image(*, work_root: Path) -> dict[str, Any]:
    image = _load_json_stdout(
        _docker(["image", "inspect", BASE_IMAGE_REF, "--format", "{{json .}}"], cwd=work_root, timeout=30),
        "base_image_inspect",
    )
    if not isinstance(image, dict):
        raise RuntimeContractError("base_image_shape_invalid")
    if image.get("Id") != BASE_IMAGE_ID:
        raise RuntimeContractError("base_image_id_mismatch")
    digests = image.get("RepoDigests")
    config = image.get("Config")
    if not isinstance(digests, list) or BASE_IMAGE_REF not in digests or not isinstance(config, dict):
        raise RuntimeContractError("base_image_digest_missing")
    environment = config.get("Env")
    if not isinstance(environment, list) or f"JAVA_VERSION={EXPECTED_JAVA_VERSION}" not in environment:
        raise RuntimeContractError("base_image_java_version_mismatch")
    return {
        "reference": BASE_IMAGE_REF,
        "image_id": BASE_IMAGE_ID,
        "java_version": EXPECTED_JAVA_VERSION,
        "raw_returned": False,
    }


def _harness_sources() -> dict[str, bytes]:
    return {
        "com/google/common/base/Supplier.java": b"""package com.google.common.base;
public interface Supplier<T> { T get(); }
""",
        "com/google/common/base/Suppliers.java": b"""package com.google.common.base;
public final class Suppliers {
  private Suppliers() {}
  public static <T> Supplier<T> memoize(Supplier<T> delegate) {
    return new Supplier<T>() {
      private boolean initialized;
      private T value;
      public synchronized T get() {
        if (!initialized) { value = delegate.get(); initialized = true; }
        return value;
      }
    };
  }
}
""",
        "org/springframework/stereotype/Component.java": b"""package org.springframework.stereotype;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface Component {}
""",
        "lombok/experimental/UtilityClass.java": b"""package lombok.experimental;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.TYPE)
public @interface UtilityClass {}
""",
        "kguard/Challenge1Harness.java": f"""package kguard;
import org.owasp.wrongsecrets.challenges.docker.Challenge1;
import org.owasp.wrongsecrets.challenges.docker.WrongSecretsConstants;
public final class Challenge1Harness {{
  private static final String MARKER = \"{DRIVER_MARKER}\";
  private Challenge1Harness() {{}}
  public static void main(String[] args) {{
    boolean matches = new Challenge1().answerCorrect(WrongSecretsConstants.password);
    System.out.println(MARKER + \"{{\\\"schema\\\":\\\"{DRIVER_RESULT_SCHEMA}\\\",\\\"answer_matches_source_constant\\\":\" + matches + \",\\\"raw_returned\\\":false}}\");
  }}
}}
""".encode("utf-8"),
    }


def _harness_source_hashes() -> dict[str, str]:
    return {relative: sha256_bytes(raw) for relative, raw in _harness_sources().items()}


def _dockerfile_template() -> str:
    return f"""FROM {BASE_IMAGE_REF}
ARG TARGET_UID=10001
RUN useradd --create-home --uid ${{TARGET_UID}} --shell /bin/bash kguard
WORKDIR /workspace
COPY --chown=10001:10001 source/ /workspace/source/
COPY --chown=10001:10001 harness/ /workspace/harness/
RUN mkdir -p /workspace/classes /workspace/out && \\
    javac -d /workspace/classes \\
      /workspace/harness/com/google/common/base/Supplier.java \\
      /workspace/harness/com/google/common/base/Suppliers.java \\
      /workspace/harness/org/springframework/stereotype/Component.java \\
      /workspace/harness/lombok/experimental/UtilityClass.java \\
      /workspace/source/src/main/java/org/owasp/wrongsecrets/challenges/Challenge.java \\
      /workspace/source/src/main/java/org/owasp/wrongsecrets/challenges/Spoiler.java \\
      /workspace/source/src/main/java/org/owasp/wrongsecrets/challenges/FixedAnswerChallenge.java \\
      /workspace/source/src/main/java/org/owasp/wrongsecrets/challenges/docker/WrongSecretsConstants.java \\
      /workspace/source/src/main/java/org/owasp/wrongsecrets/challenges/docker/Challenge1.java \\
      /workspace/harness/kguard/Challenge1Harness.java && \\
    chown -R 10001:10001 /workspace/classes /workspace/out
USER 10001:10001
ENV HOME=/tmp
"""


def _staged_source_hashes(staged_source: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for relative, expected_sha256 in SOURCE_FILES.items():
        raw = _safe_source_file(staged_source, relative).read_bytes()
        actual = sha256_bytes(raw)
        if relative != "src/main/java/org/owasp/wrongsecrets/challenges/docker/Challenge1.java":
            if actual != expected_sha256:
                raise RuntimeContractError("staged_source_file_hash_mismatch")
        result[relative] = actual
    return result


def _negative_challenge_patch(raw: bytes) -> tuple[bytes, dict[str, Any]]:
    count = raw.count(PATCH_ANCHOR)
    if count != 1:
        raise RuntimeContractError("negative_patch_anchor_ambiguous")
    patched = raw.replace(PATCH_ANCHOR, PATCH_REPLACEMENT, 1)
    if patched == raw or patched.count(PATCH_ANCHOR) != 0:
        raise RuntimeContractError("negative_patch_not_applied")
    return patched, {
        "patch_id": NEGATIVE_PATCH_ID,
        "anchor_count": count,
        "source_sha256": sha256_bytes(raw),
        "derived_sha256": sha256_bytes(patched),
        "raw_returned": False,
    }


def _copy_source_context(source_root: Path, *, variant: str, temporary_root: Path) -> tuple[Path, dict[str, Any]]:
    if variant not in {"positive", "negative"}:
        raise RuntimeContractError("execution_variant_invalid")
    context_root = temporary_root / "context"
    source_target = context_root / "source"
    source_target.mkdir(parents=True, exist_ok=False)
    for relative in SOURCE_FILES:
        original = _safe_source_file(source_root, relative)
        destination = source_target / Path(relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, destination)
    harness_target = context_root / "harness"
    harness_sources = _harness_sources()
    for relative, raw in harness_sources.items():
        destination = harness_target / Path(relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    source_path = _safe_source_file(
        source_target, "src/main/java/org/owasp/wrongsecrets/challenges/docker/Challenge1.java"
    )
    original = source_path.read_bytes()
    patch: dict[str, Any] | None = None
    if variant == "negative":
        patched, patch = _negative_challenge_patch(original)
        source_path.write_bytes(patched)
    staged_hashes = _staged_source_hashes(source_target)
    expected_challenge = SOURCE_FILES[
        "src/main/java/org/owasp/wrongsecrets/challenges/docker/Challenge1.java"
    ]
    if variant == "positive" and staged_hashes[
        "src/main/java/org/owasp/wrongsecrets/challenges/docker/Challenge1.java"
    ] != expected_challenge:
        raise RuntimeContractError("positive_staged_source_hash_mismatch")
    if variant == "negative":
        if patch is None or patch["source_sha256"] != expected_challenge:
            raise RuntimeContractError("negative_patch_source_binding_invalid")
        if staged_hashes[
            "src/main/java/org/owasp/wrongsecrets/challenges/docker/Challenge1.java"
        ] != patch["derived_sha256"]:
            raise RuntimeContractError("negative_patch_derivative_binding_invalid")
    harness_hashes = _harness_source_hashes()
    if any(sha256_bytes((harness_target / Path(relative)).read_bytes()) != digest for relative, digest in harness_hashes.items()):
        raise RuntimeContractError("harness_source_hash_mismatch")
    return context_root, {
        "variant": variant,
        "relevant_file_sha256": staged_hashes,
        "negative_patch": patch,
        "harness_source_sha256": harness_hashes,
        "raw_returned": False,
    }


def _build_contract_sha256(
    *, variant: str, source: Mapping[str, Any], base_image: Mapping[str, Any], staged: Mapping[str, Any]
) -> tuple[str, str]:
    dockerfile_sha256 = sha256_bytes(_dockerfile_template().encode("utf-8"))
    contract = {
        "schema": "k_guard_l2_wrongsecrets_challenge1_image_contract.v1",
        "variant": variant,
        "source": {
            key: source[key]
            for key in (
                "repository_id",
                "commit",
                "commit_tree",
                "source_tree_sha256",
                "current_source_receipt_sha256",
            )
        },
        "base_image": base_image,
        "relevant_file_sha256": staged["relevant_file_sha256"],
        "negative_patch": staged["negative_patch"],
        "harness_source_sha256": staged["harness_source_sha256"],
        "dockerfile_sha256": dockerfile_sha256,
        "toolchain": "javac_jdk25_source_closure",
        "raw_returned": False,
    }
    return _canonical_sha256(contract), dockerfile_sha256


def _read_image(image_reference: str, *, work_root: Path) -> dict[str, Any]:
    image = _load_json_stdout(
        _docker(["image", "inspect", image_reference, "--format", "{{json .}}"], cwd=work_root, timeout=30),
        "replay_image_inspect",
    )
    if not isinstance(image, dict):
        raise RuntimeContractError("replay_image_shape_invalid")
    return image


def _build_replay_image(
    *,
    source_root: Path,
    source: Mapping[str, Any],
    base_image: Mapping[str, Any],
    variant: str,
    work_root: Path,
    timeout: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="kguard-wrongsecrets-build-") as temporary:
        context_root, staged = _copy_source_context(
            source_root, variant=variant, temporary_root=Path(temporary)
        )
        contract_sha256, dockerfile_sha256 = _build_contract_sha256(
            variant=variant, source=source, base_image=base_image, staged=staged
        )
        tag = f"kguard-l2/wrongsecrets-challenge1:{contract_sha256[:16]}-{variant}"
        labels = {
            "kguard.execution.contract": EXECUTION_CONTRACT_LABEL,
            "kguard.execution.variant": variant,
            "kguard.execution.contract-sha256": contract_sha256,
            "kguard.source.repository": REPOSITORY_ID,
            "kguard.source.commit": SOURCE_COMMIT,
            "kguard.source.tree": SOURCE_TREE,
            "kguard.source.tree-sha256": SOURCE_TREE_SHA256,
            "kguard.source.dockerfile-sha256": dockerfile_sha256,
        }
        arguments = [
            "build",
            "--pull=false",
            "--network=none",
            "--progress=quiet",
            "--tag",
            tag,
        ]
        for key, value in sorted(labels.items()):
            arguments.extend(["--label", f"{key}={value}"])
        arguments.extend(["--file", "-", str(context_root)])
        result = _docker(
            arguments,
            cwd=work_root,
            timeout=timeout,
            input_bytes=_dockerfile_template().encode("utf-8"),
        )
        _expect_success(result, "replay_image_build")
        image = _read_image(tag, work_root=work_root)
        image_id = image.get("Id")
        config = image.get("Config")
        actual_labels = config.get("Labels") if isinstance(config, dict) else None
        if not isinstance(image_id, str) or not IMAGE_ID_RE.fullmatch(image_id):
            raise RuntimeContractError("replay_image_id_invalid")
        if not isinstance(actual_labels, dict) or any(actual_labels.get(key) != value for key, value in labels.items()):
            raise RuntimeContractError("replay_image_label_mismatch")
        image_receipt = {
            "image_id": image_id,
            "contract_label": EXECUTION_CONTRACT_LABEL,
            "variant": variant,
            "contract_sha256": contract_sha256,
            "dockerfile_sha256": dockerfile_sha256,
            "source_derived": True,
            "build_network": "none",
            "fresh_source_compile_proven": True,
            "runtime_supply_chain_proven": False,
            "build_command": _command_receipt(result),
            "staged_source": staged,
            "raw_returned": False,
        }
        return image_receipt, {"tag": tag, "image_id": image_id, "labels": labels}


def _container_id(result: CommandResult, label: str) -> str:
    _expect_success(result, label)
    value = result.stdout.decode("ascii", errors="ignore").strip()
    if not re.fullmatch(r"[0-9a-f]{12,64}", value):
        raise RuntimeContractError(f"{label}_id_invalid")
    return value


def _inspect_container(container_id: str, *, work_root: Path) -> dict[str, Any]:
    value = _load_json_stdout(
        _docker(["container", "inspect", container_id, "--format", "{{json .}}"], cwd=work_root, timeout=30),
        "container_inspect",
    )
    if not isinstance(value, dict):
        raise RuntimeContractError("container_inspect_shape_invalid")
    return value


def _tmpfs_matches(actual: object, expected: Mapping[str, str]) -> bool:
    if not isinstance(actual, dict) or set(actual) != set(expected):
        return False
    return all(actual.get(path) == options for path, options in expected.items())


def _container_isolation(inspect: Mapping[str, Any]) -> dict[str, Any]:
    host = inspect.get("HostConfig")
    config = inspect.get("Config")
    network = inspect.get("NetworkSettings")
    mounts = inspect.get("Mounts")
    if not all(isinstance(value, Mapping) for value in (host, config, network)) or not isinstance(mounts, list):
        return {"passed": False, "raw_returned": False}
    port_bindings = host.get("PortBindings")
    ports = network.get("Ports")
    no_host_port = port_bindings in ({}, None) and (ports in ({}, None) or all(value is None for value in ports.values()))
    cap_drop = host.get("CapDrop")
    security_opt = host.get("SecurityOpt")
    passed = (
        host.get("ReadonlyRootfs") is True
        and host.get("Privileged") is False
        and host.get("NetworkMode") == "none"
        and config.get("User") == APP_USER
        and isinstance(cap_drop, list)
        and "ALL" in cap_drop
        and isinstance(security_opt, list)
        and "no-new-privileges=true" in security_opt
        and host.get("Memory") == APP_MEMORY_BYTES
        and host.get("NanoCpus") == APP_NANO_CPUS
        and host.get("PidsLimit") == APP_PIDS_LIMIT
        and _tmpfs_matches(host.get("Tmpfs"), APP_TMPFS)
        and no_host_port
        and host.get("Binds") in (None, [])
        and not mounts
    )
    return {
        "passed": passed,
        "read_only_root": host.get("ReadonlyRootfs") is True,
        "non_root_user": config.get("User") == APP_USER,
        "cap_drop_all": isinstance(cap_drop, list) and "ALL" in cap_drop,
        "no_new_privileges": isinstance(security_opt, list) and "no-new-privileges=true" in security_opt,
        "network_none": host.get("NetworkMode") == "none",
        "no_host_port": no_host_port,
        "no_bind_or_volume_mount": host.get("Binds") in (None, []) and not mounts,
        "tmpfs_contract": _tmpfs_matches(host.get("Tmpfs"), APP_TMPFS),
        "resource_limits": (
            host.get("Memory") == APP_MEMORY_BYTES
            and host.get("NanoCpus") == APP_NANO_CPUS
            and host.get("PidsLimit") == APP_PIDS_LIMIT
        ),
        "raw_returned": False,
    }


def _cleanup_container(container_id: str, *, work_root: Path) -> dict[str, Any]:
    result = _docker(["container", "rm", "--force", container_id], cwd=work_root, timeout=60)
    removed = not result.timed_out and not result.output_truncated and result.returncode == 0
    probe = _docker(["container", "inspect", container_id], cwd=work_root, timeout=30)
    absent = not probe.timed_out and probe.returncode != 0
    return {"removed": removed, "absent_after_cleanup": absent, "raw_returned": False}


def _cleanup_image(image_id: str, *, work_root: Path) -> dict[str, Any]:
    result = _docker(["image", "rm", "--force", image_id], cwd=work_root, timeout=90)
    removed = not result.timed_out and not result.output_truncated and result.returncode == 0
    probe = _docker(["image", "inspect", image_id], cwd=work_root, timeout=30)
    absent = not probe.timed_out and probe.returncode != 0
    return {"removed": removed, "absent_after_cleanup": absent, "raw_returned": False}


def _driver_command() -> str:
    return "exec java -cp /workspace/classes kguard.Challenge1Harness"


def _parse_driver_result(output: bytes) -> dict[str, Any]:
    try:
        lines = output.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise RuntimeContractError("driver_output_not_utf8") from exc
    markers = [line[len(DRIVER_MARKER) :] for line in lines if line.startswith(DRIVER_MARKER)]
    if len(markers) != 1 or any(line and not line.startswith(DRIVER_MARKER) for line in lines):
        raise RuntimeContractError("driver_marker_invalid")
    try:
        value = json.loads(markers[0])
    except json.JSONDecodeError as exc:
        raise RuntimeContractError("driver_result_not_json") from exc
    expected_keys = {
        "schema",
        "answer_matches_source_constant",
        "raw_returned",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise RuntimeContractError("driver_result_shape_invalid")
    if (
        value.get("schema") != DRIVER_RESULT_SCHEMA
        or value.get("raw_returned") is not False
        or not isinstance(value.get("answer_matches_source_constant"), bool)
    ):
        raise RuntimeContractError("driver_result_binding_invalid")
    return value


def _expected_observation(mode: str, value: Mapping[str, Any]) -> bool:
    if mode == "positive":
        return value.get("answer_matches_source_constant") is True
    if mode == "negative":
        return value.get("answer_matches_source_constant") is False
    raise RuntimeContractError("driver_mode_invalid")


def _create_container(image_id: str, *, work_root: Path) -> tuple[str, dict[str, Any]]:
    arguments = [
        "container",
        "create",
        "--network",
        "none",
        "--read-only",
        "--user",
        APP_USER,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--pids-limit",
        str(APP_PIDS_LIMIT),
        "--memory",
        str(APP_MEMORY_BYTES),
        "--cpus",
        "2",
        "--label",
        f"kguard.execution.contract={EXECUTION_CONTRACT_LABEL}",
        "--entrypoint",
        "/bin/sh",
    ]
    for path, options in sorted(APP_TMPFS.items()):
        arguments.extend(["--tmpfs", f"{path}:{options}"])
    arguments.extend([image_id, "-c", _driver_command()])
    container_id = _container_id(_docker(arguments, cwd=work_root, timeout=60), "container_create")
    isolation = _container_isolation(_inspect_container(container_id, work_root=work_root))
    if isolation["passed"] is not True:
        cleanup = _cleanup_container(container_id, work_root=work_root)
        if cleanup["removed"] is not True or cleanup["absent_after_cleanup"] is not True:
            raise RuntimeContractError("container_isolation_invalid_cleanup_failed")
        raise RuntimeContractError("container_isolation_invalid")
    return container_id, isolation


def _run_one(image_id: str, *, work_root: Path, mode: str, timeout: int) -> dict[str, Any]:
    container_id: str | None = None
    run: dict[str, Any] | None = None
    try:
        container_id, isolation = _create_container(image_id, work_root=work_root)
        start = _docker(["container", "start", "--attach", container_id], cwd=work_root, timeout=timeout)
        _expect_success(start, "container_start")
        inspect = _inspect_container(container_id, work_root=work_root)
        state = inspect.get("State")
        if not isinstance(state, Mapping) or state.get("ExitCode") != 0:
            raise RuntimeContractError("container_exit_invalid")
        observation = _parse_driver_result(start.stdout)
        if not _expected_observation(mode, observation):
            raise RuntimeContractError(f"{mode}_observation_invalid")
        run = {
            "mode": mode,
            "driver_sha256": sha256_bytes(_driver_command().encode("utf-8")),
            "observation": observation,
            "isolation": isolation,
            "driver_command": _command_receipt(start),
            "passed": True,
            "raw_returned": False,
        }
    finally:
        if container_id is not None:
            cleanup = _cleanup_container(container_id, work_root=work_root)
            if cleanup["removed"] is not True or cleanup["absent_after_cleanup"] is not True:
                raise RuntimeContractError("container_cleanup_failed")
            if run is not None:
                run["cleanup"] = cleanup
    if run is None:
        raise RuntimeContractError("run_result_missing")
    return run


def _consensus_projection(run: Mapping[str, Any]) -> dict[str, Any]:
    observation = run.get("observation")
    isolation = run.get("isolation")
    if not isinstance(observation, Mapping) or not isinstance(isolation, Mapping):
        raise RuntimeContractError("run_projection_shape_invalid")
    return {
        "mode": run.get("mode"),
        "driver_sha256": run.get("driver_sha256"),
        "observation": {
            key: observation.get(key)
            for key in (
                "schema",
                "answer_matches_source_constant",
                "raw_returned",
            )
        },
        "isolation": {
            key: isolation.get(key)
            for key in (
                "passed",
                "read_only_root",
                "non_root_user",
                "cap_drop_all",
                "no_new_privileges",
                "network_none",
                "no_host_port",
                "no_bind_or_volume_mount",
                "tmpfs_contract",
                "resource_limits",
                "raw_returned",
            )
        },
        "cleanup": run.get("cleanup"),
        "passed": run.get("passed"),
        "raw_returned": run.get("raw_returned"),
    }


def _tool_provenance(source_verifier_sha256: str) -> dict[str, Any]:
    return {
        "runner_sha256": _runner_sha256(),
        "source_verifier_sha256": source_verifier_sha256,
        "docker_cli": "docker",
        "raw_returned": False,
    }


def _claim_boundary(*, negative: bool) -> dict[str, bool]:
    return {
        "execution_oracle_only": True,
        "source_mutated_negative_control": negative,
        "detector_finding_mapping_proven": False,
        "secret_detection_accuracy_proven": False,
        "java_framework_depth_proven": False,
        "runtime_supply_chain_proven": False,
        "upstream_junit_execution_proven": False,
        "third_party_library_semantics_generalized": False,
        "guardian_release_proven": False,
        "h100_proven": False,
    }


def _execute(
    source_root: Path,
    p23a_registry: Path,
    *,
    timeout: int,
    variant: str,
    positive_receipt: Mapping[str, Any] | None = None,
    positive_receipt_sha256: str | None = None,
) -> dict[str, Any]:
    work_root = Path(tempfile.mkdtemp(prefix="kguard-wrongsecrets-runtime-"))
    image_id: str | None = None
    image_cleanup: dict[str, Any] | None = None
    try:
        source, _, source_verifier_sha256 = verify_source_workspace(source_root, p23a_registry)
        _read_source_files(source_root)
        base_image = _verify_base_image(work_root=work_root)
        image, image_ref = _build_replay_image(
            source_root=source_root,
            source=source,
            base_image=base_image,
            variant=variant,
            work_root=work_root,
            timeout=timeout,
        )
        image_id = image_ref["image_id"]
        runs = [_run_one(image_id, work_root=work_root, mode=variant, timeout=timeout) for _ in range(2)]
        if _consensus_projection(runs[0]) != _consensus_projection(runs[1]):
            raise RuntimeContractError("internal_repeatability_mismatch")
        source_after, _, _ = verify_source_workspace(source_root, p23a_registry)
        if source_after != source:
            raise RuntimeContractError("source_changed_during_execution")
        image_cleanup = _cleanup_image(image_id, work_root=work_root)
        if image_cleanup["removed"] is not True or image_cleanup["absent_after_cleanup"] is not True:
            raise RuntimeContractError("image_cleanup_failed")
        image_id = None
        common = {
            "source": source,
            "base_image": base_image,
            "image_contract": image,
            "runs": runs,
            "internal_repeat_exact": True,
            "tool_provenance": _tool_provenance(source_verifier_sha256),
            "image_cleanup": image_cleanup,
            "admission_blockers": list(ADMISSION_BLOCKERS),
            "release_gate_passed": False,
            "claim_boundary": _claim_boundary(negative=variant == "negative"),
            "raw_returned": False,
        }
        if variant == "positive":
            return {
                "schema": SCHEMA,
                "scenario": "wrongsecrets-challenge1-javac-harness",
                "execution_contract_status": "EXECUTION_CONTRACT_PASS",
                **common,
            }
        if positive_receipt is None or positive_receipt_sha256 is None:
            raise RuntimeContractError("positive_receipt_missing")
        return {
            "schema": NEGATIVE_CONTROL_SCHEMA,
            "scenario": "wrongsecrets-challenge1-derived-empty-answer-javac-control",
            "negative_control_status": "NEGATIVE_CONTROL_PASS",
            "positive_receipt_sha256": positive_receipt_sha256,
            "positive_receipt_semantic_sha256": _canonical_sha256(
                semantic_projection(positive_receipt, negative=False)
            ),
            **common,
        }
    finally:
        if image_id is not None:
            cleanup = _cleanup_image(image_id, work_root=work_root)
            if cleanup["removed"] is not True or cleanup["absent_after_cleanup"] is not True:
                raise RuntimeContractError("image_cleanup_failed")
        shutil.rmtree(work_root, ignore_errors=True)


def execute_contract(source_root: Path, p23a_registry: Path, *, timeout: int) -> dict[str, Any]:
    return _execute(source_root, p23a_registry, timeout=timeout, variant="positive")


def _load_canonical_receipt(path: Path, *, negative: bool) -> tuple[dict[str, Any], str]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeContractError("receipt_invalid_path")
    raw = path.read_bytes()
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError("receipt_not_json") from exc
    if not isinstance(receipt, dict) or canonical_json_bytes(receipt) != raw:
        raise RuntimeContractError("receipt_not_canonical")
    if negative:
        validate_negative_control_receipt(receipt)
    else:
        validate_receipt(receipt)
    return receipt, sha256_bytes(raw)


def execute_negative_control(
    source_root: Path, p23a_registry: Path, *, positive_receipt_path: Path, timeout: int
) -> dict[str, Any]:
    positive_receipt, positive_receipt_sha256 = _load_canonical_receipt(
        positive_receipt_path, negative=False
    )
    return _execute(
        source_root,
        p23a_registry,
        timeout=timeout,
        variant="negative",
        positive_receipt=positive_receipt,
        positive_receipt_sha256=positive_receipt_sha256,
    )


def _assert_raw_free(value: object) -> None:
    if isinstance(value, Mapping):
        if "raw_returned" in value and value["raw_returned"] is not False:
            raise RuntimeContractError("receipt_raw_boundary_invalid")
        for nested in value.values():
            _assert_raw_free(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_raw_free(nested)


def _validate_hash(value: object, label: str) -> None:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise RuntimeContractError(f"{label}_invalid")


def _validate_source(value: object) -> None:
    if not isinstance(value, Mapping):
        raise RuntimeContractError("receipt_source_invalid")
    expected = {
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
        "p23a_observed_receipt_sha256": P23A_OBSERVED_RECEIPT_SHA256,
        "p23a_app_receipt_sha256": P23A_APP_RECEIPT_SHA256,
        "p23a_app_receipt_semantic_sha256": P23A_APP_SEMANTIC_SHA256,
        "file_count": 861,
        "total_bytes": 224325617,
        "raw_returned": False,
    }
    if any(value.get(key) != expected_value for key, expected_value in expected.items()):
        raise RuntimeContractError("receipt_source_binding_invalid")
    _validate_hash(value.get("p23a_registry_sha256"), "receipt_p23a_registry_sha256")
    _validate_hash(value.get("current_source_receipt_sha256"), "receipt_current_source_receipt_sha256")


def _validate_base_image(value: object) -> None:
    if value != {
        "reference": BASE_IMAGE_REF,
        "image_id": BASE_IMAGE_ID,
        "java_version": EXPECTED_JAVA_VERSION,
        "raw_returned": False,
    }:
        raise RuntimeContractError("receipt_base_image_invalid")


def _validate_staged_source(value: object, *, variant: str) -> None:
    if not isinstance(value, Mapping):
        raise RuntimeContractError("receipt_staged_source_invalid")
    hashes = value.get("relevant_file_sha256")
    if not isinstance(hashes, Mapping) or set(hashes) != set(SOURCE_FILES):
        raise RuntimeContractError("receipt_staged_source_hashes_invalid")
    for relative, expected in SOURCE_FILES.items():
        actual = hashes.get(relative)
        if relative.endswith("Challenge1.java") and variant == "negative":
            continue
        if actual != expected:
            raise RuntimeContractError("receipt_staged_source_hash_mismatch")
    if value.get("harness_source_sha256") != _harness_source_hashes():
        raise RuntimeContractError("receipt_harness_source_hashes_invalid")
    patch = value.get("negative_patch")
    if variant == "positive":
        if patch is not None:
            raise RuntimeContractError("receipt_positive_patch_present")
    else:
        if not isinstance(patch, Mapping) or patch.get("patch_id") != NEGATIVE_PATCH_ID:
            raise RuntimeContractError("receipt_negative_patch_invalid")
        if patch.get("anchor_count") != 1 or patch.get("source_sha256") != SOURCE_FILES[
            "src/main/java/org/owasp/wrongsecrets/challenges/docker/Challenge1.java"
        ]:
            raise RuntimeContractError("receipt_negative_patch_binding_invalid")
        _validate_hash(patch.get("derived_sha256"), "receipt_negative_patch_derivative")
        if hashes.get("src/main/java/org/owasp/wrongsecrets/challenges/docker/Challenge1.java") != patch.get(
            "derived_sha256"
        ):
            raise RuntimeContractError("receipt_negative_patch_hash_mismatch")
    if value.get("variant") != variant or value.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_staged_source_variant_invalid")


def _validate_image(value: object, *, variant: str) -> None:
    if not isinstance(value, Mapping):
        raise RuntimeContractError("receipt_image_invalid")
    required = {
        "image_id",
        "contract_label",
        "variant",
        "contract_sha256",
        "dockerfile_sha256",
        "source_derived",
        "build_network",
        "fresh_source_compile_proven",
        "runtime_supply_chain_proven",
        "build_command",
        "staged_source",
        "raw_returned",
    }
    if set(value) != required or not isinstance(value.get("image_id"), str) or not IMAGE_ID_RE.fullmatch(value["image_id"]):
        raise RuntimeContractError("receipt_image_shape_invalid")
    if (
        value.get("contract_label") != EXECUTION_CONTRACT_LABEL
        or value.get("variant") != variant
        or value.get("source_derived") is not True
        or value.get("build_network") != "none"
        or value.get("fresh_source_compile_proven") is not True
        or value.get("runtime_supply_chain_proven") is not False
        or value.get("raw_returned") is not False
    ):
        raise RuntimeContractError("receipt_image_binding_invalid")
    _validate_hash(value.get("contract_sha256"), "receipt_image_contract_sha256")
    _validate_hash(value.get("dockerfile_sha256"), "receipt_dockerfile_sha256")
    _validate_staged_source(value.get("staged_source"), variant=variant)
    command = value.get("build_command")
    if (
        not isinstance(command, Mapping)
        or command.get("returncode") != 0
        or command.get("timed_out") is not False
        or command.get("output_truncated") is not False
        or command.get("raw_returned") is not False
    ):
        raise RuntimeContractError("receipt_image_build_command_invalid")


def _validate_run(value: object, *, variant: str) -> None:
    if not isinstance(value, Mapping):
        raise RuntimeContractError("receipt_run_invalid")
    required = {
        "mode",
        "driver_sha256",
        "observation",
        "isolation",
        "driver_command",
        "cleanup",
        "passed",
        "raw_returned",
    }
    if set(value) != required or value.get("mode") != variant or value.get("passed") is not True or value.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_run_shape_invalid")
    if value.get("driver_sha256") != sha256_bytes(_driver_command().encode("utf-8")):
        raise RuntimeContractError("receipt_run_driver_invalid")
    observation = value.get("observation")
    if not isinstance(observation, Mapping) or not _expected_observation(variant, observation):
        raise RuntimeContractError("receipt_run_observation_invalid")
    isolation = value.get("isolation")
    if not isinstance(isolation, Mapping) or isolation.get("passed") is not True:
        raise RuntimeContractError("receipt_run_isolation_invalid")
    required_isolation = (
        "read_only_root",
        "non_root_user",
        "cap_drop_all",
        "no_new_privileges",
        "network_none",
        "no_host_port",
        "no_bind_or_volume_mount",
        "tmpfs_contract",
        "resource_limits",
    )
    if any(isolation.get(key) is not True for key in required_isolation):
        raise RuntimeContractError("receipt_run_isolation_contract_invalid")
    command = value.get("driver_command")
    if (
        not isinstance(command, Mapping)
        or command.get("returncode") != 0
        or command.get("timed_out") is not False
        or command.get("output_truncated") is not False
        or command.get("raw_returned") is not False
    ):
        raise RuntimeContractError("receipt_run_driver_command_invalid")
    _validate_cleanup(value.get("cleanup"), "container")


def _validate_cleanup(value: object, label: str) -> None:
    if value != {"removed": True, "absent_after_cleanup": True, "raw_returned": False}:
        raise RuntimeContractError(f"receipt_{label}_cleanup_invalid")


def _validate_common_receipt(receipt: Mapping[str, Any], *, variant: str) -> None:
    required = {
        "schema",
        "scenario",
        "source",
        "base_image",
        "image_contract",
        "runs",
        "internal_repeat_exact",
        "tool_provenance",
        "image_cleanup",
        "admission_blockers",
        "release_gate_passed",
        "claim_boundary",
        "raw_returned",
    }
    if variant == "positive":
        required.add("execution_contract_status")
    else:
        required.update({"negative_control_status", "positive_receipt_sha256", "positive_receipt_semantic_sha256"})
    if set(receipt) != required:
        raise RuntimeContractError("receipt_keys_invalid")
    _validate_source(receipt.get("source"))
    _validate_base_image(receipt.get("base_image"))
    _validate_image(receipt.get("image_contract"), variant=variant)
    runs = receipt.get("runs")
    if not isinstance(runs, list) or len(runs) != 2:
        raise RuntimeContractError("receipt_runs_invalid")
    for run in runs:
        _validate_run(run, variant=variant)
    if _consensus_projection(runs[0]) != _consensus_projection(runs[1]) or receipt.get("internal_repeat_exact") is not True:
        raise RuntimeContractError("receipt_internal_repeat_invalid")
    tool = receipt.get("tool_provenance")
    if not isinstance(tool, Mapping) or tool.get("runner_sha256") != _runner_sha256() or tool.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_tool_provenance_invalid")
    _validate_hash(tool.get("source_verifier_sha256"), "receipt_source_verifier_sha256")
    _validate_cleanup(receipt.get("image_cleanup"), "image")
    if receipt.get("admission_blockers") != list(ADMISSION_BLOCKERS) or receipt.get("release_gate_passed") is not False:
        raise RuntimeContractError("receipt_claim_boundary_invalid")
    if receipt.get("claim_boundary") != _claim_boundary(negative=variant == "negative") or receipt.get("raw_returned") is not False:
        raise RuntimeContractError("receipt_claim_boundary_shape_invalid")
    _assert_raw_free(receipt)


def validate_receipt(receipt: dict[str, Any]) -> None:
    _validate_common_receipt(receipt, variant="positive")
    if receipt.get("schema") != SCHEMA or receipt.get("scenario") != "wrongsecrets-challenge1-javac-harness":
        raise RuntimeContractError("positive_receipt_identity_invalid")
    if receipt.get("execution_contract_status") != "EXECUTION_CONTRACT_PASS":
        raise RuntimeContractError("positive_receipt_status_invalid")


def validate_negative_control_receipt(receipt: dict[str, Any]) -> None:
    _validate_common_receipt(receipt, variant="negative")
    if (
        receipt.get("schema") != NEGATIVE_CONTROL_SCHEMA
        or receipt.get("scenario") != "wrongsecrets-challenge1-derived-empty-answer-javac-control"
        or receipt.get("negative_control_status") != "NEGATIVE_CONTROL_PASS"
    ):
        raise RuntimeContractError("negative_receipt_identity_invalid")
    _validate_hash(receipt.get("positive_receipt_sha256"), "negative_positive_receipt_sha256")
    _validate_hash(receipt.get("positive_receipt_semantic_sha256"), "negative_positive_semantic_sha256")


def semantic_projection(receipt: Mapping[str, Any], *, negative: bool) -> dict[str, Any]:
    source = receipt.get("source")
    image = receipt.get("image_contract")
    runs = receipt.get("runs")
    if not isinstance(source, Mapping) or not isinstance(image, Mapping) or not isinstance(runs, list):
        raise RuntimeContractError("semantic_projection_shape_invalid")
    projection = {
        "schema": receipt.get("schema"),
        "scenario": receipt.get("scenario"),
        "source": {
            key: source.get(key)
            for key in (
                "repository_id",
                "commit",
                "commit_tree",
                "source_tree_sha256",
                "p23a_registry_sha256",
                "p23a_observed_receipt_sha256",
                "p23a_app_receipt_sha256",
                "p23a_app_receipt_semantic_sha256",
                "current_source_receipt_sha256",
                "file_count",
                "total_bytes",
                "raw_returned",
            )
        },
        "base_image": receipt.get("base_image"),
        "image_contract": {
            key: image.get(key)
            for key in (
                "contract_label",
                "variant",
                "contract_sha256",
                "dockerfile_sha256",
                "source_derived",
                "build_network",
                "fresh_source_compile_proven",
                "runtime_supply_chain_proven",
                "staged_source",
                "raw_returned",
            )
        },
        "runs": [_consensus_projection(run) for run in runs],
        "internal_repeat_exact": receipt.get("internal_repeat_exact"),
        "admission_blockers": receipt.get("admission_blockers"),
        "release_gate_passed": receipt.get("release_gate_passed"),
        "claim_boundary": receipt.get("claim_boundary"),
        "raw_returned": receipt.get("raw_returned"),
    }
    if negative:
        projection["negative_control_status"] = receipt.get("negative_control_status")
        projection["positive_receipt_semantic_sha256"] = receipt.get("positive_receipt_semantic_sha256")
    else:
        projection["execution_contract_status"] = receipt.get("execution_contract_status")
    return projection


def _write_new_output(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise RuntimeContractError("output_path_already_exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(dict(payload)))


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay the P2.3B.6 WrongSecrets Challenge1 process oracle.")
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--p23a-registry", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--negative", action="store_true")
    parser.add_argument("--positive-receipt", type=Path)
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.negative != (args.positive_receipt is not None):
        parser.error("--negative and --positive-receipt must be supplied together")
    try:
        if args.negative:
            receipt = execute_negative_control(
                args.source_root.resolve(),
                args.p23a_registry.resolve(),
                positive_receipt_path=args.positive_receipt.resolve(),
                timeout=args.timeout,
            )
        else:
            receipt = execute_contract(args.source_root.resolve(), args.p23a_registry.resolve(), timeout=args.timeout)
        _write_new_output(args.output.resolve(), receipt)
    except RuntimeContractError as exc:
        print(f"HOLD:{exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
