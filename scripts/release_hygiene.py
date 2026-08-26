from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__:
    from .evidence_tree import package_tree_sha256
else:
    from evidence_tree import package_tree_sha256

GENERATED_NOISE_PREFIXES = (
    ".coverage",
    ".pytest_cache/",
    ".ruff_cache/",
    ".mypy_cache/",
    "tmp/",
    "terminals/",
    "k-guard.sarif",
    "k-guard-self-scan.json",
)

RELEASE_SOURCE_PREFIXES = (
    ".github/",
    "benchmarks/",
    "datasets/",
    "docs/",
    "examples/",
    "scripts/",
    "src/",
    "tests/",
    "tracking/",
)

RELEASE_EVIDENCE_PREFIX = "evidence/"
RELEASE_SUBMISSION_PREFIX = "submission/"

RELEASE_ROOT_FILES = {
    ".gitattributes",
    ".gitignore",
    "CODE_OF_CONDUCT.md",
    "contest-readiness-report.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "MANIFEST.in",
    "PUBLIC-SNAPSHOT.json",
    "README.md",
    "MANIFEST.in",
    "requirements-evidence.lock",
    "requirements-evidence.in",
    "requirements-build.lock",
    "requirements-pip-audit.in",
    "requirements-pip-audit.lock",
    "requirements-semgrep.in",
    "requirements-semgrep.lock",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "pyproject.toml",
}

RELEASE_ROOT_PREFIXES = ("LICENSES/",)

ROOT_EVIDENCE_REPORTS = {
    "audit-report.json",
    "authorized-dynamic-harness-report.json",
    "benchmark-report.json",
    "competitive-dogfood-report.json",
    "contest-readiness-report.json",
    "corpus-governance-report.json",
    "fixture-metrics.json",
    "license-report.json",
    "sbom.cdx.json",
    "site-scale-calibration-report.json",
    "synthetic-korean-corpus-report.json",
}

REQUIRED_RELEASE_FILES = (
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "README.md",
    "contest-readiness-report.json",
    "contest-readiness-report.md",
    "THIRD_PARTY_NOTICES.md",
    "LICENSES/Apache-2.0.txt",
    "PUBLIC-SNAPSHOT.json",
    "requirements-evidence.lock",
    "requirements-evidence.in",
    "requirements-build.lock",
    "requirements-pip-audit.in",
    "requirements-pip-audit.lock",
    "requirements-semgrep.in",
    "requirements-semgrep.lock",
    "pyproject.toml",
    "src/k_guard_mcp/__init__.py",
    "tracking/README.md",
    "tracking/improvements.jsonl",
    "docs/release-hygiene.md",
)

PACKAGE_BUILD_INPUTS = (
    "src/k_guard_mcp",
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "LICENSES",
    "MANIFEST.in",
)

PERFORMANCE_V2_ACCEPTANCE_CHECKS = {
    "100mib_peak_rss_at_most_2gib",
    "10_to_100mib_p50_time_ratio_at_most_15",
    "complete_candidate_coverage",
    "concurrency_4_and_8_retain_70pct_single_worker_throughput",
    "each_100mib_sample_at_most_300s",
    "exact_corpus_bytes",
    "fresh_process_cold_end_to_end_p95_at_most_8s",
    "scaling_p50_throughput_at_least_0_5_mib_s",
    "source_matches_head",
    "source_pre_run_clean",
    "source_unchanged",
    "all_benign_result_invariance_observed",
    "warm_1mib_p95_at_most_5s",
}
PERFORMANCE_V2_SUPPORTED_CLAIM_PREFIX = (
    "single-host scanner capacity on the contest_full synthetic all-benign low-signal protocol"
)
PERFORMANCE_V2_SMALL_SAMPLE_P95_INTERPRETATION = (
    "p95 equals the observed maximum for scaling n=5 and concurrency n=16"
)
HISTORICAL_PUBLICATION_SCOPE = "historical_private_source_revision"
PACKAGE_READY_RELEASE_STATUSES = frozenset(
    {"package_ready_field_evidence_pending", "award_evidence_ready"}
)


def _run_git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _run_git_bytes(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )


def _normalize_path(path: str) -> str:
    if " -> " in path:
        path = path.split(" -> ", 1)[1]
    return path.replace("\\", "/")


def git_status_entries() -> list[dict[str, str]]:
    result = _run_git(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git status failed")
    return parse_porcelain_z(result.stdout)


def parse_porcelain_z(payload: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    records = payload.split("\0")
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record:
            continue
        if len(record) < 4:
            path = _normalize_path(record)
            entries.append({"status": "??", "path": path, "category": classify_path(path)})
            continue
        status = record[:2]
        path = _normalize_path(record[3:])
        entries.append({"status": status, "path": path, "category": classify_path(path)})
        if status[0] in {"R", "C"} or status[1] in {"R", "C"}:
            index += 1
    return entries


def classify_path(path: str) -> str:
    normalized = _normalize_path(path)
    if normalized in RELEASE_ROOT_FILES or normalized.startswith(RELEASE_ROOT_PREFIXES):
        return "release_root"
    if normalized in ROOT_EVIDENCE_REPORTS:
        return "root_evidence_report"
    if normalized.startswith(GENERATED_NOISE_PREFIXES):
        return "generated_noise"
    if normalized.startswith(RELEASE_EVIDENCE_PREFIX):
        return "release_evidence"
    if normalized.startswith(RELEASE_SUBMISSION_PREFIX):
        return "release_submission"
    if normalized.startswith(RELEASE_SOURCE_PREFIXES):
        return "release_source"
    if normalized.endswith((".md", ".json", ".jsonl", ".csv")):
        return "review_required_artifact"
    return "unclassified"


def _project_version() -> str:
    payload = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(payload["project"]["version"])


def _package_version() -> str | None:
    init_text = (ROOT / "src/k_guard_mcp/__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', init_text, re.MULTILINE)
    return match.group(1) if match else None


def _release_tag_status(expected_tag: str | None, project_version: str) -> dict[str, Any]:
    expected = f"v{project_version}"
    if expected_tag is None:
        return {"required": False, "provided": None, "expected": expected, "valid": True}
    return {
        "required": True,
        "provided": expected_tag,
        "expected": expected,
        "valid": expected_tag == expected,
    }


def _package_input_byte_status() -> dict[str, Any]:
    listing = _run_git_bytes(["ls-files", "-z", "--", *PACKAGE_BUILD_INPUTS])
    if listing.returncode != 0:
        return {
            "valid": False,
            "tracked_file_count": 0,
            "mismatch_count": 0,
            "mismatches": [],
            "error": "git ls-files failed",
        }
    tracked = [raw.decode("utf-8") for raw in listing.stdout.split(b"\0") if raw]
    mismatches: list[str] = []
    for relative in tracked:
        candidate = ROOT / relative
        indexed = _run_git_bytes(["show", f":{relative}"])
        if not candidate.is_file() or indexed.returncode != 0 or candidate.read_bytes() != indexed.stdout:
            mismatches.append(relative)
    return {
        "valid": not mismatches,
        "tracked_file_count": len(tracked),
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "error": None,
    }


def _tracking_jsonl_status() -> dict[str, Any]:
    path = ROOT / "tracking/improvements.jsonl"
    rows = 0
    errors: list[str] = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        rows += 1
        try:
            json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {index}: {exc.msg}")
    return {"path": "tracking/improvements.jsonl", "valid": not errors, "rows": rows, "errors": errors}


def _root_json_artifacts_status() -> dict[str, Any]:
    parsed: list[str] = []
    errors: list[str] = []
    for name in sorted(ROOT_EVIDENCE_REPORTS):
        path = ROOT / name
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            semantic_error = _evidence_report_semantic_error(name, payload)
            if semantic_error:
                errors.append(f"{name}: {semantic_error}")
            else:
                parsed.append(name)
        except json.JSONDecodeError as exc:
            errors.append(f"{name}: {exc.msg}")
    return {"valid": not errors, "parsed": parsed, "errors": errors}


def _release_authorization_status(required: bool) -> dict[str, Any]:
    """Keep honest historical/blocked reports separate from publish authority."""

    try:
        readiness = json.loads(
            (ROOT / "contest-readiness-report.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        readiness = {}
    try:
        performance = json.loads(
            (ROOT / "benchmark-report.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        performance = {}

    package_ready = (
        isinstance(readiness, dict)
        and readiness.get("package_ready") is True
        and readiness.get("submission_ready") is True
        and readiness.get("status") in PACKAGE_READY_RELEASE_STATUSES
    )
    publication = performance.get("publication_binding") if isinstance(performance, dict) else None
    current_source_performance = isinstance(performance, dict) and bool(performance) and publication is None
    return {
        "required": required,
        "contest_readiness": {
            "package_ready": readiness.get("package_ready") if isinstance(readiness, dict) else None,
            "status": readiness.get("status") if isinstance(readiness, dict) else None,
            "valid": package_ready if required else True,
        },
        "performance_evidence": {
            "publication_scope": publication.get("scope") if isinstance(publication, dict) else None,
            "current_source_equivalence": current_source_performance,
            "valid": current_source_performance if required else True,
        },
    }


def _evidence_report_semantic_error(name: str, payload: Any) -> str | None:
    if not isinstance(payload, dict) or not payload:
        return "nonempty JSON object required"
    if name == "audit-report.json":
        if payload.get("passed") is not True or payload.get("pip_audit_available") is not True or _safe_int(payload.get("vulnerability_count"), -1) != 0:
            return "passed=true, pip_audit_available=true, vulnerability_count=0 required"
    elif name == "license-report.json":
        zero_fields = ("unknown_license_count", "review_required_count", "unresolved_dependency_count", "lock_mismatch_count")
        if payload.get("passed") is not True or _safe_int(payload.get("component_count"), 0) <= 0 or any(_safe_int(payload.get(field), -1) != 0 for field in zero_fields):
            return "passed license report with components and zero unresolved/review/lock counts required"
    elif name == "sbom.cdx.json":
        if payload.get("bomFormat") != "CycloneDX" or not isinstance(payload.get("components"), list) or not payload["components"]:
            return "nonempty CycloneDX component list required"
    elif name == "benchmark-report.json":
        slo = payload.get("slo", {}) if isinstance(payload.get("slo"), dict) else {}
        if payload.get("schema") == "k_guard_performance_benchmark.v2":
            return _performance_v2_semantic_error(payload)
        if slo.get("all_met") is not True or slo.get("synthetic_throughput_met") is not True:
            return "all benchmark SLOs must pass"
    elif name == "competitive-dogfood-report.json":
        if not isinstance(payload.get("repos"), list) or not payload["repos"]:
            return "nonempty repo comparison list required"
    elif name == "contest-readiness-report.json":
        return _contest_readiness_semantic_error(payload)
    elif name == "fixture-metrics.json":
        coverage = payload.get("coverage", {}) if isinstance(payload.get("coverage"), dict) else {}
        if payload.get("passed") is not True or coverage.get("all_required_rules_observed") is not True:
            return "passed fixture metrics with complete required-rule coverage required"
    elif "passed" in payload and payload.get("passed") is not True:
        return "passed=true required"
    return None


def _performance_v2_semantic_error(payload: dict[str, Any]) -> str | None:
    if payload.get("profile") != "contest_full":
        return "contest_full profile required for release evidence; quick_ci is CI-only"
    if payload.get("passed") is not True or payload.get("raw_free") is not True:
        return "passed=true and raw_free=true required"
    protocol = payload.get("protocol", {}) if isinstance(payload.get("protocol"), dict) else {}
    if (
        protocol.get("single_host") is not True
        or protocol.get("scaling_mib") != [10, 50, 100]
        or protocol.get("concurrency_levels") != [1, 4, 8]
        or _safe_int(protocol.get("cold_samples"), 0) < 20
        or _safe_int(protocol.get("warm_samples"), 0) < 20
        or _safe_int(protocol.get("scaling_samples_per_size"), 0) < 5
        or _safe_int(protocol.get("concurrency_jobs_per_level"), 0) < 16
        or protocol.get("percentile_method") != "nearest_rank"
        or protocol.get("small_sample_p95_interpretation")
        != PERFORMANCE_V2_SMALL_SAMPLE_P95_INTERPRETATION
        or not str(protocol.get("concurrency_mechanism", "")).startswith("ThreadPoolExecutor inside one CPython process")
        or protocol.get("process_level_scaling_measured") is not False
        or not str(protocol.get("corpus_signal_profile", "")).startswith("synthetic all-benign low-signal")
        or not str(protocol.get("cold_definition", "")).startswith("fresh_process_cold")
        or not str(protocol.get("warm_definition", "")).startswith("persistent_process_and_scanner_warm")
    ):
        return "exact contest protocol and explicit cold/warm definitions required"
    binding = payload.get("source_binding", {}) if isinstance(payload.get("source_binding"), dict) else {}
    if not all(
        binding.get(field) is True
        for field in (
            "pre_run_clean",
            "head_unchanged",
            "package_tree_unchanged",
            "runner_unchanged",
            "source_unchanged",
            "working_tree_matches_head_package",
            "runner_matches_head",
        )
    ):
        return "clean, HEAD-matching, unchanged source binding required"
    pre = binding.get("pre", {}) if isinstance(binding.get("pre"), dict) else {}
    post = binding.get("post", {}) if isinstance(binding.get("post"), dict) else {}
    publication = payload.get("publication_binding")
    if publication is None:
        current_package_hash = package_tree_sha256(ROOT / "src" / "k_guard_mcp")
        current_runner_hash = hashlib.sha256((ROOT / "scripts" / "benchmark.py").read_bytes()).hexdigest()
        if (
            pre.get("working_package_tree_sha256") != current_package_hash
            or pre.get("runner_sha256") != current_runner_hash
        ):
            return "performance source binding does not match the current package and benchmark runner bytes"
    else:
        publication_error = _historical_publication_binding_error(publication, binding, pre, post)
        if publication_error:
            return publication_error
    environment = payload.get("environment", {}) if isinstance(payload.get("environment"), dict) else {}
    required_environment = (
        "python_implementation",
        "python_version",
        "python_executable_sha256",
        "os_system",
        "os_version",
        "machine",
        "logical_cpu_count",
        "installed_distribution_set_sha256",
        "peak_memory_backend",
    )
    if any(not environment.get(field) for field in required_environment) or environment.get("raw_free") is not True:
        return "complete raw-free runtime/environment binding required"
    acceptance = payload.get("acceptance", {}) if isinstance(payload.get("acceptance"), dict) else {}
    checks = acceptance.get("checks", {}) if isinstance(acceptance.get("checks"), dict) else {}
    if set(checks) != PERFORMANCE_V2_ACCEPTANCE_CHECKS:
        return "the exact 13 named v2 performance acceptance checks are required"
    if acceptance.get("all_met") is not True or any(value is not True for value in checks.values()):
        return "every named v2 performance acceptance check must pass"
    for field in ("cold", "warm"):
        section = payload.get(field, {}) if isinstance(payload.get(field), dict) else {}
        if section.get("fingerprints_stable") is not True or section.get("all_candidates_complete") is not True:
            return f"{field} samples require stable result fingerprints and complete candidate coverage"
    warm_delta = payload.get("warm_vs_cold", {}) if isinstance(payload.get("warm_vs_cold"), dict) else {}
    if (
        not isinstance(warm_delta.get("p50_seconds_delta"), (int, float))
        or not isinstance(warm_delta.get("p50_ratio"), (int, float))
        or not isinstance(warm_delta.get("peak_rss_bytes_delta"), int)
        or warm_delta.get("persistent_scanner_reuse_beyond_20_scans_measured") is not False
    ):
        return "explicit warm-versus-cold delta and 20-scan scope boundary required"
    for field, expected in (("scaling", {"10", "50", "100"}), ("concurrency", {"1", "4", "8"})):
        sections = payload.get(field, {}) if isinstance(payload.get(field), dict) else {}
        if set(sections) != expected or any(
            not isinstance(section, dict)
            or section.get("fingerprints_stable") is not True
            or section.get("all_candidates_complete") is not True
            for section in sections.values()
        ):
            return f"complete stable {field} sections required"
    boundary = payload.get("claim_boundary", {}) if isinstance(payload.get("claim_boundary"), dict) else {}
    supported_claim = boundary.get("supported_claim")
    supported_claim_has_exact_scope_prefix = isinstance(supported_claim, str) and (
        supported_claim == PERFORMANCE_V2_SUPPORTED_CLAIM_PREFIX
        or supported_claim.startswith(PERFORMANCE_V2_SUPPORTED_CLAIM_PREFIX + "; ")
    )
    if not supported_claim_has_exact_scope_prefix:
        return "supported_claim must use the exact contest_full synthetic all-benign low-signal scope prefix"
    if not all(
        boundary.get(field) is True
        for field in (
            "not_field_accuracy",
            "not_third_party_comparison",
            "not_hardware_normalized",
            "not_cold_disk_or_cold_cache",
            "one_reported_environment_only",
            "synthetic_inputs",
            "all_benign_low_signal_inputs",
            "not_finding_dense_scaling",
            "empty_result_digest_has_limited_discriminating_power",
            "not_process_level_scaling",
            "raw_free",
        )
    ):
        return "explicit synthetic single-host claim boundary required"
    fingerprint = payload.get("report_fingerprint_sha256")
    canonical = dict(payload)
    canonical.pop("report_fingerprint_sha256", None)
    expected_fingerprint = hashlib.sha256(
        json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if fingerprint != expected_fingerprint:
        return "report fingerprint mismatch"
    return None


def _historical_publication_binding_error(
    publication: Any,
    binding: dict[str, Any],
    pre: dict[str, Any],
    post: dict[str, Any],
) -> str | None:
    if not isinstance(publication, dict) or publication != {
        "current_public_source_equivalence_claimed": False,
        "measured_revision_available_in_public_history": False,
        "scope": HISTORICAL_PUBLICATION_SCOPE,
    }:
        return "exact historical public-snapshot performance boundary required"
    measured_revision = binding.get("measured_git_head")
    if not isinstance(measured_revision, str) or re.fullmatch(r"[0-9a-f]{40}", measured_revision) is None:
        return "historical measured revision must be a full lowercase Git SHA"
    package_hash = pre.get("working_package_tree_sha256")
    runner_hash = pre.get("runner_sha256")
    if not isinstance(package_hash, str) or re.fullmatch(r"[0-9a-f]{64}", package_hash) is None:
        return "historical package-tree digest is invalid"
    if not isinstance(runner_hash, str) or re.fullmatch(r"[0-9a-f]{64}", runner_hash) is None:
        return "historical benchmark-runner digest is invalid"
    if (
        binding.get("git_head") != measured_revision
        or pre.get("git_head") != measured_revision
        or post.get("git_head") != measured_revision
        or pre.get("clean") is not True
        or post.get("clean") is not True
        or pre.get("head_package_tree_sha256") != package_hash
        or post.get("working_package_tree_sha256") != package_hash
        or post.get("head_package_tree_sha256") != package_hash
        or pre.get("head_runner_sha256") != runner_hash
        or post.get("runner_sha256") != runner_hash
        or post.get("head_runner_sha256") != runner_hash
    ):
        return "historical source binding is internally inconsistent"
    return None


def _contest_readiness_semantic_error(payload: dict[str, Any]) -> str | None:
    if payload.get("schema") != "k_guard_contest_readiness.v3":
        return "contest readiness v3 schema required"
    package_ready = payload.get("package_ready")
    submission_ready = payload.get("submission_ready")
    award_ready = payload.get("award_evidence_ready")
    if not all(isinstance(value, bool) for value in (package_ready, submission_ready, award_ready)):
        return "boolean package, submission, and award readiness fields required"
    if submission_ready is not package_ready:
        return "submission_ready compatibility alias must equal package_ready"
    internal = payload.get("internal_checks")
    external = payload.get("external_checks")
    blockers = payload.get("blockers")
    if (
        not isinstance(internal, dict)
        or not internal
        or any(not isinstance(value, bool) for value in internal.values())
        or not isinstance(external, dict)
        or not external
        or any(not isinstance(value, bool) for value in external.values())
        or not isinstance(blockers, list)
        or any(not isinstance(value, str) for value in blockers)
    ):
        return "boolean readiness checks and a string blocker list required"
    expected_package = all(internal.values())
    expected_award = expected_package and all(external.values())
    expected_status = (
        "award_evidence_ready"
        if expected_award
        else "package_ready_field_evidence_pending"
        if expected_package
        else "package_verification_blocked"
    )
    expected_blockers = [name for name, passed in {**internal, **external}.items() if not passed]
    if package_ready is not expected_package or award_ready is not expected_award:
        return "readiness booleans must be derived from the published checks"
    if payload.get("status") != expected_status:
        return "readiness status does not match the published checks"
    if blockers != expected_blockers:
        return "readiness blockers do not match the failed published checks"
    return None


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _ignored_release_artifacts_status() -> dict[str, Any]:
    candidates = [ROOT / "build", ROOT / "dist", *sorted((ROOT / "src").glob("*.egg-info"))]
    present = [path.relative_to(ROOT).as_posix() for path in candidates if path.exists()]
    return {"valid": not present, "present": present}


def _evidence_tree_status() -> dict[str, Any]:
    evidence_root = ROOT / "evidence"
    if not evidence_root.exists():
        return {"valid": True, "manifest": "evidence/SHA256SUMS", "listed": 0, "errors": []}

    manifest = evidence_root / "SHA256SUMS"
    errors: list[str] = []
    listed: set[str] = set()
    if not manifest.is_file():
        return {
            "valid": False,
            "manifest": "evidence/SHA256SUMS",
            "listed": 0,
            "errors": ["evidence/SHA256SUMS is required when evidence/ exists"],
        }

    for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (evidence/[A-Za-z0-9._/\-]+)", line)
        if not match:
            errors.append(f"line {line_number}: expected '<sha256>  evidence/<path>'")
            continue
        expected_sha256, relative = match.groups()
        candidate = (ROOT / relative).resolve()
        try:
            candidate.relative_to(evidence_root.resolve())
        except ValueError:
            errors.append(f"line {line_number}: path escapes evidence root")
            continue
        if relative in listed:
            errors.append(f"line {line_number}: duplicate path {relative}")
            continue
        listed.add(relative)
        if not candidate.is_file():
            errors.append(f"missing listed evidence file: {relative}")
            continue
        actual_sha256 = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if actual_sha256 != expected_sha256:
            errors.append(f"digest mismatch: {relative}")

    required = {
        path.relative_to(ROOT).as_posix()
        for path in evidence_root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    for relative in sorted(required - listed):
        errors.append(f"unlisted evidence file: {relative}")
    for relative in sorted(listed - required):
        errors.append(f"manifest entry is not a release evidence artifact: {relative}")
    return {
        "valid": not errors,
        "manifest": "evidence/SHA256SUMS",
        "listed": len(listed),
        "errors": errors,
    }


def build_report(strict_clean: bool = False, expected_tag: str | None = None) -> dict[str, Any]:
    entries = git_status_entries()
    grouped: dict[str, list[dict[str, str]]] = {}
    for entry in entries:
        grouped.setdefault(entry["category"], []).append({"status": entry["status"], "path": entry["path"]})

    project_version = _project_version()
    package_version = _package_version()
    version_consistent = project_version == package_version
    release_tag = _release_tag_status(expected_tag, project_version)
    package_input_bytes = _package_input_byte_status()
    missing_required = [path for path in REQUIRED_RELEASE_FILES if not (ROOT / path).exists()]
    tracking_jsonl = _tracking_jsonl_status()
    root_json_artifacts = _root_json_artifacts_status()
    release_authorization = _release_authorization_status(
        strict_clean or expected_tag is not None
    )
    evidence_tree = _evidence_tree_status()
    ignored_release_artifacts = _ignored_release_artifacts_status()
    generated_noise = grouped.get("generated_noise", [])
    unclassified = grouped.get("unclassified", [])
    review_required_artifacts = grouped.get("review_required_artifact", [])

    pass_conditions = {
        "version_consistent": version_consistent,
        "release_tag_matches_version": bool(release_tag["valid"]),
        "tracking_jsonl_valid": bool(tracking_jsonl["valid"]),
        "root_json_artifacts_valid": bool(root_json_artifacts["valid"]),
        "contest_package_ready_for_release": bool(
            release_authorization["contest_readiness"]["valid"]
        ),
        "current_source_performance_evidence_for_release": bool(
            release_authorization["performance_evidence"]["valid"]
        ),
        "evidence_tree_valid": bool(evidence_tree["valid"]),
        "no_ignored_release_artifacts": bool(ignored_release_artifacts["valid"]),
        "required_release_files_present": not missing_required,
        "no_generated_noise_in_git_status": not generated_noise,
        "no_review_required_artifacts": not review_required_artifacts,
        "no_unclassified_changes": not unclassified,
        "clean_worktree_when_strict": not entries if strict_clean else True,
        "package_input_bytes_match_index_when_strict": bool(package_input_bytes["valid"]) if strict_clean else True,
    }

    return {
        "schema": "k_guard_release_hygiene.v1",
        "strict_clean": strict_clean,
        "passed": all(pass_conditions.values()),
        "pass_conditions": pass_conditions,
        "version": {
            "pyproject": project_version,
            "package": package_version,
            "consistent": version_consistent,
            "release_tag": release_tag,
        },
        "package_input_bytes": package_input_bytes,
        "required_release_files": {
            "missing": missing_required,
        },
        "tracking_jsonl": tracking_jsonl,
        "root_json_artifacts": root_json_artifacts,
        "release_authorization": release_authorization,
        "evidence_tree": evidence_tree,
        "ignored_release_artifacts": ignored_release_artifacts,
        "git_status": {
            "dirty": bool(entries),
            "entry_count": len(entries),
            "categories": {key: len(value) for key, value in sorted(grouped.items())},
            "entries_by_category": grouped,
        },
        "release_boundary": {
            "release_candidate_categories": [
                "release_root",
                "release_source",
                "root_evidence_report",
                "release_evidence",
                "release_submission",
            ],
            "blocking_categories": ["review_required_artifact", "unclassified", "generated_noise"],
            "excluded_runtime_prefixes": list(GENERATED_NOISE_PREFIXES),
            "publish_rule": "Run with --strict-clean after committing the release candidate; strict or tagged release authorization requires package_ready=true with a package-ready status and current-source performance evidence, while historical performance and honestly blocked readiness reports remain valid only for non-release hygiene. Strict mode also requires an empty status and exact worktree/index bytes for package build inputs. Tagged releases require --expected-tag v{project.version}.",
        },
    }


def _print_text(report: dict[str, Any]) -> None:
    status = "PASS" if report["passed"] else "FAIL"
    print(f"K-Guard release hygiene: {status}")
    print(f"strict_clean={report['strict_clean']}")
    print(
        "version="
        f"{report['version']['pyproject']} "
        f"(package {report['version']['package']}, consistent={report['version']['consistent']})"
    )
    release_tag = report["version"]["release_tag"]
    if release_tag["required"]:
        print(
            f"release_tag={release_tag['provided']} "
            f"(expected {release_tag['expected']}, valid={release_tag['valid']})"
        )
    package_bytes = report["package_input_bytes"]
    print(
        "package_input_bytes="
        f"{package_bytes['tracked_file_count']} tracked, "
        f"{package_bytes['mismatch_count']} mismatched"
    )
    print(f"git_status_dirty={report['git_status']['dirty']} entries={report['git_status']['entry_count']}")
    print("categories:")
    for category, count in report["git_status"]["categories"].items():
        print(f"  {category}: {count}")
    failed = [name for name, passed in report["pass_conditions"].items() if not passed]
    if failed:
        print("failed_conditions:")
        for name in failed:
            print(f"  {name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check K-Guard release worktree hygiene.")
    parser.add_argument("--json", action="store_true", help="Write machine-readable JSON.")
    parser.add_argument("--strict-clean", action="store_true", help="Require a completely clean git worktree.")
    parser.add_argument("--expected-tag", help="Require an exact v{project.version} release tag.")
    args = parser.parse_args(argv)

    report = build_report(strict_clean=args.strict_clean, expected_tag=args.expected_tag)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        _print_text(report)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
