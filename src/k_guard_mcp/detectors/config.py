from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.ids import IdFactory
from k_guard_mcp.models import Finding


CONFIG_SIGNAL_MARKERS = (
    "access-control-allow-origin",
    "cors",
    "debug",
    "sourcemap",
    "next_public",
    "vite_",
    "react_app_",
    "docker.sock",
    "privileged",
    "secrets.",
    "node_tls_reject_unauthorized",
    "rejectunauthorized",
    "verify",
    "uses",
    ":latest",
    "content-security-policy",
    "blockpublicaccess",
    "publicaccessblock",
    "public_bucket",
    "public-bucket",
    "makepublic",
)

_DOCKER_SOCKET_BIND_MOUNT = re.compile(
    r"/{1,2}var/run/docker\.sock\s*:\s*/{1,2}var/run/docker\.sock(?:\s*:\s*(?:ro|rw))?",
    re.IGNORECASE,
)
_DOCKER_SOCKET_API_ENDPOINT = re.compile(
    r"(?:unix:///{0,1}var/run/docker\.sock|(?:base_url|endpoint|host|socketpath|socket_path)\s*[:=].*docker\.sock)",
    re.IGNORECASE,
)
_GHA_MUTABLE_ACTION_REF = re.compile(
    r"\buses\s*:\s*['\"]?"
    r"[a-z0-9_.-]+/[a-z0-9_.-]+(?:/[a-z0-9_.-]+)*"
    r"@(main|master|latest)(?=['\"\s#]|$)",
    re.IGNORECASE,
)
_GHA_RELEASE_ACTION_MARKERS = (
    "actions-gh-pages",
    "actions-tagger",
    "action-gh-release",
    "action-hosting-deploy",
    "create-release",
    "deploy-cloudrun",
    "github-pages-deploy-action",
    "gh-action-pypi-publish",
    "goreleaser-action",
    "ncipollo/release-action",
    "publish-docker",
    "scp-action",
    "ssh-action",
    "upload-release",
    "vercel-action",
)
_GHA_RELEASE_COMMAND = re.compile(
    r"(?im)(?:^|[;&|]\s*)"
    r"(?:sudo\s+)?(?:"
    r"npm\s+publish\b|"
    r"docker\s+push\b|"
    r"docker\s+buildx\s+build\b[^\r\n]*\s--push\b|"
    r"gh\s+release\b|"
    r"scp\s+\S|"
    r"rsync\s+\S|"
    r"twine\s+upload\b|"
    r"cargo\s+publish\b|"
    r"dotnet\s+nuget\s+push\b|"
    r"mvn\s+deploy\b|"
    r"(?:gradle|gradlew|\.\\gradlew|\./gradlew)\b[^\r\n]*\bpublish\b|"
    r"goreleaser(?:\s+release)?\b|"
    r"kubectl\s+apply\b|"
    r"helm\s+upgrade\b|"
    r"vercel\s+deploy\b|"
    r"firebase\s+deploy\b|"
    r"gcloud\s+run\s+deploy\b|"
    r"az\s+webapp\s+deploy\b"
    r")",
    re.IGNORECASE,
)
_GHA_RUNTIME_OR_RELEASE_SECRET = re.compile(
    r"secrets\.(?:"
    r"database_url|db_password|postgres(?:ql)?_password|secret_key|private_key|"
    r"service_role(?:_key)?|aws_access_key_id|aws_secret_access_key|"
    r"azure_credentials|google_credentials|gcp_service_account_key|"
    r"kubeconfig|kube_config|cloudflare_api_token|vercel_token|"
    r"netlify_auth_token|heroku_api_key|"
    r"(?:deploy|deployment|docker|npm|registry|publish|release|ssh)[a-z0-9_]*"
    r"(?:token|password|key|secret)|"
    r"(?:token|password|key|secret)[a-z0-9_]*"
    r"(?:deploy|deployment|docker|npm|registry|publish|release|ssh)"
    r")\b",
    re.IGNORECASE,
)
_GHA_RELEASE_WRITE_PERMISSIONS = frozenset(
    {"contents", "packages", "deployments", "pages", "id-token"}
)
_GHA_FALSE_VALUES = frozenset({"", "0", "false", "no", "off", "none", "null"})
_GHA_RELEASE_ENVIRONMENT = re.compile(
    r"(?:^|[-_/.])(?:prod(?:uction)?|release|deploy(?:ment)?)(?:$|[-_/.])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _GithubJob:
    name: str
    start_line: int
    end_line: int
    data: Mapping[str, Any]


@dataclass(frozen=True)
class _GithubWorkflow:
    global_permissions: Any
    global_environment: Any
    jobs: tuple[_GithubJob, ...]
    parse_error: bool = False


@dataclass(frozen=True)
class _GithubMutableRefAssessment:
    severity: str
    confidence: str
    subtype: str
    context_hash: str | None = None


class ConfigDetector:
    def __init__(self, id_factory: IdFactory | None = None) -> None:
        self.ids = id_factory or IdFactory()

    def scan_text(self, text: str, file: str | None = None) -> list[Finding]:
        if str(file or "").lower().endswith((".md", ".txt", ".log", ".csv", ".tsv")):
            return []
        lower_text = text.lower()
        if not any(marker in lower_text for marker in CONFIG_SIGNAL_MARKERS):
            return []
        findings: list[Finding] = []
        normalized_text = _normalize_yaml_line_endings(text)
        lines = _config_lines_without_comments(normalized_text)
        github_workflow = (
            _parse_github_workflow(normalized_text)
            if _github_workflow_path(file)
            and _GHA_MUTABLE_ACTION_REF.search(normalized_text)
            else None
        )
        for idx, line in enumerate(lines, start=1):
            lower = line.lower()
            if re.search(r"access-control-allow-origin\s*[:=]\s*['\"]?\*", lower) or re.search(r"cors\s*\([^)]*origin\s*:\s*['\"]?\*", lower):
                findings.append(self._finding("CONFIG_CORS_WILDCARD", "medium", "medium", "Wildcard CORS origin needs endpoint review", line, idx, file, "Confirm the endpoint is intentionally public; otherwise restrict CORS origins to trusted domains."))
            reflected_origin = re.search(
                r"(?:access-control-allow-origin|origin\s*:)[^\n]*(?:request|req)[^\n]*origin", lower
            )
            credentialed = re.search(r"(?:access-control-allow-credentials|credentials\s*:)\s*['\"]?true", lower)
            if reflected_origin and credentialed:
                findings.append(self._finding("CONFIG_CORS_REFLECTED_CREDENTIALS", "high", "high", "Request Origin is reflected with credentials", line, idx, file, "Use an exact trusted-origin allowlist before enabling credentialed cross-origin requests."))
            if re.search(r"\bdebug\s*[:=]\s*(true|1|yes)\b", lower):
                findings.append(self._finding("CONFIG_DEBUG_TRUE", "medium", "medium", "Debug mode enabled", line, idx, file, "Disable debug mode outside local development."))
            if "sourcemap" in lower and re.search(r"(true|enabled|hidden-source-map|source-map)", lower):
                findings.append(self._finding("CONFIG_SOURCE_MAP_ENABLED", "medium", "medium", "Source map appears enabled", line, idx, file, "Do not expose production source maps unless access controlled."))
            public_env = re.search(r"\b(next_public|vite_|react_app_)", lower)
            if public_env and re.search(r"(secret|token|private|password|service_role)", lower):
                findings.append(self._finding("CONFIG_PUBLIC_ENV_SECRET", "critical", "high", "Client-exposed environment variable name contains secret semantics", line, idx, file, "Move secrets to server-only environment variables."))
            elif public_env and re.search(r"api[_-]?key", lower) and not re.search(r"(?:firebase|mapbox|google[_-]?maps|public|anon).*api[_-]?key|api[_-]?key.*(?:public|anon)", lower):
                findings.append(self._finding("CONFIG_PUBLIC_ENV_API_KEY_REVIEW", "medium", "low", "Client API key needs provider restriction review", line, idx, file, "Confirm the provider treats this as a public client identifier, then restrict origin/API scope, quota, and billing alerts; otherwise move it server-side."))
            if public_env and ("supabase_service_role_key" in lower or "service_role" in lower and "supabase" in lower):
                findings.append(self._finding("CONFIG_SUPABASE_SERVICE_ROLE", "critical", "high", "Supabase service role key is client-exposed", line, idx, file, "Never expose service role keys to browsers or public bundles."))
            if public_env and ("firebase_private_key" in lower or "private_key" in lower and "firebase" in lower):
                findings.append(self._finding("CONFIG_FIREBASE_PRIVATE_KEY", "critical", "high", "Firebase private key is client-exposed", line, idx, file, "Keep Firebase private keys server-side only."))
            if "docker.sock" in lower:
                subtype = _docker_socket_subtype(line, file)
                findings.append(
                    self._finding(
                        "CONFIG_DOCKER_SOCK",
                        "critical",
                        "high",
                        "Docker socket access needs intent review",
                        line,
                        idx,
                        file,
                        "Treat Docker socket access as host-control authority. Remove it, place a constrained socket proxy in front of it, or document and approve the service's control-plane purpose.",
                        detector_subtype=subtype,
                    )
                )
            if re.search(r"\bprivileged\s*:\s*true\b", lower):
                findings.append(self._finding("CONFIG_DOCKER_PRIVILEGED", "high", "medium", "Docker privileged mode enabled", line, idx, file, "Avoid privileged containers unless strictly required."))
            if re.search(r"\becho\b.*\$\{\{\s*secrets\.", lower):
                findings.append(self._finding("CONFIG_GHA_SECRET_ECHO", "critical", "medium", "GitHub Actions may echo secrets", line, idx, file, "Do not print secrets in CI logs."))
            explicit_tls_bypass = re.search(r"(?:node_tls_reject_unauthorized\s*[:=]\s*['\"]?0|rejectunauthorized\s*:\s*false)", lower)
            contextual_verify_bypass = re.search(r"(?:^|[\s,{])verify\s*[:=]\s*false", lower) and re.search(r"(?:https?|tls|ssl|requests?\.|httpx|urllib)", lower)
            if explicit_tls_bypass or contextual_verify_bypass:
                findings.append(self._finding("CONFIG_TLS_VERIFY_DISABLED", "high", "high", "TLS certificate verification disabled", line, idx, file, "Restore certificate verification and install the intended CA chain instead of bypassing trust checks."))
            if _GHA_MUTABLE_ACTION_REF.search(lower):
                assessment = _github_action_mutable_ref_context(
                    github_workflow,
                    idx - 1,
                    file,
                )
                findings.append(
                    self._finding(
                        "CONFIG_GHA_MUTABLE_ACTION_REF",
                        assessment.severity,
                        assessment.confidence,
                        "GitHub Action uses a mutable branch or latest tag",
                        line,
                        idx,
                        file,
                        "Pin third-party actions to a reviewed full commit SHA and use an update workflow for controlled upgrades.",
                        detector_subtype=assessment.subtype,
                        context_hash=assessment.context_hash,
                    )
                )
            if re.search(r"(?:^\s*from\s+\S+:latest\b|\bimage\s*:\s*\S+:latest\b)", lower):
                findings.append(self._finding("CONFIG_CONTAINER_LATEST_TAG", "medium", "high", "Container image uses the mutable latest tag", line, idx, file, "Pin release images to an immutable digest or reviewed version tag."))
            if "content-security-policy" in lower and ("'unsafe-eval'" in lower or '"unsafe-eval"' in lower):
                findings.append(self._finding("CONFIG_CSP_UNSAFE_EVAL", "high", "high", "Content Security Policy allows unsafe-eval", line, idx, file, "Remove unsafe-eval and refactor code or dependencies that require runtime string evaluation."))
            if re.search(r"(?:blockpublicaccess|publicaccessblock)\s*[:=]\s*false", lower):
                findings.append(self._finding("CONFIG_PUBLIC_STORAGE_REVIEW", "high", "medium", "Storage configuration appears to permit public access", line, idx, file, "Keep user uploads and private records non-public; expose only reviewed public assets through a separate bucket or signed URLs."))
            elif re.search(r"public[_-]?bucket\s*[:=]\s*true", lower) or re.search(r"makepublic\s*\(\s*true", lower):
                findings.append(self._finding("CONFIG_PUBLIC_STORAGE_REVIEW", "medium", "low", "Storage is explicitly public and needs data-class review", line, idx, file, "Confirm the bucket contains only approved public assets; keep user uploads and private records in a separate non-public store."))
        return findings

    def _finding(
        self,
        rule_id: str,
        severity: str,
        confidence: str,
        title: str,
        line: str,
        line_no: int,
        file: str | None,
        recommendation: str,
        *,
        detector_subtype: str | None = None,
        context_hash: str | None = None,
    ) -> Finding:
        return Finding(
            id=self.ids.next(),
            source="config",
            rule_id=rule_id,
            severity=severity,
            confidence=confidence,
            title=title,
            file=file,
            line_start=line_no,
            line_end=line_no,
            evidence=_safe_config_evidence(
                line,
                detector_subtype=detector_subtype,
                context_hash=context_hash,
            ),
            why_it_matters="Unsafe configuration can expose sensitive data or weaken access controls.",
            recommendation=recommendation,
        )


def _safe_config_evidence(
    line: str,
    *,
    detector_subtype: str | None = None,
    context_hash: str | None = None,
) -> str:
    prefix = f"detector_subtype={detector_subtype} " if detector_subtype else ""
    context = f"context_hash={context_hash} " if context_hash else ""
    return (
        f"{prefix}{context}line_hash={evidence_hash(line)} "
        f"scheme={evidence_hash_scheme()} raw_returned=false"
    )


def _docker_socket_subtype(line: str, file: str | None) -> str:
    if _docker_socket_documentation_path(file):
        return "docker_socket_documentation"
    if _DOCKER_SOCKET_BIND_MOUNT.search(line):
        return "docker_socket_bind_mount"
    if _DOCKER_SOCKET_API_ENDPOINT.search(line):
        return "docker_socket_api_endpoint"
    return "docker_socket_reference"


def _docker_socket_documentation_path(file: str | None) -> bool:
    normalized = str(file or "").replace("\\", "/").casefold()
    name = normalized.rsplit("/", 1)[-1]
    parts = set(normalized.split("/"))
    return bool(
        parts & {"doc", "docs", "documentation", "tutorial", "tutorials"}
        or "documentationmarkdown" in name
        or "docsmarkdown" in name
        or name.startswith(("readme.", "guide."))
    )


def _github_action_mutable_ref_context(
    workflow: _GithubWorkflow | None,
    line_index: int,
    file: str | None,
) -> _GithubMutableRefAssessment:
    if not _github_workflow_path(file):
        return _GithubMutableRefAssessment(
            "medium",
            "medium",
            "gha_mutable_action_context_unverified",
        )
    if workflow is None or workflow.parse_error:
        return _GithubMutableRefAssessment(
            "high",
            "low",
            "gha_mutable_action_workflow_parse_failed",
            evidence_hash("github_workflow_parse_failed"),
        )

    job = _github_job_for_line(workflow, line_index)
    if job is None:
        return _GithubMutableRefAssessment(
            "high",
            "low",
            "gha_mutable_action_job_unresolved",
            evidence_hash("github_workflow_job_unresolved"),
        )

    release_operation = _github_job_has_release_operation(job.data)
    reusable_workflow_authority = (
        _github_job_has_reusable_workflow_authority(job.data)
    )
    write_permission = _github_permissions_have_release_write(
        _github_effective_permissions(workflow, job)
    )
    artifact_chain = _github_workflow_has_release_artifact_chain(workflow, job)
    authority_text = "\n".join(
        (
            _yaml_scalar_text(workflow.global_environment),
            _yaml_scalar_text(job.data),
        )
    )
    runtime_or_release_secret = bool(
        _GHA_RUNTIME_OR_RELEASE_SECRET.search(authority_text)
    )
    context_hash = _github_action_context_hash(
        job,
        release_operation=release_operation,
        reusable_workflow_authority=reusable_workflow_authority,
        write_permission=write_permission,
        artifact_chain=artifact_chain,
        runtime_or_release_secret=runtime_or_release_secret,
    )
    if release_operation:
        return _GithubMutableRefAssessment(
            "high",
            "medium",
            "gha_mutable_action_release_operation",
            context_hash,
        )
    if reusable_workflow_authority:
        return _GithubMutableRefAssessment(
            "high",
            "medium",
            "gha_mutable_action_reusable_workflow_authority",
            context_hash,
        )
    if write_permission:
        return _GithubMutableRefAssessment(
            "high",
            "medium",
            "gha_mutable_action_write_permission",
            context_hash,
        )
    if artifact_chain:
        return _GithubMutableRefAssessment(
            "high",
            "medium",
            "gha_mutable_action_release_artifact_chain",
            context_hash,
        )
    if runtime_or_release_secret:
        return _GithubMutableRefAssessment(
            "high",
            "medium",
            "gha_mutable_action_runtime_or_release_secret",
            context_hash,
        )
    return _GithubMutableRefAssessment(
        "medium",
        "high",
        "gha_mutable_action_review",
        context_hash,
    )


def _github_workflow_path(file: str | None) -> bool:
    normalized = str(file or "").replace("\\", "/").casefold()
    return normalized.endswith((".yml", ".yaml")) and (
        normalized.startswith(".github/workflows/")
        or "/.github/workflows/" in normalized
    )


def _parse_github_workflow(text: str) -> _GithubWorkflow:
    try:
        root_node = yaml.compose(text, Loader=yaml.SafeLoader)
        if root_node is None or _yaml_has_ambiguous_mapping(root_node):
            return _GithubWorkflow(None, None, (), parse_error=True)
        root_data = yaml.safe_load(text)
    except yaml.YAMLError:
        return _GithubWorkflow(None, None, (), parse_error=True)
    if not isinstance(root_node, MappingNode) or not isinstance(root_data, Mapping):
        return _GithubWorkflow(None, None, (), parse_error=True)

    jobs_node = _yaml_mapping_node_value(root_node, "jobs")
    jobs_data = _mapping_value(root_data, "jobs")
    if not isinstance(jobs_node, MappingNode) or not isinstance(jobs_data, Mapping):
        return _GithubWorkflow(
            _mapping_value(root_data, "permissions"),
            _mapping_value(root_data, "env"),
            (),
            parse_error=True,
        )

    job_nodes = list(jobs_node.value)
    jobs_end_line = jobs_node.end_mark.line + (
        1 if jobs_node.end_mark.column > 0 else 0
    )
    jobs: list[_GithubJob] = []
    seen_names: set[str] = set()
    for index, (key_node, _value_node) in enumerate(job_nodes):
        if not isinstance(key_node, ScalarNode):
            return _GithubWorkflow(None, None, (), parse_error=True)
        name = str(key_node.value)
        if name in seen_names:
            return _GithubWorkflow(None, None, (), parse_error=True)
        seen_names.add(name)
        data = _mapping_value(jobs_data, name, case_sensitive=True)
        if not isinstance(data, Mapping):
            return _GithubWorkflow(None, None, (), parse_error=True)
        start_line = key_node.start_mark.line
        end_line = (
            job_nodes[index + 1][0].start_mark.line
            if index + 1 < len(job_nodes)
            else jobs_end_line
        )
        jobs.append(_GithubJob(name, start_line, end_line, data))

    return _GithubWorkflow(
        _mapping_value(root_data, "permissions"),
        _mapping_value(root_data, "env"),
        tuple(jobs),
        parse_error=not jobs,
    )


def _yaml_has_ambiguous_mapping(
    node: Node,
    visited: set[int] | None = None,
) -> bool:
    visited = set() if visited is None else visited
    node_identity = id(node)
    if node_identity in visited:
        return False
    visited.add(node_identity)

    if isinstance(node, MappingNode):
        keys: set[str] = set()
        for key_node, value_node in node.value:
            if not isinstance(key_node, ScalarNode):
                return True
            key = str(key_node.value).casefold()
            if key in keys:
                return True
            keys.add(key)
            if _yaml_has_ambiguous_mapping(value_node, visited):
                return True
        return False
    if isinstance(node, SequenceNode):
        return any(
            _yaml_has_ambiguous_mapping(item, visited)
            for item in node.value
        )
    return False


def _yaml_mapping_node_value(node: Node, key: str) -> Node | None:
    if not isinstance(node, MappingNode):
        return None
    expected = key.casefold()
    for key_node, value_node in node.value:
        if (
            isinstance(key_node, ScalarNode)
            and str(key_node.value).casefold() == expected
        ):
            return value_node
    return None


def _github_job_for_line(
    workflow: _GithubWorkflow,
    line_index: int,
) -> _GithubJob | None:
    return next(
        (
            job
            for job in workflow.jobs
            if job.start_line <= line_index < job.end_line
        ),
        None,
    )


def _github_effective_permissions(
    workflow: _GithubWorkflow,
    job: _GithubJob,
) -> Any:
    if _mapping_has_key(job.data, "permissions"):
        return _mapping_value(job.data, "permissions")
    return workflow.global_permissions


def _github_permissions_have_release_write(permissions: Any) -> bool:
    if isinstance(permissions, str):
        return permissions.strip().casefold() == "write-all"
    if not isinstance(permissions, Mapping):
        return False
    return any(
        str(key).strip().casefold() in _GHA_RELEASE_WRITE_PERMISSIONS
        and str(value).strip().casefold() == "write"
        for key, value in permissions.items()
    )


def _github_job_has_release_operation(job_data: Mapping[str, Any]) -> bool:
    job_uses = str(_mapping_value(job_data, "uses") or "").casefold()
    if any(marker in job_uses for marker in _GHA_RELEASE_ACTION_MARKERS):
        return True
    for step in _github_job_steps(job_data):
        uses = str(_mapping_value(step, "uses") or "").casefold()
        if any(marker in uses for marker in _GHA_RELEASE_ACTION_MARKERS):
            return True
        if "docker/build-push-action" in uses:
            with_block = _mapping_value(step, "with")
            push = (
                _mapping_value(with_block, "push")
                if isinstance(with_block, Mapping)
                else None
            )
            if _github_value_enables_action(push):
                return True
        run = _mapping_value(step, "run")
        if isinstance(run, str) and _GHA_RELEASE_COMMAND.search(run):
            return True
    return False


def _github_job_has_reusable_workflow_authority(
    job_data: Mapping[str, Any],
) -> bool:
    uses = str(_mapping_value(job_data, "uses") or "").casefold()
    if "/.github/workflows/" not in uses:
        return False

    secrets = _mapping_value(job_data, "secrets")
    if isinstance(secrets, str) and secrets.strip().casefold() == "inherit":
        return True
    if isinstance(secrets, Mapping) and bool(secrets):
        return True

    environment = _yaml_scalar_text(
        _mapping_value(job_data, "environment")
    ).strip()
    return bool(
        environment and _GHA_RELEASE_ENVIRONMENT.search(environment)
    )


def _github_value_enables_action(value: Any) -> bool:
    if value is True:
        return True
    if value is False or value is None:
        return False
    normalized = str(value).strip().casefold()
    return normalized not in _GHA_FALSE_VALUES


def _github_job_steps(job_data: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    steps = _mapping_value(job_data, "steps")
    if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)):
        return ()
    return tuple(step for step in steps if isinstance(step, Mapping))


def _github_workflow_has_release_artifact_chain(
    workflow: _GithubWorkflow,
    source_job: _GithubJob,
) -> bool:
    source_artifacts = _github_artifact_names(source_job.data, upload=True)
    if not source_artifacts:
        return False

    lineage: dict[str, frozenset[str]] = {
        source_job.name: source_artifacts
    }
    for _ in workflow.jobs:
        changed = False
        for downstream in workflow.jobs:
            inherited = frozenset(
                artifact
                for dependency in _github_job_needs(downstream.data)
                for artifact in lineage.get(dependency, ())
            )
            if not inherited:
                continue

            downloaded = _github_artifact_names(
                downstream.data,
                upload=False,
            )
            consumes_lineage = bool(
                downloaded
                and _github_artifact_names_overlap(inherited, downloaded)
            )
            if (
                consumes_lineage
                and _github_job_has_release_operation(downstream.data)
            ):
                return True

            propagated = set(inherited)
            if consumes_lineage:
                propagated.update(
                    _github_artifact_names(
                        downstream.data,
                        upload=True,
                    )
                )
            combined = frozenset(
                set(lineage.get(downstream.name, ())) | propagated
            )
            if combined != lineage.get(downstream.name):
                lineage[downstream.name] = combined
                changed = True
        if not changed:
            break
    return False


def _github_artifact_names(
    job_data: Mapping[str, Any],
    *,
    upload: bool,
) -> frozenset[str]:
    marker = "actions/upload-artifact" if upload else "actions/download-artifact"
    names: set[str] = set()
    for step in _github_job_steps(job_data):
        uses = str(_mapping_value(step, "uses") or "").casefold()
        if marker not in uses:
            continue
        with_block = _mapping_value(step, "with")
        name = (
            _mapping_value(with_block, "name")
            if isinstance(with_block, Mapping)
            else None
        )
        if name is None:
            names.add("artifact" if upload else "*")
        else:
            names.add(str(name).strip())
    return frozenset(names)


def _github_artifact_names_overlap(
    uploaded_names: frozenset[str],
    downloaded_names: frozenset[str],
) -> bool:
    return "*" in downloaded_names or bool(uploaded_names & downloaded_names)


def _github_job_needs(job_data: Mapping[str, Any]) -> frozenset[str]:
    needs = _mapping_value(job_data, "needs")
    if isinstance(needs, str):
        return frozenset({needs})
    if isinstance(needs, Sequence) and not isinstance(needs, (str, bytes)):
        return frozenset(str(item) for item in needs)
    return frozenset()


def _github_action_context_hash(
    job: _GithubJob,
    *,
    release_operation: bool,
    reusable_workflow_authority: bool,
    write_permission: bool,
    artifact_chain: bool,
    runtime_or_release_secret: bool,
) -> str:
    payload = {
        "artifact_chain": artifact_chain,
        "job_name_hash": evidence_hash(job.name),
        "release_operation": release_operation,
        "reusable_workflow_authority": reusable_workflow_authority,
        "runtime_or_release_secret": runtime_or_release_secret,
        "write_permission": write_permission,
    }
    return evidence_hash(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    )


def _mapping_has_key(mapping: Mapping[Any, Any], key: str) -> bool:
    expected = key.casefold()
    return any(str(candidate).casefold() == expected for candidate in mapping)


def _mapping_value(
    mapping: Mapping[Any, Any],
    key: str,
    *,
    case_sensitive: bool = False,
) -> Any:
    if case_sensitive:
        return mapping.get(key)
    expected = key.casefold()
    return next(
        (
            value
            for candidate, value in mapping.items()
            if str(candidate).casefold() == expected
        ),
        None,
    )


def _yaml_scalar_text(value: Any) -> str:
    if isinstance(value, Mapping):
        return "\n".join(
            f"{key}\n{_yaml_scalar_text(item)}"
            for key, item in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return "\n".join(_yaml_scalar_text(item) for item in value)
    return "" if value is None else str(value)


def _normalize_yaml_line_endings(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _config_lines_without_comments(text: str) -> list[str]:
    lines: list[str] = []
    in_block_comment = False
    for raw_line in text.splitlines():
        output: list[str] = []
        quote = ""
        escaped = False
        index = 0
        while index < len(raw_line):
            character = raw_line[index]
            next_character = raw_line[index + 1] if index + 1 < len(raw_line) else ""
            if in_block_comment:
                if character == "*" and next_character == "/":
                    in_block_comment = False
                    index += 2
                    continue
                index += 1
                continue
            if escaped:
                output.append(character)
                escaped = False
            elif character == "\\" and quote:
                output.append(character)
                escaped = True
            elif quote:
                output.append(character)
                if character == quote:
                    quote = ""
            elif character in {"'", '"', "`"}:
                quote = character
                output.append(character)
            elif character == "/" and next_character == "*":
                in_block_comment = True
                index += 2
                continue
            elif character == "#":
                break
            elif character == "/" and next_character == "/" and (index == 0 or raw_line[index - 1].isspace()):
                break
            elif character == "-" and next_character == "-" and (index == 0 or raw_line[index - 1].isspace()):
                break
            else:
                output.append(character)
            index += 1
        lines.append("".join(output))
    return lines
