from __future__ import annotations

import csv
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence

from k_guard_mcp.hashing import (
    EVIDENCE_HMAC_ENV,
    evidence_hash,
    evidence_hash_scheme,
    operator_evidence_key_value_is_valid,
)


SERVER_NAME = "k-guard"
SUPPORTED_CLIENTS = ("chatgpt", "grok", "codex", "antigravity")
CLIENT_CHOICES = ("auto", *SUPPORTED_CLIENTS, "all")
PROFILE_CHOICES = ("workspace", "local-dev")

_CLIENT_EXECUTABLES = {"chatgpt": "tunnel-client", "grok": "grok", "codex": "codex"}
_CHATGPT_TUNNEL_ID_ENV = "CONTROL_PLANE_TUNNEL_ID"
_CHATGPT_TUNNEL_PROFILE = "k-guard"
_LOCAL_PROBE_ENV = "K_GUARD_MCP_ENABLE_PROBE"
_DEEP_PROBE_ENV = "K_GUARD_MCP_ENABLE_DEEP_ACTIVE_PROBE"
_PROBE_ENV_VARS = (
    _LOCAL_PROBE_ENV,
    "K_GUARD_MCP_ENABLE_SESSION_PROBE",
    _DEEP_PROBE_ENV,
    "K_GUARD_MCP_ENABLE_EXTERNAL_PROBE",
    "K_GUARD_MCP_EXTERNAL_ALLOWED_HOSTS",
)
_MAX_JSON_BYTES = 4 * 1024 * 1024
_RECEIPT_SCHEMA_VERSION = 1
_WORKSPACE_BINDING_SCHEMA_VERSION = 1
_WORKSPACE_ROOT_ENV = "K_GUARD_WORKSPACE_ROOT"
_WORKSPACE_HASH_CONTEXT = b"k-guard-workspace-root-v1\0"
_WORKSPACE_HASH_SCHEME = "hmac-sha256:operator-keyed:workspace-root-v1:len16"
_LAUNCHER_MARKER = "K_GUARD_PRIVATE_LAUNCHER_V1"
_CLIENT_LABELS = {
    "chatgpt": "ChatGPT / GPT",
    "grok": "Grok",
    "codex": "Codex",
    "antigravity": "Antigravity",
    "auto": "자동 찾기",
    "installer": "설치 기록",
}
_CHECK_LABELS = {
    "private_launcher": "안경선배 실행기",
    "operator_evidence_key": "검수 증거 키",
    "secret_not_embedded": "키 원문 비포함",
    "private_permissions": "개인 설치 경로",
    "workspace_binding": "감사 workspace 결속",
    "workspace_binding_consistency": "workspace 설치 기록 일치",
    "external_probes_default_off": "동적 점검 범위",
    "launcher_runtime": "MCP 실행기 기동",
    "install_receipt": "설치 기록",
}
_WINDOWS_SET_PRIVATE_ACL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$target = [string]$request.path
$sid = [System.Security.Principal.SecurityIdentifier]::new([string]$request.sid)
$isDirectory = [bool]$request.is_directory
$acl = if ($isDirectory) {
    [System.Security.AccessControl.DirectorySecurity]::new()
} else {
    [System.Security.AccessControl.FileSecurity]::new()
}
$acl.SetAccessRuleProtection($true, $false)
$inheritance = [System.Security.AccessControl.InheritanceFlags]::None
if ($isDirectory) {
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
}
$privateRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    $inheritance,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
)
[void]$acl.AddAccessRule($privateRule)
$acl.SetOwner($sid)
if ($isDirectory) {
    [System.IO.Directory]::SetAccessControl($target, $acl)
} else {
    [System.IO.File]::SetAccessControl($target, $acl)
}
""".strip()
_WINDOWS_READ_PRIVATE_ACL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$target = [string]$request.path
if ([bool]$request.is_directory) {
    $acl = [System.IO.Directory]::GetAccessControl($target)
} else {
    $acl = [System.IO.File]::GetAccessControl($target)
}
$fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
$rules = @(
    $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
        [PSCustomObject]@{
            sid = $_.IdentityReference.Value
            access_type = $_.AccessControlType.ToString()
            inherited = [bool]$_.IsInherited
            full_control = [bool](($_.FileSystemRights -band $fullControl) -eq $fullControl)
            inheritance_flags = $_.InheritanceFlags.ToString()
            propagation_flags = $_.PropagationFlags.ToString()
        }
    }
)
[PSCustomObject]@{
    protected = [bool]$acl.AreAccessRulesProtected
    owner_sid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    rules = [object[]]$rules
} | ConvertTo-Json -Compress -Depth 4
""".strip()


class InstallerError(RuntimeError):
    pass


@dataclass(frozen=True)
class _CommandOutcome:
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and self.error is None


@dataclass(frozen=True)
class _Locations:
    user_home: Path
    private_dir: Path
    launcher: Path
    key: Path
    workspace_binding: Path
    receipt: Path
    antigravity_config: Path


@dataclass(frozen=True)
class _InstallFileState:
    path: Path
    existed: bool
    content: bytes
    mode: int


def install(
    client: str = "auto",
    profile: str = "workspace",
    dry_run: bool = False,
    *,
    home: str | Path | None = None,
    cwd: str | Path | None = None,
    workspace: str | Path | None = None,
    python_executable: str | Path | None = None,
) -> dict[str, Any]:
    """Install K-Guard for one or more supported MCP clients.

    The returned structure is deliberately secret-free. In particular, it never
    contains the operator evidence key or captured client command output.
    """

    _validate_choice(client, CLIENT_CHOICES, "client")
    _validate_choice(profile, PROFILE_CHOICES, "profile")
    locations = _locations(home)
    report = _install_report_base(client, profile, dry_run, locations)
    requested_workspace = workspace if workspace is not None else cwd if cwd is not None else Path.cwd()
    try:
        workspace_root = _canonical_workspace(requested_workspace)
    except InstallerError:
        report.update(
            {
                "status": "설치 중단",
                "message": "감사 workspace가 존재하는 일반 디렉터리가 아니거나 symlink 또는 junction을 포함해 어떤 설정도 바꾸지 않았습니다.",
                "error_code": "INVALID_WORKSPACE",
                "workspace_binding": {
                    "configured": False,
                    "status": "invalid",
                    "raw_path_returned": False,
                },
            }
        )
        return _finalize_install_report(report)
    report["workspace_binding"] = _workspace_reference(workspace_root)
    python = str(Path(python_executable or sys.executable).expanduser().resolve())
    discovered = _discover_clients(locations)
    targets = _resolve_targets(client, discovered)

    if not Path(python).is_file():
        report.update(
            {
                "status": "설치 중단",
                "message": "현재 Python 실행 파일을 확인할 수 없습니다.",
                "error_code": "PYTHON_EXECUTABLE_NOT_FOUND",
            }
        )
        return _finalize_install_report(report)

    if not targets:
        report.update(
            {
                "status": "설치할 클라이언트 없음",
                "message": "지원 클라이언트를 찾지 못했습니다. --client로 대상을 직접 지정해 주세요.",
                "error_code": "NO_SUPPORTED_CLIENT_FOUND",
            }
        )
        return _finalize_install_report(report)

    try:
        receipt = _load_receipt(locations.receipt)
    except InstallerError:
        report.update(
            {
                "status": "설치 중단",
                "message": "기존 K-Guard 설치 기록이 올바른 JSON이 아닙니다. 원본을 보존한 채 중단했습니다.",
                "error_code": "INVALID_INSTALL_RECEIPT",
            }
        )
        return _finalize_install_report(report)

    actionable_targets = [
        target for target in targets if target == "antigravity" or bool(discovered.get(target))
    ]
    preflight_errors: list[dict[str, Any]] = []
    if client in {"all", "chatgpt"}:
        preflight_errors.extend(
            _client_not_found(target)
            for target in targets
            if target in _CLIENT_EXECUTABLES and not discovered.get(target)
        )
        if "chatgpt" in actionable_targets and not _chatgpt_tunnel_id_is_valid():
            preflight_errors.append(_chatgpt_tunnel_id_required())
    if "antigravity" in targets:
        antigravity_error = _antigravity_preflight_error(locations)
        if antigravity_error is not None:
            preflight_errors.append(antigravity_error)
    if preflight_errors:
        report["clients"] = preflight_errors
        report["status"] = "연결 전 준비 필요"
        report["message"] = "요청한 클라이언트를 연결하기 전에 필요한 준비가 남아 있어 어떤 설정도 바꾸지 않았습니다."
        report["preflight_passed"] = False
        return _finalize_install_report(report)
    if not actionable_targets:
        report["clients"] = [_client_not_found(target) for target in targets]
        report["status"] = "설치할 클라이언트 없음"
        report["message"] = "지정한 클라이언트 CLI를 찾지 못해 어떤 파일도 만들지 않았습니다."
        return _finalize_install_report(report)

    transaction_state: tuple[_InstallFileState, ...] = ()
    if dry_run:
        try:
            launcher_result = _plan_launcher(locations, workspace_root)
        except InstallerError as exc:
            report.update(
                {
                    "status": "설치 계획 중단",
                    "message": str(exc),
                    "error_code": "PRIVATE_LAUNCHER_PREFLIGHT_FAILED",
                }
            )
            return _finalize_install_report(report)
    else:
        try:
            transaction_state = _capture_install_transaction(locations, targets)
            launcher_result = _prepare_launcher(locations, profile, python, workspace_root)
        except InstallerError as exc:
            rollback = _rollback_install_transaction(transaction_state, locations) if transaction_state else None
            report.update(
                {
                    "status": "설치 중단",
                    "message": str(exc),
                    "error_code": "PRIVATE_LAUNCHER_SETUP_FAILED",
                }
            )
            if rollback is not None:
                report["installation_transaction"] = rollback
                report["workspace_binding"] = _current_workspace_reference(locations, status="rolled_back")
                if rollback["shared_state_restored"] is not True:
                    report.update(
                        {
                            "status": "설치 롤백 실패 · 사용 중단",
                            "message": "설치 준비가 실패했고 이전 공유 설치 상태도 완전히 복원하지 못했습니다. doctor가 통과할 때까지 MCP를 사용하지 마세요.",
                            "error_code": "INSTALL_TRANSACTION_ROLLBACK_FAILED",
                        }
                    )
            return _finalize_install_report(report)
    report["launcher"] = launcher_result
    workspace_result = launcher_result.get("workspace_binding")
    if isinstance(workspace_result, dict):
        report["workspace_binding"] = workspace_result

    results: list[dict[str, Any]] = []
    backups: list[str] = []
    workspace_backup = workspace_result.get("backup") if isinstance(workspace_result, dict) else None
    if isinstance(workspace_backup, str):
        backups.append(workspace_backup)
    for target in targets:
        executable = discovered.get(target)
        if target in _CLIENT_EXECUTABLES and not executable:
            results.append(_client_not_found(target))
            continue
        if target == "chatgpt":
            result = _install_chatgpt(str(executable), python, locations.launcher, profile, workspace_root, dry_run)
        elif target == "antigravity":
            result = _install_antigravity(locations, python, profile, dry_run)
        else:
            result = _install_cli_client(
                target,
                str(executable),
                python,
                locations.launcher,
                profile,
                workspace_root,
                dry_run,
            )
        result["profile"] = profile
        results.append(result)
        backup = result.get("backup")
        if isinstance(backup, str):
            backups.append(backup)

    transaction_viable = bool(results) and all(
        item.get("ok") is True or item.get("configured") is True for item in results
    )
    recordable = [item for item in results if item.get("ok") or item.get("configured")]
    receipt_failed = False
    if transaction_viable and recordable and not dry_run:
        try:
            receipt_backup = _write_receipt(
                locations,
                receipt,
                profile,
                python,
                recordable,
            )
            if receipt_backup:
                backups.append(str(receipt_backup))
        except InstallerError:
            receipt_failed = True
            transaction_viable = False
            results.append(
                {
                    "client": "installer",
                    "ok": False,
                    "status": "receipt_failed",
                    "message": "클라이언트 등록은 실행됐지만 설치 기록을 안전하게 저장하지 못했습니다.",
                    "mechanism": "private installation receipt",
                    "scope": "user",
                }
            )

    transaction_rollback: dict[str, Any] | None = None
    if not dry_run and not transaction_viable:
        transaction_rollback = _rollback_install_transaction(transaction_state, locations)
        for item in results:
            if item.get("ok") is True or item.get("configured") is True:
                item["transaction_state"] = "shared_state_rolled_back"
        report["installation_transaction"] = transaction_rollback
        report["workspace_binding"] = _current_workspace_reference(locations, status="rolled_back")
    elif not dry_run:
        report["installation_transaction"] = {
            "committed": True,
            "rolled_back": False,
            "shared_state_restored": False,
            "rollback_scope": "not_required",
            "external_client_registration_reversal_guaranteed": False,
        }

    report["clients"] = results
    report["backups"] = backups
    report["ok"] = bool(results) and all(bool(item.get("ok")) for item in results)
    report["partial_configuration"] = transaction_viable and any(
        item.get("ok") is True or item.get("configured") is True for item in results
    ) and any(item.get("ok") is not True for item in results)
    if transaction_rollback is not None and transaction_rollback["shared_state_restored"] is not True:
        report["status"] = "설치 롤백 실패 · 사용 중단"
        report["message"] = "클라이언트 연결이 실패했고 이전 공유 설치 상태도 완전히 복원하지 못했습니다. doctor가 통과할 때까지 MCP를 사용하지 마세요."
        report["error_code"] = "INSTALL_TRANSACTION_ROLLBACK_FAILED"
    elif transaction_rollback is not None:
        report["status"] = "설치 취소 · 이전 상태 복원"
        report["message"] = (
            "설치 기록 저장이 실패해 이전 안경선배 공유 상태를 복원했습니다."
            if receipt_failed
            else "클라이언트 연결이 완료되지 않아 이전 안경선배 공유 상태를 복원했습니다."
        )
        report["error_code"] = (
            "INSTALL_RECEIPT_TRANSACTION_FAILED" if receipt_failed else "CLIENT_REGISTRATION_TRANSACTION_FAILED"
        )
    elif report["ok"]:
        report["status"] = "설치 계획 확인" if dry_run else "설치 완료"
        report["message"] = (
            "설정 파일을 바꾸지 않고 설치 계획만 확인했습니다."
            if dry_run
            else (
                "안경선배가 연결됐습니다. 로컬 read-only 점검은 켜졌고 외부·세션 프로브는 꺼져 있습니다."
                if profile == "local-dev"
                else "안경선배가 연결됐습니다. 동적·외부 프로브는 기본으로 꺼져 있습니다."
            )
        )
    elif report["partial_configuration"]:
        report["status"] = "부분 연결 · 다음 단계 필요"
        report["message"] = "일부 클라이언트는 준비됐고 일부는 남았습니다. 완료된 설정은 유지했으며 next_steps에 남은 연결 순서를 표시했습니다."
    else:
        report["status"] = "일부 확인 필요"
        report["message"] = "완료되지 않은 클라이언트가 있습니다. client 항목을 확인해 주세요."
    return _finalize_install_report(report)


def doctor(
    client: str = "auto",
    *,
    home: str | Path | None = None,
    cwd: str | Path | None = None,
    python_executable: str | Path | None = None,
) -> dict[str, Any]:
    """Diagnose launcher privacy, runtime health, and client registrations."""

    _validate_choice(client, CLIENT_CHOICES, "client")
    locations = _locations(home)
    workspace = Path(cwd or Path.cwd()).expanduser().resolve()
    python = str(Path(python_executable or sys.executable).expanduser().resolve())
    discovered = _discover_clients(locations)

    receipt_error = False
    try:
        receipt = _load_receipt(locations.receipt)
    except InstallerError:
        receipt = {}
        receipt_error = True
    receipt_clients = receipt.get("clients", {}) if isinstance(receipt.get("clients"), dict) else {}
    targets = _resolve_targets(client, discovered, receipt_clients.keys())

    receipt_profile = str(receipt.get("profile") or "")
    checks, workspace_reference, workspace_root_hash = _doctor_launcher_checks(
        locations,
        python,
        workspace,
        receipt_profile,
        receipt,
    )
    if receipt_error:
        checks.append(
            _check(
                "install_receipt",
                False,
                "설치 기록 JSON을 읽을 수 없습니다. 파일을 복구하거나 다시 설치해 주세요.",
            )
        )
    else:
        checks.append(
            _check(
                "install_receipt",
                bool(receipt),
                "설치 기록을 확인했습니다." if receipt else "설치 기록이 아직 없습니다.",
            )
        )

    client_results = [
        _doctor_client(
            target,
            discovered.get(target),
            locations,
            python,
            workspace,
            receipt_clients,
            receipt_profile,
            workspace_root_hash=workspace_root_hash,
        )
        for target in targets
    ]
    if not targets:
        client_results.append(
            {
                "client": "auto",
                "ok": False,
                "status": "not_found",
                "message": "진단할 지원 클라이언트를 찾지 못했습니다.",
                "mechanism": "auto discovery",
            }
        )

    ok = bool(targets) and all(item["ok"] for item in checks) and all(item["ok"] for item in client_results)
    external_probe_check = next((item for item in checks if item.get("name") == "external_probes_default_off"), {})
    launcher_policy_verified = external_probe_check.get("ok") is True
    profiles_by_client = {
        str(item.get("client")): str(item.get("profile"))
        for item in client_results
        if isinstance(item, dict) and item.get("client") in SUPPORTED_CLIENTS and item.get("profile") in PROFILE_CHOICES
    }
    active_profiles = set(profiles_by_client.values())
    effective_profile = next(iter(active_profiles)) if len(active_profiles) == 1 else "mixed" if active_profiles else receipt_profile or None
    local_dynamic = (
        True
        if launcher_policy_verified and active_profiles == {"local-dev"}
        else False
        if launcher_policy_verified and active_profiles == {"workspace"}
        else None
    )
    report = {
        "schema_version": 1,
        "command": "doctor",
        "ok": ok,
        "status": "등록 확인 · 실제 호출 대기" if ok else "복구 필요",
        "message": (
            "설치 파일과 클라이언트 등록은 확인했습니다. AI 대화에서 안경선배 도구를 한 번 호출하면 연결 확인이 끝납니다."
            if ok
            else "연결 전에 고칠 설치 항목이 있습니다. 아래 첫 번째 다음 행동부터 실행하세요."
        ),
        "verification_scope": "launcher_registration_and_available_cli_diagnostics",
        "runtime_and_app_connection_verified": bool(client_results)
        and all(item.get("runtime_and_app_connection_verified") is True for item in client_results),
        "requested_client": client,
        "profile": effective_profile,
        "profiles_by_client": profiles_by_client,
        "external_probing_enabled": False if launcher_policy_verified else None,
        "local_dynamic_probing_enabled": local_dynamic,
        "operator_key_value_returned": False,
        "launcher": str(locations.launcher),
        "workspace_binding": workspace_reference,
        "checks": checks,
        "clients": client_results,
    }
    return _finalize_doctor_report(report)


def format_install_text(report: dict[str, Any]) -> str:
    lines = ["안경선배 MCP 연결", f"상태: {report.get('status', '확인 필요')}", str(report.get("message", ""))]
    profile = str(report.get("profile") or "workspace")
    profile_label = "로컬 앱까지 점검" if profile == "local-dev" else "코드와 설정 점검"
    lines.extend(["", f"[1/3] 연결 준비 · {profile_label}"])
    launcher = report.get("launcher", {}) if isinstance(report.get("launcher"), dict) else {}
    lines.append(_format_result_line(launcher, "사용자 전용 실행기"))
    workspace = report.get("workspace_binding", {}) if isinstance(report.get("workspace_binding"), dict) else {}
    lines.append(_format_workspace_line(workspace))

    lines.extend(["", "[2/3] AI 클라이언트"])
    clients = report.get("clients", []) if isinstance(report.get("clients"), list) else []
    if clients:
        for item in clients:
            if not isinstance(item, dict):
                continue
            label = _client_display_label(item)
            lines.append(_format_result_line(item, label))
    else:
        lines.append("[확인] 연결할 지원 클라이언트를 찾지 못했습니다.")

    lines.extend(["", "[3/3] 다음 행동"])
    steps = report.get("next_steps", []) if isinstance(report.get("next_steps"), list) else []
    if not steps:
        steps = ["k-guard doctor --client auto"]
    lines.extend(f"{index}. {step}" for index, step in enumerate(steps[:3], start=1))
    return "\n".join(lines)


def format_doctor_text(report: dict[str, Any]) -> str:
    lines = ["안경선배 연결 진단", f"상태: {report.get('status', '확인 필요')}", str(report.get("message", "")), "", "[1/3] 로컬 실행 환경"]
    for item in report.get("checks", []):
        name = _CHECK_LABELS.get(str(item.get("name") or ""), str(item.get("name") or "설치 항목"))
        lines.append(_format_result_line(item, name))
    lines.extend(["", "[2/3] AI 클라이언트"])
    for item in report.get("clients", []):
        name = _client_display_label(item)
        lines.append(_format_result_line(item, name))
    lines.extend(["", "[3/3] 다음 행동"])
    steps = report.get("next_steps", []) if isinstance(report.get("next_steps"), list) else []
    if not steps:
        steps = ["AI 클라이언트를 다시 시작하고 안경선배 도구 목록을 확인하세요."]
    lines.extend(f"{index}. {step}" for index, step in enumerate(steps[:3], start=1))
    return "\n".join(lines)


def _finalize_install_report(report: dict[str, Any]) -> dict[str, Any]:
    requested = str(report.get("requested_client") or "auto")
    profile = str(report.get("profile") or "workspace")
    steps: list[str] = []
    if report.get("dry_run") is True and report.get("ok") is True:
        steps.append(f"실제 연결: k-guard install --client {requested} --profile {profile}")
    else:
        for item in report.get("clients", []) if isinstance(report.get("clients"), list) else []:
            if not isinstance(item, dict):
                continue
            item_steps = item.get("next_steps", []) if isinstance(item.get("next_steps"), list) else []
            steps.extend(str(step) for step in item_steps)
            failure_code = str(item.get("failure_code") or "")
            client = str(item.get("client") or requested)
            if failure_code == "CLIENT_CLI_NOT_FOUND":
                steps.append(f"k-guard install --client {client} --profile {profile}")
            elif failure_code == "TUNNEL_CLIENT_NOT_FOUND":
                steps.append(f"k-guard install --client chatgpt --profile {profile}")
            elif failure_code == "CHATGPT_TUNNEL_ID_REQUIRED":
                steps.append("현재 셸에 CONTROL_PLANE_TUNNEL_ID를 설정한 뒤 다시 실행하세요.")
            elif failure_code in {"INVALID_ANTIGRAVITY_CONFIG", "INVALID_MCP_SERVERS_SCHEMA"}:
                steps.append(f"k-guard install --client antigravity --profile {profile}")
    if report.get("ok") is True:
        steps.extend(
            [
                f"연결 진단: k-guard doctor --client {requested}",
                "AI 클라이언트를 다시 시작하세요.",
                '대화에서 "안경선배로 이 앱을 끝까지 봐줘"라고 요청하세요.',
            ]
        )
    elif not steps:
        safe_profile = profile if profile in PROFILE_CHOICES else "workspace"
        steps.append(f"복구 설치: k-guard install --client {requested} --profile {safe_profile}")
    steps = _unique_steps(steps)[:3]
    report["next_steps"] = steps
    report["connection_state"] = (
        "plan_ready"
        if report.get("dry_run") is True and report.get("ok") is True
        else "configured_restart_required"
        if report.get("ok") is True
        else "additional_action_required"
        if any(isinstance(item, dict) and item.get("configured") is True for item in report.get("clients", []))
        else "repair_required"
    )
    report["experience"] = {
        "schema": "k_guard_install_experience.v1",
        "persona": "안경선배",
        "connection_state": report["connection_state"],
        "next_steps": steps,
        "runtime_and_app_connection_verified": False,
        "raw_returned": False,
    }
    return report


def _finalize_doctor_report(report: dict[str, Any]) -> dict[str, Any]:
    requested = str(report.get("requested_client") or "auto")
    profile = str(report.get("profile") or "workspace")
    profiles_by_client = report.get("profiles_by_client", {}) if isinstance(report.get("profiles_by_client"), dict) else {}
    steps: list[str] = []
    clients = report.get("clients", []) if isinstance(report.get("clients"), list) else []
    prerequisite_missing = False
    for item in clients:
        if not isinstance(item, dict) or item.get("failure_code") not in {"CLIENT_CLI_NOT_FOUND", "TUNNEL_CLIENT_NOT_FOUND"}:
            continue
        prerequisite_missing = True
        item_steps = item.get("next_steps", []) if isinstance(item.get("next_steps"), list) else []
        steps.extend(str(step) for step in item_steps)
        client = str(item.get("client") or requested)
        client_profile = str(item.get("profile") or "workspace")
        if client_profile not in PROFILE_CHOICES:
            client_profile = "workspace"
        steps.append(f"k-guard install --client {client} --profile {client_profile}")
    checks = report.get("checks", []) if isinstance(report.get("checks"), list) else []
    if not prerequisite_missing and any(isinstance(item, dict) and item.get("ok") is not True for item in checks):
        if profile == "mixed" and profiles_by_client:
            steps.extend(
                f"복구 설치: k-guard install --client {client} --profile {client_profile}"
                for client, client_profile in sorted(profiles_by_client.items())
                if client in SUPPORTED_CLIENTS and client_profile in PROFILE_CHOICES
            )
        else:
            safe_profile = profile if profile in PROFILE_CHOICES else "workspace"
            steps.append(f"복구 설치: k-guard install --client {requested} --profile {safe_profile}")
    for item in clients:
        if not isinstance(item, dict) or item.get("failure_code") in {"CLIENT_CLI_NOT_FOUND", "TUNNEL_CLIENT_NOT_FOUND"}:
            continue
        item_steps = item.get("next_steps", []) if isinstance(item.get("next_steps"), list) else []
        steps.extend(str(step) for step in item_steps)
    if report.get("ok") is True:
        steps.extend(
            [
                "AI 클라이언트를 다시 시작하세요.",
                '대화에서 "안경선배 도구 목록을 보여줘"라고 요청하세요.',
                '도구가 보이면 "안경선배로 이 앱을 끝까지 봐줘"라고 요청하세요.',
            ]
        )
    elif not steps:
        safe_profile = profile if profile in PROFILE_CHOICES else "workspace"
        steps.append(f"복구 설치: k-guard install --client {requested} --profile {safe_profile}")
    steps = _unique_steps(steps)[:3]
    verified = report.get("runtime_and_app_connection_verified") is True
    report["next_steps"] = steps
    report["connection_state"] = "tool_call_verified" if verified else "configured_restart_required" if report.get("ok") is True else "repair_required"
    report["experience"] = {
        "schema": "k_guard_install_experience.v1",
        "persona": "안경선배",
        "connection_state": report["connection_state"],
        "next_steps": steps,
        "runtime_and_app_connection_verified": verified,
        "raw_returned": False,
    }
    return report


def _format_workspace_line(item: dict[str, Any]) -> str:
    status = str(item.get("status") or "")
    marker = "계획" if status.startswith("planned_") else "완료" if status in {"created", "updated", "preserved", "verified"} else "확인"
    basename = str(item.get("basename") or "workspace")
    root_hash = str(item.get("root_hash") or "식별자 없음")
    return f"[{marker}] 감사 workspace · {basename} · id {root_hash} · 원문 경로는 표시하지 않습니다."


def _format_result_line(item: dict[str, Any], label: str) -> str:
    status = str(item.get("status") or "")
    if status == "planned":
        marker = "계획"
    elif item.get("ok") is True or item.get("ready") is True:
        marker = "완료"
    elif item.get("configured") is True or status in {"needs_action", "profile_initialized_needs_action"}:
        marker = "대기"
    else:
        marker = "확인"
    message = str(item.get("message") or "상태 정보가 없습니다.")
    return f"[{marker}] {label} · {message}"


def _client_display_label(item: dict[str, Any]) -> str:
    client = str(item.get("client") or "")
    label = _CLIENT_LABELS.get(client, client or "알 수 없는 클라이언트")
    profile = str(item.get("profile") or "")
    if profile in PROFILE_CHOICES:
        profile_label = "로컬 앱까지 점검" if profile == "local-dev" else "코드와 설정 점검"
        return f"{label} / {profile_label}"
    return label


def _unique_steps(steps: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for step in steps:
        normalized = step.strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            unique.append(normalized)
    return unique


def _install_report_base(client: str, profile: str, dry_run: bool, locations: _Locations) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "command": "install",
        "ok": False,
        "status": "설치 준비",
        "message": "K-Guard MCP 설치를 준비하고 있습니다.",
        "requested_client": client,
        "profile": profile,
        "dry_run": dry_run,
        "external_probing_enabled": False,
        "local_dynamic_probing_enabled": profile == "local-dev",
        "operator_key_value_returned": False,
        "launcher": {
            "ready": False,
            "status": "not_started",
            "path": str(locations.launcher),
            "operator_key_configured": False,
            "operator_key_value_returned": False,
        },
        "clients": [],
        "backups": [],
    }


def _locations(home: str | Path | None) -> _Locations:
    user_home = Path(home or Path.home()).expanduser().resolve()
    private_dir = user_home / ".k-guard"
    return _Locations(
        user_home=user_home,
        private_dir=private_dir,
        launcher=private_dir / "mcp-launcher.py",
        key=private_dir / "operator-evidence.key",
        workspace_binding=private_dir / "workspace-binding.json",
        receipt=private_dir / "installation.json",
        antigravity_config=user_home / ".gemini" / "config" / "mcp_config.json",
    )


def _canonical_workspace(value: str | Path) -> Path:
    try:
        candidate = Path(os.path.abspath(Path(value).expanduser()))
        if _has_unsafe_existing_ancestor(candidate):
            raise InstallerError("unsafe workspace path")
        metadata = candidate.stat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise InstallerError("workspace is not a directory")
        canonical = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise InstallerError("감사 workspace를 안전하게 확인할 수 없습니다.") from exc
    if _has_unsafe_existing_ancestor(canonical) or not canonical.is_dir():
        raise InstallerError("감사 workspace가 일반 디렉터리가 아닙니다.")
    return canonical


def _workspace_basename(root: Path) -> str:
    return root.name or root.drive or root.anchor.rstrip("/\\") or "root"


def _workspace_root_hash(root: Path, key: str) -> str:
    if not operator_evidence_key_value_is_valid(key):
        raise InstallerError("운영자 키로 workspace 식별자를 만들 수 없습니다.")
    payload = _WORKSPACE_HASH_CONTEXT + str(root).encode("utf-8", errors="surrogatepass")
    return hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()[:16]


def _workspace_reference(root: Path, key: str | None = None, *, status: str = "validated") -> dict[str, Any]:
    if key is not None and operator_evidence_key_value_is_valid(key):
        root_hash = _workspace_root_hash(root, key)
        hash_scheme = _WORKSPACE_HASH_SCHEME
    else:
        root_hash = evidence_hash(str(root))
        hash_scheme = f"{evidence_hash_scheme()}:workspace-root"
    return {
        "configured": True,
        "status": status,
        "basename": _workspace_basename(root),
        "root_hash": root_hash,
        "hash_scheme": hash_scheme,
        "raw_path_returned": False,
    }


def _workspace_binding_payload(root: Path) -> dict[str, Any]:
    return {
        "schema_version": _WORKSPACE_BINDING_SCHEMA_VERSION,
        "canonical_root": str(root),
    }


def _load_workspace_binding(path: Path, *, require_live_root: bool) -> Path:
    payload = _load_json_object(path, "K-Guard workspace 결속")
    root_value = payload.get("canonical_root")
    if payload.get("schema_version") != _WORKSPACE_BINDING_SCHEMA_VERSION or not isinstance(root_value, str):
        raise InstallerError("K-Guard workspace 결속 형식이 올바르지 않습니다.")
    if not root_value or "\x00" in root_value:
        raise InstallerError("K-Guard workspace 결속 값이 올바르지 않습니다.")
    root = Path(root_value)
    normalized = Path(os.path.normpath(root_value))
    if not root.is_absolute() or os.path.normcase(root_value) != os.path.normcase(str(normalized)):
        raise InstallerError("K-Guard workspace 결속 값이 canonical 절대 경로가 아닙니다.")
    if not require_live_root:
        return root
    canonical = _canonical_workspace(root)
    if _normalize_command_path(str(canonical)) != _normalize_command_path(str(root)):
        raise InstallerError("K-Guard workspace 결속 값이 현재 canonical 경로와 일치하지 않습니다.")
    return canonical


def _workspace_receipt_record(locations: _Locations, root: Path, key: str) -> dict[str, Any]:
    return {
        "binding_file": locations.workspace_binding.name,
        "root_basename": _workspace_basename(root),
        "root_hash": _workspace_root_hash(root, key),
        "hash_scheme": _WORKSPACE_HASH_SCHEME,
        "private_permissions_required": True,
        "raw_path_stored": False,
    }


def _receipt_workspace_matches(
    receipt: object,
    locations: _Locations,
    root: Path | None,
    key: str | None,
) -> bool:
    if not isinstance(receipt, dict) or root is None or key is None:
        return False
    record = receipt.get("workspace_binding")
    if not isinstance(record, dict):
        return False
    try:
        expected_hash = _workspace_root_hash(root, key)
    except InstallerError:
        return False
    return (
        receipt.get("launcher") == str(locations.launcher)
        and record.get("binding_file") == locations.workspace_binding.name
        and record.get("root_hash") == expected_hash
        and record.get("hash_scheme") == _WORKSPACE_HASH_SCHEME
        and record.get("private_permissions_required") is True
        and record.get("raw_path_stored") is False
    )


def _validate_choice(value: str, choices: Sequence[str], name: str) -> None:
    if value not in choices:
        raise ValueError(f"Unsupported {name}: {value}")


def _discover_clients(locations: _Locations) -> dict[str, str | None]:
    discovered: dict[str, str | None] = {
        name: shutil.which(executable) for name, executable in _CLIENT_EXECUTABLES.items()
    }
    antigravity_cli = shutil.which("agy") or shutil.which("antigravity")
    antigravity_present = (
        bool(antigravity_cli)
        or locations.antigravity_config.exists()
        or locations.antigravity_config.parent.exists()
    )
    discovered["antigravity"] = str(locations.antigravity_config) if antigravity_present else None
    return discovered


def _resolve_targets(
    requested: str,
    discovered: dict[str, str | None],
    receipt_clients: Sequence[str] = (),
) -> list[str]:
    if requested == "all":
        return list(SUPPORTED_CLIENTS)
    if requested != "auto":
        return [requested]
    installed = set(receipt_clients)
    return [name for name in SUPPORTED_CLIENTS if discovered.get(name) or name in installed]


def _preflight_private_installation(locations: _Locations) -> None:
    paths = (
        locations.private_dir,
        locations.launcher,
        locations.key,
        locations.workspace_binding,
        locations.receipt,
    )
    if any(_is_unsafe_link(path) for path in paths) or _has_unsafe_existing_ancestor(locations.private_dir.parent):
        raise InstallerError("개인 설치 경로에 symlink 또는 junction이 있어 원본을 보존한 채 중단했습니다.")
    if locations.private_dir.exists() and not locations.private_dir.is_dir():
        raise InstallerError("~/.k-guard 경로가 일반 디렉터리가 아닙니다.")
    for path in (locations.launcher, locations.key, locations.workspace_binding, locations.receipt):
        if path.exists() and not path.is_file():
            raise InstallerError("개인 설치 파일 경로가 일반 파일이 아닙니다.")
    if locations.workspace_binding.exists():
        _load_workspace_binding(locations.workspace_binding, require_live_root=False)


def _capture_install_transaction(
    locations: _Locations,
    targets: Sequence[str],
) -> tuple[_InstallFileState, ...]:
    _preflight_private_installation(locations)
    paths = [
        locations.launcher,
        locations.key,
        locations.workspace_binding,
        locations.receipt,
    ]
    if "antigravity" in targets:
        paths.append(locations.antigravity_config)

    states: list[_InstallFileState] = []
    for path in paths:
        if _is_unsafe_link(path) or _has_unsafe_existing_ancestor(path.parent):
            raise InstallerError("설치 트랜잭션 대상 경로에 symlink 또는 junction이 있어 변경하지 않았습니다.")
        if not path.exists():
            states.append(_InstallFileState(path=path, existed=False, content=b"", mode=0o600))
            continue
        try:
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_JSON_BYTES:
                raise InstallerError("설치 트랜잭션 대상 파일의 크기 또는 형식이 올바르지 않습니다.")
            states.append(
                _InstallFileState(
                    path=path,
                    existed=True,
                    content=path.read_bytes(),
                    mode=stat.S_IMODE(metadata.st_mode),
                )
            )
        except OSError as exc:
            raise InstallerError("기존 설치 상태를 메모리에 안전하게 보관할 수 없습니다.") from exc
    return tuple(states)


def _rollback_install_transaction(
    states: Sequence[_InstallFileState],
    locations: _Locations,
) -> dict[str, Any]:
    restored = 0
    failed = False
    for state in states:
        try:
            if _is_unsafe_link(state.path) or _has_unsafe_existing_ancestor(state.path.parent):
                raise InstallerError("롤백 대상 경로가 안전하지 않습니다.")
            if state.existed:
                if state.path.exists() and not state.path.is_file():
                    raise InstallerError("롤백 대상이 일반 파일이 아닙니다.")
                _atomic_write_bytes(state.path, state.content, state.mode)
                private_mode = 0o700 if state.path == locations.launcher else 0o600
                _harden_private_path(state.path, is_directory=False, mode=private_mode)
            elif state.path.exists():
                if not state.path.is_file():
                    raise InstallerError("새로 만들어진 롤백 대상이 일반 파일이 아닙니다.")
                state.path.unlink()
            restored += 1
        except (InstallerError, OSError):
            failed = True

    return {
        "committed": False,
        "rolled_back": True,
        "shared_state_restored": not failed and restored == len(states),
        "restored_file_states": restored,
        "expected_file_states": len(states),
        "rollback_scope": "launcher_key_workspace_binding_receipt_and_managed_json",
        "external_client_registration_reversal_guaranteed": False,
    }


def _current_workspace_reference(locations: _Locations, *, status: str) -> dict[str, Any]:
    try:
        if not locations.workspace_binding.is_file() or not locations.key.is_file():
            raise InstallerError("workspace 결속이 없습니다.")
        root = _load_workspace_binding(locations.workspace_binding, require_live_root=False)
        key = _read_operator_key(locations.key)
        return _workspace_reference(root, key, status=status)
    except InstallerError:
        return {
            "configured": False,
            "status": "not_configured",
            "raw_path_returned": False,
        }


def _prepare_launcher(
    locations: _Locations,
    profile: str,
    python: str,
    workspace: Path | None = None,
) -> dict[str, Any]:
    workspace_root = _canonical_workspace(workspace or Path.cwd())
    _preflight_private_installation(locations)
    _ensure_private_directory(locations.private_dir)
    key_status = _ensure_operator_key(locations.key)
    key = _read_operator_key(locations.key)

    binding_existed = locations.workspace_binding.exists()
    existing_workspace = (
        _load_workspace_binding(locations.workspace_binding, require_live_root=False)
        if binding_existed
        else None
    )
    binding_changed = existing_workspace is None or _normalize_command_path(str(existing_workspace)) != _normalize_command_path(str(workspace_root))
    binding_backup = _backup_json(locations.workspace_binding) if binding_existed and binding_changed else None
    if binding_changed:
        _atomic_write_json(locations.workspace_binding, _workspace_binding_payload(workspace_root), private=True)
    effective_workspace = workspace_root if binding_changed or existing_workspace is None else existing_workspace
    _harden_private_path(locations.workspace_binding, is_directory=False, mode=0o600)
    binding_status = "updated" if binding_existed and binding_changed else "created" if binding_changed else "preserved"

    launcher_text = _launcher_source(locations.key, locations.workspace_binding)
    if key in launcher_text:
        raise InstallerError("런처에 운영자 키가 포함되지 않도록 설치를 중단했습니다.")

    launcher_existed = locations.launcher.exists()
    launcher_status = "preserved"
    try:
        launcher_matches = launcher_existed and locations.launcher.read_text(encoding="utf-8") == launcher_text
    except (OSError, UnicodeError) as exc:
        raise InstallerError("기존 개인 런처를 읽을 수 없어 원본을 보존한 채 중단했습니다.") from exc
    if not launcher_matches:
        _atomic_write_text(locations.launcher, launcher_text, 0o700)
        launcher_status = "updated" if launcher_existed else "created"
    _harden_private_path(locations.launcher, is_directory=False, mode=0o700)
    _harden_private_path(locations.key, is_directory=False, mode=0o600)
    workspace_result = _workspace_reference(effective_workspace, key, status=binding_status)
    if binding_backup is not None:
        workspace_result["backup"] = str(binding_backup)
    return {
        "ready": True,
        "status": launcher_status,
        "message": "비밀값을 출력하지 않는 사용자 전용 런처가 준비됐습니다.",
        "path": str(locations.launcher),
        "operator_key_configured": True,
        "operator_key_status": key_status,
        "operator_key_value_returned": False,
        "external_probing_enabled": False,
        "local_dynamic_probing_enabled": profile == "local-dev",
        "python": python,
        "workspace_binding": workspace_result,
    }


def _plan_launcher(locations: _Locations, workspace: Path | None = None) -> dict[str, Any]:
    workspace_root = _canonical_workspace(workspace or Path.cwd())
    _preflight_private_installation(locations)
    key_configured = False
    key: str | None = None
    if locations.key.exists():
        key = _read_operator_key(locations.key)
        key_configured = True
    existing_workspace = (
        _load_workspace_binding(locations.workspace_binding, require_live_root=False)
        if locations.workspace_binding.exists()
        else None
    )
    binding_matches = existing_workspace is not None and _normalize_command_path(str(existing_workspace)) == _normalize_command_path(str(workspace_root))
    binding_status = "planned_preserve" if binding_matches else "planned_update" if existing_workspace is not None else "planned_create"
    effective_workspace = existing_workspace if binding_matches and existing_workspace is not None else workspace_root
    source_matches = False
    if locations.launcher.exists():
        try:
            source_matches = locations.launcher.read_text(encoding="utf-8") == _launcher_source(
                locations.key,
                locations.workspace_binding,
            )
        except (OSError, UnicodeError) as exc:
            raise InstallerError("기존 개인 런처를 읽을 수 없어 설치 계획을 중단했습니다.") from exc
    return {
        "ready": locations.launcher.is_file() and key_configured and binding_matches and source_matches,
        "status": "planned",
        "message": "사용자 전용 런처, 운영자 증거 키, 감사 workspace 결속을 준비할 예정입니다.",
        "path": str(locations.launcher),
        "operator_key_configured": key_configured,
        "operator_key_value_returned": False,
        "workspace_binding": _workspace_reference(effective_workspace, key, status=binding_status),
    }


def _launcher_source(key_path: Path, workspace_binding_path: Path | None = None) -> str:
    binding_path = workspace_binding_path or key_path.with_name("workspace-binding.json")
    probe_names = repr(_PROBE_ENV_VARS)
    return (
        "#!/usr/bin/env python3\n"
        f"# {_LAUNCHER_MARKER}\n"
        "from __future__ import annotations\n\n"
        "import json\n"
        "import os\n"
        "import stat\n"
        "import sys\n"
        "from pathlib import Path\n\n"
        "def _unsafe_link(_path):\n"
        "    try:\n"
        "        if _path.is_symlink():\n"
        "            return True\n"
        "        _attributes = int(getattr(_path.lstat(), 'st_file_attributes', 0))\n"
        "    except OSError:\n"
        "        return False\n"
        "    return bool(_attributes & int(getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0)))\n\n"
        "def _has_unsafe_ancestor(_path):\n"
        "    _current = Path(os.path.abspath(_path))\n"
        "    while True:\n"
        "        if _unsafe_link(_current):\n"
        "            return True\n"
        "        if _current.parent == _current:\n"
        "            return False\n"
        "        _current = _current.parent\n\n"
        "_profile = 'workspace'\n"
        "if sys.argv[1:]:\n"
        "    if len(sys.argv) != 3 or sys.argv[1] != '--profile' or sys.argv[2] not in {'workspace', 'local-dev'}:\n"
        "        raise SystemExit(64)\n"
        "    _profile = sys.argv[2]\n"
        "sys.argv = [sys.argv[0]]\n"
        f"_key_path = Path({str(key_path)!r})\n"
        "if _has_unsafe_ancestor(_key_path) or not _key_path.is_file():\n"
        "    raise SystemExit(78)\n"
        "try:\n"
        "    _operator_key = _key_path.read_text(encoding='utf-8').strip()\n"
        "except OSError:\n"
        "    raise SystemExit(78)\n"
        "if len(_operator_key) < 32:\n"
        "    raise SystemExit(78)\n"
        f"os.environ[{EVIDENCE_HMAC_ENV!r}] = _operator_key\n"
        "from k_guard_mcp.hashing import operator_evidence_key_is_valid\n"
        "if not operator_evidence_key_is_valid():\n"
        "    raise SystemExit(78)\n"
        f"_binding_path = Path({str(binding_path)!r})\n"
        "if _has_unsafe_ancestor(_binding_path) or not _binding_path.is_file():\n"
        "    raise SystemExit(78)\n"
        "try:\n"
        f"    if _binding_path.stat().st_size > {_MAX_JSON_BYTES}:\n"
        "        raise SystemExit(78)\n"
        "    _binding = json.loads(_binding_path.read_text(encoding='utf-8'))\n"
        "except (OSError, UnicodeError, json.JSONDecodeError):\n"
        "    raise SystemExit(78)\n"
        f"if not isinstance(_binding, dict) or _binding.get('schema_version') != {_WORKSPACE_BINDING_SCHEMA_VERSION}:\n"
        "    raise SystemExit(78)\n"
        "_root = _binding.get('canonical_root')\n"
        "if not isinstance(_root, str) or not _root or '\\x00' in _root:\n"
        "    raise SystemExit(78)\n"
        "_workspace = Path(_root)\n"
        "try:\n"
        "    _resolved_workspace = _workspace.resolve(strict=True)\n"
        "    _workspace_mode = _workspace.stat().st_mode\n"
        "except (OSError, RuntimeError):\n"
        "    raise SystemExit(78)\n"
        "if (\n"
        "    not _workspace.is_absolute()\n"
        "    or os.path.normcase(str(_workspace)) != os.path.normcase(os.path.normpath(str(_workspace)))\n"
        "    or _has_unsafe_ancestor(_workspace)\n"
        "    or not stat.S_ISDIR(_workspace_mode)\n"
        "    or os.path.normcase(str(_resolved_workspace)) != os.path.normcase(str(_workspace))\n"
        "):\n"
        "    raise SystemExit(78)\n"
        f"os.environ[{_WORKSPACE_ROOT_ENV!r}] = str(_workspace)\n"
        f"for _name in {probe_names}:\n"
        "    os.environ.pop(_name, None)\n"
        "del _operator_key\n"
        "if _profile == 'local-dev':\n"
        f"    os.environ[{_LOCAL_PROBE_ENV!r}] = '1'\n"
        f"    os.environ[{_DEEP_PROBE_ENV!r}] = '1'\n"
        "from k_guard_mcp.server import main\n\n"
        "raise SystemExit(main())\n"
    )


def _ensure_private_directory(path: Path) -> None:
    if _is_unsafe_link(path) or _has_unsafe_existing_ancestor(path.parent):
        raise InstallerError("~/.k-guard 경로에 symlink 또는 junction이 있어 개인 키 생성을 중단했습니다.")
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise InstallerError("~/.k-guard 개인 디렉터리를 만들 수 없어 설치를 중단했습니다.") from exc
    if not path.is_dir():
        raise InstallerError("~/.k-guard 경로가 디렉터리가 아닙니다.")
    _harden_private_path(path, is_directory=True, mode=0o700)


def _ensure_operator_key(path: Path) -> str:
    if _is_unsafe_link(path) or _has_unsafe_existing_ancestor(path.parent):
        raise InstallerError("운영자 키 경로에 symlink 또는 junction이 있어 설치를 중단했습니다.")
    if path.exists():
        _read_operator_key(path)
        return "preserved"

    key = secrets.token_urlsafe(48)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        _read_operator_key(path)
        return "preserved"
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(key + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    _harden_private_path(path, is_directory=False, mode=0o600)
    return "created"


def _read_operator_key(path: Path) -> str:
    try:
        if not path.is_file() or path.stat().st_size > 4096:
            raise InstallerError("기존 운영자 키 파일이 올바르지 않아 원본을 보존한 채 중단했습니다.")
        key = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise InstallerError("기존 운영자 키 파일을 읽을 수 없어 원본을 보존한 채 중단했습니다.") from exc
    if not operator_evidence_key_value_is_valid(key) or any(character.isspace() for character in key):
        raise InstallerError("기존 운영자 키 형식이 올바르지 않아 원본을 보존한 채 중단했습니다.")
    return key


def _install_cli_client(
    client: str,
    executable: str,
    python: str,
    launcher: Path,
    profile: str,
    workspace: Path,
    dry_run: bool,
) -> dict[str, Any]:
    command, scope, mechanism = _client_install_command(client, executable, python, launcher, profile)
    if dry_run:
        return {
            "client": client,
            "ok": True,
            "status": "planned",
            "message": "공식 클라이언트 명령으로 등록할 예정입니다.",
            "mechanism": mechanism,
            "scope": scope,
        }
    outcome = _run_command(command, cwd=workspace, timeout=45)
    return {
        "client": client,
        "ok": outcome.ok,
        "status": "installed" if outcome.ok else "failed",
        "message": (
            "공식 클라이언트 명령으로 등록했습니다."
            if outcome.ok
            else "클라이언트 등록 명령이 완료되지 않았습니다. 해당 CLI 로그인과 권한을 확인해 주세요."
        ),
        "mechanism": mechanism,
        "scope": scope,
        **({"failure_code": outcome.error or "CLIENT_COMMAND_FAILED"} if not outcome.ok else {}),
        **(
            {
                "next_steps": [
                    f"{client} login으로 로그인 상태를 확인하세요.",
                    f"{client} mcp --help로 MCP 명령 사용 가능 여부를 확인하세요.",
                    f"k-guard install --client {client} --profile {profile}",
                ]
            }
            if not outcome.ok
            else {}
        ),
    }


def _client_install_command(
    client: str,
    executable: str,
    python: str,
    launcher: Path,
    profile: str,
) -> tuple[list[str], str, str]:
    launch = [python, str(launcher), "--profile", profile]
    if client == "codex":
        return [executable, "mcp", "add", SERVER_NAME, "--", *launch], "user", "codex mcp add"
    if client == "grok":
        return (
            [executable, "mcp", "add", "--scope", "user", SERVER_NAME, "--", *launch],
            "user",
            "grok mcp add",
        )
    raise InstallerError(f"지원하지 않는 CLI 클라이언트입니다: {client}")


def _install_chatgpt(
    executable: str,
    python: str,
    launcher: Path,
    profile: str,
    workspace: Path,
    dry_run: bool,
) -> dict[str, Any]:
    tunnel_id = os.environ.get(_CHATGPT_TUNNEL_ID_ENV, "").strip()
    if not _chatgpt_tunnel_id_is_valid():
        return _chatgpt_tunnel_id_required()
    mcp_command = _expected_launch_command(python, launcher, profile)
    command = [
        executable,
        "init",
        "--sample",
        "sample_mcp_stdio_local",
        "--profile",
        _CHATGPT_TUNNEL_PROFILE,
        "--tunnel-id",
        tunnel_id,
        "--mcp-command",
        mcp_command,
    ]
    if dry_run:
        return {
            "client": "chatgpt",
            "ok": True,
            "status": "planned",
            "message": "Secure MCP Tunnel 로컬 stdio 프로필을 초기화할 예정입니다.",
            "mechanism": "tunnel-client init sample_mcp_stdio_local",
            "scope": "openai-organization",
            "tunnel_id_ref": evidence_hash(tunnel_id),
            "tunnel_id_value_returned": False,
        }
    outcome = _run_command(command, cwd=workspace, timeout=45)
    if outcome.ok:
        return {
            "client": "chatgpt",
            "ok": False,
            "configured": True,
            "status": "profile_initialized_needs_action",
            "message": "Secure MCP Tunnel 프로필만 준비했습니다. 실행 중인 터널과 ChatGPT 개발자 모드 앱 연결은 아직 확인되지 않았습니다.",
            "mechanism": "tunnel-client init sample_mcp_stdio_local",
            "scope": "openai-organization",
            "tunnel_id_ref": evidence_hash(tunnel_id),
            "tunnel_id_value_returned": False,
            "action_code": "CHATGPT_RUNTIME_AND_APP_CONNECTION_REQUIRED",
            "next_steps": [
                f"tunnel-client doctor --profile {_CHATGPT_TUNNEL_PROFILE} --explain",
                f"tunnel-client run --profile {_CHATGPT_TUNNEL_PROFILE}",
                "Platform tunnel settings에서 소유 Platform 조직과 대상 ChatGPT workspace를 연결합니다.",
                "ChatGPT Settings > Plugins에서 개발자 모드 앱을 만들고 Connection=Tunnel로 해당 tunnel을 선택한 뒤 K-Guard tool 호출을 확인합니다.",
            ],
        }
    return {
        "client": "chatgpt",
        "ok": False,
        "configured": False,
        "status": "failed",
        "message": "Secure MCP Tunnel 프로필 초기화가 완료되지 않았습니다. 터널 권한과 tunnel-client 설치를 확인해 주세요.",
        "mechanism": "tunnel-client init sample_mcp_stdio_local",
        "scope": "openai-organization",
        "tunnel_id_ref": evidence_hash(tunnel_id),
        "tunnel_id_value_returned": False,
        "failure_code": outcome.error or "TUNNEL_INIT_FAILED",
    }


def _install_antigravity(locations: _Locations, python: str, profile: str, dry_run: bool) -> dict[str, Any]:
    path = locations.antigravity_config
    try:
        payload = _load_json_object(path, "Antigravity MCP 설정") if path.exists() else {}
    except InstallerError:
        return {
            "client": "antigravity",
            "ok": False,
            "status": "invalid_config",
            "message": "기존 Antigravity JSON이 올바르지 않아 원본을 보존했습니다.",
            "mechanism": "~/.gemini/config/mcp_config.json",
            "scope": "user",
            "failure_code": "INVALID_ANTIGRAVITY_CONFIG",
        }

    existing_servers = payload.get("mcpServers", {})
    if not isinstance(existing_servers, dict):
        return {
            "client": "antigravity",
            "ok": False,
            "status": "invalid_config",
            "message": "기존 mcpServers 값이 객체가 아니어서 원본을 보존했습니다.",
            "mechanism": "~/.gemini/config/mcp_config.json",
            "scope": "user",
            "failure_code": "INVALID_MCP_SERVERS_SCHEMA",
        }

    updated = dict(payload)
    servers = dict(existing_servers)
    servers[SERVER_NAME] = _antigravity_server_entry(python, locations.launcher, profile)
    updated["mcpServers"] = servers
    if updated == payload:
        return {
            "client": "antigravity",
            "ok": True,
            "status": "already_configured",
            "message": "기존 Antigravity 설정이 이미 최신 상태입니다.",
            "mechanism": "~/.gemini/config/mcp_config.json",
            "scope": "user",
        }
    if dry_run:
        return {
            "client": "antigravity",
            "ok": True,
            "status": "planned",
            "message": "기존 JSON을 보존해 mcpServers.k-guard만 병합할 예정입니다.",
            "mechanism": "~/.gemini/config/mcp_config.json",
            "scope": "user",
        }

    try:
        backup = _backup_json(path) if path.exists() else None
        _atomic_write_json(path, updated, private=True)
    except InstallerError:
        return {
            "client": "antigravity",
            "ok": False,
            "status": "write_failed",
            "message": "Antigravity 설정을 안전하게 저장하지 못했습니다. 기존 백업을 확인해 주세요.",
            "mechanism": "~/.gemini/config/mcp_config.json",
            "scope": "user",
            "failure_code": "ANTIGRAVITY_CONFIG_WRITE_FAILED",
        }
    result: dict[str, Any] = {
        "client": "antigravity",
        "ok": True,
        "status": "installed",
        "message": "기존 설정을 보존해 mcpServers.k-guard를 병합했습니다.",
        "mechanism": "~/.gemini/config/mcp_config.json",
        "scope": "user",
    }
    if backup:
        result["backup"] = str(backup)
    return result


def _antigravity_server_entry(python: str, launcher: Path, profile: str) -> dict[str, Any]:
    return {
        "command": python,
        "args": [str(launcher), "--profile", profile],
        "env": {name: "0" for name in _PROBE_ENV_VARS},
    }


def _write_receipt(
    locations: _Locations,
    existing: dict[str, Any],
    profile: str,
    python: str,
    successful: list[dict[str, Any]],
) -> Path | None:
    _harden_private_path(locations.workspace_binding, is_directory=False, mode=0o600)
    workspace_root = _load_workspace_binding(locations.workspace_binding, require_live_root=True)
    key = _read_operator_key(locations.key)
    workspace_record = _workspace_receipt_record(locations, workspace_root, key)
    expected_launcher = _launcher_source(locations.key, locations.workspace_binding)
    try:
        launcher_matches = locations.launcher.is_file() and locations.launcher.read_text(encoding="utf-8") == expected_launcher
    except (OSError, UnicodeError) as exc:
        raise InstallerError("설치 기록 전에 개인 런처를 확인할 수 없습니다.") from exc
    if not launcher_matches:
        raise InstallerError("개인 런처와 workspace 결속이 일치하지 않아 설치 기록을 쓰지 않았습니다.")

    updated = dict(existing)
    previous_clients = existing.get("clients", {}) if isinstance(existing.get("clients"), dict) else {}
    clients: dict[str, Any] = {}
    for name, value in previous_clients.items():
        if name not in SUPPORTED_CLIENTS or not isinstance(value, dict):
            continue
        previous = dict(value)
        previous["workspace_root_hash"] = workspace_record["root_hash"]
        previous["workspace_hash_scheme"] = workspace_record["hash_scheme"]
        previous["workspace_binding_file"] = workspace_record["binding_file"]
        clients[name] = previous
    now = datetime.now(UTC).isoformat()
    for item in successful:
        name = str(item.get("client", ""))
        if name not in SUPPORTED_CLIENTS:
            continue
        installed = item.get("ok") is True
        configuration_state = "installed" if installed else str(item.get("status") or "configured")
        clients[name] = {
            "installed": installed,
            "configuration_state": configuration_state,
            "profile": profile,
            "mechanism": str(item.get("mechanism", "")),
            "scope": str(item.get("scope", "")),
            "python": python,
            "launcher": str(locations.launcher),
            "workspace_root_hash": workspace_record["root_hash"],
            "workspace_hash_scheme": workspace_record["hash_scheme"],
            "workspace_binding_file": workspace_record["binding_file"],
            "external_probing_enabled": False,
            "local_dynamic_probing_enabled": profile == "local-dev",
            "installed_at": now,
        }
    updated.update(
        {
            "schema_version": _RECEIPT_SCHEMA_VERSION,
            "server": SERVER_NAME,
            "profile": profile,
            "python": python,
            "launcher": str(locations.launcher),
            "workspace_binding": workspace_record,
            "external_probing_enabled": False,
            "local_dynamic_probing_enabled": profile == "local-dev",
            "clients": clients,
            "updated_at": now,
        }
    )
    backup = _backup_json(locations.receipt) if locations.receipt.exists() else None
    _atomic_write_json(locations.receipt, updated, private=True)
    _harden_private_path(locations.receipt, is_directory=False, mode=0o600)
    return backup


def _load_receipt(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    payload = _load_json_object(path, "K-Guard 설치 기록")
    clients = payload.get("clients", {})
    if not isinstance(clients, dict):
        raise InstallerError("K-Guard 설치 기록의 clients 값이 올바르지 않습니다.")
    return payload


def _client_not_found(client: str) -> dict[str, Any]:
    if client == "chatgpt":
        return {
            "client": "chatgpt",
            "ok": False,
            "status": "not_found",
            "message": "OpenAI Secure MCP Tunnel의 tunnel-client를 찾지 못했습니다. 공식 Tunnels 페이지에서 설치한 뒤 다시 실행해 주세요.",
            "mechanism": "OpenAI Secure MCP Tunnel",
            "scope": "openai-organization",
            "failure_code": "TUNNEL_CLIENT_NOT_FOUND",
            "next_steps": [
                "OpenAI Secure MCP Tunnel 안내에서 tunnel-client를 설치하세요.",
                "터미널을 다시 열고 tunnel-client --help를 확인하세요.",
            ],
        }
    install_name = _CLIENT_LABELS.get(client, client)
    return {
        "client": client,
        "ok": False,
        "status": "not_found",
        "message": f"{client} CLI를 찾지 못했습니다. 클라이언트를 먼저 설치한 뒤 다시 실행해 주세요.",
        "mechanism": f"{client} mcp add",
        "scope": "unavailable",
        "failure_code": "CLIENT_CLI_NOT_FOUND",
        "next_steps": [
            f"{install_name}를 설치하거나 업데이트한 뒤 로그인하세요.",
            f"터미널을 다시 열고 {client} --help를 확인하세요.",
        ],
    }


def _antigravity_preflight_error(locations: _Locations) -> dict[str, Any] | None:
    path = locations.antigravity_config
    if not path.exists():
        return None
    try:
        payload = _load_json_object(path, "Antigravity MCP 설정")
    except InstallerError:
        return {
            "client": "antigravity",
            "ok": False,
            "status": "invalid_config",
            "message": "기존 Antigravity JSON이 올바르지 않아 어떤 설정도 바꾸지 않았습니다.",
            "mechanism": "~/.gemini/config/mcp_config.json",
            "scope": "user",
            "failure_code": "INVALID_ANTIGRAVITY_CONFIG",
            "next_steps": [
                "Antigravity의 MCP 화면에서 View raw config를 열어 JSON 문법을 복구하세요.",
            ],
        }
    if not isinstance(payload.get("mcpServers", {}), dict):
        return {
            "client": "antigravity",
            "ok": False,
            "status": "invalid_config",
            "message": "기존 mcpServers 값이 객체가 아니어서 어떤 설정도 바꾸지 않았습니다.",
            "mechanism": "~/.gemini/config/mcp_config.json",
            "scope": "user",
            "failure_code": "INVALID_MCP_SERVERS_SCHEMA",
            "next_steps": [
                "Antigravity raw config에서 mcpServers를 JSON 객체로 복구하세요.",
            ],
        }
    return None


def _chatgpt_tunnel_id_is_valid() -> bool:
    return re.fullmatch(r"tunnel_[A-Za-z0-9_-]{8,128}", os.environ.get(_CHATGPT_TUNNEL_ID_ENV, "").strip()) is not None


def _chatgpt_tunnel_id_required() -> dict[str, Any]:
    return {
        "client": "chatgpt",
        "ok": False,
        "status": "needs_tunnel_id",
        "message": "ChatGPT 연결에는 OpenAI Tunnels에서 만든 CONTROL_PLANE_TUNNEL_ID가 필요합니다.",
        "mechanism": "OpenAI Secure MCP Tunnel",
        "scope": "openai-organization",
        "failure_code": "CHATGPT_TUNNEL_ID_REQUIRED",
        "tunnel_id_value_returned": False,
    }


def _doctor_launcher_checks(
    locations: _Locations,
    python: str,
    workspace: Path,
    profile: str,
    receipt: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any], str | None]:
    del profile
    launcher_exists = locations.launcher.is_file() and not _has_unsafe_existing_ancestor(locations.launcher)
    key_valid = False
    key = ""
    if locations.key.is_file() and not _has_unsafe_existing_ancestor(locations.key):
        try:
            key = _read_operator_key(locations.key)
            key_valid = True
        except InstallerError:
            key_valid = False

    binding_root: Path | None = None
    if locations.workspace_binding.is_file() and not _has_unsafe_existing_ancestor(locations.workspace_binding):
        try:
            binding_root = _load_workspace_binding(locations.workspace_binding, require_live_root=True)
        except InstallerError:
            binding_root = None
    binding_valid = binding_root is not None
    workspace_root_hash = _workspace_root_hash(binding_root, key) if binding_root is not None and key_valid else None
    workspace_reference = (
        _workspace_reference(binding_root, key if key_valid else None, status="verified")
        if binding_root is not None
        else {"configured": False, "status": "missing_or_invalid", "raw_path_returned": False}
    )

    source_valid = False
    no_embedded_key = False
    if launcher_exists:
        try:
            source = locations.launcher.read_text(encoding="utf-8")
            expected_source = _launcher_source(locations.key, locations.workspace_binding)
            source_valid = source == expected_source
            no_embedded_key = not key or key not in source
        except (OSError, UnicodeError):
            source_valid = False

    private_permissions = (
        locations.private_dir.is_dir()
        and _private_permissions_ok(locations.private_dir, 0o700)
        and locations.key.is_file()
        and _private_permissions_ok(locations.key, 0o600)
        and locations.launcher.is_file()
        and _private_permissions_ok(locations.launcher, 0o700)
        and locations.workspace_binding.is_file()
        and _private_permissions_ok(locations.workspace_binding, 0o600)
        and locations.receipt.is_file()
        and _private_permissions_ok(locations.receipt, 0o600)
    )
    receipt_binding_matches = _receipt_workspace_matches(receipt, locations, binding_root, key if key_valid else None)

    runtime_ok = False
    if launcher_exists and key_valid and binding_valid and source_valid and Path(python).is_file():
        runtime_ok = _run_command([python, str(locations.launcher), "--profile", "workspace"], cwd=workspace, timeout=15, input_text="").ok

    workspace_message = (
        f"{workspace_reference['basename']} workspace 결속과 keyed id {workspace_reference['root_hash']}를 확인했습니다."
        if binding_valid
        else "감사 workspace 결속 파일이 없거나 현재의 일반 디렉터리를 가리키지 않습니다."
    )
    workspace_check = _check("workspace_binding", binding_valid, workspace_message)
    workspace_check["workspace"] = workspace_reference
    checks = [
        _check("private_launcher", launcher_exists and source_valid, "프로필과 무관한 사용자 전용 MCP 실행기 전체 내용이 일치합니다." if launcher_exists and source_valid else "실행기가 없거나 현재 설치본의 전체 내용과 일치하지 않습니다."),
        _check("operator_evidence_key", key_valid, "운영자 증거 키가 준비돼 있으며 값은 반환하지 않습니다." if key_valid else "운영자 증거 키가 없거나 올바르지 않습니다."),
        workspace_check,
        _check("workspace_binding_consistency", receipt_binding_matches, "런처가 읽는 workspace 결속과 설치 기록의 keyed id가 일치합니다." if receipt_binding_matches else "workspace 결속, 런처, 설치 기록의 identity가 일치하지 않습니다."),
        _check("secret_not_embedded", no_embedded_key, "런처에 운영자 키 원문이 포함되지 않았습니다." if no_embedded_key else "런처에서 운영자 키 원문이 발견됐습니다."),
        _check("private_permissions", private_permissions, "개인 설치 경로의 접근 권한을 확인했습니다." if private_permissions else "개인 설치 경로의 접근 권한을 다시 설정해야 합니다."),
        _check("external_probes_default_off", source_valid, "검증된 실행기가 외부·세션 점검을 끄고 클라이언트에 결속된 프로필만 적용합니다." if source_valid else "실행기 전체 내용이 달라 점검 범위 계약을 확인하지 못했습니다."),
        _check("launcher_runtime", runtime_ok, "런처가 stdio EOF에서 정상 종료했습니다." if runtime_ok else "런처 실행을 확인하지 못했습니다."),
    ]
    return checks, workspace_reference, workspace_root_hash


def _doctor_client(
    client: str,
    executable: str | None,
    locations: _Locations,
    python: str,
    workspace: Path,
    receipt_clients: dict[str, Any],
    fallback_profile: str,
    *,
    workspace_root_hash: str | None = None,
) -> dict[str, Any]:
    record = receipt_clients.get(client)
    client_profile = (
        str(record.get("profile"))
        if isinstance(record, dict) and record.get("profile") in PROFILE_CHOICES
        else fallback_profile
        if fallback_profile in PROFILE_CHOICES
        else "workspace"
    )
    if client in _CLIENT_EXECUTABLES and not executable:
        result = _client_not_found(client)
        result["profile"] = client_profile
        return result
    receipt_ok = _receipt_matches(
        record,
        python,
        locations.launcher,
        profile=client_profile,
        workspace_root_hash=workspace_root_hash,
    )
    if client == "antigravity":
        return _doctor_antigravity(locations, python, client_profile, receipt_ok=receipt_ok)

    if client == "codex":
        outcome = _run_command([str(executable), "mcp", "get", SERVER_NAME, "--json"], cwd=workspace, timeout=20)
        config_ok = outcome.ok and _command_json_matches(outcome.stdout, python, locations.launcher, client_profile)
        ok = config_ok and receipt_ok
        message = (
            "Codex 등록의 실행 명령과 설치 기록이 일치합니다. 실제 Codex 세션의 K-Guard 도구 호출은 별도 확인이 필요합니다."
            if ok
            else "Codex 등록 또는 설치 기록이 현재 런처와 일치하지 않습니다."
        )
        mechanism = "codex mcp get --json"
        runtime_handshake_verified = False
    elif client == "grok":
        registration = _run_command([str(executable), "mcp", "list", "--json"], cwd=workspace, timeout=20)
        outcome = _run_command([str(executable), "mcp", "doctor", SERVER_NAME, "--json"], cwd=workspace, timeout=30)
        identity_ok = registration.ok and _grok_registration_matches(registration.stdout, python, locations.launcher, client_profile)
        ok = identity_ok and outcome.ok and receipt_ok
        message = "Grok의 현재 k-guard 실행 명령, 연결 진단, 설치 기록이 모두 일치합니다." if ok else "Grok의 현재 k-guard 실행 명령, 연결 진단, 설치 기록 중 확인할 항목이 있습니다."
        mechanism = "grok mcp list --json + doctor --json"
        runtime_handshake_verified = outcome.ok
    elif client == "chatgpt":
        receipt_ok = _receipt_matches(
            receipt_clients.get(client),
            python,
            locations.launcher,
            profile=client_profile,
            require_installed=False,
            configuration_state="profile_initialized_needs_action",
            workspace_root_hash=workspace_root_hash,
        )
        outcome = _run_command(
            [str(executable), "doctor", "--profile", _CHATGPT_TUNNEL_PROFILE, "--json"],
            cwd=workspace,
            timeout=45,
        )
        identity_ok = outcome.ok and _tunnel_doctor_matches(outcome.stdout, python, locations.launcher, client_profile)
        profile_ready = identity_ok and receipt_ok
        ok = False
        message = (
            "K-Guard 터널 profile identity는 확인했습니다. 실행 중인 tunnel-client와 ChatGPT 앱의 실제 tool 호출까지 확인해야 연결 완료입니다."
            if profile_ready
            else "ChatGPT 터널 profile이 현재 K-Guard 런처와 일치하지 않거나 진단에 실패했습니다."
        )
        mechanism = "tunnel-client doctor --profile k-guard --json"
        runtime_handshake_verified = False
    else:
        return _client_not_found(client)
    result = {
        "client": client,
        "ok": ok,
        "status": (
            "cli_diagnostic_passed"
            if ok and client == "grok"
            else "configured"
            if ok
            else "needs_action"
            if client == "chatgpt" and profile_ready
            else "needs_attention"
        ),
        "message": message,
        "mechanism": mechanism,
        "profile": client_profile,
        "configuration_identity_verified": ok,
        "runtime_handshake_verified": runtime_handshake_verified,
        "runtime_and_app_connection_verified": False,
    }
    if client == "chatgpt":
        result.update(
            {
                "profile_identity_verified": profile_ready,
                "runtime_and_app_connection_verified": False,
                "next_steps": [
                    "현재 셸에 Tunnels Read + Use 권한의 CONTROL_PLANE_API_KEY를 설정합니다.",
                    f"tunnel-client run --profile {_CHATGPT_TUNNEL_PROFILE}",
                    "Platform tunnel settings에서 소유 Platform 조직과 대상 ChatGPT workspace를 연결합니다.",
                    "ChatGPT Settings > Plugins의 개발자 모드 앱에서 Connection=Tunnel로 해당 tunnel을 선택하고 K-Guard tool 호출을 확인합니다.",
                ],
            }
        )
    return result


def _doctor_antigravity(locations: _Locations, python: str, profile: str, *, receipt_ok: bool) -> dict[str, Any]:
    preflight_error = _antigravity_preflight_error(locations)
    if preflight_error is not None:
        preflight_error.update(
            {
                "profile": profile,
                "configuration_identity_verified": False,
                "runtime_handshake_verified": False,
                "runtime_and_app_connection_verified": False,
            }
        )
        preflight_error.setdefault("next_steps", []).append(
            f"k-guard install --client antigravity --profile {profile}"
        )
        return preflight_error
    try:
        payload = _load_json_object(locations.antigravity_config, "Antigravity MCP 설정")
    except InstallerError:
        payload = {}
    servers = payload.get("mcpServers", {}) if isinstance(payload, dict) else {}
    entry = servers.get(SERVER_NAME) if isinstance(servers, dict) else None
    expected = _antigravity_server_entry(python, locations.launcher, profile)
    ok = isinstance(entry, dict) and entry == expected and receipt_ok
    return {
        "client": "antigravity",
        "ok": ok,
        "status": "configured" if ok else "needs_attention",
        "message": (
            "Antigravity mcpServers 설정, K-Guard 실행 명령, 설치 기록이 일치합니다. 실제 Antigravity 세션의 K-Guard 도구 호출은 별도 확인이 필요합니다."
            if ok
            else "Antigravity mcpServers.k-guard 설정 또는 설치 기록을 다시 확인해야 합니다."
        ),
        "mechanism": "~/.gemini/config/mcp_config.json",
        "profile": profile,
        "configuration_identity_verified": ok,
        "runtime_handshake_verified": False,
        "runtime_and_app_connection_verified": False,
    }


def _receipt_matches(
    record: object,
    python: str,
    launcher: Path,
    *,
    profile: str | None = None,
    require_installed: bool = True,
    configuration_state: str | None = None,
    workspace_root_hash: str | None = None,
) -> bool:
    if not isinstance(record, dict):
        return False
    return (
        (record.get("installed") is True if require_installed else record.get("installed") is False)
        and record.get("python") == python
        and record.get("launcher") == str(launcher)
        and record.get("external_probing_enabled") is False
        and (profile is None or record.get("profile") == profile)
        and (configuration_state is None or record.get("configuration_state") == configuration_state)
        and (workspace_root_hash is None or record.get("workspace_root_hash") == workspace_root_hash)
    )


def _grok_registration_matches(text: str, python: str, launcher: Path, profile: str) -> bool:
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return False
    entries = payload if isinstance(payload, list) else payload.get("servers", []) if isinstance(payload, dict) else []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("name") != SERVER_NAME or entry.get("enabled") is False:
            continue
        args = entry.get("args")
        if (
            _normalize_command_path(str(entry.get("command") or "")) == _normalize_command_path(python)
            and isinstance(args, list)
            and len(args) == 3
            and _normalize_command_path(str(args[0])) == _normalize_command_path(str(launcher))
            and args[1:] == ["--profile", profile]
        ):
            return True
    return False


def _tunnel_doctor_matches(text: str, python: str, launcher: Path, profile: str) -> bool:
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return False
    if not isinstance(payload, dict) or payload.get("result") != "ok":
        return False
    checks = payload.get("checks")
    if not isinstance(checks, list):
        return False
    target = next((item for item in checks if isinstance(item, dict) and item.get("id") == "mcp_target"), None)
    return (
        isinstance(target, dict)
        and target.get("status") == "PASS"
        and str(target.get("summary") or "").strip() == _expected_launch_command(python, launcher, profile)
    )


def _expected_launch_command(python: str, launcher: Path, profile: str) -> str:
    launch = [python, str(launcher), "--profile", profile]
    return subprocess.list2cmdline(launch) if os.name == "nt" else shlex.join(launch)


def _command_json_matches(text: str, python: str, launcher: Path, profile: str) -> bool:
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return False
    if not isinstance(payload, dict) or payload.get("name") != SERVER_NAME or payload.get("enabled") is not True:
        return False
    transport = payload.get("transport")
    if not isinstance(transport, dict) or transport.get("type") != "stdio":
        return False
    command = transport.get("command")
    args = transport.get("args")
    return (
        isinstance(command, str)
        and _normalize_command_path(command) == _normalize_command_path(python)
        and isinstance(args, list)
        and len(args) == 3
        and isinstance(args[0], str)
        and _normalize_command_path(args[0]) == _normalize_command_path(str(launcher))
        and args[1:] == ["--profile", profile]
    )


def _normalize_command_path(value: str) -> str:
    return os.path.normcase(os.path.normpath(value))


def _check(name: str, ok: bool, message: str) -> dict[str, Any]:
    return {"name": name, "ok": ok, "status": "pass" if ok else "fail", "message": message}


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    if _is_unsafe_link(path):
        raise InstallerError(f"{label} 경로가 symlink 또는 junction이어서 읽지 않았습니다.")
    try:
        if not path.is_file() or path.stat().st_size > _MAX_JSON_BYTES:
            raise InstallerError(f"{label} 파일 크기 또는 형식이 올바르지 않습니다.")
        text = path.read_text(encoding="utf-8-sig")
        payload = {} if not text.strip() else json.loads(text)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InstallerError(f"{label} JSON을 읽을 수 없습니다.") from exc
    if not isinstance(payload, dict):
        raise InstallerError(f"{label} JSON 루트는 객체여야 합니다.")
    return payload


def _backup_json(path: Path) -> Path:
    if _is_unsafe_link(path) or not path.is_file():
        raise InstallerError("백업할 JSON 파일이 일반 파일이 아닙니다.")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    backup = path.with_name(f"{path.name}.bak-{stamp}-{secrets.token_hex(3)}")
    try:
        shutil.copy2(path, backup)
    except OSError as exc:
        raise InstallerError("JSON 변경 전 백업을 만들 수 없습니다.") from exc
    _harden_private_path(backup, is_directory=False, mode=0o600)
    return backup


def _atomic_write_json(path: Path, payload: dict[str, Any], *, private: bool) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    _atomic_write_text(path, text, 0o600 if private else 0o644)
    if private:
        _harden_private_path(path, is_directory=False, mode=0o600)


def _atomic_write_text(path: Path, text: str, mode: int) -> None:
    _atomic_write_bytes(path, text.encode("utf-8"), mode)


def _atomic_write_bytes(path: Path, content: bytes, mode: int) -> None:
    if _is_unsafe_link(path) or _has_unsafe_existing_ancestor(path.parent):
        raise InstallerError("대상 경로에 symlink 또는 junction이 있어 파일을 변경하지 않았습니다.")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    except OSError as exc:
        raise InstallerError("파일을 원자적으로 저장하지 못했습니다.") from exc


def _harden_private_path(path: Path, *, is_directory: bool, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError as exc:
        raise InstallerError("개인 설치 경로의 접근 권한을 설정하지 못했습니다.") from exc
    if os.name != "nt":
        return
    sid = _windows_current_sid()
    request = json.dumps({"path": str(path), "sid": sid, "is_directory": is_directory})
    outcome = _run_command(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_SET_PRIVATE_ACL_SCRIPT],
        timeout=15,
        input_text=request,
    )
    if not outcome.ok or not _windows_private_acl_ok(path, sid=sid, is_directory=is_directory):
        raise InstallerError("Windows 사용자 전용 ACL을 설정하지 못했습니다.")


def _windows_current_sid() -> str:
    outcome = _run_command(["whoami", "/user", "/fo", "csv", "/nh"], timeout=10)
    if not outcome.ok:
        raise InstallerError("현재 Windows 사용자 SID를 확인하지 못했습니다.")
    try:
        row = next(csv.reader([outcome.stdout.strip()]))
    except (StopIteration, csv.Error) as exc:
        raise InstallerError("현재 Windows 사용자 SID 형식을 확인하지 못했습니다.") from exc
    if len(row) < 2 or not row[1].startswith("S-1-"):
        raise InstallerError("현재 Windows 사용자 SID 형식을 확인하지 못했습니다.")
    return row[1]


def _private_permissions_ok(path: Path, expected_mode: int) -> bool:
    try:
        if _is_unsafe_link(path) or _has_unsafe_existing_ancestor(path.parent) or not path.exists():
            return False
        if os.name != "nt":
            return stat.S_IMODE(path.stat().st_mode) == expected_mode
        return _windows_private_acl_ok(path, sid=_windows_current_sid(), is_directory=path.is_dir())
    except (InstallerError, OSError):
        return False


def _is_unsafe_link(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        attributes = int(getattr(path.lstat(), "st_file_attributes", 0))
    except OSError:
        return False
    return bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)))


def _has_unsafe_existing_ancestor(path: Path) -> bool:
    current = path.absolute()
    while True:
        if _is_unsafe_link(current):
            return True
        if current.parent == current:
            return False
        current = current.parent


def _windows_private_acl_ok(path: Path, *, sid: str, is_directory: bool) -> bool:
    outcome = _run_command(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_READ_PRIVATE_ACL_SCRIPT],
        timeout=10,
        input_text=json.dumps({"path": str(path), "is_directory": is_directory}),
    )
    if not outcome.ok:
        return False
    try:
        payload = json.loads(outcome.stdout)
    except (json.JSONDecodeError, TypeError):
        return False
    if not isinstance(payload, dict) or payload.get("protected") is not True or payload.get("owner_sid") != sid:
        return False
    rules = payload.get("rules")
    if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
        return False
    rule = rules[0]
    inheritance_flags = {part.strip() for part in str(rule.get("inheritance_flags") or "").split(",")}
    expected_flags = {"ContainerInherit", "ObjectInherit"} if is_directory else {"None"}
    return (
        rule.get("sid") == sid
        and rule.get("access_type") == "Allow"
        and rule.get("inherited") is False
        and rule.get("full_control") is True
        and inheritance_flags == expected_flags
        and rule.get("propagation_flags") == "None"
    )


def _run_command(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: float = 30,
    input_text: str | None = None,
) -> _CommandOutcome:
    try:
        completed = subprocess.run(
            list(argv),
            cwd=str(cwd) if cwd else None,
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _CommandOutcome(None, error="COMMAND_TIMEOUT")
    except OSError:
        return _CommandOutcome(None, error="COMMAND_START_FAILED")
    return _CommandOutcome(completed.returncode, completed.stdout or "", completed.stderr or "")
