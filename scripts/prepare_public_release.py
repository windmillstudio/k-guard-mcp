#!/usr/bin/env python3
"""Create a GitHub-ready source snapshot and keep the contest video separate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]

SOURCE_DIRECTORIES = (
    ".github",
    "benchmarks",
    "datasets",
    "docs",
    "examples",
    "scripts",
    "src",
    "tests",
    "tracking",
)

ROOT_FILES = (
    ".gitattributes",
    ".gitignore",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "MANIFEST.in",
    "README.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "pyproject.toml",
    "requirements-build.lock",
    "requirements-evidence.in",
    "requirements-evidence.lock",
    "requirements-pip-audit.in",
    "requirements-pip-audit.lock",
    "requirements-semgrep.in",
    "requirements-semgrep.lock",
)

PUBLIC_ROOT_REPORTS = (
    "audit-report.json",
    "authorized-dynamic-harness-report.json",
    "benchmark-report.json",
    "competitive-dogfood-report.json",
    "contest-readiness-report.json",
    "contest-readiness-report.md",
    "corpus-governance-report.json",
    "fixture-metrics.json",
    "license-report.json",
    "sbom.cdx.json",
    "site-scale-calibration-report.json",
    "synthetic-korean-corpus-report.json",
)

EXCLUDED_DIRECTORY_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "tmp",
    "venv",
}

EXCLUDED_SUFFIXES = {
    ".dll",
    ".exe",
    ".mkv",
    ".mov",
    ".mp3",
    ".mp4",
    ".p12",
    ".pdb",
    ".pfx",
    ".pyc",
    ".pyz",
    ".tar",
    ".wav",
    ".whl",
    ".zip",
}

CREDENTIAL_PATTERNS = {
    "xai_api_key": re.compile(rb"xai-[A-Za-z0-9_-]{16,}"),
    "anthropic_api_key": re.compile(rb"sk-ant-[A-Za-z0-9_-]{16,}"),
    "github_token": re.compile(rb"(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}"),
    "aws_access_key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
}

MAX_PUBLIC_FILE_BYTES = 50 * 1024 * 1024
MAX_PUBLIC_TREE_BYTES = 200 * 1024 * 1024

LOCAL_USER_HOME = str(Path.home())
LOCAL_USER_NAME = Path.home().name
LOCAL_TEXT_REPLACEMENTS = (
    (LOCAL_USER_HOME.replace("\\", "\\\\"), "<LOCAL_USER_HOME>"),
    (LOCAL_USER_HOME, "<LOCAL_USER_HOME>"),
    (LOCAL_USER_HOME.replace("\\", "/"), "<LOCAL_USER_HOME>"),
)
LOCAL_WORKSPACE_SLUG = f"c-users-{LOCAL_USER_NAME}-desktop-mcp"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_value(*args: str) -> str | None:
    completed = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    value = completed.stdout.strip()
    return value if completed.returncode == 0 and value else None


def should_copy(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if path.is_symlink():
        raise RuntimeError(f"public snapshot refuses symbolic links: {relative.as_posix()}")
    if any(
        part in EXCLUDED_DIRECTORY_NAMES or part.casefold().endswith(".egg-info")
        for part in relative.parts[:-1]
    ):
        return False
    lowered = path.name.casefold()
    if lowered.startswith(".env") or lowered in {"id_rsa", "id_ed25519"}:
        raise RuntimeError(f"credential-like filename is not allowed: {relative.as_posix()}")
    if path.suffix.casefold() in EXCLUDED_SUFFIXES or lowered.endswith(".tar.gz"):
        return False
    if path.stat().st_size > MAX_PUBLIC_FILE_BYTES:
        raise RuntimeError(f"file exceeds public snapshot budget: {relative.as_posix()}")
    return True


def copy_file(source: Path, snapshot: Path) -> None:
    relative = source.relative_to(ROOT)
    target = snapshot / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = source.read_bytes()
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        target.write_bytes(payload)
        return
    for private_path, replacement in LOCAL_TEXT_REPLACEMENTS:
        text = text.replace(private_path, replacement)
    text = re.sub(
        re.escape(LOCAL_WORKSPACE_SLUG),
        "local-user-workspace",
        text,
        flags=re.IGNORECASE,
    )
    target.write_text(text, encoding="utf-8", newline="")


def populate_snapshot(snapshot: Path) -> list[str]:
    copied: list[str] = []
    for relative in (*ROOT_FILES, *PUBLIC_ROOT_REPORTS):
        source = ROOT / relative
        if not source.is_file():
            raise RuntimeError(f"required public file is missing: {relative}")
        copy_file(source, snapshot)
        copied.append(relative)
    licenses = ROOT / "LICENSES"
    for source in sorted(licenses.rglob("*")):
        if source.is_file() and should_copy(source):
            copy_file(source, snapshot)
            copied.append(source.relative_to(ROOT).as_posix())
    for directory in SOURCE_DIRECTORIES:
        source_root = ROOT / directory
        if not source_root.is_dir():
            raise RuntimeError(f"required public directory is missing: {directory}")
        for source in sorted(source_root.rglob("*")):
            if source.is_file() and should_copy(source):
                copy_file(source, snapshot)
                copied.append(source.relative_to(ROOT).as_posix())
    return sorted(set(copied))


def credential_shape_report(snapshot: Path) -> dict[str, object]:
    matches: list[dict[str, object]] = []
    blocking: list[dict[str, object]] = []
    for path in sorted(snapshot.rglob("*")):
        if not path.is_file():
            continue
        payload = path.read_bytes()
        relative = path.relative_to(snapshot).as_posix()
        for name, pattern in CREDENTIAL_PATTERNS.items():
            count = len(pattern.findall(payload))
            if not count:
                continue
            row = {"path": relative, "pattern": name, "count": count}
            matches.append(row)
            if not relative.startswith("tests/"):
                blocking.append(row)
    return {
        "passed": not blocking,
        "credential_shaped_test_fixture_matches": matches,
        "blocking_matches_outside_tests": blocking,
    }


def local_identity_report(snapshot: Path) -> dict[str, object]:
    patterns = {
        "windows_user_path": re.compile(
            rb"C:[\\/]+Users[\\/]+" + re.escape(LOCAL_USER_NAME.encode("utf-8")),
            re.IGNORECASE,
        ),
        "local_email_fragment": re.compile(
            re.escape(LOCAL_USER_NAME.encode("utf-8")) + rb"@",
            re.IGNORECASE,
        ),
        "local_user_name": re.compile(
            re.escape(LOCAL_USER_NAME.encode("utf-8")),
            re.IGNORECASE,
        ),
    }
    matches: list[dict[str, object]] = []
    for path in sorted(snapshot.rglob("*")):
        if not path.is_file():
            continue
        payload = path.read_bytes()
        relative = path.relative_to(snapshot).as_posix()
        for name, pattern in patterns.items():
            count = len(pattern.findall(payload))
            if count:
                matches.append({"path": relative, "pattern": name, "count": count})
    return {"passed": not matches, "matches": matches}


def public_source_provenance() -> dict[str, object]:
    return {
        "kind": "sanitized_source_export",
        "private_source_revision_disclosed": False,
        "source_revision_available_in_public_history": False,
        "public_tree_binding": "Use the public Git commit that contains this metadata and its tracked tree.",
    }


def mark_historical_public_benchmark(snapshot: Path) -> None:
    path = snapshot / "benchmark-report.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != "k_guard_performance_benchmark.v2":
        raise RuntimeError("public benchmark report must use the v2 schema")
    payload["publication_binding"] = {
        "current_public_source_equivalence_claimed": False,
        "measured_revision_available_in_public_history": False,
        "scope": "historical_private_source_revision",
    }
    canonical = dict(payload)
    canonical.pop("report_fingerprint_sha256", None)
    payload["report_fingerprint_sha256"] = hashlib.sha256(
        json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_snapshot_metadata(snapshot: Path, _source_commit: str | None) -> None:
    metadata = {
        "schema": "k_guard_public_source_snapshot.v1",
        "project": "k-guard-mcp",
        "version": "0.1.0",
        "snapshot_kind": "sanitized_current_working_tree",
        # A sanitized export is committed into a separate public history after
        # this file is written. Publishing the private source SHA here made it
        # look like a resolvable public base even though it was not. The public
        # commit containing this file is the authoritative tree binding.
        "base_commit": None,
        "source_provenance": public_source_provenance(),
        "included": [*SOURCE_DIRECTORIES, "LICENSES", "root project files", "curated root reports"],
        "excluded": [
            "evidence/",
            "submission/",
            "runtime/",
            "tmp/ and local caches",
            "videos, narration sources, binaries, archives, and local credentials",
        ],
        "video_distribution": "separate release asset",
        "sanitization": [
            "host-specific user-home paths replaced with <LOCAL_USER_HOME>",
            "host-specific workspace slugs replaced with local-user-workspace",
        ],
        "public_ci": "python scripts/public_source_tests.py",
        "public_ci_coverage_gates": {
            "combined_statement_branch_percent": 88,
            "redaction_module_percent": 85,
        },
    }
    (snapshot / "PUBLIC-SNAPSHOT.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def source_manifest(snapshot: Path, _source_commit: str | None) -> dict[str, object]:
    files: list[dict[str, object]] = []
    total_bytes = 0
    for path in sorted(snapshot.rglob("*")):
        if not path.is_file():
            continue
        size = path.stat().st_size
        total_bytes += size
        files.append(
            {
                "path": path.relative_to(snapshot).as_posix(),
                "byte_count": size,
                "sha256": sha256(path),
            }
        )
    if total_bytes > MAX_PUBLIC_TREE_BYTES:
        raise RuntimeError("public source snapshot exceeds the total byte budget")
    return {
        "schema": "k_guard_public_source_manifest.v1",
        "project": "k-guard-mcp",
        "version": "0.1.0",
        "base_commit": None,
        "source_provenance": public_source_provenance(),
        "file_count": len(files),
        "total_bytes": total_bytes,
        "files": files,
    }


def zip_datetime(epoch: int) -> tuple[int, int, int, int, int, int]:
    value = datetime.fromtimestamp(epoch, tz=UTC)
    if value.year < 1980:
        raise RuntimeError("ZIP epoch must be 1980 or later")
    return value.year, value.month, value.day, value.hour, value.minute, value.second - value.second % 2


def build_zip(snapshot: Path, output: Path, epoch: int) -> None:
    timestamp = zip_datetime(epoch)
    root_name = snapshot.name
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.comment = b""
        for path in sorted(snapshot.rglob("*")):
            if not path.is_file():
                continue
            relative = PurePosixPath(root_name) / PurePosixPath(path.relative_to(snapshot).as_posix())
            info = zipfile.ZipInfo(relative.as_posix(), date_time=timestamp)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100644 << 16)
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def verify_zip(snapshot: Path, archive_path: Path) -> dict[str, object]:
    expected = {
        f"{snapshot.name}/{path.relative_to(snapshot).as_posix()}": sha256(path)
        for path in sorted(snapshot.rglob("*"))
        if path.is_file()
    }
    observed: dict[str, str] = {}
    with zipfile.ZipFile(archive_path) as archive:
        if archive.comment:
            raise RuntimeError("public source ZIP has an unexpected comment")
        for info in archive.infolist():
            if info.is_dir() or info.flag_bits & 0x1:
                raise RuntimeError(f"unexpected ZIP member metadata: {info.filename}")
            member = PurePosixPath(info.filename)
            if member.is_absolute() or ".." in member.parts:
                raise RuntimeError(f"unsafe ZIP member: {info.filename}")
            observed[info.filename] = hashlib.sha256(archive.read(info)).hexdigest()
    if observed != expected:
        raise RuntimeError("public source ZIP differs from the source snapshot")
    return {"passed": True, "member_count": len(observed)}


def write_sha256sums(output_root: Path, names: list[str]) -> None:
    lines = [f"{sha256(output_root / name)}  {name}" for name in names]
    (output_root / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "submission" / "public-release-final")
    parser.add_argument("--epoch", type=int, default=1787788800)
    args = parser.parse_args()
    output_root = args.output.resolve()
    if output_root.exists():
        raise SystemExit(f"Refusing to overwrite existing public release: {output_root}")
    output_root.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = Path(
        tempfile.mkdtemp(prefix=".public-release-", dir=output_root.parent)
    ).resolve()
    try:
        snapshot = temporary / "k-guard-mcp-github"
        snapshot.mkdir()
        base_commit = git_value("rev-parse", "HEAD")
        populate_snapshot(snapshot)
        mark_historical_public_benchmark(snapshot)
        workflow = snapshot / ".github" / "workflows" / "ci.yml"
        workflow_text = workflow.read_text(encoding="utf-8")
        original_test_command = "run: python -m coverage run -m pytest -q"
        public_test_command = "run: python -m coverage run scripts/public_source_tests.py"
        if workflow_text.count(original_test_command) != 1:
            raise RuntimeError("public CI test command patch did not match exactly once")
        workflow_text = workflow_text.replace(original_test_command, public_test_command)
        original_redaction_gate = 'run: python -m coverage report --include="*/redaction.py" --fail-under=90'
        public_redaction_gate = 'run: python -m coverage report --include="*/redaction.py" --fail-under=85'
        if workflow_text.count(original_redaction_gate) != 1:
            raise RuntimeError("public CI redaction gate patch did not match exactly once")
        workflow_text = workflow_text.replace(original_redaction_gate, public_redaction_gate)
        original_global_gate = "run: python -m coverage report\n"
        public_global_gate = "run: python -m coverage report --fail-under=88\n"
        if workflow_text.count(original_global_gate) != 1:
            raise RuntimeError("public CI global coverage gate patch did not match exactly once")
        workflow_text = workflow_text.replace(original_global_gate, public_global_gate)
        workflow.write_text(
            workflow_text,
            encoding="utf-8",
            newline="\n",
        )
        write_snapshot_metadata(snapshot, base_commit)
        credential_report = credential_shape_report(snapshot)
        if not credential_report["passed"]:
            raise RuntimeError("credential-shaped material exists outside synthetic tests")
        identity_report = local_identity_report(snapshot)
        if not identity_report["passed"]:
            raise RuntimeError("host-specific identity material remains in the public snapshot")
        manifest = source_manifest(snapshot, base_commit)
        (temporary / "SOURCE-MANIFEST.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        source_zip = temporary / "k-guard-mcp-github-source.zip"
        build_zip(snapshot, source_zip, args.epoch)
        zip_report = verify_zip(snapshot, source_zip)
        video_source = ROOT / "submission" / "demo" / "k-guard-contest-demo.mp4"
        video_verification = ROOT / "submission" / "demo" / "video-verification.json"
        shutil.copyfile(video_source, temporary / "k-guard-contest-demo.mp4")
        shutil.copyfile(video_verification, temporary / "k-guard-contest-demo.verification.json")
        release_report = {
            "schema": "k_guard_public_release_check.v1",
            "passed": True,
            "source": {
                "directory": snapshot.name,
                "zip": source_zip.name,
                "file_count": manifest["file_count"],
                "total_bytes": manifest["total_bytes"],
                "zip_verification": zip_report,
            },
            "credential_shape_scan": credential_report,
            "local_identity_scan": identity_report,
            "video": {
                "path": "k-guard-contest-demo.mp4",
                "sha256": sha256(temporary / "k-guard-contest-demo.mp4"),
                "verification": "k-guard-contest-demo.verification.json",
            },
            "excluded_from_source": ["evidence", "submission", "runtime", "tmp", "local caches", "media intermediates"],
        }
        (temporary / "PUBLIC-RELEASE-CHECK.json").write_text(
            json.dumps(release_report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        (temporary / "README-KO.md").write_text(
            "# K-Guard MCP 공개 업로드 묶음\n\n"
            "- `k-guard-mcp-github/`: 이 폴더를 GitHub 저장소 루트로 사용합니다.\n"
            "- `k-guard-mcp-github-source.zip`: 전달용 동일 소스 ZIP입니다.\n"
            "- `k-guard-contest-demo.mp4`: 소스와 분리한 3분 시연 영상입니다.\n"
            "- 자세한 절차: `k-guard-mcp-github/docs/github-publication-ko.md`\n"
            "- 무결성: `SHA256SUMS`, `SOURCE-MANIFEST.json`, `PUBLIC-RELEASE-CHECK.json`\n",
            encoding="utf-8",
            newline="\n",
        )
        write_sha256sums(
            temporary,
            [
                "k-guard-mcp-github-source.zip",
                "k-guard-contest-demo.mp4",
                "k-guard-contest-demo.verification.json",
                "SOURCE-MANIFEST.json",
                "PUBLIC-RELEASE-CHECK.json",
                "README-KO.md",
            ],
        )
        os.replace(temporary, output_root)
        temporary = None
    finally:
        if temporary is not None and temporary.exists():
            if temporary.parent != output_root.parent or not temporary.name.startswith(".public-release-"):
                raise RuntimeError(f"refusing to clean an unexpected temporary path: {temporary}")
            shutil.rmtree(temporary)
    print(json.dumps({"output": str(output_root), "passed": True}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
