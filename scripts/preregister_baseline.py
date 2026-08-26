from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "k_guard_baseline_preregistration.v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
CONTRACT_HEADINGS = {
    "denominator": (
        "## 5. 분리된 코퍼스 레인",
        "## 6. H100 표본 합격수",
    ),
    "oracle": (
        "## 3. 정답 오라클 위계",
        "## 4. 라벨 계약",
        "### 9.1 기계 matching",
    ),
    "severity": ("### 3.1 Severity 계약",),
    "canonicalization": (
        "### 3.1 Severity 계약",
        "### 9.1 기계 matching",
        "### 9.4 결정론적 app PASS 함수",
    ),
    "stop": (
        "## 12. 즉시 중단·rollback 조건",
        "## 13. 잠긴 제품 게이트",
    ),
    "claim": (
        "## 1. 판정과 증명 경계",
        "## 14. 허용 주장과 금지 주장",
    ),
}
RULE_EXACT_PATHS = frozenset(
    {
        "src/k_guard_mcp/access_policy.py",
        "src/k_guard_mcp/analyzers.py",
        "src/k_guard_mcp/collector.py",
        "src/k_guard_mcp/composite.py",
        "src/k_guard_mcp/cross_plane.py",
        "src/k_guard_mcp/database_gate.py",
        "src/k_guard_mcp/flow.py",
        "src/k_guard_mcp/governance.py",
        "src/k_guard_mcp/guardian.py",
        "src/k_guard_mcp/java_flow.py",
        "src/k_guard_mcp/privacy_taxonomy.py",
        "src/k_guard_mcp/release_policy.py",
        "src/k_guard_mcp/rules.py",
        "src/k_guard_mcp/scanner.py",
        "src/k_guard_mcp/severity.py",
        "src/k_guard_mcp/taint.py",
        "src/k_guard_mcp/validation.py",
    }
)


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git(repo_root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise ValueError(f"git command failed: {' '.join(args)}")
    return result


def _git_text(repo_root: Path, *args: str) -> str:
    return _git(repo_root, *args).stdout.decode("utf-8", errors="strict").strip()


def _regular_or_symlink_content(root: Path, relative: str) -> tuple[str, bytes] | None:
    candidate = root / Path(relative)
    try:
        unresolved = candidate.absolute()
        if not unresolved.is_relative_to(root):
            raise ValueError(f"worktree path escapes repository: {relative}")
        if candidate.is_symlink():
            return "symlink", os.readlink(candidate).encode("utf-8", errors="surrogatepass")
        if not candidate.exists():
            return None
        if not candidate.is_file():
            raise ValueError(f"worktree path is not a regular file: {relative}")
        if not candidate.resolve(strict=True).is_relative_to(root):
            raise ValueError(f"worktree path resolves outside repository: {relative}")
        return "file", candidate.read_bytes()
    except OSError as exc:
        raise ValueError(f"worktree path cannot be read: {relative}") from exc


def _git_object_content(repo_root: Path, spec: str) -> bytes | None:
    result = _git(repo_root, "show", spec, check=False)
    if result.returncode != 0:
        return None
    return result.stdout


def _dirty_paths(repo_root: Path) -> list[dict[str, Any]]:
    raw = _git(
        repo_root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--no-renames",
    ).stdout
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        if len(record) < 4 or record[2:3] != b" ":
            raise ValueError("git returned an invalid porcelain record")
        status = record[:2].decode("ascii", errors="strict")
        if "U" in status or status in {"AA", "DD"}:
            raise ValueError("unmerged paths cannot be preregistered")
        relative = record[3:].decode("utf-8", errors="strict").replace("\\", "/")
        if not relative or relative in seen or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError("git returned an unsafe or duplicate dirty path")
        seen.add(relative)
        worktree = _regular_or_symlink_content(repo_root, relative)
        head_content = _git_object_content(repo_root, f"HEAD:{relative}")
        index_content = _git_object_content(repo_root, f":{relative}")
        rows.append(
            {
                "path": relative,
                "status": status,
                "head_sha256": sha256_bytes(head_content) if head_content is not None else None,
                "index_sha256": sha256_bytes(index_content) if index_content is not None else None,
                "worktree_kind": worktree[0] if worktree is not None else "missing",
                "worktree_sha256": sha256_bytes(worktree[1]) if worktree is not None else None,
                "worktree_byte_count": len(worktree[1]) if worktree is not None else 0,
            }
        )
    rows.sort(key=lambda row: row["path"])
    return rows


def _tracked_paths(repo_root: Path) -> list[str]:
    raw = _git(repo_root, "ls-files", "-z").stdout
    paths = [item.decode("utf-8", errors="strict").replace("\\", "/") for item in raw.split(b"\0") if item]
    if not paths or len(paths) != len(set(paths)):
        raise ValueError("tracked path inventory is empty or contains duplicates")
    return sorted(paths)


def _path_records(repo_root: Path, paths: Iterable[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for relative in sorted(set(paths)):
        content = _regular_or_symlink_content(repo_root, relative)
        rows.append(
            {
                "path": relative,
                "kind": content[0] if content is not None else "missing",
                "sha256": sha256_bytes(content[1]) if content is not None else None,
                "byte_count": len(content[1]) if content is not None else 0,
            }
        )
    return rows


def _fingerprint(name: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        raise ValueError(f"{name} fingerprint has no inputs")
    body = json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "schema": f"k_guard_{name}_fingerprint.v1",
        "sha256": sha256_bytes(f"k_guard_{name}_fingerprint.v1\0".encode("ascii") + body),
        "file_count": len(rows),
        "files": rows,
    }


def _rule_paths(tracked: Iterable[str]) -> list[str]:
    return [
        path
        for path in tracked
        if path in RULE_EXACT_PATHS or path.startswith("src/k_guard_mcp/detectors/")
    ]


def _config_paths(tracked: Iterable[str]) -> list[str]:
    return [
        path
        for path in tracked
        if path.startswith("src/k_guard_mcp/analyzer_profiles/")
        or path.endswith("/expectations.json")
        or path.endswith("/pack.json")
        or path in {"pyproject.toml", "requirements-evidence.lock"}
    ]


def _dependency_paths(tracked: Iterable[str]) -> list[str]:
    return [
        path
        for path in tracked
        if path == "pyproject.toml"
        or path.startswith("requirements-") and path.endswith(".lock")
        or path.startswith("requirements") and path.endswith(".txt")
    ]


def _declared_dependencies(repo_root: Path) -> dict[str, Any]:
    pyproject_path = repo_root / "pyproject.toml"
    if not pyproject_path.is_file() or pyproject_path.is_symlink():
        raise ValueError("pyproject.toml is missing or unsafe")
    try:
        project = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))["project"]
        runtime = project["dependencies"]
        optional = project.get("optional-dependencies", {})
    except (KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("pyproject dependency contract is invalid") from exc
    if not isinstance(runtime, list) or not all(isinstance(item, str) for item in runtime):
        raise ValueError("runtime dependency declarations are invalid")
    if not isinstance(optional, dict) or not all(
        isinstance(name, str)
        and isinstance(values, list)
        and all(isinstance(item, str) for item in values)
        for name, values in optional.items()
    ):
        raise ValueError("optional dependency declarations are invalid")
    return {
        "runtime": sorted(runtime),
        "optional": {name: sorted(values) for name, values in sorted(optional.items())},
    }


def _runtime_fingerprint() -> dict[str, Any]:
    executable = Path(sys.executable).resolve(strict=True)
    if not executable.is_file():
        raise ValueError("Python executable is not a regular file")
    distributions = sorted(
        (
            str(distribution.metadata.get("Name") or distribution.name).casefold(),
            str(distribution.version),
        )
        for distribution in importlib.metadata.distributions()
    )
    if not distributions:
        raise ValueError("installed distribution inventory is empty")
    distribution_bytes = json.dumps(distributions, separators=(",", ":")).encode("utf-8")
    payload = {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_executable_sha256": sha256_bytes(executable.read_bytes()),
        "platform_system": platform.system(),
        "platform_release": platform.release(),
        "platform_machine": platform.machine(),
        "installed_distribution_count": len(distributions),
        "installed_distribution_set_sha256": sha256_bytes(distribution_bytes),
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "schema": "k_guard_runtime_fingerprint.v1",
        **payload,
        "sha256": sha256_bytes(b"k_guard_runtime_fingerprint.v1\0" + body),
    }


def _section_bytes(lines: list[str], heading: str) -> bytes:
    matches = [index for index, line in enumerate(lines) if line.rstrip("\r\n") == heading]
    if len(matches) != 1:
        raise ValueError(f"consensus heading is missing or duplicated: {heading}")
    start = matches[0]
    level = len(heading) - len(heading.lstrip("#"))
    end = len(lines)
    for index in range(start + 1, len(lines)):
        stripped = lines[index].lstrip()
        if not stripped.startswith("#"):
            continue
        match = re.match(r"^(#+)\s", stripped)
        if match and len(match.group(1)) <= level:
            end = index
            break
    return "".join(lines[start:end]).replace("\r\n", "\n").encode("utf-8")


def _consensus_contract(consensus_path: Path) -> dict[str, Any]:
    if not consensus_path.is_file() or consensus_path.is_symlink():
        raise ValueError("consensus plan must be a regular file")
    raw = consensus_path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("consensus plan must be UTF-8") from exc
    lines = text.splitlines(keepends=True)
    references: dict[str, list[dict[str, str]]] = {}
    for contract, headings in CONTRACT_HEADINGS.items():
        references[contract] = [
            {"heading": heading, "section_sha256": sha256_bytes(_section_bytes(lines, heading))}
            for heading in headings
        ]
    return {
        "source_name": consensus_path.name,
        "sha256": sha256_bytes(raw),
        "byte_count": len(raw),
        "references": references,
    }


def build_preregistration(repo_root: Path, consensus_path: Path) -> dict[str, Any]:
    root = repo_root.resolve(strict=True)
    discovered_root = Path(_git_text(root, "rev-parse", "--show-toplevel")).resolve(strict=True)
    if discovered_root != root:
        raise ValueError("repository path must be the Git worktree root")
    head = _git_text(root, "rev-parse", "HEAD")
    tree = _git_text(root, "rev-parse", "HEAD^{tree}")
    if REVISION_RE.fullmatch(head) is None or REVISION_RE.fullmatch(tree) is None:
        raise ValueError("Git HEAD or tree is not a full object ID")
    tracked = _tracked_paths(root)
    dirty = _dirty_paths(root)
    dirty_hash = sha256_bytes(
        b"k_guard_dirty_path_set.v1\0"
        + json.dumps(dirty, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    dependency_files = _fingerprint("dependency_files", _path_records(root, _dependency_paths(tracked)))
    declared = _declared_dependencies(root)
    dependency_contract = {
        "files": dependency_files,
        "declared": declared,
    }
    dependency_contract["sha256"] = sha256_bytes(
        b"k_guard_dependency_contract.v1\0"
        + json.dumps(dependency_contract, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "git": {
            "head": head,
            "head_tree": tree,
            "dirty_path_count": len(dirty),
            "dirty_path_set_sha256": dirty_hash,
            "dirty_paths": dirty,
        },
        "fingerprints": {
            "rules": _fingerprint("rules", _path_records(root, _rule_paths(tracked))),
            "config": _fingerprint("config", _path_records(root, _config_paths(tracked))),
            "dependencies": dependency_contract,
            "runtime": _runtime_fingerprint(),
        },
        "consensus_plan": _consensus_contract(consensus_path.resolve(strict=True)),
        "validation_policy": {
            "mode": "fail_closed_exact_recomputation",
            "dirty_worktree_allowed_only_when_content_hash_bound": True,
            "unmerged_paths_allowed": False,
            "manifest_output_must_be_outside_repository": True,
            "raw_source_content_embedded": False,
        },
    }
    payload["manifest_sha256"] = sha256_bytes(canonical_json_bytes(payload))
    return payload


def load_preregistration(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 20 * 1024 * 1024:
        raise ValueError("preregistration manifest is missing, unsafe, or oversized")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("preregistration manifest is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError("preregistration manifest is not canonical JSON")
    digest = payload.get("manifest_sha256")
    unsigned = dict(payload)
    unsigned.pop("manifest_sha256", None)
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise ValueError("preregistration manifest hash is invalid")
    if sha256_bytes(canonical_json_bytes(unsigned)) != digest:
        raise ValueError("preregistration manifest hash mismatch")
    return payload


def verify_preregistration(repo_root: Path, consensus_path: Path, manifest_path: Path) -> dict[str, Any]:
    actual = load_preregistration(manifest_path)
    if actual.get("schema") != SCHEMA:
        raise ValueError("preregistration schema is unsupported")
    expected = build_preregistration(repo_root, consensus_path)
    if actual != expected:
        raise ValueError("baseline or preregistered contract changed after freeze")
    return actual


def _outside_repository(repo_root: Path, output: Path) -> bool:
    root = repo_root.resolve(strict=True)
    candidate = output.absolute().resolve(strict=False)
    return not candidate.is_relative_to(root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze and verify the K-Guard Phase 0-1 preregistration.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    verify = subparsers.add_parser("verify")
    for command in (create, verify):
        command.add_argument("--repo", type=Path, required=True)
        command.add_argument("--consensus", type=Path, required=True)
        command.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            if not _outside_repository(args.repo, args.manifest):
                raise ValueError("manifest output must be outside the repository")
            if args.manifest.exists() or args.manifest.is_symlink():
                raise ValueError("manifest output already exists")
            payload = build_preregistration(args.repo, args.consensus)
            args.manifest.parent.mkdir(parents=True, exist_ok=True)
            temporary = args.manifest.with_name(args.manifest.name + ".tmp")
            if temporary.exists() or temporary.is_symlink():
                raise ValueError("temporary manifest path already exists")
            temporary.write_bytes(canonical_json_bytes(payload))
            os.replace(temporary, args.manifest)
        else:
            verify_preregistration(args.repo, args.consensus, args.manifest)
    except (OSError, ValueError) as exc:
        print(f"HOLD: {exc}", file=sys.stderr)
        return 2
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
