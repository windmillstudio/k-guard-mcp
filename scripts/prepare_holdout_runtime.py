from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import venv
from pathlib import Path
from typing import Any

try:
    from scripts.holdout_protocol import (
        build_wheelhouse_manifest,
        build_scanner_scaffold_manifest,
        canonical_json_bytes,
        load_install_report,
        load_wheelhouse_manifest,
        sha256_file,
        write_runtime_environment,
    )
except ModuleNotFoundError:
    from holdout_protocol import (
        build_wheelhouse_manifest,
        build_scanner_scaffold_manifest,
        canonical_json_bytes,
        load_install_report,
        load_wheelhouse_manifest,
        sha256_file,
        write_runtime_environment,
    )


def _canonical_name(value: Any) -> str:
    return re.sub(r"[-_.]+", "-", str(value or "")).casefold()


def seal_install_report(path: Path, wheel_sha256: str) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    install_rows = payload.get("install") if isinstance(payload, dict) else None
    if payload.get("version") != "1" or not isinstance(install_rows, list) or not install_rows:
        raise ValueError("pip did not produce a valid installation report")
    artifact_rows: list[dict[str, str]] = []
    root_matches = 0
    names: set[str] = set()
    for row in install_rows:
        if not isinstance(row, dict):
            raise ValueError("pip installation report row is invalid")
        metadata = row.get("metadata")
        download = row.get("download_info")
        if not isinstance(metadata, dict) or not isinstance(download, dict):
            raise ValueError("pip installation report metadata is invalid")
        name = _canonical_name(metadata.get("name"))
        version = str(metadata.get("version") or "")
        archive = download.get("archive_info")
        hashes = archive.get("hashes") if isinstance(archive, dict) else None
        digest = str(hashes.get("sha256") or "") if isinstance(hashes, dict) else ""
        if not name or not version or name in names or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("pip installation artifact identity is invalid")
        names.add(name)
        artifact_rows.append({"name": name, "version": version, "sha256": digest})
        if name == "k-guard-mcp" and row.get("requested") is True and digest == wheel_sha256:
            root_matches += 1
    if root_matches != 1:
        raise ValueError("pip installation report is not rooted in the requested K-Guard wheel")
    payload["k_guard_install_artifact_set_sha256"] = hashlib.sha256(
        json.dumps(sorted(artifact_rows, key=lambda row: row["name"]), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    path.write_bytes(canonical_json_bytes(payload))
    return payload


def prepare_runtime(
    wheel: Path,
    preregistration_root: Path,
    wheelhouse_dir: Path,
    wheelhouse_manifest_path: Path,
    venv_dir: Path,
    install_report_path: Path,
    runtime_environment_path: Path,
    probe_script: Path,
) -> dict[str, Any]:
    wheel_path = wheel.resolve(strict=True)
    if wheel_path.suffix.casefold() != ".whl" or wheel_path.is_symlink():
        raise ValueError("holdout runtime requires a regular wheel artifact")
    if venv_dir.exists():
        raise ValueError("holdout runtime directory must not exist before preparation")
    if install_report_path.exists() or runtime_environment_path.exists():
        raise ValueError("holdout runtime evidence outputs must not already exist")
    prereg_root = preregistration_root.resolve(strict=True)
    if wheelhouse_dir.exists() or wheelhouse_manifest_path.exists():
        raise ValueError("holdout wheelhouse outputs must not already exist")
    if (
        not wheelhouse_dir.resolve().is_relative_to(prereg_root)
        or not wheelhouse_manifest_path.resolve().is_relative_to(prereg_root)
        or wheelhouse_manifest_path.resolve().parent != wheelhouse_dir.resolve()
    ):
        raise ValueError("holdout wheelhouse evidence must be under the preregistration root")
    installer_dir = venv_dir.with_name(f"{venv_dir.name}-installer")
    if installer_dir.exists():
        raise ValueError("holdout installer runtime directory must not already exist")
    venv.EnvBuilder(with_pip=False, clear=False, symlinks=False).create(venv_dir)
    scanner_scaffold = build_scanner_scaffold_manifest(venv_dir)
    scanner_python = (
        venv_dir / "Scripts" / "python.exe"
        if sys.platform == "win32"
        else venv_dir / "bin" / "python"
    ).resolve(strict=True)
    venv.EnvBuilder(with_pip=True, clear=False, symlinks=False).create(installer_dir)
    installer_python = (
        installer_dir / "Scripts" / "python.exe"
        if sys.platform == "win32"
        else installer_dir / "bin" / "python"
    ).resolve(strict=True)
    try:
        wheelhouse_dir.mkdir(parents=True)
        download = subprocess.run(
            [
                str(installer_python),
                "-I",
                "-B",
                "-m",
                "pip",
                "download",
                "--disable-pip-version-check",
                "--no-input",
                "--only-binary=:all:",
                "--dest",
                str(wheelhouse_dir),
                str(wheel_path),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=900,
        )
        if download.returncode != 0:
            raise RuntimeError(download.stderr.strip() or download.stdout.strip() or "wheelhouse download failed")
        wheel_hash = sha256_file(wheel_path)
        bound_roots = [path for path in wheelhouse_dir.glob("*.whl") if sha256_file(path) == wheel_hash]
        if len(bound_roots) != 1:
            raise RuntimeError("wheelhouse does not contain exactly one copy of the bound K-Guard wheel")
        wheelhouse_payload = build_wheelhouse_manifest(wheelhouse_dir, prereg_root)
        wheelhouse_manifest_path.parent.mkdir(parents=True, exist_ok=True)
        wheelhouse_manifest_path.write_bytes(canonical_json_bytes(wheelhouse_payload))

        install_report_path.parent.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            [
                str(installer_python),
                "-I",
                "-B",
                "-m",
                "pip",
                "--python",
                str(scanner_python),
                "install",
                "--disable-pip-version-check",
                "--no-input",
                "--no-compile",
                "--only-binary=:all:",
                "--no-index",
                "--find-links",
                str(wheelhouse_dir),
                "--report",
                str(install_report_path),
                str(bound_roots[0]),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=900,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "pip installation failed")
    finally:
        shutil.rmtree(installer_dir, ignore_errors=False)
    if installer_dir.exists():
        raise RuntimeError("temporary holdout installer runtime was not removed")
    install_report = seal_install_report(install_report_path, wheel_hash)
    runtime_environment = write_runtime_environment(
        scanner_python,
        probe_script,
        runtime_environment_path,
        scanner_scaffold,
    )
    load_install_report(
        install_report_path,
        wheel_sha256=wheel_hash,
        runtime_environment=runtime_environment,
    )
    load_wheelhouse_manifest(
        prereg_root,
        {
            "manifest_path": wheelhouse_manifest_path.resolve().relative_to(prereg_root).as_posix(),
            "manifest_sha256": sha256_file(wheelhouse_manifest_path),
            "artifact_set_sha256": wheelhouse_payload["artifact_set_sha256"],
        },
        runtime_environment=runtime_environment,
        install_report=install_report,
    )
    return {
        "bound_wheel": str(bound_roots[0].resolve()),
        "scanner_python": str(scanner_python),
        "scanner_python_sha256": runtime_environment["python"]["executable_sha256"],
        "runtime_environment_sha256": sha256_file(runtime_environment_path),
        "pip_install_report_sha256": sha256_file(install_report_path),
        "pip_install_artifact_set_sha256": install_report[
            "k_guard_install_artifact_set_sha256"
        ],
        "installed_distribution_set_sha256": runtime_environment[
            "installed_distribution_set_sha256"
        ],
        "prefix_tree_sha256": runtime_environment["prefix_tree"]["sha256"],
        "base_runtime_tree_sha256": runtime_environment["base_runtime_tree"]["sha256"],
        "scanner_scaffold_tree_sha256": scanner_scaffold["tree_sha256"],
        "wheelhouse_manifest_sha256": sha256_file(wheelhouse_manifest_path),
        "wheelhouse_artifact_set_sha256": wheelhouse_payload["artifact_set_sha256"],
        "raw_returned": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create an isolated wheel-installed scanner runtime and seal its file-level evidence."
    )
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--preregistration-root", type=Path, required=True)
    parser.add_argument("--wheelhouse-dir", type=Path, required=True)
    parser.add_argument("--wheelhouse-manifest", type=Path, required=True)
    parser.add_argument("--venv-dir", type=Path, required=True)
    parser.add_argument("--install-report", type=Path, required=True)
    parser.add_argument("--runtime-environment", type=Path, required=True)
    parser.add_argument(
        "--probe-script",
        type=Path,
        default=Path(__file__).resolve().with_name("holdout_runtime_probe.py"),
    )
    args = parser.parse_args()
    result = prepare_runtime(
        args.wheel,
        args.preregistration_root,
        args.wheelhouse_dir,
        args.wheelhouse_manifest,
        args.venv_dir,
        args.install_report,
        args.runtime_environment,
        args.probe_script,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
