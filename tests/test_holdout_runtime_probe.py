from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.holdout_protocol import (
    build_scanner_scaffold_manifest,
    capture_runtime_environment,
)


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "scripts" / "holdout_runtime_probe.py"


def _record_hash(payload: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode("ascii").rstrip("=")


@pytest.fixture(scope="session")
def isolated_base_python(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Avoid inheriting hardlinks created by unrelated host-process tests."""

    source = Path(sys.base_prefix).resolve(strict=True)
    base = tmp_path_factory.mktemp("holdout-runtime-base") / "base"
    shutil.copytree(
        source,
        base,
        ignore=shutil.ignore_patterns("site-packages", "__pycache__"),
        copy_function=shutil.copy2,
        # Some official macOS Python frameworks contain optional Tk/Tcl
        # header symlinks whose targets are not shipped.  They are unrelated
        # to the isolated runtime under test and must not make fixture setup
        # platform-image dependent.
        ignore_dangling_symlinks=True,
    )
    python = base / ("python.exe" if sys.platform == "win32" else "bin/python")
    if not python.is_file() or python.is_symlink() or python.stat().st_nlink != 1:
        pytest.fail("isolated base runtime is not a regular independent executable")
    return python


def _fixture_runtime(tmp_path: Path, isolated_base_python: Path) -> tuple[Path, Path, dict]:
    environment = tmp_path / "venv"
    subprocess.run(
        [
            str(isolated_base_python),
            "-I",
            "-B",
            "-S",
            "-m",
            "venv",
            "--without-pip",
            "--copies",
            str(environment),
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=120,
    )
    scaffold = build_scanner_scaffold_manifest(environment)
    scanner = environment / ("Scripts/python.exe" if __import__("sys").platform == "win32" else "bin/python")
    purelib = Path(
        subprocess.check_output(
            [str(scanner), "-I", "-B", "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
            text=True,
        ).strip()
    )
    package = purelib / "k_guard_mcp"
    dist_info = purelib / "k_guard_mcp-0.1.0.dist-info"
    package.mkdir()
    dist_info.mkdir()
    package_payload = b"VERSION = '0.1.0'\n"
    metadata_payload = b"Metadata-Version: 2.1\nName: k-guard-mcp\nVersion: 0.1.0\n\n"
    wheel_payload = b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
    (package / "__init__.py").write_bytes(package_payload)
    (dist_info / "METADATA").write_bytes(metadata_payload)
    (dist_info / "WHEEL").write_bytes(wheel_payload)
    rows = [
        f"k_guard_mcp/__init__.py,sha256={_record_hash(package_payload)},{len(package_payload)}\n",
        f"k_guard_mcp-0.1.0.dist-info/METADATA,sha256={_record_hash(metadata_payload)},{len(metadata_payload)}\n",
        f"k_guard_mcp-0.1.0.dist-info/WHEEL,sha256={_record_hash(wheel_payload)},{len(wheel_payload)}\n",
        "k_guard_mcp-0.1.0.dist-info/RECORD,,\n",
    ]
    (dist_info / "RECORD").write_text("".join(rows), encoding="utf-8", newline="")
    return scanner, package / "__init__.py", scaffold


def test_isolated_runtime_probe_binds_installed_files_and_rejects_record_tamper(
    tmp_path: Path, isolated_base_python: Path
) -> None:
    scanner, package_file, scaffold = _fixture_runtime(tmp_path, isolated_base_python)

    payload = capture_runtime_environment(scanner, PROBE, scaffold)

    assert payload["attestation_passed"] is True
    assert payload["python"]["isolated_flag"] == 1
    assert payload["python"]["dont_write_bytecode_flag"] == 1
    assert payload["python"]["include_system_site_packages"] is False
    assert payload["base_site_package_import_paths"] == []
    assert payload["k_guard"]["import_root"].startswith("<prefix>/")
    assert payload["installed_distribution_count"] == 1

    package_file.write_text("VERSION = 'tampered'\n", encoding="utf-8")
    with pytest.raises(ValueError, match="attestation failed"):
        capture_runtime_environment(scanner, PROBE, scaffold)


def test_isolated_runtime_probe_rejects_orphan_pth_and_detects_record_rewrite(
    tmp_path: Path, isolated_base_python: Path
) -> None:
    scanner, package_file, scaffold = _fixture_runtime(tmp_path, isolated_base_python)
    original = capture_runtime_environment(scanner, PROBE, scaffold)
    site_packages = package_file.parent.parent
    orphan = site_packages / "attacker.pth"
    orphan.write_text("import attacker\n", encoding="utf-8")
    with pytest.raises(ValueError, match="attestation failed"):
        capture_runtime_environment(scanner, PROBE, scaffold)
    orphan.unlink()

    changed_payload = b"VERSION = 'same-version-different-code'\n"
    package_file.write_bytes(changed_payload)
    record = site_packages / "k_guard_mcp-0.1.0.dist-info" / "RECORD"
    rows = record.read_text(encoding="utf-8").splitlines()
    rows[0] = (
        "k_guard_mcp/__init__.py,sha256="
        + _record_hash(changed_payload)
        + f",{len(changed_payload)}"
    )
    record.write_text("\n".join(rows) + "\n", encoding="utf-8", newline="")
    changed = capture_runtime_environment(scanner, PROBE, scaffold)

    assert changed["attestation_passed"] is True
    assert changed["prefix_tree"]["sha256"] != original["prefix_tree"]["sha256"]
    assert (
        changed["installed_distribution_set_sha256"]
        != original["installed_distribution_set_sha256"]
    )


def test_isolated_runtime_probe_rejects_system_site_packages(
    tmp_path: Path, isolated_base_python: Path
) -> None:
    scanner, _package_file, scaffold = _fixture_runtime(tmp_path, isolated_base_python)
    config = scanner.parents[1] / "pyvenv.cfg"
    original = config.read_text(encoding="utf-8")
    config.write_text(
        original.replace("include-system-site-packages = false", "include-system-site-packages = true"),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="attestation failed"):
        capture_runtime_environment(scanner, PROBE, scaffold)


def test_isolated_runtime_probe_rejects_unowned_file_outside_site_packages(
    tmp_path: Path, isolated_base_python: Path
) -> None:
    scanner, _package_file, scaffold = _fixture_runtime(tmp_path, isolated_base_python)
    injected = scanner.parent / "stable-unowned.dll"
    injected.write_bytes(b"not a wheel-owned runtime file")

    with pytest.raises(ValueError, match="attestation failed"):
        capture_runtime_environment(scanner, PROBE, scaffold)


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="Windows hardlink boundary")
def test_isolated_runtime_probe_rejects_hardlinked_scanner_file(
    tmp_path: Path, isolated_base_python: Path
) -> None:
    scanner, _package_file, scaffold = _fixture_runtime(tmp_path, isolated_base_python)
    os.link(scanner, scanner.with_name("python-hardlink.exe"))

    with pytest.raises(ValueError, match="attestation failed"):
        capture_runtime_environment(scanner, PROBE, scaffold)
