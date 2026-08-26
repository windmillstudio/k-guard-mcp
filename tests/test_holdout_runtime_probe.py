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


def _runtime_copy_ignores(directory: str, names: list[str]) -> set[str]:
    ignored = set(
        shutil.ignore_patterns("site-packages", "__pycache__")(directory, names)
    )
    parent = Path(directory)
    ignored.update(
        name
        for name in names
        if (parent / name).is_symlink() and not (parent / name).exists()
    )
    return ignored


def _materialize_runtime_symlinks(root: Path) -> None:
    """Replace platform-created venv aliases with independent local copies."""

    root = root.resolve(strict=True)
    for _pass in range(256):
        links: list[Path] = []
        for directory, dirnames, filenames in os.walk(root, followlinks=False):
            parent = Path(directory)
            links.extend(
                parent / name
                for name in (*dirnames, *filenames)
                if (parent / name).is_symlink()
            )
        if not links:
            return

        for link in sorted(links, key=lambda path: len(path.parts), reverse=True):
            if not link.is_symlink():
                continue
            target = link.resolve(strict=True)
            if target == root or target in root.parents or target in link.parents:
                pytest.fail(
                    f"cyclic runtime alias cannot be materialized: {link.relative_to(root)}"
                )
            staged = link.with_name(f".{link.name}.materialized")
            if staged.exists() or staged.is_symlink():
                pytest.fail(
                    f"runtime alias staging path already exists: {staged.relative_to(root)}"
                )
            if target.is_dir():
                shutil.copytree(
                    target,
                    staged,
                    # Preserve nested links as links so a cycle cannot make
                    # copytree recurse forever; the next pass materializes
                    # each one under the same explicit checks.
                    symlinks=True,
                    copy_function=shutil.copy2,
                )
            elif target.is_file():
                shutil.copy2(target, staged)
            else:
                pytest.fail(
                    "runtime alias target is not a regular file or directory: "
                    f"{link.relative_to(root)}"
                )
            link.unlink()
            staged.replace(link)

    pytest.fail("runtime alias materialization did not converge")


def test_runtime_copy_ignores_only_truly_dangling_links(tmp_path: Path) -> None:
    (tmp_path / "python-real").write_bytes(b"runtime")
    try:
        os.symlink("python-real", tmp_path / "python")
        os.symlink("missing-target", tmp_path / "missing")
    except (NotImplementedError, OSError):
        pytest.skip("symbolic-link creation is unavailable")

    ignored = _runtime_copy_ignores(
        str(tmp_path),
        ["python", "missing", "site-packages", "__pycache__"],
    )

    assert ignored == {"missing", "site-packages", "__pycache__"}


def test_materialize_runtime_symlinks_creates_independent_files(tmp_path: Path) -> None:
    target = tmp_path / "runtime-real"
    target.write_bytes(b"runtime")
    alias = tmp_path / "runtime-alias"
    try:
        os.symlink(target.name, alias)
    except (NotImplementedError, OSError):
        pytest.skip("symbolic-link creation is unavailable")

    _materialize_runtime_symlinks(tmp_path)

    assert alias.read_bytes() == b"runtime"
    assert not alias.is_symlink()
    assert alias.stat().st_nlink == 1


def test_scanner_scaffold_rejects_nonstandard_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "runtime-real"
    target.write_bytes(b"runtime")
    try:
        os.symlink(target.name, tmp_path / "runtime-alias")
    except (NotImplementedError, OSError):
        pytest.skip("symbolic-link creation is unavailable")

    with pytest.raises(ValueError, match="reparse point"):
        build_scanner_scaffold_manifest(tmp_path)


@pytest.fixture(scope="session")
def isolated_base_python(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Avoid inheriting hardlinks created by unrelated host-process tests."""

    source = Path(sys.base_prefix).resolve(strict=True)
    base = tmp_path_factory.mktemp("holdout-runtime-base") / "base"
    shutil.copytree(
        source,
        base,
        # Official macOS frameworks may contain optional Tk/Tcl header links
        # whose targets are not shipped.  Resolve dangling links relative to
        # their containing directory so valid POSIX links such as bin/python
        # are still followed and copied into independent regular files.
        ignore=_runtime_copy_ignores,
        copy_function=shutil.copy2,
    )
    python = base / ("python.exe" if sys.platform == "win32" else "bin/python")
    if not python.is_file() or python.is_symlink() or python.stat().st_nlink != 1:
        pytest.fail("isolated base runtime is not a regular independent executable")
    reported_base = Path(
        subprocess.check_output(
            [str(python), "-I", "-B", "-S", "-c", "import sys; print(sys.base_prefix)"],
            stdin=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=30,
        ).strip()
    ).resolve(strict=True)
    if reported_base != base.resolve(strict=True):
        # Official framework CPython builds on macOS have fixed shared-library
        # paths and cannot be relocated by copying.  A false positive baseline
        # would make the negative tests vacuously pass, so skip every dependent
        # isolated-runtime test while keeping the fail-closed link test above.
        pytest.skip("host CPython base runtime is non-relocatable")
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
    scanner = environment / ("Scripts/python.exe" if __import__("sys").platform == "win32" else "bin/python")
    purelib = Path(
        subprocess.check_output(
            [str(scanner), "-I", "-B", "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
            text=True,
        ).strip()
    )
    # Some framework builds create executable or library aliases lazily on
    # first launch even when venv was asked for copies.  The probe attests both
    # the venv and its copied base runtime.  Keep the production rejection
    # strict and normalize only those two test fixtures before binding them.
    base_runtime = (
        isolated_base_python.parent
        if sys.platform == "win32"
        else isolated_base_python.parents[1]
    )
    _materialize_runtime_symlinks(base_runtime)
    _materialize_runtime_symlinks(environment)
    scaffold = build_scanner_scaffold_manifest(environment)
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
