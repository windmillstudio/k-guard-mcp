from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

import pytest

from scripts.evidence_tree import package_tree_sha256, package_tree_sha256_at_revision, wheel_package_contract


def test_package_tree_hash_binds_paths_and_content_but_ignores_bytecode(tmp_path: Path) -> None:
    package = tmp_path / "package"
    package.mkdir()
    (package / "a.py").write_text("value = 1\n", encoding="utf-8")
    first = package_tree_sha256(package)

    cache = package / "__pycache__"
    cache.mkdir()
    (cache / "a.cpython-311.pyc").write_bytes(b"generated")
    assert package_tree_sha256(package) == first

    (package / "a.py").write_text("value = 2\n", encoding="utf-8")
    assert package_tree_sha256(package) != first

    (package / "a.py").write_text("value = 1\n", encoding="utf-8")
    (package / "b.py").write_text("value = 1\n", encoding="utf-8")
    assert package_tree_sha256(package) != first


def test_package_tree_hash_canonicalizes_text_line_endings_only(tmp_path: Path) -> None:
    package = tmp_path / "package"
    package.mkdir()
    text = package / "contract.json"
    binary = package / "asset.png"
    text.write_bytes(b'{\r\n  "ok": true\r\n}\r\n')
    binary.write_bytes(b"PNG\r\nbytes")
    crlf_hash = package_tree_sha256(package)

    text.write_bytes(b'{\n  "ok": true\n}\n')
    lf_hash = package_tree_sha256(package)

    assert crlf_hash == lf_hash
    binary.write_bytes(b"PNG\nbytes")
    assert package_tree_sha256(package) != lf_hash


def test_package_tree_hash_at_revision_reads_committed_blobs(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "K-Guard Test"], cwd=tmp_path, check=True)
    package = tmp_path / "src" / "k_guard_mcp"
    package.mkdir(parents=True)
    source = package / "contract.json"
    source.write_bytes(b'{\n  "value": 1\n}\n')
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=tmp_path, check=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True).strip()

    committed = package_tree_sha256_at_revision(tmp_path, revision)
    assert committed == package_tree_sha256(package)

    source.write_bytes(b'{\n  "value": 2\n}\n')
    assert package_tree_sha256(package) != committed
    with pytest.raises(ValueError, match="revision"):
        package_tree_sha256_at_revision(tmp_path, "not-a-revision")


def test_wheel_package_contract_binds_archive_package_bytes_and_identity(tmp_path: Path) -> None:
    package = tmp_path / "k_guard_mcp"
    package.mkdir()
    (package / "__init__.py").write_text("VERSION = '1.2.3'\n", encoding="utf-8")
    (package / "asset.json").write_text('{\r\n  "ok": true\r\n}\r\n', encoding="utf-8")
    wheel = tmp_path / "k_guard_mcp-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.write(package / "__init__.py", "k_guard_mcp/__init__.py")
        archive.write(package / "asset.json", "k_guard_mcp/asset.json")
        archive.writestr(
            "k_guard_mcp-1.2.3.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: k-guard-mcp\nVersion: 1.2.3\n",
        )

    contract = wheel_package_contract(wheel)

    assert contract == {
        "package_tree_sha256": package_tree_sha256(package),
        "distribution": "k-guard-mcp",
        "version": "1.2.3",
        "package_file_count": 2,
    }


def test_wheel_package_contract_rejects_non_wheel_and_unsafe_members(tmp_path: Path) -> None:
    fake = tmp_path / "k_guard_mcp-1.0.0-py3-none-any.whl"
    fake.write_bytes(b"not a wheel")
    with pytest.raises((ValueError, zipfile.BadZipFile)):
        wheel_package_contract(fake)

    unsafe = tmp_path / "k_guard_mcp-1.0.1-py3-none-any.whl"
    with zipfile.ZipFile(unsafe, "w") as archive:
        archive.writestr("../k_guard_mcp/__init__.py", "")
        archive.writestr(
            "k_guard_mcp-1.0.1.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: k-guard-mcp\nVersion: 1.0.1\n",
        )
    with pytest.raises(ValueError, match="unsafe"):
        wheel_package_contract(unsafe)
