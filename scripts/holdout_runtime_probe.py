from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import site
import sys
import sysconfig
from pathlib import Path
from typing import Any, Iterable


RUNTIME_ENVIRONMENT_SCHEMA = "k_guard_holdout_runtime_environment.v2"
INSTALLED_TREE_SCHEMA = "k_guard_installed_distribution_tree_sha256.v1"
PACKAGE_TREE_SCHEMA = "k_guard_package_tree_sha256.v2"
SCANNER_SCAFFOLD_SCHEMA = "k_guard_scanner_venv_scaffold.v1"
TEXT_SUFFIXES = {
    ".cs",
    ".go",
    ".java",
    ".js",
    ".json",
    ".kt",
    ".md",
    ".php",
    ".py",
    ".rb",
    ".toml",
    ".ts",
    ".txt",
    ".yaml",
    ".yml",
}


def configure_no_site_runtime() -> Path:
    if sys.platform != "win32" or sys.flags.no_site != 1:
        raise RuntimeError("holdout runtime must start on Windows with Python -S")
    executable = Path(sys.executable).resolve(strict=True)
    prefix = executable.parents[1]
    purelib = (prefix / "Lib" / "site-packages").resolve(strict=True)
    base_prefix = Path(sys.base_prefix).resolve(strict=True)
    retained: list[str] = []
    for value in sys.path:
        resolved = Path(value or os.curdir).resolve()
        if resolved == purelib:
            continue
        if resolved.is_relative_to(prefix):
            continue
        if resolved.is_relative_to(base_prefix) and any(
            part.casefold() in {"site-packages", "dist-packages"}
            for part in resolved.relative_to(base_prefix).parts
        ):
            continue
        retained.append(value)
    sys.prefix = str(prefix)
    sys.exec_prefix = str(prefix)
    sys.path[:] = [*retained, str(purelib)]
    site.ENABLE_USER_SITE = False
    return prefix


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def _normalized_path(path: Path, prefix: Path, base_prefix: Path) -> str:
    resolved = path.resolve()
    if resolved.is_relative_to(prefix):
        return "<prefix>/" + resolved.relative_to(prefix).as_posix()
    if resolved.is_relative_to(base_prefix):
        return "<base_prefix>/" + resolved.relative_to(base_prefix).as_posix()
    return "<outside>/" + hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()[:20]


def _is_base_site_package(path: Path, base_prefix: Path) -> bool:
    resolved = path.resolve()
    if not resolved.is_relative_to(base_prefix):
        return False
    return any(
        part.casefold() in {"site-packages", "dist-packages"}
        for part in resolved.relative_to(base_prefix).parts
    )


def _base_site_package_roots(base_prefix: Path) -> tuple[Path, ...]:
    candidates = [
        base_prefix / "Lib" / "site-packages",
        *base_prefix.glob("lib/python*/site-packages"),
        *base_prefix.glob("lib/python*/dist-packages"),
    ]
    return tuple(sorted({path.resolve() for path in candidates if path.is_dir()}, key=str))


def _include_system_site_packages(prefix: Path) -> bool | None:
    config = prefix / "pyvenv.cfg"
    if not config.is_file() or config.is_symlink():
        return None
    values = {}
    try:
        for line in config.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key.strip().casefold()] = value.strip().casefold()
    except (OSError, UnicodeError):
        return None
    raw = values.get("include-system-site-packages")
    if raw == "true":
        return True
    if raw == "false":
        return False
    return None


def _installed_tree_sha256(entries: Iterable[tuple[str, int, str]]) -> str:
    digest = hashlib.sha256()
    digest.update((INSTALLED_TREE_SCHEMA + "\0").encode("ascii"))
    for relative, size, file_hash in sorted(entries):
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(file_hash))
    return digest.hexdigest()


def _filesystem_tree_attestation(
    root: Path,
    *,
    excluded_prefixes: tuple[Path, ...] = (),
) -> tuple[dict[str, Any], set[str], list[str]]:
    entries: list[tuple[str, int, str]] = []
    files: set[str] = set()
    errors: list[str] = []
    seen_casefold: dict[str, str] = {}
    resolved_root = root.resolve(strict=True)
    exclusions = tuple(path.resolve() for path in excluded_prefixes if path.exists())
    pending = [resolved_root]
    while pending:
        directory = pending.pop()
        try:
            directory_entries = sorted(os.scandir(directory), key=lambda value: value.name.casefold())
        except OSError:
            errors.append("runtime_tree_directory_unreadable")
            continue
        for entry in directory_entries:
            path = Path(entry.path)
            relative = path.relative_to(resolved_root).as_posix()
            try:
                metadata = path.stat(follow_symlinks=False)
            except OSError:
                errors.append(f"runtime_tree_entry_unresolvable:{relative}")
                continue
            if entry.is_symlink() or getattr(metadata, "st_file_attributes", 0) & 0x400:
                errors.append(f"runtime_tree_reparse_point:{relative}")
                continue
            folded = relative.casefold()
            previous = seen_casefold.setdefault(folded, relative)
            if previous != relative:
                errors.append("runtime_tree_case_collision")
                continue
            try:
                resolved = path.resolve(strict=True)
            except OSError:
                errors.append(f"runtime_tree_entry_unresolvable:{relative}")
                continue
            if not resolved.is_relative_to(resolved_root):
                errors.append(f"runtime_tree_entry_outside_root:{relative}")
                continue
            if any(resolved == prefix or resolved.is_relative_to(prefix) for prefix in exclusions):
                continue
            if entry.is_dir(follow_symlinks=False):
                pending.append(resolved)
                continue
            if not entry.is_file(follow_symlinks=False):
                errors.append(f"runtime_tree_nonregular_entry:{relative}")
                continue
            if metadata.st_nlink != 1:
                errors.append(f"runtime_tree_hardlink:{relative}")
            file_hash, size = _sha256_file(resolved)
            entries.append((relative, size, file_hash))
            files.add(relative)
    file_rows = [
        {"path": relative, "byte_count": size, "sha256": file_hash}
        for relative, size, file_hash in sorted(entries)
    ]
    return (
        {
            "schema": INSTALLED_TREE_SCHEMA,
            "sha256": _installed_tree_sha256(entries),
            "file_count": len(entries),
            "byte_count": sum(size for _path, size, _hash in entries),
            "files": file_rows,
        },
        files,
        errors,
    )


def _package_tree_sha256(package_root: Path) -> tuple[str, int]:
    entries: list[tuple[str, bytes]] = []
    for path in package_root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(package_root)
        if "__pycache__" in relative.parts or relative.suffix.casefold() in {".pyc", ".pyo"}:
            continue
        payload = path.read_bytes()
        if path.suffix.casefold() in TEXT_SUFFIXES:
            payload = payload.replace(b"\r\n", b"\n")
        entries.append((relative.as_posix(), payload))
    if not entries:
        raise ValueError("installed K-Guard package contains no files")
    digest = hashlib.sha256()
    digest.update((PACKAGE_TREE_SCHEMA + "\0").encode("ascii"))
    for relative, payload in sorted(entries):
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest(), len(entries)


def _scanner_scaffold_rows(payload: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    errors: list[str] = []
    rows = payload.get("files") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != SCANNER_SCAFFOLD_SCHEMA
        or payload.get("raw_returned") is not False
        or not isinstance(rows, list)
        or payload.get("file_count") != len(rows or [])
    ):
        return {}, ["scanner_scaffold_manifest_invalid"]
    normalized: dict[str, dict[str, Any]] = {}
    casefold_paths: set[str] = set()
    for row in rows:
        path = str(row.get("path") or "") if isinstance(row, dict) else ""
        digest = str(row.get("sha256") or "") if isinstance(row, dict) else ""
        byte_count = row.get("byte_count") if isinstance(row, dict) else None
        relative = Path(path)
        if (
            not isinstance(row, dict)
            or not path
            or "\\" in path
            or relative.is_absolute()
            or ".." in relative.parts
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(byte_count, int)
            or byte_count < 0
            or path in normalized
            or path.casefold() in casefold_paths
        ):
            errors.append("scanner_scaffold_file_invalid")
            continue
        normalized[path] = {"path": path, "sha256": digest, "byte_count": byte_count}
        casefold_paths.add(path.casefold())
    canonical_rows = sorted(normalized.values(), key=lambda row: row["path"])
    expected_hash = hashlib.sha256(
        (SCANNER_SCAFFOLD_SCHEMA + "\0").encode("ascii")
        + json.dumps(canonical_rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if rows != canonical_rows or payload.get("tree_sha256") != expected_hash:
        errors.append("scanner_scaffold_manifest_hash_invalid")
    return normalized, errors


def _platform_attestation() -> dict[str, str]:
    if sys.platform == "win32":
        version = sys.getwindowsversion()
        platform_version = tuple(int(value) for value in version.platform_version)
        return {
            "system": "Windows",
            "release": ".".join(str(value) for value in platform_version[:2]),
            "version": ".".join(str(value) for value in platform_version),
            "machine": sysconfig.get_platform(),
        }
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": sysconfig.get_platform(),
    }


def _record_hash_matches(mode: str, value: str, actual_sha256: str) -> bool:
    if mode != "sha256":
        return False
    expected = base64.urlsafe_b64encode(bytes.fromhex(actual_sha256)).decode("ascii").rstrip("=")
    return value == expected


def _distribution_attestation(
    distribution: importlib.metadata.Distribution,
    prefix: Path,
) -> tuple[dict[str, Any], list[str], list[str]]:
    errors: list[str] = []
    owned_paths: list[str] = []
    name = _canonical_name(str(distribution.metadata.get("Name") or ""))
    version = distribution.version
    files = list(distribution.files or [])
    if not name or not version or not files:
        return ({"name": name, "version": version}, [f"distribution_inventory_incomplete:{name}"], [])

    tree_entries: list[tuple[str, int, str]] = []
    installed_files: list[dict[str, Any]] = []
    metadata_hashes: list[str] = []
    record_hashes: list[str] = []
    direct_url_hashes: list[str] = []
    record_verified = 0
    record_unhashed: list[str] = []
    for package_path in files:
        raw_relative = str(package_path).replace("\\", "/")
        unresolved = Path(distribution.locate_file(package_path))
        try:
            resolved = unresolved.resolve(strict=True)
        except OSError:
            errors.append(f"distribution_file_missing:{name}:{raw_relative}")
            continue
        if unresolved.is_symlink() or not resolved.is_file() or not resolved.is_relative_to(prefix):
            errors.append(f"distribution_file_outside_prefix_or_nonregular:{name}:{raw_relative}")
            continue
        relative = resolved.relative_to(prefix).as_posix()
        actual_hash, actual_size = _sha256_file(resolved)
        tree_entries.append((relative, actual_size, actual_hash))
        installed_files.append(
            {"path": relative, "sha256": actual_hash, "byte_count": actual_size}
        )
        owned_paths.append(relative)
        recorded_size = package_path.size
        recorded_hash = package_path.hash
        if recorded_size is not None and int(recorded_size) != actual_size:
            errors.append(f"record_size_mismatch:{name}:{raw_relative}")
        if recorded_hash is None:
            record_unhashed.append(relative)
        elif not _record_hash_matches(recorded_hash.mode, recorded_hash.value, actual_hash):
            errors.append(f"record_hash_mismatch:{name}:{raw_relative}")
        else:
            record_verified += 1
        lower = raw_relative.casefold()
        if lower.endswith(".dist-info/metadata"):
            metadata_hashes.append(actual_hash)
        if lower.endswith(".dist-info/record"):
            record_hashes.append(actual_hash)
        if lower.endswith(".dist-info/direct_url.json"):
            direct_url_hashes.append(actual_hash)

    allowed_unhashed = {
        path
        for path in record_unhashed
        if path.casefold().endswith((".dist-info/record", ".pyc", ".pyo"))
    }
    unexpected_unhashed = sorted(set(record_unhashed) - allowed_unhashed)
    if unexpected_unhashed:
        errors.extend(f"record_hash_missing:{name}:{path}" for path in unexpected_unhashed)
    if len(metadata_hashes) != 1 or len(record_hashes) != 1:
        errors.append(f"distribution_dist_info_incomplete:{name}")
    return (
        {
            "name": name,
            "version": version,
            "metadata_sha256": metadata_hashes[0] if len(metadata_hashes) == 1 else None,
            "record_sha256": record_hashes[0] if len(record_hashes) == 1 else None,
            "direct_url_sha256": direct_url_hashes[0] if len(direct_url_hashes) == 1 else None,
            "installed_tree_schema": INSTALLED_TREE_SCHEMA,
            "installed_tree_sha256": _installed_tree_sha256(tree_entries) if tree_entries else None,
            "installed_file_count": len(tree_entries),
            "installed_byte_count": sum(size for _path, size, _hash in tree_entries),
            "installed_files": sorted(installed_files, key=lambda row: row["path"]),
            "record_verified_file_count": record_verified,
            "record_unhashed_allowed": sorted(allowed_unhashed),
            "active_requires_dist": sorted(distribution.requires or []),
        },
        errors,
        owned_paths,
    )


def capture(scanner_scaffold: dict[str, Any]) -> dict[str, Any]:
    prefix = Path(sys.prefix).resolve(strict=True)
    base_prefix = Path(sys.base_prefix).resolve(strict=True)
    executable = Path(sys.executable)
    executable_hash, executable_size = _sha256_file(executable)
    errors: list[str] = []
    scaffold_rows, scaffold_errors = _scanner_scaffold_rows(scanner_scaffold)
    errors.extend(scaffold_errors)
    if sys.prefix == sys.base_prefix:
        errors.append("scanner_python_is_not_a_virtual_environment")
    if (
        sys.flags.isolated != 1
        or sys.flags.ignore_environment != 1
        or sys.flags.no_user_site != 1
        or sys.flags.dont_write_bytecode != 1
        or sys.flags.safe_path != 1
        or sys.flags.no_site != 1
    ):
        errors.append("scanner_python_is_not_isolated")
    if site.ENABLE_USER_SITE is not False:
        errors.append("scanner_user_site_is_enabled")
    include_system_site_packages = _include_system_site_packages(prefix)
    if include_system_site_packages is not False:
        errors.append("scanner_system_site_packages_not_disabled")

    prefix_tree, prefix_files, prefix_tree_errors = _filesystem_tree_attestation(prefix)
    errors.extend(prefix_tree_errors)
    base_site_packages = _base_site_package_roots(base_prefix)
    base_runtime_tree, _base_files, base_tree_errors = _filesystem_tree_attestation(
        base_prefix,
        excluded_prefixes=base_site_packages,
    )
    errors.extend(base_tree_errors)

    distributions: list[dict[str, Any]] = []
    names: list[str] = []
    owners: dict[str, list[str]] = {}
    for distribution in importlib.metadata.distributions():
        row, row_errors, paths = _distribution_attestation(distribution, prefix)
        name = str(row.get("name") or "")
        names.append(name)
        distributions.append(row)
        errors.extend(row_errors)
        for path in paths:
            owners.setdefault(path, []).append(name)
    duplicate_names = sorted(name for name in set(names) if names.count(name) > 1 or not name)
    shared_files = sorted(path for path, values in owners.items() if len(set(values)) > 1)
    if duplicate_names:
        errors.append("duplicate_distribution_names")
    if shared_files:
        errors.append("distribution_file_ownership_overlap")
    site_roots = {(prefix / "Lib" / "site-packages").resolve(strict=True)}
    site_files = {
        path.relative_to(prefix).as_posix()
        for root in site_roots
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    unowned_site_files = sorted(site_files - set(owners))
    if unowned_site_files:
        errors.append("unowned_site_package_files")
    owner_paths = set(owners)
    scaffold_paths = set(scaffold_rows)
    prefix_rows = {
        row["path"]: row
        for row in prefix_tree.get("files", [])
        if isinstance(row, dict) and isinstance(row.get("path"), str)
    }
    scaffold_distribution_overlaps = sorted(scaffold_paths & owner_paths)
    expected_prefix_paths = scaffold_paths | owner_paths
    unowned_prefix_files = sorted(set(prefix_files) - expected_prefix_paths)
    missing_prefix_files = sorted(expected_prefix_paths - set(prefix_files))
    modified_scaffold_files = sorted(
        path
        for path, expected in scaffold_rows.items()
        if path in prefix_rows
        and (
            prefix_rows[path].get("sha256") != expected["sha256"]
            or prefix_rows[path].get("byte_count") != expected["byte_count"]
        )
    )
    if scaffold_distribution_overlaps:
        errors.append("scanner_scaffold_overwritten_by_distribution")
    if unowned_prefix_files:
        errors.append("unowned_scanner_prefix_files")
    if missing_prefix_files:
        errors.append("scanner_prefix_expected_files_missing")
    if modified_scaffold_files:
        errors.append("scanner_scaffold_files_modified")
    distributions.sort(key=lambda row: (str(row.get("name") or ""), str(row.get("version") or "")))

    resolved_search_path = [Path(value or os.curdir).resolve() for value in sys.path]
    normalized_search_path = [
        _normalized_path(path, prefix, base_prefix) for path in resolved_search_path
    ]
    outside_search_paths = sorted(
        value for value in normalized_search_path if value.startswith("<outside>/")
    )
    base_site_search_paths = sorted(
        normalized
        for path, normalized in zip(resolved_search_path, normalized_search_path)
        if _is_base_site_package(path, base_prefix)
    )
    if outside_search_paths:
        errors.append("import_search_path_outside_attested_runtime")
    if base_site_search_paths:
        errors.append("base_site_packages_on_import_search_path")

    package_spec = importlib.util.find_spec("k_guard_mcp")
    package_locations = list(package_spec.submodule_search_locations or []) if package_spec is not None else []
    if len(package_locations) != 1:
        errors.append("k_guard_package_import_location_invalid")
        package_root = None
        package_tree = None
        package_file_count = 0
    else:
        package_root = Path(package_locations[0]).resolve(strict=True)
        if not package_root.is_relative_to(prefix):
            errors.append("k_guard_package_import_outside_scanner_prefix")
        try:
            package_tree, package_file_count = _package_tree_sha256(package_root)
        except (OSError, ValueError):
            package_tree = None
            package_file_count = 0
            errors.append("k_guard_package_tree_unavailable")
    try:
        project_distribution = importlib.metadata.distribution("k-guard-mcp")
        project_version = project_distribution.version
    except importlib.metadata.PackageNotFoundError:
        project_version = None
        errors.append("k_guard_distribution_missing")

    customization_modules = []
    for module_name in ("sitecustomize", "usercustomize"):
        try:
            specification = importlib.util.find_spec(module_name)
        except (ImportError, ValueError):
            specification = None
        if specification is not None:
            customization_modules.append(module_name)
    if customization_modules:
        errors.append("python_customization_module_present")

    distribution_set_payload = [
        {
            "name": row.get("name"),
            "version": row.get("version"),
            "metadata_sha256": row.get("metadata_sha256"),
            "record_sha256": row.get("record_sha256"),
            "installed_tree_sha256": row.get("installed_tree_sha256"),
        }
        for row in distributions
    ]
    distribution_set_sha256 = hashlib.sha256(
        json.dumps(distribution_set_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema": RUNTIME_ENVIRONMENT_SCHEMA,
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "cache_tag": str(sys.implementation.cache_tag or ""),
            "abi_flags": str(getattr(sys, "abiflags", "")),
            "byteorder": sys.byteorder,
            "executable": _normalized_path(executable, prefix, base_prefix),
            "executable_sha256": executable_hash,
            "executable_byte_count": executable_size,
            "prefix_is_virtual_environment": sys.prefix != sys.base_prefix,
            "isolated_flag": sys.flags.isolated,
            "ignore_environment_flag": sys.flags.ignore_environment,
            "no_user_site_flag": sys.flags.no_user_site,
            "dont_write_bytecode_flag": sys.flags.dont_write_bytecode,
            "safe_path_flag": sys.flags.safe_path,
            "no_site_flag": sys.flags.no_site,
            "user_site_enabled": site.ENABLE_USER_SITE,
            "include_system_site_packages": include_system_site_packages,
            "manual_site_bootstrap": True,
        },
        "platform": _platform_attestation(),
        "install_scheme": {
            "purelib": _normalized_path(prefix / "Lib" / "site-packages", prefix, base_prefix),
            "platlib": _normalized_path(prefix / "Lib" / "site-packages", prefix, base_prefix),
            "scripts": _normalized_path(prefix / "Scripts", prefix, base_prefix),
            "data": _normalized_path(prefix, prefix, base_prefix),
            "include": _normalized_path(prefix / "Include", prefix, base_prefix),
        },
        "import_search_path": normalized_search_path,
        "outside_import_search_paths": outside_search_paths,
        "base_site_package_import_paths": base_site_search_paths,
        "python_customization_modules": customization_modules,
        "k_guard": {
            "distribution": "k-guard-mcp",
            "version": project_version,
            "import_root": (
                _normalized_path(package_root, prefix, base_prefix)
                if package_root is not None
                else None
            ),
            "package_tree_schema": PACKAGE_TREE_SCHEMA,
            "package_tree_sha256": package_tree,
            "package_file_count": package_file_count,
        },
        "installed_distribution_count": len(distributions),
        "installed_distribution_set_sha256": distribution_set_sha256,
        "installed_distributions": distributions,
        "duplicate_distribution_names": duplicate_names,
        "shared_distribution_files": shared_files,
        "unowned_site_package_files": unowned_site_files,
        "scanner_scaffold": scanner_scaffold,
        "scaffold_distribution_overlaps": scaffold_distribution_overlaps,
        "unowned_prefix_files": unowned_prefix_files,
        "missing_prefix_files": missing_prefix_files,
        "modified_scaffold_files": modified_scaffold_files,
        "prefix_tree": prefix_tree,
        "base_runtime_tree": base_runtime_tree,
        "attestation_errors": sorted(set(errors)),
        "attestation_passed": not errors,
        "raw_returned": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scaffold-manifest", type=Path, required=True)
    args = parser.parse_args()
    configure_no_site_runtime()
    scaffold_raw = args.scaffold_manifest.resolve(strict=True).read_bytes()
    scaffold = json.loads(scaffold_raw.decode("utf-8"))
    if not isinstance(scaffold, dict) or _canonical_bytes(scaffold) != scaffold_raw:
        raise ValueError("scanner scaffold manifest must be canonical JSON")
    payload = capture(scaffold)
    sys.stdout.buffer.write(_canonical_bytes(payload))
    return 0 if payload["attestation_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
