from __future__ import annotations

import importlib.metadata
import json
from pathlib import Path

from k_guard_mcp.dependency_evidence import (
    declared_dependency_scope,
    dependency_lock_mismatches,
    evidence_lock_report,
    installed_dependency_closure,
    normalize_name,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    dependency_scope = declared_dependency_scope(PROJECT_ROOT)
    allowed_names, unresolved_dependencies = installed_dependency_closure(
        dependency_scope["all_requirements"]
    )
    lock_report = evidence_lock_report(PROJECT_ROOT)
    packages = []
    seen: set[tuple[str, str]] = set()
    for dist in sorted(importlib.metadata.distributions(), key=lambda item: item.metadata["Name"].lower()):
        name = dist.metadata["Name"]
        if name.lower() in {"pip", "setuptools", "wheel"}:
            continue
        if normalize_name(name) not in allowed_names:
            continue
        key = (name.lower(), dist.version)
        if key in seen:
            continue
        seen.add(key)
        packages.append(
            {
                "type": "library",
                "name": name,
                "version": dist.version,
                "purl": f"pkg:pypi/{name.lower()}@{dist.version}",
            }
        )
    component_versions = {
        normalize_name(str(component["name"])): str(component["version"])
        for component in packages
    }
    lock_mismatches = dependency_lock_mismatches(
        allowed_names,
        component_versions,
        lock_report,
    )
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "k-guard-mcp",
                "version": "0.1.0",
            },
            "properties": [
                {
                    "name": "k-guard-mcp:sbom-scope",
                    "value": "declared project dependency closure for runtime, dev, and mcp extras",
                },
                {
                    "name": "k-guard-mcp:runtime-dependencies",
                    "value": ", ".join(dependency_scope["runtime"]),
                },
                {
                    "name": "k-guard-mcp:evidence-lock-sha256",
                    "value": str(lock_report["sha256"]),
                },
            ],
        },
        "components": packages,
        "properties": [
            {
                "name": "k-guard-mcp:evidence-lock-valid",
                "value": str(bool(lock_report["valid"])).lower(),
            },
            {
                "name": "k-guard-mcp:lock-mismatch-count",
                "value": str(len(lock_mismatches)),
            },
            {
                "name": "k-guard-mcp:unresolved-dependency-count",
                "value": str(len(unresolved_dependencies)),
            },
        ],
    }
    Path("sbom.cdx.json").write_text(json.dumps(sbom, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if bool(lock_report["valid"]) and not lock_mismatches and not unresolved_dependencies else 1


if __name__ == "__main__":
    raise SystemExit(main())
