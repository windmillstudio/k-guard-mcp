from __future__ import annotations

import importlib.metadata
import hashlib
import json
import re
from pathlib import Path

try:
    from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression
except ImportError:  # The dev extra declares packaging; absence must fail closed.
    InvalidLicenseExpression = ValueError  # type: ignore[assignment,misc]
    canonicalize_license_expression = None  # type: ignore[assignment]

from k_guard_mcp.dependency_evidence import (
    declared_dependency_scope,
    dependency_lock_mismatches,
    evidence_lock_report,
    installed_dependency_closure,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
UNKNOWN_LICENSE_VALUES = {"", "UNKNOWN", "UNLICENSED", "N/A", "NONE", "NOASSERTION"}
STRONG_COPYLEFT_PREFIXES = ("AGPL-", "GPL-", "SSPL-", "OSL-", "EUPL-", "RPL-", "RPSL-")
STRONG_COPYLEFT_IDS = {"QPL-1.0", "Sleepycat", "Watcom-1.0"}

LEGACY_LICENSE_ALIASES = {
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "isc license": "ISC",
    "mit license": "MIT",
    "mozilla public license 2.0": "MPL-2.0",
    "python software foundation license": "PSF-2.0",
    "the unlicense (unlicense)": "Unlicense",
}

LICENSE_CLASSIFIER_EXPRESSIONS = {
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: Artistic License": "Artistic-2.0",
    "License :: OSI Approved :: BSD License": "LicenseRef-PyPI-BSD-Classifier",
    "License :: OSI Approved :: Common Development and Distribution License 1.0 (CDDL-1.0)": "CDDL-1.0",
    "License :: OSI Approved :: Eclipse Public License 1.0 (EPL-1.0)": "EPL-1.0",
    "License :: OSI Approved :: Eclipse Public License 2.0 (EPL-2.0)": "EPL-2.0",
    "License :: OSI Approved :: European Union Public Licence 1.0 (EUPL 1.0)": "EUPL-1.0",
    "License :: OSI Approved :: European Union Public Licence 1.1 (EUPL 1.1)": "EUPL-1.1",
    "License :: OSI Approved :: European Union Public Licence 1.2 (EUPL 1.2)": "EUPL-1.2",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0-only",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
    "License :: OSI Approved :: GNU General Public License (GPL)": "LicenseRef-PyPI-GPL-Classifier",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Mozilla Public License 1.0 (MPL)": "MPL-1.0",
    "License :: OSI Approved :: Mozilla Public License 1.1 (MPL 1.1)": "MPL-1.1",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: Other/Proprietary License": "LicenseRef-Proprietary",
    "License :: Free For Educational Use": "LicenseRef-Free-For-Educational-Use",
    "License :: Free For Home Use": "LicenseRef-Free-For-Home-Use",
    "License :: Free for non-commercial use": "LicenseRef-Free-For-Noncommercial-Use",
    "License :: Public Domain": "LicenseRef-Public-Domain",
}


def main() -> int:
    dependency_scope = declared_dependency_scope(PROJECT_ROOT)
    allowed_names, unresolved_dependencies = installed_dependency_closure(dependency_scope["all_requirements"])
    lock_report = evidence_lock_report(PROJECT_ROOT)
    components: list[dict[str, object]] = []
    unknown_matches: list[dict[str, object]] = []
    review_required: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()

    distributions = sorted(importlib.metadata.distributions(), key=lambda item: _distribution_name(item).lower())
    for dist in distributions:
        name = _distribution_name(dist)
        normalized_name = _normalize_name(name)
        if not name or normalized_name in {"pip", "setuptools", "wheel"}:
            continue
        if normalized_name not in allowed_names:
            continue
        key = (normalized_name, dist.version)
        if key in seen:
            continue
        seen.add(key)

        assessment = _license_assessment(dist)
        component: dict[str, object] = {"name": name, "version": dist.version, **assessment}
        components.append(component)
        if assessment["unknown"]:
            unknown_matches.append(component)
        if assessment["review_required"]:
            review_required.append(component)

    component_versions = {
        _normalize_name(str(component["name"])): str(component["version"])
        for component in components
    }
    lock_mismatches = dependency_lock_mismatches(
        allowed_names,
        component_versions,
        lock_report,
    )

    report = {
        "scope": "declared_project_dependency_closure",
        "dependency_scope": dependency_scope,
        "component_count": len(components),
        "unknown_license_count": len(unknown_matches),
        "review_required_count": len(review_required),
        "unresolved_dependency_count": len(unresolved_dependencies),
        "unresolved_dependencies": sorted(unresolved_dependencies),
        "evidence_lock": lock_report,
        "lock_mismatch_count": len(lock_mismatches),
        "lock_mismatches": lock_mismatches,
        "review_policy": {
            "metadata_precedence": ["License-Expression", "License", "installed license file", "Classifier"],
            "unknown_or_unresolved": "fail",
            "strong_copyleft": "manual_review",
            "nonstandard_license_reference": "manual_review",
            "strong_copyleft_prefixes": STRONG_COPYLEFT_PREFIXES,
            "strong_copyleft_ids": sorted(STRONG_COPYLEFT_IDS),
        },
        "unknown_matches": unknown_matches,
        "review_required_matches": review_required,
        # Retained for consumers of the previous report schema.
        "restricted_license_hints": (*STRONG_COPYLEFT_PREFIXES, *sorted(STRONG_COPYLEFT_IDS)),
        "restricted_matches": review_required,
        "passed": (
            not unknown_matches
            and not review_required
            and not unresolved_dependencies
            and bool(lock_report["valid"])
            and not lock_mismatches
        ),
        "components": components,
    }
    Path("license-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    summary_keys = (
        "component_count",
        "unknown_license_count",
        "review_required_count",
        "unresolved_dependency_count",
        "lock_mismatch_count",
        "passed",
    )
    print(json.dumps({key: report[key] for key in summary_keys}, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


def _license_assessment(dist: importlib.metadata.Distribution) -> dict[str, object]:
    metadata = dist.metadata
    expression = _clean_metadata_value(metadata.get("License-Expression"))
    if expression:
        return _assess_expression(expression, "License-Expression")

    legacy = _clean_metadata_value(metadata.get("License"))
    if legacy and legacy.upper() not in UNKNOWN_LICENSE_VALUES:
        direct = _assess_expression(_legacy_expression(legacy), "License")
        if not direct["unknown"]:
            return direct

    classifiers = [
        classifier.strip()
        for classifier in metadata.get_all("Classifier") or []
        if classifier.strip().startswith("License ::")
    ]
    if classifiers:
        mapped = [LICENSE_CLASSIFIER_EXPRESSIONS.get(classifier) for classifier in classifiers]
        if all(mapped):
            if "LicenseRef-PyPI-BSD-Classifier" in mapped:
                file_evidence = _installed_license_file_expression(dist)
                if file_evidence is not None:
                    expression, relative_path, content_sha256 = file_evidence
                    assessment = _assess_expression(expression, "installed-license-file")
                    assessment["license_file"] = relative_path
                    assessment["license_file_sha256"] = content_sha256
                    assessment["metadata_notes"] = ["ambiguous_bsd_classifier_resolved_from_installed_license_text"]
                    return assessment
            classifier_assessment = _assess_expression(" OR ".join(sorted(set(mapped))), "Classifier")
            if legacy:
                classifier_assessment["metadata_notes"] = ["legacy_license_fallback_to_classifier"]
            return classifier_assessment
        return _unresolved_assessment("; ".join(classifiers), "Classifier", "non_spdx_license_classifier")

    if legacy:
        reason = "unknown_license" if legacy.upper() in UNKNOWN_LICENSE_VALUES else "non_spdx_license_metadata"
        return _unresolved_assessment(legacy, "License", reason)
    return _unresolved_assessment("UNKNOWN", "none", "unknown_license", review_required=False)


def _installed_license_file_expression(
    dist: importlib.metadata.Distribution,
) -> tuple[str, str, str] | None:
    for entry in dist.files or []:
        relative_path = str(entry).replace("\\", "/")
        name = Path(relative_path).name.lower()
        if not name.startswith(("license", "copying")):
            continue
        path = Path(dist.locate_file(entry))
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if not raw or len(raw) > 256 * 1024:
            continue
        text = " ".join(raw.decode("utf-8", errors="replace").lower().split())
        expression = _classify_bsd_license_text(text)
        if expression:
            return expression, relative_path, hashlib.sha256(raw).hexdigest()
    return None


def _classify_bsd_license_text(text: str) -> str | None:
    normalized = " ".join(text.lower().split())
    restriction_markers = (
        "commercial use is prohibited",
        "non-commercial use only",
        "noncommercial use only",
        "not for commercial use",
        "for educational use only",
        "may not be sold",
    )
    if any(marker in normalized for marker in restriction_markers):
        return None
    required_clauses = (
        "redistribution and use in source and binary forms, with or without modification, are permitted",
        "redistributions of source code must retain the above copyright notice",
        "redistributions in binary form must reproduce the above copyright notice",
        "this software is provided",
        '"as is"',
        "in no event shall",
        "be liable",
    )
    if not all(clause in normalized for clause in required_clauses):
        return None
    has_third_clause = (
        "neither the name" in normalized
        and "may be used to endorse or promote products derived from this software" in normalized
    )
    return "BSD-3-Clause" if has_third_clause else "BSD-2-Clause"


def _assess_expression(value: str, source: str) -> dict[str, object]:
    declared = _clean_metadata_value(value)
    if declared.upper() in UNKNOWN_LICENSE_VALUES:
        return _unresolved_assessment(declared or "UNKNOWN", source, "unknown_license", review_required=False)
    if canonicalize_license_expression is None:
        return _unresolved_assessment(declared, source, "license_policy_parser_unavailable")
    try:
        canonical = canonicalize_license_expression(declared)
    except InvalidLicenseExpression:
        return _unresolved_assessment(declared, source, "non_spdx_license_metadata")

    identifiers = _license_identifiers(canonical)
    nonstandard = sorted(identifier for identifier in identifiers if "LicenseRef-" in identifier or identifier.startswith("DocumentRef-"))
    strong_copyleft = sorted(
        identifier
        for identifier in identifiers
        if identifier in STRONG_COPYLEFT_IDS or identifier.startswith(STRONG_COPYLEFT_PREFIXES)
    )
    review_reasons = []
    if strong_copyleft:
        review_reasons.append("strong_copyleft:" + ",".join(strong_copyleft))
    if nonstandard:
        review_reasons.append("nonstandard_license_reference:" + ",".join(nonstandard))
    return {
        "license": canonical,
        "declared_license": declared,
        "license_expression": canonical,
        "license_source": source,
        "policy_status": "review_required" if review_reasons else "allowed",
        "unknown": False,
        "review_required": bool(review_reasons),
        "policy_reasons": review_reasons,
    }


def _unresolved_assessment(value: str, source: str, reason: str, *, review_required: bool = True) -> dict[str, object]:
    reasons = [reason]
    if review_required and reason != "non_spdx_license_metadata":
        reasons.append("nonstandard_license_review")
    return {
        "license": value or "UNKNOWN",
        "declared_license": value or "UNKNOWN",
        "license_expression": "UNKNOWN",
        "license_source": source,
        "policy_status": "unknown_review_required" if review_required else "unknown",
        "unknown": True,
        "review_required": review_required,
        "policy_reasons": reasons,
    }


def _legacy_expression(value: str) -> str:
    return LEGACY_LICENSE_ALIASES.get(value.strip().lower(), value.strip())


def _license_identifiers(expression: str) -> set[str]:
    return {
        token
        for token in re.findall(r"(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+|[A-Za-z0-9][A-Za-z0-9.+-]*", expression)
        if token not in {"AND", "OR", "WITH"}
    }


def _distribution_name(dist: importlib.metadata.Distribution) -> str:
    return str(dist.metadata.get("Name") or "")


def _normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _clean_metadata_value(value: object) -> str:
    return " ".join(str(value or "").split())


if __name__ == "__main__":
    raise SystemExit(main())
