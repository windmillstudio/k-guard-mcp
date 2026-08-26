from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Iterable, Mapping, Sequence

from k_guard_mcp.mcp_normalization import normalize_for_threat_matching
from k_guard_mcp.models import Finding
from k_guard_mcp.severity import severity_rank, validate_severity


CVSS_V4_BASE_ORDER = (
    "AV",
    "AC",
    "AT",
    "PR",
    "UI",
    "VC",
    "VI",
    "VA",
    "SC",
    "SI",
    "SA",
)
CVSS_V4_BASE_VALUES = {
    "AV": frozenset({"N", "A", "L", "P"}),
    "AC": frozenset({"L", "H"}),
    "AT": frozenset({"N", "P"}),
    "PR": frozenset({"N", "L", "H"}),
    "UI": frozenset({"N", "P", "A"}),
    "VC": frozenset({"H", "L", "N"}),
    "VI": frozenset({"H", "L", "N"}),
    "VA": frozenset({"H", "L", "N"}),
    "SC": frozenset({"H", "L", "N"}),
    "SI": frozenset({"H", "L", "N"}),
    "SA": frozenset({"H", "L", "N"}),
}
PLANES = frozenset({"site", "api", "data", "operations"})
DISPOSITIONS = frozenset({"block", "warn", "suppress", "inconclusive"})
MECHANISM_TRUTHS = frozenset({"present", "absent", "uncertain"})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CWE = re.compile(r"CWE-(?:[1-9][0-9]*)\Z")


@dataclass(frozen=True)
class CvssV4SeverityContract:
    vector: str
    score: Decimal
    bucket: str
    calculator_id: str
    calculator_sha256: str


def validate_cvss_v4_severity(
    *,
    vector: str,
    score: str | int | Decimal,
    declared_bucket: str,
    calculator_id: str,
    calculator_sha256: str,
    expected_calculator_sha256: str,
) -> CvssV4SeverityContract:
    """Validate a preregistered base vector and externally calculated bucket.

    Score calculation deliberately remains outside this module. The caller must
    pin the FIRST-compatible calculator artifact whose digest is recorded here.
    """

    normalized_vector = _canonical_cvss_v4_base_vector(vector)
    normalized_score = _decimal_score(score)
    bucket = _bucket_for_score(normalized_score)
    declared = validate_severity(_required_text(declared_bucket, "declared_bucket").casefold())
    if declared != bucket:
        raise ValueError(
            f"declared_bucket {declared!r} does not match score bucket {bucket!r}"
        )
    calculator = _required_text(calculator_id, "calculator_id")
    digest = _required_text(calculator_sha256, "calculator_sha256").casefold()
    if _SHA256.fullmatch(digest) is None:
        raise ValueError("calculator_sha256 must be a lowercase or uppercase SHA-256 hex digest")
    expected_digest = _required_text(
        expected_calculator_sha256, "expected_calculator_sha256"
    ).casefold()
    if _SHA256.fullmatch(expected_digest) is None:
        raise ValueError("expected_calculator_sha256 must be a SHA-256 hex digest")
    if digest != expected_digest:
        raise ValueError("calculator_sha256 does not match the preregistered calculator")
    return CvssV4SeverityContract(
        vector=normalized_vector,
        score=normalized_score,
        bucket=bucket,
        calculator_id=calculator,
        calculator_sha256=digest,
    )


def _canonical_cvss_v4_base_vector(vector: str) -> str:
    raw = _required_text(vector, "vector")
    parts = raw.split("/")
    if not parts or parts[0] != "CVSS:4.0":
        raise ValueError("vector must start with CVSS:4.0")
    metrics: dict[str, str] = {}
    for component in parts[1:]:
        if component.count(":") != 1:
            raise ValueError(f"invalid CVSS component {component!r}")
        metric, value = component.split(":", 1)
        if metric not in CVSS_V4_BASE_VALUES:
            raise ValueError(f"unsupported or non-base CVSS v4.0 metric {metric!r}")
        if metric in metrics:
            raise ValueError(f"duplicate CVSS metric {metric!r}")
        if value not in CVSS_V4_BASE_VALUES[metric]:
            raise ValueError(f"invalid value {value!r} for CVSS metric {metric!r}")
        metrics[metric] = value
    missing = [metric for metric in CVSS_V4_BASE_ORDER if metric not in metrics]
    if missing:
        raise ValueError(f"severity_inconclusive: missing CVSS metrics {missing}")
    return "CVSS:4.0/" + "/".join(
        f"{metric}:{metrics[metric]}" for metric in CVSS_V4_BASE_ORDER
    )


def _decimal_score(value: str | int | Decimal) -> Decimal:
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError("score must be a decimal string, integer, or Decimal; float is not deterministic")
    try:
        score = Decimal(value)
    except (InvalidOperation, TypeError, ValueError) as error:
        raise ValueError("score must be a finite decimal") from error
    if not score.is_finite() or score < Decimal("0.0") or score > Decimal("10.0"):
        raise ValueError("score must be between 0.0 and 10.0")
    if score.as_tuple().exponent < -1:
        raise ValueError("score must have at most one decimal place")
    return score.quantize(Decimal("0.0"))


def _bucket_for_score(score: Decimal) -> str:
    if score >= Decimal("9.0"):
        return "critical"
    if score >= Decimal("7.0"):
        return "high"
    if score >= Decimal("4.0"):
        return "medium"
    if score > Decimal("0.0"):
        return "low"
    return "info"


@dataclass(frozen=True)
class AtomicFacet:
    cwe: str
    source: str
    boundary: str
    resource: str
    redacted_fingerprint: str
    response_location: str = ""
    response_hash: str = ""


@dataclass(frozen=True)
class ActionabilityEvidence:
    affected_flow: str
    verification_command: str
    severity_basis: str
    disposition: str
    disposition_basis: str
    reproduction_succeeded: bool
    fix_verification_succeeded: bool
    three_ai_first_pass_agreed: bool

    def __post_init__(self) -> None:
        if self.disposition not in DISPOSITIONS:
            raise ValueError(f"invalid disposition {self.disposition!r}")


@dataclass(frozen=True)
class CompositeFinding:
    lineage_id: str
    plane: str
    finding: Finding
    facets: tuple[AtomicFacet, ...]
    actionability: ActionabilityEvidence

    def __post_init__(self) -> None:
        object.__setattr__(self, "plane", _validate_plane(self.plane))
        object.__setattr__(
            self,
            "lineage_id",
            _required_text(self.lineage_id, "lineage_id"),
        )
        if not self.facets:
            raise ValueError("composite finding must declare at least one complete atomic facet")


@dataclass(frozen=True)
class AtomicFinding:
    atom_id: str
    parent_finding_id: str
    lineage_id: str
    plane: str
    rule_id: str
    severity: str
    cwe: str
    source: str
    boundary: str
    resource: str
    redacted_fingerprint: str
    response_location: str
    response_hash: str
    finding: Finding
    actionability: ActionabilityEvidence

    @property
    def identity_key(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.lineage_id,
            self.plane,
            self.cwe,
            self.source,
            self.boundary,
            self.resource,
        )

    @property
    def duplicate_key(self) -> tuple[str, str, str, str, str, str, str]:
        return (
            self.lineage_id,
            self.plane,
            self.cwe,
            self.source,
            self.boundary,
            self.resource,
            self.redacted_fingerprint,
        )

    @property
    def is_blocker(self) -> bool:
        return self.actionability.disposition == "block"

    def is_actionable(self) -> bool:
        location_present = bool(
            (self.finding.file and self.finding.line_start is not None)
            or self.finding.url
            or self.resource
        )
        required_text = (
            self.actionability.affected_flow,
            self.finding.why_it_matters,
            self.actionability.verification_command,
            self.finding.recommendation,
            self.finding.fix_verification,
            self.actionability.severity_basis,
            self.actionability.disposition_basis,
            self.finding.inspected_scope or "",
            self.finding.not_inspected or "",
        )
        return (
            location_present
            and all(bool(value.strip()) for value in required_text)
            and self.actionability.reproduction_succeeded
            and self.actionability.fix_verification_succeeded
            and self.actionability.three_ai_first_pass_agreed
            and self.actionability.disposition != "inconclusive"
        )


@dataclass(frozen=True)
class DuplicateLedgerEntry:
    duplicate_key: tuple[str, str, str, str, str, str, str]
    kept_atom_id: str
    removed_atom_id: str
    kept_parent_finding_id: str
    removed_parent_finding_id: str


@dataclass(frozen=True)
class CanonicalizationResult:
    atoms: tuple[AtomicFinding, ...]
    duplicate_ledger: tuple[DuplicateLedgerEntry, ...]


def canonicalize_findings(
    composites: Iterable[CompositeFinding],
) -> CanonicalizationResult:
    materialized = tuple(composites)
    _require_unique(
        (
            f"{composite.lineage_id}\0{composite.finding.id}"
            for composite in materialized
        ),
        "lineage/parent finding identity",
    )
    expanded = [
        _build_atom(composite, facet)
        for composite in materialized
        for facet in composite.facets
    ]
    expanded.sort(key=_atom_sort_key)
    kept: dict[tuple[str, str, str, str, str, str, str], AtomicFinding] = {}
    ledger: list[DuplicateLedgerEntry] = []
    for atom in expanded:
        current = kept.get(atom.duplicate_key)
        if current is None:
            kept[atom.duplicate_key] = atom
            continue
        ledger.append(
            DuplicateLedgerEntry(
                duplicate_key=atom.duplicate_key,
                kept_atom_id=current.atom_id,
                removed_atom_id=atom.atom_id,
                kept_parent_finding_id=current.parent_finding_id,
                removed_parent_finding_id=atom.parent_finding_id,
            )
        )
    atoms = tuple(sorted(kept.values(), key=_atom_sort_key))
    return CanonicalizationResult(
        atoms=atoms,
        duplicate_ledger=tuple(
            sorted(
                ledger,
                key=lambda item: (
                    item.duplicate_key,
                    item.kept_atom_id,
                    item.removed_atom_id,
                ),
            )
        ),
    )


def _build_atom(composite: CompositeFinding, facet: AtomicFacet) -> AtomicFinding:
    finding = composite.finding
    severity = validate_severity(finding.severity)
    cwe = _normalize_cwe(facet.cwe)
    source = _normalize_identity(facet.source, "source", casefold=True)
    boundary = _normalize_identity(facet.boundary, "boundary", casefold=True)
    resource = _normalize_resource(facet.resource)
    fingerprint = _normalize_identity(
        facet.redacted_fingerprint,
        "redacted_fingerprint",
        casefold=True,
    )
    response_location = _optional_identity(facet.response_location, casefold=True)
    response_hash = _optional_sha256(facet.response_hash, "response_hash")
    payload = (
        composite.lineage_id.strip(),
        composite.plane,
        finding.id,
        finding.rule_id,
        severity,
        cwe,
        source,
        boundary,
        resource,
        fingerprint,
        response_location,
        response_hash,
    )
    atom_id = "atom-" + hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:24]
    return AtomicFinding(
        atom_id=atom_id,
        parent_finding_id=finding.id,
        lineage_id=composite.lineage_id.strip(),
        plane=composite.plane,
        rule_id=finding.rule_id,
        severity=severity,
        cwe=cwe,
        source=source,
        boundary=boundary,
        resource=resource,
        redacted_fingerprint=fingerprint,
        response_location=response_location,
        response_hash=response_hash,
        finding=finding,
        actionability=composite.actionability,
    )


def _atom_sort_key(atom: AtomicFinding) -> tuple[object, ...]:
    return (
        atom.duplicate_key,
        severity_rank(atom.severity),
        0 if not atom.is_actionable() else 1,
        atom.rule_id,
        atom.parent_finding_id,
        atom.atom_id,
    )


@dataclass(frozen=True)
class OracleScenario:
    scenario_id: str
    lineage_id: str
    plane: str
    cwe: str
    source: str
    boundary: str
    resource: str
    severity: str
    mechanism_truth: str
    rule_family: str = ""
    redacted_fingerprint: str = ""
    response_location: str = ""
    response_hash: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "scenario_id", _required_text(self.scenario_id, "scenario_id"))
        object.__setattr__(self, "lineage_id", _required_text(self.lineage_id, "lineage_id"))
        object.__setattr__(self, "plane", _validate_plane(self.plane))
        object.__setattr__(self, "cwe", _normalize_cwe(self.cwe))
        object.__setattr__(self, "source", _normalize_identity(self.source, "source", casefold=True))
        object.__setattr__(self, "boundary", _normalize_identity(self.boundary, "boundary", casefold=True))
        object.__setattr__(self, "resource", _normalize_resource(self.resource))
        object.__setattr__(
            self,
            "rule_family",
            _optional_identity(self.rule_family, casefold=True),
        )
        object.__setattr__(
            self,
            "redacted_fingerprint",
            _optional_identity(self.redacted_fingerprint, casefold=True),
        )
        object.__setattr__(
            self,
            "response_location",
            _optional_identity(self.response_location, casefold=True),
        )
        object.__setattr__(
            self,
            "response_hash",
            _optional_sha256(self.response_hash, "response_hash"),
        )
        if self.mechanism_truth not in MECHANISM_TRUTHS:
            raise ValueError(f"invalid mechanism_truth {self.mechanism_truth!r}")
        severity = self.severity.casefold() if isinstance(self.severity, str) else ""
        if self.mechanism_truth == "present":
            severity = validate_severity(severity)
            if severity not in {"high", "critical"}:
                raise ValueError(
                    "present oracle scenarios must be high or critical"
                )
        elif severity != "none":
            raise ValueError(
                "absent or uncertain oracle scenarios must use severity 'none'"
            )
        object.__setattr__(self, "severity", severity)

    @property
    def identity_key(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.lineage_id,
            self.plane,
            self.cwe,
            self.source,
            self.boundary,
            self.resource,
        )


@dataclass(frozen=True)
class FindingScenarioMatch:
    scenario_id: str
    atom_id: str


@dataclass(frozen=True)
class MatchResult:
    matches: tuple[FindingScenarioMatch, ...]
    unmatched_scenario_ids: tuple[str, ...]
    unmatched_atom_ids: tuple[str, ...]

    @property
    def scenario_to_atom(self) -> Mapping[str, str]:
        return {match.scenario_id: match.atom_id for match in self.matches}


def match_findings_one_to_one(
    scenarios: Sequence[OracleScenario],
    atoms: Sequence[AtomicFinding],
) -> MatchResult:
    _require_unique((scenario.scenario_id for scenario in scenarios), "scenario_id")
    _require_unique((atom.atom_id for atom in atoms), "atom_id")
    scenario_groups: dict[
        tuple[str, str, str, str, str, str], list[OracleScenario]
    ] = {}
    atom_groups: dict[
        tuple[str, str, str, str, str, str], list[AtomicFinding]
    ] = {}
    for scenario in scenarios:
        scenario_groups.setdefault(scenario.identity_key, []).append(scenario)
    for atom in atoms:
        atom_groups.setdefault(atom.identity_key, []).append(atom)
    matches: list[FindingScenarioMatch] = []
    matched_scenarios: set[str] = set()
    matched_atoms: set[str] = set()
    for key in sorted(set(scenario_groups) & set(atom_groups)):
        ordered_scenarios = sorted(
            scenario_groups[key], key=lambda item: item.scenario_id
        )
        ordered_atoms = sorted(atom_groups[key], key=lambda item: item.atom_id)
        atom_owner: dict[str, str] = {}
        scenario_by_id = {scenario.scenario_id: scenario for scenario in ordered_scenarios}

        def assign(scenario: OracleScenario, visited: set[str]) -> bool:
            for atom in ordered_atoms:
                if atom.atom_id in visited or not _scenario_matches_atom(scenario, atom):
                    continue
                visited.add(atom.atom_id)
                owner_id = atom_owner.get(atom.atom_id)
                if owner_id is None or assign(scenario_by_id[owner_id], visited):
                    atom_owner[atom.atom_id] = scenario.scenario_id
                    return True
            return False

        for scenario in ordered_scenarios:
            assign(scenario, set())
        for atom_id, scenario_id in atom_owner.items():
            matches.append(FindingScenarioMatch(scenario_id, atom_id))
            matched_scenarios.add(scenario_id)
            matched_atoms.add(atom_id)
    return MatchResult(
        matches=tuple(sorted(matches, key=lambda item: (item.scenario_id, item.atom_id))),
        unmatched_scenario_ids=tuple(
            sorted(
                scenario.scenario_id
                for scenario in scenarios
                if scenario.scenario_id not in matched_scenarios
            )
        ),
        unmatched_atom_ids=tuple(
            sorted(atom.atom_id for atom in atoms if atom.atom_id not in matched_atoms)
        ),
    )


def _scenario_matches_atom(
    scenario: OracleScenario,
    atom: AtomicFinding,
) -> bool:
    if scenario.identity_key != atom.identity_key:
        return False
    optional_pairs = (
        (scenario.rule_family, atom.rule_id.casefold()),
        (scenario.redacted_fingerprint, atom.redacted_fingerprint),
        (scenario.response_location, atom.response_location),
        (scenario.response_hash, atom.response_hash),
    )
    return all(not expected or expected == actual for expected, actual in optional_pairs)


@dataclass(frozen=True)
class RunReceipt:
    run_id: str
    canonical_output_sha256: str
    inventory_complete: bool
    had_error: bool = False
    timed_out: bool = False
    unsupported: bool = False
    hold_incomplete: bool = False

    def __post_init__(self) -> None:
        _required_text(self.run_id, "run_id")
        _optional_sha256(self.canonical_output_sha256, "canonical_output_sha256", required=True)

    @property
    def scope_complete(self) -> bool:
        return (
            self.inventory_complete
            and not self.had_error
            and not self.timed_out
            and not self.unsupported
            and not self.hold_incomplete
        )


@dataclass(frozen=True)
class PlaneGate:
    plane: str
    passed: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "plane", _validate_plane(self.plane))


@dataclass(frozen=True)
class AppPassDecision:
    lineage_id: str
    passed: bool
    fully_actionable_app: bool
    criteria: tuple[tuple[str, bool], ...]
    failure_reasons: tuple[str, ...]


def evaluate_app_pass(
    *,
    lineage_id: str,
    runs: Sequence[RunReceipt],
    scenarios: Sequence[OracleScenario],
    atoms: Sequence[AtomicFinding],
    match_result: MatchResult,
    applicable_planes: Sequence[str],
    plane_gates: Sequence[PlaneGate],
    kpriv_applicable: bool = False,
    kpriv_passed: bool = False,
) -> AppPassDecision:
    lineage = _required_text(lineage_id, "lineage_id")
    if len(runs) != 3:
        raise ValueError("exactly three run receipts are required")
    _require_unique((run.run_id for run in runs), "run_id")
    if any(scenario.lineage_id != lineage for scenario in scenarios):
        raise ValueError("every scenario must belong to the evaluated lineage")
    if any(atom.lineage_id != lineage for atom in atoms):
        raise ValueError("every atom must belong to the evaluated lineage")
    _require_unique((scenario.scenario_id for scenario in scenarios), "scenario_id")
    _require_unique((atom.atom_id for atom in atoms), "atom_id")

    scenario_by_id = {scenario.scenario_id: scenario for scenario in scenarios}
    atom_by_id = {atom.atom_id: atom for atom in atoms}
    _validate_match_result(match_result, scenario_by_id, atom_by_id)
    pairings = [
        (scenario_by_id[match.scenario_id], atom_by_id[match.atom_id])
        for match in match_result.matches
    ]
    present_scenarios = [
        scenario for scenario in scenarios if scenario.mechanism_truth == "present"
    ]
    uncertain_scenarios = [
        scenario for scenario in scenarios if scenario.mechanism_truth == "uncertain"
    ]
    matched_present = {
        scenario.scenario_id: atom
        for scenario, atom in pairings
        if scenario.mechanism_truth == "present"
    }
    matched_absent = [
        atom
        for scenario, atom in pairings
        if scenario.mechanism_truth == "absent"
        and (atom.severity in {"high", "critical"} or atom.is_blocker)
    ]
    severity_mismatches = [
        scenario.scenario_id
        for scenario, atom in pairings
        if scenario.mechanism_truth == "present" and scenario.severity != atom.severity
    ]
    matched_atom_ids = {match.atom_id for match in match_result.matches}
    unexpected = [
        atom
        for atom in atoms
        if atom.atom_id not in matched_atom_ids
        and (atom.severity in {"high", "critical"} or atom.is_blocker)
    ]
    actionability_targets = {
        atom.atom_id: atom
        for scenario, atom in pairings
        if scenario.mechanism_truth == "present" and atom.severity in {"high", "critical"}
    }
    actionability_targets.update({atom.atom_id: atom for atom in atoms if atom.is_blocker})

    normalized_applicable = tuple(sorted({_validate_plane(plane) for plane in applicable_planes}))
    gate_by_plane: dict[str, bool] = {}
    for gate in plane_gates:
        if gate.plane in gate_by_plane:
            raise ValueError(f"duplicate plane gate {gate.plane!r}")
        gate_by_plane[gate.plane] = gate.passed
    plane_complete = (
        set(gate_by_plane) == set(normalized_applicable)
        and all(gate_by_plane.values())
        and (not kpriv_applicable or kpriv_passed)
    )

    criteria = (
        ("scope_complete", all(run.scope_complete for run in runs)),
        (
            "repeatable",
            len({run.canonical_output_sha256.casefold() for run in runs}) == 1,
        ),
        ("oracle_conclusive", not uncertain_scenarios),
        (
            "critical_complete",
            all(
                scenario.scenario_id in matched_present
                and matched_present[scenario.scenario_id].severity == "critical"
                for scenario in present_scenarios
                if scenario.severity == "critical"
            ),
        ),
        (
            "high_complete",
            all(
                scenario.scenario_id in matched_present
                and matched_present[scenario.scenario_id].severity == "high"
                for scenario in present_scenarios
                if scenario.severity == "high"
            ),
        ),
        ("negative_clean", not matched_absent),
        ("no_unexpected", not unexpected and not severity_mismatches),
        (
            "actionable",
            all(atom.is_actionable() for atom in actionability_targets.values()),
        ),
        ("plane_complete", plane_complete),
    )
    failures = tuple(name for name, passed in criteria if not passed)
    passed = not failures
    return AppPassDecision(
        lineage_id=lineage,
        passed=passed,
        fully_actionable_app=passed,
        criteria=criteria,
        failure_reasons=failures,
    )


def _validate_match_result(
    result: MatchResult,
    scenario_by_id: Mapping[str, OracleScenario],
    atom_by_id: Mapping[str, AtomicFinding],
) -> None:
    scenario_ids = [match.scenario_id for match in result.matches]
    atom_ids = [match.atom_id for match in result.matches]
    _require_unique(scenario_ids, "matched scenario_id")
    _require_unique(atom_ids, "matched atom_id")
    if any(value not in scenario_by_id for value in scenario_ids):
        raise ValueError("match result references an unknown scenario")
    if any(value not in atom_by_id for value in atom_ids):
        raise ValueError("match result references an unknown atom")
    for match in result.matches:
        if not _scenario_matches_atom(
            scenario_by_id[match.scenario_id],
            atom_by_id[match.atom_id],
        ):
            raise ValueError("match result contains a non-identical scenario/atom pair")
    expected_unmatched_scenarios = tuple(sorted(set(scenario_by_id) - set(scenario_ids)))
    expected_unmatched_atoms = tuple(sorted(set(atom_by_id) - set(atom_ids)))
    if result.unmatched_scenario_ids != expected_unmatched_scenarios:
        raise ValueError("match result has inconsistent unmatched scenarios")
    if result.unmatched_atom_ids != expected_unmatched_atoms:
        raise ValueError("match result has inconsistent unmatched atoms")


def _required_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty text")
    return value.strip()


def _validate_plane(value: str) -> str:
    plane = _required_text(value, "plane").casefold()
    if plane not in PLANES:
        raise ValueError(f"invalid plane {value!r}; expected one of {sorted(PLANES)}")
    return plane


def _normalize_cwe(value: str) -> str:
    cwe = _required_text(value, "cwe").upper()
    if _CWE.fullmatch(cwe) is None:
        raise ValueError("cwe must use canonical CWE-<positive integer> form")
    return cwe


def _normalize_identity(value: str, name: str, *, casefold: bool) -> str:
    normalized = normalize_for_threat_matching(_required_text(value, name))
    normalized = " ".join(normalized.split())
    return normalized.casefold() if casefold else normalized


def _normalize_resource(value: str) -> str:
    normalized = _normalize_identity(value, "resource", casefold=False).replace("\\", "/")
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    return normalized


def _optional_identity(value: str, *, casefold: bool) -> str:
    if not value:
        return ""
    return _normalize_identity(value, "optional identity", casefold=casefold)


def _optional_sha256(value: str, name: str, *, required: bool = False) -> str:
    if not value and not required:
        return ""
    digest = _required_text(value, name).casefold()
    if _SHA256.fullmatch(digest) is None:
        raise ValueError(f"{name} must be a SHA-256 hex digest")
    return digest


def _require_unique(values: Iterable[str], name: str) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise ValueError(f"duplicate {name} {value!r}")
        seen.add(value)
