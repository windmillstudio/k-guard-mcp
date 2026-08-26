from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import pytest

from k_guard_mcp.models import Finding
from k_guard_mcp.oracle_contracts import (
    ActionabilityEvidence,
    AtomicFacet,
    CompositeFinding,
    MatchResult,
    OracleScenario,
    PlaneGate,
    RunReceipt,
    canonicalize_findings,
    evaluate_app_pass,
    match_findings_one_to_one,
    validate_cvss_v4_severity,
)


CVSS_HIGH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"
SHA = "a" * 64


def _finding(
    finding_id: str = "raw-1",
    *,
    severity: str = "high",
    rule_id: str = "API_IDOR",
) -> Finding:
    return Finding(
        id=finding_id,
        source="test-detector",
        rule_id=rule_id,
        severity=severity,
        confidence="high",
        title="Cross-tenant object access",
        evidence="redacted evidence",
        why_it_matters="Another tenant can read the object.",
        recommendation="Check tenant ownership before returning the object.",
        file="src/routes/orders.ts",
        line_start=42,
        line_end=44,
        inspected_scope="All declared API routes were inspected.",
        not_inspected="Runtime infrastructure outside the fixture was not inspected.",
        fix_verification="Run the cross-tenant regression and expect HTTP 404.",
    )


def _actionability(
    *,
    disposition: str = "block",
    agreed: bool = True,
) -> ActionabilityEvidence:
    return ActionabilityEvidence(
        affected_flow="request.user -> order lookup -> response",
        verification_command="pytest -q tests/test_orders.py::test_cross_tenant_denied",
        severity_basis="Pinned CVSS v4.0 manifest and O1 differential.",
        disposition=disposition,
        disposition_basis="Production route with a reproducible tenant boundary bypass.",
        reproduction_succeeded=True,
        fix_verification_succeeded=True,
        three_ai_first_pass_agreed=agreed,
    )


def _facet(
    *,
    cwe: str = "CWE-639",
    source: str = "request.user.id",
    boundary: str = "order.tenant_id",
    resource: str = "/api/orders/:id",
    fingerprint: str = "fp-order-tenant",
) -> AtomicFacet:
    return AtomicFacet(
        cwe=cwe,
        source=source,
        boundary=boundary,
        resource=resource,
        redacted_fingerprint=fingerprint,
    )


def _composite(
    finding_id: str = "raw-1",
    *,
    severity: str = "high",
    disposition: str = "block",
    facets: tuple[AtomicFacet, ...] | None = None,
    agreed: bool = True,
) -> CompositeFinding:
    return CompositeFinding(
        lineage_id="app-001",
        plane="api",
        finding=_finding(finding_id, severity=severity),
        facets=facets or (_facet(),),
        actionability=_actionability(disposition=disposition, agreed=agreed),
    )


def _scenario(
    scenario_id: str = "scenario-1",
    *,
    severity: str | None = None,
    truth: str = "present",
    facet: AtomicFacet | None = None,
) -> OracleScenario:
    identity = facet or _facet()
    return OracleScenario(
        scenario_id=scenario_id,
        lineage_id="app-001",
        plane="api",
        cwe=identity.cwe,
        source=identity.source,
        boundary=identity.boundary,
        resource=identity.resource,
        severity=severity or ("high" if truth == "present" else "none"),
        mechanism_truth=truth,
    )


def _runs(*, digest: str = SHA, complete: bool = True) -> tuple[RunReceipt, ...]:
    return tuple(
        RunReceipt(
            run_id=f"run-{index}",
            canonical_output_sha256=digest,
            inventory_complete=complete,
        )
        for index in range(3)
    )


def _evaluate(
    scenarios: tuple[OracleScenario, ...],
    composites: tuple[CompositeFinding, ...],
    *,
    runs: tuple[RunReceipt, ...] | None = None,
    planes: tuple[PlaneGate, ...] = (PlaneGate("api", True),),
):
    canonical = canonicalize_findings(composites)
    matching = match_findings_one_to_one(scenarios, canonical.atoms)
    return evaluate_app_pass(
        lineage_id="app-001",
        runs=runs or _runs(),
        scenarios=scenarios,
        atoms=canonical.atoms,
        match_result=matching,
        applicable_planes=("api",),
        plane_gates=planes,
    )


def test_cvss_v4_contract_canonicalizes_order_and_locks_bucket_provenance() -> None:
    shuffled = "CVSS:4.0/SA:N/SI:N/SC:N/VA:N/VI:L/VC:H/UI:P/PR:N/AT:N/AC:L/AV:N"

    contract = validate_cvss_v4_severity(
        vector=shuffled,
        score="8.7",
        declared_bucket="high",
        calculator_id="FIRST-CVSS-v4.0@pinned",
        calculator_sha256=SHA.upper(),
        expected_calculator_sha256=SHA,
    )

    assert contract.vector == CVSS_HIGH
    assert contract.score == Decimal("8.7")
    assert contract.bucket == "high"
    assert contract.calculator_sha256 == SHA


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"vector": CVSS_HIGH.replace("/SA:N", "")}, "severity_inconclusive"),
        ({"vector": CVSS_HIGH + "/AV:L"}, "duplicate CVSS metric"),
        ({"vector": CVSS_HIGH + "/E:A"}, "non-base"),
        ({"score": "8.75"}, "one decimal"),
        ({"score": 8.7}, "float is not deterministic"),
        ({"declared_bucket": "critical"}, "does not match"),
        ({"calculator_sha256": "not-a-hash"}, "SHA-256"),
        ({"calculator_sha256": "b" * 64}, "preregistered calculator"),
    ],
)
def test_cvss_v4_contract_rejects_ambiguous_or_unbound_inputs(
    overrides: dict[str, object], message: str
) -> None:
    values: dict[str, object] = {
        "vector": CVSS_HIGH,
        "score": "8.7",
        "declared_bucket": "high",
        "calculator_id": "FIRST-CVSS-v4.0@pinned",
        "calculator_sha256": SHA,
        "expected_calculator_sha256": SHA,
    }
    values.update(overrides)

    with pytest.raises(ValueError, match=message):
        validate_cvss_v4_severity(**values)  # type: ignore[arg-type]


def test_atomic_canonicalization_is_order_independent_and_preserves_parent() -> None:
    second = _facet(
        cwe="CWE-862",
        source="request.user.role",
        boundary="admin authorization",
        resource="/api/admin/orders",
        fingerprint="fp-admin",
    )
    forward = canonicalize_findings((_composite(facets=(_facet(), second)),))
    reverse = canonicalize_findings((_composite(facets=(second, _facet())),))

    assert [atom.atom_id for atom in forward.atoms] == [atom.atom_id for atom in reverse.atoms]
    assert {atom.parent_finding_id for atom in forward.atoms} == {"raw-1"}
    assert {atom.cwe for atom in forward.atoms} == {"CWE-639", "CWE-862"}
    assert forward.duplicate_ledger == ()


def test_duplicate_ledger_is_deterministic_and_keeps_fail_closed_atom() -> None:
    actionable = _composite("z-actionable", agreed=True)
    non_actionable = _composite("a-non-actionable", agreed=False)

    first = canonicalize_findings((actionable, non_actionable))
    second = canonicalize_findings((non_actionable, actionable))

    assert first == second
    assert len(first.atoms) == 1
    assert first.atoms[0].parent_finding_id == "a-non-actionable"
    assert first.atoms[0].is_actionable() is False
    assert len(first.duplicate_ledger) == 1
    assert first.duplicate_ledger[0].removed_parent_finding_id == "z-actionable"


def test_one_to_one_matching_is_maximum_stable_and_never_reuses_an_atom() -> None:
    # Different fingerprints avoid canonical duplicate removal while preserving match identity.
    composites = (
        _composite("raw-b", facets=(_facet(fingerprint="fp-b"),)),
        _composite("raw-a", facets=(_facet(fingerprint="fp-a"),)),
    )
    atoms = canonicalize_findings(composites).atoms
    scenarios = (_scenario("scenario-b"), _scenario("scenario-a"))

    result = match_findings_one_to_one(scenarios, tuple(reversed(atoms)))

    assert len(result.matches) == 2
    assert len({match.atom_id for match in result.matches}) == 2
    assert [match.scenario_id for match in result.matches] == ["scenario-a", "scenario-b"]
    assert result.unmatched_atom_ids == ()
    assert result.unmatched_scenario_ids == ()


def test_one_to_one_matching_leaves_excess_atoms_unmatched() -> None:
    atoms = canonicalize_findings(
        (
            _composite("raw-a", facets=(_facet(fingerprint="fp-a"),)),
            _composite("raw-b", facets=(_facet(fingerprint="fp-b"),)),
        )
    ).atoms

    result = match_findings_one_to_one((_scenario(),), atoms)

    assert len(result.matches) == 1
    assert len(result.unmatched_atom_ids) == 1


def test_matching_never_crosses_lineage_boundaries() -> None:
    atom = canonicalize_findings(
        (replace(_composite(), lineage_id="app-002"),)
    ).atoms[0]

    result = match_findings_one_to_one((_scenario(),), (atom,))

    assert result.matches == ()
    assert result.unmatched_scenario_ids == ("scenario-1",)
    assert result.unmatched_atom_ids == (atom.atom_id,)


def test_one_to_one_matching_honors_optional_fingerprint_without_losing_maximum() -> None:
    atoms = canonicalize_findings(
        (
            _composite("raw-a", facets=(_facet(fingerprint="fp-a"),)),
            _composite("raw-b", facets=(_facet(fingerprint="fp-b"),)),
        )
    ).atoms
    scenarios = (
        _scenario("generic"),
        replace(_scenario("specific"), redacted_fingerprint="fp-a"),
    )

    result = match_findings_one_to_one(scenarios, atoms)
    by_scenario = {match.scenario_id: match.atom_id for match in result.matches}
    atom_by_id = {atom.atom_id: atom for atom in atoms}

    assert len(result.matches) == 2
    assert atom_by_id[by_scenario["specific"]].redacted_fingerprint == "fp-a"


def test_dynamic_resource_is_an_exact_actionability_location_without_a_line() -> None:
    raw = _finding()
    raw.file = None
    raw.line_start = None
    raw.line_end = None
    raw.url = "http://local.test/api/orders/1"
    composite = replace(_composite(), finding=raw)

    atom = canonicalize_findings((composite,)).atoms[0]

    assert atom.is_actionable() is True


def test_app_pass_is_the_fully_actionable_necessary_and_sufficient_result() -> None:
    decision = _evaluate((_scenario(),), (_composite(),))

    assert decision.passed is True
    assert decision.fully_actionable_app is True
    assert all(value for _, value in decision.criteria)
    assert decision.failure_reasons == ()


def test_negative_only_control_can_pass_but_uncertain_oracle_cannot() -> None:
    negative = _evaluate((_scenario(truth="absent"),), ())
    uncertain = _evaluate((_scenario(truth="uncertain"),), ())

    assert negative.passed is True
    assert uncertain.passed is False
    assert "oracle_conclusive" in uncertain.failure_reasons


@pytest.mark.parametrize(
    ("scenarios", "composites", "runs", "planes", "failure"),
    [
        ((_scenario(),), (_composite(),), _runs(complete=False), (PlaneGate("api", True),), "scope_complete"),
        (
            (_scenario(),),
            (_composite(),),
            (_runs()[0], _runs()[1], replace(_runs()[2], canonical_output_sha256="b" * 64)),
            (PlaneGate("api", True),),
            "repeatable",
        ),
        ((_scenario(severity="critical"),), (_composite(severity="high"),), _runs(), (PlaneGate("api", True),), "critical_complete"),
        ((_scenario(truth="absent"),), (_composite(),), _runs(), (PlaneGate("api", True),), "negative_clean"),
        ((_scenario(),), (_composite(agreed=False),), _runs(), (PlaneGate("api", True),), "actionable"),
        ((_scenario(),), (_composite(disposition="warn", agreed=False),), _runs(), (PlaneGate("api", True),), "actionable"),
        ((_scenario(),), (_composite(),), _runs(), (PlaneGate("api", False),), "plane_complete"),
    ],
)
def test_app_pass_fails_closed_for_each_locked_contract(
    scenarios: tuple[OracleScenario, ...],
    composites: tuple[CompositeFinding, ...],
    runs: tuple[RunReceipt, ...],
    planes: tuple[PlaneGate, ...],
    failure: str,
) -> None:
    decision = _evaluate(scenarios, composites, runs=runs, planes=planes)

    assert decision.passed is False
    assert decision.fully_actionable_app is False
    assert failure in decision.failure_reasons


def test_app_pass_rejects_unexpected_high_or_blocker_atom() -> None:
    unexpected_facet = _facet(
        cwe="CWE-79",
        source="query.q",
        boundary="html response",
        resource="/search",
        fingerprint="fp-xss",
    )
    decision = _evaluate(
        (_scenario(),),
        (_composite(), _composite("raw-xss", facets=(unexpected_facet,))),
    )

    assert decision.passed is False
    assert "no_unexpected" in decision.failure_reasons


def test_app_pass_requires_exactly_three_consistent_receipts_and_match_ledger() -> None:
    canonical = canonicalize_findings((_composite(),))
    scenario = _scenario()
    matching = match_findings_one_to_one((scenario,), canonical.atoms)

    with pytest.raises(ValueError, match="exactly three"):
        evaluate_app_pass(
            lineage_id="app-001",
            runs=_runs()[:2],
            scenarios=(scenario,),
            atoms=canonical.atoms,
            match_result=matching,
            applicable_planes=("api",),
            plane_gates=(PlaneGate("api", True),),
        )

    invalid = MatchResult(
        matches=matching.matches,
        unmatched_scenario_ids=("scenario-1",),
        unmatched_atom_ids=(),
    )
    with pytest.raises(ValueError, match="inconsistent unmatched scenarios"):
        evaluate_app_pass(
            lineage_id="app-001",
            runs=_runs(),
            scenarios=(scenario,),
            atoms=canonical.atoms,
            match_result=invalid,
            applicable_planes=("api",),
            plane_gates=(PlaneGate("api", True),),
        )
