from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts.materialize_calibration_corpus import (
    ADMISSION_RECEIPT_SCHEMA,
    EVENT_REQUEST_SCHEMA,
    LABEL_REQUEST_SCHEMA,
    PLAN_REQUEST_SCHEMA,
    append_event,
    build_label_commitment,
    build_plan,
    campaign_status,
    canonical_json_bytes,
    load_ledger,
    load_plan,
    main,
    seal_labels,
    status_from_paths,
    write_plan,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _domain(domain: bytes, value: object) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value, line=True).rstrip(b"\n")).hexdigest()


def _candidate(slot: dict, slot_id: str, rank: int, number: int) -> dict:
    generator_without_hash = {
        "dependency_sha256": _sha(f"dependencies:{slot_id}:{rank}"),
        "family": slot["generator_family"],
        "generator_commit": f"{(number % 15) + 1:x}" * 40,
        "license_content_sha256": _sha(f"license:{slot_id}:{rank}"),
        "license_spdx": "MIT",
        "model": f"model-{slot['generator_family']}",
        "prompt_sha256": _sha(f"prompt:{slot_id}:{rank}"),
        "sampling": {"strategy": "deterministic", "temperature": "0.0"},
        "scanner_output_absent_at_seal": True,
        "seed": number * 10 + rank,
        "version": "1.0.0",
    }
    lineage_id = f"{slot_id}-candidate-{rank}"
    template = _sha(f"template:{slot_id}:{rank}")
    source = _sha(f"source:{slot_id}:{rank}")
    cell = {
        "coverage_tags": sorted(slot["coverage_tags"]),
        "cwe": slot["cwe"],
        "family": slot["family"],
        "framework": slot["framework"],
        "generator_family": slot["generator_family"],
        "language": slot["language"],
        "plane": slot["plane"],
        "severity": slot["severity"],
    }
    subject = {
        "generator": generator_without_hash,
        "lineage_id": lineage_id,
        "quota_cell_sha256": _domain(b"k_guard_l3_quota_cell.v1\0", cell),
        "source_identity_sha256": source,
        "template_identity_sha256": template,
    }
    return {
        "lineage_id": lineage_id,
        "template_identity_sha256": template,
        "source_identity_sha256": source,
        "generator": {
            **generator_without_hash,
            "provenance_sha256": _domain(b"k_guard_l3_generator_provenance.v1\0", subject),
        },
    }


def _spec(*, reserves: int = 1) -> dict:
    slots = []
    languages = ("javascript", "typescript", "python", "java", "kotlin", "go")
    tags = ("nextjs", "express", "supabase", "firebase", "sql-rls", "mcp-proxy", "gha-docker-iac", "korean-privacy")
    families = ("source-flow", "auth-rls-db", "dependency-sca", "gha-docker-iac", "policy-kpriv")
    generator_families = ("template", "codex", "claude", "grok")
    absolute = 0
    for plane in ("site", "api", "data", "operations"):
        for number in range(1, 16):
            absolute += 1
            slot_id = f"{plane}-{number:02d}"
            tag = tags[(absolute - 1) % len(tags)]
            slot = {
                "slot_id": slot_id,
                "plane": plane,
                "language": languages[(absolute - 1) % len(languages)],
                "framework": tag,
                "family": families[(absolute - 1) % len(families)],
                "generator_family": generator_families[(absolute - 1) % len(generator_families)],
                "coverage_tags": [tag],
                "cwe": "CWE-79" if plane == "site" else "CWE-862",
                "severity": "critical" if number % 5 == 0 else "high",
            }
            slot["candidates"] = [_candidate(slot, slot_id, rank, absolute) for rank in range(reserves + 1)]
            slots.append(slot)
    return {
        "schema": PLAN_REQUEST_SCHEMA,
        "detector_artifact_sha256": _sha("detector"),
        "cvss_calculator": {"id": "first-cvss-v4-calculator", "artifact_sha256": _sha("calculator")},
        "scanner_output_absent_at_seal": True,
        "slots": slots,
    }


def _reseal_candidate(specification: dict, slot_index: int, candidate_index: int = 0) -> None:
    slot = specification["slots"][slot_index]
    candidate = slot["candidates"][candidate_index]
    generator_without_hash = dict(candidate["generator"])
    generator_without_hash.pop("provenance_sha256")
    cell = {
        "coverage_tags": sorted(slot["coverage_tags"]),
        "cwe": slot["cwe"],
        "family": slot["family"],
        "framework": slot["framework"],
        "generator_family": slot["generator_family"],
        "language": slot["language"],
        "plane": slot["plane"],
        "severity": slot["severity"],
    }
    subject = {
        "generator": generator_without_hash,
        "lineage_id": candidate["lineage_id"],
        "quota_cell_sha256": _domain(b"k_guard_l3_quota_cell.v1\0", cell),
        "source_identity_sha256": candidate["source_identity_sha256"],
        "template_identity_sha256": candidate["template_identity_sha256"],
    }
    candidate["generator"]["provenance_sha256"] = _domain(
        b"k_guard_l3_generator_provenance.v1\0", subject
    )


def _change_plane(specification: dict) -> None:
    specification["slots"][0]["plane"] = "api"
    for candidate_index in range(len(specification["slots"][0]["candidates"])):
        _reseal_candidate(specification, 0, candidate_index)


def _duplicate_identity(specification: dict, field: str) -> None:
    specification["slots"][1]["candidates"][0][field] = specification["slots"][0]["candidates"][0][field]
    _reseal_candidate(specification, 1)


def _reseal_all(specification: dict) -> None:
    for slot_index, slot in enumerate(specification["slots"]):
        for candidate_index in range(len(slot["candidates"])):
            _reseal_candidate(specification, slot_index, candidate_index)


def _rehash_event_admission(event: dict) -> None:
    receipt = event["admission_receipt"]
    receipt.pop("receipt_sha256", None)
    receipt["receipt_sha256"] = _domain(b"k_guard_l3_admission_receipt.v1\0", receipt)
    event["evidence_hashes"] = {"admission_receipt_sha256": receipt["receipt_sha256"]}


def _admission_receipt(slot: dict, candidate: dict) -> dict:
    critical = slot["severity"] == "critical"
    snapshot = _sha(f"snapshot:{candidate['lineage_id']}")
    exploit_command = _sha(f"exploit-command:{candidate['lineage_id']}")
    patch_kinds = {
        "source-flow": ["ast-guard"],
        "auth-rls-db": ["policy"],
        "dependency-sca": ["manifest-entry", "lockfile-hunk"],
        "gha-docker-iac": ["workflow-step"],
        "policy-kpriv": ["config-key"],
    }
    receipt = {
        "schema": ADMISSION_RECEIPT_SCHEMA,
        "lineage_id": candidate["lineage_id"],
        "admission_passed": True,
        "expected_disposition": "block",
        "scanner_output_absent_at_seal": True,
        "vulnerable_tree_sha256": _sha(f"vulnerable:{candidate['lineage_id']}"),
        "fixed_tree_sha256": _sha(f"fixed:{candidate['lineage_id']}"),
        "negative_control_tree_sha256": _sha(f"negative:{candidate['lineage_id']}"),
        "exploit_vulnerable": {
            "command_sha256": exploit_command,
            "executed": True,
            "harness_passed": True,
            "exploit_succeeded": True,
            "receipt_sha256": _sha(f"exploit-vulnerable:{candidate['lineage_id']}"),
            "result_sha256": _sha(f"exploit-vulnerable-result:{candidate['lineage_id']}"),
        },
        "exploit_fixed": {
            "command_sha256": exploit_command,
            "executed": True,
            "harness_passed": True,
            "exploit_succeeded": False,
            "receipt_sha256": _sha(f"exploit-fixed:{candidate['lineage_id']}"),
            "result_sha256": _sha(f"exploit-fixed-result:{candidate['lineage_id']}"),
        },
        "negative_control": {
            "command_sha256": _sha(f"negative-command:{candidate['lineage_id']}"),
            "executed": True,
            "harness_passed": True,
            "control_triggered": False,
            "receipt_sha256": _sha(f"negative-control:{candidate['lineage_id']}"),
            "result_sha256": _sha(f"negative-result:{candidate['lineage_id']}"),
        },
        "fixed_functional": {
            "command_sha256": _sha(f"functional-command:{candidate['lineage_id']}"),
            "executed": True,
            "harness_passed": True,
            "passed": True,
            "receipt_sha256": _sha(f"fixed-functional:{candidate['lineage_id']}"),
            "result_sha256": _sha(f"fixed-functional-result:{candidate['lineage_id']}"),
        },
        "bounded_causal_patch": {
            "validator_id": f"bounded-causal-patch.{slot['family']}.v1",
            "validator_sha256": _sha(f"patch-validator:{slot['family']}"),
            "receipt_sha256": _sha(f"patch:{candidate['lineage_id']}"),
            "passed": True,
            "production_file_count": 1,
            "logical_changed_lines": 4,
            "change_kinds": sorted(patch_kinds[slot["family"]]),
            "invariants_unchanged": True,
        },
        "ast_config_diff": {
            "validator_id": f"ast-config-diff.{slot['family']}.v1",
            "validator_sha256": _sha(f"diff-validator:{slot['family']}"),
            "receipt_sha256": _sha(f"diff:{candidate['lineage_id']}"),
            "passed": True,
        },
        "build_result": {
            "command_sha256": _sha(f"build-command:{candidate['lineage_id']}"),
            "executed": True,
            "harness_passed": True,
            "passed": True,
            "receipt_sha256": _sha(f"build:{candidate['lineage_id']}"),
            "result_sha256": _sha(f"build-result:{candidate['lineage_id']}"),
        },
        "functional_snapshot": {
            "before_sha256": snapshot,
            "after_sha256": snapshot,
            "equal": True,
            "receipt_sha256": _sha(f"snapshot-receipt:{candidate['lineage_id']}"),
        },
        "license_provenance": {
            "verified": True,
            "license_spdx": candidate["generator"]["license_spdx"],
            "license_content_sha256": candidate["generator"]["license_content_sha256"],
            "provenance_sha256": candidate["generator"]["provenance_sha256"],
            "receipt_sha256": _sha(f"license-receipt:{candidate['lineage_id']}"),
        },
        "oracle_bundle_sha256": _sha(f"oracle-bundle:{candidate['lineage_id']}"),
        "cvss_v4": {
            "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
            "score": "9.8" if critical else "8.1",
            "severity": slot["severity"],
            "calculator_id": "first-cvss-v4-calculator",
            "calculator_artifact_sha256": _sha("calculator"),
            "result_sha256": _sha(f"cvss-result:{candidate['lineage_id']}"),
        },
    }
    receipt["receipt_sha256"] = _domain(b"k_guard_l3_admission_receipt.v1\0", receipt)
    return receipt


def _rejected_receipt(candidate: dict) -> dict:
    receipt = {
        "schema": ADMISSION_RECEIPT_SCHEMA,
        "lineage_id": candidate["lineage_id"],
        "admission_passed": False,
        "failure_codes": ["oracle-failed"],
        "provenance_sha256": candidate["generator"]["provenance_sha256"],
        "scanner_output_absent_at_seal": True,
    }
    receipt["receipt_sha256"] = _domain(b"k_guard_l3_admission_receipt.v1\0", receipt)
    return receipt


def _event(slot: dict, status: str, *, candidate: str | None = None, replacement: str | None = None) -> dict:
    stages = {
        "reserved": "reservation",
        "materializing": "materialization",
        "admitted": "verification",
        "rejected": "verification",
        "replaced": "replacement",
        "finalized": "finalization",
    }
    lineage_id = candidate or slot["candidates"][0]["lineage_id"]
    candidate_record = next(item for item in slot["candidates"] if item["lineage_id"] == lineage_id)
    admission_receipt = (
        _admission_receipt(slot, candidate_record)
        if status == "admitted"
        else _rejected_receipt(candidate_record)
        if status == "rejected"
        else None
    )
    evidence = (
        {"admission_receipt_sha256": admission_receipt["receipt_sha256"]}
        if admission_receipt
        else {"receipt": _sha(f"{slot['slot_id']}:{status}:{lineage_id}")}
    )
    return {
        "schema": EVENT_REQUEST_SCHEMA,
        "slot_id": slot["slot_id"],
        "candidate_lineage_id": lineage_id,
        "stage": stages[status],
        "status": status,
        "evidence_hashes": evidence,
        "admission_receipt": admission_receipt,
        "replacement_lineage_id": replacement,
    }


def _label(slot: dict, candidate: str, detector_sha256: str, index: int) -> dict:
    candidate_record = next(item for item in slot["candidates"] if item["lineage_id"] == candidate)
    receipt = _admission_receipt(slot, candidate_record)
    return {
        "slot_id": slot["slot_id"],
        "lineage_id": candidate,
        "scenario_id": f"scenario-{index:03d}",
        "oracle_id": f"oracle-{index:03d}",
        "plane": slot["plane"],
        "language": slot["language"],
        "framework": slot["framework"],
        "family": slot["family"],
        "generator_family": slot["generator_family"],
        "coverage_tags": slot["coverage_tags"],
        "cwe": slot["cwe"],
        "cvss_v4": receipt["cvss_v4"],
        "severity": slot["severity"],
        "expected_disposition": receipt["expected_disposition"],
        "vulnerable_truth": "present",
        "fixed_truth": "absent",
        "negative_control_truth": "absent",
        "oracle_bundle_sha256": receipt["oracle_bundle_sha256"],
        "vulnerable_tree_sha256": receipt["vulnerable_tree_sha256"],
        "fixed_tree_sha256": receipt["fixed_tree_sha256"],
        "negative_control_tree_sha256": receipt["negative_control_tree_sha256"],
        "provenance_sha256": candidate_record["generator"]["provenance_sha256"],
        "admission_receipt_sha256": receipt["receipt_sha256"],
        "detector_artifact_sha256": detector_sha256,
        "scanner_output_absent_at_seal": True,
    }


def _paths(tmp_path: Path, *, reserves: int = 1) -> tuple[dict, Path, Path]:
    plan_path = tmp_path / "plan.json"
    plan = write_plan(_spec(reserves=reserves), plan_path)
    return plan, plan_path, tmp_path / "events.jsonl"


def _finalize_all(plan: dict, plan_path: Path, ledger_path: Path) -> None:
    for slot in plan["slots"]:
        for status in ("reserved", "materializing", "admitted", "finalized"):
            append_event(plan_path, ledger_path, _event(slot, status))


def _label_request(plan: dict, states: dict | None = None) -> dict:
    return {
        "schema": LABEL_REQUEST_SCHEMA,
        "sealed_at": "2026-07-18T12:00:00Z",
        "detector_artifact_sha256": plan["detector_artifact_sha256"],
        "scanner_output_absent_at_seal": True,
        "labels": [
            _label(
                slot,
                (states or {})
                .get(slot["slot_id"], {"candidate_lineage_id": slot["candidates"][0]["lineage_id"]})[
                    "candidate_lineage_id"
                ],
                plan["detector_artifact_sha256"],
                index,
            )
            for index, slot in enumerate(plan["slots"], start=1)
        ],
    }


def test_plan_is_deterministic_and_locks_sixty_balanced_slots() -> None:
    first = build_plan(_spec())
    second = build_plan(copy.deepcopy(_spec()))

    assert first == second
    assert first["slot_count"] == 60
    assert first["plane_counts"] == {"site": 15, "api": 15, "data": 15, "operations": 15}
    assert len({slot["quota_cell_sha256"] for slot in first["slots"]}) > 1
    assert all(candidate["reserve_order"] == rank for slot in first["slots"] for rank, candidate in enumerate(slot["candidates"]))
    assert all(
        candidate["quota_cell_sha256"] == slot["quota_cell_sha256"]
        for slot in first["slots"]
        for candidate in slot["candidates"]
    )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value["slots"].pop(), "exactly 60"),
        (_change_plane, "plane quota drift"),
        (
            lambda value: _duplicate_identity(value, "lineage_id"),
            "duplicate lineage",
        ),
        (
            lambda value: _duplicate_identity(value, "template_identity_sha256"),
            "duplicate template",
        ),
        (
            lambda value: _duplicate_identity(value, "source_identity_sha256"),
            "duplicate source",
        ),
        (lambda value: value.__setitem__("scanner_output_absent_at_seal", False), "must be true"),
    ],
)
def test_plan_fails_closed_on_quota_or_identity_drift(mutate, message: str) -> None:
    specification = _spec()
    mutate(specification)
    with pytest.raises(ValueError, match=message):
        build_plan(specification)


def test_plan_refuses_overwrite_and_hash_tamper(tmp_path: Path) -> None:
    plan, plan_path, _ = _paths(tmp_path)
    with pytest.raises(ValueError, match="overwrite"):
        write_plan(_spec(), plan_path)

    tampered = copy.deepcopy(plan)
    tampered["slots"][0]["severity"] = "critical"
    plan_path.write_bytes(canonical_json_bytes(tampered))
    with pytest.raises(ValueError, match="hash mismatch"):
        load_plan(plan_path)


def test_plan_rejects_sixty_python_slots_even_with_valid_provenance() -> None:
    specification = _spec()
    for slot in specification["slots"]:
        slot["language"] = "python"
    _reseal_all(specification)

    with pytest.raises(ValueError, match="language group coverage missing"):
        build_plan(specification)


def test_plan_rejects_missing_required_ecosystem_even_with_valid_provenance() -> None:
    specification = _spec()
    for slot in specification["slots"]:
        if slot["coverage_tags"] == ["nextjs"]:
            slot["coverage_tags"] = ["express"]
    _reseal_all(specification)

    with pytest.raises(ValueError, match="required ecosystem coverage missing: nextjs"):
        build_plan(specification)


def test_plan_rejects_missing_generator_provenance() -> None:
    specification = _spec()
    specification["slots"][0]["candidates"][0]["generator"].pop("provenance_sha256")

    with pytest.raises(ValueError, match="missing=provenance_sha256"):
        build_plan(specification)


def test_plan_rejects_candidate_not_sealed_before_scanner_output() -> None:
    specification = _spec()
    specification["slots"][0]["candidates"][0]["generator"]["scanner_output_absent_at_seal"] = False
    _reseal_candidate(specification, 0)

    with pytest.raises(ValueError, match="not sealed before scanner output"):
        build_plan(specification)


def test_plan_rejects_generator_family_share_above_forty_percent() -> None:
    specification = _spec()
    for slot in specification["slots"][:25]:
        slot["generator_family"] = "dominant"
        for candidate in slot["candidates"]:
            candidate["generator"]["family"] = "dominant"
    _reseal_all(specification)

    with pytest.raises(ValueError, match="generator family share exceeds 40%: dominant"):
        build_plan(specification)


def test_ledger_accepts_legal_append_only_lifecycle_and_rejects_duplicate_transition(tmp_path: Path) -> None:
    plan, plan_path, ledger_path = _paths(tmp_path)
    slot = plan["slots"][0]

    for status in ("reserved", "materializing", "admitted", "finalized"):
        event = append_event(plan_path, ledger_path, _event(slot, status))
        assert event["sequence"] >= 1
    events = load_ledger(ledger_path, plan)
    assert len(events) == 4
    assert events[0]["previous_event_sha256"] == "0" * 64
    assert events[-1]["previous_event_sha256"] == events[-2]["event_sha256"]

    with pytest.raises(ValueError, match="illegal transition"):
        append_event(plan_path, ledger_path, _event(slot, "finalized"))
    assert len(load_ledger(ledger_path, plan)) == 4


def test_admitted_event_rejects_arbitrary_or_minimal_evidence(tmp_path: Path) -> None:
    plan, plan_path, ledger_path = _paths(tmp_path)
    slot = plan["slots"][0]
    append_event(plan_path, ledger_path, _event(slot, "reserved"))
    append_event(plan_path, ledger_path, _event(slot, "materializing"))

    arbitrary = _event(slot, "admitted")
    arbitrary["evidence_hashes"] = {"receipt": _sha("looks-valid")}
    with pytest.raises(ValueError, match="does not bind"):
        append_event(plan_path, ledger_path, arbitrary)

    minimal = _event(slot, "admitted")
    minimal["admission_receipt"] = {
        "schema": ADMISSION_RECEIPT_SCHEMA,
        "lineage_id": slot["candidates"][0]["lineage_id"],
        "admission_passed": True,
        "receipt_sha256": _sha("minimal"),
    }
    minimal["evidence_hashes"] = {"admission_receipt_sha256": _sha("minimal")}
    with pytest.raises(ValueError, match="keys invalid"):
        append_event(plan_path, ledger_path, minimal)


def test_admission_rejects_cvss31_even_when_receipt_hash_is_recomputed(tmp_path: Path) -> None:
    plan, plan_path, ledger_path = _paths(tmp_path)
    slot = plan["slots"][0]
    append_event(plan_path, ledger_path, _event(slot, "reserved"))
    append_event(plan_path, ledger_path, _event(slot, "materializing"))
    event = _event(slot, "admitted")
    event["admission_receipt"]["cvss_v4"]["vector"] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    _rehash_event_admission(event)

    with pytest.raises(ValueError, match="CVSS:4.0"):
        append_event(plan_path, ledger_path, event)


def test_admission_rejects_cvss_calculator_result_and_severity_mismatch(tmp_path: Path) -> None:
    plan, plan_path, ledger_path = _paths(tmp_path)
    slot = plan["slots"][0]
    append_event(plan_path, ledger_path, _event(slot, "reserved"))
    append_event(plan_path, ledger_path, _event(slot, "materializing"))

    calculator = _event(slot, "admitted")
    calculator["admission_receipt"]["cvss_v4"]["calculator_artifact_sha256"] = _sha("wrong-calculator")
    _rehash_event_admission(calculator)
    with pytest.raises(ValueError, match="calculator artifact mismatch"):
        append_event(plan_path, ledger_path, calculator)

    missing_result = _event(slot, "admitted")
    missing_result["admission_receipt"]["cvss_v4"].pop("result_sha256")
    _rehash_event_admission(missing_result)
    with pytest.raises(ValueError, match="missing=result_sha256"):
        append_event(plan_path, ledger_path, missing_result)

    severity = _event(slot, "admitted")
    severity["admission_receipt"]["cvss_v4"]["severity"] = "critical" if slot["severity"] == "high" else "high"
    _rehash_event_admission(severity)
    with pytest.raises(ValueError, match="result/severity mismatch"):
        append_event(plan_path, ledger_path, severity)


def test_hash_valid_semantic_invalid_admission_is_rejected(tmp_path: Path) -> None:
    plan, plan_path, ledger_path = _paths(tmp_path)
    slot = plan["slots"][0]
    append_event(plan_path, ledger_path, _event(slot, "reserved"))
    append_event(plan_path, ledger_path, _event(slot, "materializing"))
    event = _event(slot, "admitted")
    event["admission_receipt"]["exploit_fixed"]["exploit_succeeded"] = True
    _rehash_event_admission(event)

    with pytest.raises(ValueError, match="semantic outcome invalid"):
        append_event(plan_path, ledger_path, event)

    oversized_patch = _event(slot, "admitted")
    oversized_patch["admission_receipt"]["bounded_causal_patch"]["production_file_count"] = 99
    _rehash_event_admission(oversized_patch)
    with pytest.raises(ValueError, match="exceeds family patch bounds"):
        append_event(plan_path, ledger_path, oversized_patch)


def test_ledger_detects_byte_tamper_and_truncation(tmp_path: Path) -> None:
    plan, plan_path, ledger_path = _paths(tmp_path)
    append_event(plan_path, ledger_path, _event(plan["slots"][0], "reserved"))
    original = ledger_path.read_bytes()

    ledger_path.write_bytes(original.replace(b'"reserved"', b'"rejected"', 1))
    with pytest.raises(ValueError, match="hash mismatch|stage does not match"):
        load_ledger(ledger_path, plan)

    ledger_path.write_bytes(original[:-1])
    with pytest.raises(ValueError, match="truncated"):
        load_ledger(ledger_path, plan)


def test_rejected_candidate_is_retained_and_replacement_uses_fixed_same_cell_order(tmp_path: Path) -> None:
    plan, plan_path, ledger_path = _paths(tmp_path, reserves=2)
    slot = plan["slots"][0]
    primary = slot["candidates"][0]["lineage_id"]
    reserve = slot["candidates"][1]["lineage_id"]
    for status in ("reserved", "materializing", "rejected"):
        append_event(plan_path, ledger_path, _event(slot, status, candidate=primary))

    wrong = slot["candidates"][2]["lineage_id"]
    with pytest.raises(ValueError, match="replacement order"):
        append_event(plan_path, ledger_path, _event(slot, "replaced", candidate=primary, replacement=wrong))
    append_event(plan_path, ledger_path, _event(slot, "replaced", candidate=primary, replacement=reserve))
    append_event(plan_path, ledger_path, _event(slot, "materializing", candidate=reserve))
    append_event(plan_path, ledger_path, _event(slot, "admitted", candidate=reserve))
    append_event(plan_path, ledger_path, _event(slot, "finalized", candidate=reserve))

    events = load_ledger(ledger_path, plan)
    assert any(event["status"] == "rejected" and event["candidate_lineage_id"] == primary for event in events)
    assert events[-1]["candidate_lineage_id"] == reserve


def test_exhausted_reserve_is_explicit_hold(tmp_path: Path) -> None:
    plan, plan_path, ledger_path = _paths(tmp_path, reserves=0)
    slot = plan["slots"][0]
    for status in ("reserved", "materializing", "rejected"):
        append_event(plan_path, ledger_path, _event(slot, status))

    report = campaign_status(plan, load_ledger(ledger_path, plan))
    assert report["disposition"] == "HOLD"
    assert report["reserve_exhausted_slots"] == [slot["slot_id"]]
    assert "reserve_exhausted" in report["reasons"]
    with pytest.raises(ValueError, match="reserve exhausted"):
        append_event(
            plan_path,
            ledger_path,
            _event(slot, "replaced", replacement="unplanned-reserve"),
        )


def test_seal_labels_binds_full_labels_and_makes_campaign_ready(tmp_path: Path) -> None:
    plan, plan_path, ledger_path = _paths(tmp_path)
    _finalize_all(plan, plan_path, ledger_path)
    events = load_ledger(ledger_path, plan)
    request = _label_request(plan)
    request_path = tmp_path / "label-request.json"
    commitment_path = tmp_path / "labels.json"
    request_path.write_text(json.dumps(request), encoding="ascii")

    assert (
        main(
            [
                "seal-labels",
                "--plan",
                str(plan_path),
                "--ledger",
                str(ledger_path),
                "--labels",
                str(request_path),
                "--output",
                str(commitment_path),
            ]
        )
        == 0
    )
    commitment = json.loads(commitment_path.read_text(encoding="ascii"))
    status = status_from_paths(plan_path, ledger_path, commitment_path)

    assert commitment["label_count"] == 60
    assert commitment["admission_receipt_count"] == 60
    assert commitment["prior_ledger_sha256"] == events[-1]["event_sha256"]
    assert commitment["ledger_event_count"] == 240
    assert commitment["scanner_output_absent_at_seal"] is True
    assert status["disposition"] == "READY_TO_SCAN"
    assert status["fully_admitted_finalized_count"] == 60
    assert status["reasons"] == []
    with pytest.raises(ValueError, match="overwrite"):
        seal_labels(plan_path, ledger_path, request, commitment_path)


def test_label_seal_rejects_incomplete_ledger_and_quota_or_truth_drift(tmp_path: Path) -> None:
    plan, plan_path, ledger_path = _paths(tmp_path)
    with pytest.raises(ValueError, match="all slots are finalized"):
        build_label_commitment(plan, [], _label_request(plan))

    _finalize_all(plan, plan_path, ledger_path)
    events = load_ledger(ledger_path, plan)
    request = _label_request(plan)
    request["labels"][0]["plane"] = "site" if plan["slots"][0]["plane"] != "site" else "api"
    with pytest.raises(ValueError, match="quota drift"):
        build_label_commitment(plan, events, request)

    request = _label_request(plan)
    request["labels"][0]["vulnerable_truth"] = "absent"
    with pytest.raises(ValueError, match="vulnerable truth"):
        build_label_commitment(plan, events, request)

    request = _label_request(plan)
    critical_index = next(index for index, slot in enumerate(plan["slots"]) if slot["severity"] == "critical")
    request["labels"][critical_index]["expected_disposition"] = "review"
    with pytest.raises(ValueError, match="Critical label must block"):
        build_label_commitment(plan, events, request)


def test_label_seal_rejects_scanner_output_detector_drift_and_bad_timestamp(tmp_path: Path) -> None:
    plan, plan_path, ledger_path = _paths(tmp_path)
    _finalize_all(plan, plan_path, ledger_path)
    events = load_ledger(ledger_path, plan)

    request = _label_request(plan)
    request["scanner_output_absent_at_seal"] = False
    with pytest.raises(ValueError, match="scanner output must be absent"):
        build_label_commitment(plan, events, request)

    request = _label_request(plan)
    request["detector_artifact_sha256"] = _sha("other-detector")
    with pytest.raises(ValueError, match="does not match plan"):
        build_label_commitment(plan, events, request)

    request = _label_request(plan)
    request["sealed_at"] = "2026-02-30T12:00:00Z"
    with pytest.raises(ValueError, match="not a real"):
        build_label_commitment(plan, events, request)


def test_commitment_tamper_or_later_ledger_append_fails_closed(tmp_path: Path) -> None:
    plan, plan_path, ledger_path = _paths(tmp_path)
    _finalize_all(plan, plan_path, ledger_path)
    commitment_path = tmp_path / "labels.json"
    seal_labels(plan_path, ledger_path, _label_request(plan), commitment_path)

    tampered = json.loads(commitment_path.read_text(encoding="ascii"))
    tampered["labels"][0]["oracle_bundle_sha256"] = _sha("tampered")
    commitment_path.write_bytes(canonical_json_bytes(tampered))
    with pytest.raises(ValueError, match="hash mismatch"):
        status_from_paths(plan_path, ledger_path, commitment_path)


def test_library_status_rejects_hash_valid_but_incomplete_commitment(tmp_path: Path) -> None:
    plan, plan_path, ledger_path = _paths(tmp_path)
    _finalize_all(plan, plan_path, ledger_path)
    events = load_ledger(ledger_path, plan)
    commitment = build_label_commitment(plan, events, _label_request(plan))
    commitment.pop("labels")
    unsigned = dict(commitment)
    unsigned.pop("commitment_sha256")
    commitment["commitment_sha256"] = hashlib.sha256(
        b"k_guard_l3_label_commitment.v1\0"
        + canonical_json_bytes(unsigned, line=True).rstrip(b"\n")
    ).hexdigest()

    with pytest.raises(ValueError, match="labels|structure"):
        campaign_status(plan, events, commitment)


def test_cli_plan_append_and_status_are_available(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    spec_path = tmp_path / "spec.json"
    plan_path = tmp_path / "plan.json"
    ledger_path = tmp_path / "events.jsonl"
    event_path = tmp_path / "event.json"
    spec_path.write_text(json.dumps(_spec()), encoding="ascii")

    assert main(["plan", "--spec", str(spec_path), "--output", str(plan_path)]) == 0
    plan = load_plan(plan_path)
    event_path.write_text(json.dumps(_event(plan["slots"][0], "reserved")), encoding="ascii")
    assert (
        main(
            [
                "append-event",
                "--plan",
                str(plan_path),
                "--ledger",
                str(ledger_path),
                "--event",
                str(event_path),
            ]
        )
        == 0
    )
    assert main(["status", "--plan", str(plan_path), "--ledger", str(ledger_path)]) == 1
    assert '"disposition": "HOLD"' in capsys.readouterr().out


def test_no_detector_or_network_dependency_is_imported() -> None:
    source = Path("scripts/materialize_calibration_corpus.py").read_text(encoding="utf-8")
    forbidden = ("k_guard_mcp", "requests", "urllib", "httpx", "socket", "subprocess")
    assert not any(f"import {name}" in source or f"from {name}" in source for name in forbidden)
