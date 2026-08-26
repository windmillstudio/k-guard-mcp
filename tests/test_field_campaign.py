from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest

from k_guard_mcp.cli import main as cli_main
from k_guard_mcp.field_campaign import (
    FIELD_APP_ROSTER_FIELDS,
    FieldCampaignRosterError,
    evaluate_field_campaign_readiness,
    load_field_app_roster,
    write_field_app_roster_template,
    write_field_campaign_status_report,
)


def _rows(count: int = 12) -> list[dict[str, str]]:
    strata = ("top", "mid", "long_tail")
    return [
        {
            "app_id": f"private-app-{index:02d}",
            "target_id": f"private-target-{index:02d}",
            "stratum": strata[(index - 1) % len(strata)],
            "source_revision": f"{index:040x}",
            "scope_basis": "owned" if index % 2 else "partner",
            "scope_assertion_ref": f"external-scope-ticket-{index:02d}",
            "recruitment_status": "accepted",
            "authorization_status": "approved",
            "scan_consent": "true",
            "aggregate_consent": "true",
        }
        for index in range(1, count + 1)
    ]


def _write_roster(path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELD_APP_ROSTER_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def test_ready_roster_loads_and_passes(tmp_path):
    roster = tmp_path / "roster.csv"
    rows = _rows()
    _write_roster(roster, rows)

    loaded = load_field_app_roster(roster)
    report = evaluate_field_campaign_readiness(roster)

    assert len(loaded) == 12
    assert loaded[0]["scan_consent"] is True
    assert report["row_count"] == 12
    assert report["app_count"] == 12
    assert report["target_count"] == 12
    assert report["stratum_counts"] == {"top": 4, "mid": 4, "long_tail": 4}
    assert report["content_sha256"] == hashlib.sha256(roster.read_bytes()).hexdigest()
    assert report["blockers"] == []
    assert report["passed"] is True
    assert report["ready"] is True


def test_empty_template_is_valid_csv_but_not_campaign_ready(tmp_path):
    roster = tmp_path / "roster.csv"

    write_field_app_roster_template(roster)
    report = evaluate_field_campaign_readiness(roster)

    assert roster.read_text(encoding="utf-8") == ",".join(FIELD_APP_ROSTER_FIELDS) + "\n"
    assert report["row_count"] == 0
    assert "roster_empty" in report["blockers"]
    assert report["ready"] is False
    with pytest.raises(FieldCampaignRosterError, match="roster_empty"):
        load_field_app_roster(roster)


def test_duplicate_app_and_target_ids_fail_closed(tmp_path):
    roster = tmp_path / "roster.csv"
    rows = _rows()
    rows[-1]["app_id"] = rows[0]["app_id"].upper()
    rows[-1]["target_id"] = rows[0]["target_id"]
    _write_roster(roster, rows)

    report = evaluate_field_campaign_readiness(roster)

    assert "duplicate_app_id" in report["blockers"]
    assert "duplicate_target_id" in report["blockers"]
    assert report["ready"] is False
    with pytest.raises(FieldCampaignRosterError, match="duplicate_app_id"):
        load_field_app_roster(roster)


def test_nonimmutable_source_revision_is_blocked(tmp_path):
    roster = tmp_path / "roster.csv"
    rows = _rows()
    rows[3]["source_revision"] = "main"
    _write_roster(roster, rows)

    report = evaluate_field_campaign_readiness(roster)

    assert report["blocker_counts"]["invalid_source_revision"] == 1
    assert report["passed"] is False


def test_all_three_strata_are_required(tmp_path):
    roster = tmp_path / "roster.csv"
    rows = _rows()
    for index, row in enumerate(rows):
        row["stratum"] = "top" if index % 2 else "mid"
    _write_roster(roster, rows)

    report = evaluate_field_campaign_readiness(roster)

    assert report["stratum_counts"]["long_tail"] == 0
    assert report["blocker_counts"]["missing_strata"] == 1
    assert report["ready"] is False


def test_written_status_report_never_contains_raw_roster_refs(tmp_path):
    roster = tmp_path / "roster.csv"
    output = tmp_path / "status.json"
    rows = _rows()
    rows[0].update(
        {
            "app_id": "private-campaign-app-z9",
            "target_id": "private-campaign-target-z9",
            "source_revision": "abcdef0123456789abcdef0123456789abcdef01",
            "scope_assertion_ref": "legal-vault-scope-assertion-z9",
        }
    )
    _write_roster(roster, rows)

    report = write_field_campaign_status_report(roster, output)
    serialized = output.read_text(encoding="utf-8")

    assert json.loads(serialized) == report
    for raw_value in (
        rows[0]["app_id"],
        rows[0]["target_id"],
        rows[0]["source_revision"],
        rows[0]["scope_assertion_ref"],
    ):
        assert raw_value not in serialized
    assert len(report["roster_refs"]) == 12
    assert report["raw_returned"] is False


def test_cli_template_and_status_fail_closed_until_roster_is_filled(tmp_path, capsys):
    roster = tmp_path / "roster.csv"
    status = tmp_path / "status.json"

    assert cli_main(["field-campaign-template", "--output", str(roster)]) == 0
    assert cli_main(["field-campaign-status", "--roster", str(roster), "--output", str(status)]) == 3

    payload = json.loads(status.read_text(encoding="utf-8"))
    assert payload["ready"] is False
    assert "roster_empty" in payload["blockers"]
    assert "roster_empty" in capsys.readouterr().out


def test_missing_and_unreadable_rosters_return_raw_free_control_failures(tmp_path, monkeypatch):
    missing = tmp_path / "missing.csv"
    missing_report = evaluate_field_campaign_readiness(missing)

    assert missing_report["blockers"] == ["roster_not_found"]
    assert missing_report["content_sha256"] == ""
    assert missing_report["roster_refs"] == []

    unreadable = tmp_path / "unreadable.csv"
    unreadable.write_text("private roster marker", encoding="utf-8")
    original_read_bytes = Path.read_bytes

    def _raise_for_roster(path: Path) -> bytes:
        if path == unreadable:
            raise OSError("private roster marker")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", _raise_for_roster)
    unreadable_report = evaluate_field_campaign_readiness(unreadable)

    assert unreadable_report["blockers"] == ["roster_unreadable"]
    assert unreadable_report["content_sha256"] == hashlib.sha256(b"").hexdigest()
    assert "private roster marker" not in json.dumps(unreadable_report)


@pytest.mark.parametrize(
    ("content", "expected_blocker"),
    [
        (b"\xff\xfe", "invalid_utf8"),
        (b'"unterminated', "malformed_csv"),
        (b"", "malformed_headers"),
    ],
)
def test_encoding_csv_and_empty_file_failures_are_bounded_and_raw_free(
    tmp_path,
    content: bytes,
    expected_blocker: str,
):
    roster = tmp_path / "roster.csv"
    roster.write_bytes(content)

    report = evaluate_field_campaign_readiness(roster)

    assert report["blockers"] == [expected_blocker]
    assert report["row_count"] == 0
    assert report["roster_refs"] == []
    assert report["raw_returned"] is False


@pytest.mark.parametrize("contact_header", [False, True])
def test_malformed_headers_reject_personal_contact_columns(tmp_path, contact_header: bool):
    roster = tmp_path / "roster.csv"
    header = list(FIELD_APP_ROSTER_FIELDS)
    header[0] = "owner_contact_email" if contact_header else "application"
    roster.write_text(",".join(header) + "\nprivate-secret\n", encoding="utf-8")

    report = evaluate_field_campaign_readiness(roster)

    assert report["blocker_counts"]["malformed_headers"] == 1
    assert ("personal_contact_field_forbidden" in report["blockers"]) is contact_header
    assert report["row_count"] == 1
    assert "private-secret" not in json.dumps(report)


def test_malformed_row_width_and_control_characters_are_not_returned(tmp_path):
    roster = tmp_path / "roster.csv"
    header = ",".join(FIELD_APP_ROSTER_FIELDS)
    roster.write_bytes((header + "\nprivate-too-short\nprivate-control,target,top," + "a" * 40 + ",owned,ref,accepted,approved,true,tru\x00e\n").encode("utf-8"))

    report = evaluate_field_campaign_readiness(roster)

    assert report["blocker_counts"]["malformed_row"] == 2
    assert report["row_count"] == 2
    assert report["app_count"] == 0
    assert report["roster_refs"] == []
    assert "private-too-short" not in json.dumps(report)
    assert "private-control" not in json.dumps(report)


def test_all_row_level_contract_failures_are_counted_without_raw_values(tmp_path):
    roster = tmp_path / "roster.csv"
    rows = _rows()
    rows[0].update(
        {
            "app_id": "",
            "target_id": "bad target",
            "stratum": "unknown",
            "source_revision": "main",
            "scope_basis": "external",
            "scope_assertion_ref": "",
            "recruitment_status": "pending",
            "authorization_status": "denied",
            "scan_consent": "maybe",
            "aggregate_consent": "false",
        }
    )
    rows[1].update(
        {
            "scope_assertion_ref": "bad value",
            "scan_consent": "false",
            "aggregate_consent": "maybe",
        }
    )
    rows[2]["app_id"] = "todo"
    rows[3]["scope_assertion_ref"] = "person@example.invalid"
    rows[4]["scope_assertion_ref"] = "tel:123456"
    _write_roster(roster, rows)

    report = evaluate_field_campaign_readiness(roster)

    expected = {
        "missing_required_value",
        "placeholder_value",
        "invalid_app_id",
        "invalid_target_id",
        "invalid_stratum",
        "invalid_source_revision",
        "invalid_scope_basis",
        "missing_scope_assertion_ref",
        "invalid_scope_assertion_ref",
        "recruitment_not_accepted",
        "authorization_not_approved",
        "invalid_scan_consent",
        "scan_consent_not_true",
        "invalid_aggregate_consent",
        "aggregate_consent_not_true",
        "personal_contact_value_forbidden",
        "app_count_out_of_range",
    }
    assert expected.issubset(report["blockers"])
    assert report["ready"] is False
    serialized = json.dumps(report, sort_keys=True)
    for raw in ("bad target", "person@example.invalid", "tel:123456", "bad value"):
        assert raw not in serialized
    assert len(report["roster_refs"]) == 8


@pytest.mark.parametrize("count", [11, 21])
def test_campaign_count_boundaries_fail_closed(tmp_path, count: int):
    roster = tmp_path / "roster.csv"
    _write_roster(roster, _rows(count))

    report = evaluate_field_campaign_readiness(roster)

    assert report["row_count"] == count
    assert report["app_count"] == count
    assert report["blocker_counts"]["row_count_out_of_range"] == 1
    assert report["blocker_counts"]["app_count_out_of_range"] == 1
    assert report["ready"] is False


def test_uppercase_values_and_utf8_bom_normalize_to_public_contract(tmp_path):
    roster = tmp_path / "roster.csv"
    rows = _rows(20)
    rows[0].update(
        {
            "stratum": "TOP",
            "source_revision": "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
            "scope_basis": "OWNED",
            "recruitment_status": "ACCEPTED",
            "authorization_status": "APPROVED",
            "scan_consent": "TRUE",
            "aggregate_consent": "TRUE",
        }
    )
    buffer = tmp_path / "plain.csv"
    _write_roster(buffer, rows)
    roster.write_text(buffer.read_text(encoding="utf-8"), encoding="utf-8-sig")

    loaded = load_field_app_roster(roster)
    report = evaluate_field_campaign_readiness(roster)

    assert report["ready"] is True
    assert report["row_count"] == 20
    assert loaded[0]["stratum"] == "top"
    assert loaded[0]["source_revision"] == rows[0]["source_revision"].lower()
    assert loaded[0]["scope_basis"] == "owned"


def test_status_output_cannot_overwrite_input_roster(tmp_path):
    roster = tmp_path / "roster.csv"
    _write_roster(roster, _rows())
    original = roster.read_bytes()

    with pytest.raises(ValueError, match="different files"):
        write_field_campaign_status_report(roster, roster)

    assert roster.read_bytes() == original
