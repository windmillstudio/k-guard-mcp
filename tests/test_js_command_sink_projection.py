from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

import pytest

from k_guard_mcp.hashing import evidence_hash
from k_guard_mcp.models import Finding
from k_guard_mcp.scanner import KGuardScanner
from scripts.project_js_command_sink_resolution import build_projection, write_projection


ROOT = Path(__file__).resolve().parents[1]
RULE_ID = "WEB_UNTRUSTED_INPUT_TO_COMMAND"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )


def _candidate(
    app: str,
    relative: str,
    line: int,
    source: str,
    label: str,
    subtype: str = "js_ts_bounded_request_to_command",
) -> dict:
    candidate_id = hashlib.sha256(
        f"{app}\0{relative}\0{line}\0{subtype}".encode("utf-8")
    ).hexdigest()[:20]
    return {
        "app": app,
        "artifact_scope": "runtime_source",
        "candidate_id": candidate_id,
        "confidence": "high",
        "detector_subtype": subtype,
        "evidence_refs": {
            "line_hash": evidence_hash(source.splitlines()[line - 1])
        },
        "expected_label": label,
        "label": "unreviewed",
        "location": {
            "body_or_header": None,
            "kind": "source",
            "source": f"{relative}:{line}",
        },
        "rationale": "",
        "raw_returned": False,
        "redacted_fingerprint": f"sha256-truncated:{candidate_id}",
        "response_hash": None,
        "rule_id": RULE_ID,
        "severity": "critical",
        "source_location": f"{relative}:{line}",
    }


def _source_receipt(
    campaign: Path,
    source_root: Path,
    app: str,
) -> tuple[dict, dict]:
    app_root = source_root / app
    files = sorted(path for path in app_root.rglob("*") if path.is_file())
    rows = []
    for path in files:
        relative = path.relative_to(app_root).as_posix()
        rows.append(
            {
                "byte_count": path.stat().st_size,
                "git_blob_sha1": hashlib.sha1(path.read_bytes()).hexdigest(),
                "mode": "100644",
                "path": relative,
                "sha256": _sha256_file(path),
            }
        )
    repository_id = app.replace("--", "/", 1)
    commit = hashlib.sha1(app.encode("utf-8")).hexdigest()
    commit_tree = hashlib.sha1(f"{app}-tree".encode("utf-8")).hexdigest()
    source_tree = hashlib.sha256(
        json.dumps(rows, sort_keys=True).encode("utf-8")
    ).hexdigest()
    receipt = {
        "commit": commit,
        "commit_match": True,
        "commit_object_hash_match": True,
        "commit_tree": commit_tree,
        "commit_tree_match": True,
        "file_count": len(rows),
        "files": rows,
        "git_fsck_output_sha256": hashlib.sha256(b"").hexdigest(),
        "git_fsck_strict_passed": True,
        "git_object_format": "sha1",
        "git_porcelain_clean": True,
        "index_tree_match": True,
        "origin_repository_id": repository_id,
        "origin_repository_match": True,
        "passed": True,
        "physical_bytes_match_git_blobs": True,
        "raw_returned": False,
        "repository_id": repository_id,
        "schema": "k_guard_git_source_materialization.v2",
        "source_tree_sha256": source_tree,
        "source_worktree_clean": True,
        "total_bytes": sum(row["byte_count"] for row in rows),
        "tree_object_reconstruction_match": True,
    }
    receipt_path = campaign / "source-receipts" / f"{app}.json"
    _write_json(receipt_path, receipt)
    app_contract = {
        "app": app,
        "commit": commit,
        "commit_tree": commit_tree,
        "repository_id": repository_id,
        "source_materialization_receipt_path": (
            f"source-receipts/{app}.json"
        ),
        "source_materialization_receipt_sha256": _sha256_file(receipt_path),
        "source_total_bytes": receipt["total_bytes"],
        "source_tree_sha256": source_tree,
        "source_worktree_clean": True,
        "tracked_files": len(rows),
    }
    return receipt, app_contract


def _baseline_report(
    source_root: Path,
    app: str,
    candidates: list[dict],
) -> dict:
    report = KGuardScanner().scan_workspace(
        source_root / app,
        include_flow=True,
    ).to_dict()
    report["findings"] = [
        finding
        for finding in report["findings"]
        if not (
            finding.get("rule_id") == RULE_ID
            and Path(str(finding.get("file") or "")).suffix.lower()
            in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
        )
    ]
    for candidate in candidates:
        relative, line_text = candidate["source_location"].rsplit(":", 1)
        subtype = candidate["detector_subtype"]
        report["findings"].append(
            {
                "artifact_scope": "runtime_source",
                "confidence": candidate["confidence"],
                "evidence": (
                    f"detector_subtype={subtype} "
                    f"line_hash={candidate['evidence_refs']['line_hash']} "
                    "scheme=hmac-sha256:public-default-key:len16 "
                    "raw_returned=false"
                ),
                "file": f"<workspace>/{relative}",
                "line_end": int(line_text),
                "line_start": int(line_text),
                "rule_id": RULE_ID,
                "severity": candidate["severity"],
                "source": (
                    "app-risk"
                    if subtype == "direct_request_to_command"
                    else "polyglot-flow"
                ),
            }
        )
    return report


def _write_report_runs(
    campaign: Path,
    app: str,
    report: dict,
    source_tree_sha256: str,
) -> tuple[list[dict], str]:
    raw = (
        json.dumps(
            report,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    report_sha256 = hashlib.sha256(raw).hexdigest()
    artifact = gzip.compress(raw, mtime=0)
    runs = []
    for run_number in (1, 2):
        report_relative = f"reports/{app}-run{run_number}.json.gz"
        report_path = campaign / report_relative
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_bytes(artifact)
        runtime_relative = f"runtime-receipts/{app}-run{run_number}.json"
        runtime_path = campaign / runtime_relative
        _write_json(
            runtime_path,
            {
                "app": app,
                "raw_returned": False,
                "run": run_number,
                "schema": "fixture.runtime.v1",
            },
        )
        runs.append(
            {
                "duration_seconds": 0.01,
                "exit_code": 0,
                "raw_report_sha256": hashlib.sha256(b"raw" + raw).hexdigest(),
                "report_artifact_encoding": "canonical-json+gzip-mtime-zero",
                "report_artifact_path": report_relative,
                "report_artifact_sha256": _sha256_file(report_path),
                "report_sha256": report_sha256,
                "run": run_number,
                "runtime_receipt_path": runtime_relative,
                "runtime_receipt_sha256": _sha256_file(runtime_path),
                "source_mutation_observed": False,
                "source_tree_sha256": source_tree_sha256,
            }
        )
    return runs, report_sha256


def _label_row(candidate: dict) -> dict:
    label = candidate["expected_label"]
    vendors = ("anthropic", "openai", "xai")
    return {
        "agreement": "unanimous",
        "app": candidate["app"],
        "artifact_scope": candidate["artifact_scope"],
        "candidate_id": candidate["candidate_id"],
        "confidence": candidate["confidence"],
        "detector_subtype": candidate["detector_subtype"],
        "http_response_sha256": candidate["response_hash"],
        "label": label,
        "raw_returned": False,
        "redacted_fingerprint": candidate["redacted_fingerprint"],
        "response_location": "not_applicable_static_source_scan",
        "reviews": [
            {
                "label": label,
                "rationale": "fixture adjudication",
                "reviewer_alias": f"{vendor}-fixture",
                "reviewer_ref": (
                    f"sha256:{hashlib.sha256(vendor.encode('utf-8')).hexdigest()}"
                ),
                "reviewer_vendor": vendor,
            }
            for vendor in vendors
        ],
        "rule_id": candidate["rule_id"],
        "scan_report_sha256": candidate["scan_report_sha256"],
        "severity": candidate["severity"],
        "source_location": candidate["source_location"],
    }


def _write_campaign(
    campaign: Path,
    source_root: Path,
    candidates: list[dict],
) -> None:
    campaign.mkdir()
    app_ids = sorted(path.name for path in source_root.iterdir() if path.is_dir())
    campaign_apps = []
    report_hashes: dict[str, str] = {}
    for app in app_ids:
        _receipt, app_contract = _source_receipt(campaign, source_root, app)
        app_candidates = [
            candidate for candidate in candidates if candidate["app"] == app
        ]
        report = _baseline_report(source_root, app, app_candidates)
        runs, report_sha256 = _write_report_runs(
            campaign,
            app,
            report,
            app_contract["source_tree_sha256"],
        )
        report_hashes[app] = report_sha256
        inventory = report["metadata"]["review_coverage"]["inventory"]
        app_contract.update(
            {
                "exact_repeat": True,
                "runs": runs,
                "supported_files": inventory["supported_file_count"],
            }
        )
        campaign_apps.append(app_contract)

    queue_rows = []
    label_rows = []
    for candidate in candidates:
        candidate["scan_report_sha256"] = report_hashes[candidate["app"]]
        queue_row = {
            key: value
            for key, value in candidate.items()
            if key != "expected_label"
        }
        queue_rows.append(queue_row)
        label_rows.append(_label_row(candidate))
    _write_json(
        campaign / "candidate-queue.json",
        {
            "schema": "k_guard_public_field_candidate_queue.v1",
            "campaign_id": "fixture",
            "candidates": queue_rows,
            "raw_returned": False,
        },
    )
    _write_json(
        campaign / "candidate-labels.json",
        {
            "schema": "k_guard_public_field_candidate_labels.v1",
            "campaign_id": "fixture",
            "candidates": label_rows,
            "raw_returned": False,
        },
    )
    preregistration_path = campaign / "preregistration.json"
    _write_json(
        preregistration_path,
        {
            "app_count": len(campaign_apps),
            "campaign_id": "fixture",
            "raw_returned": False,
            "schema": "fixture.preregistration.v1",
        },
    )
    _write_json(
        campaign / "campaign.json",
        {
            "analyzer_package_tree_hash_schema": (
                "k_guard_package_tree_sha256.v2"
            ),
            "analyzer_package_tree_sha256": hashlib.sha256(
                b"baseline-package"
            ).hexdigest(),
            "apps": campaign_apps,
            "campaign_id": "fixture",
            "preregistration_path": "preregistration.json",
            "preregistration_sha256": _sha256_file(preregistration_path),
            "raw_returned": False,
            "schema": "k_guard_public_field_campaign.v1",
            "source_revision": hashlib.sha1(b"fixture-source").hexdigest(),
            "tracked_worktree_clean": True,
        },
    )


def _single_candidate_fixture(
    tmp_path: Path,
    *,
    source: str = "export function run(req) { exec(req.body.command); }\n",
    line_hash: str | None = None,
) -> tuple[Path, Path, dict]:
    campaign = tmp_path / "campaign"
    source_root = tmp_path / "sources"
    target = source_root / "fixture-app" / "src/run.ts"
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")
    (target.parent / ".empty-receipt-fixture").write_bytes(b"")
    candidate = _candidate(
        "fixture-app",
        "src/run.ts",
        1,
        source,
        "true_positive",
        "direct_request_to_command",
    )
    if line_hash is not None:
        candidate["evidence_refs"]["line_hash"] = line_hash
    _write_campaign(campaign, source_root, [candidate])
    return campaign, source_root, candidate


def test_projection_separates_detector_error_from_release_actionability(
    tmp_path: Path,
) -> None:
    campaign = tmp_path / "campaign"
    source_root = tmp_path / "sources"
    fixtures = {
        "tp": (
            "src/run.ts",
            "import * as cp from 'node:child_process';\n"
            "export function run(req) {\n"
            "  const command = req.body.command;\n"
            "  cp.exec(command);\n"
            "}\n",
            4,
            "true_positive",
            "js_ts_bounded_request_to_command",
        ),
        "fp": (
            "src/match.ts",
            "export function match(req) { /[a-z]+/.exec(req.body.value); }\n",
            1,
            "false_positive",
            "js_ts_bounded_request_to_command",
        ),
        "benign": (
            "src/lab.ts",
            "export function lab(req) {\n"
            "  const command = req.body.command;\n"
            "  exec(command);\n"
            "}\n",
            3,
            "benign",
            "js_ts_bounded_request_to_command",
        ),
        "direct-benign": (
            "src/direct.js",
            "const cp = require('node:child_process');\n"
            "export function lab(req) { cp.exec(req.body.command); }\n",
            2,
            "benign",
            "direct_request_to_command",
        ),
    }
    candidates = []
    for app, (relative, source, line, label, subtype) in fixtures.items():
        target = source_root / app / relative
        target.parent.mkdir(parents=True)
        target.write_text(source, encoding="utf-8")
        candidates.append(
            _candidate(app, relative, line, source, label, subtype)
        )
    _write_campaign(campaign, source_root, candidates)

    payload = build_projection(
        repo_root=ROOT,
        campaign_dir=campaign,
        source_root=source_root,
    )

    assert payload["outcome_counts"] == {
        "detector_false_positive_removed": 1,
        "non_actionable_mechanism_retained": 2,
        "true_positive_retained": 1,
    }
    assert payload["prior_labeled_candidate_count"] == 4
    assert payload["baseline_full_universe_command_finding_count"] == 4
    assert payload["current_full_universe_command_finding_count"] == 3
    assert payload["current_actionability_on_prior_labels"] == 0.333333
    assert payload["exact_repeat"] is True
    assert payload["source_binding_contract_passed"] is True
    assert payload["full_app_coverage_contract_passed"] is True
    assert payload["current_analysis_limit_contract_passed"] is True
    assert payload["baseline_analysis_limit_contract_passed"] is True
    assert payload["regression_probe_contract_passed"] is True
    assert payload["detector_delta_contract_passed"] is True
    assert payload["full_universe_contract_passed"] is True
    assert payload["hypothesis_passed"] is True
    assert payload["release_gate_passed"] is False
    assert payload["qualification_eligible"] is False


def test_projection_rejects_source_that_drifted_from_materialization_receipt(
    tmp_path: Path,
) -> None:
    campaign, source_root, _candidate_row = _single_candidate_fixture(tmp_path)
    target = source_root / "fixture-app" / "src/run.ts"
    target.write_text(
        "export function run(req) { exec(req.body.changed); }\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="source receipt hash mismatch"):
        build_projection(
            repo_root=ROOT,
            campaign_dir=campaign,
            source_root=source_root,
        )


def test_projection_rejects_candidate_line_hash_mismatch(
    tmp_path: Path,
) -> None:
    campaign, source_root, _candidate_row = _single_candidate_fixture(
        tmp_path,
        line_hash="0" * 16,
    )

    with pytest.raises(ValueError, match="candidate line hash mismatch"):
        build_projection(
            repo_root=ROOT,
            campaign_dir=campaign,
            source_root=source_root,
        )


def test_projection_fails_hypothesis_for_unlabeled_current_candidate(
    tmp_path: Path,
) -> None:
    source = (
        "export function first(req) { exec(req.body.first); }\n"
        "export function second(req) { exec(req.body.second); }\n"
    )
    campaign = tmp_path / "campaign"
    source_root = tmp_path / "sources"
    target = source_root / "fixture-app" / "src/run.ts"
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")
    candidate = _candidate(
        "fixture-app",
        "src/run.ts",
        1,
        source,
        "true_positive",
        "direct_request_to_command",
    )
    _write_campaign(campaign, source_root, [candidate])

    payload = build_projection(
        repo_root=ROOT,
        campaign_dir=campaign,
        source_root=source_root,
    )

    assert payload["unmatched_current_candidate_count"] == 1
    assert payload["detector_delta_contract_passed"] is False
    assert payload["hypothesis_passed"] is False
    assert payload["release_gate_passed"] is False


def test_projection_fails_closed_on_current_analysis_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign, source_root, _candidate_row = _single_candidate_fixture(tmp_path)
    original = KGuardScanner.scan_workspace

    def limited_scan(
        self: KGuardScanner,
        path: str | Path,
        include_flow: bool = True,
    ):
        result = original(self, path, include_flow=include_flow)
        result.findings.append(
            Finding(
                id="fixture-limit",
                source="js-ts-taint",
                rule_id="STATIC_ANALYSIS_LIMIT_REACHED",
                severity="high",
                confidence="high",
                title="Fixture analysis limit",
                evidence=(
                    "detector_subtype=fixture_limit limit_ref=0123456789abcdef "
                    "raw_returned=false"
                ),
                why_it_matters="The fixture simulates incomplete analysis.",
                recommendation="Remove the fixture limit.",
                file=str(Path(path) / "src/run.ts"),
                line_start=1,
                line_end=1,
            )
        )
        return result.finalize()

    monkeypatch.setattr(KGuardScanner, "scan_workspace", limited_scan)
    payload = build_projection(
        repo_root=ROOT,
        campaign_dir=campaign,
        source_root=source_root,
    )

    assert payload["current_analysis_limit_count"] == 1
    assert payload["current_analysis_limit_contract_passed"] is False
    assert payload["full_universe_contract_passed"] is False
    assert payload["hypothesis_passed"] is False


def test_projection_rejects_campaign_receipt_hash_tamper(
    tmp_path: Path,
) -> None:
    campaign, source_root, _candidate_row = _single_candidate_fixture(tmp_path)
    manifest_path = campaign / "campaign.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["apps"][0]["source_materialization_receipt_sha256"] = "0" * 64
    _write_json(manifest_path, manifest)

    with pytest.raises(ValueError, match="baseline app receipt binding invalid"):
        build_projection(
            repo_root=ROOT,
            campaign_dir=campaign,
            source_root=source_root,
        )


def test_projection_rejects_queue_label_identity_drift(
    tmp_path: Path,
) -> None:
    campaign, source_root, _candidate_row = _single_candidate_fixture(tmp_path)
    labels_path = campaign / "candidate-labels.json"
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    labels["candidates"][0]["severity"] = "medium"
    _write_json(labels_path, labels)

    with pytest.raises(ValueError, match="queue/label severity mismatch"):
        build_projection(
            repo_root=ROOT,
            campaign_dir=campaign,
            source_root=source_root,
        )


def test_projection_refuses_to_overwrite_evidence(tmp_path: Path) -> None:
    output = tmp_path / "projection.json"
    output.write_text("{}\n", encoding="utf-8")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        write_projection(output, {"schema": "fixture"})
