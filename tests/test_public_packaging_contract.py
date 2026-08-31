from __future__ import annotations

import contextlib
import io
import json
import tomllib
from pathlib import Path

import anyio
from packaging.requirements import Requirement
from packaging.version import Version

from k_guard_mcp import cli
from scripts import prepare_public_release


ROOT = Path(__file__).resolve().parents[1]
KOREAN_FIXTURE = Path("tests/fixtures/korean_fixture_corpus.json")


def _requirements(values: list[str]) -> dict[str, Requirement]:
    parsed = [Requirement(value) for value in values]
    return {item.name.casefold(): item for item in parsed}


def test_runtime_dependency_contract_matches_the_audited_lock() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    runtime = _requirements(project["dependencies"])
    optional_mcp = _requirements(project["optional-dependencies"]["mcp"])
    evidence_pins = _requirements(
        [
            line
            for line in (ROOT / "requirements-evidence.in").read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
    )

    assert Version("1.28.1") in runtime["mcp"].specifier
    assert Version("2.0.0") not in runtime["mcp"].specifier
    assert runtime["mcp"].specifier == optional_mcp["mcp"].specifier
    assert Version("0.28.1") in runtime["httpx"].specifier
    assert Version("1.0.0") not in runtime["httpx"].specifier
    assert str(evidence_pins["mcp"].specifier) == "==1.28.1"
    assert str(evidence_pins["httpx"].specifier) == "==0.28.1"
    assert project["urls"] == {
        "Homepage": "https://github.com/windmillstudio/k-guard-mcp",
        "Repository": "https://github.com/windmillstudio/k-guard-mcp",
        "Issues": "https://github.com/windmillstudio/k-guard-mcp/issues",
    }


def test_readme_korean_corpus_path_exists_and_the_documented_command_runs(tmp_path: Path) -> None:
    from k_guard_mcp import server

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    documented_path = KOREAN_FIXTURE.as_posix()
    assert documented_path in readme
    assert ".k-guard/korean-fixture-corpus.json" not in readme
    assert "OWNER/REPOSITORY" not in readme
    assert "-R windmillstudio/k-guard-mcp" in readme

    async def listed_tool_names() -> set[str]:
        return {tool.name for tool in await server.create_mcp_server().list_tools()}

    undocumented_tools = sorted(
        name for name in anyio.run(listed_tool_names) if f"`{name}`" not in readme
    )
    assert undocumented_tools == []
    assert (ROOT / KOREAN_FIXTURE).is_file()

    output = tmp_path / "fixture-metrics.json"
    with contextlib.redirect_stdout(io.StringIO()):
        return_code = cli.main(
            [
                "score-corpus",
                "--corpus",
                str(ROOT / KOREAN_FIXTURE),
                "--output",
                str(output),
                "--json",
            ]
        )
    report = json.loads(output.read_text(encoding="utf-8"))
    assert return_code == 0
    assert report["passed"] is True
    assert report["raw_free"] is True


def test_public_snapshot_does_not_publish_an_unresolvable_private_base(tmp_path: Path) -> None:
    checked_in = json.loads((ROOT / "PUBLIC-SNAPSHOT.json").read_text(encoding="utf-8"))
    assert checked_in["base_commit"] is None
    assert checked_in["source_provenance"] == prepare_public_release.public_source_provenance()

    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    prepare_public_release.write_snapshot_metadata(snapshot, "a" * 40)
    generated = json.loads((snapshot / "PUBLIC-SNAPSHOT.json").read_text(encoding="utf-8"))
    assert generated["base_commit"] is None
    assert generated["source_provenance"]["private_source_revision_disclosed"] is False
    assert generated["source_provenance"]["source_revision_available_in_public_history"] is False


def test_public_export_marks_performance_as_historical_and_rebinds_fingerprint(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    path = snapshot / "benchmark-report.json"
    path.write_text(
        json.dumps(
            {
                "schema": "k_guard_performance_benchmark.v2",
                "passed": True,
                "report_fingerprint_sha256": "0" * 64,
            }
        ),
        encoding="utf-8",
    )

    prepare_public_release.mark_historical_public_benchmark(snapshot)
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["publication_binding"] == {
        "current_public_source_equivalence_claimed": False,
        "measured_revision_available_in_public_history": False,
        "scope": "historical_private_source_revision",
    }
    assert report["report_fingerprint_sha256"] != "0" * 64


def test_public_audit_workflow_uses_source_only_selector_and_least_privilege() -> None:
    workflow = (ROOT / ".github" / "workflows" / "k-guard-audit.yml").read_text(encoding="utf-8")
    assert "run: python scripts/public_source_tests.py" in workflow
    assert "run: python -m pytest -q" not in workflow
    assert "      contents: read\n" in workflow
    assert "      security-events: write\n" in workflow
    assert "sarif_file: k-guard.sarif" in workflow
    assert "        if: always()\n        with:\n          sarif_file: k-guard.sarif" not in workflow
    assert prepare_public_release.rewrite_public_audit_workflow(workflow) == workflow


def test_public_audit_workflow_rewrite_helper_sanitizes_internal_audit_job() -> None:
    internal = (
        "name: K-Guard Audit\n"
        "jobs:\n"
        "  k-guard-audit:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: Run regression tests\n"
        "        run: python -m pytest -q\n"
        "      - name: Upload self-scan JSON\n"
        "        if: always()\n"
        "        with:\n"
        "          name: k-guard-self-scan\n"
        "      - name: Upload SARIF\n"
        "        uses: github/codeql-action/upload-sarif@deadbeef\n"
        "        if: always()\n"
        "        with:\n"
        "          sarif_file: k-guard.sarif\n"
    )
    rewritten = prepare_public_release.rewrite_public_audit_workflow(internal)
    assert "run: python scripts/public_source_tests.py" in rewritten
    assert "run: python -m pytest -q" not in rewritten
    assert "      contents: read\n" in rewritten
    assert "      security-events: write\n" in rewritten
    assert "        if: always()\n        with:\n          sarif_file: k-guard.sarif" not in rewritten
    assert "        if: always()\n        with:\n          name: k-guard-self-scan" in rewritten
    assert prepare_public_release.rewrite_public_audit_workflow(rewritten) == rewritten
