from __future__ import annotations

import contextlib
import io
import json
import re
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


def test_public_distribution_support_and_audit_selector_are_aligned() -> None:
    metadata = json.loads((ROOT / "PUBLIC-SNAPSHOT.json").read_text(encoding="utf-8"))
    audit = (ROOT / ".github" / "workflows" / "k-guard-audit.yml").read_text(encoding="utf-8")
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert metadata["schema"] == "k_guard_public_source_snapshot.v1"
    assert metadata["public_ci"] == "python scripts/public_source_tests.py"
    assert (ROOT / "scripts" / "public_source_tests.py").is_file()
    assert f"run: {metadata['public_ci']}" in audit
    assert project["requires-python"] == ">=3.11,<3.15"
    assert "Programming Language :: Python :: 3.14" in project["classifiers"]
    assert 'python-version: ["3.11", "3.12", "3.13", "3.14"]' in ci


def test_active_workflow_actions_use_current_immutable_node24_pins() -> None:
    workflow_text = "\n".join(
        (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
        for name in ("ci.yml", "release.yml", "k-guard-audit.yml")
    )
    expected = {
        "actions/checkout": ("3d3c42e5aac5ba805825da76410c181273ba90b1", "v7", 5),
        "actions/setup-python": ("5fda3b95a4ea91299a34e894583c3862153e4b97", "v7", 5),
        "actions/setup-go": ("b7ad1dad31e06c5925ef5d2fc7ad053ef454303e", "v7", 2),
        "actions/upload-artifact": ("043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", "v7", 5),
        "github/codeql-action/upload-sarif": (
            "cdf488f595d80d6e07e03d4674febd5ab45fa938",
            "v4",
            1,
        ),
        "actions/attest": ("1e69f48acb82d1966a394da916b4c1698aa569d6", "v4", 2),
    }

    refs = re.findall(
        r"uses:\s+((?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+)@([0-9a-f]{40})\s+#\s+(v\d+)",
        workflow_text,
    )
    expected_refs = [
        (action, sha, major)
        for action, (sha, major, count) in expected.items()
        for _ in range(count)
    ]
    assert sorted(refs) == sorted(expected_refs)
    external_uses = [
        ref
        for ref in re.findall(r"^\s*-?\s*uses:\s+(\S+)", workflow_text, flags=re.MULTILINE)
        if not ref.startswith("./")
    ]
    assert len(external_uses) == len(refs)

    lines = workflow_text.splitlines()
    setup_go_steps = [index for index, line in enumerate(lines) if "uses: actions/setup-go@" in line]
    assert len(setup_go_steps) == 2
    assert all(
        any("cache: false" in line for line in lines[index + 1 : index + 6])
        for index in setup_go_steps
    )


def test_user_facing_guardian_workflow_uses_current_immutable_action_pins() -> None:
    workflow = (
        ROOT / "docs" / "templates" / "github-actions" / "guardian-release-gate.yml"
    ).read_text(encoding="utf-8")
    refs = re.findall(
        r"uses:\s+((?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+)@([0-9a-f]{40})\s+#\s+(v\d+)",
        workflow,
    )
    assert refs == [
        ("actions/checkout", "3d3c42e5aac5ba805825da76410c181273ba90b1", "v7"),
        ("actions/setup-python", "5fda3b95a4ea91299a34e894583c3862153e4b97", "v7"),
        (
            "actions/upload-artifact",
            "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "v7",
        ),
    ]
    assert len(re.findall(r"^\s*-?\s*uses:\s+", workflow, flags=re.MULTILINE)) == len(refs)


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
