from __future__ import annotations

import contextlib
import io
import json
import tomllib
from pathlib import Path

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


def test_readme_korean_corpus_path_exists_and_the_documented_command_runs(tmp_path: Path) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    documented_path = KOREAN_FIXTURE.as_posix()
    assert documented_path in readme
    assert ".k-guard/korean-fixture-corpus.json" not in readme
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
