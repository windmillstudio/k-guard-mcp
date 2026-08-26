from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "run_maven_osv_observe_ab.py"
SPEC = importlib.util.spec_from_file_location("run_maven_osv_observe_ab_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
observer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = observer
SPEC.loader.exec_module(observer)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pom(path: Path) -> None:
    path.write_text(
        """<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example</groupId>
  <artifactId>observe</artifactId>
  <version>1.0.0</version>
  <properties>
    <xstream.version>1.4.5</xstream.version>
  </properties>
</project>
""",
        encoding="utf-8",
    )


def _payload(*, expected_present: bool) -> bytes:
    vulnerabilities = []
    if expected_present:
        vulnerabilities.append(
            {
                "id": "GHSA-test-test-test",
                "aliases": ["CVE-2013-7285"],
                "database_specific": {"severity": "CRITICAL"},
            }
        )
    else:
        vulnerabilities.append(
            {
                "id": "CVE-2020-0001",
                "aliases": [],
                "database_specific": {"severity": "HIGH"},
            }
        )
    return json.dumps(
        {
            "experimental_config": {},
            "results": [
                {
                    "source": {"path": "hidden"},
                    "groups": [],
                    "packages": [
                        {
                            "groups": [],
                            "package": {
                                "name": "com.thoughtworks.xstream:xstream",
                                "version": "1.4.5" if expected_present else "1.4.7",
                                "ecosystem": "Maven",
                            },
                            "vulnerabilities": vulnerabilities,
                        }
                    ],
                }
            ],
        },
        sort_keys=True,
    ).encode("utf-8")


def _runner(argv, cwd, timeout_seconds, maximum_bytes):
    del cwd, timeout_seconds, maximum_bytes
    if argv[-1] == "--version":
        return observer.ProcessResult(0, b"osv-scanner version: 2.4.0\n", b"", 27, 0)
    pom_path = Path(argv[argv.index("--lockfile") + 1])
    expected_present = b"<xstream.version>1.4.5</xstream.version>" in pom_path.read_bytes()
    raw = _payload(expected_present=expected_present)
    return observer.ProcessResult(1, raw, b"", len(raw), 0)


def test_h5a_admits_only_a_repeated_exact_cve_differential_and_never_promotes(tmp_path: Path) -> None:
    pom = tmp_path / "pom.xml"
    scanner = tmp_path / "osv-scanner.exe"
    _pom(pom)
    scanner.write_bytes(b"verified-test-binary")

    report = observer.measure_h5a(
        pom,
        scanner,
        expected_positive_sha256=_sha256(pom),
        runner=_runner,
    )

    assert report["complete"] is True
    assert report["status"] == "MEASURED_HOLD"
    assert report["oracle"] == {
        "positive_expected_cve_exactly_once": True,
        "negative_expected_cve_absent": True,
        "pair_admitted": True,
        "raw_returned": False,
    }
    assert report["repeat"]["semantic_exact"] is True
    assert report["repeat"]["raw_output_exact"] is True
    assert report["hypothesis"]["warning_promotion_admitted"] is False
    assert report["hypothesis"]["blocking_promotion_admitted"] is False
    assert report["claim_boundary"]["k_guard_maven_sca_added"] is False
    assert report["claim_boundary"]["guardian_policy_changed"] is False
    assert report["claim_boundary"]["release_gate_passed"] is False
    assert "com.thoughtworks.xstream" not in json.dumps(report, sort_keys=True)
    assert "1.4.5" not in json.dumps(report, sort_keys=True)


def test_h5a_fails_closed_when_the_pinned_source_hash_changes(tmp_path: Path) -> None:
    pom = tmp_path / "pom.xml"
    scanner = tmp_path / "osv-scanner.exe"
    _pom(pom)
    scanner.write_bytes(b"verified-test-binary")

    report = observer.measure_h5a(
        pom,
        scanner,
        expected_positive_sha256="0" * 64,
        runner=_runner,
    )

    assert report["complete"] is False
    assert report["status"] == "CONTROL_HOLD"
    assert report["control_errors"] == ["positive_pom_sha256_mismatch"]


def test_h5a_fails_closed_when_the_mutation_is_not_single_and_exact(tmp_path: Path) -> None:
    pom = tmp_path / "pom.xml"
    scanner = tmp_path / "osv-scanner.exe"
    pom.write_text("<xstream.version>1.4.5</xstream.version><xstream.version>1.4.5</xstream.version>", encoding="utf-8")
    scanner.write_bytes(b"verified-test-binary")

    report = observer.measure_h5a(
        pom,
        scanner,
        expected_positive_sha256=_sha256(pom),
        runner=_runner,
    )

    assert report["complete"] is False
    assert report["control_errors"] == ["positive_pom_expected_xstream_property_not_exactly_once"]


def test_h5a_cli_exposes_only_non_promoting_observer_inputs() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "--positive-pom" in completed.stdout
    assert "--scanner" in completed.stdout
    assert "--baseline-receipt" in completed.stdout
    assert "--expected-positive-sha256" in completed.stdout
    assert "--output" in completed.stdout
