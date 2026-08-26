from __future__ import annotations

import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import tomllib
import unittest


TEST_DIR = Path(__file__).resolve().parent
DEMO_ROOT = TEST_DIR.parent
REPO_ROOT = TEST_DIR.parents[3]


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


license_report = _load_module("license_report_contract", REPO_ROOT / "scripts" / "license_report.py")
demo = _load_module("contest_demo_contract", DEMO_ROOT / "demo.py")


class FakeMetadata(dict):
    def __init__(self, values: dict[str, str], classifiers: list[str] | None = None):
        super().__init__(values)
        self.classifiers = classifiers or []

    def get_all(self, name: str) -> list[str]:
        return list(self.classifiers) if name == "Classifier" else []


class FakeDistribution:
    def __init__(self, values: dict[str, str], classifiers: list[str] | None = None):
        self.metadata = FakeMetadata(values, classifiers)


class ReleaseContractTests(unittest.TestCase):
    def test_license_expression_precedence_and_fail_closed_policy(self):
        copyleft = license_report._license_assessment(
            FakeDistribution({"License-Expression": "GPL-3.0-only", "License": "MIT"})
        )
        self.assertEqual(copyleft["license_source"], "License-Expression")
        self.assertTrue(copyleft["review_required"])
        self.assertIn("strong_copyleft:GPL-3.0-only", copyleft["policy_reasons"])

        unknown = license_report._license_assessment(
            FakeDistribution({"License-Expression": "UNKNOWN", "License": "MIT"})
        )
        self.assertTrue(unknown["unknown"])
        self.assertEqual(unknown["license_source"], "License-Expression")

        nonstandard = license_report._license_assessment(
            FakeDistribution({"License-Expression": "LicenseRef-Commercial"})
        )
        self.assertFalse(nonstandard["unknown"])
        self.assertTrue(nonstandard["review_required"])

        missing = license_report._license_assessment(FakeDistribution({}))
        self.assertTrue(missing["unknown"])

    def test_plain_install_declares_mcp_and_license_archive_allowlist(self):
        config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertTrue(any(item.startswith("mcp>=") for item in config["project"]["dependencies"]))
        self.assertTrue(any(item.startswith("mcp>=") for item in config["project"]["optional-dependencies"]["mcp"]))
        self.assertEqual(config["project"]["license"], "MIT")
        self.assertEqual(config["project"]["license-files"], ["LICENSE", "THIRD_PARTY_NOTICES.md", "LICENSES/*"])
        self.assertIn("requirements-evidence.lock", (REPO_ROOT / "MANIFEST.in").read_text(encoding="utf-8"))

    def test_release_workflow_builds_and_smokes_wheel(self):
        workflow = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        for contract in (
            "python -m build",
            "requirements-build.lock",
            "normalize_sdist.py",
            "verify_reproducible_builds.py",
            "verify_release_archives.py",
            "requirements-evidence.lock",
            "SHA256SUMS",
            "python -m venv",
            "dist/*.whl",
            "k-guard\" --help",
            "create_mcp_server",
            "actions/upload-artifact@v4",
            "license-report.json",
        ):
            self.assertIn(contract, workflow)

    def test_guardian_template_uses_source_checkout_and_documents_future_pins(self):
        template = (REPO_ROOT / "docs" / "templates" / "github-actions" / "guardian-release-gate.yml").read_text(encoding="utf-8")
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("K_GUARD_SOURCE_PATH", template)
        self.assertIn('python -m pip install "${{ env.K_GUARD_SOURCE_PATH }}"', template)
        self.assertNotIn("python -m pip install k-guard-mcp", template)
        self.assertIn("<published-sha256>", readme)
        self.assertIn("<40-character-commit>", readme)

    def test_docs_separate_wheel_runtime_and_source_verification_assets(self):
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        install_doc = (REPO_ROOT / "docs" / "mcp-client-install.md").read_text(encoding="utf-8")
        self.assertIn("## 설치된 wheel CLI", readme)
        self.assertIn("## 소스 체크아웃 전용 검증", readme)
        self.assertIn("wheel만 설치하면 런타임 명령만 제공", readme)
        self.assertIn("requirements-evidence.lock", install_doc)
        self.assertIn("SHA256SUMS", install_doc)
        self.assertIn(
            "python -m pip install --require-hashes -r .\\requirements-evidence.lock",
            install_doc,
        )
        self.assertIn("python -m pip install --no-deps .\\k_guard_mcp-0.1.0-py3-none-any.whl", install_doc)

    def test_coverage_precision_and_metric_language_are_exact(self):
        config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        coverage = config["tool"]["coverage"]["report"]
        self.assertEqual(coverage["fail_under"], 90)
        self.assertEqual(coverage["precision"], 2)
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("branch-inclusive combined coverage", readme)
        self.assertIn("`89.90%`", readme)

    def test_issue_forms_and_private_security_route_are_actionable(self):
        issue_root = REPO_ROOT / ".github" / "ISSUE_TEMPLATE"
        self.assertTrue((issue_root / "bug-report.yml").is_file())
        self.assertTrue((issue_root / "feature-request.yml").is_file())
        self.assertIn("blank_issues_enabled: false", (issue_root / "config.yml").read_text(encoding="utf-8"))
        security = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("GitHub Private Vulnerability Reporting", security)
        self.assertIn("Report a vulnerability", security)
        self.assertNotIn("security@", security.lower())

    def test_demo_contract_has_version_app_binding_hmac_and_two_states(self):
        metadata = json.loads((DEMO_ROOT / "demo-metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["schema"], "k_guard_contest_demo.v2")
        self.assertEqual(metadata["demo_version"], "2.0.0")
        self.assertFalse(metadata["canonical_ship_expected"])
        self.assertFalse(metadata["real_app_validation"])
        with (DEMO_ROOT / "guardian-targets.csv").open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual({row["app_id"] for row in rows}, {"contest-demo-v1"})
        self.assertEqual(len({row["target_id"] for row in rows}), len(rows))
        runbook = (DEMO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("K_GUARD_EVIDENCE_HMAC_KEY", runbook)
        self.assertIn("실제 앱 검증 주장은 하지 않는다", runbook)
        self.assertIn("python examples/contest-demo/v1/demo.py run", runbook)

        with tempfile.TemporaryDirectory() as temp_dir:
            work_dir = Path(temp_dir)
            demo.prepare("hold", work_dir)
            hold_source = (work_dir / "app" / "app.py").read_text(encoding="utf-8")
            demo.prepare("fixed", work_dir)
            fixed_source = (work_dir / "app" / "app.py").read_text(encoding="utf-8")
        self.assertIn("SYNTHETIC_DEMO_KEY", hold_source)
        self.assertNotIn("SYNTHETIC_DEMO_KEY", fixed_source)
        self.assertIn("WHERE email = ?", fixed_source)

    def test_demo_one_command_proves_risk_fix_and_fail_closed_qualification(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            scorecard = demo.run_demo(Path(temp_dir))

        self.assertTrue(scorecard["passed"])
        self.assertEqual(scorecard["transition"], ["hold_fix", "hold_qualification"])
        self.assertEqual(scorecard["application_transition"], ["risk_blocked", "clear_in_reviewed_scope"])
        self.assertFalse(scorecard["release_authority_claimed"])

if __name__ == "__main__":
    unittest.main()
