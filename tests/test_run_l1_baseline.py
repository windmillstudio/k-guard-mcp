from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "run_l1_baseline.py"


def test_l1_baseline_cli_exposes_pinned_inputs_and_external_evidence_contract() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "--manifest" in completed.stdout
    assert "--benchmark-java" in completed.stdout
    assert "--benchmark-python" in completed.stdout
    assert "--baseline-receipt" in completed.stdout
    assert "--output-dir" in completed.stdout
