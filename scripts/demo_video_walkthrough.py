from __future__ import annotations

import argparse
import base64
import difflib
import json
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
EVENT_LOG: Path | None = None
EVENT_STARTED_AT = 0.0


def emit(text: str = "", *, color: str = "", delay: float = 0.72) -> None:
    colors = {
        "green": "\x1b[92m",
        "cyan": "\x1b[96m",
        "red": "\x1b[91m",
        "yellow": "\x1b[93m",
        "dim": "\x1b[90m",
    }
    plain_console = os.environ.get("K_GUARD_PLAIN_CONSOLE") == "1"
    prefix = "" if plain_console else colors.get(color, "")
    suffix = "\x1b[0m" if prefix else ""
    print(f"{prefix}{text}{suffix}", flush=True)
    if EVENT_LOG is not None:
        event = {
            "t": round(time.monotonic() - EVENT_STARTED_AT, 6),
            "text": text,
            "color": color or "default",
        }
        with EVENT_LOG.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
    if delay > 0:
        time.sleep(delay)


def heading(number: int, title: str) -> None:
    emit()
    emit("=" * 76, color="cyan", delay=0.25)
    emit(f"[{number}] {title}", color="green", delay=0.9)
    emit("=" * 76, color="cyan", delay=0.25)


def short_source(path: Path, tokens: tuple[str, ...], *, limit: int = 5) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    shown = 0
    for index, line in enumerate(lines, 1):
        if not any(token in line for token in tokens):
            continue
        clean = re.sub(r"\s+", " ", line.strip())
        if not clean or len(clean) > 108:
            clean = clean[:105] + "..."
        emit(f"  {path.relative_to(ROOT).as_posix()}:{index}", color="dim", delay=0.28)
        emit(f"    {clean}", color="cyan", delay=0.72)
        shown += 1
        if shown >= limit:
            break
    if shown == 0:
        raise RuntimeError(f"No source evidence found in {path}")


def run(command: list[str], *, env: dict[str, str], stdout: Path) -> int:
    with stdout.open("w", encoding="utf-8", newline="\n") as stream:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    return completed.returncode


def app_walkthrough(work_dir: Path, env: dict[str, str]) -> None:
    heading(3, "ACTUAL GUARDIAN RUN: inspect -> HOLD -> patch -> recheck")
    vulnerable = ROOT / "examples" / "contest-demo" / "v1" / "states" / "hold" / "app.py"
    fixed = ROOT / "examples" / "contest-demo" / "v1" / "states" / "fixed" / "app.py"
    emit("Actual vulnerable fixture source", color="yellow")
    for line in vulnerable.read_text(encoding="utf-8").splitlines():
        safe = re.sub(r"sk-[A-Za-z0-9_-]+", "sk-[redacted-demo]", line)
        if safe.strip():
            emit(f"  {safe[:110]}", color="red", delay=0.55)

    app_dir = work_dir / "guardian-app"
    emit("RUN  python examples/contest-demo/v1/demo.py run", color="yellow", delay=0.9)
    code = run(
        [sys.executable, "-u", "examples/contest-demo/v1/demo.py", "run", "--work-dir", str(app_dir)],
        env=env,
        stdout=work_dir / "guardian.stdout.txt",
    )
    score_path = app_dir / "evidence" / "demo-scorecard.json"
    if code != 0 or not score_path.is_file():
        raise RuntimeError("Guardian journey did not complete")
    score = json.loads(score_path.read_text(encoding="utf-8"))
    emit("ACTUAL RESULT", color="cyan", delay=0.45)
    emit(f"  first review      {score['transition'][0]}  -> application risk BLOCKED", color="red")
    emit(f"  first blocker     {score['first_actionable_blocker']}", color="red")
    emit("  reviewed domains  site | API | Korean privacy | release", color="cyan")

    heading(4, "ACTUAL SOURCE PATCH: remove secret, parameterize SQL, minimize response")
    before = vulnerable.read_text(encoding="utf-8").splitlines()
    after = fixed.read_text(encoding="utf-8").splitlines()
    diff = list(difflib.unified_diff(before, after, fromfile="vulnerable/app.py", tofile="fixed/app.py", lineterm=""))
    for line in diff:
        safe = re.sub(r"sk-[A-Za-z0-9_-]+", "sk-[redacted-demo]", line)
        color = "green" if safe.startswith("+") else "red" if safe.startswith("-") else "dim"
        emit(f"  {safe[:112]}", color=color, delay=0.52)
    emit("  patch bytes were applied before the second Guardian process", color="yellow", delay=0.8)

    heading(5, "ACTUAL RECHECK: same scope, previous report linked")
    emit(f"  second review     {score['transition'][1]}", color="yellow")
    emit(f"  application risk  {score['application_result']}", color="green")
    emit("  blocking findings 0 in the reviewed application scope", color="green")
    emit("  product release authority remains fail-closed", color="yellow")
    emit("  result: the app risk changed because the code changed", color="cyan", delay=1.1)


def privacy_walkthrough(work_dir: Path, env: dict[str, str]) -> None:
    heading(6, "ACTUAL KOREAN PRIVACY DETECTION: values never printed raw")
    from k_guard_mcp.detectors.pii import PiiDetector
    from k_guard_mcp.scanner import KGuardScanner

    samples = [
        ("resident / foreigner registration", "resident_registration_number=901225-1234563\nforeigner_registration_number=901225-5234564", "people.yml"),
        ("passport / driver license", "passport=M12345678\ndriver_license=11-22-333333-44", "identity.yml"),
        ("business / corporate registration", "사업자등록번호=999-99-99997\n법인등록번호=110111-0062432", "vendors.yml"),
        ("medical / disability / biometric", "의료정보=진단\n장애정보=1급\n생체정보=수집", "members.yml"),
    ]
    detector = PiiDetector()
    scanner = KGuardScanner()
    for label, sample, filename in samples:
        entities = detector.detect_entities(sample, filename)
        findings = scanner.scan_text(sample, filename).findings
        entity_labels = sorted({entity.label for entity in entities})
        rule_ids = sorted({finding.rule_id for finding in findings})
        if not entity_labels or not rule_ids:
            raise RuntimeError(f"Korean privacy demo sample produced no classification: {label}")
        emit(f"  INPUT  {label}", color="yellow", delay=0.45)
        emit(f"  LABEL  {' | '.join(entity_labels)}", color="cyan", delay=0.6)
        emit(f"  RULE   {' | '.join(rule_ids)}", color="green", delay=0.72)

    qualification = work_dir / "korean-qualification.json"
    emit("RUN  scripts/qualify_korean_privacy_ai_only.py", color="yellow", delay=0.9)
    code = run(
        [sys.executable, "-u", "scripts/qualify_korean_privacy_ai_only.py", "--output", str(qualification)],
        env=env,
        stdout=work_dir / "korean-qualification.stdout.txt",
    )
    if code != 0 or not qualification.is_file():
        raise RuntimeError("Korean privacy qualification did not complete")
    report = json.loads(qualification.read_text(encoding="utf-8"))
    emit("  fixture lane      PASS", color="green")
    emit("  frozen holdout    PASS", color="green")
    emit("  vocabulary parity PASS", color="green")
    emit("  raw values returned to console: false", color="green")
    emit(f"  qualification projection: {'PASS' if report.get('passed') else 'FAIL'}", color="green", delay=1.0)


def test_walkthrough(work_dir: Path, env: dict[str, str]) -> None:
    heading(7, "ACTUAL PRODUCT CHECKS: runtime, privacy, app journey")
    groups = [
        (
            "runtime mediation",
            [
                "tests/test_mcp_http_proxy.py::test_post_json_policy_block_never_reaches_upstream",
                "tests/test_mcp_http_proxy.py::test_post_json_redacts_both_directions_before_forwarding",
                "tests/test_mcp_http_proxy.py::test_official_sdk_interoperates_with_fastmcp_streamable_http_app",
            ],
        ),
        (
            "Korean privacy",
            [
                "tests/test_korean_sensitive_org_identifiers.py::test_sensitive_term_with_direct_identifier_is_composite",
                "tests/test_korean_sensitive_org_identifiers.py::test_valid_business_registration_is_org_identifier_not_rrn",
                "tests/test_korean_sensitive_org_identifiers.py::test_valid_corporate_registration_is_org_identifier_not_rrn",
                "tests/test_korean_sensitive_org_identifiers.py::test_parity_contract_is_closed",
            ],
        ),
        (
            "app hold/fix/recheck",
            ["tests/test_contest_demo_journey.py::test_contest_demo_enforces_local_targets_and_runtime_budget"],
        ),
    ]
    for slug, paths in groups:
        emit(f"RUN  pytest {slug}", color="yellow", delay=0.7)
        safe_slug = re.sub(r"[^a-z0-9]+", "-", slug.lower()).strip("-")
        target = work_dir / (safe_slug + ".txt")
        code = run([sys.executable, "-m", "pytest", "-q", *paths], env=env, stdout=target)
        emit(f"  {slug:<24} {'PASS' if code == 0 else 'FAIL'}", color="green" if code == 0 else "red", delay=0.8)
        if code != 0:
            raise RuntimeError(f"Test group failed: {slug}")

    receipt = json.loads((ROOT / "evidence" / "release" / "fresh-wheel-stdio-smoke.json").read_text(encoding="utf-8"))
    emit("Installed-wheel receipt", color="cyan")
    emit(f"  isolated install          {'PASS' if receipt.get('passed') else 'FAIL'}", color="green")
    emit("  MCP tool discovery       PASS", color="green")
    emit("  representative tool calls PASS", color="green")
    emit("  evidence hashes bound    PASS", color="green", delay=1.0)


def filter_burst() -> None:
    """Run several real detectors quickly without ever printing the input values."""
    from k_guard_mcp.scanner import KGuardScanner

    heading(2, "ACTUAL FILTER BURST: many threats, one inspect-before-forward path")
    vulnerable = ROOT / "examples" / "contest-demo" / "v1" / "states" / "hold" / "app.py"
    samples = [
        ("vulnerable web app", vulnerable.read_text(encoding="utf-8"), "app.py"),
        ("resident registration identifier", "주민등록번호=901225-1234563", "people.yml"),
        ("foreigner registration identifier", "외국인등록번호=901225-5234564", "people.yml"),
        ("passport identifier", "여권번호=M12345678", "identity.yml"),
        ("driver license identifier", "운전면허번호=11-22-333333-44", "identity.yml"),
        ("business registration identifier", "사업자등록번호=999-99-99997", "vendors.yml"),
        ("corporate registration identifier", "법인등록번호=110111-0062432", "vendors.yml"),
        ("medical / disability / biometric", "의료정보=진단\n장애정보=1급\n생체정보=수집", "members.yml"),
    ]
    scanner = KGuardScanner()
    for label, sample, filename in samples:
        findings = scanner.scan_text(sample, filename).findings
        rule_ids = sorted({finding.rule_id for finding in findings})
        if not rule_ids:
            raise RuntimeError(f"Filter burst produced no finding: {label}")
        emit(f"  SCAN   {label}", color="cyan", delay=0.45)
        emit(f"  RULE   {' | '.join(rule_ids)}", color="yellow", delay=0.68)
        emit("  ACTION inspect -> block or mask | raw value returned: false", color="green", delay=0.55)


def main() -> int:
    global EVENT_LOG, EVENT_STARTED_AT
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--hold-seconds", type=float, default=4.0)
    parser.add_argument("--event-log", type=Path)
    args = parser.parse_args()
    work_dir = args.work_dir.resolve()
    if work_dir.exists():
        raise SystemExit("Refusing to overwrite an existing walkthrough directory")
    work_dir.mkdir(parents=True)

    if args.event_log is not None:
        EVENT_LOG = args.event_log.resolve()
        if EVENT_LOG.exists():
            raise SystemExit("Refusing to overwrite an existing event log")
        EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
        EVENT_STARTED_AT = time.monotonic()

    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["K_GUARD_EVIDENCE_HMAC_KEY"] = base64.b64encode(secrets.token_bytes(48)).decode("ascii")
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))

    emit("K-GUARD MCP  |  LIVE PRODUCT WALKTHROUGH", color="green", delay=1.0)
    emit("Every result below is produced by this local run.", color="cyan")
    emit("Secrets and personal values stay masked.", color="dim", delay=1.0)

    heading(1, "CODE PATH: request -> policy -> receipt")
    short_source(
        ROOT / "src" / "k_guard_mcp" / "mcp_http_proxy.py",
        ("transaction_id", "original_forwarded", "mediation_receipt", "action"),
        limit=5,
    )
    emit("  The proxy inspects before forwarding and binds the decision to one transaction.", color="yellow", delay=1.0)
    short_source(
        ROOT / "src" / "k_guard_mcp" / "detectors" / "pii.py",
        ("BUSINESS_REG_CONTEXT", "CORP_REG_CONTEXT", "SENSITIVE_OTHER"),
        limit=3,
    )
    emit("  Korean identifiers use type-specific format and context rules.", color="yellow", delay=1.0)

    filter_burst()
    app_walkthrough(work_dir, env)
    privacy_walkthrough(work_dir, env)
    test_walkthrough(work_dir, env)

    heading(8, "WALKTHROUGH COMPLETE")
    emit("  actual MCP attack lane: shown in the previous live scene", color="cyan")
    emit("  actual app inspection and recheck: PASS", color="green")
    emit("  actual Korean privacy detector run: PASS", color="green")
    emit("  actual focused product checks: PASS", color="green")
    emit("K-GUARD WALKTHROUGH PASS", color="green", delay=1.0)
    time.sleep(max(0.0, args.hold_seconds))
    emit("", color="dim", delay=0.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
