from __future__ import annotations

import json
from pathlib import Path

from k_guard_mcp.scanner import KGuardScanner


NAMES = ["홍길동", "김철수", "이영희", "박민준", "최서연", "정도윤", "강하은", "조현우", "윤지아", "임서준"]
DOMAINS = ["example.com", "example.co.kr", "sample.kr", "test.local", "mail.example"]
AREAS = ["서울특별시 강남구", "부산광역시 해운대구", "대구광역시 수성구", "인천광역시 연수구", "광주광역시 북구"]


def main() -> int:
    scanner = KGuardScanner()
    positives = _positive_cases()
    negatives = _negative_cases()
    positive_hits = 0
    positive_results = []
    for case in positives:
        result = scanner.scan_text(case["text"], case["file"])
        rules = sorted({finding.rule_id for finding in result.findings})
        passed = any(rule in rules for rule in case["expected_any"])
        positive_hits += int(passed)
        positive_results.append({"name": case["name"], "passed": passed, "expected_any": case["expected_any"], "rules": rules})

    false_positive_cases = 0
    negative_results = []
    for case in negatives:
        result = scanner.scan_text(case["text"], case["file"])
        rules = sorted({finding.rule_id for finding in result.findings})
        passed = not rules
        false_positive_cases += int(bool(rules))
        negative_results.append({"name": case["name"], "passed": passed, "rules": rules})

    recall = positive_hits / len(positives)
    false_positive_rate = false_positive_cases / len(negatives)
    report = {
        "positive_count": len(positives),
        "negative_count": len(negatives),
        "recall": recall,
        "false_positive_rate": false_positive_rate,
        "thresholds": {"minimum_recall": 0.95, "maximum_false_positive_rate": 0.05},
        "passed": recall >= 0.95 and false_positive_rate <= 0.05,
        "positives_sample": positive_results[:20],
        "negatives_sample": negative_results[:20],
    }
    Path("synthetic-korean-corpus-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


def _positive_cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    for idx in range(250):
        name = NAMES[idx % len(NAMES)]
        phone = f"010-{1000 + idx % 9000:04d}-{2000 + idx % 7000:04d}"
        cases.append({"name": f"person_phone_{idx}", "file": "synthetic.csv", "text": f"name,phone\n{name},{phone}\n", "expected_any": ["KR_COMBO_PERSON_PHONE"]})
    for idx in range(150):
        name = NAMES[idx % len(NAMES)]
        email = f"user{idx}+kr@{DOMAINS[idx % len(DOMAINS)]}"
        cases.append({"name": f"person_email_{idx}", "file": "synthetic.csv", "text": f"name,email\n{name},{email}\n", "expected_any": ["KR_COMBO_PERSON_EMAIL"]})
    for idx in range(100):
        name = NAMES[idx % len(NAMES)]
        address = f"{AREAS[idx % len(AREAS)]} 테스트로 {idx + 1}"
        cases.append({"name": f"person_address_{idx}", "file": "synthetic.csv", "text": f"name,address\n{name},{address}\n", "expected_any": ["KR_COMBO_PERSON_ADDRESS"]})
    return cases


def _negative_cases() -> list[dict[str, object]]:
    return [
        {"name": f"negative_{idx}", "file": "synthetic.txt", "text": f"release note item {idx}: UI copy and sample code without identifiers"}
        for idx in range(100)
    ]


if __name__ == "__main__":
    raise SystemExit(main())
