from __future__ import annotations

import json
from pathlib import Path


MIN_ADVERSARIAL = 45
MIN_KOREAN_POSITIVES = 25
MIN_KOREAN_NEGATIVES = 15


def main() -> int:
    adversarial = json.loads(Path("tests/fixtures/adversarial_redaction_corpus.json").read_text(encoding="utf-8"))
    korean = json.loads(Path("tests/fixtures/korean_fixture_corpus.json").read_text(encoding="utf-8"))
    errors = []
    errors.extend(_unique_names("adversarial", adversarial))
    errors.extend(_unique_names("korean_positive", korean["positives"]))
    errors.extend(_unique_names("korean_negative", korean["negatives"]))
    if len(adversarial) < MIN_ADVERSARIAL:
        errors.append(f"adversarial corpus below minimum: {len(adversarial)} < {MIN_ADVERSARIAL}")
    if len(korean["positives"]) < MIN_KOREAN_POSITIVES:
        errors.append(f"korean positives below minimum: {len(korean['positives'])} < {MIN_KOREAN_POSITIVES}")
    if len(korean["negatives"]) < MIN_KOREAN_NEGATIVES:
        errors.append(f"korean negatives below minimum: {len(korean['negatives'])} < {MIN_KOREAN_NEGATIVES}")
    for case in adversarial:
        if not case.get("raw") or not case.get("forbidden"):
            errors.append(f"adversarial case missing raw/forbidden: {case.get('name')}")
    for case in korean["positives"]:
        if not case.get("expected_any"):
            errors.append(f"korean positive missing expected_any: {case.get('name')}")

    report = {
        "adversarial_count": len(adversarial),
        "korean_positive_count": len(korean["positives"]),
        "korean_negative_count": len(korean["negatives"]),
        "minimums": {
            "adversarial": MIN_ADVERSARIAL,
            "korean_positives": MIN_KOREAN_POSITIVES,
            "korean_negatives": MIN_KOREAN_NEGATIVES,
        },
        "errors": errors,
        "passed": not errors,
    }
    Path("corpus-governance-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


def _unique_names(label: str, cases: list[dict[str, object]]) -> list[str]:
    names = [str(case.get("name")) for case in cases]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    return [f"{label} duplicate names: {', '.join(duplicates)}"] if duplicates else []


if __name__ == "__main__":
    raise SystemExit(main())
