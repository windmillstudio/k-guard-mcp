# Contributing to K-Guard MCP

K-Guard MCP welcomes fixes, detector rules, Korean privacy cases, framework adapters, documentation, and reproducible field feedback.

## Setup

```bash
python -m venv .venv
python -m pip install -e ".[mcp,dev]"
python -m pytest -q
```

Before opening a pull request:

```bash
python scripts/fixture_metrics.py
python scripts/release_hygiene.py --json
python scripts/dependency_audit.py
git diff --check
```

## Rule changes

Every new or changed detector rule should include:

1. A positive test that reproduces the risky pattern.
2. A negative test for a realistic benign pattern.
3. Raw-free evidence that does not echo source values, credentials, or personal data.
4. A stable rule id, severity, confidence, explanation, recommendation, inspected scope, and uninspected scope.
5. Korean fixture coverage when the rule affects Korean personal data or governance.

Do not add real secrets, personal data, customer source, private URLs, session values, or partner reports to tests or issues. Use unmistakably synthetic fixtures.

## Pull requests

- Keep changes scoped and explain the user-visible behavior.
- Include the commands you ran and their results.
- Describe false-positive and false-negative tradeoffs.
- Update the relevant guide when changing CLI, MCP tools, report contracts, or release gates.
- Do not weaken Guardian or data-release checks only to make a test pass.

## Product language

The project may describe itself as an automated senior-style pre-release auditor. It must not claim to replace human business judgment, legal review, or guarantee defect-free software. Field-accuracy claims require reviewed owned/partner TP/FP/FN data.

See [the product north star](docs/product-north-star-ko.md) and [SECURITY.md](SECURITY.md).
