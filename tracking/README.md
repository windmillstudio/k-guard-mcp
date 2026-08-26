# Improvement Tracking

This directory is the append-only tracking lane for commercial hardening work.

## Rules

- Record each meaningful improvement in `improvements.jsonl`.
- Keep one JSON object per line.
- Include changed files, reason, verification, and reviewer impact when known.
- Use `git diff` before and after each implementation batch.
- Do not put raw secrets, raw PII, partner data, or unsanitized findings in tracking entries.

## Recommended Commands

```bash
git status --short
git diff -- src tests docs README.md pyproject.toml
python scripts/release_hygiene.py --json
python -m pytest -q
```

For this repository, generated runtime caches and scratch directories are ignored by `.gitignore`; report artifacts such as SBOM, audit, benchmark, and corpus metrics remain trackable. New loose Markdown/CSV/JSON/JSONL artifacts outside the documented source and evidence lanes are blocking until they are moved, promoted, or ignored. Use `python scripts/release_hygiene.py --strict-clean` only after the intended release commit has been created.
