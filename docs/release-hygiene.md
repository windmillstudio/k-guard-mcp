# Release Hygiene

This document defines how to read a K-Guard release-candidate worktree before it is committed, tagged, or published.

## Goal

Release cleanup should make the worktree explainable:

- Source, tests, docs, workflows, datasets, benchmark templates, and root evidence reports are allowed release-candidate changes.
- Runtime scratch output such as `tmp/`, terminal captures, caches, coverage files, local SARIF exports, and local self-scan JSON should not appear in `git status`.
- The tracking lane must remain valid JSONL.
- `pyproject.toml` and `src/k_guard_mcp/__init__.py` must agree on the package version.
- Package build inputs must be byte-identical to their Git index blobs at the strict boundary, including line endings.
- A release tag must exactly equal `v{project.version}`.
- A publish or tag step should use a clean worktree after the intended release commit is created.

## Local Check

```bash
python scripts/release_hygiene.py
python scripts/release_hygiene.py --json
python scripts/release_hygiene.py --strict-clean
python scripts/release_hygiene.py --strict-clean --expected-tag v0.1.0
```

Default mode is for an in-progress release candidate. It passes only when dirty entries are in release-candidate categories and `generated_noise`, `review_required_artifact`, and `unclassified` are all absent.

`--strict-clean` is for the final publish boundary. It fails unless the worktree is clean and package build input bytes match the Git index. This catches Windows clean-filter cases where `git status` is empty but a wheel would contain CRLF bytes different from the committed LF blobs.

## Included Categories

- `release_root`: project metadata such as `.gitignore`, `README.md`, `pyproject.toml`, and license files.
- `release_source`: source code, tests, scripts, docs, workflows, tracking, datasets, and benchmark templates.
- `root_evidence_report`: curated JSON evidence reports kept at repository root.
- `release_evidence`: hash-bound evidence records under `evidence/`.
- `release_submission`: contest report, recordings, rights record, and media under `submission/`.
- `review_required_artifact`: Markdown, CSV, JSON, or JSONL files outside the standard source folders. These are blocking, not a tolerated bucket. The hygiene check will not pass until they are moved into a release source folder, promoted into a curated root evidence report, or ignored as runtime output.

## Excluded Runtime Output

The repository ignores these by default:

- `.coverage`
- `.pytest_cache/`
- `.ruff_cache/`
- `.mypy_cache/`
- `tmp/`
- `terminals/`
- `k-guard.sarif`
- `k-guard-self-scan.json`

These files can exist locally, but they should not be part of the release candidate unless they are intentionally promoted into a documented evidence artifact.

## Release Candidate Rule

Before asking for CTO review, run:

```bash
python scripts/release_hygiene.py --json
python -m pytest -q
```

Before tagging or publishing, run:

```bash
python scripts/release_hygiene.py --strict-clean --expected-tag v0.1.0
python -m pytest -q
```

If `--strict-clean` fails only because intended files are still uncommitted, create the release commit first and rerun it.

The `.github/workflows/release.yml` workflow waits for the reusable three-OS CI matrix before building. It runs the same strict-clean check for tags and manual verification, requires exact tag/version identity for `v*`, installs Semgrep and pip-audit from separate hashed locks, creates Sigstore attestations, and publishes successful tag artifacts as an immutable GitHub Release. A manual run builds and verifies artifacts but does not publish a release.

## Reproducible Artifacts

The release workflow pins the build frontend and backend with `requirements-build.lock`, derives `SOURCE_DATE_EPOCH` from the release commit, and builds the wheel and sdist twice. Setuptools already applies the epoch to wheel ZIP entries, but its sdist command can retain current-time directory and `egg-info` metadata. `scripts/normalize_sdist.py` therefore validates and repacks each sdist with fixed timestamps, ownership, modes, ordering, and gzip metadata before the two artifact hashes are compared.

```bash
export SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
python -m build --no-isolation --outdir dist-first
python scripts/normalize_sdist.py dist-first/*.tar.gz
rm -rf build src/*.egg-info
python -m build --no-isolation --outdir dist-second
python scripts/normalize_sdist.py dist-second/*.tar.gz
python scripts/verify_reproducible_builds.py --first dist-first --second dist-second
```

Normalization rejects absolute paths, parent traversal, duplicate names, links, devices, and every other non-regular archive member. It writes beside the artifact and replaces the original only after the normalized archive can be reopened and validated.
