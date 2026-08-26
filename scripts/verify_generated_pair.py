from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from k_guard_mcp.pair_evidence import (
    PairEvidenceError,
    load_canonical_json,
    verify_pair_evidence,
    write_new_json,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay a generated vulnerable/fixed pair in the locked Docker verifier."
    )
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manifest = load_canonical_json(args.manifest, label="pair manifest")
        plan = load_canonical_json(args.plan, label="verification plan")
        result = verify_pair_evidence(args.bundle_root, manifest, plan)
        write_new_json(args.output, result)
    except (FileExistsError, OSError, PairEvidenceError, ValueError) as exc:
        print(f"verify_generated_pair: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
