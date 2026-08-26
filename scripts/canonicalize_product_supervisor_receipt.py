from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from k_guard_mcp.product_hardening_receipts import (
    canonical_json_bytes,
    canonicalize_actual_supervisor_receipt_file,
    validate_canonical_supervisor_receipt,
)


def _write_new(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(canonical_json_bytes(payload))
    except FileExistsError as exc:
        raise ValueError("output already exists; receipts are append-only") from exc


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Canonicalize one observed K-Guard supervisor receipt without inventing missing evidence."
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-label")
    args = parser.parse_args()

    try:
        receipt = canonicalize_actual_supervisor_receipt_file(
            args.source.resolve(strict=True),
            source_path=args.source_label,
        )
        validate_canonical_supervisor_receipt(receipt, require_phase_review=False)
        _write_new(args.output.resolve(), receipt)
    except (OSError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "schema": "k_guard_control_error.v1",
                    "status": "HOLD",
                    "error": str(exc),
                    "raw_returned": False,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2

    print(
        json.dumps(
            {
                "schema": "k_guard_canonicalization_result.v1",
                "status": "PASS",
                "output": str(args.output.resolve()),
                "product_gate_admissible": receipt["validation"]["product_gate_admissible"],
                "failure_reasons": receipt["validation"]["failure_reasons"],
                "raw_returned": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
