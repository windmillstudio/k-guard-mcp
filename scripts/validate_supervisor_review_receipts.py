from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from k_guard_mcp.supervisor_reviews import canonical_json_bytes, evaluate_supervisor_review_receipts


def _load_canonical(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("supervisor review receipt input must be UTF-8 JSON") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError("supervisor review receipt input must use canonical JSON")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail-closed validation for cross-provider supervisor review receipts."
    )
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    try:
        decision = evaluate_supervisor_review_receipts(_load_canonical(args.receipts))
    except ValueError as exc:
        raise SystemExit(f"HOLD: {exc}") from exc
    print(json.dumps(decision, ensure_ascii=False, sort_keys=True))
    return 0 if decision["status"] == "FIX" else 2


if __name__ == "__main__":
    raise SystemExit(main())
