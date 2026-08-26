from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from k_guard_mcp import raw_free_evidence


SCHEMA = "k_guard_raw_free_candidate_receipt.v1"


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load_queue(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("candidate queue must be UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("candidate queue must be a JSON object")
    return payload, raw


def build_receipt(queue_path: Path) -> dict[str, Any]:
    queue, queue_raw = _load_queue(queue_path.resolve(strict=True))
    summary = raw_free_evidence.summarize_public_candidate_queue(queue)
    validator = Path(__file__).resolve(strict=True)
    contract = Path(raw_free_evidence.__file__).resolve(strict=True)
    return {
        "schema": SCHEMA,
        "candidate_queue_sha256": _sha256(queue_raw),
        "candidate_queue_schema": queue["schema"],
        "claim_boundary": {
            "proves_candidate_evidence_shape": True,
            "proves_raw_free_output_contract": True,
            "proves_detector_accuracy": False,
            "proves_release_readiness": False,
        },
        "summary": summary,
        "tool_provenance": {
            "contract_module_sha256": _sha256(contract.read_bytes()),
            "validator_sha256": _sha256(validator.read_bytes()),
        },
        "raw_returned": False,
    }


def write_receipt(path: Path, payload: dict[str, Any]) -> None:
    output = path.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite receipt: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(_canonical_bytes(payload).decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and summarize a raw-free public candidate queue")
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = build_receipt(args.queue)
    write_receipt(args.output, receipt)
    print(
        json.dumps(
            {
                "candidate_count": receipt["summary"]["candidate_count"],
                "receipt_sha256": _sha256(args.output.read_bytes()),
                "raw_returned": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
