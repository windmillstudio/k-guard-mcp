from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import quote
from urllib.request import Request, urlopen

from k_guard_mcp.release_policy import RELEASE_BLOCKING_POLICY, release_lane
from k_guard_mcp.scanner import KGuardScanner


SCHEMA = "k_guard_mcp_config_development_calibration.v1"
MAX_SOURCE_BYTES = 2 * 1024 * 1024
DISCOVERY_QUERIES = (
    "alwaysAllow language:JSON",
    "mcpServers npx language:JSON",
    "mcpServers http language:JSON",
    "git+https mcp language:JSON",
)
CALIBRATION_RULES = frozenset(
    {
        "MCP_AUTOMATIC_TOOL_APPROVAL",
        "MCP_INSECURE_REMOTE_TRANSPORT",
        "MCP_MUTABLE_GIT_SOURCE",
        "MCP_PRIVILEGED_CONTAINER_SURFACE",
        "MCP_STATIC_CREDENTIAL_IN_CONFIG",
        "MCP_UNPINNED_PACKAGE_EXECUTION",
    }
)
SUBTYPE_PATTERN = re.compile(r"\bdetector_subtype=([^\s;]+)")


@dataclass(frozen=True)
class PublicSource:
    repository: str
    commit: str
    path: str
    blob_sha1: str
    discovery_query: str

    @property
    def source_url(self) -> str:
        encoded_path = quote(self.path, safe="/._-@")
        return f"https://github.com/{self.repository}/blob/{self.commit}/{encoded_path}"

    @property
    def raw_url(self) -> str:
        encoded_path = quote(self.path, safe="/._-@")
        return f"https://raw.githubusercontent.com/{self.repository}/{self.commit}/{encoded_path}"


SOURCES = (
    PublicSource("JCMais/node-libcurl", "332acfd65220553412194c8552bd965611dc41b1", ".mcp.json", "cdc788db0f445936492e51ebf7899da63bb9011d", DISCOVERY_QUERIES[0]),
    PublicSource("elusznik/mcp-server-code-execution-mode", "27d23b8e2c7666c442708d02dbe4e838e9a63038", ".kilocode/mcp.json", "d10b58f55d2a9e8d51cfdefccd1347d6d7164360", DISCOVERY_QUERIES[0]),
    PublicSource("ruvnet/dynamo-mcp", "4eaf6b54e35d063af20f4afb620130d6269eed24", "@mcp.json", "db8b81d983e1b13fb1715bd6ee9c7cb699cff7d1", DISCOVERY_QUERIES[0]),
    PublicSource("imdbcooper/Quartz", "60352bbf9b606a76e25a4aa49ef7f316cd273886", ".kilocode/mcp.example.json", "e076ff7aa7b2c55f137a3ba2066af87149b2f66b", DISCOVERY_QUERIES[0]),
    PublicSource("growilabs/growi-mcp-server", "ec715c4271798328f0fafde63040921bf7bf5b1c", ".roo/mcp.json", "edcc24b59639a340a834cb498bf8a627f006b36c", DISCOVERY_QUERIES[0]),
    PublicSource("Automattic/wp-calypso", "188b4cd6e0189a70728112e00371d1d09b18c238", ".mcp.json", "b7edcd69f5fff5bfd76be6b8278d1b5d56c88fa2", DISCOVERY_QUERIES[1]),
    PublicSource("vybenetwork/solana-mcp-vybe", "94acd3b8d3d3162618c78fa12fadab2f75855252", "mcp.json", "14409cb39e1b962234a33f348170ab7eeda4a7fc", DISCOVERY_QUERIES[1]),
    PublicSource("willianpinho/large-file-mcp", "5d99a44b1e1e6b08c6b4794a9f74c1023574a323", ".mcp.json", "eacaa6be392a6d12aaa9e5228436b7921d7d146d", DISCOVERY_QUERIES[1]),
    PublicSource("messiaspichaujr/newshoes-gatsby", "1acaccc0fadd886c89e820efb4510146264a77af", ".mcp.json", "c4492e137e11fbb5f684a6e6ea342c73d4971416", DISCOVERY_QUERIES[1]),
    PublicSource("jparksecurity/resync-mcp-client", "d3b3e6ddf2c16e86cc6021f3d8c13ea81322826b", "mcp.json", "3eb12d2496cf06087cb359bd522909361c110a23", DISCOVERY_QUERIES[1]),
    PublicSource("leandrowylde/finawise", "ebcc16949689fcbe7e0ad75e10ce94028c3ac7aa", "mcp.json", "dde7ac289eb8ba73ab24e92cb9f668713f678733", DISCOVERY_QUERIES[1]),
    PublicSource("emilykelt/revisionThing", "27fe5c5c2975292c2d834ae88762fcfa79f300ad", ".mcp.json", "609e88595406e1b5d27f808ea1960ffcde8d25f8", DISCOVERY_QUERIES[1]),
    PublicSource("crgarcia12/microhack-dashboard", "328ab34dda9828deae5afe698c05ea73a93bfc7c", ".mcp.json", "0d1731357037dca05b95f65599a806169fb32d26", DISCOVERY_QUERIES[1]),
    PublicSource("damiant/movies-angular-demo", "01102b60a525f5c2b12d81826fd6e5e103a5aebc", "mcp.json", "d1cdeeb16f62ab698c2de91e475778b197463095", DISCOVERY_QUERIES[1]),
    PublicSource("brontolano/ERP-Pesantren", "753814d11c784a5e583508dcea1505ba69ea5bef", "MCP.json", "a78ac41bb144f3a1a6f154219114673a3dba9914", DISCOVERY_QUERIES[1]),
    PublicSource("New1Direction/korgex", "8a09d96808b31f1a4a14e4ce767be2f428f53114", "mcp.json", "bc3cb582b626c6dbd3aba998d834ed9fbcb6229a", DISCOVERY_QUERIES[1]),
    PublicSource("MDGrey33/claude_mind", "303e9b0d30de1ce60fe3f7a6d9d96535d374ef48", ".mcp.json", "cc10b86350aab104168036ce2f647f15e02b122c", DISCOVERY_QUERIES[1]),
    PublicSource("sks17/PaperPigeon", "8ca2339322941cf457a6cbda6bc00fce00d445db", ".mcp.json", "179f9b35be639244f1ca5dbeb452c437bda9b11b", DISCOVERY_QUERIES[2]),
    PublicSource("leeroybrun/edison", "bcc29518ea57d54f66e141a758ea3bc6e5343ce0", ".mcp.json", "bc89351ef5563158f0e35ab3741a19fa10d618b1", DISCOVERY_QUERIES[2]),
    PublicSource("kurrent-io/KurrentDB", "67a6419ef9d5b8dc5496722f3dd3f7b5e5d54f8a", ".mcp.json", "1d5b8ab728116a32560e0730048ff24f4bad1732", DISCOVERY_QUERIES[3]),
    PublicSource("microsoft-foundry/mcp-foundry", "93bc2600ad0e65f6aac4de319347236be8bed580", "mcp.json", "977753b66dd83edca4cf9fb9a9c0dfd7d081fce5", DISCOVERY_QUERIES[3]),
    PublicSource("hospitaljobsin/hospitaljobsin", "5133e176588ac27d106c375a504c051cae616618", ".mcp.json", "448f0c3f723509ad97d3149fefb25b66735012a0", DISCOVERY_QUERIES[3]),
    PublicSource("Baragji/rapport-assistent", "6dcd6c3ccdda9b30af899679c1caa73118dd1790", "mcp.json", "bef356cdce015f0ffbfcee1c07ec32bd7352906e", DISCOVERY_QUERIES[3]),
    PublicSource("zsembek/Cube.js-MCP-server", "776c96332cdc4f0492e534697db45aa5c00c6055", "config.json", "553bcaab4b2df7ed2d6a95825e2a099cae04c96a", DISCOVERY_QUERIES[3]),
    PublicSource("ng/claude-sandbox", "2a9e1eee40066e73f6d935c68213f3a4be54c072", "claude.json", "387afbcd7ad41a1e6346f8959ab5058fe73a6a3f", DISCOVERY_QUERIES[3]),
    PublicSource("zerlake/thesisai-philippines", "8bbb66290fdcf4d2641d7806e5f7a8a54b9395c6", "amp.json", "c3bf09f2c488b892dfd1a2278763d51f56e881dc", DISCOVERY_QUERIES[3]),
    PublicSource("aegntic/DAILYDOCO", "9c95abe001f99b1ca0ab892768b2ab4cb424ae3e", ".mcp.json", "b9af1d3b345f798fb2f6ae19be507dc9e6034892", DISCOVERY_QUERIES[3]),
    PublicSource("chirag127/agent-mcps", "34d079f430ce3a8ba73f0a7bb5b5680b488eba74", "mcps.json", "d570856028804a368dd63b374268169642549de5", DISCOVERY_QUERIES[3]),
    PublicSource("Tommi2Day/symcon-mcp-server", "a093a2429f577dc4b24ab2e38d308f79978e93bb", "mcp.json", "2bde1d82f9259c735401b01aa85e17e75a2e64e7", DISCOVERY_QUERIES[2]),
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _git_blob_sha1(value: bytes) -> str:
    prefix = f"blob {len(value)}\0".encode("ascii")
    return hashlib.sha1(prefix + value, usedforsecurity=False).hexdigest()


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _analyzer_contract() -> dict[str, str]:
    root = Path(__file__).resolve().parents[1]
    relative_paths = (
        "src/k_guard_mcp/detectors/mcp_threat.py",
        "src/k_guard_mcp/release_policy.py",
        "src/k_guard_mcp/scanner.py",
        "scripts/mcp_config_development_calibration.py",
    )
    hashes = {relative: _sha256_file(root / relative) for relative in relative_paths}
    hashes["contract_sha256"] = _sha256_bytes(_canonical_json(hashes).encode("utf-8"))
    return hashes


def fetch_public_source(source: PublicSource, timeout_seconds: float = 30.0) -> bytes:
    request = Request(source.raw_url, headers={"User-Agent": "k-guard-development-calibration/1"})
    with urlopen(request, timeout=timeout_seconds) as response:
        payload = response.read(MAX_SOURCE_BYTES + 1)
    if len(payload) > MAX_SOURCE_BYTES:
        raise ValueError(f"source exceeds {MAX_SOURCE_BYTES} bytes: {source.repository}:{source.path}")
    return payload


def build_calibration(
    sources: tuple[PublicSource, ...] = SOURCES,
    fetcher: Callable[[PublicSource], bytes] = fetch_public_source,
) -> dict[str, object]:
    if not sources:
        raise ValueError("at least one public source is required")
    repositories = [source.repository for source in sources]
    source_keys = [(source.repository, source.commit, source.path) for source in sources]
    if len(repositories) != len(set(repositories)) or len(source_keys) != len(set(source_keys)):
        raise ValueError("development calibration sources must use unique repositories and source keys")

    scanner = KGuardScanner()
    rows: list[dict[str, object]] = []
    source_records: list[dict[str, object]] = []
    for source in sources:
        payload = fetcher(source)
        actual_blob_sha1 = _git_blob_sha1(payload)
        if actual_blob_sha1 != source.blob_sha1:
            raise ValueError(
                f"Git blob mismatch for {source.repository}:{source.path}; "
                f"expected {source.blob_sha1}, got {actual_blob_sha1}"
            )
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError(f"source is not UTF-8 text: {source.repository}:{source.path}") from exc

        source_sha256 = _sha256_bytes(payload)
        findings = scanner.scan_text(text, source.path).findings
        selected = [finding for finding in findings if finding.rule_id in CALIBRATION_RULES]
        source_records.append(
            {
                **asdict(source),
                "source_url": source.source_url,
                "source_bytes": len(payload),
                "source_sha256": source_sha256,
                "calibration_finding_count": len(selected),
                "raw_returned": False,
            }
        )
        source_lines = text.splitlines()
        occurrences: Counter[tuple[int, str, str]] = Counter()
        for finding in selected:
            line = int(finding.line_start or 0)
            if line <= 0 or line > len(source_lines):
                raise ValueError(f"finding lacks a valid source line: {source.repository}:{source.path}")
            subtype_match = SUBTYPE_PATTERN.search(finding.evidence or "")
            subtype = subtype_match.group(1) if subtype_match else str(finding.source or "unknown")
            occurrence_key = (line, finding.rule_id, subtype)
            occurrences[occurrence_key] += 1
            occurrence_index = occurrences[occurrence_key]
            identity = {
                "repository": source.repository,
                "commit": source.commit,
                "path": source.path,
                "line": line,
                "rule_id": finding.rule_id,
                "detector_subtype": subtype,
                "source_sha256": source_sha256,
                "occurrence_index": occurrence_index,
            }
            fingerprint = _sha256_bytes(_canonical_json(identity).encode("utf-8"))
            rows.append(
                {
                    "candidate_id": fingerprint[:20],
                    "redacted_fingerprint": f"sha256-truncated:{fingerprint[:20]}",
                    "repository": source.repository,
                    "commit": source.commit,
                    "source_url": source.source_url,
                    "source_location": f"{source.path}:{line}",
                    "source_file_sha256": source_sha256,
                    "source_line_sha256": _sha256_bytes(source_lines[line - 1].encode("utf-8")),
                    "occurrence_index": occurrence_index,
                    "rule_id": finding.rule_id,
                    "detector_subtype": subtype,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "artifact_scope": finding.artifact_scope,
                    "release_lane": release_lane(finding, "high"),
                    "manual_label": "unreviewed",
                    "raw_returned": False,
                }
            )

    rows.sort(key=lambda row: (str(row["repository"]), str(row["source_location"]), str(row["rule_id"])))
    source_records.sort(key=lambda row: str(row["repository"]).casefold())
    rule_counts = Counter(str(row["rule_id"]) for row in rows)
    lane_counts = Counter(str(row["release_lane"]) for row in rows)
    scope_counts = Counter(str(row["artifact_scope"]) for row in rows)
    candidate_ids = [str(row["candidate_id"]) for row in rows]
    checks = {
        "all_source_blobs_verified": len(source_records) == len(sources),
        "all_sources_unique": len(source_keys) == len(set(source_keys)),
        "all_candidates_source_bound": all(
            len(str(row["source_file_sha256"])) == 64 and len(str(row["source_line_sha256"])) == 64
            for row in rows
        ),
        "candidate_ids_unique": len(candidate_ids) == len(set(candidate_ids)),
        "multiple_rules_observed": len(rule_counts) >= 4,
        "raw_source_omitted": all(row["raw_returned"] is False for row in rows + source_records),
    }
    return {
        "schema": SCHEMA,
        "evidence_role": "public_development_policy_calibration",
        "release_blocking_policy": RELEASE_BLOCKING_POLICY,
        "analyzer_contract": _analyzer_contract(),
        "source_discovery": {
            "queries": list(DISCOVERY_QUERIES),
            "selection": "Purposive public MCP-configuration development sample, fixed before this replay by repository commit and Git blob SHA-1.",
            "source_count": len(source_records),
            "repository_count": len(set(repositories)),
        },
        "population": {
            "candidate_count": len(rows),
            "candidate_repository_count": len({str(row["repository"]) for row in rows}),
            "rule_counts": dict(sorted(rule_counts.items())),
            "lane_counts": dict(sorted(lane_counts.items())),
            "artifact_scope_counts": dict(sorted(scope_counts.items())),
        },
        "checks": checks,
        "sources": source_records,
        "rows": rows,
        "holdout_exclusions": sorted(set(repositories), key=str.casefold),
        "claim_boundary": {
            "independent_holdout": False,
            "manually_adjudicated": False,
            "qualifies_release_policy": False,
            "proves_precision_recall_or_prevalence": False,
            "reason": "These sources were selected and inspected during rule development. Rows are structural signals with unreviewed labels; every repository is excluded from the next preregistered holdout.",
        },
        "raw_returned": False,
    }


def write_calibration(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay pinned public MCP configurations for development calibration.")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    payload = build_calibration()
    write_calibration(args.output, payload)
    return 0 if all(payload["checks"].values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
