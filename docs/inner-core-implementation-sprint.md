# Inner-Core Implementation Sprint

작성일: 2026-07-07 KST

## 목표

K-Guard MCP를 단순 표층/맨틀 검사에서 한 단계 끌어올려, 개인정보가 코드, 런타임 MCP event, 로컬 저장소, 동적 응답, LLM/MCP/external sink 사이에서 어떻게 움직일 수 있는지 raw-free evidence로 결합 판정한다.

## 구현된 검사 축

| 축 | 구현 | 현재 깊이 | 한계 |
| --- | --- | --- | --- |
| AST/taint | `src/k_guard_mcp/taint.py` | L4-L5 | Python intra-procedural AST, JS/TS lightweight intra-file taint, 제한적 route-to-service summary를 지원. JS/TS 정밀 AST, 타입 해석, alias-complete import, middleware/RLS 증명은 다음 단계. |
| Runtime MCP observer/proxy | `src/k_guard_mcp/mcp_runtime.py`, `src/k_guard_mcp/mcp_proxy.py`, `src/k_guard_mcp/mcp_http_proxy.py` | L4-L5 | JSONL/JSON 관찰, stdio JSON-RPC와 Streamable HTTP POST/GET SSE/DELETE 전달 전 block/redact. binary·비표준 transport는 제외. |
| Session read-only probe | `SafeHttpProbe` + CLI `probe --session-file` | L4 | GET 요청에만 short-lived exact-origin 세션을 붙이고 identity response digest를 검증함. form submit/mutation 없음. |
| DB/storage/log connector | `src/k_guard_mcp/connectors.py` | L4-L5 for local SQLite/log/storage | 원격 DB, object storage, backup은 아직 미검사. |
| Retention/deletion review | `src/k_guard_mcp/retention.py` | L3 | marker 기반 정적 gap 검사. 실제 삭제 실행이나 backup purge는 미검증. |
| Cross-plane verdict | `src/k_guard_mcp/cross_plane.py` | L5 triage verdict | file/event/project scope correlation. exact record lineage는 live proxy/trace 필요. |
| FP/FN scoreboard | `src/k_guard_mcp/scoreboard.py` + CLI/MCP | L4 | fixture 기준 정량화. 실제 고객 데이터셋 무결성 보증은 아님. |

## 새 CLI

```bash
python -m k_guard_mcp.cli probe http://localhost:3000 --session-file session.headers.json --json
python -m k_guard_mcp.cli observe-mcp --events mcp-events.jsonl --json
python -m k_guard_mcp.cli score-corpus --corpus tests/fixtures/korean_fixture_corpus.json --output fixture-metrics.json --json
```

## 새 MCP tools

- `observe_mcp_events`
- `observe_mcp_event`
- `score_fixture_corpus`

기존 `scan_workspace`는 이제 static/config/PII/MCP threat/rule pack/flow에 더해 local connector, retention/deletion review, cross-plane verdict를 포함한다.

## Raw-free 원칙

- SQLite/log/storage sample 값은 결과에 저장하지 않는다.
- MCP runtime event content는 hash/count/rule만 남긴다.
- 세션 헤더 값은 저장하지 않고 header name/count만 남긴다.
- AST evidence는 source/sink line hash만 남긴다.
- Cross-plane verdict는 scope hash와 rule count만 남긴다.

## 검증

고정 테스트 수와 산출물 해시는 이 역사적 sprint 문서에 복제하지 않는다. 현재 커밋의 pytest, coverage, benchmark, archive, fresh-wheel MCP 근거는 `contest-2026-submission-ko.md`와 release workflow에서만 갱신한다.

## 남은 내핵 작업

1. Full JS/TS AST 또는 tree-sitter 기반 taint.
2. Inter-procedural Python taint.
3. 구현된 Streamable HTTP proxy의 추가 SDK/언어 상호운용과 binary·비표준 transport 경계 검증.
4. Read-only remote connectors for Postgres, Supabase, Firebase, S3, cloud logs.
5. Deletion execution verification and backup purge evidence.
6. Runtime exact lineage instead of order-based event correlation.
7. Project-specific allowlist/baseline UX for reducing known public-contact noise.
