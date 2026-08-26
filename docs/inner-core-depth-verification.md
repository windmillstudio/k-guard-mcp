# K-Guard Inner Core Depth Verification

검증일: 2026-07-06 KST

> 역사적 기준선 문서입니다. 아래 `Current Depth By Domain`과 외부 CTO 표는 2026-07-06 당시 판정이며 현재 릴리스 상태를 설명하지 않습니다. 현재 제품 계약은 `k-guard-review-verdict-ko.md`, `guardian-mode-ko.md`, `pre-release-auditor-hardening-plan-ko.md`를 우선합니다.

목적: K-Guard MCP가 사용자가 말한 "지구 내핵까지 파고드는 감사기" 수준인지, 아니면 아직 표층/맨틀/외핵 단계인지 외부 CTO 역할 검수와 Codex 자체 검토로 판정한다.

## 결론

현재 K-Guard MCP는 모든 영역에서 내핵 감사기(L5)가 아니다.

정직한 현재 표현은 다음이 맞다.

> 표층 스캐너는 넘었고, 일부 영역은 맨틀을 지나 외핵까지 들어간다. 하지만 코드, 런타임, DB, 로그, 외부 전송, LLM/MCP tool, 보존/삭제까지 이어지는 전 구간을 권한 있는 증거로 닫는 내핵 감사기는 아직 아니다.

상용 제출 문구에서는 "ultimate auditor completed"가 아니라 "local-first Korean privacy and MCP audit platform with raw-free evidence graph, CI/SARIF, dynamic verification, and a roadmap to inner-core audit depth"라고 표현해야 한다.

## Depth Scale

| Level | 이름 | 의미 |
| --- | --- | --- |
| L0 | 미검사 | 해당 영역을 보지 않는다. |
| L1 | 표층 | 파일명, 경로, 헤더, 단순 문자열 같은 marker 위주로 본다. |
| L2 | 얕은 맨틀 | 알려진 패턴, 설정, route, schema, source map, rule pack을 본다. |
| L3 | 깊은 맨틀 | 여러 증거를 연결해서 "어디서 수집되어 어디로 흐르는지"를 추론한다. |
| L4 | 외핵 | 실행 중인 앱, 응답, CI/SARIF, evidence hash처럼 직접 검증 가능한 증거가 있다. |
| L5 | 내핵 | 코드, 런타임, 저장소, 로그, 외부 전송, LLM/MCP tool, 보존/삭제를 raw-free evidence graph로 end-to-end 연결하고, 오탐/미탐 지표까지 측정한다. |

## External CTO Review

| Reviewer | 판정 | 요약 |
| --- | --- | --- |
| Grok | 내핵 아님 | 전체는 L3, 일부 evidence/CI는 L4. AST taint, runtime MCP proxy, authenticated session, DB/log/storage, retention/deletion, Korean PII to MCP/LLM sink 결합이 부족하다고 판정. |
| GLM | 내핵 아님 | 응답은 timeout으로 완전 JSON은 못 받았지만, 내용상 L3 중심에 일부 L4가 있다고 판단. DB/log/retention/session/runtime MCP/AST/metrics 부재를 핵심 gap으로 지적. |
| Antigravity | 내핵 아님 | static code L2, dynamic web L4, privacy compliance L3, MCP threat L2, CI/reporting L5로 평가. 전체는 L3이며 내핵 기준 미달. |
| Codex | 내핵 아님 | 현재 제품은 "감사기"의 방향은 맞지만, 모든 분야를 내핵까지 보는 수준은 아니다. 깊이를 주장하려면 권한 있는 read-only connector와 runtime 관찰 계층이 더 필요하다. |

## 당시 Current Depth By Domain

| Domain | 현재 깊이 | 근거 |
| --- | --- | --- |
| Korean PII/static corpus | L2-L3 | 한국형 개인정보 taxonomy, composite detector, fixture 기반 평가가 있으나 AST 기반 source-to-sink는 아직 약하다. |
| env/API/secret exposure | L2-L3 | 정적 탐지와 redaction/evidence hash는 있으나 실제 secret 사용 경로까지 완전 추적하지는 않는다. |
| Source map/OpenAPI/security headers | L2-L4 | 정적 marker와 안전한 동적 GET/OPTIONS 검증으로 접근 가능 여부를 직접 확인한다. |
| Dynamic web probe | L3-L4 | 사용자가 권한을 확인한 origin에 대해 non-mutating probe를 수행하고 결과를 raw-free evidence로 남긴다. |
| Data flow graph | L3 | source/sink를 휴리스틱으로 연결하지만, runtime trace와 DB/log connector가 없어 end-to-end 확정은 아니다. |
| MCP tool poisoning/hidden instruction/exfiltration | L2-L3 | rule 기반 탐지는 있으나 실제 MCP runtime proxy/interceptor로 tool call을 관찰하지는 않는다. |
| LLM/outbound sink | L2-L3 | agentic sink signal은 있으나 실제 provider 호출, prompt chain, tool result 이동은 runtime에서 잡지 못한다. |
| DB/storage/log/backend | L0-L1 | 아직 전용 read-only connector와 schema/data-flow 검증이 없다. |
| Retention/deletion | L0 | 개인정보 보존 기간, 삭제 API, 로그 잔존 검증은 아직 없다. |
| Evidence/SARIF/CI | L4-L5 | SARIF, partial fingerprint, HMAC evidence hash, CI fail-on contract가 있어 증거화 수준은 높다. |
| FP/FN measurement | L1-L2 | fixture corpus는 있으나 상용 기준의 정량 precision/recall dashboard는 아직 부족하다. |

## 이후 구현된 범위

- batch `mcp-intercept`와 line-delimited stdio JSON-RPC `mcp-proxy` block/redact
- read-only SQLite/log/json/csv/tsv connector와 retention/deletion marker review
- operator-keyed evidence bundle, Guardian 단일 앱·intent·scope·source snapshot 결속
- 지원 후보 인벤토리와 검사 전후 drift 비교, 대용량·미검사 후보 fail-closed
- 별도 validation-source Guardian과 12~20개 앱 TP/FP/FN 수동 라벨 게이트

SSE, Streamable HTTP, binary framing, 원격 DB 정책 증명, 완전한 JS/TS inter-procedural 타입 분석은 여전히 이 문서의 L5 경계 밖이다.

## What Is Needed For L5 Inner Core

1. AST taint analysis: request body, form field, DB row, env, log, outbound call, LLM/MCP tool call까지 source-to-sink를 코드 구조로 추적한다.
2. Runtime MCP observer: MCP server/tool manifest, tool description, 실제 tool call/result 흐름을 local proxy 방식으로 관찰한다.
3. Authenticated session import: 사용자가 제공한 세션으로 read-only 화면/API를 검사하되 form submit, mutation, fuzzing은 하지 않는다.
4. DB/storage/log read-only connectors: SQLite/Postgres/MySQL/Supabase/Firebase/S3/log file을 읽기 전용으로 연결하고 raw는 저장하지 않는다.
5. Retention/deletion verification: 수집된 개인정보가 로그와 저장소에 얼마나 남는지, 삭제 경로가 실제로 존재하는지 확인한다.
6. Cross-plane Korean privacy verdict: "주민번호 후보가 API 응답에 있고, 같은 값 계열이 로그/LLM/MCP tool/external sink로 흐른다"처럼 결합 판정을 만든다.
7. Precision/recall scoreboard: 한국형 fixture corpus와 adversarial corpus로 PII, secret, prompt injection, exfiltration 탐지의 FP/FN을 계속 측정한다.
8. Raw-free evidence graph export: 노드와 edge는 hash, class, route, file, sink, confidence만 저장하고 원문 값은 저장하지 않는다.

## Product Claim Guardrail

지금 말해도 되는 것:

- 한국형 개인정보와 MCP/LLM 흐름을 함께 보는 로컬 우선 감사기
- raw-free evidence hash와 SARIF/CI를 지원하는 상용화 지향 감사 도구
- 동적 웹 검증, 정적 스캔, 설정 스캔, MCP threat rule을 결합한 L3-L4 감사 플랫폼

아직 말하면 안 되는 것:

- 모든 앱을 내핵까지 완전 감사한다
- DB, 로그, LLM, MCP, 외부 전송, 삭제까지 100% 추적한다
- 법적 적합성이나 개인정보보호위원회 인증을 제공한다
- 인증 영역을 사용자 동의 없이 깊게 스캔한다
