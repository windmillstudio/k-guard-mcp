# Pre-Release Auditor Hardening Plan

## 제품 포지션

K-Guard MCP의 대표 포지션은 "전지전능한 보증서"가 아니라 "출하 전 시니어 감사관 스타일의 privacy/MCP release gate"다.

정확한 표현:

> K-Guard MCP는 바이브코딩 앱을 출하 전에 점검하는 local-first privacy/MCP audit gate다. Guardian release gate는 raw-free evidence, coverage gap, drift, fix plan을 묶어 configured threshold에서 fail-closed로 막는다.

금지 표현:

- 완전한 보안 인증서
- 모든 취약점 탐지
- zero FP/FN
- legal/PIPC compliance guarantee
- runtime MCP 공격 자동 차단
- full JS/TS taint 또는 full app coverage

## 대표 Gate 결정

대표 release gate는 `guardian --fail-on high`와 MCP `guardian_audit(..., fail_on="high")`다.

`security_gate`는 workspace-only quick gate다. 빠른 pre-check로는 유용하지만 HTTP target, MCP runtime export, imported report, drift, coverage gap을 모두 다루지 않으므로 대표 release gate가 아니다.

## 이번에 잠근 계약

- `security_gate`는 invalid threshold, MCP argument budget failure, 잘못된 budget env, missing workspace target, workspace budget failure, scan exception에서 항상 `security_gate.passed=false`를 반환한다.
- `security_gate.execution_contract.coverage_model`은 `workspace_only`로 표시한다.
- `security_gate.security_gate.canonical_release_gate`는 `guardian_audit`로 표시한다.
- 문서와 recommended prompt는 pre-deploy gate에 `guardian_audit(..., fail_on="high")`를 우선 사용하게 바꾼다.
- `mcp-intercept`는 MCP runtime observer의 block/redact decision을 batch event stream에 실제 적용한다. MCP `enforce_mcp_events`는 raw-free report-only 형태로 같은 결정을 보여주며 forwarded event content는 반환하지 않는다.
- JS/TS 룰은 Next.js route/server action, Express IDOR route param, Supabase service-role/RLS hint, Firebase Admin auth boundary heuristic을 추가한다.
- suppression CSV는 app id, audit profile, 현재 source snapshot/review evidence hash, target id, owner, reason, expiry, finding fingerprint가 없으면 fail-closed policy finding으로 gate를 닫는다. 다른 앱·snapshot 재사용, Guardian coverage gap, MCP control-failure rule은 허용하지 않는다.
- `validation-report`는 Guardian 후보와 design-partner manual labels를 app/target/finding 단위로 묶어 TP/FP/FN/benign/inconclusive 비율과 claim status를 낸다. 엄격 field claim은 12-20개의 서로 다른 Guardian `app_id`와 최소 20개 high/critical 후보 수동 판정 전에는 ready를 내지 않는다.
- `data-release-gate`는 `K_GUARD_EVIDENCE_HMAC_KEY`, canonical high Guardian release claim, target-level intent/scope와 source snapshot, 현재 report와 일치하는 operator-keyed evidence bundle, 별도의 primary/repeat validation-source Guardian 원본, ground-truth/review/preregistration 원본, reviewer/custodian 역할 서명, Korean PII fixture/score, CLI `mcp-intercept` report와 실제 forwarded JSONL을 모두 요구한다. 원본으로 field validation을 다시 실행해 역할 서명과 projection을 재검증하고, validation candidate app/target/finding refs와 repeat의 content/bundle/execution attestation/toolchain/manifest/snapshot/candidate multiset도 다시 계산한다. 12~20개 partner 검증 앱은 현재 출하하는 단일 앱과 독립된 성능 근거이며 두 범위를 섞지 않는다. Korean score는 fixture 재계산 결과와, forwarded 파일은 content hash·byte·line·event count와 일치해야 한다. 하나라도 없거나 report-only MCP 관찰만 있으면 fail-closed다.

## 남은 하드닝 작업

### P0. Guardian 중심 제품 경험

- opinionated guardian manifest template: workspace, local HTTP, MCP event export, prior report row를 앱 하나 기준으로 자동 구성한다.
- GitHub Action template: `docs/templates/github-actions/guardian-release-gate.yml`를 제공한다.
- baseline/suppression policy: suppressions must bind app, profile, current release scope, target, owner, reason, expiry, and evidence fingerprint. Coverage/control failure는 suppression 대상이 아니다. CSV 정책과 fail-closed 적용은 구현됐고, UI/PR annotation은 남았다.
- PR annotation/SARIF: top blockers와 fix plan을 PR에서 바로 읽게 한다.

### P1. Runtime MCP enforcement

현재 `observe_mcp_events`와 `observe_mcp_event`는 advisory block/redact decision을 낸다. `mcp-intercept`는 exported/stdio-style batch JSONL에 그 decision을 적용한다.

필요한 것:

- live local MCP proxy/interceptor packaging for common clients
- forwarding 전 `block` decision 강제
- forwarding 전 `redact` decision 적용
- audit log는 raw-free hash/count/rule만 저장
- bypass/allow override에는 owner, reason, expiry 필요

### P1. JS/TS/framework depth

현재 JS/TS taint는 lightweight intra-file에 더해 제한적 route-to-service summary를 지원한다. 완전한 TypeScript 타입 해석, alias-complete import, middleware auth 증명은 아직 다음 단계다.

우선순위:

- Next.js route handler/server action source-to-sink
- Express/FastAPI request body/query/header to log/response/external sink
- Supabase/Firebase client/admin key misuse
- Supabase RLS/auth boundary hints
- IDOR/BOLA route shape heuristic
- webhook/upload/payment callback risk rules
- inter-file/import/type 해석은 현재 제한적 summary부터 시작하고 단계적으로 확장

### P1. 실사용 검증

synthetic/internal tests는 제품 배선 검증이고 시장 증거는 아니다.

필요한 검증:

- owned/partner vibe-coded apps 12-20개
- workspace + local/authorized HTTP + optional MCP runtime export
- 후보별 manual verdict: `true_positive`, `false_positive`, `benign`, `inconclusive`
- FP/FN/manual-review rate 공개
- high/critical unresolved가 남은 app은 pass claim 금지

### P2. Packaging and trust

- signed release/provenance
- versioned rule packs
- reproducible install path
- CI cache and performance budget
- evidence hash policy enforcing operator-keyed mode in release workflows

## 통과 기준

다음이 충족될 때 "시니어 감사관 스타일 release gate" claim을 더 강하게 말할 수 있다.

- `guardian --fail-on high`가 대표 경로로 문서, CI, MCP prompt에서 일관되게 사용된다.
- gate mode에서 coverage gap과 MCP control failure가 모두 fail로 나타난다.
- design-partner app 검증에서 12-20개 앱과 20개 이상 high/critical 후보에 manual TP/FP/FN 라벨이 있다.
- 데이터 출하 판단은 `data-release-gate`가 통과해야 하며, 여기에는 Guardian intent/scope contract, evidence bundle, 한국형 개인정보 corpus recall/FP budget, 필수 rule coverage 재계산, validation source Guardian 후보 대조, CLI MCP interceptor report, 그리고 실제 forwarded JSONL 파일 검증/재스캔이 포함된다.
- runtime MCP enforcement는 advisory가 아니라 proxy/interceptor에서 실제 block/redact를 수행한다.
- JS/TS/framework rules가 주요 vibe-coded stack의 auth/data-flow 실수를 잡는다.
