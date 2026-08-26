# K-Guard 현재 제품 작업 분해와 종료 운영판

작성일: 2026-07-24  
상태: `ACTIVE`  
<!-- release-program-current-card: P2.4B.3.13; status=ACTIVE; completed=A; next=B -->
기계 상태: [goal-state JSON](release-program-goal-state.json)  
상세 근거: [출하 검증 프로그램 장부](release-program-phase-ledger-ko.md)  
원자 카드 정의: [원자 제품 목표 보드](release-program-atomic-goals-ko.md)
남은 제품 작업 순서: [제품 작업 카드 카탈로그](release-program-product-card-catalog-ko.md)

## 이 문서를 읽는 법

이 문서는 감독관 호출 목록이 아니라 **K-Guard 제품을 실제로 완성하기 위한 현재 작업
지도**다. 과거 사전등록과 완료 패킷은 각 카드 문서에 보존한다. 여기서는 현재 목표, 선행
조건, 종료 규칙, 다음에 열 카드만 한 번에 읽는다.

- 완료된 작은 카드의 수를 제품 정확도나 출하 준비도 퍼센트로 환산하지 않는다.
- 한 카드의 `FIX_NARROW`는 그 카드가 명시한 좁은 능력만 뜻한다.
- 사이트, API, 데이터, 운영 중 하나라도 미달이면 제품 전체는 `HOLD`다.
- `goal-state JSON`과 이 문서가 다르면 JSON은 기계 상태, 이 문서는 사람이 읽는 운영판으로
  취급하고 차이는 다음 카드의 A 단계에서 먼저 바로잡는다.

## 카드가 끝나는 정확한 순간

모든 구현, 측정, 설치, UX, 운영 통제 카드는 동일한 A-G를 가진다. 따라서 "코드를
고쳤다"나 "테스트가 하나 통과했다"는 완료가 아니다.

| Gate | 그 카드에서 끝낼 일 | 통과하지 못했을 때 |
| --- | --- | --- |
| A | 목표, 입력, oracle, 제외, 비주장을 결과 전에 고정 | `HOLD`, B 금지 |
| B | 코드 또는 provenance를 현재 target hash에 결속 | target drift면 A부터 재시작 |
| C | positive/negative, tamper, fail-closed focused test | `HOLD` |
| D | 외부 output 또는 허가된 실행을 독립적으로 두 번 생성 | semantic difference면 `HOLD` |
| E | full regression, coverage, 호환성 확인 | error, timeout, unsupported는 `HOLD` |
| F1 | Claude Opus 5 max와 Grok 4.6 xhigh가 같은 고정 입력을 독립 검토 | 한 lane이라도 미달이면 승격 금지 |
| F2 | 같은 target과 packet으로 두 모델의 두 번째 독립 검토 | supervisor comparator가 `FIX`가 아니면 승격 금지 |
| G | evidence hash, comparator, 비주장을 장부에 기록 | 이때만 `FIX_NARROW` |

모델 한 개의 임시 의견은 구현 방향을 확인하는 보조 신호일 수 있지만, 카드나 페이즈를
`FIX_NARROW`로 바꾸지 못한다. provider 오류, timeout, model/packet/target drift도 숨기지
않고 `EVIDENCE_READY` 또는 `MEASURED_HOLD`로 남긴다.

**페이즈 종료**는 더 엄격하다. 해당 페이즈의 모든 child 카드가 G까지 닫힌 뒤에 child ID,
제외 항목, evidence hash, claim boundary를 담은 phase packet을 만들고 Claude/Grok F1/F2를
다시 수행한다. leaf의 두 lane 통과는 phase 통과를 대신하지 않는다.

## 현재 한 줄 상태

**제품은 출하 `HOLD`다. P8.2A Windows supervisor command resolution은 `FIX_NARROW`로 닫혔다.
현재 유일한 카드는 P2.4B.3.13 API13이며 current-target A는 DONE, 다음은 B다. current accepted HEAD
`6f0874c5bc3bebceecca41030b8ffe4f14026fc0` / tree `4c6545ff743a2ea54c737aa7caed2adaec77d7c8`에
결속한다. `04e9dd8e`에 결속된 옛 API13 A-E/F1 `BLOCKED_PROVIDER` evidence는 보존 역사이며 현재
target 완료 근거가 아니고, review lanes는 아직 실행할 수 없다.**

| 상위 목표 | 현재 상태 | 제품이 아직 말할 수 없는 것 |
| --- | --- | --- |
| G1 정직한 분모와 oracle | `IN_PROGRESS` | 전체 oracle completeness, TP/FP/FN |
| G2 측정 가능한 탐지 성능 | `NOT_STARTED` | precision, recall, Wilson, 실전 탐지력 |
| G3 정확한 Guardian gate | `NOT_STARTED` | 자동 block 적중률 |
| G4 사이트/API/데이터/운영 깊이 | `NOT_STARTED` | 각 평면의 시니어급 검토 범위 |
| G5 설치와 사용 가능성 | `NOT_STARTED` | 네 클라이언트의 최종 호환성 |
| G6 정직한 출하 주장 | `NOT_STARTED` | `GO_RELEASE` |
| G7 목표 통제와 독립 검증 | `IN_PROGRESS` | receipt/phase/disposition 제어는 남음 |

## G1. 정직한 분모와 oracle

### P0. 기준선과 실행 환경

| 카드 | 한 가지 달성 목표 | 상태 |
| --- | --- | --- |
| P0.1 | target, dirty worktree, analyzer, toolchain을 current receipt로 결속 | `FIX_NARROW` |
| P0.2 | full regression shard의 누락 없는 실행 | `FIX_NARROW` |
| P0.3 | Claude, Grok, GLM 고정 실행 경로 health 확인 | `FIX_NARROW` |
| P0.4 | P0 phase packet의 Claude Opus 5/Grok 4.6 F1/F2 | `FIX_NARROW` |

### P1. oracle과 finding 1:1

| 카드 | 한 가지 달성 목표 | 선행 조건 | 상태 |
| --- | --- | --- | --- |
| P1.1A | 좁은 source-bound oracle schema | P0 | `FIX_NARROW` |
| P1.1B | full registry에 schema와 severity 의무 적용 | P1.1A | `NOT_STARTED` |
| P1.2A | registry 재물질화 repeat validator | P1.1A | `FIX_NARROW` |
| P1.2B | High/Critical/blocker finding:scenario 1:1 위반 시 score 거부 | P1.2A | `NOT_STARTED` |
| P1.3A | raw-free candidate receipt relation | P1.2A | `FIX_NARROW` |
| P1.3B | current source response receipt의 two-run binding | P1.3A | `NOT_STARTED` |
| P1.4A | WebGoat IDOR positive execution repeat | P1.3A | `FIX_NARROW` |
| P1.4B | WebGoat IDOR negative-control repeat | P1.4A | `FIX_NARROW` |
| P1.4C | 남은 local execution oracle의 positive/negative 확대 | P1.4A-P1.4B | `NOT_STARTED` |
| P1.5 | 공개 XStream SCA observe-only differential | P1.3A | `FIX_NARROW` |
| P1.6A | P1 완료/미완료 claim boundary phase review | P1.1B-P1.4C | `NOT_STARTED` |

### P2. 공개 분모와 holdout 재료

| 카드 | 한 가지 달성 목표 | 상태 |
| --- | --- | --- |
| P2.1A / P2.1B | OWASP BenchmarkJava 2,740건의 official denominator와 clean-worktree replay | `FIX_NARROW` |
| P2.2A / P2.2B | OWASP BenchmarkPython official denominator와 clean-worktree replay | `FIX_NARROW` |
| P2.3A | 6개 local app source/license/revision/runtime registry | `FIX_NARROW` |
| P2.3B.1-.7 | WebGoat, Juice Shop, NodeGoat, PyGoat, crAPI, WrongSecrets execution boundary와 six-app aggregate | `FIX_NARROW` |
| P2.4A | generated pair 60 blueprint 사전등록 | `FIX_NARROW` |
| P2.4B.1 | external source-triplet staging contract | `FIX_NARROW` |
| P2.4B.2.01-.19 | source-flow 19개 slot의 source-tree identity | 각각 `FIX_NARROW` |
| P2.4B.2.20 | 19 slot raw-free aggregate, exclusion `0` | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.01 | api-01 Express route-IDOR source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.02 | api-02 Next.js service-IDOR source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.03 | api-03 Supabase missing-RLS source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.04 | api-04 Firebase open-rule source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.05 | api-05 Next.js admin-boundary source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.06 | api-06 Express mass-assignment source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.07 | api-07 Supabase service-role key source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.08 | api-08 Firebase storage read-rule source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.09 | api-09 FastAPI dependency-auth source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.10 | api-10 Django REST object-owner source-tree identity | `FIX_NARROW` - A-G와 3AI F1/r3 comparator `FIX`; F2 timeout 보존 |
| P2.4B.3.11 | api-11 Flask role-guard source-tree identity | `FIX_NARROW` - A-G와 3AI F1/r3 comparator `FIX`; r2 packet-diff `HOLD` 보존 |
| P2.4B.3.12 | api-12 Spring method-auth source-tree identity | `FIX_NARROW` - A-G와 r2/r3 Claude/Grok/GLM comparator `FIX`; initial GLM `HOLD` 보존 |
| P2.4B.3.13 | api-13 Ktor resource-owner source-tree identity | `ACTIVE` - current-target A DONE, B next; 옛 E/F1 `BLOCKED_PROVIDER` evidence 보존, 현재 target 완료 근거 아님; review lanes 아직 실행 불가 |
| P2.4B.3.14-.20 | 나머지 auth-rls-db leaf와 family aggregate | `NOT_STARTED` |
| P2.4B.4 | dependency-sca 7개 deterministic source triplet | `NOT_STARTED` |
| P2.4B.5 | gha-docker-iac 8개 deterministic source triplet | `NOT_STARTED` |
| P2.4B.6 | policy-kpriv 7개 deterministic source triplet | `NOT_STARTED` |
| P2.4B.7 | 60 primary의 execution, patch/invariant, admission | `NOT_STARTED` |
| P2.4B.8 | 60 slot aggregate, exclusion `0`, P2.4B phase review | `NOT_STARTED` |
| P2.5A | public stress 후보 100개의 source/license/provenance | `NOT_STARTED` |
| P2.5B | top/mid/long-tail 층화와 exclusion 사전등록 | `NOT_STARTED` |
| P2.6A | H100 membership freeze | `NOT_STARTED` |
| P2.6B | 네 평면 25개씩, severity/exclusion 독립 검증 | `NOT_STARTED` |
| P2.7A | P2 provenance/exclusion phase F1/F2 | `NOT_STARTED` |

`P2.4B.2.01-.19`의 종료는 source-tree inventory만 의미한다. runtime exploit, detector
finding, recall, H100, release claim은 다음 카드의 책임이다.

## G2. 측정 가능한 탐지 성능: P3

| 카드 | 한 가지 달성 목표 | 선행 조건 | 상태 |
| --- | --- | --- | --- |
| P3.1A | scanner input, timeout, supported-file coverage 계약 봉인 | P2.7A | `NOT_STARTED` |
| P3.1B | 전수 scan 미완료면 Guardian `HOLD` | P3.1A | `NOT_STARTED` |
| P3.2A | oracle 없는 TP/FP/FN/TN/Wilson 계산 거부 | P3.1B | `NOT_STARTED` |
| P3.2B | 평면별 actionability, recall, specificity, app-complete 계산 | P3.2A | `NOT_STARTED` |
| P3.3A | rule/subtype/language/plane candidate 편중 계산 | P3.2B | `NOT_STARTED` |
| P3.4A | timeout/unsupported/control error를 coverage `HOLD`로 집계 | P3.3A | `NOT_STARTED` |
| P3.5A | baseline 오류군과 claim boundary phase F1/F2 | P3.2B-P3.4A | `NOT_STARTED` |

## G3. 정확한 Guardian gate: P4

P4는 지금 오류군 이름을 미리 정하지 않는다. `P3.5A`가 oracle로 계산한 모집단 가중 손실
1위만 하나 골라 아래 여섯 카드를 새 instance로 연다. 한 오류군의 통과는 다른 오류군의
통과가 아니다.

| 템플릿 카드 | 한 가지 달성 목표 | 상태 |
| --- | --- | --- |
| P4.`error`.1A | 오류군, 개발 분모, 목표 수치 사전등록 | `LOCKED_UNTIL_P3.5A` |
| P4.`error`.2A | observe-only 구현과 기존 block 영향 0 | `LOCKED_UNTIL_P3.5A` |
| P4.`error`.3A | paired A/B recall, specificity, speed, repeatability 비교 | `LOCKED_UNTIL_P3.5A` |
| P4.`error`.4A | 충분한 independent oracle 뒤 warn 승격 | `LOCKED_UNTIL_P3.5A` |
| P4.`error`.5A | preregistered holdout과 gate 뒤 block 승격 | `LOCKED_UNTIL_P3.5A` |
| P4.`error`.6A | 오류군 phase packet Claude Opus 5/Grok 4.6 F1/F2 | `LOCKED_UNTIL_P3.5A` |

## G4. 네 평면의 검토 깊이: P5

각 행은 독립 카드다. 평면 한 곳의 six-card 종료도 해당 평면의 "측정 준비"일 뿐
탐지율이나 출하 승인은 아니다.

| 평면 | .1 oracle | .2 허가된 실행 경계 | .3 최대 오류군 A/B | .4 coverage HOLD | .5 사용자 계약 | .6 phase F1/F2 | 상태 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P5.S 사이트 | static/XSS/injection | local web execution | paired A/B | crawl/timeout/unsupported | finding, 수정, 재검사 UX | 2AI | 모두 `NOT_STARTED` |
| P5.A API | auth/IDOR/BOLA | route-to-service | paired A/B | auth/coverage | route/권한 설명 UX | 2AI | 모두 `NOT_STARTED` |
| P5.D 데이터 | SQL/RLS/PII/retention | read-only DB/storage | paired A/B | connector/control error | 한국 개인정보 다음 행동 UX | 2AI | 모두 `NOT_STARTED` |
| P5.O 운영 | secret/SCA/CI-IaC/MCP | runtime proxy/protocol | paired A/B | runtime/protocol | suppression/CI policy UX | 2AI | 모두 `NOT_STARTED` |

## G5. 실제 설치와 사용 가능성: P7

| 카드 | 한 가지 달성 목표 | 선행 조건 | 상태 |
| --- | --- | --- | --- |
| P7.1A | fresh wheel, CLI, stdio MCP, evidence binding clean replay | P5 phase review | `NOT_STARTED` |
| P7.2A | GPT, Grok, Codex, Antigravity 설치, restart, tool list, Guardian 호출 | P7.1A | `NOT_STARTED` |
| P7.3A | license, SBOM, known limits, evidence raw-free release bundle | P7.2A | `NOT_STARTED` |
| P7.4A | 모든 phase exit을 canonical Guardian `GO/HOLD`로 계산 | P7.3A | `NOT_STARTED` |
| P7.5A | final packet Claude Opus 5/Grok 4.6 unanimous F1/F2 | P6.5A, P7.4A | `NOT_STARTED` |

과거 install smoke는 보존하되 이 카드의 final evidence가 아니다. 최종 target에서 네
클라이언트가 같은 Guardian 결론을 내야 한다.

## G6. 정직한 최종 출하 주장: P6

| 카드 | 한 가지 달성 목표 | 선행 조건 | 상태 |
| --- | --- | --- | --- |
| P6.1A | analyzer/rule/toolchain/H100/label one-way freeze | P2.6B, P5 phase review | `NOT_STARTED` |
| P6.2A | H100 blind run과 oracle scoring 분리 | P6.1A | `NOT_STARTED` |
| P6.3A | overall/plane/Critical/specificity/concentration/speed gate 계산 | P6.2A | `NOT_STARTED` |
| P6.4A | 수정 없는 두 번째 H100 semantic equality | P6.3A | `NOT_STARTED` |
| P6.5A | release disposition Claude Opus 5/Grok 4.6 F1/F2 | P6.4A | `NOT_STARTED` |

## G7. 목표 통제와 독립 검증 운영: P8

| 카드 | 한 가지 달성 목표 | 선행 조건 | 상태 |
| --- | --- | --- | --- |
| P8.1 | G0-G7/P0-P8, 단일 active, A-G, 3AI F1/F2를 state validator로 강제 | 없음 | `FIX_NARROW` |
| P8.1B | current JSON과 세 사람이 읽는 운영판의 active/gate/next 동기화 | P8.1 | `FIX_NARROW` - initial D `HOLD` 보존, corrected A-G와 3AI comparator `FIX` |
| P8.2A | Windows에서 Claude/Cline npm shim을 subprocess 실행 경로로 정규화 | P8.1B | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX`; Windows supervisor contract만 해당 |
| P8.2B | Windows long-packet을 native Claude/Cline executable로 전송 | P8.2A | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX` |
| P8.2D | GLM source-free health terminal contract | P8.2B | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX`; invalid field ID와 Claude timeout receipt 보존 |
| P8.2E | G1-G6 product-card catalog와 phase-exit review binding | P8.2D | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX`; registry transition control만 해당 |
| P8.2C | `FIX_NARROW`/phase 상태와 machine/supervisor receipt hash 결속 | P8.2B | `NOT_STARTED` |
| P8.3 | child/exclusion/F1/F2를 raw-free phase packet으로 검증 | P8.2C | `NOT_STARTED` |
| P8.4 | G1-G7/P0-P8 및 수치 gate 미달이면 `GO_RELEASE` 거부 | P8.3 | `NOT_STARTED` |

## 다음 카드 선택 규칙

1. 현재 `ACTIVE` 카드 하나만 코드, 규칙, 표본, 실행 증거를 바꾼다.
2. 같은 카드의 A-E를 끝내기 전에는 Claude/Grok을 완료 판정 목적으로 호출하지 않는다.
3. E가 끝나면 F1과 F2를 수행한다. 두 lane과 comparator가 모두 `FIX`일 때만 G로 간다.
4. G에서 좁은 claim과 evidence hash를 기록한 뒤에만 다음 카드 A를 연다.
5. 어떤 card/phase가 `MEASURED_HOLD`면 실패를 보존하고, 그 실패 원인을 해결하는 단일 카드로
   돌아간다. 합격선, oracle, 표본을 결과 뒤에 낮추지 않는다.

이 규칙으로 현재 작업은 "감독 목표"와 별개로 사이트, API, 데이터, 운영, 설치, 성능,
출하 주장을 각각 독립 제품 목표로 끝까지 닫는다.
