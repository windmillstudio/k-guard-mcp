# K-Guard 제품 목표 레지스트리

작성일: 2026-07-24  
상태: `ACTIVE`  
<!-- release-program-current-card: P2.4B.3.13; status=ACTIVE; completed=A; next=B -->
공식 evidence 원본: [출하 검증 프로그램 장부](release-program-phase-ledger-ko.md)  
카드별 원본: [원자 제품 목표 보드](release-program-atomic-goals-ko.md)  
남은 제품 작업 순서: [제품 작업 카드 카탈로그](release-program-product-card-catalog-ko.md)  
실행 순서: [제품 목표 분해와 페이즈 실행 지도](release-program-execution-map-ko.md)
기계 상태 계약: [goal-state JSON](release-program-goal-state.json) / [목표 통제와 독립 검증 운영](release-program-goal-control-ko.md)

## 이 문서가 고정하는 운영 방식

이 레지스트리는 감독 AI를 호출한 횟수를 관리하는 문서가 아니다. K-Guard 제품이
획득해야 할 능력을 `목표 -> 페이즈 -> 원자 카드`로 쪼개고, 각 단계가 실제로 닫혔는지
판정하는 제품 운영 계약이다.

- 한 번에 `ACTIVE`일 수 있는 구현 또는 측정 카드는 하나다.
- 카드 하나는 A-G 전체가 끝나기 전에는 완료가 아니다.
- 카드의 F는 Claude Opus 5 max와 Grok 4.6 xhigh가 독립적으로 반박하는 완료 gate다.
- leaf가 닫혀도 상위 phase가 자동 완료되지 않는다. 모든 child와 phase packet을 다시 검증한다.
- 목표 통제 G7도 별도 제품 운영 목표다. G1-G6을 감독 호출 횟수로 바꾸지 않고, 단일 활성 카드와
  카드/phase F1/F2 의무를 기계 상태 계약으로 확인한다.
- `FIX_NARROW`의 개수는 탐지율, 시니어 동등성, 출하 준비도 퍼센트가 아니다.
- 최종 `GO_RELEASE`는 아래 모든 제품 목표와 고정 수치 gate가 동시에 통과할 때만 가능하다.

## 북극성과 최상위 제품 목표

**북극성(G0):** K-Guard는 한국 바이브코더가 출하 직전에 호출하는 시니어 감사관형
fail-closed release gate다. 사이트, API, 데이터, 운영 중 하나라도 근거가 부족하면
결론은 `HOLD`다.

| 목표 | 제품이 실제로 얻어야 하는 능력 | 완료에 필요한 페이즈 | 현재 상태 |
| --- | --- | --- | --- |
| G1 정직한 분모와 oracle | 무엇을 보고 무엇을 제외했는지, 취약/수정/negative와 provenance를 다시 만들 수 있음 | P0, P1, P2 | `IN_PROGRESS` |
| G2 측정 가능한 탐지 성능 | TP/FP/FN/TN, recall, specificity, Wilson, coverage, 편중을 fail-closed로 계산 | P3 | `NOT_STARTED` |
| G3 정확한 Guardian gate | 가장 큰 오류군 하나를 observe -> warn -> block 순서로만 근거 있게 승격 | P4 반복 | `NOT_STARTED` |
| G4 네 평면의 검토 깊이 | 사이트, API, 데이터, 운영을 각각 oracle, 실행 경계, coverage, UX로 검증 | P5.S/A/D/O | `NOT_STARTED` |
| G5 실제 사용 가능성 | fresh install, CLI, stdio MCP, GPT/Grok/Codex/Antigravity에서 같은 결론을 재현 | P7.1-P7.4 | `NOT_STARTED` |
| G6 정직한 출하 주장 | 동결 H100, 전체 수치, 반복성, two-lane 최종 검토를 동시에 통과 | P6, P7.5 | `NOT_STARTED` |
| G7 목표 통제와 독립 검증 운영 | 모든 기존 작업을 phase와 원자 카드로 추적하고, 단일 ACTIVE 및 카드/phase two-lane F1/F2를 fail-closed로 확인 | P8 | `IN_PROGRESS` |

`G1`의 일부 source-tree 계약이 닫혔다고 `G2`의 탐지 성능이나 `G6`의 출하 승인이
생기지 않는다. 이 분리는 의도적이며, 아직 숫자로 측정하지 않은 효용을 과장하지 않기
위한 fail-closed 규칙이다.

## 페이즈별 달성 목표와 종료 gate

| 페이즈 | 이 페이즈에서만 달성할 것 | 원자 작업 분해 | 페이즈 종료 정의 | 완료 후 외부 검증 |
| --- | --- | --- | --- | --- |
| P0 | 동일 target과 toolchain을 다시 실행 | baseline, 환경, full regression, provider health | target drift 없이 receipts 결속 | 모든 P0 child 후 Claude/Grok F1/F2 phase packet |
| P1 | oracle과 finding을 1:1로 정직하게 연결 | schema, severity, raw-free receipt, score refusal, execution admission | label 누락/중복/control error를 score 성공으로 바꾸지 못함 | 모든 P1 child 후 two-lane F1/F2 phase packet |
| P2 | 성능 분모가 provenance와 exclusion을 가짐 | 공개 corpus, local apps, generated pairs, stress 100, H100 | source/license/revision 및 vulnerable/fixed/negative가 two-run으로 결속 | 각 leaf F1/F2와 P2 aggregate F1/F2 |
| P3 | 고정 수치를 계산 가능 | scan input, scorer, plane metrics, distribution, coverage HOLD | TP/FP/FN/TN와 누락 범위를 기계적으로 산출 | 각 card와 P3 baseline packet F1/F2 |
| P4 | 오류군 하나를 수치 악화 없이 교정 | hypothesis, observe, A/B, warn, block | holdout과 속도/재현성/기존 회귀를 함께 통과 | 오류군마다 F1/F2 phase packet |
| P5 | 네 제품 평면의 실전 검토 깊이 | 평면별 oracle, 실행, A/B, coverage, UX, phase review | S/A/D/O 각 평면의 6 card가 모두 닫힘 | 각 card와 각 평면 F1/F2 |
| P6 | 최종 결과를 숨김 표본에서 재현 | freeze, blind run, scoring, second run, disposition | H100 전수와 모든 고정 수치가 동시에 통과 | P6 F1/F2 release packet |
| P7 | 사람이 설치하고 같은 결론을 얻음 | fresh install, client tool list, bundle, canonical gate, final unanimity | 4 client에서 동일 Guardian GO/HOLD 재현 | P7 card별 F1/F2 및 P7.5 final packet |
| P8 | 목표 통제와 독립 검증을 실제로 작동 | goal-state, receipt binding, phase packet, final disposition control을 분리 | 단일 active, card/phase review, release claim refusal이 기계적으로 확인 | P8 card별 F1/F2 및 P8 phase packet |

## 모든 원자 카드의 완료 정의

| Gate | 작업 내용 | 실패 또는 미완료 시 상태 |
| --- | --- | --- |
| A | 가설, 입력, oracle, 제외, 성공 기준, claim boundary 사전등록 | `HOLD`; B 이후 진행 금지 |
| B | 코드 또는 source/oracle provenance를 content-bound target에 결속 | target drift면 A부터 재시작 |
| C | focused positive/negative와 fail-closed test | 누락/실패면 `HOLD` |
| D | independent output 또는 허가된 execution을 두 번 생성 | semantic difference면 `HOLD` |
| E | full regression, coverage, compatibility 확인 | timeout, unsupported, control error는 `HOLD` |
| F1 | Claude Opus 5/Grok 4.6의 첫 독립 검토 | 한 lane이라도 `HOLD`, `BLOCKED`, timeout이면 승격 금지 |
| F2 | 동일 target/packet으로 두 번째 독립 검토 | semantic comparator가 `FIX`가 아니면 승격 금지 |
| G | evidence hash, comparator, 명시적 비주장 범위를 장부에 기록 | 이때만 `FIX_NARROW` |

F1/F2의 결과는 oracle label이나 합격선을 바꾸지 않는다. 두 AI는 결속, 재현성,
claim boundary, 증거 누락, 과장된 출하 주장을 독립적으로 반박한다. Claude는 지정
파일을 read-only로 직접 검토하고, Grok은 동등한 raw-free packet을 검토한다.

### 카드 종료 시 two-lane 호출 규칙

1. 카드 소유자는 A-E receipts, target hash, claim boundary, 두 run comparator를 packet으로 봉인한다.
2. 동일 packet을 Claude Opus 5 max와 Grok 4.6 xhigh에 F1로 보낸다.
3. 두 lane이 모두 `GO`여도 같은 target/packet으로 F2를 다시 실행한다.
4. F1/F2 semantic comparator가 `FIX`일 때만 G에서 `FIX_NARROW`로 승격한다.
5. phase의 모든 child가 `FIX_NARROW`가 된 뒤, phase summary packet에도 위 1-4를 다시 적용한다.
6. provider 장애는 숨기지 않는다. 복구 후 다시 실행할 수는 있지만, 그 사이 카드는
   `TEMPORARY_PENDING_REVIEW`이며 다음 카드의 근거나 최종 성능 근거가 될 수 없다.

## 현재 실행 큐

| 순서 | 원자 카드 | 제품 능력 한 문장 | 현 상태 | 다음 허용 행동 |
| --- | --- | --- | --- | --- |
| 1 | P2.4B.2.13 | `site-13` Java/Spring JDBC query primary/reserve source-tree identity를 두 번 같은 결과로 materialize | `FIX_NARROW` - A-G와 3AI F1/F2 완료 | Java/Spring/JDBC runtime과 detector 성능은 비주장 |
| 2 | P2.4B.2.14 | `site-14` Kotlin/Ktor HTML response source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 완료 | Kotlin/Ktor runtime과 browser/XSS execution은 비주장 |
| 3 | P8.1 | G0-G7, P0-P8, 단일 active, A-G/3AI 규칙을 canonical state와 validator로 확인 | `FIX_NARROW` - A-G와 final 3AI F1/F2 comparator `FIX` | P8.2 receipt binding은 별도 카드 |
| 4 | P8.1B | current JSON과 세 사람이 읽는 운영판의 current marker 동기화 | `FIX_NARROW` - initial D `HOLD` 보존, corrected A-G와 3AI comparator `FIX` | 목표 통제만 해당, P8.2 receipt binding은 별도 카드 |
| 4A | P8.2A | Windows npm shim을 Claude/Grok/GLM supervisor subprocess의 executable path로 정규화 | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX` | Windows supervisor contract만 해당 |
| 4B | P8.2B | Windows long-packet을 native Claude/Cline executable로 전송 | `FIX_NARROW` - A-G와 3AI comparator `FIX` | native transport만 해당 |
| 4D | P8.2D | GLM source-free health terminal contract | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` | invalid field ID와 Claude timeout receipt를 보존한 좁은 contract 종료 |
| 4E | P8.2E | G1-G6 product-card catalog와 phase-exit review binding | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX` | registry transition control만 해당 |
| 5 | P2.4B.2.15 | `site-15` Go/chi SQL builder source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` | Go/chi/DB runtime과 detector 성능은 비주장 |
| 5 | P2.4B.2.16 | `data-03` TypeScript/Prisma raw-query source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` | TypeScript/Prisma/DB runtime과 detector 성능은 비주장 |
| 6 | P2.4B.2.17 | `data-07` Python/FastAPI parameterized-query source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` | Python/FastAPI/SQLite runtime과 detector 성능은 비주장 |
| 7 | P2.4B.2.18 | `data-09` Java/Spring JDBC concat source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` | Java/Spring/JDBC runtime과 detector 성능은 비주장 |
| 8 | P2.4B.2.19 | `data-14` Go/pgx query-format source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` | Go/pgx/PostgreSQL runtime과 detector 성능은 비주장 |
| 9 | P2.4B.2.20 | 19 source-flow leaf aggregate와 exclusion `0` | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` | source inventory만 비주장 |
| 10 | P2.4B.3.01 | api-01 Express route-IDOR source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` | runtime/detector/release 비주장 |
| 11 | P2.4B.3.02 | api-02 Next.js service-IDOR source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` | runtime/detector/release 비주장 |
| 12 | P2.4B.3.03 | api-03 Supabase missing-RLS source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` | Supabase runtime/RLS enforcement는 비주장 |
| 12 | P2.4B.3.04 | api-04 Firebase open-rule source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` | Firebase runtime/rule enforcement는 비주장 |
| 13 | P2.4B.3.05 | api-05 Next.js admin-boundary source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` | Next.js runtime authorization은 비주장 |
| 14 | P2.4B.3.06 | api-06 Express mass-assignment source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` | Express update semantics는 비주장 |
| 15 | P2.4B.3.07 | api-07 Supabase service-role key source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` | bundler/runtime과 Supabase project access는 비주장 |
| 16 | P2.4B.3.08 | api-08 Firebase storage read-rule source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` | Firebase runtime과 rule enforcement는 비주장 |
| 17 | P2.4B.3.09 | api-09 FastAPI dependency-auth source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` | FastAPI runtime authorization은 비주장 |
| 18 | P2.4B.3.10 | api-10 Django REST object-owner source-tree identity | `FIX_NARROW` - A-G와 3AI F1/r3 comparator `FIX`; F2 timeout 보존 | Django REST runtime authorization과 object ownership semantics는 비주장 |
| 19 | P2.4B.3.11 | api-11 Flask role-guard source-tree identity | `FIX_NARROW` - A-G와 3AI F1/r3 comparator `FIX`; r2 packet-diff `HOLD` 보존 | Flask runtime authorization과 role semantics는 비주장 |
| 20 | P2.4B.3.12 | api-12 Spring method-auth source-tree identity | `FIX_NARROW` - A-G와 r2/r3 Claude/Grok/GLM comparator `FIX`; initial GLM `HOLD` 보존 | Spring runtime authorization과 method-security enforcement는 비주장 |
| 21 | P2.4B.3.13 | api-13 Ktor resource-owner source-tree identity | `ACTIVE` - current-target A DONE, B next; 옛 E/F1 `BLOCKED_PROVIDER` evidence 보존, 현재 target 완료 근거 아님 | B; review lanes 아직 실행 불가 |
| 22 | P2.4B.3.14-.20 | 나머지 auth-rls-db leaf와 family aggregate | `NOT_STARTED` | .13 G 뒤 순차 진행 |
| 12 | P2.4B.4-.8 | 나머지 generated family, admission, aggregate | `NOT_STARTED` | P2.4B.3.20 phase packet 종료 뒤 |
| 11 | P2.5-P2.7 | public stress 100, H100 membership, P2 phase review | `NOT_STARTED` | generated pair corpus 완료 뒤 |
| 12 | P3-P7 | 측정, 교정, 평면 깊이, 설치, H100, 최종 출하 | `NOT_STARTED` | 각 선행 phase exit 뒤 |

현재 P2.4B.2.01-.14는 각각 그 제한된 source-tree identity 계약에 한해
`FIX_NARROW`다. 그것들은 runtime execution, scanner detection, TP/FP/FN, H100,
release를 입증하지 않는다. P8.1, P2.4B.2.15부터 P2.4B.2.19까지는 각각 `FIX_NARROW`로 닫혔고,
`P2.4B.2.20`, `P2.4B.3.01`, `P2.4B.3.02`, `P2.4B.3.03`, `P2.4B.3.04`, `P2.4B.3.05`, `P2.4B.3.06`, `P2.4B.3.07`, `P2.4B.3.08`, `P2.4B.3.09`, `P2.4B.3.10`, `P2.4B.3.11`, `P2.4B.3.12`, `P8.1B`, `P8.2E`, `P8.2A`는 각각 A-G를 닫았다. api-12의 첫 GLM `HOLD`는 보존했고, 같은 clarified packet의 r2/r3 supervisor comparator `FIX`만 승격 근거다. 현재 유일한
카드는 `P2.4B.3.13`이며 current-target A DONE, B next의 `ACTIVE` 카드다. 옛 E/F1 evidence는 현재 target 완료 근거가 아니고 review lanes는 아직 실행할 수 없다. P8.2B/P8.2D/P8.2E/P8.2A의 A-G `FIX_NARROW`와 API13/P8.2A health/F1의
`BLOCKED_PROVIDER`는 모두 보존한다.

## 보고와 상태 갱신 규칙

카드 또는 phase가 바뀔 때마다 상태 보고는 반드시 아래 네 줄을 포함한다.

1. `카드 또는 페이즈 ID / 상태 / 이번에 얻은 제품 능력`
2. `통과 또는 미달 gate와 evidence receipt/hash`
3. `Claude Opus 5, Grok 4.6 F1/F2와 semantic comparator 상태`
4. `명시적 비주장과 다음에 열 수 있는 카드 하나`

상태가 `MEASURED_HOLD`이면 실패를 삭제하거나 기준을 완화하지 않는다. 실패 원인을
다루는 새 원자 카드를 만들고, observe-only -> paired A/B -> warn -> block 절차를 다시
시작한다.

## 최종 출하 gate

다음은 모두 동시에 필요하다. 평균 점수와 부분 완료로 어느 항목도 상쇄하지 않는다.

- 자동 차단 적중률 90% 이상, Wilson 95% 하한 80% 이상
- 앱 단위 완전 적중률 90% 이상, Wilson 95% 하한 80% 이상
- High/Critical recall 90% 이상, Critical recall 100%
- specificity 90% 이상, 동일 H100 두 run의 semantic equality
- 단일 규칙 후보 편중 50% 이하, `check_my_app` 5초 계약 유지
- Guardian의 지원 범위 미완료, timeout, control error는 모두 fail-closed `HOLD`
- 설치, CLI, MCP protocol, client compatibility 회귀 없음
- Claude Opus 5 max와 Grok 4.6 xhigh의 final packet F1/F2 모두 `GO`, comparator `FIX`
- G7 P8.1, P8.1B, P8.2-P8.4가 목표 계층, human-status sync, receipt binding, phase packet, release claim refusal을 검증하고 최종 P8 packet을 통과

이 조건 하나라도 비어 있으면 현재 상태는 `HOLD`다.
