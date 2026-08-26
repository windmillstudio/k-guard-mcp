# K-Guard 제품 목표 분해와 페이즈 실행 지도

작성일: 2026-07-23  
상태: `ACTIVE`  
<!-- release-program-current-card: P2.4B.3.13; status=ACTIVE; completed=A; next=B -->
공식 상태 원본: [출하 검증 프로그램 장부](release-program-phase-ledger-ko.md)  
카드별 상태판: [제품 목표 운영판](release-program-goal-board-ko.md)
원자 구현 순서: [원자 제품 목표 보드](release-program-atomic-goals-ko.md)
남은 제품 작업 순서: [제품 작업 카드 카탈로그](release-program-product-card-catalog-ko.md)
목표 계층과 종료 기준: [제품 목표 레지스트리](release-program-goal-register-ko.md)
기계 상태 계약: [goal-state JSON](release-program-goal-state.json) / [목표 통제와 독립 검증 운영](release-program-goal-control-ko.md)

## 이 지도의 원칙

이 프로그램의 목표는 감독관의 `GO`를 많이 받는 것이 아니다. 제품이 실제로 다음
능력을 차례대로 획득하는 것이 목표이며, Claude Opus 5 max와 Grok 4.6 xhigh는
각 능력 카드가 닫힐 때 증거와 주장을 독립적으로 반박해 보는 마지막 관문이다.

한 카드의 `FIX_NARROW`는 바로 다음 카드의 **입력 계약**일 뿐이다. 탐지 정확도,
시니어 동등성, 출하 가능성으로 자동 환산하지 않는다.

큰 페이즈의 제목만 완료로 쓰지 않는다. 모든 구현과 측정은 원자 카드에 매핑하고,
카드의 A-E 기계 증거가 끝난 뒤 Claude Opus 5 max와 Grok 4.6 xhigh F1/F2를 거친다.
페이즈 종료 때도 child card와 별도의 phase packet F1/F2를 다시 수행한다.

## 제품 목표 트리

```text
북극성: 한국 바이브코더의 출하 전 시니어 감사관형 fail-closed Guardian
|
|-- G1 정직한 분모와 oracle
|   |-- P0 기준선과 실행 환경 봉인
|   |-- P1 oracle/finding 결속 계약
|   `-- P2 공개·생성·holdout 표본의 provenance와 실행 oracle
|
|-- G2 측정 가능한 탐지 성능
|   `-- P3 scanner baseline, TP/FP/FN/TN, coverage와 분포 측정
|
|-- G3 정확한 release gate
|   `-- P4 최대 오류군 하나씩 observe -> warn -> block 승격
|
|-- G4 네 제품 평면의 검토 깊이
|   `-- P5 사이트 / API / 데이터 / 운영 각각의 oracle, coverage, UX
|
|-- G5 실제 사용 가능성
|   `-- P7 설치, CLI, stdio MCP, 4개 클라이언트 호환성, release bundle
|
`-- G6 정직한 출하 주장
    `-- P6 H100 동결·blind scoring·반복성과 P7.5 최종 처분

`-- G7 목표 통제와 독립 검증 운영
    `-- P8 단일 active, card/phase review, receipt binding, release claim refusal
```

## 페이즈별 작은 목표와 종료 조건

| 페이즈 | 제품이 얻는 한 가지 능력 | 작업을 더 쪼개는 기준 | 페이즈 종료 조건 | 감독 검증 호출 |
| --- | --- | --- | --- | --- |
| P0 | 같은 target과 도구로 다시 실행할 수 있음 | baseline hash, toolchain, clean/full regression, supervisor health를 각각 카드화 | target drift 없이 회귀/환경 receipt가 결속 | P0 하위 카드 A-E 후 F1/F2 |
| P1 | finding과 oracle을 정직하게 1:1로 연결할 수 있음 | schema, severity, raw-free receipt, score-refusal을 각각 카드화 | 누락/중복/unsupported를 score 성공으로 바꾸지 않는 validator | P1 카드별 A-E 후 F1/F2 |
| P2 | 성능 측정에 쓸 표본이 provenance와 제외 사유를 가짐 | corpus, local app, generated pair, stress, H100을 따로 카드화 | source/license/revision, vulnerable/fixed/negative, exclusion이 two-run으로 결속 | P2 leaf마다 A-E 후 F1/F2 |
| P3 | TP/FP/FN/TN와 모든 고정 수치를 계산할 수 있음 | input/timeout, scorer, plane metric, distribution, coverage HOLD를 분리 | metric engine이 oracle 없는 결과나 control error를 통과시키지 않음 | P3 카드별 A-E 후 F1/F2 |
| P4 | 정확도를 훼손하지 않고 한 오류군을 교정할 수 있음 | hypothesis, observe, paired A/B, warn, block을 절대 합치지 않음 | 사전등록 holdout과 모든 회귀를 통과한 개선만 block | P4 가설 하나의 A-E 후 F1/F2 |
| P5 | 사이트/API/데이터/운영을 각각 깊이 있게 검토할 수 있음 | 평면마다 oracle, execution, A/B, coverage, UX, phase review 여섯 카드 | 네 평면 모두 독립적으로 측정 준비 완료 | 평면 카드 및 평면 phase packet의 F1/F2 |
| P6 | 최종 수치가 재현되는지 말할 수 있음 | freeze, blind run, scoring, repeat, release review를 분리 | H100 전체와 평면별 gate가 동시에 충족 | P6 카드와 최종 packet의 F1/F2 |
| P7 | 사람이 설치하고 Guardian 결론을 받을 수 있음 | fresh install, client tool list, bundle, canonical disposition, final unanimity를 분리 | GPT/Grok/Codex/Antigravity에서 동일 GO/HOLD가 재현 | P7 카드별 및 P7.5 F1/F2 |
| P8 | 기존 제품 목표를 끝까지 추적하고 독립 검증하는 운영 통제를 얻음 | state, receipt binding, phase packet, disposition refusal을 각각 카드화 | G1-G7/P0-P8와 단일 active, card/phase two-lane F1/F2 의무가 기계적으로 확인 | P8 카드별 및 P8 phase packet F1/F2 |

## 카드 내부의 고정 순서

각 작은 작업은 다음 일곱 칸을 **순서대로** 닫는다. F는 제품 목표가 아니라 완료한
제품 증거에 대한 독립 검증이다.

| 칸 | 해야 할 일 | 통과하지 못했을 때 |
| --- | --- | --- |
| A | 가설, 입력, 제외, 성공/실패 조건, claim boundary 사전등록 | `HOLD`; 다음 칸 금지 |
| B | 코드 또는 공개 source/oracle 결속 | target drift면 A부터 재시작 |
| C | focused positive/negative test | fail-closed negative가 없으면 `HOLD` |
| D | 두 번 독립 실행하고 semantic comparator 생성 | 결과 불일치면 `HOLD` |
| E | full regression, coverage, compatibility 확인 | timeout/누락/error는 `HOLD` |
| F1/F2 | Claude Opus 5/Grok 4.6이 같은 target/packet을 두 번 독립 검토 | 한 lane이라도 미완료면 승격 금지 |
| G | evidence hash, comparator, 남은 비주장 범위를 장부에 기록 | 이때만 `FIX_NARROW` |

감독 모델 하나가 응답하지 않으면, 이미 만든 기계 증거로 다음 **비승격 측정**만 할 수
있다. 그 카드의 `FIX_NARROW`, 평면 완료, 최종 `GO_RELEASE`는 두 lane이 모두 두 번
검토될 때까지 보류한다.

## 현재 열린 카드

현재 동시에 구현 중인 카드는 하나뿐이며, [goal-state JSON](release-program-goal-state.json)의 validator가
그 사실과 세 supervisor lane/두 review run 의무를 확인한다.

| 작업 ID | 제품 목표 | 이번 카드에서 실제로 달성할 것 | 완료가 아닌 것 | 상태 |
| --- | --- | --- | --- | --- |
| P2.4B.2.02 | G1 / P2 | `site-02` Express SQL query의 primary/reserve vulnerable/fixed/negative source triplet을 external root에 두 번 같은 tree identity로 materialize | live exploit, scanner detection, TP/FP/FN, SQLi recall, release approval | `FIX_NARROW` |
| P2.4B.2.03 | G1 / P2 | `site-03` Express command-exec primary/reserve vulnerable/fixed/negative source triplet을 external root에 두 번 같은 tree identity로 materialize | command execution, scanner detection, TP/FP/FN, command-injection recall, release approval | `FIX_NARROW` |
| P2.4B.2.04 | G1 / P2 | `site-04` Next.js path-traversal primary/reserve source triplet을 independent external root에 두 번 같은 tree identity로 materialize | file access execution, scanner detection, TP/FP/FN, path-traversal recall, release approval | `FIX_NARROW` |
| P2.4B.2.05 | G1 / P2 | `site-05` Next.js untrusted-redirect primary/reserve source triplet을 independent external root에 두 번 같은 tree identity로 materialize | redirect execution, scanner detection, TP/FP/FN, redirect recall, release approval | `FIX_NARROW` |
| P2.4B.2.06 | G1 / P2 | `site-06` Express SSRF primary preview/reserve avatar source triplet을 independent external root에 두 번 같은 tree identity로 materialize | HTTP execution, scanner detection, TP/FP/FN, SSRF recall, release approval | `FIX_NARROW` |
| P2.4B.2.07 | G1 / P2 | `site-07` Next.js prototype-pollution primary preferences/reserve profile source triplet을 independent external root에 두 번 같은 tree identity로 materialize | prototype mutation execution, scanner detection, TP/FP/FN, prototype-pollution recall, release approval | `FIX_NARROW` |
| P2.4B.2.08 | G1 / P2 | `site-08` Express unsafe-deserialize primary import-settings/reserve restore-session source triplet을 independent external root에 두 번 같은 tree identity로 materialize | deserializer/code execution, scanner detection, TP/FP/FN, unsafe-deserialization recall, release approval | `FIX_NARROW` |
| P2.4B.2.09 | G1 / P2 | `site-09` Next.js client-secret primary checkout/reserve integrations source triplet을 independent external root에 두 번 같은 tree identity로 materialize | real secret validity, client bundle exposure, external request, scanner detection, TP/FP/FN, client-secret recall, release approval | `FIX_NARROW` |
| P2.4B.2.10 | G1 / P2 | `site-10` Express CORS-origin primary checkout/reserve integrations source triplet을 independent external root에 두 번 같은 tree identity로 materialize | browser CORS behavior, cross-origin read, deployed allowlist correctness, scanner detection, TP/FP/FN, CORS-origin recall, release approval | `FIX_NARROW` |
| P2.4B.2.11 | G1 / P2 | `site-11` Django template-XSS primary checkout/reserve integrations source triplet을 independent external root에 두 번 같은 tree identity로 materialize | browser rendering, script execution, Django runtime behavior, scanner detection, TP/FP/FN, template-XSS recall, release approval | `FIX_NARROW` |
| P2.4B.2.12 | G1 / P2 | `site-12` Flask file-read primary exports/reserve templates source triplet을 independent external root에 두 번 같은 tree identity로 materialize | filesystem read, traversal exploit, Flask runtime behavior, scanner detection, TP/FP/FN, file-read recall, release approval | `FIX_NARROW` |
| P2.4B.2.13 | G1 / P2 | `site-13` Java/Spring JDBC query primary/reserve vulnerable/fixed/negative source triplet을 independent external root에 두 번 같은 tree identity로 materialize | JDBC/DB execution, scanner detection, TP/FP/FN, SQLi recall, release approval | `FIX_NARROW` |
| P2.4B.2.14 | G1 / P2 | `site-14` Kotlin/Ktor HTML response primary/reserve vulnerable/fixed/negative source triplet을 independent external root에 두 번 같은 tree identity로 materialize | Kotlin/Ktor runtime, browser/XSS execution, scanner detection, TP/FP/FN, XSS recall, release approval | `FIX_NARROW` |
| P2.4B.2.15 | G1 / P2 | `site-15` Go/chi SQL builder source-tree identity를 external two-run, regression, Claude/Grok/GLM F1/F2 comparator까지 결속 | Go/chi/DB runtime, SQLi exploit, scanner detection, TP/FP/FN, SQLi recall, release approval | `FIX_NARROW` |
| P2.4B.2.16 | G1 / P2 | `data-03` TypeScript/Prisma raw-query source-tree identity를 v2 materializer identity, regression, Claude/Grok/GLM F1/F2 comparator까지 결속 | TypeScript/Prisma/DB runtime, SQLi exploit, scanner detection, TP/FP/FN, SQLi recall, release approval | `FIX_NARROW` |
| P2.4B.2.17 | G1 / P2 | `data-07` Python/FastAPI parameterized-query source-tree identity를 external two-run, regression, Claude/Grok/GLM F1/F2 comparator까지 결속 | Python/FastAPI/SQLite runtime, SQLi exploit, scanner detection, TP/FP/FN, SQLi recall, release approval | `FIX_NARROW` |
| P2.4B.2.18 | G1 / P2 | `data-09` Java/Spring JDBC concat primary/reserve source-tree binding, external r1/r2 repeat, baseline/focused/full regression r1/r2, Claude/Grok/GLM F1/F2 comparator를 결속 | Java/Spring/JDBC runtime, SQLi exploit, scanner detection, TP/FP/FN, SQLi recall, release approval | `FIX_NARROW` |
| P2.4B.2.19 | G1 / P2 | `data-14` Go/pgx query-format primary/reserve source-tree binding, external r1/r2 repeat, baseline/focused/full regression r1/r2, Claude/Grok/GLM F1/F2 comparator를 결속 | Go/pgx/PostgreSQL runtime, SQLi exploit, scanner detection, TP/FP/FN, SQLi recall, release approval | `FIX_NARROW` |
| P2.4B.2.20 | G1 / P2 | 19 source-flow leaf의 fixed-order raw-free evidence inventory와 exclusion `0`을 aggregate r1/r2, regression, 3AI comparator까지 결속 | runtime execution, scanner detection, TP/FP/FN, recall, release approval | `FIX_NARROW` |
| P2.4B.3.01 | G1 / P2 | api-01 Express route-IDOR primary/reserve source-tree identity를 A-G와 3AI F1/F2로 결속 | runtime authorization, exploitability, scanner detection, TP/FP/FN, release approval | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.02 | G1 / P2 | api-02 Next.js service-IDOR primary/reserve source-tree identity를 A-G와 3AI F1/F2로 결속 | runtime authorization, exploitability, scanner detection, TP/FP/FN, release approval | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.03 | G1 / P2 | api-03 Supabase missing-RLS primary/reserve source-tree identity를 A-G와 3AI F1/F2로 결속 | Supabase runtime, RLS enforcement, detector, TP/FP/FN, release approval | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.04 | G1 / P2 | api-04 Firebase open-rule primary/reserve source-tree identity를 A-G와 3AI F1/F2로 결속 | Firebase runtime, rule enforcement, detector, TP/FP/FN, release approval | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.05 | G1 / P2 | api-05 Next.js admin-boundary primary/reserve source-tree identity를 A-G와 3AI F1/F2로 결속 | Next.js runtime authorization, detector, TP/FP/FN, release approval | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.06 | G1 / P2 | api-06 Express mass-assignment primary/reserve source-tree identity를 A-G와 3AI F1/F2로 결속 | Express request/update semantics, detector, TP/FP/FN, release approval | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.07 | G1 / P2 | api-07 Supabase service-role key primary/reserve source-tree identity를 A-G와 3AI F1/F2로 결속 | bundler/runtime, Supabase project access, detector, TP/FP/FN, release approval | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.08 | G1 / P2 | api-08 Firebase storage read-rule primary/reserve source-tree identity를 A-G와 3AI F1/F2로 결속 | Firebase runtime and rule enforcement, detector, TP/FP/FN, release approval | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.09 | G1 / P2 | api-09 FastAPI dependency-auth primary/reserve source-tree identity를 A-G와 3AI F1/F2로 결속 | FastAPI runtime authorization, detector, TP/FP/FN, release approval | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.10 | G1 / P2 | api-10 Django REST object-owner primary/reserve source-tree identity를 A-G와 3AI F1/r3로 결속 | Django REST runtime authorization, object ownership semantics, detector, TP/FP/FN, release approval | `FIX_NARROW` - A-G와 comparator `FIX`; F2 timeout 보존 |
| P2.4B.3.11 | G1 / P2 | api-11 Flask role-guard primary/reserve source-tree identity를 A-G와 3AI F1/r3로 결속 | Flask runtime authorization, role semantics, detector, TP/FP/FN, release approval | `FIX_NARROW` - r2 packet-diff `HOLD` 보존, r1/r3 comparator `FIX` |
| P2.4B.3.12 | G1 / P2 | api-12 Spring method-auth primary/reserve source-tree identity를 A-G와 clarified r2/r3 3AI comparator까지 결속 | Spring runtime authorization, method-security enforcement, detector, TP/FP/FN, release approval | `FIX_NARROW` - initial GLM `HOLD` 보존, r2/r3 comparator `FIX` |
| P2.4B.3.13 | G1 / P2 | api-13 Ktor resource-owner primary/reserve source-tree identity의 current-target A 사전등록을 닫고 B provenance 결속으로 진행 | Ktor runtime authorization, resource ownership semantics, detector, TP/FP/FN, release approval | `ACTIVE` - current-target A DONE, B next; 옛 E/F1 `BLOCKED_PROVIDER` evidence 보존, 현재 target 완료 근거 아님; review lanes 아직 실행 불가 |
| P8.1 | G7 / P8 | G0-G7/P0-P8, 단일 active, A-G와 3AI F1/F2 의무를 canonical state와 validator로 확인 | 탐지 성능, TP/FP/FN, H100, release approval | `FIX_NARROW` - final comparator `FIX` |
| P8.1B | G7 / P8 | current JSON과 세 사람이 읽는 운영판의 active/gate/next marker 동기화 | 탐지 성능, TP/FP/FN, H100, release approval | `FIX_NARROW` - initial D `HOLD` 보존, corrected comparator `FIX` |
| P8.2A | G7 / P8 | Windows npm shim을 Claude/Grok/GLM supervisor subprocess의 executable path로 정규화 | 탐지 성능, supervisor review 내용, TP/FP/FN, H100, release approval | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX`; Windows supervisor contract만 해당 |
| P8.2B | G7 / P8 | Windows long review packet을 native Claude/Cline executable로 전송 | 탐지 성능, supervisor review 내용, TP/FP/FN, H100, release approval | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P8.2D | G7 / P8 | GLM source-free health terminal contract를 strict parser와 결속 | 탐지 성능, supervisor review 내용, TP/FP/FN, H100, release approval | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX`; invalid field ID와 Claude timeout receipt 보존 |
| P8.2E | G7 / P8 | G1-G6 product-card catalog와 phase-exit review binding을 canonical state/validator로 결속 | 탐지 성능, supervisor review 내용, TP/FP/FN, H100, release approval | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX`; registry transition control만 해당 |

P2.4B.2.01부터 .20과 P2.4B.3.01은 각각 G까지 닫혔다. P2.4B.2.17의 two-run
machine/supervisor comparator도 `FIX`였고 Python/FastAPI/SQLite runtime은 명시적으로 비주장이다.
P8.1, P8.1B, data-09, data-14, 19-slot aggregate, api-01, api-02, api-03, api-04, api-05, api-06, api-07, api-08, api-09, api-10, api-11, api-12, P8.2E, P8.2A는 모두 `FIX_NARROW`다. api-12의 initial GLM `HOLD`는 보존했고 clarified r2/r3 comparator `FIX`만 승격 근거다. API13 F1 r1의 Claude/GLM `BLOCKED_PROVIDER`도 보존한다. P8.2B Windows native supervisor transport와 P8.2D GLM health terminal contract도 `FIX_NARROW`다. 현재 `ACTIVE` 카드는 **P2.4B.3.13 API13 Ktor resource-owner**이며 current-target A는 DONE, 다음은 B다. 옛 E/F1 evidence는 현재 target 완료 근거가 아니고 review lanes는 아직 실행할 수 없다.
P2.4B.2.12의 two-run machine/supervisor comparator는 `FIX`였고 single-review
`REPEATABILITY_GAP`은 승격 근거와 구분해 보존했다. P2.4B.2.11의 two-run machine/supervisor
comparator도 `FIX`였고, single-review `REPEATABILITY_GAP`은 승격 근거와 구분해 보존했다.
P2.4B.2.10의 two-run machine comparator와 F1/F3 retry supervisor comparator는 `FIX`였다.
intermediate F2 GLM `BLOCKED_PROVIDER`, health r2 recovery, single-review `REPEATABILITY_GAP`은
승격 근거와 구분해 보존했다. `source-flow` 19개 전체, 60개 생성 pair 전체, P2 또는 제품 자체를
완료로 표시하지 않는다. 전체 leaf 순서는 [P2.4B.2 source-flow WBS](p24b2-source-flow-materialization-wbs-ko.md)가
원본이며, 현재 운영 leaf는 P8.2E의 F1이다.

## 상태를 읽는 법

- `NOT_STARTED`: 목표와 종료 조건은 있으나 작업을 시작하지 않음
- `IN_PROGRESS`: A-E 중 일부를 수행 중이며 성능/출하 근거가 아님
- `PAUSED`: 사전등록 또는 일부 gate는 보존하지만, 현재 단일 active 카드가 아니므로 다음 gate를 시작하지 않음
- `MEASURED_HOLD`: 기계 측정 결과가 기준 미달 또는 불완전
- `TEMPORARY_PENDING_REVIEW`: A-E 증거는 있으나 F1/F2가 아직 닫히지 않음
- `FIX_NARROW`: 한 작은 제품 계약만 종료 조건까지 통과
- `GO_RELEASE`: 모든 P0-P8 종료 조건과 고정 수치가 동시에 충족

## 다음 카드 선택 규칙

1. 열린 카드를 G까지 닫거나 `MEASURED_HOLD`로 기록한다.
2. 카드가 `FIX_NARROW`이면 의존하는 바로 다음 카드 하나만 연다.
3. 정확도 개선은 P3가 baseline 오류군을 계량한 뒤 P4에서만 시작한다.
4. Data-14는 G까지 `FIX_NARROW`로 닫혔으므로 19-slot aggregate의 A 사전등록을 열었다. aggregate는 현재 A만 닫았고, 다음 active는 aggregate가 G까지 닫히거나 `MEASURED_HOLD`가 된 뒤에만 연다.
5. P6 최종 holdout과 고정 기준 전에는 어떤 중간 결과도 출하 `GO`라 부르지 않는다.
