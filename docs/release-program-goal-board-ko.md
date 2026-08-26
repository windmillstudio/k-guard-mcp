# K-Guard 제품 목표 운영판

작성일: 2026-07-23  
상태: `ACTIVE`  
상세 작업 장부: [출하 검증 프로그램 장부](release-program-phase-ledger-ko.md)  
페이즈 실행 지도: [제품 목표 분해와 페이즈 실행 지도](release-program-execution-map-ko.md)  
원자 제품 목표 보드: [원자 제품 목표 보드](release-program-atomic-goals-ko.md)  
목표 계층과 카드/페이즈 종료 기준: [제품 목표 레지스트리](release-program-goal-register-ko.md)  
기계 상태 계약: [goal-state JSON](release-program-goal-state.json) / [목표 통제와 독립 검증 운영](release-program-goal-control-ko.md)  
현재 작업과 종료 순서: [현재 제품 작업 분해와 종료 운영판](release-program-current-work-breakdown-ko.md)  
공통 검증 계약: [Oracle Program Operating Contract](oracle-program-operating-contract-ko.md)

## 이 문서의 역할

이 문서는 "감독관을 불렀다"가 아니라 K-Guard 제품 자체가 어떤 능력을 얻었는지를
작업 카드 단위로 관리하는 운영판이다. 코드 한 조각, 테스트 한 번, 감독관 한 번의
의견만으로는 어떤 카드도 완료가 아니다.

정식 상태와 evidence path/hash의 원본은 항상 출하 검증 프로그램 장부에 둔다. 이
운영판은 그 원본을 대체하지 않고, 다음에 무엇을 끝내야 하는지와 각 작업이 제품
목표에 왜 필요한지를 한눈에 보이게 한다. 실제 구현 순서와 카드별 상태는 원자 제품
목표 보드에서 관리하며, 감독 검토는 그 카드의 F gate다.

## 북극성과 제품 목표

**북극성:** K-Guard는 한국 바이브코더가 출하 직전에 호출하는 시니어 감사관 스타일의
fail-closed release gate다. 사이트, API, 데이터, 운영 중 어느 한 영역이라도 근거가
부족하면 전체 결과는 `HOLD`다.

| 목표 ID | 제품 목표 | 완료를 뜻하는 상태 | 현재 위치 |
| --- | --- | --- | --- |
| G1 | 정직한 분모와 재현 가능한 oracle | source, license, exclusion, vulnerable/fixed 결과가 재현되고 finding:scenario가 1:1로 묶임 | 진행 중 |
| G2 | 측정 가능한 탐지 성능 | TP/FP/FN/TN, recall, specificity, Wilson, coverage가 기계적으로 계산됨 | 시작 전 |
| G3 | 정확한 Guardian 출하 게이트 | 가장 큰 오류군 하나씩 observe -> warn -> block으로만 승격 | 시작 전 |
| G4-S | 사이트 검토 깊이 | 정적 취약점, 허가된 local web path, XSS/주입, coverage HOLD가 oracle로 입증됨 | phase 시작 전 |
| G4-A | API 검토 깊이 | 인증/인가, IDOR/BOLA, route-to-service 경계가 oracle로 입증됨 | phase 시작 전 |
| G4-D | 데이터 검토 깊이 | SQL/RLS, 저장/로그/전송, 한국 개인정보, 보존/파기가 oracle로 입증됨 | phase 시작 전 |
| G4-O | 운영 검토 깊이 | secrets, SCA, CI/IaC, MCP runtime, protocol, suppression/CI 정책이 oracle로 입증됨 | phase 시작 전 |
| G5 | 실제 사용 가능성 | clean 설치, CLI, stdio MCP, GPT/Grok/Codex/Antigravity에서 같은 Guardian 결론을 재현 | phase 시작 전; 과거 smoke는 최종 증거가 아님 |
| G6 | 정직한 출하 주장 | H100, 모든 수치 gate, 반복성, 3AI 최종 처분이 동시에 통과 | 시작 전 |
| G7 | 목표 통제와 독립 검증 운영 | G1-G6의 원자 카드, 단일 active, card/phase F1/F2, GO_RELEASE claim refusal을 기계적으로 확인 | 진행 중 |

`G4-S/A/D/O` 중 하나라도 미달하면 G6은 `GO_RELEASE`가 될 수 없다. 평균 점수로
다른 평면의 실패를 상쇄하지 않는다.

## 카드 완료 규칙

모든 `P*.*` 카드는 아래 순서가 끝나기 전에는 다음 카드의 전제조건을 만족하지 않는다.

| 순서 | 카드 안에서 끝낼 일 | 통과 판정 |
| --- | --- | --- |
| A | 가설, oracle, 입력, 제외, claim boundary 사전등록 | 결과를 본 뒤 기준/표본을 바꿀 수 없음 |
| B | 코드 diff 또는 공개 source/oracle provenance를 target hash에 결속 | target drift면 처음부터 다시 실행 |
| C | 변경 경계 focused test | fail-closed negative test를 포함해 통과 |
| D | local execution/materialization을 독립 output으로 두 번 실행 | semantic comparator가 일치 |
| E | 전체 회귀, coverage, 호환성 확인 | 누락, error, flaky 결과는 `HOLD` |
| F1 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2의 첫 독립 검토 | 모두 `GO`여도 반복 전에는 승격 금지 |
| F2 | 같은 target과 packet으로 세 감독관의 두 번째 검토 | supervisor semantic comparator가 `FIX` |
| G | 장부에 evidence hash, comparator, 남은 비주장 범위를 기록 | 이때만 `FIX_NARROW` 가능 |

감독관은 ground truth, severity, 합격선을 바꾸지 않는다. Claude는 지정 파일을
read-only로 직접 검토하고, Grok과 GLM은 같은 raw-free evidence packet을 독립적으로
검토한다. 세 lane 중 하나라도 `HOLD`, `BLOCKED`, timeout, model/target/packet drift면
카드는 `TEMPORARY_PENDING_REVIEW` 또는 `MEASURED_HOLD`다. 다음 비승격 측정만 가능하며
`FIX_NARROW`, 수치 점수, H100, release 근거에는 넣지 않는다.

## 제품 목표별 작업 카드

### G1. 정직한 분모와 oracle

| 카드 | 달성할 한 가지 | 완료 증거 | 상태 |
| --- | --- | --- | --- |
| P0.1-P0.4 | 기준선, 전체 회귀, 감독관 실행 경로를 봉인 | target/toolchain receipt와 3AI 반복 comparator | `FIX_NARROW` |
| P1.1B | 공통 oracle schema와 severity 규칙을 full registry에 적용 | schema validator와 negative fixture | 대기 |
| P1.2B | High/Critical/blocker finding:scenario 1:1 위반 시 점수 산출 거부 | score-refusal test와 receipt | 대기 |
| P1.3B | response 후보가 있는 current source의 raw-free receipt를 두 번 생성 | response binding comparator | 대기 |
| P1.4C | local execution oracle을 positive/negative pair로 전부 확대 | six-app source-bound pair receipt | 대기 |
| P1.6A | G1의 완료/미완료 범위를 phase packet으로 분리 | 3AI phase review comparator | 대기 |

### G1. 공개 분모와 holdout 재료

| 카드 | 달성할 한 가지 | 완료 증거 | 상태 |
| --- | --- | --- | --- |
| P2.1A-P2.2B | OWASP BenchmarkJava/Python 전량의 공식 분모를 clean worktree 두 곳에서 재현 | official source/license/expected-result comparator | `FIX_NARROW` |
| P2.3A | 6개 local app의 source, license, revision, 허용 runtime을 봉인 | six-source registry | `FIX_NARROW` |
| P2.3B.1 | WebGoat IDOR positive/negative execution boundary | source-bound pair와 3AI comparator | `FIX_NARROW` |
| P2.3B.2 | Juice Shop BOLA execution boundary | source-bound pair와 3AI comparator | `FIX_NARROW` |
| P2.3B.3 | NodeGoat IDOR execution boundary | source-bound pair와 3AI comparator | `FIX_NARROW` |
| P2.3B.4 | PyGoat sensitive-data execution boundary | source-bound pair와 3AI comparator | `FIX_NARROW` |
| P2.3B.5 | crAPI vehicle BOLA execution boundary | source-bound positive/negative pair, cleanup, repeat comparator | `FIX_NARROW` |
| P2.3B.6 | WrongSecrets execution boundary | Maven branch `MEASURED_HOLD` 보존 후 [Challenge1 Javac harness source-bound pair](p23b6-wrongsecrets-challenge1-javac-harness-preregistration-ko.md), 3AI 2회 comparator | `FIX_NARROW` |
| P2.3B.7 | [6개 앱의 coverage/exclusion/repeat aggregate](p23b7-six-app-execution-aggregate-preregistration-ko.md) | six-app aggregate manifest와 3AI comparator | `FIX_NARROW` |
| P2.4A | [개발 generated pair 60 청사진 사전등록](p24a-generated-pair-blueprint-preregistration-ko.md) | 60 slot quota/oracle/reserve blueprint의 external two-run comparator와 3AI two-run review | `FIX_NARROW` |
| P2.4B.1 | [external source-triplet staging contract](p24b1-generated-pair-staging-preregistration-ko.md) | 60/120/360 slot-reserve-path/raw-free repeat comparator와 3AI two-run review | `FIX_NARROW` |
| P2.4B.2 | [`source-flow` 19개 slot leaf materialization](p24b2-source-flow-materialization-wbs-ko.md) | leaf별 primary/reserve tree comparator와 3AI two-run review | `FIX_NARROW` - .01-.20 A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3 | [`auth-rls-db` 19개 leaf materialization](p24b3-auth-rls-db-materialization-wbs-ko.md) | leaf별 primary/reserve tree comparator와 3AI two-run review | `IN_PROGRESS` - .01-.10 `FIX_NARROW`, .11 A 완료, B 진행 |
| P2.4B.4-P2.4B.8 | [나머지 family/admission/aggregate microcard](p24b-generated-pair-materialization-wbs-ko.md) | family/aggregate manifest comparator와 3AI two-run review | 대기 |
| P2.5A-P2.5B | 공개 source stress 100개 provenance와 top/mid/long-tail 층화 고정 | acquisition/stratification manifest | 대기 |
| P2.6A-P2.6B | H100 membership, 4개 평면 25개씩, severity/exclusion을 결과 전 동결 | H100/plane-balance receipt | 대기 |
| P2.7A | 전체 P2 provenance/exclusion을 3AI가 두 번 검토 | phase review comparator | 대기 |

### G2. 측정 가능한 기준선

| 카드 | 달성할 한 가지 | 완료 증거 | 상태 |
| --- | --- | --- | --- |
| P3.1A-P3.1B | frozen denominator에 대한 scanner input/timeout/coverage 계약과 동일 결과 두 번 | baseline contract와 repeat comparator | 대기 |
| P3.2A | TP/FP/FN/TN와 Wilson을 fail-closed로 계산 | scorer test/receipt | 대기 |
| P3.2B | 평면별 actionability, recall, specificity, app-complete 계산 | metric report | 대기 |
| P3.3A | rule/subtype/language/plane 후보 편중 계산 | distribution report | 대기 |
| P3.4A | unsupported/timeout/control error를 통과가 아닌 `HOLD`로 집계 | coverage hold report | 대기 |
| P3.5A | baseline claim boundary와 가장 큰 오류군을 3AI가 두 번 검토 | phase review comparator | 대기 |

### G3. 한 오류군씩 교정하는 Guardian

| 카드 | 달성할 한 가지 | 완료 증거 | 상태 |
| --- | --- | --- | --- |
| P4.1A | 가장 큰 단일 오류군과 개발 분모를 사전등록 | hypothesis receipt | 대기 |
| P4.2A | 새 개선을 observe-only로 구현하고 기존 block 영향 0 확인 | shadow comparison | 대기 |
| P4.3A | 동일 분모 paired A/B에서 recall/specificity/speed/repeatability 비교 | A/B report | 대기 |
| P4.4A | 충분한 독립 oracle이 있을 때 warn으로만 승격 | warning gate receipt | 대기 |
| P4.5A | 사전등록 holdout과 전체 수치 기준 통과 시에만 block 승격 | block gate receipt | 대기 |
| P4.6A | 가설 하나, 변경 하나, 증거 하나를 3AI가 두 번 검토 | phase review comparator | 대기 |

P4는 오류군마다 반복한다. 하나를 고쳤다고 다른 오류군까지 완료 처리하지 않는다.

### G4. 사이트, API, 데이터, 운영의 제품 깊이

각 평면은 아래 여섯 카드가 전부 `FIX_NARROW`이고 해당 phase review까지 통과해야만
"그 평면의 측정 준비가 완료"다. 이는 탐지 성능이나 release GO와는 별개다.

| 평면 | 카드 1 | 카드 2 | 카드 3 | 카드 4 | 카드 5 | 카드 6 |
| --- | --- | --- | --- | --- | --- |
| P5.S 사이트 | static/XSS/injection oracle | local web execution | 최대 오류군 A/B | coverage HOLD | Guardian UX/호환성 | 3AI phase review |
| P5.A API | auth/IDOR/BOLA oracle | route/service execution | 최대 오류군 A/B | coverage HOLD | Guardian UX/호환성 | 3AI phase review |
| P5.D 데이터 | SQL/RLS/PII/retention oracle | read-only connector execution | 최대 오류군 A/B | coverage HOLD | Korean PII UX/호환성 | 3AI phase review |
| P5.O 운영 | secret/SCA/CI-IaC/MCP oracle | runtime/protocol execution | 최대 오류군 A/B | coverage HOLD | suppression/CI UX/호환성 | 3AI phase review |

### G5. 실제 사용 가능성

| 카드 | 달성할 한 가지 | 완료 증거 | 상태 |
| --- | --- | --- | --- |
| P7.1A | fresh wheel, stdio, CLI, evidence binding을 깨끗한 환경에서 재현 | install receipt | `IN_PROGRESS` - 과거 smoke 증거만 있으며 최종 target 재현은 미완료 |
| P7.2A | GPT, Grok, Codex, Antigravity 설치 경로와 tool list 확인 | client compatibility receipt | `IN_PROGRESS` - 과거 확인만 있으며 최종 target 재현은 미완료 |
| P7.3A | license, SBOM, known limits를 포함한 raw-free release bundle | release bundle hash | 대기 |
| P7.4A | Guardian이 모든 exit gate로 canonical GO/HOLD를 계산 | canonical disposition | 대기 |

### G6. 최종 출하 주장

| 카드 | 달성할 한 가지 | 완료 증거 | 상태 |
| --- | --- | --- | --- |
| P6.1A | analyzer/rule/toolchain/H100/labels hash를 one-way freeze | freeze receipt | 대기 |
| P6.2A | H100 blind run과 oracle scoring을 분리 실행 | immutable blind-run bundle | 대기 |
| P6.3A | 전체/평면/Critical/specificity/concentration/speed gate 계산 | final metrics receipt | 대기 |
| P6.4A | 수정 없는 두 번째 H100 run의 semantic equality | repeat comparator | 대기 |
| P6.5A | release disposition을 3AI가 두 번 독립 검토 | release review comparator | 대기 |

### G7. 목표 통제와 독립 검증 운영

| 카드 | 달성할 한 가지 | 완료 증거 | 상태 |
| --- | --- | --- | --- |
| P8.1 | [G0-G7/P0-P8, 단일 active, A-G, 3AI F1/F2를 canonical state로 고정](release-program-goal-control-ko.md) | state validator, negative test, machine two-run, final 3AI comparator | `FIX_NARROW` |
| P8.2A | Windows npm shim supervisor command resolution | resolver, command-builder test, health r1/r2, 3AI comparator | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX`; Windows supervisor contract만 해당 |
| P8.2B | Windows native supervisor transport | native resolver, long-packet transport probe/comparator, r1/r2, 3AI comparator | `FIX_NARROW` |
| P8.2D | GLM source-free health terminal contract | system contract, strict parser negative test, health r1/r2, 3AI comparator | `FIX_NARROW` - A-G와 3AI comparator `FIX`; invalid field ID와 Claude timeout receipt 보존 |
| P8.2E | G1-G6 product-card catalog와 phase-exit review binding | catalog schema, predecessor/phase-exit validator, 3AI comparator | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX`; registry transition control만 해당 |
| P8.2C | `FIX_NARROW`와 phase 상태를 receipt/comparator hash에 결속 | receipt-link validator와 negative fixture | 대기 |
| P8.3 | phase child/exclusion/F1/F2를 phase packet으로 결속 | phase packet comparator | 대기 |
| P8.4 | G1-G7/P0-P8 미달이면 canonical release claim을 거부 | final disposition validator | 대기 |
| P7.5A | 최종 packet의 3AI 만장일치와 canonical Guardian 판정 | unanimous comparator | 대기 |

## 현재 순서와 호출 시점

현재 구현/측정 작업은 하나만 열어 둔다.

1. **P2.3B.5 crAPI vehicle BOLA**: A-G와 supervisor comparator를 통과해 `FIX_NARROW`로 기록됐다. 이는 한 local execution oracle pair이지 BOLA/IDOR 탐지 성능이 아니다.
2. **P2.3B.6 WrongSecrets**: Maven branch `MEASURED_HOLD`를 보존한 채, Javac harness source-bound positive/negative pair, focused test, 두 번 실행, full regression, 3AI 2회 comparator를 통과해 `FIX_NARROW`로 기록됐다. 이는 Challenge1 한 predicate의 좁은 실행 oracle이다.
3. **P2.3B.7 six-app aggregate**: [aggregate 사전등록](p23b7-six-app-execution-aggregate-preregistration-ko.md)의 6개 앱/18개 component, exclusion `0`, raw-free authority contract, 3AI two-run comparator를 통과해 `FIX_NARROW`로 기록됐다. 이는 새 앱 실행이나 탐지 성능이 아니다.
4. **P2.4A generated pair 60 청사진 사전등록**: [60 slot blueprint](p24a-generated-pair-blueprint-preregistration-ko.md)의 60 slot, plane/severity/oracle/reserve, external repeatability, 3AI two-run review를 `FIX_NARROW`로 완료했다. 이 결과는 실제 pair나 detector accuracy가 아니다.
5. **P2.4B.1 staging contract**: [사전등록과 결과](p24b1-generated-pair-staging-preregistration-ko.md)의 external source-triplet stage와 slot/reserve binding은 machine repeat과 3AI two-run comparator를 통과해 `FIX_NARROW`다. 이는 빈 path reservation뿐이며 source, execution, detector 성능을 뜻하지 않는다.
6. **P2.4B.2.01 site-01 source-flow**: primary/reserve의 6 source tree를 external r1/r2와 3AI two-run comparator로 `FIX_NARROW` 완료했다. 이것은 site-01 tree identity뿐이며 execution·scanner·metric은 아니다.
7. **P2.4B.2.02 site-02 source-flow**: [사전등록과 결과](p24b202-site02-source-flow-preregistration-ko.md)의 JavaScript/Express SQL query primary/reserve 6 source tree, focused test, source comparator, Claude/Grok/GLM two-run comparator가 `FIX_NARROW`다. 이 결과는 source tree identity뿐이며 execution·scanner·metric은 아니다.
8. **P2.4B.2.03 site-03 source-flow**: [사전등록과 결과](p24b203-site03-source-flow-preregistration-ko.md)의 JavaScript/Express command-exec primary/reserve 6 source tree, focused/full attestation, source comparator, Claude/Grok/GLM r3/r4 comparator가 `FIX_NARROW`다. r1/r2의 GLM `TEST_ATTESTATION_GAP`은 삭제하지 않고 결과 문서에 남아 있다. 이 결과는 source tree identity뿐이며 execution·scanner·metric은 아니다.
9. **P2.4B.2.04 site-04 path-traversal**: [사전등록과 결과](p24b204-site04-source-flow-preregistration-ko.md)의 Next.js primary/reserve source triplet, focused/full regression, machine repeat, Claude/Grok/GLM two-run comparator가 `FIX_NARROW`다. 각 단회 review의 `REPEATABILITY_GAP` HOLD도 보존했다. 이 결과는 source tree identity뿐이다.
10. **P2.4B.2.05 site-05 untrusted-redirect**: [사전등록과 결과](p24b205-site05-source-flow-preregistration-ko.md)의 Next.js continue/signin primary/reserve source triplet, focused/full regression, machine repeat, Claude/Grok/GLM two-run comparator가 `FIX_NARROW`다. 이전 target의 first full `CONTROL_HOLD`와 health-only GLM `BLOCKED_PROVIDER`는 삭제하지 않고 F packet에 포함했다. 이 결과는 source tree identity뿐이며 redirect execution·scanner·metric은 아니다.
11. **P2.4B.2.06 site-06 ssrf-fetch**: [사전등록과 결과](p24b206-site06-source-flow-preregistration-ko.md)의 Express preview/avatar route, `url`/`imageUrl`, candidate별 `https` allowlist, static internal negative control, strict writer/comparator, focused test, external r1/r2 comparator, Claude/Grok/GLM F1/F2 semantic comparator가 `FIX_NARROW`다. 이 결과는 source tree identity만 뜻하며 HTTP/SSRF execution·scanner·metric은 아니다.
12. **P2.4B.2.07 site-07 prototype-pollution**: [사전등록과 결과](p24b207-site07-source-flow-preregistration-ko.md)의 Next.js preferences/profile source triplet, focused/full regression, machine repeat, Claude/Grok/GLM F1/F2 comparator가 `FIX_NARROW`다. 이 결과는 source tree identity뿐이며 prototype execution·scanner·metric은 아니다.
13. **P8.1 목표 통제**: final target의 state validator, generic next-card positive test, external two-run, `2650 passed/5 skipped` full regression, Claude/Grok/GLM F1/F2 comparator `FIX`로 `FIX_NARROW`가 됐다. 이는 운영 통제만 뜻한다.
14. **P2.4B.2.15 site-15**: Go/chi SQL builder source tree의 A-G를 모두 닫았다. external r1/r2 source comparator, focused 5/5, full r1/r2 각각 2,655 passed, Claude/Grok/GLM F1/F2 lane `GO`, supervisor comparator `FIX`로 `FIX_NARROW`다. 이 결과는 source tree identity뿐이다.
15. **P2.4B.2.16 data-03**: TypeScript/Prisma raw-query의 A-G를 닫았다. v2 external r1/r2 source comparator, focused 20/20, full r1/r2 각 2,663 passed/5 skipped, Claude/Grok/GLM F1/F2 lane `GO`, supervisor comparator `FIX`로 `FIX_NARROW`다. 이 결과는 source tree identity뿐이다.
16. **P2.4B.2.17 data-07**: Python/FastAPI parameterized-query의 A-G를 닫았다. external r1/r2 source comparator, focused 35/35, full r2/r3 각 2,669 passed/5 skipped, Claude/Grok/GLM F1/F2 lane `GO`, supervisor comparator `FIX`로 `FIX_NARROW`다. initial full r1의 stale goal-state expectation `CONTROL_HOLD`는 보존하고 승격 근거에서 제외했다. 이 결과는 source tree identity뿐이다.
17. **P2.4B.2.18 data-09**: Java/Spring JDBC concat의 primary/reserve route, input, table, `Statement` concat과 `PreparedStatement` fixed boundary, static negative와 비주장을 A에서 고정했다. B/C focused `41 passed`, D external r1/r2 comparator `FIX`, E full r1/r2 각 `2675 passed, 5 skipped`, Claude/Grok/GLM F1/F2 lane `GO`, supervisor comparator `FIX`로 `FIX_NARROW`다. 이 결과는 source tree identity뿐이다.
18. **P2.4B.2.19 data-14**: Go/pgx query-format의 primary/reserve route, input, table, `fmt.Sprintf` vulnerable boundary, `$1` fixed boundary, static negative와 비주장을 A에서 고정했다. B/C focused `47 passed`, D external r1/r2 comparator `FIX`, E full r1/r2 각 `2681 passed, 5 skipped`, Claude/Grok/GLM F1/F2 lane `GO`, supervisor comparator `FIX`로 `FIX_NARROW`다. 이 결과는 source tree identity뿐이다.
19. **P2.4B.2.20 aggregate**: 19 slot, 38 candidates, 114 source triplets, 342 files, fixed slot order와 exclusion `0`을 A에서 고정했다. B/C focused `6 passed`, D external r1/r2 aggregate comparator `FIX`, E baseline/focused/full, F1/F2 all-lane `GO`, G supervisor comparator `FIX`를 닫아 `FIX_NARROW`다. initial full r1 `CONTROL_HOLD`는 보존했고 source inventory 이외의 주장은 추가하지 않는다.
20. **P2.4B.3.01 api-01 route-IDOR**: 첫 Express route ownership source-tree의 A-G를 닫았다. full r1의 single `CONTROL_HOLD`는 보존하고 full r2/r3의 동일 target `2693 passed, 5 skipped`를 확보했다. Claude Opus 4.8/Grok 4.5/Cline GLM 5.2 F1/F2는 모두 `GO`, supervisor comparator는 `FIX`다. 이 결과는 source-tree identity뿐이다.
21. **P2.4B.3.02 api-02 service-IDOR**: Next.js service ownership leaf의 A-G를 닫았다. current baseline, focused 36 passed, full r1/r2/r3 각 2,701 passed/5 skipped, Claude/Grok/GLM F1/F2 all-lane `GO`, supervisor comparator `FIX`로 `FIX_NARROW`다. 이 결과는 source-tree identity뿐이다.
18. 새 카드도 A-E가 끝난 뒤에만 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2을 같은 raw-free packet으로 두 번 호출한다. semantic comparator가 `FIX`일 때만 그 카드의 `FIX_NARROW` 승격을 허용한다. 한 카드의 실패를 다른 카드 완료로 상쇄하지 않는다.

외부 감독관은 코드 작성 중간이나 health check만으로 호출하지 않는다. **A-E가 끝난 카드의
F 단계에서만** 호출하며, 그 카드의 G 단계가 끝나기 전에는 다음 제품 주장을 추가하지
않는다.

## 금지 규칙

- 테스트 하나가 통과했다고 제품 목표를 완료로 표시하지 않는다.
- 감독관 한 명의 `GO`, 한 번의 review, 또는 health check를 `FIX_NARROW`로 쓰지 않는다.
- response/raw finding, token, credential, 고객 데이터는 evidence packet에 넣지 않는다.
- 결과를 본 뒤 H100 membership, oracle label, severity, threshold를 완화하지 않는다.
- coverage limit, timeout, unsupported path, control error는 성공이 아니라 `HOLD`다.
- `FIX_NARROW`의 수를 accuracy, senior-equivalence, release readiness 퍼센트로 환산하지 않는다.

## 한 줄 상태

현재 제품은 **운영/분모/oracle 준비를 검증 중인 `HOLD` 후보**다. P2.4A 청사진,
P2.4B.1 staging contract, P2.4B.2.01 site-01부터 P2.4B.2.17 data-07까지의 source tree는 각각 `FIX_NARROW`로 닫혔다.
P8.1 목표 통제, P8.1B human-status-board sync, Data-09, Data-14, P2.4B.2.20, P2.4B.3.01,
P2.4B.3.02, P2.4B.3.03, P2.4B.3.04, P2.4B.3.05, P2.4B.3.06, P2.4B.3.07, P2.4B.3.08, P2.4B.3.09, P2.4B.3.10, P2.4B.3.11, P2.4B.3.12, P8.2B, P8.2D, P8.2E, P8.2A는 각각 `FIX_NARROW`다. api-12의 initial GLM `HOLD`, API13 및 P8.2A health/F1 `BLOCKED_PROVIDER`는 보존한다. 현재 카드는 **P2.4B.3.13 API13 Ktor resource-owner**의 F1이며,
별도 탐지 성능이나 출하 가능성 주장은 계속 하지 않는다.
