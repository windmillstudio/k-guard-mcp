# K-Guard 제품 작업 카드 카탈로그

작성일: 2026-07-25  
상태: `ACTIVE` - 계획과 순서는 고정했지만 제품 출하는 `HOLD`  
공식 현재 카드: [goal-state JSON](release-program-goal-state.json)의 `P2.4B.3.13`  
상세 근거 장부: [원자 제품 목표 보드](release-program-atomic-goals-ko.md)

## 이 문서의 역할

감독 실행기만 관리하지 않는다. K-Guard가 실제로 얻어야 할 제품 능력을 작은 카드로
나누고, 한 카드가 끝나기 전에는 다음 카드를 열지 않는 순서를 적는다.

`FIX_NARROW`는 그 카드에 적힌 한 가지 계약만 끝났다는 뜻이다. 탐지 정확도, 시니어
동등성, 한국 개인정보 완결성, 출하 `GO`를 뜻하지 않는다. 카드가 많거나 완료 카드가
많아도 전체 평균으로 통과시키지 않는다.

`P8.2D`는 GLM health terminal contract를, `P8.2E`는 이 카탈로그의 machine-readable registry와
validator 결속을, `P8.2A`는 Windows supervisor command resolution을 각각 `FIX_NARROW`로 닫았다.
현재 `P2.4B.3.13`은 새 supervisor target에서 E baseline/focused/full을 재검증해 닫았고, 같은
raw-free packet의 F1 독립 검토를 대기한다. 이 전이는 제품 성능 카드나 출하 주장을 새로 열지 않는다.

## 모든 카드의 고정 종료 규칙

| Gate | 해야 할 일 | 실패 시 처분 |
| --- | --- | --- |
| A | 가설, 입력, oracle, 제외, 성공 조건과 비주장을 결과 전에 고정 | `HOLD`, 다음 gate 금지 |
| B | 코드, 공개 source, 실행 환경 또는 규칙을 target hash에 결속 | drift면 A부터 다시 시작 |
| C | focused positive/negative와 fail-closed test | negative/control error가 약하면 `HOLD` |
| D | 외부 root 또는 독립 실행을 두 번 수행하고 semantic comparator 생성 | 불일치면 `HOLD` |
| E | baseline, full regression, coverage, 호환성 확인 | timeout, 누락, unsupported, control error는 `HOLD` |
| F1 | Claude Opus 4.8, Grok 4.5, GLM 5.2가 같은 packet을 독립 검토 | 한 lane이라도 비정상이면 승격 금지 |
| F2 | 같은 target과 packet으로 세 모델의 두 번째 독립 검토 | F1/F2 comparator가 `FIX`가 아니면 승격 금지 |
| G | hash, comparator, 남은 비주장을 장부에 기록 | 이때만 `FIX_NARROW` |

세 모델의 역할은 oracle label을 만드는 일이 아니라, evidence binding, 재현성, 누락, 과장된
주장을 반박하는 일이다. 한 모델이 응답하지 않으면 관찰용 측정은 할 수 있어도 카드나 페이즈를
`FIX_NARROW`로 올리지 않는다.

## 페이즈 종료의 별도 검토

각 leaf 카드의 F1/F2는 페이즈 완료를 대신하지 않는다. 페이즈의 모든 child가 닫힌 뒤에는
아래의 `phase exit` 카드를 연다.

1. child ID, evidence hash, 제외 항목, 비주장을 raw-free phase packet에 고정한다.
2. Claude Opus 4.8, Grok 4.5, GLM 5.2가 packet을 F1과 F2로 각각 검토한다.
3. 두 검토의 semantic comparator가 `FIX`여야 페이즈를 `FIX_NARROW`로 기록한다.
4. 한 child라도 `NOT_STARTED`, `PAUSED`, `MEASURED_HOLD`, `BLOCKED`이면 phase exit은 열리지 않는다.

## 작업 순서

```text
P8.2D GLM health contract
  -> P8.2E product-card registry binding
  -> P8.2A supervisor command current-target revalidation
  -> P2.4B.3.13 API-13 재개
  -> P2 나머지 표본과 oracle
  -> P3 측정 엔진
  -> P4 가장 큰 오류군 하나의 observe/warn/block
  -> P5 사이트/API/데이터/운영 깊이
  -> P6 H100 blind holdout
  -> P7 설치와 클라이언트 호환
  -> P8 phase exit 및 최종 처분
```

이 순서는 속도를 위해 병렬로 열지 않는다. 독립적으로 안전한 준비 작업은 기록할 수 있지만,
다음 카드의 B 이후 실행과 승격은 현재 카드의 G 또는 명시적 `MEASURED_HOLD` 뒤에만 한다.

## G1. 정직한 분모와 oracle

| ID | 한 가지 완료 목표 | 선행 카드 | 상태 |
| --- | --- | --- | --- |
| P0.5A | 기준선, toolchain, clean/full regression, AI 실행 경로의 P0 phase packet | historical P0 leaves | `FIX_NARROW` |
| P1.1B | 모든 registry의 oracle schema와 severity를 기계 검증 | P0.5A | `NOT_STARTED` |
| P1.2B | High/Critical/blocker finding:scenario 1:1 미충족 시 scoring 거부 | P1.1B | `NOT_STARTED` |
| P1.3B | response 후보 raw-free receipt의 두 번 binding 비교 | P1.2B | `NOT_STARTED` |
| P1.4C | local execution positive/negative pair의 공통 admission | P1.3B | `NOT_STARTED` |
| P1.6A phase exit | P1 packet의 독립 3AI F1/F2 | P1.1B-P1.4C | `NOT_STARTED` |

## G1. P2 공개 분모, 생성 pair, holdout

이미 좁게 닫힌 historical source-tree 카드도 runtime exploit, detector recall, TP/FP/FN, H100,
release를 승인하지 않는다. 그 점을 잊지 않기 위해 아래에서 closed source identity와 앞으로의
execution/scoring 카드를 분리한다.

| ID | 한 가지 완료 목표 | 선행 카드 | 상태 |
| --- | --- | --- | --- |
| P2.1A / P2.1B | OWASP BenchmarkJava 공식 분모와 independent clean-worktree repeat | P0.5A | `FIX_NARROW` |
| P2.2A / P2.2B | OWASP BenchmarkPython 공식 분모와 independent clean-worktree repeat | P0.5A | `FIX_NARROW` |
| P2.3A / P2.3B.7 | 여섯 local app의 source registry, execution oracle, aggregate provenance | P1.4C | `FIX_NARROW` |
| P2.4A | generated pair 60개 blueprint의 결과 전 동결 | P1.4C | `FIX_NARROW` |
| P2.4B.1 | external staging layout, slot/reserve/path/raw-free contract | P2.4A | `FIX_NARROW` |
| P2.4B.2 | source-flow 19개 source-triplet identity와 aggregate | P2.4B.1 | `FIX_NARROW` |
| P2.4B.3.01-.12 | auth/RLS/DB leaf 12개의 source-tree identity | P2.4B.2 | `FIX_NARROW` |
| P2.4B.3.13 | Ktor resource-owner source-tree identity의 새 supervisor target E 재검증 | P8.2A | `ACTIVE` - A-E 완료, raw-free packet F1 |
| P2.4B.3.14 | Go chi handler BOLA source-tree identity | P2.4B.3.13 | `NOT_STARTED` |
| P2.4B.3.15 | Go gin middleware auth source-tree identity | P2.4B.3.14 | `NOT_STARTED` |
| P2.4B.3.16 | Supabase PostgreSQL RLS-disabled source-tree identity | P2.4B.3.15 | `NOT_STARTED` |
| P2.4B.3.17 | Prisma broad-grant source-tree identity | P2.4B.3.16 | `NOT_STARTED` |
| P2.4B.3.18 | Spring tenant-policy source-tree identity | P2.4B.3.17 | `NOT_STARTED` |
| P2.4B.3.19 | Ktor row-filter source-tree identity | P2.4B.3.18 | `NOT_STARTED` |
| P2.4B.3.20 | 19-slot auth/RLS/DB family aggregate와 exclusion `0` | P2.4B.3.19 | `NOT_STARTED` |
| P2.4B.4 | dependency/SCA 7개 source triplet deterministic materialization | P2.4B.3.20 | `NOT_STARTED` |
| P2.4B.5 | GHA/Docker/IaC 8개 source triplet deterministic materialization | P2.4B.4 | `NOT_STARTED` |
| P2.4B.6 | policy/K-privacy 7개 source triplet deterministic materialization | P2.4B.5 | `NOT_STARTED` |
| P2.4B.7 | 60 primary vulnerable/fixed/negative execution, patch/invariant admission | P2.4B.6 | `NOT_STARTED` |
| P2.4B.8 | 60-slot aggregate, exclusion `0`, two materialization repeat, P2.4B phase review | P2.4B.7 | `NOT_STARTED` |
| P2.5A | 공개 stress 앱 100개의 source, license, strata provenance | P2.4B.8 | `NOT_STARTED` |
| P2.5B | public stress sample의 duplicate, scope, exclusion fail-closed admission | P2.5A | `NOT_STARTED` |
| P2.6A | H100 membership과 4개 평면 25개씩의 사전등록 | P2.5B | `NOT_STARTED` |
| P2.6B | H100 severity, exclusion, blinded-label access 경계 동결 | P2.6A | `NOT_STARTED` |
| P2.7A phase exit | P2 provenance/exclusion phase packet의 3AI F1/F2 | P2.6B | `NOT_STARTED` |

## G2. 측정 가능한 탐지 성능

| ID | 한 가지 완료 목표 | 선행 카드 | 상태 |
| --- | --- | --- | --- |
| P3.1A | scanner input, timeout, supported-file coverage 계약의 repeat | P2.7A | `NOT_STARTED` |
| P3.1B | 전수 scan 미완료 시 Guardian이 통과 대신 `HOLD` | P3.1A | `NOT_STARTED` |
| P3.2A | oracle 없는 TP/FP/FN/TN과 Wilson 계산 거부 | P3.1B | `NOT_STARTED` |
| P3.2B | 평면별 actionability, recall, specificity, app-complete 계산 | P3.2A | `NOT_STARTED` |
| P3.3A | rule/subtype/language/plane 후보 편중 계산 | P3.2B | `NOT_STARTED` |
| P3.4A | timeout, unsupported, control error를 coverage `HOLD`로 집계 | P3.3A | `NOT_STARTED` |
| P3.5A phase exit | baseline 오류군과 claim boundary phase packet의 3AI F1/F2 | P3.4A | `NOT_STARTED` |

## G3. 가장 큰 오류군 하나씩 Guardian에 승격

`selected`는 P3.5A가 모집단 가중 손실 1위를 측정한 뒤에만 실제 오류군 이름으로 바꾼다.
그 전에는 XSS, IDOR, 개인정보, SCA 중 무엇이든 임의로 block rule로 올리지 않는다.

| ID | 한 가지 완료 목표 | 선행 카드 | 상태 |
| --- | --- | --- | --- |
| P4.0A | 오류군 선택, 개발 분모, label, 목표 수치 사전등록 | P3.5A | `NOT_STARTED` |
| P4.selected.1A | 선택 오류군의 observe-only 구현과 기존 block 영향 0 | P4.0A | `NOT_STARTED` |
| P4.selected.2A | paired A/B에서 recall, specificity, speed, repeatability 비교 | P4.selected.1A | `NOT_STARTED` |
| P4.selected.3A | 독립 oracle이 충분할 때 warn 승격 | P4.selected.2A | `NOT_STARTED` |
| P4.selected.4A | 사전등록 holdout과 모든 gate 통과 시에만 block 승격 | P4.selected.3A | `NOT_STARTED` |
| P4.selected.5A | shadow/warn/block 전이의 rollback, suppression, regression 결속 | P4.selected.4A | `NOT_STARTED` |
| P4.selected.6A phase exit | 선택 오류군 phase packet의 3AI F1/F2 | P4.selected.5A | `NOT_STARTED` |

## G4. 사이트, API, 데이터, 운영의 검토 깊이

각 row는 독립 카드다. 한 평면의 `.2`가 닫혀도 다른 평면의 실행, detector accuracy, H100,
release를 승인하지 않는다. 각 평면의 `.6`은 해당 평면의 phase exit이며, `P5.5A`는 네 평면을
모은 P5 전체 phase exit이다.

| 평면 | .1 oracle | .2 실행 경계 | .3 baseline/오류군 | .4 coverage HOLD | .5 사용자 계약 | .6 phase exit |
| --- | --- | --- | --- | --- | --- |
| P5.S 사이트 | static/XSS/injection oracle | 허가된 local web execution | 가장 큰 오류군 paired A/B | crawl/timeout/unsupported fail-closed | finding, 수정안, 재검사 UX | 3AI F1/F2 |
| P5.A API | auth/IDOR/BOLA oracle | route-to-service execution | 가장 큰 오류군 paired A/B | auth/coverage fail-closed | route, 권한, 수정 설명 UX | 3AI F1/F2 |
| P5.D 데이터 | SQL/RLS/PII/retention oracle | read-only DB/storage connector | 가장 큰 오류군 paired A/B | connector/control error `HOLD` | 한국 개인정보 설명과 다음 행동 | 3AI F1/F2 |
| P5.O 운영 | secret/SCA/CI-IaC/MCP oracle | runtime proxy/protocol execution | 가장 큰 오류군 paired A/B | runtime/protocol coverage `HOLD` | suppression, CI policy UX | 3AI F1/F2 |

실제 카드 ID는 `P5.S.1`부터 `P5.S.6`, `P5.A.1`부터 `P5.A.6`, `P5.D.1`부터 `P5.D.6`,
`P5.O.1`부터 `P5.O.6`이다. 각 평면은 `.1 -> .2 -> .3 -> .4 -> .5 -> .6` 순서로만 진행한다.
네 `.6` 카드가 모두 `FIX_NARROW`가 된 뒤에만 `P5.5A phase exit`을 연다.

| ID | 한 가지 완료 목표 | 선행 카드 | 상태 |
| --- | --- | --- | --- |
| P5.S.1-.6 | 사이트 평면의 oracle, local execution, A/B, coverage, UX, phase review | P4.selected.6A | `NOT_STARTED` |
| P5.A.1-.6 | API 평면의 oracle, route/service execution, A/B, coverage, UX, phase review | P5.S.6 | `NOT_STARTED` |
| P5.D.1-.6 | 데이터 평면의 oracle, read-only connector, A/B, coverage, Korean PII UX, phase review | P5.A.6 | `NOT_STARTED` |
| P5.O.1-.6 | 운영 평면의 oracle, proxy/protocol execution, A/B, coverage, policy UX, phase review | P5.D.6 | `NOT_STARTED` |
| P5.5A phase exit | 네 평면 child와 exclusion의 P5 packet 3AI F1/F2 | P5.S.6, P5.A.6, P5.D.6, P5.O.6 | `NOT_STARTED` |

## G6. 정직한 최종 출하 주장

| ID | 한 가지 완료 목표 | 선행 카드 | 상태 |
| --- | --- | --- | --- |
| P6.1A | analyzer, rule pack, toolchain, H100, label의 one-way freeze | P2.6B, P5.5A | `NOT_STARTED` |
| P6.2A | H100 blind run과 oracle scoring의 분리 실행 | P6.1A | `NOT_STARTED` |
| P6.3A | 전체/평면/Critical/specificity/concentration/speed 고정 gate 계산 | P6.2A | `NOT_STARTED` |
| P6.4A | 수정 없는 두 번째 H100 run의 semantic equality | P6.3A | `NOT_STARTED` |
| P6.5A phase exit | release disposition packet의 3AI F1/F2 | P6.4A | `NOT_STARTED` |

## G5. 설치와 실제 사용 가능성

| ID | 한 가지 완료 목표 | 선행 카드 | 상태 |
| --- | --- | --- | --- |
| P7.1A | fresh wheel 설치, CLI, stdio MCP, evidence binding 재현 | P5.5A | `NOT_STARTED` |
| P7.2A | GPT, Grok, Codex, Antigravity에서 install, restart, tool list, Guardian 호출 재현 | P7.1A | `NOT_STARTED` |
| P7.3A | license, SBOM, known limits, evidence raw-free release bundle | P7.2A | `NOT_STARTED` |
| P7.4A | 모든 phase exit을 하나의 canonical `GO/HOLD`로 계산 | P7.3A | `NOT_STARTED` |
| P7.5A phase exit | 설치/호환 phase packet과 최종 packet의 3AI F1/F2 | P6.5A, P7.4A | `NOT_STARTED` |

## G7. 목표 통제와 독립 검증 운영

| ID | 한 가지 완료 목표 | 선행 카드 | 상태 |
| --- | --- | --- | --- |
| P8.1 | G0-G7/P0-P8, single-active, A-G, 3AI F1/F2의 canonical state validator | none | `FIX_NARROW` |
| P8.1B | current state와 사람이 읽는 세 보드의 active/gate/next marker 동기화 | P8.1 | `FIX_NARROW` |
| P8.2B | Windows native executable로 long supervisor packet 전달 | P8.1B | `FIX_NARROW` |
| P8.2D | GLM source-free health terminal contract와 strict parser | P8.2B | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX`; invalid field ID와 Claude timeout receipt 보존 |
| P8.2E | 이 제품 카드 카탈로그를 canonical state와 validator에 결속 | P8.2D | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX`; registry transition control만 해당 |
| P8.2A | Windows supervisor command current-target health, regression, F1/F2 재검증 | P8.2E | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX`; Windows supervisor contract만 해당 |
| P8.2C | card/phase status와 machine/supervisor receipt hash 결속 | P8.2A | `NOT_STARTED` |
| P8.3 | phase child, excluded work, F1/F2를 phase packet으로 검증 | P8.2C | `NOT_STARTED` |
| P8.4 | G1-G7/P0-P8 gate 하나라도 없으면 `GO_RELEASE` 거부 | P8.3 | `NOT_STARTED` |
| P8.5A phase exit | P8 운영 통제 phase packet의 3AI F1/F2 | P8.4 | `NOT_STARTED` |

## 현재 상태를 읽는 법

- `ACTIVE`: 현재 카드의 다음 gate만 수행한다.
- `PAUSED`: 증거는 보존하지만 현재 카드가 아니므로 다음 gate를 열지 않는다.
- `FIX_NARROW`: 해당 카드의 A-G와 card-level 3AI two-run comparator만 닫혔다.
- `NOT_STARTED`: 선행 카드 또는 A 사전등록을 기다린다.
- `MEASURED_HOLD`와 `BLOCKED`: 실패 또는 외부 제약을 삭제하지 않고 보존한다.

다음 실제 구현은 `P2.4B.3.13`의 F1이다. prior API13 E/F1 evidence는 새 supervisor target의 승격 근거가 아니다.
