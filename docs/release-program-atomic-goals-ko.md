# K-Guard 원자 제품 목표 보드

작성일: 2026-07-23  
상태: `ACTIVE`  
공식 evidence 원본: [출하 검증 프로그램 장부](release-program-phase-ledger-ko.md)  
상위 제품 목표: [제품 목표 운영판](release-program-goal-board-ko.md)  
실행 순서: [제품 목표 분해와 페이즈 실행 지도](release-program-execution-map-ko.md)
목표 계층과 종료 기준: [제품 목표 레지스트리](release-program-goal-register-ko.md)
남은 제품 작업 순서: [제품 작업 카드 카탈로그](release-program-product-card-catalog-ko.md)
기계 상태 계약: [goal-state JSON](release-program-goal-state.json) / [목표 통제와 독립 검증 운영](release-program-goal-control-ko.md)

## 이 보드가 잠그는 것

이 보드는 감독 AI를 많이 호출하는 계획이 아니다. K-Guard가 실제로 획득해야 할
제품 능력을 원자 카드로 분리하고, 어느 카드가 무엇을 증명했는지와 다음에 열 수
있는 카드 하나를 고정하는 보드다.

- `FIX_NARROW`는 한 카드의 명시적 계약만 끝났다는 뜻이다.
- 카드의 수나 `FIX_NARROW` 수를 탐지 정확도, 인간 시니어 동등성, 출하 준비도 퍼센트로
  환산하지 않는다.
- 카드 하나의 실패는 다른 카드의 통과로 상쇄되지 않는다.
- 다음 구현 또는 측정 카드는 현재 카드가 `G`까지 닫히거나 `MEASURED_HOLD`로 보존된 뒤에만
  연다.

## 상태와 완료 규칙

| 상태 | 뜻 | 다음 행동 |
| --- | --- | --- |
| `NOT_STARTED` | 입력 계약이 아직 열리지 않음 | 선행 카드와 A 사전등록을 확인 |
| `ACTIVE` | A 또는 B 구현 중 | 같은 카드 안에서만 작업 |
| `PAUSED` | A 또는 일부 기계 gate는 보존했으나 현재 active가 아닌 카드 | 지정된 현재 카드의 G 뒤에만 재개 |
| `EVIDENCE_READY` | A-E 기계 증거 완료, AI 검토 대기 | F1을 호출 |
| `REVIEWING` | F1 또는 F2 실행 중 | packet, target, model drift를 막음 |
| `FIX_NARROW` | A-G와 두 번의 3AI semantic comparator가 모두 통과 | 바로 다음 의존 카드 하나만 열기 |
| `MEASURED_HOLD` | 수치, coverage, repeatability 또는 독립 검토가 미달 | 실패 증거 보존 후 원인 카드로 되돌아감 |
| `BLOCKED` | 권한, 공식 source, 실행 환경 등 외부 입력이 없음 | blocker를 장부에 기록하고 다른 독립 카드 선택 |

모든 카드의 최소 완료 순서는 동일하다.

| Gate | 제품 작업 | 완료 판정 |
| --- | --- | --- |
| A | 가설, oracle, 입력, 제외, claim boundary 사전등록 | 결과를 본 뒤 표본, label, 기준을 바꿀 수 없음 |
| B | 코드 또는 공개 source/oracle provenance를 target hash에 결속 | target drift면 카드 전체를 다시 실행 |
| C | focused positive/negative 및 fail-closed test | 위반, tamper, coverage error를 통과로 바꾸지 않음 |
| D | 독립 external output 또는 execution을 두 번 생성 | semantic comparator가 `FIX`이고 repeat exact |
| E | full regression, 현재 baseline, 호환성 검증 | failure, timeout, unsupported path, drift는 `HOLD` |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2의 독립 검토를 같은 target/claim으로 두 번 실행 | 세 lane 모두 `GO`, supervisor semantic comparator `FIX` |
| G | evidence path/hash, comparator, 비주장 범위를 장부에 기록 | 이때만 `FIX_NARROW` |

## 3AI 호출 계약

F 단계는 카드가 A-E를 완료한 뒤 자동으로 열리는 **제품 완료 조건**이다. health check,
한 번의 답변, 한 AI의 `GO`는 완료가 아니다.

1. 카드 소유자는 target hash, focused/full attestation, two-run machine comparator, claim boundary를
   raw-free packet으로 고정한다.
2. Claude Opus 4.8은 지정 파일을 read-only로 직접 검토한다. Grok 4.5와 Cline GLM 5.2는
   같은 주장과 동등한 raw-free packet을 독립 검토한다.
3. 세 모델의 첫 검토 `F1`을 실행한다. timeout, `HOLD`, packet/model/target drift는 승격을 멈춘다.
4. 같은 target과 packet으로 두 번째 검토 `F2`를 실행한다. 두 review의 semantic comparator가
   `FIX`여야 한다.
5. 카드가 아닌 **페이즈 전체**를 닫을 때는, 모든 child `FIX_NARROW`를 모은 phase packet에도
   이 F1/F2를 한 번 더 적용한다. leaf의 감독 통과는 phase 통과를 대신하지 않는다.

모델은 oracle label, severity, 합격선을 정하지 않는다. 모델의 역할은 결속, 재현성, claim
boundary, 누락된 evidence를 반박하는 것이다. `GO`도 해당 카드의 범위 밖 제품 성능을 승인하지
않으며, 한 lane이라도 응답하지 않으면 `EVIDENCE_READY` 또는 `MEASURED_HOLD`로 남긴다.

## 제품 목표와 원자 카드

### G1. 정직한 분모와 oracle

| 카드 | 제품이 얻는 한 가지 능력 | 선행 조건 | 현재 상태 |
| --- | --- | --- | --- |
| P0.1-P0.4 | target, toolchain, full regression, AI 실행 경로를 재현 | 없음 | `FIX_NARROW` |
| P1.1B | oracle schema와 severity가 모든 registry에서 기계 검증됨 | P0 | `NOT_STARTED` |
| P1.2B | High/Critical/blocker finding:scenario 1:1이 아니면 scoring을 거부 | P1.1B | `NOT_STARTED` |
| P1.3B | response 후보의 raw-free receipt를 두 번 생성하고 binding을 비교 | P1.2B | `NOT_STARTED` |
| P1.4C | local execution positive/negative pair의 공통 admission 계약 | P1.3B | `NOT_STARTED` |
| P1.6A | G1 phase packet을 두 번 독립 검토 | P1.1B-P1.4C | `NOT_STARTED` |
| P2.1A-P2.2B | BenchmarkJava/Python 공식 분모를 clean worktree 두 곳에서 재현 | P0 | `FIX_NARROW` |
| P2.3A-P2.3B.7 | 6개 local app의 source, 실행 oracle, aggregate provenance를 결속 | P1.4C | `FIX_NARROW` |
| P2.4A | generated pair 60개 blueprint를 결과 전 동결 | P1.4C | `FIX_NARROW` |
| P2.4B.1 | generated pair 빈 staging contract를 external repeat으로 검증 | P2.4A | `FIX_NARROW` |
| P2.4B.2.01-.03 | source-flow site-01, site-02, site-03 source tree identity | P2.4B.1 | `FIX_NARROW` |
| P2.4B.2.04 | site-04 path-traversal primary/reserve source tree identity | P2.4B.1 | `FIX_NARROW` |
| P2.4B.2.05 | site-05 untrusted-redirect primary/reserve source tree identity | P2.4B.2.04 | `FIX_NARROW` |
| P2.4B.2.06 | site-06 SSRF primary/reserve source tree identity | P2.4B.2.05 | `FIX_NARROW` |
| P2.4B.2.07 | site-07 prototype-pollution primary/reserve source tree identity | P2.4B.2.06 | `FIX_NARROW` |
| P2.4B.2.08 | site-08 unsafe-deserialize primary/reserve source tree identity | P2.4B.2.07 | `FIX_NARROW` |
| P2.4B.2.09 | site-09 client-secret primary/reserve source tree identity | P2.4B.2.08 | `FIX_NARROW` |
| P2.4B.2.10 | site-10 CORS-origin primary/reserve source tree identity | P2.4B.2.09 | `FIX_NARROW` |
| P2.4B.2.11 | site-11 template-XSS primary/reserve source tree identity | P2.4B.2.10 | `FIX_NARROW` |
| P2.4B.2.12 | site-12 file-read primary/reserve source tree identity | P2.4B.2.11 | `FIX_NARROW` |
| P2.4B.2.13 | site-13 JDBC query primary/reserve source tree identity | P2.4B.2.12 | `FIX_NARROW` |
| P2.4B.2.14 | site-14 HTML response primary/reserve source tree identity | P2.4B.2.13 | `FIX_NARROW` |
| P2.4B.2.15 | site-15 SQL builder primary/reserve source tree identity | P2.4B.2.14 | `FIX_NARROW` |
| P2.4B.2.16 | data-03 Prisma raw-query primary/reserve source tree identity | P2.4B.2.15 | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.2.17 | data-07 FastAPI parameterized-query primary/reserve source tree identity | P2.4B.2.16 | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.2.18 | data-09 Spring JDBC concat primary/reserve source tree identity | P2.4B.2.17 | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.2.19 | data-14 pgx query-format primary/reserve source tree identity | P2.4B.2.18 | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.2.20 | 19 slot source-flow aggregate와 exclusion `0` | .01-.19 | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.01 | api-01 Express route-IDOR source-tree identity | P2.4B.2.20 | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.02 | api-02 Next.js service-IDOR source-tree identity | P2.4B.3.01 | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.03 | api-03 Supabase missing-RLS source-tree identity | P2.4B.3.02 | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.04 | api-04 Firebase open-rule source-tree identity | P2.4B.3.03 | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.05 | api-05 Next.js admin-boundary source-tree identity | P2.4B.3.04 | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.06 | api-06 Express mass-assignment source-tree identity | P2.4B.3.05 | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.07 | api-07 Supabase service-role key source-tree identity | P2.4B.3.06 | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.08 | api-08 Firebase storage read-rule source-tree identity | P2.4B.3.07 | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.09 | api-09 FastAPI dependency-auth source-tree identity | P2.4B.3.08 | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.10 | api-10 Django REST object-owner source-tree identity | P2.4B.3.09 | `FIX_NARROW` - A-G와 3AI F1/r3 comparator `FIX`; F2 timeout 보존 |
| P2.4B.3.11 | api-11 Flask role-guard source-tree identity | P2.4B.3.10 | `FIX_NARROW` - A-G와 3AI F1/r3 comparator `FIX`; r2 packet-diff `HOLD` 보존 |
| P2.4B.3.12 | api-12 Spring method-auth source-tree identity | P2.4B.3.11 | `FIX_NARROW` - A-G와 clarified r2/r3 3AI comparator `FIX`; initial GLM `HOLD` 보존 |
| P2.4B.3.13 | api-13 Ktor resource-owner source-tree identity | P2.4B.3.12 | `ACTIVE` - A-E 완료, prior E/F1 `BLOCKED_PROVIDER` 보존; 새 target packet F1 |
| P2.4B.3.14-.20 | 나머지 auth-rls-db leaf와 family aggregate | P2.4B.3.13 | `NOT_STARTED` |
| P2.4B.4-.8 | 남은 generated family materialization, admission, aggregate | P2.4B.3.20 | `NOT_STARTED` |
| P2.5A-P2.5B | 공개 source stress 100개의 source/license/층화 provenance | P2.4B | `NOT_STARTED` |
| P2.6A-P2.6B | H100 membership, 4개 평면 25개씩, severity/exclusion 동결 | P2.5 | `NOT_STARTED` |
| P2.7A | P2 전체 provenance/exclusion phase review | P2.1-P2.6 | `NOT_STARTED` |

`P2.4B.2`의 19개 leaf 세부 목록과 순서는 [source-flow materialization WBS](p24b2-source-flow-materialization-wbs-ko.md)에 고정한다. 하나의 source tree는 execution, scanner finding, accuracy, H100을 승인하지 않는다.

### G2. 측정 가능한 탐지 성능

| 카드 | 제품이 얻는 한 가지 능력 | 선행 조건 | 현재 상태 |
| --- | --- | --- | --- |
| P3.1A | scanner input, timeout, supported-file coverage 계약을 두 번 재현 | P2.7A | `NOT_STARTED` |
| P3.1B | 전수 scan이 끝나지 않으면 Guardian이 `HOLD`를 반환 | P3.1A | `NOT_STARTED` |
| P3.2A | TP/FP/FN/TN, Wilson 계산을 oracle 없이 거부 | P3.1B | `NOT_STARTED` |
| P3.2B | 평면별 actionability, recall, specificity, app-complete를 계산 | P3.2A | `NOT_STARTED` |
| P3.3A | rule, subtype, language, plane 후보 편중을 계산 | P3.2B | `NOT_STARTED` |
| P3.4A | timeout, unsupported, control error를 성공 대신 coverage `HOLD`로 집계 | P3.3A | `NOT_STARTED` |
| P3.5A | baseline 오류군과 claim boundary phase review | P3.4A | `NOT_STARTED` |

### G3. 오류군 하나씩 Guardian에 승격

오류군의 이름은 P3.5A가 측정한 모집단 가중 손실 1위만 사용한다. 미리 기능을 늘리거나
새 규칙을 차단으로 넣지 않는다. 각 오류군은 아래 여섯 원자 카드를 **다시** 가진다.

| 카드 template | 제품이 얻는 한 가지 능력 | 선행 조건 |
| --- | --- | --- |
| P4.`error`.1A | 오류군, 개발 분모, 목표 수치 사전등록 | P3.5A |
| P4.`error`.2A | observe-only 구현과 기존 block 영향 0 증명 | .1A |
| P4.`error`.3A | paired A/B에서 recall, specificity, speed, repeatability 비교 | .2A |
| P4.`error`.4A | 독립 oracle 충분 시 warn 승격 | .3A |
| P4.`error`.5A | 사전등록 holdout과 모든 gate 통과 시 block 승격 | .4A |
| P4.`error`.6A | error-group phase packet의 3AI F1/F2 review | .5A |

### G4. 네 검토 평면의 실제 깊이

각 평면은 아래 여섯 원자 카드가 모두 `FIX_NARROW`이고 phase-level F1/F2를 통과해야
측정 준비가 된다. 이는 성능 또는 release `GO`가 아니다.

| 평면 | .1 oracle | .2 실행 경계 | .3 baseline/오류군 | .4 coverage HOLD | .5 사용자 계약 | .6 phase review |
| --- | --- | --- | --- | --- | --- |
| P5.S 사이트 | static/XSS/injection oracle | 허가된 local web execution | 최대 오류군 paired A/B | crawl/timeout/unsupported fail-closed | Guardian finding/수정/재검사 UX | 3AI two-run |
| P5.A API | auth/IDOR/BOLA oracle | route-to-service execution | 최대 오류군 paired A/B | auth/coverage fail-closed | Guardian route/권한 설명 UX | 3AI two-run |
| P5.D 데이터 | SQL/RLS/PII/retention oracle | read-only DB/storage connector | 최대 오류군 paired A/B | connector/control error HOLD | 한국 개인정보 설명과 다음 행동 | 3AI two-run |
| P5.O 운영 | secret/SCA/CI-IaC/MCP oracle | runtime proxy/protocol execution | 최대 오류군 paired A/B | runtime/protocol coverage HOLD | suppression/CI policy UX | 3AI two-run |

각 셀은 `P5.<plane>.1`부터 `P5.<plane>.6`까지의 별도 카드다. 모든 카드에 A-G를 적용한다.
예를 들어 P5.A.2가 닫혀도 API 전체, IDOR 탐지율, 출하 승인에는 아무 주장도 추가되지 않는다.

### G5. 사람이 실제로 설치하고 사용할 수 있음

| 카드 | 제품이 얻는 한 가지 능력 | 선행 조건 | 현재 상태 |
| --- | --- | --- | --- |
| P7.1A | fresh wheel 설치, CLI, stdio MCP, evidence binding을 깨끗한 환경에서 재현 | P5.* phase review | `NOT_STARTED` |
| P7.2A | GPT, Grok, Codex, Antigravity 각각에서 설치, restart, tool list, Guardian 호출을 재현 | P7.1A | `NOT_STARTED` |
| P7.3A | license, SBOM, known limits, evidence를 raw-free release bundle로 결속 | P7.2A | `NOT_STARTED` |
| P7.4A | Guardian이 모든 phase exit을 한 canonical `GO/HOLD`로 계산 | P7.3A | `NOT_STARTED` |
| P7.5A | 최종 packet의 3AI 만장일치 comparator | P6.5A, P7.4A | `NOT_STARTED` |

### G6. 정직한 최종 출하 주장

| 카드 | 제품이 얻는 한 가지 능력 | 선행 조건 | 현재 상태 |
| --- | --- | --- | --- |
| P6.1A | analyzer, rule pack, toolchain, H100, label을 one-way freeze | P2.6B, P5.*.6 | `NOT_STARTED` |
| P6.2A | H100 blind run과 oracle scoring을 분리 실행 | P6.1A | `NOT_STARTED` |
| P6.3A | 전체/평면/Critical/specificity/concentration/speed 고정 gate 계산 | P6.2A | `NOT_STARTED` |
| P6.4A | 수정 없는 두 번째 H100 run의 semantic equality | P6.3A | `NOT_STARTED` |
| P6.5A | release disposition의 3AI F1/F2 review | P6.4A | `NOT_STARTED` |

### G7. 목표 통제와 독립 검증 운영

| 카드 | 제품이 얻는 한 가지 능력 | 선행 조건 | 현재 상태 |
| --- | --- | --- | --- |
| P8.1 | G0-G7/P0-P8, 단일 active, A-G와 Claude/Grok/GLM F1/F2 의무를 canonical state로 검증 | 없음 | `FIX_NARROW` - final machine/supervisor comparator `FIX` |
| P8.1B | current JSON과 세 사람이 읽는 운영판의 active/gate/next를 marker로 동기화 | P8.1 | `FIX_NARROW` - initial D `HOLD` 보존, corrected A-G와 3AI comparator `FIX` |
| P8.2A | Windows npm shim supervisor command resolution | P8.1B | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX`; Windows supervisor contract만 해당 |
| P8.2B | Windows native supervisor transport | P8.2A | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX` |
| P8.2D | GLM health terminal contract | P8.2B | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX`; invalid field ID와 Claude timeout receipt 보존 |
| P8.2E | G1-G6 product-card catalog와 phase-exit review binding | P8.2D | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX`; registry transition control만 해당 |
| P8.2C | `FIX_NARROW`/phase 상태와 machine/supervisor receipt hash의 결속 | P8.2B | `NOT_STARTED` |
| P8.3 | phase child, excluded work, F1/F2를 phase packet으로 검증 | P8.2C | `NOT_STARTED` |
| P8.4 | 모든 G1-G7/P0-P8 gate가 없으면 `GO_RELEASE`를 거부 | P8.3 | `NOT_STARTED` |

## 완료 leaf 기록과 다음 전이

**기록 시작 카드: `P2.4B.2.09 site-09 client-secret source-flow`.**

- A: primary checkout과 reserve integrations, `checkoutProviderKey`/`integrationApiToken`, synthetic literal, same-origin handoff, static negative label 사전등록 완료
- B: site-09 전용 materializer/comparator 결속 완료
- C: 6 focused tests 통과
- D: external r1/r2 source triplet comparator `FIX`, semantic fingerprint
  `1751d54cceb642f691cc15b89efdfc34f2b689f75ade5121d991c960209e1e09`
- E: initial full r1 `CONTROL_HOLD`를 보존하고, evidence-time target에서 focused 6/6, isolated clean full r2/r3 각각 2,611 passed, 5 skipped, 0 failed
- F1/F2: Claude Opus 4.8, Grok 4.5, Cline GLM 5.2가 두 run에서 모두 lane `GO`를 냈다. 각 단회 run의
  `REPEATABILITY_GAP` unpromoted `HOLD`는 보존했고, health r1 GLM `BLOCKED_PROVIDER`와 health r2 recovery도
  기록했다. two-run supervisor comparator가 `FIX`다.
- G: supervisor semantic fingerprint `cba3a729c6283a2f39839d8fba492ee164e2c8099092069b27b736f34505617e`,
  comparator `FIX`, repeat exact

site-09의 `FIX_NARROW`가 닫힌 당시에는 `P2.4B.2.10`의 A 사전등록이 다음 하나의 카드였다. site-09는 real secret validity,
client bundle exposure, external request, scanner, TP/FP/FN, H100, release를 여전히 승인하지 않는다.

## 완료 leaf: P2.4B.2.10

- A-C: JavaScript/Express CORS-origin primary checkout와 reserve integrations, request `origin`, reflected handler,
  candidate별 allowlist, static `204` negative control을 사전등록하고 site-10 전용 materializer/comparator와 focused 6/6을 결속했다.
- D: external r1/r2 source comparator `FIX`, semantic fingerprint
  `51164406c8bf2cd2cae3036c005a679efa8dede1e9f69d38e41a7398c5e74d31`
- E: focused 6/6, isolated clean full r1/r2 각각 2,617 passed, 5 skipped, 0 failed; evidence-time baseline current와 diff check 통과
- F: F1 세 lane `GO`; intermediate F2 GLM `BLOCKED_PROVIDER`와 health r2 recovery를 보존한 뒤 동일 packet F3 retry에서
  세 lane `GO`, Claude direct-file 5/5; 두 정상 run semantic comparator `FIX`
- G: supervisor semantic fingerprint `f954872a436d3a1b71dfda719b1088302a3ca0f80b3adcd40057eba9da76df42`, comparator `FIX`, repeat exact

site-10의 `FIX_NARROW`가 닫혀 `P2.4B.2.11`의 A 사전등록을 다음 하나의 카드로 연다. site-10은 browser CORS behavior,
cross-origin read, deployed allowlist correctness, scanner, TP/FP/FN, H100, release를 여전히 승인하지 않는다.

## 완료 leaf: P2.4B.2.11

- A-C: Python/Django template-XSS primary checkout와 reserve integrations, `message`/`notice` parameter, `mark_safe` source
  condition, `escape` fixed boundary, static negative paragraph를 사전등록하고 site-11 전용 materializer/comparator와 focused 6/6을 결속했다.
- D: external r1/r2 source comparator `FIX`, semantic fingerprint
  `2c0c4e8a7e73b899abea04722ce1a53e641d8bdbe1d184116d8d30dfb8d1f2ed`
- E: focused 6/6, isolated clean full r1/r2 각각 2,623 passed, 5 skipped, 0 failed; evidence-time baseline current와 diff check 통과
- F: Claude Opus 4.8, Grok 4.5, Cline GLM 5.2가 F1/F2 모두 lane `GO`, Claude direct-file 5/5; supervisor comparator `FIX`
- G: supervisor semantic fingerprint `e047b1bbf621c01ba50e771077f1859ba304fe5754572c6fab26e05bd3f8a5b8`, comparator `FIX`, repeat exact

site-11의 `FIX_NARROW`가 닫혀 `P2.4B.2.12`의 A 사전등록을 다음 하나의 카드로 연다. site-11은 browser rendering,
script execution, deployed Django configuration, scanner, TP/FP/FN, H100, release를 여전히 승인하지 않는다.

## 완료 leaf: P2.4B.2.12

- A-C: Python/Flask file-read primary exports와 reserve templates, `file`/`name` parameter, raw `Path` read source condition,
  resolved-path fixed boundary, static negative text를 사전등록하고 site-12 전용 materializer/comparator와 focused 6/6을 결속했다.
- D: external r1/r2 source comparator `FIX`, semantic fingerprint
  `ffc7c7c98eb23ae2166dae5a3ec14db0480b80c152deb12fb4c309ef04c7773c`
- E: focused 6/6, isolated clean full r1/r2 각각 2,629 passed, 5 skipped, 0 failed; evidence-time baseline current와 diff check 통과
- F: Claude Opus 4.8, Grok 4.5, Cline GLM 5.2가 F1/F2 모두 lane `GO`, Claude direct-file 5/5; supervisor comparator `FIX`
- G: supervisor semantic fingerprint `083adab1b6226325efa622403b67ff07a253f26f377ce7aeb273836881267ce1`, comparator `FIX`, repeat exact

site-12의 `FIX_NARROW`가 닫혀 `P2.4B.2.13`의 A 사전등록을 다음 하나의 카드로 연다. site-12는 filesystem read,
traversal exploit, deployed Flask configuration, scanner, TP/FP/FN, H100, release를 여전히 승인하지 않는다.

## 완료 leaf: P2.4B.2.13

- A-C: Java/Spring JDBC primary orders와 reserve integrations, `id`/`provider` request parameter, concatenated query,
  `PreparedStatement.setString` fixed boundary, static negative controller를 사전등록하고 site-13 전용 materializer/comparator와 focused 6/6을 결속했다.
- D: external r1/r2 source comparator `FIX`, semantic fingerprint
  `37476b02780d0c555ef7ae48cdd413300970451821b42d3bd580b103a22dcfbd`
- E: focused r2 6/6, isolated clean full r1/r2 각각 2,635 passed, 5 skipped, 0 failed; evidence-time baseline current와 diff check 통과.
  Windows path selector로 시도한 focused r1은 receipt 생성 전 `test_selector_invalid`로 거부됐으며 성공 evidence에 쓰지 않았다.
- F: Claude Opus 4.8, Grok 4.5, Cline GLM 5.2가 F1/F2 모두 lane `GO`, Claude direct-file 5/5; supervisor comparator `FIX`
- G: supervisor semantic fingerprint `cee63659d209f8848675793276e98329ccb8d45ea6e3837c3204041257b47ca5`, comparator `FIX`, repeat exact

site-13 다음 `P2.4B.2.14`는 A-G를 닫아 `FIX_NARROW`가 됐다. P8.1 목표 통제, Site-15, Data-03, Data-07도
각각 A-G를 닫아 `FIX_NARROW`가 됐다. Data-09도 A-G를 닫아 `FIX_NARROW`가 됐다. 다음 유일한 `ACTIVE` 카드는
data-14도 A-G를 닫아 `FIX_NARROW`가 됐다. 다음 유일한 `ACTIVE` 카드는 19-slot aggregate의 A 사전등록을
보존한 `P2.4B.2.20`은 A-G를 닫아 `FIX_NARROW`가 됐고, 다음 유일한 `ACTIVE` 카드는
`P2.4B.3.01 api-01 route-IDOR`의 A 사전등록이다.

## 보고 형식

매 작업 보고는 아래 네 줄을 반드시 포함한다.

1. `카드 ID / 상태 / 제품 능력 한 문장`
2. `완료 gate A-G와 evidence receipt hash`
3. `Claude, Grok, GLM F1/F2 상태와 comparator`
4. `명시적 비주장 및 다음에 열 카드 하나`

이 형식을 지키면 “무엇을 만들었는지”, “무엇이 아직 증명되지 않았는지”, “왜 다음 작업이
그것인지”를 한 번에 추적할 수 있다.
