# K-Guard 출하 검증 프로그램 장부

작성일: 2026-07-22  
상태: `ACTIVE`  
우선 계약: [Oracle Program Operating Contract](oracle-program-operating-contract-ko.md)
운영판: [제품 목표 운영판](release-program-goal-board-ko.md)
페이즈 실행 지도: [제품 목표 분해와 페이즈 실행 지도](release-program-execution-map-ko.md)
원자 구현 목표: [원자 제품 목표 보드](release-program-atomic-goals-ko.md)
기계 상태 계약: [goal-state JSON](release-program-goal-state.json) / [목표 통제와 독립 검증 운영](release-program-goal-control-ko.md)
목표 계층과 종료 기준: [제품 목표 레지스트리](release-program-goal-register-ko.md)

## 이 장부의 목적

이 문서는 K-Guard를 출하 전 한국형 바이브코드 감사관으로 검증하는 작업을 작은
완료 단위로 나눈 공식 장부다. 기능을 많이 만들었다는 사실과 제품 성능을 입증했다는
사실을 구분한다. 각 항목은 코드, 실행 증거, 독립 감독 검토를 모두 갖추기 전까지
완료가 아니다. 각 제품 작업은 원자 제품 목표 보드의 A-G gate에 매핑하며, leaf 완료 후와
phase 종료 후 모두 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2의 F1/F2 검토를 거친다.

### 북극성

K-Guard는 한국 바이브코더가 출하 직전에 호출하는 시니어 감사관 스타일의
fail-closed release gate다. 사이트, API, 데이터, 운영 중 어느 한 영역이라도
근거가 부족하면 전체 결과는 `HOLD`다.

이 프로그램은 인간 검토자나 무단 외부 사이트 탐침을 성능 분모로 사용하지 않는다.
TP/FN은 공개된 공식 oracle, upstream 취약-수정 차분, 공개 소스에서 재현한
취약 앱, 기계 검증 생성 pair로만 정한다. 외부 사이트는 소스 공개 또는 명시적
권한이 있을 때만 로컬에서 재현하며, 비허가 대상에 능동 probe를 하지 않는다.

Claude, Grok, GLM은 oracle label을 정하지 않는다. 이들은 변경이 주장 범위를
지키는지, 증거가 결속됐는지, 출하 처분이 과장되지 않았는지를 독립 검토한다.

## 최종 GO의 고정 조건

아래 조건은 H100 실행 전에만 변경할 수 있다. 결과를 본 뒤 완화하거나 표본을
바꾸지 않는다.

| 항목 | 최종 기준 |
| --- | --- |
| 자동 차단 적중률 | 90% 이상, Wilson 95% 하한 80% 이상 |
| 앱 단위 완전 적중률 | 90% 이상, Wilson 95% 하한 80% 이상 |
| High/Critical recall | 90% 이상 |
| Critical recall | 100% |
| Specificity | 90% 이상 |
| 반복성 | 동일 H100 결과 2회 의미상 100% 일치 |
| 후보 편중 | 단일 규칙 후보 비율 50% 이하 |
| 빠른 점검 | `check_my_app` 계약 5초 이내 |
| Guardian | 지원 범위를 조용히 생략하지 않고 fail-closed |
| 제품 호환성 | 설치, CLI, MCP protocol, 기존 회귀 테스트에 회귀 없음 |
| 감독 검토 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 전원 GO, 같은 target에서 2회 의미상 일치 |

## 완료 상태의 의미

| 상태 | 의미 |
| --- | --- |
| `NOT_STARTED` | 아직 실행하거나 증거를 만들지 않음 |
| `IN_PROGRESS` | 작업 중이며 성능이나 출하 주장에 사용할 수 없음 |
| `MEASURED_HOLD` | 측정은 했으나 기준 미달 또는 oracle 불완전 |
| `TEMPORARY_PENDING_REVIEW` | 증거는 있으나 세 감독관 중 한 lane이 미완료, HOLD, BLOCKED, 또는 반복 미완료 |
| `FIX_NARROW` | 한정된 하위 계약이 코드, 테스트, 2회 증거, 세 감독관의 반복 검토를 통과함. 제품 성능 또는 출하 GO는 아님 |
| `GO_RELEASE` | 모든 Phase 0-7과 수치 기준을 통과한 최종 상태 |

`FIX_NARROW` 하나가 oracle label, TP/FP/FN 수치, H100, rule block 승격, 제품 출하를
자동으로 승인하지 않는다.

## 감독관 공통 완료 절차

모든 작업 단위는 다음을 순서대로 지킨다.

1. 변경 전 가설, 대상 오류군, 예상 측정 변화, claim boundary를 기록한다.
2. target을 HEAD와 content-bound dirty-worktree hash로 봉인한다.
3. focused test, 전체 회귀, 필요한 실행 oracle 2회, raw-free artifact manifest를 만든다.
4. Claude Opus 4.8은 지정 파일 직접 읽기 검토를 한다. Grok 4.5와 Cline GLM 5.2는 같은 raw-free packet을 검토한다.
5. 세 lane 모두 `GO`여야 한다. 아직 반복 비교 전인 각 review run은 `REPEATABILITY_GAP` 하나를 남긴 unpromoted `HOLD`가 정상이다.
6. 동일 packet과 target으로 두 review run을 만들고 semantic comparator가 `FIX`여야 그 작업 단위가 `FIX_NARROW`다.
7. 하나라도 `HOLD`, `BLOCKED`, target drift, packet drift, 코드 변경, 수치 하락이면 해당 작업은 `HOLD`로 보존한다. 다음 비승격 측정 외에는 진행하지 않는다.

감독관을 사용할 수 없으면 한 lane의 `GO`로 비승격 측정만 진행할 수 있다. 하지만
해당 phase 또는 release를 `FIX_NARROW`나 `GO_RELEASE`로 표기하지 않는다.

## 제품 목표와 작업 단위 운영 규약

감독관 검토 자체가 목표가 아니다. 아래 여섯 제품 목표를 실제로 달성하는 것이
목표이며, 감독관은 각 완료 단위의 독립적인 반대 의견을 제공하는 gate다.

| 제품 목표 | 성공 상태 | 이를 입증하는 Phase |
| --- | --- | --- |
| G1. 정직한 분모 | 무엇을 검사했고 무엇을 빼지 않았는지 source, license, oracle로 재현 가능 | P0-P2 |
| G2. 측정 가능한 탐지 | finding과 oracle이 1:1로 연결되고 TP/FP/FN/TN을 계산 가능 | P1, P3 |
| G3. 정확한 출하 게이트 | 가장 큰 오류군을 한 번에 하나씩 교정하고 observe, warn, block을 근거로 승격 | P4 |
| G4. 네 평면의 실사용 깊이 | 사이트, API, 데이터, 운영을 각각 독립 oracle과 fail-closed coverage로 검증 | P5 |
| G5. 실제 사용 가능성 | 사용자가 설치, CLI, MCP에서 같은 Guardian 결론과 다음 행동을 얻음 | P7.1-P7.2 |
| G6. 출하 주장 가능성 | 동결된 H100과 모든 수치 gate, 반복 실행, 독립 처분 검토를 동시에 통과 | P6-P7 |

### 모든 작업 ID의 공통 완료 패킷

`P*.*` 또는 그 하위 작업은 아래 일곱 칸을 모두 채우기 전까지 완료가 아니다. 각
작업은 장부에서 이 순서를 유지하며, 코드 작업과 검증 작업을 섞어 완료로 표시하지
않는다.

| 칸 | 산출물 | 실패 시 처리 |
| --- | --- | --- |
| A. 사전등록 | 가설, 입력, 제외, claim boundary, 성공/실패 조건 | 상태 `HOLD`, 구현 승격 금지 |
| B. 구현 또는 자료 결속 | 코드 diff 또는 source/oracle manifest와 content hash | target drift면 처음부터 다시 봉인 |
| C. focused 검증 | 변경 경계의 fail-closed 단위 테스트 | 실패한 test를 삭제하거나 기대값을 낮추지 않음 |
| D. 실행 반복 | 필요한 local oracle 또는 materialization을 독립 output에 두 번 실행 | 두 run이 다르면 원인을 보존하고 `HOLD` |
| E. 전체 회귀 | target 전체 test shard, coverage/compatibility 계약 확인 | 누락, 오류, flaky 결과는 `HOLD` |
| F. 3AI 독립 검토 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2가 같은 target을 2회 검토하고 comparator `FIX` | 한 lane이라도 미완료면 `TEMPORARY_PENDING_REVIEW` |
| G. 장부 승격 | evidence path/hash, 외부 comparator, 남은 비주장 범위를 기록 | 이 칸 전에는 `FIX_NARROW` 표기 금지 |

한 시점에는 구현 또는 측정 작업 하나만 `IN_PROGRESS`로 둔다. source preflight,
외부 도구 health, 이미 봉인된 evidence 읽기는 병렬로 할 수 있지만, 서로 다른 두
작업의 코드 변경이나 점수 산출은 동시에 진행하지 않는다. 작업의 A-G가 끝난 뒤에만
다음 작업의 A로 이동한다.

### Phase별 세부 목표 지도

아래 표는 기존 Phase를 실제 완료 순서로 더 나눈 WBS다. 아직 `NOT_STARTED`인
행은 예정일 뿐 성능 주장에 쓰지 않는다. 각 행은 위 A-G 완료 패킷과 세 감독관의
2회 검토를 똑같이 적용받는다.

| WBS | 세부 목표 | 선행 조건 | 완료 증거 |
| --- | --- | --- | --- |
| P1.1B | 공통 oracle schema의 모든 필수 필드와 severity 규칙을 실제 registry에 적용 | P1.1A | schema validator, negative fixtures, 2회 receipt |
| P1.2B | High/Critical 및 blocker의 finding:scenario 1:1 점수 차단기를 full registry에 적용 | P1.2A | reject receipt, score-refusal test |
| P1.3B | response 후보가 있는 current source에서 raw-free response receipt를 2회 생성 | P1.3A | raw-free candidate manifest, response binding comparator |
| P1.4C | 남은 local execution oracle을 positive/negative pair로 한 개씩 확대 | P1.4A-P1.4B | source-derived two-run positive/negative receipts |
| P1.6A | P1 전체의 아직 미완료 범위와 완료 범위를 phase review packet으로 분리 | P1.1B-P1.4C | phase review comparator |
| P2.1A | BenchmarkJava 2,740건의 current denominator receipt를 두 번 materialize | P0 | official source/license/expected-result manifest comparator |
| P2.1B | BenchmarkJava independent clean-worktree replay | 같은 raw Git blob에서 새 외부 clean worktree를 독립 생성하고 P2.1A와 Java case, exclusion, source-tree projection이 같은지 비교 | second clean-worktree receipt와 cross-worktree comparison |
| P2.2A | BenchmarkPython current denominator receipt | P2.1B | official source/license/expected-result manifest comparator |
| P2.2B | BenchmarkPython independent clean-worktree replay | P2.2A | second clean-worktree receipt와 cross-worktree comparison |
| P2.3A | 6개 local app의 source, license, revision, allowed local runtime을 각각 봉인 | P2.1B | six-source registry |
| P2.3B.1 | WebGoat IDOR execution boundary | P2.3A | 새 source registry에 결속된 positive/negative pair receipt |
| P2.3B.2 | Juice Shop execution boundary | P2.3B.1 | source-bound positive/negative pair receipt |
| P2.3B.3 | NodeGoat execution boundary | P2.3B.2 | source-bound positive/negative pair receipt |
| P2.3B.4 | PyGoat execution boundary | P2.3B.3 | source-bound positive/negative pair receipt |
| P2.3B.5 | crAPI execution boundary | P2.3B.4 | source-bound positive/negative pair receipt |
| P2.3B.6 | WrongSecrets execution boundary | P2.3B.5 | source-bound positive/negative pair receipt |
| P2.3B.7 | six-app execution aggregate | P2.3B.1-P2.3B.6 | six-app coverage and repeat manifest |
| P2.4A | generated pair 60개의 generator, severity, vulnerable/fixed/negative oracle과 reserve 사양을 사전등록 | P2.1B | [immutable blueprint](p24a-generated-pair-blueprint-preregistration-ko.md) |
| P2.4B.1-P2.4B.8 | [generated pair 60 materialization을 staging/family/admission/aggregate로 분해](p24b-generated-pair-materialization-wbs-ko.md) | P2.4A | family/aggregate manifest comparator |
| P2.5A | 공개 source stress 후보 100개의 source-only 권한, license, provenance를 결속 | P2.1B | source acquisition registry |
| P2.5B | top/mid/long-tail 층화와 exclusion 규칙을 scanner 결과 전에 고정 | P2.5A | stratification manifest |
| P2.6A | H100의 generated 80개와 공개 oracle 20개의 membership을 결과 전에 동결 | P2.4B, P2.5B | H100 manifest hash |
| P2.6B | H100의 네 평면 25개씩, severity, exclusion을 독립 검증 | P2.6A | plane balance receipt |
| P2.7A | P2 전체 provenance와 exclusion을 세 감독관 2회 검토 | P2.6B | phase review comparator |
| P3.1A | frozen denominator의 baseline scanner input/timeout/coverage 계약을 봉인 | P2.7A | baseline execution contract |
| P3.1B | 수정 없는 baseline 두 run의 semantic result comparator를 통과 | P3.1A | repeat receipt |
| P3.2A | oracle scorer가 TP/FP/FN/TN과 Wilson을 fail-closed 계산 | P3.1B | scoring test/receipt |
| P3.2B | 평면별 actionability, recall, specificity, app-complete 지표를 계산 | P3.2A | metric report |
| P3.3A | rule/subtype/language/plane candidate concentration을 계산 | P3.1B | distribution report |
| P3.4A | unsupported, timeout, control error를 명시 HOLD로 집계 | P3.1B | coverage hold report |
| P3.5A | baseline claim boundary와 최대 오류군을 세 감독관 2회 검토 | P3.2B-P3.4A | phase review comparator |
| P4.1A | 수치상 가장 큰 단일 오류군의 가설과 개발 분모를 사전등록 | P3.5A | hypothesis receipt |
| P4.2A | 해당 개선을 observe-only로 구현하고 기존 block 결과가 불변임을 검증 | P4.1A | shadow comparison |
| P4.3A | 동일 분모 paired A/B에서 recall, specificity, speed, repeatability를 비교 | P4.2A | A/B report |
| P4.4A | 독립 pair가 충분할 때 warn으로만 승격 | P4.3A | warning gate receipt |
| P4.5A | 사전등록 holdout과 전체 수치 gate가 충족될 때만 block 승격 | P4.4A | block gate receipt |
| P4.6A | 가설 하나와 변경 하나의 처분을 세 감독관 2회 검토 | P4.5A 또는 HOLD | phase review comparator |
| P5.S/A/D/O/I | 각 제품 평면마다 oracle → baseline → 한 오류군 A/B → coverage → UX/compatibility → 3AI review를 독립 완료 | P3.5A, 관련 P4 결과 | 각 평면의 six-part receipt |
| P6.1A | analyzer/rule/toolchain/H100/labels hash를 one-way freeze | P2.6B, P5 평면 완료 | freeze receipt |
| P6.2A | H100 단회 blind run과 oracle scoring을 분리 실행 | P6.1A | immutable blind-run bundle |
| P6.3A | 전체/평면/Critical/특이도/편중/속도 gate를 계산 | P6.2A | final metrics receipt |
| P6.4A | 수정 없는 second run의 semantic equality를 검증 | P6.3A | repeat comparator |
| P6.5A | release disposition을 세 감독관 2회 검토 | P6.4A | release review comparator |
| P7.1A | fresh wheel, stdio, CLI, evidence binding을 깨끗한 환경에서 재현 | P6.5A | install receipt |
| P7.2A | GPT, Grok, Codex, Antigravity 설치 문서와 tool list를 확인 | P7.1A | client compatibility receipt |
| P7.3A | evidence, license, SBOM, known limits를 raw-free release bundle로 결속 | P7.2A | release bundle hash |
| P7.4A | Guardian canonical gate로 GO/HOLD를 계산 | P7.3A | canonical disposition |
| P7.5A | 최종 release packet을 세 감독관 2회 검토 | P7.4A | unanimous comparator |
| P8.1 | G0-G7/P0-P8, 단일 active와 A-G/3AI F1/F2 의무를 canonical state로 검증 | 없음 | goal-state validator, negative test, 3AI comparator |
| P8.1B | current JSON과 사람이 읽는 세 운영판의 active/gate/next 동기화 | P8.1 | marker validator, stale-marker negative fixture |
| P8.2A | Windows npm shim supervisor command resolution | P8.1B | resolver, command-builder test, health r1/r2, 3AI comparator |
| P8.2B | Windows native supervisor transport | P8.2A | native resolver, long-packet transport test, r1/r2, 3AI comparator |
| P8.2C | `FIX_NARROW`/phase 상태를 receipt/comparator hash와 결속 | P8.2B | receipt-link validator |
| P8.3 | phase child/exclusion/F1/F2를 phase packet으로 결속 | P8.2C | phase packet comparator |
| P8.4 | G1-G7/P0-P8 미달이면 `GO_RELEASE`를 거부 | P8.3 | final disposition validator |

## Phase별 제품 목표

### Phase 0. 운영 기준선과 회귀 신뢰성

**목표:** 이후의 결과가 어느 코드와 환경에서 나온 것인지 재현 가능하게 만든다.

| 작업 ID | 작업 | 완료 조건 | 현재 상태 |
| --- | --- | --- | --- |
| P0.1 | 기준선 봉인 | HEAD, dirty worktree, analyzer, toolchain을 current receipt로 결속 | `FIX_NARROW` |
| P0.2 | 전체 회귀 shard | 모든 test file을 정확히 한 번씩 12 shard로 실행, 누락 0, 실패 0, aggregate hash 보존 | `FIX_NARROW` |
| P0.3 | 감독관 health | Claude, Grok, GLM의 고정 모델 경로와 no-tool health receipt 확인 | `FIX_NARROW` |
| P0.4 | 운영 attestation 검토 | P0.1-P0.3을 세 감독관 2회 동등 검토 후 comparator `FIX` | `FIX_NARROW` |

현재 근거는 `phase5-current-baseline-20260722-r12`,
`phase5-regression-shards-20260722-r3`,
`phase0-supervisor-review-20260722-r3-r4-comparison.json`에 있다. 이 결과는
2,428개 테스트의 운영 회귀 기준선만 뜻한다. 탐지 정확도나 출하 성능은 아직
증명하지 않는다.

### Phase 1. Oracle 및 측정 인프라

**목표:** finding 하나와 oracle scenario 하나를 기계적으로 연결할 수 있게 만든다.

| 작업 ID | 작업 | 완료 조건 | 현재 상태 |
| --- | --- | --- | --- |
| P1.1 | oracle schema | severity, source, vulnerable/fixed pair, expected disposition, reproduction, fix verification 필수 검증 | `IN_PROGRESS` |
| P1.2 | 1:1 validator | High/Critical 및 blocker가 1 finding : 1 scenario로 결속되지 않으면 점수 산출 거부 | `IN_PROGRESS` |
| P1.1A | L2 3-scenario source-bound schema | 고정된 공개 6개 소스 중 WebGoat의 site/API/data 각 1개 scenario를 execution, CWE, CVSS, positive/negative, state-reset 증거에 결속하고 나머지 411개 후보를 명시적으로 HOLD | `FIX_NARROW` |
| P1.2A | L2 3-scenario re-extraction validator | 동일 고정 입력으로 registry를 2회 byte-exact 재물질화하고, 모든 입력과 candidate inventory가 다르면 validated HOLD조차 거부 | `FIX_NARROW` |
| P1.3 | raw-free receipts | redacted fingerprint, detector subtype, 위치 종류, response hash만 저장하고 원문 비저장 | `IN_PROGRESS` |
| P1.3A | raw-free candidate receipt relation | v2 source/response 관계와 v1 직접 `response_hash`/위치 결속을 fail-closed로 검증하고, 두 receipt와 세 감독관 반복 검토를 같은 r17 target에 결속 | `FIX_NARROW` |
| P1.4 | execution repeat | 각 execution oracle은 같은 로컬 source target에서 두 번 재현 | `IN_PROGRESS` |
| P1.4A | WebGoat IDOR positive execution repeat | 고정 WebGoat IDOR upstream integration test의 새 source-derived receipt 두 개를 각각 내부 두 번 실행하고 deterministic build-contract comparator 및 세 감독관 반복 검토에 결속 | `FIX_NARROW` |
| P1.4B | WebGoat IDOR negative-control repeat | P1.4A의 current positive receipt에 결속된 source-mutated negative control을 새로 두 receipt로 실행하고 positive/negative 경계를 반복 검증 | `FIX_NARROW` |
| P1.5 | H5A SCA observe | WebGoat XStream 공개 CVE의 source-bound positive/negative OSV differential을 관찰 전용으로 재검증 | `FIX_NARROW` |
| P1.6 | 감독관 검토 | P1.1-P1.5의 좁은 계약을 세 감독관 2회 비교 | `NOT_STARTED` |

**Phase exit:** oracle 또는 측정기에만 `FIX_NARROW`을 줄 수 있다. 이 phase는 아직
detector accuracy와 rule promotion을 승인하지 않는다.

P1.5는 r13 target에서 positive CVE 1건, one-property negative control 0건을
각각 두 번 재현했고 semantic comparison을 통과했다. Claude Opus 4.8, Grok 4.5,
Cline GLM 5.2도 같은 packet의 r3/r4에서 모두 `GO`를 냈다. 근거는
`phase1-h5a-maven-xstream-osv-observe-20260722-r1-r2-comparison.json`과
`phase1-h5a-supervisor-review-20260722-r3-r4-comparison.json`이다. OSV 원문
출력은 반복 사이에 달랐으므로 일반 Maven SCA, warning/block, Guardian, 성능
지표, H100, release 승격은 여전히 명시적으로 금지된다.

P1.1A/P1.2A는 r14 target에서 새 registry 두 개가 같은
`462ca9548242f03eda84629a62184c4fa25cbd9787d8a1f1651dcfa9d2496dde`로
물질화되고, 64개 focused test와 2,428개 전체 회귀를 통과한 좁은 계약이다.
Claude Opus 4.8, Grok 4.5, Cline GLM 5.2의 r1/r2 검토도 semantic comparator
`FIX`를 통과했다. 근거는
`phase1-l2-three-scenario-registry-20260722-r1`,
`phase1-l2-three-scenario-registry-20260722-r2`,
`phase1-regression-shards-20260722-r2/aggregate-v2.json`,
`phase1-l2-three-scenario-supervisor-review-20260722-r1-r2-comparison.json`이다.
이는 후보 414개 중 411개가 아직 완전한 oracle가 없음을 보존하는 계약이다.
따라서 전체 P1.1/P1.2, 탐지 정확도, TP/FP/FN, rule 승격, H100, 출하는 여전히
`HOLD`다.

P1.3A는 r17 target에서 raw-free candidate evidence의 형식과 관계를 좁게
고정했다. source 후보는 `response_hash`와 body/header 위치를 `null`로
요구하고, response 후보는 안전한 위치와 64-hex response hash를 요구한다.
기존 v1 field queue에서도 `response_hash`와 위치를 직접 binding field로
만들어 변경된 관계를 우회할 수 없게 했다. focused test는 107 passed, 1 skipped,
전체 r17 회귀는 2,430 passed, 5 skipped, 0 failed, 0 errors였고, 31개 source
후보 receipt 두 개는 같은
`7a9c3f94e2a977017d907d0d40006f7698830b0984f8f93fc59e9ff92b218bbd`였다.
Claude Opus 4.8, Grok 4.5, Cline GLM 5.2의 r1/r2 검토는 모두 `GO`와
`REPEATABILITY_GAP`만 남겼고 semantic comparator가 `FIX`를 확인했다. 근거는
`phase1-p13-raw-free-supervisor-review-20260723-r1-r2-comparison.json`이다.
다만 이 queue는 response 후보 0개인 역사적 source replay이며 analyzer/source
currentness mismatch 네 건이 남아 있다. 따라서 이 결과는 response 탐지 성능,
공개 앱 성능, TP/FP/FN, precision/recall, Guardian, H100, release를 증명하지
않으며, 전체 P1.3은 계속 `IN_PROGRESS`다.

P1.4A는 r19 target에서 고정 WebGoat IDOR upstream integration test의 positive
execution contract를 새로 두 번 물질화했다. 각 receipt는 source-derived image
하나와 network `none` runtime 두 번, non-root/read-only/capability-drop/resource
limits, owned image/container/volume cleanup을 포함하고
`EXECUTION_CONTRACT_PASS`를 냈다. 첫 비교는 nonce, temporary path, dynamic tag가
들어간 build-command hash를 의미값으로 잘못 묶어 `HOLD`가 되었고, 그 실패
evidence는 보존했다. 이후 runner가 `--no-cache`, `--pull=false`, build network,
contract label, base image, Dockerfile을 묶는 deterministic build-contract hash를
기록하도록 보완했으며 새 r3/r4 receipt comparator가 `FIX`를 냈다. focused test는
28 passed, 전체 r19 회귀는 2,436 passed, 5 skipped, 0 failed, 0 errors였다.
Claude Opus 4.8, Grok 4.5, Cline GLM 5.2는 r1/r2 모두 `GO`와
`REPEATABILITY_GAP`만 남겼고 semantic comparator가 `FIX`를 확인했다. 근거는
`phase1-p14a-webgoat-idor-execution-20260723-r3-r4-comparison.json`과
`phase1-p14a-webgoat-idor-supervisor-review-20260723-r1-r2-comparison.json`이다.
이는 positive upstream integration test 한 개의 local execution repeatability만
뜻한다. negative control, independent upstream fixed revision, scanner finding
mapping, CWE/CVSS, TP/FP/FN, API authorization, Guardian, H100, release는 전부
여전히 `HOLD`이며 전체 P1.4도 `IN_PROGRESS`다.

P1.4B는 P1.4A r3 positive receipt SHA-256
`f2afead44a548fd861c550acd2ee17dd52e3a3dae434f43bfc85f43ea74b0365`를 runner에
고정하고 같은 source receipt hash만 허용하는 source-mutated negative control을
새로 두 번 실행했다. 각 receipt의 내부 두 run은 registered exit `1`과
control-triggered normalized outcome을 냈고, source checkout은 변경되지 않았으며
cleanup도 통과했다. negative comparator는 positive anchor, mutation hash,
deterministic build contract, source, isolation, normalized negative outcome을
결속하고 runtime nonce 등 휘발성 값만 제외해 `FIX`를 냈다. focused test는 32
passed, 전체 r20 회귀는 2,440 passed, 5 skipped, 0 failed, 0 errors였다.
Claude Opus 4.8, Grok 4.5, Cline GLM 5.2의 r1/r2 검토도 모두 `GO`와
`REPEATABILITY_GAP`만 남겼고 semantic comparator가 `FIX`를 확인했다. 근거는
`phase1-p14b-webgoat-idor-negative-control-20260723-r1-r2-comparison.json`과
`phase1-p14b-webgoat-idor-negative-supervisor-review-20260723-r1-r2-comparison.json`이다.
이것은 source-mutated local negative oracle만 뜻한다. independent upstream fixed
revision, scanner finding mapping, CWE/CVSS, TP/FP/FN, API authorization, Guardian,
H100, release는 전부 여전히 `HOLD`이며 전체 P1.4도 `IN_PROGRESS`다.

### Phase 2. 공개 분모와 holdout 구성

**목표:** 개발 중 표본과 최종 표본을 섞지 않는 측정 분모를 고정한다.

| 작업 ID | 작업 | 완료 조건 | 현재 상태 |
| --- | --- | --- | --- |
| P2.1 | OWASP BenchmarkJava | 2,740 case의 공식 expected result, license, source hash 검증 및 materialization | `IN_PROGRESS` |
| P2.1A | BenchmarkJava current denominator receipt | 2,740 case의 공식 expected result, license, source hash, exclusion을 current target에서 두 번 재물질화하고 raw-free manifest로 결속 | `FIX_NARROW` |
| P2.1B | BenchmarkJava independent clean-worktree replay | 별도 raw-blob clean worktree에서 Java projection을 다시 materialize하고 P2.1A와 교차 비교 | `FIX_NARROW` |
| P2.2 | OWASP BenchmarkPython | 전량 공식 expected result, license, source hash 검증 및 materialization | `FIX_NARROW` |
| P2.2A | BenchmarkPython current denominator receipt | 1,230 case의 공식 expected result, license, source hash, exclusion을 새 raw-blob clean worktree에서 두 번 재물질화하고 raw-free manifest로 결속 | `FIX_NARROW` |
| P2.2B | BenchmarkPython independent clean-worktree replay | P2.2A worktree를 재사용하지 않고 새 raw-blob clean worktree에서 Python projection을 재물질화해 교차 비교 | `FIX_NARROW` |
| P2.3 | 로컬 취약 앱 6개 | Juice Shop, WebGoat, NodeGoat, PyGoat, crAPI, WrongSecrets의 source-derived execution oracle과 six-app aggregate | `FIX_NARROW` |
| P2.3A | 여섯 local source registry | source origin, revision/tree/blob, root license, 선언된 runtime allowance, source-only repeatability를 결속 | `FIX_NARROW` |
| P2.3B.1 | WebGoat IDOR execution boundary | 새 P2.3A source receipt에서 positive/negative execution oracle을 재결속 | `FIX_NARROW` |
| P2.3B.2 | Juice Shop execution boundary | source-bound positive/negative execution oracle | `FIX_NARROW` |
| P2.3B.3 | NodeGoat execution boundary | source-bound positive/negative execution oracle | `FIX_NARROW` |
| P2.3B.4 | PyGoat execution boundary | source-bound positive/negative execution oracle | `FIX_NARROW` |
| P2.3B.5 | crAPI execution boundary | source-bound positive/negative execution oracle | `FIX_NARROW` - [BOLA 사전등록](p23b5-crapi-vehicle-bola-preregistration-ko.md) |
| P2.3B.6 | WrongSecrets execution boundary | Maven branch `MEASURED_HOLD` 보존; [Challenge1 Javac harness positive/negative execution oracle](p23b6-wrongsecrets-challenge1-javac-harness-preregistration-ko.md), 3AI two-run comparator | `FIX_NARROW` |
| P2.3B.7 | six-app execution aggregate | [six-app aggregate 사전등록](p23b7-six-app-execution-aggregate-preregistration-ko.md), coverage/exclusion/repeatability와 3AI two-run comparator | `FIX_NARROW` |
| P2.4A | 개발 generated pair 60 청사진 | 60 slot, plane/severity/oracle/reserve/local generator profile을 scanner output 전에 고정하고 external repeat/3AI two-run review를 결속 | `FIX_NARROW` - [사전등록과 결과](p24a-generated-pair-blueprint-preregistration-ko.md) |
| P2.4B.1 | 개발 generated pair source-triplet staging | external stage, blueprint/slot/reserve/path/raw-free binding을 machine repeat과 3AI two-run comparator로 fail-closed 검증 | `FIX_NARROW` - [사전등록과 결과](p24b1-generated-pair-staging-preregistration-ko.md) |
| P2.4B.2 | [`source-flow` 19개 slot leaf materialization](p24b2-source-flow-materialization-wbs-ko.md) | primary/reserve source triplet과 tree identity를 slot별로 두 번 검증 | `FIX_NARROW` - .01-.20 A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3 | [`auth-rls-db` 19개 leaf materialization](p24b3-auth-rls-db-materialization-wbs-ko.md) | primary/reserve source triplet과 tree identity를 slot별로 두 번 검증 | `IN_PROGRESS` - .01-.12 `FIX_NARROW`, .13 A-D 완료, E 대기 |
| P2.4B.4-P2.4B.8 | 개발 generated pair 나머지 family/admission/aggregate | 60 source-bound vulnerable/fixed/negative triplet과 machine admission receipt를 family별로 두 번 검증 | `NOT_STARTED` |
| P2.5 | 공개 source stress 100개 | 기존 41개와 신규 자연 공개 앱 59개를 top/mid/long-tail로 층화하고 source-only 권한을 기록 | `NOT_STARTED` |
| P2.6 | 최종 H100 동결 | generated pair 80 + 공개 oracle pair 20, 4개 평면 각 25 case, exclusion 사전등록 | `NOT_STARTED` |
| P2.7 | 감독관 검토 | 분모, 제외, 라이선스, oracle provenance의 2회 외부 검토 | `NOT_STARTED` |

**Phase exit:** H100 membership과 severity를 동결한다. 아직 detector 변경이나 결과
확인은 하지 않는다.

#### P2.3A 완료 패킷

P2.3A는 과거 source-only PASS JSON을 재사용하지 않고 새 canonical seed와 source
receipt sidecar를 만들었다. 아래 일곱 칸은 r29 target에서 모두 닫혔으며, 이 완료는
source provenance와 선언-only 범위에만 한정된다.

| 칸 | 세부 목표 | 현재 상태 |
| --- | --- | --- |
| A | 여섯 source identity, 선언-only runtime allowance, scanner/oracle 제외를 사전등록 | `DONE` - [P2.3A 사전등록](p23a-six-local-source-registry-preregistration-ko.md) |
| B | source receipt와 canonical seed를 fresh clean checkout에서 생성 | `DONE` - clean-source admission `PASS`, seed SHA-256 `95f48fd53d3d411be9dbaa7b78a130a893d1fbf87bbc92f7ce40f1d6dbaf2fef` |
| C | source tamper, path traversal, overwrite, raw-free claim boundary focused test | `DONE` - focused/compatibility 160 passed, source-materialization 25 passed, clean-source 4 passed |
| D | 새 seed의 source-only materialization 두 run과 semantic comparison | `DONE` - `phase2-p23a-six-source-registry-20260723-r1-r2-comparison.json` `FIX` |
| E | current target full regression | `DONE` - r29 12/12 shard, 2,465 passed, 5 skipped, 0 failed, 0 errors |
| F | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 review run | `DONE` - `phase2-p23a-supervisor-review-20260723-r2-r3-comparison.json` `FIX` |
| G | evidence hash/path와 남은 runtime/oracle HOLD를 장부에 기록 | `DONE` - runtime isolation, machine oracle, scanner accuracy, metrics, H100, release는 모두 `HOLD` |

#### P2.3B.1 완료 패킷

P2.3B.1은 P2.3A WebGoat clean source registry에 source-bound positive execution과
source-mutated negative control을 다시 결속했다. historical raw positive receipt hash 하나를
신뢰하지 않고, current runner/source verifier/base image provenance와 source receipt가 모두
일치할 때만 negative control을 실행한다. positive raw receipt hash가 매 실행 달라도 positive
comparator가 두 receipt와 semantic equality를 `FIX`로 확인하고, 각 negative receipt가 그
서로 다른 anchor에 정확히 묶일 때만 negative comparator가 `FIX`가 된다.

| 칸 | 세부 목표 | 현재 상태 |
| --- | --- | --- |
| A | WebGoat IDOR rebind 가설, 제외, claim boundary 사전등록 | `DONE` - [P2.3B.1 사전등록](p23b1-webgoat-idor-rebind-preregistration-ko.md) |
| B | stale historical receipt pin을 current provenance와 same-source binding으로 교체 | `DONE` - stale provenance, source mismatch, missing/non-FIX positive comparison, mismatched negative anchor를 fail-closed로 거부 |
| C | replay/comparator/evidence/materializer focused suite | `DONE` - 119 passed |
| D | sealed r33 target에서 새 positive r5/r6, negative r5/r6 실행과 comparison | `DONE` - positive/negative comparator 모두 `FIX`, `repeat_exact=true` |
| E | current target full regression | `DONE` - r16 12/12 shard, 2,465 passed, 5 skipped, 0 failed, 0 errors; `aggregate-v3.json` `COMPLETE` |
| F | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 review run | `DONE` - 두 run 전원 `GO`, blocker 0, claim boundary confirmed; `phase2-p23b1-supervisor-review-20260723-r1-r2-comparison.json` `FIX` |
| G | evidence와 비주장 범위를 장부에 기록 | `DONE` - detector accuracy, general IDOR, TP/FP/FN, severity, warning/block, Guardian, H100, release는 모두 `HOLD` |

#### P2.3B.2 완료 패킷

P2.3B.2는 P2.3A Juice Shop clean source registry의 upstream cross-user basket read를
current source-built adapter image에서 재현했다. compiled route의 ownership guard는
transient derivative에만 한 번 삽입했으며, source checkout을 바꾸지 않았다. positive는
`200`과 expected basket id, negative는 `403`을 같은 Bjoern fixture와 loopback-only
runtime에서 관찰했다.

| 칸 | 세부 목표 | 현재 상태 |
| --- | --- | --- |
| A | Juice Shop BOLA 가설, source/image provenance, negative mutation, claim boundary 사전등록 | `DONE` - [P2.3B.2 사전등록](p23b2-juice-shop-basket-bola-preregistration-ko.md) |
| B | P2.3A registry/image/route patch/runtime/cleanup을 fail-closed로 결속 | `DONE` - stale source, image label, route marker, HTTP outcome, isolation, cleanup, positive anchor mismatch를 거부 |
| C | replay, patch, driver parser, registry, comparator, source verifier focused suite | `DONE` - r34 focused 63 passed, 0 failed, 0 errors, 0 skipped |
| D | sealed r34 target에서 positive r1/r2, negative r1/r2와 two comparator | `DONE` - positive/negative comparator 모두 `FIX`, `repeat_exact=true` |
| E | current target full regression | `DONE` - r17 12/12 shard, 2,478 passed, 5 skipped, 0 failed, 0 errors; aggregate `COMPLETE` |
| F | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two review run | `DONE` - 모든 lane `GO`, blocker 0, claim boundary confirmed; `phase2-p23b2-supervisor-review-20260723-r1-r2-comparison.json` `FIX` |
| G | evidence path와 one-route claim boundary를 장부에 기록 | `DONE` - BOLA detector accuracy, general IDOR, TP/FP/FN, severity, warning/block, Guardian, H100, release는 모두 `HOLD` |

#### P2.3B.3 완료 패킷

P2.3B.3은 P2.3A NodeGoat clean source registry의 allocations direct-object-reference를
current source image와 pinned local Mongo execution dependency에서 재현했다. source route의
`req.params.userId` 사용은 transient derivative에서 정확히 한 번 `req.session.userId`로
대체했으며 source checkout은 바꾸지 않았다. positive는 HTTP `200`과 foreign allocation을,
negative는 HTTP `200`, foreign allocation 부재, own allocation 존재를 internal-only runtime에서
관찰했다.

| 칸 | 세부 목표 | 현재 상태 |
| --- | --- | --- |
| A | NodeGoat IDOR 가설, source/image/runtime provenance, negative mutation, claim boundary 사전등록 | `DONE` - [P2.3B.3 사전등록](p23b3-nodegoat-allocations-idor-preregistration-ko.md) |
| B | P2.3A registry/image/route patch/Mongo/runtime/cleanup을 fail-closed로 결속 | `DONE` - stale source, image label, route marker, Mongo digest, seed/state, HTTP outcome, isolation, cleanup, positive anchor mismatch를 거부 |
| C | replay, Node 12 seed compatibility, patch, driver parser, registry, comparator, source verifier focused suite | `DONE` - r40 focused 86 passed, 0 failed, 0 errors, 0 skipped |
| D | sealed r40 target에서 positive r7/r8, negative r9/r10과 two comparator | `DONE` - positive/negative comparator 모두 `FIX`, `repeat_exact=true`; intermediate negative r7 exit 137 HOLD는 development evidence로 보존 |
| E | current target full regression | `DONE` - r18 12/12 shard, 2,494 passed, 5 skipped, 0 failed, 0 errors; aggregate `COMPLETE` |
| F | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two review run | `DONE` - 모든 lane `GO`, blocker 0, claim boundary confirmed; Claude direct-file attestation 12/12; `phase2-p23b3-supervisor-review-20260723-r1-r2-comparison.json` `FIX` |
| G | evidence path와 one-route claim boundary를 장부에 기록 | `DONE` - IDOR detector accuracy, general authorization recall, TP/FP/FN, severity, warning/block, Guardian, H100, release는 모두 `HOLD` |

#### P2.3B.4 완료 패킷

P2.3B.4는 P2.3A PyGoat clean source registry의 standalone sensitive-data-exposure
subproject를 source-built image에서 재현했다. unauthenticated
`/api/all-users/` positive는 `200`, non-empty users array, credit-card, SSN,
API-key field shape만 raw-free boolean으로 관찰한다. negative derivative는
`all_users_data_view` 바로 앞에 이미 import된 `@login_required`를 정확히 한 번만
삽입하고 같은 request가 `302`, users JSON 부재, login redirect를 반환해야 한다.
source response body, fixture credential, raw headers, SQLite data, container log는 evidence에
저장하지 않는다.

| 칸 | 세부 목표 | 현재 상태 |
| --- | --- | --- |
| A | PyGoat source/image/runtime provenance, decorator mutation, claim boundary 사전등록 | `DONE` - [P2.3B.4 사전등록](p23b4-pygoat-sensitive-data-preregistration-ko.md) |
| B | P2.3A registry, source/image file hash, immutable source copy, non-root tmpfs adapter, loopback driver, cleanup을 fail-closed로 결속 | `DONE` - registry/image/source hash, marker ambiguity, outcome, isolation, cleanup, positive anchor mismatch를 거부 |
| C | replay/comparator, patch, driver parser, registry, isolation, raw-free receipt focused suite | `DONE` - r41 focused 12 passed, 0 failed, 0 errors, 0 skipped; receipt `58964a1f99c78cdcbb0b76ee6acfaec4af07b59ff5a99828cd1b0dcac3d25180` |
| D | sealed r41 target에서 positive r2/r3, negative r4/r5와 two comparator | `DONE` - positive/negative comparator 모두 `FIX`, `repeat_exact=true`; initial positive r1 app-start failure는 development `HOLD` evidence로 보존 |
| E | current target full regression | `DONE` - r19 12/12 shard, 2,506 passed, 5 skipped, 0 failed, 0 errors; aggregate `8a69f009d3be3955521f99883ea464f0014fbe6a0388a0af749f165a2f0f6dba` |
| F | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two review run | `DONE` - r3/r4 모든 lane `GO`, blocker 0, Claude direct-file 12/12; `phase2-p23b4-supervisor-review-20260723-r3-r4-comparison.json` `FIX`. r1/r2 packet-text drift `HOLD`도 보존 |
| G | evidence와 one-endpoint claim boundary를 장부에 기록 | `DONE` - sensitive-data/Korean-personal-data detector accuracy, authorization/IDOR recall, TP/FP/FN, severity, warning/block, DB/RLS, Guardian, H100, release는 모두 `HOLD` |

### Phase 3. 변경 전 성능 기준선

**목표:** 현재 제품이 무엇을 맞추고 무엇을 놓치는지 TP/FP/FN/TN으로 공개한다.

| 작업 ID | 작업 | 완료 조건 | 현재 상태 |
| --- | --- | --- | --- |
| P3.1 | 두 번 기준선 실행 | 같은 frozen denominator를 두 번 실행하고 semantic 결과가 일치 | `NOT_STARTED` |
| P3.2 | 기계 채점 | TP, FP, FN, TN, recall, specificity, Wilson 하한을 plane별로 계산 | `NOT_STARTED` |
| P3.3 | 후보 분포 | rule, detector subtype, 언어, 평면별 후보 편중을 산출 | `NOT_STARTED` |
| P3.4 | coverage 판정 | 지원 불가, timeout, scanner/control error를 통과가 아닌 explicit HOLD로 집계 | `NOT_STARTED` |
| P3.5 | 감독관 검토 | 액션 가능성 및 claim boundary만 세 감독관 2회 검토 | `NOT_STARTED` |

**Phase exit:** 가장 큰 오류군을 숫자로 하나 선택할 수 있어야 한다. 기준선 자체가
합격선을 못 넘으면 `MEASURED_HOLD`이며, 그것이 정상적인 결과다.

### Phase 4. 한 오류군의 A/B 교정

**목표:** 가장 큰 가중 오류군 하나만 고쳐서 다른 지표를 망치지 않는지 증명한다.

| 작업 ID | 작업 | 완료 조건 | 현재 상태 |
| --- | --- | --- | --- |
| P4.1 | 가설 사전등록 | 오류군, rule boundary, 예상 변화, 개발 표본을 수정 전에 기록 | `NOT_STARTED` |
| P4.2 | observe 구현 | 새 규칙은 finding을 관찰만 하며 block 영향 0 | `NOT_STARTED` |
| P4.3 | paired A/B | 동일 개발 분모에서 before/after, recall, specificity, 속도, 반복성을 비교 | `NOT_STARTED` |
| P4.4 | warn 승격 | independent pair와 모든 새 후보의 oracle이 있을 때만 warning | `NOT_STARTED` |
| P4.5 | block 승격 | 사전등록 holdout과 최종 수치 조건을 통과할 때만 block | `NOT_STARTED` |
| P4.6 | 감독관 검토 | 가설 하나, 변경 하나, 증거 하나의 2회 외부 검토 | `NOT_STARTED` |

**Phase exit:** 성능이 좋아도 holdout, 속도, 다른 plane, 기존 설치/호환성이 하락하면
승격하지 않는다. 필요하면 observe로 되돌리고 실패 증거를 보존한다.

### Phase 5. 제품 평면별 깊이

**목표:** 올인원 기능 목록이 아니라 네 제품 평면을 각각 측정 가능한 계약으로 완성한다.

| 작업 ID | 평면 | 최소 완료 조건 | 현재 상태 |
| --- | --- | --- | --- |
| P5.S | 사이트 | 정적 취약점, XSS/주입, 허가된 로컬 web path, coverage error fail-closed | `IN_PROGRESS` |
| P5.A | API | 인증/인가, IDOR/BOLA, route-to-service 경계, local execution oracle | `IN_PROGRESS` |
| P5.D | 데이터 | SQL/RLS, 저장·로그·외부 전송, Korean PII, 보존·파기, read-only connector 경계 | `IN_PROGRESS` |
| P5.O | 운영 | secrets, SCA, CI/IaC, MCP proxy/interceptor, protocol, suppression/CI policy | `IN_PROGRESS` |
| P5.I | 설치와 UX | GPT, Grok, Codex, Antigravity 대상 설치, CLI, quick check, Guardian, 한국어 다음 행동 | `IN_PROGRESS` |

각 평면은 해당 P4 방식으로 독립 oracle, baseline, A/B, observe/warn/block, 세 감독관
반복 검토를 가져야 한다. 하나의 평면이 `FIX_NARROW`여도 전체 제품 GO가 아니다.

### Phase 6. 동결된 H100 최종 검증

**목표:** 개발 중 보지 않은 표본에서 전체 조건을 동시에 검증한다.

| 작업 ID | 작업 | 완료 조건 | 현재 상태 |
| --- | --- | --- | --- |
| P6.1 | 후보 동결 | analyzer, rule pack, toolchain, H100 manifest, labels의 hash 고정 | `NOT_STARTED` |
| P6.2 | 단회 블라인드 실행 | H100 100개를 한번만 채점하고 결과 후 rule/label/threshold 변경 금지 | `NOT_STARTED` |
| P6.3 | 수치 게이트 | 전체 90/100, 각 평면 24/25, Critical 100%, 나머지 고정 기준 전부 충족 | `NOT_STARTED` |
| P6.4 | 반복 실행 | 수정 없이 두 번째 run이 첫 결과와 의미상 정확히 일치 | `NOT_STARTED` |
| P6.5 | 감독관 검토 | release disposition을 세 감독관 2회 독립 검토 | `NOT_STARTED` |

**Phase exit:** 수치 하나라도 미달이면 `MEASURED_HOLD`다. 표본을 빼거나 기준을 낮춰
GO로 바꾸지 않는다.

### Phase 7. 출하 판정과 재현 가능한 사용 경험

**목표:** 실제 사용자가 설치해 CLI와 MCP로 같은 Guardian 결론에 도달하는지 확인한다.

| 작업 ID | 작업 | 완료 조건 | 현재 상태 |
| --- | --- | --- | --- |
| P7.1 | 패키지 재현 | fresh wheel 설치, stdio MCP, CLI smoke, evidence binding | `IN_PROGRESS` |
| P7.2 | 클라이언트 호환 | GPT, Grok, Codex, Antigravity의 문서화된 설치 경로와 tool list 확인 | `IN_PROGRESS` |
| P7.3 | release bundle | H100, baseline, coverage, license, SBOM, evidence, known limits를 한 bundle로 결속 | `NOT_STARTED` |
| P7.4 | 최종 GO/HOLD | Guardian canonical gate와 모든 Phase exit을 함께 평가 | `NOT_STARTED` |
| P7.5 | 외부 최종 검토 | 세 감독관 전원의 두 번 동일한 release disposition | `NOT_STARTED` |

`GO_RELEASE`가 되기 전에는 제품을 "출하 전 시니어 감사관 지향"으로 설명할 수는
있지만, "인간 시니어 동급", "전 영역 보장", "실전 정확도 검증 완료"라고 쓰지 않는다.

### Phase 8. 목표 통제와 독립 검증 운영

**목표:** 기존 G1-G6 제품 작업을 하나씩 끝내는 과정 자체가 재현 가능하고, 감독 검토가
선택 사항이 아니라 card/phase 종료 조건임을 fail-closed로 확인한다. 이 phase는 탐지
성능, H100, 출하 승인에 대한 제품 성능 주장을 추가하지 않는다.

| 작업 ID | 작업 | 완료 조건 | 현재 상태 |
| --- | --- | --- | --- |
| P8.1 | goal-state와 단일 active validator | G0-G7/P0-P8, gate prefix, 3AI 2회 policy, release refusal negative test | `FIX_NARROW` - 9 focused passed, 2650 passed/5 skipped full, machine/3AI comparator `FIX` |
| P8.1B | human status board sync | current JSON과 세 운영판의 current marker 일치, stale marker 거부 | `FIX_NARROW` - initial D `HOLD` 보존, corrected A-G와 3AI comparator `FIX` |
| P8.2A | Windows supervisor command resolution | npm `.cmd`/`.exe` path resolution, health r1/r2, 3AI comparator | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX`; Windows supervisor contract만 해당 |
| P8.2B | Windows native supervisor transport | native `.exe` discovery, long-packet transport probe/comparator r1/r2, 3AI comparator | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P8.2D | GLM health terminal contract | system contract, strict parser negative test, health r1/r2, 3AI comparator | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX`; invalid field ID와 Claude timeout receipt 보존 |
| P8.2E | G1-G6 product-card catalog와 phase-exit review binding | catalog schema, predecessor/phase-exit validator, 3AI comparator | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX`; registry transition control만 해당 |
| P8.2C | receipt binding | `FIX_NARROW`/phase 상태가 evidence/comparator 없이 기록될 수 없음을 negative fixture로 검증 | `NOT_STARTED` |
| P8.3 | phase packet | child/exclusion/3AI F1/F2 phase packet의 two-run comparator | `NOT_STARTED` |
| P8.4 | final disposition control | G1-G7/P0-P8 및 수치 gate 미달의 `GO_RELEASE` 거부 | `NOT_STARTED` |

**Phase exit:** P8.1, P8.1B, P8.2A-P8.2C, P8.3-P8.4 각각 A-G와 세 감독관 F1/F2를 통과하고 P8 phase packet도
`FIX_NARROW`여야 한다. P8은 다른 phase를 대체하지 않는다.

## 현재 다음 한 작업

P2.1A와 P2.1B는 모두 `FIX_NARROW`다. P2.1A는 r22 target에서 Git raw blob으로
만든 clean Java worktree를 공식 BenchmarkJava 1.2 revision, tree, expected-result,
license와 대조했다. P2.1B는 r23 target에서 P2.1A worktree를 재사용하지 않고 별도의
raw-blob clean worktree와 새 carrier manifest를 만들었다. 두 manifest는 동일
SHA-256 `223cf168ec7ad1461afbb4b82755275d3e9c8194bc50f825384fda1199470a80`이고,
Java projection은 정확히 2,740 case다. P2.1B cross-worktree comparator는
`phase2-p21b-benchmarkjava-cross-worktree-20260723-r1-comparison.json`에서 `FIX`였고,
세 감독관의 재시도 r1/r2 semantic comparison도
`phase2-p21b-benchmarkjava-supervisor-review-20260723-r23-retry-r1-r2-comparison.json`에서
`FIX`였다. r23 focused 58 passed와 전체 회귀 2,445 passed, 5 skipped, 0 failed,
0 errors도 같은 target에 결속됐다. 최초 Windows checkout의 `core.autocrlf=true` 물리
바이트 mismatch, 대문자 field-id review attempt, 그리고 P2.1B의 300초 Claude timeout은
모두 fail-closed 실패 증거로 보존했고 승인 증거로 사용하지 않는다.

P2.2A도 `FIX_NARROW`다. r24 target에서 새 Python raw-blob clean worktree를 만들고
공식 BenchmarkPython 0.1 revision, tree, expected-result, license와 대조했다. 같은
Python source에서 생성한 scanner 미관찰 carrier manifest 두 개는 모두 SHA-256
`223cf168ec7ad1461afbb4b82755275d3e9c8194bc50f825384fda1199470a80`였고, Python
projection은 정확히 1,230 case다. Python comparator는
`phase2-p22a-benchmarkpython-denominator-20260723-r1-r2-comparison.json`에서 `FIX`였고,
Claude Opus 4.8의 직접 파일 10개 검토, Grok 4.5, Cline GLM 5.2의 r1/r2 semantic
comparison도
`phase2-p22a-benchmarkpython-supervisor-review-20260723-r24-r1-r2-comparison.json`에서
`FIX`였다. r24 focused 52 passed와 전체 회귀 2,450 passed, 5 skipped, 0 failed,
0 errors도 같은 target에 결속됐다. 이 결과는 Python 분모와 provenance만 승인한다.

P2.2B도 `FIX_NARROW`다. r25 target에서 P2.2A의 Python worktree를 재사용하지 않고
새 raw-blob clean worktree와 carrier manifest를 만들었다. P2.2A/P2.2B manifest는 모두
SHA-256 `223cf168ec7ad1461afbb4b82755275d3e9c8194bc50f825384fda1199470a80`였고,
Python projection은 정확히 1,230 case다. cross-worktree comparator는
`phase2-p22b-benchmarkpython-cross-worktree-20260723-r1-comparison.json`에서 `FIX`였고,
Claude Opus 4.8 직접 파일 10개 검토, Grok 4.5, Cline GLM 5.2의 r1/r2 semantic
comparison도
`phase2-p22b-benchmarkpython-supervisor-review-20260723-r25-r1-r2-comparison.json`에서
`FIX`였다. r25 focused 52 passed와 전체 회귀 2,450 passed, 5 skipped, 0 failed,
0 errors도 같은 target에 결속됐다. 이 결과는 Python 분모와 provenance만 승인한다.

P2.3A는 `FIX_NARROW`다. 새 ordinary non-shallow clone 여섯 개는 source origin,
revision/tree/blob, root license와 strict fsck를 다시 대조했고, canonical seed와
source-only materialization r1/r2가 semantic-exact였다. Claude Opus 4.8, Grok 4.5,
Cline GLM 5.2도 raw-free review packet의 두 run에서 모두 `GO`와
`REPEATABILITY_GAP`만 남겼고, comparator가 `FIX`를 냈다. 근거는
`phase2-p23a-six-source-registry-20260723-r1-r2-comparison.json`과
`phase2-p23a-supervisor-review-20260723-r2-r3-comparison.json`이다. 최초 대문자
field ID 실행은 receipt 생성 전에 fail-closed로 거부됐고 승인 근거에 포함하지 않는다.
이 결과는 source provenance와 선언된 local runtime allowance만 뜻한다.

P2.3B.1은 `FIX_NARROW`다. sealed r33 target에서 positive r5/r6와 negative r5/r6를 새로
실행했고 두 execution comparator는 모두 `FIX`, `repeat_exact=true`였다. r16 전체 회귀는
12/12 shard `COMPLETE`, 2,465 passed, 5 skipped, 0 failed, 0 errors이며, Claude Opus 4.8,
Grok 4.5, Cline GLM 5.2의 r1/r2 review comparator도 `FIX`였다. 이 증거는 WebGoat 하나의
source-bound execution oracle pair에만 적용된다.

P2.3B.2도 `FIX_NARROW`다. sealed r34 target에서 Juice Shop의 upstream cross-user basket
read positive와 transient compiled ownership-guard negative를 각각 두 번 실행했다. positive와
negative comparator는 모두 `FIX`, `repeat_exact=true`였고, r17 full regression은 12/12 shard
`COMPLETE`, 2,478 passed, 5 skipped, 0 failed, 0 errors였다. Claude Opus 4.8, Grok 4.5,
Cline GLM 5.2의 r1/r2 review comparator도 `FIX`였다. 이 결과는 한 source-bound BOLA
execution oracle pair만 뜻하며 K-Guard BOLA/IDOR 탐지 성능은 여전히 증명하지 않는다.

P2.3B.3도 `FIX_NARROW`다. sealed r40 target에서 NodeGoat allocations cross-user read
positive r7/r8와 transient `req.session.userId` negative r9/r10를 각각 두 번 실행했다.
positive와 negative comparator는 모두 `FIX`, `repeat_exact=true`였고, r18 full regression은
12/12 shard `COMPLETE`, 2,494 passed, 5 skipped, 0 failed, 0 errors였다. Claude Opus 4.8,
Grok 4.5, Cline GLM 5.2의 r1/r2 review comparator도 `FIX`였다. 이 결과는 NodeGoat 한
source-bound execution oracle pair만 뜻하며 K-Guard IDOR 탐지 성능은 여전히 증명하지 않는다.

P2.3B.4도 `FIX_NARROW`다. sealed r41 target에서 PyGoat standalone
sensitive-data-exposure source image의 unauthenticated all-users positive r2/r3와 transient
`@login_required` negative r4/r5를 각각 두 번 실행했다. positive와 negative comparator는
모두 `FIX`, `repeat_exact=true`였고, r19 full regression은 12/12 shard `COMPLETE`,
2,506 passed, 5 skipped, 0 failed, 0 errors였다. Claude Opus 4.8, Grok 4.5, Cline GLM 5.2의
identical-packet r3/r4 review comparator도 `FIX`였다. initial positive r1 runtime failure와
r1/r2 supervisor packet-text drift `HOLD`는 실패 증거로 보존되어 있으며 승인 근거에 포함하지
않는다. 이 결과는 한 source-bound all-users API execution oracle pair만 뜻하며 K-Guard
sensitive-data 또는 Korean-personal-data 탐지 성능은 증명하지 않는다.

#### P2.3B.5 완료 패킷

P2.3B.5는 P2.3A crAPI raw-blob source registry의 authenticated cross-owner vehicle
location route를 current source image에서 재현했다. transient derivative에는
current authenticated owner vehicle set을 검사하는 guard를 정확히 한 번 삽입했다. negative의
generic JSON error envelope는 허용하되 target vehicle field shape, location, full name,
email 중 하나라도 있으면 `HOLD`다. source checkout, seed credential, JWT, UUID, response
body, header, container log는 evidence에 보관하지 않는다.

| 칸 | 세부 목표 | 현재 상태 |
| --- | --- | --- |
| A | crAPI BOLA 가설, source/image/runtime provenance, negative mutation, claim boundary 사전등록 | `DONE` - [P2.3B.5 사전등록](p23b5-crapi-vehicle-bola-preregistration-ko.md) |
| B | P2.3A registry/source file hash/source-image label, ephemeral DB, internal-only runtime, cleanup, one-anchor owner guard를 fail-closed로 결속 | `DONE` - source/image/patch/outcome/isolation/cleanup/positive-anchor mismatch를 거부 |
| C | replay/comparator, patch, raw-free driver failure classifier, isolation, cleanup focused suite | `DONE` - 13 passed, 0 failed, 0 skipped |
| D | sealed r46 target에서 positive r1/r2, negative r1/r2와 two comparator | `DONE` - `phase2-p23b5-crapi-vehicle-bola-20260723-r5`의 positive/negative comparator 모두 `FIX`, `repeat_exact=true` |
| E | current target full regression | `DONE` - `python -m pytest -q`: 2,519 passed, 5 skipped, 0 failed, 0 errors |
| F | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two review run | `DONE` - r1/r2 모든 lane `GO`, blocker 0, Claude direct-files 1, Grok/GLM sanitized-packet 2; `supervisor-review-r1-r2-comparison.json` `FIX` |
| G | evidence와 one-route claim boundary를 장부에 기록 | `DONE` - baseline `e5c9ee744c31d1bc6025b70cd7c9067bca3a19975cf3daff5ac759c0d8667453`; detector accuracy, general BOLA/IDOR, severity, TP/FP/FN, Korean PII, warning/block, Guardian, H100, release는 모두 `HOLD` |

개발 중 source-image isolation false HOLD, constructor cleanup leak, negative error-envelope
false HOLD와 잘못된 comparator input은 모두 fail-closed `HOLD` evidence로 보존했다. 이들은
r46 승격 근거가 아니다. P2.3B.5는 crAPI 한 route의 source-bound positive/negative execution
oracle과 반복성만 뜻하며, K-Guard의 탐지 성능을 뜻하지 않는다.

P2.3B.6 WrongSecrets는 Maven `MEASURED_HOLD`를 보존한 상태로, Challenge1 Javac harness의
source-derived positive/negative execution oracle과 3AI two-run comparator를 `FIX_NARROW`로
완료했다. P2.3B.7은 여섯 앱/18 component comparator, exclusion `0`, raw-free authority,
aggregate repeat, 3AI two-run comparator를 `FIX_NARROW`로 완료했다. 이는 generic secret
detection, 새 앱 실행, 성능 지표 또는 release를 뜻하지 않는다. **P2.4A generated pair 60 청사진
사전등록**은 external two-run comparator와 Claude/Grok/GLM two-run review를 통과해 `FIX_NARROW`로
완료했다. 이 상태는 actual source pair가 아니라 60 slot의 사전등록만 뜻한다. **P2.4B.1**은
external source-triplet staging contract를 machine repeat과 Claude/Grok/GLM two-run comparator로
`FIX_NARROW` 완료했다. 이 결과도 source가 없는 120 candidate path/360 empty directory reservation일
뿐이다. P2.4B.2.01은 `site-01` primary/reserve의 6 source tree를 external repeat과
Claude/Grok/GLM two-run comparator로 `FIX_NARROW` 완료했다. P2.4B.2.02도 `site-02`
JavaScript/Express SQL query primary/reserve 6 source tree의 materialization, focused attestation,
source repeat, Claude/Grok/GLM two-run comparator를 `FIX_NARROW` 완료했다. r2 full regression의
single-failure `CONTROL_HOLD`는 삭제하지 않았고 same-target r3/r4 clean receipt와 함께 해당 leaf
문서에 보존했다. **P2.4B.2.03**도 `site-03` JavaScript/Express command-exec primary/reserve 6
source tree의 materialization, focused/full attestation, source comparator, Claude/Grok/GLM r3/r4
semantic comparator를 `FIX_NARROW`로 완료했다. 첫 r1/r2 packet의 GLM `TEST_ATTESTATION_GAP` HOLD는
삭제하지 않고 결과 문서에 보존했다. 세 leaf 모두 source tree identity만 뜻하며
execution/admission/scanner metric을 만들지 않는다. P2.4B.2.04는 Next.js path-traversal route,
input, fixture root, fixed root-confinement, static negative control의 A-G를 닫았다. current-target r2에서
focused 6/6, full 2,581 passed, machine comparator `FIX`, Claude/Grok/GLM F1/F2 lane `GO`, supervisor
semantic comparator `FIX`를 기록했다. 단회 review의 intentional `REPEATABILITY_GAP` HOLD는 삭제하지
않고 보존했다. P2.4B.2.05는 Next.js untrusted-redirect continue/signin route, `next`/`returnTo`,
same-origin fixed boundary, static internal negative control의 A-G를 닫았다. current target에서 focused 6/6과
isolated full r1/r2 각각 2,587 passed, machine comparator `FIX`, Claude/Grok/GLM F1/F2 lane `GO`, supervisor
semantic comparator `FIX`를 기록했다. 이전 target의 first full `CONTROL_HOLD`와 health-only GLM
`BLOCKED_PROVIDER`는 삭제하지 않고 F packet에 보존했다. 두 leaf 모두 source tree identity만 뜻하며 다음은
P2.4B.2.06 A다. **P2.4B.2.06**은 JavaScript/Express SSRF primary preview와 reserve avatar의
`url`/`imageUrl`, candidate별 `https` host allowlist, static internal negative control을 strict writer/comparator로
결속했다. evidence-time target에서 focused 6/6, isolated full r1/r2 각각 2,593 passed, external source comparator
`FIX`, Claude/Grok/GLM F1/F2 lane `GO`, supervisor semantic comparator `FIX`를 기록했다. single-review
`REPEATABILITY_GAP`은 승격 근거에서 제외해 보존했다. 이 leaf도 source tree identity만 뜻하며 HTTP/SSRF
execution, scanner metric, TP/FP/FN, H100, release를 승인하지 않는다. P2.4B.2.07은 Next.js primary preferences와
reserve profile route, `preferences`/`profile` JSON field, fixed explicit field set, static negative object를 A에서 동결했다.
site-07 전용 materializer/comparator, focused 6/6, external source comparator `FIX`, isolated full r1/r2 각각 2,599 passed,
Claude/Grok/GLM F1/F2 lane `GO`, supervisor semantic comparator `FIX`를 기록했다. single-review `REPEATABILITY_GAP`은
승격 근거에서 제외해 보존했다. 이 leaf도 source tree identity만 뜻하며 prototype mutation execution, scanner metric,
TP/FP/FN, H100, release를 승인하지 않는다. **P2.4B.2.08**은 Express primary import-settings와 reserve restore-session route,
`serializedSettings`/`serializedSession` JSON body field, fixed explicit field set, static negative object를 A에서 동결했다.
site-08 전용 materializer/comparator, focused 6/6, external source comparator `FIX`, isolated full r1/r2 각각 2,605 passed,
Claude/Grok/GLM F1/F2 lane `GO`, supervisor semantic comparator `FIX`를 기록했다. single-review
`REPEATABILITY_GAP`은 승격 근거에서 제외해 보존했다. 이 leaf도 source tree identity만 뜻하며 deserializer/code execution,
scanner metric, TP/FP/FN, H100, release를 승인하지 않는다. **P2.4B.2.09**는 TypeScript/Next.js client-secret
primary checkout/reserve integrations의 synthetic literal, server handoff, static negative label을 A에서 동결했다.
site-09 전용 materializer/comparator, focused 6/6, external source comparator `FIX`, isolated clean full r2/r3 각각
2,611 passed, Claude/Grok/GLM F1/F2 lane `GO`, supervisor semantic comparator `FIX`를 기록했다. initial full r1
`CONTROL_HOLD`, health r1 GLM `BLOCKED_PROVIDER`, single-review `REPEATABILITY_GAP`은 승격 근거에서 제외해 보존했다.
이 leaf도 source tree identity만 뜻하며 real secret validity, client bundle exposure, external request, scanner metric,
TP/FP/FN, H100, release를 승인하지 않는다. **P2.4B.2.10**은 JavaScript/Express CORS-origin primary checkout/reserve
integrations의 request `origin`, reflected handler, candidate별 allowlist, static `204` negative control을 A에서 동결했다.
site-10 전용 materializer/comparator, focused 6/6, external source comparator `FIX`, isolated clean full r1/r2 각각
2,617 passed, Claude/Grok/GLM F1과 health recovery 뒤 F3 retry lane `GO`, supervisor semantic comparator `FIX`를
기록했다. intermediate F2 GLM `BLOCKED_PROVIDER`와 single-review `REPEATABILITY_GAP`은 승격 근거에서 제외해 보존했다.
이 leaf도 source tree identity만 뜻하며 browser CORS behavior, cross-origin read, deployed allowlist correctness, scanner metric,
TP/FP/FN, H100, release를 승인하지 않는다. **P2.4B.2.11**은 Python/Django template-XSS primary checkout/reserve
integrations의 `message`/`notice` query parameter, `mark_safe` source condition, `escape` fixed boundary, static negative
paragraph를 A에서 동결했다. site-11 전용 materializer/comparator, focused 6/6, external source comparator `FIX`, isolated
clean full r1/r2 각각 2,623 passed, Claude/Grok/GLM F1/F2 lane `GO`, supervisor semantic comparator `FIX`를 기록했다.
single-review `REPEATABILITY_GAP`은 승격 근거에서 제외해 보존했다. 이 leaf도 source tree identity만 뜻하며 browser rendering,
script execution, deployed Django configuration, scanner metric, TP/FP/FN, H100, release를 승인하지 않는다. **P2.4B.2.12**는
Python/Flask file-read primary exports/reserve templates의 `file`/`name` parameter, raw `Path` read source condition,
resolved-path fixed boundary, static negative text를 A에서 동결했다. site-12 전용 materializer/comparator, focused 6/6,
external source comparator `FIX`, isolated clean full r1/r2 각각 2,629 passed, Claude/Grok/GLM F1/F2 lane `GO`, supervisor
semantic comparator `FIX`를 기록했다. single-review `REPEATABILITY_GAP`은 승격 근거에서 제외해 보존했다. 이 leaf도 source
tree identity만 뜻하며 filesystem read, traversal exploit, deployed Flask configuration, scanner metric, TP/FP/FN, H100,
release를 승인하지 않는다. **P2.4B.2.13**은 Java/Spring JDBC primary orders/reserve integrations source triplet,
focused 6/6, external r1/r2 comparator `FIX`, clean full r1/r2 각각 2,635 passed, Claude/Grok/GLM F1/F2 lane `GO`,
supervisor semantic comparator `FIX`를 기록했다. Windows path selector의 pre-receipt rejection은 성공 근거로 쓰지
않았다. 이 leaf는 source tree identity만 뜻하며 Java/Maven/Spring runtime, JDBC driver/database/query execution,
scanner metric, TP/FP/FN, H100, release를 승인하지 않는다. P8.1 목표 통제는 `FIX_NARROW`로
닫혔다. **P2.4B.2.15 Site-15**는 Go/chi SQL builder primary/reserve source triplet, focused 5/5,
external r1/r2 comparator `FIX`, full r1/r2 각각 2,655 passed, Claude/Grok/GLM F1/F2 lane `GO`,
supervisor semantic comparator `FIX`를 기록해 `FIX_NARROW`가 됐다. Windows backslash selector는 pre-receipt
단계에서 거부돼 성공 근거에 쓰지 않았다. 이 leaf도 source tree identity만 뜻하며 Go/chi/DB runtime, SQLi
execution, scanner metric, TP/FP/FN, H100, release를 승인하지 않는다. Data-03 `P2.4B.2.16`, Data-07
`P2.4B.2.17`, Data-09 `P2.4B.2.18`, Data-14 `P2.4B.2.19`도 A-G를 `FIX_NARROW`로 닫았으며, 다음 유일한
카드 `P2.4B.2.20`은 A-G를 닫아 `FIX_NARROW`가 됐다. 다음 유일한 카드는 auth-rls-db 첫 leaf
`P2.4B.3.01`과 `P2.4B.3.02`는 각각 A-G `FIX_NARROW`로 닫혔다. api-02는 current baseline,
focused 36 passed, full r1/r2/r3 각 2,701 passed/5 skipped, Claude/Grok/GLM F1/F2 all-lane `GO`,
supervisor comparator `FIX`를 기록했으며 source-tree identity만 주장한다. P8.1B도 human-status sync에 한해
`FIX_NARROW`다. api-03 Supabase missing-RLS도 A-G와 3AI comparator `FIX`로 source-tree identity만 닫혔다.
api-04 Firebase open-rule와 api-05 Next.js admin-boundary도 각각 A-G와 3AI comparator `FIX`로 source-tree identity만
닫혔다. api-06 Express mass-assignment, api-07 Supabase service-role key, api-08 Firebase storage read-rule, api-09 FastAPI dependency-auth, api-10 Django REST object-owner, api-11 Flask role-guard, api-12 Spring method-auth, P8.2B Windows native supervisor transport, P8.2D GLM health terminal contract, P8.2E product-card registry binding, P8.2A Windows supervisor command resolution도 각각 A-G와 3AI comparator `FIX`로 좁게 닫혔다. api-11의 packet 문구가 달랐던 r2 comparator `HOLD`, api-12 initial GLM `HOLD`, P8.2D invalid field ID와 Claude timeout, API13 및 P8.2A health/F1 `BLOCKED_PROVIDER`는 보존한다. 현재 유일한 카드는 P2.4B.3.13 API13 Ktor resource-owner의 F1이다.

## 진행률을 읽는 법

현재 `FIX_NARROW`는 Phase 0 운영 기준선 묶음과 Phase 1의 H5A, L2 3-scenario,
raw-free candidate receipt, WebGoat IDOR positive/negative execution-repeat 하위 계약과
P2.3B.1 rebind, P2.3B.2 Juice Shop execution, P2.3B.3 NodeGoat execution,
P2.3B.4 PyGoat execution, P2.3B.5 crAPI execution 계약뿐이다. 이는 **운영·측정 준비도**의 일부일 뿐이며, 최종 출하 기준의
수치 gate는 아직 0개 통과다. 따라서 이 장부는 제품 출시 완성도를 퍼센트 하나로
부풀리지 않는다.

| 관점 | 현재 값 |
| --- | --- |
| 운영·측정 좁은 하위 계약 | 33개 `FIX_NARROW` |
| 최종 release phase | 0 / 9 phase `GO_RELEASE` |
| 최종 수치 gate | 0 / 10 통과 |
| 최종 출하 상태 | `HOLD` |

매 작업이 끝날 때 이 문서의 작업 ID, evidence path/hash, 외부 review comparator,
남은 위험을 함께 갱신한다. `FIX_NARROW`가 아닌 항목은 완료 수에 넣지 않는다.
