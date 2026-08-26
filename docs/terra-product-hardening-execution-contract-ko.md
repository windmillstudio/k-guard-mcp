# K-Guard 제품 단련 실행 계약

문서 상태: `FINAL_CANDIDATE_FOR_SUPERVISOR_BINDING`

결정 마감: `2026-07-31 18:00 KST`

대표 목표: K-Guard를 한국 바이브코더가 출하 전에 호출하는 시니어 감사관과 fail-closed release gate로 검증한다. 마감일까지 합격선을 낮추지 않은 `GO` 또는 근거가 완결된 `HOLD`를 낸다.

이 문서는 Qwen이 제품 구현을 수행하고 SOL, Claude Opus 5, Grok 4.5가 감독하기 위한 단일 실행 계약이다. 기존 파일명은 증거 링크 안정성을 위해 유지한다. 이 계약 SHA에 대한 Opus 5와 Grok 4.5의 `GO` receipt가 모두 봉인되는 순간부터 이 파일을 수정하지 않는다. 진행 상태, 실행 로그, 외부 모델 검수 receipt는 저장소 밖 증거 디렉터리에만 추가한다.

## 1. 역할과 권한

| 역할 | 책임 | 금지 사항 |
| --- | --- | --- |
| Qwen 3-worker pool | SOL이 서명한 가설 하나를 겹치지 않는 세 작업으로 구현하는 유일한 제품 코드 작성자 | 같은 파일 동시 수정, 측정 하네스, holdout, gate 상수, oracle, 검수 receipt, 다른 가설 변경 |
| CODEX SOL | 범위, 분모, oracle, 합격선, 측정 실행, 증거 결속, 최종 판정 | 제품 후보 직접 구현, 결과를 본 뒤 기준·라벨·분모 변경 |
| Claude Opus 5 | 지정된 소스 파일 직접 읽기, 구현·경계·증거 독립 검수 | 제품 수정, 검수하지 않은 범위 승인, 다른 감독자 판정 열람 |
| Grok 4.5 | sanitized evidence packet의 actionability·출하 처분 독립 검수 | 제품 수정, 소스 직접 검수 주장, 기준 완화, 다른 감독자 판정 열람 |
| GLM 5.2 | 감독자 장애 시 원인 분리를 위한 비의결 보조 검수 | 제품 수정, SOL·Opus·Grok의 필수 의결권 대체 |

중앙 모델 pin은 다음과 같다.

| 역할 | provider / 실행기 | 정확한 모델 ID | 현재 상태 |
| --- | --- | --- | --- |
| 구현 | Codex profile `qwen` / `Model_Studio_Token_Plan_Personal` | `qwen3.8-max-preview` | 3-worker 동시 health `GO` |
| 직접 소스 감독 | Claude CLI | `claude-opus-5` | 직접 호출 확인 |
| packet 감독 | Grok CLI | `grok-4.5` | health 확인 |
| 비의결 보조 | Cline Pass | `cline-pass/glm-5.2` | health 확인 |

`qwen3.8-max-preview`는 Codex profile `qwen`, provider `Model_Studio_Token_Plan_Personal`, local model catalog에 고정돼 있다. 세 개의 독립 read-only health 호출이 동시에 종료 코드 0, runtime model ID 일치, 도구 호출·파일 변경 0으로 완료됐다. 증거는 `<LOCAL_USER_HOME>/Desktop/mcp/k-guard-live-evidence/product-hardening-20260731/planning/qwen-parallel-health-r1.json`이다.

현재 제품 Phase 자동 검수 코드는 `claude-opus-4-8`, `grok-4.5`, `cline-pass/glm-5.2`에 고정되어 있다. Claude CLI에서는 `claude-opus-5` 실제 호출이 확인됐지만 자동 제품 검수 경로는 아직 5로 전환되지 않았다. Phase 0에서 모델 pin, health receipt, receipt validator를 함께 갱신해 검증하기 전에는 제품 Phase의 Opus 5 검수라고 기록할 수 없다.

Phase 0 시작 전에 수행하는 실행 계약 검수는 이 자동 제품 검수 경로의 예외다. SOL이 직접 Claude CLI의 `claude-opus-5`와 Grok CLI의 `grok-4.5`를 서로 독립적으로 호출하고, 11절의 contract receipt schema와 validator를 통과한 receipt만 Phase 0 Entry 권한을 만든다. 이 예외는 실행 계약 검수에만 적용되며 제품 Phase 승인으로 확대할 수 없다.

Qwen 구현은 후보 하나당 사전등록된 정확히 세 작업을 동시에 여는 고정 3-worker pool로 수행한다. 세 worker는 같은 preregistration과 base commit에서 시작하지만 서로 다른 Git worktree·branch와 겹치지 않는 write path를 사용한다. 세 독립 작업이 준비되지 않으면 pool을 시작하지 않는다. 시작한 후보에는 작업을 추가하거나 완료 슬롯을 보충하지 않으며, 세 작업이 모두 종료된 뒤에만 통합한다. 자동 merge와 같은 파일 동시 수정은 금지한다.

병렬 감독은 통합 candidate와 같은 봉인 packet을 대상으로 동시에 시작한다. SOL, Opus, Grok은 서로의 초안·판정을 보지 않고 receipt를 먼저 봉인한다. 세 receipt가 모두 봉인된 뒤 SOL이 집계한다.

## 2. 현재 목표 상태

목표 ID: `k-guard-product-hardening-20260731`

상태 축은 섞지 않는다.

- `goal_status`: `ACTIVE`
- `phase_status`: `NOT_STARTED`
- `release_status`: `HOLD`
- `terminal_disposition`: `NONE`
- `executor_status`: `HEALTHY_LOCKED_UNTIL_PHASE_0_ENTRY`

완료 정의:

1. 모든 필수 Phase의 정량 게이트를 통과한다.
2. 각 Phase마다 SOL, Grok 4.5, Claude Opus 5의 유효한 독립 receipt가 모두 `GO`다.
3. 최종 H100, 설치, CLI, MCP, Guardian, 호환성 증거가 동일 후보와 결속된다.
4. 하나라도 미달 또는 미측정이면 최종 결과는 `HOLD`다.

마감은 판정 완료 시각이지 `GO` 보장 시각이 아니다.

## 3. 지금까지 작업한 내역

### 3.1 검증 틀

- OWASP BenchmarkJava 2,740건과 BenchmarkPython 1,230건의 고정 revision, Git tree, raw blob 바이트를 검증하는 물질화 경로를 만들었다.
- 공식 3,970건을 두 번 실행하고 TP/FP/FN/TN, Wilson 하한, 후보 분포, oracle 연결 상태를 기록하는 L1 runner를 만들었다.
- baseline receipt, target hash, source integrity receipt, raw-free evidence packet, 외부 모델 검수 runner의 기반을 만들었다.
- 공개 앱, 로컬 취약 앱, 생성 pair, API·인증·RLS·DB 시나리오를 위한 다수의 물질화·반복 비교 스크립트와 preregistration 초안이 있다.
- 작업 관리가 110개 세부 카드로 과도하게 분해돼 제품 성능 개선보다 절차 작업이 앞선 문제가 확인됐다.

### 3.2 제품 코드

- 현재 worktree에는 정적·흐름 분석, Java/JS/TS/Python, API·권한 관련 대규모 변경이 존재한다.
- 특히 `src/k_guard_mcp/detectors/polyglot.py`와 `src/k_guard_mcp/taint.py` 변경량이 크지만, 전체 제품 성능을 통과했다는 증거는 없다.
- Java servlet XSS observer와 encoder·상수 분기 억제 시도가 구현돼 있다.
- 이 변경들은 현재 제품 후보이지 출하 승인 코드가 아니다.

### 3.3 현재 worktree

- HEAD: `04e9dd8e7dc788d8242db138278758303ba6f27d`
- tracked modified: `16`
- untracked: `364`
- 합계: `380`

Phase 0에서 검증 틀, 제품 코드, 문서, 생성 증거를 분리하고 재현 가능한 후보를 만들기 전에는 어떤 성능 결과도 최종 출하 증거로 승격하지 않는다.

## 4. 현재 측정 기준선

기준선 증거:

- `<LOCAL_USER_HOME>/Desktop/mcp/k-guard-live-evidence/performance-baseline-current-r1/baseline-receipt-r2.json`
- `<LOCAL_USER_HOME>/Desktop/mcp/k-guard-live-evidence/performance-baseline-current-r1/l1-manifest.json`
- `<LOCAL_USER_HOME>/Desktop/mcp/k-guard-live-evidence/performance-baseline-current-r1/l1-current-run-r2/l1-baseline-report.json`

| 항목 | 현재 값 | 판정 |
| --- | ---: | --- |
| 공식 분모 | 3,970 | 보존 |
| 지원 분모 | 1,911 | 개발 기준선 |
| 미지원 분모 | 2,059 | 최종 정확도 주장 불가 |
| TP / FP / FN / TN | 423 / 0 / 541 / 947 | recall 미달 |
| recall | 43.8797% | 목표 90% 미달 |
| recall Wilson 95% 하한 | 40.7775% | 미달 |
| specificity | 100% | 지원·매핑 범위 한정 |
| High/Critical 후보 | 513 | 90건 oracle 미연결 |
| 최다 규칙 점유율 | 277/513 = 53.9961% | 목표 50% 초과 |
| 동일 결과 반복 | 100% | 통과 |
| 전체 상태 | `MEASURED_HOLD` | 출하 불가 |

지원 분모의 양성 시나리오는 `TP + FN = 964`다. recall 90%에는 최소 TP 868이 필요하므로 현재 FN 541건 중 최소 445건을 추가 탐지해야 한다.

현재 지원 FN 분포:

| 우선순위 | 계열 | 양성 | 음성 | 합계 | 현재 FN |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | Java XSS | 246 | 209 | 455 | 246 |
| 2 | Java path traversal | 133 | 135 | 268 | 133 |
| 3 | Java command injection | 126 | 125 | 251 | 126 |
| 4 | Java secure-cookie | 36 | 31 | 67 | 36 |

최다 규칙을 억제해 점유율을 낮추는 행위는 금지한다. 현재 최다 규칙 count 277이 유지된다면 비최다 실탐지 후보가 최소 41건 추가돼 총 후보가 554 이상이어야 50% 이하가 된다. 모든 변경 후 실제 분포를 다시 계산한다.

이 기준선은 dirty worktree에서 얻은 `development_only` 증거다. Phase 0의 clean baseline이 이를 대체하며, 고정 비율 기준은 바꾸지 않고 다음 공개식으로 파생 상수만 다시 계산한다.

```text
minimum_tp = ceil(0.90 * (tp + fn))
required_new_tp = max(0, minimum_tp - tp)
minimum_total_candidates = ceil(top_rule_count / 0.50)
```

현재 값은 `minimum_tp=868`, `required_new_tp=445`, `minimum_total_candidates=554`다.

H1~H3의 양성 scenario ID가 서로 배타적이고 현재 FN 집합과 정확히 일치한다는 manifest 검증을 전제로 구성 산술은 다음과 같다.

```text
H1 minimum new TP = ceil(0.90 * 246) = 222
H2 minimum new TP = ceil(0.90 * 133) = 120
H3 minimum new TP = ceil(0.90 * 126) = 114
composed TP        = 423 + 222 + 120 + 114 = 879
composed recall    = 879 / 964 = 91.1826%
```

따라서 H1~H3가 각각 90%를 통과하면 현재 분모에서는 전체 TP 868 기준을 산술상 넘는다. Phase 0 manifest가 ID 배타성 또는 현재 FN 일치를 증명하지 못하면 이 산술은 무효이며 `HOLD`다. secure-cookie는 전체 recall 산술에는 필수가 아니지만 Critical scenario가 한 건이라도 포함되면 Critical recall 100%를 위해 필수 Phase 3C로 승격한다. Phase 0에서 secure-cookie tuning과 교집합이 0인 별도 validation 양성 30개·음성 30개를 확보하지 못하면 그 이후에 분모를 만들지 않고 `goal_status=COMPLETED_HOLD`, `release_status=HOLD`, `terminal_disposition=RELEASE_HOLD_FINAL`로 닫는다.

## 5. 이미 수정한 사항과 검증 결과

### 5.1 외부 검수 field ID fail-fast

문제:

- 대문자가 포함된 잘못된 `field_id`가 외부 모델 세 개를 호출한 뒤 마지막 receipt 검증에서 실패했다.

수정:

- `src/k_guard_mcp/supervisor_reviews.py`에 `validate_field_id`를 추가했다.
- `scripts/execute_supervisor_review.py`가 provider 호출 전에 field ID를 검증한다.
- `tests/test_execute_supervisor_review.py`에 invalid ID가 provider 호출 전에 실패하고 출력 디렉터리도 만들지 않는 회귀 테스트를 추가했다.

검증:

- `tests/test_execute_supervisor_review.py`와 `tests/test_supervisor_reviews.py`: `33 passed`.
- 허용 형식: `[a-z0-9][a-z0-9._-]{0,127}`.

이 수정은 검수 비용 낭비를 막는 control-plane 수정이며 제품 탐지 성능 개선으로 계산하지 않는다.

### 5.2 Java XSS H4A 관찰 A/B

증거:

- `<LOCAL_USER_HOME>/Desktop/mcp/k-guard-live-evidence/performance-baseline-current-r1/hypotheses/H1-java-xss-servlet-observe-r2/java-xss-observe-ab-report.json`

| 변형 | TP / FP / FN / TN | recall | precision | specificity |
| --- | --- | ---: | ---: | ---: |
| control | 0 / 0 / 246 / 209 | 0% | 0% | 100% |
| H4A observer | 94 / 63 / 152 / 146 | 38.2114% | 59.8726% | 69.8565% |

판정:

- 두 번의 결과는 완전히 일치했다.
- recall은 올랐지만 precision과 specificity가 기준에 크게 미달한다.
- `observe` 결과로만 보존하며 `warn` 또는 `block` 승격은 금지한다.
- 기존 observer를 임계값으로 조정하지 않고 source/sink/encoder/safe-path 모델을 재설계해야 한다.

## 6. 외부 AI 검수 현황

| 항목 | 모델 | 결과 | 출하 권한 |
| --- | --- | --- | --- |
| health receipt | Claude Opus 4.8 | HEALTHY | 없음 |
| health receipt | Grok 4.5 | HEALTHY | 없음 |
| health receipt | GLM 5.2 | HEALTHY | 없음 |
| H4A 검수 r1 | 3개 provider 호출 후 invalid uppercase field ID | 실패 보존 | 없음 |
| H4A 검수 r2 | 사용자 지시에 따라 실행 중지 | receipt 없음 | 없음 |
| 계획 협의 | Claude Opus 5 | 실제 모델 호출 확인 | 계획 자문만, 제품 승인 아님 |
| 실행 계약 r1 | Claude Opus 5 | `HOLD`, blocker 14건·권고 8건 | 문서 검수만, 제품 승인 아님 |
| Qwen 병렬 health r1 | `qwen3.8-max-preview` 3-worker | 3/3 `HEALTHY`, runtime ID 일치 | Phase 0 entry 전 구현 권한 없음 |

health evidence:

- `<LOCAL_USER_HOME>/Desktop/mcp/k-guard-live-evidence/performance-baseline-current-r1/reviews/health-20260725-r1`

현재 완료된 제품 Phase 외부 검수는 `0개`다. health, 계획 자문, 실행 계약 검수를 제품 승인으로 확대 해석하지 않는다.

## 7. 고정 최종 합격선

모든 metric은 `denominator_id`, manifest SHA-256, scenario ID 목록, severity, 출력 mode, 최소 표본을 preregistration에 결속한다. 전역 specificity와 계열별 recall·precision·specificity를 분리해 보고한다.

| metric | 적용 mode·분모 | 최소 표본 | 합격선 |
| --- | --- | ---: | --- |
| block precision | H100의 `counted_block=true` finding 전건 | counted finding 70건 | 90% 이상, Wilson 95% 하한 80% 이상 |
| scenario 완전 적중률 | H100 pair slot 100개 | 100개 | 90% 이상, Wilson 95% 하한 80% 이상 |
| High/Critical recall | H100의 H/C 양성 case 전건 | H/C 양성 70건 | 90% 이상 |
| Critical recall | H100의 Critical 양성 case 전건 | Critical 양성 20건 | 100% |
| global specificity | 고정·수정 side 음성 case 전건 | 음성 100건 | 90% 이상 |
| family recall | 해당 개발 계열 양성 전건 | 30건 | 90% 이상 |
| family precision | 해당 개발 계열 candidate 전건 | 30건 | 90% 이상 |
| family specificity | 해당 개발 계열 음성 전건 | 30건 | 90% 이상 |
| finding 만장일치 | H100 H/C `counted_block=true` finding 전건 | 70건 | 90% 이상, `inconclusive=0` |

표본이 최소치보다 작으면 비율이 높아도 `HOLD`다. 모든 Critical finding은 별도로 100% 만장일치해야 한다.

출력 mode 계약:

- `observe`: 개발 evidence에만 기록한다. 사용자 경고·차단을 만들지 않으며 release recall, block precision, 앱 완전 적중률에 포함하지 않는다.
- `warn`: 사용자에게 보이지만 출하를 차단하지 않는다. warning actionability만 별도 보고하며 release recall 또는 block precision에 포함하지 않는다.
- `block`: 최종 `GO` release manifest에 결속된 Guardian의 운영 fail-closed 출하 처분이다. 공개된 최종 release metric에는 이 mode를 계산한다.
- `block_candidate`: 아직 배포할 수 없는 후보 상태다. 봉인된 개발·Phase 4·H100·Phase 6 평가 환경에서는 `block`과 동일하게 Guardian을 차단하고 같은 block metric 산식에 포함하지만, release manifest가 `GO`가 아니면 패키지 배포와 운영 활성화를 거부한다. Phase 5·6을 통과해 `release block`으로 승격할 때 wheel·rule·mode byte를 바꾸지 않는다. 따라서 평가 중 counted mode는 `block_candidate`, 최종 공개 release의 counted mode는 `block`이다.

metric script의 단일 normative alias는 `counted_block`이다. pre-release sealed evaluation에서는 원본 mode가 `block_candidate`인 finding만 `counted_block=true`이고, 최종 GO release에서는 원본 mode가 `block`인 finding만 true다. `observe`와 `warn`은 어떤 단계에서도 이 alias로 계산하지 않는다.

승격 계약:

1. `observe → warn`: 고정 개발 분모에서 family recall, precision, specificity가 각각 90% 이상이고 최소 표본, 두 번의 완전 일치, 전체 회귀 0을 충족해야 한다.
2. `warn → block_candidate`: 별도 고정 개발 검증 분모에서 같은 수치와 High/Critical oracle 1:1 연결, 빠른 점검 계약, 감독자 3자 `GO`를 충족해야 한다.
3. `block_candidate → release block`: Phase 5 H100에서 최종 block metric을 통과해야 한다. H100 결과를 본 뒤 승격 규칙이나 코드를 바꿀 수 없다.

공통 최종 조건:

- 동일 입력 두 번의 canonical 결과 재현율 100%.
- 단일 규칙 후보 점유율 50% 이하.
- 각 Phase의 `candidate-distribution.json`에 top rule 전체 후보 수와 oracle-confirmed true-positive 수를 함께 기록한다. 점유율을 낮추기 위해 oracle-confirmed true-positive 후보를 숨기거나 mode를 낮출 수 없으며, 직전 FIX 대비 그 수가 감소하면 `HOLD`다.
- Guardian은 선언된 지원 범위를 생략하지 않는다.
- 기존 CLI, MCP, 클라이언트 호환성 회귀 0.

`check_my_app` 5초 계약은 Phase 0에서 다음 roster로 봉인한다.

| ID | 고정 대상 | 크기 층 |
| --- | --- | --- |
| `lat-small-kguard-fixture` | K-Guard quick-check fixture의 tree SHA | 지원 파일 100개 이하, 1 MiB 이하 |
| `lat-medium-nodegoat-pin` | NodeGoat 고정 revision의 tree SHA | 지원 파일 101~1,000개 또는 1~10 MiB |
| `lat-large-webgoat-pin` | WebGoat 고정 revision의 tree SHA | 지원 파일 1,001~10,000개 또는 10~100 MiB |

Phase 0 receipt는 각 대상의 정확한 revision, tree SHA, 지원 파일 수·byte 수와 측정 장비의 CPU, RAM, OS build, Python, wheel SHA를 기록한다. 대상이 층 조건에 맞지 않으면 roster를 구현 전에 다시 봉인하고 이전 roster는 폐기 receipt로 남긴다.

각 대상은 새 프로세스의 cold run 5회와 같은 설치·설정에서의 warm run 5회를 측정한다. 30회 모두 wall-clock 5.000초 이하여야 한다. timeout, silent fallback, 범위 생략은 실패다. quick contract의 파일·byte 한도를 넘으면 5초 안에 `scope_incomplete=true`, `passed=false`, 누락 수를 반환해야 하며 정상 통과로 계산하지 않는다.

기준 미달, 최소 표본 미달, 증거 누락, 미측정은 모두 `HOLD`다.

## 8. 공통 Phase 게이트

상태 enum은 축별로 분리한다.

- `goal_status`: `ACTIVE`, `BLOCKED_EXTERNAL`, `COMPLETED_GO`, `COMPLETED_HOLD`.
- `phase_status`: `NOT_STARTED`, `ACTIVE`, `MEASURED_HOLD`, `PENDING_REVIEW`, `FIX`.
- `release_status`: `HOLD`, `GO`.
- `review_status`: `NOT_STARTED`, `RUNNING`, `GO`, `HOLD`, `BLOCKED`.
- `terminal_disposition`: `NONE`, `RELEASE_HOLD_FINAL`.
- `executor_status`: `HEALTHY_LOCKED_UNTIL_PHASE_0_ENTRY`, `READY`, `RUNNING`, `BLOCKED`, `COMPLETE`.

`goal_status=BLOCKED_EXTERNAL`은 외부 provider·corpus·권한 장애가 발생했지만 해당 6시간 retry window 또는 마감이 끝나지 않은 일시 상태다. 이 상태에서는 다음 Phase와 제품 수정 권한을 열지 않는다. 장애가 복구되면 직전 상태로 돌아가고, retry window 또는 최종 마감이 끝나면 `goal_status=COMPLETED_HOLD`, `release_status=HOLD`, `terminal_disposition=RELEASE_HOLD_FINAL`로 닫는다.

고정 계약 파일:

`<LOCAL_USER_HOME>/Desktop/mcp/local-user-workspace/outputs/k-guard-mcp/docs/terra-product-hardening-execution-contract-ko.md`

이 정확한 path는 Phase 0~6의 모든 allowed/forbidden manifest에서 immutable forbidden write path로 우선 적용한다. 더 넓은 allowed path가 이 파일을 포함해도 이 금지가 이긴다. Qwen과 제품 수정 도구는 읽기·쓰기 대상에서 제외하며 `development-exclusion-manifest.json`에 path, frozen SHA-256, byte count, `reason=immutable_execution_contract`로 기록한다.

모든 Phase는 구현 또는 측정 전에 `entry-receipt.json`을 봉인한다. 필수 진입 조건:

1. 이전 Phase가 `FIX`이고 `may_start_next_phase=true`다. Phase 0은 동일한 계약 SHA-256에 결속되고 contract receipt validator를 통과한 Opus 5와 Grok 4.5의 최종 실행 계약 receipt가 모두 `GO`인 것으로 이를 대신한다. 어느 하나라도 `HOLD`, `BLOCKED`, validator 실패면 Phase 0을 시작할 수 없다.
2. 현재 preregistration SHA-256이 구현 전에 봉인됐다.
3. `denominator_id`, manifest SHA-256, exact scenario IDs, 양성·음성·severity 수, output mode, 최소 표본이 존재한다.
4. 허용 파일과 금지 파일의 정확한 path 목록 및 사전 tree/blob SHA가 서명됐다.
5. 예측 metric, 최대 FP/FN, kill 조건, rollback target commit이 서명됐다.
6. 변경 전 control run 두 번이 완전 일치했고 artifact SHA가 봉인됐다.
7. Qwen 병렬 health receipt가 provider `Model_Studio_Token_Plan_Personal`, model `qwen3.8-max-preview`, worker 3/3 종료 코드 0, runtime ID 일치, 0보다 큰 token usage로 `GO`다. 제품 파일을 쓰지 않는 Phase 0 계약 검수에는 적용하지 않는다.
8. 고정 freeze-check wrapper를 새 append-only output path로 호출해 계약 파일 바이트에서 SHA-256과 byte count를 새로 계산한다. freeze output의 `contract_file_sha256`과 `contract_byte_count`는 agreement 내부의 `contract_sha256`과 `contract_byte_count`에 각각 같아야 한다. freeze output의 `checker_sha256`은 11절 pin과 같아야 하고, `phase_id`와 `event=entry`가 현재 호출과 같아야 한다. `entry-receipt.json`은 freeze output 파일 자체의 SHA-256을 `contract_freeze_check_sha256`에 기록한다. 이 값은 agreement 내부 필드와 비교하지 않는다. 문자열 복사, checker 미실행, output 재사용, 수동 receipt, 불일치, 누락이면 해당 Phase를 시작하지 않는다.

모든 Phase의 exit 조건:

1. 지정된 A/B 또는 전수 측정 두 번을 완료했다.
2. 정량 gate, 회귀, 속도, 반복성을 전부 통과했다.
3. SOL, Opus 5, Grok 4.5 receipt가 각각 `GO`다.
4. artifact manifest와 phase decision이 결속됐다.

`sealed_packet_sha256`은 preregistration, target, source packet, 측정 artifact manifest, reviewer prompt, contract SHA를 정렬된 canonical JSON으로 묶은 hash다. 감독자는 같은 `sealed_packet_sha256`을 인증·timeout·provider 장애로 `BLOCKED`된 경우에만 최대 세 번까지 호출할 수 있다. provider별 최초 호출부터 6시간 안에 세 번 모두 `BLOCKED`이거나, 6시간이 끝날 때 terminal receipt가 없으면 호출 횟수와 무관하게 Phase를 `MEASURED_HOLD`로 닫는다. 한 번이라도 `GO` 또는 `HOLD` receipt가 기록되면 그 supervisor의 해당 packet 판정은 terminal이며 재호출하지 않는다. 최초 receipt와 superseded `BLOCKED` receipt 전부를 `evidence-manifest.json`에 남긴다. 모델 교체나 검수 생략은 허용하지 않는다.

한 감독자가 `HOLD`면 수치가 통과해도 `FIX`가 아니다. 한 감독자가 응답하지 않으면 `PENDING_REVIEW`이며 Qwen은 다음 가설을 시작하지 않는다.

수치 통과 뒤 감독자 `HOLD`는 다음과 같이 한 번만 처리한다.

- `HOLD`를 낸 supervisor가 receipt에 `blocker_class=code_change|evidence_only`를 직접 기록한다. 누락되거나 두 분류가 섞이면 `code_change`로 처리한다.
- 제품 코드나 동작 변경이 필요한 `code_change` blocker는 candidate attempt를 소비한다. 남은 attempt가 있으면 새 preregistration 뒤 Qwen이 수정하고, 없으면 `goal_status=COMPLETED_HOLD`, `release_status=HOLD`, `terminal_disposition=RELEASE_HOLD_FINAL`로 닫는다.
- 코드·측정 결과·기준을 바꾸지 않는 receipt 포맷 또는 누락 증거 `evidence_only` blocker만 한 번 재포장할 수 있다. 재포장은 정확히 한 개의 새 `sealed_packet_sha256`을 만들고 기존 SOL·Opus·Grok `GO` receipt를 전부 무효화한다. 세 감독자가 새 packet을 서로 독립적으로 모두 다시 검수하며 기존 GO는 승계하지 않는다. 최초 `HOLD`부터 6시간 안에 끝내며 재포장 후에도 하나라도 `HOLD`면 `MEASURED_HOLD`로 닫는다.
- reviewer prompt, 모델, source packet, 측정 artifact, 분모, oracle, 기준을 바꾼 재검수는 재포장이 아니라 새 candidate attempt다.

## 9. Qwen WIP=1 실행·실패 계약

WIP=1은 동시에 하나의 제품 가설만 연다는 뜻이다. 그 가설의 구현은 다음 고정 3-worker pool로 나눈다.

1. SOL이 `phase_id`, 가설, 분모, mode, 예측 수치, kill 조건, rollback target을 서명한다.
2. SOL이 가설을 정확히 세 개의 독립 job으로 분해하고 job별 허용·금지 path와 통합 순서를 봉인한다. 허용 write path는 서로 겹칠 수 없다.
3. launcher가 clean base commit, 호출 시점의 Qwen 3/3 health, enabled job 정확히 3개, 경로 비중복을 확인한 경우에만 세 worktree를 동시에 연다.
4. 각 Qwen worker는 자기 worktree·branch의 허용 파일만 수정하고 구조화 결과와 candidate commit을 제출한다. worker가 먼저 끝나도 슬롯을 보충하지 않으며 세 worker가 모두 끝날 때까지 닫힌 상태로 둔다.
5. SOL은 세 branch의 경계와 결과를 검증한다. 정확히 세 개의 사전등록 job에서 각각 비어 있지 않은 worker commit 하나가 있어야 하며, 누락·빈 commit·경계 위반·실패가 하나라도 있으면 candidate 전체를 무효화하고 attempt를 소비하며 rollback receipt를 남긴다. 세 commit이 모두 유효할 때만 preregistration 순서대로 integration worktree에 적용해 하나의 candidate commit으로 봉인한다. SOL은 통합 중 제품 파일 내용을 편집하거나 충돌을 해결할 수 없고, 충돌이 나면 candidate를 무효화하고 attempt를 소비한다.
6. worker-local 테스트는 구현자 피드백일 뿐 권위 있는 증거가 아니다. SOL이 통합 candidate에서 focused regression, 전체 regression, latency와 tuning 분모의 control/candidate A/B를 각각 두 번 다시 실행한다. tuning gate를 통과한 같은 candidate commit을 별도 promotion validation denominator에서도 두 번 실행해 완전 일치하는 `promotion-validation-report.json`을 만든다. 두 validation run과 report까지 있어야 `warn → block_candidate` gate 증거가 완성된다.
7. Phase 1~3과 조건부 Phase 3C의 첫 candidate가 수치 미달이면 원인과 두 번째 preregistration을 먼저 봉인한 뒤 Qwen pool에 한 번만 수정 기회를 준다.
8. 두 번째 candidate도 미달이면 required Phase는 `goal_status=COMPLETED_HOLD`, `release_status=HOLD`, `terminal_disposition=RELEASE_HOLD_FINAL`로 닫고 H100 실행 권한을 영구 제거한다.
9. 수치 통과 후 SOL, Opus, Grok 검수를 병렬 호출한다.
10. 세 감독자가 모두 `GO`면 Phase를 `FIX`로 닫고 다음 Phase를 연다.

안전하게 분리 가능한 승인 job이 세 개 미만이면 임의 작업을 만들어 슬롯을 채우지 않고 Phase를 시작하지 않는다.

재시도 범위:

- Phase 1~3과 조건부 Phase 3C 개발 가설만 최대 두 candidate attempt를 허용한다.
- Phase 4 통합 측정은 제품 파일을 수정하지 않는 단일 attempt다. 수치·oracle·분포·반복성·회귀 중 하나라도 실패하면 이전 Phase를 다시 열지 않고 `goal_status=COMPLETED_HOLD`, `release_status=HOLD`, `terminal_disposition=RELEASE_HOLD_FINAL`로 닫는다.
- Phase 5 H100과 Phase 6 출하 검증은 candidate 수정·재시도를 허용하지 않는다.
- H100은 결과를 열람하기 전에 두 deterministic run을 한 번의 verdict event로 실행·봉인한다.
- H100 결과를 열람한 뒤 코드, 규칙, 기준, 라벨, 분모를 변경하면 candidate는 무효이며 `goal_status=COMPLETED_HOLD`, `release_status=HOLD`, `terminal_disposition=RELEASE_HOLD_FINAL`이다.

rollback 계약:

1. 실패 candidate는 `git reset`, `checkout --`, 파일 덮어쓰기가 아니라 비파괴 `git revert <candidate_commit>`으로 되돌린다.
2. analyzer target이 직전 `FIX` commit과 동일한지 tree SHA로 확인한다.
3. 직전 `FIX`의 focused·full regression과 핵심 metric을 다시 측정한다.
4. `rollback-receipt.json`에 실패 commit, revert commit, 이전·복원 tree SHA, 검사 결과, log SHA, 충돌 시 integration worktree와 임시 branch 정리 결과를 기록한다.
5. 이후 통합 회귀에서 문제가 발견되면 가장 최근 candidate만 먼저 revert하고 이전 `FIX`를 재측정한다.

필수 Phase가 두 attempt 안에 `FIX`되지 않거나 Phase 4 단일 측정 또는 Phase 5·6이 실패하면 `goal_status=COMPLETED_HOLD`, `release_status=HOLD`, `terminal_disposition=RELEASE_HOLD_FINAL`로 고정한다. 이후 허용 작업은 증거 완결, 실패 분석, 다음 릴리스 계획뿐이다. 기준을 낮추거나 H100을 다시 실행할 수 없다.

Qwen은 holdout 경로·credential·oracle·결과, gate 상수, 측정 runner, reviewer prompt·receipt를 읽거나 수정할 수 없다.

## 10. Phase별 실행 계획

### Phase 0. 검증 틀 및 후보 봉인

목표:

- dirty worktree를 검증 틀, 제품 코드, 문서, 생성 증거로 분리하고 재현 가능한 시작점을 만든다.

Entry gate:

- 이 실행 계약의 SHA-256과 동일한 해시에 결속된 Claude Opus 5 및 Grok 4.5 독립 검수 receipt가 모두 `GO`이고 11절 contract receipt validator를 통과했다. 어느 하나라도 `HOLD`, `BLOCKED`, validator 실패면 Entry gate는 실패다.
- 현재 dirty baseline의 두 control run과 repeat receipt가 존재한다.
- Phase 0 allowed/forbidden path manifest와 clean snapshot 생성 절차가 구현 전에 봉인됐다.
- 네 family의 promotion validation source registry가 exact scenario ID, 양성·음성 수, lineage, blob/tree SHA와 함께 봉인됐고 family별 최소 30/30 가용성이 확인됐다.
- 최초 계획일 대비 실제 지연 시간과 남은 Phase 시간을 `schedule-drift-receipt.json`에 기록했으며 `2026-07-31 18:00 KST` terminal HOLD를 유지하고 후속 Phase 시간을 압축하지 않는다.
- Qwen 구현이 필요한 변경 전에 `qwen3.8-max-preview` 3-worker health receipt가 `GO`다.

허용 범위:

- 모델 pin·health·receipt validator와 그 focused test.
- entry-receipt·phase-decision assembler와 validator, focused fail-closed test.
- clean snapshot, denominator, target, evidence manifest 도구와 문서. 고정 계약 파일 자체는 제외한다.
- preregistration에 정확히 열거된 control-plane 파일.

금지 범위:

- 제품 detector·taint·rule 구현.
- 고정 계약 파일과 contract validator·freeze checker pin 수정.
- H100 oracle·target·scanner output.
- 고정 비율 기준과 기존 공개 oracle 라벨.

필수 작업:

- Opus 5 자동 검수 pin과 health/receipt validator를 함께 갱신하고 focused test와 전체 회귀를 통과시킨다.
- 제품 분석기 target과 control/evidence target을 분리하되 최종 bundle은 둘을 모두 결속한다.
- 현재 공개 OWASP와 41개 앱을 `development_only`로 표시한다.
- clean checkout에서 regression pass/fail/skip count와 전체 log SHA를 봉인한다.
- 개발 분모별 exact scenario ID, blob/tree SHA, 양성·음성·severity 수를 denominator registry에 봉인한다.
- Qwen 구현 작업을 열기 전 Phase 0 Entry preregistration에 public oracle·기계 검증 pair source registry를 봉인한다. XSS, path traversal, command injection, secure-cookie별 양성 30개 이상과 음성 30개 이상, source lineage, exact scenario ID, blob/tree SHA가 있어야 한다. Phase 0에서 실제 pool을 물질화해 registry와 대조하며 부족하면 `goal_status=COMPLETED_HOLD`, `release_status=HOLD`, `terminal_disposition=RELEASE_HOLD_FINAL`로 닫는다. secure-cookie pool은 Critical 유무와 관계없이 미리 확보한다.
- Phase 1~3과 조건부 Phase 3C tuning scenario와 교집합이 0인 별도 family별 promotion validation denominator를 source pool에서 선택해 exact scenario ID, manifest SHA, 양성·음성·severity 수와 함께 봉인한다. tuning/validation 교집합이 하나라도 있으면 `HOLD`다.
- latency roster 세 대상의 exact revision, tree SHA, 지원 파일 수·byte 수와 장비 상태를 봉인한다.
- 신규 H100은 scanner 출력 전에 SOL이 oracle과 manifest hash를 별도 credential 경계에 봉인한다.
- `development-exclusion-manifest.json`에는 Qwen 접근 여부와 관계없이 모든 tuning denominator, promotion validation denominator, Qwen이 본 공개·생성 corpus, 문서를 category, exact scenario ID, blob/tree SHA, source lineage로 기록한다. 각 category manifest SHA와 전체 combined-set SHA를 함께 봉인한다.
- 두 contract `GO` receipt가 봉인된 시점부터 이 문서 수정 금지를 다시 확인하고 현재 SHA를 모든 후속 receipt에 결속한다.

Exit gate:

- clean checkout에서 기준선 두 번 완전 일치.
- dirty 개발 기준선을 clean 기준선으로 대체하고 공개식으로 모든 파생 상수를 다시 계산.
- 모델 pin: `qwen3.8-max-preview`, `claude-opus-5`, `grok-4.5`.
- Qwen, Opus, Grok health receipt 유효하고 0보다 큰 token usage.
- clean regression pass/fail/skip count와 log SHA 존재, 실패 0.
- 고정 합격선, 분모, oracle, analyzer/control target 해시 존재.
- H1~H3 scenario ID 배타성과 현재 FN 일치 증명.
- H1~H3 및 secure-cookie tuning denominator와 각 promotion validation denominator의 scenario ID 교집합 0.
- combined development exclusion set에 tuning·promotion validation·Qwen-seen category가 모두 있고 category manifest SHA와 combined-set SHA가 결속됐다.
- entry-receipt·phase-decision assembler가 freeze output 파일 SHA를 실제 바이트에서 재계산하고 `may_start_next_phase == (phase_status=FIX and SOL/Opus/Grok GO)`를 강제하는 focused test를 통과했다.
- latency roster와 측정 장비 receipt 존재.
- holdout scanner output 0건.
- SOL, Opus, Grok Phase 0 검수 `GO`.

### Phase 1. H1 Java XSS 재설계

가설:

- 요청 입력에서 HTML sink까지 1~2홉 흐름, 검증된 encoder/sanitizer, 상수·안전 분기를 함께 모델링하면 기존 H4A의 FP63과 FN152를 동시에 줄일 수 있다.

Entry gate:

- Phase 0 `FIX`, `may_start_next_phase=true`.
- Phase 0 clean denominator registry에서 재계산한 Java XSS tuning denominator `246 positive / 209 negative`, exact 455 scenario IDs와 manifest SHA가 봉인됐다. dirty-baseline FN 집합과 다르면 조정하지 않고 `HOLD`다.
- 별도 XSS promotion validation denominator의 exact scenario ID와 tuning 교집합 0 proof가 봉인됐다.
- control 두 번 완전 일치.
- allowed/forbidden path, 예측 `TP>=222`, `FP<=20`, kill 조건과 rollback target 봉인.

허용 범위:

- Java XSS detector, 그 detector의 focused test, H1 preregistration에서 지정한 최소 공통 분석 helper.

금지 범위:

- XSS 이외 detector, benchmark runner, oracle, H100, gate·reviewer 코드.

Exit gate:

- Java XSS recall 90% 이상.
- precision 90% 이상.
- specificity 90% 이상.
- FP 전건과 잔여 FN 전건의 subtype 분류.
- 빠른 점검 5초 이하.
- 반복성 100%, 기존 회귀 0.
- tuning 분모에서 `observe → warn`, 별도 promotion validation 분모에서 `warn → block_candidate` gate를 순서대로 통과하고 Exit output mode가 `block_candidate`다.
- SOL, Opus, Grok `GO`.

### Phase 2. H2 Java path traversal

가설:

- H1의 공통 흐름 분석을 재사용하고 path sink, canonicalization, base-directory containment를 모델링하면 별도 엔진 없이 FN133을 줄일 수 있다.

Entry gate:

- Phase 1 `FIX`, `may_start_next_phase=true`.
- Phase 0 clean denominator registry에서 재계산한 Java path traversal tuning denominator `133 positive / 135 negative`, exact 268 scenario IDs와 manifest SHA가 봉인됐다. dirty-baseline FN 집합과 다르면 조정하지 않고 `HOLD`다.
- 별도 path traversal promotion validation denominator의 exact scenario ID와 tuning 교집합 0 proof가 봉인됐다.
- 현재 H1 candidate를 포함한 control 두 번 완전 일치.
- allowed path, forbidden path, 예측 `TP>=120`, `FP<=13`, kill 조건과 rollback target 봉인.

허용 범위:

- preregistration에 지정된 path sink·canonicalization 로직, 기존 공통 helper의 최소 확장, focused test.

금지 범위:

- XSS 의미 변경, 별도 path 전용 흐름 엔진, runner, oracle, H100, gate·reviewer 코드.

Exit gate:

- 계열 recall, precision, specificity 각각 90% 이상.
- H1 수치 하락 없음.
- 별도 path 전용 흐름 엔진 신설 없음.
- 빠른 점검 5초 이하, 반복성 100%, 전체 회귀 0.
- tuning 분모에서 `observe → warn`, 별도 promotion validation 분모에서 `warn → block_candidate` gate를 순서대로 통과하고 Exit output mode가 `block_candidate`다.
- SOL, Opus, Grok `GO`.

### Phase 3. H3 Java command injection

가설:

- 동일 흐름 분석에 실행 sink, 문자열 조립, 고정 명령·안전 인자 구분을 추가하면 FN126을 FP 예산 안에서 줄일 수 있다.

Entry gate:

- Phase 2 `FIX`, `may_start_next_phase=true`.
- Phase 0 clean denominator registry에서 재계산한 Java command injection tuning denominator `126 positive / 125 negative`, exact 251 scenario IDs와 manifest SHA가 봉인됐다. dirty-baseline FN 집합과 다르면 조정하지 않고 `HOLD`다.
- 별도 command injection promotion validation denominator의 exact scenario ID와 tuning 교집합 0 proof가 봉인됐다.
- 현재 H1·H2 candidate를 포함한 control 두 번 완전 일치.
- allowed path, forbidden path, 예측 `TP>=114`, `FP<=12`, kill 조건과 rollback target 봉인.

허용 범위:

- preregistration에 지정된 command sink·문자열 조립·안전 인자 로직, 공통 helper의 최소 확장, focused test.

금지 범위:

- H1·H2 의미 변경, 별도 command 전용 흐름 엔진, runner, oracle, H100, gate·reviewer 코드.

Exit gate:

- 계열 recall, precision, specificity 각각 90% 이상.
- H1·H2 수치 하락 없음.
- 통합 specificity 90% 이상.
- 빠른 점검 5초 이하, 반복성 100%, 전체 회귀 0.
- tuning 분모에서 `observe → warn`, 별도 promotion validation 분모에서 `warn → block_candidate` gate를 순서대로 통과하고 Exit output mode가 `block_candidate`다.
- SOL, Opus, Grok `GO`.

### Phase 3C. 조건부 Java secure-cookie

Phase 0 severity manifest에 secure-cookie Critical이 없으면 `phase3c_required=false`와 oracle proof를 봉인하고 이 Phase를 실행하지 않는다. Critical이 한 건이라도 있으면 다음 계약이 필수다.

Entry gate:

- Phase 3 `FIX`, `may_start_next_phase=true`.
- Phase 0 clean denominator registry에서 재계산한 secure-cookie tuning denominator `36 positive / 31 negative`, exact 67 scenario IDs와 manifest SHA가 봉인됐다.
- 별도 secure-cookie promotion validation denominator의 양성 30개 이상·음성 30개 이상, exact scenario ID, source lineage, tuning 교집합 0 proof가 Phase 0에서 봉인됐다.
- control 두 번 완전 일치, allowed/forbidden path, 최대 FP/FN, kill 조건, rollback target 봉인.

허용 범위:

- secure-cookie detector, cookie attribute 해석, 그 detector의 focused test.

금지 범위:

- H1~H3 의미 변경, runner, oracle, H100, gate·reviewer 코드, Phase 0 뒤 validation denominator 생성·교체.

Exit gate:

- secure-cookie family recall, precision, specificity 각각 90% 이상.
- Critical recall 100%.
- tuning 분모에서 `observe → warn`, 별도 promotion validation 분모에서 `warn → block_candidate` gate를 순서대로 통과하고 Exit output mode가 `block_candidate`다.
- H1~H3 수치 하락 없음, 빠른 점검 5초 이하, 반복성 100%, 전체 회귀 0.
- SOL, Opus, Grok `GO`.

### Phase 4. 통합 정적·oracle 게이트

Entry gate:

- Phase 3 `FIX`, `may_start_next_phase=true`.
- clean 지원 분모 exact 1,911 scenario ID와 analyzer target SHA 봉인.
- 전체 control 두 번 완전 일치.
- 측정·oracle mapping allowed path와 모든 제품 파일 forbidden path 봉인.
- Phase 0 severity manifest에 secure-cookie Critical이 있으면 별도 `Phase 3C`가 `FIX`여야 한다.
- Phase 4는 제품 수정이 금지된 단일 측정 attempt이며 실패 시 `goal_status=COMPLETED_HOLD`, `release_status=HOLD`, `terminal_disposition=RELEASE_HOLD_FINAL`이다.

허용 범위:

- 전수 측정 실행, oracle 연결, metric·분포·증거 생성.

금지 범위:

- 제품 코드, rule mode, oracle 라벨, gate·reviewer 기준 수정.

필수 작업:

- 지원 분모 1,911건을 고정 후보로 두 번 전수 실행한다.
- 봉인된 analyzer target에서 발생한 High/Critical 후보 전건과 새 후보를 1:1 oracle에 연결한다. 예상 후보 수는 참고값일 뿐 gate 분모를 제한하지 않는다.
- 단일 규칙 후보 점유율과 후보 다양성을 다시 계산한다.
- secure-cookie Critical이 있으면 Phase 3C `FIX` receipt와 봉인된 `block_candidate` mode를 검증하고, 없으면 Phase 0의 `phase3c_required=false` oracle proof를 검증한다. Phase 4에서 이 결정을 바꾸거나 분모를 만들 수 없다.
- H1~H3의 실제 TP를 baseline TP와 합성해 전체 `TP>=868`을 직접 확인한다.

Exit gate:

- 지원 분모 recall 90% 이상, 최소 TP 868.
- Critical recall 100%.
- specificity 90% 이상.
- unpaired High/Critical 후보 0.
- 단일 규칙 후보 점유율 50% 이하.
- `counted_block=true`가 원본 `block_candidate` 이외 mode에 부여된 수 0.
- 반복성 100%, 전체 회귀 0.
- SOL, Opus, Grok `GO`.

### Phase 5. 미접촉 H100

기존 OWASP와 이미 본 공개 앱은 holdout으로 사용하지 않는다.

Entry gate:

- Phase 4 `FIX`, `may_start_next_phase=true`.
- release candidate commit·wheel·analyzer target SHA 봉인.
- SOL이 H100 custody receipt, encrypted manifest SHA, untouched proof, 실행 명령 SHA를 봉인.
- Phase 0 combined development exclusion set의 manifest SHA와 scenario-ID·blob/tree·lineage zero-intersection proof command SHA를 봉인.
- Qwen 세션 종료와 holdout credential 미제공을 access log로 확인.
- H100 결과 공개 전에 두 deterministic run을 연속 실행하는 단일 verdict script SHA 봉인.

H100 구성:

- 총 100개의 1:1 oracle pair slot이다. 각 slot은 취약 side 1개와 수정·정상 side 1개로 구성한다.
- 각 취약 side는 정확히 하나의 canonical expected block finding과 1:1 대응한다. 중복 detector 신호는 scenario 단위로 canonicalize하며 별도 TP로 늘리지 않는다.
- 생성 pair 80개와 공개 upstream 수정 revision 기반 pair 20개다.
- 사이트·정적 코드 25 pair.
- API·인증·IDOR·데이터 권한 25 pair.
- 한국 개인정보·SCA·IaC 25 pair.
- MCP runtime·DB·CLI·운영 25 pair.
- 각 평면은 생성 pair 20개와 공개 pair 5개다.
- 취약 side 100개는 모두 High/Critical oracle이고 Critical은 최소 20개다.
- 수정·정상 side 100개가 global specificity 분모다.

한 slot의 `slot_pass`는 취약 side의 요구 finding·처분이 모두 맞고 수정·정상 side에서 금지 finding·처분이 하나도 없어야 한다. `app_complete_actionability`는 해당 slot의 모든 High/Critical finding에 위치, 영향, 재현, 수정안, 수정 확인이 있고 출하 처분이 맞아야 한다.

holdout 독립성:

- H100 owner와 실행자는 SOL이다.
- holdout encrypted root, oracle key, target credential, 실행 결과는 Qwen에 제공하지 않는다.
- 모든 tuning denominator, promotion validation denominator, Qwen-seen corpus를 합친 `development-exclusion-manifest.json` combined set과 H100 사이 exact scenario ID, blob/tree SHA, source lineage 교집합 0을 기계적으로 증명한다. 교집합이 있거나 lineage를 증명하지 못하면 H100 등록을 거부한다.
- 생성 pair는 개발 corpus 생성에 사용한 template·parameter·seed 계보와 분리됐다는 lineage attestation이 있어야 하며, template 또는 parameter lineage가 겹치거나 증명되지 않으면 H100 등록을 거부한다.
- H100은 작업 저장소 밖 별도 encrypted directory에 두고, Qwen 세션이 종료된 뒤 SOL 실행 시간에만 mount한다.
- candidate commit 시각, H100 manifest 봉인 시각, scanner 실행 시각, access log를 결속해 결과 열람 전 candidate가 고정됐음을 증명한다.
- 각 pair는 1:1 oracle, source lineage, 취약·수정 revision 또는 기계 검증 생성 provenance가 있어야 한다. 하나라도 없으면 H100 등록을 거부한다. `untouched-proof.json`은 combined-set manifest SHA와 zero-intersection proof SHA도 포함한다.

Exit gate:

- 전체 90/100 이상.
- 각 평면 24/25 이상.
- 평면 gate 때문에 실효 최소 slot pass는 `96/100`이며, `90/100`은 독립 하한으로만 유지한다.
- block precision 90% 이상, Wilson 하한 80% 이상.
- High/Critical recall 90% 이상, Critical recall 100%.
- specificity 90% 이상.
- app complete actionability 90/100 이상, Wilson 하한 80% 이상.
- 하나의 verdict event 안에서 실행한 두 결과가 canonical byte 기준 완전 일치.
- Guardian 지원 범위 누락 0.
- 결과를 본 뒤 코드 수정 0.
- H100 target·oracle에 대한 Qwen read/access 0.
- SOL, Opus, Grok `GO`.

H100 결과가 실패하거나 두 실행이 다르거나 결과 공개 뒤 변경이 발생하면 재시도하지 않고 `goal_status=COMPLETED_HOLD`, `release_status=HOLD`, `terminal_disposition=RELEASE_HOLD_FINAL`이다.

### Phase 6. 제품·출하 판정

Entry gate:

- Phase 5 `FIX`, `may_start_next_phase=true`.
- H100을 통과한 동일 candidate commit과 wheel SHA 봉인.
- 설치·CLI·MCP·클라이언트 명령, 예상 결과, timeout, 로그 redaction 규칙을 실행 전에 봉인.

허용 범위:

- 봉인 wheel 설치와 실행, transcript·evidence index·최종 receipt 생성.

금지 범위:

- 제품·패키지·설정·규칙 수정, wheel 재빌드, H100 재실행.

필수 작업:

- fresh wheel 설치.
- 사람이 CLI만으로 실행.
- MCP 설치, restart, tool list, `check_my_app`, Guardian 실행.
- GPT, Grok, Codex, Antigravity 호환 확인.
- 최종 evidence index와 모든 receipt hash 결속.

Exit gate:

- 설치·CLI·MCP·클라이언트 회귀 0.
- Phase 0에서 봉인한 동일 latency roster, 장비 receipt, wheel SHA와 cold 5회·warm 5회 프로토콜로 `check_my_app` 30회 모두 5.000초 이하.
- Guardian 지원 범위 누락 0.
- finding 단위 세 검토자 만장일치 90% 이상, inconclusive 0.
- CODEX SOL, Grok 4.5, Claude Opus 5 최종 terminal verdict 모두 `GO`.
- 최종 수치 게이트 전항 통과.

전항을 통과하고 최종 evidence index가 봉인된 경우에만 성공 terminal tuple을 `goal_status=COMPLETED_GO`, `release_status=GO`, `terminal_disposition=NONE`, `executor_status=COMPLETE`로 기록한다.

하나라도 실패하거나 미측정이면 재빌드·재시도 없이 `goal_status=COMPLETED_HOLD`, `release_status=HOLD`, `terminal_disposition=RELEASE_HOLD_FINAL`이다.

## 11. 증거와 로그 계약

증거 root:

`<LOCAL_USER_HOME>/Desktop/mcp/k-guard-live-evidence/product-hardening-20260731/`

Phase 디렉터리:

`phase-<n>-<slug>/attempt-<1|2>/`

Phase 0 진입 전 contract review receipt는 제품 Phase 자동 검수와 분리해 `planning/`에 저장한다. 필수 파일은 `opus5-contract-receipt.json`, `grok45-contract-receipt.json`, `contract-agreement-receipt.json`이다.

각 supervisor contract receipt의 필수 필드:

- `schema_version`
- `reviewer`
- `requested_model_id`
- `runtime_model_id`
- `contract_sha256`
- `verdict=GO|HOLD|BLOCKED`
- `blockers`
- `product_approval=false`
- `usage.input_tokens`, `usage.output_tokens`, `usage.total_tokens`이며 각각 0보다 큰 정수
- `started_at`, `completed_at`, `session_id`
- `direct_file_read=true`, `reviewed_path`
- `peer_verdict_supplied=false`
- `provider_envelope_path`, redacted provider envelope SHA-256, canonical review result SHA-256

허용 model binding은 Opus의 `requested_model_id=claude-opus-5`, `runtime_model_id=claude-opus-5`와 Grok의 `requested_model_id=grok-4.5`, provider가 반환한 고정 runtime alias `runtime_model_id=grok-4.5-build` 두 쌍뿐이다. 다른 문자열, 빈 usage, contract SHA 불일치, 다른 supervisor 판정 입력, 원문 file-read 부재는 전부 `BLOCKED`다.

SOL의 deterministic contract receipt validator는 두 JSON의 schema, model binding, contract SHA, terminal verdict, token usage, 독립성 필드를 검사한다. 두 receipt가 모두 `GO`일 때만 자신의 script SHA-256, 입력 receipt SHA-256 두 개, contract SHA-256을 담은 `contract-agreement-receipt.json`을 생성한다. validator 오류, 미지원 field 값, receipt 누락은 예외 없이 실패하고 Phase 0을 열지 않는다.

고정 contract toolchain:

| 파일 | SHA-256 |
| --- | --- |
| `planning/tools/run_contract_receipt_validator.ps1` | `1444bd4899a38abb1ad6248d1bbc9f39b108fef237af9d62f7de5fc3b91f14aa` |
| `planning/tools/validate_contract_receipts.py` | `0ab4c1f19e82787ce388d3b0001beb0b6f60bc364bae03a79bf074516b04c32b` |
| `planning/tools/contract-review-receipt.schema.json` | `c54d826cdd9e72443377bd33e63c3c56b6ed90fe202ec55f96993c99a8c544cb` |
| `planning/tools/contract-review-envelope-redacted.schema.json` | `c9c7d9160968488c6f013c0ce7ebc12f12821c5567aef84637c083a18c3853f0` |
| `planning/tools/contract-agreement-receipt.schema.json` | `8392431377ce9646879602dd7c3455f8efde5b625edd5bf8f6c7154dd1210505` |
| `planning/tools/contract-freeze-check.schema.json` | `6ef2a7529ff4549a766c24f2995c13d6f869c9e9224a969b839c0d075bc5a902` |
| `planning/tools/run_contract_freeze_check.ps1` | `9061f2805178b289a0dfa2a93ae1c72d1ce225c9bdbf110df2efcd7f20d2bc0b` |
| `planning/tools/verify_contract_freeze.py` | `6c1b556848b0d65ce19ce1e790c34ec898464c281823888cd0860bb1d8bfc880` |
| `planning/tools/test_validate_contract_receipts.py` | `d87acee004e86e31086aeb427f78c8043cf9996ef36c367846e2f812363e48a9` |
| `planning/tools/test_verify_contract_freeze.py` | `9f020e27d9c60b2f2a7a6e189585f12e8b4362a9e7bb2212ad648a2d33e051dc` |

모든 path의 root는 `<LOCAL_USER_HOME>/Desktop/mcp/k-guard-live-evidence/product-hardening-20260731/`다. Python 파일을 직접 호출하지 않고 pinned PowerShell wrapper만 호출한다. SOL caller는 매 invocation 직전에 wrapper 자체 SHA를 위 표와 대조한 뒤 wrapper를 호출한다. wrapper는 Python과 schema SHA를 실제 바이트에서 먼저 계산해 위 pin과 다르면 실행 전에 `BLOCKED`한다. JSON schema는 실행기의 별도 판정원이 아니라 hardcoded field validator의 declarative mirror다. self-test가 schema property 집합과 Python 허용 field 집합의 완전 일치를 검사한다. receipt validator는 redacted provider envelope 파일을 직접 읽어 SHA와 receipt 필드를 대조하고 서로 다른 supervisor session ID를 요구한다. envelope는 모든 중첩 object를 재귀 검사해 `thought`, `raw_response`, `raw_prompt`, `api_key`, `secret` key가 하나라도 있으면 차단한다. 입력 receipt 자체 SHA-256은 receipt 안에 자기 참조로 넣지 않고 validator가 원본 byte에서 계산해 agreement와 evidence manifest에 기록한다.

freeze hash glossary:

- `contract-agreement-receipt.json.contract_sha256`: 동결된 계약 파일 내용의 SHA-256.
- `contract-agreement-receipt.json.contract_byte_count`: 동결된 계약 파일 byte count.
- `contract-freeze-*.json.contract_file_sha256`: freeze 실행 때 실제 계약 파일에서 다시 계산한 SHA-256이며 agreement의 `contract_sha256`과 비교한다.
- `contract-freeze-*.json.contract_agreement_sha256`: on-disk `contract-agreement-receipt.json` 파일 자체의 SHA-256.
- `contract-freeze-*.json.checker_sha256`: 실행된 `verify_contract_freeze.py` 파일 SHA-256이며 위 toolchain pin과 비교한다.
- `entry-receipt.json` 또는 `phase-decision.json`의 `contract_freeze_check_sha256`: on-disk freeze output 파일 자체의 SHA-256. agreement 내부에는 이 필드가 없으며 agreement와 직접 비교하지 않는다.

self-test evidence:

`<LOCAL_USER_HOME>/Desktop/mcp/k-guard-live-evidence/product-hardening-20260731/planning/contract-toolchain-test-r6.json`

Phase 유형별 필수 파일:

| 유형 | 필수 파일 |
| --- | --- |
| Phase 0 freeze | contract review receipt 2개, `contract-agreement-receipt.json`, `entry-receipt.json`, `schedule-drift-receipt.json`, `clean-target-receipt.json`, `denominator-registry.json`, `promotion-validation-denominator.json`, `development-exclusion-manifest.json`, `derived-gate-constants.json`, `control-run-1.json`, `control-run-2.json`, `repeat-report.json`, `regression-baseline.json`, `latency-roster.json`, `qwen-health.json`, `opus5-health.json`, `grok-health.json`, `holdout-custody-receipt.json`, entry/decision assembler validation receipt, 감독 receipt 3개, `evidence-manifest.json`, `phase-decision.json` |
| Phase 1~3 A/B | `entry-receipt.json`, `preregistration.json`, `target-receipt.json`, control 2개, candidate 2개, `paired-ab-report.json`, `promotion-validation-run-1.json`, `promotion-validation-run-2.json`, `promotion-validation-report.json`, `focused-tests.json`, `full-regression.json`, `latency-report.json`, 필요 시 `rollback-receipt.json`, 감독 receipt 3개, `evidence-manifest.json`, `phase-decision.json` |
| Phase 3C conditional A/B | Phase 1~3 A/B 파일 전부, `phase3c-required-proof.json`, secure-cookie tuning·validation denominator receipt |
| Phase 4 full measurement | `entry-receipt.json`, `target-receipt.json`, full run 2개, `repeat-report.json`, `oracle-mapping.json`, `metric-report.json`, `candidate-distribution.json`, `full-regression.json`, `latency-report.json`, 감독 receipt 3개, `evidence-manifest.json`, `phase-decision.json` |
| Phase 5 H100 | `entry-receipt.json`, `holdout-custody-receipt.json`, `untouched-proof.json`, combined-set manifest SHA, `development-exclusion-proof.json`, `candidate-receipt.json`, `verdict-event-receipt.json`, hidden run 2개, `repeat-report.json`, `h100-metric-report.json`, `finding-review-set.json`, 감독 receipt 3개, `evidence-manifest.json`, `phase-decision.json` |
| Phase 6 release | `entry-receipt.json`, `wheel-receipt.json`, `fresh-install.json`, `cli-transcript.json`, `mcp-transcript.json`, `client-compatibility.json`, `guardian-scope-report.json`, `finding-unanimity.json`, 감독 final receipt 3개, `release-evidence-index.json`, `release-decision.json` |

모든 Phase 행에는 entry 직전 `contract-freeze-entry.json`과 decision 직전 `contract-freeze-decision.json`을 추가한다. 두 파일은 pinned freeze-check wrapper가 새 경로에 생성해야 하며 수동 작성 receipt는 무효다.

`promotion-validation-report.json`은 validation denominator ID, manifest SHA-256, exact scenario IDs, 양성·음성·severity 수, output mode, candidate commit, analyzer target SHA, 두 run artifact SHA, canonical repeat equality, TP/FP/FN/TN, recall·precision·specificity를 포함한다. 하나라도 없거나 두 run이 다르면 승격하지 않는다.

감독 receipt 3개는 `sol-receipt.json`, `opus5-receipt.json`, `grok-receipt.json`이다. GLM을 호출한 경우 `glm-advisory-receipt.json`을 추가하지만 필수 의결을 대체하지 않는다.

제품 Phase supervisor receipt 필수 필드는 `phase_id`, `attempt`, `sealed_packet_sha256`, `contract_file_sha256`, `reviewer`, `requested_model_id`, `runtime_model_id`, `session_id`, 양수 token usage, `peer_verdict_supplied=false`, `verdict`, `blockers`, `blocker_class`, redacted provider envelope path·SHA-256, source 또는 sanitized packet attestation이다. Phase 0에서 이 schema와 deterministic validator를 봉인한다. validator는 같은 packet의 SOL·Opus·Grok session ID가 pairwise distinct인지, 최대 세 `BLOCKED` 호출과 최초 호출 후 6시간 terminal window를 기계적으로 검사한다. phase, packet, contract SHA 중 하나라도 다르면 과거 GO receipt 재사용을 차단한다.

동결 전 contract review와 제품 Phase review의 성공·실패·`BLOCKED` receipt를 모두 append-only로 보존하고 `evidence-manifest.json` 또는 planning index에 열거한다. superseded receipt도 삭제하지 않는다.

모든 파일은 SHA-256, byte count, analyzer target, control target에 결속한다. 기존 경로를 덮어쓰지 않는 append-only 규칙을 적용한다. raw secret, 개인정보, 전체 응답 본문은 저장하지 않는다.

매일 KST 23:59 전에 `daily-hash-inventory-YYYYMMDD.json`을 만들고 이전 inventory SHA를 연결한다. inventory에는 증거 root뿐 아니라 고정 계약 파일의 실제 SHA-256·byte count와 위 contract toolchain 파일 전부를 넣는다. 증거 root 전체와 고정 계약 파일 byte copy는 같은 날 다음 off-workspace backup에 복제하고 두 root의 manifest SHA 일치를 검사한다.

`<LOCAL_USER_HOME>/Documents/k-guard-release-evidence-backup/product-hardening-20260731/`

backup의 고정 계약 사본은 `frozen-contract/terra-product-hardening-execution-contract-ko.md`에 두며 원본 계약 path, SHA-256, byte count를 backup manifest에 기록한다. daily inventory 또는 backup 비교에서 계약 파일이 다르면 진행 중 Phase를 즉시 실패로 닫는다.

Phase decision 필수 필드:

- `phase_id`
- `contract_file_sha256`
- `contract_byte_count`
- `contract_agreement_sha256`
- `contract_freeze_checker_sha256`
- `contract_freeze_check_sha256`
- `goal_status`
- `phase_status`
- `release_status`
- `terminal_disposition`
- `attempt`
- `numeric_gate_passed`
- `repeat_exact`
- `regression_passed`
- `review_verdicts`
- `failure_reasons`
- `may_start_next_phase`
- `artifact_manifest_sha256`

`phase-decision.json`과 `entry-receipt.json`은 각각 sealing 직전에 pinned freeze-check wrapper를 새 append-only path로 실행한다. freeze output의 `phase_id`와 `event`가 현재 Phase 및 `entry|decision`과 같아야 한다. `contract_file_sha256`과 `contract_byte_count`는 agreement 내부 값과 비교하고, `contract_agreement_sha256`은 현재 on-disk agreement 파일 hash와 비교하며, `contract_freeze_checker_sha256`은 toolchain pin과 비교한다. freeze output 파일 자체의 hash를 `contract_freeze_check_sha256`에 기록한다. agreement에는 freeze output hash가 없으므로 이를 agreement field와 비교하지 않는다. 불일치, checker 재사용, 수동 작성, 누락이면 해당 Phase를 실패로 닫는다. `may_start_next_phase=true`는 `phase_status=FIX`이고 SOL, Opus, Grok receipt가 모두 `GO`일 때만 허용한다.

## 12. 외부 AI 검수 계약

검수 시점:

- 정량 게이트와 회귀가 먼저 통과한 후 호출한다.
- SOL packet 봉인 후 Opus와 Grok을 동시에 호출하며 서로의 판정을 입력에 넣지 않는다.

공통 입력:

- Phase claim boundary.
- preregistration hash.
- target hash.
- A/B 요약과 원본 artifact hash.
- promotion validation run 2개와 `promotion-validation-report.json`의 artifact hash, denominator binding, repeat equality, metric.
- 반복성·회귀·속도 결과.
- 다음 Phase로 넘어가도 되는지에 대한 단일 질문.

Claude Opus 5 추가 입력:

- preregistration에 지정된 직접 소스 파일.
- 성공한 file-read attestation.

file-read attestation은 파일마다 다음 필드를 가져야 한다.

- `path`
- `sha256`
- `byte_count`
- `successful_tool_call_id`
- `successful_tool_result_id`
- `inspected_line_ranges`
- `excerpt_sha256`
- `raw_excerpt_returned=false`
- `validator_status`

`excerpt_sha256`은 검수한 line range의 정확한 UTF-8 byte를 순서대로 연결해 계산하되 원문은 receipt에 저장하지 않는다. validator는 현재 파일 SHA·byte count, 유효 line 범위, excerpt hash, 성공 tool call/result ID 존재를 확인한다. 하나라도 다르면 Opus verdict를 `BLOCKED`로 강제한다.

감독 경계:

- SOL은 원본 수치 artifact와 manifest를 검증하지만 제품 후보 코드를 구현하지 않는다.
- Opus 5만 preregistration에 지정된 소스를 직접 읽는다.
- Grok은 sanitized packet만 검수하며 직접 소스 검수라고 주장할 수 없다.
- GLM은 호출하더라도 비의결 advisory다.

H100 finding 검수 집합:

- H100에서 생성된 High/Critical `counted_block=true` finding 전건이며 sampling은 금지한다.
- 최소 finding 수는 70건이다. 70건 미만이면 `HOLD`다.
- 각 finding은 `finding_id`, `oracle_id`, redacted fingerprint, detector subtype, body/header/code 위치, response 또는 snippet hash, severity, 영향, 재현법, 수정안, 수정 확인 test hash를 포함한다.
- raw secret, 개인정보, 전체 response body는 포함하지 않는다.

각 감독자는 finding마다 다음 label 중 하나만 낸다.

- `true_positive`: oracle과 위치·영향·처분이 일치한다.
- `false_positive`: finding 또는 block 처분이 oracle과 불일치한다.
- `benign`: 신호는 존재하지만 의도된 안전 동작이라 block 대상이 아니다.
- `inconclusive`: 제공 증거로 판정할 수 없다.

만장일치율:

```text
unanimous_count = 세 감독자가 동일한 non-inconclusive label을 낸 finding 수
unanimity_rate  = unanimous_count / 전체 검수 finding 수
```

분모에서 conflict나 inconclusive finding을 제거하지 않는다. `inconclusive`가 한 건이라도 있으면 최종 gate 실패다. Critical finding은 전건 100% 만장일치, 전체 finding은 90% 이상이어야 한다.

유효 verdict:

- `GO`: 좁은 Phase claim과 증거가 완결됐다.
- `HOLD`: 코드·증거·수치·경계에 blocker가 있다.
- `BLOCKED`: 인증, timeout, provider 장애로 검수를 수행하지 못했다.

`BLOCKED`는 `GO`가 아니며 다음 Phase 권한을 만들지 않는다.

## 13. 일정

| 날짜 | 목표 |
| --- | --- |
| 7월 25일 | 실행 계약 최종 검수, Qwen 3-worker health 봉인 |
| 7월 26일 | Phase 0 봉인과 세 감독자 검수 |
| 7월 27일 | Phase 1 Java XSS와 Phase 검수 |
| 7월 28일 | Phase 2 path traversal과 Phase 검수 |
| 7월 29일 | Phase 3 command injection과 Phase 검수, 필요한 경우 Phase 3C 준비 |
| 7월 30일 오전 | 조건부 Phase 3C와 Phase 4 통합 정적·oracle 게이트 |
| 7월 30일 오후 | Phase 5 H100 |
| 7월 31일 | Phase 6 설치·호환·최종 검수, 18:00 GO/HOLD |

각 가설의 두 번째 측정까지 실패하면 해당 Phase를 같은 마감 안에서 계속 고치지 않는다. 최종 판정은 `HOLD`로 고정하고 남은 시간은 실패 증거와 다음 릴리스 작업을 정리하는 데 사용한다.

일정 지연을 만회하기 위한 분모 축소, gate 완화, 검수 생략, scope shedding은 금지한다. 계획일을 넘긴 Phase는 후속 Phase 시간을 압축하지 않는다. `2026-07-31 18:00 KST`까지 Phase 6가 완결되지 않으면 `goal_status=COMPLETED_HOLD`, `release_status=HOLD`, `terminal_disposition=RELEASE_HOLD_FINAL`로 닫고 증거 index와 실패 분석만 완성한다.

## 14. 현재 시작 권한

- 현재 허용: 이 실행 계약의 Opus 5·Grok 독립 검수, Qwen 3-worker health receipt 결속, Phase 0 preregistration 준비.
- 현재 금지: Qwen 제품 파일 수정, Phase 1 제품 구현, H100 scanner 실행.
- Qwen 구현 권한 조건: exact model `qwen3.8-max-preview`, provider `Model_Studio_Token_Plan_Personal`, 동시 worker 3/3 종료 코드 0, runtime model ID 일치, worker별 token usage 0 초과, health `GO`.
- Phase 1 시작 조건: Phase 0 `FIX`와 `may_start_next_phase=true`.

동결 전 contract review가 인증·timeout·provider 장애로 `BLOCKED`되면 해당 supervisor만 최초 호출부터 6시간 안에 최대 세 번 재호출할 수 있다. 6시간 안에 terminal receipt가 없으면 계약 후보는 `HOLD`다. `HOLD`는 해당 contract SHA에서 terminal이며 문서를 수정해 새 SHA를 만든 뒤 Opus와 Grok을 모두 새로 독립 호출해야 한다. `GO`도 해당 SHA에서 terminal이고 다른 supervisor 입력으로 재사용하지 않는다.

이 문서의 현재 SHA-256에 대한 Claude Opus 5 직접 검수 receipt와 Grok 4.5 독립 계약 검수 receipt가 모두 `GO`인 경우에만 Phase 0 실행 계약이 확정된다. 두 receipt를 받은 뒤 문서 자체를 다시 수정하지 않고 외부 receipt가 이 hash를 `CONTRACT_AGREED`로 결속한다.

## 15. 외부 계약 검수 이력과 반영표

첫 직접 검수 대상 SHA-256:

`1681ae1eba13e360c9767bc7b52f24835fdebe729969b32874e25c82bf7ada35`

판정은 `HOLD`, blocker 14건과 비차단 권고 8건이었다. 이 검수는 계획 문서 검수이며 제품 Phase 승인이 아니다.

| blocker | 반영 위치 |
| --- | --- |
| `B01-DEV-DENOMINATOR-UNBOUND` | 4, 7, 8절 denominator·family 계약 |
| `B02-GATE-SCOPE-AND-MIN-SAMPLE` | 7절 metric별 mode·분모·최소 표본 |
| `B03-PROMOTION-LADDER-UNDEFINED` | 7절 observe→warn→block 승격 |
| `B04-PHASE-COMPOSITION-ARITHMETIC-UNPROVEN` | 4절 H1~H3 구성 산술 |
| `B05-ENTRY-GATE-MISSING` | 8절 공통 entry와 10절 Phase별 entry |
| `B06-RETRY-VS-HOLDOUT-CONTRADICTION` | 9절 재시도 범위와 10절 H100 단일 event |
| `B07-ROLLBACK-RULES-ABSENT` | 9절 비파괴 revert·복원 receipt |
| `B08-PROGRAM-FAILURE-SEMANTICS-AMBIGUOUS` | 9절 `RELEASE_HOLD_FINAL` |
| `B09-HOLDOUT-INDEPENDENCE-INCOMPLETE` | Phase 5 custody·접근 금지·untouched proof |
| `B10-EVIDENCE-FILE-LIST-UNSATISFIABLE` | 11절 Phase 유형별 파일 |
| `B11-FILE-READ-ATTESTATION-UNVERIFIABLE` | 12절 attestation schema·validator |
| `B12-PER-FINDING-UNANIMITY-NO-MECHANISM` | 12절 finding set·label·산식 |
| `B13-BASELINE-PROVENANCE-CONFLICT` | 4절 development-only와 Phase 0 clean 대체 |
| `B14-LATENCY-CONTRACT-UNMEASURABLE` | 7절 고정 roster·30회·5초 계약 |
| `B15-JOB-CARDINALITY-AND-REFILL` | 1, 9절 정확히 3개 job·refill 금지 |
| `B16-PHASE0-ENTRY-OMITS-GROK-FREEZE` | 8, 10, 14절 동일 계약 SHA의 Opus·Grok 동시 GO |
| `B17-OPUS5-ENTRY-RECEIPT-CIRCULARITY` | 1, 11절 계약 검수 예외와 receipt schema·validator |
| `B18-CONTRACT-FREEZE-POINT-CONFLICT` | 서문, 8, 10, 11, 14절 단일 freeze와 SHA 재검증 |
| `B19-PROMOTION-LADDER-NOT-WIRED-TO-PHASES` | 7, 10절 분리 validation 분모와 mode 승격 |
| `B20-INTEGRATION-COMMIT-COUNT-UNBOUND` | 9절 정확히 3개 non-empty commit |
| `B21-PHASE4-RETRY-VS-FORBIDDEN-SCOPE` | 9, 10절 Phase 4 단일 측정 attempt |
| `B22-CONTRACT-FREEZE-NOT-BYTE-VERIFIED` | 8, 11, 14절 actual-byte freeze checker·공통 금지 path·이중 백업 |
| `B23-FREEZE-CHECK-SHA-FIELD-UNSATISFIABLE` | 8, 11절 agreement·checker·freeze output hash glossary |
| `B24-PHASE3C-PROMOTION-VALIDATION-POOL-INFEASIBLE` | 4, 10, 11절 secure-cookie 외부 30/30 validation pool과 조건부 Phase 3C |
| `B25-PROMOTION-VALIDATION-MEASUREMENT-UNEVIDENCED` | 9, 11, 12절 validation 2회·report·감독 packet |
| `B26-VALIDATION-POOL-NOT-IN-H100-EXCLUSION-PROOF` | Phase 0 combined exclusion set과 Phase 5 scenario·lineage 교집합 0 |

비차단 권고인 상태 enum 분리, H100 실효 96/100 명시, 중앙 model ID, regression count·log hash, reviewer retry, deadline HOLD, 모든 Phase 파일 경계, append-only 이중 보관도 각각 1, 2, 7~13절에 반영했다.
