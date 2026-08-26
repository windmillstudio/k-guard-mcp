# P2.3B.1 WebGoat IDOR execution rebind 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 프로그램: [P2.3B execution oracle 사전등록](p23b-local-execution-oracle-program-preregistration-ko.md)

## 가설

`replay_l2_webgoat_idor.py`의 negative control은 역사적 positive receipt SHA-256 하나에
고정돼 있어 P2.3A의 새 clean source registry에서 만든 현재 positive execution receipt를
정당하게 연결할 수 없다. 이 pin을 제거하는 대신, caller가 준 positive receipt가 아래
모든 조건을 만족할 때만 control을 실행하도록 하면 stale receipt 재사용을 막으면서 새
source registry에 execution pair를 다시 결속할 수 있다.

1. canonical JSON이고 `EXECUTION_CONTRACT_PASS`다.
2. WebGoat의 고정 repository, commit, tree, source-tree hash와 일치한다.
3. 현재 runner, 현재 source verifier, 고정 base image가 모두 일치한다.
4. positive receipt의 source receipt hash가 지금 재검증한 source root의 receipt hash와
   정확히 일치한다.

## 변경 범위

| 대상 | 변경 |
| --- | --- |
| `scripts/replay_l2_webgoat_idor.py` | historical positive hash 하나를 admission 기준으로 사용하지 않고 현재 tool provenance와 같은 source receipt binding을 요구 |
| `tests/test_replay_l2_webgoat_idor.py` | canonical, pass, provenance, source receipt mismatch의 fail-closed test 추가 또는 갱신 |
| `scripts/compare_l2_idor_negative_control_repeats.py` | positive raw receipt hash의 변동은 별도 positive comparator가 두 anchor와 `FIX`를 결속할 때만 허용 |
| `tests/test_compare_l2_idor_negative_control_repeats.py` | positive comparator와 각 negative anchor의 불일치, positive comparator `HOLD`, mutation을 fail-closed로 확인 |

다른 detector, rule, severity, source identity, Docker isolation policy, test expectation,
admission blocker, release threshold는 변경하지 않는다.

## 성공 조건

1. old receipt hash를 바꾼 입력은 provenance 또는 same-source check에서 `HOLD`가 된다.
2. 새 current positive receipt는 P2.3A의 `webgoat` source root와 같은 source receipt를
   가질 때만 negative control의 입력이 된다.
3. 기존 역사적 negative evidence는 기존 receipt validation과 문서 보존 범위에서
   깨지지 않는다.
4. focused tests, 두 live positive/negative execution receipt, comparator, full regression,
   Claude/Grok/GLM 두 review run을 모두 통과해야 한다.

## 실행 후 관찰과 보정 가설

첫 두 live pair에서 positive execution comparator는 `FIX`였으나 negative comparator는
`HOLD`였다. 구조적 비교 결과 차이는
`positive_execution_contract.receipt_sha256` 하나뿐이었다. 이 hash는 두 current
positive receipt의 raw JSON hash이며, image ID, nonce, command output hash가 달라져도
positive semantic comparator가 이미 같은 execution contract임을 확인한 값이다.

따라서 negative comparator는 raw hash를 조용히 무시하지 않는다. 새 입력으로 positive
comparison receipt를 받고, `status=FIX`, `repeat_exact=true`, 서로 다른 두 positive raw
receipt hash, 그리고 각각의 negative positive-anchor 일치를 모두 검증한 뒤에만 해당
raw hash 차이를 volatile binding으로 취급한다. source receipt hash, runner/verifier/base
image, mutation, normalized negative result, isolation, cleanup 중 하나라도 다르면 계속
`HOLD`다.

## 완료 패킷 (2026-07-23)

| 칸 | 결과 |
| --- | --- |
| A | 이 문서의 가설, 변경 범위, 성공 조건, 비주장 범위를 변경 전에 고정했다. |
| B | `replay_l2_webgoat_idor.py`는 historical raw receipt hash 대신 현재 runner/source verifier/base image provenance와 같은 P2.3A source receipt를 요구하도록 바뀌었다. negative comparator는 두 positive raw receipt의 `FIX` comparison과 각각의 anchor 일치를 강제한다. |
| C | replay, import compatibility, positive/negative comparator, execution-evidence, oracle-materializer focused suite가 `119 passed`로 통과했다. |
| D | sealed r33 target에서 positive r5/r6와 negative r5/r6를 새로 실행했다. `phase2-p23b1-webgoat-idor-positive-20260723-r5-r6-comparison.json`과 `phase2-p23b1-webgoat-idor-negative-20260723-r5-r6-comparison.json`은 모두 `FIX`, `repeat_exact=true`다. |
| E | r16 full regression은 12/12 shard `COMPLETE`, 2,465 passed, 5 skipped, 0 failed, 0 errors다. aggregate는 `phase1-regression-shards-20260723-r16/aggregate-v3.json`에 결속됐다. |
| F | supervisor health r3에서 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2가 모두 healthy였다. 두 review run에서 세 lane 모두 `GO`, blocker 0, claim boundary confirmed, nonblocking `REPEATABILITY_GAP` 하나였고 `phase2-p23b1-supervisor-review-20260723-r1-r2-comparison.json`이 `FIX`를 냈다. |
| G | 이 결과는 source-bound WebGoat IDOR positive/negative execution pair와 그 repeatability만 `FIX_NARROW`로 기록한다. detector performance, TP/FP/FN, severity, warn/block, Guardian, H100, release는 계속 `HOLD`다. |

## 실패와 주장 경계

Docker build, Maven warmup, source verification, isolation, reset, cleanup, positive/negative
result, repeatability 중 하나라도 실패하면 P2.3B.1은 `HOLD`다. 이 작업은 WebGoat의
하나의 upstream IDOR execution pair를 P2.3A source registry에 재결속하는 것일 뿐,
detector 정확도, IDOR 일반화, API 권한 모델, TP/FP/FN, warning/block, Guardian, H100,
제품 release를 증명하지 않는다.
