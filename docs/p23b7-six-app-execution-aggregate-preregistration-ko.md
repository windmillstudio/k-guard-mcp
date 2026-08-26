# P2.3B.7 여섯 앱 execution oracle aggregate 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 프로그램: [P2.3B execution oracle 사전등록](p23b-local-execution-oracle-program-preregistration-ko.md)

## 한 문장 목표

P2.3B.1-P2.3B.6에서 각각 `FIX_NARROW`로 고정한 raw-free positive repeat, negative
repeat, supervisor repeat comparator를 한 개의 6-app membership manifest로 다시 검증한다.
이 카드는 새 취약점 탐지나 앱 재실행이 아니라, 이미 선택한 여섯 카드의 coverage와 exclusion을
기계적으로 결속하는 작업이다.

## 사전 고정 분모와 입력

P2.3A source registry는
`<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p23a-six-source-registry-20260723-r2\materialization-r2.json`이며,
SHA-256은 `d954a641efcfc1948d91a9f669d2db329df798cfd511d088e73f20281bc15eb1`이다.

분모는 정확히 `webgoat`, `juice-shop`, `nodegoat`, `pygoat`, `crapi`, `wrongsecrets` 6개다.
제외는 `0`개다. 각 앱은 positive repeat, negative repeat, Claude/Grok/GLM supervisor
repeat comparator 3개를 모두 가져야 한다. 파일 부재, non-canonical JSON, raw boundary 위반,
`status != FIX`, `repeat_exact != true`, component authority mismatch, supervisor field-id
mismatch 중 하나라도 있으면 해당 앱을 조용히 제외하지 않고 aggregate 전체를 `HOLD`로 한다.

| 앱 | source receipt SHA-256 | positive / negative / supervisor comparison |
| --- | --- | --- |
| webgoat | `7755ce29a5450b9803f46effb6f42fe7624e39b317c99546eb74624a3380b83b` | `phase2-p23b1-webgoat-idor-positive-20260723-r5-r6-comparison.json` / `phase2-p23b1-webgoat-idor-negative-20260723-r5-r6-comparison.json` / `phase2-p23b1-supervisor-review-20260723-r1-r2-comparison.json` |
| juice-shop | `4ed955ad49e650a12139a21e8fc0491a102fd346e4920ca771668e3cf0f9a93a` | `phase2-p23b2-juice-shop-bola-development-20260723-r3-r4-positive-comparison.json` / `phase2-p23b2-juice-shop-bola-development-20260723-r3-r4-negative-comparison.json` / `phase2-p23b2-supervisor-review-20260723-r1-r2-comparison.json` |
| nodegoat | `d3ad5d453bb7d35580f3bf21dfcbab1bbf53555b7144f94da917cd6513ee21ab` | `phase2-p23b3-nodegoat-allocations-idor-development-20260723-r7-r8-positive-comparison.json` / `phase2-p23b3-nodegoat-allocations-idor-development-20260723-r9-r10-negative-comparison.json` / `phase2-p23b3-supervisor-review-20260723-r1-r2-comparison.json` |
| pygoat | `0bf2824174f6e979893bda964f87e394c3689db69a3825cab646880156f2fa5c` | `phase2-p23b4-pygoat-sensitive-data-development-20260723-r2-r3-positive-comparison.json` / `phase2-p23b4-pygoat-sensitive-data-development-20260723-r4-r5-negative-comparison.json` / `phase2-p23b4-supervisor-review-20260723-r3-r4-comparison.json` |
| crapi | `d86a9985f9eda5e391112a26a092f7a5273bde393c386ae8968f91399df7429b` | `phase2-p23b5-crapi-vehicle-bola-20260723-r5/positive-r1-r2-comparison.json` / `phase2-p23b5-crapi-vehicle-bola-20260723-r5/negative-r1-r2-comparison.json` / `phase2-p23b5-crapi-vehicle-bola-20260723-r5/supervisor-review-r1-r2-comparison.json` |
| wrongsecrets | `58509e4ad992c66e1b230a66d9f7e18c6c080aea07fb110e07b08d4295455485` | `phase2-p23b7-six-app-aggregate-20260723-r1/wrongsecrets-positive-authority-v2.json` / `phase2-p23b7-six-app-aggregate-20260723-r1/wrongsecrets-negative-authority-v2.json` / `phase2-p23b6-wrongsecrets-challenge1-javac-20260723-r1/supervisor-review-r1-retry-900-r2-comparison.json` |

## A-G 완료 조건

| Gate | 산출물 | 즉시 HOLD 조건 |
| --- | --- | --- |
| A | 이 문서와 6-app membership, exclusion `0`, claim boundary | 결과를 본 뒤 앱이나 artifact를 교체 |
| B | aggregate materializer와 two-run comparator | relative-path escape, symlink, raw artifact, unknown app을 허용 |
| C | canonical JSON, source registry, 18 component comparison, missing/raw/tamper regression test | component 하나를 누락해도 통과 |
| D | external evidence root에서 aggregate r1/r2와 comparator | app set, component hash, coverage, tool hash가 달라도 통과 |
| E | 새 baseline seal, focused tests, full regression | target drift, test failure, shard 누락 |
| F | 동일 packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 run | 한 lane `HOLD`/`BLOCKED`, direct-file attestation 누락, repeat mismatch |
| G | ledger와 goal board에 `FIX_NARROW` 기록 | aggregate를 detector accuracy, 6-app 재실행, H100, release로 과장 |

## 명시적 비주장

이 카드는 여섯 historical card의 already-recorded comparator가 빠짐없이 존재하고 서로
raw-free/authority contract를 지키는지만 재검증한다. 앱을 새로 실행하지 않으며, 각 앱의
전체 취약점, K-Guard finding 정확도, TP/FP/FN, recall, specificity, severity, warning/block,
Guardian, H100, 한국 개인정보 성능, 출하 승인에 대한 증거가 아니다.

## 사전 측정 전 계약 보강 기록

첫 aggregate materialization은 output을 만들기 전에
`wrongsecrets_positive_authority_invalid`으로 fail-closed했다. 기존 WrongSecrets r1/r2
comparison은 `status=FIX`와 `repeat_exact=true`는 기록했지만 `authority` object가 없었다.
legacy exception을 만들지 않는다. 이 카드의 B 단계에서 comparator가 다른 앱과 같은
`may_mark_field_fix` 및 non-release authority를 기록하도록 보강하고, original r1/r2 receipt를
입력으로 새 v2 comparison 두 개를 만든다. 기존 P2.3B.6 artifact와 Maven `MEASURED_HOLD`는
삭제하거나 덮어쓰지 않는다.

## 실행 결과와 좁은 승격

증거 root: `<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p23b7-six-app-aggregate-20260723-r1`

| Gate | 결과 |
| --- | --- |
| A | 이 문서로 정확히 6개 앱, 제외 `0`, 앱당 component comparator `3`개를 결과 전에 고정했다. |
| B | `aggregate_l2_execution_oracles.py`와 two-run comparator를 추가했다. WrongSecrets legacy comparator의 authority 누락은 예외로 허용하지 않고, preserved r1/r2 receipt를 입력으로 authority-v2 positive/negative comparison을 새로 만들었다. |
| C | aggregate, aggregate comparator, WrongSecrets comparator focused suite는 `12 passed`였다. missing component, raw boundary, source binding drift, partial anchor CLI 입력은 모두 fail-closed로 검증했다. |
| D | `aggregate-r1.json`과 `aggregate-r2.json`의 SHA-256은 모두 `2c6fdaffecd35bb92727b8e00df5f40f1920d6b65f62102099b62cb6b268ea1a`이고, `aggregate-r1-r2-comparison.json`은 `repeat_exact=true`, `status=FIX`였다. 6개 앱과 18개 component, exclusion `0`, `release_gate_passed=false`를 기록했다. |
| E | `baseline-r2.json` receipt SHA-256은 `7f5749431c9414a68a6bdbea1e4ac10c9e49371c6010b13a3fa1d44f97970183`이고 current target 검증과 `git diff --check`를 통과했다. `python -m pytest -q`는 `2538 passed, 5 skipped, 0 failed in 1184.13s`였다. |
| F1 | `supervisor-review-r1`에서 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2가 모두 `GO`였다. Claude는 지정한 7개 direct file을 읽은 attestation을 남겼고 target은 변하지 않았다. |
| F2/G | `supervisor-review-r2`도 전원 `GO`였고, `supervisor-review-r1-r2-comparison.json`은 semantic fingerprint `795e69a83122b8327fb42dc29299cbc73cda8c9104a77d9401d247ae01cec0f4`, `repeat_exact=true`, `status=FIX`를 기록했다. |

첫 aggregate 시도의 `wrongsecrets_positive_authority_invalid`은 source receipt 또는 oracle의
실패가 아니라 evidence contract 불일치였고, output 없이 fail-closed했다. 보강 후에도 기존
P2.3B.6 execution receipt와 Maven `MEASURED_HOLD`를 변경하지 않았다.

이 `FIX_NARROW`는 6개 historical card와 18개 component comparator의 membership, coverage,
exclusion, raw-free/authority binding만 뜻한다. 새 앱 실행, detector accuracy, TP/FP/FN,
Korean PII 성능, Guardian/H100, release를 승인하지 않는다.
