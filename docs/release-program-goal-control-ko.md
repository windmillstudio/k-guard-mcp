# K-Guard 목표 통제와 독립 검증 운영 계약

작성일: 2026-07-24  
상태: `IN_PROGRESS`  
기계 상태 원본: [goal-state JSON](release-program-goal-state.json)  
제품 목표 원본: [제품 목표 레지스트리](release-program-goal-register-ko.md)  
원자 작업 원본: [원자 제품 목표 보드](release-program-atomic-goals-ko.md)
남은 제품 작업 순서: [제품 작업 카드 카탈로그](release-program-product-card-catalog-ko.md)
현재 작업 운영판: [현재 제품 작업 분해와 종료 운영판](release-program-current-work-breakdown-ko.md)

## 이 카드가 해결하는 문제

감독 AI를 많이 부르는 것과 제품 목표를 하나씩 끝내는 것은 다르다. 이 계약은 기존의
G1-G6 제품 목표를 없애거나 감독 목표로 대체하지 않는다. 각 제품 목표를 `페이즈 -> 원자
카드 -> A-G gate`로 추적하고, 어떤 카드가 지금 실제로 열려 있는지와 two-lane 검토가 언제
의무인지 한 곳에서 fail-closed로 확인한다.

`P8`과 `G7`은 제품 탐지율을 올리는 기능이 아니다. 목표, evidence, 감독 검토의 관계를
숨기지 않는 **출하 운영 통제**다. 따라서 P8의 완료는 TP/FP/FN, 시니어 동등성, H100,
출하 승인 어느 것도 추가로 증명하지 않는다.

## G7과 P8의 원자 작업

| 카드 | 이 카드에서 얻는 한 가지 운영 능력 | 완료 증거 | 상태 |
| --- | --- | --- | --- |
| P8.1 | G0-G7, P0-P8, 단일 활성 카드, A-G 및 3AI F1/F2 요구를 canonical JSON과 validator로 확인 | `validate_release_program_goals.py`, repeat comparator focused tests, two-run receipt, 3AI comparator | `FIX_NARROW` - A-G와 final 3AI F1/F2 완료 |
| P8.1B | current JSON과 사람이 읽는 세 운영판의 active card/gate/next gate 동기화 | marker validator와 stale-marker negative fixture | `FIX_NARROW` - initial D `HOLD` 보존, corrected A-G와 3AI comparator `FIX` |
| P8.2A | Windows npm shim을 Python subprocess 실행 경로로 정규화 | resolver, positive/negative command-builder test, health r1/r2, 3AI comparator | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX`; Windows supervisor contract만 해당 |
| P8.2B | Windows long review packet을 native Claude/Cline executable로 전송 | native resolver, transport probe/comparator, r1/r2, 3AI comparator | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P8.2D | GLM source-free health terminal contract | GLM system contract, strict parser negative test, health r1/r2, 3AI comparator | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX`; invalid field ID와 Claude timeout receipt 보존 |
| P8.2E | G1-G6 제품 작업 카탈로그와 single-active 전이를 canonical state/validator에 결속 | card catalog schema, predecessor/phase-exit/3AI gate validator, negative fixture, 3AI comparator | `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX`; registry transition control만 해당 |
| P8.2C | `FIX_NARROW`와 phase 종료 상태가 실제 machine/supervisor receipt hash 없이 기록되지 않게 결속 | receipt-link validator와 negative fixture | `NOT_STARTED` - P8.2B G 뒤 |
| P8.3 | phase packet의 child completion, excluded work, F1/F2 comparator를 한 번에 확인 | phase packet manifest와 two-run comparator | `NOT_STARTED` |
| P8.4 | 최종 `GO_RELEASE`가 G1-G7과 P0-P8의 필수 gate를 동시에 요구하도록 canonical disposition에 결속 | final disposition validator와 negative fixture | `NOT_STARTED` |

P8.1, Site-15, Data-03, Data-07, Data-09, Data-14, P2.4B.2.20, api-01, api-02가 각각 G까지 종료됐다.
그 결과 P8.1B가 유일한 `ACTIVE` 카드로 전이됐다. 이것이 문서상으로 여러 카드가 동시에 `ACTIVE`로 보이던
이전 상태를 고치는 다음 적용 사례다.

P8.1B는 이 전이를 사람이 읽는 운영판에도 강제하는 후속 원자 카드였다. 첫 D는 새
`human_status_boards` field를 goal-state repeat comparator가 아직 허용하지 않아 `HOLD`가 됐다.
두 external output은 보존하고, P8.1B는 B/C corrective를 마쳐 새 target에서 D를 다시 수행했다.
revised D r3/r4 comparator와 F1/F2 supervisor comparator는 모두 `FIX`였고, 이제 P8.1B는
human-status sync에 한해 `FIX_NARROW`다. 다음 product card는 `P2.4B.3.03 api-03`의 B다.

P8.1 D는 외부 evidence root의 `phase8-p81-goal-control-20260724-r1`과 `r2`에서 같은
target을 검증했다. comparator `FIX`, semantic fingerprint
`59a811b5c0bc7e20b6f7390b9357e8a75b4b341c6d9f32f058a980ca7d29c400`이며 이 값은 목표
통제 상태의 repeatability만 뜻한다.

처음 E의 `2649 passed, 5 skipped, 0 failed` full regression은 `EVIDENCE_READY` 상태를
허용하는 validator code 변경 전 target에서 실행됐다. 실패를 숨기지 않듯 target drift도
무시하지 않으므로, 그 run은 보존하되 승격 근거에서 제외했다. 위 `EVIDENCE_READY`는
current target full regression이 성공했을 때만 실제 F gate 후보가 된다.

초기 r3/r4 machine comparator와 r1/r2 supervisor comparator는 모두 `FIX`였지만, validator가
P8 phase만 active로 허용해 다음 Site-15 전이를 직접 검증하지 못한다는 범위 결함이 발견됐다.
이전 receipt는 삭제하지 않고 보존하되, generic next-card transition code와 positive test를 추가한
새 target의 D-E-F가 완료될 때까지 P8.1 승격 근거에는 쓰지 않는다.

최종 D는 `phase8-p81-goal-control-20260724-r5`/`r6`에서 같은 target으로 두 번 실행해
comparator `FIX`, semantic fingerprint
`691c68c217d440c3afe58c32f1087dfcbd877431ab9789f9dbaddd76ebd0265b`를 얻었다.

최종 E는 `2650 passed, 5 skipped, 0 failed` full regression과 `9 passed` focused tests를
current target에서 통과했다. 최종 F1/F2에서 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2는
모두 lane `GO`였고, supervisor comparator `FIX`, semantic fingerprint
`028849314cdef29e809945011f7975724950f320d7fb19e06c31256d0008176d`를 기록했다. 이 결과는
P8.1 운영 통제에만 적용되며 탐지 성능, TP/FP/FN, H100, 출하 승인은 계속 `HOLD`다.

## 모든 제품 작업의 공통 종료 순서

| Gate | 작업별 완료 조건 | 실패 시 다음 상태 |
| --- | --- | --- |
| A | 가설, 입력, oracle, 제외, claim boundary 사전등록 | `HOLD`; B 금지 |
| B | 코드 또는 provenance를 target에 결속 | target drift면 A부터 |
| C | positive/negative, tamper, fail-closed focused test | `HOLD` |
| D | independent output 또는 허가된 execution을 두 번 생성 | semantic difference면 `HOLD` |
| E | full regression, coverage, compatibility | error/timeout/unsupported는 `HOLD` |
| F1 | Claude Opus 5 max, Grok 4.6 xhigh 첫 독립 검토 | 한 lane이라도 미달이면 승격 금지 |
| F2 | 같은 target/packet 두 번째 독립 검토 | semantic comparator가 `FIX`가 아니면 승격 금지 |
| G | evidence hash, comparator, 비주장 범위를 장부에 기록 | 그때만 `FIX_NARROW` |

카드의 A-E가 끝난 뒤에는 F1/F2가 자동으로 다음 gate다. F1 또는 F2에 timeout,
`HOLD`, `BLOCKED`, target/model/packet drift가 있으면 카드는 `EVIDENCE_READY` 또는
`MEASURED_HOLD`로 남는다. 임시로 한 AI만 응답해도 비승격 관찰은 가능하지만, 해당 카드나
phase를 `FIX_NARROW` 또는 `GO_RELEASE`로 기록하지 않는다.

## 페이즈 종료 시의 별도 검증

leaf card의 F1/F2는 phase 완료를 대신하지 않는다. 각 P0-P8의 child가 모두 종료된 뒤,
phase summary packet에 대해 다음을 다시 실행한다.

1. child ID, evidence reference, 제외 항목, claim boundary를 raw-free phase packet으로 봉인한다.
2. Claude Opus 5와 Grok 4.6이 같은 packet을 F1과 F2로 각각 검토한다.
3. 두 정상 run의 supervisor comparator가 `FIX`일 때만 phase를 `FIX_NARROW`로 바꾼다.
4. 아직 열려 있거나 `MEASURED_HOLD`인 child가 하나라도 있으면 phase 및 상위 제품 목표는 `IN_PROGRESS` 또는 `HOLD`다.

## 사람이 확인하는 명령

```powershell
python scripts/validate_release_program_goals.py
python -m pytest tests/test_validate_release_program_goals.py -q
```

첫 명령은 한 카드만 `ACTIVE`이고 현재 카드가 재개 가능한 다음 work card인지, 세 감독관과 두 review run이 필수인지 검증한다. 두 번째 명령은 잘못된
gate 순서, 두 번째 활성 카드, GLM lane 누락, 미완료 상태의 `GO_RELEASE`를 거부하는지
검증한다.

P8.1은 위 절차를 `FIX_NARROW`로 완료했고, state는 Site-15를 유일한 active card로 전환했다.
P8.2A-P8.4도 같은 절차를 다시 거쳐야 하며, 이 문서는 검토 자체를 대신하지 않는다.
