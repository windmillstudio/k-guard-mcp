# P8.2D GLM health terminal contract 사전등록

작성일: 2026-07-25  
상태: `FIX_NARROW` - A-G와 Claude/Grok/GLM two-run comparator `FIX`  
상위 카드: [목표 통제와 독립 검증 운영](release-program-goal-control-ko.md)

## 한 문장 목표

Windows native Cline GLM health lane이 source-free health JSON을 가끔 parse 불가한 자유 형식으로
끝내지 않도록, 기존 raw-free terminal contract를 `--system`으로도 명시해 strict parser를 약화하지
않고 반복 가능한 health receipt를 만든다.

## 시작 전 관찰과 범위

P8.2A current-target D의 첫 health receipt는 Grok `BLOCKED_PROVIDER`였고 retry-r1은 세 lane
`HEALTHY`였지만 retry-r2에서 GLM은 exit 0과 함께 terminal parser가 거부되어 `BLOCKED_PROVIDER`가
됐다. 세 receipt는 삭제하지 않는다.

동일 native Cline executable에 user prompt만 준 transient diagnostic은 정상 JSON을 반환했고, 같은
terminal-only 계약을 `--system`으로 추가한 3회 transient check도 모두 strict parser를 통과했다.
이 관찰은 결과가 아니라 B 가설의 근거다.

## A: 결과 전 고정한 계약

| 항목 | 고정 내용 |
| --- | --- |
| 대상 | `check_external_supervisor_health.py`의 GLM/Cline `--json --plan` source-free health lane만 대상이다. |
| positive | `--system`은 정확한 expected JSON, no tools, no plan, no explanation을 같은 terminal contract로 명시한다. strict parser는 하나의 `run_result`와 exact object만 계속 허용한다. |
| negative | parser가 prose, fenced JSON, 복수 `run_result`, 누락 필드, 다른 object를 건강으로 승격하지 않는다. provider/model fallback, raw output persistence, retry 성공만으로 release claim은 금지한다. |
| replay | focused tests, current-target health r1/r2 semantic comparator, baseline/focused/full regression, Claude/Grok/GLM F1/F2를 새 target에서 수행한다. |
| failure handling | P8.2A D의 Grok/GLM blocked receipts는 보존한다. 새 retry pair 중 하나라도 unhealthy이거나 comparator가 `FIX`가 아니면 이 카드는 `HOLD`다. |

## 명시적 비주장

이 카드는 GLM health terminal formatting만 다룬다. provider 장기 가용성, 모델 판단 품질, native
transport 전체, product security, API/DB/개인정보 탐지, TP/FP/FN, Guardian, 설치 완결성, 출하 승인을
증명하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | contract, positive/negative, non-claim, preserved failure 사전등록 | `DONE` |
| B | GLM health `--system` terminal contract binding | `DONE` - expected JSON, no tools, no plan, no explanation을 system contract에 결속 |
| C | system/strict parser/negative focused tests | `DONE` - health focused 8 passed; extra field, fenced JSON, duplicate terminal result는 건강으로 승격하지 않음 |
| D | current-target health r1/r2와 semantic comparator | `DONE` - r1/r2 모두 Claude/Grok/GLM `HEALTHY`, comparator `FIX`, semantic fingerprint `03038067812c00824a01bf958d00780c8cdd47caa7235544020e8224318bb503` |
| E | baseline, focused/full regression, target equality | `DONE` - E-0와 F1-bound E-1 모두 baseline, focused 49 passed, full 2,785 passed/5 skipped/0 failed, control error와 target drift 없음. |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two-run review | `DONE` - r2/r3 모두 세 lane `GO`; Claude는 6 direct file attestation, supervisor comparator `FIX` |
| G | comparator hash와 non-claim 기록 | `DONE` - 아래 D/E/F evidence와 comparator를 결속; 이 카드의 명시적 비주장은 유지 |

## 재개 경계

P8.2D는 `FIX_NARROW`로 닫혔지만 P8.2E product-card registry binding이 G까지 끝나기 전에는
P8.2A D와 API13을 재개하지 않는다. P8.2D의 code 또는 status target이 바뀌면 P8.2A는 D부터,
API13은 E부터 새 evidence를 만든다.

## D evidence

- r1/r2: `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase8-p82d-glm-health-terminal-contract-20260725-r1.json`,
  `...-r2.json` - 세 lane 모두 `HEALTHY`
- comparison: `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase8-p82d-glm-health-terminal-contract-20260725-r1-r2-comparison.json`
  - status `FIX`, semantic fingerprint `03038067812c00824a01bf958d00780c8cdd47caa7235544020e8224318bb503`, file SHA-256
    `ae4a30f55a6f339e74bb60bec4ffa23d327214bf52f2ed0e37eba1064880b5b3`

## E evidence

E-0은 A-D target에서 만든 baseline, focused 49 passed, full 2,785 passed/5 skipped/0 failed bundle이다.
상태가 A-E로 전이해 target이 바뀌었으므로 F1/F2에는 사용하지 않고 보존했다.

F1-bound E-1은 A-E target에서 다시 실행했다.

- baseline: `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase8-p82d-glm-health-terminal-contract-20260725-f1-baseline.json`
  - receipt file SHA-256 `d98b830beba38b19f6b50981d7aba70e76a7f9f316bf65db28e74d8b0412ed3a`
- focused: `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase8-p82d-glm-health-terminal-contract-20260725-f1-focused\\regression-attestation.json`
  - 49 passed, file SHA-256 `57592c73e3d2310a1c56fec36ad077c36e652cf2290e02047fea84a96e1bf414`
- full: `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase8-p82d-glm-health-terminal-contract-20260725-f1-full\\regression-attestation.json`
  - 2,785 passed / 5 skipped / 0 failed in 1,147,016 ms, file SHA-256
    `cd7d435a574d5d2fb6be97198333cc9bebc766e629d772a11db18cd83ab87e57`

## F/G evidence

- preserved preflight failure: uppercase `P8.2D` field ID packet was rejected by the receipt validator before a
  valid decision bundle; output directory `...\\supervisor-review-v1-r1` is retained.
- preserved provider failure: `...\\supervisor-review-v1-r1-retry` has Claude `BLOCKED_TIMEOUT` at 180 seconds,
  while Grok and GLM returned `GO`. It is not a promotion input.
- clean F1/F2: `...\\supervisor-review-v1-r2` and `...\\supervisor-review-v1-r3` both have Claude/Grok/GLM `GO`;
  Claude directly attested all 6 declared files in both runs.
- comparator: `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase8-p82d-glm-health-terminal-contract-20260725-supervisor-review-v1-r2-r3-comparison.json`
  - status `FIX`, semantic fingerprint `82f0e7eccf07919cf7e8649dc0ed114af5000e0646dfc8732176b9bc1dfd1101`, file SHA-256
    `4d0918d826ef3f16efa47cb211fe50fd82024c169be7349d4d47358136977b04`
