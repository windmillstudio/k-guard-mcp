# P8.2E 제품 작업 카드 레지스트리 결속 사전등록

작성일: 2026-07-25  
상태: `FIX_NARROW` - A-G와 Claude/Grok/GLM two-run comparator 완료  
상위 카드: [목표 통제와 독립 검증 운영](release-program-goal-control-ko.md)  
사람이 읽는 입력: [제품 작업 카드 카탈로그](release-program-product-card-catalog-ko.md)

## 한 문장 목표

G1-G6의 남은 제품 작업이 큰 페이즈 제목이나 자유 문장에만 남지 않도록, 각 카드의
ID, 목표, 페이즈, 선행 조건, gate 상태, phase exit, Claude/Grok/GLM two-run review 의무를
canonical machine registry와 validator에 결속한다.

## A: 결과 전 고정한 계약

| 항목 | 고정 내용 |
| --- | --- |
| 대상 | `release-program-product-card-catalog-ko.md`에 적은 G1-G7 / P0-P8 제품 카드와 P8.2E 자체의 machine-readable registry, goal-state validator다. |
| positive | 모든 card는 고유 ID, G/P 관계, 선행 card, A-G 상태, standard 3AI two-run review profile, 비주장, 하나의 phase-exit 관계를 가진다. 현재 active card는 goal-state와 registry에서 정확히 하나이며 같은 ID/gate여야 한다. |
| negative | duplicate ID, 존재하지 않는 predecessor, 다른 G/P 관계, 비정상 gate prefix, review profile 누락, phase exit 누락 또는 중복, `FIX_NARROW`인데 A-G/3AI 조건이 없는 card, second active card를 validator가 거부한다. |
| replay | focused positive/negative tests, registry/goal-state two-run validation comparator, baseline/focused/full regression, Claude/Grok/GLM F1/F2를 새 target에서 수행한다. |
| failure handling | P8.2D의 invalid uppercase field ID packet과 Claude 180-second timeout receipt는 보존한다. registry validation 또는 한 review lane이라도 실패하면 P8.2E는 `HOLD`이며 다음 product card를 열지 않는다. |

## 명시적 비주장

이 카드는 탐지 규칙, scanner coverage, TP/FP/FN, High/Critical recall, 한국 개인정보 정확도,
Guardian 판정 품질, 실제 앱 실증, 설치 호환성, H100, release approval을 증명하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | registry schema, positive/negative, phase exit, claim boundary 사전등록 | `DONE` |
| B | machine-readable registry와 goal-state validator binding | `DONE` - canonical registry 110 cards, catalog SHA-256 binding, active/paused card drift와 phase exit을 goal-state validator가 검증 |
| C | schema, predecessor, gate, phase-exit, active-card negative focused tests | `DONE` - duplicate ID, unknown dependency, missing phase exit, fake FIX, catalog drift, active-card drift를 fail-closed로 검증 |
| D | external registry/goal-state validation r1/r2와 semantic comparator | `DONE` - r1/r2가 같은 110 cards, open 85, 9 phase exits와 target을 보고했고 comparator `FIX` |
| E | baseline, focused/full regression, target equality | `DONE` - E-1 baseline과 focused 17 passed가 같은 target equality를 통과했다. 첫 full은 2,789 passed/1 failed/5 skipped `CONTROL_HOLD`로 보존했고, 같은 target의 full-r2는 2,790 passed/5 skipped/0 failed로 `COMPLETE`였다. |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two-run review | `DONE` - r1/r2에서 세 lane이 모두 narrow `GO`를 냈고 semantic comparator가 `FIX`, `repeat_exact=true`를 기록했다. 단회 review의 반복 전 비승격 상태는 승격 근거에 사용하지 않았다. |
| G | comparator hash와 non-claim 기록 | `DONE` - machine comparator, regression receipts, supervisor comparator, 첫 full `CONTROL_HOLD`와 비주장을 아래에 함께 기록했다. |

## 재개 경계

P8.2E는 G까지 `FIX_NARROW`로 닫혔다. P8.2A도 G까지 `FIX_NARROW`로 닫혔고, API13이 유일한
`ACTIVE` 카드로 새 supervisor target E를 진행한다. 이 카드의 종료는
제품 탐지 성능이나 출하 `GO`를 추가로 주장하지 않는다.

## G: 종료 evidence와 비주장

- machine r1/r2 comparator: `9afc682e858fb4c8e8f837bfdf1f8e3194861365df8568a660bf8c44a67e731b`,
  `FIX`, `repeat_exact=true`.
- E-1 baseline: `63e69a707ed273b7db6c529c9b06c614067385b62c5ce5b330972b204aedae45`.
  focused receipt: `33fc2ff073d8f7f3496c0af314b6538f88e6e56dfef870ab6c12ee5dbd8999c1`.
- 첫 full `CONTROL_HOLD` receipt: `5f077adf7eb4d0f776736e583cbcc5a44f39e2f7c97d55a6db9b5e0d9931891e`.
  같은 target full-r2 `COMPLETE` receipt: `f0575aedf1693fd77a8ccfe2dbb9b0081f97cf148c3a7aab68e74674b73f2860`.
- Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 r1/r2 supervisor comparator:
  `c83a57d1e825d5b32ecc2bb5c342e4f7ea2e6f5ae5d7dbe5eb513fb709b01a58`,
  `FIX`, `repeat_exact=true`.

위 hash는 외부 evidence root의 raw-free receipt를 가리킨다. 이 종료는 registry 결속과
전이 통제만 승인한다. 탐지 규칙, scanner coverage, TP/FP/FN, High/Critical recall, 한국
개인정보 정확도, Guardian 판정 품질, 실제 앱 실증, 설치 호환성, H100, release approval은 모두
여전히 `HOLD`다.
