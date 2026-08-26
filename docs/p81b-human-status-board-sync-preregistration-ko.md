# P8.1B 현재 상태 운영판 동기화 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW` - initial D `HOLD` 보존, corrective B/C와 revised D-E-F1/F2-G 완료  
상위 목표: G7 목표 통제와 독립 검증 운영

## 한 문장 목표

canonical `goal-state JSON`의 유일한 active card와 사람이 읽는 세 운영판의 현재 카드, 완료 gate,
다음 gate를 기계적으로 일치시킨다.

## A: 결과 전 고정한 계약

- 대상 문서는 `release-program-current-work-breakdown-ko.md`, `release-program-execution-map-ko.md`,
  `release-program-goal-register-ko.md` 세 개뿐이다.
- 각 문서는 `release-program-current-card` marker를 정확히 한 번 포함하고, active card ID, status,
  completed gates, next gate가 canonical JSON과 같아야 한다.
- marker 누락, 중복, stale 값, path escape, symlink, UTF-8 decode 오류는 모두 `HOLD`다.
- 이 카드는 사람이 읽는 현재 상태와 기계 상태의 동기화만 주장한다. evidence receipt binding,
  phase packet, 탐지 성능, TP/FP/FN, Guardian, H100, release를 주장하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | 대상 문서, marker fields, 비주장, resume order 사전등록 | `DONE` |
| B | validator와 repeat comparator가 같은 summary schema를 결속 | `DONE` - `human_status_boards` schema binding 추가 |
| C | 정상 marker와 stale marker 및 changed-board-set 거부 focused test | `DONE` - focused suite `12 passed` |
| D | external raw-free goal-state evidence 두 번 생성과 semantic comparison | `DONE` - initial r1/r2 `HOLD` 보존, revised r3/r4 comparator `FIX` |
| E | current target full regression, state repeat, compatibility | `DONE` - focused `12 passed`; full `2702 passed, 5 skipped, 0 failed` |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two-run review | `DONE` - 두 run 전 lane `GO`; supervisor comparator `FIX` |
| G | evidence hash, comparator, 비주장 기록 | `DONE` - 아래 evidence와 narrow claim 기록 |

## 재개 규칙

`P2.4B.3.02 api-02`가 G까지 닫혀 이 카드가 유일한 active card가 됐다. initial D는 external
r1/r2 output을 생성했지만 repeat comparator가 새 `human_status_boards` field를 옛 schema로 거부했다.
이 `HOLD`는 보존한다. comparator와 changed-board-set negative test를 결속한 새 target에서 B/C를
재완료했고 D를 다시 수행했다. P8.1B만 `FIX_NARROW`이며 P8 phase 완료를 주장하지 않는다.

## D-G evidence와 비주장

- revised machine comparator: `phase8-p81b-status-board-sync-20260724\\p81b-r3-r4-comparison.json`,
  SHA-256 `03138e25524b1148d6bfbb1244a04daa94985f30e70691eb65aed83893b9423b`, `repeat_exact=true`, `status=FIX`
- current baseline: `...-r5\\baseline.json`, SHA-256
  `70216cb075381029e747b5cd77fc1043d589e62ae00b3684bee43540f3c243d5`
- focused/full attestation: SHA-256
  `1d9d9bc77adb4ca9951e0e0c026ce3f90e7562c128916703fcc0fc42baa11de5` / `37e3bf4bca677af1b2cf8dd9da8a44937d4acf9329ebbcad101c6e2a719e5f06`
- supervisor health: SHA-256 `19ab3e27c66db837d86ec7692883892dfa8b1cd31dc801a843b9083a42d33431`
- F1/F2 supervisor comparator: `phase8-p81b-status-board-sync-20260724\\p81b-supervisor-r1-r2-comparison.json`,
  SHA-256 `d4df10965bd2daa4d32f7b2a119be6ea03801b46377882a7b60064485bfc45c5`, semantic fingerprint
  `e1a4b2087043efb3c1ee6de03ca95f2e2547b6f1a9c473b1085f04c2cdfcfe93`, `repeat_exact=true`, `status=FIX`

이 결과는 canonical JSON과 세 사람이 읽는 운영판의 active card/gate/next gate marker가 같은지를
fail-closed로 확인하는 능력만 닫는다. receipt-link binding, phase completion, 탐지 성능, TP/FP/FN,
H100, Guardian, release는 계속 별도 카드의 `HOLD`다.
