# P2.4B.2.20 source-flow 19-slot aggregate 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW` - A-G 완료, 다음 `P2.4B.3.01` A 열림  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)  
목표/종료 기준: [제품 목표 레지스트리](release-program-goal-register-ko.md)

## 한 문장 목표

이미 독립적으로 닫힌 19개 `source-flow` leaf의 raw-free materialization/comparator/supervisor evidence를
고정 순서 manifest로 결속하고, 누락 또는 제외가 있으면 fail-closed로 `HOLD`한다.

## 고정 denominator와 binding

- slot order: `site-01`부터 `site-15`, `data-03`, `data-07`, `data-09`, `data-14`
- denominator: slot `19`, candidate `38`, primary `19`, reserve `19`, source triplet `114`, source file `342`
- leaf admission: 각 slot은 source r1/r2 comparator `FIX`, F1/F2 Claude Opus 4.8/Grok 4.5/Cline GLM 5.2 lane `GO`,
  supervisor comparator `FIX`를 모두 가져야 한다.
- exclusion: `excluded_slot_ids`는 반드시 빈 배열이다. 누락 leaf, 중복 slot, 잘못된 slot order, comparator `HOLD`,
  raw source returned, evidence path overlap은 aggregate `HOLD`다.
- output: source content, exploit input, secret, URL, provider raw output 없이 slot ID, canonical evidence digest,
  comparator status와 raw-free claim boundary만 기록한다.

## 명시적 비주장

이 카드는 19개 source tree identity evidence의 inventory completeness만 증명한다. compiler/runtime execution,
SQLi exploitability, scanner finding, TP/FP/FN, recall, specificity, 한국 개인정보 정확도, H100, release를 증명하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | denominator, fixed slot order, per-leaf admission, exclusion `0`, raw-free/non-claim 사전등록 | `DONE` |
| B | aggregate manifest writer와 strict evidence locator/validator | `DONE` - `aggregate_l3_source_flow.py` |
| C | missing/duplicate/order drift, wrong comparator status, raw/path leakage, overwrite focused test | `DONE` - aggregate/comparator focused `6 passed` |
| D | 새 external aggregate r1/r2 comparator | `DONE` - external comparator `FIX`, semantic fingerprint `228f6202be3ac1109c86ce0ad71d82e8e1b8ca2c18c4181c382d12e964655ca6` |
| E | baseline, focused/full regression | `DONE` - baseline, focused `15 passed`, full r1 `CONTROL_HOLD` 보존, full r2/r3 각각 `2687 passed, 5 skipped` |
| F1/F2 | Claude, Grok, GLM two-run review | `DONE` - 두 run 모두 세 lane `GO`, top-level unpromoted `HOLD` 보존 |
| G | machine/supervisor comparator `FIX`와 비주장 기록 | `DONE` - supervisor comparator `FIX`, fingerprint `39b4f9c7fadbe77bc41d9bb769a455fb7101ca37d23053895b68e31ef98827ae` |

## 시작 경계

Data-14의 G가 `FIX`로 닫힌 뒤에만 이 A 사전등록을 열었다. B는 이미 종료된 19개 leaf의 source를 다시
materialize하거나 runtime을 실행하지 않는다. 오직 raw-free evidence binding과 completeness만 검증한다.

## 완료의 의미

aggregate `FIX_NARROW`는 P2.4B.2 source-flow materialization denominator가 누락 없이 결속됐다는 뜻뿐이다.
제품 탐지 성능, 특정 취약점의 적중률, 실제 앱 안전성, 출하 승인은 이후 독립 측정 카드의 책임이다.

## A-D 결과 기록

- B: [aggregate writer/validator](../scripts/aggregate_l3_source_flow.py)는 고정 slot order, exact denominator,
  raw-free output, external-only input/output, 모든 source/supervisor evidence 경로의 전역 중복 거부를
  fail-closed로 강제한다.
- C: [focused tests](../tests/test_aggregate_l3_source_flow.py)와
  [repeat comparator tests](../tests/test_compare_l3_source_flow_aggregate_repeats.py)는 missing/order/raw/scope/
  overwrite/tamper/semantic-drift를 각각 `HOLD`하는지 검증했다.
- D: external `r1`/`r2` aggregate의 file hash와 aggregate hash는 같았고, comparator는 `FIX`,
  `repeat_exact=true`, `raw_returned=false`, exclusion `0`을 기록했다. 이 결과의 semantic fingerprint는
  `228f6202be3ac1109c86ce0ad71d82e8e1b8ca2c18c4181c382d12e964655ca6`이다.

E의 baseline receipt는 `46cf1c2c8a5e9054d5176df325ff226ce5b794cd6b739c50d46d2f26af450f50`, focused receipt는
`d0c1171312ace848241c604a1b3bbcb92357b3cda87a6136e2073a8d9ed3b5fd`다. full r1
`CONTROL_HOLD` receipt `2965289483a239b67001110ebea9833dee8fcdbc78dd08c1bdabe85f3f89bc62`는 삭제하지 않았다.
같은 target의 clean full r2/r3 receipt는 각각
`01c7f3d64e496e589629f5554a58a4ec78ec03b640a7eecf4196e8e2262e5bc3`,
`da95d19c386910c11f7538f1a9ecbf2978d2dfb6f13eaca02dcfc3f0ece700ea`다.

F1/F2의 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 lane은 모두 `GO`였고 target unchanged였다.
단회 run의 top-level `HOLD`는 repeat comparator 전의 `test_attestation_incomplete` 상태로 보존했다.
두 run의 supervisor comparator `FIX`가 위 G fingerprint를 기록했다.
