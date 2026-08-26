# P2.4B.2.17 data-07 FastAPI parameterized-query source-flow 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW` - A-G 완료; Python/FastAPI source-tree identity만 승인  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)  
목표/종료 기준: [제품 목표 레지스트리](release-program-goal-register-ko.md)

## 한 문장 목표

`data-07` Python/FastAPI parameterized-query slot의 primary와 fixed-order reserve `vulnerable`, `fixed`,
`negative` source tree를 materialize하기 전에 path input, SQL construction, fixed boundary와 비주장 경계를
고정한다.

## 고정 binding

- slot/scenario/oracle: `data-07` / `dev-data-07-parameterized-query` /
  `l3-gen-data-07-parameterized-query`
- plane/family/language/framework: `data` / `source-flow` / `python` / `fastapi`; coverage tag `sql-rls`
- CWE/severity/profile: `CWE-89` / `high` / `deterministic-fixture-v1`
- primary rank `0`: `app/api/checkout/orders.py`, function `get_order_by_id`, route `/orders/{order_id}`,
  parameter `order_id`, table `orders`, result `status`, static negative `orders-ready`
- reserve rank `1`: `app/api/integrations/providers.py`, function `get_provider_by_slug`, route
  `/integrations/{provider}`, parameter `provider`, table `integrations`, result `endpoint`, static negative
  `integrations-ready`
- `vulnerable`은 FastAPI path parameter를 SQLite `connection.execute` SQL f-string에 보존한다. `fixed`는
  같은 parameter를 `?` placeholder와 tuple argument로만 전달한다. `negative`는 path parameter와 database
  source 없이 static JSON response만 반환한다.
- 각 tree는 MIT `LICENSE`, canonical `pyproject.toml`, 하나의 Python/FastAPI source만 포함한다.

## 명시적 비주장

이 카드는 Python compile, dependency install, FastAPI runtime, SQLite/database connection/query execution,
SQLi exploit, scanner finding, TP/FP/FN, recall, H100, release를 증명하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim과 primary/reserve source/route/function/parameter/table/static-text 사전등록 | `DONE` |
| B | `materialize_l3_source_flow_slot.py --slot-id data-07`의 FastAPI parameterized-query immutable renderer와 generic comparator | `DONE` - renderer-scoped identity와 Data-03 identity regression guard |
| C | receipt/source tamper, vulnerable/fixed role swap, root binding, staging-tree tamper, repository overlap, overwrite focused test | `DONE` - focused target suite `35 passed` |
| D | 새 external root r1/r2 comparator | `DONE` - `FIX`, semantic fingerprint `59d97d25a8972fc758bbd0fa00dea557ae0e21b7352188fd80977258bb035aec` |
| E | baseline, focused/full regression | `DONE` - focused `35 passed`, full r2/r3 각 `2669 passed, 5 skipped, 0 failed, 0 errors` |
| F1/F2 | Claude, Grok, GLM two-run review | `DONE` - F1/F2 모두 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 lane `GO` |
| G | machine/supervisor comparator `FIX`와 비주장 기록 | `DONE` - supervisor semantic comparator `FIX`, fingerprint `5ddced36cccbcd4a2aa5bbb44a6df349b792d1173369b38bb03f0189ad17c556` |

## 시작 경계

Data-03의 G가 `FIX`로 닫힌 뒤에만 이 A 사전등록을 열었다. B는 이 문서의 binding을 변경하지 않으며,
기존 slot으로 fallback하지 않는 `data-07` 전용 renderer와 renderer-scoped materializer identity를 추가해야 한다.
Data-03의 v1/v2 receipt, comparator, supervisor evidence는 Data-07의 성공 근거가 아니다.

## 완료의 의미

이 leaf는 primary/reserve source triplet의 tree identity만 검증한다. Python/FastAPI/SQLite 실행, 실제 query
parameterization 효과, SQLi 탐지, 한국 개인정보 처리, detector accuracy, H100, release는 이후 별도 oracle과
측정 카드에서만 다룬다.

## 완료 증거와 다음 경계

공식 external root는
`<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24b217-data07-source-flow-20260724-r2`다.
machine comparator `data07-r1-r2-comparison.json`은 materializer identity
`d6adff11f104c943640e83e752fccc8626be11297ff781acfdaabc27b9071981`와 semantic fingerprint
`59d97d25a8972fc758bbd0fa00dea557ae0e21b7352188fd80977258bb035aec`를 기록했다. Data-03 identity는 focused
regression에서 이전 sealed hash `0ee88866766e7b78f4f7b45859dd5bafa15d108d6b49f745db62e1f3334dd99f`로 유지됐다.

E의 evidence-time target baseline receipt는
`ee2985c07344ceab63205516d90c63d69aa69f46a69d3585fd5933cb0d8dcdec`, focused receipt는
`0e7496d1b76ff576baa392e6848121e59e12a0390979492bb5032dbd6f8a0b30`다. full r2/r3 receipt는 각각
`82c4dcb7cb70e305536157f611423cc8818c25737e84fde583c47e284743ac87`,
`938d9e069ae29cd904e6915f38c1c1d3099c725c722bdffcd1714052118e9ef4`다. 앞선 full r1은 goal-state active card
expectation 두 건이 stale해 `CONTROL_HOLD`였고, 원인 수정 후 target이 바뀌었으므로 이 promotion evidence에는
사용하지 않았다. r1 receipt `e61df74230576da3cfeef43c2aee5a465891160b36abc676273be5c44c8e1206`는 삭제하지 않고 보존한다.

F1의 첫 output directory는 upper-case field ID가 runner input validation에서 거부된 pre-provider 기록이다. 실제
F1/F2는 `supervisor-review-v1-r2`, `supervisor-review-v1-r3`이며 모든 lane `GO`, target unchanged였다.
`supervisor-review-v1-r2-r3-comparison.json`은 `FIX`, semantic fingerprint
`5ddced36cccbcd4a2aa5bbb44a6df349b792d1173369b38bb03f0189ad17c556`다. top-level single-run
`test_attestation_incomplete`은 F2 전 반복 gap을 정직하게 남기는 runner 상태이며, F1/F2 comparator가 그 동일한
nonblocking gap과 세 lane의 `GO`를 비교해 `FIX`를 결정했다.

이 `FIX_NARROW`는 Java/Spring `data-09`의 A 사전등록만 열 수 있다. Python/FastAPI/SQLite runtime, SQLi execution,
scanner finding, TP/FP/FN, recall, Korean privacy coverage, H100, release는 계속 승인하지 않는다.
