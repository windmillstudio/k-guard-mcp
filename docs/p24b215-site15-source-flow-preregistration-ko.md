# P2.4B.2.15 site-15 SQL builder source-flow 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW`  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)  
목표/종료 기준: [제품 목표 레지스트리](release-program-goal-register-ko.md)

## 한 문장 목표

`site-15` Go/chi SQL builder slot의 primary와 fixed-order reserve `vulnerable`, `fixed`, `negative`
source tree를 materialize하기 전, source path와 query construction 역할을 고정한다.

## 고정 binding

- slot/scenario/oracle: `site-15` / `dev-site-15-sql-builder` / `l3-gen-site-15-sql-builder`
- plane/family/language/framework: `site` / `source-flow` / `go` / `chi`; coverage tag `express`
- CWE/severity/profile: `CWE-89` / `critical` / `deterministic-transform-v1`
- primary rank `0`: `internal/checkout/orders.go`, handler `orderLookup`, route `/orders`, parameter `id`,
  table `orders`, result `status`, static negative `orders-ready`
- reserve rank `1`: `internal/integrations/providers.go`, handler `providerLookup`, route `/integrations`, parameter
  `provider`, table `integrations`, result `endpoint`, static negative `integrations-ready`
- `vulnerable`은 request parameter를 `fmt.Sprintf` SQL string에 넣는 source condition을 보존한다.
  `fixed`는 placeholder와 args를 가진 database API 호출만 사용한다. `negative`는 parameter와 database source 없이
  static response만 반환한다.
- 각 tree는 MIT `LICENSE`, canonical `go.mod`, 하나의 Go/chi handler source만 포함한다.

## 명시적 비주장

이 카드는 Go compiler, dependency download, chi runtime, DB connection/query execution, SQLi exploit,
scanner finding, TP/FP/FN, recall, H100, release를 증명하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim과 primary/reserve source/route/parameter/table/static-text 사전등록 | `DONE` |
| B | `materialize_l3_source_flow_slot.py --slot-id site-15`의 Go/chi SQL builder immutable materializer와 generic comparator | `DONE` |
| C | receipt/source tamper, vulnerable/fixed role swap, root binding, staging-tree tamper, repository overlap, overwrite focused test | `DONE` - `5 passed` |
| D | external r1/r2 comparator | `DONE` - `FIX`, semantic fingerprint `0c3643ac941661db1a40c7797f15af67a800d79893408e0ebd269eb6476d2beb` |
| E | baseline, focused/full regression | `DONE` - focused 5/5, full r1/r2 각각 2,655 passed, 5 skipped, 0 failed, 0 errors |
| F1/F2 | Claude, Grok, GLM two-run review | `DONE` - 두 run 모두 세 lane `GO`, Claude direct-file 5/5 |
| G | machine/supervisor comparator `FIX`와 비주장 기록 | `DONE` - repeat exact, comparator `FIX` |

## 완료 evidence

- D: external materialization comparator `FIX`, semantic fingerprint
  `0c3643ac941661db1a40c7797f15af67a800d79893408e0ebd269eb6476d2beb`.
- E: baseline `bb2a3052359ae13cc388efeac60119493935f2e06bba635075be97dfc5cdd8cf`; focused
  `e21915af65fa365bbe217257d1b592ce668a80cef278b98e17fb7fc22de16201`; full r1/r2
  `f872553e0f7faa883100547b321e14850cbdf472ab80195c3fa009f04a63456a`,
  `c163f6409ffc320848acb73c6157da36fcf1b68c419d0c93bd4c693b74348d2c`.
  첫 focused CLI는 Windows backslash selector를 pre-receipt 단계에서 거부해 실행 receipt를 만들지 못했고,
  성공 근거에 쓰지 않았다. POSIX selector로 만든 별도 external run만 E evidence에 사용했다.
- F/G: Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 모두 F1/F2 lane `GO`; supervisor semantic fingerprint
  `3a7b5ed4835b707915f6fc839db2d84e496458e43631ebcd7ccb0265610675c8`, comparator `FIX`.

이 결과는 source tree identity와 그 evidence contract만 뜻한다. Go compiler, chi/DB runtime, SQLi execution,
scanner detection, TP/FP/FN, H100, release는 여전히 비주장이다. Data-03과 Data-07도 A-G를 `FIX_NARROW`로
닫았고, 다음 active는 A를 사전등록한 [`P2.4B.2.18 data-09`](p24b218-data09-source-flow-preregistration-ko.md)이며,
B Spring JDBC concat renderer/comparator를 진행한다.

## v1 evidence lineage 재검증

Data-03 추가 뒤 공용 materializer의 whole-module hash가 바뀌어 v1 receipt가 불필요하게 무효화되는 결함을
발견했다. v2는 slot/renderer-specific identity를 사용하고, 이 카드의 historical v1 hash만 explicit allowlist로
읽는다. external `site15-v1-r1-r2-revalidation.json`은 두 기존 receipt의 staging binding, candidate,
root binding, byte-for-byte tree를 다시 검증해 semantic equality를 확인했다. authority는
`may_revalidate_legacy_evidence=true`, `may_mark_field_fix=false`다. 따라서 이 결과는 기존 `FIX_NARROW`를
새로 승격하거나 범위를 넓히지 않는다.
