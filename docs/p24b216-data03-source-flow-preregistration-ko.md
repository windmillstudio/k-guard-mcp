# P2.4B.2.16 data-03 Prisma raw-query source-flow 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW` - A-G 완료; TypeScript/Prisma source-tree identity만 승인  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)  
목표/종료 기준: [제품 목표 레지스트리](release-program-goal-register-ko.md)

## 한 문장 목표

`data-03` TypeScript/Prisma raw-query slot의 primary와 fixed-order reserve `vulnerable`, `fixed`,
`negative` source tree를 materialize하기 전에 query construction 역할과 비주장 경계를 고정한다.

## 고정 binding

- slot/scenario/oracle: `data-03` / `dev-data-03-raw-query` / `l3-gen-data-03-raw-query`
- plane/family/language/framework: `data` / `source-flow` / `typescript` / `prisma`; coverage tag `sql-rls`
- CWE/severity/profile: `CWE-89` / `high` / `deterministic-transform-v1`
- primary rank `0`: `src/data/checkout/orders.ts`, function `findOrderById`, parameter `id`, table `orders`,
  result `status`, static negative `orders-ready`
- reserve rank `1`: `src/data/integrations/providers.ts`, function `findProviderBySlug`, parameter `provider`,
  table `integrations`, result `endpoint`, static negative `integrations-ready`
- `vulnerable`은 parameter를 string-interpolated `prisma.$queryRawUnsafe` source condition에 넣는다.
  `fixed`는 `Prisma.sql` parameter binding을 가진 `prisma.$queryRaw` 호출만 사용한다. `negative`는 parameter와
  Prisma/database source 없이 static response 값만 반환한다.
- 각 tree는 MIT `LICENSE`, canonical `package.json`, 하나의 TypeScript/Prisma source만 포함한다.

## 명시적 비주장

이 카드는 TypeScript compiler, dependency install, Prisma runtime, database connection/query execution, SQLi exploit,
scanner finding, TP/FP/FN, recall, H100, release를 증명하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim과 primary/reserve source/function/parameter/table/static-text 사전등록 | `DONE` |
| B | `materialize_l3_source_flow_slot.py --slot-id data-03`의 Prisma raw-query immutable materializer와 generic comparator | `DONE` |
| C | receipt/source tamper, vulnerable/fixed role swap, root binding, staging-tree tamper, repository overlap, overwrite focused test | `DONE` - `5 passed` |
| D | external r1/r2 comparator | `DONE` - v2 r1/r2 `FIX`, semantic fingerprint `ff4fdca9b7ec7ab0d115d8348851694d2a7d961c51ad3553c868fcd81b32351d` |
| E | baseline, focused/full regression | `DONE` - baseline/current target, focused `20 passed`, full r1/r2 각 `2663 passed, 5 skipped, 0 failed, 0 errors` |
| F1/F2 | Claude, Grok, GLM two-run review | `DONE` - F1/F2 모두 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 lane `GO` |
| G | machine/supervisor comparator `FIX`와 비주장 기록 | `DONE` - supervisor semantic comparator `FIX`, fingerprint `0cb35770dd66726f469b0ec62a8e304c6281ae47f59a36e58f5e96b36c005823` |

## 시작 경계

Site-15의 G가 `FIX`로 닫힌 뒤에만 이 A 사전등록을 열었다. B 구현은 이 문서의 binding을 변경하지 않으며,
새 materializer는 `data-03`을 fallback 없이 명시적으로 지원해야 했다. 이후 slot을 추가할 때는
기존 materializer identity와 receipt 검증을 깨지 않는 별도 renderer identity를 추가해야 한다.

## Evidence lineage migration

초기 external r1은 materializer v1의 whole-module hash를 사용했다. 이후 공용 materializer에 다른 slot을
추가하면 관련 없는 기존 receipt까지 검증 불가가 되는 결함을 발견했다. 그 r1 evidence는 삭제하거나 D의
성공 근거로 재사용하지 않는다. v2는 공통 materialization contract, 해당 renderer 구현 hash, slot definition을
분리해 기록한다. v1은 `data-03`의 정확한 historical hash만 허용하고 현재의 staging binding, candidate,
root binding, byte-for-byte tree 검증도 모두 통과해야 읽을 수 있다.

공식 D 증거는 새 external root
`phase2-p24b216-data03-source-flow-20260724-r2/data03-v2-r1-r2-comparison.json`의 v2 r1/r2다.
기존 Site-15 v1 r1/r2는 `phase2-p24b216-evidence-lineage-20260724-r1/site15-v1-r1-r2-revalidation.json`에서
재검증했지만 `may_mark_field_fix=false`인 migration-only 결과다. 이 migration은 execution, scanner,
TP/FP/FN, H100, release를 새로 주장하지 않는다.

## 완료 증거와 다음 경계

E의 evidence-time target은 HEAD `04e9dd8e7dc788d8242db138278758303ba6f27d`와 같은 dirty-worktree
fingerprint에서 두 번 실행했다. baseline receipt hash는
`f781cd7ed40f60b0fb977e1ce4fbbb283cb79ddf84f6a3aa938425d87547df92`, focused regression receipt hash는
`15f4c6709515552c2625b8de7aa110ad64414e2dd17a61cca41048ae90dd1563`다. full r1/r2 receipt hash는 각각
`ac5e01c362d7685db530aed4a89a10d2b6ce883cb7f81612e97e5c997523787a`,
`94b49434c0499d4bde29a51b7287a4107d83359a68f6eddd5b3272a7c01a92a9`다.

F1/F2 supervisor packet은 같은 evidence-time target을 확인한 뒤 작성했다. Claude는 direct-file
attestation 5/5를 포함했고, Grok과 GLM에는 동등한 raw-free packet을 전달했다. 두 run 모두 세 lane이
`GO`였으며, 단일 review envelope의 `test_attestation_incomplete`는 full regression receipt가 packet에
없다는 runner-level 상태일 뿐 카드의 E 증거나 F lane 판정을 무효화하지 않는다. 이 차이는 comparator에
그대로 보존했다.

공식 external root는
`<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24b216-data03-source-flow-20260724-r2`다.
machine comparator는 `data03-v2-r1-r2-comparison.json`, supervisor comparator는
`supervisor-review-v2-r1-r2-comparison.json`이다. 이 `FIX_NARROW`는 Python/FastAPI `data-07`의 A
사전등록을 열 수 있게 할 뿐, TypeScript compiler, Prisma/database runtime, SQLi execution, scanner finding,
TP/FP/FN, recall, H100, release를 승인하지 않는다.
