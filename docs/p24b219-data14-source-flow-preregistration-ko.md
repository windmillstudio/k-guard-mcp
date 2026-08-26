# P2.4B.2.19 data-14 Go pgx query-format source-flow 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW` - A-G 완료; Go/pgx source-tree identity만 승인  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)  
목표/종료 기준: [제품 목표 레지스트리](release-program-goal-register-ko.md)

## 한 문장 목표

`data-14` Go/pgx query-format slot의 primary와 fixed-order reserve `vulnerable`, `fixed`, `negative`
source tree를 materialize하기 전에 request path input, PostgreSQL query construction, placeholder boundary와
비주장 경계를 고정한다.

## 고정 binding

- slot/scenario/oracle: `data-14` / `dev-data-14-query-format` / `l3-gen-data-14-query-format`
- plane/family/language/framework: `data` / `source-flow` / `go` / `pgx`; coverage tag `sql-rls`
- CWE/severity/profile: `CWE-89` / `high` / `deterministic-template-v1`
- primary rank `0`: `internal/checkout/invoices.go`, package `checkout`, function `FindInvoiceByNumber`, route
  `/invoices/{number}`, parameter `number`, table `invoices`, result `amount`, static negative `invoices-ready`
- reserve rank `1`: `internal/catalog/products.go`, package `catalog`, function `FindProductBySKU`, route
  `/products/{sku}`, parameter `sku`, table `products`, result `price`, static negative `products-ready`
- `vulnerable`은 Go path parameter를 `fmt.Sprintf` SQL string에 보존하고 pgx `QueryRow`에 전달한다. `fixed`는
  PostgreSQL `$1` placeholder와 별도 argument만 사용한다. `negative`는 request input과 pgx/database source 없이
  static response만 반환한다.
- 각 tree는 MIT `LICENSE`, canonical `go.mod`, 하나의 Go/pgx source만 포함한다.

## 명시적 비주장

이 카드는 Go compile, module download, pgx/PostgreSQL connection/query execution, SQLi exploit, scanner finding,
TP/FP/FN, recall, H100, release를 증명하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim과 primary/reserve source/package/function/route/parameter/table/static-text 사전등록 | `DONE` |
| B | `materialize_l3_source_flow_slot.py --slot-id data-14`의 Go pgx query-format immutable renderer와 generic comparator | `DONE` - renderer-scoped identity와 기존 Data-09 identity regression guard |
| C | receipt/source tamper, vulnerable/fixed role swap, root binding, staging-tree tamper, repository overlap, overwrite focused test | `DONE` - focused target suite `47 passed` |
| D | 새 external root r1/r2 comparator | `DONE` - `FIX`, semantic fingerprint `3b3578c6904748ab9c788b23eacb108a5af09dee6cadda3a9a7a89346bef5707` |
| E | baseline, focused/full regression | `DONE` - baseline, focused `47 passed`, full r1/r2 각 `2681 passed, 5 skipped, 0 failed, 0 errors` |
| F1/F2 | Claude, Grok, GLM two-run review | `DONE` - F1/F2 모두 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 lane `GO` |
| G | machine/supervisor comparator `FIX`와 비주장 기록 | `DONE` - supervisor semantic comparator `FIX`, fingerprint `f68c78f5284c19ff40d37bebc805356b9398758af3c4b7f5c930fdc3dea1cae0` |

## 시작 경계

Data-09의 G가 `FIX`로 닫힌 뒤에만 이 A 사전등록을 열었다. B는 이 문서의 binding을 변경하지 않고,
기존 renderer로 fallback하지 않는 `data-14` 전용 Go/pgx query-format renderer와 renderer-scoped materializer
identity를 추가했다. Data-09의 receipt, comparator, supervisor evidence는 Data-14의 성공 근거가 아니다.

## 완료의 의미

이 leaf는 primary/reserve source triplet의 tree identity만 검증한다. Go/pgx/PostgreSQL 실행, 실제 query
parameterization 효과, SQLi 탐지, 한국 개인정보 처리, detector accuracy, H100, release는 이후 별도 oracle과
측정 카드에서만 다룬다.

## 완료 증거와 다음 경계

공식 external root는 `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b219-data14-source-flow-20260724`다.
machine comparator `data14-r1-r2-comparison.json`은 `FIX`, `repeat_exact: true`, materializer identity
`a5ee02a88f41e89a4cd113f2ee8c6816132c28d8fb85a2eb041a4365a615bb6d`, semantic fingerprint
`3b3578c6904748ab9c788b23eacb108a5af09dee6cadda3a9a7a89346bef5707`를 기록한다. raw source는 반환하지 않는다.

C의 focused suite는 goal-state validator, generic/source-slot comparator, Site-15, Data-03, Data-07, Data-09, Data-14의
materialization과 repeat contract를 함께 실행해 `47 passed`였다. E는 이 문서와 구현을 포함한 target을 새로
baseline으로 봉인한 뒤 focused 및 full regression을 서로 다른 external run directory에서 실행했다.

E baseline receipt는 `9c3c04baa3165c8bb3f448f023bace5d4b9f2a216b87e1e4dd97aa63ad6380e6`, focused receipt는
`647d1bd22d5ef578e03d37cf5518d6b001696ec550fb269820daf9ef078a0715`다. full r1/r2 receipt는 각각
`7e95c49a24586438a6df5552829e75f427ff7730699074660edac3ea011c2e40`,
`d727e68657e99d20213e56754ec4d0bf1502613e00a42e3097b7c9e12a1fbb62`다. 네 evidence 모두 target
`04e9dd8e7dc788d8242db138278758303ba6f27d`와 dirty-worktree fingerprint
`04bceb439517b8b0b8fa05c710be113d060233499b1a71d1575783d6df671564`를 가리킨다.

F1/F2의 official external output directory는 각각 `supervisor-review-v1-r1`, `supervisor-review-v1-r2`다. 두 run의
Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 lane은 모두 `GO`였고 target unchanged였다. 각 single run의 top-level
`HOLD`는 F2 전 `test_attestation_incomplete`를 정직하게 보존하는 runner 상태이며, two-run comparator
`supervisor-review-v1-r1-r2-comparison.json`이 그 동일한 nonblocking gap과 세 lane `GO`를 비교해 `FIX`를 결정했다.

이 `FIX_NARROW`는 19-slot source-flow aggregate의 A 사전등록만 열 수 있다. Go/pgx/PostgreSQL runtime, SQLi scanner,
TP/FP/FN, H100, release는 여전히 승인하지 않는다.
