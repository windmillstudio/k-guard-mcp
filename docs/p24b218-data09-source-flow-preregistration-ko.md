# P2.4B.2.18 data-09 Spring JDBC concat source-flow 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW` - A-G 완료; Java/Spring JDBC source-tree identity만 승인  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)  
목표/종료 기준: [제품 목표 레지스트리](release-program-goal-register-ko.md)

## 한 문장 목표

`data-09` Java/Spring JDBC concat slot의 primary와 fixed-order reserve `vulnerable`, `fixed`, `negative`
source tree를 materialize하기 전에 request path input, JDBC query construction, prepared-statement boundary와
비주장 경계를 고정한다.

## 고정 binding

- slot/scenario/oracle: `data-09` / `dev-data-09-jdbc-concat` / `l3-gen-data-09-jdbc-concat`
- plane/family/language/framework: `data` / `source-flow` / `java` / `spring`; coverage tag `sql-rls`
- CWE/severity/profile: `CWE-89` / `high` / `deterministic-transform-v1`
- primary rank `0`: `src/main/java/com/kguard/checkout/OrdersController.java`, class `OrdersController`, method
  `findOrderById`, route `/orders/{id}`, parameter `id`, table `orders`, result `status`, static negative
  `orders-ready`
- reserve rank `1`: `src/main/java/com/kguard/integrations/ProvidersController.java`, class `ProvidersController`,
  method `findProviderBySlug`, route `/integrations/{provider}`, parameter `provider`, table `integrations`, result
  `endpoint`, static negative `integrations-ready`
- `vulnerable`은 Spring path parameter를 JDBC `Statement.executeQuery` concatenated SQL source condition에 넣는다.
  `fixed`는 `PreparedStatement`의 `?` placeholder와 `setString`만 사용한다. `negative`는 path parameter와
  JDBC/database source 없이 static `ResponseEntity`만 반환한다.
- 각 tree는 MIT `LICENSE`, canonical `pom.xml`, 하나의 Java/Spring controller source만 포함한다.

## 명시적 비주장

이 카드는 Java compiler, Maven dependency download, Spring runtime, JDBC/database connection/query execution,
SQLi exploit, scanner finding, TP/FP/FN, recall, H100, release를 증명하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim과 primary/reserve source/class/method/route/parameter/table/static-text 사전등록 | `DONE` |
| B | `materialize_l3_source_flow_slot.py --slot-id data-09`의 Spring JDBC concat immutable renderer와 generic comparator | `DONE` - renderer-scoped identity와 기존 Data-07 identity regression guard |
| C | receipt/source tamper, vulnerable/fixed role swap, root binding, staging-tree tamper, repository overlap, overwrite focused test | `DONE` - focused target suite `41 passed` |
| D | 새 external root r1/r2 comparator | `DONE` - `FIX`, semantic fingerprint `90ac52e0d7be683091334f617421fa418d586e075ad626eea9cc913e6c6c6075` |
| E | baseline, focused/full regression | `DONE` - baseline, focused `41 passed`, full r1/r2 각 `2675 passed, 5 skipped, 0 failed, 0 errors` |
| F1/F2 | Claude, Grok, GLM two-run review | `DONE` - F1/F2 모두 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 lane `GO` |
| G | machine/supervisor comparator `FIX`와 비주장 기록 | `DONE` - supervisor semantic comparator `FIX`, fingerprint `a98588083aa12e0f3449b1616c63a0c4810bede9cca3f65701c665db5f939db6` |

## 시작 경계

Data-07의 G가 `FIX`로 닫힌 뒤에만 이 A 사전등록을 열었다. B는 이 문서의 binding을 바꾸지 않고,
기존 renderer로 fallback하지 않는 `data-09` 전용 Java/Spring JDBC concat renderer와 renderer-scoped
materializer identity를 추가했다. Data-07의 receipt, comparator, supervisor evidence는 Data-09의 성공 근거가 아니다.

## 완료의 의미

이 leaf는 primary/reserve source triplet의 tree identity만 검증한다. Java/Spring/JDBC 실행, 실제 prepared-statement
효과, SQLi 탐지, 한국 개인정보 처리, detector accuracy, H100, release는 이후 별도 oracle과 측정 카드에서만 다룬다.

## 완료 증거와 다음 경계

공식 external root는 `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b218-data09-source-flow-20260724`다.
machine comparator `data09-r1-r2-comparison.json`은 `FIX`, `repeat_exact: true`, materializer identity
`85adae961398d163e9eb59378711f38f06ba53e68052f1fc6ac9b13d1e6bb5cd`, semantic fingerprint
`90ac52e0d7be683091334f617421fa418d586e075ad626eea9cc913e6c6c6075`를 기록한다. raw source는 반환하지 않는다.

C의 focused suite는 goal-state validator, generic/source-slot comparator, Site-15, Data-03, Data-07, Data-09의
materialization과 repeat contract를 함께 실행해 `41 passed`였다. E는 이 문서와 구현을 포함한 target을 새로
baseline으로 봉인한 뒤 focused 및 full regression을 서로 다른 external run directory에서 실행했다.

E baseline receipt는 `c2beca7a75ec2339310b033d1ee345d3de3f21210d3460ab7b422e510701a927`, focused receipt는
`b041175658ff64c907a6a076eb8cb77cebdf293ba0dbec9b9e8e9f28e829d107`다. full r1/r2 receipt는 각각
`06ef875bfaabe4051e72f779e3e74191c4b45e0efb248becc57a070e0944989d`,
`7ed1d098fc2f311ca32ce3027a7c9d1ce16cdf2cfe6df88cd2c77c95e0458f16`다. 네 evidence 모두 target
`04e9dd8e7dc788d8242db138278758303ba6f27d`와 dirty-worktree fingerprint
`5622a2581f93147b279b7922b17e40766969d4c9d7c28fd2deec8eba85b717f0`를 가리킨다.

F1/F2의 official external output directory는 각각 `supervisor-review-v1-r1`, `supervisor-review-v1-r2`다. 두 run의
Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 lane은 모두 `GO`였고 target unchanged였다. 각 single run의 top-level
`HOLD`는 F2 전 `test_attestation_incomplete`를 정직하게 보존하는 runner 상태이며, two-run comparator
`supervisor-review-v1-r1-r2-comparison.json`이 그 동일한 nonblocking gap과 세 lane `GO`를 비교해 `FIX`를 결정했다.

이 `FIX_NARROW`는 다음 `data-14`의 A 사전등록만 열 수 있다. Java compiler/Maven/Spring/JDBC runtime, SQLi scanner,
TP/FP/FN, H100, release는 여전히 승인하지 않는다.
