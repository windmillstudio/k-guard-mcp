# P2.4B.2.13 site-13 JDBC source-flow materialization 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW`  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)  
목표/종료 기준: [제품 목표 레지스트리](release-program-goal-register-ko.md)

## 한 문장 목표

P2.4A의 `site-13` JDBC query slot에서 primary와 fixed-order reserve 두 candidate의 Java/Spring
`vulnerable`, `fixed`, `negative` source tree를 새 external root에 deterministic fixture로 materialize하는
계약을 source 생성 전에 고정한다.

## 고정 binding

- slot: `site-13`, scenario `dev-site-13-jdbc-query`, oracle `l3-gen-site-13-jdbc-query`
- plane/family/language/framework: `site` / `source-flow` / `java` / `spring`; blueprint coverage tag는 `express`
- CWE/severity/profile: `CWE-89` / `high` / `deterministic-fixture-v1`
- candidate rank: primary `0`, reserve `1`; 총 2 candidate와 6 source tree
- primary source: `src/main/java/dev/kguard/checkout/OrderLookupController.java`, `findOrder`, `/orders`,
  `id`, `orders`, result column `status`, static negative text `orders-ready`
- reserve source: `src/main/java/dev/kguard/integrations/IntegrationLookupController.java`, `findIntegration`,
  `/integrations`, `provider`, `integrations`, result column `endpoint`, static negative text `integrations-ready`
- `vulnerable` tree는 request parameter를 SQL string에 연결하고 `Statement.executeQuery(query)`로 전달하는
  JDBC source condition을 보존한다. `fixed` tree는 placeholder query와 `PreparedStatement`, `setString`으로
  한정된 변경을 한다. `negative` tree는 request parameter, `DataSource`, SQL source 없이 static response만 반환한다.
- source layout은 P2.4B.1의 `slots/site-13/candidate-<rank>/<state>` relative path를 그대로 쓴다.
  P2.4B.1 external stage root는 read-only이며 절대 수정하지 않는다.
- 각 tree에는 MIT `LICENSE`, canonical `pom.xml`, 하나의 Java/Spring controller source만 있다.
- site-13 materializer/comparator는 별도 versioned file로 만든다. 앞선 leaf의 source, receipt, comparator byte
  binding을 바꾸거나 이 카드의 승인 근거로 재사용하지 않는다.

## Tree 역할

| 상태 | source intent | 이 카드가 증명하지 않는 것 |
| --- | --- | --- |
| `vulnerable` | request parameter를 JDBC SQL string에 결합하는 source condition | DB 연결, SQL 실행, SQLi exploit, detector finding |
| `fixed` | placeholder와 `PreparedStatement.setString`을 사용하는 bounded source change | runtime query correctness 또는 배포 DB access control |
| `negative` | SQL/parameter 없이 static response만 반환하는 control | scanner specificity 또는 test sensitivity |

primary와 reserve는 source path, controller, handler, route, parameter, table, result column, static text가 다르다.
이 구분은 reserve 순서와 source tree identity를 위한 것이며, 실제 JDBC 사용 빈도나 detector performance를 뜻하지 않는다.
materializer는 source text만 생성하며 Java compiler, Maven, Spring runtime, JDBC driver, database connection, SQL query,
HTTP request, browser, network request, runtime output 반환을 실행하지 않는다.

## Fail-closed 규칙

- preregistered blueprint/staging receipt/root이 external path가 아니거나 canonical validation을 통과하지 못하면 거부한다.
- slot/rank/language/framework/profile/path binding이 고정값과 다르면 거부한다.
- stage root source 삽입, symlink, unexpected source file/directory, receipt/source tamper, role swap, root binding mismatch,
  repository output, input/output overlap, overwrite를 모두 거부한다.
- primary와 reserve 중 하나라도 없거나 `vulnerable`/`fixed`/`negative` 세 역할이 구분되지 않으면 materialization을
  성공으로 표시하지 않는다.
- 이 카드는 source writer다. 외부 대상, localhost, container, service endpoint, Java/Spring runtime, JDBC driver,
  database, browser로 generated source를 실행하지 않는다.

## A-G gate

| Gate | P2.4B.2.13 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim과 primary/reserve source/controller/route/parameter/table/static-text identity를 external source 생성 전에 고정 | `DONE` |
| B | site-13만 허용하는 immutable materializer와 comparator를 target에 결속 | `DONE` - Java/Spring JDBC source-only materializer와 repeat comparator를 별도 versioned file로 결속 |
| C | receipt/tree/staging tamper, role swap, root binding, repository output, overlap, overwrite focused test | `DONE` - materializer/comparator focused tests 6 passed, 0 failed |
| D | external root에서 primary/reserve 6 tree의 r1/r2 comparator 생성 | `DONE` - comparator `FIX`, semantic fingerprint `37476b02780d0c555ef7ae48cdd413300970451821b42d3bd580b103a22dcfbd` |
| E | current target baseline, focused/full regression, validate-current, diff check | `DONE` - baseline current, focused 6/6, clean full r1/r2 각각 2,635 passed, 5 skipped, 0 failed, 0 errors |
| F1/F2 | 같은 target/packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 번 검토 | `DONE` - 두 run 모두 세 lane `GO`, Claude direct-file 5/5, supervisor comparator `FIX` |
| G | machine 및 supervisor comparator가 `FIX`일 때만 `P2.4B.2.13` 기록 | `DONE` - evidence-time target, machine comparator, 3AI comparator와 명시적 비주장을 결속 |

## 완료 evidence

- D: `phase2-p24b213-site13-source-flow-20260724-r1/site13-r1-r2-comparison.json`은 `FIX`,
  `repeat_exact=true`이며 semantic fingerprint는
  `37476b02780d0c555ef7ae48cdd413300970451821b42d3bd580b103a22dcfbd`다. materializer SHA-256은
  `40dcc1c605397a9d0c1b5dfc914e0c9a2776479ec9d53acf93c417447641db27`다.
- E: evidence-time baseline receipt는 `37d969ede2024c3afc2c8d829910f2da82509b673359f128c2f2a87eb1ddcaa7`이고,
  focused r2 receipt는 `c8be4c4724b693b643485a415999edd3346b8a5205c1a908deda7aa74a6dc1fb`다.
  clean full r1/r2 receipt는 각각
  `fd7abb656b9b181a8b64a592b6bb95334b96613889993ddb4519c7611b109f6e`,
  `99fdb2e127f1ddeead0ee5dc2fe9af34d6771011c5d381d61f971fa9bcf60fa0`이며, 두 run은 같은 target에서
  각각 2,635 passed, 5 skipped, 0 failed, 0 errors다. focused r1의 Windows path selector는 run directory와
  receipt를 만들기 전에 `test_selector_invalid`로 거부됐으므로 성공 evidence나 F packet artifact로 사용하지 않았다.
- F1/F2: source-free health r1에서 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2가 모두 `HEALTHY`였다.
  두 review run에서 세 lane이 모두 `GO`, blocker `0`, claim boundary confirmed였고 Claude는 다섯 직접 파일의
  attestation을 두 번 남겼다. 단회 `REPEATABILITY_GAP`은 비승격 상태로 보존했다.
- G: `supervisor-review-r1-r2-comparison.json`은 `FIX`, `repeat_exact=true`, semantic fingerprint
  `cee63659d209f8848675793276e98329ccb8d45ea6e3837c3204041257b47ca5`다.

## 명시적 비주장

P2.4B.2.13의 `FIX_NARROW`는 site-13 한 slot의 source tree identity만 뜻한다. Java compiler/Maven/Spring runtime,
JDBC driver/database connection/query execution, SQLi exploit, deployed configuration, scanner finding, true positive,
false positive, false negative, precision, recall, 다른 source-flow slot, 전체 60 pair, H100, release는 계속 `HOLD`다.
