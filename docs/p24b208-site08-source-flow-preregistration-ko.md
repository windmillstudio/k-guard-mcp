# P2.4B.2.08 site-08 source-flow materialization 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW`  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)

## 한 문장 목표

P2.4A의 `site-08` unsafe-deserialize slot에 대해 primary와 fixed-order reserve 두 candidate의
JavaScript/Express `vulnerable`, `fixed`, `negative` source tree를 새 external root에 deterministic template로
materialize하는 계약을 source 생성 전에 고정한다.

## 고정 binding

- slot: `site-08`, scenario `dev-site-08-unsafe-deserialize`, oracle
  `l3-gen-site-08-unsafe-deserialize`
- plane/family/language/framework: `site` / `source-flow` / `javascript` / `express`
- CWE/severity/profile: `CWE-502` / `critical` / `deterministic-template-v1`
- candidate rank: primary `0`, reserve `1`; 총 2 candidate와 6 source tree
- primary route: `routes/import-settings.js`, request body field `serializedSettings`, fixed declared fields
  `theme`/`locale`, static negative object `{ theme: "system", locale: "ko-KR" }`
- reserve route: `routes/restore-session.js`, request body field `serializedSession`, fixed declared fields
  `role`/`ttlSeconds`, static negative object `{ role: "viewer", ttlSeconds: 900 }`
- `vulnerable` tree는 request body의 serialized string을 injected `legacySerializer.deserialize(...)`에 전달하는
  source condition을 보존한다. `fixed` tree는 legacy serializer를 호출하지 않고 JSON parse, plain-object 경계,
  declared field/type allowlist만 거친 새 object를 만든다. `negative` tree는 request body를 읽지 않고 candidate별
  static object만 반환한다.
- source layout은 P2.4B.1의 `slots/site-08/candidate-<rank>/<state>` relative path를 그대로 쓴다.
  P2.4B.1 external stage root는 read-only이며 절대 수정하지 않는다.
- 각 tree에는 MIT `LICENSE`, canonical `package.json`, 하나의 JavaScript Express route source만 있다.
- site-08 materializer/comparator는 별도 versioned file로 만든다. 앞선 leaf의 source, receipt, comparator byte
  binding을 바꾸거나 승인 근거로 재사용하지 않는다.

## Tree 역할

| 상태 | source intent | 이 카드가 증명하지 않는 것 |
| --- | --- | --- |
| `vulnerable` | request body의 serialized string을 injected legacy deserializer에 generic 전달하는 source condition | deserializer 실행, code execution, detector finding |
| `fixed` | legacy deserializer를 호출하지 않고 JSON object와 declared scalar field만 검증 후 새 object에 반영하는 bounded source change | framework/runtime correctness 또는 functional test |
| `negative` | request body를 읽지 않고 static response object만 반환하는 control | scanner specificity 또는 test sensitivity |

primary와 reserve는 route, request field, declared field set, static object가 다르다. 이 구분은 reserve 순서와
source tree identity를 위한 것이며, 실전 unsafe-deserialization 빈도나 detector performance를 의미하지 않는다.
materializer는 source text만 생성하며 serializer, JavaScript runtime, external HTTP request, browser, payload execution,
runtime output 반환을 하지 않는다.

## Fail-closed 규칙

- preregistered blueprint/staging receipt/root이 external path가 아니거나 canonical validation을 통과하지 못하면
  거부한다.
- slot/rank/framework/profile/path binding이 고정값과 다르면 거부한다.
- stage root source 삽입, symlink, unexpected source file/directory, receipt/source tamper, role swap, root binding
  mismatch, repository output, input/output overlap, overwrite를 모두 거부한다.
- primary와 reserve 중 하나라도 없거나 `vulnerable`/`fixed`/`negative` 세 역할이 구분되지 않으면 materialization을
  성공으로 표시하지 않는다.
- 이 카드는 source writer다. 외부 대상, localhost, 컨테이너, service endpoint, serializer, JavaScript runtime으로
  generated source를 실행하지 않는다.

## A-G gate

| Gate | P2.4B.2.08 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim과 primary/reserve route/input/field/static identity를 source 생성 전에 고정 | `DONE` |
| B | site-08만 허용하는 immutable materializer와 comparator를 target에 결속 | `DONE` - site-08 전용 materializer/comparator와 source hash binding |
| C | receipt/tree/staging tamper, role swap, root binding, repository output, overlap, overwrite focused test | `DONE` - materializer/comparator focused tests 6 passed, 0 failed |
| D | external root에서 primary/reserve 6 tree의 r1/r2 comparator 생성 | `DONE` - comparator `FIX`, semantic fingerprint `bab542fc7845e07b1af8ccc7d6c5cd34e790cef20a4b1220ae0425f76a4706b5` |
| E | current target baseline, focused/full regression, validate-current, diff check | `DONE` - focused 6/6, isolated full r1/r2 각각 2,605 passed, 5 skipped, 0 failed, 0 errors; baseline current 및 diff check 통과 |
| F1/F2 | 같은 target/packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 번 검토 | `DONE` - 두 run 모두 세 lane `GO`, Claude direct-file 5/5, supervisor comparator `FIX` |
| G | machine 및 supervisor comparator가 `FIX`일 때만 `P2.4B.2.08` 기록 | `DONE` - evidence-time target, machine comparator, 3AI comparator와 명시적 비주장을 결속 |

## 완료 evidence

- D: `phase2-p24b208-site08-source-flow-20260724-r1/site08-r1-r2-comparison.json`은
  `FIX`, `repeat_exact=true`이며 materializer SHA-256은
  `e3fbfe1a79d2844536d2dfd7b2d8352cd34dc2e58f70cbdb83d25abea7d4d285`다.
- E: evidence-time baseline receipt는
  `e492609d8c619948320096021c9315faa90af098cc5b0c525ddb74e0767f005c`다. focused receipt는
  `e7d4baff6d81628b9c4585e24ff660d82d96603ca0f07e66951203a8ff425efe`이며, full r1/r2 receipt는 각각
  `a982dd25b8e7c5d3706239ab2e15f43279b0efe3e1c77418e19a7f8a004d83dd`,
  `ee56dbacbca483eff15b376413db4ea72907cde65c91403feaa284ddcdf84c0d`다. 모든 실행 전후 target은 같다.
- F1/F2: Claude Opus 4.8은 다섯 직접 파일을 읽은 attestation을 두 번 남겼고, Grok 4.5와
  Cline GLM 5.2도 raw-free packet에서 두 번 모두 lane `GO`를 냈다. 단회 envelope의
  `REPEATABILITY_GAP`은 의도된 비승격 상태로 보존했다.
- G: `supervisor-review-r1-r2-comparison.json`은 `FIX`, `repeat_exact=true`, semantic fingerprint
  `60eb632c4eca013280722e138cc1cd8ebe19c451b50db8844dca24354f867912`다. 결과 기록은 evidence-time
  target 뒤에 작성되며 해당 target이나 승인 범위를 바꾸지 않는다.

## 명시적 비주장

P2.4B.2.08이 `FIX_NARROW`가 되더라도 site-08 한 slot의 source tree identity만 뜻한다. deserializer execution,
code execution, source runtime behavior, scanner finding, true positive, false negative, precision, recall, 다른
11개 source-flow slot, 전체 60 pair, H100, release는 계속 `HOLD`다.
