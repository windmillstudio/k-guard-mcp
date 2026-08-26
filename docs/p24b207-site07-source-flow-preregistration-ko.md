# P2.4B.2.07 site-07 source-flow materialization 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW`  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)

## 한 문장 목표

P2.4A의 `site-07` prototype-pollution slot에 대해 primary와 fixed-order reserve 두 candidate의
TypeScript/Next.js `vulnerable`, `fixed`, `negative` source tree를 새 external root에 deterministic fixture로
materialize하는 계약을 source 생성 전에 고정한다.

## 고정 binding

- slot: `site-07`, scenario `dev-site-07-prototype-pollution`, oracle
  `l3-gen-site-07-prototype-pollution`
- plane/family/language/framework: `site` / `source-flow` / `typescript` / `nextjs`
- CWE/severity/profile: `CWE-1321` / `high` / `deterministic-fixture-v1`
- candidate rank: primary `0`, reserve `1`; 총 2 candidate와 6 source tree
- primary route: `app/api/preferences/route.ts`, request JSON field `preferences`, fixed explicit fields
  `theme`/`locale`, static negative response `{ theme: "system", locale: "ko-KR" }`
- reserve route: `app/api/profile/route.ts`, request JSON field `profile`, fixed explicit fields
  `displayName`/`timeZone`, static negative response `{ displayName: "guest", timeZone: "Asia/Seoul" }`
- `vulnerable` tree는 해당 input object를 `Object.assign(...)`으로 mutable default object에 전달하는 source
  condition을 보존한다. `fixed` tree는 input object를 병합하지 않고 preregistered explicit fields만 type check하여
  새 object에 복사한다. `negative` tree는 request body를 읽지 않고 candidate별 static object만 반환한다.
- source layout은 P2.4B.1의 `slots/site-07/candidate-<rank>/<state>` relative path를 그대로 쓴다.
  P2.4B.1 external stage root는 read-only이며 절대 수정하지 않는다.
- 각 tree에는 MIT `LICENSE`, canonical `package.json`, 하나의 TypeScript route source만 있다.
- site-07 materializer/comparator는 별도 versioned file로 만든다. 앞선 leaf의 source, receipt, comparator byte
  binding을 바꾸거나 승인 근거로 재사용하지 않는다.

## Tree 역할

| 상태 | source intent | 이 카드가 증명하지 않는 것 |
| --- | --- | --- |
| `vulnerable` | request JSON object가 mutable default object에 generic `Object.assign(...)`으로 병합되는 source condition | prototype mutation 실행, object behavior, detector finding |
| `fixed` | request object의 generic merge 없이 declared scalar field만 검증 후 새 response object에 반영하는 bounded source change | framework/runtime correctness 또는 functional test |
| `negative` | request body를 읽지 않고 static response object만 반환하는 control | scanner specificity 또는 test sensitivity |

primary와 reserve는 route, request field, declared field set, static object가 다르다. 이 구분은 reserve 순서와
source tree identity를 위한 것이며, 실전 prototype-pollution 빈도나 detector performance를 의미하지 않는다.
materializer는 source text만 생성하며 외부 HTTP 요청, browser, payload execution, object mutation execution,
runtime output 반환을 하지 않는다.

## Fail-closed 규칙

- preregistered blueprint/staging receipt/root이 external path가 아니거나 canonical validation을 통과하지 못하면
  거부한다.
- slot/rank/framework/profile/path binding이 고정값과 다르면 거부한다.
- stage root source 삽입, symlink, unexpected source file/directory, receipt/source tamper, role swap, root binding
  mismatch, repository output, input/output overlap, overwrite를 모두 거부한다.
- primary와 reserve 중 하나라도 없거나 `vulnerable`/`fixed`/`negative` 세 역할이 구분되지 않으면 materialization을
  성공으로 표시하지 않는다.
- 이 카드는 source writer다. 외부 대상, localhost, 컨테이너, service endpoint, JavaScript runtime으로 generated
  source를 실행하지 않는다.

## A-G gate

| Gate | P2.4B.2.07 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim과 primary/reserve route/input/field/static identity를 source 생성 전에 고정 | `DONE` |
| B | site-07만 허용하는 immutable materializer와 comparator를 target에 결속 | `DONE` - site-07 전용 materializer/comparator와 source hash binding |
| C | receipt/tree/staging tamper, role swap, root binding, repository output, overlap, overwrite focused test | `DONE` - materializer/comparator focused tests 6 passed, 0 failed |
| D | external root에서 primary/reserve 6 tree의 r1/r2 comparator 생성 | `DONE` - comparator `FIX`, `repeat_exact=true`, semantic fingerprint `92ad844f11c74b7f77fbaa049213aa1a54feab71c878f40ee79dedda7c4ee57f` |
| E | current target baseline, focused/full regression, validate-current, diff check | `DONE` - focused 6 passed; isolated full r1/r2 각각 2,599 passed, 5 skipped, 0 failed; evidence-time target unchanged |
| F1/F2 | 같은 target/packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 번 검토 | `DONE` - 세 lane 모두 F1/F2 `GO`; 각 단회 run의 `REPEATABILITY_GAP`은 보존 |
| G | machine 및 supervisor comparator가 `FIX`일 때만 `P2.4B.2.07` 기록 | `DONE` - supervisor comparator `FIX`, `repeat_exact=true`, semantic fingerprint `507e24682d9d7ebd244690ff5e84229eb466a251734c5caf155af13731ea1d32` |

## 완료 증거

- evidence root: `<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24b207-site07-source-flow-20260724-r1`
- baseline/validate receipt: `77ce65fce882c8c9d158717a4bc61d57a94db0fd89511becffccdfd6d7ea58d9`
- focused regression receipt: `59e984ebbcc99527cf2f0c5abe7d04158a3c00653b1d36b9c3f508ed086d4478`
- isolated full regression r1/r2 receipt: `0bd56707dd3e30e96783e59f0cb71e6bd6878725eebd232cabcc95b5df5f81e2` /
  `1993c6e76ea16d729e01f2beabe3454a82058745735944356c16fb8b52996bfc`
- D machine comparator: `site07-r1-r2-comparison.json` is `FIX`, repeat exact; materializer SHA-256
  `ee07de6edc44989f3b579ec0f84904c796d6eb4ccaee618e9d509782cde1912c`
- F1/F2 supervisor packet: Claude Opus 4.8 direct-file review, Grok 4.5, Cline GLM 5.2가 모두 각 run에서
  lane `GO`를 냈다. top-level single-run envelope의 intentional `REPEATABILITY_GAP`은 승격 근거가 아니며,
  `supervisor-review-r1-r2-comparison.json`의 two-run semantic comparator `FIX`만 G의 근거다.
- 위 evidence는 HEAD `04e9dd8e7dc788d8242db138278758303ba6f27d`와 evidence-time dirty target에 결속됐다.
  이 문서의 완료 기록은 증거 생성 뒤의 문서 변경이며, 기존 evidence target을 현재 worktree의 승인으로
  바꾸지 않는다.

## 명시적 비주장

P2.4B.2.07이 `FIX_NARROW`가 되더라도 site-07 한 slot의 source tree identity만 뜻한다. prototype-pollution
execution, source runtime behavior, scanner finding, true positive, false negative, precision, recall, 다른
12개 source-flow slot, 전체 60 pair, H100, release는 계속 `HOLD`다.
