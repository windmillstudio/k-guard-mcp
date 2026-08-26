# P2.4B.2.09 site-09 source-flow materialization 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW`  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)

## 한 문장 목표

P2.4A의 `site-09` client-secret slot에 대해 primary와 fixed-order reserve 두 candidate의
TypeScript/Next.js `vulnerable`, `fixed`, `negative` source tree를 새 external root에 deterministic transform으로
materialize하는 계약을 source 생성 전에 고정한다.

## 고정 binding

- slot: `site-09`, scenario `dev-site-09-client-secret`, oracle `l3-gen-site-09-client-secret`
- plane/family/language/framework: `site` / `source-flow` / `typescript` / `nextjs`
- CWE/severity/profile: `CWE-798` / `critical` / `deterministic-transform-v1`
- candidate rank: primary `0`, reserve `1`; 총 2 candidate와 6 source tree
- primary route: `app/checkout/page.tsx`, client identifier `checkoutProviderKey`, synthetic literal
  `k_guard_demo_client_key_primary`, server handoff endpoint `/api/checkout-session`, static negative label
  `Continue checkout`
- reserve route: `app/integrations/page.tsx`, client identifier `integrationApiToken`, synthetic literal
  `k_guard_demo_client_token_reserve`, server handoff endpoint `/api/integration-connect`, static negative label
  `Connect integration`
- `vulnerable` tree는 client component source 안에서 synthetic embedded credential-like literal을 Authorization
  header에 보존하는 source condition이다. literal은 실제 credential이 아니며 external request는 실행하지 않는다.
  `fixed` tree는 client source에서 해당 literal과 Authorization header를 제거하고 relative same-origin server
  handoff만 요청한다. `negative` tree는 request와 credential-like literal 없이 candidate별 static label만 렌더링한다.
- source layout은 P2.4B.1의 `slots/site-09/candidate-<rank>/<state>` relative path를 그대로 쓴다.
  P2.4B.1 external stage root는 read-only이며 절대 수정하지 않는다.
- 각 tree에는 MIT `LICENSE`, canonical `package.json`, 하나의 TypeScript Next.js page source만 있다.
- site-09 materializer/comparator는 별도 versioned file로 만든다. 앞선 leaf의 source, receipt, comparator byte
  binding을 바꾸거나 승인 근거로 재사용하지 않는다.

### Binding 교정 기록

초기 문서 초안은 선행 leaf의 `deterministic-template-v1`을 가정했으나, source materialization 전에 실행한
P2.4A blueprint/staging preflight에서 site-09의 정식 profile이 `deterministic-transform-v1`임을 확인했다.
이 값만 사전등록에 교정했으며 candidate 수, rank, CWE, severity, route, 역할, 합격선, 비주장은 바꾸지 않았다.
이전 값으로 생성한 source tree나 external evidence는 없다.

## Tree 역할

| 상태 | source intent | 이 카드가 증명하지 않는 것 |
| --- | --- | --- |
| `vulnerable` | client component에 synthetic credential-like literal과 outbound Authorization-header source condition을 둠 | 키 유효성, external request, browser bundle, detector finding |
| `fixed` | client source의 literal과 Authorization header를 제거하고 same-origin server handoff만 남김 | server endpoint의 authentication 또는 runtime correctness |
| `negative` | request와 credential-like literal 없이 static label만 렌더링하는 control | scanner specificity 또는 test sensitivity |

primary와 reserve는 route, client identifier, synthetic literal, handoff endpoint, static label이 다르다. 이 구분은
reserve 순서와 source tree identity를 위한 것이며, 실전 client-secret 빈도나 detector performance를 의미하지 않는다.
materializer는 source text만 생성하며 Node.js runtime, browser, bundler, external HTTP request, browser request,
runtime output 반환을 하지 않는다.

## Fail-closed 규칙

- preregistered blueprint/staging receipt/root이 external path가 아니거나 canonical validation을 통과하지 못하면
  거부한다.
- slot/rank/framework/profile/path binding이 고정값과 다르면 거부한다.
- stage root source 삽입, symlink, unexpected source file/directory, receipt/source tamper, role swap, root binding
  mismatch, repository output, input/output overlap, overwrite를 모두 거부한다.
- primary와 reserve 중 하나라도 없거나 `vulnerable`/`fixed`/`negative` 세 역할이 구분되지 않으면 materialization을
  성공으로 표시하지 않는다.
- 이 카드는 source writer다. 외부 대상, localhost, 컨테이너, service endpoint, Node.js runtime, browser, bundler로
  generated source를 실행하지 않는다.

## A-G gate

| Gate | P2.4B.2.09 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim과 primary/reserve route/client identifier/synthetic literal/handoff/static identity를 source 생성 전에 고정 | `DONE` |
| B | site-09만 허용하는 immutable materializer와 comparator를 target에 결속 | `DONE` - site-09 전용 materializer/comparator와 source hash binding |
| C | receipt/tree/staging tamper, role swap, root binding, repository output, overlap, overwrite focused test | `DONE` - materializer/comparator focused tests 6 passed, 0 failed |
| D | external root에서 primary/reserve 6 tree의 r1/r2 comparator 생성 | `DONE` - comparator `FIX`, semantic fingerprint `1751d54cceb642f691cc15b89efdfc34f2b689f75ade5121d991c960209e1e09` |
| E | current target baseline, focused/full regression, validate-current, diff check | `DONE` - focused 6/6, prior r1 `CONTROL_HOLD` 보존, isolated clean full r2/r3 각각 2,611 passed, 5 skipped, 0 failed, 0 errors; baseline current 및 diff check 통과 |
| F1/F2 | 같은 target/packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 번 검토 | `DONE` - 두 run 모두 세 lane `GO`, Claude direct-file 5/5, supervisor comparator `FIX` |
| G | machine 및 supervisor comparator가 `FIX`일 때만 `P2.4B.2.09` 기록 | `DONE` - evidence-time target, machine comparator, 3AI comparator와 명시적 비주장을 결속 |

## 완료 evidence

- D: `phase2-p24b209-site09-source-flow-20260724-r1/site09-r1-r2-comparison.json`은
  `FIX`, `repeat_exact=true`이며 materializer SHA-256은
  `a74ff7dd752de4d30f4b90ec019bddfc4194221812c46f7c0361a44901045ec0`다.
- E: evidence-time baseline receipt는
  `c2140aa019d9e29103bf975eda7552d2ab811c75cdfe5ac6f059cd3b7d412548`다. focused receipt는
  `93f5c994cc4a0cf4aa2a071592dbb2a2cd57968e25c5e8521d7075753d6346a9`다. full r1은 target unchanged 상태에서
  1 failure의 `CONTROL_HOLD`였고 승인 근거가 아니다. direct last-failed rerun은 통과했지만 full evidence가 아니다.
  clean full r2/r3 receipt는 각각 `479408327e844dd2e37b583862e5781895df61373047334bac9bcca9af8337ab`,
  `68339613bf4eab7073b07ec2d82a0dde00594afa455dd6a8395a26d8f4281765`이며, 둘 다 2,611 passed, 5 skipped,
  0 failed, 0 errors와 같은 target을 기록했다.
- F1/F2: health r1의 GLM lane `BLOCKED_PROVIDER`는 보존했다. source-free health r2에서 세 lane이 모두
  `HEALTHY`가 된 뒤 F1/F2를 실행했다. Claude Opus 4.8은 다섯 직접 파일을 읽은 attestation을 두 번 남겼고,
  Grok 4.5와 Cline GLM 5.2도 raw-free packet에서 두 번 모두 lane `GO`를 냈다. 단회 envelope의
  `REPEATABILITY_GAP`은 의도된 비승격 상태로 보존했다.
- G: `supervisor-review-r1-r2-comparison.json`은 `FIX`, `repeat_exact=true`, semantic fingerprint
  `cba3a729c6283a2f39839d8fba492ee164e2c8099092069b27b736f34505617e`다. 결과 기록은 evidence-time
  target 뒤에 작성되며 해당 target이나 승인 범위를 바꾸지 않는다.

## 명시적 비주장

P2.4B.2.09이 `FIX_NARROW`가 되더라도 site-09 한 slot의 source tree identity만 뜻한다. real secret validity,
client bundle exposure, external HTTP request, source runtime behavior, scanner finding, true positive, false negative,
precision, recall, 다른 10개 source-flow slot, 전체 60 pair, H100, release는 계속 `HOLD`다.
