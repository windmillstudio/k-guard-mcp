# P2.4B.2.10 site-10 source-flow materialization 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW`  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)

## 한 문장 목표

P2.4A의 `site-10` CORS-origin slot에 대해 primary와 fixed-order reserve 두 candidate의
JavaScript/Express `vulnerable`, `fixed`, `negative` source tree를 새 external root에 deterministic fixture로
materialize하는 계약을 source 생성 전에 고정한다.

## 고정 binding

- slot: `site-10`, scenario `dev-site-10-cors-origin`, oracle `l3-gen-site-10-cors-origin`
- plane/family/language/framework: `site` / `source-flow` / `javascript` / `express`
- CWE/severity/profile: `CWE-942` / `high` / `deterministic-fixture-v1`
- candidate rank: primary `0`, reserve `1`; 총 2 candidate와 6 source tree
- primary route: `routes/checkout-cors.js`, request header `origin`, reflected CORS handler
  `applyCheckoutCors`, fixed allowlist `https://shop.example.invalid`, negative status `204`
- reserve route: `routes/integrations-cors.js`, request header `origin`, reflected CORS handler
  `applyIntegrationsCors`, fixed allowlist `https://portal.example.invalid`, negative status `204`
- `vulnerable` tree는 request header origin을 `Access-Control-Allow-Origin`에 반사하고
  `Access-Control-Allow-Credentials: true`를 함께 설정하는 source condition을 보존한다. `fixed` tree는
  candidate별 exact allowlist를 통과한 origin에만 이 두 header와 `Vary: Origin`을 설정한다. `negative` tree는
  request header를 읽지 않고 CORS response header도 설정하지 않은 채 `204`를 반환한다.
- source layout은 P2.4B.1의 `slots/site-10/candidate-<rank>/<state>` relative path를 그대로 쓴다.
  P2.4B.1 external stage root는 read-only이며 절대 수정하지 않는다.
- 각 tree에는 MIT `LICENSE`, canonical `package.json`, 하나의 JavaScript Express route source만 있다.
- site-10 materializer/comparator는 별도 versioned file로 만든다. 앞선 leaf의 source, receipt, comparator byte
  binding을 바꾸거나 승인 근거로 재사용하지 않는다.

## Tree 역할

| 상태 | source intent | 이 카드가 증명하지 않는 것 |
| --- | --- | --- |
| `vulnerable` | request origin reflection과 credentialed CORS header source condition | browser CORS behavior, cross-origin read, detector finding |
| `fixed` | exact allowlist origin에만 credentialed CORS header와 `Vary`를 설정하는 bounded source change | allowlist의 실제 운영 적합성 또는 framework/runtime correctness |
| `negative` | origin을 읽지 않고 CORS header 없이 204를 반환하는 control | scanner specificity 또는 test sensitivity |

primary와 reserve는 route, handler, fixed allowlist가 다르다. 이 구분은 reserve 순서와 source tree identity를 위한 것이며,
실전 CORS 취약성 빈도나 detector performance를 의미하지 않는다. materializer는 source text만 생성하며 Express runtime,
HTTP request, browser, network request, runtime output 반환을 하지 않는다.

## Fail-closed 규칙

- preregistered blueprint/staging receipt/root이 external path가 아니거나 canonical validation을 통과하지 못하면
  거부한다.
- slot/rank/framework/profile/path binding이 고정값과 다르면 거부한다.
- stage root source 삽입, symlink, unexpected source file/directory, receipt/source tamper, role swap, root binding
  mismatch, repository output, input/output overlap, overwrite를 모두 거부한다.
- primary와 reserve 중 하나라도 없거나 `vulnerable`/`fixed`/`negative` 세 역할이 구분되지 않으면 materialization을
  성공으로 표시하지 않는다.
- 이 카드는 source writer다. 외부 대상, localhost, 컨테이너, service endpoint, Express runtime, browser로
  generated source를 실행하지 않는다.

## A-G gate

| Gate | P2.4B.2.10 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim과 primary/reserve route/header/handler/allowlist/status identity를 source 생성 전에 고정 | `DONE` |
| B | site-10만 허용하는 immutable materializer와 comparator를 target에 결속 | `DONE` - site-10 전용 materializer/comparator와 source hash binding |
| C | receipt/tree/staging tamper, role swap, root binding, repository output, overlap, overwrite focused test | `DONE` - materializer/comparator focused tests 6 passed, 0 failed |
| D | external root에서 primary/reserve 6 tree의 r1/r2 comparator 생성 | `DONE` - comparator `FIX`, semantic fingerprint `51164406c8bf2cd2cae3036c005a679efa8dede1e9f69d38e41a7398c5e74d31` |
| E | current target baseline, focused/full regression, validate-current, diff check | `DONE` - focused 6/6, clean full r1/r2 각각 2,617 passed, 5 skipped, 0 failed, 0 errors; baseline current 및 diff check 통과 |
| F1/F2 | 같은 target/packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 번 검토 | `DONE` - F1과 health recovery 뒤 동일 packet F3 retry에서 세 lane `GO`, Claude direct-file 5/5, supervisor comparator `FIX`; intermediate F2 GLM `BLOCKED_PROVIDER` 보존 |
| G | machine 및 supervisor comparator가 `FIX`일 때만 `P2.4B.2.10` 기록 | `DONE` - evidence-time target, machine comparator, valid 3AI repeat comparator와 명시적 비주장을 결속 |

## 완료 evidence

- D: `phase2-p24b210-site10-source-flow-20260724-r1/site10-r1-r2-comparison.json`은
  `FIX`, `repeat_exact=true`이며 materializer SHA-256은
  `c8974b3f977c14c08bbe5fc5a3f44f096d6f46ffa514f92756776fa5985d`다.
- E: evidence-time baseline receipt는
  `1829a68018502fa050d1bbe1d1e710af798caa74bf95864fb49c9ea58135fc5d`다. focused receipt는
  `def818cb87ac3f97083c084f7f47aeacd021d71d9f0c82ef366bd22e6c574608`이며 6 passed, 0 failed,
  0 errors를 기록했다. clean full r1/r2 receipt는 각각
  `4be0f748a38e783f5178dd8db87b195e8638490ced9872f27abd936cc7455aba`,
  `0633f9f5fac694437f1266260f86fe67d517941be2f48f5185b074898f46096f`다. 두 full run은 각각
  2,617 passed, 5 skipped, 0 failed, 0 errors와 같은 target을 기록했다.
- F1/F2: health r1은 세 lane `HEALTHY`였다. F1은 세 lane `GO`였다. intermediate F2의 GLM lane은
  `BLOCKED_PROVIDER`였고 이 영수증은 삭제하지 않는다. source-free health r2가 세 lane `HEALTHY`를 확인한 뒤
  같은 packet으로 F3 retry를 실행했고 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2가 모두 lane `GO`를 냈다.
  Claude는 다섯 직접 파일의 attestation을 F1과 F3 retry에 각각 남겼다. 단회 envelope의
  `REPEATABILITY_GAP`은 의도된 비승격 상태로 보존했다.
- G: `supervisor-review-r1-r3-retry-comparison.json`은 `FIX`, `repeat_exact=true`, semantic fingerprint
  `f954872a436d3a1b71dfda719b1088302a3ca0f80b3adcd40057eba9da76df42`다. 이 결과 기록은 evidence-time target 뒤에
  작성되며 해당 target이나 승인 범위를 바꾸지 않는다.

## 명시적 비주장

P2.4B.2.10이 `FIX_NARROW`가 되더라도 site-10 한 slot의 source tree identity만 뜻한다. browser CORS behavior,
cross-origin read, deployed allowlist correctness, source runtime behavior, scanner finding, true positive, false negative,
precision, recall, 다른 9개 source-flow slot, 전체 60 pair, H100, release는 계속 `HOLD`다.
