# P2.4B.2.06 site-06 source-flow materialization 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)

## 한 문장 목표

P2.4A의 `site-06` SSRF slot에 대해 primary와 fixed-order reserve 두 candidate의 JavaScript/Express
`vulnerable`, `fixed`, `negative` source tree를 새 external root에 deterministic transform으로 materialize하는
계약을 source 생성 전에 고정한다.

## 고정 binding

- slot: `site-06`, scenario `dev-site-06-ssrf-fetch`, oracle `l3-gen-site-06-ssrf-fetch`
- plane/family/language/framework: `site` / `source-flow` / `javascript` / `express`
- CWE/severity/profile: `CWE-918` / `high` / `deterministic-transform-v1`
- candidate rank: primary `0`, reserve `1`; 총 2 candidate와 6 source tree
- primary route: `routes/preview.js`, request query field `url`, approved host
  `preview.internal.test`, static negative target `https://preview.internal.test/health`
- reserve route: `routes/avatar.js`, request query field `imageUrl`, approved host
  `cdn.internal.test`, static negative target `https://cdn.internal.test/avatar.png`
- source layout은 P2.4B.1의 `slots/site-06/candidate-<rank>/<state>` relative path를 그대로 쓴다.
  P2.4B.1 external stage root는 read-only이며 절대 수정하지 않는다.
- 각 tree에는 MIT `LICENSE`, canonical `package.json`, 하나의 JavaScript Express route source만 있다.
- site-06 materializer/comparator는 별도 versioned file로 만든다. 기존 leaf의 receipt byte binding을 바꾸지 않는다.

## Tree 역할

| 상태 | source intent | 이 카드가 증명하지 않는 것 |
| --- | --- | --- |
| `vulnerable` | request query target을 scheme/host validation 없이 injected `httpClient.get(...)`에 전달하는 source condition | 실제 HTTP 요청, SSRF 재현 또는 detector finding |
| `fixed` | `https`와 candidate별 approved host를 모두 확인한 target만 injected client에 전달하고 나머지는 local error response로 끝내는 bounded source change | 실제 allowlist 동작 또는 framework/runtime correctness |
| `negative` | request input을 읽지 않고 candidate별 static internal test target만 injected client에 전달하는 control | scanner specificity 또는 test sensitivity |

primary와 reserve는 route, query key, approved host, static target이 다르다. 이 구분은 reserve 순서와
source tree identity를 위한 것이며, 실전 SSRF 빈도나 detector performance를 의미하지 않는다. 소스에는
synthetic `.test` host만 적고 materializer는 source text만 생성한다. 외부 HTTP 요청, DNS 조회, browser,
payload, URL 결과 반환은 이 카드에서 금지한다.

## Fail-closed 규칙

- preregistered blueprint/staging receipt/root이 external path가 아니거나 canonical validation을 통과하지
  못하면 거부한다.
- slot/rank/framework/profile/path binding이 고정값과 다르면 거부한다.
- stage root source 삽입, symlink, unexpected source file/directory, receipt/source tamper, role swap,
  root binding mismatch, repository output, input/output overlap, overwrite를 모두 거부한다.
- primary와 reserve 중 하나라도 없거나 `vulnerable`/`fixed`/`negative` 세 역할이 구분되지 않으면
  materialization을 성공으로 표시하지 않는다.
- 이 카드는 source writer다. 외부 대상, localhost, 컨테이너, 서비스 endpoint로 실제 요청을 보내지 않는다.

## A-G gate

| Gate | P2.4B.2.06 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim과 primary/reserve route/query/allowlist/static identity를 source 생성 전에 고정 | `DONE` |
| B | site-06만 허용하는 immutable materializer와 comparator를 target에 결속 | `DONE` - site-06 전용 materializer/comparator와 source hash binding |
| C | receipt/tree/staging tamper, role swap, root binding, repository output, overlap, overwrite focused test | `DONE` - materializer/comparator focused tests 6 passed, 0 failed |
| D | external root에서 primary/reserve 6 tree의 r1/r2 comparator 생성 | `DONE` - comparator `FIX`, `repeat_exact=true`, semantic fingerprint `7c06405a6c07ce7390bdbef88cd5cb82869219f57ff24f288e6ebe33818e64ff` |
| E | current target baseline, focused/full regression, validate-current, diff check | `DONE` - focused 6 passed; isolated full r1/r2 각각 2,593 passed, 5 skipped, 0 failed; evidence-time target unchanged |
| F1/F2 | 같은 target/packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 번 검토 | `DONE` - 세 lane 모두 F1/F2 `GO`; 각 단회 run의 `REPEATABILITY_GAP`은 보존 |
| G | machine 및 supervisor comparator가 `FIX`일 때만 `P2.4B.2.06` 기록 | `DONE` - supervisor comparator `FIX`, `repeat_exact=true`, semantic fingerprint `465feeb19cb132d43616b81cafcecd4577e31c52190e12d7ccbd997f5db97739` |

## 완료 증거

- evidence root: `<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24b206-site06-source-flow-20260724-r1`
- baseline/validate receipt: `6b929ee76b6cddbb26dd50937d678218f410dd7b3fee7c490b7f7abbbb9c138c`
- focused regression receipt: `a95b208df21edaaef384c18bb0f44246b96a1f62393e3add70082ace9994d077`
- isolated full regression r1/r2 receipt: `47066a8c90014c8fc57911f14668a53496ba4f52272f11bbd81dcbc765017adb` /
  `cabafdb7fdb447fc6e6910ce1900f891ab48316f0b41d218b8a61a0cf80101cd`
- D machine comparator: `site06-r1-r2-comparison.json` is `FIX`, repeat exact; materializer SHA-256
  `d6baee6d4a3f4a293bca9375d3a802a8f6aa0b4713eb9c967f8c30497a303e97`
- F1/F2 supervisor packet: Claude Opus 4.8 direct-file review, Grok 4.5, Cline GLM 5.2가 모두 각 run에서
  lane `GO`를 냈다. top-level single-run envelope의 intentional `REPEATABILITY_GAP`은 승격 근거가 아니며,
  `supervisor-review-r1-r2-comparison.json`의 two-run semantic comparator `FIX`만 G의 근거다.
- 위 evidence는 HEAD `04e9dd8e7dc788d8242db138278758303ba6f27d`와 evidence-time dirty target에 결속됐다.
  이 문서의 완료 기록은 증거 생성 뒤의 문서 변경이며, 기존 evidence target을 현재 worktree의 승인으로
  바꾸지 않는다.

## 명시적 비주장

P2.4B.2.06이 `FIX_NARROW`가 되더라도 site-06 한 slot의 source tree identity만 뜻한다. HTTP/SSRF
execution, network egress control, scanner finding, true positive, false negative, precision, recall, 다른
13개 source-flow slot, 전체 60 pair, H100, release는 계속 `HOLD`다.
