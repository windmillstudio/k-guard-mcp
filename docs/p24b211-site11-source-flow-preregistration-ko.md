# P2.4B.2.11 site-11 source-flow materialization 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW`  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)

## 한 문장 목표

P2.4A의 `site-11` template-XSS slot에 대해 primary와 fixed-order reserve 두 candidate의
Python/Django `vulnerable`, `fixed`, `negative` source tree를 새 external root에 deterministic template로
materialize하는 계약을 외부 source tree 생성 전에 고정한다.

## 고정 binding

- slot: `site-11`, scenario `dev-site-11-template-xss`, oracle `l3-gen-site-11-template-xss`
- plane/family/language/framework: `site` / `source-flow` / `python` / `django`; blueprint coverage tag는 `express`
- CWE/severity/profile: `CWE-79` / `high` / `deterministic-template-v1`
- candidate rank: primary `0`, reserve `1`; 총 2 candidate와 6 source tree
- primary view: `views/checkout.py`, handler `checkout_notice`, query parameter `message`, static negative text
  `Checkout is available.`
- reserve view: `views/integrations.py`, handler `integration_notice`, query parameter `notice`, static negative text
  `Integrations are available.`
- `vulnerable` tree는 Django request query 값을 `mark_safe`로 HTML paragraph source에 넣는 source condition을 보존한다.
  `fixed` tree는 같은 query 값을 `escape`한 뒤 HTML paragraph source에 넣는다. `negative` tree는 request query를 읽지 않고
  candidate별 static paragraph만 반환한다.
- source layout은 P2.4B.1의 `slots/site-11/candidate-<rank>/<state>` relative path를 그대로 쓴다.
  P2.4B.1 external stage root는 read-only이며 절대 수정하지 않는다.
- 각 tree에는 MIT `LICENSE`, canonical `pyproject.toml`, 하나의 Python Django view source만 있다.
- site-11 materializer/comparator는 별도 versioned file로 만든다. 앞선 leaf의 source, receipt, comparator byte
  binding을 바꾸거나 승인 근거로 재사용하지 않는다.

## Tree 역할

| 상태 | source intent | 이 카드가 증명하지 않는 것 |
| --- | --- | --- |
| `vulnerable` | request query와 `mark_safe` HTML source condition | browser rendering, script execution, detector finding |
| `fixed` | 같은 query에 `escape`를 적용하는 bounded source change | Django runtime escaping 또는 template integration correctness |
| `negative` | request query 없이 static HTML paragraph를 반환하는 control | scanner specificity 또는 test sensitivity |

primary와 reserve는 view path, handler, parameter, static text가 다르다. 이 구분은 reserve 순서와 source tree identity를 위한 것이며,
실전 template-XSS 빈도나 detector performance를 의미하지 않는다. materializer는 source text만 생성하며 Django runtime,
HTTP request, browser, network request, runtime output 반환을 하지 않는다.

## Fail-closed 규칙

- preregistered blueprint/staging receipt/root이 external path가 아니거나 canonical validation을 통과하지 못하면
  거부한다.
- slot/rank/framework/profile/path binding이 고정값과 다르면 거부한다.
- stage root source 삽입, symlink, unexpected source file/directory, receipt/source tamper, role swap, root binding
  mismatch, repository output, input/output overlap, overwrite를 모두 거부한다.
- primary와 reserve 중 하나라도 없거나 `vulnerable`/`fixed`/`negative` 세 역할이 구분되지 않으면 materialization을
  성공으로 표시하지 않는다.
- 이 카드는 source writer다. 외부 대상, localhost, 컨테이너, service endpoint, Django runtime, browser로
  generated source를 실행하지 않는다.

## A-G gate

| Gate | P2.4B.2.11 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim과 primary/reserve view/handler/parameter/static-text identity를 external source 생성 전에 고정 | `DONE` |
| B | site-11만 허용하는 immutable materializer와 comparator를 target에 결속 | `DONE` - site-11 전용 materializer/comparator와 source hash binding |
| C | receipt/tree/staging tamper, role swap, root binding, repository output, overlap, overwrite focused test | `DONE` - materializer/comparator focused tests 6 passed, 0 failed |
| D | external root에서 primary/reserve 6 tree의 r1/r2 comparator 생성 | `DONE` - comparator `FIX`, semantic fingerprint `2c0c4e8a7e73b899abea04722ce1a53e641d8bdbe1d184116d8d30dfb8d1f2ed` |
| E | current target baseline, focused/full regression, validate-current, diff check | `DONE` - focused 6/6, clean full r1/r2 각각 2,623 passed, 5 skipped, 0 failed, 0 errors; baseline current 및 diff check 통과 |
| F1/F2 | 같은 target/packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 번 검토 | `DONE` - 두 run 모두 세 lane `GO`, Claude direct-file 5/5, supervisor comparator `FIX` |
| G | machine 및 supervisor comparator가 `FIX`일 때만 `P2.4B.2.11` 기록 | `DONE` - evidence-time target, machine comparator, 3AI comparator와 명시적 비주장을 결속 |

## 완료 evidence

- D: `phase2-p24b211-site11-source-flow-20260724-r1/site11-r1-r2-comparison.json`은
  `FIX`, `repeat_exact=true`이며 materializer SHA-256은
  `2f460e6cc65d5246776bf8043f1334ef57134ee9be5418d1e53c5330a88a43db`다.
- E: evidence-time baseline receipt는
  `9fc50b2be6f121de98a86ad60364489527cff522b6199652c4b4f4ada31db999`다. focused receipt는
  `f403d5fb47c3ba50b75d8d9efe759388ddb61d40e3ee3bd825138e0399b9e2a5`이며 6 passed, 0 failed,
  0 errors를 기록했다. clean full r1/r2 receipt는 각각
  `a6101fcc18ac53c3c47943e8667f88a61790a385faef446d18225866fae54f00`,
  `e10648fbeba73362dcfe58880857fd0713dd03f4109b6c51ab0e442ad5f846b7`다. 두 full run은 각각
  2,623 passed, 5 skipped, 0 failed, 0 errors와 같은 target을 기록했다.
- F1/F2: source-free health r1에서 세 lane이 모두 `HEALTHY`였다. Claude Opus 4.8, Grok 4.5, Cline GLM 5.2는
  두 run 모두 lane `GO`를 냈고, Claude는 다섯 직접 파일의 attestation을 두 번 남겼다. 단회 envelope의
  `REPEATABILITY_GAP`은 의도된 비승격 상태로 보존했다.
- G: `supervisor-review-r1-r2-comparison.json`은 `FIX`, `repeat_exact=true`, semantic fingerprint
  `e047b1bbf621c01ba50e771077f1859ba304fe5754572c6fab26e05bd3f8a5b8`다. 이 결과 기록은 evidence-time target 뒤에
  작성되며 해당 target이나 승인 범위를 바꾸지 않는다.

## 명시적 비주장

P2.4B.2.11이 `FIX_NARROW`가 되더라도 site-11 한 slot의 source tree identity만 뜻한다. browser rendering,
script execution, deployed Django configuration, source runtime behavior, scanner finding, true positive, false negative,
precision, recall, 다른 8개 source-flow slot, 전체 60 pair, H100, release는 계속 `HOLD`다.
