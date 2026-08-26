# P2.4B.2.12 site-12 source-flow materialization 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW`  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)

## 한 문장 목표

P2.4A의 `site-12` file-read slot에 대해 primary와 fixed-order reserve 두 candidate의
Python/Flask `vulnerable`, `fixed`, `negative` source tree를 새 external root에 deterministic transform으로
materialize하는 계약을 외부 source tree 생성 전에 고정한다.

## 고정 binding

- slot: `site-12`, scenario `dev-site-12-file-read`, oracle `l3-gen-site-12-file-read`
- plane/family/language/framework: `site` / `source-flow` / `python` / `flask`; blueprint coverage tag는 `express`
- CWE/severity/profile: `CWE-22` / `high` / `deterministic-transform-v1`
- candidate rank: primary `0`, reserve `1`; 총 2 candidate와 6 source tree
- primary route: `routes/exports.py`, handler `download_export`, query parameter `file`, bounded root
  `/srv/app/exports`, static negative text `Export list is available.`
- reserve route: `routes/templates.py`, handler `download_template`, query parameter `name`, bounded root
  `/srv/app/templates`, static negative text `Template list is available.`
- `vulnerable` tree는 Flask request query 값을 `Path` base root에 그대로 결합해 `read_text`하는 source condition을 보존한다.
  `fixed` tree는 candidate path를 `resolve()`하고 base root가 parent chain에 없으면 `404`를 반환한다. `negative` tree는
  request query를 읽지 않고 candidate별 static text만 반환한다.
- source layout은 P2.4B.1의 `slots/site-12/candidate-<rank>/<state>` relative path를 그대로 쓴다.
  P2.4B.1 external stage root는 read-only이며 절대 수정하지 않는다.
- 각 tree에는 MIT `LICENSE`, canonical `pyproject.toml`, 하나의 Python Flask route source만 있다.
- site-12 materializer/comparator는 별도 versioned file로 만든다. 앞선 leaf의 source, receipt, comparator byte
  binding을 바꾸거나 승인 근거로 재사용하지 않는다.

## Tree 역할

| 상태 | source intent | 이 카드가 증명하지 않는 것 |
| --- | --- | --- |
| `vulnerable` | request path parameter를 base path에 결합해 읽는 source condition | file access, traversal exploit, detector finding |
| `fixed` | resolved path가 base root 안에 있는지 확인하는 bounded source change | Flask runtime containment correctness 또는 access-control policy |
| `negative` | request parameter 없이 static text를 반환하는 control | scanner specificity 또는 test sensitivity |

primary와 reserve는 route, handler, parameter, base path, static text가 다르다. 이 구분은 reserve 순서와 source tree identity를 위한 것이며,
실전 file-read 빈도나 detector performance를 의미하지 않는다. materializer는 source text만 생성하며 Flask runtime,
filesystem read, HTTP request, browser, network request, runtime output 반환을 하지 않는다.

## Fail-closed 규칙

- preregistered blueprint/staging receipt/root이 external path가 아니거나 canonical validation을 통과하지 못하면
  거부한다.
- slot/rank/framework/profile/path binding이 고정값과 다르면 거부한다.
- stage root source 삽입, symlink, unexpected source file/directory, receipt/source tamper, role swap, root binding
  mismatch, repository output, input/output overlap, overwrite를 모두 거부한다.
- primary와 reserve 중 하나라도 없거나 `vulnerable`/`fixed`/`negative` 세 역할이 구분되지 않으면 materialization을
  성공으로 표시하지 않는다.
- 이 카드는 source writer다. 외부 대상, localhost, 컨테이너, service endpoint, Flask runtime, filesystem, browser로
  generated source를 실행하지 않는다.

## A-G gate

| Gate | P2.4B.2.12 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim과 primary/reserve route/handler/parameter/base/static-text identity를 external source 생성 전에 고정 | `DONE` |
| B | site-12만 허용하는 immutable materializer와 comparator를 target에 결속 | `DONE` - site-12 전용 materializer/comparator와 source hash binding |
| C | receipt/tree/staging tamper, role swap, root binding, repository output, overlap, overwrite focused test | `DONE` - materializer/comparator focused tests 6 passed, 0 failed |
| D | external root에서 primary/reserve 6 tree의 r1/r2 comparator 생성 | `DONE` - comparator `FIX`, semantic fingerprint `ffc7c7c98eb23ae2166dae5a3ec14db0480b80c152deb12fb4c309ef04c7773c` |
| E | current target baseline, focused/full regression, validate-current, diff check | `DONE` - focused 6/6, clean full r1/r2 각각 2,629 passed, 5 skipped, 0 failed, 0 errors; baseline current 및 diff check 통과 |
| F1/F2 | 같은 target/packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 번 검토 | `DONE` - 두 run 모두 세 lane `GO`, Claude direct-file 5/5, supervisor comparator `FIX` |
| G | machine 및 supervisor comparator가 `FIX`일 때만 `P2.4B.2.12` 기록 | `DONE` - evidence-time target, machine comparator, 3AI comparator와 명시적 비주장을 결속 |

## 완료 evidence

- D: `phase2-p24b212-site12-source-flow-20260724-r1/site12-r1-r2-comparison.json`은 `FIX`,
  `repeat_exact=true`이며 materializer SHA-256은 `f7cb49e64e6455f29154b344422d982f536a5c68fcb7a0434b3bdb1af2672f38`다.
- E: baseline receipt `7da57efe48f8d4863194faa04e1a7580f941e29f88ff2c71f479587dee942c57`, focused receipt
  `eb6f9a175aa7e1fed0b8a29c5731c86086070bb640978dae554cb111bc1d3659`, clean full r1/r2 receipt
  `91e7591a7588f3092713287a841275d5e36a54a9f238d42c65a14f4a1103724e`,
  `005265aaa03ae06e02e2dc35aa35625fa2397b9b5cb27b569b02264337da07d2`를 기록했다. full run 두 번은 각각
  2,629 passed, 5 skipped, 0 failed, 0 errors와 같은 target을 기록했다.
- F1/F2: source-free health r1에서 세 lane이 `HEALTHY`였고 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2가
  두 run 모두 lane `GO`를 냈다. Claude는 다섯 직접 파일의 attestation을 두 번 남겼으며 단회
  `REPEATABILITY_GAP`은 비승격 상태로 보존했다.
- G: `supervisor-review-r1-r2-comparison.json`은 `FIX`, `repeat_exact=true`, semantic fingerprint
  `083adab1b6226325efa622403b67ff07a253f26f377ce7aeb273836881267ce1`다.

## 명시적 비주장

P2.4B.2.12가 `FIX_NARROW`가 되더라도 site-12 한 slot의 source tree identity만 뜻한다. filesystem read,
path traversal exploit, deployed Flask configuration, source runtime behavior, scanner finding, true positive, false negative,
precision, recall, 다른 7개 source-flow slot, 전체 60 pair, H100, release는 계속 `HOLD`다.
