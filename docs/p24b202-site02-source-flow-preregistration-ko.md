# P2.4B.2.02 site-02 source-flow materialization 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)

## 한 문장 목표

P2.4A의 `site-02` SQL query slot에 대해 primary와 fixed-order reserve 두 candidate의
JavaScript/Express `vulnerable`, `fixed`, `negative` source tree를 새 external root에
deterministic template으로 materialize한다.

## 고정 binding

- slot: `site-02`, scenario `dev-site-02-sqli-query`, oracle `l3-gen-site-02-sqli-query`
- plane/family/language/framework: `site` / `source-flow` / `javascript` / `express`
- CWE/severity: `CWE-89` / `high`
- P2.4A generator profile: `deterministic-template-v1`
- candidate rank: primary `0`, reserve `1`; 총 2 candidate와 6 source tree
- primary route: `routes/account.js`, `req.query.email`
- reserve route: `routes/invoice.js`, `req.query.reference`
- source layout은 P2.4B.1의 `slots/site-02/candidate-<rank>/<state>` relative path를 그대로 쓴다.
  P2.4B.1 evidence root의 빈 directory는 읽기 전용이며 절대 수정하지 않는다.
- 각 tree에는 MIT `LICENSE`, canonical `package.json`, 하나의 JavaScript route source만 있다.

`materialize_l3_source_flow_slot.py`는 현재 `site-02`만 explicit configuration으로 허용한다.
다른 slot ID는 default renderer나 fallback 없이 `source_flow_slot_not_preregistered`로 거부한다.

## Tree 역할

| 상태 | source intent | 이 카드가 증명하지 않는 것 |
| --- | --- | --- |
| `vulnerable` | request query 값을 SQL string에 concat하는 조건을 보존 | live SQL injection exploit 성공 |
| `fixed` | placeholder와 bound parameter로 바꾼 bounded source change | 실제 DB functional correctness |
| `negative` | request input과 관계없는 static-state query control | scanner specificity 또는 test sensitivity |

primary는 account lookup, reserve는 invoice lookup이라는 서로 다른 template identity를 가진다.
이는 reserve 순서와 source tree identity를 위한 구분이다. 두 candidate의 실전 발생 빈도,
CWE severity 이외의 영향, detector performance를 뜻하지 않는다.

## Fail-closed 규칙

- preregistered blueprint/staging receipt/root이 external path가 아니거나 canonical validation을
  통과하지 못하면 거부한다.
- slot/rank/framework/profile/path binding이 고정값과 다르면 거부한다.
- stage root에 source를 넣은 흔적, symlink, unexpected source file/directory, source content
  tamper, receipt tamper, root binding mismatch는 거부한다.
- materialization root/receipt은 새 external path여야 한다. repository output, input/output overlap,
  overwrite를 거부한다.
- 두 run의 root-specific binding은 각 receipt가 따로 검증한다. repeat comparator는 source tree
  identity와 공통 stage-tree identity만 비교하며 absolute root path나 per-run artifact path는
  semantic drift로 취급하지 않는다.

## 실행 방법

P2.4B.1의 두 independent stage root를 read-only 입력으로 사용한다.

```powershell
python scripts/materialize_l3_source_flow_slot.py materialize `
  --slot-id site-02 `
  --blueprint <p24a-root>\blueprint-r1.json `
  --staging-receipt <p24b1-root>\staging-r1.json `
  --staging-root <p24b1-root>\stage-r1 `
  --materialization-root <external-evidence-root>\materialization-r1 `
  --output <external-evidence-root>\site02-r1.json

python scripts/materialize_l3_source_flow_slot.py materialize `
  --slot-id site-02 `
  --blueprint <p24a-root>\blueprint-r2.json `
  --staging-receipt <p24b1-root>\staging-r2.json `
  --staging-root <p24b1-root>\stage-r2 `
  --materialization-root <external-evidence-root>\materialization-r2 `
  --output <external-evidence-root>\site02-r2.json

python scripts/compare_l3_source_flow_slot_repeats.py `
  --slot-id site-02 `
  --first-blueprint <p24a-root>\blueprint-r1.json `
  --first-staging-receipt <p24b1-root>\staging-r1.json `
  --first-staging-root <p24b1-root>\stage-r1 `
  --first-materialization-root <external-evidence-root>\materialization-r1 `
  --first-receipt <external-evidence-root>\site02-r1.json `
  --second-blueprint <p24a-root>\blueprint-r2.json `
  --second-staging-receipt <p24b1-root>\staging-r2.json `
  --second-staging-root <p24b1-root>\stage-r2 `
  --second-materialization-root <external-evidence-root>\materialization-r2 `
  --second-receipt <external-evidence-root>\site02-r2.json `
  --output <external-evidence-root>\site02-r1-r2-comparison.json
```

## A-G gate

| Gate | P2.4B.2.02 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim을 external materialization 전에 고정 | `DONE` |
| B | site-02만 허용하는 strict slot materializer와 comparator를 target에 결속 | `DONE` - r2 baseline `e20c3a8a38f065e6b435c1adbeff646dda4c3dd32128b9660b0e5e775d27d3ba` |
| C | unsupported slot, receipt/tree/staging tamper, source-content tamper, vulnerable/fixed role swap, root binding, repository output, overlap, overwrite focused test | `DONE` - raw-free focused attestation `7 passed`, `0 failed`, `0 errors` |
| D | external root에서 primary/reserve 6 tree의 r1/r2 comparator 생성 | `DONE` - `repeat_exact=true`, `status=FIX` |
| E | current target baseline, focused/full regression, validate-current, diff check | `DONE_WITH_PRESERVED_HOLD` - r2 control HOLD 한 건을 보존하고, 같은 target의 r3/r4 full attestation이 각각 `2569 passed, 5 skipped, 0 failed, 0 errors` |
| F1/F2 | 같은 target/packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 번 검토 | `DONE` - 두 run 모두 전원 `GO`, 각 lane은 정확히 하나의 `REPEATABILITY_GAP` |
| G | machine 및 supervisor comparator가 `FIX`일 때만 `P2.4B.2.02` 기록 | `DONE` - 이 leaf만 `FIX_NARROW` |

## 실행 결과

최종 승격 evidence root는
`<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24b202-site02-source-flow-20260723-r2`다.
결속 target은 HEAD `04e9dd8e7dc788d8242db138278758303ba6f27d`, dirty path set SHA-256
`635f04238320cfd37a79e546f8bfe283838ea82252854d8f5bd2e77748934739`, dirty worktree SHA-256
`74e83870459b2ab4191bd026f12ecf2eef5613eb842a3d08eac12e716b28eb3c`다.

- baseline receipt 내부 SHA-256은 `e20c3a8a38f065e6b435c1adbeff646dda4c3dd32128b9660b0e5e775d27d3ba`,
  파일 SHA-256은 `e14fc4f201d4e807ce94687655c10ce982945e14157abfbb877f88e29097c6c4`다.
- r1/r2는 primary와 reserve 각각의 `vulnerable/fixed/negative` source tree, 총 6 tree와
  18 file을 materialize했다. receipt 파일 SHA-256은 각각
  `1704f42799abf019cd0e1844eb53a32c777acd653ec8f7ac2b1518d755fdbcc1`,
  `f70e979bf13b6279818285cd9a115eaf825affe36f8a506204be7685c615fb83`다.
- source comparator는 `repeat_exact=true`, `status=FIX`였고 파일 SHA-256은
  `30116025449a5d03628d03ddf51c60a3bd558bfc8dc235e2660d0a81af39d83a`다.
- focused attestation은 7 passed, 0 failed, 0 errors, 0 skipped이며 receipt 파일 SHA-256은
  `3bdb4a338f020c4460196da8bc5112081c86e10867b38def3d0956a6b8a56ae0`다.
- full regression r2는 `2568 passed, 1 failed, 5 skipped`의 `CONTROL_HOLD`였고 receipt SHA-256
  `c29c5a0879174df4be3b6eec3242f8c6d03444e161bb81d33a68a1ae2b1a451b`로 보존했다. 같은 target의
  r3/r4는 각각 `2569 passed, 5 skipped, 0 failed, 0 errors`로 `COMPLETE`였고 파일 SHA-256은
  `d3750caa8bb3e7c335075500c841e815586d08f22212951feeba461e40483984`,
  `3520e9b198bb472f50c76848339ced017c135d3b05aa9b57c2452e0e09f6e0af`다. r2 failure의 raw test
  output은 raw-free attestation 계약상 보관하지 않았으며, r2 receipt를 삭제하거나 clean 결과로
  대체하지 않았다.
- health r2는 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 전원 `HEALTHY`였다.
  Claude direct-files, Grok sanitized-packet, GLM sanitized-packet의 두 review run은 전부
  `GO`, blocker 0, claim boundary confirmed, `REPEATABILITY_GAP` 하나였다. supervisor comparator는
  fingerprint `10844b79676428c5b2b7459b2102ee811dc15a9805585398a6e0e27ae2b8526e`,
  `repeat_exact=true`, `status=FIX`였고 파일 SHA-256은
  `b0da14ddac26e43681977c79b0afd01122e8d71f6933f8f3a5af5dcd9961923b`다.

## 명시적 비주장

P2.4B.2.02가 `FIX_NARROW`가 되더라도 site-02 한 slot의 **source tree identity**만 뜻한다.
exploit/functional/negative execution, machine admission, scanner finding, true positive, false negative,
precision, recall, Korean privacy coverage, 다른 18개 source-flow slot, 전체 60 pair, H100, release는
계속 `HOLD`다.

## 보존된 감독 HOLD와 재시도 조건

첫 호출 `supervisor-review-r1`은 `field-id`의 대문자 `P`가 runner 형식에 맞지 않아 reviewer
receipt 전에 거부됐다. 첫 실제 검토 `supervisor-review-r1-retry`는 Grok 4.5와 Cline GLM 5.2가
`GO`와 nonblocking `REPEATABILITY_GAP`을 냈지만, Claude Opus 4.8이
`TEST_ATTESTATION_GAP`으로 `HOLD`를 냈다. 이 결과는 삭제하거나 승인 근거로 바꾸지 않는다.

후속 r2 target은 source-content tamper와 vulnerable/fixed role-swap focused test, raw-free focused
attestation, preserved r2 full-regression HOLD 및 same-target r3/r4 clean receipt를 packet에 결속했다.
이 packet의 Claude/Grok/GLM r1/r2 semantic comparator가 `FIX`이므로, 과거 실패를 감추지 않은 채
P2.4B.2.02의 좁은 source-tree 계약만 `FIX_NARROW`로 기록한다.
