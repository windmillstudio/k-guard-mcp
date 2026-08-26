# P2.4B.2.03 site-03 source-flow materialization 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)

## 한 문장 목표

P2.4A의 `site-03` command-exec slot에 대해 primary와 fixed-order reserve 두 candidate의
JavaScript/Express `vulnerable`, `fixed`, `negative` source tree를 새 external root에
deterministic transform으로 materialize한다.

## 고정 binding

- slot: `site-03`, scenario `dev-site-03-command-exec`, oracle `l3-gen-site-03-command-exec`
- plane/family/language/framework: `site` / `source-flow` / `javascript` / `express`
- CWE/severity: `CWE-78` / `critical`
- P2.4A generator profile: `deterministic-transform-v1`
- candidate rank: primary `0`, reserve `1`; 총 2 candidate와 6 source tree
- primary route: `routes/archive.js`, request field `target`
- reserve route: `routes/export.js`, request field `format`
- source layout은 P2.4B.1의 `slots/site-03/candidate-<rank>/<state>` relative path를 그대로 쓴다.
  P2.4B.1 evidence root의 빈 directory는 읽기 전용이며 절대 수정하지 않는다.
- 각 tree에는 MIT `LICENSE`, canonical `package.json`, 하나의 JavaScript route source만 있다.
- site-02 receipt가 binding한 materializer 파일은 수정하지 않는다. site-03은 별도 versioned
  materializer와 comparator를 가져 이전 leaf receipt를 무효화하지 않는다.

## Tree 역할

| 상태 | source intent | 이 카드가 증명하지 않는 것 |
| --- | --- | --- |
| `vulnerable` | request query 값을 shell command string에 concat해 `runner.exec(...)`에 전달하는 조건을 보존 | live command injection 성공 |
| `fixed` | fixed allowlist와 argument array를 `runner.execFile(...)`로 전달하는 bounded source change | 실제 host command 또는 functional correctness |
| `negative` | request input과 관계없는 static argument-array command control | scanner specificity 또는 test sensitivity |

primary는 archive target, reserve는 export format이라는 서로 다른 transform identity를 가진다.
이는 reserve 순서와 source tree identity를 위한 구분이며, 실전 발생 빈도나 detector performance를 뜻하지 않는다.

## Fail-closed 규칙

- preregistered blueprint/staging receipt/root이 external path가 아니거나 canonical validation을
  통과하지 못하면 거부한다.
- slot/rank/framework/profile/path binding이 고정값과 다르면 거부한다.
- stage root에 source를 넣은 흔적, symlink, unexpected source file/directory, source content
  tamper, vulnerable/fixed role swap, receipt tamper, root binding mismatch는 거부한다.
- materialization root/receipt은 새 external path여야 한다. repository output, input/output overlap,
  overwrite를 거부한다.
- 각 r1/r2 receipt는 자신의 materializer byte hash와 root binding을 검증한다. repeat comparator는
  source tree identity와 공통 stage-tree identity만 비교하며 absolute root path를 semantic drift로
  취급하지 않는다.

## 실행 방법

P2.4B.1의 두 independent stage root를 read-only 입력으로 사용한다. materializer는 source를
생성할 뿐 command를 실행하지 않는다.

```powershell
python scripts/materialize_l3_source_flow_site03.py materialize `
  --blueprint <p24a-root>\blueprint-r1.json `
  --staging-receipt <p24b1-root>\staging-r1.json `
  --staging-root <p24b1-root>\stage-r1 `
  --materialization-root <external-evidence-root>\materialization-r1 `
  --output <external-evidence-root>\site03-r1.json

python scripts/materialize_l3_source_flow_site03.py materialize `
  --blueprint <p24a-root>\blueprint-r2.json `
  --staging-receipt <p24b1-root>\staging-r2.json `
  --staging-root <p24b1-root>\stage-r2 `
  --materialization-root <external-evidence-root>\materialization-r2 `
  --output <external-evidence-root>\site03-r2.json

python scripts/compare_l3_source_flow_site03_repeats.py `
  --first-blueprint <p24a-root>\blueprint-r1.json `
  --first-staging-receipt <p24b1-root>\staging-r1.json `
  --first-staging-root <p24b1-root>\stage-r1 `
  --first-materialization-root <external-evidence-root>\materialization-r1 `
  --first-receipt <external-evidence-root>\site03-r1.json `
  --second-blueprint <p24a-root>\blueprint-r2.json `
  --second-staging-receipt <p24b1-root>\staging-r2.json `
  --second-staging-root <p24b1-root>\stage-r2 `
  --second-materialization-root <external-evidence-root>\materialization-r2 `
  --second-receipt <external-evidence-root>\site03-r2.json `
  --output <external-evidence-root>\site03-r1-r2-comparison.json
```

## A-G gate

| Gate | P2.4B.2.03 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim을 source 생성 전에 고정 | `DONE` |
| B | site-03만 허용하는 immutable materializer와 comparator를 target에 결속 | `DONE` - baseline receipt `54b2a75c9529cdc988483d1518709ec920eea46ed5e2eee63d6627e36e552b5d` |
| C | receipt/tree/staging tamper, role swap, root binding, repository output, overlap, overwrite focused test | `DONE` - raw-free focused attestation `6 passed`, `0 failed`, `0 errors` |
| D | external root에서 primary/reserve 6 tree의 r1/r2 comparator 생성 | `DONE` - `repeat_exact=true`, `status=FIX` |
| E | current target baseline, focused/full regression, validate-current, diff check | `DONE` - full attestation `2575 passed, 5 skipped, 0 failed, 0 errors` |
| F1/F2 | 같은 target/packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 번 검토 | `DONE` - clarified packet r3/r4 전원 `GO`, 각각 nonblocking `REPEATABILITY_GAP` 하나 |
| G | machine 및 supervisor comparator가 `FIX`일 때만 `P2.4B.2.03` 기록 | `DONE` - 이 leaf만 `FIX_NARROW` |

## 실행 결과

승격 evidence root는
`<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24b203-site03-source-flow-20260723-r1`다.
결속 target은 HEAD `04e9dd8e7dc788d8242db138278758303ba6f27d`, dirty path set SHA-256
`c7b536fabecf1f258db22f48e190c6f6ad5968f25465475389b731c221f64d63`, dirty worktree SHA-256
`208dc719f587c6b71e9fd6990dcdd204846c4e1f3939b0190be5670c5a0dc61e`다.

- baseline receipt 내부 SHA-256은 `54b2a75c9529cdc988483d1518709ec920eea46ed5e2eee63d6627e36e552b5d`,
  파일 SHA-256은 `48508bfa04a30db600a0b4a785b718aae588d5fda97ac6a3099d2bf2b92e9075`다.
- r1/r2는 primary와 reserve 각각의 `vulnerable/fixed/negative` source tree, 총 6 tree와
  18 file을 materialize했다. receipt 파일 SHA-256은 각각
  `8c5f45d5d98fd4756cc08aa3a3b8cfc199d965d59649924f1ce3d883c935f352`,
  `57006c9b19706cdc20608f4c96318f4cb8abf9dbf105d05baf8eeddc65b2dfab`다.
- source comparator는 `repeat_exact=true`, `status=FIX`, semantic fingerprint
  `8c23649b93e14aa2f9ea6723bc4bf8b3a0b0ab43a319bd7a3c781475500153a6`였고 파일 SHA-256은
  `fa90466c622cd9a8075a263b83a634a4dd6c7f404cfa5c03ef5db970aeb66337`다.
- focused regression receipt 내부 SHA-256은
  `1f0c777df8d985eca5f61c7c89eb7d94d9a7fb6d59f78a249d3d79bc7d2d74a9`이며 `6 passed`,
  `0 failed`, `0 errors`, `0 skipped`였다. 파일 SHA-256은
  `8dab0a33ab0f8d232e4b60aeb7fc7c7d8359c0b052c400e77ce2c8deb94ba7ec`다.
- full regression receipt 내부 SHA-256은
  `241dfd2c05a43e3e7d05b98e35eef63586e565522e93f3137590eccdbef3a9ea`이며 `2575 passed`,
  `5 skipped`, `0 failed`, `0 errors`였다. 파일 SHA-256은
  `3fa9047c80cf7f06cbd27a3f7330b8c72bcc4548dbb1090de99d80e2082d7572`다.
- health r1은 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 전원 `HEALTHY`였고 파일 SHA-256은
  `92c366f054be1aaa2f8ef887ee1c232004bfa9623ec216f659603935be5a3e`다.
- 첫 supervisor packet r1은 전원 `GO`와 `REPEATABILITY_GAP`을 냈다. 같은 packet의 r2에서
  GLM이 `TEST_ATTESTATION_GAP`으로 `HOLD`를 내어 이 결과는 삭제하지 않고 보존했다. focused/full
  attestation이 모두 통과했고 first-run repeat field는 nonblocking이라는 문장을 명확히 한 새 raw-free
  packet r3/r4에서는 세 lane 모두 `GO`와 `REPEATABILITY_GAP` 하나를 냈다. r3/r4 semantic
  comparator는 fingerprint `e48a036940aa3edb67ef635467687862b4859208e033e5d91a936540dd99417e`,
  `repeat_exact=true`, `status=FIX`였고 파일 SHA-256은
  `2edef483214e3d79db86bb8b6f35c26f811e4757c6783de4e77334c589b46c8d`다.

## 명시적 비주장

P2.4B.2.03이 `FIX_NARROW`가 되더라도 site-03 한 slot의 **source tree identity**만 뜻한다.
exploit/functional/negative execution, machine admission, scanner finding, true positive, false negative,
precision, recall, Korean privacy coverage, 다른 18개 source-flow slot, 전체 60 pair, H100, release는
계속 `HOLD`다.
