# P2.4B.2.04 site-04 source-flow materialization 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)

## 한 문장 목표

P2.4A의 `site-04` path-traversal slot에 대해 primary와 fixed-order reserve 두 candidate의
TypeScript/Next.js `vulnerable`, `fixed`, `negative` source tree를 새 external root에
deterministic fixture로 materialize할 수 있는 계약을 먼저 고정한다.

## 고정 binding

- slot: `site-04`, scenario `dev-site-04-path-traversal`, oracle `l3-gen-site-04-path-traversal`
- plane/family/language/framework: `site` / `source-flow` / `typescript` / `nextjs`
- CWE/severity: `CWE-22` / `high`
- P2.4A generator profile: `deterministic-fixture-v1`
- candidate rank: primary `0`, reserve `1`; 총 2 candidate와 6 source tree
- primary route: `app/api/report/route.ts`, request query field `name`, fixture root `/srv/reports`,
  static negative filename `summary.txt`
- reserve route: `app/api/download/route.ts`, request query field `document`, fixture root `/srv/exports`,
  static negative filename `terms.pdf`
- source layout은 P2.4B.1의 `slots/site-04/candidate-<rank>/<state>` relative path를 그대로 쓴다.
  P2.4B.1 evidence root의 빈 directory는 읽기 전용이며 절대 수정하지 않는다.
- 각 tree에는 MIT `LICENSE`, canonical `package.json`, 하나의 TypeScript route source만 있다.
- site-01/site-02/site-03 materializer와 comparator는 receipt byte binding을 가진다. site-04는
  별도 versioned materializer와 comparator를 가져 이전 leaf receipt를 무효화하지 않는다.

## Tree 역할

| 상태 | source intent | 이 카드가 증명하지 않는 것 |
| --- | --- | --- |
| `vulnerable` | request query filename을 `path.join(fixtureRoot, input)`에 그대로 넣고 `readFile(...)`에 전달하는 조건을 보존 | 실제 파일 접근 또는 traversal exploit 성공 |
| `fixed` | `path.resolve`와 `path.relative` 기반 root-confinement 검사를 거친 bounded source change | 실제 host file system 또는 functional correctness |
| `negative` | request input을 읽지 않는 static filename control | scanner specificity 또는 test sensitivity |

primary는 report file, reserve는 download file이라는 서로 다른 fixture identity를 가진다.
이는 reserve 순서와 source tree identity를 위한 구분이며, 실전 발생 빈도나 detector performance를 뜻하지 않는다.

## Fail-closed 규칙

- preregistered blueprint/staging receipt/root이 external path가 아니거나 canonical validation을
  통과하지 못하면 거부한다.
- slot/rank/framework/profile/path binding이 고정값과 다르면 거부한다.
- stage root에 source를 넣은 흔적, symlink, unexpected source file/directory, source content
  tamper, vulnerable/fixed role swap, receipt tamper, root binding mismatch는 거부한다.
- materialization root/receipt은 새 external path여야 한다. repository output, input/output overlap,
  overwrite를 거부한다.
- source materialization은 route text만 생성한다. HTTP request, `readFile`, 실제 local file,
  traversal payload를 실행하거나 반환하지 않는다.

## 실행 방법

P2.4B.1의 두 independent stage root를 read-only 입력으로 사용한다. materializer는 source를
생성할 뿐 HTTP request 또는 file read를 실행하지 않는다.

```powershell
python scripts/materialize_l3_source_flow_site04.py materialize `
  --blueprint <p24a-root>\blueprint-r1.json `
  --staging-receipt <p24b1-root>\staging-r1.json `
  --staging-root <p24b1-root>\stage-r1 `
  --materialization-root <external-evidence-root>\materialization-r1 `
  --output <external-evidence-root>\site04-r1.json

python scripts/materialize_l3_source_flow_site04.py materialize `
  --blueprint <p24a-root>\blueprint-r2.json `
  --staging-receipt <p24b1-root>\staging-r2.json `
  --staging-root <p24b1-root>\stage-r2 `
  --materialization-root <external-evidence-root>\materialization-r2 `
  --output <external-evidence-root>\site04-r2.json

python scripts/compare_l3_source_flow_site04_repeats.py `
  --first-blueprint <p24a-root>\blueprint-r1.json `
  --first-staging-receipt <p24b1-root>\staging-r1.json `
  --first-staging-root <p24b1-root>\stage-r1 `
  --first-materialization-root <external-evidence-root>\materialization-r1 `
  --first-receipt <external-evidence-root>\site04-r1.json `
  --second-blueprint <p24a-root>\blueprint-r2.json `
  --second-staging-receipt <p24b1-root>\staging-r2.json `
  --second-staging-root <p24b1-root>\stage-r2 `
  --second-materialization-root <external-evidence-root>\materialization-r2 `
  --second-receipt <external-evidence-root>\site04-r2.json `
  --output <external-evidence-root>\site04-r1-r2-comparison.json
```

## A-G gate

| Gate | P2.4B.2.04 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim과 primary/reserve route identity를 source 생성 전에 고정 | `DONE` |
| B | site-04만 허용하는 immutable materializer와 comparator를 target에 결속 | `DONE` - materializer SHA-256 `7c6b0633cff783b52f6d8859e930c5d615bb38dc865d9d2877184076232863a3` |
| C | receipt/tree/staging tamper, role swap, root binding, repository output, overlap, overwrite focused test | `DONE` - 6 passed, 0 failed |
| D | external root에서 primary/reserve 6 tree의 r1/r2 comparator 생성 | `DONE` - `FIX`, repeat exact, semantic fingerprint `0f66476b9791509ed6f5a226d433966ae28efd46cb92c350b7f85816a0b1b472` |
| E | current target baseline, focused/full regression, validate-current, diff check | `DONE` - full 2581 passed, 5 skipped, 0 failed, 0 errors; target unchanged |
| F1/F2 | 같은 target/packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 번 검토 | `DONE` - 두 run의 세 lane 모두 `GO`; single-review `REPEATABILITY_GAP` HOLD를 보존하고 repeat comparator `FIX` |
| G | machine 및 supervisor comparator가 `FIX`일 때만 `P2.4B.2.04` 기록 | `DONE` - r2 evidence와 comparator를 이 문서에 결속 |

## B-G 결과 결속

- current target baseline r2 receipt: `756e6bbe193eb7f977659cab1850136fb41fc7ec27b6c7003a7c789aa5540013`
  (`HEAD 04e9dd8e7dc788d8242db138278758303ba6f27d`, dirty worktree
  `54bddb61b11ca287b31d9f142a830ca87a4d8b71bbfb1fb0ce9c4d5c52a641bf`)
- machine materialization comparator: `FIX`, `repeat_exact=true`, semantic fingerprint
  `0f66476b9791509ed6f5a226d433966ae28efd46cb92c350b7f85816a0b1b472`, file SHA-256
  `6a0004842fd8fd2070c107b8d93ccce8a2a4b1ca406053c4d85c128656ad9f65`
- focused attestation: `6 passed, 0 failed, 0 errors, 0 skipped`, receipt SHA-256
  `6f08ee98e1ddead5c7dee6ad204f08d5f95a92dd7a657cc1ba4e455a3a328ff7`
- full attestation: `2581 passed, 5 skipped, 0 failed, 0 errors`, receipt SHA-256
  `26bfd1aaee8558f4b926f3e50777ab408c475b46fa7be23f84904ae05000d7de`
- Claude Opus 4.8 direct-files, Grok 4.5 raw-free packet, Cline GLM 5.2 raw-free packet의 F1/F2 lane은
  모두 `GO`다. 두 단회 run은 의도된 `REPEATABILITY_GAP` 때문에 `HOLD`로 보존됐고, 두 review의
  supervisor comparator는 `FIX`, `repeat_exact=true`, semantic fingerprint
  `cdb7bfeab20d9f70464ca04aa21445ae59e621d045ee92cdcc86b5a6f7566c2c`, file SHA-256
  `e19e7671e94c31ae3410c0d3b874881ad9b0f2e3b576346172e0dae4e30317cc`다.

## 명시적 비주장

P2.4B.2.04이 `FIX_NARROW`가 되더라도 site-04 한 slot의 **source tree identity**만 뜻한다.
exploit/functional/negative execution, machine admission, scanner finding, true positive, false negative,
precision, recall, Korean privacy coverage, 다른 18개 source-flow slot, 전체 60 pair, H100, release는
계속 `HOLD`다.
