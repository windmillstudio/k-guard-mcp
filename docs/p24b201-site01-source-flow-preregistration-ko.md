# P2.4B.2.01 site-01 source-flow materialization 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)

## 한 문장 목표

P2.4A의 `site-01` XSS rendering slot에 대해, fixed primary와 reserve 순서를 바꾸지 않은
두 candidate의 TypeScript/Next.js `vulnerable`, `fixed`, `negative` source tree를 새 external
root에 deterministic fixture로 materialize한다.

## 고정 binding

- slot: `site-01`, scenario `dev-site-01-xss-render`, oracle `l3-gen-site-01-xss-render`
- plane/family/language/framework: `site` / `source-flow` / `typescript` / `nextjs`
- CWE/severity: `CWE-79` / `high`
- P2.4A generator profile: `deterministic-fixture-v1`
- candidate rank: primary `0`, reserve `1`; 총 2 candidate와 6 source tree
- source layout은 P2.4B.1의 `slots/site-01/candidate-<rank>/<state>` relative path를 그대로 쓴다.
  P2.4B.1 evidence root의 빈 directory는 절대 수정하지 않는다.
- 각 tree에는 MIT `LICENSE`, canonical `package.json`, 하나의 `.tsx` page file만 있다.

## Tree 역할

| 상태 | source intent | 이 카드가 증명하지 않는 것 |
| --- | --- | --- |
| `vulnerable` | user-controlled HTML rendering condition을 보존 | exploit이 실제 성공한다는 사실 |
| `fixed` | text rendering boundary로 바꾼 bounded source change | functional regression이 없다는 사실 |
| `negative` | target condition이 없는 static rendering control | test sensitivity 또는 scanner specificity |

primary는 profile bio rendering, reserve는 announcement rendering이라는 서로 다른 fixture
identity를 가진다. 이것은 reserve 순서 보존과 tree identity를 위한 구분이며, 두 candidate의
실전 발생 빈도나 severity를 뜻하지 않는다.

## Fail-closed 규칙

- preregistered blueprint/staging receipt/root이 external path가 아니거나 canonical validation을
  통과하지 못하면 거부한다.
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
python scripts/materialize_l3_source_flow_site01.py materialize `
  --blueprint <p24a-root>\blueprint-r1.json `
  --staging-receipt <p24b1-root>\staging-r1.json `
  --staging-root <p24b1-root>\stage-r1 `
  --materialization-root <external-evidence-root>\materialization-r1 `
  --output <external-evidence-root>\site01-r1.json

python scripts/materialize_l3_source_flow_site01.py materialize `
  --blueprint <p24a-root>\blueprint-r2.json `
  --staging-receipt <p24b1-root>\staging-r2.json `
  --staging-root <p24b1-root>\stage-r2 `
  --materialization-root <external-evidence-root>\materialization-r2 `
  --output <external-evidence-root>\site01-r2.json

python scripts/compare_l3_source_flow_site01_repeats.py `
  --first-blueprint <p24a-root>\blueprint-r1.json `
  --first-staging-receipt <p24b1-root>\staging-r1.json `
  --first-staging-root <p24b1-root>\stage-r1 `
  --first-materialization-root <external-evidence-root>\materialization-r1 `
  --first-receipt <external-evidence-root>\site01-r1.json `
  --second-blueprint <p24a-root>\blueprint-r2.json `
  --second-staging-receipt <p24b1-root>\staging-r2.json `
  --second-staging-root <p24b1-root>\stage-r2 `
  --second-materialization-root <external-evidence-root>\materialization-r2 `
  --second-receipt <external-evidence-root>\site01-r2.json `
  --output <external-evidence-root>\site01-r1-r2-comparison.json
```

## A-G gate

| Gate | P2.4B.2.01 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim을 source 생성 전에 고정 | `DONE` |
| B | site-01만 허용하는 strict fixture materializer와 comparator 결속 | `DONE` |
| C | receipt/tree/staging tamper, root binding, repository output, overlap, overwrite focused test | `DONE` - `6 passed` |
| D | external root에서 primary/reserve 6 tree의 r1/r2 comparator 생성 | `DONE` - `repeat_exact=true`, `status=FIX` |
| E | current target baseline, focused/full regression, validate-current, diff check | `DONE` - focused `24 passed`, full `2562 passed, 5 skipped`, baseline current/diff check 통과 |
| F1/F2 | 같은 target/packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 번 검토 | `DONE` - 두 run 모두 전원 `GO` + 정확히 하나의 `REPEATABILITY_GAP` |
| G | machine 및 supervisor comparator가 `FIX`일 때만 `P2.4B.2.01` 기록 | `DONE` - site-01만 `FIX_NARROW` |

## 실행 결과

evidence root는
`<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24b201-site01-source-flow-20260723-r1`이다.
결속 target은 HEAD `04e9dd8e7dc788d8242db138278758303ba6f27d`, dirty path set SHA-256
`108681abe790607cf2b0ffdc25a3e9368317f20ba4bdd96cafdf43435d0decb7`, dirty worktree SHA-256
`d8eddead468256a3888be850383c205711e6b40e0c8337ab8f6de017e3bc1337`다.

- baseline receipt 내부 SHA-256은 `2ca93ae1c77c841b4f407f35b973c2d352779f117136a4cff0adac7ef4ae2d35`,
  파일 SHA-256은 `fa4411a9e3fe3f5f81253c50d41c51707426af1d851c9d3a2d2ce80732607a65`다.
- r1/r2는 primary와 reserve 각각의 `vulnerable/fixed/negative` source tree, 총 6 tree와
  18 file을 materialize했다. receipt 파일 SHA-256은 각각
  `e7cc4483b813196033e7178f3b51aeb22abc0de749b86ccb0a04823212634c5a`,
  `35783cd0eb97737c60e0f9db5cf8583765d18677c9f4179c315d079ac0598c4c`다.
- site-01 tree comparator는 `repeat_exact=true`, `status=FIX`였고 파일 SHA-256은
  `e73e4ab200eba92b2f6dc7fc89687561e8522f0b6fe46f5487c02461de459e6f`다.
- `python -m pytest -q`는 `2562 passed, 5 skipped in 1017.47s`를 기록했다. baseline
  `--validate-current`, r1/r2 receipt validate, `git diff --check`도 통과했다.
- health receipt는 세 lane 모두 `HEALTHY`였고 파일 SHA-256은
  `6c9e2cbd81d5d6f2af3c20fa567f9dcb4e99e830c974db8bc405a5e2a09272c5`다.
- Claude Opus 4.8, Grok 4.5, Cline GLM 5.2는 r1/r2 모두 같은 target, manifest, packet에서
  `GO`와 정확히 하나의 nonblocking `REPEATABILITY_GAP`을 냈다. supervisor comparator는
  fingerprint `9ac061cb25f7b682e45302ac68b41010eeb087ac8dd27f7c349eec4044d7f6bb`,
  `repeat_exact=true`, `status=FIX`였고 파일 SHA-256은
  `2a914110110cd2956b218cb87c6322d28f5019b6df31867c0e4ac53e2e416738`다.

두 source receipt의 output root binding/artifact hash는 path별로 다르지만, 각 receipt가 따로
검증한다. comparator는 이 정상적인 실행 위치 차이를 제외하고 공통 stage-tree와 source-tree
identity를 비교했다. 첫 supervisor run의 `HOLD`도 reviewer 거절이 아니라 두 번째 supervisor
run 전의 mandatory `REPEATABILITY_GAP`을 보존한 상태였다.

## 명시적 비주장

P2.4B.2.01이 `FIX_NARROW`가 되더라도 site-01 한 slot의 **source tree identity**만 뜻한다.
exploit/functional/negative execution, machine admission, scanner finding, true positive, false negative,
precision, recall, Korean privacy coverage, 다른 18개 source-flow slot, 전체 60 pair, H100, release는
계속 `HOLD`다.
