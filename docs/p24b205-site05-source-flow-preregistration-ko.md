# P2.4B.2.05 site-05 source-flow materialization 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)

## 한 문장 목표

P2.4A의 `site-05` untrusted-redirect slot에 대해 primary와 fixed-order reserve 두 candidate의
TypeScript/Next.js `vulnerable`, `fixed`, `negative` source tree를 새 external root에
deterministic template로 materialize하는 계약을 source 생성 전에 고정한다.

## 고정 binding

- slot: `site-05`, scenario `dev-site-05-untrusted-redirect`, oracle
  `l3-gen-site-05-untrusted-redirect`
- plane/family/language/framework: `site` / `source-flow` / `typescript` / `nextjs`
- CWE/severity: `CWE-601` / `high`
- P2.4A generator profile: `deterministic-template-v1`
- candidate rank: primary `0`, reserve `1`; 총 2 candidate와 6 source tree
- primary route: `app/api/continue/route.ts`, request query field `next`, static negative path `/welcome`
- reserve route: `app/api/signin/route.ts`, request query field `returnTo`, static negative path `/dashboard`
- source layout은 P2.4B.1의 `slots/site-05/candidate-<rank>/<state>` relative path를 그대로 쓴다.
  P2.4B.1 evidence root의 빈 directory는 읽기 전용이며 절대 수정하지 않는다.
- 각 tree에는 MIT `LICENSE`, canonical `package.json`, 하나의 TypeScript route source만 있다.
- site-01, site-02, site-03, site-04 materializer와 comparator는 receipt byte binding을 가진다.
  site-05는 별도 versioned materializer와 comparator를 가져 이전 leaf receipt를 무효화하지 않는다.

## Tree 역할

| 상태 | source intent | 이 카드가 증명하지 않는 것 |
| --- | --- | --- |
| `vulnerable` | request query redirect target을 URL validation 없이 `NextResponse.redirect(...)`에 전달하는 조건을 보존 | 실제 redirect 또는 external navigation 실행 |
| `fixed` | request origin과 같은 origin인 relative target만 허용하고 나머지는 fixed internal path로 되돌리는 bounded source change | 실제 framework behavior 또는 functional correctness |
| `negative` | request input을 읽지 않고 static internal path만 redirect하는 control | scanner specificity 또는 test sensitivity |

primary는 continue target, reserve는 signin return target이라는 서로 다른 template identity를 가진다.
이는 reserve 순서와 source tree identity를 위한 구분이며, 실전 발생 빈도나 detector performance를 뜻하지 않는다.

## Fail-closed 규칙

- preregistered blueprint/staging receipt/root이 external path가 아니거나 canonical validation을
  통과하지 못하면 거부한다.
- slot/rank/framework/profile/path binding이 고정값과 다르면 거부한다.
- stage root에 source를 넣은 흔적, symlink, unexpected source file/directory, source content
  tamper, vulnerable/fixed role swap, receipt tamper, root binding mismatch는 거부한다.
- materialization root/receipt은 새 external path여야 한다. repository output, input/output overlap,
  overwrite를 거부한다.
- materializer는 source route text만 생성한다. HTTP request, browser navigation, external redirect,
  request payload 또는 URL을 실행하거나 반환하지 않는다.

## 실행 방법

P2.4B.1의 두 independent stage root를 read-only 입력으로 사용한다. site-05 전용 materializer는
source tree만 생성한다.

```powershell
python scripts/materialize_l3_source_flow_site05.py materialize `
  --blueprint <p24a-root>\blueprint-r1.json `
  --staging-receipt <p24b1-root>\staging-r1.json `
  --staging-root <p24b1-root>\stage-r1 `
  --materialization-root <external-evidence-root>\materialization-r1 `
  --output <external-evidence-root>\site05-r1.json

python scripts/materialize_l3_source_flow_site05.py materialize `
  --blueprint <p24a-root>\blueprint-r2.json `
  --staging-receipt <p24b1-root>\staging-r2.json `
  --staging-root <p24b1-root>\stage-r2 `
  --materialization-root <external-evidence-root>\materialization-r2 `
  --output <external-evidence-root>\site05-r2.json

python scripts/compare_l3_source_flow_site05_repeats.py `
  --first-blueprint <p24a-root>\blueprint-r1.json `
  --first-staging-receipt <p24b1-root>\staging-r1.json `
  --first-staging-root <p24b1-root>\stage-r1 `
  --first-materialization-root <external-evidence-root>\materialization-r1 `
  --first-receipt <external-evidence-root>\site05-r1.json `
  --second-blueprint <p24a-root>\blueprint-r2.json `
  --second-staging-receipt <p24b1-root>\staging-r2.json `
  --second-staging-root <p24b1-root>\stage-r2 `
  --second-materialization-root <external-evidence-root>\materialization-r2 `
  --second-receipt <external-evidence-root>\site05-r2.json `
  --output <external-evidence-root>\site05-r1-r2-comparison.json
```

## A-G gate

| Gate | P2.4B.2.05 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim과 primary/reserve route identity를 source 생성 전에 고정 | `DONE` |
| B | site-05만 허용하는 immutable materializer와 comparator를 target에 결속 | `DONE` - site-05 전용 materializer/comparator와 source hash binding |
| C | receipt/tree/staging tamper, role swap, root binding, repository output, overlap, overwrite focused test | `DONE` - 6 passed, 0 failed |
| D | external root에서 primary/reserve 6 tree의 r1/r2 comparator 생성 | `DONE` - `FIX`, repeat exact |
| E | current target baseline, focused/full regression, validate-current, diff check | `DONE` - current target focused 6/6과 isolated full r1/r2가 각각 2,587 passed, 5 skipped, 0 failed로 완료. target before/after는 모두 동일 |
| F1/F2 | 같은 target/packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 번 검토 | `DONE` - F1/F2 세 lane 모두 `GO`, 각 단회 review의 유일한 nonblocking code는 `REPEATABILITY_GAP` |
| G | machine 및 supervisor comparator가 `FIX`일 때만 `P2.4B.2.05` 기록 | `DONE` - machine와 supervisor two-run comparator 모두 `FIX`, `FIX_NARROW` 기록 |

## 완료 증거와 보존한 실패 이력

- current target baseline receipt:
  `<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24b205-site05-source-flow-20260723-r2\baseline-r2.json`
  (`785a9873c653ae40d719761dc3cc5d79dca5315959c7cd09f22bffd8613c445c`)
- current external materialization r1/r2 comparator는 `FIX`, `repeat_exact=true`이고 semantic fingerprint는
  `1723d5b91c2fce1b52b2bdb7b6c52e3f50488593ab8aabcddf5cdbb70eb9d9b9`다.
- focused attestation은 `6 passed`, receipt
  `0304d0cd817434a1c9944a8cdc9b1363349d5ce6248d034baea48fa73c24d8a2`다. current target full attestation r1/r2는
  각각 `2,587 passed, 5 skipped, 0 failed`, receipt
  `763085cbaf0243bf7a8a1dc6d8e95723c8d3ed3da5a36d9006de3ed80bb045c5`와
  `89e49fa73ab7563809b2061ef364415e5130a006aa8705fad86850cb55ca1dad`다.
- 이전 document target에서 첫 full attestation은 `CONTROL_HOLD` (`2,586 passed, 1 failed, 5 skipped`, receipt
  `01f0e6f6af9b6fee4feed30212ebd121e95ac23f785f4f73a528b0ae0b4e65ee`)였다. 이 receipt는 삭제하지 않았고,
  같은 이전 target의 isolated r2/r3 clean pass와 함께 F packet에 포함했다. 이 leaf의 좁은 source-tree 결론은
  해당 control failure가 제품 성능 실패가 아니라 과거 회귀 이력이라는 사실을 지우지 않는다.
- health-only r2는 GLM lane `BLOCKED_PROVIDER`로 끝났고, fresh r3는 세 lane 모두 `HEALTHY`였다. 둘 다 raw-free
  evidence로 보존했으며 health 결과 자체는 code, field, release 승인 근거가 아니다.
- Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 F1/F2 receipt는 동일 packet과 current target에 결속됐다. supervisor
  comparator는 `FIX`, `repeat_exact=true`, semantic fingerprint
  `0dccead73e8dd66b26fa45098b0627c421eee64c76f2c6ea94f924860b4b5525`다:
  `<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24b205-site05-source-flow-20260723-r2\supervisor-review-r1-r2-comparison.json`.

## 명시적 비주장

P2.4B.2.05가 `FIX_NARROW`가 되더라도 site-05 한 slot의 **source tree identity**만 뜻한다.
redirect/functional/negative execution, machine admission, scanner finding, true positive, false negative,
precision, recall, Korean privacy coverage, 다른 18개 source-flow slot, 전체 60 pair, H100, release는
계속 `HOLD`다.
