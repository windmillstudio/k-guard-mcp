# P2.4B.1 generated pair source-triplet staging 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
선행 조건: [P2.4A generated pair 60 청사진](p24a-generated-pair-blueprint-preregistration-ko.md) `FIX_NARROW`

## 한 문장 목표

P2.4A에서 고정한 60개 slot의 primary와 reserve 후보를 바꾸지 못하도록, 외부 evidence
root에만 `vulnerable/fixed/negative` **빈 경로**와 raw-free marker를 두 번 같은 의미로 예약한다.

이 카드는 source code, exploit input, 실행 receipt, scanner finding을 만들지 않는다. 따라서
이 카드는 source-triplet materialization이나 detector 성능의 증거가 아니다.

## 고정 입력과 분모

- P2.4A blueprint content SHA-256:
  `3489c9a802a960a1c31451cb12d3cd2976d8c87be0c4c37c7c9e7fcf8a05e2a6`
- 60 slot, 각 slot primary rank `0` 1개와 fixed-order reserve rank `1` 1개
- 총 candidate 120개, 빈 triplet directory 360개
- 동일 slot의 미리 정한 reserve만 교체 후보가 될 수 있다. 다른 slot 추가·제외·교체는
  `HOLD`다.

## 생성되는 외부 layout

각 candidate의 relative path는 아래 계약 하나만 허용한다.

```text
<stage-root>/
  slots/<slot-id>/candidate-<0|1>/
    stage-marker.json
    vulnerable/
    fixed/
    negative/
```

`stage-marker.json`은 slot, scenario/oracle ID, rank, raw-free claim boundary, canonical hash만
갖는다. 세 state directory는 이 카드에서 반드시 비어 있어야 한다. source file, exploit,
secret, URL, scanner output, 실행 로그는 어느 경로에도 허용되지 않는다.

receipt에는 absolute path를 저장하지 않는다. stage root는 one-way hash로만 결속되고, 각 run은
별도 external root를 사용한다.

## Fail-closed 규칙

- blueprint가 external path가 아니거나 preregistered content hash와 다르면 거부한다.
- receipt, stage root, comparator output을 repository 안에 쓰거나 기존 artifact를 덮어쓰면 거부한다.
- output과 stage root가 겹치면 거부한다.
- symlink, path traversal, 예상 밖 file/directory, marker tamper, 빈 triplet directory 위반은 거부한다.
- 60 slot, 120 candidate, 360 directory, primary/reserve order, family/plane binding 중 하나라도
  달라지면 receipt validation 또는 repeat comparison은 `HOLD`다.

실패한 stage root는 삭제하거나 재사용하지 않는다. 새 external root에서만 다시 시작한다.

## 실행 방법

P2.4A evidence의 canonical blueprint를 입력으로 두 번 independent stage한다.

```powershell
python scripts/stage_l3_generated_pair_source_triplets.py stage `
  --blueprint <LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24a-generated-pair-blueprint-20260723-r1\blueprint-r1.json `
  --stage-root <external-evidence-root>\stage-r1 `
  --output <external-evidence-root>\staging-r1.json

python scripts/stage_l3_generated_pair_source_triplets.py stage `
  --blueprint <LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24a-generated-pair-blueprint-20260723-r1\blueprint-r2.json `
  --stage-root <external-evidence-root>\stage-r2 `
  --output <external-evidence-root>\staging-r2.json

python scripts/compare_l3_generated_pair_staging_repeats.py `
  --first-receipt <external-evidence-root>\staging-r1.json `
  --first-blueprint <LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24a-generated-pair-blueprint-20260723-r1\blueprint-r1.json `
  --first-stage-root <external-evidence-root>\stage-r1 `
  --second-receipt <external-evidence-root>\staging-r2.json `
  --second-blueprint <LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24a-generated-pair-blueprint-20260723-r1\blueprint-r2.json `
  --second-stage-root <external-evidence-root>\stage-r2 `
  --output <external-evidence-root>\staging-r1-r2-comparison.json
```

## A-G gate

| Gate | P2.4B.1 완료 조건 | 현재 |
| --- | --- | --- |
| A | 이 문서의 60/120/360, rank, raw-free, non-claim contract를 source 생성 전에 고정 | `DONE` |
| B | strict stager와 repeat comparator를 current target에 결속 | `DONE` |
| C | quota, marker/receipt tamper, root binding, orphan file, repository output, overlap, overwrite focused test | `DONE` - `6 passed` |
| D | external root에서 stage r1/r2와 semantic comparator 생성 | `DONE` - `repeat_exact=true`, `status=FIX` |
| E | current target baseline, focused/full regression, validate-current, diff check | `DONE` - focused `18 passed`, full `2556 passed, 5 skipped`, baseline current/diff check 통과 |
| F1/F2 | 같은 target/packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 번 검토 | `DONE` - 두 run 모두 전원 `GO` + 정확히 하나의 `REPEATABILITY_GAP` |
| G | comparator와 three-lane semantic comparator가 `FIX`일 때만 `FIX_NARROW` 기록 | `DONE` - P2.4B.1만 `FIX_NARROW` |

## 실행 결과

evidence root는
`<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24b1-generated-pair-staging-20260723-r1`이다.
이 card가 결속한 target은 HEAD
`04e9dd8e7dc788d8242db138278758303ba6f27d`, dirty path set SHA-256
`4493a161fa3dd4c32e69e60395b142234f8949e6a844f970aed0fb32f3577584`, dirty worktree
SHA-256 `f881017ef88c33213120681531e7ba25900aac8190c5a471ef034ce272d5fdf2`다.

- baseline receipt 내부 SHA-256은 `e4035fc55106329c57fcc691d775196a85cfe8af61b9edff3802769f376a1fe7`이고,
  파일 SHA-256은 `5d364622eebf40a348ad8083d9aef2b48277a782b3cf1a9ede08fb069db392bf`다.
- stage r1/r2는 각각 120 candidate와 360 empty triplet directory를 만들었다. 두 receipt의
  파일 SHA-256은 각각 `46d15f764a305fddce01c68087ccb4496550feae5205f0fa1df78e1abfe217aa`,
  `eb917fea96da6a8ae9d7858380aba0b0e89af67ce30b39666cf650e86e884345`다.
- staging measurement comparator는 `repeat_exact=true`, `status=FIX`였고 파일 SHA-256은
  `3a7fd56e79171ae38b5bdfa65752ddee50916d98f96d9d26a5a449d62bd0d2b1`다.
- `python -m pytest -q`는 `2556 passed, 5 skipped in 985.72s`를 기록했다. baseline
  `--validate-current`, 두 receipt validate, `git diff --check`도 통과했다.
- health receipt는 세 lane 모두 `HEALTHY`였고 파일 SHA-256은
  `979c398e588cd65ab20b9ddc240c785688689090152bb964660410fefef9c98c`다.
- Claude Opus 4.8, Grok 4.5, Cline GLM 5.2는 r1/r2 모두 같은 target, artifact manifest,
  review packet에서 `GO`와 정확히 하나의 nonblocking `REPEATABILITY_GAP`을 냈다. supervisor
  comparator는 fingerprint `1b586257dc958ea7e638b7b7938847cbe52e0842a17c27ceb18bfa69e18eef55`,
  `repeat_exact=true`, `status=FIX`였고 파일 SHA-256은
  `4eb60a09d5e2227f5247386983cb57e3bcf76a6dfc42abb3d7be981387f4cd95`다.

첫 supervisor run의 runner status `HOLD`는 reviewer 거절이 아니었다. supervisor 두 번째
run 전에는 `repeat_exact=false`가 강제되므로 세 lane의 `REPEATABILITY_GAP`을 test-attestation
불완전으로 보존한 것이다. 두 번째 동일 packet run과 semantic comparator를 통과한 뒤에만
P2.4B.1을 `FIX_NARROW`로 기록했다.

## 명시적 비주장

P2.4B.1이 `FIX_NARROW`가 되더라도 120 candidate가 source triplet을 가진다는 뜻은 아니다.
`source_triplets_materialized=false`, `execution_oracles_proved=false`,
`eligible_for_tp_fp_fn=false`, `eligible_for_h100=false`, `release_gate_passed=false`는 유지된다.
P2.4B.2-P2.4B.6이 family별 source를 materialize하고, P2.4B.7이 machine admission과
execution oracle을 통과해야 비로소 개발 corpus claim을 할 수 있다.
