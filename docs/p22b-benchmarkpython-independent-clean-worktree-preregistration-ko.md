# P2.2B BenchmarkPython independent clean-worktree replay 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 장부: [release-program-phase-ledger-ko.md](release-program-phase-ledger-ko.md) P2.2B

## 한 문장 목표

P2.2A에서 사용한 Python clean worktree를 재사용하지 않고, 같은 공식 Git raw blob에서
새 external worktree를 독립 materialize한 뒤 BenchmarkPython 1,230 case projection이
P2.2A와 같은지 검증한다.

## 독립성 계약

| 항목 | 조건 |
| --- | --- |
| source origin/revision/tree | P2.2A와 같은 공식 BenchmarkPython 0.1 고정값 |
| Python worktree | 새 output path, 새 raw blob extraction, P2.2A output 재사용 금지 |
| materialization | 새 Python carrier manifest output, 기존 manifest overwrite 금지 |
| Java carrier | 이미 결속된 P2.1B clean source만 carrier-only로 사용, Java 재승인 금지 |
| cross comparison | P2.2A manifest와 P2.2B manifest를 `p2.2b-benchmarkpython-independent-clean-worktree-replay` field key로 비교 |
| scanner | 실행 또는 관찰 금지 |
| source contents | Git blob raw bytes만 사용, source code 원문을 evidence에 저장하지 않음 |

P2.2A Python worktree 또는 source receipt를 복사해 P2.2B의 결과로 쓰면 즉시 `HOLD`다.
source revision과 tree가 같아도 새 output 및 raw-blob materialization이 없으면 독립
replay로 승인하지 않는다.

## 합격 조건

1. 두 번째 Python source receipt가 `git_cat_file_raw_blob`, clean worktree, 공식
   revision, tree, origin을 만족한다.
2. 새 carrier manifest의 Python projection이 P2.2A manifest와 공식 clean source
   projection 모두에 정확히 일치한다.
3. case 1,230개, expected-result/license hash, case-set hash, source-tree hash,
   exclusion policy와 scanner 미관찰 상태가 동일하다.
4. comparator field key가 기존 소문자 receipt 계약을 만족하고 P2.2B를 가리킨다.
5. focused tests, current target 전체 회귀, 세 감독관의 두 번 동일 review가 모두
   통과한다.

## 즉시 HOLD와 claim boundary

source output 재사용, raw blob mismatch, 다른 revision/tree/origin, output overwrite,
case 수/해시/정책 차이, scanner 관찰, target drift, 또는 review repeat 불일치는 모두
`HOLD`다.

이 작업은 BenchmarkPython provenance의 독립 replay만 강화한다. BenchmarkJava 분모,
탐지 정확도, TP/FP/FN/TN, recall, precision, warning/block, Guardian, H100, release를
승인하지 않는다.

## 완료 근거

- P2.2A path와 다른 output path에서 Python raw Git blob worktree를 새로 만들었고,
  source receipt는 `git_cat_file_raw_blob` 및 `worktree_clean=true`를 기록했다.
- P2.2A/P2.2B carrier manifest의 SHA-256은 모두
  `223cf168ec7ad1461afbb4b82755275d3e9c8194bc50f825384fda1199470a80`였다.
- `phase2-p22b-benchmarkpython-cross-worktree-20260723-r1-comparison.json`은 1,230
  Python case, source tree, license, expected-result, exclusion, scanner 미관찰을
  다시 확인해 `FIX`를 냈다.
- r25 target에서 focused test 52개와 전체 회귀 2,450 passed / 5 skipped / 0 failed가
  통과했다.
- Claude Opus 4.8 직접 파일 검토 10개, Grok 4.5, Cline GLM 5.2의 두 review run은
  `phase2-p22b-benchmarkpython-supervisor-review-20260723-r25-r1-r2-comparison.json`
  에서 semantic `FIX`로 일치했다.
