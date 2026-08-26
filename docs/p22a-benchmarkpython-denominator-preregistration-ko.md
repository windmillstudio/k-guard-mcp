# P2.2A BenchmarkPython current denominator receipt 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 장부: [release-program-phase-ledger-ko.md](release-program-phase-ledger-ko.md) P2.2A

## 한 문장 목표

OWASP BenchmarkPython 0.1의 공식 1,230개 case를 scanner 실행 전에 두 번
materialize하고, 공식 source, license, expected-results, case set, exclusion이 같은
분모임을 raw-free receipt로 고정한다.

## 입력과 provenance

| 입력 | 고정값 |
| --- | --- |
| Python origin | `https://github.com/OWASP-Benchmark/BenchmarkPython.git` |
| Python revision | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` |
| Python tree | `52367e858afa7841580a006e665c706b67874c4f` |
| Python expected results | `expectedresults-0.1.csv`, SHA-256 `6396f37c97cfd0c018db3d8750095ce6c678a083f83620cfb3e88fe27a46bb0c` |
| Python license | `LICENSE`, `GPL-3.0-only`, SHA-256 `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986` |
| Python official denominator | 정확히 1,230 unique case, 각 행 정확히 한 번 |

새 P2.2A Python clean worktree는 Git raw blob에서 materialize한다. 현재 L1 manifest
schema가 Java와 Python을 함께 요구하므로 Java는 이미 결속된 P2.1B clean source를
carrier-only 입력으로 쓴다. **P2.2A의 승인 대상은 Python projection 하나뿐**이며,
Java 분모를 다시 승인하지 않는다.

## 실행 계약

1. 새 Python source receipt가 `git_cat_file_raw_blob`, clean worktree, 공식 revision,
   tree, origin과 physical blob bytes를 확인한다.
2. 같은 P2.2A Python source에서 새 external output directory 두 곳에 carrier manifest를
   materialize한다. 기존 output을 덮어쓰지 않는다.
3. Python comparator는 두 full manifest에서 Python projection의 source, license,
   expected result, 1,230 case, source tree, case set, exclusion policy를 동일하게
   확인한다.
4. comparator output은 source code, expected-results 원문, finding, scanner output을
   저장하거나 반환하지 않는다.
5. focused tests, current target 전체 회귀, Claude Opus 4.8 직접 파일 검토, Grok 4.5와
   Cline GLM 5.2의 raw-free 검토를 각각 두 번 실행한다.

## 합격과 HOLD 경계

source receipt mismatch, revision/tree/origin/license/expected-results SHA mismatch,
1,230 case 누락·중복, untracked file, symlink/reparse point, output overwrite,
scanner 관찰, target drift, 또는 review repeat 불일치는 즉시 `HOLD`다.

이 작업은 BenchmarkPython **분모와 provenance**만 고정한다. 탐지 정확도, recall,
precision, specificity, TP/FP/FN/TN, High/Critical 성능, warning/block, Guardian,
H100, 설치 호환성, 제품 출하를 승인하거나 추정하지 않는다. P2.2B는 별도 clean
worktree에서의 독립 replay를 다음 단위로 검증한다.

## 완료 근거

- 새 Python worktree의 source receipt는 `git_cat_file_raw_blob`, clean worktree,
  공식 origin, revision, tree를 기록했다.
- 두 carrier manifest의 SHA-256은 모두
  `223cf168ec7ad1461afbb4b82755275d3e9c8194bc50f825384fda1199470a80`였다.
- `phase2-p22a-benchmarkpython-denominator-20260723-r1-r2-comparison.json`은
  1,230 Python case, source tree, license, expected-result, exclusion, scanner
  미관찰을 다시 확인해 `FIX`를 냈다.
- r24 target에서 focused test 52개와 전체 회귀 2,450 passed / 5 skipped / 0 failed가
  통과했다.
- Claude Opus 4.8 직접 파일 검토 10개, Grok 4.5, Cline GLM 5.2의 두 review run은
  `phase2-p22a-benchmarkpython-supervisor-review-20260723-r24-r1-r2-comparison.json`
  에서 semantic `FIX`로 일치했다.
