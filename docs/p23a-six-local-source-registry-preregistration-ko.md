# P2.3A 여섯 로컬 취약 앱 source registry 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW` (2026-07-23)  
상위 장부: [release-program-phase-ledger-ko.md](release-program-phase-ledger-ko.md) P2.3A
감독 receipt ID: `p2.3a-six-local-source-registry`

## 한 문장 목표

Juice Shop, WebGoat, NodeGoat, PyGoat, crAPI, WrongSecrets의 공개 source origin,
revision, Git tree, source byte tree, root license, 그리고 선언된 로컬 격리 요구를
새 canonical seed로 결속하고 source-only 결과를 독립 output 두 개에서 비교한다.

## 왜 새로 만든다

2026-07-18의 source-only materialization 결과는 남아 있지만, 이를 재실행할 수 있는
canonical seed와 source receipt bundle은 보존돼 있지 않다. 과거 PASS JSON을 현재
증거로 재사용하지 않는다. 현재 남아 있는 여섯 clean checkout을 immutable identity와
Git blob까지 다시 대조해 새 seed를 만든다.

## 고정 입력과 허용 범위

| 항목 | 고정 계약 |
| --- | --- |
| app set | `crapi`, `juice-shop`, `nodegoat`, `pygoat`, `webgoat`, `wrongsecrets` 정확히 여섯 개 |
| source identity | `materialize_l2_sources.py`의 immutable `EXPECTED_IDENTITIES`와 repository, commit, tree, source-tree hash, source receipt hash, root license가 모두 일치 |
| source verification | ordinary non-shallow standalone Git clone, clean worktree, exact index/tree, Git blob byte 대조, strict fsck |
| source acquisition | 기존 partial clone은 입력으로 사용하지 않는다. 공개 GitHub 원본에서 고정 commit을 filter 없이 새 ordinary clone으로 materialize한 뒤에만 seed 생성 |
| receipt equivalence | raw receipt가 기존 hash와 다르면 `git_porcelain_clean` 한 정보성 boolean만 제외한 semantic hash가 immutable 값과 같아야 함. 다른 필드 차이는 즉시 HOLD |
| local runtime allowance | loopback only, external egress denied, isolated container, cap-drop-all, no-new-privileges, read-only-root를 선언으로만 결속 |
| source receipt | source root 안의 새로운 sidecar directory에만 저장하며 overwrite 금지 |
| public evidence | source code, Git file list, absolute checkout path, scanner output을 포함하지 않는 raw-free summary와 source-only materialization 결과만 저장 |
| scanner | 실행, 관찰, finding score 산출 금지 |
| runtime | 컨테이너 실행과 실제 isolation 증명 금지. 이것은 P2.3B 이후의 별도 작업 |
| oracle | `machine_oracles=[]`로 명시하고 machine-oracle gate는 `HOLD`로 유지 |

## 완료 패킷

| 칸 | P2.3A 산출물 | 완료 조건 |
| --- | --- | --- |
| A | 이 문서 | 입력, 제외, claim boundary와 실패 조건을 코드 전 기록 |
| B | `materialize_l2_source_seed.py` | 여섯 checkout의 source receipt와 canonical seed를 no-overwrite로 생성 |
| C | focused tests | missing/tampered source, overwrite, raw-free boundary, changed source를 fail-closed로 거부 |
| D | materialization two-run | 같은 새 seed에서 서로 다른 external output 두 개를 만들고 semantic comparator가 `FIX` |
| E | full regression | 현재 target의 전체 shard가 누락 0, 실패 0 |
| F | external review | Claude Opus 4.8 direct-files, Grok 4.5, Cline GLM 5.2가 같은 packet을 두 번 `GO`하고 semantic comparator `FIX` |
| G | ledger promotion | evidence path/hash, 남은 runtime/oracle 범위를 장부에 기록 |

## 완료 결과

P2.3A의 완료 target은 HEAD `04e9dd8e7dc788d8242db138278758303ba6f27d`와
current baseline receipt
`7a3b25ee7e3a51e2350e2f49a140a9f9f222a1473ab69dfd7b2f9b6e356870f3`에 결속됐다.

1. 새 ordinary non-shallow clean source root의 여섯 source license admission은
   `PASS`였고, raw Git blob 대조, commit/tree, root license, strict fsck를 통과했다.
   근거는 `phase2-p23a-clean-sources-20260723-r1/clean-source-summary.json`이다.
2. canonical seed SHA-256은
   `95f48fd53d3d411be9dbaa7b78a130a893d1fbf87bbc92f7ce40f1d6dbaf2fef`이며,
   source-only materialization 두 실행은 semantic-exact였다. comparator는
   `phase2-p23a-six-source-registry-20260723-r1-r2-comparison.json`에서 `FIX`다.
3. focused/compatibility 검증은 160 passed, source-materialization 검증은 25 passed,
   clean-source materializer 검증은 4 passed였다. 전체 r29 회귀는 12 shard,
   2,465 passed, 5 skipped, 0 failed, 0 errors였고 aggregate SHA-256은
   `22a6731352a87c183d9fdcdacff51663ae149c38de0dcc40c556057d13543741`다.
4. Claude Opus 4.8, Grok 4.5, Cline GLM 5.2는 두 review run에서 모두 `GO`와
   `REPEATABILITY_GAP` 하나만 남겼다. 두 run의 supervisor comparator는
   `phase2-p23a-supervisor-review-20260723-r2-r3-comparison.json`에서 `FIX`다.
5. 처음의 대문자 field ID 실행은 runner validator가 receipt 생성 전에
   fail-closed로 거부했다. 그 directory는 실패 기록으로 보존하며, 이 완료 근거에
   포함하지 않는다.

이 완료는 source provenance, 선언된 local runtime allowance, source-only
repeatability만 뜻한다. 실제 runtime isolation, execution oracle, scanner accuracy,
TP/FP/FN, H100, warning/block 승격, 제품 release는 모두 계속 `HOLD`다.

## 합격 및 즉시 HOLD

다음이 모두 성립해야 P2.3A만 `FIX_NARROW`로 승격한다.

1. 여섯 app이 정확히 한 번씩 있고 source origin, commit, tree, physical source bytes,
   license가 immutable identity와 일치한다.
2. 두 source-only materialization 결과가 같은 seed와 같은 tool provenance에 묶이고
   source/license admission은 `PASS`다.
3. runtime isolation과 machine oracle gate는 둘 다 명시적으로 `HOLD`이며,
   `release_gate_passed=false`, `scanner_output_observed=false`, `raw_returned=false`다.
4. seed, receipt sidecar, materialization, comparator, review evidence 어느 것도
   기존 파일을 overwrite하지 않는다.
5. focused tests, full regression, 세 감독관의 두 review run이 모두 통과한다.

checkout dirty state, Git origin/revision/tree/blob/license mismatch, partial/shallow/shared Git
layout, source root traversal, sidecar/output overwrite, source/raw scanner data의 public
evidence 유입, runtime 또는 oracle을 PASS로 과장, target drift, 또는 review 불일치는
모두 `HOLD`다.

## Claim boundary

이 작업은 공개 여섯 앱의 **source provenance와 선언된 local runtime allowance**만
입증한다. 컨테이너가 실제로 격리돼 실행된다는 사실, 취약점의 존재, detector accuracy,
TP/FP/FN/TN, recall, specificity, warning/block, Guardian, H100, 제품 release를 전혀
승인하지 않는다.
