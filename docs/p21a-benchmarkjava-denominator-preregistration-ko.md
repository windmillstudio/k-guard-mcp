# P2.1A BenchmarkJava current denominator receipt 사전등록

작성일: 2026-07-23  
상태: `IN_PROGRESS`  
상위 장부: [release-program-phase-ledger-ko.md](release-program-phase-ledger-ko.md) P2.1A

감독 receipt의 기계용 field key는 기존 소문자 계약에 맞춘
`p2.1a-benchmarkjava-current-denominator`다. 사람용 WBS 표기 `P2.1A`와 같은
작업을 가리키며, 이 매핑은 별도 작업이나 성능 주장을 만들지 않는다.

## 한 문장 목표

OWASP BenchmarkJava 1.2의 공식 2,740개 case를 scanner 실행 전에 두 번
materialize하고, 공식 source, license, expected-results, case set, exclusion이 같은
분모임을 raw-free receipt로 고정한다.

## 입력과 provenance

| 입력 | 고정값 |
| --- | --- |
| Java origin | `https://github.com/OWASP-Benchmark/BenchmarkJava.git` |
| Java revision | `79b9bd6177e07991a9c11dc19e457c840e229931` |
| Java tree | `717509a4aeaf3cfacb8b1d8dec2c61ed9f88451a` |
| Java expected results | `expectedresults-1.2.csv`, SHA-256 `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1` |
| Java license | `LICENSE`, `GPL-2.0-only`, SHA-256 `c03cea027b4b40e4402fabd08557736727ec3d5bc54ad64ab6472de432198cad` |
| Java official denominator | 정확히 2,740 unique case, 각 행 정확히 한 번 |
| clean Java source receipt | `phase2-p21a-clean-source-20260723-r1/benchmarkjava-source-receipt.json` |

기존 Windows checkout은 `core.autocrlf=true`여서 작업 파일의 물리 바이트가 Git blob과
달랐다. 이 작업은 해당 checkout을 허용하지 않는다. `git cat-file` raw blob에서
새로 만든 외부 clean worktree만 사용하며, source materialization receipt는
`byte_source=git_cat_file_raw_blob`, `worktree_clean=true`여야 한다.

현재 L1 manifest schema가 Java와 Python을 함께 요구하므로, carrier manifest를 만들
때에는 같은 방식으로 materialize한 BenchmarkPython checkout을 보조 입력으로 쓴다.
그러나 **P2.1A의 승인 대상은 Java projection 하나뿐**이다. Python 1,230 case의
분모 승인이나 P2.2 완료 주장은 이 작업에서 금지한다.

## 실행 계약

1. clean Java/Python worktree의 revision, tree, origin, expected-results, license,
   physical blob bytes를 materializer가 fail-closed로 확인한다.
2. `scripts/materialize_l1_benchmarks.py`를 scanner 없이 독립 output directory에 두 번
   실행한다. 기존 output은 절대 덮어쓰지 않는다.
3. 비교기는 두 full manifest를 엄격히 파싱하고, Java corpus projection의 source,
   license, expected result, 2,740 case, source tree, case set, exclusion policy가
   동일한지 확인한다.
4. 비교기 output은 source code, expected-results 원문, finding, scanner output을
   저장하거나 반환하지 않는다.
5. 구현 target은 comparator와 tests를 포함한 뒤 current baseline receipt와 전체 회귀로
   봉인한다. 그 target과 같은 packet을 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2가
   각각 두 번 검토한다.

## 합격 조건

| 조건 | 합격 |
| --- | --- |
| Java revision/tree/origin | 위 고정값과 정확히 일치 |
| official rows | 2,740 unique case, 누락/중복/암묵적 제외 없음 |
| source integrity | tracked tree, physical bytes, license, expected-results가 Git blob과 일치 |
| scanner 관찰 | `false` |
| 두 materialization | canonical manifest와 Java projection이 의미상 정확히 일치 |
| 코드 검증 | focused tests와 current target 전체 회귀가 모두 통과 |
| 독립 검토 | 세 감독관의 같은 packet 2회 검토와 semantic comparator가 `FIX` |

## 즉시 HOLD 조건

다음 중 하나라도 발생하면 receipt를 만들지 않거나 `HOLD`로 보존한다.

- `core.autocrlf` 등으로 physical bytes가 Git blob과 다름
- revision, tree, origin, license, expected-results SHA, 2,740 count 중 하나라도 다름
- untracked file, symlink/reparse point, output overwrite, malformed manifest
- scanner output이 관찰되거나 Java case가 제외됨
- 두 run 또는 3AI review packet의 semantic comparison이 다름

## claim boundary

이 작업은 BenchmarkJava **분모와 provenance**만 고정한다. 탐지 정확도, recall,
precision, specificity, TP/FP/FN/TN, High/Critical 성능, warning/block, Guardian,
H100, 설치 호환성, 제품 출하를 승인하거나 추정하지 않는다.
