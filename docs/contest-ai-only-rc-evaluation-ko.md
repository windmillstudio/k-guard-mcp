# K-Guard 공모전 AI-only RC 자체 평가

> **역사적 비현재 자료:** 이 문서의 revision `6286846` 성능과 당시 회귀 수치는 2026-08-24 자체평가 snapshot이다. 현재 제출 성능은 product source `72e2aea`에 결속된 `benchmark-report.json`과 `evidence/qualification/target-grade-process-scaling-r1.json`만 사용한다. 이 문서는 현재 제출 수치나 현재 v6 client 인증으로 인용하지 않는다.

기준일: 2026-08-24  
평가 성격: AI-only 자체 평가와 동일 고정 payload read-only 모델 검토. 인간 독립감사나 현장검증이 아님

평가 단위: 현재 구현, 고정 fixture/holdout, 공개 benchmark, 단일 장비 합성 성능, 재현 가능한 제출 계약

## 결론

K-Guard는 **로컬 MCP 기반 출하 전 보안 감사관의 공모전 RC 후보**다. 설치·전체 검수·범위 누락·source drift·한국 개인정보·raw-free 증거·fail-closed 출하 판단을 하나의 제품 흐름으로 연결한 점은 완성도가 높다. 다만 실제 owned/partner 앱은 0/12이고, 사람 독립 라벨이나 현장 TP/FP/FN은 없다. 따라서 “인간 시니어급 현장 정확도”, “모든 취약점 탐지”, “운영 SLO”, “경쟁 제품 대비 정량 우위”는 주장하지 않는다.

최종 RC 판정은 다음 네 조건을 모두 충족한 뒤 확정한다.

1. clean HEAD 전체 회귀 통과
2. 단일 장비 contest-full 성능 보고서 통과
3. 동일 고정 payload에 대한 Grok 4.6 xhigh·Claude Opus 5 max read-only 감사와 Sol 재판정
4. 공개 GitHub URL·YouTube URL이 들어간 공식 Word/PDF와 제출 ZIP 검증

## 정확도·재현 근거

| 근거 lane | 기록 결과 | 무결성 | 허용되는 해석 |
|---|---:|---|---|
| 한국 fixture | positive TP 70/FN 0, clean negative FP 0/TN 27, targeted-absence 20건 별도, workspace contract 5건 별도 | PASS | 평가자 작성 개발 fixture의 규칙 회귀 |
| 한국 고정 holdout | TP 43/FN 0/FP 0/TN 25, 68건, exact two-run | PASS | 구현 후 고정한 합성 holdout 점검. blind/field/registry accuracy 아님 |
| 현재 공개 앱 재현 | 12개 앱×2회, 자동 후보 14건, 취약 probe 11/11, benign training fixture 1/1 | PASS | 현재 source의 재현성과 선택 probe 탐지. full-app recall 아님 |
| OWASP BenchmarkJava CWE-89 최초 | TP 51/FN 221/FP 33/TN 199, recall 0.1875, precision 0.607143, specificity 0.857759 | PASS, verdict HOLD | 공개 사전등록 단일 경계에서 낮은 최초 성능을 그대로 보존 |
| NIST Juliet Java CWE-89 최초 | TP 180/FN 30/FP 0/TN 210, recall 0.857143, precision 1.0, specificity 1.0 | PASS | 공개 사전등록 단일 경계 최초 결과 |
| OWASP BenchmarkPython 역사 결과 | 지원 범위 366건과 high/critical 후보 기록 존재 | FAIL | 5개 내부 artifact의 digest·size drift 때문에 현재 제출 정확도 근거로 사용 금지 |
| Juliet 튜닝 후 동일 corpus replay | TP 210/FN 0/FP 0/TN 210 | FAIL | first-result digest binding 불일치이며 새 독립 holdout도 아니므로 정확도 승격 금지 |

fixture 117건과 한국 holdout 68건은 **185회 별도 lane 평가**로만 표기한다. 중복 제거가 검증되지 않았으므로 pooled unique count와 combined confusion matrix는 `null`이다.

## 한국 개인정보 구현 범위

- 주민등록번호·외국인등록번호·여권번호·운전면허번호 네 고유식별자 계약
- 사업자등록번호 checksum 경계와 법인등록번호의 역사적 checksum/현재 명시 문맥 경계
- 개인 식별자와 조직번호가 충돌할 때 개인 식별자를 우선하는 privacy-first 분류
- `장애`, `장애정보`, `생체정보`, `지문`, `홍채`, `건강상태` 여섯 표현의 raw detector·scanner·server vocabulary parity
- 원문을 보고서에 넣지 않는 raw-free 투영과 source/package hash 결박

실시간 행정 등록 검증, 법률 자문, 실제 조직 데이터 분포의 정확도는 범위 밖이다.

## 단일 장비 성능

측정 프로토콜은 1 MiB cold/warm 각 20회, 10/50/100 MiB 각 5회, 동시성 1/4/8에서 각 16 job, nearest-rank p50/p95, peak RSS, exact byte·candidate coverage·result invariance를 요구한다. 입력은 finding 0건의 합성 all-benign low-signal 반복-comment corpus이고 파일시스템 cache는 비우지 않는다. scaling 5회와 concurrency 16회의 nearest-rank p95는 각 표본의 최댓값과 같다.

측정 revision `62868460b4d5b538d8d67fa62683d95bd4a4b277`, Windows build `10.0.26200`/AMD64 (`platform.release` 원시값 `10`), 32 logical CPU, CPython 3.11.9 한 대에서 다음 결과를 얻었다. report SHA-256은 `2ef685d0a6694fcbb12dcc159b2ec3c4894fdc82181e5d9012a8f74fd6df6bae`, fingerprint는 `b18762e5e2ab3ab09cb9a366165ac77369d7e0f38f4af719b00d046041081da9`다. `platform.release` 값만으로 Windows 제품명을 단정하지 않는다. source·runner·package가 측정 전후 동일하고 측정 당시 HEAD와 일치했으며 acceptance 13개가 모두 통과했다.

| 구간 | p50 | p95 | p50 처리량 | peak RSS |
|---|---:|---:|---:|---:|
| 1 MiB fresh-process cold scan | 1.418744초 | 1.433883초 | 0.704849 MiB/s | 64.003906 MiB |
| 1 MiB cold end-to-end | 1.753639초 | 1.811199초 | - | 64.003906 MiB |
| 1 MiB persistent-process/scanner warm | 1.531529초 | 1.610702초 | 0.652942 MiB/s | 67.097656 MiB |
| 10 MiB | 15.278002초 | 19.837566초(표본 max) | 0.654536 MiB/s | 64.007812 MiB |
| 50 MiB | 75.044579초 | 79.834287초(표본 max) | 0.666271 MiB/s | 96.613281 MiB |
| 100 MiB | 154.101438초 | 170.655168초(표본 max) | 0.648923 MiB/s | 147.226562 MiB (154,378,240 bytes) |

warm scanner 재사용은 이번 실행에서 cold보다 p50이 0.112785초 느렸고 peak RSS는 3,244,032 bytes 컸다. 이전 실행과 방향이 달라 warm의 일반적 성능 우위나 열위를 주장하지 않으며, 20회 이후의 장시간 재사용 거동은 측정하지 않았다.

동시성 1/4/8은 한 CPython 프로세스 안의 `ThreadPoolExecutor` 작업이며 CPU-bound scan은 GIL 제약을 받는다. 최종 실행의 aggregate 처리량은 각각 0.658680/0.640030/0.642181 MiB/s, speedup은 1.000000/0.971686/0.974951이었다. level-1 job latency는 p50 1.520717초, max 1.684323초였고 병렬 효율은 24.2921%/12.1869%, 8-way p50 job latency는 12.276124초였다. 이전 실행에서는 thread level의 처리량이 level-1보다 높았지만 최종 실행에서는 낮아져 실행마다 방향이 바뀌었다. 따라서 일반적 병렬 이득이나 회귀를 주장하지 않는다. 프로세스 병렬 확장은 측정하지 않았으며, acceptance의 concurrency 항목은 단일 worker 처리량의 70% 이상 유지 여부일 뿐 선형 병렬 가속을 뜻하지 않는다.

모든 측정 corpus에서 finding이 0건이므로 stable empty-result digest는 빈 결과 투영이 반복됐다는 점만 확인한다. 이 digest는 finding이 존재하는 출력의 누락·변형을 구분하는 식별력이 없으며, finding-bearing 입력에서의 결과 불변성을 증명하지 않는다.

이 결과는 합성 low-signal corpus의 단일 장비 측정이며 운영 SLO, cold disk/cache, 실제 대형 저장소 분포, 타 제품 대비 속도를 증명하지 않는다.

## 완성도 평가

| 평가축 | 현재 판단 | 근거와 제한 |
|---|---|---|
| 제품 흐름 완성도 | 높음 | 설치→검수 접수→수정 우선순위→source-bound 증거→HOLD/SHIP 계약이 연결됨 |
| 한국 현지화 | 높음(개발 근거) | 고유식별자·조직번호·민감어 계약과 합성 fixture/holdout 존재. field 미검증 |
| 보안 설계 | 높음 | raw-free, workspace binding, source drift, symlink/junction, coverage gap, suppression expiry를 fail-closed 처리 |
| 공개 정답셋 성능 | 혼합 | Juliet 최초는 강한 precision/specificity, BenchmarkJava recall은 낮아 HOLD. 실패도 숨기지 않음 |
| 성능 근거 | 개발 범위 확립 | 단일 장비 합성 1~100 MiB와 in-process thread 동시성 측정 통과. 운영 SLO·process-level scaling·실저장소 분포는 미확립 |
| 현장 정확도 | 미확립 | owned/partner 0/12, 인간 독립 라벨 없음 |
| 제출 준비도 | 조건부 | 제품·근거는 RC 수준, 공개 GitHub/YouTube와 최종 Word/PDF/ZIP이 남음 |

## 다른 보안 MCP와의 차별점

K-Guard의 차별점은 특정 finding 종류 하나가 아니라 **범위 완전성과 출하 권한을 같은 증거 계약으로 묶는 것**이다. 일반적인 MCP 보안 프록시가 도구 호출 허용·차단이나 런타임 정책에 집중하고, 정적 scanner가 finding 목록에 집중한다면, K-Guard는 사이트·API·데이터·운영 네 영역의 검수 접수, 한국 개인정보 문맥, source snapshot, 미검사 범위, raw-free 영수증, 최종 Guardian 판정을 하나의 사용자 여정으로 연결한다.

이 문서는 범주 수준 차별점을 설명하며 동일 corpus·동일 라벨 정책의 독립 비교실험 없이 경쟁 제품보다 정확하거나 빠르다고 주장하지 않는다.
