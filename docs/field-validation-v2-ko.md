# 실전 정확도 검증 v3

## 목적

이 절차는 K-Guard가 실제 바이브코딩 앱에서 얼마나 잘 찾고 얼마나 자주 틀리는지 재현 가능하게 측정한다. 공개 벤치마크, seeded mutation, owned/partner 앱 증거를 서로 섞지 않는다.

## 외부 검증자 trust anchor

로컬 roster와 서명 파일은 절차 무결성을 재계산할 수 있지만, 앱 소유권과 파트너 승인, reviewer의 실제 신원까지 스스로 증명하지는 못한다. 공모전 `award_evidence_ready` 판정은 다음 원본에 더해 독립 검증자가 발행한 `evidence/field/external-verifier-attestation.json`을 요구한다.

- 독립 검증자는 scope assertion, 파트너 승인, scan·aggregate 동의, 이중 판정, 서로 다른 두 번의 Guardian 실행, 비합성 앱 여부를 원자료에서 확인한다.
- 검증 환경 관리자는 attestation 파일의 SHA-256을 `K_GUARD_TRUSTED_FIELD_ATTESTATION_SHA256`에 외부 trust anchor로 넣는다.
- 프로젝트 운영자가 자기 파일을 만들고 자기 환경변수를 넣은 결과는 독립 검증이 아니다. 공식 판정에는 프로젝트와 분리된 검증 환경의 digest pin이 필요하다.
- trust anchor가 없거나 파일이 바뀌면 앱이 12개 이상이어도 award evidence는 fail-closed한다.

이 attestation은 검토 절차를 고정하는 증거다. K-Guard가 법적 소유권, 사람의 신원, 수상 자격을 독자적으로 보증한다는 뜻은 아니다.

| 증거 등급 | 용도 | 허용 주장 |
|---|---|---|
| internal fixture | 규칙 회귀 | 테스트 통과 |
| public development benchmark | 공개 정답셋 성능 | 지원 카테고리 공개 벤치마크 점수 |
| seeded mutation | 탐지 회귀와 재현성 | 삽입 패턴의 합성 회귀 결과 |
| owned/partner preregistered holdout | 실제 제품 정확도 | 고정 기준을 통과한 field validation |

공개 OWASP 케이스는 규칙 개발에 사용했으므로 독립 holdout으로 부르지 않는다. `public_benchmark_ready`는 `field_validation_ready`와 다른 상태다.

## 표본 계약

- 서로 다른 `app_id` 12-20개
- 전체 사례 120개 이상
- 취약 사례 50개 이상, clean 사례 40개 이상
- critical 취약 사례 5개 이상
- `top`, `mid`, `long_tail` 세 strata 모두 포함
- 스캔 전에 잠근 preregistered holdout 70개 이상이면서 전체의 30% 이상
- holdout 취약·clean·high/critical 후보 각각 35개 이상
- 모든 사례를 같은 소스 커밋에서 2회 재현
- 두 명의 독립 리뷰어가 판정하고 불일치는 제3자가 조정
- 각 리뷰어 판정 행은 운영자·custodian과 다른 reviewer 키로 서명
- split custodian은 운영자·리뷰어와 다른 키로 스캔 전에 preregistration 서명
- high/critical 후보를 일부만 고르지 않고 전부 판정

고정 통과선은 전체 candidate precision 0.80 이상, preregistered holdout candidate precision 0.80 이상, holdout high/critical recall 0.90 이상, holdout critical recall 1.00, holdout specificity 0.90 이상이다. Precision·high/critical recall·specificity는 점추정치와 Wilson 95% 하한이 모두 같은 바닥을 넘어야 한다. 모든 후보는 잠근 development 또는 holdout 사례 범위 하나에만 귀속되어야 하며, 귀속 불명이나 양쪽 split 중복은 실패다. 기준을 낮춘 보고서는 field claim을 발급하지 않는다.

지표 분모는 보고서의 서명된 `metric_contract`로 고정한다. candidate `(false_positive + benign) / (true_positive + false_positive + benign)`는 `false_discovery_rate`이고, `false_positive_rate`는 clean 사례의 `FP / (FP + TN)`이다. 두 값을 바꿔 쓰지 않는다. Field 정확도 보고서와 별개로 데이터 출하 게이트는 알려진 false negative와 benign high/critical 후보를 각각 0건만 허용한다.

## 실행 순서

먼저 `field-campaign-status`로 12-20개 앱 roster의 불변 source revision, strata, 외부 scope assertion, 승인·동의를 확인한다. Custodian은 이 roster 원본과 ground truth를 함께 서명하며, 이후 field/data gate는 roster의 앱·대상 집합이 두 Guardian 실행과 ground truth에 정확히 일치하는지 다시 계산한다.

1. 앱 목록과 `source_ref`, 정답 사례, development/holdout 구분을 스캔 전에 잠근다.
2. 두 리뷰어가 ground-truth 행을 판정하고 각자 키로 서명한다.
3. 운영자와 분리된 custodian 키로 ground-truth와 split을 preregister한다.
4. 각 앱을 같은 `app_id`의 `korean_senior/high` Guardian manifest로 실행한다.
5. 동일 소스·도구체인에서 고유 execution ID를 가진 repeat Guardian을 실행한다.
6. 모든 후보 리뷰 큐를 자동 생성한다.
7. 두 리뷰어가 `verdict_1`, `verdict_2`, `final_verdict`를 채우고 각 행을 서명한다.
8. 엄격 field profile을 실행한다.

```bash
python -m k_guard_mcp.cli field-campaign-template \
  --output benchmarks/field-app-roster.csv

python -m k_guard_mcp.cli field-campaign-status \
  --roster benchmarks/field-app-roster.csv \
  --output field-campaign-status.json

python -m k_guard_mcp.cli field-validation-template \
  --ground-truth-output benchmarks/field-ground-truth.csv \
  --review-output benchmarks/field-review.csv

python -m k_guard_mcp.cli field-validation-sign \
  --ground-truth benchmarks/field-ground-truth.csv

python -m k_guard_mcp.cli field-validation-preregister \
  --roster benchmarks/field-app-roster.csv \
  --ground-truth benchmarks/field-ground-truth.csv \
  --custodian-id split-custodian-a \
  --output benchmarks/field-preregistration.json

python -m k_guard_mcp.cli field-validation-queue \
  --guardian-report guardian-primary.json \
  --output benchmarks/field-review.csv

python -m k_guard_mcp.cli field-validation-sign \
  --review benchmarks/field-review.csv

python -m k_guard_mcp.cli field-validation-report \
  --guardian-report guardian-primary.json \
  --repeat-guardian-report guardian-repeat.json \
  --ground-truth benchmarks/field-ground-truth.csv \
  --roster benchmarks/field-app-roster.csv \
  --review benchmarks/field-review.csv \
  --preregistration benchmarks/field-preregistration.json \
  --profile field \
  --output field-validation.json
```

서명 명령에는 `K_GUARD_FIELD_REVIEWER_HMAC_KEYS` JSON 객체가 필요하다. preregistration에는 별도의 `K_GUARD_FIELD_CUSTODIAN_HMAC_KEY`가 필요하며 두 값은 `K_GUARD_EVIDENCE_HMAC_KEY`와 달라야 한다. 키는 저장소나 CSV에 넣지 않는다.

`field-validation-queue`는 fingerprint, detector subtype, artifact scope, file/body/header 위치 종류와 존재하는 response hash만 내보낸다. 원문 응답이나 개인정보 값은 리뷰 큐에 복사하지 않는다.

`profile=field`는 primary/repeat Guardian 양쪽의 운영자 서명 evidence bundle과 현재 보고서 projection이 일치하는지도 확인한다. Guardian method, 고유 execution ID, 생성 시각, 현재 package/ruleset source hash, 실제 manifest, 완료 target, 소스 스냅샷, 후보 인벤토리가 모두 결속되어야 한다. repeat는 다른 execution ID와 bundle을 가져야 하며 toolchain, manifest 내용, workspace/HTTP/MCP 대상 입력과 실행 증거가 primary와 같아야 한다. 후보 비교는 집합이 아니라 심각도와 중복 수까지 포함한 multiset 해시다. preregistration 시점은 조작 가능한 일반 JSON 시각이 아니라 서명된 primary Guardian bundle 생성 시각보다 앞서야 한다.

역할별 HMAC은 한 운영자 키로 모든 역할을 덮어쓰는 것을 막는 로컬 provenance 장치다. preregistration은 당시 Guardian toolchain도 함께 잠근다. 다만 평문 정답을 custodian과 운영 절차가 관리하므로 이를 cryptographically blind라고 부르지 않는다. 실제 사람의 신원, 고용관계, 이해상충 부재와 두 번의 실행이 서로 독립적이었다는 사실은 외부 조직 절차나 원격 attestation이 확인해야 하며 K-Guard가 증명한다고 표현하지 않는다.

## 공개 개발 벤치마크 스냅샷

2026-07-12에 OWASP Benchmark Python `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`를 같은 소스로 두 번 실행했다.

- 전체 1,230개 중 현재 규칙 매핑이 있는 지원 사례 366개, 명시적 비지원 사례 864개
- 정답 규칙 매핑 기준 TP 151, FN 0, FP 0, TN 215: recall 1.0
- clean 사례 범위의 모든 high/critical 후보 기준 FP 11, TN 204: specificity 0.948837, FPR 0.051163
- 지원 사례 파일의 high/critical 후보 185개를 모두 라벨링: TP 151, FP 34, precision 0.816216, false discovery rate 0.183784
- 예상 밖 후보는 `WEB_UNTRUSTED_INPUT_TO_HTML` 18개와 `AST_TAINT_PII_TO_DB_WRITE` 16개이며 숨기지 않고 FP로 포함
- 두 실행의 후보 집합 exact match와 Jaccard 1.0

이 수치는 공개 개발셋 결과이며 독립 holdout이나 owned/partner 실전 정확도가 아니다. 재현 명령은 다음과 같다.

```bash
python -m k_guard_mcp.cli owasp-python-benchmark \
  --repo BenchmarkPython \
  --output-dir benchmark-output \
  --require-ready
```

현재 seeded mutation 자산은 25개 경로에서 TP 25/FN 0/FP 0/TN 25지만, 1개 앱·1개 expected rule·1개 find/replace operator의 복제다. 따라서 상태는 `seeded_mutation_regression_ready`, 등급은 `single_pattern_seeded_regression`이며 build/test/runtime oracle이나 독립 취약성 판정을 통과한 벤치마크로 부르지 않는다.

## 첫 Guardian baseline

첫 `guardian --fail-on high` 실행은 `initial_snapshot`이다. 이것은 현재 위험을 승인하거나 suppression으로 바꾸는 동작이 아니다.

- 현재 blocker와 coverage gap은 첫 실행에서도 그대로 실패한다.
- 실행이 완료되고 소스 스냅샷이 유지된 결과만 다음 비교점으로 보관한다.
- 다음 실행에서 `--previous guardian-primary.json`을 사용하면 새로 생긴 blocker와 해결된 항목을 분리한다.
- baseline 변경은 별도 코드 리뷰를 거치며, 새 blocker를 단순 흡수하지 않는다.

## 판정값

후보 판정은 `true_positive`, `false_positive`, `benign`, `inconclusive` 중 하나다. 정답 사례는 `vulnerable` 또는 `clean`이다. `inconclusive`, 누락된 이중 리뷰, 재현 실패, 잘못된 app/target binding은 모두 fail-closed다.

## 현재 주장 경계

공식 OWASP Benchmark Python의 지원 카테고리 결과와 공개 앱 smoke 결과는 제품 개발 증거다. 실제 12-20개 owned/partner 앱의 독립 라벨이 입력되어 `field_validation_ready`가 나오기 전까지 인간 시니어와 동급의 실전 정확도를 주장하지 않는다.
