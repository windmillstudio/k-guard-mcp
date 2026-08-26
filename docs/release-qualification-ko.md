# Guardian 필수 Qualification

Guardian high는 네 영역 리뷰만 깨끗하다고 SHIP하지 않는다. 현재 소스의 deep 분석과 dependency audit, 실제 MCP 정책 집행, JIT/JEA·DB 제어 회귀, owned/partner field 정확도까지 다섯 게이트를 모두 요구한다.

## 다섯 게이트

| 게이트 | 필수 증거 | 대표 실패 조건 |
|---|---|---|
| `deep_multilang` | workspace별 Semgrep deep + 9개 언어 90-case 보고서 | 대상 목록 불일치, 엔진/프로필 해시 불일치, high/critical, FN/FP, 반복 불일치 |
| `software_composition` | 같은 실행에서 만든 Python/npm/Go SCA 보고서 | lock 미커버, 엔진 누락, 부분 JSON, source drift, 알려진 취약점 |
| `streamable_http_runtime` | `runtime-validate`의 2회 매트릭스 보고서 | POST/GET/DELETE, JSON/SSE, server request, allow/deny, tool filtering, audit chain 중 하나라도 미실행 |
| `agent_database_controls` | `control-validate`의 18-case 2회 보고서 | 토큰·scope·budget·audit 또는 SQL AST·RBAC·EXPLAIN·격리 사례 실패 |
| `field_accuracy` | 12~20개 owned/partner 앱의 사전등록 holdout·독립 라벨링 보고서 | roster/범위/서명/반복/TP·FP·FN 기준 미충족 |

모든 외부 보고서는 `K_GUARD_EVIDENCE_HMAC_KEY`가 설정된 환경에서 현재 도구chain으로 생성해야 한다. 공개 기본키, 다른 소스 해시, 누락된 필수 게이트는 canonical release 증거가 아니다.

## 1. 분석기 준비

```powershell
python -m pip install --require-hashes -r requirements-build.lock
python -m pip install --require-hashes -r requirements-evidence.lock
python -m pip install --no-build-isolation --no-deps -e .
python -m venv .tooling/semgrep
python -m venv .tooling/pip-audit
.\.tooling\semgrep\Scripts\python -m pip install --require-hashes -r requirements-semgrep.lock
.\.tooling\pip-audit\Scripts\python -m pip install --require-hashes -r requirements-pip-audit.lock
$env:Path = "$PWD\.tooling\semgrep\Scripts;$PWD\.tooling\pip-audit\Scripts;$env:Path"
$env:K_GUARD_EVIDENCE_HMAC_KEY = "<release secret>"
k-guard language-validate --output language-validation.json
k-guard sca . --output sca-standalone.json
```

Semgrep은 `1.174.0`과 전체 dependency hash closure로 고정되고, 메인 K-Guard 환경과 분리된다. 언어팩은 Python/JavaScript/TypeScript/Java/Kotlin/Go/PHP/Ruby/C#의 90개 eligible target과 Semgrep `paths.scanned` 정규화 집합이 정확히 같아야 한다. 실제 저장소에서도 독립 열거한 대상만 비공개 임시 staging에 복제해 실행하므로 앱의 ignore 설정이나 Semgrep 기본 제외가 검증 범위를 조용히 줄일 수 없다. Guardian은 `--run-sca`가 있을 때 각 workspace에서 SCA를 다시 실행한다. SCA 엔진은 advisory DB를 조회할 수 있으므로 이 플래그가 명시적 동적 확인 허가다. 생략하면 조용히 통과하지 않고 `SCA_COVERAGE_INCOMPLETE` high finding을 남긴다.

## 2. 권한·DB 제어

```powershell
k-guard control-validate --output control-validation.json
```

이 명령은 짧은 수명의 서명 grant, default deny, 도구·resource scope, 호출 예산, 변조·만료 거부, 도구 목록 필터, HMAC audit chain을 검증한다. DB 쪽은 단일 bounded SELECT AST, column RBAC, EXPLAIN, SQLite query-only authorizer, forged write, 결과 예산, 경로 격리, 파일 불변성을 검증한다. 18개 사례를 두 번 실행한 정규화 projection이 정확히 같아야 한다.

이는 제품 제어의 synthetic regression 증거다. 배포된 IAM/RLS와 실제 사업 권한이 맞다는 증명은 아니다.

## 3. Streamable HTTP Runtime

```powershell
k-guard runtime-validate --output runtime-validation.json
```

공식 검증 명령은 실제 ASGI proxy 경계를 두 번 통과하며 다음을 모두 발생시킨다.

- POST, GET SSE, DELETE
- JSON response와 SSE event
- server request와 같은 principal의 response 상관관계
- 허용된 tool call과 거부된 tool call
- 권한에 따른 `tools/list` 필터
- Origin 강제, Authorization upstream 비전달
- HMAC-chained audit 검증

실제 upstream을 운영할 때는 `access-policy-template`, `agent-grant`, `mcp-http-proxy --access-policy ... --access-audit-log ... --require-origin`을 사용한다. access policy를 켰는데 앱·세션·목적·감사 로그 중 하나라도 비면 proxy가 시작되지 않는다.

## 4. Field Bootstrap

field 정확도는 제품 코드나 public benchmark만으로 만들 수 없다. 12~20개 실제 owned/partner 앱과 외부 scope assertion을 roster에 넣고 첫 Guardian 실행 전에 ground truth와 roster를 custodian이 함께 고정한다.

```powershell
k-guard field-campaign-template --output field-app-roster.csv
k-guard field-campaign-status --roster field-app-roster.csv --output field-campaign-status.json
k-guard field-validation-preregister --roster field-app-roster.csv --ground-truth field-ground-truth.csv --custodian-id split-custodian-a --output field-preregistration.json
```

Synthetic, public benchmark, seeded mutation은 regression 증거로 유용하지만 `field_accuracy`를 대신하지 않는다.

## 5. 최종 Guardian

```powershell
k-guard guardian `
  --manifest guardian-targets.csv `
  --fail-on high `
  --run-probes `
  --run-sca `
  --language-validation-report language-validation.json `
  --mcp-http-proxy-report runtime-validation.json `
  --control-validation-report control-validation.json `
  --field-validation-report field-validation.json `
  --output guardian-release.json
```

Deep·SCA finding은 별도 부록이 아니라 workspace target의 canonical finding plane, top rules, fix plan, drift에 병합된다. Deep/SCA 제어 공백은 suppression으로 지울 수 없다.

최종 SHIP은 아래 둘이 모두 `true`일 때뿐이다.

```text
guardian_gate.passed
guardian_gate.canonical_release_authority
```

실제 field 데이터가 없으면 `field_accuracy`가 실패하고 `hold_qualification`을 유지한다.
