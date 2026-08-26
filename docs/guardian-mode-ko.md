# K-Guard Guardian Mode

Guardian의 사용자 안내 인격은 `안경선배`입니다. 엔진이나 게이트가 하나 더 생기는 것이 아니라, 대표 출하 게이트 결과를 `ship`, `hold_fix`, `hold_coverage`, `hold_authority`, `hold_qualification`, `review_only`로 번역하고 다음 행동을 최대 3개로 줄입니다. 자동화 계약은 `guardian_gate`, `review_contract`, `release_qualification`이 담당하며, `experience.claim_boundary`는 인간 판단이나 무결점 보증을 대신하지 않는다는 경계를 함께 기록합니다.

Guardian mode는 K-Guard를 일회성 스캐너가 아니라 꾸준히 지켜보는 보안 지킴이로 쓰기 위한 모드입니다.

목표는 단순합니다.

1. 내가 관리할 대상 목록을 manifest로 등록합니다.
2. K-Guard가 코드, 허가하고 실행을 켠 웹, MCP runtime, 기존 리포트를 한 번에 봅니다.
3. 위험도를 요약하고, 새로 생긴 blocking finding을 따로 표시합니다.
4. rule별 해결책과 재검증 방법을 같이 줍니다.

## 한국형 시니어 검수 프로필

새 템플릿은 `audit_profile=korean_senior`를 사용합니다. 이 프로필의 출하 게이트는 다음 네 영역을 모두 완료해야 통과합니다.

| 영역 | 필수 증거 |
|---|---|
| `site_security` | workspace 정적 검사 + `deep_active=true` HTTP 검사 |
| `api_exposure` | route/data-flow 정적 검사 + HTTP 노출 검사 + 유효한 선언 endpoint |
| `data_management` | 한국 개인정보/고유·민감정보/저장소/보존·파기 검사 + 명시적 목적·데이터·사용자·scope assertion |
| `operational_risk` | dependency lock/CI/auth test/rate-limit/MCP 구성 검사 + flow 분석 실행 |

판정은 `review_contract.passed`, `review_contract.domains`, `release_qualification.gates`, `guardian_gate.passed`에서 확인합니다. `korean_senior`에서 한 영역이라도 빠지거나 `deep_multilang`, `software_composition`, `streamable_http_runtime`, `agent_database_controls`, `field_accuracy` 다섯 qualification 중 하나가 비면 finding이 0개여도 출하 게이트는 닫힙니다. workspace는 지원되는 운영 소스 파일이 실제로 존재하고 텍스트로 읽혀야 하며 빈 폴더, 설정만 있는 폴더, 테스트 파일만 있는 폴더, 읽지 못한 바이너리형 소스만 있는 폴더는 완료로 계산하지 않습니다. 기존 매니페스트처럼 `audit_profile`이 없으면 `standard`로 처리되며, 이 결과를 4영역 시니어 검수 완료라고 표현하면 안 됩니다.

`public_endpoints`에는 실제 앱의 읽기 전용 검사 경로를 `|` 또는 `,`로 적습니다. Guardian은 고정 기본 경로와 함께 같은 origin의 안전한 path만 GET/OPTIONS로 실행합니다. 절대 URL, `..`, 템플릿 path, 50개 초과 항목은 실행 범위로 인정하지 않습니다.

`session_file`이 있으면 같은 경로를 비로그인 상태와 제공된 읽기 전용 세션 상태로 각각 실행합니다. 따라서 로그인 검사가 공개 노출 검사를 덮어쓰지 않습니다. 파일은 manifest 디렉터리 안에 있어야 하며 exact origin, 24시간 이내 만료 시각, 허용된 인증 헤더를 선언해야 합니다. `identity_assertion`의 경로·2xx 상태·응답 SHA-256까지 일치해야 로그인 비교를 완료로 인정합니다. 요청/제어 오류가 있거나 유효한 선언 endpoint가 없거나 선언 경로가 2xx·401·403에 도달하지 못하면 `korean_senior` 동적 영역은 fail-closed로 남습니다.

한국 고영향 데이터 통제는 workspace 어디엔가 `encrypt`, `authorize`, `audit_log`라는 단어가 있는지만 보지 않습니다. 주석을 제외하고 각 필드 이름과 암호화·권한·접근기록 코드가 연결된 경우만 해당 필드의 가시적 통제 증거로 인정합니다. CI/DI/개인통관고유부호 같은 연결 가능 서비스 식별자는 주민등록번호 계열과 별도 기술 범주로 보고합니다. 이는 법률 준수 판정이 아니라 코드 검수 신호입니다.

## 지원 대상

| kind | 의미 |
|---|---|
| `workspace` | 로컬 코드/설정/fixture/log/SQLite/MCP config를 검사합니다. |
| `http` | 허가된 origin에 안전한 GET/OPTIONS 동적 검사를 보냅니다. |
| `mcp_events` | MCP runtime/proxy JSONL export를 관찰합니다. |
| `report` | 기존 K-Guard raw-free JSON report를 다시 집계합니다. |

## 의도와 Scope 계약

Guardian manifest는 감사 대상뿐 아니라 `business_purpose`, `data_classes`, `user_scope`, `public_endpoints`, `scope_basis`, `scope_proof_ref`를 함께 기록합니다.
K-Guard가 앱의 사업 의도를 인간 시니어처럼 완전히 이해했다는 뜻은 아닙니다. 대신 manifest assertion이 있는지, scope 근거가 명시적인 `scope_proof_ref`로 남았는지, 그리고 그 값이 raw-free 해시 참조로 리포트에 묶였는지를 확인합니다. `locator`와 기존 `authorization_note`만으로는 scope assertion complete가 되지 않습니다.
`data-release-gate`는 `K_GUARD_EVIDENCE_HMAC_KEY`와 원래 Guardian manifest를 입력받아 현재 manifest 내용과 workspace source-tree digest가 서명된 감사 시점 snapshot과 같은지 먼저 확인합니다. Guardian은 workspace 검사 직전/직후 content snapshot도 비교하며, 둘이 다르면 `GUARDIAN_SOURCE_CHANGED_DURING_AUDIT`로 해당 실행을 막고 실질 검수 건수에서 제외합니다. 릴리스 권한을 부여하는 실행은 변경되지 않는 CI checkout에서 수행해야 합니다. Guardian과 모든 target은 정확히 `fail_on=high`여야 하며, 최종 Guardian의 `korean_senior` 4영역 review contract와 명시적 target-level intent/scope contract, operator-keyed evidence bundle이 모두 일치해야 합니다. 서명된 `passed=true` 값만 신뢰하지 않고 target finding의 high/critical 여부, 읽힌 실질 운영 소스, flow 실행, HTTP 요청/오류/필수 경로 도달 증거를 다시 계산합니다. field validation에 사용한 ground-truth/review/preregistration과 primary/repeat Guardian 원본도 다시 열어 역할 서명, content/bundle, 실행 attestation, 동일 toolchain/manifest/source snapshot, exact candidate multiset을 재검증합니다. 한국 거버넌스 코퍼스도 양성 3개, 음성 2개와 필수 `KR_DATA_*` 네 규칙을 요구합니다.

`SHIP`은 `release_authority_claim`에 고정됩니다. 이 claim은 단일 app id, high gate 입력, summary/drift/review hash, target별 review evidence, workspace source snapshot을 하나로 묶고 operator-keyed bundle 안에 포함됩니다. 임의의 HMAC bundle이나 다른 보고서의 서명을 붙이는 것만으로는 `guardian_gate.canonical_release_authority=true`가 되지 않습니다.

Suppression도 같은 경계를 따릅니다. CSV의 각 waiver는 app id, `korean_senior` profile, 현재 source snapshot 또는 HTTP/report evidence hash, target id, finding fingerprint, owner, reason, expiry에 결합됩니다. 앱이나 source snapshot이 바뀌면 fingerprint와 release scope가 달라지므로 이전 waiver를 재사용할 수 없습니다. Coverage gap과 MCP control failure는 여전히 suppression 대상이 아닙니다.

## 기본 사용

```powershell
python -m k_guard_mcp.cli guardian-template --output benchmarks/guardian-targets.csv
python -m k_guard_mcp.cli guardian --manifest benchmarks/guardian-targets.csv --output guardian-report.json --markdown guardian-report.md --html guardian-report.html
```

이 기본 명령은 리포트를 생성하는 모드입니다. finding이 있어도 리포트를 남기고 종료합니다.

릴리즈 게이트로 쓰려면 `--fail-on`을 명시합니다.

```powershell
python -m k_guard_mcp.cli guardian --manifest benchmarks/guardian-targets.csv --output guardian-report.json --fail-on high --run-sca --language-validation-report language-validation.json --mcp-http-proxy-report runtime-validation.json --control-validation-report control-validation.json --field-validation-report field-validation.json
```

이 경우 blocking target, 새 blocking finding, 또는 다섯 qualification 중 하나라도 미완료면 exit code `3`으로 끝납니다.
단, `--previous`가 없는 첫 실행은 `initial_snapshot`으로 봅니다. 현재 blocking finding이나 coverage gap은 그대로 게이트를 막지만, 모든 현재 finding을 “새로 생긴 drift”라고 부르지는 않습니다.
게이트 모드에서 HTTP row가 manifest에 있는데 `--run-probes` 없이 실행하면, 해당 row는 통과가 아니라 coverage gap으로 기록되고 exit code `3`으로 끝납니다.

HTTP probe까지 실행하려면 명시적으로 켭니다.

```powershell
python -m k_guard_mcp.cli guardian --manifest benchmarks/guardian-targets.csv --run-probes --output guardian-report.json
```

## MCP에서 사용

MCP tool:

- `create_guardian_manifest_template`
- `guardian_audit`

MCP에서 HTTP probe를 실제로 실행하려면 서버 환경변수가 필요합니다.

```powershell
$env:K_GUARD_MCP_ENABLE_PROBE="1"
python -m k_guard_mcp.server
```

manifest에 외부 origin이 있으면 `K_GUARD_MCP_ENABLE_EXTERNAL_PROBE=1`도 필요합니다. `deep_active=true` row가 있으면 `K_GUARD_MCP_ENABLE_DEEP_ACTIVE_PROBE=1`, `session_file` row가 있으면 `K_GUARD_MCP_ENABLE_SESSION_PROBE=1`도 별도로 필요합니다.

각 HTTP row에는 `authorized=true`가 있어야 합니다. 외부 origin row에는 `authorization_note`도 기록해야 합니다.
MCP 클라이언트에서 게이트 판정이 필요하면 `guardian_audit(..., fail_on="high")`처럼 호출하고 반환 JSON의 `guardian_gate.passed`를 읽습니다.
`fail_on`을 주지 않은 report mode에서도 MCP opt-in이나 manifest policy 문제가 생기면 bare scan 결과가 아니라 `method`, `baseline`, `execution_contract`, `summary`, `drift`, `findings`가 있는 guardian-shaped response로 돌아옵니다. 게이트 모드일 때만 여기에 `guardian_gate.passed=false`가 추가됩니다.

## Drift 감시

이전 리포트를 넘기면 새로 생긴 finding과 해결된 finding을 분리합니다.

```powershell
python -m k_guard_mcp.cli guardian --manifest benchmarks/guardian-targets.csv --previous guardian-report-old.json --output guardian-report-new.json
```

`new_blocking_findings`가 있으면 배포 전 우선 확인 대상입니다. 자동으로 멈추게 하려면 `--fail-on high`처럼 게이트 옵션을 같이 씁니다.
이전 리포트가 없으면 drift 비교는 하지 않습니다. 이때 `baseline.status`는 `initial_snapshot`, `drift.comparison_available`은 `false`, `new_blocking_finding_count`는 `0`입니다.
리포트의 `execution_contract`에는 실행된 대상, 건너뛴 대상, 실패한 대상, HTTP 실행 개수가 함께 기록됩니다.

## 하지 않는 것

Guardian mode는 아래 행위를 하지 않습니다.

- 비밀번호 대입
- credential stuffing
- form 제출
- 데이터 변경 요청
- exploit payload
- 무차별 경로 탐색
- recursive crawling
- 다른 origin redirect 따라가기

즉, Guardian mode는 공격자가 아니라 보안 담당자에게 필요한 지속 감사/설명/수정 가이드를 제공합니다.

## 결과 해석

리포트에는 다음이 포함됩니다.

- target별 gate pass/fail
- baseline 상태
- severity 요약
- 새 blocking finding
- resolved finding 개수
- 반복되는 top rule
- rule별 fix plan
- test suggestion
- verification command 방향

K-Guard의 원칙은 raw-free입니다. 원문 개인정보나 secret을 리포트에 저장하지 않고 rule, class, count, route, hash, confidence 중심으로 설명합니다.
