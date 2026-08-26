# Synthetic Loopback Deep Probe Calibration

## 목적

K-Guard의 deep active probe가 실제로 정해진 위험 신호를 잡고, 로그인 화면/SPA shell/HTML fallback 같은 흔한 오탐은 누르는지 검증한다.

이 검증은 외부 사이트 500개를 능동 스캔하는 것이 아니다. 정답을 아는 로컬 synthetic loopback target을 500회 호출하고, 대시보드와 같은 `scan_url(..., deep_active=True)` 경로로 검사한다.

따라서 이 문서에서 말하는 500은 "500개 실제 웹사이트"가 아니라 "24개 대표 시나리오를 반복한 500개 loopback target invocation"이다. 실제 취약점 발견, 외부 침투 테스트, 법적 인증, L5 inner-core 감사를 의미하지 않는다.

## 검사 범위

각 synthetic target은 local loopback origin 아래의 `/site-0001`, `/site-0002` 같은 subpath로 제공된다.

검사하는 대표 항목:

- 보안 헤더 누락
- CORS wildcard + credentials
- `/admin` 로그인 화면, SPA shell, 실제 관리자 콘솔, 애매한 관리자 route
- `/api`, `/api/users` JSON 노출
- bulk 개인정보 JSON
- secret-like token 응답
- `swagger.json`, `openapi.json`
- Next.js source map
- `.env`
- `.git/config`
- `backup.sql`
- `phpinfo.php`
- `actuator/env`
- directory listing
- stack trace
- external redirect boundary
- HTML fallback false-positive cases

## 하지 않는 것

- 외부 공개 사이트 deep probe
- 로그인 시도
- 비밀번호 대입
- 폼 제출
- 파일 업로드
- 데이터 변경
- exploit payload
- fuzzing
- recursive crawling
- 다른 host redirect 따라가기

## 실행

```bash
python scripts/deep_probe_synthetic_calibration.py \
  --targets 500 \
  --output tmp/deep-probe-synthetic-500.json \
  --markdown tmp/deep-probe-synthetic-500.md \
  --html tmp/deep-probe-synthetic-500.html
```

## 500개 결과

| metric | value |
|---|---:|
| target count | 500 |
| scenario count | 24 |
| expected rule total | 481 |
| observed rule total | 481 |
| missing expected rules | 0 |
| unexpected rules | 0 |
| recall | 1.0 |
| exact target pass rate | 1.0 |
| unexpected high targets | 0 |
| negative controls | pass |

주요 rule별 결과:

| rule | expected | observed |
|---|---:|---:|
| `DYN_UNAUTH_API_JSON` | 83 | 83 |
| `DYN_RESPONSE_SECRET_LEAK` | 63 | 63 |
| `DYN_PUBLIC_DEBUG_ENDPOINT` | 42 | 42 |
| `DYN_SECURITY_HEADERS_MISSING` | 21 | 21 |
| `DYN_CORS_WILDCARD_CREDENTIALS` | 21 | 21 |
| `DYN_UNAUTH_ADMIN_ACCESS` | 21 | 21 |
| `DYN_ADMIN_ROUTE_REVIEW_REQUIRED` | 21 | 21 |
| `DYN_RESPONSE_PII_LEAK` | 21 | 21 |
| `DYN_OPENAPI_EXPOSED` | 21 | 21 |
| `DYN_SOURCE_MAP_ACCESSIBLE` | 21 | 21 |
| `DYN_EXPOSED_ENV_FILE` | 21 | 21 |
| `DYN_EXPOSED_GIT_CONFIG` | 21 | 21 |
| `DYN_EXPOSED_BACKUP_OR_DUMP` | 21 | 21 |
| `DYN_DIRECTORY_LISTING` | 21 | 21 |
| `DYN_DEBUG_ERROR_LEAK` | 21 | 21 |
| `DYN_REDIRECT_TO_DISALLOWED_HOST` | 21 | 21 |
| `DYN_RESPONSE_PII_REVIEW` | 20 | 20 |

## 해석

이 결과가 의미하는 것:

- deep active detector가 대표 노출 시나리오를 놓치지 않는다.
- 로그인 화면과 SPA shell은 관리자 취약점으로 올리지 않는다.
- HTML fallback은 `.env`, OpenAPI, source map으로 오탐하지 않는다.
- 결과는 raw-free aggregate로 남는다.
- 의도적으로 틀린 expected를 넣는 negative control에서 missing/unexpected rule을 감지한다.

이 결과가 의미하지 않는 것:

- 외부 사이트 500개에서 실제 취약점이 발견됐다는 뜻이 아니다.
- 500개의 서로 다른 실서비스 구조를 대표한다는 뜻이 아니다.
- 전체 인터넷 deep scan이 안전하거나 허가됐다는 뜻이 아니다.
- 법적 보증이나 보안 인증이 아니다.
- 모든 framework, 모든 edge case, 모든 개인정보 유형에 대한 완전성 보장은 아니다.

실제 외부 사이트 deep probe는 소유, 파트너 승인, bug bounty scope, allowlist, domain proof, 사용자 attestation 같은 권한 근거가 있을 때만 실행한다.
