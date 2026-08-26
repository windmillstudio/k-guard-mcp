# 안경선배 사용 가이드

## 어떤 검수를 쓸까

| 상황 | 도구 | 결과 |
|---|---|---|
| 전체 워크스페이스 감사 시작 | `check_my_app` | 즉시 작업 ID를 주고 전체 정적·흐름·저장소 검수를 계속 실행 |
| 장기 감사 완료까지 확인 | `continue_review` | `queued/running/completed/failed` 상태와 terminal 결과 |
| 변경분만 확인 | `scan_diff` | Git diff의 새 위험 후보 |
| 로컬 사이트 응답 확인 | `probe_http` | 고정 경로 GET/OPTIONS 결과 |
| 출하 감사 시작 | `start_review_before_ship` | Guardian high와 허가된 live 검수를 장기 작업으로 실행 |
| MCP 이벤트 전달 전 확인 | `mcp-intercept` | block/redact가 적용된 JSONL |
| stdio MCP 실시간 집행 | `mcp-proxy -- <upstream argv>` | 요청·응답·notification 양방향 block/redact와 raw-free 제어 보고서 |
| HTTP MCP 실시간 집행 | `mcp-http-proxy --upstream <URL>` | Streamable HTTP POST/GET SSE/DELETE 양방향 집행과 실행 증거 |
| 다중 언어 개발 검증 | `language-validate` | Python/JavaScript/TypeScript/Java/Kotlin/Go/PHP/Ruby/C# 90-case TP/FN/FP/TN 및 두 번 반복 증거 |
| dependency/lock 검증 | `sca` / `software_composition_audit` | Python/npm/Go lock coverage와 알려진 취약점 |
| agent·DB 제어 검증 | `control-validate` / `validate_policy_controls` | JIT/JEA 8건 + SQL AST/RBAC/격리 10건, 두 번 반복 |
| HTTP 정책 매트릭스 | `runtime-validate` / `validate_streamable_http_runtime` | POST/GET/DELETE, JSON/SSE, allow/deny, audit chain 2회 |
| 데이터 산출물 출하 | `data_release_gate` | 서명·라벨·코퍼스·interceptor 증거 게이트 |

일반 앱 출하의 권한 엔진은 `review_before_ship`이 실행하는 Guardian high 하나다. 사용자 흐름은 `check_my_app → continue_review`로 전체 workspace 감사를 끝낸 뒤 `start_review_before_ship → continue_review`로 출하 감사를 끝낸다. `security_gate`, `scan --fail-on`은 보조 검사다.

전체 workspace에는 소스와 설정뿐 아니라 `dist`, `build`, `.next`의 배포용 텍스트 산출물이 포함된다. 전후 후보 집합과 실제 읽은 파일 수·경로 SHA-256이 하나라도 맞지 않으면 범위 미완료 high finding으로 멈춘다.

## 표준 출하 루프

1. 앱을 만든다.
2. `check_my_app`으로 전체 검수를 시작하고 `continue_review`를 terminal 상태까지 반복한다.
3. 실제 목적, 데이터 종류, 사용자 범위, 공개 API와 scope proof를 확인한다. 모르는 값은 추측하지 않는다.
4. 앱을 로컬에서 실행한다.
5. 9개 언어팩, SCA, agent·DB control, Streamable HTTP runtime, 12~20개 field 보고서를 준비한다.
6. 확인된 값과 보고서 경로를 `start_review_before_ship`에 전달하고 `run_software_composition=true` 및 local/authorized live 검수를 명시적으로 시작한다.
7. `continue_review`로 Guardian 완료까지 기다린 뒤 `experience.presentation`의 판정, 이유, 다음 행동을 읽는다.
8. `suggest_fix(rule_id)`로 수정안을 받고 다시 실행한다.
9. `ship`이 되면 같은 커밋의 보고서와 증거 묶음을 보관한다.

## 네 가지 검수 영역

### 사이트

입력값이 SQL, 명령, 파일, URL, HTML로 바로 흐르는지, 쿠키·CORS·디버그·소스맵·배포 설정이 위험한지 본다.

### API 노출

인증 없는 관리자/API 응답, IDOR/BOLA 모양, mass assignment, SSRF, route auth boundary, 공개 endpoint 도달 여부를 본다.

### 데이터 관리

한국 개인정보, 주민등록번호·CI/DI·계좌·의료정보 같은 고영향 필드, 암호화·접근통제·접근기록, 보존·파기, 외부 전달 후보를 본다.

### 운영 위험

CI 게이트, lockfile, 인증 테스트, rate limit 근거, MCP 설정, 런타임 이벤트와 출하 증거의 완결성을 본다.

## 결과를 읽는 순서

1. `review_job.state`가 `completed`인지 확인
2. 일반 완료 결과의 `experience.details.presentation` 또는 Guardian 완료 결과의 `experience.presentation`
3. `verdict`, `why`, `next_actions`
4. `guardian_gate.passed`
5. `review_contract.domains`
6. high/critical finding과 `suggest_fix`
7. `not_inspected`와 `claim_boundary`

finding 수가 0이어도 `hold_coverage`일 수 있다. 확인하지 못한 영역은 안전하다고 간주하지 않는다.

네 영역이 모두 완료되어도 `deep_multilang`, `software_composition`, `streamable_http_runtime`, `agent_database_controls`, `field_accuracy` 중 하나가 비면 `hold_qualification`이다. 자세한 생성 순서는 [Guardian 필수 qualification](release-qualification-ko.md)을 따른다.

모든 대상이 하나의 `app_id`로 결속되지 않았거나 유효한 `K_GUARD_EVIDENCE_HMAC_KEY`가 없으면 `hold_authority`다. 키는 32바이트 이상이며 충분히 무작위여야 한다. 공개 기본키와 같은 값, 짧은 값, 반복문자형 저엔트로피 값은 공개 기본키 모드로 강등되며 출하 권한으로 인정하지 않는다.

데이터 출하에 사용할 `mcp-intercept`는 `--app-id`, `--session-id`, `--guardian-report`를 함께 받아야 한다. 보고서의 schema·producer·앱·세션·Guardian content/bundle 결속과 운영자 키 서명이 현재 입력과 모두 일치해야 `data-release-gate`의 runtime evidence가 된다. data gate에는 field validation의 primary/repeat Guardian, ground-truth CSV, review CSV, preregistration 원본을 모두 입력한다. 게이트는 역할별 서명을 다시 검증하고 field projection을 재계산한 뒤 content/bundle/execution attestation/toolchain/manifest/source snapshot/HTTP·MCP 대상 입력/candidate multiset을 확인한다. 알려진 false negative 또는 benign high/critical 후보가 하나라도 있으면 데이터 출하를 막는다. 일반 관찰용으로 세 인자를 생략할 수는 있지만 그 보고서는 데이터 출하 증거로 인정되지 않는다.

## 오탐 처리

오탐이라고 생각되면 바로 숨기지 않는다.

1. 같은 규칙이 두 번 재현되는지 확인한다.
2. 실제 코드 경로와 배포 환경에서 benign인지 판정한다.
3. `true_positive`, `false_positive`, `benign`, `inconclusive` 중 하나로 기록한다.
4. suppression에는 app id, `korean_senior` profile, 현재 source snapshot/review evidence hash, target id, rule id, fingerprint, owner, reason, 만료일을 넣는다.
5. 다른 앱·다른 snapshot에 재사용하거나 만료된 suppression은 Guardian을 통과시키지 않는다.

## 자주 쓰는 요청문

전체 검수:

```text
check_my_app으로 현재 프로젝트 전체 검수를 시작해줘.
continue_review를 completed 또는 failed까지 반복하고, 완료 전에는 통과라고 말하지 마.
완료 결과의 판정, 이유, 다음 행동을 먼저 보여주고 세부 finding은 그 뒤에 설명해줘.
```

출하 검수:

```text
실제 사업 목적과 검수 범위를 먼저 확인한 뒤 start_review_before_ship을 실행해줘.
continue_review로 Guardian이 완료될 때까지 기다려줘.
안경선배 판정, 이유, 다음 행동 3개, 빠진 검수 영역, blocking rule 순서로 알려줘.
ship이 아니면 배포를 권하지 마.
```

수정 반복:

```text
blocking rule마다 suggest_fix를 호출해 수정해줘.
수정 후 같은 manifest와 high 기준으로 Guardian을 다시 실행해줘.
```

## 제품 경계

- 앱의 사업 의도와 법적 적합성을 인간처럼 이해하지 않는다.
- 완전한 TypeScript 타입·프레임워크·inter-procedural 분석기는 아니다.
- 로컬 SQLite는 AST/RBAC/EXPLAIN/query-only authorizer까지 집행하지만 클라우드 IAM, 원격 DB 정책, 백업, 실제 파기 실행은 별도 확인이 필요하다.
- 외부 대상 권한은 운영자의 assertion 경계다.
- 12~20개 실제 owned/partner 앱의 수동 TP/FP/FN 라벨이 없으면 인간 시니어와 동급 정확도를 주장하지 않는다.
