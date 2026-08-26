# Streamable HTTP MCP 프록시

`k-guard mcp-http-proxy`는 고정된 upstream MCP endpoint 앞에서 POST, GET SSE, DELETE를 전달하는 loopback ASGI reverse proxy다. 요청과 응답은 전달 전에 K-Guard runtime policy를 거치며 block/redact/control failure를 raw-free 보고서로 남긴다.

## 기본 실행

```powershell
$env:K_GUARD_EVIDENCE_HMAC_KEY = "<CI secret>"
k-guard mcp-http-proxy `
  --upstream http://127.0.0.1:9000/mcp `
  --host 127.0.0.1 `
  --port 8765 `
  --report mcp-http-proxy.json `
  --receipt-log mcp-http-proxy.receipts.jsonl
```

클라이언트 endpoint는 `http://127.0.0.1:8765/mcp`다. listen host는 loopback 값만 허용한다. upstream redirect는 따라가지 않으며 Origin, transport header, request/response/SSE event 크기, timeout, JSON-RPC ID와 session lifecycle을 제한한다.

`Authorization`은 기본적으로 upstream에 전달하지 않는다. 브라우저 Origin은 기본 localhost allowlist 또는 반복 가능한 `--allowed-origin`으로 제한한다. release runtime에서는 `--require-origin`을 사용한다.

## Default-Deny JIT/JEA

```powershell
$env:K_GUARD_AGENT_JWT_KEY = "<random 32+ byte secret>"
k-guard access-policy-template --output access-policy.json
k-guard agent-grant `
  --policy access-policy.json `
  --output reviewer.jwt `
  --app-id APP --session-id SESSION --purpose RELEASE_REVIEW `
  --subject AGENT --role release-reviewer `
  --method tools/list --method tools/call `
  --tool check_my_app --tool start_review_before_ship
k-guard mcp-http-proxy `
  --upstream http://127.0.0.1:9000/mcp `
  --port 8765 --report mcp-http-proxy.json --require-origin `
  --access-policy access-policy.json `
  --access-app-id APP --access-session-id SESSION `
  --access-purpose RELEASE_REVIEW `
  --access-audit-log access-audit.jsonl
```

HTTP client는 `reviewer.jwt`의 값을 `Authorization: Bearer ...`로 proxy에 보낸다. stdio `mcp-proxy`만 `K_GUARD_AGENT_TOKEN` 환경변수에서 grant를 읽는다.

Grant는 issuer/audience/subject/JTI/iat/nbf/exp, 앱, 세션, 목적, 역할, method/tool/resource scope, 호출 예산에 결속된다. exact 또는 명시적 trailing `/*` scope만 허용하고 전역 `*`는 거부한다. `tools/list`는 grant가 볼 수 있는 도구만 남긴다. principal별 MCP session lifecycle을 분리하므로 다른 agent가 같은 session ID로 pending server request를 가져갈 수 없다.

정책을 켜면 app/session/purpose/audit log가 모두 필수다. 감사 기록은 raw-free SHA-256/HMAC chain이며 기록 실패는 이후 요청을 거부한다. Access grant Authorization은 upstream 전달 옵션과 함께 사용할 수 없다.

## 판정

- `passed=true`: 실제 POST 왕복과 JSON/SSE 응답이 있었고 제어 오류가 없음
- `not_exercised`: 프록시는 준비됐지만 실제 왕복 증거가 없음
- `failed_closed`: timeout, redirect, malformed JSON/SSE, ID/session 불일치, 보고서 쓰기 실패 등 제어 공백 발생

정상적으로 차단된 요청은 upstream에 전달되지 않는다. runtime finding이 남은 보고서는 프록시 집행 성공과 별개로 Guardian release qualification에서 막힌다.

## Finding → 차단 → 감사 receipt

HTTP와 stdio 프록시는 같은 `k_guard_runtime_mediation_receipt.v1` 계약을 사용한다. 각 JSON-RPC 교환에는 wire ID와 분리된 무작위 `transaction_id`가 붙고, 다음 정보가 한 receipt에 함께 기록된다.

- 전송 방향과 실제 조치(`allow`, `redact`, `block`, `deny`)
- finding 참조와 rule ID
- 원문 또는 안전한 대체본의 실제 전달 여부
- 이전 receipt digest, 현재 digest, HMAC-SHA256 chain tag
- 접근정책 거부라면 access audit decision의 동일 `transaction_ref`

receipt는 upstream 또는 client에 전달하기 전에 sidecar에 `fsync`된다. 기록 실패 시 원문을 보내지 않고 fail-closed 한다. HTTP 보고서와 stdio 보고서 모두 `mediation_receipts`와 `evidence_bundle`을 포함한다. 원문 argument, 결과, secret, PII는 receipt에 저장하지 않는다.

`--receipt-log`를 생략하고 `--report`를 지정하면 `<report>.receipts.jsonl`을 쓴다. 둘 다 없으면 receipt는 메모리에만 있으므로 장기 감사 증거가 아니다. HMAC은 공유 비밀키 무결성 태그다. 공개 기본키 모드는 self-consistency만 확인하며, 실제 변조 저항 주장은 유효한 `K_GUARD_EVIDENCE_HMAC_KEY`와 `require_operator_key=True` 검증을 통과한 경우로 제한한다.

공식 Python MCP 클라이언트의 로컬 공격 실행은 다음으로 재현한다.

```powershell
$env:K_GUARD_EVIDENCE_HMAC_KEY = '<32바이트 이상의 고엔트로피 로컬 키>'
$env:PYTHONPATH = (Resolve-Path 'src').Path
python examples/contest-demo/runtime-attack/demo.py --work-dir tmp/runtime-attack-demo
```

정상 호출 허용, 공격 403, 악성 upstream 호출 0, 동일 거래의 finding/action 결속, operator-key 검증, 변조본 거부가 모두 참이어야 성공한다.

Guardian qualification은 이 기본 `passed`보다 강하다. 아래 명령이 POST/GET/DELETE, JSON/SSE, server request 상관관계, allow/deny, tool filtering, Origin, Authorization 비전달, audit chain을 두 번 같은 결과로 실행해야 한다.

```powershell
$env:K_GUARD_EVIDENCE_HMAC_KEY = "<release secret>"
k-guard runtime-validate --output runtime-validation.json
```

이 매트릭스는 proxy complete-mediation 회귀 증거이며 임의의 외부 MCP 서버나 앱 비즈니스 로직을 인증하는 증명서는 아니다.
