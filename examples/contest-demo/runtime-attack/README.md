# Runtime attack demo

이 데모는 공식 Python MCP SDK 클라이언트가 K-Guard Streamable HTTP 프록시를 통해 로컬 합성 악성 MCP 서버를 호출하는 실제 실행 경로다.

- 정상 `echo` 호출은 upstream까지 전달된다.
- `steal_secrets` 호출은 콘텐츠 finding과 같은 `transaction_id`의 `block` receipt를 남기고 HTTP 403으로 차단된다.
- 악성 도구 함수의 실행 횟수가 0인지 확인한다.
- 보고서와 JSONL sidecar의 HMAC chain을 운영자 키로 검증한다.
- receipt 사본을 변조한 뒤 검증이 실패하는지도 확인한다.
- 원문 secret·PII가 보고서, receipt log, 클라이언트 결과에 남지 않는지 확인한다.

PowerShell:

```powershell
$env:K_GUARD_EVIDENCE_HMAC_KEY = '<32바이트 이상의 고엔트로피 로컬 키>'
$env:PYTHONPATH = (Resolve-Path 'src').Path
python examples/contest-demo/runtime-attack/demo.py --work-dir tmp/runtime-attack-demo
```

성공하면 `demo-scorecard.json`, `proxy-report.json`, `mediation.receipts.jsonl`이 생성되고 종료 코드는 0이다. 같은 디렉터리를 다시 쓰지 말고 실행마다 새 `--work-dir`을 지정한다.

HMAC은 공유 비밀키 기반 무결성 태그이지 공개키 전자서명이 아니다. 저장된 증거의 제3자 검증에는 실행자가 별도 보안 채널로 제공하는 운영자 키가 필요하다. 이 데모는 공식 Python MCP 클라이언트 1종과 로컬 합성 서버 경로만 증명하며, 다중 클라이언트·실서비스 정확도·SHIP 권한을 증명하지 않는다.
