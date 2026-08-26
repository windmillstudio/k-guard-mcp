# AI 클라이언트 상호운용 실증

- 최소 기준: `3`개
- 검증 완료: `3`개
- 현재 v6 process 증거 게이트: `PASS`
- review provenance: `self-attested separate assertion`; 외부 심사자 신원·독립성 검증 아님
- revision 경계: v6 evidence record는 fresh-wheel receipt가 고정한 product source revision, package tree, wheel SHA-256/바이트에 결속된다. evidence-only commit revision은 추적용 비게이트 필드이며 v5 이하는 현재 후보로 승격하지 않는다.

| 클라이언트 | 상태 | 증거 |
|---|---|---|
| chatgpt | pending | 녹화·별도 review assertion 대기 |
| grok | verified | grok-20260825-current-01 / `e91db2a3ea68...` |
| codex | verified | codex-20260825-current-01 / `ffd19d0fe26c...` |
| antigravity | verified | antigravity-20260825-current-01 / `83f6ac83d5a4...` |

## 판정 경계

동일한 fresh-wheel release receipt에 고정된 product source revision, package tree, 설치 wheel SHA-256/바이트, 녹화 원본, 필수 5단계, host decoder가 수락한 10초 이상 녹화와 대표 sanitized frame 결속, compact 전체 pagination, release handshake, 재연결 후 tools/list와 read-only 호출, 별도 review assertion이 기록된 클라이언트만 process 검증 완료로 집계한다. handshake 의미 parity는 영상과 별도 review가 보조하는 self-attested 전사이며 canonical terminal response digest에 결속되지 않았다. 노출 판정은 클라이언트별 provenance를 보존한다. Grok은 로컬 transcript digest에 결속된 K-Guard MCP rawOutput audit이고, Codex와 Antigravity는 structured client self-report이며 deterministic 검증으로 승격하지 않는다. client startup/cwd context self-report는 별도 보존하고 MCP response 합격 범위에서 제외한다. review assertion은 외부 심사자 신원이나 독립성을 증명하지 않는다.
