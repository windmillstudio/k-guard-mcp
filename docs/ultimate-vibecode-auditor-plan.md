# Ultimate Vibe-Code Auditor Plan

작성일: 2026-07-06

## 북극성

K-Guard MCP는 바이브코딩으로 만든 웹앱, 일반 코드, MCP 구성을 대상으로 개인정보가 어디서 수집되고 어디로 응답/로그/외부전송/LLM/MCP tool을 통해 흘러가는지 raw-free evidence graph로 보여주는 한국형 로컬 보안 감사 도구다.

여기에 MCP tool poisoning, hidden instruction, exfiltration, YARA/LLM-like rule engine, SARIF/CI까지 합쳐서 바이브코더가 별도 2차 감사를 돌리지 않아도 되는 "궁극의 바이브코드 감사기"를 목표로 한다.

## CTO 리뷰 결론

세 reviewer의 공통 지적:

- 개인정보 탐지 기반은 강하지만, 아직 "궁극의 감사기"로는 부족하다.
- heuristic flow map은 provenance-backed evidence graph로 올라가야 한다.
- MCP poisoning/hidden instruction/exfiltration은 1급 탐지면이어야 한다.
- SARIF/CI가 없으면 사용자는 결국 다른 도구를 한 번 더 돌린다.
- raw-free 보장은 CLI, MCP, dashboard, SARIF, crash path까지 검증되어야 한다.

이번 1차 구현에 반영한 것:

- MCP-native threat detector
- YARA-lite local rule pack
- SARIF exporter
- `--fail-on` CI contract
- GitHub Actions example
- LLM/MCP sink flow finding
- raw-free line hash provenance for MCP/rule/flow findings

## Product Gates

| Gate | 기준 |
| --- | --- |
| G1 raw-free | JSON, Markdown, SARIF, dashboard, MCP response에 raw PII/secret/prompt payload가 없어야 한다 |
| G2 MCP threat | hidden instruction, tool poisoning review signal, exfiltration intent, overbroad file access를 탐지해야 한다 |
| G3 evidence graph | flow finding은 source/sink file:line과 raw-free hash를 가져야 한다 |
| G4 CI | SARIF 생성과 severity threshold 실패 코드가 있어야 한다 |
| G5 local-first | 기본 스캔은 외부 전송 없이 로컬에서 끝나야 한다 |
| G6 Korean privacy depth | 한국형 직접/고유/서비스/민감/결합 개인정보 기준과 PIPC-style basis가 finding에 붙어야 한다 |

## 1차 구현 범위

### MCP Threat Detector

파일:

- `src/k_guard_mcp/detectors/mcp_threat.py`

탐지:

- `MCP_HIDDEN_INSTRUCTION`
- `MCP_TOOL_POISONING`
- `MCP_EXFILTRATION_INTENT`
- `MCP_DANGEROUS_COMMAND`
- `MCP_OVERBROAD_FILE_ACCESS`
- `MCP_TOOL_SHADOWING_ADVISORY`

출력 원칙:

- raw line 저장 금지
- `line_hash=<hmac-sha256-prefix>`만 evidence에 저장
- 실행하지 않는 no-exec static scan

### YARA-lite Rule Pack

파일:

- `src/k_guard_mcp/rules.py`

탐지:

- `RULE_YARA_LITE_MCP_PROMPT_INJECTION`
- `RULE_YARA_LITE_EXFIL_COMMAND`
- `RULE_YARA_LITE_KR_BULK_SCHEMA`

의미:

- 진짜 YARA 엔진 의존 없이 built-in deterministic rule pack으로 시작
- 이후 외부 `.kguard-rules.yml` 또는 YARA 호환 rule loader로 확장

### SARIF/CI

파일:

- `src/k_guard_mcp/reports.py`
- `src/k_guard_mcp/cli.py`
- `.github/workflows/k-guard-audit.yml`

사용:

```bash
python -m k_guard_mcp.cli scan . --sarif k-guard.sarif --fail-on high
```

의미:

- `critical` 또는 `high` finding이 있으면 exit code `3`
- GitHub Code Scanning 업로드 가능
- vibe coder가 "대시보드를 읽어야만" 하는 상태에서 벗어나 CI 차단 신호를 받음

### Flow Provenance

파일:

- `src/k_guard_mcp/flow.py`

추가:

- source/sink line hash
- LLM/MCP tool sink
- `FLOW_SENSITIVE_TO_AGENTIC_SINK`
- audit depth 4 metadata

## 다음 강화 루프

이번 구현은 CTO 지적 중 "first sprint"의 시작점이다. 아직 남은 내핵 작업은 다음과 같다.

1. AST-based taint analysis
   - Python AST 먼저
   - JS/TS는 TypeScript AST 또는 tree-sitter 계열 검토

2. Runtime MCP guard/proxy
   - MCP tool call 입출력 관찰
   - hidden instruction과 exfil sink를 런타임에서 차단/기록
   - raw-free event log

3. Rule engine externalization
   - `.kguard-rules.yml`
   - YARA 호환 subset
   - allowlist/baseline

4. Evidence pack
- SARIF
- HTML report
- flow graph JSON
- audit manifest with hashes
- evidence hash policy with `K_GUARD_EVIDENCE_HMAC_KEY`

5. Corpus expansion
   - poisoned MCP fixture
   - hidden instruction fixture
   - exfil command fixture
   - LLM/MCP sink fixture
   - Korean vibe-coded app corpus

## Positioning

K-Guard는 "또 하나의 보안 스캐너"가 아니라 다음 제품이어야 한다.

> 바이브코더가 자기 코드와 MCP 구성을 못 믿을 때, 로컬에서 한 번 돌려 개인정보 흐름, MCP poisoning, exfiltration, CI 차단 신호까지 한 번에 받는 한국형 궁극 감사기.
