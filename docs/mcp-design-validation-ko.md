# 안경선배 MCP 설치·제품 디자인 검증

검증 기준일: 2026-07-14

## 검증 원칙

초보 바이브코더가 설치 결과를 스스로 해석하지 않아도 다음 행동을 끝낼 수 있는지를 기준으로 본다. `설정 등록`, `클라이언트 진단`, `실제 도구 호출`은 서로 다른 상태로 표시하며, 확인하지 않은 연결을 완료로 꾸미지 않는다.

## CDO 검토 결과와 반영

| 기준 | 결과 | 구현 |
|---|---|---|
| 사람용 설치 기본 화면 | 통과 | `연결 준비 → AI 클라이언트 → 다음 행동` 3단계 출력 |
| 자동화 계약 | 통과 | `install --json`, `doctor --json`으로 구조화 결과 유지 |
| 설정과 실제 연결 구분 | 통과 | `connection_state=configured_restart_required`, 실제 tool 호출은 별도 |
| 프로필 간섭 방지 | 통과 | 불변 실행기와 클라이언트별 `--profile` 결속 |
| 다중 설치 사전 확인 | 부분 통과 | `--client all`은 누락된 실행 파일, tunnel ID, Antigravity JSON 구조를 변경 전에 확인. 외부 CLI 실행 중 실패의 완전 자동 롤백은 후속 과제 |
| 실패 복구 행동 | 통과 | `doctor`가 첫 번째 다음 행동으로 정확한 `k-guard install` 복구 명령 제시 |
| 대표 출하 흐름 | 통과 | 사용자 도구는 `start_review_before_ship → continue_review`, 내부 엔진은 세부 정보로 분리 |
| 미완료와 확인된 위험 동시 표시 | 통과 | `hold_incomplete`에서도 확인된 critical/high 건수와 수정 순서 유지 |
| 모바일 첫 행동 | 통과 | 390×844에서 URL 입력 459px, 권한 확인 518px, 실행 버튼 하단 719px |
| 실제 클라이언트 상호운용 | 부분 통과 | Codex·Grok·Antigravity의 녹화 및 SHA-256 결속 과정 증거는 확인됐다. ChatGPT는 대기 중이며, 별도 검토 진술은 자기진술이라 외부 독립성까지 증명하지 않는다. |

## 공식 클라이언트 계약 대조

- Codex: `codex mcp add`, `codex mcp get`, 로컬 STDIO 서버 계약을 사용한다. <https://developers.openai.com/codex/mcp/>
- Grok: `grok mcp add --scope user`, `grok mcp list --json`, `grok mcp doctor` 계약을 사용한다. <https://docs.x.ai/build/features/mcp-servers>
- Antigravity: `~/.gemini/config/mcp_config.json`의 공유 `mcpServers` 설정과 `/mcp` 확인 흐름을 사용한다. <https://codelabs.developers.google.com/google-workspace-mcp-antigravity>
- ChatGPT: 로컬 5분 경로와 분리하고 Secure MCP Tunnel의 profile, daemon, workspace app 연결을 별도 상태로 표시한다. <https://developers.openai.com/api/docs/guides/secure-mcp-tunnels>

## 현재 판정

코드 기반 P0/P1과 로컬 합성 제품 흐름은 통과했다. Codex·Grok·Antigravity는 `install → restart → tool list → check_my_app → reconnect` 과정 녹화와 SHA-256 결속을 갖췄다. 다만 이 기록은 2026-07-13 기준의 과정 증거이며 현재 버전 UI 인증이나 외부 심사자 신원·독립성 증명은 아니다. ChatGPT까지 네 클라이언트 호환 완료로 주장하려면 [상호운용 실증 키트](client-interop-evidence-kit-ko.md)로 동일한 실제 화면 재현과 증거 레코드를 추가해야 한다.
