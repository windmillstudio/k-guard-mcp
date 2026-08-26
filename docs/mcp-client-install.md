# K-Guard MCP 클라이언트 설치 참고서

처음 설치한다면 [한국어 5분 설치](quickstart-ko.md)를 먼저 보세요. 이 문서는 ChatGPT, Grok, Codex, Antigravity 네 설치 어댑터의 상세 연결 절차와 환경 변수 경계를 설명합니다. 실제 클라이언트별 호환성은 tool 호출 증거가 쌓이기 전까지 별도 검증 상태로 표시합니다.

K-Guard MCP는 로컬 `stdio` MCP 서버입니다. Grok, Codex, Antigravity는 로컬 자식 프로세스로 실행하고, ChatGPT는 OpenAI Secure MCP Tunnel을 통해 같은 서버에 연결합니다. Cursor, Claude Code, Cline은 정식 설치·연결 지원 대상이 아닙니다. 다만 그 도구들이 만든 MCP 설정 파일은 감사 입력으로 검사할 수 있습니다.

## 현재 소스에서 설치

저장소 루트에서 실행합니다.

```powershell
python -m pip install --require-hashes -r requirements-build.lock
python -m pip install --require-hashes -r requirements-evidence.lock
python -m pip install --no-build-isolation --no-deps .
k-guard-mcp
```

공개 패키지 인덱스 배포를 전제로 하지 않습니다. 개발과 테스트가 목적이라면 아래처럼 evidence lock을 사용합니다.

```powershell
python -m pip install --require-hashes -r requirements-build.lock
python -m pip install --require-hashes -r requirements-evidence.lock
python -m pip install --no-build-isolation --no-deps -e .
```

release workflow가 만든 wheel을 설치할 때는 같은 release의 `requirements-evidence.lock`을 hash-locked requirements로 사용하고 `SHA256SUMS`에서 wheel·sdist·lock을 먼저 대조합니다. 이어서 GitHub OIDC/Sigstore SLSA attestation을 검증합니다.

```powershell
gh attestation verify .\k_guard_mcp-0.1.0-py3-none-any.whl -R OWNER/REPOSITORY
```

release의 `release-provenance.sigstore.json`과 `release-sbom.sigstore.json`은 offline verification에 사용할 원본 bundle입니다. attestation이 없거나 repository identity와 digest가 맞지 않으면 설치를 중단합니다.

```powershell
python -m pip install --require-hashes -r .\requirements-evidence.lock
python -m pip install --no-deps .\k_guard_mcp-0.1.0-py3-none-any.whl
```

`k-guard-mcp` 명령을 직접 실행하면 터미널에서는 계속 대기하는 것이 정상입니다. MCP 클라이언트가 자식 프로세스로 실행할 때는 클라이언트가 수명을 관리합니다. 명령을 찾지 못하면 `python -m k_guard_mcp.server`를 사용하세요.

## 자동 연결

일반 설치에서는 클라이언트 JSON을 직접 고치지 않습니다.

```powershell
k-guard install --client auto --profile local-dev --workspace .
k-guard doctor --client auto
```

Windows 애플리케이션 제어 정책이 `pip`가 만든 `k-guard.exe`를 차단하는 환경에서는 `python -m k_guard_mcp.cli install ...`과 `python -m k_guard_mcp.cli doctor ...`을 사용합니다. 이 경로도 설치된 wheel의 동일한 CLI와 판정 로직을 실행합니다.

기본 출력은 안경선배의 사람용 3단계 요약이다. CI나 설치 자동화만 `install --json`, `doctor --json`을 사용합니다.

설치기는 `~/.k-guard`에 현재 Python 절대 경로를 사용하는 개인 실행기, 운영자 evidence key, 설치 기록과 사용자 전용 workspace binding을 만듭니다. `--workspace PATH`는 존재하는 일반 디렉터리만 허용하며 생략하면 설치 명령을 호출한 cwd를 사용합니다. symlink·junction·비존재 경로는 어떤 설정도 바꾸기 전에 거부하고, 재설치로 workspace가 바뀌면 기존 binding을 백업한 뒤 원자적으로 교체합니다. 런처는 경로 원문을 출력하지 않고 `K_GUARD_WORKSPACE_ROOT`로 서버에 전달하며, receipt와 `doctor` 출력에는 basename과 keyed hash만 남깁니다. 실행기 자체는 profile과 무관하게 고정되고, 각 클라이언트 등록에 `workspace` 또는 `local-dev`가 별도 결속됩니다. 한 클라이언트의 profile 재설치가 다른 클라이언트 동작을 바꾸지 않습니다.

- `--profile workspace`: 코드·설정·흐름 중심, 동적 검수 꺼짐
- `--profile local-dev`: localhost GET/OPTIONS와 작은 고정 심화 경로만 켜짐
- 외부 대상과 인증 세션 검수: 두 profile 모두 기본 꺼짐
- `--workspace PATH`: 감사 root를 private binding에 결속, 기본값은 호출 cwd
- `--dry-run`: 파일을 바꾸지 않고 원문 없는 설치 계획만 확인

대상 선택지는 `chatgpt`, `grok`, `codex`, `antigravity`, `auto`, `all`입니다. `all`은 네 실행 파일과 ChatGPT tunnel ID를 먼저 확인하고 준비가 빠졌으면 어떤 설정도 바꾸지 않습니다. 외부 CLI 실행 중 일부만 완료된 경우에는 `부분 연결 · 다음 단계 필요`로 표시하고 완료된 대상을 숨기지 않습니다.

## doctor 결과를 읽는 법

`doctor`의 `ok=true`와 `connection_state=configured_restart_required`는 개인 실행기, 설치 기록, 등록 identity와 실행 가능한 CLI 진단 범위를 확인했다는 뜻입니다. 실제 AI 클라이언트 화면에서 K-Guard 도구 호출을 완료했다는 뜻은 아닙니다.

- Codex·Antigravity 성공 상태: `configured`
- Grok CLI 진단 성공 상태: `cli_diagnostic_passed`
- ChatGPT profile 준비 상태: `needs_action`
- `runtime_and_app_connection_verified=false`: 실제 클라이언트 tool 호출은 아직 별도 확인 필요

마지막 연결 확인은 각 클라이언트에서 `check_my_app`을 호출해 응답을 받는 것입니다.

## ChatGPT / GPT

ChatGPT는 localhost MCP 서버에 직접 연결하지 않습니다. OpenAI Platform tunnel settings에서 tunnel을 만들고 공식 `tunnel-client`를 설치합니다. tunnel에는 소유·관리하는 Platform 조직과 실제 앱을 만들 대상 ChatGPT workspace를 모두 연결해야 합니다. Platform 조직에만 연결하면 Enterprise/Edu workspace 목록에 자동으로 나타나지 않습니다. 현재 셸에 tunnel ID와 Tunnels Read + Use 권한의 API key를 설정한 뒤 설치·진단·실행합니다.

```powershell
$env:CONTROL_PLANE_TUNNEL_ID="tunnel_..."
$env:CONTROL_PLANE_API_KEY="<Tunnels Read + Use 권한의 OpenAI API key>"
k-guard install --client chatgpt --profile local-dev --workspace .
k-guard doctor --client chatgpt --json
tunnel-client run --profile k-guard
```

API key는 현재 셸의 환경 변수로만 넣고 저장소, 설치 기록, 명령 출력에 남기지 않습니다. K-Guard 설치기는 공식 `sample_mcp_stdio_local` profile이 정확한 개인 런처를 가리키도록 준비하지만, tunnel daemon과 ChatGPT 앱의 실제 호출까지 대신 확인할 수는 없습니다.

그래서 profile 생성 후에도 결과는 다음처럼 남습니다.

- 설치 상태: `profile_initialized_needs_action`
- 최상위 상태: `부분 연결 · 다음 단계 필요`
- CLI 종료 코드: `2`
- `profile_identity_verified`: profile이 정확한 Python·런처를 가리키는지
- `runtime_and_app_connection_verified`: 실제 tunnel과 ChatGPT tool 호출 확인 여부

`tunnel-client run`이 정상인 동안 다음 순서로 실제 앱 연결을 끝냅니다.

1. Platform tunnel settings에서 소유 Platform 조직과 대상 ChatGPT workspace association을 확인합니다.
2. 대상 workspace 관리자가 developer mode 접근을 허용했는지 확인하고, 사용자 계정에서 developer mode를 켭니다.
3. ChatGPT `Settings → Plugins` 또는 `chatgpt.com/plugins`에서 `+`를 눌러 developer-mode app을 만듭니다.
4. Connection에서 `Tunnel`을 선택하고 `k-guard` tunnel을 고릅니다. 보이지 않으면 workspace association과 Tunnels Read + Use 권한을 다시 확인합니다.
5. 광고된 K-Guard 도구 목록을 확인하고 새 대화에서 `check_my_app`을 실제 호출합니다.

공식 기준 원문은 [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)과 [Connect from ChatGPT](https://developers.openai.com/apps-sdk/deploy/connect-chatgpt)를 따른다.

## Codex

```powershell
k-guard install --client codex --profile local-dev --workspace .
k-guard doctor --client codex --json
```

설치기는 `codex mcp add`를 사용합니다. doctor는 `codex mcp get k-guard --json`에서 `name`, `enabled`, `transport.type`, 실제 Python command, 실행기 경로와 `--profile` 결속을 구조적으로 대조합니다. args 어딘가에 예상 경로가 있다는 이유만으로 통과시키지 않습니다.

수동 등록이 필요할 때만 아래 명령을 사용합니다.

```powershell
codex mcp add k-guard -- python -m k_guard_mcp.server
codex mcp get k-guard --json
```

doctor 성공 뒤 Codex 대화에서 `check_my_app`을 호출해 실제 연결을 마무리합니다.

### Codex 비대화형 실행의 승인 경계

`check_my_app`, `continue_review`, `explain_rule`, `suggest_fix`, `security_gate`는 MCP에
`readOnlyHint=true`, `destructiveHint=false`, `openWorldHint=false`를 광고합니다. 이 값은
클라이언트가 참고하는 힌트이며 승인 정책을 우회하는 권한은 아닙니다. 특히
`check_my_app`은 파일이나 네트워크를 변경하지 않지만, 후속 조회를 위한 프로세스 내부
작업 상태를 만듭니다.

승인 UI가 없는 `codex exec`에서는 클라이언트 정책이 MCP 호출을 거부할 수 있습니다.
이 경우 거부된 뒤 같은 검사를 다시 시작하지 말고, 실행 전에 다음 중 하나를 선택합니다.

- 사람이 확인 가능한 대화형 세션에서 한 번 승인합니다.
- 조직 정책이 허용하면 Codex의 MCP 도구 승인/자동 검토 정책을 미리 구성합니다.
- 외부에서 쓰기·네트워크·대상 경계를 격리한 신뢰된 자동화에서만
  `codex --dangerously-bypass-approvals-and-sandbox exec ...`를 사용합니다.

마지막 플래그는 이름 그대로 Codex의 승인과 sandbox를 모두 끕니다. K-Guard가 부여하는
권한이 아니며, 일반 개발 셸이나 출처를 확인하지 않은 저장소의 기본값으로 사용하면 안 됩니다.

## Grok

```powershell
k-guard install --client grok --profile local-dev --workspace .
k-guard doctor --client grok --json
```

설치기는 `grok mcp add --scope user`를 사용합니다. doctor는 `grok mcp list --json`의 정확한 Python·launcher identity와 `grok mcp doctor`를 모두 확인합니다. 그래도 최종 확인은 Grok 대화에서 K-Guard 도구를 한 번 호출하는 것입니다.

## Antigravity

```powershell
k-guard install --client antigravity --profile local-dev --workspace .
k-guard doctor --client antigravity --json
```

Antigravity 2.0/IDE/CLI는 `~/.gemini/config/mcp_config.json`의 `mcpServers`를 공유합니다. 설치기는 공식 `agy` CLI 또는 공유 설정 경로를 발견하고, 기존 JSON을 백업한 뒤 `mcpServers.k-guard`만 병합합니다. malformed JSON이나 객체가 아닌 `mcpServers`는 원본을 보존한 채 중단합니다. 설정을 새로 읽히려면 Antigravity의 MCP 화면에서 Refresh하거나 CLI에서 `/mcp`를 열고, 실제 연결은 K-Guard 도구 호출로 확인합니다.

`agy --print`도 승인 UI를 표시하지 못하면 MCP 호출을 fail-closed로 거부합니다. Agy
1.1.19가 제공하는 비대화형 자동 승인 스위치는 `--dangerously-skip-permissions`입니다.
사람이 승인할 수 없는 작업에서는 호출이 시작되기 전에 실행 방식을 정하고, 외부에서
파일·네트워크·대상 경계를 격리한 신뢰된 자동화에서만 다음 형태를 사용합니다.

```powershell
agy --dangerously-skip-permissions --print="안경선배 check_my_app을 실행해줘"
```

이 스위치는 K-Guard 한 도구가 아니라 Agy 세션의 모든 도구 승인 요청을 건너뜁니다.
따라서 대화형 개발의 기본값으로 저장하거나, 격리되지 않은 임의 저장소에 적용하면 안 됩니다.

## 대표 MCP 도구

- `check_my_app(path=".", include_flow=true)`: 전체 워크스페이스 검수를 작업으로 접수
- `continue_review(review_id, wait_seconds=3.5)`: `completed` 또는 `failed`가 될 때까지 반복
- `start_review_before_ship(initial_review_id, app_id, business_purpose, data_classes, user_scope, scope_proof_ref, ...)`: 같은 source snapshot의 완료된 1차 검수 영수증으로 Guardian high를 접수
- Guardian high 동기 엔진은 내부 구현이며 MCP 도구로 직접 노출하지 않습니다.
- `scan_workspace`, `scan_text`, `scan_diff`, `scan_mcp_config`: 정적·흐름·설정 검사
- `deep_analyzer_audit`, `validate_multilang_pack`: 현재 소스 deep 분석과 9개 언어 개발팩 검증
- `software_composition_audit`: 명시적 advisory lookup 허가 뒤 Python/npm/Go lock 감사
- `validate_policy_controls`, `validate_streamable_http_runtime`: JIT/JEA·DB와 HTTP complete-mediation 반복 검증
- `probe_http`: 권한 있는 대상의 제한된 읽기 전용 동적 검사
- `observe_mcp_events`, `observe_mcp_event`: runtime 관찰·권고
- `enforce_mcp_events`: batch block/redact 판정 보고
- `guardian_audit`: 네 영역 + 다섯 qualification release gate
- `data_release_gate`: 서명된 Guardian·수동 라벨·한국 코퍼스·interceptor evidence 결속

`queued`와 `running`은 통과가 아닙니다. 출하 권한은 `start_review_before_ship`이 실행하는 Guardian high 결과에만 있습니다.

## 동적 검수 opt-in

MCP 동적 검수는 기본적으로 꺼져 있습니다.

localhost 기본 검사:

```json
{"K_GUARD_MCP_ENABLE_PROBE": "1"}
```

권한 있는 외부 대상:

```json
{
  "K_GUARD_MCP_ENABLE_PROBE": "1",
  "K_GUARD_MCP_ENABLE_EXTERNAL_PROBE": "1",
  "K_GUARD_MCP_EXTERNAL_ALLOWED_HOSTS": "staging.example.com"
}
```

읽기 전용 세션 header 파일:

```json
{
  "K_GUARD_MCP_ENABLE_PROBE": "1",
  "K_GUARD_MCP_ENABLE_SESSION_PROBE": "1"
}
```

작은 고정 심화 경로:

```json
{
  "K_GUARD_MCP_ENABLE_PROBE": "1",
  "K_GUARD_MCP_ENABLE_DEEP_ACTIVE_PROBE": "1"
}
```

심화 모드도 password guessing, 로그인 시도, form 제출, mutation, 재귀 crawling, exploit payload를 실행하지 않습니다.

Guardian qualification 보고서는 tool argument로 전달하거나 사용자 전용 launcher 환경에 아래 경로만 설정합니다. 원문 키나 개인정보를 넣지 않습니다.

```json
{
  "K_GUARD_SEMGREP_EXECUTABLE": "<semgrep executable>",
  "K_GUARD_LANGUAGE_VALIDATION_REPORT": "<language-validation.json>",
  "K_GUARD_MCP_HTTP_PROXY_REPORT": "<mcp-http-proxy.json>",
  "K_GUARD_CONTROL_VALIDATION_REPORT": "<control-validation.json>",
  "K_GUARD_FIELD_VALIDATION_REPORT": "<field-validation.json>"
}
```

## 출하 전 Guardian

manifest에는 실제 `workspace`, 권한 있는 HTTP origin, `business_purpose`, `data_classes`, `user_scope`, `public_endpoints`, `scope_proof_ref`를 입력합니다. 값을 모르면 AI가 만들지 않고 사용자에게 확인해야 합니다.

출하 가능 판정은 모두 만족해야 합니다.

- `guardian_gate.passed == true`
- `guardian_gate.canonical_release_authority == true`
- `review_contract.profile == "korean_senior"`
- `site_security`, `api_exposure`, `data_management`, `operational_risk` 네 domain이 모두 통과
- `deep_multilang`, `software_composition`, `streamable_http_runtime`, `agent_database_controls`, `field_accuracy` 다섯 qualification이 모두 통과

소스, 동적 실행, 흐름, 목적·범위, endpoint evidence 중 하나라도 빠지면 finding이 0개여도 HOLD입니다. `security_gate`는 workspace-only 빠른 확인이며 Guardian을 대체하지 않습니다.

## 권장 요청문

```text
안경선배로 이 워크스페이스를 끝까지 봐줘. check_my_app을 시작하고
continue_review를 state=completed 또는 failed가 될 때까지 반복해줘.
queued/running은 통과로 말하지 마. 완료 결과는 판정, 이유, 다음 행동 3개,
세부 근거 순서로 설명하고 원문 개인정보·키·로컬 절대 경로는 출력하지 마.
```

출하 전에는 다음처럼 요청합니다.

```text
실제 app id, 사업 목적, 데이터 종류, 사용자 범위, scope proof,
권한 있는 live URL과 공개 endpoint를 나에게 확인해줘. 모르는 값은 만들지 마.
코드를 고쳤다면 check_my_app을 다시 완료하고, 확인된 값과 최신 review_id로
start_review_before_ship을 실행한 뒤 Guardian이 terminal이 될 때까지
continue_review를 반복해줘. 네 domain과 canonical release authority가 모두 통과한
ship 결과일 때만 출하 가능이라고 말해줘.
```
