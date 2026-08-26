# AI 클라이언트 상호운용 실증 키트

이 문서는 ChatGPT, Grok, Codex, Antigravity에서 K-Guard MCP가 실제로 연결되는 장면을 현재 revision 결과보고서용 증거로 만드는 절차다. 설치 설정이나 로컬 SDK smoke만으로는 호환 완료로 계산하지 않는다. 최소 3개 클라이언트가 같은 source revision과 같은 설치 wheel에 결속되고, 녹화와 별도 review assertion까지 끝나야 process 증거 게이트가 통과한다. 현재 assertion은 self-attested이며 외부 심사자 신원이나 독립성을 증명하지 않는다.

현재 집계 결과는 [클라이언트 상호운용 상태](client-interop-status-ko.md)에서 확인한다.

## 완료의 정의

클라이언트 하나는 한 번의 연속 녹화에서 다음 다섯 단계를 모두 보여야 한다.

| 단계 | 화면에 남길 사실 | 통과 기준 |
|---|---|---|
| `install` | 고정 source revision, 클라이언트명, profile, 설치 결과 | 설치 명령 성공 또는 ChatGPT의 명시적 다음 단계 표시 |
| `restart` | 클라이언트 완전 재시작 또는 공식 MCP refresh | 이전 프로세스가 아닌 새 세션에서 연결 |
| `tool_list` | K-Guard 도구 목록 | `check_my_app`, `continue_review`, `start_review_before_ship` 모두 표시 |
| `check_my_app` | 소유 fixture에서 실제 tool call | 첫 receipt의 실행 상태 `running`, 표시 판정 `review_in_progress`, hashed `review_id` 참조, 원문 비반환 |
| `reconnect` | MCP 서버 재시작 또는 연결 refresh 뒤 재호출 | 다시 `tools/list`를 읽고 read-only 도구 호출 성공 |

`reconnect`는 메모리 안의 기존 review job이 서버 재시작 뒤 유지된다는 주장이 아니다. 전송 연결을 다시 맺은 뒤 새 도구 호출이 된다는 상호운용 검증이다.

## 증거 계약

- 클라이언트마다 별도 녹화 파일과 별도 SHA-256을 사용한다.
- 모든 클라이언트가 같은 정확한 source revision과 설치 wheel SHA-256/바이트 수를 기록한다.
- `continue_review`를 `state=completed`까지 반복하고 기본 `compact` 모드의 모든 findings 페이지를 offset 0부터 `has_more=false`까지 읽는다.
- 페이지마다 hashed finding ID를 기록한다. `next_offset` 건너뜀·정지, 중복 ID, 전체 count 누락은 실패다.
- terminal 응답의 review job, review receipt, primary workflow, release eligibility 일치, compact response contract를 확인한다.
- 작업자와 검토자는 서로 다른 `sha256:<64 hex>` 식별자로 기록한다.
- 검토자는 영상의 다섯 단계, 타임코드, 클라이언트 버전, 도구 계약을 직접 확인한다.
- 토큰, 이메일, 사용자명, 로컬 사용자 경로, 실제 개인정보는 화면과 관찰 JSON에서 가린다.
- 영상 편집본을 제출한다면 편집 완료 파일을 최종 artifact로 삼아 해시한다.
- `evidence/clients/runs/*.json`에는 로컬 절대 경로가 아니라 제출 묶음의 상대 locator와 해시만 남긴다.

## 촬영 전 고정

실증 전 소스를 커밋하고 작업 트리가 깨끗한지 확인한다. 실제 앱 대신 소유 fixture인 `examples/contest-demo/v1`을 사용할 때는 **그 fixture 디렉터리 자체를 K-Guard의 고정 워크스페이스 루트로 설치·바인딩**한다. 상위 저장소를 루트로 바인딩한 뒤 하위 경로만 넘기는 방식은 허용하지 않는다.

```powershell
git status --short
git rev-parse HEAD
python -m pytest -q
python scripts/client_interop_evidence.py init --client codex
```

마지막 명령은 `tmp/client-interop/codex-observation.json`을 만든다. `tmp`는 저장소에 커밋되지 않는다. `recorded_at`, 버전, 타임코드, 실제 관찰값과 서로 다른 작업자·검토자 ref를 채운다.

## 공통 촬영 큐

1. 화면 녹화를 시작하고 `git rev-parse HEAD`와 클라이언트 버전을 보여준다.
2. 해당 클라이언트 설치 명령과 `k-guard doctor --client <name> --json`을 실행한다.
3. 클라이언트를 완전히 닫았다가 열거나 공식 MCP refresh를 실행한다.
4. 클라이언트의 MCP 화면에서 K-Guard 도구 목록을 연다.
5. 소유 fixture 자체가 고정 워크스페이스 루트로 바인딩됐는지 doctor/설정 검증으로 확인한 뒤, 아래 요청으로 `check_my_app(path=".")`을 실제 호출한다.
6. 같은 `review_id`로 `continue_review`를 완료 상태까지 반복한다. `findings_page.next_offset`을 따라 모든 compact 페이지를 읽고 ID fingerprint 목록을 기록한다.
7. MCP 연결이나 클라이언트를 한 번 더 재시작한 뒤 `tools/list`와 read-only 도구 호출을 반복한다.
8. 녹화를 종료하고 토큰·개인정보·로컬 사용자 식별자가 보이지 않는지 별도 검토자가 확인한다.

실행 상태와 사용자 표시 판정은 서로 다른 필드다. 관찰 레코드는 `check_my_app.state=running`과 `check_my_app.presentation_code=review_in_progress`를 따로 저장하며, 둘 중 하나를 다른 값으로 대체하지 않는다.

terminal 응답의 handshake는 필드 존재 여부만 기록하지 않는다. 관찰 JSON에는 아래 실제 값도 함께 옮긴다.

- receipt·primary workflow의 `eligible_for_release_review`와 release contract·guardian handoff의 `eligible_to_start_guardian` 네 값은 모두 boolean이며 서로 같아야 한다.
- `release_review_contract.status`와 `guardian_handoff.status`는 모두 `ready` 또는 `blocked`이고 서로 같아야 한다. `ready`는 네 eligibility가 모두 `true`일 때만, `blocked`는 모두 `false`일 때만 허용한다.
- release contract·guardian handoff의 `release_verdict_issued` 두 값과 top-level·primary workflow·release contract·guardian handoff의 `canonical_release_authority` 네 실제 값은 모두 `false`여야 한다. 이 단계는 출하 판정이 아니다.
- top-level·primary workflow·release contract·guardian handoff의 `next_tool` 네 실제 값은 서로 같고, `ready`이면 `start_review_before_ship`, `blocked`이면 `check_my_app`이어야 한다.
- `review_coverage.status`는 `available_declared_scope` 또는 `unavailable_fail_closed`만 허용한다. `unavailable_fail_closed`이면 네 eligibility는 모두 `false`여야 한다.

이 의미 parity는 관찰자가 terminal 응답 값을 구조화 JSON으로 옮긴 self-attested 전사다. 녹화와 별도 review assertion이 이를 보조하지만 canonical terminal-response 바이트의 digest에 결속된 독립 인증은 아니다.

호출 문구는 네 클라이언트에서 동일하게 유지한다.

```text
안경선배로 이 워크스페이스 전체 검수를 시작해.
check_my_app(path=".", include_flow=true)를 실제 호출하고,
첫 응답의 status와 review_id 존재 여부를 보여줘.
완료 판정은 아직 내리지 마.
```

## 클라이언트별 장면

### Codex

```powershell
k-guard install --client codex --profile local-dev
k-guard doctor --client codex --json
codex mcp get k-guard --json
```

Codex를 재시작하고 MCP 도구 목록에서 대표 도구 3개를 확인한 뒤 공통 호출 문구를 실행한다. 재연결 장면에서는 Codex를 다시 열거나 K-Guard 연결을 refresh한 뒤 새 호출을 실행한다.

### Grok

```powershell
k-guard install --client grok --profile local-dev
k-guard doctor --client grok --json
grok mcp list --json
grok mcp doctor
```

Grok 세션을 재시작하고 도구 목록과 실제 호출을 같은 화면 흐름으로 남긴다. CLI 진단만으로는 완료가 아니며 대화 안의 tool call이 포함되어야 한다.

### Antigravity

```powershell
k-guard install --client antigravity --profile local-dev
k-guard doctor --client antigravity --json
```

Antigravity를 재시작하거나 MCP 화면에서 Refresh한 뒤 `/mcp`에서 K-Guard 도구를 확인한다. 공통 호출을 실행하고 다시 Refresh한 뒤 새 호출이 되는 장면을 남긴다.

### ChatGPT

ChatGPT는 로컬 stdio 서버에 직접 붙지 않으므로 Secure MCP Tunnel과 workspace app 연결이 먼저 필요하다.

```powershell
$env:CONTROL_PLANE_TUNNEL_ID="tunnel_..."
$env:CONTROL_PLANE_API_KEY="<현재 셸에만 입력>"
k-guard install --client chatgpt --profile local-dev
k-guard doctor --client chatgpt --json
tunnel-client run --profile k-guard
```

녹화에는 API key 값을 포함하지 않는다. ChatGPT developer-mode app에서 K-Guard 도구 목록과 실제 호출을 보여준 뒤 tunnel 또는 app 연결을 다시 맺고 새 호출을 실행한다. 상세 연결은 [MCP 클라이언트 설치 참고서](mcp-client-install.md)를 따른다.

## 녹화 수집

영상과 관찰 JSON을 같은 임시 폴더에 둔다. JSON의 `recording.artifact`는 이 폴더 아래 상대 경로여야 한다.

```powershell
python scripts/client_interop_evidence.py collect `
  --observation tmp/client-interop/codex-observation.json `
  --artifact-root tmp/client-interop `
  --output evidence/clients/runs/codex-20260713-01.json
```

수집기는 다음 조건에서 파일을 만들지 않고 실패한다.

- 녹화 파일이 없거나 1KB 미만 placeholder이거나 선언 길이가 10초 미만
- source revision 불일치
- 설치 wheel SHA-256·바이트 누락, source revision 혼합, 클라이언트별 wheel 혼합
- 다섯 단계 중 하나라도 실패 또는 타임코드 범위 오류
- 대표 도구 3개 누락
- `check_my_app` 첫 응답 계약 불일치
- `continue_review` terminal 완료 누락
- compact pagination의 offset 정지·건너뜀·중복 ID·미수집 finding
- release handshake 필드 누락, eligibility/status parity 충돌, release authority·verdict 과장, next-tool·coverage 의미 불일치
- 재연결 뒤 `tools/list` 또는 read-only 호출 미확인
- 작업자와 검토자 동일
- 원시 token 패턴이나 로컬 사용자 경로 포함

## 집계와 보고서 삽입

클라이언트별 수집을 마친 뒤 상태표와 증거 해시를 다시 만든다.

```powershell
python scripts/client_interop_evidence.py summarize --refresh-manifest
python scripts/client_interop_evidence.py verify-status
python scripts/contest_readiness.py --require-award-evidence
```

첫 번째 명령은 다음 파일을 갱신한다.

- `evidence/clients/interop-status.json`: 공모전 게이트가 읽는 구조화 상태
- `docs/client-interop-status-ko.md`: 결과보고서에 붙일 표
- `evidence/SHA256SUMS`: 모든 증거 레코드의 저장소 해시

`verify-status`는 기록된 숫자를 믿지 않고 현재 revision, 동일 wheel binding, compact 전체 pagination, release handshake, reconnect proof, 고유 영상 해시, 필수 단계 수, 별도 review assertion을 다시 계산한다. 의미 검증 전 구형 v3/v4 verified run은 `historical_nonqualifying_files`에만 표시하고 v5 current-revision readiness에는 포함하지 않는다. 알 수 없는 schema와 손상 JSON은 계속 오류다. 같은 녹화 파일을 여러 클라이언트에 재사용하거나 `verified_client_count`만 고친 상태는 실패한다. 서로 다른 reviewer ref는 역할 분리 표식일 뿐 외부 신원 증명이 아니다.

## 보고서 표현

3개 이상 통과한 뒤 사용할 문장:

> 동일한 고정 source revision과 설치 wheel에서 ChatGPT·Grok·Codex·Antigravity 중 총 N개 클라이언트의 설치, 재시작, 도구 목록, `check_my_app`, terminal `continue_review`, compact 전체 pagination, release handshake, 재연결 후 `tools/list`와 read-only 호출을 별도 assertion으로 확인했다. 클라이언트별 영상과 구조화 레코드는 서로 다른 SHA-256으로 결속했으며, assertion은 self-attested이고 미검증 클라이언트는 완료 범위에 포함하지 않았다.

사용하면 안 되는 문장:

- 모든 GPT 및 모든 MCP 클라이언트와 완전 호환
- 설정 등록만으로 실제 tool call 검증 완료
- 클라이언트 하나의 영상을 네 제품 호환 근거로 재사용
- 로컬 SDK smoke를 실제 사용자 화면 검증으로 표현

## 최종 체크

- [ ] 현재 revision·현재 wheel에서 네 클라이언트 중 최소 3개 `verified`
- [ ] 클라이언트별 영상 SHA-256 고유
- [ ] compact 모든 finding 페이지 연속 수집
- [ ] release handshake·reconnect proof 완료
- [ ] 별도 검토자 판정 완료
- [ ] 결과보고서 표와 `interop-status.json` 수치 일치
- [ ] 영상 안의 token·개인정보·로컬 사용자 경로 제거
- [ ] 영상 원본 3개를 각 레코드의 published locator에 게시
- [ ] `contest_readiness.py --require-award-evidence`의 다른 외부 blocker도 별도 확인
