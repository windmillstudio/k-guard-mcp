# K-Guard MCP 5분 설치

K-Guard MCP는 로컬 `stdio` MCP 서버다. Codex, Grok, Antigravity는 5분 로컬 경로로 연결한다. ChatGPT는 공식 Secure MCP Tunnel과 workspace 설정이 더 필요하므로 별도 경로로 안내한다. 소스와 검사 결과는 기본적으로 현재 컴퓨터 안에서 처리된다.

## 1. 준비

- Python 3.11~3.13
- 검사할 프로젝트와 이 저장소
- Windows PowerShell, macOS Terminal, Linux shell 중 하나

### 처음 쓰는 사람: 가장 짧은 경로

공개 패키지 인덱스 배포를 가정하지 않는다. 저장소 루트에서 가상환경을 만들고 현재 소스를 설치한다.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
```

macOS/Linux:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install .
```

이 경로는 제품을 처음 실행하기 위한 설치다. 공모전 심사나 릴리스 재현처럼 정확히 고정된 의존성 증거가 필요하면 아래 검증 경로를 사용한다.

### 심사·재현 검증 경로

```bash
python -m pip install --require-hashes -r requirements-build.lock
python -m pip install --require-hashes -r requirements-evidence.lock
python -m pip install --no-build-isolation --no-deps .
```

K-Guard 자체를 수정하거나 pytest와 `scripts/**`를 실행할 개발자는 마지막 명령에 `-e`를 추가한다.

### release wheel 설치

release workflow 산출물에서 정확한 wheel을 받은 경우에는 함께 배포된 `requirements-evidence.lock`을 hash-locked requirements로 사용한다. 파일명과 wheel·sdist·lock의 SHA-256은 같은 release의 `SHA256SUMS`로 확인하고, `gh attestation verify <wheel> -R windmillstudio/k-guard-mcp`로 GitHub OIDC/Sigstore SLSA provenance도 검증한다.

```bash
python -m pip install --require-hashes -r ./requirements-evidence.lock
python -m pip install --no-deps ./k_guard_mcp-0.1.0-py3-none-any.whl
```

설치 확인:

```bash
k-guard --help
```

Windows 관리형 PC에서 애플리케이션 제어 정책이 `pip`의 콘솔 런처를 막으면 아래 모듈 명령을 사용한다. 설치된 wheel과 실행되는 CLI 코드는 같다.

```powershell
python -m k_guard_mcp.cli --help
```

## 2. MCP 클라이언트 연결

설치된 클라이언트를 자동으로 찾아 연결한다.

```bash
k-guard install --client auto --profile local-dev --workspace .
k-guard doctor --client auto
```

같은 Windows 대체 경로는 `python -m k_guard_mcp.cli install ...`과 `python -m k_guard_mcp.cli doctor ...`이다.

기본 출력은 사람이 읽는 3단계 화면이다. 자동화에서는 `--json`을 붙인다.

```text
안경선배 MCP 연결
상태: 설치 완료

[1/3] 연결 준비
[2/3] AI 클라이언트
[3/3] 다음 행동
```

설치 어댑터는 ChatGPT, Grok, Codex, Antigravity를 제공한다. 한 클라이언트만 연결하려면 `--client chatgpt`, `--client grok`, `--client codex`, `--client antigravity` 중 하나를 사용한다. 공모전 3분 설치 시연은 로컬 경로가 짧고 실제 진단 명령이 있는 Codex를 대표로 사용한다. `--client all`은 네 클라이언트의 실행 파일과 ChatGPT tunnel ID를 먼저 확인하고, 준비가 빠졌으면 어떤 설정도 바꾸지 않는다.

ChatGPT는 별도 사전 준비 경로다. `tunnel-client`, `CONTROL_PLANE_TUNNEL_ID`, doctor/run 시 Tunnels Read + Use 권한의 `CONTROL_PLANE_API_KEY`, Platform 조직·workspace association, 실행 중인 tunnel, 개발자 모드 앱 연결이 필요하다. 설치 결과의 `profile_initialized_needs_action`은 실패를 숨긴 것이 아니라 로컬 profile만 준비되고 실제 앱 호출은 아직 확인되지 않았다는 뜻이다.

설치기는 현재 Python 절대 경로를 사용하는 사용자 전용 런처와 `workspace-binding.json`을 `~/.k-guard`에 만들고, 기존 클라이언트 설정은 병합한다. `--workspace`를 생략하면 설치 명령을 실행한 현재 디렉터리가 결속된다. symlink·junction·비존재 경로는 설정을 바꾸기 전에 거부하며, 재설치로 workspace가 바뀌면 이전 binding을 백업한다. 화면에는 workspace basename과 keyed hash만 표시하고 운영자 evidence key와 전체 경로는 출력하지 않는다.

- `--profile workspace`: 코드·설정·흐름 중심, 동적 probe 꺼짐
- `--profile local-dev`: localhost GET/OPTIONS와 작은 고정 심화 경로 켜짐
- `--workspace PATH`: 검사할 프로젝트 root를 고정. 기본값은 설치 명령의 현재 디렉터리
- 두 profile 모두 외부·세션 probe는 꺼짐

설정 파일을 바꾸기 전에 계획만 보려면 `--dry-run`을 붙인다. 수동 JSON 설정이 필요한 경우에는 [MCP 클라이언트 설치 참고서](mcp-client-install.md)를 사용한다.

## 3. 첫 검수

MCP 클라이언트에서 아래처럼 요청한다.

```text
안경선배의 check_my_app으로 현재 워크스페이스 전체 검수를 시작해줘.
continue_review를 state=completed 또는 failed가 될 때까지 반복하고,
완료 전에는 통과나 안전이라고 말하지 마. 완료된 experience.presentation 순서대로 판정, 이유, 다음 행동 3개를 먼저 말하고,
원문 개인정보나 비밀값은 출력하지 마.
```

AI는 먼저 `check_my_app`을 호출한다. 첫 응답은 전체 검수 작업의 접수 상태이며 판정이 아니다. `continue_review`를 terminal 상태까지 반복한 뒤 `experience.presentation`의 `verdict`, `why`, `next_actions` 순서로 읽는다. 완료 결과의 `review_receipt`는 설치한 workspace와 현재 source tree에 묶인다.

전체 검수는 소스·설정·테스트·문서뿐 아니라 `dist`, `build`, `.next`의 배포용 텍스트 산출물도 읽는다. 지원 후보 중 하나라도 읽지 못했거나 전후 후보 지문이 달라지면 `MCP_EXHAUSTIVE_SCOPE_INCOMPLETE` 또는 `GUARDIAN_SCAN_INVENTORY_MISMATCH`로 HOLD한다.

## 4. 출하 전 Guardian

```text
현재 앱의 app id, 실제 business purpose, data classes, user scope,
scope proof, local live URL과 public endpoints를 나에게 확인해줘.
코드를 고쳤다면 check_my_app을 다시 완료해줘. 추측하지 말고 확인된 값과
최신 완료 결과의 review_id만 start_review_before_ship에 전달해줘.
continue_review로 Guardian이 완료될 때까지 기다린 뒤 experience.presentation의 판정, 이유, 다음 행동부터 보여줘.
```

`--profile local-dev`로 설치했다면 로컬 동적 검사의 환경 변수는 사용자 전용 런처가 설정한다. 외부 주소는 자동 허용하지 않는다.

외부 주소는 owned/partner 범위가 명확할 때만 별도 허용한다. 기본값은 로컬 주소만 허용한다.

## 5. 판정 읽기

- `experience.details.presentation.verdict.code=review_in_progress`: 아직 검수 중, 통과 아님
- 완료된 Guardian의 `experience.presentation.verdict.code=ship`: 설정한 범위와 high 기준에서 출하 가능
- `experience.presentation.verdict.code=hold_fix`: blocking finding 수정 필요
- `experience.presentation.verdict.code=hold_coverage`: 동적 검사, 흐름, 목적·범위 같은 증거 부족
- `experience.presentation.verdict.code=hold_authority`: 모든 대상의 동일 `app_id` 또는 운영자 서명키 증거 부족
- `experience.presentation.verdict.code=hold_qualification`: deep/multilanguage, Streamable HTTP runtime, 12~20개 field 정확도 증거 부족
- `experience.presentation.verdict.code=review_only`: 검수 보고서만 생성됨. `Guardian high`로 다시 실행해야 출하 판정이 생김

`application_assurance`는 현재 앱의 검수 범위와 blocking risk를, `auditor_qualification`은 K-Guard 버전 자체의 deep·SCA·runtime·DB·field 검증 상태를 나타낸다. 앱이 clear여도 감사 도구 자격 증거가 덜 차면 `hold_qualification`이 유지된다. `ship`은 무결점 보증이 아니므로 보고서의 `claim_boundary`와 `review_contract`를 함께 보관한다.

## 문제 해결

- MCP 도구가 안 보임: 클라이언트를 다시 시작하고 `python -m k_guard_mcp.server` 경로를 확인한다.
- `ModuleNotFoundError`: MCP 클라이언트가 설치에 사용한 Python과 같은 Python을 쓰는지 확인한다.
- 동적 검사가 막힘: 로컬 앱이 실행 중인지, `--profile local-dev`로 설치했는지 확인한다.
- Guardian이 계속 보류됨: `experience.presentation.next_actions`, `review_contract.domains.*.missing`, `release_qualification.gates.*.failed_checks`를 차례로 본다.
- `MCP_INITIAL_REVIEW_SOURCE_DRIFT`: 코드가 바뀌었다. `check_my_app`을 다시 완료하고 새 `review_id`를 사용한다.
- `MCP_WORKSPACE_SCOPE_MISMATCH`: 다른 프로젝트가 결속됐다. 의도한 프로젝트에서 `k-guard install --workspace .`을 다시 실행하고 클라이언트를 재시작한다.
- 설치 상태가 애매함: `k-guard doctor --client auto`의 `[3/3] 다음 행동`을 위에서부터 실행한다. 자동화에서는 `--json`을 붙인다. `connection_state=configured_restart_required`는 등록 확인일 뿐 실제 tool 호출 완료가 아니다.

전체 옵션은 [MCP 클라이언트 설치 참고서](mcp-client-install.md)에서 확인한다.
