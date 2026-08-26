# K-Guard Contest Demo v2

이 디렉터리는 180초 이내 화면 시연을 위한 **로컬 합성 fixture**다. 실제 앱 검증 주장은 하지 않는다. `demo-metadata.json`의 `real_app_validation`은 `false`이며, 이 결과는 실제 field accuracy, MCP client 상호운용, 수상 실적, SHIP 또는 canonical release authority의 증거가 아니다.

## 화면 여정

`run`은 다음 순서를 한국어 console에 즉시 출력한다.

1. 취약 합성 fixture 공개
2. 첫 Guardian 검수와 `hold_fix`
3. 실제 report 순서의 첫 actionable blocker
4. 취약 fixture와 fixed fixture 사이의 실제 unified diff 및 적용 확인
5. 같은 manifest와 이전 report를 사용한 재검수
6. 앱 위험 `clear_in_reviewed_scope`와 제품 `hold_qualification`의 분리

각 Guardian subprocess의 stdout은 숨겨 두지 않는다. wrapper가 받은 즉시 `verdict`와 전체 gate를 한국어 한 줄로 정규화해 출력한다. 성공 transcript에는 동적 port, HMAC key, 절대경로, 실행시간을 넣지 않아 같은 제품 상태에서 재현 가능하다.

## 고정 계약

- 버전: `k_guard_contest_demo.v2`, `2.0.0`
- 실행 표면: `python -m k_guard_mcp.cli guardian`을 호출하는 로컬 제품 CLI 데모
- MCP 경계: MCP client를 실행하거나 MCP 상호운용 증거를 만들었다고 주장하지 않음
- 앱 바인딩: workspace와 HTTP row 모두 `app_id=contest-demo-v1`
- 대상: 현재 작업용 workspace와 OS가 배정한 `127.0.0.1` port만 허용
- 공개 대상: 호출하지 않으며 runtime manifest 검증이 다른 host를 거부
- 증거 키: 실행 세션마다 `K_GUARD_EVIDENCE_HMAC_KEY`를 준비하고 커밋하지 않음
- 실행 예산: 전체 180초, Guardian 단계당 75초, 종료 여유 10초
- 기대 앱 전이: `risk_blocked -> clear_in_reviewed_scope`
- 기대 제품 전이: `hold_fix -> hold_qualification`
- SHIP/수상 주장: 하지 않음

## 실행

저장소 루트에서 개발 의존성을 설치한 뒤 실행한다.

```powershell
python -m pip install --require-hashes -r requirements-evidence.lock
python -m pip install --no-build-isolation --no-deps -e .
python examples/contest-demo/v1/demo.py dry-run
python examples/contest-demo/v1/demo.py run
```

`dry-run`은 계획과 기대 계약만 출력한다. Guardian 검사, HTTP 요청, 파일 patch를 실행하지 않으며 결과 증거가 아니다. 실제 `run`은 ignored 경로 `tmp/contest-demo-v1`에서 loopback 서버, 두 번의 Guardian CLI 검수, patch, transcript와 scorecard 생성을 수행한다.

CLI exit `3`은 두 단계 모두 의도된 fail-closed 제품 gate다. wrapper는 앱 위험 전이와 qualification HOLD 경계가 모두 맞고 모든 계약 check가 참일 때 exit `0`을 반환한다.

## 산출물

실제 실행은 다음 파일을 `tmp/contest-demo-v1/evidence/`에 만든다.

- `hold.json`, `hold.md`, `hold.html`: 첫 실제 Guardian 결과
- `fixed.json`, `fixed.md`, `fixed.html`: 같은 범위의 재검수 결과
- `demo-transcript.txt`: 화면에 표시한 정규화된 여정
- `demo-scorecard.json`: 두 실제 report에서 계산한 경계 scorecard

체크인된 `submission/demo/dry-run-*` 파일은 무실행 계약 예시다. 촬영 순서와 정확한 내레이션은 `submission/demo/RUNBOOK.md`를 따른다.

## 검증

```powershell
python -m pytest tests/test_contest_demo_journey.py -q
python -m unittest discover -s examples/contest-demo/v1/tests -v
```

실제 시연 직전에는 `run`을 다시 실행하고 `demo-scorecard.json`의 `passed`와 모든 `checks`가 `true`인지 확인한다. 앱 위험 CLEAR는 검수한 합성 앱 범위의 판정일 뿐이며, 제품 qualification과 release authority는 계속 fail-closed일 수 있다.
