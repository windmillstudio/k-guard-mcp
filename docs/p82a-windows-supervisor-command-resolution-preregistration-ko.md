# P8.2A Windows supervisor command resolution 사전등록

작성일: 2026-07-25  
상태: `FIX_NARROW` - A-G와 Claude/Grok/GLM two-run comparator 완료  
상위 카드: [목표 통제와 독립 검증 운영](release-program-goal-control-ko.md)

## 한 문장 목표

Windows의 Python subprocess에서 npm이 만든 `claude.cmd`와 `cline.cmd` shim을 bare command로
놓치지 않고, Claude Opus 4.8·Grok 4.5·Cline GLM 5.2 supervisor runner가 실제 실행 가능한
경로를 같은 방식으로 선택하게 한다.

## 시작 전 관찰과 범위

`P2.4B.3.13 api-13`의 F1 r1은 Grok만 `GO`였고 Claude와 GLM은 `BLOCKED_PROVIDER`였다.
원인은 제품 finding이나 API13 source tree가 아니라 Windows Python subprocess가 bare
`claude`/`cline`을 npm shim으로 해석하지 못한 실행기 경로였다. 해당 실패 evidence는 외부 root
`<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24b313-api13-ktor-resource-owner-20260725-supervisor-review-v1-r1`
에 그대로 보존한다.

사전등록 전의 진단 patch와 health r1은 원인 확인용이며 이 카드의 B-D 또는 승격 근거로 쓰지
않는다. 아래 A 계약 이후의 새 target에서만 이 카드의 evidence를 다시 만든다.

## A: 결과 전 고정한 계약

| 항목 | 고정 내용 |
| --- | --- |
| 대상 실행기 | `claude`, `grok`, `cline`의 명시 executable 또는 PATH bare command |
| 해결 규칙 | PATH에서 찾을 수 있으면 subprocess가 직접 실행할 absolute file path를 사용하고, 명시 existing file도 absolute path로 정규화한다. 찾지 못하면 원래 문자열을 유지해 기존 fail-closed `BLOCKED_PROVIDER` 경로를 사용한다. |
| 적용 지점 | `execute_supervisor_review.py`와 `check_external_supervisor_health.py`의 실제 subprocess command builder |
| positive | bare `claude`/`cline`은 Windows npm `.cmd` shim으로, bare `grok`은 `.exe`로 command 첫 항목이 정규화된다. |
| negative | 존재하지 않는 command는 성공이나 fallback model로 바뀌지 않고 원 문자열을 유지한다. 외부 provider 실행 실패는 `BLOCKED_*`로 남는다. |
| replay | 새 target에서 focused test, health r1/r2, health semantic comparator, full regression, Claude/Grok/GLM F1/F2를 순서대로 다시 실행한다. |

## 명시적 비주장

이 카드는 Windows process invocation과 supervisor availability만 다룬다. Claude·Grok·GLM이
실제 product code를 승인했다는 뜻도 아니며, supervisor review의 내용 적합성, API13 Ktor
resource ownership, scanner 탐지, TP/FP/FN, H100, Guardian, 설치 완결성 또는 `GO_RELEASE`를
증명하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | 위 실행기, positive/negative, fail-closed, claim boundary 사전등록 | `DONE` |
| B | 공통 resolver와 두 command builder의 post-registration binding | `DONE` - `supervisor_executable_resolution.py`와 two runner mapping |
| C | shim, explicit file, missing command, command-builder focused tests | `DONE` - resolver/supervisor/health/comparator/goal focused 44 passed |
| D | 새 target health r1/r2와 semantic comparator | `DONE` - Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 모두 r1/r2 `HEALTHY`; comparator `FIX`, `repeat_exact=true` |
| E | focused/full regression 및 target equality | `DONE` - A-D target의 E-0 baseline, focused 54 passed, full 2,790 passed/5 skipped/0 failed가 target equality를 통과했다. F1/F2 packet에는 아래 A-E state의 E-1 replay를 별도 생성한다. |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two-run review | `DONE` - 초기 r1 Claude direct-file timeout을 보존했다. clean r2/r3은 세 lane 모두 `GO`, Claude direct-file 6개 attestation, comparator `FIX`, `repeat_exact=true`다. |
| G | comparator hash와 non-claim 기록 | `DONE` - D/E-0/E-1/F receipt와 comparator, timeout failure, 비주장을 아래에 기록했다. |

## 재개 경계

P8.2B는 G까지 `FIX_NARROW`로 닫혔다. native transport code가 같은 resolver의 실제 실행 경로를
`.cmd`에서 native `.exe`로 바꿨으므로 P8.2A는 A-C만 유지하고 D health r1/r2부터 다시 수행해야 했다.
그 첫 current-target D에서 GLM health terminal instability가 확인돼 P8.2D를 별도 카드로 열었다.
P8.2D와 P8.2E는 각각 G까지 닫혔다. P8.2A도 current-target F1/F2 comparator `FIX`까지 닫혔다.
API13은 새 supervisor target에서 E baseline/focused/full부터 재개한다.

## D external health evidence

- r1/r2 health receipt SHA-256은 각각
  `14a45fb242b7ca7080b6336e86de78fd8d2059bead10c6f8f1ce02d72ecace0a` /
  `303031b8ad6b9efa6e73ea4f1f036cd0f326bcbef699558f01f9b24207bb83b3`다.
- 두 run은 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 모두 `HEALTHY`였고 same measurement
  fingerprint `a268b5f321cea2e88be5150ee31222af3adf8248e9d9b9f7d215bd47127ca4b5`를 기록했다.
- comparator receipt SHA-256은 `282280fcf90188ec8a0c1aceb80dd347e4d09586b16855a02de14c9b5ecc1f9f`이며,
  `repeat_exact=true`, `status=FIX`, semantic fingerprint
  `03038067812c00824a01bf958d00780c8cdd47caa7235544020e8224318bb503`다. 이는 supervisor
  availability repeatability만 뜻하며 product review 또는 release approval은 아니다.

## E-0 regression evidence

- baseline receipt `8d7f02c452cd5b567f946b089fd6534b91066bbe055fc363f1bc6feba96f44e1`, file SHA-256
  `665451d6343ddcb03c6d1d516702b79b1e5eede72e63f83f57b25d0242113f23`.
- focused receipt `c70e64e19ac797f857a2e366f4309bca4abaad2d615d14cfd62455f2530e49f3`, 54 passed / 0 failed,
  file SHA-256 `b1cab6b593bff475e862d82f21710098084847c6d1802f2500eee2477ad423db`.
- full receipt `232bfafd57f2abbc06c7b35afc0fadc2fe589ff744635ec9c891fb17d3f1e037`,
  2,790 passed / 5 skipped / 0 failed in 1,067,313 ms, file SHA-256
  `c1bdc2babf1276fe586262c63b7713e4cfd0bae23520b0d3c1e2fb303b58f6d7`.
- baseline, focused, full의 target before/after는 같은 HEAD와 dirty-worktree hash를 기록했다.
  baseline 명령에 다음 명령을 잘못 붙인 첫 invocation은 parser가 evidence 생성 전 거부했고, receipt를
  만들지 않았다. 그 실패를 승격 근거로 쓰지 않았으며, baseline과 attestation은 위처럼 독립 실행했다.

E-0는 A-D state의 회귀 증거다. 상태를 A-E로 전이한 뒤에는 F1/F2에 쓸 E-1 baseline/focused/full을
같은 방식으로 다시 생성한다.

## E-1 regression evidence

- baseline receipt `5e728b2eb57c9e49fd80788ec642afdc587e14cb6b9ce9710539180d7545c5f6`, file SHA-256
  `3076aed2d6ddcac19c275bc78d334098c30e6cf40d8c83b34bbd92a04cc651db`.
- focused receipt `9ea91b74badb8d29e891f3372d191cd895b4a59c63e127fa5cfada09097a739c`, 54 passed / 0 failed,
  file SHA-256 `2a4d2edc28741a4dcf32957125b2355f10145cbffda07ecabad4111e1baabb6c`.
- full receipt `5e0c2fa800b4a51d0bc9faa0e7e05cb07a358d460dd006f7dbc255e3e4a2d241`,
  2,790 passed / 5 skipped / 0 failed in 1,122,469 ms, file SHA-256
  `96dca238d340d1031d3a9859ed320dc122088a4be61faa3f2eed730b22eb1548`.

## F/G supervisor evidence

- preserved r1 failure: 8 direct files and 300-second allowance produced Claude `BLOCKED_TIMEOUT`; Grok/GLM
  were `GO`, but the decision stayed `HOLD`. decision SHA-256
  `1862de7c99ef10bc0ead0a83a08538fbfb0382a7213473e5d50d0e4c3f54db1d`.
- clean r2/r3 limited Claude direct inspection to the six implementation/test files that define resolver and
  runner behavior. Claude, Grok, and GLM were all `GO` in both runs; Claude attested all six direct files.
- r2/r3 comparator SHA-256 `65cca02ee525701de1cb880b4a7e728f77e671ffe955fe6e2c4072edfc73bc7b`,
  `FIX`, `repeat_exact=true`, semantic fingerprint
  `9e1e3e76632a753c794dbbeb6958cc7e0dff9978a455766a2f3cc79d856eded0`.

이 종료는 Windows supervisor executable resolution과 source-free health availability만 승인한다.
review quality, API13 Ktor ownership, detector 성능, TP/FP/FN, 한국 개인정보, H100, 설치 완결성,
release approval은 모두 `HOLD`다.
