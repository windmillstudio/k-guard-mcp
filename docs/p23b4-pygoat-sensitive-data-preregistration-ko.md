# P2.3B.4 PyGoat sensitive-data API execution oracle 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 프로그램: [P2.3B execution oracle 사전등록](p23b-local-execution-oracle-program-preregistration-ko.md)

## 가설

P2.3A의 PyGoat source receipt와 일치하는 local source-built image에서,
`dockerized_labs/sensitive_data_exposure`가 공개적으로 설명한 unauthenticated all-users
API exposure를 내부 전용 Docker network에서 재현할 수 있다. source-defined demo fixture가
준비된 뒤 session 없이 `/api/all-users/`를 요청하면 취약 source는 HTTP `200`과 하나 이상의
user record, 그리고 credit-card, SSN, API-key field 존재를 반환한다.

같은 source image에서 `dataexposure/views.py`의 `all_users_data_view`에 이미 import된
`@login_required` decorator를 정확히 한 번 추가한 negative derivative를 만들면, 같은
unauthenticated request는 redirect HTTP `302`를 받고 all-users JSON을 받지 않는다. 이 차이는
source-mutated negative control이며 upstream fixed revision, general data-exposure/IDOR
detection accuracy, 또는 K-Guard finding의 증거가 아니다.

## 사전 고정 입력

| 항목 | 고정값 또는 검증 방법 |
| --- | --- |
| source | P2.3A `pygoat` source receipt의 repository `adeyosemanputra/pygoat`, commit `19d17cc8874861142b330636d068bbde54e86b85`, commit tree `1ee82a01f5ac80df289327eca929c9f5aff2a9c4`, source tree SHA-256 `156486b1531432930bf9df68f2886a20531c28a7aeffe95c9f095286eee3821c` |
| source license | root `LICENSE.md`, MIT, SHA-256 `f3e0249f489c8823e83c5f6e4a65795e624ef9024381722f21592134dcab611f` |
| source subproject | `dockerized_labs/sensitive_data_exposure`; source Dockerfile SHA-256 `007de200786f943a4905cf245a4049fe403848b14122a9ef728c2c0697da31da` |
| upstream positive oracle | subproject `README.md`의 public API all-users leak 설명, `dataexposure/urls.py`의 `/api/all-users/`, `dataexposure/views.py`의 unauthenticated `all_users_data_view` |
| positive observation | unauthenticated loopback-only GET은 HTTP `200`; parsed JSON은 non-empty `users` array와 expected record field-presence booleans를 가진다. response body, demo credential, record value는 evidence에 저장하지 않는다. |
| negative mutation | `dataexposure/views.py`에서 `def all_users_data_view(request):` 바로 앞에 `@login_required` line 하나만 삽입한다. import는 source에 이미 존재해야 하고 anchor가 한 번이 아니면 `HOLD`다. |
| negative observation | 같은 unauthenticated loopback-only GET은 redirect HTTP `302`, `users` JSON body 부재, login redirect boolean을 관찰한다. redirect는 follow하지 않는다. |
| image provenance | source `Dockerfile`, `entrypoint.sh`, `views.py`, `urls.py`, `models.py`, `requirements.txt` bytes와 P2.3A source receipt를 build 전에 대조한다. source base image와 no-network derived replay image에는 commit/tree/source-tree/subproject hash와 tool hash를 label로 결속한다. |
| runtime adapter | source Dockerfile가 `/app`에 SQLite migration과 demo fixture를 만들므로, source base image는 immutable `/opt/pygoat-source`를 보관하고 replay app은 non-root writable `/app` tmpfs에 source를 복사해 source entrypoint를 실행한다. adapter와 negative patch는 transient derivative에만 존재한다. |
| execution | fresh internal-only Docker network, host port 없음, external egress 없음, read-only rootfs, non-root app user, all capabilities dropped, no-new-privileges, bounded `/app`, `/tmp`, home tmpfs, no bind/volume mount, app driver는 app container loopback만 사용 |
| evidence | source, response body, demo credential, SQLite file, raw HTTP headers, absolute checkout path, container log를 저장하지 않고 canonical hash, structured status/boolean, image and tool provenance만 저장 |

## 변경 범위

| 대상 | 허용 변경 |
| --- | --- |
| 새 replay runner 및 tests | P2.3A source binding, source-image and adapter provenance, bounded decorator patch, tmpfs runtime, loopback driver, Docker isolation/cleanup, raw-free receipt와 repeat comparator를 구현 |
| 문서와 ledger | 실행 결과와 narrow claim boundary를 기록 |

K-Guard detector, rule, severity, scoring, warning/block policy, Guardian threshold, P2.3A source
checkout과 source identity는 변경하지 않는다. source base image는 fixed source subproject의
Dockerfile로 만들고, runtime adapter와 negative patch는 transient derivative에서만 만든다.

## 성공 조건

1. P2.3A source receipt, root license, source base-image labels, extracted source file hash,
   source Dockerfile/entrypoint hash 중 하나라도 맞지 않으면 실행 전 `HOLD`다.
2. negative decorator anchor가 정확히 한 번이 아니거나 import/route/source bytes가 기대값과
   다르면 `HOLD`다.
3. positive는 unauthenticated `200`, non-empty users, expected field-presence booleans를,
   negative는 unauthenticated `302`, users JSON 부재, login redirect boolean을 같은 bounded
   driver로 관찰한다.
4. app/seed/driver 컨테이너, derived image, temporary network 중 하나라도 cleanup하지 못하거나
   internal-network, no-host-port, read-only/tmpfs, non-privileged 조건을 재검사하지 못하면
   `HOLD`다.
5. positive/negative pair는 별도 output에서 두 번 실행하고 semantic comparator가 `FIX`여야 한다.
6. focused tests, current target full regression, Claude Opus 4.8/Grok 4.5/Cline GLM 5.2의 두
   review run comparator를 통과해야 한다.

## 명시적 비주장

이 작업은 PyGoat 한 standalone source subproject의 source-bound unauthenticated all-users
data-exposure positive/negative execution pair와 repeatability만 다룬다. K-Guard가 Korean
personal-data, sensitive-data exposure, IDOR, access control을 탐지했다는 주장, general
recall, TP/FP/FN/TN, CVSS/CWE, authenticated crawling, warning/block promotion, database/RLS,
Guardian completeness, H100, 제품 release는 이 작업에서 승인하지 않는다.

source-defined fixture는 isolated demo data이며, real personal data, field-app validation,
production database assurance, or runtime supply-chain/rebuild quality를 의미하지 않는다.

## 실행 결과와 장부 승격

이 문서의 사전등록을 기준으로 source-bound implementation, focused test, local replay,
full regression, external supervisor review를 순서대로 실행했다. final code target은
`phase0-current-baseline-20260723-r41`이며 baseline receipt SHA-256은
`6157144629f26a95363f77e64977d819e84688269ca463f65ae212b98571ae0d`다.

| 단계 | 결과 |
| --- | --- |
| focused test | `phase2-p23b4-focused-regression-20260723-r1/regression-attestation.json`, 12 passed, 0 failed, 0 errors, 0 skipped, receipt SHA-256 `58964a1f99c78cdcbb0b76ee6acfaec4af07b59ff5a99828cd1b0dcac3d25180` |
| positive repeat | development r2/r3의 unauthenticated all-users observation은 각각 성공했고, `phase2-p23b4-pygoat-sensitive-data-development-20260723-r2-r3-positive-comparison.json`은 `FIX`, `repeat_exact=true`다. |
| negative repeat | transient decorator negative r4/r5는 각각 expected `302`, no-users JSON, login redirect observation을 충족했고, `phase2-p23b4-pygoat-sensitive-data-development-20260723-r4-r5-negative-comparison.json`은 `FIX`, `repeat_exact=true`다. |
| full regression | `phase1-regression-shards-20260723-r19/aggregate.json`, 12/12 shard complete, 2,506 passed, 5 skipped, 0 failed, 0 errors, aggregate SHA-256 `8a69f009d3be3955521f99883ea464f0014fbe6a0388a0af749f165a2f0f6dba` |
| external review | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2가 동일 raw-free packet r3/r4를 각각 `GO`로 판정했고, `phase2-p23b4-supervisor-review-20260723-r3-r4-comparison.json`은 `FIX`, `repeat_exact=true`다. Claude direct-file attestation은 12/12다. |

개발 중 initial positive r1은 immutable source copy의 read-only mode가 runtime copy에도
보존되어 Django patch write가 막히면서 `HOLD`였다. adapter는 source copy 자체가 아니라
non-root `/app` tmpfs copy에만 user write permission을 복원하도록 수정했고, r1 evidence는
삭제하지 않았다. 최초 supervisor r1/r2는 내용이 다른 repeat summary를 사용해 semantic
comparison이 `HOLD`였으며, 동일 packet r3/r4를 새로 실행해 `FIX`를 얻었다. 이 실패
증거 역시 삭제하거나 승인 근거로 바꾸지 않는다.

따라서 이 항목은 P2.3B.4의 source-bound local execution contract에 한해
`FIX_NARROW`다. 이 결과만으로 finding, detector subtype, Korean PII accuracy,
TP/FP/FN, severity, warning/block, Guardian, H100, release를 승인하지 않는다.
