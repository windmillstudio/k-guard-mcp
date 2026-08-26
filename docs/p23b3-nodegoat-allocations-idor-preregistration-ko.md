# P2.3B.3 NodeGoat allocations IDOR execution oracle 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 프로그램: [P2.3B execution oracle 사전등록](p23b-local-execution-oracle-program-preregistration-ko.md)

## 가설

P2.3A의 NodeGoat source receipt와 일치하는 local source-built image에서, OWASP
NodeGoat가 스스로 설명하는 allocations IDOR를 내부 전용 Docker network에서 재현할 수
있다. 공개 seed의 일반 사용자 `user1`으로 로그인한 뒤 `/allocations/3`을 요청하면 현재
취약 source는 HTTP `200`으로 다른 사용자 allocation 화면을 렌더링한다.

같은 source image에서 `app/routes/allocations.js`의 URL parameter 사용을 session user ID
사용으로 정확히 한 곳만 바꾼 negative derivative를 만들면, 같은 login/request는 여전히
HTTP `200`이지만 타인 allocation 화면을 렌더링하지 않는다. 이 차이는 source-mutated
negative control이며 upstream fixed revision, 일반 IDOR 탐지 성능, 또는 K-Guard finding의
증거가 아니다.

## 사전 고정 입력

| 항목 | 고정값 또는 검증 방법 |
| --- | --- |
| source | P2.3A `nodegoat` source receipt의 repository `owasp/nodegoat`, commit `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`, source tree SHA-256 `352404981579791fafc18f70649c772a03f304b8895c4f239fbd9863ef5f8a52` |
| upstream positive oracle | source `app/views/tutorial/a4.html`의 allocations direct-object-reference tutorial과 `app/routes/allocations.js`의 `req.params.userId` flow |
| positive observation | seeded `user1` session으로 `/allocations/3`을 읽을 때 HTTP `200`과 foreign-allocation boolean이 관찰됨 |
| negative mutation | `app/routes/allocations.js`에서 exact `req.params.userId` destructuring block 하나를 `req.session.userId` block으로 교체 |
| negative observation | 같은 session/request에서 HTTP `200`, foreign-allocation boolean `false`, own-allocation boolean `true` |
| source application image | local `kguard-l2/nodegoat:c5cb68a7`, image ID `sha256:0b25b431d05093835f50099d7281fc25553f45802e75f4686e31fee6ffafc71b`, label commit과 extracted route hash를 P2.3A source와 일치 확인 |
| database runtime | local-only `mongo@sha256:7250955b2354cc6ad3548b428628e441e34625caa39dd64906e85adf369e1942`; NodeGoat source distribution에는 포함되지 않는 execution dependency이며 runtime image license/supply-chain quality를 주장하지 않음 |
| execution | fresh internal-only Docker network, host port 없음, source/seed/app/database container 모두 non-privileged, read-only rootfs와 bounded tmpfs/resource limits, app driver는 app container loopback만 사용 |
| evidence | source, session cookie, login material, response body, seed data, absolute checkout path를 저장하지 않고 canonical hash와 structured boolean/status만 저장 |

## 변경 범위

| 대상 | 허용 변경 |
| --- | --- |
| 새 replay runner 및 tests | P2.3A source/registry binding, pinned local image verification, internal network lifecycle, state reset, bounded single-file mutation, loopback driver, isolation/cleanup, raw-free receipt와 repeat comparator 구현 |
| 문서와 ledger | 실행 결과와 narrow claim boundary 기록 |

K-Guard detector, rule, severity, scoring, warning/block policy, Guardian threshold, P2.3A source
checkout과 source identity는 변경하지 않는다. negative patch는 transient build context에서만
만들며 source checkout에 쓰지 않는다.

## 성공 조건

1. P2.3A source receipt, source image commit label, extracted route hash, Mongo image digest 중 하나라도 맞지 않으면 실행 전 `HOLD`다.
2. negative patch anchor가 정확히 한 번이 아니거나 original source bytes와 patched bytes가 같으면 `HOLD`다.
3. 각 inner run은 새 internal network와 seeded DB를 만들고, positive는 foreign allocation `true`, negative는 foreign allocation `false`와 own allocation `true`를 관찰한다.
4. app, seed, database container 또는 network의 ownership, cleanup, no-host-port, internal-network, read-only/tmpfs, non-privileged 조건을 재검사하지 못하면 `HOLD`다.
5. positive/negative pair는 별도 output에서 두 번 실행하고 semantic comparator가 `FIX`여야 한다.
6. focused tests, current target full regression, Claude Opus 4.8/Grok 4.5/Cline GLM 5.2의 두 review run comparator를 통과해야 한다.

## 명시적 비주장

이 작업은 NodeGoat 한 route의 source-bound IDOR positive/negative execution pair와
repeatability만 다룬다. K-Guard가 IDOR를 탐지했다는 주장, general authorization/IDOR
recall, TP/FP/FN/TN, CVSS/CWE, authenticated crawling, warning/block promotion, database
policy/RLS, Guardian completeness, H100, 제품 release는 이 작업에서 승인하지 않는다.

Mongo runtime image는 local execution dependency일 뿐 NodeGoat source provenance 또는
fresh dependency rebuild, runtime supply-chain security, product release quality를 보장하지
않는다.

## 완료 패킷 (2026-07-23)

| 칸 | 결과 |
| --- | --- |
| A | 이 문서에서 P2.3A source binding, NodeGoat tutorial/route oracle, Mongo execution allowance, 단일 route mutation, isolation 조건과 비주장 범위를 실행 전에 고정했다. |
| B | `replay_l2_nodegoat_idor.py`는 P2.3A registry와 Git blob source, NodeGoat image label/route hash, pinned Mongo digest, bounded one-site negative patch, internal-only Docker network, state reset, raw-free receipt, owned-resource cleanup을 fail-closed로 검증한다. `compare_l2_nodegoat_idor_repeats.py`는 positive pair와 corresponding positive anchor에 결속된 negative pair를 각각 비교한다. |
| C | sealed r40 target에서 focused attestation은 86 passed, 0 failed, 0 errors, 0 skipped이며 NodeGoat replay/comparator와 source-materialization 계약을 함께 검사했다. |
| D | r40 target에서 positive r7/r8은 각각 `EXECUTION_CONTRACT_PASS`, negative r9/r10은 각각 `NEGATIVE_CONTROL_PASS`였다. positive와 negative comparator는 모두 `FIX`, `repeat_exact=true`다. 중간 negative r7의 exit 137 `HOLD` evidence는 삭제하지 않고 development evidence로 보존했다. |
| E | r40 full regression은 12/12 shard `COMPLETE`, 2,494 passed, 5 skipped, 0 failed, 0 errors이며 aggregate SHA-256은 `ff809defd064ca4da22d6816bfa0d437ce87ec6d79565c7d0e03db5f519c81d0`다. |
| F | health r2에서 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2가 모두 healthy였다. 두 review run은 전원 `GO`, blocker 0, claim boundary confirmed, nonblocking `REPEATABILITY_GAP` 하나였고 review comparator는 `FIX`였다. Claude는 지정한 12개 direct file을 읽은 attestation을 남겼다. |
| G | 이 작업은 one-source, one-route, source-mutated control의 execution repeatability만 `FIX_NARROW`로 기록한다. K-Guard IDOR detector accuracy, general authorization recall, TP/FP/FN, severity, warning/block, Guardian, H100, release는 모두 `HOLD`다. |

주요 외부 evidence는 `phase0-current-baseline-20260723-r40`,
`phase2-p23b3-focused-regression-20260723-r2`,
`phase1-regression-shards-20260723-r18`,
`phase2-p23b3-nodegoat-allocations-idor-development-20260723-r7`,
`phase2-p23b3-nodegoat-allocations-idor-development-20260723-r8`,
`phase2-p23b3-nodegoat-allocations-idor-development-20260723-r9`,
`phase2-p23b3-nodegoat-allocations-idor-development-20260723-r10`,
`phase2-p23b3-nodegoat-allocations-idor-development-20260723-r7-r8-positive-comparison.json`,
`phase2-p23b3-nodegoat-allocations-idor-development-20260723-r9-r10-negative-comparison.json`,
`phase2-p23b3-supervisor-review-20260723-r1-r2-comparison.json`에 보존한다.
