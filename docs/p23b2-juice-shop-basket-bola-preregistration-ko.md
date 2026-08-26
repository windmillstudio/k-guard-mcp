# P2.3B.2 Juice Shop basket BOLA execution oracle 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 프로그램: [P2.3B execution oracle 사전등록](p23b-local-execution-oracle-program-preregistration-ko.md)

## 가설

P2.3A의 Juice Shop source receipt와 일치하는 local source-built adapter image에서, upstream
API test `test/api/basket.test.ts`의 `GET existing basket of another user`가 뜻하는 동작을
loopback-only로 재현할 수 있다. 공개 test fixture의 Bjoern 계정으로 `/rest/basket/2`를
호출하면 현재 취약 source에서는 HTTP `200`과 basket id `2`가 관찰된다.

같은 source image에서 `routes/basket.ts`의 ownership 누락을 정확히 한 군데만 보완한
compiled negative derivative를 만들면, 같은 request는 HTTP `403`이 된다. 이 차이는
source-mutated negative control이며, upstream fixed revision이나 일반 BOLA 탐지 성능의
증거가 아니다.

## 사전 고정 입력

| 항목 | 고정값 또는 검증 방법 |
| --- | --- |
| source | P2.3A `juice-shop` source receipt의 repository `juice-shop/juice-shop`, commit `33518f5a0911e25d9df747b1e70fb7af279a755c`, source tree SHA-256 `9a109ac9217946774a0c5d356d2a9836c06153d4ae1fe21de92aa71556525fae` |
| positive oracle | upstream `test/api/basket.test.ts`의 `GET existing basket of another user`, source `routes/basket.ts`, challenge metadata `basketAccessChallenge` |
| positive observation | authenticated Bjoern fixture가 `/rest/basket/2`에서 `200`과 basket id `2`를 받음 |
| negative mutation | compiled `build/routes/basket.js`의 retrieve-basket path에 authenticated user `bid`와 requested basket id가 다르면 `403`으로 종료하는 authorization guard 하나를 삽입 |
| negative observation | 같은 fixture/request가 `403`이고 basket body를 성공으로 해석하지 않음 |
| image provenance | base image ID, OCI revision, app id, source-tree label, current source Dockerfile hash가 P2.3A source receipt 및 current source와 모두 일치해야 함 |
| execution | local Docker only, host port 없음, external network 없음, read-only rootfs, non-root `65532:0`, all capabilities dropped, no-new-privileges, bounded tmpfs/resource limits |
| evidence | source, token, response body, public fixture password, absolute checkout path를 기록하지 않고 canonical hash와 structured status만 저장 |

## 변경 범위

| 대상 | 허용 변경 |
| --- | --- |
| 새 replay runner 및 tests | current source-image provenance, bounded patch, loopback driver, Docker isolation/cleanup, raw-free receipt, repeat comparator를 구현 |
| 문서와 ledger | 실행 결과와 narrow claim boundary를 기록 |

K-Guard detector, rule, severity, scoring, warning/block policy, Guardian threshold, source identity,
P2.3A receipt, upstream source checkout은 변경하지 않는다. negative patch는 transient build
context 안에서만 만들며 source checkout에 쓰지 않는다.

## 성공 조건

1. base source image가 P2.3A source receipt의 commit/tree와 source Dockerfile bytes에 맞지 않으면 실행 전 `HOLD`다.
2. base compiled route가 기대한 marker를 정확히 한 번 포함하지 않거나 negative patch가 하나 이상의 위치를 바꾸면 `HOLD`다.
3. positive는 `200`과 expected basket id, negative는 `403`을 같은 bounded driver로 관찰한다.
4. each positive/negative pair는 별도 output에서 두 번 실행하고 semantic comparator가 `FIX`여야 한다.
5. container, owned derived images, temporary network/volumes 중 하나라도 cleanup하지 못하거나 isolation re-inspection이 실패하면 `HOLD`다.
6. focused tests, current target full regression, Claude Opus 4.8/Grok 4.5/Cline GLM 5.2의 두 review run comparator를 통과해야 한다.

## 명시적 비주장

이 작업은 Juice Shop 한 route의 source-bound BOLA positive/negative execution pair와
repeatability만 다룬다. K-Guard가 BOLA를 탐지했다는 주장, general IDOR/BOLA recall,
TP/FP/FN/TN, CVSS/CWE, authenticated web crawling, warning/block promotion, database/RLS,
Guardian completeness, H100, 제품 release는 이 작업에서 승인하지 않는다.

현재 local image의 provenance label은 P2.3A source tree와 맞는 preflight input일 뿐,
dependency-supply-chain의 fresh rebuild 또는 release quality를 보장하지 않는다.

## 완료 패킷 (2026-07-23)

| 칸 | 결과 |
| --- | --- |
| A | 이 문서에서 upstream API test, P2.3A source binding, compiled negative mutation, loopback-only Docker 조건과 비주장 범위를 실행 전에 고정했다. |
| B | `replay_l2_juice_shop_bola.py`는 P2.3A registry, Git blob source receipt, source-built image와 adapter image provenance, compiled route patch anchor, non-root/read-only/no-network Docker runtime, cleanup을 모두 fail-closed로 검증한다. `compare_l2_juice_shop_bola_repeats.py`는 positive pair와 positive anchor에 결속된 negative pair를 각각 비교한다. |
| C | sealed r34 target에서 focused attestation은 63 passed, 0 failed, 0 errors, 0 skipped이며 source verifier와 shard contract도 함께 검사했다. |
| D | r34 target에서 positive r1/r2는 각각 `EXECUTION_CONTRACT_PASS`, negative r1/r2는 각각 `NEGATIVE_CONTROL_PASS`였다. positive와 negative comparator는 모두 `FIX`, `repeat_exact=true`다. |
| E | r34 full regression은 12/12 shard `COMPLETE`, 2,478 passed, 5 skipped, 0 failed, 0 errors이며 aggregate SHA-256은 `88fa06b8c0fe1a8dbf1ab6f15ae502e24db0305c8859e5cc606a60ce5af6ce5d`다. |
| F | health receipt에서 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2가 모두 healthy였다. 두 review run은 전원 `GO`, blocker 0, claim boundary confirmed, nonblocking `REPEATABILITY_GAP` 하나였고 review comparator는 `FIX`였다. |
| G | 이 작업은 one-source, one-route, source-mutated control의 execution repeatability만 `FIX_NARROW`로 기록한다. K-Guard BOLA detector accuracy, general IDOR recall, TP/FP/FN, severity, warning/block, Guardian, H100, release는 모두 `HOLD`다. |

주요 외부 evidence는 `phase0-current-baseline-20260723-r34`,
`phase2-p23b2-focused-regression-20260723-r1`,
`phase1-regression-shards-20260723-r17`,
`phase2-p23b2-juice-shop-bola-20260723-r1`,
`phase2-p23b2-juice-shop-bola-20260723-r2`,
`phase2-p23b2-juice-shop-bola-20260723-r1-r2-positive-comparison.json`,
`phase2-p23b2-juice-shop-bola-20260723-r1-r2-negative-comparison.json`,
`phase2-p23b2-supervisor-review-20260723-r1-r2-comparison.json`에 보존한다.
