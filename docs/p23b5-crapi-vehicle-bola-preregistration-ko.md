# P2.3B.5 crAPI vehicle BOLA execution oracle 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 프로그램: [P2.3B execution oracle 사전등록](p23b-local-execution-oracle-program-preregistration-ko.md)

## 가설

P2.3A registry와 동일한 crAPI identity source에서 authenticated actor가 다른 seeded
owner의 vehicle location endpoint를 호출하면, source route가 owner check 없이 path
vehicle ID만 사용하므로 HTTP `200`과 target vehicle location response field shape를
반환한다. 이는 source 문서의 BOLA challenge 1과 source
`VehicleController.getLocationBOLA` 및 `VehicleServiceImpl.getVehicleLocation`의
request-owner 미결속을 함께 사용한 source-bound execution oracle이다.

같은 source image의 transient negative derivative에서는
`getLocationBOLA`에 authenticated request를 추가하고,
`vehicleService.getVehicleDetails(request)`의 current-owner vehicle set에 path
`carId`가 없으면 `403`을 반환하는 소유권 guard를 정확히 한 번 삽입한다. 같은 actor,
target vehicle, request shape에서 negative는 target location response를 반환하지 않아야
한다. 이 negative는 source-mutated control이며 upstream fixed revision, general BOLA/IDOR
detection accuracy, 또는 K-Guard finding의 증거가 아니다.

## 사전 고정 입력

| 항목 | 고정값 또는 검증 방법 |
| --- | --- |
| source | P2.3A `crapi` receipt의 repository `owasp/crapi`, commit `73d309cc8f28bbdeed31dbb35f05dba8354de3c9`, commit tree `86d22e42ca8f8e3c903f30146ad0df51483b8df0`, source tree SHA-256 `f76c89d35f9b7d34c3b12c6b2f64177e0845957f85fab52613bbc18354925d52` |
| source license | root `LICENSE.md`, Apache-2.0, SHA-256 `c98881e3c37ee7331ff667bc0ae59415e5405ea18974c50fa44cd0308623415c` |
| source receipt | P2.3A app receipt SHA-256 `d86a9985f9eda5e391112a26a092f7a5273bde393c386ae8968f91399df7429b`, semantic SHA-256 `e284ea288d5a36a07661f279690c6e62bdd62e5905c2e2b3d733022efb64daaf` |
| relevant source bytes | P2.3A raw-blob source tree만 허용한다. identity `Dockerfile` `6ecdd3a650640d5b1ead281b0299cf5e3bd9764e62cd3b490ded246bfea782c0`; `entrypoint.sh` `855332e32c5e8e7a55568a59c44fe0cc88f6608b8ba8fddd4dcf2105a07fd18f`; `build.gradle.kts` `aff24988756aac240601f2874fcdc0239084db31cd0d9fa727db5354f97085cf`; `application.properties` `0a7805c942f360856f6a65a45db2b810ca56ce7015ba2d795694015b30368b26`; controller `c49f5ab14aab7b80386c5e309d6e493360ab86f21d41d939002f1d2961f78789`; service `1eadd6a4020699ea0e48e2ab3a245afc2618daf8e75ec97057f84a883d34a2c7`; seed config `9ac5f89ec9dd9c3397b66916f5998146c43ea1603d5b3fc1b6029425b088c9f4`; seed fixture `48a12a8a65695424def59cd21f4036ffe1af3201b6a933cca45f14dc8c80c369` |
| upstream positive oracle | source `docs/challenges.md` challenge 1 and `docs/challengeSolutions.md` describe another user's vehicle location access. `VehicleController` maps `GET /identity/api/v2/vehicle/{carId}/location`; the controller takes no request owner and the service resolves only `findByUuid(carId)`. |
| actor and target | two different source-defined seed identities and their distinct vehicle UUIDs. Credentials, JWT, UUID values, response body, full name, email, and location values remain process-memory only and are never written to evidence. |
| positive observation | driver logs in the actor through the source identity API and calls the target path with that actor's valid bearer token. It records only HTTP status, token-present boolean, target-not-actor boolean, response-object boolean, and field-presence booleans for `carId`, `fullName`, `email`, and `vehicleLocation`. |
| negative mutation | replace the exact controller method signature/body anchor once so it accepts `HttpServletRequest` and rejects a path `carId` absent from the current authenticated user's `vehicleService.getVehicleDetails(request)` set. Existing source tree is never modified; only a derived source copy is patched. |
| negative observation | same actor and target request returns `403`, has no target response field shape, and no location/full-name/email value is emitted. The same driver must also prove the actor and target identities differ before either outcome can be accepted. |
| runtime | identity service is built from the bound source Dockerfile. A fresh PostgreSQL runtime dependency and a one-shot driver run in a fresh Docker internal network with no host port, no bind/volume mount, no external egress during replay, explicit cleanup, bounded timeout, and raw-free receipt. Root filesystem, non-root execution, tmpfs, capabilities, and no-new-privileges are verified rather than assumed; unsupported hardening becomes `HOLD`. |

## 변경 범위

| 대상 | 허용 변경 |
| --- | --- |
| 새 replay runner와 tests | P2.3A source binding, source image build, ephemeral database and identity runtime, authenticated driver, one-anchor owner-guard mutation, isolation/cleanup checks, raw-free receipt와 repeat comparator를 구현 |
| 문서와 ledger | 실행 결과와 one-route narrow claim boundary를 기록 |

K-Guard detector, rule, severity, scoring, warning/block policy, Guardian threshold, P2.3A
source checkout과 source identity는 변경하지 않는다. crAPI source image의 upstream source는
수정하지 않고, negative control은 transient derived build context에서만 만든다.

## 성공 조건

1. P2.3A receipt, root license, commit/tree/source tree, relevant source file hash, source image
   label, actor/target distinctness, or mutation anchor 중 하나라도 맞지 않으면 실행 전
   `HOLD`다.
2. positive는 valid actor token, HTTP `200`, distinct target, and target response field-presence
   boolean을 모두 관찰해야 한다. token, UUID, credential, body, header, seed data는 evidence에
   쓰지 않는다.
3. negative는 same actor/target request에서 HTTP `403`, target response-field absence, and
   owner-guard marker를 모두 관찰해야 한다. `401`, timeout, exit code difference만으로는
   negative가 아니다.
4. app, database, driver container, derived image, temporary network 중 하나라도 cleanup하지
   못하거나 internal-network, no-host-port, no-bind-mount, no-egress, hardening property를
   재검사하지 못하면 `HOLD`다.
5. positive/negative pair는 서로 다른 external output에서 두 번 실행하고 semantic comparator가
   `FIX`여야 한다.
6. focused tests, current target full regression, Claude Opus 4.8/Grok 4.5/Cline GLM 5.2의
   두 review run comparator를 통과해야 한다.

## 실행 결과와 승격

아래 결과는 `2026-07-23` sealed r46 target에서 생성했다. 기준선 receipt SHA-256은
`e5c9ee744c31d1bc6025b70cd7c9067bca3a19975cf3daff5ac759c0d8667453`이고, target은
HEAD `04e9dd8e7dc788d8242db138278758303ba6f27d`, dirty worktree SHA-256
`d09cbb893adb273bc75e18fa121a98eae7e67316a94f7982821eb3163f5b55db`에 결속됐다.

| 칸 | 결과 |
| --- | --- |
| A | 이 사전등록의 source, actor/target, mutation, 제외, 비주장 경계를 변경하지 않았다. |
| B | replay runner와 comparator는 source tree, source image label, Docker isolation, ephemeral secret, cleanup, one-anchor mutation을 fail-closed로 결속했다. source checkout은 변경하지 않았다. |
| C | `tests/test_replay_l2_crapi_vehicle_bola.py`와 `tests/test_compare_l2_crapi_vehicle_bola_repeats.py`는 13 passed였다. |
| D | `phase2-p23b5-crapi-vehicle-bola-20260723-r5`의 positive r1/r2 comparator와 negative r1/r2 comparator는 모두 `FIX`, `repeat_exact=true`였다. negative 두 receipt는 서로 다른 positive receipt pair에 결속됐다. |
| E | `python -m pytest -q`는 2,519 passed, 5 skipped, 0 failed였다. |
| F | Claude Opus 4.8 direct-files, Grok 4.5 sanitized-packet, Cline GLM 5.2 sanitized-packet이 r1/r2 모두 `GO`를 냈다. 세 lane은 모두 `REPEATABILITY_GAP`만 nonblocking으로 기록했고 supervisor comparator가 `FIX`, `repeat_exact=true`를 확인했다. |
| G | 이 문서와 release ledger에 evidence path, hash, 비주장 범위를 기록해 `FIX_NARROW`로 승격했다. |

개발 중 발생한 isolation false HOLD, container cleanup 결함, negative generic-error-envelope
false HOLD, 잘못된 comparator 입력은 모두 `HOLD` evidence로 보존했다. 수정 뒤 새 target을
다시 봉인하고 r46 결과만 승격 근거로 사용했다.

이 승격은 source-bound local crAPI execution oracle 한 쌍의 반복성만 뜻한다. target의
vehicle response를 실제로 탐지하는 K-Guard rule의 정확도, 일반 BOLA/IDOR 탐지, severity,
TP/FP/FN, 한국 개인정보 성능, warning/block, Guardian, H100, release를 승인하지 않는다.

## 명시적 비주장

이 작업은 crAPI identity service의 source-bound authenticated cross-owner vehicle location
positive/negative execution pair와 그 반복성만 다룬다. K-Guard가 BOLA, IDOR, API exposure,
Korean personal data, authorization을 탐지했다는 주장, general recall, TP/FP/FN/TN, CVSS/CWE,
authenticated crawling coverage, warning/block promotion, database/RLS, Guardian completeness,
H100, 제품 release는 이 작업에서 승인하지 않는다.

source-defined seed fixture는 isolated demo data이며 real personal data, field-app validation,
production database assurance, or runtime supply-chain/rebuild quality를 의미하지 않는다.
