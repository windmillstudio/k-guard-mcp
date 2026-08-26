# P2.4B.3.13 api-13 Ktor resource-owner source-tree 사전등록

작성일: 2026-07-25  
상태: `ACTIVE` - approved-manifest 결속 교정 target의 A만 `DONE`, 다음은 B. 2026-08-23 two-lane F1 HOLD는 불변 보존하며 교정 target B-E 전에는 새 F1/F2를 실행하지 않는다.
상위 카드: [auth-rls-db 19-slot WBS](p24b3-auth-rls-db-materialization-wbs-ko.md)

## 한 문장 목표

`api-13`의 primary와 같은 slot의 pre-registered reserve에 대해 Kotlin/Ktor resource-owner
vulnerable/fixed/negative source tree만 deterministic하게 materialize할 계약을 결과 전에 고정한다.

## A: 결과 전 고정한 binding

| 항목 | primary | reserve |
| --- | --- | --- |
| slot / scenario / oracle | `api-13` / `dev-api-13-resource-owner` / `l3-gen-api-13-resource-owner` | 같은 slot의 pre-registered reserve |
| source role | `GET /accounts/{accountId}/documents/{documentId}` document resource route | `GET /workspaces/{workspaceId}/files/{fileId}` file resource route |
| framework | Kotlin / Ktor | Kotlin / Ktor |
| vulnerable boundary | `documentId`만으로 repository lookup source를 만들고 `accountId` 또는 actor-owner predicate를 source에 넣지 않음 | `fileId`만으로 repository lookup source를 만들고 `workspaceId` 또는 actor-owner predicate를 source에 넣지 않음 |
| fixed boundary | source에 `documentId`와 `actorId`를 함께 받는 owner-scoped repository lookup을 명시 | source에 `fileId`와 `actorId`를 함께 받는 owner-scoped repository lookup을 명시 |
| fixed marker | `resource owner enforcement not materialized` static marker source | 같은 marker contract |
| negative control | Ktor import, route/mapping, resource lookup, actor/owner predicate가 없는 static Kotlin status source | 같은 negative contract |
| severity | CWE-639 / High | same slot reserve |

고정 invariants:

- vulnerable, fixed, negative는 각각 별도 source role이며 fixed는 vulnerable route source를 재사용하지 않는다.
- primary/reserve route, vulnerable actor-owner predicate 부재, fixed owner-scoped lookup, negative exclusion,
  slot/blueprint binding이 바뀌면 `HOLD`다.
- fixed owner-scoped lookup은 실제 Ktor authentication, authenticated principal provenance, tenant/workspace
  membership, HTTP server, database, network call 또는 성공 응답을 만들지 않는다.
- source tree에는 실제 계정, secret, access token, database connection string을 넣지 않는다.
- 이 카드는 source-tree identity만 다룬다. Ktor runtime authorization, resource ownership enforcement,
  endpoint execution, exploitability, detector finding, precision/recall, H100, Guardian, release는 주장하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | 위 binding, primary/reserve, source-role, 비주장 사전등록 | `DONE` - current-target |
| B | api-13 scoped renderer와 strict receipt validator | 구 `materialize_l3_auth_rls_db_api13.py` 결과는 이력 보존, 현재 target 완료 비인정. current-target B가 다음 |
| C | owner-predicate/path/raw/overwrite/tamper focused test | 구 api-13 focused chain `6 passed`는 이력 보존, 현재 target 완료 비인정 |
| D | external r1/r2 source comparator | 구 comparator `FIX`, semantic fingerprint `632caf7f...00d82`는 이력 보존, 현재 target 완료 비인정 |
| E | baseline, focused/full regression, target equality | 구 supervisor-target/pre-P8.2A E는 이력 보존, 현재 target 완료 비인정 |
| F1/F2 | Claude Opus 5 max, Grok 4.6 xhigh two-run review | `PENDING` - current-target B-E 뒤에만 실행. 구 3-lane F1 HOLD는 불변 이력, 현재 target 완료 비인정 |
| G | supervisor comparator `FIX`, evidence hash, 비주장 기록 | `NOT_STARTED` |

## Gate G 전 비승격 상태와 외부 evidence 결속

이 저장소의 machine/human status는 Gate G 전까지 의도적으로 `ACTIVE`, completed `A`, next `B`에
머문다. B-E의 candidate receipt를 만든 직후 저장소 상태 문서를 갱신하면 review target 자체가
바뀌어 그 receipt가 즉시 stale해지기 때문이다. 따라서 다음 계약을 사용한다.

- B-E candidate receipt는 저장소 밖 고정 evidence root에만 새 파일로 생성한다.
- external audit payload manifest는 repository direct file과 external raw-free receipt를 각각
  path/label, byte count, SHA-256으로 고정하고 전체 direct-file-set SHA-256을 기록한다.
- supervisor runner는 operator가 승인한 payload-manifest SHA-256, 현재 target, claim boundary,
  Opus 5 max/Grok 4.6 xhigh 정책, 모든 direct file과 artifact 매핑이 하나라도 다르면 provider 호출 전에 중단한다.
- Claude만 승인된 repository file과 external raw-free receipt를 Read한다. Grok packet에는 external
  absolute path나 파일 원문을 넣지 않고 식별자, 해시, test basis와 비승격 계약만 넣는다.
- repository status가 아직 A라는 사실 자체는 evidence gap이 아니다. B-E receipt가 없거나 승인
  manifest에 결속되지 않은 경우는 `EVIDENCE_BINDING_GAP`이고, 두 GO run과 comparator `FIX` 없이
  상태를 바꾸는 것은 `RELEASE_NONPROMOTION_GAP`이다.
- 두 review run과 comparator가 모두 통과한 뒤에만 Gate G 상태 갱신과 다음 카드 Gate A를 같은
  post-review 변경으로 수행한다. 그 변경은 새 target이며 과거 API13 review target으로 소급하지 않는다.

## 보존한 2026-08-23 Opus 5/Grok 4.6 F1 HOLD

- approved external payload manifest SHA-256은
  `da0f7e400901e6d2d5ec21d53e5eac0a7cda8dccd77c63840ac974f60eaaeb60`였고,
  repository direct file 29개, 427211 bytes를 포함했다.
- Grok 4.6 xhigh는 `GO`와 nonblocking `REPEATABILITY_GAP`을 냈다. Claude Opus 5 max는
  `CLAIM_BOUNDARY_GAP`, `EVIDENCE_BINDING_GAP`으로 `HOLD`를 냈다.
- decision / receipts / packet / generated evidence-manifest SHA-256은 각각
  `4a4ec8a69aed825b79bbb193674928a3700eac75c0fe6412ded5694b56f0d52b` /
  `49e27b80e50e1100ed226823dc6a58509de44c91ec7a398487e87212aac81e2d` /
  `6440772d0e7003d4e71929a059a8f7bd9ae50023ab6031d4aa8707e6536f99c4` /
  `995135510d2523c09b32b91b1edd33e22ff69b0fb2a09b8340d9af2fe4b6664f`다.
- 원인은 operator 승인 manifest SHA가 generated review packet에 직접 결속되지 않았고, artifact
  manifest가 generic label만 남겨 repository path 매핑을 잃었으며, B-E raw-free receipt가 Claude
  direct Read set에 없었던 점이다. A-only pre-promotion status 설명도 packet에 없었다.
- 이 HOLD는 성공으로 바꾸거나 F2와 비교하지 않는다. 교정 target은 manifest v2 binding,
  repository-path artifact mapping, external receipt direct Read, explicit pre-promotion contract를 구현한
  뒤 B-E를 다시 측정하고 새 stem으로만 검토한다.

## current-target Gate A restart

Sol preflight accepted identity: HEAD `6f0874c5bc3bebceecca41030b8ffe4f14026fc0`, tree
`4c6545ff743a2ea54c737aa7caed2adaec77d7c8`, porcelain `0`.

기존 API13 A binding table과 claim boundary는 변경 없이 이 identity에 재고정한다. 구 r1/r2,
pre-P8.2A, F1 HOLD evidence는 불변 이력이며 현재 target 완료로 인정하지 않는다. 현재 target
완료는 A만이고 다음은 B다. F1/F2는 `PENDING`이며 실행하지 않는다. G는 `NOT_STARTED`다.
이 restart는 runtime authorization, detector accuracy, H100, Guardian, release를 주장하지 않는다.

## E 재실행의 결과 전 focused scope

pre-P8.2A raw-free receipt는 selector hash와 `18 passed`만 남기고 selector 원문을 보존하지
않는다. 따라서 그 범위를 추측해 재현했다고 주장하지 않는다. 새 supervisor target E에서는
아래 네 직접 의존 test selector를 **결과 전에** focused scope로 고정한다.

- `tests/test_build_l3_generated_pair_blueprint.py`
- `tests/test_stage_l3_generated_pair_source_triplets.py`
- `tests/test_materialize_l3_auth_rls_db_api13.py`
- `tests/test_compare_l3_auth_rls_db_api13_repeats.py`

이 chain은 blueprint quota/tamper, staging binding/tamper, api-13 source role/path/raw/overwrite
tamper, r1/r2 comparator tamper refusal을 함께 검증한다. 새 target에서 먼저 실행한 api-13
전용 6-test receipt는 scope 확인 기록으로 보존하지만, 위 네 selector complete receipt가
없으면 E 통과 근거로 사용하지 않는다. 이 scope도 Kotlin/Ktor runtime authorization,
endpoint execution, detector accuracy, TP/FP/FN, H100, Guardian, release를 검증하거나
주장하지 않는다.

## A blueprint evidence와 비주장

- upstream generated-pair blueprint의 `api-13` record는 `kotlin`, `ktor`, `CWE-639`, `high`,
  `deterministic-fixture-v1`, `dev-api-13-resource-owner`,
  `l3-gen-api-13-resource-owner`와 scanner output absent-at-seal binding을 가진다.
- blueprint SHA-256은 `3489c9a802a960a1c31451cb12d3cd2976d8c87be0c4c37c7c9e7fcf8a05e2a6`이며, raw-free 원본은
  외부 evidence root `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24a-generated-pair-blueprint-20260723-r1\\blueprint-r1.json`에만 있다.
- 이 A evidence는 source tree, execution oracle, scanner detection, TP/FP/FN, H100, Guardian 또는 release를 증명하지 않는다.

## 시작 경계

이 leaf는 `P2.4B.3.12 api-12`가 G까지 `FIX_NARROW`로 닫힌 뒤 열었다. B 이전에는 source를
materialize하거나 scanner 결과를 보지 않는다. 새 renderer는 다른 `auth-rls-db` slot, 실제 Ktor
application, runtime authorization, scanner score, Guardian block rule을 수정하거나 승인하지 않는다.

## B/C renderer와 focused evidence

- renderer는 primary `DocumentRoute.kt`와 reserve `FileRoute.kt`를 별도 source role로 만들고,
  vulnerable에는 `findById`만 두며 fixed에는 `findByIdAndOwnerId(resourceId, actorId)` source를 명시한다.
- fixed marker는 `resource owner enforcement not materialized`만 선언한다. 실제 Ktor authentication,
  principal provenance, membership, HTTP server, database 또는 성공 응답을 만들지 않는다. negative control은
  static `Status.kt`만 포함하며 Ktor import, route, resource lookup, actor-owner predicate를 포함하지 않는다.
- focused chain은 source role, owner predicate, path, raw-free receipt, overwrite, source/receipt/path tamper와
  repeat-comparator tamper refusal을 포함해 `6 passed`였다. 이 결과는 source-tree identity의 B/C만 검증하며
  Ktor runtime authorization, resource ownership enforcement, detector accuracy, TP/FP/FN, H100, Guardian, release는 비주장이다.

## D external repeat evidence

- r1/r2 source materialization은 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b313-api13-ktor-resource-owner-20260725`에만 생성했다.
- r1/r2 raw-free receipt SHA-256은 각각
  `d08ace103d488ba34251b049959edbc99134e168fcd8ae69083661c8067bfc06` /
  `adb497025b62b89d7a6c86e0d268775ba908bd9c38df92a8c7305a6daad6ccc`다.
- raw-free comparator SHA-256은 `71183e7e78d480326d8f9c61db13b318c8a38c5492c0a3390d639714872e0d22`다.
  staged blueprint binding, source-triplet identity, materializer hash만 비교했고 semantic fingerprint
  `632caf7f35e3720ba8ac6fce8fa92bc2cebcb3dea9e57f31938ad0b12ec00d82`, `repeat_exact=true`, `status=FIX`를 기록했다.
- 이 D 결과도 source-tree identity만 확인한다. Ktor runtime authorization, resource ownership enforcement,
  endpoint execution, detector, TP/FP/FN, H100, Guardian, release에 관한 권한은 없다.

## E: 새 supervisor target regression evidence

- baseline receipt는 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b313-api13-ktor-resource-owner-20260725-supervisor-target-r1\\baseline-current.json`에만 있으며,
  receipt SHA-256은 `354718a6f7a276e291d61f1a4ee5832d75ddf843821098d9c7edfd66e69c6872`다.
  `--validate-current`는 `valid=true`, `current=true`를 냈다.
- 사전고정한 four-selector focused dependency chain은 `19 passed, 0 failed, 0 errors, 0 skipped`이며 receipt SHA-256은
  `91890363b551939dfc14a73b898ffc57290079b144948723742cf171850cd145`다.
- full attestation은 `2,790 passed, 5 skipped, 0 failed, 0 errors`, timeout/control error `0`이며 receipt SHA-256은
  `0f1d498fbc5a32a4250516b5376e9dd52d78ae24e9ee257bbf2cbf61ac03d208`다.
- baseline, focused before/after, full before/after는 모두 같은 HEAD
  `04e9dd8e7dc788d8242db138278758303ba6f27d`, dirty path set
  `51e12348080f51cd605933e3490d1313a5d7153cc0c7b8a87f957caa6a8b8046`, dirty worktree
  `d64c176745aa05d84ef138c9017fa5370ebfc3274b4cec6a6e51e6fc991e43b3`다.
- 이 E 결과는 source-tree renderer와 its dependency-chain/test-review packet의 회귀 경계만 뜻한다.
  Kotlin/Ktor runtime authorization, resource ownership enforcement, detector accuracy, TP/FP/FN, H100, Guardian,
  release는 비주장이다.

## 보존한 pre-P8.2A E와 중단된 F1 evidence

- baseline receipt SHA-256은 `a2ed75fe9c795e0eb78294322deabc00c1c8d257bbbc1383f8d8adaab1f45f6c`다.
  focused receipt SHA-256은 `8f6f703bc92b2667f41862a560497e382f460ffa9afe610e377dd2f7928286e2`이며
  18 passed, 0 failed였다. full receipt SHA-256은
  `5d47d0a8315c40507bc55fac0530411a7dd9e8f19c084157cea42fb392dc6336`이며 2,768 passed,
  5 skipped, 0 failed와 target before/after equality를 기록했다.
- F1 r1 evidence root
  `<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24b313-api13-ktor-resource-owner-20260725-supervisor-review-v1-r1`
  의 decision은 Grok `GO`, Claude/GLM `BLOCKED_PROVIDER`, overall `HOLD`다. 이는 api-13 claim의
  `HOLD` 결론이며 삭제하거나 `REPEATABILITY_GAP`으로 바꾸지 않는다.
- 원인은 처음에 Windows Python subprocess가 npm `claude`/`cline` shim을 bare executable로 찾지 못한
  supervisor runner 경로였고, shim fix 뒤에는 long-packet transport가 별도 blocker로 확인됐다.
  P8.2B와 P8.2A의 target 변경 뒤 기존 E/F1 evidence는 승격 근거로 재사용하지 않으며, API13은
  P8.2A G 후 새 baseline부터 E를 재측정한다.
