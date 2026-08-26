# P2.4B.3.08 api-08 Firebase storage read-rule source-tree 사전등록

작성일: 2026-07-25  
상태: `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX`  
상위 카드: [auth-rls-db 19-slot WBS](p24b3-auth-rls-db-materialization-wbs-ko.md)

## 한 문장 목표

`api-08`의 primary와 같은 slot의 pre-registered reserve에 대해 TypeScript/Firebase storage read-rule
vulnerable/fixed/negative source tree만 deterministic하게 materialize할 계약을 결과 전에 고정한다.

## A: 결과 전 고정한 binding

| 항목 | primary | reserve |
| --- | --- | --- |
| slot / scenario / oracle | `api-08` / `dev-api-08-storage-read` / `l3-gen-api-08-storage-read` | 같은 slot의 pre-registered reserve |
| source role | user-scoped `/uploads/{userId}/{allPaths=**}` storage rule | owner-scoped `/documents/{ownerId}/{allPaths=**}` storage rule |
| framework | TypeScript / Firebase | TypeScript / Firebase |
| vulnerable boundary | user-scoped object match 안에서 `allow read: if true;` | owner-scoped object match 안에서 `allow read: if true;` |
| fixed boundary | `request.auth != null && request.auth.uid == userId` owner predicate만 read allow expression으로 사용 | `request.auth != null && request.auth.uid == ownerId` owner predicate만 read allow expression으로 사용 |
| negative control | Firebase storage service, `allow read`, user/owner object match가 없는 static status source | 같은 negative contract |
| severity | CWE-284 / High | same slot reserve |

고정 invariants:

- vulnerable, fixed, negative는 각각 별도 source role이며 fixed는 vulnerable rule source를 재사용하지 않는다.
- primary/reserve의 object match path, `allow read: if true`, fixed owner identifier와 authenticated predicate,
  negative exclusion, slot/blueprint binding이 바뀌면 `HOLD`다.
- source tree에는 실제 Firebase project ID, credential, access token, 실제 사용자 데이터, network call을 넣지 않는다.
- 이 카드는 source-tree identity만 다룬다. Firebase rule deployment, Cloud Storage rule enforcement, authenticated
  principal semantics, cross-user object access, exploitability, detector finding, precision/recall, H100, Guardian,
  release는 주장하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | 위 binding, primary/reserve, source-role, 비주장 사전등록 | `DONE` |
| B | api-08 scoped renderer와 strict receipt validator | `DONE` - `materialize_l3_auth_rls_db_api08.py` |
| C | role/path/raw/overwrite/tamper focused test | `DONE` - api-08 focused chain `6 passed` |
| D | external r1/r2 source comparator | `DONE` - comparator `FIX`, semantic fingerprint `7d0417ac...07110` |
| E | baseline, focused/full regression, target equality | `DONE` - focused `18 passed`; full `2,738 passed, 5 skipped, 0 failed` |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two-run review | `DONE` - r1/r2 전 lane `GO`; comparator `FIX` |
| G | supervisor comparator `FIX`, evidence hash, 비주장 기록 | `DONE` - 아래 evidence와 narrow claim 기록 |

## 시작 경계

이 leaf는 `P2.4B.3.07 api-07`가 G까지 `FIX_NARROW`로 닫힌 뒤 열었다. B 이전에는 source를 만들거나
scanner 결과를 보지 않는다. 새 renderer는 다른 `auth-rls-db` slot, 실제 Firebase project, Firebase deployment,
scanner score, Guardian block rule을 수정하거나 승인하지 않는다.

## A blueprint evidence와 비주장

- raw-free blueprint는 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b308-api08-firebase-storage-read-20260725\\api08-pre-registration-blueprint.json`에만 생성했다.
- blueprint file SHA-256: `3dddfa838cba2cc54e1fca7195f314e513ddec8ab9ae2cfd45843b492a7023bd`.
  `api-08`은 `typescript`, `firebase`, `CWE-284`, `high`, `deterministic-template-v1`과 public scanner output
  absent-at-seal binding을 가진다.
- 이 evidence는 source tree, 실행 oracle, scanner detection, TP/FP/FN, H100, Guardian 또는 release를 증명하지 않는다.

## D external evidence

- r1/r2 source materialization은 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b308-api08-firebase-storage-read-20260725`에만 생성했다.
- raw-free comparator SHA-256: `675840cadd4a0f11a0f0d618c15ba659a2bae8824b3fd1cea1964b83e67f8776`.
  comparator는 slot `api-08`, source-triplet identity, staged blueprint binding, materializer hash만 확인했고
  semantic fingerprint `7d0417acff454e88027e37bad7e5f415c3f79f96304f0b9584d4be0aa4007110`,
  `repeat_exact=true`, `status=FIX`를 기록했다. Firebase runtime, rule enforcement, project access, exploit,
  detector, TP/FP/FN, H100, Guardian, release 판단에는 권한이 없다.

## E-G evidence와 비주장

- current baseline receipt SHA-256: `e3b25d6615ae311270a7d945c3372022a53d50e9674286162d7c3b77b6e83633`.
  full regression 뒤 `--validate-current`도 `current=true`로 통과했다.
- focused/full attestation receipt SHA-256:
  `b6d763f1d1e9506805157f1d30772d536b86c8cd292b65879a63bb9ad635b246` /
  `f6c0ffc80bdd535f6911e43527d47ccb7e13548e3bb620bab307320ae318d22f`.
  - focused 18 passed, full 2,738 passed, 5 skipped, 0 failed; control error와 target drift 없음.
- supervisor health raw-free receipt file SHA-256: `04ec68b6a2413dc20c1e767765ba3ec25b8a53599fad6afe2dee07a3542d2175`.
  이것은 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2의 availability만 확인하며 승인 evidence는 아니다.
- same-target F1/r2에서 세 모델은 전 lane `GO`였다. 각 단회 terminal `HOLD`는 second independent run이
  아직 없다는 `test_attestation_incomplete`만 기록한 비승격 상태다. supervisor comparator SHA-256
  `4645008f444f49750c4f459a770f16ce5289ae7cb2c8dee35d5a74bf2196aa26`, semantic fingerprint
  `859e4bc15aa9b45bccd9d6dca7ef3989ab54c6016e1caa30ea24a8820cc49fb0`, `repeat_exact=true`, `status=FIX`다.

이 결과는 `api-08` primary/reserve vulnerable/fixed/negative Firebase storage read-rule source-tree identity만
`FIX_NARROW`로 닫는다. Firebase rule deployment, Cloud Storage enforcement, authenticated-principal semantics,
cross-user object access, exploit, detector accuracy, TP/FP/FN, H100, Guardian 또는 release를 증명하지 않는다.
