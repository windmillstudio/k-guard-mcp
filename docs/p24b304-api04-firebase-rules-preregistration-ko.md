# P2.4B.3.04 api-04 Firebase open-rule source-tree 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX`  
상위 카드: [auth-rls-db 19-slot WBS](p24b3-auth-rls-db-materialization-wbs-ko.md)

## 한 문장 목표

`api-04`의 primary와 같은 slot의 pre-registered reserve에 대해 TypeScript/Firebase open-rule
vulnerable/fixed/negative source tree만 deterministic하게 materialize할 계약을 결과 전에 고정한다.

## A: 결과 전 고정한 binding

| 항목 | primary | reserve |
| --- | --- | --- |
| slot / scenario / oracle | `api-04` / `dev-api-04-rule-open` / `l3-gen-api-04-rule-open` | 같은 slot의 pre-registered reserve |
| source role | Firestore `teamNotes` rule과 server-side repository declaration | Storage `customerDocuments` rule과 server-side repository declaration |
| framework | TypeScript / Firebase | TypeScript / Firebase |
| vulnerable boundary | matching document에 `allow read, write: if true` | matching object에 `allow read, write: if true` |
| fixed boundary | authenticated owner identity를 `resource.data.ownerId`와 request data owner field에 결속 | authenticated owner identity를 object metadata owner field와 write metadata에 결속 |
| negative control | Firebase rule, collection/object match, repository query가 없는 static status source | Firebase rule, collection/object match, repository query가 없는 static status source |
| severity | CWE-284 / Critical | same slot reserve |

고정 invariants:

- vulnerable, fixed, negative는 각각 별도 source role이며 fixed는 vulnerable rule source를 재사용하지 않는다.
- primary/reserve의 rule kind, match path, unconditional allow, authenticated owner predicate, slot/blueprint binding이 바뀌면 `HOLD`다.
- source tree에는 실제 Firebase project ID, API key, service credential, 실제 사용자 데이터, network call을 넣지 않는다.
- 이 카드는 source-tree identity만 다룬다. Firebase deployment, Firestore/Storage rule enforcement, cross-tenant
  access, exploitability, detector finding, precision/recall, H100, Guardian, release는 주장하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | 위 binding, primary/reserve, source-role, 비주장 사전등록 | `DONE` |
| B | api-04 scoped renderer와 strict receipt validator | `DONE` - `materialize_l3_auth_rls_db_api04.py` |
| C | role/path/raw/overwrite/tamper focused test | `DONE` - focused chain `6 passed` |
| D | external r1/r2 source comparator | `DONE` - comparator `FIX`, semantic fingerprint `def5b7d4...fc816` |
| E | baseline, focused/full regression, target equality | `DONE` - focused `18 passed`; full `2714 passed, 5 skipped, 0 failed` |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two-run review | `DONE` - successful r1-retry/r2 전 lane `GO`; comparator `FIX` |
| G | supervisor comparator `FIX`, evidence hash, 비주장 기록 | `DONE` - 아래 evidence와 narrow claim 기록 |

## 시작 경계

이 leaf는 `P2.4B.3.03 api-03`이 G까지 `FIX_NARROW`로 닫힌 뒤 열었다. 새 renderer는 다른
`auth-rls-db` slot, 실제 Firebase project, scanner score, Guardian block rule을 수정하거나 승인하지 않는다.
B 이전에는 source를 만들거나 scanner 결과를 보지 않는다.

## D external evidence

- r1 receipt SHA-256: `82f6c70ebfa8dfd2b45a50bb94151d16a96c8974fd663eaca19e154d2c3585ef`
- r2 receipt SHA-256: `f9ab0394070f90a4832c9dc639c3f56389a58cac9195da6daf4b115ddd392dd0`
- raw-free comparator SHA-256: `2ecb50e915e641a6ae4525ad3185133261716a19565b4f1bd06ef3f5d71e1403`
- comparator는 slot `api-04`, source-triplet identity, staged blueprint binding, materializer hash만 확인했고
  `repeat_exact=true`, `status=FIX`를 기록했다. Firebase runtime, rule enforcement, exploit, detector,
  TP/FP/FN, H100, Guardian, release 판단에는 권한이 없다.

## E-G evidence와 비주장

- current baseline receipt SHA-256: `8c805f1bcff43a59152eddbcce2dde8a62f8f1f89d6257de461d9b32f9adae0a`
- focused/full attestation receipt SHA-256:
  `6c0d7204f61a7b8f0e051208fa0975bb61b96c7f971dd2bbea9bec07236047f7` /
  `e88b84fcf89d31e466d047299f09e76b64abd2d2e104ad9e856be85c4c5b864f`
  - focused 18 passed, full 2,714 passed, 5 skipped, 0 failed; control error와 target drift 없음.
- supervisor health receipt SHA-256: `252ec0f6a2ac743e870ae49ef49bccc61d4843e1dadf5525c9d81b40165bc148`.
  이것은 세 provider의 availability만 확인하며 승인 evidence는 아니다.
- initial F1은 Claude와 Grok `GO`, GLM `HOLD` (`TEST_ATTESTATION_GAP`)였고 승격 근거로 쓰지 않았다.
  raw-free decision SHA-256 `3beecc0908d4e10f8d571e3a5fea4bf2e0b0411f4ea5e069d218abe79d01072d`는
  `...supervisor-review-v1-r1`에 보존한다.
- same-target clarified r1-retry와 r2는 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 전 lane `GO`였다.
  단회 terminal `HOLD`는 second independent run이 아직 없다는 `test_attestation_incomplete`만 기록한
  비승격 상태이며, 두 정상 run의 supervisor comparator SHA-256
  `c3e7c7a1ea4159e948df9a90c0b4784d82c9caa74aaaa5114059e6481949f2f7`, semantic fingerprint
  `e82c2312e7412bb87446dcb069d12d23aac472c5c530b0cbe5d1220349065e18`, `repeat_exact=true`, `status=FIX`다.

이 결과는 `api-04` primary/reserve vulnerable/fixed/negative Firebase source-tree identity만
`FIX_NARROW`로 닫는다. Firebase deployment, Firestore/Storage rule enforcement, real cross-tenant access,
exploit, detector accuracy, TP/FP/FN, H100, Guardian 또는 release를 증명하지 않는다.
