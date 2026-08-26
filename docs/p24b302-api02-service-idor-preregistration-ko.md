# P2.4B.3.02 api-02 Next.js service-IDOR source-tree 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX`  
상위 카드: [auth-rls-db 19-slot WBS](p24b3-auth-rls-db-materialization-wbs-ko.md)

## 한 문장 목표

`api-02`의 primary와 same-slot reserve에 대해 TypeScript/Next.js service-level ownership boundary의
vulnerable/fixed/negative source tree만 deterministic하게 materialize하고, raw-free tree identity를 두 번
같은 결과로 결속한다.

## A: 결과 전 고정한 binding

| 항목 | primary | reserve |
| --- | --- | --- |
| slot / scenario / oracle | `api-02` / `dev-api-02-service-idor` / `l3-gen-api-02-service-idor` | 같은 slot의 pre-registered reserve |
| source role | `GET /api/users/:userId` route handler와 user service | `GET /api/accounts/:accountId` route handler와 account service |
| framework | TypeScript / Next.js | TypeScript / Next.js |
| request identity | `session.user.id` | `session.user.id` |
| vulnerable boundary | service가 entity ID만으로 lookup, requester predicate 없음 | service가 entity ID만으로 lookup, requester predicate 없음 |
| fixed boundary | service가 entity ID와 requester ID를 함께 predicate에 결속 | service가 entity ID와 requester ID를 함께 predicate에 결속 |
| negative control | `GET /api/health` static response, session/entity lookup 없음 | `GET /api/health` static response, session/entity lookup 없음 |
| severity | CWE-639 / High | same slot reserve |

고정 invariants:

- vulnerable, fixed, negative는 각각 별도 source role이며 fixed는 vulnerable source를 재사용하지 않는다.
- primary/reserve의 route, parameter, service entity, requester predicate가 바뀌거나 slot/blueprint binding이 달라지면 `HOLD`다.
- source tree에는 실제 credential, 실제 사용자 데이터, 실제 endpoint URL, network call을 넣지 않는다.
- 이 카드는 runtime request, Next.js deployment, DB execution, 실제 ownership enforcement, IDOR exploitability,
  detector finding, precision/recall, H100, release를 주장하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | 위 binding, primary/reserve, source-role, 비주장 사전등록 | `DONE` |
| B | api-02 scoped renderer와 strict receipt validator | `DONE` - `materialize_l3_auth_rls_db_api02.py` |
| C | role/path/raw/overwrite/tamper focused test | `DONE` - focused chain `34 passed` |
| D | external r1/r2 source comparator | `DONE` - comparator `FIX`, semantic fingerprint `557f9a97...32498` |
| E | baseline, focused/full regression, target equality | `DONE` - focused 36 passed; full r1/r2/r3 each 2,701 passed, 5 skipped |
| F1/F2 | Claude, Grok, GLM two-run review | `DONE` - all lanes `GO`; supervisor comparator `FIX` |
| G | supervisor comparator `FIX`, evidence hash, 비주장 기록 | `DONE` - narrow claim only |

## 시작 경계

이 leaf는 `P2.4B.3.01 api-01`이 G까지 `FIX_NARROW`로 닫힌 뒤에만 열었다. 새 renderer는 다른
`auth-rls-db` slot, source-flow slot, 실제 API 실행, scanner score, Guardian block rule을 수정하거나 승인하지 않는다.

## D external evidence

- r1 receipt SHA-256: `6522cfa9ed55850a819f702c153821f4ef2b41b1a56a6ebf91975d040fb6b2f1`
- r2 receipt SHA-256: `f641af5e2abbb93b465aae717686eb9b8cdef536c88c796a3d61028c7af09a2d`
- raw-free comparator SHA-256: `c1334aab30b5ed6dd334f4035234517a801249bf7d38db4636cc777599fc3082`
- comparator는 같은 materializer, raw-free receipt projection, slot `api-02`만 확인했다. runtime authorization,
  exploit, detector, TP/FP/FN, H100, release 판단에는 권한이 없다.

## E-G evidence

- current baseline receipt SHA-256: `d439fd0981791a3e0e3b912ff24f77f1decf496b035a9d70003a57cb7bc4eba4`
- focused regression receipt SHA-256: `e2be607960b01004b2ba9d4ab08944ece3c80d6810dfa8ef3b469593d428a4dc`
  - 36 passed, 0 failed, 0 errors, 0 skipped; target before/after identical.
- full regression r1/r2/r3 receipt SHA-256:
  `f672f03cad01bf042236bebc74c441470921fa065526611b839befb6477ab5a9`,
  `b27d1aacff19a64eba129761704ac666194e127c12245421447ccccf91d8e9e3`,
  `81188180df2b645ed5cfa184311ea144c77567c81e52472e88cd14f48957c7a3`
  - each 2,701 passed, 0 failed, 0 errors, 5 skipped; same current target.
- supervisor health SHA-256: `4f3f3f645fb41198ca31e96f1d4a7f95f75f34bc34a849609abd04520c6935a0`
  - Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 healthy.
- F1/F2: all three lanes returned `GO` in both runs. Each single run retained only the expected nonblocking
  `REPEATABILITY_GAP`; the two-run supervisor comparator is `FIX`, semantic fingerprint
  `2be236bbe699dc5606a4eb9e82e003af13e60600e98c1df0191ccfd169ce753b`, file SHA-256
  `6b1799d7e81e0155b5d4b6a9e2e7f09390b86fdb742cac0e32723d510c6091a1`.

이 증거는 `api-02`의 deterministic source-tree identity만 `FIX_NARROW`로 닫는다. Next.js runtime,
session 처리, 실제 DB ownership enforcement, IDOR exploit, detector accuracy, TP/FP/FN, H100, Guardian 또는
release를 증명하지 않는다.
