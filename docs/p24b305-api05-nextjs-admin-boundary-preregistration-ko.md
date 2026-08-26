# P2.4B.3.05 api-05 Next.js admin-boundary source-tree 사전등록

작성일: 2026-07-25  
상태: `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX`  
상위 카드: [auth-rls-db 19-slot WBS](p24b3-auth-rls-db-materialization-wbs-ko.md)

## 한 문장 목표

`api-05`의 primary와 같은 slot의 pre-registered reserve에 대해 TypeScript/Next.js 관리자 권한 경계의
vulnerable/fixed/negative source tree만 deterministic하게 materialize할 계약을 결과 전에 고정한다.

## A: 결과 전 고정한 binding

| 항목 | primary | reserve |
| --- | --- | --- |
| slot / scenario / oracle | `api-05` / `dev-api-05-admin-boundary` / `l3-gen-api-05-admin-boundary` | 같은 slot의 pre-registered reserve |
| source role | App Router admin audit route와 server-side repository declaration | App Router organization billing route와 server-side repository declaration |
| framework | TypeScript / Next.js | TypeScript / Next.js |
| vulnerable boundary | authenticated session 존재만 확인하고 admin-only audit resource를 반환 | authenticated session 존재만 확인하고 admin-only billing resource를 반환 |
| fixed boundary | session identity의 `role === "admin"`을 server-side route에서 확인한 뒤 audit resource를 반환 | 같은 server-side role predicate를 확인한 뒤 billing resource를 반환 |
| negative control | Next.js route, admin role predicate, admin resource가 없는 static status source | Next.js route, admin role predicate, admin resource가 없는 static status source |
| severity | CWE-285 / Critical | same slot reserve |

고정 invariants:

- vulnerable, fixed, negative는 각각 별도 source role이며 fixed는 vulnerable route source를 재사용하지 않는다.
- primary/reserve의 framework, route role, admin resource, authenticated-session-only boundary, explicit server-side
  `role === "admin"` predicate, slot/blueprint binding이 바뀌면 `HOLD`다.
- source tree에는 실제 identity provider URL, session secret, access token, 실제 사용자 데이터, network call을 넣지 않는다.
- 이 카드는 source-tree identity만 다룬다. Next.js deployment, middleware semantics, session verification correctness,
  real administrator authorization, cross-tenant access, exploitability, detector finding, precision/recall, H100,
  Guardian, release는 주장하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | 위 binding, primary/reserve, source-role, 비주장 사전등록 | `DONE` |
| B | api-05 scoped renderer와 strict receipt validator | `DONE` - `materialize_l3_auth_rls_db_api05.py` |
| C | role/path/raw/overwrite/tamper focused test | `DONE` - focused chain `6 passed` |
| D | external r1/r2 source comparator | `DONE` - comparator `FIX`, semantic fingerprint `ca0af4d9...c055b` |
| E | baseline, focused/full regression, target equality | `DONE` - focused `18 passed`; full `2720 passed, 5 skipped, 0 failed` |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two-run review | `DONE` - r1/r2 전 lane `GO`; comparator `FIX` |
| G | supervisor comparator `FIX`, evidence hash, 비주장 기록 | `DONE` - 아래 evidence와 narrow claim 기록 |

## 시작 경계

이 leaf는 `P2.4B.3.04 api-04`가 G까지 `FIX_NARROW`로 닫힌 뒤 열었다. B 이전에는 source를 만들거나
scanner 결과를 보지 않는다. 새 renderer는 다른 `auth-rls-db` slot, 실제 Next.js application, scanner score,
Guardian block rule을 수정하거나 승인하지 않는다.

## D external evidence

- r1/r2 source materialization은 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b305-api05-nextjs-admin-20260725`에만 생성했다.
- r1/r2 receipt SHA-256: `8789a800f4fae65ec5a0fa775fd90f8c0f16dcf7351b1bdb5a8f2d270d3c1d32` /
  `2a9eeca2d2279c33414c0c1aed90d44b213d29ec323d5781f09abfa4a187ba89`.
- raw-free comparator SHA-256: `5115d038231089859f372288ade086bae1e66d82987d3fbd0da9ad6d179f4c1c`.
- raw-free comparator는 slot `api-05`, source-triplet identity, staged blueprint binding, materializer hash만 확인했고
  semantic fingerprint `ca0af4d90cce1b48c017bdc4eb95dfb2e178c978824f090c7df6d3b554bc055b`,
  `repeat_exact=true`, `status=FIX`를 기록했다.

## E-G evidence와 비주장

- current baseline receipt SHA-256: `9ab00db48c1df23ad113ce5a6d4c287fe3a1f4c19eac2746900aacd75e330fdf`.
  full regression 뒤 `--validate-current`도 `current=true`로 통과했다.
- focused/full attestation receipt SHA-256:
  `aa56887de17f4de663fc759213752e0620cb771947bcc1c6feaa295c07352eaa` /
  `1cc60adc2c81100931aabb95ef86423de6a6250499b62a65e1f74d36a297943b`.
  - focused 18 passed, full 2,720 passed, 5 skipped, 0 failed; control error와 target drift 없음.
- supervisor health raw-free receipt file SHA-256: `8d4f5a48480e9b0ae755fe11d05b67658f534988f2b0e93908fc065f3be36a22`.
  이것은 세 provider availability만 확인하며 승인 evidence는 아니다.
- same-target F1/r2에서 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2는 전 lane `GO`였다.
  단회 terminal `HOLD`는 second independent run이 아직 없다는 `test_attestation_incomplete`만 기록한
  비승격 상태다. supervisor comparator SHA-256
  `114d204f3701adc8d91d8158c414644ab94cd21e0bbd92598bbb7a4d2f8bc7e7`, semantic fingerprint
  `f6b14bde2cf4a13f7ed175acac953658660d07019e84d8201bc74f844b763305`, `repeat_exact=true`, `status=FIX`다.

이 결과는 `api-05` primary/reserve vulnerable/fixed/negative Next.js administrator-boundary source-tree
identity만 `FIX_NARROW`로 닫는다. Next.js deployment, middleware/session semantics, real administrator
authorization, cross-tenant access, exploit, detector accuracy, TP/FP/FN, H100, Guardian 또는 release를 증명하지 않는다.
