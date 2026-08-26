# P2.4B.3.03 api-03 Supabase missing-RLS source-tree 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX`  
상위 카드: [auth-rls-db 19-slot WBS](p24b3-auth-rls-db-materialization-wbs-ko.md)

## 한 문장 목표

`api-03`의 primary와 같은 slot의 pre-registered reserve에 대해 TypeScript/Supabase의
missing-RLS vulnerable/fixed/negative source tree만 deterministic하게 materialize할 계약을 결과 전에
고정한다.

## A: 결과 전 고정한 binding

| 항목 | primary | reserve |
| --- | --- | --- |
| slot / scenario / oracle | `api-03` / `dev-api-03-rls-missing` / `l3-gen-api-03-rls-missing` | 같은 slot의 pre-registered reserve |
| source role | `team_notes` migration과 server-side repository query | `customer_documents` migration과 server-side repository query |
| framework | TypeScript / Supabase | TypeScript / Supabase |
| vulnerable boundary | user-owned row table을 만들지만 RLS enable statement와 owner policy가 없음 | user-owned row table을 만들지만 RLS enable statement와 owner policy가 없음 |
| fixed boundary | 같은 table에 RLS enable과 `auth.uid()` owner `using` 및 `with check` policy를 함께 결속 | 같은 table에 RLS enable과 `auth.uid()` owner `using` 및 `with check` policy를 함께 결속 |
| negative control | Supabase table, migration, repository query가 없는 static status source | Supabase table, migration, repository query가 없는 static status source |
| severity | CWE-284 / Critical | same slot reserve |

고정 invariants:

- vulnerable, fixed, negative는 각각 별도 source role이며 fixed는 vulnerable migration 또는 policy source를 재사용하지 않는다.
- primary/reserve의 table, owner column, RLS enable, `using`, `with check`, slot/blueprint binding이 바뀌면 `HOLD`다.
- source tree에는 실제 Supabase URL, service-role key, access token, 실제 사용자 데이터, network call을 넣지 않는다.
- 이 카드는 source-tree identity만 다룬다. Supabase runtime, PostgreSQL RLS enforcement, policy semantics,
  cross-tenant read, exploitability, detector finding, precision/recall, H100, Guardian, release는 주장하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | 위 binding, primary/reserve, source-role, 비주장 사전등록 | `DONE` |
| B | api-03 scoped renderer와 strict receipt validator | `DONE` - `materialize_l3_auth_rls_db_api03.py` |
| C | role/path/raw/overwrite/tamper focused test | `DONE` - focused chain `6 passed` |
| D | external r1/r2 source comparator | `DONE` - comparator `FIX`, semantic fingerprint `e9123262...4c328` |
| E | baseline, focused/full regression, target equality | `DONE` - focused `18 passed`; full `2708 passed, 5 skipped, 0 failed` |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two-run review | `DONE` - successful r1-retry/r2 전 lane `GO`; comparator `FIX` |
| G | supervisor comparator `FIX`, evidence hash, 비주장 기록 | `DONE` - 아래 evidence와 narrow claim 기록 |

## 시작 경계

이 leaf는 `P2.4B.3.02 api-02`가 G까지 `FIX_NARROW`로 닫힌 뒤 열었다. 새 renderer는 다른
`auth-rls-db` slot, source-flow slot, 실제 Supabase project, scanner score, Guardian block rule을 수정하거나
승인하지 않는다. B 이전에는 source를 만들거나 scanner 결과를 보지 않는다.

## D external evidence

- r1 receipt SHA-256: `9270d0c375e410bd32cf7c7557d148dddd07d734a759ad1200a0d70812e54557`
- r2 receipt SHA-256: `2bc22fb1769dbc5690a249bd1677f53a521a70d0a560db9e9050247cc5c40c6f`
- raw-free comparator SHA-256: `a6aa37ae83fa172c7ce114569f9d4cd7d11e6c8aa1e7f8b519915c065d2e68eb`
- comparator는 slot `api-03`, source-triplet identity, staged blueprint binding, materializer hash만 확인했고
  `repeat_exact=true`, `status=FIX`를 기록했다. Supabase runtime, RLS enforcement, exploit, detector,
  TP/FP/FN, H100, Guardian, release 판단에는 권한이 없다.

## E-G evidence와 비주장

- current baseline receipt SHA-256: `d02cbeda773c0b79369db834bca22f0b2a536fc54b28aafdc3160d4d07fe3a57`
- focused/full attestation receipt SHA-256:
  `25e7d75b501840d4735f01d30a2dea68d04ad24b589ca3ed497ff9a9414e1540` /
  `4ba46b26b1f0ce9ac873a57d60f3a03acf04ad00e64ed441a1c39d2590a3960c`
  - focused 18 passed, full 2,708 passed, 5 skipped, 0 failed; control error와 target drift 없음.
- supervisor health receipt SHA-256: `e816b4fb31bf0e5c47a7dd1f6b5cd26211e01ab34e6396c77cbfc2fd54d71793`
- first F1 run은 Claude와 GLM `BLOCKED_TIMEOUT`, Grok `GO`였고 승격 근거로 쓰지 않았다. 그 raw-free
  timeout receipt는 `...supervisor-review-v1-r1`에 보존한다.
- timeout만 600초로 확대한 same-target `r1-retry`와 `r2`는 Claude Opus 4.8, Grok 4.5,
  Cline GLM 5.2 전 lane `GO`였다. supervisor comparator SHA-256
  `8212af42ec7cb69e8008cc3fc57edfecadcb58529f9cc3c67f165d614ae391c1`, semantic fingerprint
  `441d934cfaa550b29afea30e4e1d2dba9c35a815d913ac12e0669b7d4d4ef164`, `repeat_exact=true`, `status=FIX`.

이 결과는 `api-03` primary/reserve vulnerable/fixed/negative source-tree identity만 `FIX_NARROW`로 닫는다.
Supabase runtime, PostgreSQL RLS enforcement, real cross-tenant access, exploit, detector accuracy, TP/FP/FN,
H100, Guardian 또는 release를 증명하지 않는다.
