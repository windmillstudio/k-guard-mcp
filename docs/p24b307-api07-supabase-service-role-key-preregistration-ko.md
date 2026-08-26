# P2.4B.3.07 api-07 Supabase service-role key source-tree 사전등록

작성일: 2026-07-25  
상태: `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX`  
상위 카드: [auth-rls-db 19-slot WBS](p24b3-auth-rls-db-materialization-wbs-ko.md)

## 한 문장 목표

`api-07`의 primary와 같은 slot의 pre-registered reserve에 대해 TypeScript/Supabase service-role key
vulnerable/fixed/negative source tree만 deterministic하게 materialize할 계약을 결과 전에 고정한다.

## A: 결과 전 고정한 binding

| 항목 | primary | reserve |
| --- | --- | --- |
| slot / scenario / oracle | `api-07` / `dev-api-07-service-role-key` / `l3-gen-api-07-service-role-key` | 같은 slot의 pre-registered reserve |
| source role | browser-reachable `src/client/supabase.ts`와 server-only `src/server/supabase-admin.ts` | browser-reachable `src/browser/supabase.ts`와 server-only `src/server/supabase-admin.ts` |
| framework | TypeScript / Supabase | TypeScript / Supabase |
| vulnerable boundary | public browser module이 `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`를 `createClient` key argument로 사용 | public browser module이 `VITE_SUPABASE_SERVICE_ROLE_KEY`를 `createClient` key argument로 사용 |
| fixed boundary | `import "server-only"`가 있는 server module만 non-public `SUPABASE_SERVICE_ROLE_KEY`를 admin client key argument로 사용하고 public env marker는 없음 | 같은 server-only boundary와 non-public key name을 사용하고 public env marker는 없음 |
| negative control | Supabase import, `createClient`, public env marker, service-role key name이 없는 static status source | 같은 negative contract |
| severity | CWE-798 / Critical | same slot reserve |

고정 invariants:

- vulnerable, fixed, negative는 각각 별도 source role이며 fixed는 vulnerable browser source를 재사용하지 않는다.
- primary/reserve의 browser path, public env marker, `createClient` key argument, fixed `server-only` marker,
  non-public key name, negative exclusion, slot/blueprint binding이 바뀌면 `HOLD`다.
- source tree에는 실제 Supabase URL, 실제 service-role key, access token, 실제 사용자 데이터, network call을 넣지 않는다.
- 이 카드는 source-tree identity만 다룬다. bundler public-env semantics, `server-only` runtime enforcement,
  Supabase project access, RLS bypass, exploitability, detector finding, precision/recall, H100, Guardian,
  release는 주장하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | 위 binding, primary/reserve, source-role, 비주장 사전등록 | `DONE` |
| B | api-07 scoped renderer와 strict receipt validator | `DONE` - `materialize_l3_auth_rls_db_api07.py` |
| C | role/path/raw/overwrite/tamper focused test | `DONE` - api-07 focused chain `6 passed` |
| D | external r1/r2 source comparator | `DONE` - comparator `FIX`, semantic fingerprint `e37bfe69...9bd31` |
| E | baseline, focused/full regression, target equality | `DONE` - focused `18 passed`; full `2,732 passed, 5 skipped, 0 failed` |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two-run review | `DONE` - r1/r2 전 lane `GO`; comparator `FIX` |
| G | supervisor comparator `FIX`, evidence hash, 비주장 기록 | `DONE` - 아래 evidence와 narrow claim 기록 |

## 시작 경계

이 leaf는 `P2.4B.3.06 api-06`가 G까지 `FIX_NARROW`로 닫힌 뒤 열었다. B 이전에는 source를 만들거나
scanner 결과를 보지 않는다. 새 renderer는 다른 `auth-rls-db` slot, 실제 Supabase project, bundler,
scanner score, Guardian block rule을 수정하거나 승인하지 않는다.

## A blueprint evidence와 비주장

- raw-free blueprint는 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b307-api07-supabase-service-role-20260725\\api07-pre-registration-blueprint.json`에만 생성했다.
- blueprint file SHA-256: `3dddfa838cba2cc54e1fca7195f314e513ddec8ab9ae2cfd45843b492a7023bd`.
  `api-07`은 `typescript`, `supabase`, `CWE-798`, `critical`, `deterministic-fixture-v1`과 public scanner output
  absent-at-seal binding을 가진다.
- 이 evidence는 source tree, 실행 oracle, scanner detection, TP/FP/FN, H100, Guardian 또는 release를 증명하지 않는다.

## D external evidence

- r1/r2 source materialization은 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b307-api07-supabase-service-role-20260725`에만 생성했다.
- raw-free comparator SHA-256: `d2a1a4d0824844cef629fb5d94e07005eca420ebfe9c4a2cc4806a1d5f9c573c`.
  comparator는 slot `api-07`, source-triplet identity, staged blueprint binding, materializer hash만 확인했고
  semantic fingerprint `e37bfe6973a581541e79213bf599704063aaf9f1f5f4df6661780e428149bd31`,
  `repeat_exact=true`, `status=FIX`를 기록했다. Supabase runtime, bundler public-env semantics, project access,
  exploit, detector, TP/FP/FN, H100, Guardian, release 판단에는 권한이 없다.

## E-G evidence와 비주장

- current baseline receipt SHA-256: `988ac134c2b171a662956d3a93141c51200debb656e99418b057e19c3342d8ea`.
  full regression 뒤 `--validate-current`도 `current=true`로 통과했다.
- focused/full attestation receipt SHA-256:
  `67af125d3b3549bd6cbb608dedc265c0d953072074d8f72b89820a50aeb3dec5` /
  `e66a71f71916e395eef202f63079999152165ee0d21d88410acc46c02ded789b`.
  - focused 18 passed, full 2,732 passed, 5 skipped, 0 failed; control error와 target drift 없음.
- supervisor health raw-free receipt file SHA-256: `c524bf2ec6bcb2005416f00982922990c6d63a55146c62123a08e45593890f36`.
  이것은 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2의 availability만 확인하며 승인 evidence는 아니다.
- same-target F1/r2에서 세 모델은 전 lane `GO`였다. 각 단회 terminal `HOLD`는 second independent run이
  아직 없다는 `test_attestation_incomplete`만 기록한 비승격 상태다. supervisor comparator SHA-256
  `baecb9c4bb080dfd5b46d9713bde30c493ba2607e56391509fbc8619d2794458`, semantic fingerprint
  `2778bd7e4f8147661caa5bb0c16423f06ec2148f71910ef47b2f3339d19389ba`, `repeat_exact=true`, `status=FIX`다.

이 결과는 `api-07` primary/reserve vulnerable/fixed/negative Supabase service-role key source-tree identity만
`FIX_NARROW`로 닫는다. bundler public-env semantics, `server-only` runtime enforcement, Supabase project access,
RLS bypass, exploit, detector accuracy, TP/FP/FN, H100, Guardian 또는 release를 증명하지 않는다.
