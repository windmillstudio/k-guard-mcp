# P2.4B.3.11 api-11 Flask role-guard source-tree 사전등록

작성일: 2026-07-25  
상태: `FIX_NARROW` - A-G와 3AI F1/r3 comparator `FIX`; r2 packet-diff `HOLD` 보존  
상위 카드: [auth-rls-db 19-slot WBS](p24b3-auth-rls-db-materialization-wbs-ko.md)

## 한 문장 목표

`api-11`의 primary와 같은 slot의 pre-registered reserve에 대해 Python/Flask role-guard
vulnerable/fixed/negative source tree만 deterministic하게 materialize할 계약을 결과 전에 고정한다.

## A: 결과 전 고정한 binding

| 항목 | primary | reserve |
| --- | --- | --- |
| slot / scenario / oracle | `api-11` / `dev-api-11-role-guard` / `l3-gen-api-11-role-guard` | 같은 slot의 pre-registered reserve |
| source role | `DELETE /admin/users/{user_id}` destructive admin route | `POST /billing/refunds/{refund_id}` finance route |
| framework | Python / Flask | Python / Flask |
| vulnerable boundary | route에 `@require_admin` guard가 없음 | route에 `@require_finance_manager` guard가 없음 |
| fixed boundary | route에 `@require_admin` decorator와 declaration source를 명시 | route에 `@require_finance_manager` decorator와 declaration source를 명시 |
| negative control | Flask route/decorator, role guard, guard declaration이 없는 static status source | 같은 negative contract |
| severity | CWE-285 / High | same slot reserve |

고정 invariants:

- vulnerable, fixed, negative는 각각 별도 source role이며 fixed는 vulnerable route source를 재사용하지 않는다.
- primary/reserve의 route, vulnerable guard 부재, fixed decorator/declaration, negative exclusion, slot/blueprint binding이
  바뀌면 `HOLD`다.
- fixed guard declaration은 runtime authorization을 구현하거나 성공을 흉내 내지 않는다. `runtime guard not materialized`
  marker를 가진 declaration source만 포함한다.
- source tree에는 실제 계정, secret, token, database connection string, network call을 넣지 않는다.
- 이 카드는 source-tree identity만 다룬다. Flask runtime authentication/authorization, role semantics, endpoint execution,
  exploitability, detector finding, precision/recall, H100, Guardian, release는 주장하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | 위 binding, primary/reserve, source-role, 비주장 사전등록 | `DONE` |
| B | api-11 scoped renderer와 strict receipt validator | `DONE` - `materialize_l3_auth_rls_db_api11.py` |
| C | role/path/raw/overwrite/tamper focused test | `DONE` - api-11 focused chain `6 passed` |
| D | external r1/r2 source comparator | `DONE` - comparator `FIX`, semantic fingerprint `7d9ba34e...c8ddb7` |
| E | baseline, focused/full regression, target equality | `DONE` - focused `18 passed`; full `2,756 passed, 5 skipped, 0 failed` |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two-run review | `DONE` - r1/r3 전 lane `GO`; r2 packet-diff `HOLD` 보존 |
| G | supervisor comparator `FIX`, evidence hash, 비주장 기록 | `DONE` - r1/r3 comparator `FIX` |

## 시작 경계

이 leaf는 `P2.4B.3.10 api-10`이 G까지 `FIX_NARROW`로 닫힌 뒤 열었다. B 이전에는 source를 만들거나
scanner 결과를 보지 않는다. 새 renderer는 다른 `auth-rls-db` slot, 실제 Flask application, runtime role guard,
scanner score, Guardian block rule을 수정하거나 승인하지 않는다.

## A blueprint evidence와 비주장

- raw-free blueprint는 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b311-api11-flask-role-guard-20260725\\api11-pre-registration-blueprint.json`에만 생성했다.
- blueprint file SHA-256: `3dddfa838cba2cc54e1fca7195f314e513ddec8ab9ae2cfd45843b492a7023bd`.
  `api-11`은 `python`, `flask`, `CWE-285`, `high`, `deterministic-template-v1`과 public scanner output
  absent-at-seal binding을 가진다.
- 이 evidence는 source tree, execution oracle, scanner detection, TP/FP/FN, H100, Guardian 또는 release를 증명하지 않는다.

## B/C renderer와 focused evidence

- renderer는 primary `app/admin.py`와 reserve `app/billing.py`를 별도 source role로 만들고, vulnerable에는
  role decorator를 넣지 않으며 fixed에는 각각 `@require_admin` 또는 `@require_finance_manager`와
  `app/guards.py` declaration source를 넣는다.
- guard declaration은 `runtime guard not materialized` marker를 내고 실행 가능한 authorization 성공을 만들지 않는다.
  negative control은 `app/status.py`만 포함하며 Flask import, route/decorator, role guard declaration을 포함하지 않는다.
- focused chain은 role/path/raw/overwrite/tamper 및 repeat-comparator tamper refusal을 포함해 `6 passed`였다.
  이 결과는 source-tree identity의 B/C만 검증하며 Flask runtime authorization, role semantics, endpoint execution,
  detector accuracy, TP/FP/FN, H100, Guardian, release는 여전히 비주장이다.

## D external repeat evidence

- r1/r2 source materialization은 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b311-api11-flask-role-guard-20260725`에만 생성했다.
- r1/r2 raw-free receipt SHA-256은 각각
  `a362e7e8b602b0ba68afcc4fa5abb6f6b19e840a768d6046530fbbd4d0b352e9` /
  `f33dd7712b263178634537e97ae48599258905b7a9a1bba85db108c8acc52a2c`다.
- raw-free comparator SHA-256은 `aa31993e5e51a76568b15e019ad5a7d4ff9a5c716578e8e010461fe47d4e0213`다.
  staged blueprint binding, source-triplet identity, materializer hash만 비교했고 semantic fingerprint
  `7d9ba34e17cf362a6bf7b65aa720914e9b1b143f4666cc54fc2b479089c8ddb7`, `repeat_exact=true`, `status=FIX`를 기록했다.
- 이 D 결과도 source-tree identity만 확인한다. Flask runtime authorization, role semantics, endpoint execution,
  detector, TP/FP/FN, H100, Guardian, release에 관한 권한은 없다.

## E-G evidence와 비주장

- current baseline receipt SHA-256은 `3f79e52f0d5f00ad6cebdae3257690dc3f215bb83d7acbaf6574d4849a1c7f8f`이며,
  full regression 뒤 `--validate-current`도 `current=true`로 통과했다.
- focused/full attestation receipt SHA-256은
  `f715c0fce1dc1ffa0328ab1648fa5d313cb2ea84b3d97b14db02af47c1624b32` /
  `a3c20a4c4d31041a3e4279be5471f51fc88c07b62781a711d41c48623023f4bc`다.
  - focused `18 passed`; full `2,756 passed`, `5 skipped`, `0 failed`, `0 errors`; control error, timeout, target drift 없음.
- supervisor health raw-free receipt file SHA-256은
  `d1aa4ec88722b80caebae1a216b2907952345fb407d81e7e9961db4258bba8e9`이며 Claude Opus 4.8,
  Grok 4.5, Cline GLM 5.2 모두 `HEALTHY`다. health receipt는 code, field-fix, release를 승인하지 않는다.
- r1/r2 supervisor comparator는 review question packet hash가 달라 `repeat_exact=false`, `HOLD`가 됐다.
  이 artifact SHA-256 `d7e871b0548de4716cc867fed9134bf8574674f815adde7be45d662f85584744`는 삭제하지 않는다.
  같은 packet으로 재호출한 r1/r3에서 세 provider 모두 `GO`였고 comparator SHA-256
  `d158ef501be1def3cac0e498c86636924db527dc01f117cbd834ce1b562e5aa9`, semantic fingerprint
  `670992953bf99be53743ad09273efe32b66236e80a735bea1e59812b9c044aa1`, `repeat_exact=true`, `status=FIX`를 기록했다.

이 결과는 `api-11` primary/reserve vulnerable/fixed/negative Flask role-guard source-tree identity만
`FIX_NARROW`로 닫는다. Flask runtime authentication/authorization, role semantics, endpoint execution,
exploit, detector accuracy, TP/FP/FN, H100, Guardian 또는 release를 증명하지 않는다.
