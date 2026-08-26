# P2.4B.3.09 api-09 FastAPI dependency-auth source-tree 사전등록

작성일: 2026-07-25  
상태: `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX`  
상위 카드: [auth-rls-db 19-slot WBS](p24b3-auth-rls-db-materialization-wbs-ko.md)

## 한 문장 목표

`api-09`의 primary와 같은 slot의 pre-registered reserve에 대해 Python/FastAPI dependency-auth
vulnerable/fixed/negative source tree만 deterministic하게 materialize할 계약을 결과 전에 고정한다.

## A: 결과 전 고정한 binding

| 항목 | primary | reserve |
| --- | --- | --- |
| slot / scenario / oracle | `api-09` / `dev-api-09-dependency-auth` / `l3-gen-api-09-dependency-auth` | 같은 slot의 pre-registered reserve |
| source role | `GET /notes/{note_id}` route와 `app/security.py` dependency declaration | `POST /reports/{report_id}` route와 `app/security.py` dependency declaration |
| framework | Python / FastAPI | Python / FastAPI |
| vulnerable boundary | protected-looking note route parameter에 `Depends(require_current_user)`가 없음 | protected-looking report route parameter에 `Depends(require_current_user)`가 없음 |
| fixed boundary | route parameter에 `current_user = Depends(require_current_user)`를 명시하고 dependency declaration을 별도 source role로 둠 | 같은 dependency boundary를 report route에 명시 |
| negative control | FastAPI router, route decorator, `Depends`, dependency declaration이 없는 static status source | 같은 negative contract |
| severity | CWE-862 / High | same slot reserve |

고정 invariants:

- vulnerable, fixed, negative는 각각 별도 source role이며 fixed는 vulnerable route source를 재사용하지 않는다.
- primary/reserve의 route decorator, route parameter, vulnerable dependency 부재, fixed `Depends(require_current_user)`,
  dependency source path, negative exclusion, slot/blueprint binding이 바뀌면 `HOLD`다.
- fixed dependency adapter는 runtime authentication을 구현하거나 성공을 흉내 내지 않는다. `runtime adapter not materialized`
  marker를 가진 선언 source만 포함한다.
- source tree에는 실제 OAuth/JWT secret, access token, 실제 사용자 데이터, network call을 넣지 않는다.
- 이 카드는 source-tree identity만 다룬다. FastAPI runtime dependency execution, authentication semantics,
  authorization enforcement, object ownership, exploitability, detector finding, precision/recall, H100, Guardian,
  release는 주장하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | 위 binding, primary/reserve, source-role, 비주장 사전등록 | `DONE` |
| B | api-09 scoped renderer와 strict receipt validator | `DONE` - `materialize_l3_auth_rls_db_api09.py` |
| C | role/path/raw/overwrite/tamper focused test | `DONE` - api-09 focused chain `6 passed` |
| D | external r1/r2 source comparator | `DONE` - comparator `FIX`, semantic fingerprint `c08553cc...55cc34` |
| E | baseline, focused/full regression, target equality | `DONE` - focused `18 passed`; full `2,744 passed, 5 skipped, 0 failed` |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two-run review | `DONE` - r1/r2 전 lane `GO`; comparator `FIX` |
| G | supervisor comparator `FIX`, evidence hash, 비주장 기록 | `DONE` - 아래 evidence와 narrow claim 기록 |

## 시작 경계

이 leaf는 `P2.4B.3.08 api-08`가 G까지 `FIX_NARROW`로 닫힌 뒤 열었다. B 이전에는 source를 만들거나
scanner 결과를 보지 않는다. 새 renderer는 다른 `auth-rls-db` slot, 실제 FastAPI application, runtime auth adapter,
scanner score, Guardian block rule을 수정하거나 승인하지 않는다.

## A blueprint evidence와 비주장

- raw-free blueprint는 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b309-api09-fastapi-dependency-auth-20260725\\api09-pre-registration-blueprint.json`에만 생성했다.
- blueprint file SHA-256: `3dddfa838cba2cc54e1fca7195f314e513ddec8ab9ae2cfd45843b492a7023bd`.
  `api-09`은 `python`, `fastapi`, `CWE-862`, `high`, `deterministic-transform-v1`과 public scanner output
  absent-at-seal binding을 가진다.
- 이 evidence는 source tree, execution oracle, scanner detection, TP/FP/FN, H100, Guardian 또는 release를 증명하지 않는다.

## B/C renderer와 focused evidence

- renderer는 primary `GET /notes/{note_id}`와 reserve `POST /reports/{report_id}`에 대해 vulnerable route의
  `Depends(require_current_user)` 부재, fixed route의 명시적 dependency parameter, fixed `app/security.py`의
  `runtime adapter not materialized` marker를 각각 별도 source role로 materialize한다.
- negative control은 `app/status.py` static source로 고정했고, FastAPI router/decorator/`Depends`/dependency declaration을
  포함하지 않는다. receipt에는 raw route source, dependency marker, source path를 반환하지 않는다.
- focused chain은 materialization role/path/raw/overwrite/tamper와 repeat-comparator tamper refusal을 함께 실행해
  `6 passed`였다. 이는 deterministic source-tree 계약의 B/C만 증명하며 FastAPI runtime authentication, authorization,
  object ownership, detector accuracy, TP/FP/FN, H100, Guardian, release는 여전히 비주장이다.

## D external repeat evidence

- r1/r2 source materialization은 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b309-api09-fastapi-dependency-auth-20260725`에만 생성했다.
- r1/r2 raw-free receipt SHA-256은 각각
  `0e300fdff216628760a58e0bfa9b6b724645d2c6ece0bbd15fbc15c71ee1b9e5` /
  `9377211a81301299fef28e1aafc0cc3899609495588793201c458af68a3e36a4`다.
- raw-free comparator SHA-256은 `60a4d0c6c5b6e79b0ac33039652b6ad8dea40bc92e8f1c4bb05f585f3c1daaa4`다.
  slot `api-09`, staged blueprint binding, source-triplet identity, materializer hash만 비교했고
  semantic fingerprint `c08553cc6d0d1d2e05d0ca34873237c2b7b13217276b4914843f2babc555cc34`,
  `repeat_exact=true`, `status=FIX`를 기록했다.
- 이 D 결과도 source-tree identity만 확인한다. FastAPI dependency runtime, authentication/authorization semantics,
  object ownership, exploitability, detector, TP/FP/FN, H100, Guardian, release에 관한 권한은 없다.

## E-G evidence와 비주장

- current baseline receipt SHA-256은 `a01e735bad9cd0436b17772517310c1e1c21642fa3e6190c4561f4b3e69e326c`이며,
  full regression 뒤 `--validate-current`도 `current=true`로 통과했다.
- focused/full attestation receipt SHA-256은
  `dcc10c7602b88ca7438b2111587e3bc67290df682cc6e76f89ad2883319e65c3` /
  `d4cb0c8a0a446fd4f449e1816ad3505bbb540af19e9795cf38a1e3e79de25fb8`다.
  - focused 18 passed, full 2,744 passed, 5 skipped, 0 failed; control error와 target drift 없음.
- supervisor health raw-free receipt file SHA-256은
  `3adc9d613e520a2bb617a87d7b6e13b285fd737357e8690bfb2915263753c416`다.
  이것은 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2의 availability만 확인하며 승인 evidence는 아니다.
- same-target F1/r2에서 세 모델은 전 lane `GO`였다. 각 단회 terminal `HOLD`는 second independent run이
  아직 없다는 `test_attestation_incomplete`만 기록한 비승격 상태다. supervisor comparator SHA-256은
  `e0a352609891bfdfe0cb9dff1f7559e380578f37950a84fe1b398591405ad3fa`, semantic fingerprint는
  `31591338dc16fa3d6026d8dfd67e440ff229d819e61682f91c2bacf710032fb8`, `repeat_exact=true`, `status=FIX`다.

이 결과는 `api-09` primary/reserve vulnerable/fixed/negative FastAPI dependency-auth source-tree identity만
`FIX_NARROW`로 닫는다. FastAPI runtime dependency execution, authentication/authorization semantics, object
ownership, exploit, detector accuracy, TP/FP/FN, H100, Guardian 또는 release를 증명하지 않는다.
