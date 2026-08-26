# P2.4B.3.10 api-10 Django REST object-owner source-tree 사전등록

작성일: 2026-07-25  
상태: `FIX_NARROW` - A-G와 3AI F1/r3 comparator `FIX`; F2 Claude timeout 보존  
상위 카드: [auth-rls-db 19-slot WBS](p24b3-auth-rls-db-materialization-wbs-ko.md)

## 한 문장 목표

`api-10`의 primary와 같은 slot의 pre-registered reserve에 대해 Python/Django REST object-owner
vulnerable/fixed/negative source tree만 deterministic하게 materialize할 계약을 결과 전에 고정한다.

## A: 결과 전 고정한 binding

| 항목 | primary | reserve |
| --- | --- | --- |
| slot / scenario / oracle | `api-10` / `dev-api-10-object-owner` / `l3-gen-api-10-object-owner` | 같은 slot의 pre-registered reserve |
| source role | `GET /orders/{order_id}` object lookup view | `GET /invoices/{invoice_id}` object lookup view |
| framework | Python / Django REST | Python / Django REST |
| vulnerable boundary | `Order.objects.get(pk=order_id)`에 `request.user` owner predicate가 없음 | `Invoice.objects.get(pk=invoice_id)`에 `request.user` account predicate가 없음 |
| fixed boundary | `Order.objects.get(pk=order_id, owner=request.user)`만 object lookup으로 사용 | `Invoice.objects.get(pk=invoice_id, account=request.user)`만 object lookup으로 사용 |
| negative control | Django REST import, route decorator, `request.user`, object lookup이 없는 static status source | 같은 negative contract |
| severity | CWE-639 / High | same slot reserve |

고정 invariants:

- vulnerable, fixed, negative는 각각 별도 source role이며 fixed는 vulnerable view source를 재사용하지 않는다.
- primary/reserve의 route, model/object parameter, vulnerable user predicate 부재, fixed owner/account predicate,
  negative exclusion, slot/blueprint binding이 바뀌면 `HOLD`다.
- fixed source는 runtime database, authenticated user fixture, HTTP server, network call 또는 성공 응답을 만들지 않는다.
- source tree에는 실제 사용자 데이터, secret, access token, database connection string을 넣지 않는다.
- 이 카드는 source-tree identity만 다룬다. Django REST runtime authentication/authorization, object ownership semantics,
  ORM execution, exploitability, detector finding, precision/recall, H100, Guardian, release는 주장하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | 위 binding, primary/reserve, source-role, 비주장 사전등록 | `DONE` |
| B | api-10 scoped renderer와 strict receipt validator | `DONE` - `materialize_l3_auth_rls_db_api10.py` |
| C | role/path/raw/overwrite/tamper focused test | `DONE` - api-10 focused chain `6 passed` |
| D | external r1/r2 source comparator | `DONE` - comparator `FIX`, semantic fingerprint `8360288a...2b8c72` |
| E | baseline, focused/full regression, target equality | `DONE` - focused `18 passed`; full `2,750 passed, 5 skipped, 0 failed` |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two-run review | `DONE` - F1/r3 전 lane `GO`; comparator `FIX` |
| G | supervisor comparator `FIX`, evidence hash, 비주장 기록 | `DONE` - F2 Claude timeout 보존과 below evidence 기록 |

## 시작 경계

이 leaf는 `P2.4B.3.09 api-09`가 G까지 `FIX_NARROW`로 닫힌 뒤 열었다. B 이전에는 source를 만들거나
scanner 결과를 보지 않는다. 새 renderer는 다른 `auth-rls-db` slot, 실제 Django REST application, runtime auth/ORM,
scanner score, Guardian block rule을 수정하거나 승인하지 않는다.

## A blueprint evidence와 비주장

- raw-free blueprint는 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b310-api10-django-object-owner-20260725\\api10-pre-registration-blueprint.json`에만 생성했다.
- blueprint file SHA-256: `3dddfa838cba2cc54e1fca7195f314e513ddec8ab9ae2cfd45843b492a7023bd`.
  `api-10`은 `python`, `django-rest`, `CWE-639`, `high`, `deterministic-fixture-v1`과 public scanner output
  absent-at-seal binding을 가진다.
- 이 evidence는 source tree, execution oracle, scanner detection, TP/FP/FN, H100, Guardian 또는 release를 증명하지 않는다.

## B/C renderer와 focused evidence

- renderer는 primary order view와 reserve invoice view에 대해 vulnerable object lookup의 `request.user` predicate 부재,
  fixed `owner=request.user` 또는 `account=request.user` predicate, URL mapping을 각각 별도 source role로 materialize한다.
- negative control은 `api/status.py` static source로 고정했고 Django REST import, route decorator, `request.user`, object lookup을
  포함하지 않는다. receipt에는 raw view source, user predicate, source path를 반환하지 않는다.
- focused chain은 materialization role/path/raw/overwrite/tamper와 repeat-comparator tamper refusal을 함께 실행해
  `6 passed`였다. 이는 deterministic source-tree 계약의 B/C만 증명하며 Django REST runtime authentication, authorization,
  object ownership, ORM execution, detector accuracy, TP/FP/FN, H100, Guardian, release는 여전히 비주장이다.

## D external repeat evidence

- r1/r2 source materialization은 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b310-api10-django-object-owner-20260725`에만 생성했다.
- r1/r2 raw-free receipt SHA-256은 각각
  `f8687e047d70d07484512ce0412c1c2f27a95fc528679e9d5b9918568c7cba58` /
  `6901cf55bbe2a7d25088ee60230d2ccc619ddde950805bfcf5b73bd9ea9bedbd`다.
- raw-free comparator SHA-256은 `4fd4e0c0c21fb974e0ac291dbd2f27d89c64809a5c89e5a2de7c49365f318876`다.
  slot `api-10`, staged blueprint binding, source-triplet identity, materializer hash만 비교했고
  semantic fingerprint `8360288a799277b1223442e9e5637a7040709ff08e143ed38b5e6b1d3a2b8c72`,
  `repeat_exact=true`, `status=FIX`를 기록했다.
- 이 D 결과도 source-tree identity만 확인한다. Django REST runtime authorization, object ownership semantics,
  ORM execution, exploitability, detector, TP/FP/FN, H100, Guardian, release에 관한 권한은 없다.

## E-G evidence와 비주장

- current baseline receipt SHA-256은 `980c67a2cae536080e60a5dca274d1d7da9ea6494a4fdeb99cbae1d3016afd0d`이며,
  full regression 뒤 `--validate-current`도 `current=true`로 통과했다.
- focused/full attestation receipt SHA-256은
  `6fee510140b0ddfadd9a2b60f9d969d5a8c56bb8e87359a95edcefe9029cb7c8` /
  `fe52706f2f9a2519f30b73046c1659ffb9e292e7f621cc32e477c681b5e91480`다.
  - focused 18 passed, full 2,750 passed, 5 skipped, 0 failed; control error와 target drift 없음.
- supervisor health raw-free receipt file SHA-256은
  `04a7bfcec32d4875a0d29b655a29dde358db2ee207716aebdee4781e0ca089ca`다.
  F2의 Claude `BLOCKED_TIMEOUT` receipt는 삭제하지 않고
  `phase2-p24b310-api10-django-object-owner-20260725-supervisor-review-v1-r2`에 보존했다. health 재확인 후
  동일 target에서 수행한 r3가 Claude/Grok/GLM 전 lane `GO`가 된 유효 second run이다.
- F1/r3 supervisor comparator SHA-256은 `d9ee60a2b851d8288e02141155df49b4d320e37091465fed9a053928fe2748dd`,
  semantic fingerprint는 `b867af57b25fa4ef139c3295c92c0ae010c223cd8dd870b8a1e1103d4db364ec`,
  `repeat_exact=true`, `status=FIX`다.

이 결과는 `api-10` primary/reserve vulnerable/fixed/negative Django REST object-owner source-tree identity만
`FIX_NARROW`로 닫는다. Django REST runtime authentication/authorization, object ownership semantics, ORM execution,
exploit, detector accuracy, TP/FP/FN, H100, Guardian 또는 release를 증명하지 않는다.
