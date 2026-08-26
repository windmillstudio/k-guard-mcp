# P2.4B.3.01 api-01 Express route-IDOR source-flow 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW` - A-G와 Claude/Grok/GLM F1/F2 comparator `FIX`  
상위 카드: [auth-rls-db 19-slot WBS](p24b3-auth-rls-db-materialization-wbs-ko.md)

## 한 문장 목표

`api-01`의 primary와 same-slot reserve에 대해 JavaScript/Express route-level ownership boundary의
vulnerable/fixed/negative source tree만 deterministic하게 materialize하고, raw-free tree identity를
두 번 같은 결과로 결속한다.

## A: 결과 전 고정한 binding

| 항목 | primary | reserve |
| --- | --- | --- |
| slot / scenario / oracle | `api-01` / `dev-api-01-route-idor` / `l3-gen-api-01-route-idor` | 같은 slot의 pre-registered reserve |
| source role | `GET /api/invoices/:invoiceId` | `GET /api/orders/:orderId` |
| framework | JavaScript / Express | JavaScript / Express |
| request identity | `req.user.id` | `req.user.id` |
| vulnerable boundary | entity ID만으로 lookup, owner predicate 없음 | entity ID만으로 lookup, owner predicate 없음 |
| fixed boundary | ID와 owner ID를 함께 predicate에 결속 | ID와 owner ID를 함께 predicate에 결속 |
| negative control | `GET /healthz` static response, entity lookup 없음 | `GET /healthz` static response, entity lookup 없음 |
| severity | CWE-862 / High | same slot reserve |

고정 invariants:

- vulnerable, fixed, negative는 각각 별도 source role이며 fixed는 vulnerable source를 재사용하지 않는다.
- primary/reserve의 route, parameter, entity, owner predicate가 바뀌거나 slot/blueprint binding이 달라지면 `HOLD`다.
- source tree에는 실제 credential, 실제 사용자 데이터, 실제 endpoint URL, network call을 넣지 않는다.
- 이 카드는 runtime request, Mongo/DB execution, 실제 ownership enforcement, IDOR exploitability,
  detector finding, precision/recall, H100, release를 주장하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | 위 binding, primary/reserve, source-role, 비주장 사전등록 | `DONE` |
| B | api-01 scoped renderer와 strict receipt validator | `DONE` - `materialize_l3_auth_rls_db_api01.py` |
| C | role/path/raw/overwrite/tamper focused test | `DONE` - focused chain `19 passed` |
| D | external r1/r2 source comparator | `DONE` - comparator `FIX`, semantic fingerprint `fcb01e2f...aa43b` |
| E | baseline, focused/full regression, target equality | `DONE WITH CONTROL_HOLD PRESERVED` - focused `28 passed`, full r2/r3 각각 `2693 passed, 5 skipped` |
| F1/F2 | Claude, Grok, GLM two-run review | `DONE` - 두 run 모두 세 lane `GO`, Claude direct-file attestation `6/6` |
| G | supervisor comparator `FIX`, evidence hash, 비주장 기록 | `DONE` - semantic comparator `FIX`, fingerprint `15a22f6d...8a8ca` |

## 시작 경계

이 leaf는 `P2.4B.2.20`의 source-flow inventory aggregate가 G까지 닫힌 뒤에만 열었다.
새 renderer는 다른 `auth-rls-db` slot, source-flow slot, 실제 API 실행, scanner score, Guardian
block rule을 수정하거나 승인하지 않는다.

## D external evidence

- r1 receipt SHA-256: `5efe2adbd5cb1d9d1601e719b1b0fe6b83d77546028d07eba837bb7b8c6bbe92`
- r2 receipt SHA-256: `c85ec9cc012457539dc6c785acbd8a106f147770ba01d04cee86f239a6db3b49`
- raw-free comparator SHA-256: `91df735d843cf0db54e63b3bcfeeaf52725f5087477988f586a15a0daa21716b`
- comparator는 같은 materializer, raw-free receipt projection, slot `api-01`만 확인했다. runtime authorization,
  exploit, detector, TP/FP/FN, H100, release 판단에는 권한이 없다.

## E regression evidence

- baseline current receipt SHA-256: `328290995354e5b439db367fb1f574a8d1bf57b866bfc96edec79ff148487d55`
- focused receipt SHA-256: `3e274eca10d038cec411d56ed6eab3f3c1dbd6643862531b2f0b3fbc3c4ca6ae`,
  `28 passed`, target before/after identical.
- full r1 receipt SHA-256: `a5d6992bed66295a5c2aef16f97e0025274aed6599964e31c9bb9faf4bf91e84`,
  `CONTROL_HOLD`, `2692 passed`, `1 failed`, target unchanged. 삭제하거나 성공 근거로 바꾸지 않는다.
- full r2 receipt SHA-256: `4cd25b70f627e570335fc131250a6795fa24c0902436135abd029ca8878dd168`,
  `2693 passed`, `5 skipped`, target before/after identical.
- full r3 receipt SHA-256: `1516c5cbb23592965a6cffcc083b306e85294b21157f95e34709c589713e836c`,
  `2693 passed`, `5 skipped`, target before/after identical.
- raw-free carrier가 r1의 failing node id를 evidence receipt에 보관하지 않아 원인은 아직 `inconclusive`다.
  F1/F2 감독 검토는 이 관찰성 부족을 card `FIX_NARROW` 승격의 blocker로 볼지 명시해야 한다.

## F/G supervisor evidence and final boundary

- health receipt SHA-256: `b92fc795ef9345279eea3037e52ba33958b79b17c7757b377a212746b8361ca0`,
  Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 모두 `HEALTHY`.
- F1/F2 decision SHA-256: 각각
  `817ebfb9665b7bfbe01ac3d899588432269a32e476665ed47419000e6725402a`.
  세 lane은 모두 `GO`, blocker `0`, nonblocking `REPEATABILITY_GAP` 하나였고 Claude는 direct-file `6/6`을
  attestation했다. single-run top-level `HOLD`는 F2 전의 intentional repeat gap이다.
- G supervisor comparator SHA-256: `d4a06d697020e2763fb7932ea51af8650d71fd0b06829fa947e5d99a9184683b`,
  `repeat_exact=true`, `FIX`, semantic fingerprint
  `15a22f6d7b5cdcd192b535c7487db970e3418cad4188a57922b62e982388a8ca`.
- 따라서 이 카드의 좁은 source-tree identity만 `FIX_NARROW`다. raw-free r1 full failure는 삭제하지 않으며,
  runtime authorization, IDOR exploitability, detector accuracy, TP/FP/FN, H100, release는 여전히 비주장이다.
