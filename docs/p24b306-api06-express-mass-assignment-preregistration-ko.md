# P2.4B.3.06 api-06 Express mass-assignment source-tree 사전등록

작성일: 2026-07-25  
상태: `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX`  
상위 카드: [auth-rls-db 19-slot WBS](p24b3-auth-rls-db-materialization-wbs-ko.md)

## 한 문장 목표

`api-06`의 primary와 같은 slot의 pre-registered reserve에 대해 JavaScript/Express mass-assignment
vulnerable/fixed/negative source tree만 deterministic하게 materialize할 계약을 결과 전에 고정한다.

## A: 결과 전 고정한 binding

| 항목 | primary | reserve |
| --- | --- | --- |
| slot / scenario / oracle | `api-06` / `dev-api-06-mass-assignment` / `l3-gen-api-06-mass-assignment` | 같은 slot의 pre-registered reserve |
| source role | profile update `PATCH /profiles/:profileId` route와 profile store declaration | team-member update `PATCH /team-members/:memberId` route와 member store declaration |
| framework | JavaScript / Express | JavaScript / Express |
| vulnerable boundary | request body 전체를 `Object.assign(profile, req.body)`로 update target에 병합 | request body 전체를 `Object.assign(member, req.body)`로 update target에 병합 |
| fixed boundary | `displayName`, `locale` allowlist만 새 update object에 명시적으로 복사 | `displayName`, `notificationOptIn` allowlist만 새 update object에 명시적으로 복사 |
| negative control | Express route, update target, `Object.assign`가 없는 static status source | Express route, update target, `Object.assign`가 없는 static status source |
| severity | CWE-915 / High | same slot reserve |

고정 invariants:

- vulnerable, fixed, negative는 각각 별도 source role이며 fixed는 vulnerable route source를 재사용하지 않는다.
- primary/reserve의 route role, update target, whole-body `Object.assign`, fixed allowlist fields,
  slot/blueprint binding이 바뀌면 `HOLD`다.
- source tree에는 실제 database URL, credential, access token, 실제 사용자 데이터, network call을 넣지 않는다.
- 이 카드는 source-tree identity만 다룬다. Express deployment, request parsing, database write semantics,
  authorization, exploitability, detector finding, precision/recall, H100, Guardian, release는 주장하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | 위 binding, primary/reserve, source-role, 비주장 사전등록 | `DONE` |
| B | api-06 scoped renderer와 strict receipt validator | `DONE` - `materialize_l3_auth_rls_db_api06.py` |
| C | role/path/raw/overwrite/tamper focused test | `DONE` - focused chain `6 passed` |
| D | external r1/r2 source comparator | `DONE` - comparator `FIX`, semantic fingerprint `78d9a32f...77329` |
| E | baseline, focused/full regression, target equality | `DONE` - focused `18 passed`; full `2,726 passed, 5 skipped, 0 failed` |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two-run review | `DONE` - r1/r2 전 lane `GO`; comparator `FIX` |
| G | supervisor comparator `FIX`, evidence hash, 비주장 기록 | `DONE` - 아래 evidence와 narrow claim 기록 |

## 시작 경계

이 leaf는 `P2.4B.3.05 api-05`가 G까지 `FIX_NARROW`로 닫힌 뒤 열었다. B 이전에는 source를 만들거나
scanner 결과를 보지 않는다. 새 renderer는 다른 `auth-rls-db` slot, 실제 Express application, scanner score,
Guardian block rule을 수정하거나 승인하지 않는다.

## D external evidence

- r1/r2 source materialization은 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b306-api06-express-mass-assignment-20260725`에만 생성했다.
- r1/r2 materialization receipt file SHA-256: `dd93d5d999a31c6e9e8ae2e84538c4688a6bbb453eebad7b3d0668d5e1a5064c` /
  `604ee8c97a0db9c5be43aa1382f1b9c2e59c237042fed074a9a87fb909316f01`.
- raw-free comparator SHA-256: `511de38781083e01b780890d710533cba45df5d46764ba72d8cc21c5ee1babe0`.
  comparator는 slot `api-06`, source-triplet identity, staged blueprint binding, materializer hash만 확인했고
  semantic fingerprint `78d9a32f0694b30c959370617effce4da8b82c9424be10b1b9264ed06a977329`,
  `repeat_exact=true`, `status=FIX`를 기록했다.

## E-G evidence와 비주장

- current baseline receipt SHA-256: `a9f9f5c9f63ce73bf54f5a90df45b90f9d6ad4a379989b1b521341259936aa86`.
  full regression 뒤 `--validate-current`도 `current=true`로 통과했다.
- focused/full attestation receipt SHA-256:
  `f04f62b30fbef4591ee9ee1a9bed8b9ee99f8f1c9651141a19d247520ee39782` /
  `f40e8d2a77a076ab07f1d6b21299317601311de5e05a157e57d17679157d09bd`.
  - focused 18 passed, full 2,726 passed, 5 skipped, 0 failed; control error와 target drift 없음.
- supervisor health raw-free receipt file SHA-256: `e13dd5ddb3817585e253e9e1ef7285bb9e0c60c5573fbc062a1c7659978dda03`.
  이것은 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2의 availability만 확인하며 승인 evidence는 아니다.
- same-target F1/r2에서 세 모델은 전 lane `GO`였다. 각 단회 terminal `HOLD`는 second independent run이
  아직 없다는 `test_attestation_incomplete`만 기록한 비승격 상태다. supervisor comparator SHA-256
  `2acf103965709dba74ac4f247116fb41f499eab23638d54c44b2b1bf62acb74c`, semantic fingerprint
  `3d6da994fe32ea82ad839d52c94334737bc59598af0a5d1ab190735d8594cbf9`, `repeat_exact=true`, `status=FIX`다.

이 결과는 `api-06` primary/reserve vulnerable/fixed/negative Express mass-assignment source-tree identity만
`FIX_NARROW`로 닫는다. Express deployment, request parsing, database update semantics, authorization, exploit,
detector accuracy, TP/FP/FN, H100, Guardian 또는 release를 증명하지 않는다.
