# P2.4B.3.12 api-12 Spring method-auth source-tree 사전등록

작성일: 2026-07-25  
상태: `FIX_NARROW` - A-G 완료, r2/r3 Claude/Grok/GLM comparator `FIX`; initial GLM `HOLD` 보존  
상위 카드: [auth-rls-db 19-slot WBS](p24b3-auth-rls-db-materialization-wbs-ko.md)

## 한 문장 목표

`api-12`의 primary와 같은 slot의 pre-registered reserve에 대해 Java/Spring method-auth
vulnerable/fixed/negative source tree만 deterministic하게 materialize할 계약을 결과 전에 고정한다.

## A: 결과 전 고정한 binding

| 항목 | primary | reserve |
| --- | --- | --- |
| slot / scenario / oracle | `api-12` / `dev-api-12-method-auth` / `l3-gen-api-12-method-auth` | 같은 slot의 pre-registered reserve |
| source role | `DELETE /admin/users/{userId}` destructive admin controller method | `POST /billing/refunds/{refundId}` finance controller method |
| framework | Java / Spring | Java / Spring |
| vulnerable boundary | method에 Spring Security `@PreAuthorize`가 없음 | method에 Spring Security `@PreAuthorize`가 없음 |
| fixed boundary | method에 `@PreAuthorize("hasRole('ADMIN')")` annotation source를 명시 | method에 `@PreAuthorize("hasAuthority('REFUND_APPROVE')")` annotation source를 명시 |
| negative control | Spring MVC/Security import, mapping annotation, `@PreAuthorize`가 없는 static Java status source | 같은 negative contract |
| severity | CWE-862 / High | same slot reserve |

고정 invariants:

- vulnerable, fixed, negative는 각각 별도 source role이며 fixed는 vulnerable controller source를 재사용하지 않는다.
- primary/reserve route, vulnerable annotation 부재, fixed annotation, negative exclusion, slot/blueprint binding이 바뀌면
  `HOLD`다.
- fixed annotation source는 실제 Spring Security 설정, role principal, HTTP server, database, network call 또는 성공 응답을 만들지 않는다.
- source tree에는 실제 계정, secret, access token, database connection string을 넣지 않는다.
- 이 카드는 source-tree identity만 다룬다. Spring runtime authentication/authorization, method-security enforcement,
  role semantics, endpoint execution, exploitability, detector finding, precision/recall, H100, Guardian, release는 주장하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | 위 binding, primary/reserve, source-role, 비주장 사전등록 | `DONE` |
| B | api-12 scoped renderer와 strict receipt validator | `DONE` - `materialize_l3_auth_rls_db_api12.py` |
| C | annotation/path/raw/overwrite/tamper focused test | `DONE` - api-12 focused chain `6 passed` |
| D | external r1/r2 source comparator | `DONE` - comparator `FIX`, semantic fingerprint `eb578edf...58890c` |
| E | baseline, focused/full regression, target equality | `DONE` - focused `18 passed`, full `2762 passed, 5 skipped`, target equality |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two-run review | `DONE` - clarified r2/r3 all-lane `GO`, comparator `FIX`; initial r1 GLM `HOLD` 보존 |
| G | supervisor comparator `FIX`, evidence hash, 비주장 기록 | `DONE` - source-tree identity만 `FIX_NARROW` |

## 시작 경계

이 leaf는 `P2.4B.3.11 api-11`이 G까지 `FIX_NARROW`로 닫힌 뒤 열었다. B 이전에는 source를 만들거나
scanner 결과를 보지 않는다. 새 renderer는 다른 `auth-rls-db` slot, 실제 Spring application, runtime method security,
scanner score, Guardian block rule을 수정하거나 승인하지 않는다.

## A blueprint evidence와 비주장

- raw-free blueprint는 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b312-api12-spring-method-auth-20260725\\api12-pre-registration-blueprint.json`에만 생성했다.
- blueprint file SHA-256: `3dddfa838cba2cc54e1fca7195f314e513ddec8ab9ae2cfd45843b492a7023bd`.
  `api-12`는 `java`, `spring`, `CWE-862`, `high`, `deterministic-transform-v1`과 public scanner output
  absent-at-seal binding을 가진다.
- 이 evidence는 source tree, execution oracle, scanner detection, TP/FP/FN, H100, Guardian 또는 release를 증명하지 않는다.

## B/C renderer와 focused evidence

- renderer는 primary `AdminController.java`와 reserve `RefundController.java`를 별도 source role로 만들고,
  vulnerable에는 `@PreAuthorize`를 넣지 않으며 fixed에는 각각 고정된 `hasRole('ADMIN')` 또는
  `hasAuthority('REFUND_APPROVE')` annotation source와 `MethodSecurityMarker.java`를 넣는다.
- marker는 `runtime method security not materialized`만 선언하며 실제 Spring Security 설정, principal, HTTP server,
  database 또는 성공 응답을 만들지 않는다. negative control은 static `Status.java`만 포함하며 Spring import와 annotation을 포함하지 않는다.
- focused chain은 annotation/path/raw/overwrite/tamper 및 repeat-comparator tamper refusal을 포함해 `6 passed`였다.
  이 결과는 source-tree identity의 B/C만 검증하며 Spring runtime authorization, method-security enforcement,
  detector accuracy, TP/FP/FN, H100, Guardian, release는 여전히 비주장이다.

## D external repeat evidence

- r1/r2 source materialization은 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b312-api12-spring-method-auth-20260725`에만 생성했다.
- r1/r2 raw-free receipt SHA-256은 각각
  `0b16463f58994cf244728d3a42e5fa00e392e1aeb10baa45c784618cf637e91e` /
  `ca61d7358547a56cd03448502129240915adb2c1bd188bdc37da8b6bd5a18044`다.
- raw-free comparator SHA-256은 `76b1223ec2e8c0d0397a9f1ba54ae546151e2601ee8e331ffec7799dca235acd`다.
  staged blueprint binding, source-triplet identity, materializer hash만 비교했고 semantic fingerprint
  `eb578edf5eb72d2b0ed6b532e718e6ad3f07b672c6c15bac36d3693d4758890c`, `repeat_exact=true`, `status=FIX`를 기록했다.
- 이 D 결과도 source-tree identity만 확인한다. Spring runtime authorization, method-security enforcement,
  endpoint execution, detector, TP/FP/FN, H100, Guardian, release에 관한 권한은 없다.

## E baseline과 regression attestation

- baseline receipt는 외부 evidence root
  `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase2-p24b312-api12-spring-method-auth-20260725-r1\\baseline.json`에만 있으며,
  SHA-256은 `177cb02c0b4aa6bf2363dd9f15f7a1e9db349e80da162d3e1316bc52fdf8eb60`이다. G 직전 `--validate-current`도 `current=true`를 냈다.
- focused attestation은 `18 passed, 0 failed, 0 errors`, target before/after identical이며 receipt SHA-256은
  `7efbe1e3c54b5e8949172b5eb27d64114d6a9e3234f1c669c46ebc36c99d36b5`다.
- full attestation은 `2762 passed, 5 skipped, 0 failed, 0 errors`, timeout/control error `0`, target before/after identical이며
  receipt SHA-256은 `b29b00bb1f8d1c1513100ab861754944f3d6c6eabd2002c76191f71a0f6abbcb`다.
- 이 E 결과도 source-tree renderer와 test/review packet의 회귀 경계만 뜻한다. Spring runtime authorization,
  method-security enforcement, detector accuracy, TP/FP/FN, H100, Guardian, release는 비주장이다.

## F/G supervisor review와 보존한 실패

- initial F1은 raw-free packet SHA-256 `5ba927454dfa7b353497a176845ddcbc08e375eea72d2ca64ae41a6a19a15ee5`에서
  Claude/Grok `GO`, GLM `HOLD`를 냈다. GLM은 first-run의 필수 nonblocking `REPEATABILITY_GAP`을 blocker로 분류했고,
  decision SHA-256 `a9f0dc168276546d06f0945565b59ab9ea81841ba495021a070664e42848c58e`를 가진다. 이 `HOLD`는 삭제하거나
  성공으로 바꾸지 않는다.
- retry r2와 동일-packet r3는 first-run gap을 runner-level `HOLD`와 provider-level blocker로 혼동하지 않는 결정을 명시했다.
  두 run 모두 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 lane `GO`, target unchanged, raw returned `false`였고
  각 decision SHA-256은 `bfbf07073aa8fd8f198e3fc6249148464c552abc426c5d0208affbff3e55b15b`다.
- r2/r3 supervisor comparator는 `repeat_exact=true`, `status=FIX`, semantic fingerprint
  `99ea876b9c19690e420a18405d0f931cca0531981e647f51f958ab480926e4ba`, comparator SHA-256
  `3b27c4c20f5372d80e58fd3affe9b711dba45b55a0ac76d0d786dc813874c2e9`를 기록했다.
- 따라서 G는 api-12 primary/reserve vulnerable/fixed/negative **source-tree identity만** `FIX_NARROW`로 기록한다.
  Spring runtime authentication/authorization, method-security enforcement, role semantics, endpoint execution,
  exploitability, detector accuracy, TP/FP/FN, H100, Guardian, release는 여전히 승인하지 않는다.
