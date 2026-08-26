# P2.4B.2 source-flow materialization 작업 분해

작성일: 2026-07-23  
상태: `IN_PROGRESS`  
상위 목표 계층: [제품 목표 레지스트리](release-program-goal-register-ko.md)  
선행 조건: [P2.4B.1 staging contract](p24b1-generated-pair-staging-preregistration-ko.md) `FIX_NARROW`

## 한 문장 목표

`source-flow` family의 고정 19개 slot을 한 번에 채우지 않는다. 각 slot의 primary와
fixed-order reserve source triplet을 독립 external root에서 materialize하고, provenance,
license, tree identity가 두 번 같을 때만 다음 slot으로 간다.

P2.4B.2는 **source tree materialization**까지만 다룬다. live exploit, fixed functional test,
negative-control execution, pair admission, scanner finding, TP/FP/FN, detector accuracy,
H100, release는 P2.4B.7 이후의 책임이다.

## 고정 입력과 공통 경계

- P2.4A blueprint content SHA-256:
  `3489c9a802a960a1c31451cb12d3cd2976d8c87be0c4c37c7c9e7fcf8a05e2a6`
- P2.4B.1의 fixed slot ID, candidate rank `0` primary와 rank `1` reserve, relative path
  `slots/<slot>/candidate-<rank>/<vulnerable|fixed|negative>`를 바꾸지 않는다.
- 각 leaf card는 새 external materialization root에만 source tree를 쓴다. P2.4B.1의
  빈 staging evidence는 읽기 전용이며, 채우거나 재사용하지 않는다.
- raw-free receipt에는 source content, exploit input, secret, URL, scanner output을 넣지 않는다.
- primary와 reserve 모두 source triplet을 materialize해야 한다. reserve를 생략하거나 scanner
  결과를 보고 candidate를 교체하면 해당 leaf는 `HOLD`다.

## Leaf card

| 카드 | 고정 slot | language/framework | CWE/severity | 단 하나의 완료 증거 | 상태 |
| --- | --- | --- | --- | --- | --- |
| P2.4B.2.01 | [`site-01` `xss-render`](p24b201-site01-source-flow-preregistration-ko.md) | TypeScript / Next.js | CWE-79 / High | primary+reserve tree identity two-run comparator | `FIX_NARROW` |
| P2.4B.2.02 | [`site-02` `sqli-query`](p24b202-site02-source-flow-preregistration-ko.md) | JavaScript / Express | CWE-89 / High | primary+reserve tree identity two-run comparator | `FIX_NARROW` |
| P2.4B.2.03 | [`site-03` `command-exec`](p24b203-site03-source-flow-preregistration-ko.md) | JavaScript / Express | CWE-78 / Critical | primary+reserve tree identity two-run comparator | `FIX_NARROW` |
| P2.4B.2.04 | [`site-04` `path-traversal`](p24b204-site04-source-flow-preregistration-ko.md) | TypeScript / Next.js | CWE-22 / High | primary+reserve tree identity two-run comparator | `FIX_NARROW` |
| P2.4B.2.05 | [`site-05` `untrusted-redirect`](p24b205-site05-source-flow-preregistration-ko.md) | TypeScript / Next.js | CWE-601 / High | primary+reserve tree identity two-run comparator | `FIX_NARROW` |
| P2.4B.2.06 | [`site-06` `ssrf-fetch`](p24b206-site06-source-flow-preregistration-ko.md) | JavaScript / Express | CWE-918 / High | primary+reserve tree identity two-run comparator | `FIX_NARROW` |
| P2.4B.2.07 | [`site-07` `prototype-pollution`](p24b207-site07-source-flow-preregistration-ko.md) | TypeScript / Next.js | CWE-1321 / High | primary+reserve tree identity two-run comparator | `FIX_NARROW` |
| P2.4B.2.08 | [`site-08` `unsafe-deserialize`](p24b208-site08-source-flow-preregistration-ko.md) | JavaScript / Express | CWE-502 / Critical | primary+reserve tree identity two-run comparator | `FIX_NARROW` |
| P2.4B.2.09 | [`site-09` `client-secret`](p24b209-site09-source-flow-preregistration-ko.md) | TypeScript / Next.js | CWE-798 / Critical | primary+reserve tree identity two-run comparator | `FIX_NARROW` |
| P2.4B.2.10 | [`site-10` `cors-origin`](p24b210-site10-source-flow-preregistration-ko.md) | JavaScript / Express | CWE-942 / High | primary+reserve tree identity two-run comparator | `FIX_NARROW` |
| P2.4B.2.11 | [`site-11` `template-xss`](p24b211-site11-source-flow-preregistration-ko.md) | Python / Django | CWE-79 / High | primary+reserve tree identity two-run comparator | `FIX_NARROW` |
| P2.4B.2.12 | [`site-12` `file-read`](p24b212-site12-source-flow-preregistration-ko.md) | Python / Flask | CWE-22 / High | primary+reserve tree identity two-run comparator | `FIX_NARROW` |
| P2.4B.2.13 | [`site-13` `jdbc-query`](p24b213-site13-source-flow-preregistration-ko.md) | Java / Spring | CWE-89 / High | primary+reserve tree identity two-run comparator | `FIX_NARROW` |
| P2.4B.2.14 | [`site-14` `html-response`](p24b214-site14-source-flow-preregistration-ko.md) | Kotlin / Ktor | CWE-79 / High | primary+reserve tree identity two-run comparator | `FIX_NARROW` |
| P2.4B.2.15 | [`site-15` `sql-builder`](p24b215-site15-source-flow-preregistration-ko.md) | Go / chi | CWE-89 / Critical | primary+reserve tree identity two-run comparator | `FIX_NARROW` |
| P2.4B.2.16 | [`data-03` `raw-query`](p24b216-data03-source-flow-preregistration-ko.md) | TypeScript / Prisma | CWE-89 / High | primary+reserve tree identity two-run comparator | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.2.17 | [`data-07` `parameterized-query`](p24b217-data07-source-flow-preregistration-ko.md) | Python / FastAPI | CWE-89 / High | primary+reserve tree identity two-run comparator | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.2.18 | [`data-09` `jdbc-concat`](p24b218-data09-source-flow-preregistration-ko.md) | Java / Spring | CWE-89 / High | primary+reserve tree identity two-run comparator | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.2.19 | [`data-14` `query-format`](p24b219-data14-source-flow-preregistration-ko.md) | Go / pgx | CWE-89 / High | primary+reserve tree identity two-run comparator | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.2.20 | [19-slot aggregate](p24b220-source-flow-aggregate-preregistration-ko.md) | all declared groups | 3 Critical + 16 High | exclusion `0`, 19-leaf manifest and repeat comparator | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |

## 각 leaf의 A-G gate

1. A: slot ID, primary/reserve order, source provenance, license, expected three tree roles, non-claim을
   source 생성 전에 고정한다.
2. B: 해당 slot만 materialize할 수 있는 strict writer와 raw-free tree manifest를 target에 결속한다.
3. C: wrong slot/rank, path escape, overwrite, symlink, unexpected file, tree hash tamper, source role
   swap을 focused test로 거부한다.
4. D: 새 external root에서 독립 r1/r2 tree와 semantic comparator를 만든다.
5. E: focused/full regression, current baseline, diff check를 통과한다.
6. F1/F2: 같은 target/packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2을 두 번 호출한다.
7. G: machine comparator와 3AI semantic comparator가 모두 `FIX`일 때만 해당 leaf를 `FIX_NARROW`로
   기록한다.

한 leaf의 `FIX_NARROW`는 다른 slot, source-flow family 전체, execution oracle, scanner recall,
한국 개인정보 정확도, H100, release를 승인하지 않는다.

## 완료 leaf: P2.4B.2.01

`site-01`의 primary/reserve 각각에 TypeScript/Next.js source tree 세 개
(`vulnerable`, `fixed`, `negative`)를 만든다. vulnerable tree는 user-controlled HTML rendering
condition을 보존하고, fixed tree는 bounded rendering boundary 수정만 포함하며, negative tree는
target condition 없는 control을 가진다. 이 문장은 source tree의 의도일 뿐, exploit 실행이나
detector finding의 증거는 아니다.

## 완료 leaf: P2.4B.2.02

[`site-02` 사전등록과 결과](p24b202-site02-source-flow-preregistration-ko.md)는 JavaScript/Express
primary/reserve source tree 6개를 external r1/r2에서 materialize했다. source comparator와
Claude Opus 4.8/Grok 4.5/Cline GLM 5.2 two-run comparator는 `FIX`였다. preserved full-regression
control HOLD 한 건은 결과 문서에 남아 있으며, 이 leaf의 `FIX_NARROW`는 source tree identity만 뜻한다.

## 완료 leaf: P2.4B.2.03

[`site-03` 사전등록과 결과](p24b203-site03-source-flow-preregistration-ko.md)는 JavaScript/Express
primary/reserve command-exec source tree 6개를 external r1/r2에서 materialize했다. source comparator와
Claude Opus 4.8/Grok 4.5/Cline GLM 5.2 clarified-packet r3/r4 comparator는 `FIX`였다. 첫 r1/r2의
GLM `TEST_ATTESTATION_GAP` HOLD는 결과 문서에 보존하며, 이 leaf의 `FIX_NARROW`는 source tree
identity만 뜻한다.

## 완료 leaf: P2.4B.2.04

[`site-04` 사전등록과 결과](p24b204-site04-source-flow-preregistration-ko.md)는 TypeScript/Next.js
primary report와 reserve download의 route/input/root/static-control identity, strict source materializer,
focused test, independent external r1/r2 tree comparator, full regression, Claude/Grok/GLM F1/F2 semantic
comparator를 결속해 `FIX_NARROW`다. single-review `REPEATABILITY_GAP` HOLD는 보존했다. 이 leaf는
source tree identity뿐이며 P2.4B.2.01/.02/.03의 template, source tree, comparator, supervisor receipt는
site-05 이후의 승인 근거가 아니다.

## 완료 leaf: P2.4B.2.05

[`site-05` 사전등록과 결과](p24b205-site05-source-flow-preregistration-ko.md)는 TypeScript/Next.js
continue/signin primary/reserve route, `next`/`returnTo` request field, fixed same-origin boundary, static internal
negative control을 strict source materializer와 comparator로 결속했다. current target focused 6/6, isolated full
r1/r2, external materialization r1/r2 comparator, Claude/Grok/GLM F1/F2 comparator가 모두 `FIX_NARROW`의
source-tree identity 계약을 닫았다. 이전 target의 first full `CONTROL_HOLD`와 health-only GLM
`BLOCKED_PROVIDER`는 삭제하지 않고 결과 문서와 F packet에 보존했다. 이 leaf는 redirect execution, scanner
finding, TP/FP/FN, metric, H100, release를 승인하지 않는다.

## 완료 leaf: P2.4B.2.06

[`site-06` 사전등록과 결과](p24b206-site06-source-flow-preregistration-ko.md)는 JavaScript/Express primary
preview와 reserve avatar route, `url`/`imageUrl` query field, candidate별 `https` host allowlist, static internal
negative control을 source 생성 전에 고정했다. site-06 전용 strict materializer/comparator, focused 6/6,
external r1/r2 source comparator, isolated full r1/r2 각각 2,593 passed, Claude/Grok/GLM F1/F2 semantic comparator가
모두 `FIX_NARROW` source-tree identity 계약을 닫았다. top-level single-review `REPEATABILITY_GAP`은 보존했다.
이 leaf는 HTTP/SSRF execution, scanner finding, TP/FP/FN, SSRF recall, H100, release를 승인하지 않는다.

## 완료 leaf: P2.4B.2.07

[`site-07 사전등록과 결과`](p24b207-site07-source-flow-preregistration-ko.md)는 TypeScript/Next.js primary
preferences와 reserve profile route, `preferences`/`profile` request JSON field, explicit fixed fields, static
negative object를 source 생성 전에 고정했다. site-07 전용 strict materializer/comparator, focused 6/6, external
r1/r2 source comparator, isolated full r1/r2 각각 2,599 passed, Claude/Grok/GLM F1/F2 semantic comparator가
모두 `FIX_NARROW` source-tree identity 계약을 닫았다. top-level single-review `REPEATABILITY_GAP`은 보존했다.
이 leaf는 prototype mutation execution, scanner finding, TP/FP/FN, prototype-pollution recall, H100, release를
승인하지 않는다.

## 완료 leaf: P2.4B.2.08

[`site-08 사전등록과 결과`](p24b208-site08-source-flow-preregistration-ko.md)는 JavaScript/Express primary import-settings와
reserve restore-session route, `serializedSettings`/`serializedSession` request body field, explicit fixed fields, static
negative object를 source 생성 전에 고정했다. site-08 전용 strict materializer/comparator, focused 6/6, external
r1/r2 source comparator, isolated full r1/r2 각각 2,605 passed, Claude/Grok/GLM F1/F2 semantic comparator가
모두 `FIX_NARROW` source-tree identity 계약을 닫았다. top-level single-review `REPEATABILITY_GAP`은 보존했다.
이 leaf는 deserializer/code execution, scanner finding, TP/FP/FN, unsafe-deserialization recall, H100, release를
승인하지 않는다.

## 완료 leaf: P2.4B.2.09

[`site-09 사전등록과 결과`](p24b209-site09-source-flow-preregistration-ko.md)는 TypeScript/Next.js primary checkout와
reserve integrations route, `checkoutProviderKey`/`integrationApiToken` client identifier, synthetic literal, same-origin
server handoff, static negative label을 source 생성 전에 고정했다. site-09 전용 strict materializer/comparator, focused
6/6, external r1/r2 source comparator, isolated clean full r2/r3 각각 2,611 passed, Claude/Grok/GLM F1/F2 semantic
comparator가 모두 `FIX_NARROW` source-tree identity 계약을 닫았다. initial full r1 `CONTROL_HOLD`와 health r1 GLM
`BLOCKED_PROVIDER`는 삭제하지 않고 결과 문서에 보존했다. 이 leaf는 real secret validity, client bundle exposure,
external request, scanner finding, TP/FP/FN, client-secret recall, H100, release를 승인하지 않는다. 다음에 열 수 있는
site-09 완료 시점에 다음으로 열린 카드 하나는 P2.4B.2.10의 A 사전등록이었다.

## 완료 leaf: P2.4B.2.10

[`site-10 사전등록과 결과`](p24b210-site10-source-flow-preregistration-ko.md)는 JavaScript/Express primary checkout와
reserve integrations route, request `origin`, reflected CORS handler, candidate별 fixed allowlist, `204` negative control을
source 생성 전에 고정했다. site-10 전용 strict materializer/comparator, focused 6/6, external r1/r2 source comparator,
isolated clean full r1/r2 각각 2,617 passed, Claude/Grok/GLM F1과 F3 retry semantic comparator가 모두
`FIX_NARROW` source-tree identity 계약을 닫았다. intermediate F2 GLM `BLOCKED_PROVIDER`와 단회
`REPEATABILITY_GAP`은 삭제하지 않고 보존했다. 이 leaf는 browser CORS behavior, cross-origin read, deployed allowlist
correctness, scanner finding, TP/FP/FN, CORS-origin recall, H100, release를 승인하지 않는다. 다음에 열 수 있는 카드 하나는
P2.4B.2.11의 A 사전등록이다.

## 완료 leaf: P2.4B.2.11

[`site-11 사전등록과 결과`](p24b211-site11-source-flow-preregistration-ko.md)는 Python/Django primary checkout와
reserve integrations view, `message`/`notice` query parameter, `mark_safe` source condition, `escape` fixed boundary,
static negative paragraph를 source 생성 전에 고정했다. site-11 전용 strict materializer/comparator, focused 6/6,
external r1/r2 source comparator, isolated clean full r1/r2 각각 2,623 passed, Claude/Grok/GLM F1/F2 semantic comparator가
모두 `FIX_NARROW` source-tree identity 계약을 닫았다. 단회 `REPEATABILITY_GAP`은 삭제하지 않고 보존했다. 이 leaf는
browser rendering, script execution, deployed Django configuration, scanner finding, TP/FP/FN, template-XSS recall, H100,
release를 승인하지 않는다. 다음에 열 수 있는 카드 하나는 P2.4B.2.12의 A 사전등록이다.

## 완료 leaf: P2.4B.2.13

[`site-13 사전등록과 결과`](p24b213-site13-source-flow-preregistration-ko.md)는 Java/Spring primary orders와
reserve integrations source triplet, request `id`/`provider`, concatenated JDBC query source condition, placeholder와
`PreparedStatement.setString` fixed boundary, static negative controller를 source 생성 전에 고정했다. site-13 전용
strict materializer/comparator, focused 6/6, external r1/r2 source comparator, isolated clean full r1/r2 각각
2,635 passed, Claude/Grok/GLM F1/F2 semantic comparator가 모두 `FIX_NARROW` source-tree identity 계약을 닫았다.
focused r1 Windows selector의 pre-receipt rejection은 성공 근거로 쓰지 않았다. 이 leaf는 Java/Maven/Spring runtime,
JDBC driver/database/query execution, SQLi exploit, scanner finding, TP/FP/FN, SQLi recall, H100, release를 승인하지 않는다.
다음에 열 수 있는 카드 하나는 P2.4B.2.14의 A 사전등록이다.
