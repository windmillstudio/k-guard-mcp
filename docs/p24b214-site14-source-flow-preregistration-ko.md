# P2.4B.2.14 site-14 HTML response source-flow 사전등록

작성일: 2026-07-24  
상태: `FIX_NARROW`  
상위 카드: [P2.4B.2 source-flow leaf WBS](p24b2-source-flow-materialization-wbs-ko.md)  
제품 목표: [G1 정직한 분모와 oracle](release-program-goal-board-ko.md)  
목표/종료 기준: [제품 목표 레지스트리](release-program-goal-register-ko.md)

## 한 문장 목표

P2.4A의 `site-14` HTML response slot에 대해 primary와 fixed-order reserve 두 candidate의 Kotlin/Ktor
`vulnerable`, `fixed`, `negative` source tree를 external root에 deterministic template으로 materialize하기 전,
slot binding과 source 역할을 고정한다.

## 고정 binding

- slot: `site-14`, scenario `dev-site-14-html-response`, oracle `l3-gen-site-14-html-response`
- plane/family/language/framework: `site` / `source-flow` / `kotlin` / `ktor`; blueprint coverage tag는 `express`
- CWE/severity/profile: `CWE-79` / `high` / `deterministic-template-v1`
- candidate rank: primary `0`, reserve `1`; 총 2 candidate와 6 source tree
- primary source: `src/main/kotlin/dev/kguard/checkout/ReceiptRoute.kt`, route `/receipt`, query parameter `message`,
  vulnerable HTML response `<section>$message</section>`, fixed HTML escaping, static negative text `receipt-ready`
- reserve source: `src/main/kotlin/dev/kguard/integrations/InviteRoute.kt`, route `/invite`, query parameter `notice`,
  vulnerable HTML response `<section>$notice</section>`, fixed HTML escaping, static negative text `invite-ready`
- `vulnerable` tree는 request query 값을 `ContentType.Text.Html` response에 보간하는 source condition을 보존한다.
  `fixed` tree는 고정된 local HTML escaping helper를 거친 값만 response에 보간한다. `negative` tree는 query parameter를
  읽지 않고 candidate별 static HTML만 반환한다.
- source layout은 `slots/site-14/candidate-<rank>/<state>`를 그대로 쓴다. P2.4B.1 stage root는 read-only다.
- 각 tree에는 MIT `LICENSE`, canonical Kotlin/Gradle build file, 하나의 Ktor route source만 둔다.

## 명시적 비주장

이 카드는 source tree identity만 다룬다. Kotlin compiler, Gradle, Ktor runtime, HTML rendering, browser script execution,
XSS exploit, deployed CSP/configuration, scanner finding, TP/FP/FN, recall, H100, release는 증명하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | slot/rank/profile/tree-role/license/non-claim과 primary/reserve source/route/parameter/HTML/static-text identity 사전등록 | `DONE` |
| B | site-14만 허용하는 immutable materializer/comparator 결속 | `DONE` - Kotlin/Ktor HTML response source-only materializer와 repeat comparator를 별도 versioned file로 결속 |
| C | tamper, role swap, root binding, repository output, overlap, overwrite focused test | `DONE` - materializer/comparator focused tests 6 passed, 0 failed |
| D | external root r1/r2 materialization comparator | `DONE` - comparator `FIX`, semantic fingerprint `7fabd55efaf9acc74618f286b0c12421727e99011c5019fa36e3d83491ade32a` |
| E | baseline, focused/full regression, compatibility | `DONE` - focused 6/6, full r1/r2 각각 2,641 passed, 5 skipped, 0 failed, 0 errors |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two-run review | `DONE` - 두 run 모두 세 lane `GO`, Claude direct-file 5/5 |
| G | machine/supervisor comparator `FIX`와 비주장 기록 | `DONE` - supervisor comparator `FIX`, repeat exact |

## 완료 evidence

- D: external source comparator `FIX`, semantic fingerprint `7fabd55efaf9acc74618f286b0c12421727e99011c5019fa36e3d83491ade32a`.
- E: baseline `c291e44dde964c2adff8eb234ac4eb895e858cb9652801c3fa3e6a9d6289ad13`; focused
  `f30054e3e378d92204701e71ef6f158294d6b3a8a99fbedfe2b12cb90494effd`; full r1/r2
  `a67327a87568d61114e73a49fc660b935ff43129d20ad6154e955edc700abf17`,
  `38215ca7437fe941354a597b885d35d22eae8b22506e26aeda5ae1263e1eb5df`.
- F/G: Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 모두 F1/F2 lane `GO`; supervisor semantic fingerprint
  `ac7932232d5593adb037713afd838af306ed8080ed8f743362e7cbd7144359b6`, comparator `FIX`.
