# P2.3B.6a WrongSecrets Challenge1 Javac harness execution oracle 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 프로그램: [P2.3B execution oracle 사전등록](p23b-local-execution-oracle-program-preregistration-ko.md)  
선행 HOLD: [Maven execution 사전등록](p23b6-wrongsecrets-challenge1-preregistration-ko.md)

## 분리 이유

Maven full-project `test-compile` 경로는 source나 official assertion을 바꾸지 않은 채
raw-free build error로 종료했고 positive receipt를 만들지 못했다. 그 결과를 삭제하거나
통과로 바꾸지 않는다. 이 카드는 그 실패를 해결했다고 주장하지 않는다.

대신 current source에서 upstream `Challenge1Test#rightAnswerShouldSolveChallenge`와 같은
predicate, 즉 `Challenge1.answerCorrect(WrongSecretsConstants.password)`를 Java 25의 좁은
source closure로 직접 실행한다. 이는 official test source를 semantic reference로 사용한
source-derived process pair이며 Maven lifecycle, 전체 dependency graph, upstream JUnit
runner 실행을 주장하지 않는다.

## 가설

P2.3A에서 고정한 WrongSecrets source의 `Challenge1`은 `getAnswer()`에서 source-defined
constant를 반환한다. source-defined `answerCorrect` predicate에 같은 constant를 입력하면
positive에서는 `true`가 되어야 한다.

transient derived copy에서 `Challenge1.getAnswer()`의 exact one return anchor만 빈 문자열로
바꾸면 같은 predicate는 `false`가 되어야 한다. positive와 negative 모두 JVM process가
정상 종료해야 하며, boolean 외의 source value는 stdout, stderr, receipt에 나오면 안 된다.

## 사전 고정 입력

| 항목 | 고정값 또는 검증 방법 |
| --- | --- |
| source | `owasp/wrongsecrets`, commit `25bdda3c380c7b16bdd2a528c9fff3700fa2b801`, tree `4946781597334bc73adb26d97d84f2677264f9d1`, source tree SHA-256 `9b85876c204c995d056206a292ba45e48731ce2a71124fc5e43f4cdea6eeff80` |
| P2.3A binding | observed receipt `a88dd137d957a2e2fb5ad01841369ee0fc2b5161c29d77c4d5087b4ff4bb4904`, app receipt `58509e4ad992c66e1b230a66d9f7e18c6c080aea07fb110e07b08d4295455485`, semantic receipt `06f9b90faa43039cd5093b577fb63f98d855134e852ab35bc40c331d423c2bba` |
| source license | root `LICENSE`, `AGPL-3.0-only`, SHA-256 `a3c8862ad142ce7c8a915663dc397c2fb56bbc61a1d1ba9dfebb55b0931c37d6` |
| source closure | `Challenge1.java`, `WrongSecretsConstants.java`, `FixedAnswerChallenge.java`, `Challenge.java`, `Spoiler.java`, upstream `Challenge1Test.java`의 current hash를 모두 검사한다. P2.3A full source verification은 build 전후에 별도로 실행한다. |
| official semantic reference | upstream `Challenge1Test#rightAnswerShouldSolveChallenge`의 source hash를 기록한다. 이 카드는 upstream JUnit test를 Maven으로 실행했다는 주장을 하지 않는다. |
| generated compile stubs | Spring `Component`와 Lombok `UtilityClass`은 compile-time annotation stub만 제공한다. Guava `Supplier`/`Suppliers.memoize`는 `FixedAnswerChallenge`가 요구하는 one-time cached value semantics만 구현한다. stub source hash와 behavior test를 receipt에 결속한다. |
| positive observation | harness가 source-defined constant를 argument로 넣은 predicate 결과 `true`, process exit `0`, marker 1개를 기록한다. 값, body, source text, absolute path는 기록하지 않는다. |
| negative control | exact return anchor 1개만 빈 return으로 바꾼 derived source에서 같은 harness가 `false`, process exit `0`, marker 1개를 기록해야 한다. compile error, timeout, exception, nonzero exit는 negative pass가 아니다. |
| toolchain | `eclipse-temurin@sha256:201fbb8886b2d273218aa3a192f0afbf7b5ff65ee8cc6ef47f5dce2171f013ea`, JDK `25.0.3+9`, `javac` only. Maven, host Java, host Maven, network dependency acquisition은 사용하지 않는다. |
| runtime | fresh source-derived image와 one-shot container. `--network none`, host port/bind/volume mount 없음, non-root, read-only rootfs, cap-drop, no-new-privileges, tmpfs/resource limit, cleanup을 inspect로 검증한다. |

## 성공 조건

1. source/P2.3A/license/source closure/stub/harness/base-image hash 중 하나라도 drift하면 `HOLD`다.
2. positive는 `true`와 exit `0`, negative는 `false`와 exit `0`을 모두 보여야 한다.
3. negative는 exact one-anchor mutation이 있어야 하며 timeout, compile error, exception, exit code
   차이만으로는 통과할 수 없다.
4. original checkout과 upstream test source는 실행 전후 byte-identical이어야 한다.
5. 각 mode는 receipt 내부 두 run과 external output 두 run에서 semantic comparator `FIX`를 통과해야 한다.
6. focused tests, 전체 회귀, Claude Opus 4.8/Grok 4.5/Cline GLM 5.2 두 review run comparator까지
   닫혀야만 `FIX_NARROW`다.

## 명시적 비주장

이 카드는 Challenge1 하나의 source-derived Java predicate와 one mutation control만 뜻한다.
upstream Maven/JUnit integration, general secret detector accuracy, Spring framework analysis,
Guava/Lombok/Spring의 전체 동작, production secret store, SCA, TP/FP/FN, Guardian, H100,
release를 검증하거나 승인하지 않는다.

## 실행 결과와 승격 근거

증거 root: `<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p23b6-wrongsecrets-challenge1-javac-20260723-r1`

| Gate | 결과 |
| --- | --- |
| A | 이 사전등록의 source, source closure, toolchain, mutation anchor, 비주장 경계를 실행 전 고정했다. |
| B | `baseline-r1.json`은 current target `04e9dd8e7dc788d8242db138278758303ba6f27d`와 source/P2.3A/license binding을 결속했고, receipt SHA-256은 `4ce9bbc24a41bb6f9a0b5c060ea664328d0b78aed8b3c419b3636369d755a5c6`이다. |
| C | `python -m pytest -q tests/test_replay_l2_wrongsecrets_challenge1.py tests/test_compare_l2_wrongsecrets_challenge1_repeats.py`는 `10 passed`였다. |
| D | positive r1/r2와 negative r1/r2는 각각 semantic comparator `FIX`였다. |
| E | `python -m pytest -q`는 `2529 passed, 5 skipped, 0 failed in 1143.86s`였고 baseline 재검증과 `git diff --check`도 통과했다. |
| F1 | 최초 `supervisor-review-r1`은 Claude direct-file lane의 `BLOCKED_TIMEOUT`으로 `HOLD`였으며 보존했다. timeout을 900초로 올린 별도 `supervisor-review-r1-retry-900`과 `supervisor-review-r2`에서는 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2가 모두 `GO`였고 Claude의 5개 direct-file attestation도 있었다. |
| F2/G | `supervisor-review-r1-retry-900-r2-comparison.json`은 두 run의 semantic fingerprint `30b4b7021885995730cc24a2ab591f83e1701b1988caac4a4d08b442dbb34f78`가 동일하고 `repeat_exact=true`, `status=FIX`임을 기록한다. |

이 `FIX_NARROW`는 source-derived Java predicate와 transient one-anchor control의 실행 경계에만
유효하다. Maven branch의 `MEASURED_HOLD`, upstream JUnit integration 부재, 일반 탐지 정확도와
출하 판단의 비주장은 그대로 유지한다.
