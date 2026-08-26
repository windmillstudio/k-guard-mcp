# P2.3B.6 WrongSecrets Challenge1 execution oracle 사전등록

작성일: 2026-07-23  
상태: `MEASURED_HOLD`  
상위 프로그램: [P2.3B execution oracle 사전등록](p23b-local-execution-oracle-program-preregistration-ko.md)

## 가설

P2.3A에서 봉인한 OWASP WrongSecrets source의 upstream
`Challenge1Test#rightAnswerShouldSolveChallenge`는 `Challenge1`이 source-defined answer와
일치할 때만 통과한다. 이 positive는 값 자체를 표준 출력이나 evidence에 내보내지 않고
JUnit assertion 결과만 사용한다.

같은 source의 transient derived copy에서 `Challenge1.getAnswer()`의 정확한 한 return
anchor만 빈 문자열 return으로 바꾸면, 같은 upstream targeted test는 assertion failure
한 건으로 실패해야 한다. 이 negative는 source-mutated control이며 original source, source
checkout, 또는 test source를 변경하지 않는다.

이 작업은 하나의 source-bound Java process execution pair와 반복성만 다룬다. K-Guard가
secret을 탐지했다는 주장, secret detector의 precision/recall, 일반 Java/Spring 분석, SCA,
Guardian, H100, 제품 출하는 이 oracle로 승인하지 않는다.

## 사전 고정 입력

| 항목 | 고정값 또는 검증 방법 |
| --- | --- |
| source | P2.3A `wrongsecrets` receipt의 repository `owasp/wrongsecrets`, commit `25bdda3c380c7b16bdd2a528c9fff3700fa2b801`, commit tree `4946781597334bc73adb26d97d84f2677264f9d1`, source tree SHA-256 `9b85876c204c995d056206a292ba45e48731ce2a71124fc5e43f4cdea6eeff80` |
| source receipt | P2.3A app receipt SHA-256 `a88dd137d957a2e2fb5ad01841369ee0fc2b5161c29d77c4d5087b4ff4bb4904`, semantic SHA-256 `06f9b90faa43039cd5093b577fb63f98d855134e852ab35bc40c331d423c2bba` |
| source license | root `LICENSE`, `AGPL-3.0-only`, SHA-256 `a3c8862ad142ce7c8a915663dc397c2fb56bbc61a1d1ba9dfebb55b0931c37d6` |
| relevant source bytes | `Challenge1.java` `c14a5c0b8fb931fb8e41d22277b0e1cf4ea905331fe3a1f24e7f19303abc0c51`; `WrongSecretsConstants.java` `1b14d121a856828be326fa9b6551bd196d1414ea85e4e083cea467846272f808`; `FixedAnswerChallenge.java` `d33d249e8ca8850397380bc810fe99070bd51aae4aaad0607c06c67770e0b75e`; `Challenge1Test.java` `25a4a7c2bbb5beea0d8a41187da761e9055906b35043a59e25909d7f13f7bbad`; `pom.xml` `aabd5452b4338823a29f86749c0da16f9d8df5ee867951c27c8ae68a8546ae50`; `mvnw` `cae96cef89ebea3531221f4ae17c23cf8edf67d00eae8306d4186ae1bbed4d02`; wrapper properties `11cac19f3e77912a89bab9663fef29068d6aaad3776382909f41cd91766005be` |
| positive oracle | upstream `Challenge1Test#rightAnswerShouldSolveChallenge`. One selected JUnit test must finish with `tests=1`, `failures=0`, `errors=0`, process exit `0`. Only normalized counts, test identifier hash, and exit class may enter evidence. |
| negative control | a derived source copy replaces exactly one byte anchor, `return WrongSecretsConstants.password;`, with a non-secret empty return. The same selected test must finish with `tests=1`, `failures=1`, `errors=0`, process exit nonzero. A timeout, compilation error, test discovery failure, or any different test count is `HOLD`, never a negative pass. |
| toolchain | host Java/Maven is intentionally not used. The source-derived image must use `eclipse-temurin@sha256:201fbb8886b2d273218aa3a192f0afbf7b5ff65ee8cc6ef47f5dce2171f013ea` (JDK 25.0.3) and source `mvnw` distribution 3.9.16. Any base image, wrapper, source, or target drift is `HOLD`. |
| build and runtime boundary | Maven dependency acquisition may occur only while building a fresh source-derived image and is recorded as an unproven build supply-chain boundary. Each actual targeted-test run uses a fresh one-shot container with `--network none`, no host port, no bind/volume mount, non-root user, read-only rootfs, `no-new-privileges`, dropped capabilities, bounded tmpfs/resource limits, and verified cleanup. Unsupported hardening is `HOLD`. |
| public evidence boundary | No secret value, source challenge payload, raw Maven output, raw test report, absolute source path, build command output, or image filesystem bytes are written to the receipt. Only fixed hashes, normalized selected-test counts, structural isolation booleans, and cleanup status are retained. |

## 변경 범위

| 대상 | 허용 변경 |
| --- | --- |
| 새 replay runner와 comparator | P2.3A source binding, temporary source derivative, image/toolchain binding, normalized JUnit report parser, isolation/cleanup checks, raw-free receipt, repeat comparator |
| focused tests | source drift, one-anchor patch, report parser, isolation, cleanup, raw-free, comparator의 fail-closed 경계 |
| 문서와 ledger | 실행 결과, evidence hash, explicit nonclaim 기록 |

K-Guard detector, rule, severity, score, warning/block policy, Guardian threshold, P2.3A source
checkout, upstream test source는 변경하지 않는다.

## 성공 조건

1. P2.3A source receipt, license, source tree, relevant file hash, image digest, wrapper version,
   source clean status 중 하나라도 불일치하면 실행 전 `HOLD`다.
2. positive와 negative 모두 selected test identifier, exact test count, failure/error count, exit
   class, derived patch hash, fresh image contract, runtime isolation, cleanup을 검증해야 한다.
3. negative는 exact one-anchor mutation 때문에 발생한 assertion failure 한 건이어야 한다.
   단순 nonzero exit, Maven/Java/tool error, timeout, test skip, build failure는 negative pass가
   아니다.
4. original source, upstream test source, P2.3A checkout은 실행 전후 byte-identical이어야 한다.
5. positive/negative pair를 서로 다른 external output에 두 번 실행하고 semantic comparator가
   `FIX`여야 한다.
6. focused tests, current target full regression, Claude Opus 4.8, Grok 4.5, Cline GLM 5.2의
   두 review run comparator를 모두 통과해야 `FIX_NARROW`다.

## 명시적 비주장

이 작업은 Challenge1 하나의 source-bound process pair와 negative-control repeatability만
뜻한다. real secret, production secret manager, secret scanning, false-positive/false-negative,
SCA, Java/Spring framework depth, Korean personal-data handling, network runtime protection,
Guardian, H100, release를 검증하거나 승인하지 않는다.

## Maven 경로의 HOLD 보존

이 사전등록의 첫 구현 target은 `2026-07-23` baseline receipt
`a593da07eb2095c8e0b73c19ef0a1722414958a8e814250bc35dea8a8f3f8be7`에 결속했다.
focused test는 통과했지만, source-derived image에서 전체 Maven `test-compile`이
`replay_image_build_failed` raw-free error로 중단되어 positive receipt를 만들지 못했다.

이 실패는 source, official test, oracle, detector, score를 바꾸지 않았고 제출 증거나
성능 수치에 사용하지 않는다. raw Maven log는 evidence에 저장하지 않았다. 따라서 이
Maven 경로는 `FIX_NARROW`가 아니며, 해당 target에서의 P2.3B.6은 명시적으로 `HOLD`다.
후속 [Javac harness 사전등록](p23b6-wrongsecrets-challenge1-javac-harness-preregistration-ko.md)은
다른 source-derived execution hypothesis로 분리한다.
