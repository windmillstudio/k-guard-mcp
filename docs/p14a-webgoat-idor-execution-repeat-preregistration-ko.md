# P1.4A WebGoat IDOR 실행 반복 사전등록

## 좁은 목표

고정된 공개 WebGoat source target에서 IDOR upstream integration test 실행
contract를 두 번 새로 수행하고, 각 receipt 안의 두 격리 실행과 receipt 사이의
의미상 결과가 모두 일치하는지 확인한다.

대상은 다음 한 시나리오뿐이다.

- repository: `webgoat/webgoat`
- commit: `5142935bf7c279882c3b0fc0ecec42c447de6fd5`
- tree: `6c45e60db0995416a5bbe5977657a78d5084dcf7`
- source tree SHA-256:
  `0b2193e30038f4366715986e939645d7851e647c6188b992311639dd7564da3c`
- integration test:
  `org.owasp.webgoat.integration.IDORIntegrationTest`

## 실행 계약

1. `replay_l2_webgoat_idor.py run`을 같은 verified source root에서 두 번
   독립 실행한다.
2. 각 receipt는 source-derived image와 network `none` runtime을 만들고,
   nonce가 다른 두 실행을 내부에서 수행한다.
3. 두 receipt는 canonical JSON이어야 하며 각각
   `EXECUTION_CONTRACT_PASS`, 내부 two-run normalized consensus, owned resource
   cleanup, `release_gate_passed=false`를 가져야 한다.
4. `compare_l2_execution_contract_repeats.py`는 nonce, raw command output hash,
   source-derived image ID, build output hash, 동적 build command hash 같은
   휘발성 값은 제외한다. 대신 runner가 기록한 deterministic build-contract hash로
   `--no-cache`, `--pull=false`, build network, contract label, base image,
   Dockerfile을 묶고, source, runner, isolation, normalized outcome, admission
   blockers, claim boundary를 비교한다.
5. 비교 결과는 `FIX` 또는 `HOLD`만 낸다. 입력 receipt 또는 target이 바뀌면
   `HOLD` 또는 invalid-input 오류다.

## 합격과 비합격

P1.4A의 합격은 두 새 receipt가 위 계약을 만족하고 semantic comparator가
`FIX`를 내는 경우뿐이다. 빌드, 격리, 실행, 정규화, cleanup 중 하나라도
실패하면 `HOLD`다. receipt를 재사용하거나 source root를 수정하면 안 된다.

## 명시적 비주장

이 작업은 한 공개 upstream integration test의 execution repeatability만
입증한다. IDOR 탐지율, scanner finding mapping, CWE/CVSS truth, 취약/수정
pair, TP/FP/FN, API 권한 검증, WebGoat 전체 성능, Guardian, H100, 제품 출하를
입증하거나 승격하지 않는다. 기존 admission blocker는 그대로 남긴다.
