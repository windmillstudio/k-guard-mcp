# P1.4B WebGoat IDOR negative-control 반복 사전등록

## 좁은 목표

P1.4A의 고정 positive receipt에만 결속된 WebGoat IDOR source-mutated negative
control을 새로 두 번 실행하고, 각 receipt의 두 격리 runtime과 receipt 사이의
의미상 결과가 모두 일치하는지 확인한다.

고정 positive anchor는 다음뿐이다.

- positive receipt SHA-256:
  `f2afead44a548fd861c550acd2ee17dd52e3a3dae434f43bfc85f43ea74b0365`
- source receipt SHA-256:
  `52ba9d0e5a85539790e9b68f82ad4d389847b4331354276e196af64367af7aaa`
- repository/commit/tree는 P1.4A와 동일한 `webgoat/webgoat`
  `5142935bf7c279882c3b0fc0ecec42c447de6fd5` / source tree
  `0b2193e30038f4366715986e939645d7851e647c6188b992311639dd7564da3c`다.

## 실행 계약

1. `negative-control`은 source copy에 정확히 한 번 적용되는
   `reject-cross-profile-update.v2` mutation만 사용한다. 원본 source checkout은
   수정하지 않는다.
2. 입력 positive receipt가 위 SHA-256과 exact source receipt hash에 맞지 않으면
   실행 전에 HOLD한다.
3. 각 negative receipt는 source-derived image와 network `none` runtime 두 번을
   만들고, expected exit `1`, 정해진 control-triggered Failsafe outcome, owned
   resource cleanup을 모두 만족해야 한다.
4. `compare_l2_idor_negative_control_repeats.py`는 nonce, temporary path, image
   ID, raw output hash, dynamic build-command hash만 제외한다. deterministic
   build-contract, positive anchor, mutation hash, source, isolation, expected
   negative outcome, admission blockers, claim boundary는 비교에 포함한다.

## 명시적 비주장

이 작업은 source-mutated negative control이 positive execution contract와
구분되어 재현되는지를 보는 local harness 계약이다. 독립 upstream fixed revision,
실제 IDOR scanner detection, CWE/CVSS, TP/FP/FN, API authorization, Guardian,
H100, release를 증명하거나 승격하지 않는다.
