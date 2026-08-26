# Evidence Hash Policy

작성일: 2026-07-06

## 목적

K-Guard는 raw-free 감사 도구다. 보고서, SARIF, MCP response, dashboard, flow graph는 원문 개인정보, secret, prompt payload를 그대로 저장하지 않는다.

대신 재현 가능한 증거 anchor로 line hash를 사용한다.

## 방식

기본 방식:

- algorithm: `HMAC-SHA256`
- evidence length: first 16 hex characters
- normalization: `strip()` 후 UTF-8 인코딩
- default key: `k-guard-public-evidence-v1`
- operator key env: `K_GUARD_EVIDENCE_HMAC_KEY`
- release authority requires at least 32 UTF-8 bytes and 128 estimated bits; the public default value, short values, and low-variation repeated values are treated as public-default mode

출력 예:

```text
line_hash=1a2b3c4d5e6f7890 scheme=hmac-sha256:operator-keyed:len16
```

## 운영 권장

로컬 개발/오픈소스 기본값은 public default key를 사용한다. 이 값은 재현성과 baseline/dedupe를 쉽게 한다.

민감 repo, 고객 repo, 상용 CI에서는 다음 환경변수를 설정한다.

```bash
K_GUARD_EVIDENCE_HMAC_KEY=<project-local-random-secret>
```

이 키는 repo에 커밋하지 않는다. CI secret 또는 로컬 환경변수로만 둔다.

`--fail-on`을 쓰는 CI 차단 경로에서 이 값이 없으면 K-Guard는 stderr에 경고를 낸다. public default key는 로컬 baseline 재현성에는 유용하지만, 상용 CI의 증거 무결성 설명에는 충분하지 않다.

## 보안 의미

- 원문 line/prompt/PII 값은 보고서에 쓰지 않는다.
- 같은 키를 쓰면 같은 line은 같은 hash가 되어 baseline/dedupe가 가능하다.
- operator key를 쓰면 단순 사전 대입으로 hash를 맞추기 어렵다.
- hash는 법적 증명이나 암호학적 원본 보존 인증이 아니라 raw-free triage anchor다.

## 한계

- public default key는 편의용이다. 민감 데이터가 많은 상용 환경에서는 반드시 operator key를 설정해야 한다.
- line hash만으로 사람에게 충분한 문맥을 주지 못할 수 있다. 이 경우 로컬 파일에서 file:line을 열어 확인한다.
- hash 충돌 가능성은 매우 낮지만 16 hex prefix이므로, 고위험 감사에서는 file path, line number, rule id, partial fingerprint를 함께 본다.

## SARIF

SARIF 결과에는 다음을 넣는다.

- redacted message
- physicalLocation file/line
- partialFingerprints.kGuardFinding
- properties.evidence_hash_scheme
- raw snippet/codeFlow/threadFlowLocation은 넣지 않는다.
