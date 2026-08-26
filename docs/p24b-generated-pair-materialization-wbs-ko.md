# P2.4B generated pair materialization 작업 분해

작성일: 2026-07-23  
상태: `IN_PROGRESS`  
선행 조건: [P2.4A generated pair 60 청사진](p24a-generated-pair-blueprint-preregistration-ko.md) `FIX_NARROW`

## 왜 다시 나누는가

P2.4A는 60개의 slot을 정직하게 고정했지만 source triplet이나 실행 oracle은 하나도
materialize하지 않았다. 60개를 한 번에 생성하고 나중에 검증하면 어느 family와 어느
execution contract가 실패했는지 알 수 없다. P2.4B는 아래 작은 카드가 모두 끝나기 전에는
generated pair 60개 완료라고 말하지 않는다.

## 고정 입력

- blueprint content SHA-256:
  `3489c9a802a960a1c31451cb12d3cd2976d8c87be0c4c37c7c9e7fcf8a05e2a6`
- 60 slot: plane별 15개, Critical 16개, primary 1개 + same-slot reserve 1개
- family 분포: `source-flow` 19, `auth-rls-db` 19, `dependency-sca` 7,
  `gha-docker-iac` 8, `policy-kpriv` 7
- source triplet은 vulnerable/fixed/negative control이며, scanner output을 보기 전에
  provenance/license/tree identity와 oracle/patch/invariant 계약을 먼저 봉인한다.

## P2.4B microcard

| 카드 | 단 하나의 달성 목표 | 완료 증거 | 상태 |
| --- | --- | --- | --- |
| P2.4B.1 | external source-triplet staging layout과 slot/reserve/path/raw-free contract | [staging preregistration과 결과](p24b1-generated-pair-staging-preregistration-ko.md)의 blueprint-bound staging receipt와 3AI two-run comparator | `FIX_NARROW` |
| P2.4B.2 | [`source-flow` 19개 slot을 leaf card로 materialization](p24b2-source-flow-materialization-wbs-ko.md) | leaf별 tree identity comparator와 family aggregate | `FIX_NARROW` - .01-.20 A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3 | [`auth-rls-db` 19개 leaf materialization](p24b3-auth-rls-db-materialization-wbs-ko.md) | leaf별 tree identity comparator와 family aggregate | `IN_PROGRESS` - .01 A 사전등록 |
| P2.4B.4 | `dependency-sca` 7개 primary/reserve source triplet을 deterministic materialization | family manifest와 tree identity comparator | 대기 |
| P2.4B.5 | `gha-docker-iac` 8개 primary/reserve source triplet을 deterministic materialization | family manifest와 tree identity comparator | 대기 |
| P2.4B.6 | `policy-kpriv` 7개 primary/reserve source triplet을 deterministic materialization | family manifest와 tree identity comparator | 대기 |
| P2.4B.7 | 60 primary의 vulnerable/fixed/negative execution, patch/invariant, machine admission | 60 admission receipt와 rejected reserve ledger | 대기 |
| P2.4B.8 | 60 slot aggregate, exclusion `0`, two materialization repeat, P2.4B phase review | aggregate comparator와 3AI two-run comparator | 대기 |

## 공통 A-G gate

각 microcard는 독립적으로 다음 순서를 완료해야 한다.

1. A: family membership, expected oracle, source/license policy, reserve order, non-claim을 먼저 고정한다.
2. B: materializer 또는 validator 변경을 current target에 결속한다.
3. C: positive, negative, path escape, raw-free, overwrite, quota drift focused test를 통과한다.
4. D: external root에서 독립 output 두 개와 semantic comparator를 만든다.
5. E: focused/full regression, baseline validate-current, diff check를 통과한다.
6. F1/F2: 같은 target과 raw-free packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2을 두 번 호출한다.
7. G: 세 lane comparator가 `FIX`일 때만 그 microcard를 `FIX_NARROW`로 기록한다.

한 microcard의 `FIX_NARROW`는 다른 family, 60개 aggregate, detector performance, H100 또는
release를 승인하지 않는다. lane 하나가 `HOLD`/`BLOCKED`이면 해당 card는 `HOLD`로 보존하고 다음
비승격 측정 외에는 진행하지 않는다.

## 완료 카드: P2.4B.1

P2.4B.1은 source code를 생성하지 않는다. 먼저 외부 evidence root에서만 허용되는 stage tree,
blueprint hash binding, slot/reserve path identity, artifact overwrite/symlink/path traversal 거부,
raw source 미노출 contract를 만든다. source triplet이나 execution은 P2.4B.2-P2.4B.7의 책임이다.

따라서 P2.4B.1이 끝나도 `source_triplets_materialized=false`, `execution_oracles_proved=false`,
`eligible_for_tp_fp_fn=false`, `release_gate_passed=false`가 유지된다.

## 다음 카드: P2.4B.2

`source-flow` family의 19개 slot에만 primary/reserve source triplet을 materialize한다.
P2.4B.1이 고정한 slot ID, candidate rank, stage path, raw-free boundary는 바꾸지 않는다.
source provenance, license, tree identity를 scanner output 전에 한 candidate씩 결속하고,
family 전체를 완료했다고 말하기 전에는 각각의 admission·execution oracle을 별도 card에서
검증한다.
