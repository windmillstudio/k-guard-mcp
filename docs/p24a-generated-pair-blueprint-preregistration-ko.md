# P2.4A generated pair 60 청사진 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 프로그램: [출하 검증 프로그램 장부](release-program-phase-ledger-ko.md)

## 한 문장 목표

scanner 결과를 보기 전에 개발용 생성 corpus의 정확히 60개 scenario slot, 각 slot의
plane/severity/CWE/family/language/framework, vulnerable/fixed/negative oracle 계약과
reserve 규칙을 고정한다.

이 카드는 **청사진만** 고정한다. source triplet, 실행 oracle, scanner finding, TP/FP/FN,
H100, 성능, 출하 승인은 P2.4A의 산출물이 아니다.

## 고정 분모

| 항목 | 고정값 |
| --- | --- |
| scenario slot | 정확히 60개 |
| macro plane | `site`, `api`, `data`, `operations` 각각 15개 |
| Critical | 각 plane 4개, 총 16개 |
| severity | `high` 또는 `critical`만 허용 |
| scenario family | `source-flow`, `auth-rls-db`, `dependency-sca`, `gha-docker-iac`, `policy-kpriv`를 모두 포함 |
| language group | JS/TS, Python, Java/Kotlin, Go를 모두 포함 |
| coverage tag | `nextjs`, `express`, `supabase`, `firebase`, `sql-rls`, `mcp-proxy`, `gha-docker-iac`, `korean-privacy`를 모두 포함 |
| generator profile | local deterministic template/transform/fixture 세 profile을 순환 배치하고 어느 하나도 40%를 넘기지 않음 |
| reserve | slot마다 primary 1개와 사전등록 reserve 1개. 같은 slot의 고정 순서 외 교체 금지 |

`coverage_tag`는 해당 case가 제품이 검증해야 하는 surface를 뜻한다. 예를 들어
`express` tag는 특정 JS runtime만을 뜻하지 않고 route/auth boundary 표본을 뜻한다.
실제 framework와 language는 별도 field에 고정한다.

## Oracle 계약

각 slot은 P2.4B에서 아래 세 tree와 네 개의 실행 receipt를 모두 가져야 한다.

| 상태 | 반드시 증명할 결과 |
| --- | --- |
| vulnerable | 격리되고 network-disabled인 harness에서 exploit이 성공 |
| fixed | 동일 exploit이 실패하고 기능 regression이 통과 |
| negative control | target condition이 없는 control에서 exploit이 실패 |
| patch/invariant | bounded causal patch와 unrelated invariant 유지가 기계적으로 확인 |

P2.4B는 각 candidate에 provenance, license content, source tree triplet, 실행 결과,
patch/invariant receipt를 모두 hash로 남겨야 한다. source content, exploit input, 민감값은
외부 evidence packet에 넣지 않는다.

## 제외와 fail-closed 규칙

- candidate가 source triplet, license, isolated execution, negative control, bounded patch,
  invariant 중 하나를 만족하지 못하면 해당 candidate는 `rejected`로 남긴다.
- 다음 candidate는 같은 slot의 미리 정한 reserve 순서만 사용할 수 있다.
- 두 candidate가 모두 admission에 실패하거나 slot 하나라도 비어 있으면 corpus 전체는
  `HOLD`다. slot을 조용히 빼거나 다른 slot으로 대체하지 않는다.
- scanner output은 candidate와 label을 봉인한 뒤에만 실행한다. scanner 결과를 보고
  scenario, severity, CWE, source, reserve 순서를 고치지 않는다.

## 코드와 실행 경계

청사진 builder는 [build_l3_generated_pair_blueprint.py](../scripts/build_l3_generated_pair_blueprint.py)이며,
repeat comparator는 [compare_l3_generated_pair_blueprint_repeats.py](../scripts/compare_l3_generated_pair_blueprint_repeats.py)다.
두 artifact 모두 repository 내부에 쓸 수 없고, 새 파일만 만들며 기존 artifact를 덮어쓰지 않는다.

예정 evidence root:

```text
<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24a-generated-pair-blueprint-20260723-r1
```

P2.4A의 두 materialization은 아래처럼 external root에서만 실행한다.

```powershell
python scripts/build_l3_generated_pair_blueprint.py build --output <evidence-root>\blueprint-r1.json
python scripts/build_l3_generated_pair_blueprint.py build --output <evidence-root>\blueprint-r2.json
python scripts/compare_l3_generated_pair_blueprint_repeats.py --first <evidence-root>\blueprint-r1.json --second <evidence-root>\blueprint-r2.json --output <evidence-root>\blueprint-r1-r2-comparison.json
```

## A-G gate

| Gate | P2.4A 완료 조건 | 현재 |
| --- | --- | --- |
| A | 이 문서, 60 slot quota, oracle/claim/exclusion 계약을 scanner output 전에 고정 | `DONE` |
| B | strict builder와 external-only writer, repeat comparator를 추가 | `DONE` |
| C | quota, hash tamper, valid semantic drift, overwrite/repository output 거부 focused test | `DONE` - `12 passed` |
| D | external artifact r1/r2와 semantic comparator를 생성 | `DONE` - 두 blueprint artifact SHA-256은 `3dddfa838cba2cc54e1fca7195f314e513ddec8ab9ae2cfd45843b492a7023bd`, comparator artifact SHA-256은 `6ad876c0ec5f226bef5a4c0dd3993d4824786fc9fd07556eaf0c2869bfc521e5`, `repeat_exact=true`, `status=FIX` |
| E | current target baseline seal, focused test, full regression, diff check | `DONE` - baseline receipt SHA-256 `4feb95fdbc64b236916306aefbfc28c040becdcbd47960205647ed16b93be6b4`, validate-current와 diff check 통과, focused `12 passed`, full `2550 passed, 5 skipped` |
| F1/F2 | 같은 target/packet으로 Claude Opus 4.8, Grok 4.5, Cline GLM 5.2를 두 번 검토 | `DONE` - r1-retry/r2-retry 전원 `GO`; supervisor semantic fingerprint `c89fd00dea6b56dd40ff8215ed8529c9488661a4df21b46ddce80175e1d446d1`, `repeat_exact=true`, `status=FIX` |
| G | evidence hash와 narrow claim boundary를 장부에 기록 | `DONE` - 이 문서, goal board, phase ledger에 P2.4A만 `FIX_NARROW`로 기록 |

## 실행 결과와 재시도 기록

evidence root는
`<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-p24a-generated-pair-blueprint-20260723-r1`이다.
두 blueprint는 모두 content blueprint SHA-256
`3489c9a802a960a1c31451cb12d3cd2976d8c87be0c4c37c7c9e7fcf8a05e2a6`를 기록했다.

첫 `supervisor-review-r1`에서는 GLM이 `EVIDENCE_BINDING_GAP`으로 `HOLD`를 냈다.
packet의 `test_attestation.repeat_exact=false`가 measurement repeat 부족이 아니라 두 번째
supervisor review가 아직 없다는 뜻임을 충분히 분리하지 못한 입력이었다. 이 artifact는
삭제하거나 재분류하지 않았다. clarification을 추가한 `supervisor-review-r1-retry`에서는
Claude Opus 4.8, Grok 4.5, Cline GLM 5.2가 모두 `GO`였다.

첫 `supervisor-review-r2`에서는 GLM이 malformed terminal JSON으로 `BLOCKED_PROVIDER`가
되었고, 직후 health check는 세 lane 모두 `HEALTHY`였다. 이 receipt도 그대로 보존했다.
같은 packet의 `supervisor-review-r2-retry`에서는 전원 `GO`였고, r1-retry/r2-retry comparator가
동일 target, evidence manifest, review packet, model pinning, direct-file attestation을 `FIX`로
결속했다. 이 재시도는 기준 완화가 아니라 provider transport failure와 review-repeat 의미를
분리한 것이다.

## 명시적 비주장

P2.4A는 60개의 **개발용 slot 계약**이다. 아직 candidate source가 없고, pair admission이나
live execution을 통과한 것도 아니다. 따라서 detector recall/precision/specificity,
Korean privacy accuracy, web/API/database/runtime coverage, 5초 계약, Guardian, H100,
release는 모두 계속 `HOLD`다.

다음 카드 P2.4B는 이 청사진을 바꾸지 않고, 각 slot에 source-bound vulnerable/fixed/negative
triplet과 machine admission receipt를 materialize한다. P2.4B가 끝나기 전에는 generated pair
60개가 있다고 주장하지 않는다.
