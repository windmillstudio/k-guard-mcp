# K-Guard Product Hardening R2 Cycle Contract

## 1. Cycle identity

- Cycle ID: `product-hardening-r2`
- Repository: `<LOCAL_USER_HOME>/Desktop/mcp/k-guard-clean-cycle-20260726-r2/repo`
- Evidence root: `<LOCAL_USER_HOME>/Desktop/mcp/k-guard-clean-cycle-20260726-r2/evidence/product-hardening-r2`
- Archive root: `<LOCAL_USER_HOME>/Desktop/mcp/k-guard-clean-cycle-20260726-r2/archive`
- Migration root: `<LOCAL_USER_HOME>/Desktop/mcp/k-guard-clean-cycle-20260726-r2/migration`
- Branch: `codex/product-hardening-r2`
- Initial status: `HOLD`

이 cycle은 기존 dirty worktree와 Git metadata를 공유하지 않는 독립 clone에서만 실행한다.
기존 `product-hardening-20260731` cycle은 terminal HOLD 기록이며 새 GO 근거로 승격하지
않는다.

## 2. Authority

- Codex가 기본 작업자이며 제품 코드, 측정 코드, 증거 결속을 책임진다.
- Qwen은 명시적으로 호출한 보조 작업자다. 기본 모델 또는 자동 작성자로 사용하지 않는다.
- Claude Opus와 Grok은 같은 sealed packet을 독립적으로 검수한다.
- 과거 GLM 검수는 회귀 자료일 뿐 필수 출하 의결권을 갖지 않는다.
- 서로 다른 AI가 같은 파일을 동시에 수정하지 않는다.

## 3. Migration result

기존 `git status --short`가 폴더를 접어 표시한 항목은 381개였다. 파일 단위
`--untracked-files=all` 결과는 389개다. 389개 모두 clean snapshot의 tracked 파일과
바이트 및 SHA-256이 같았다.

- `migrated_clean_snapshot`: 389
- `quarantine`: 0
- `missing_from_clean_snapshot`: 0
- `generated_excluded`: 0

권위 있는 상세 분류는 외부
`migration/dirty-worktree-classification.json`에 보존한다. 원본 dirty worktree는
읽기 전용 참고 자료이며 수정, 정리, reset, clean의 대상이 아니다.

## 4. Canonical receipt contract

제품 Phase 검수 영수증은
`src/k_guard_mcp/schemas/k-guard-product-supervisor-receipt-v1.schema.json` 한 종류만
사용하며 wheel에도 포함한다.
권위 있는 의미 검증기는
`src/k_guard_mcp/product_hardening_receipts.py`다.

고정 필드:

- receipt context, phase, attempt
- reviewer, requested model, runtime model, session
- contract SHA-256, sealed packet SHA-256, candidate commit and tree
- normalized positive token usage
- peer verdict 미제공 증명
- verdict, product approval, blockers, blocker class
- redacted provider envelope와 reviewer attestation의 path 및 SHA-256
- source receipt schema, path, SHA-256, canonical 여부
- 재계산 가능한 validation summary와 `raw_returned=false`

필수 reviewer는 `sol`, `opus`, `grok` 세 명이다. 세 receipt가 같은 phase, attempt,
contract, packet에 결속되고 session ID가 서로 다르며 모두 `GO`일 때만 Phase를
`FIX`로 닫는다.

과거 실제 receipt는 손실 없이 canonical history로 변환할 수 있다. 다만 phase,
attempt, sealed packet, positive usage 또는 attestation이 실제 source에 없으면 null로
보존하고 `product_gate_admissible=false`로 판정한다. 인접 파일의 값을 복사하거나
추정해서 빈 증거를 채우지 않는다.

## 5. Fixed acceptance gates

- block precision >= 90%, Wilson 95% lower bound >= 80%
- app complete hit rate >= 90%, Wilson 95% lower bound >= 80%
- High/Critical recall >= 90%
- Critical recall = 100%
- specificity >= 90%
- same input reproducibility = 100%
- single-rule candidate concentration <= 50%
- `check_my_app` <= 5 seconds
- Guardian omitted supported scope = 0
- CLI, MCP, client regression = 0
- SOL, Opus, Grok = all GO

평균값으로 실패한 평면을 덮지 않는다. 미측정도 실패다.

## 6. R2 entry order

1. Independent repository, migration classification, archive hashes를 봉인한다.
2. 실제 receipt fixture로 canonical schema와 fail-closed validator를 검증한다.
3. 새 HEAD와 tree, tool hashes, Python 및 OS 환경을 cycle entry에 기록한다.
4. clean baseline을 같은 입력으로 두 번 실행한다.
5. denominator, oracle, severity, exclusion set을 새 cycle SHA에 결속한다.
6. 가장 큰 측정 오류 한 개만 paired A/B로 개선한다.
7. 수치 통과 후 SOL, Opus, Grok receipt를 동시에 수집한다.

이 문서와 bootstrap 완료만으로 Phase 0 또는 release를 GO로 표시하지 않는다. 새
baseline, denominator, oracle, 반복 측정, 감독 receipt가 모두 없으므로 현재 출하
상태는 `HOLD`다.
