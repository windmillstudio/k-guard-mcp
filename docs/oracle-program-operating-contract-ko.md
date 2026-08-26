# K-Guard Oracle Program Operating Contract

작성일: 2026-07-21

## 북극성

K-Guard는 한국 바이브코더가 출하 전에 호출하는 시니어 감사관과 fail-closed release gate다. 제품의 폭이나 평균 점수로 GO를 주장하지 않는다. 사이트, API, 데이터, 공급망, MCP, 운영 중 하나라도 잠긴 기준을 통과하지 못하면 전체 판정은 HOLD다.

## 현재 상태

완료된 하위 기반:

- package, CLI, MCP stdio, fresh-wheel smoke, 일부 public replay와 evidence hash binding
- OWASP BenchmarkJava/BenchmarkPython materialization tooling
- generated-pair Docker live-replay authority boundary
- Korean PII rules, Korean remediation UX, raw-free evidence envelope
- historical client recordings three cases
- current source, dependency, toolchain, dirty-worktree target baseline receipt
  was sealed again on 2026-07-22; every subsequent corpus result must bind that
  receipt and fail if the target changes during execution
- L2 tmpfs ownership and nonce-bound replay measurement contract, narrowly FIX

부분 완료:

- six local vulnerable apps의 source receipt와 candidate registry가 있고, WebGoat
  IDOR 한 시나리오만 source-bound execution, CWE, CVSS, state-reset evidence를
  모두 결속해 registry candidate `PASS`가 됐다. 나머지 413 candidate와 전체 L2,
  release는 계속 HOLD다.
- WebGoat IDOR 하나는 source-derived image에서 두 번의 `network none` 실행이
  정규화 후 일치하는 execution contract를 통과했고, Claude direct review와
  Grok/GLM packet review에서 `GO_MEASUREMENT_PATCH`를 받았다. 이는 severity,
  scanner finding, TP/FP/FN, release authority가 아닌 실행 재현성 증거다.
- 같은 WebGoat IDOR에는 positive receipt에 결속한 deterministic copied-source
  negative control도 있다. 두 번의 offline run에서 지정된 parent/child 결과가
  일치했지만, 이는 test sensitivity 증거일 뿐 independent upstream fix,
  severity, scanner finding, TP/FP/FN authority는 아니다. r5는 Claude direct
  review와 Grok/GLM packet review에서 `GO_MEASUREMENT_PATCH`를 받아 이 좁은
  execution-sensitivity field만 `FIX`다. L2 overall과 release는 계속 HOLD다.
- WebGoat Missing Function Access Control 하나는 실제 pre-change scanner 기준선에서
  vulnerable/negative 양쪽 모두 0건이었음을 먼저 동결했다. 새 Spring observer는
  정확히 같은 source-bound pair에서 vulnerable 1건, negative 0건을 두 번 동일하게
  재현했다. Claude Opus 4.8, Grok 4.5, Cline GLM-5.2가 같은 target에서 `GO`했고
  receipt validator가 이 **narrow scanner-differential field**만 `FIX`로 판정했다.
  이 결과는 manual-review observation 후보 한 쌍의 증거이며, TP/FP/FN 지표, L2,
  H100, release authority는 아니다.
- 같은 시나리오의 state-reset adapter는 positive와 negative receipt 각각의 두
  cleanup run, 네 unique nonce, owned container와 volume 제거, source-derived
  image 부재를 별도 증거로 재생성한다. 이 증거는 위 한 쌍의 재현성 결속을
  보강하지만 L2 또는 release authority를 만들지 않는다.
- Missing Function Access Control 시나리오도 같은 state-reset adapter를 통해
  execution, negative control, CWE mechanism, cleanup evidence를 한 selector에
  결속했다. 두 registry materialization은 byte-identical했지만 CVSS와 expected
  disposition이 없으므로 candidate와 전체 registry는 계속 `HOLD`다. 이 새
  attachment는 세 외부 감독관이 같은 target에서 검토하기 전까지 `FIX`가 아니다.
- 41-app public source pool은 있으나 100-app stress corpus와 final H100은 없다.
- Guardian, runtime proxy, protocol, SCA, database controls는 regression evidence만 있으며 field/release authority는 없다.

미완료:

- every High/Critical/blocker to one machine oracle scenario
- development generated pairs 60, public stress apps 100, final H100 (generated 80 + public 20)
- measured TP/FP/FN/TN, blind actionability review, observe-to-block promotion, final GO evidence bundle

## L1 전량 기준선 실행

L1은 OWASP BenchmarkJava 2,740건과 BenchmarkPython 1,230건, 총 3,970건을
같은 고정 분모로 두 번 실행하는 공개 개발 기준선이다. 이 단계의 목적은 제품을
통과시키는 것이 아니라, 현재 탐지기에서 어떤 언어·카테고리·후보가 비어 있는지
숫자로 드러내는 것이다.

`scripts/run_l1_baseline.py`는 다음을 강제한다.

- scan 전에 locked L1 manifest, expected-results, LICENSE, 모든 materialized source file의
  hash와 파일 집합을 검증한다.
- Java와 Python을 각각 두 번 스캔하고, source tree가 실행 전후에 같지 않으면
  control HOLD로 끝낸다.
- 공식 3,970건은 지원 여부와 관계없이 `total_case_count`에 남긴다. 현재 규칙에
  매핑되지 않은 카테고리는 정확도 분모에서 조용히 제외하지 않고
  `unsupported_case_count`로 분리한다.
- 매핑된 공식 oracle은 scenario TP/FP/FN/TN으로, 매핑되지 않은 High/Critical 후보는
  `unpaired_candidate_count`로 별도 보관한다. unpaired가 하나라도 있으면
  `one_finding_to_one_oracle_complete=false`이며 승격할 수 없다. 이때
  `labeled_candidate_precision`은 일부 라벨된 후보의 참고값일 뿐이고,
  `candidate_precision_eligible=false`라면 차단 적중률이나 출하 기준으로 사용할 수 없다.
- 결과는 `MEASURED_HOLD`로만 생성된다. exact repeat가 나와도 public development
  benchmark이며, field accuracy와 release GO를 뜻하지 않는다.

실행 전에는 현재 코드와 환경을 새 external receipt로 봉인한다. output 경로는 저장소
밖의 새 디렉터리여야 하고, 기존 evidence를 덮어쓰지 않는다.

```powershell
python scripts/seal_current_baseline.py `
  --output C:\evidence\k-guard\baseline-<run-id>.json

python scripts/run_l1_baseline.py `
  --manifest C:\evidence\k-guard\l1-manifest.json `
  --benchmark-java C:\sources\BenchmarkJava `
  --benchmark-python C:\sources\BenchmarkPython `
  --baseline-receipt C:\evidence\k-guard\baseline-<run-id>.json `
  --output-dir C:\evidence\k-guard\l1-full-baseline-<run-id>
```

이 L1 runner는 현재 `KGuardScanner`의 base static path를 측정한다. Guardian의
Semgrep deep plane, SCA, runtime proxy, DB control은 별도 평면이며 이 결과로
대체하거나 합산하지 않는다. 이 환경에서는 bundled Semgrep executable이 Windows
application control에 의해 시작되지 않았으므로, 우회 실행을 하지 않고 Guardian
deep plane을 계속 control HOLD로 둔다.

## 잠긴 판정 규칙

1. TP/FN ground truth는 vulnerable/fixed execution differential, official expected result, upstream fixed revision, 또는 machine-verified generated pair만으로 정한다.
2. AI supervisor는 ground truth를 정하지 않는다. source-bound evidence의 actionability와 release disposition만 blind review한다.
3. 모든 High/Critical와 release blocker는 location, impact, reproduction, fix, and fix-verification test를 가진 1:1 oracle scenario와 결속한다.
4. 새 규칙은 observe, warn, block 순서로만 승격한다.
5. 기준선, label definition, threshold는 final H100 결과를 본 뒤 변경하지 않는다.
6. final GO는 전체 90/100 이상, macro-plane별 24/25 이상, Critical recall 100%, High/Critical recall 90% 이상, blocker actionability 90% 이상, Wilson 95% lower 80% 이상, exact repeat 100%를 동시에 만족할 때만 가능하다.

## 감독관 운영

| Role | Required model | Invocation contract | Current status |
| --- | --- | --- | --- |
| Implementer | Codex GPT-5.6 SOL | Code, tests, evidence binding. Does not self-approve a field. | Available |
| Supervisor A | `claude-opus-5` | Read-only audit, `--effort max --permission-mode plan`; no write tools. | Required current direct-file lane |
| Supervisor B | `grok-4.6` | Read-only, no-tool single-session audit with `--reasoning-effort xhigh`. Planning, memory, subagents, and web search are disabled. | Required current sanitized-packet lane |

GLM-5.2 completed a no-tool supplied-evidence review for the L2 tmpfs/replay
patch. That result is valid only as an evidence-packet review; it must not be
represented as a direct repository-file audit until an interactive Cline
session can grant read-only tool approval. Provider credentials are never
written into this repository or evidence bundle.

### Verified CLI invocation

2026-07-21의 초기 health check는 세 lane에서 exit 0과 legacy
`{"verdict":"GO","model_check":"healthy","scope":"no-tool-health-check"}`를 반환했다.
그 legacy receipt는 가용성 기록으로만 남기며 supervisor-review receipt나 field
approval로 파싱할 수 없다. 이후 health check는 `status="HEALTHY"`,
`approval=false`를 강제한다. 이 결과는 인증, 실행 파일, 요청-응답 경로의
가용성만 뜻하며 제품 성능이나 특정 변경의 승인은 뜻하지 않는다. 2026-07-22에는
Claude Opus 4.8, Grok 4.5, Cline GLM 5.2의 실제 no-tool 요청-응답을 다시 확인했다.
GLM의 첫 실패는 인증 실패가 아니라 `provider`와 `model`을 분리한 잘못된 CLI
형식이었고, `--model cline-pass/glm-5.2`로 고정해 정상 응답을 확인했다.

이 확인은 아래 도구로 재현한다. tool은 임시 빈 작업 디렉터리에서 source-free
요청을 보내고, provider raw output, reasoning, credential, source를 저장하지 않는다.
Claude CLI 2.1.177은 빈 `--tools` 인자를 거부하므로 Claude lane은 무소스 prompt,
임시 빈 작업 디렉터리, `--permission-mode plan`, `--no-session-persistence`로
실행한다. 이 health check는 외부 모델의 file/tool access를 인증하지 않으며,
그 사실도 receipt claim boundary에 명시한다. 생성되는
`k_guard_external_supervisor_health_receipt.v2`는 의도적으로
`k_guard_supervisor_review_receipts.v5`와 스키마가 달라 field `FIX`나 release
approval로 validator에 넣을 수 없다. `measurement_fingerprint_sha256`은 생성 시각과
출력 경로를 제외한 두 lane의 terminal 상태를 결속한다. 같은 구현 상태에서 두 번
실행한 health receipt는 이 fingerprint가 같아야 하며, 같더라도 가용성만 뜻한다.

```powershell
python scripts/check_external_supervisor_health.py `
  --claude-exe <LOCAL_USER_HOME>\.local\bin\claude.exe `
  --grok-exe <LOCAL_USER_HOME>\.grok\bin\grok.exe `
  --output C:\evidence\k-guard\supervisor-health-<run-id>.json
```

실제 분야 검토에서는 아래 형태를 사용하고, 응답의 최종 verdict만 evidence에 보존한다.
추론 이벤트, 인증 정보, raw source와 raw finding은 보존하지 않는다.

```powershell
claude --print $prompt --model claude-opus-5 --effort max --verbose --output-format stream-json `
  --json-schema $schema --permission-mode plan --allowedTools Read --max-turns 100

grok --single $prompt --model grok-4.6 --json-schema $schema `
  --disable-web-search --no-subagents --no-memory --no-plan `
  --reasoning-effort xhigh --permission-mode plan
```

반복되는 수동 wrapper를 쓰지 않는다. `scripts/execute_supervisor_review.py`는
동일 target, operator-approved payload-manifest SHA, artifact path/hash, sanitized packet,
test attestation을 먼저 묶고 두 lane을 병렬 실행한다. Claude에는 manifest에 고정된
repository-relative 파일과 저장소 밖 raw-free receipt만 `Read` direct-files 검토로
보내고, Grok에는 absolute path나 파일 원문을 제거한 identifier/hash packet만 보낸다. reasoning event, provider raw
output, credential, source는 저장하지 않으며 terminal decision 하나가 아니면
fail-closed한다.

두 lane은 같은 일을 했다고 주장하지 않는다. Claude Opus는 source-direct verifier이며,
모든 지정 파일의 성공한 `Read` tool result가 있을 때만 direct-files receipt를 낸다.
Grok 4.6은 raw-free evidence auditor다. 그 `GO`는 packet 안의 모델 고정,
approved payload manifest, path-bound artifact manifest, target, Claude direct-review 요구사항, test attestation, repeatability
계약이 서로 결속됐다는 판단이지 소스 코드를 직접 읽었다는 뜻이 아니다.

approved payload manifest는 현재 target과 claim boundary, Claude/Grok exact model·effort·tool
policy, repository direct file, external raw-free receipt, 각 byte count/SHA-256, 전체
direct-file-set SHA-256을 고정한다. manifest 본문의 `transmission_authorized=false`는 payload
자체가 자기 권한을 만들지 못하게 하는 값이며, runner 명령의 별도
`--operator-approved-manifest-sha256`가 실제 file SHA와 같을 때만 실행된다. generated
evidence manifest와 review packet은 이 approved-manifest SHA를 다시 포함한다. artifact는
generic label만 남기지 않고 repository file이면 상대경로까지 결속한다. external receipt의
absolute path는 Claude Read 명령에만 쓰고 Grok packet과 canonical receipt에는 넣지 않는다.

terminal receipt의 필수 결정 필드는 `verdict`, `blocker_count`,
`nonblocking_count`, `claim_boundary_confirmed`, `blocker_codes`, `nonblocking_codes`다.
코드는 미리 정한 provenance, claim-boundary, repeatability, raw-free, model-pinning,
direct-review, terminal-contract, test-attestation 범주만 쓸 수 있고 각 배열 길이는
해당 count와 같아야 한다. 서로 다른 결함이 같은 범주이면 코드는 반복될 수 있다.
`finding_summary`와 provider가 붙인 추가 설명은 receipt에
저장하거나 판정에 사용하지 않는 advisory이며, 결정 필드·code·일관성이 하나라도
어긋나면 fail-closed한다.

```powershell
python scripts/execute_supervisor_review.py `
  --output-dir C:\evidence\k-guard\field-review-<run-id> `
  --field-id <narrow-field-id> `
  --claim-boundary "<non-promoting narrow claim>" `
  --review-question "<question>" `
  --direct-file scripts\changed-file.py `
  --external-direct-file focused-receipt=C:\evidence\focused-receipt.json `
  --artifact implementation=scripts\changed-file.py `
  --artifact focused-receipt=C:\evidence\focused-receipt.json `
  --approved-payload-manifest C:\evidence\approved-payload-manifest.json `
  --operator-approved-manifest-sha256 <exact-approved-file-sha256> `
  --focused-summary "<focused command: pass count>" `
  --full-regression-summary "python -m pytest -q: pass/skip count" `
  --repeat-summary "<two-run semantic repeat evidence>" `
  --focused-passed --full-regression-passed
```

이 runner가 만든 `k_guard_supervisor_review_receipts.v5` bundle만 receipt validator의
입력이 될 수 있다. health receipt는 여전히 가용성 확인일 뿐이며, 이 runner로
실행한 두 감독관의 `GO`와 같은 target 결속을 대신하지 못한다.

`--repeat-exact`는 의도적으로 제공하지 않는다. runner 한 번의 결과는 unpromoted
baseline이며 `repeat_exact=false`로만 기록된다. 같은 target·manifest·packet·direct-file
binding에서 나온 두 baseline을 `scripts/compare_supervisor_review_repeats.py`로 비교한다.
두 run이 모두 two-lane `GO`, preflight/target-unchanged, raw-free 조건을 만족하고 semantic
fingerprint가 같을 때만 comparator가 이 좁은 field에 `FIX`를 낸다. 그 `FIX`도 oracle,
성능 지표, H100, release를 승인하지 않는다.

baseline의 terminal `GO`는 field 승인과 다르다. baseline은 두 AI가 다른 material
blocker가 없음을 `GO`로 확인하면서도, 각 receipt에 `REPEATABILITY_GAP` 하나를
nonblocking으로 기록해야 한다. runner status는 계속 `HOLD`다. 두 baseline이 그 코드까지
완전히 일치할 때만 comparator가 field `FIX`를 낸다. 따라서 반복 미완료를 조용히 통과시키지
않고, 반대로 반복을 만들기 위한 관찰 run 자체를 불가능하게도 만들지 않는다.

```powershell
python scripts/compare_supervisor_review_repeats.py `
  --run-a C:\evidence\k-guard\field-review-a `
  --run-b C:\evidence\k-guard\field-review-b `
  --output C:\evidence\k-guard\field-repeat-comparison.json
```

과거 v4 replay에서 Cline의 `$prompt`는 stdin이 아니라 위치 인수였고 JSON event
stream의 terminal decision 하나만 채택했다. 이 legacy parser는 과거 영수증 검증을
위해 보존하지만 새 v5 review에서 Cline을 호출하지 않는다. Claude direct-files lane은 `stream-json`의
성공한 `Read` tool result를 메모리에서만 지정 repository/external 파일의 resolved path 집합과 대조한다. receipt에는
원문·absolute path·tool result를 저장하지 않고, 지정 파일 수와 identifier 집합 hash만 남긴다.
이 대조가 하나라도 빠지면 `BLOCKED`이며 자기신고 문구로 대체할 수 없다.
Claude stream의 final text가 설명과 terminal JSON을 함께 내는 경우에는 완전한 required
decision field를 가진 JSON object가 정확히 하나일 때만 그것을 채택한다. 두 개 이상,
없음, 필드 불일치는 모두 fail-closed다. Grok terminal은 이 recovery를 쓰지 않는다.

### Baseline 재봉인

새 corpus campaign이나 다음 detector 변경 전에 현재 상태를 한 번 봉인한다. receipt는
저장소 밖의 evidence 경로에만 쓴다. 저장 과정이 worktree를 바꾸어 검토 target을
자기오염시키지 않도록 하기 위해서다.

```powershell
python scripts/seal_current_baseline.py `
  --output C:\evidence\k-guard\baseline-<run-id>.json

python scripts/seal_current_baseline.py `
  --validate C:\evidence\k-guard\baseline-<run-id>.json

python scripts/seal_current_baseline.py `
  --validate-current C:\evidence\k-guard\baseline-<run-id>.json
```

이 receipt는 HEAD, content-bound dirty worktree fingerprint, analyzer package tree,
build/evidence lockfile hash, Python/Git/Pytest/Docker와 핵심 dependency version을
canonical JSON으로 결속한다. performance, TP/FP/FN, release의 증거는 아니며,
동일 상태에서 byte-exact하게 반복되고 내용이 바뀌면 새 receipt가 필요하다.
`--validate`는 과거 receipt의 형식과 hash만 검사하고, `--validate-current`는 현재
worktree와 실제 tool/dependency 환경까지 다시 계산해 오래된 receipt 재사용을 거부한다.

### 분야별 감독관 실행 절차

각 개선은 아래 순서를 벗어나지 않는다. 넓은 기능을 추가한 뒤 나중에 한꺼번에
검증하지 않는다.

1. Codex는 한 오류군, 한 claim boundary, 한 target revision, 한 예상 측정
   변화를 먼저 기록한다. target은 `head_git_oid`, `dirty_path_set_sha256`,
   `dirty_worktree_sha256`의 세 값으로 고정한다. 마지막 값은 Git diff와
   untracked 파일 상태를 content-bound fingerprint로 묶은 값이다.
2. focused test, full regression, 두 번의 필요한 재현 실행, evidence manifest를
   만든다. sanitized review packet의 canonical SHA-256도 함께 만든다. 실제
   claim에 필요한 것이 아니면 외부 모델에 보내지 않는다.
3. Claude Opus 5와 Grok 4.6에게 같은 sanitized packet을 각각 보낸다. packet은 target
   commit 또는 dirty-patch hash, changed-file list, 실행 명령과 exit code,
   artifact hash, claim boundary, 남은 위험만 포함한다.
4. 각 감독관은 `GO`, `HOLD`, `BLOCKED` 중 하나, material blocker, nonblocking
   risk, 검토 범위를 반환한다. 외부 모델의 의견은 oracle label이나 합격선을
   바꾸지 못한다.
5. Codex는 blocker를 고치거나 HOLD로 보존한다. 두 lane이 같은 target, evidence
   manifest, review packet을 `GO`로 검토하고 현재 직접 파일 검토가 인증된
   Claude lane 하나 이상이 `direct-files` scope이기 전에는 그 분야를 `FIX`로
   쓰지 않는다. Grok의 direct-files capability를 추가하려면 H100 전에
   별도 capability receipt와 이 contract의 명시적 변경이 필요하다.

감독관 응답은 다음과 같이 최소화해 보관한다. provider의 raw reasoning, token
stream, credential, raw source/finding은 증거에 넣지 않는다.

```json
{
  "provider": "claude|grok",
  "model": "pinned exact model id",
  "review_scope": "direct-files|sanitized-packet|unavailable",
  "target": {
    "head_git_oid": "40 lower hex Git object ID",
    "dirty_path_set_sha256": "64 lower hex",
    "dirty_worktree_sha256": "64 lower hex content-bound worktree fingerprint"
  },
  "evidence_manifest_sha256": "...",
  "review_packet_sha256": "...",
  "verdict": "GO|HOLD|BLOCKED",
  "blocked_reason": "null|BLOCKED_PROVIDER|BLOCKED_AUTH|BLOCKED_RATE_LIMIT|BLOCKED_TIMEOUT",
  "blocker_count": 0,
  "nonblocking_count": 0,
  "claim_boundary_confirmed": true,
  "raw_returned": false
}
```

후보의 두 receipt는 반드시
`k_guard_supervisor_review_receipts.v5` bundle로 묶고, 아래 validator가
기계적으로 해석한다. health check JSON, 모델의 raw text, reasoning stream은 이
입력으로 사용할 수 없다.

```powershell
python scripts/validate_supervisor_review_receipts.py --receipts <canonical-receipts.json>
```

### Review prompt contract

Every external supervisor receives only the target commit, changed-file list, test commands/results, evidence-manifest hashes, and claim boundaries. The prompt must require one of `GO`, `HOLD`, or `BLOCKED`, material findings with file/line evidence, and residual risk. It must prohibit code edits, active probing, label changes, threshold changes, and raw sensitive-data output.

### Temporary availability rule

An unavailable supervisor is recorded as `BLOCKED_PROVIDER`, `BLOCKED_AUTH`, `BLOCKED_RATE_LIMIT`, or `BLOCKED_TIMEOUT` with timestamp, model request, sanitized error class, target commit, and evidence hash.

- A field may continue to the next **non-promoting** measurement step only when focused and full regression pass, no supervisor returned `HOLD`, and at least one external supervisor returned `GO`.
- An unavailable supervisor is represented by a `BLOCKED` receipt with its exact blocked reason. If even one required lane is unavailable, times out, or lacks the required review scope, the field is `TEMPORARY_PENDING_REVIEW`, never final `FIX`.
- `TEMPORARY_PENDING_REVIEW` cannot count as a fixed field, scorecard achievement, sample quota, H100 input, performance metric, release prerequisite, or rule-promotion evidence. It only permits the next non-promoting measurement step.
- A field becomes `FIX` only when the machine validator sees all of the following on the same unchanged target: Claude `claude-opus-5` and Grok `grok-4.6` each return `GO`; both bind the identical `head_git_oid`, `dirty_path_set_sha256`, `dirty_worktree_sha256`, evidence-manifest SHA-256, and review-packet SHA-256; focused/full/repeat attestation passes; and Claude's `GO` receipt is `direct-files`. A previously unavailable lane must review the unchanged target before the field can be FIX.
- A `FIX` field still cannot change oracle labels, TP/FP/FN metrics, H100, or product release by itself. Final product GO requires both supervisor lanes and every separate numerical gate, unless the product contract is explicitly changed before H100 preregistration.

## Execution order

1. Re-seal the current source baseline: HEAD, dirty-patch hash, analyzer hash, tool versions, and environment receipt.
2. Pre-register severity, four 25-case macro planes, corpus membership, 1:1 oracle IDs, expected dispositions, and all H100 exclusions.
3. Complete L2 oracle admission for the six local apps before detector changes. No candidate without a machine oracle enters TP/FN metrics.
4. Materialize and verify L1 full benchmarks, 60 development generated pairs, and 100 public stress apps.
5. Run two fresh baseline executions. Bind reports, coverage receipts, runtime limits, and repeat hashes.
6. Score TP/FP/FN/TN mechanically, then submit only actionability/release evidence to supervisors.
7. Select the single highest weighted error bucket. Change only that bucket on development data, run paired A/B, and promote observe to warn to block only on passing evidence.
8. Freeze the candidate revision. Run the blinded H100 once; a second execution can verify exact reproducibility but cannot alter labels, rules, or the scored result.
9. Produce the final evidence bundle and evaluate GO/HOLD.

## First implementation target

The first field is L2 oracle admission, not a new detector. The current registry has 414 candidates and one admitted WebGoat scenario. The work is to make the six local applications produce complete, source-bound, resettable oracle records with one finding-to-one-scenario mapping. This is the shortest path to trustworthy TP/FN measurement and prevents more feature work from widening an unmeasured system.
