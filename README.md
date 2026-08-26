# K-Guard MCP

> **안경선배 · 바이브코딩 선배**
>
> 만드는 흐름은 끊지 않고, 출하는 대충 넘기지 않습니다.

K-Guard MCP는 바이브코딩 결과물을 출하하기 전에 **사이트, API 노출, 데이터 관리, 운영 위험**을 함께 검수하는 로컬 우선 MCP 감사관입니다. Guardian은 문제가 없는 것과 아직 보지 못한 것을 구분하고, `출하 가능 / 고치고 출하 / 검수 범위 부족` 판정과 다음 행동을 한국어로 돌려줍니다.

K-Guard는 인간의 사업 판단이나 법률 검토를 대신하는 보증서가 아닙니다. 시니어 개발자가 출하 전 묻는 질문과 fail-closed 게이트를 자동화합니다.

[5분 설치](docs/quickstart-ko.md) · [설치·디자인 검증](docs/mcp-design-validation-ko.md) · [사용 가이드](docs/usage-guide-ko.md) · [GitHub 공개 안내](docs/github-publication-ko.md) · [필수 qualification](docs/release-qualification-ko.md) · [제품 북극성](docs/product-north-star-ko.md) · [전체 도그푸드 판정](docs/dogfood-ship-assessment-2026-07-15-ko.md) · [2026 대회 출품 준비](docs/contest-2026-submission-ko.md)

## 첫 5분: 현재 소스 체크아웃

아직 공개 패키지 인덱스 배포를 전제로 하지 않습니다. 처음 실행할 때는 저장소 루트에서 현재 소스를 설치하고, 안경선배가 보여주는 다음 행동을 따라갑니다.

```powershell
python -m pip install .
k-guard install --client auto --profile local-dev --workspace .
k-guard doctor --client auto
```

`auto`는 설치된 Grok, Codex, Antigravity를 찾아 사용자 범위에 `k-guard` MCP를 병합하고, OpenAI `tunnel-client`가 있으면 ChatGPT용 로컬 profile을 준비합니다. `--workspace .`은 지금 프로젝트를 private binding으로 고정합니다. 이후 MCP가 다른 working directory에서 시작돼도 이 프로젝트를 검사하며, 경계 밖 경로는 high HOLD로 거부합니다. ChatGPT doctor/run에는 Tunnels Read + Use 권한의 `CONTROL_PLANE_API_KEY`도 현재 셸에 필요합니다. ChatGPT는 그 뒤 `tunnel-client run`과 개발자 모드 앱 연결이 남으므로 설치기는 성공으로 꾸미지 않고 `부분 연결 · 다음 단계 필요`를 반환합니다. 기존 설정은 보존하고 JSON 변경 전에는 백업을 만들며, 운영자 evidence key와 workspace 원문은 `~/.k-guard`의 사용자 전용 파일에만 저장합니다. `local-dev`는 localhost read-only probe와 작은 고정 심화 경로만 켜며 외부·세션 probe는 계속 꺼 둡니다. 정적 검사만 필요하면 `--profile workspace`를 사용합니다.

설치와 진단의 기본 출력은 `연결 준비 → AI 클라이언트 → 다음 행동` 세 단계다. 자동화는 `install --json`, `doctor --json`을 사용합니다. 공모전 심사·릴리스 재현과 코드 수정은 [5분 설치의 심사·재현 검증 경로](docs/quickstart-ko.md)를 사용해 build·evidence lock을 `--require-hashes`로 설치합니다. Semgrep `1.174.0`과 `pip-audit` `2.10.1`도 각각 `requirements-semgrep.lock`, `requirements-pip-audit.lock`의 전체 hash closure를 격리 venv에 설치해 감사 대상 런타임을 변형하지 않습니다.

MCP 클라이언트에서:

```text
안경선배로 이 앱을 끝까지 봐줘. check_my_app으로 전체 검수를 시작하고,
continue_review를 state=completed 또는 failed가 될 때까지 반복해줘.
완료 전에는 통과라고 말하지 마. 코드를 고쳤다면 check_my_app을 다시 완료해줘.
출하 전에는 실제 사업 목적과 범위를 확인한 뒤 최신 review_id로
start_review_before_ship을 실행하고 다시 continue_review로 Guardian 완료까지 기다려줘.
experience.presentation 순서대로 판정, 이유, 다음 행동 3개만 먼저 말해줘.
```

`check_my_app`은 5초 안에 대충 끝내는 검사가 아니라 전체 워크스페이스 감사를 접수하는 도구입니다. 첫 응답은 `review_in_progress`이며 `continue_review`가 완료될 때까지 출하 판단을 내리지 않습니다. `dist`, `build`, `.next`의 배포용 텍스트 산출물도 검사하고, 후보 개수·경로 SHA-256·읽기 완료가 맞지 않으면 high로 막습니다. 완료 결과는 workspace와 source tree SHA-256에 묶인 `review_receipt`를 냅니다. 코드가 바뀌면 예전 `review_id`로 출하 검수를 시작할 수 없고 `check_my_app`을 다시 완료해야 합니다.

## 안경선배 판정

| 코드 | 뜻 | 다음 행동 |
|---|---|---|
| `ship` | 설정한 범위와 high 기준에서 출하 가능 | 같은 커밋의 보고서와 증거 보관 |
| `hold_fix` | blocking finding 존재 | `suggest_fix` 후 같은 게이트 재실행 |
| `hold_coverage` | 동적 검사·흐름·목적·범위 증거 부족 | 빠진 검수 영역부터 채우기 |
| `hold_authority` | 단일 앱 결속·운영자 서명 증거 부족 | 동일 `app_id`와 `K_GUARD_EVIDENCE_HMAC_KEY`로 재실행 |
| `hold_qualification` | 앱 위험과 별개로 감사 도구의 deep·SCA·runtime·DB·field 자격 증거 부족 | `application_assurance`와 `auditor_qualification`을 분리해 확인 |
| `review_only` | 검토용 보고서만 생성 | `fail_on=high`로 출하 판정 실행 |

모든 대표 결과는 `experience.presentation`과 호환 alias인 `experience.details.presentation`을 함께 제공하며 순서는 `verdict → why → next_actions → details`로 고정됩니다. Guardian은 앱 위험을 `application_assurance`, 감사 도구 자체의 검증 상태를 `auditor_qualification`로 따로 보여줍니다. `experience.verdict_code`, `experience.verdict_message`, `experience.summary`는 기존 보고서 호환 필드입니다.

## 무엇을 보나

K-Guard combines:

- Static scan: Korean PII, composite PII, Korean organization identifiers (사업자등록번호 checksum syntax validation; 법인등록번호 historical Annex checksum or post-2025-01-31 4+2+7 explicit-context/syntax recognition, not live registry validation), secrets
- Config scan: CORS/debug/source map/env prefix risks
- Senior app-risk scan: direct request-to-SQL/command/file/URL/HTML sinks, mass assignment, open redirect, browser token storage, weak cookies, plaintext password comparison, and JWT decode-without-verify
- Korean data-governance scan: unique/sensitive field declarations, encryption/access-control evidence, access logging, external processor review, retention, and erasure
- MCP-native threat scan: hidden instructions, tool poisoning, exfiltration intent, and overbroad local access across direct text plus bounded Unicode/confusable, escaped/percent/HTML, Base64, split-fragment, and three-line rolling normalization
- Structured MCP config review: shell wrappers, mutable package launchers, plain remote HTTP, fixed credentials, unsafe links/read failures, and fail-closed discovery bounds across project/Codex/Grok/Antigravity config candidates
- YARA-lite local rule pack: prompt-injection markers, exfil command markers, Korean bulk schema hints
- Safe dynamic probe: localhost HTTP checks, explicitly authorized external-origin checks, optional bounded deep exposure checks, plus optional user-provided read-only session headers
- Data Flow Risk Map: heuristic graph plus Python AST and lightweight JS/TS source -> sink taint analysis, including unique-import Python helper parameter-to-sink summaries and limited JS/TS route-to-service IDOR summaries
- MCP runtime observer/interceptor: JSON/JSONL and stream-ready event checks for hidden instruction, PII-to-agentic/external sink flow, plus batch block/redact enforcement for forwarded event streams
- Semgrep deep adapter: offline 40-rule profile, exact scanned-target proof, pinned `1.174.0` identity, source snapshot binding, and fail-closed JS/TS/Python/Java/Kotlin/Go/PHP/Ruby/C# findings
- Nine-language validation pack: Python/JavaScript/TypeScript/Java/Kotlin/Go/PHP/Ruby/C# 90 pinned vulnerable/clean cases, TP/FN/FP/TN scoring, and exact two-run fingerprint reproduction
- Software composition analysis: bounded Python/npm/Go manifest and lock coverage with `pip-audit`, `npm audit`, and `govulncheck`; partial engine, lock, output, or source-drift failure blocks release
- Streamable HTTP MCP proxy: POST/GET SSE/DELETE complete mediation, principal-bound lifecycle, default-deny JIT/JEA grants, filtered tool inventory, bounded streams, and HMAC-chained raw-free audit logs
- Database controls: SQLGlot AST allowlist, role/database/schema/table/column RBAC, EXPLAIN-before-read, SQLite query-only authorizer, path containment, and row/cell/result/time budgets
- Read-only connectors: local SQLite, log, JSON/CSV/TSV storage sampling without raw value storage; connector gaps become high findings
- Retention/deletion review: flags missing retention/deletion markers when personal-data signals exist
- Cross-plane verdicts: correlates Korean PII findings with LLM/MCP/external/data-at-rest sink evidence
- FP/FN scoreboard: fixture corpus recall and false-positive rate. FPR uses `measurable_negative_count` as denominator (clean negatives with no `expected_absent`); `negative_count` is all declared negatives and `targeted_absence_case_count` covers selected-rule absences that do not enter the FPR denominator. A zero measurable-negative denominator is reported as FPR 0.0.
- SARIF/CI output: fail builds on configured severities
- `korean_senior` Guardian profile: fail-closed four-domain contract for site security, API exposure, data management, and operational risk
- Primary MCP tools: `check_my_app`, `continue_review`, `start_review_before_ship`; internal canonical engine: Guardian high; guided prompt: `guided_review`
- Advanced MCP tools: `scan_workspace`, `deep_analyzer_audit`, `validate_multilang_pack`, `software_composition_audit`, `validate_policy_controls`, `validate_streamable_http_runtime`, `scan_text`, `scan_diff`, `scan_mcp_config`, `probe_http`, `build_flow_map`, `observe_mcp_events`, `enforce_mcp_events`, `observe_mcp_event`, `score_fixture_corpus`, `data_release_gate`, `create_field_campaign_template`, `field_campaign_status`, `guardian_audit`, `explain_rule`, `suggest_fix`, `security_gate`

## 설치 경계

release workflow가 만든 정확한 wheel과 함께 배포된 `requirements-evidence.lock`을 받은 사용자는 저장소 없이 아래처럼 감사된 dependency closure를 재현할 수 있습니다. `k-guard`, `k-guard-dashboard`, `k-guard-mcp`, `python -m k_guard_mcp.cli`, `python -m k_guard_mcp.server`는 설치된 wheel의 명령입니다.

release에는 `SHA256SUMS`, GitHub OIDC로 서명된 SLSA provenance bundle, CycloneDX SBOM attestation bundle도 포함됩니다. 온라인에서는 `gh attestation verify ./k_guard_mcp-0.1.0-py3-none-any.whl -R OWNER/REPOSITORY`로 빌드 주체와 digest를 확인한 뒤 설치합니다. checksum만 맞고 attestation이 검증되지 않으면 공식 release artifact로 취급하지 않습니다.

```bash
python -m pip install --require-hashes -r ./requirements-evidence.lock
python -m pip install --no-deps ./k_guard_mcp-0.1.0-py3-none-any.whl
k-guard --help
k-guard install --client auto --profile local-dev --workspace .
k-guard doctor --client auto
```

Windows 애플리케이션 제어 정책이 `pip`의 `k-guard.exe` 콘솔 런처를 차단하는 관리형 PC에서는 같은 wheel의 모듈 진입점을 사용합니다. 기능과 판정 계약은 동일합니다.

```powershell
python -m k_guard_mcp.cli --help
python -m k_guard_mcp.cli install --client auto --profile local-dev --workspace .
python -m k_guard_mcp.cli doctor --client auto
```

wheel만 설치하면 런타임 명령만 제공됩니다. release sdist와 저장소 체크아웃에는 `scripts/...`, `tests/fixtures/...`, 검증 템플릿이 포함됩니다. 개발 환경은 저장소 루트에서 두 lock을 `--require-hashes`로 설치한 뒤 `python -m pip install --no-build-isolation --no-deps -e .`로 준비합니다. evidence lock은 릴리스 dependency closure의 버전과 허용 SHA-256을 함께 고정하며, 라이선스·취약점·SBOM·fresh-wheel smoke가 같은 파일을 사용합니다.

## 안경선배 검수실

권한 있는 사이트를 화면에서 확인하려면 로컬 대시보드를 실행합니다.

```bash
k-guard-dashboard --port 8765
```

브라우저에서 `http://127.0.0.1:8765/`를 엽니다. 화면은 `선배 판정 → 발견 → 검사 로그 → 노출 지도` 순서이며, 최종 출하 권한은 화면이 아니라 MCP의 `start_review_before_ship`에만 있습니다. 브랜드 이미지는 프로젝트용으로 생성한 원본 자산이며 provenance는 `docs/brand-assets.md`에 기록합니다.

## 설치된 wheel CLI

아래 명령 중 `tests/fixtures/korean_fixture_corpus.json`은 **소스 체크아웃에서 바로 실행할 수 있는 공개 예제 corpus**입니다. wheel만 설치한 사용자는 같은 스키마의 자체 fixture 경로로 바꿉니다.

```bash
python -m k_guard_mcp.cli scan .
python -m k_guard_mcp.cli scan . --json report.json --markdown report.md
python -m k_guard_mcp.cli scan . --sarif k-guard.sarif --fail-on high
python -m k_guard_mcp.cli probe http://localhost:3000
python -m k_guard_mcp.cli probe http://localhost:3000 --deep-active
python -m k_guard_mcp.cli probe http://localhost:3000 --session-file session.headers.json --json
python -m k_guard_mcp.cli probe https://staging.example.com --allow-external --authorization-note "owned staging domain" --json
python -m k_guard_mcp.cli flow . --svg flow.svg --html flow.html
python -m k_guard_mcp.cli observe-mcp --events mcp-events.jsonl --json
python -m k_guard_mcp.cli mcp-proxy --report mcp-proxy-report.json --response-timeout 30 -- python -m your_upstream_mcp_server
python -m k_guard_mcp.cli mcp-http-proxy --upstream http://127.0.0.1:9000/mcp --port 8765 --report mcp-http-proxy.json --receipt-log mcp-http-proxy.receipts.jsonl
python -m k_guard_mcp.cli deep-analyze . --output deep-analyzer.json
python -m k_guard_mcp.cli language-validate --output language-validation.json
python -m k_guard_mcp.cli sca . --output sca.json
python -m k_guard_mcp.cli control-validate --output control-validation.json
python -m k_guard_mcp.cli runtime-validate --output runtime-validation.json
python -m k_guard_mcp.cli access-policy-template --output access-policy.json
python -m k_guard_mcp.cli agent-grant --policy access-policy.json --output agent.jwt --app-id APP --session-id SESSION --purpose RELEASE_REVIEW --subject AGENT --role release-reviewer --method tools/list --method tools/call --tool check_my_app --tool start_review_before_ship
python -m k_guard_mcp.cli score-corpus --corpus tests/fixtures/korean_fixture_corpus.json --output fixture-metrics.json --json
python -m k_guard_mcp.cli benchmark-template --output benchmarks/field-benchmark-template.csv
python -m k_guard_mcp.cli benchmark --manifest benchmarks/field-benchmark-template.csv --output field-benchmark.json --markdown field-benchmark.md --html field-benchmark.html
python -m k_guard_mcp.cli guardian-template --output benchmarks/guardian-targets.csv
python -m k_guard_mcp.cli suppression-template --output .k-guard/suppressions.csv
python -m k_guard_mcp.cli field-campaign-template --output benchmarks/field-app-roster.csv
python -m k_guard_mcp.cli field-campaign-status --roster benchmarks/field-app-roster.csv --output field-campaign-status.json
python -m k_guard_mcp.cli field-validation-template --ground-truth-output benchmarks/field-ground-truth.csv --review-output benchmarks/field-review.csv
python -m k_guard_mcp.cli field-validation-sign --ground-truth benchmarks/field-ground-truth.csv
python -m k_guard_mcp.cli field-validation-preregister --roster benchmarks/field-app-roster.csv --ground-truth benchmarks/field-ground-truth.csv --custodian-id split-custodian-a --output benchmarks/field-preregistration.json
python -m k_guard_mcp.cli guardian --manifest benchmarks/guardian-targets.csv --output guardian-report.json --markdown guardian-report.md --html guardian-report.html
python -m k_guard_mcp.cli guardian --manifest benchmarks/guardian-targets.csv --suppressions .k-guard/suppressions.csv --fail-on high --run-probes --run-sca --language-validation-report language-validation.json --mcp-http-proxy-report runtime-validation.json --control-validation-report control-validation.json --field-validation-report field-validation.json --output guardian-gate.json
python -m k_guard_mcp.cli field-validation-queue --guardian-report guardian-gate.json --output benchmarks/field-review.csv
python -m k_guard_mcp.cli field-validation-sign --review benchmarks/field-review.csv
python -m k_guard_mcp.cli field-validation-report --guardian-report guardian-gate.json --repeat-guardian-report guardian-gate-repeat.json --roster benchmarks/field-app-roster.csv --ground-truth benchmarks/field-ground-truth.csv --review benchmarks/field-review.csv --preregistration benchmarks/field-preregistration.json --profile field --output field-validation.json
python -m k_guard_mcp.cli mcp-intercept --events mcp-events.jsonl --forwarded-output forwarded.jsonl --report intercept-report.json --app-id YOUR_APP_ID --session-id RELEASE_SESSION_ID --guardian-report guardian-gate.json --fail-on-block
python -m k_guard_mcp.cli data-release-gate --guardian-report guardian-gate.json --guardian-manifest .k-guard/guardian-targets.csv --validation-source-guardian-report validation-source-guardian.json --validation-repeat-guardian-report validation-source-guardian-repeat.json --validation-report field-validation.json --validation-review benchmarks/field-review.csv --validation-ground-truth benchmarks/field-ground-truth.csv --validation-preregistration benchmarks/field-preregistration.json --validation-roster benchmarks/field-app-roster.csv --korean-fixture-corpus tests/fixtures/korean_fixture_corpus.json --korean-corpus-report fixture-metrics.json --mcp-intercept-report intercept-report.json --mcp-forwarded-output forwarded.jsonl --output data-release-gate.json
```

`session.headers.json` is short-lived and bound to one exact origin. Guardian only counts an authenticated comparison as complete when the asserted identity response also matches:

```json
{
  "origin": "http://localhost:3000",
  "expires_at": "2026-07-14T12:30:00+09:00",
  "headers": {"Cookie": "session=<local-test-session>"},
  "identity_assertion": {
    "path": "/api/me",
    "expected_status": 200,
    "expected_body_sha256": "<64 lowercase hex characters>"
  }
}
```

Keep the file inside the invoked workspace, or beside the Guardian manifest. Files outside that boundary, links, expired sessions, mismatched origins, unsupported headers, and oversized files fail closed. The digest covers the exact bounded response bytes before UTF-8 decoding; raw session values and response bodies are not written to findings.

## 소스 체크아웃 전용 검증

아래 `scripts/**`와 pytest는 wheel에 포함되는 사용자 명령이 아닙니다.

```bash
python -m pytest -q
python scripts/site_scale_calibration.py
python scripts/deep_probe_synthetic_calibration.py --targets 500 --output tmp/deep-probe-synthetic-500.json --markdown tmp/deep-probe-synthetic-500.md --html tmp/deep-probe-synthetic-500.html
python scripts/inner_core_product_gate.py --targets 500 --output tmp/inner-core-product-gate-500.json --markdown tmp/inner-core-product-gate-500.md --html tmp/inner-core-product-gate-500.html
python scripts/mcp_evasion_calibration.py --output evidence/regression/mcp-evasion-normalization.json
python examples/contest-demo/v1/demo.py run
python scripts/contest_readiness.py --output contest-readiness-report.json --markdown contest-readiness-report.md
python scripts/build_top_domain_manifest.py --output datasets/tranco-passive-homepage-10k.csv --limit 10000
python scripts/passive_homepage_calibration.py --targets datasets/tranco-passive-homepage-10k.csv --output reports/passive-homepage-10k-summary.json --checkpoint-jsonl reports/passive-homepage-10k-checkpoint.jsonl --max-targets 10000 --delay-ms 500
```

Coverage gate의 `90.00%`는 statement와 branch opportunity를 함께 계산한 branch-inclusive combined coverage입니다. branch 자체가 90%라는 뜻이 아니며, `precision=2`와 `fail_under=90`을 사용하므로 `89.90%`는 실패합니다.

## 소스 체크아웃 Release Hygiene

Use the release hygiene check before CTO review or publish prep:

```bash
python scripts/release_hygiene.py --json
```

Default mode validates that a dirty release-candidate worktree is classified, free of visible runtime scratch output, and free of unresolved review-required artifacts. Use `--strict-clean` after the intended release commit; strict mode also compares every package build input byte with its Git index blob. Tagged publication additionally requires `--expected-tag v{project.version}`. The release workflow waits for the reusable Windows/macOS/Linux CI matrix, creates attestations, and publishes the tag artifacts as a GitHub Release. Details are in `docs/release-hygiene.md`.

The Guardian Actions template currently installs the exact K-Guard source checkout selected by the workflow commit; it does not assume a PyPI package. Before copying it to another repository, vendor K-Guard at a commit-pinned path and set `K_GUARD_SOURCE_PATH`. After release artifacts exist, consumers should pin either an exact wheel plus its published SHA-256, or a full 40-character Git commit in a direct-reference requirement. Replace the placeholders only with an actual release location:

```text
k-guard-mcp @ https://<artifact-host>/<exact-wheel>.whl#sha256=<published-sha256>
k-guard-mcp @ git+https://<repository-url>.git@<40-character-commit>
```

K-Guard's primary license is MIT. Apache-2.0 upstream attribution, reviewed
revisions, modified-file mapping, and excluded license boundaries are recorded
in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
[docs/upstream-adoption.md](docs/upstream-adoption.md).

## MCP

```bash
python -m pip install --require-hashes -r requirements-build.lock
python -m pip install --require-hashes -r requirements-evidence.lock
python -m pip install --no-build-isolation --no-deps .
k-guard-mcp
```

MCP `probe_http` is disabled by default. Enable it only for trusted audit sessions:

```bash
K_GUARD_MCP_ENABLE_PROBE=1 python -m k_guard_mcp.server
```

Authenticated read-only probing through MCP also requires `K_GUARD_MCP_ENABLE_SESSION_PROBE=1` and a short-lived, origin-bound local `session_file`. Header values are read locally and are not written to findings. A header alone never proves login: Guardian requires the optional `identity_assertion` to match before authenticated comparison coverage can pass.

Bounded deep active probing through MCP also requires `K_GUARD_MCP_ENABLE_DEEP_ACTIVE_PROBE=1` and `probe_http(..., deep_active=true)`. This mode checks a small fixed list of exposed env/git/backup/debug paths and still avoids login attempts, mutations, fuzzing, and exploit payloads.

Authorized external probing through MCP also requires `K_GUARD_MCP_ENABLE_EXTERNAL_PROBE=1` plus either `K_GUARD_MCP_EXTERNAL_ALLOWED_HOSTS=example.com,staging.example.com` or a per-call `external_authorized=true` with an `authorization_note`. The report records the authorization basis with `DYN_EXTERNAL_TARGET_AUTHORIZATION_AUDIT`.

설치와 연결은 ChatGPT, Grok, Codex, Antigravity 네 클라이언트에 맞췄으며 자세한 절차는 `docs/quickstart-ko.md`와 `docs/mcp-client-install.md`에 있습니다.

공모전 결과보고서와 실제 호환성 증거를 준비할 때는 `docs/contest-2026-result-report-draft-ko.md`와 `docs/client-interop-evidence-kit-ko.md`를 사용합니다. 실제 호환 완료는 클라이언트별 `install → restart → tool list → check_my_app → reconnect` 녹화, 고유 SHA-256, 별도 검토가 모두 있는 범위만 집계합니다.

MCP calls also enforce argument and inline-text budgets by default:

- `K_GUARD_MCP_MAX_FILES=1000`
- `K_GUARD_MCP_MAX_MB=10`
- `K_GUARD_MCP_MAX_TEXT_MB=1`
- `K_GUARD_MCP_MAX_ARG_CHARS=4096`
- `K_GUARD_MCP_GUARDIAN_MAX_TARGETS=100`
- `K_GUARD_MCP_GUARDIAN_MAX_REQUESTS=200`

Guardian MCP calls preflight the whole manifest against the target, filtered-file, byte, and projected HTTP-request budgets. File expansion is bounded at the configured limit plus one detection entry, so an oversized tree is rejected without first enumerating the entire tree. Oversized multi-target work returns a Guardian-shaped fail-closed report; use the CLI or split the manifest for intentionally larger batches. Dynamic HTTP inspection reads at most 1 MiB per response by default and also stops at 16 MiB, 80 requests, or 30 seconds per probe run.

## Safety Defaults

- JSON/Markdown/MCP outputs pass through a central redaction layer
- SARIF output also passes through the same redaction layer and stores raw-free evidence
- Dynamic probe only allows `localhost`, `127.0.0.1`, and `::1` by default
- External dynamic probe requires explicit authorization evidence and opt-in, then remains fixed-path, read-only, same-origin, and no-redirect. Each request resolves only allowlisted public addresses and connects to the selected validated IP while preserving the original HTTP Host/TLS SNI.
- Dynamic probe does not follow redirects to non-allowlisted hosts
- Dynamic probe uses non-destructive HTTP methods only
- `--deep-active` is a bounded authorized check for common exposed `.env`, `.git/config`, backup/dump, and debug/runtime paths. It is not recursive crawling, password guessing, exploit payloading, or a path brute-force dictionary.
- Dynamic probe uses a timeout and caps sampled response bodies
- External secret validity checks are not performed

## Severity and Confidence

Severity values are validated centrally:

- `critical`: credential/private-key/DB URL exposure, direct high-risk identifiers, or unauthenticated sensitive routes
- `high`: strongly identifying combinations, risky localhost exposure, or sensitive flow candidates
- `medium`: standalone contact/location/config signals and hardening findings
- `low`: weak heuristic signals
- `info`: informational observations

Confidence values are `high`, `medium`, and `low`.

## Data Flow And Inner-Core Limits

The flow map is explicitly EXPERIMENTAL and marked as `heuristic+ast-taint+js-ts-taint` with `line-distance+python-intra-procedural-ast+js-ts-intra-file+limited-interprocedural-taint` precision.
It is a developer triage aid: Python AST taint is supported, and JS/TS now has lightweight intra-file taint, limited route-to-service summaries, plus framework-aware heuristics for Next.js route handlers/server actions, Express IDOR-shaped route params, Supabase service-role/RLS boundary hints, and Firebase Admin auth-boundary hints. Full TypeScript type checking, alias-complete import resolution, middleware proof, deployed RLS/Firebase rule proof, and complete inter-procedural taint remain roadmap items.
Flow findings include raw-free source/sink line hashes to make evidence reproducible without echoing sensitive values.
Flow visualizations are generated as local SVG/HTML without external JavaScript or CDN dependencies. The same redaction layer protects JSON, Markdown, SVG, HTML, and MCP responses.

Runtime MCP observation ingests JSONL/JSON event exports through `observe_mcp_events` and can also evaluate one event at a time through `observe_mcp_event(session_id=...)`. CLI `mcp-intercept` applies those `block` and `redact` decisions to a batch event stream before writing forwarded JSONL. CLI `mcp-proxy -- <upstream argv>` is the live enforcement path for line-delimited stdio JSON-RPC. CLI `mcp-http-proxy --upstream <URL>` enforces the same policy across Streamable HTTP POST, GET SSE, and DELETE session lifecycles, with official Python MCP SDK interoperability coverage. Both proxies emit the same raw-free, transaction-linked HMAC receipt chain for access deny and content allow/redact/block decisions; configured sidecar persistence happens before forwarding and fails closed. Operator-secret verification is required for tamper-resistance claims because HMAC is a shared-secret tag, not a public-key signature. Both proxies fail closed on invalid framing, correlation errors, size or timeout limits, and transport control failures. Streaming observer state has bounded idle/LRU session retention. MCP `enforce_mcp_events` remains report-only. Binary framing, nonstandard transports, and a universal drop-in proxy for every MCP client remain roadmap work.

Read-only connectors inspect local SQLite/log/storage files only. Remote Postgres/Supabase/Firebase/S3, backups, and actual deletion execution are roadmap items.

## Feedback Drift Loop

```bash
k-guard feedback --type fn --rule PII_PHONE --text "missed sample" --output feedback.jsonl
k-guard feedback-export --input feedback.jsonl --output feedback-summary.json --reviewed
```

Feedback files are sanitized before write and summarized locally for corpus tuning. False-negative snippets use extra conservative token masking because the detector may have missed the sensitive value.
`feedback-export` requires `--reviewed` or `K_GUARD_FEEDBACK_EXPORT_REVIEWED=1` so accidental automated exports fail closed. Review `feedback-summary.json` before sharing it outside the partner environment; do not transmit raw `feedback.jsonl`.

## Field Benchmark

`benchmark-template` creates a 20/20/10 manifest:

- 20 general baseline sites or reports
- 20 vibe-coded suspected sites or reports
- 10 owned, partner-approved, or bug-bounty scoped targets

`benchmark` aggregates raw-free K-Guard JSON reports and, only with `--run-probes`, authorized manifest rows marked `mode=probe`. It reports high/critical target rate, strong-identifier detection rate, top rules, and manual false-positive rate by cohort. The default path is report-only so benchmark work can start from dashboard exports without touching external sites.

The same workflow is available through MCP as `create_benchmark_template` and `field_benchmark`. MCP benchmark probes require the same explicit probe opt-ins as `probe_http`.

## Guardian Mode

`guardian-template` creates an authorized target manifest for continuous product guarding. A row can point to a local workspace, an HTTP origin, an MCP runtime JSONL export, or an existing raw-free K-Guard JSON report. `guardian` aggregates all rows into one raw-free report with per-target gates, new/resolved finding drift, top recurring rules, and fix recipes from `suggest_fix`.

Guardian manifests also carry raw-free business-intent and scope assertion fields: `business_purpose`, `data_classes`, `user_scope`, `public_endpoints`, `scope_basis`, and `scope_proof_ref`. K-Guard does not claim human-level business understanding or prove ownership by itself; it records whether those assertions exist and stores only hashed refs. Scope completion requires an explicit `scope_proof_ref`; locators and legacy authorization notes are not treated as proof. Data-release gating requires those target-level contracts and verified operator-keyed evidence bundles whose artifact hashes match the current report before treating a report as shipment evidence.

New templates set `audit_profile=korean_senior`. In this profile a release gate does not pass merely because it found zero blockers. It also requires a substantive workspace with at least one supported and successfully decoded production source file, flow analysis, a completed deep HTTP review, declared endpoint paths that actually return 2xx/3xx/401/403 rather than only 404, and explicit purpose/data/user/scope assertions. Guardian content-hashes each workspace immediately before and after its audit; a mismatch emits `GUARDIAN_SOURCE_CHANGED_DURING_AUDIT`, blocks the target, and excludes that run from substantive coverage. Use an immutable CI checkout for release authority. The report exposes `review_contract.domains` for `site_security`, `api_exposure`, `data_management`, and `operational_risk`; `guardian_gate.passed` remains false when any required domain is incomplete. Legacy manifests without `audit_profile` remain on the narrower `standard` profile and must not be presented as four-domain senior coverage.

`public_endpoints` is executable review scope, not decorative metadata. Guardian safely adds valid same-origin paths from that field to the fixed GET/OPTIONS probe set (maximum 50; no absolute URL, parent traversal, or templated path). This lets the API review cover app-specific read-only endpoints while keeping the probe bounded.

When an HTTP row includes `session_file`, Guardian runs the same bounded path set twice: once unauthenticated and once with the operator-provided read-only session. This keeps public exposure checks visible instead of replacing them with an authenticated-only view. The session must prove both an auth-wall transition and the declared identity response digest. A `korean_senior` gate rejects HTTP coverage when either proof is absent, when a probe produced request or control errors, or when no valid declared endpoint scope was reached.

`guardian --fail-on high` is the canonical pre-release gate. It is the workflow to use when K-Guard should decide whether a target app can ship under a configured threshold. Workspace-only `scan --fail-on` and MCP `security_gate` are quick checks; they do not replace Guardian's manifest, coverage-gap, drift, and multi-target execution contract.

By default, `guardian` writes a report and exits successfully so teams can review findings without turning it into a release blocker. Use `--fail-on high` when the same report should act as a CI gate; it exits with code `3` when blocking targets or new blocking findings are present. On the first run without `--previous`, the report is an `initial_snapshot`: current blockers and coverage gaps can still fail the gate, but K-Guard does not label every current finding as new drift. In gate mode, HTTP rows in the manifest must actually execute via `--run-probes` or they become coverage gaps instead of silent passes.

HTTP rows are not executed unless `--run-probes` is passed. The CLI path is for a trusted local operator and uses explicit CLI flags/manifest rows as its opt-in. MCP is agent-mediated and stricter: `guardian_audit(..., run_probes=true)` requires `K_GUARD_MCP_ENABLE_PROBE=1`; manifests that request external, deep-active, or session probes additionally require `K_GUARD_MCP_ENABLE_EXTERNAL_PROBE=1`, `K_GUARD_MCP_ENABLE_DEEP_ACTIVE_PROBE=1`, or `K_GUARD_MCP_ENABLE_SESSION_PROBE=1` respectively. Guardian mode still uses fixed safe GET/OPTIONS probes and does not perform login attempts, password guessing, mutation, exploit payloads, recursive crawling, or cross-host redirect following.

MCP clients should pass `fail_on="high"` to `guardian_audit` for the canonical release-gate verdict in `guardian_gate.passed`; process exit codes remain a CLI concern. Use `--previous previous-guardian-report.json` to turn the report into a drift monitor. New blocking findings are listed separately only when a previous report is loaded; combine `--previous` with `--fail-on` when those findings should stop a release. If MCP control checks stop guardian before target execution, report mode and gate mode both return a guardian-shaped response with `execution_contract`, `summary`, and `findings`; gate mode additionally includes `guardian_gate.passed=false`. The report includes an `execution_contract` section so skipped, errored, and executed targets are visible in one place, including Markdown and HTML exports.

MCP `security_gate(path, fail_on)` is a quick workspace-only gate. It now returns `security_gate.passed=false` on MCP control failures such as invalid thresholds, argument budgets, workspace budget limits, or scan exceptions, but it intentionally reports `coverage_model="workspace_only"`. Use Guardian for release decisions that need HTTP targets, MCP runtime exports, prior reports, or coverage-gap accounting.

Suppression policy is fail-closed. `suppression-template` creates a CSV that binds every waiver to `app_id`, `audit_profile`, the current source snapshot or review-evidence hash, `target_id`, finding fingerprint, owner, reason, and future expiry. A waiver cannot be replayed against another app or changed release snapshot; invalid, stale, or expired rows add a high-severity policy finding. Suppressions cannot clear Guardian coverage gaps or MCP control-failure rules. `field-validation-queue` exports every high/critical candidate with a redacted fingerprint, detector subtype, artifact scope, file/body/header location kind, and available response hash. The strict `field-validation-report --profile field` claim remains closed until 12-20 owned/partner apps, 120 labeled cases, 50 positives, 40 negatives, five critical cases, three strata, a preregistered holdout with at least 70 cases, 35 positives, 35 negatives and 35 candidates, role-separated reviewer/custodian signatures, and an exact second canonical Guardian execution pass all fixed thresholds. Overall/holdout precision, holdout high/critical recall, and holdout specificity must pass both the point estimate and Wilson 95% lower-bound floor; critical holdout recall remains exactly 1.0. Every candidate must bind to exactly one frozen development/holdout scope. Candidate `(false_positive + benign) / (true_positive + false_positive + benign)` is reported as false discovery rate; false-positive rate is calculated only over clean cases as `FP / (FP + TN)`. The data-release gate is stricter: any known false negative or benign high/critical candidate blocks release. `K_GUARD_FIELD_REVIEWER_HMAC_KEYS` and `K_GUARD_FIELD_CUSTODIAN_HMAC_KEY` must be distinct from the operator evidence key; these local HMACs separate roles but do not prove real-world identity or cryptographically independent execution. Legacy `validation-*` commands aggregate candidate labels only and cannot establish field recall.

The public automatic-block qualification contract is separate from field validation. `release_blocker_actionability_v3` requires a preregistered census of at least 100 automatic blockers, 0.90 candidate actionability, and a 0.80 Wilson 95% lower bound. It also requires automatic blockers in at least 20 applications. An application counts as fully actionable only when every automatic blocker in that application is labeled `true_positive`; both its fully-actionable application rate and Wilson lower bound must pass 0.90 and 0.80. This app-level sensitivity gate prevents dozens of correlated lines in one repository from creating false statistical confidence. Manual-review and policy-integrity holds remain fail-closed but are excluded from automatic-block actionability.

The complete evidence-tier, first-baseline, labeling, and repeat-run contract is documented in [`docs/field-validation-v2-ko.md`](docs/field-validation-v2-ko.md).

`data-release-gate` is stricter: it requires `K_GUARD_EVIDENCE_HMAC_KEY`, the original Guardian manifest, a canonical `high` Guardian claim bound to the current report, target evidence and source snapshots, separately signed primary and repeat validation-source Guardian originals, the exact ground-truth/reviewer CSVs, the original custodian preregistration, Korean corpus evidence, and the actual MCP interceptor forwarded stream. It reruns field validation from those originals, revalidates reviewer/custodian HMACs, and requires the recomputed projection to equal the submitted report. It also reopens the repeat Guardian and independently checks content, bundle, execution attestation, toolchain, manifest, source/HTTP/MCP inputs, and exact candidate multiset. Design-partner validation is intentionally independent from the single app currently being released; its candidate app/target/finding refs must match the validation-source Guardian report, not masquerade as release-app coverage. A reusable GitHub Actions template lives at `docs/templates/github-actions/guardian-release-gate.yml`.

Unauthenticated JSON is split by risk. Sensitive/private-record structure remains `DYN_UNAUTH_API_JSON` at high severity; JSON without those indicators becomes `DYN_PUBLIC_API_JSON_REVIEW` at info severity so an intentional public API does not block release merely for returning JSON.

`scripts/site_scale_calibration.py` runs local black-box HTTP fixtures for large general HTML noise, medium public contact pages, small vibe-coded bulk JSON, valid strong identifiers, and bank-account JSON. It does not use external network access.

`scripts/deep_probe_synthetic_calibration.py` runs a local synthetic loopback calibration harness through the same dashboard `scan_url(..., deep_active=True)` path. The default evidence run uses 500 loopback invocations over 24 bounded scenarios; this is not 500 real websites, not vulnerability discovery, and not penetration testing. It covers `.env`, `.git/config`, backup SQL, debug endpoints, admin/API exposure, OpenAPI, source maps, CORS, redirects, PII/secret response tiers, and false-positive controls for login walls, SPA shells, and HTML fallbacks. It also includes negative controls that prove the expected-vs-observed scorer can detect injected missing and unexpected rules. It does not use external network access; real external deep probes still require explicit target authorization.

`scripts/inner_core_product_gate.py` runs the broader local synthetic product gate for the "inner-core" audit claim. It combines the 500-target loopback deep-probe calibration with static code/config/MCP text checks, Python AST taint, MCP runtime JSONL observation, read-only SQLite/log/storage connectors, retention/deletion review, cross-plane PII-to-agentic/external verdicts, and raw-free evidence graph checks. This gate must have zero missing required rules, zero unexpected deep-probe rules, passing negative controls, non-empty flow graph nodes/edges, and no forbidden raw markers in the serialized report. It is a product-depth gate, not proof of third-party site vulnerability discovery.

The CI workflow runs the full pytest suite plus a 24-target inner-core gate on push/pull request, which covers every synthetic scenario once. The scheduled/manual audit workflow runs the 500-target inner-core gate and uploads its JSON/Markdown/HTML evidence pack. The repository self-SARIF scan is uploaded as non-gating evidence because this scanner repository intentionally contains detector rules, fixtures, and documentation examples that should trigger K-Guard findings; use `--fail-on` against the product being audited, not against K-Guard's own fixture-heavy source tree unless a project-specific baseline exists.

`scripts/passive_homepage_calibration.py` runs GET `/` only homepage calibration from a CSV manifest. It supports `--max-targets`, `--delay-ms`, `--checkpoint-jsonl`, and `--resume` for 10k-scale sharded runs. It reports cohort, rank-bucket, outcome, and hygiene-tier aggregates such as `well_managed_quiet`, `hardening_gap`, `boundary_redirect`, and `messy_or_risky_signal`, so noisy well-managed sites and messy long-tail sites can be calibrated separately. It also emits a `release_gate` with pass/warn/fail checks for measurement yield, high/critical rate, strong-identifier rate, and boundary redirect rate. It does not request `/admin`, `/api`, `.env`, `.git`, OPTIONS, or recursive paths.

`scripts/build_top_domain_manifest.py` creates that passive calibration manifest automatically from a public top-domain CSV or ZIP source. The default source is Tranco's latest top-1m ZIP, so operators do not need to manually collect 10,000 URLs. Use `--start-rank` to build long-tail messy-candidate cohorts, for example ranks 900,001 through 910,000. Majestic Million-style CSVs can also be supplied with `--source-url`.

## AI-only contest RC evidence

The contest RC keeps development evidence in separate lanes instead of publishing one pooled accuracy number:

```powershell
python scripts/qualify_korean_privacy_ai_only.py --output evidence/qualification/korean-privacy-ai-only-v1.json
python scripts/ai_public_benchmark_scorecard.py --output evidence/qualification/ai-public-benchmark-scorecard-v1.json
python scripts/benchmark.py --profile contest --output benchmark-report.json
```

- The Korean qualification reports 117 fixture cases and a frozen 68-case evaluator-authored holdout as separate lanes. It also checks five workspace contracts, the four official unique-identifier concepts, business/corporate-number boundaries, and six sensitive-vocabulary surfaces. It does not publish a pooled confusion matrix or claim blind, human-adjudicated, registry, partner, or field accuracy.
- The public scorecard preserves current and historical lanes separately. `--require-integrity-pass` deliberately fails while any selected historical artifact has a digest or binding mismatch; a report can still be generated so an inadmissible historical result remains visible instead of being silently rewritten or dropped.
- The contest performance profile measures exact synthetic all-benign low-signal corpora on one disclosed host, including fresh-process cold and persistent-scanner warm latency, 10/50/100 MiB scaling, in-process CPython thread concurrency 1/4/8, peak RSS, complete candidate coverage, and raw-free result invariance. It does not measure finding-dense scaling, process-level parallelism, production SLO, field accuracy, hardware-normalized comparison, or third-party superiority.

## Current Limits

- Product hardening roadmap: [docs/pre-release-auditor-hardening-plan-ko.md](docs/pre-release-auditor-hardening-plan-ko.md)
- PDF/DOCX/HWP extraction is not included yet
- Dynamic checks are localhost-only unless explicitly allowlisted or attested by the operator for an owned, partner-approved, or bug-bounty scoped external target
- User-provided session headers are attached only to read-only GET requests and header values are not stored
- JS/TS taint is conservative and lightweight, with intra-file taint, limited route-to-service summaries, and framework-aware heuristics for common Next.js/Express/Supabase/Firebase boundary mistakes; Python AST taint is intra-procedural
- Runtime MCP observation and the MCP `enforce_mcp_events` tool remain advisory; `mcp-proxy` and `mcp-http-proxy` perform actual bidirectional enforcement for line-delimited stdio JSON-RPC and the tested Streamable HTTP lifecycle. Binary framing, nonstandard transports, and a universal drop-in proxy for every client remain outside the enforced boundary
- Remote DB/storage/backups and actual deletion execution are not verified yet
- Korean PII patterns are rule-based and need project-specific false-positive tuning
- Korean business registration numbers use checksum syntax validation on synthetic/vendor-authored fixtures. Historical corporate registration numbers (issued before 2025-01-31) may use the old Annex alternating 1,2 weighted checksum. Since 2025-01-31, current corporate numbers are 4 registry + 2 type + 7 serial digits with no checksum, so detection is explicit field-context/syntax recognition only. None of this is natural-person PII, live registry validation, or independent field validation. Context-only current values are unverified syntax/context recognition. Privacy-first ambiguity: a plausible Korean RRN/FRN wins over a corporate or business label, header, or split JSON key, and is never classified or redacted as an organization ID.
- The evaluator-authored 68-case Korean sensitive/org holdout (`evidence/holdout/korean-sensitive-org-v1.cjson`) is a post-implementation inspection of synthetic oracles, not a blind field-accuracy or registry-validation study. A case passes when every `must_all` rule is present, each `must_any` group has at least one matching rule, and no `forbidden` rule appears (per-case any-rule recall). After this pass the frozen manifest scores 68/68 with recall 1.0, specificity 1.0, and exact two-run repeat. That is not a claim of live field accuracy.
