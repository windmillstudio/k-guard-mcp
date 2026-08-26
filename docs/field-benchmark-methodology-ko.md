# K-Guard Field Benchmark Methodology

## 목적

K-Guard가 "아무 사이트나 빨갛게 만드는 도구"가 아니라, 바이브코딩 산출물에서 자주 나오는 위험 신호를 더 잘 잡는지 정량화한다.

측정 지표:

- cohort별 high/critical target 발생률
- cohort별 강한 개인정보 식별자 탐지율
- rule별 발생 빈도
- 수동 검토 기준 false-positive 비율
- 측정 불가/권한 없음/보고서 없음 target 수

## Cohort

### 1. general 20

정상 운영 baseline이다.

가능한 대상:

- 직접 운영하거나 파트너 승인을 받은 일반 홈페이지
- 이미 K-Guard dashboard에서 허가를 확인하고 export한 raw-free JSON report
- 보안적으로 성숙한 일반 서비스의 허가된 staging/demo target

주의:

- 무작위 공공/대기업 사이트를 K-Guard가 능동 probe하는 방식으로 채우지 않는다.
- 권한이 없는 일반 사이트는 benchmark manifest에 `mode=report`로 두고, 별도 허가된 report가 없으면 `skipped_no_report`로 남긴다.

### 2. vibecoded_suspected 20

빠르게 만든 웹앱, AI builder/low-code/no-code/바이브코딩 산출물로 의심되는 비교군이다.

분류 근거 예:

- 기본 `/api`, `/api/users`, `/admin`, `/swagger.json`, source map 노출 패턴이 보이는 앱
- 운영자가 "AI/vibe coding으로 만든 앱"이라고 공개했거나 직접 확인한 앱
- 본인/팀/파트너가 vibe coding 방식으로 만든 테스트 또는 staging 앱
- 버그바운티/파트너 범위 안에서 점검 가능한 rapid-built 앱

주의:

- 보고서에는 "vibecoded_suspected"라고 쓰고, 특정 외부 서비스를 공개적으로 "바이브코딩이라 취약하다"라고 단정하지 않는다.
- 실제 제출물에는 target 실명 대신 익명 ID를 쓰는 것이 안전하다.

### 3. authorized_owned_partner 10

제품 실효성을 보여주는 권한 있는 실제 target이다.

가능한 대상:

- 본인 소유 도메인
- 팀/파트너가 점검을 승인한 도메인
- bug bounty scope에 포함된 도메인
- domain proof 또는 dashboard attestation을 기록한 도메인

## Manifest 사용법

템플릿 생성:

```bash
python -m k_guard_mcp.cli benchmark-template --output benchmarks/field-benchmark-template.csv
```

raw-free report만 집계:

```bash
python -m k_guard_mcp.cli benchmark \
  --manifest benchmarks/field-benchmark-template.csv \
  --output field-benchmark.json \
  --markdown field-benchmark.md \
  --html field-benchmark.html
```

권한 있는 target만 실제 probe까지 수행:

```bash
python -m k_guard_mcp.cli benchmark \
  --manifest benchmarks/field-benchmark-template.csv \
  --output field-benchmark.json \
  --markdown field-benchmark.md \
  --html field-benchmark.html \
  --run-probes
```

`--run-probes`가 없으면 `mode=probe` row도 실행하지 않는다. 이 기본값은 실수로 외부 target을 건드리지 않기 위한 안전장치다.

## Manifest Columns

| Column | 의미 |
|---|---|
| `target_id` | 익명 target ID. 예: `general-01`, `vibe-03`, `auth-02` |
| `cohort` | `general`, `vibecoded_suspected`, `authorized_owned_partner` 중 하나 |
| `url` | target URL. report-only row라면 비워도 된다 |
| `mode` | `report` 또는 `probe` |
| `authorized` | probe row에서 권한 확인 여부 |
| `authorization_note` | 소유, 파트너 승인, bug bounty scope 등 raw-free 근거 |
| `deep_active` | `.env`, `.git/config`, backup/debug 고정 경로 확인 여부 |
| `report_path` | 기존 K-Guard JSON report 경로 |
| `manual_verdict` | 기본 수동 판정: `true_positive`, `false_positive`, `needs_review` |
| `notes` | raw-free 메모 |

## Manual Review CSV

수동 오탐 판정은 별도 CSV로 넣는다.

```csv
target_id,rule_id,verdict,notes
vibe-01,DYN_RESPONSE_PII_LEAK,true_positive,confirmed strong identifier
general-03,DYN_SECURITY_HEADERS_MISSING,false_positive,accepted public static site
*,DYN_SOURCE_MAP_ACCESSIBLE,needs_review,review source-map policy manually
```

`verdict` 값:

- `true_positive`
- `false_positive`
- `needs_review`
- `unknown`

## 제출 문구

좋은 문구:

> K-Guard는 20/20/10 field benchmark manifest를 통해 일반 baseline, vibe-coded suspected, 권한 있는 실제 target을 분리 측정한다. 결과는 raw-free JSON/Markdown/HTML로 집계되며, high/critical target rate, strong identifier rate, manual false-positive rate를 cohort별로 비교한다.

피해야 할 문구:

- "일반 사이트는 절대 안 나온다."
- "바이브코딩 사이트는 전부 취약하다."
- "K-Guard 결과는 법적 인증이다."
- "권한 없는 외부 사이트를 자동으로 대량 스캔한다."

## 해석 기준

좋은 신호:

- general cohort의 high/critical target rate가 낮다.
- vibecoded_suspected cohort의 high/critical target rate가 상대적으로 높다.
- vibecoded_suspected 또는 authorized cohort에서 `DYN_RESPONSE_PII_LEAK` strong identifier tier가 실제 true positive로 확인된다.
- manual false-positive rate가 낮거나, FP가 특정 rule에 집중되어 튜닝 가능하다.

나쁜 신호:

- general cohort에서도 high/critical이 대량 발생한다.
- `DYN_RESPONSE_PII_LEAK`가 공개 회사 연락처/입금 계좌만으로 high를 많이 만든다.
- manual review 없이 high/critical rate만 홍보한다.
- probe 실패/timeout을 취약점처럼 집계한다.
