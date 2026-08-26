# Passive Homepage 10k Calibration

## 목적

대형/중형 일반 홈페이지에서 K-Guard가 개인정보 high/critical을 과하게 띄우는지 검증한다.

이 검증은 보안 경로 점검이 아니다.

- 요청: `GET /` only
- 하지 않음: `OPTIONS`, `/admin`, `/api`, `/.env`, `/.git`, backup/debug path, recursive crawl
- 저장: raw-free summary, rule id, status, content-type, cohort aggregate
- high/critical 후보 저장: detector subtype, redacted evidence fingerprint, body/header 위치, body/header hash, truncation 상태, 수동 판정
- 저장하지 않음: 응답 원문, 개인정보 원문, secret 원문

## Claim Boundary

`passive_homepage_calibration.py`의 결과는 "실제 취약점 발견" 보고서가 아니다.

말할 수 있는 것:

- 공개 홈페이지 후보에 `GET /`만 보내고 raw-free 후보 신호를 분류했다.
- high/critical 또는 strong identifier 후보가 있으면 release gate가 fail되며 수동 판정을 요구한다.
- 보안 헤더 누락과 redirect boundary는 hardening/comparability signal이지 확인된 침해나 노출이 아니다.
- 같은 사이트를 2회 이상 다시 찍었을 때 rule id와 redacted fingerprint가 유지되는지 비교했다. body/header hash는 응답 변동성 기록이지 그 자체로 확정 판정은 아니다.

말하면 안 되는 것:

- 특정 사이트의 비밀/개인정보 유출을 확인했다.
- API, 관리자 페이지, `.env`, `.git`, 인증 후 화면, 크롤링 경로를 검증했다.
- passive 결과만으로 법적 준수, 취약점 부재, 또는 실제 사고 가능성을 증명했다.

실제 deep/authorized 검증 주장은 별도 workflow에서만 한다. owned, partner-approved, 또는 bug-bounty scoped 대상에 대해 명시적 승인 근거를 남기고 dynamic/deep probe 또는 field benchmark를 실행한 뒤, TP/FP/FN 수동 판정을 붙여야 한다.

## 입력 CSV

사용자가 1만 개 사이트를 직접 모으지 않는다. 공개 top-domain 데이터셋에서 재현 가능한 manifest를 만든다.

기본 권장 소스:

- Tranco latest top-1m: 여러 랭킹을 30일 평균한 연구용 top-domain 목록
- Majestic Million: referring subnet 기준 상위 100만 도메인 CSV

K-Guard 기본 스크립트는 Tranco ZIP을 직접 내려받아 `target_id,cohort,url,rank,domain,source_url` 형식으로 변환한다.

```bash
python scripts/build_top_domain_manifest.py \
  --output datasets/tranco-passive-homepage-10k.csv \
  --limit 10000 \
  --cohort large_general \
  --target-prefix tranco
```

Majestic 등 다른 CSV를 쓰려면:

```bash
python scripts/build_top_domain_manifest.py \
  --source-url https://downloads.majestic.com/majestic_million.csv \
  --output datasets/majestic-passive-homepage-10k.csv \
  --limit 10000 \
  --cohort large_general \
  --target-prefix majestic
```

```csv
target_id,cohort,url,rank,domain,source_url
tranco-00001,large_general,https://google.com/,1,google.com,https://tranco-list.eu/top-1m.csv.zip
tranco-00002,large_general,https://cloudflare.com/,2,cloudflare.com,https://tranco-list.eu/top-1m.csv.zip
```

권장 cohort:

- `large_general`
- `medium_general`
- `small_general`
- `vibecoded_suspected`
- `authorized_owned_partner`

## 10k 실행 예시

```bash
python scripts/passive_homepage_calibration.py \
  --targets datasets/tranco-passive-homepage-10k.csv \
  --output reports/passive-homepage-10k-summary.json \
  --checkpoint-jsonl reports/passive-homepage-10k-checkpoint.jsonl \
  --review reports/passive-homepage-manual-review.csv \
  --require-operator-key \
  --max-targets 10000 \
  --delay-ms 500 \
  --timeout 6 \
  --max-body-bytes 1048576
```

중단 후 재개:

```bash
python scripts/passive_homepage_calibration.py \
  --targets datasets/tranco-passive-homepage-10k.csv \
  --output reports/passive-homepage-10k-summary.json \
  --checkpoint-jsonl reports/passive-homepage-10k-checkpoint.jsonl \
  --resume \
  --max-targets 10000 \
  --delay-ms 500
```

## 합격 기준 예시

일반 homepage calibration의 1차 기준:

- `release_gate.status`는 `pass`, `warn`, `fail` 중 하나다.
- 기본 측정률 기준은 `min_measurement_yield=0.8`이다. 코호트별 eligible 측정률이 이보다 낮으면 결과가 너무 빈약하므로 `fail`이다.
- 기본 high/critical 기준은 `max_high_critical_rate=0.0`이다. 하나라도 actionable high/critical이 나오면 수동 검토나 detector tuning 전에는 `fail`이다.
- 기본 강식별자 기준은 `max_strong_identifier_rate=0.0`이다. 주민번호/운전면허/카드/CI/DI 같은 강한 개인정보 후보가 나오면 `fail`이다.
- 기본 boundary 경고 기준은 `warn_boundary_rate=0.75`이다. 외부 host redirect가 많으면 취약점으로 보지는 않지만 homepage 비교력이 떨어지므로 `warn`이다.
- `large_general.strong_identifier_target_rate == 0`
- `medium_general.strong_identifier_target_rate == 0`
- `DYN_RESPONSE_PII_LEAK`가 일반 홈페이지에서 반복 발생하지 않음
- security header missing은 high/critical calibration 실패로 보지 않음
- redirect boundary는 `boundary_target_rate`로 별도 분리하고 high/critical 발생률에는 넣지 않음
- 잘관리된 후보와 엉망/방치 후보를 나눠 비교한다. 같은 rule이 두 집단에서 모두 흔하면 noise 가능성이 크고, 엉망 후보에서만 몰리면 제품 신호로 유지한다.
- high/critical 후보는 `finding_evidence`에 raw-free evidence가 있어야 한다. 필수 필드는 `detector_subtype`, `location`, `redacted_fingerprint`, `body_sha256`, `headers_sha256`, `body_truncated`, `manual_review`이다.
- 수동 판정값은 `true_positive`, `false_positive`, `benign`, `inconclusive` 중 하나다. 소유자 확인 없이 공개 홈페이지에서만 본 후보는 기본적으로 `inconclusive`로 두고, 확정 취약점처럼 말하지 않는다.
- `false_positive`/`benign`처럼 gate를 여는 판정은 `redacted_fingerprint`, `detector_subtype`, `body_sha256`가 현재 증거와 일치해야 반영된다. `headers_sha256`를 넣으면 그것도 일치해야 한다. anchor가 없거나 어긋난 non-blocking 판정은 `needs_review`로 되돌린다.
- report 루트의 `candidate_review_queue`는 `high_or_critical_targets`, `strong_identifier_targets`, `needs_review_targets`를 가진다. 각 후보 row는 rule, detector subtype, redacted fingerprint, body/header hash, location, 수동 판정을 포함한다.
- 집계값은 observed와 unresolved를 나눈다. `*_observed_target_count/rate`는 passive 후보 신호 전체이고, 기존 `*_target_count/rate`는 `false_positive`/`benign` 판정을 뺀 release-gating unresolved 후보만 센다. `true_positive`, `inconclusive`, `needs_review`는 gate를 막는다.

## 후보 판정과 재현성

high/critical 또는 strong identifier 후보가 나오면 다음 순서로 닫는다.

1. 후보별 `finding_evidence` 또는 `candidate_review_queue`에서 `detector_subtype`, `location`, `redacted_fingerprint`, `body_sha256`, `headers_sha256`, `body_truncated`, `manual_review`를 확인한다.
2. 같은 target을 최소 2회 다시 실행한다. 재현성 표기는 rule id와 redacted fingerprint 안정성을 기준으로 하고, body/header hash 안정성은 별도 volatility signal로 둔다.
3. 수동 판정 CSV에 `target_id,rule_id,verdict,reviewer,notes,redacted_fingerprint,detector_subtype,body_sha256,headers_sha256`를 기록한다. `headers_sha256`는 변동성이 크면 생략할 수 있지만, `false_positive`/`benign`에는 `redacted_fingerprint`, `detector_subtype`, `body_sha256`가 필요하다.
4. `false_positive`/`benign`은 observed 후보로 남지만 release gate에서는 제외한다. `true_positive`/`inconclusive`/미판정은 계속 fail이다.
5. 산출물 fingerprint는 `K_GUARD_EVIDENCE_HMAC_KEY`를 설정한 operator-keyed HMAC으로 만든다. 키 값은 report에 쓰지 않는다.

보고서에는 outcome taxonomy도 들어간다.

- `http_2xx`: 홈페이지 응답을 분석함
- `http_3xx_boundary_redirect`: 입력 host 밖으로 redirect되어 따라가지 않음
- `http_3xx_canonical_redirect`: 같은 등록 도메인/`www` 계열 canonical redirect
- `http_3xx_allowed_redirect`: 허용 범위 안 redirect
- `http_4xx`: 막힘/없음/차단 페이지
- `http_5xx`: 서버 오류
- `error_dns`, `error_tls`, `error_timeout`, `error_connection`, `error_other`: 네트워크/인증서/연결 실패
- `skipped_probable_infrastructure`: CDN/DNS/edge/static처럼 홈페이지가 아닌 인프라 도메인으로 분류해 release denominator에서는 제외하지만 보고서에는 남김

`pass`의 의미:

- `pass`는 해당 샤드의 passive detector calibration gate를 통과했다는 뜻이다.
- `pass`가 해당 사이트들이 안전하다, 20k 전체 검증이 끝났다, 취약점이 없다는 뜻은 아니다.
- security header missing, directory listing, boundary redirect, not-homepage 후보는 `Non-Gating Observations`로 남긴다. 이 값은 release gate를 바로 실패시키지는 않지만 제품 튜닝과 수동 검토 대상이다.
- `1,000-site shard`는 1,000개에 요청을 시도한 샤드라는 뜻이며, 1,000개 모두가 성공적으로 측정됐다는 뜻이 아니다. 측정 성공 수와 eligible 측정률을 함께 봐야 한다.

## 해석

이 calibration은 "K-Guard가 대형 홈페이지의 숫자/토큰/빌드 state를 개인정보로 오탐하지 않는가"를 보는 테스트다.

이 검증으로 증명하지 않는 것:

- 특정 사이트의 보안 취약점
- API, 관리자 페이지, source map, `.env`, `.git` 노출 여부
- 법적 준수 또는 보안 인증

위 항목은 권한 있는 target에서만 K-Guard dynamic probe로 별도 확인한다.

## 잘관리된 후보 vs 엉망 후보 비교

단순히 대형 사이트만 보면 "깨끗한 표본에서 조용하다"만 확인된다. K-Guard의 목적은 바이브코딩/방치형 산출물에서 개인정보와 설정 실수를 잡는 것이므로, passive calibration도 두 층으로 나눈다.

- 잘관리된 후보: Tranco 상위권, 예: rank 1~10,000
- 엉망/방치 후보: Tranco 하위권, 예: rank 900,001~910,000
- 자동 품질 티어: `well_managed_quiet`, `hardening_gap`, `boundary_redirect`, `blocked_or_missing_page`, `messy_or_risky_signal`, `unmeasured`

하위권 후보 manifest:

```bash
python scripts/build_top_domain_manifest.py \
  --output datasets/tranco-long-tail-passive-homepage-10k.csv \
  --limit 10000 \
  --start-rank 900001 \
  --cohort messy_candidate_long_tail \
  --target-prefix tranco-tail
```

상위/중간/하위 stratified 비교 예시:

```powershell
python scripts/build_top_domain_manifest.py `
  --output tmp/tranco-top-passive-34.csv `
  --limit 34 `
  --start-rank 1 `
  --cohort top_general `
  --target-prefix tranco-top

python scripts/build_top_domain_manifest.py `
  --output tmp/tranco-mid-passive-33.csv `
  --limit 33 `
  --start-rank 100001 `
  --cohort mid_general `
  --target-prefix tranco-mid

python scripts/build_top_domain_manifest.py `
  --output tmp/tranco-long-passive-33.csv `
  --limit 33 `
  --start-rank 900001 `
  --cohort long_tail_messy_candidate `
  --target-prefix tranco-longtail

$top = Import-Csv tmp/tranco-top-passive-34.csv
$mid = Import-Csv tmp/tranco-mid-passive-33.csv
$tail = Import-Csv tmp/tranco-long-passive-33.csv
@($top) + @($mid) + @($tail) | Export-Csv tmp/tranco-stratified-passive-homepage-100.csv -NoTypeInformation -Encoding utf8

python scripts/passive_homepage_calibration.py `
  --targets tmp/tranco-stratified-passive-homepage-100.csv `
  --output tmp/tranco-stratified-passive-homepage-100.json `
  --checkpoint-jsonl tmp/tranco-stratified-passive-homepage-100.jsonl `
  --max-targets 100 `
  --delay-ms 0 `
  --timeout 4
```

2026-07-09 keyed stratified 100 smoke 결과:

| cohort | 대상 | eligible 측정 | observed high/critical | unresolved high/critical | observed 강식별자 | unresolved 강식별자 | boundary | 주요 rule |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `top_general` | 34 | 25/25 = 1.0 | 0 | 0 | 0 | 0 | 0.36 | none |
| `mid_general` | 33 | 26/33 = 0.7879 | 0 | 0 | 0 | 0 | 0.1154 | `DYN_SECURITY_HEADERS_MISSING=11` |
| `long_tail_messy_candidate` | 33 | 30/33 = 0.9091 | 0 | 0 | 0 | 0 | 0.0667 | `DYN_SECURITY_HEADERS_MISSING=19` |

중간에 하위권 1건이 `DRIVER_LICENSE`로 high가 되었으나, 원문 저장 없이 근거 tier만 확인한 결과 `license` 일반 문맥이 한국 운전면허로 오탐되는 케이스였다. 이후 `license` 단독 문맥은 운전면허로 보지 않고, `driver`, `driver_license`, `운전면허`, `면허번호`처럼 더 좁은 문맥만 인정하도록 조정했다.

그 다음 `example.com -> www.example.com` 같은 같은 등록 도메인 canonical redirect를 `boundary`에서 분리했다. 최신 keyed stratified run은 high/critical과 강식별자 후보가 0이지만, `mid_general` eligible 측정률이 0.8 미만이라 `release_gate.status=fail`이다. 이 샤드는 제품 주장을 올리는 근거로 쓰지 않는다.

## 이전 500 + 500 참고 샤드 결과

Tranco 상위 500개와 long-tail 500개에 대해 passive `GET /` 샤드를 실행했던 이전 기록이다. 이 실행은 20k 전체 완료가 아니라 1,000개 샤드 검증이며, 최신 keyed 100 + stratified 100 결과가 현재 release 판단에서 우선한다.

| cohort | 시도 | homepage 후보 | 측정 | eligible 측정률 | high/critical | 강식별자 | boundary | 주요 observation |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `large_general` | 500 | 409 | 369 | 0.9022 | 0.0 | 0.0 | 0.1897 | 보안 헤더 누락 55, 비홈페이지 후보 91 |
| `messy_candidate_long_tail` | 500 | 500 | 425 | 0.85 | 0.0 | 0.0 | 0.0824 | 보안 헤더 누락 211, 디렉터리 리스팅 2 |

당시 combined strict summary는 `decision=pass`였다. 단, 최신 keyed live validation은 아래처럼 `decision=fail`이므로 현재 제품 주장이나 release 판단에는 최신 keyed 결과를 우선한다.

이번 샤드에서 추가로 확인한 구현 품질 항목:

- `--resume --max-targets`가 샤드 경계를 넘지 않도록 수정했다. 예를 들어 10,000개 manifest에서 `--max-targets 500`이면 resume 이후에도 정확히 첫 500개만 집계한다.
- Tranco 상위권에 섞인 CDN/DNS/update/static 전용 도메인은 `skipped_probable_infrastructure`로 보고서에 남기되 release denominator에서는 제외한다.
- 실제 일반 사이트 후보인 `instagram.com`, `twitter.com`, `github.io`, `amazonaws.com`, `tamburins.com` 같은 도메인은 homepage 후보로 남도록 regression test를 추가했다.

## 2026-07-09 live passive 검증 기록

- long-tail 100: `tmp/live-site-messy-100-keyed-report.json`
- stratified 100: `tmp/tranco-stratified-passive-100-keyed-report.json`
- combined summary: `tmp/passive-real-world-validation-summary-keyed.json`
- fingerprint mode: operator-keyed HMAC. 키 값은 저장하지 않는다.
- raw pattern scan: OpenAI-style key, email, RRN, credit-card-like pattern 모두 미검출.

long-tail 100 결과:

| cohort | 대상 | eligible 측정 | observed high/critical | unresolved high/critical | observed 강식별자 | unresolved 강식별자 | gate |
|---|---:|---:|---:|---:|---:|---:|---|
| `long_tail_messy_candidate` | 100 | 92/100 = 0.92 | 4 | 4 | 2 | 2 | fail |

후보 4건은 모두 `inconclusive`다. 공개 홈페이지 `GET /` 후보 신호일 뿐이며, 소유자 확인 또는 raw-local 맥락 판정 없이 true positive로 말하지 않는다.

| target_id | domain | rules | detector subtype | manual verdict |
|---|---|---|---|---|
| `tranco-longtail-00070` | `statelotterykerala.com` | `DYN_RESPONSE_SECRET_LEAK`, `DYN_SECURITY_HEADERS_MISSING` | `secret_indicator:SECRET_OPENAI_STYLE_KEY` | `inconclusive` |
| `tranco-longtail-00079` | `stdt.ir` | `DYN_RESPONSE_PII_LEAK`, `DYN_SECURITY_HEADERS_MISSING` | `strong_identifier_tier_detected` | `inconclusive` |
| `tranco-longtail-00081` | `stee-rike3.com` | `DYN_RESPONSE_PII_LEAK` | `strong_identifier_tier_detected` | `inconclusive` |
| `tranco-longtail-00094` | `stk88.monster` | `DYN_RESPONSE_SECRET_LEAK`, `DYN_SECURITY_HEADERS_MISSING` | `secret_indicator:SECRET_OPENAI_STYLE_KEY` | `inconclusive` |

재현성:

- 같은 4개 후보를 A/B로 재실행했다.
- 4개 모두 rule id와 redacted fingerprint가 안정적이었다.
- body hash는 3/4 안정적이었다. header hash는 0/4 안정적이었다.
- 따라서 현재 말할 수 있는 것은 "passive 후보 신호가 재현됐다"까지이며, byte-level response 안정성이나 실제 노출 확정은 말하지 않는다.
