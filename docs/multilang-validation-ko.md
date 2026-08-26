# 9개 언어 개발 검증 팩

## 범위

번들 `semgrep-deep.yml`은 40개 규칙으로 Python, JavaScript, TypeScript, Java, Kotlin, Go, PHP, Ruby, C#을 검사한다. 고정 개발팩은 9개 언어 모두에서 다섯 규칙군을 회귀 검증한다.

- SQL injection
- command injection
- path traversal
- SSRF
- IDOR/authorization-adjacent object lookup

각 언어는 취약 5건과 정상 5건, 전체는 90건이다. 주장 경계는 `development_validation_not_field_accuracy`다. 이 팩은 실제 앱 분포의 정확도나 배포된 권한 정책을 증명하지 않는다.

## Fail-Closed 계약

실행 전에 다음을 모두 확인한다.

- pack/expectations/profile/rule/fixture SHA-256 일치
- Semgrep 정확 버전 `1.174.0`
- 중복 JSON key·case ID·fixture 경로 없음
- 절대경로, `..`, 역슬래시, symlink, pack 외부 이탈 없음
- 언어별 positive/negative 5건과 다섯 category 완전성
- 실제 fixture 집합과 기대 집합 일치
- eligible target 90개와 Semgrep `paths.scanned` 정규화 집합 정확 일치
- 스캔 전 eligible target 열거 2회 일치
- 저장소의 `.gitignore`/Semgrep 기본 제외가 증명 범위를 줄이지 못하도록, 두 번 열거한 정확한 파일 집합만 비공개 임시 staging에 복제해 스캔하고 원본 source snapshot과 다시 대조
- 두 analyzer run의 source snapshot, toolchain, finding fingerprint multiset 일치

파일이 0개거나 일부만 스캔됐는데 결과가 0건인 경우는 clean이 아니라 control failure다.

## 실행

```powershell
python -m venv .tooling/semgrep
.\.tooling\semgrep\Scripts\python -m pip install --require-hashes -r requirements-semgrep.lock
$env:Path = "$PWD\.tooling\semgrep\Scripts;$env:Path"
k-guard language-validate --output language-validation.json
```

Python API:

```python
from k_guard_mcp.analyzers import SemgrepAnalyzerAdapter
from k_guard_mcp.language_validation import DEFAULT_LANGUAGE_VALIDATION_PACK, run_language_validation_pack

report = run_language_validation_pack(
    DEFAULT_LANGUAGE_VALIDATION_PACK,
    SemgrepAnalyzerAdapter(executable="semgrep"),
)
```

취약 사례는 정확한 `(rule_id, relative_file)` 탐지 때 TP, 누락 시 FN이다. 정상 사례에 finding이 있으면 FP, 없으면 TN이다. 기대에 매핑되지 않은 finding도 준비 상태를 차단한다.

## 2026-07-12 실증 결과

Semgrep `1.174.0`으로 90개 fixture를 두 번 실행한다.

| 언어 | TP | FN | FP | TN | Recall | Specificity | Precision |
|---|---:|---:|---:|---:|---:|---:|---:|
| Python | 5 | 0 | 0 | 5 | 1.0 | 1.0 | 1.0 |
| JavaScript | 5 | 0 | 0 | 5 | 1.0 | 1.0 | 1.0 |
| TypeScript | 5 | 0 | 0 | 5 | 1.0 | 1.0 | 1.0 |
| Java | 5 | 0 | 0 | 5 | 1.0 | 1.0 | 1.0 |
| Kotlin | 5 | 0 | 0 | 5 | 1.0 | 1.0 | 1.0 |
| Go | 5 | 0 | 0 | 5 | 1.0 | 1.0 | 1.0 |
| PHP | 5 | 0 | 0 | 5 | 1.0 | 1.0 | 1.0 |
| Ruby | 5 | 0 | 0 | 5 | 1.0 | 1.0 | 1.0 |
| C# | 5 | 0 | 0 | 5 | 1.0 | 1.0 | 1.0 |
| 전체 | 45 | 0 | 0 | 45 | 1.0 | 1.0 | 1.0 |

두 실행의 45개 finding fingerprint multiset SHA-256은 모두 `fdeca97c9d05c610411d529a18bc42545471eb74c9d30320abd94392fbd9d9fb`로 같았다. 제어 오류와 미매핑 finding은 0건이었다.

| 대상 | SHA-256 |
|---|---|
| pack | `8863d7ed5d5a8331b626c1138446414c9d89165d70176740ebbe4c22363da3d0` |
| expectations | `eb69dfaf7235361948afc06fb16bb00e015c540ab2f44be2c9d8e0c5bb5bc4ac` |
| profile | `c29adf2272f2683ff090e10f9411899cc561bc010721a9ff0db9ee142d02c816` |
| profile rules | `48261d3ef57c823d0805961c093fa94a69b90fc588e34a18d7dbee4d235dee20` |
| validator | `2adbe1b12002653d3a172d88378b1e9f2b457de38eecfec7f7aa9a4879f930db` |
| adapter | `dce41b1445b19129739df3fb3ad394b2636da6f0d0bc3548f59328ce6b373849` |
| command contract | `25abe14a37d752f3462b1443ccd3cf6ae49a8e38ad1c3968f5f9ba08f99c6cb7` |

## 경계

Semgrep Community Edition 규칙은 file-local/intrafile 분석이다. 완전한 inter-procedural 타입 해석, middleware inheritance, 배포된 RLS/IAM, 실제 object ownership은 별도 검토와 거부 테스트가 필요하다.
