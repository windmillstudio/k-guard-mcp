# K-Guard 2단계 현장 캠페인 키트

## 목적

이 키트는 실제 정확도 검증을 시작하기 전에 owned/partner 앱 모집 명부가 최소 실행 조건을 충족하는지 확인한다. 명부 CSV는 운영 입력이며 공개 보고서가 아니다. 상태 JSON에는 앱 ID, 대상 ID, 소스 리비전, 외부 범위 확인 참조의 원문을 넣지 않는다.

명부 준비 완료만으로 공모전 field evidence가 완료되지는 않는다. 두 번의 Guardian 원본, 사전등록, ground truth, 독립 이중 리뷰를 재계산한 뒤에도 별도의 독립 검증자 attestation과 외부에서 고정한 `K_GUARD_TRUSTED_FIELD_ATTESTATION_SHA256`이 있어야 `award_evidence_ready`가 열릴 수 있다. 이 trust anchor는 앱 소유권과 reviewer 신원이 K-Guard 바깥의 assertion 경계임을 강제한다.

## 명부 계약

`benchmarks/field-app-roster-template.csv`는 헤더만 있는 빈 템플릿이다. 행마다 다음 열을 모두 채운다.

| 열 | 허용 값 | 의미 |
|---|---|---|
| `app_id` | 고유한 불투명 ID | 앱 이름이나 담당자 이름 대신 캠페인 내부 ID 사용 |
| `target_id` | 고유한 불투명 ID | Guardian 대상과 연결할 내부 ID |
| `stratum` | `top`, `mid`, `long_tail` | 앱 표본 층 |
| `source_revision` | 40자 또는 64자 16진수 | 스캔할 변경 불가능한 커밋/콘텐츠 리비전 |
| `scope_basis` | `owned`, `partner` | 소유 앱 또는 파트너 승인 앱 여부 |
| `scope_assertion_ref` | 비어 있지 않은 외부 참조 | 계약, 티켓, 승인 저장소 등 K-Guard 밖의 범위 확인 근거 |
| `recruitment_status` | `accepted` | 모집 수락 완료 |
| `authorization_status` | `approved` | 스캔 승인 완료 |
| `scan_consent` | `true` | 해당 앱 스캔 동의 |
| `aggregate_consent` | `true` | 원문 없는 집계 결과 사용 동의 |

준비 완료에는 서로 다른 앱과 대상이 각각 12-20개 있어야 하고 세 stratum이 모두 한 행 이상 포함되어야 한다. 앱 ID와 대상 ID는 대소문자만 다른 값도 중복으로 처리한다. 템플릿 문구, 예시 값, 빈 필드, 잘못된 열, 열 수가 다른 행, 40/64자 16진수가 아닌 리비전은 모두 실패한다.

개인 이름, 이메일, 전화번호 또는 개인 연락처 열을 추가하지 않는다. `scope_assertion_ref`에도 연락처를 적지 말고 외부 시스템의 불투명 티켓/문서 참조만 사용한다. 승인 문서 원문과 연락처는 해당 외부 시스템의 접근 통제로 관리한다.

## 운영 절차

1. 빈 템플릿을 별도 운영 위치에 복제하고 12-20개 앱 행을 채운다.
2. 각 앱의 모집 수락, 스캔 승인, 두 동의를 외부 기록과 대조한다.
3. 브랜치 이름이 아니라 고정된 40/64자 소스 리비전을 기록한다.
4. 세 stratum과 ID 중복을 검사한 뒤 readiness 상태 JSON을 만든다.
5. `ready=true`인 명부의 콘텐츠 SHA-256을 이후 preregistration과 실행 기록에 결속한다.
6. 명부가 바뀌면 상태 JSON을 다시 만들고 새 콘텐츠 SHA-256을 사용한다.

Python API 사용 예시는 다음과 같다.

```python
from k_guard_mcp.field_campaign import (
    load_field_app_roster,
    write_field_app_roster_template,
    write_field_campaign_status_report,
)

write_field_app_roster_template("private/field-app-roster.csv")

# 이 지점에서 외부 승인 기록을 확인하며 CSV 행을 채운다.

# 모든 계약을 통과하지 못하면 ValueError가 발생한다.
rows = load_field_app_roster("private/field-app-roster.csv")

report = write_field_campaign_status_report(
    "private/field-app-roster.csv",
    "evidence/field-campaign-readiness.json",
)
assert report["ready"] is True
```

빈 템플릿은 올바른 CSV이지만 캠페인 준비 완료 상태는 아니다. 운영 중간 점검에는 `evaluate_field_campaign_readiness()`를 사용하면 예외 대신 `blockers`와 집계 수를 확인할 수 있다. 실제 실행 단계에서는 반드시 `load_field_app_roster()`가 성공한 명부만 사용한다.

## 상태 JSON 경계

상태 보고서는 다음 정보만 낸다.

- 명부 파일 바이트의 `content_sha256`
- 행, 고유 앱, 고유 대상, stratum별 개수
- 원문이 없는 안정적인 blocker 코드와 발생 횟수
- 동일한 값의 `passed`, `ready` 불리언
- 앱, 대상, 소스 리비전, 범위 확인 참조의 HMAC 해시 참조
- `raw_returned=false`

상태 JSON은 외부 승인 자체를 증명하지 않는다. 명부에 기록된 assertion을 검사하고 원문을 숨기는 준비 게이트다. 외부 범위 확인 문서의 진위, 승인자의 권한, 실제 모집 동의는 조직 절차에서 별도로 검증해야 한다.
