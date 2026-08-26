from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


PIPC_RISK_BASIS = (
    "개보위 가명정보 처리 가이드라인의 위험도 기반 판단처럼 데이터 유형, "
    "처리목적/환경, 민감도, 결합 가능성을 함께 보는 triage 기준입니다."
)
PIPC_UNSTRUCTURED_BASIS = (
    "개보위 비정형데이터 기준처럼 단건 문자열만 보지 않고 문맥, 환경, "
    "식별 가능성, 다른 정보와의 결합 가능성을 함께 보는 triage 기준입니다."
)
PIPC_CREDENTIAL_BASIS = (
    "개보위가 GitHub 등 개발 협업도구의 접근키/API 토큰 노출을 개인정보처리시스템 "
    "무단 접근과 유출 사고로 이어질 수 있는 위험으로 본 기준을 반영합니다."
)


@dataclass(frozen=True)
class PrivacyClass:
    name: str
    axes: tuple[str, ...]
    basis: str = PIPC_RISK_BASIS


LABEL_CLASSES: dict[str, PrivacyClass] = {
    "RRN_VALID": PrivacyClass("고유식별정보/직접식별자", ("direct_identifier", "unique_identifier", "high_impact")),
    "RRN": PrivacyClass("고유식별정보/직접식별자 후보", ("direct_identifier", "unique_identifier", "high_impact")),
    "FRN": PrivacyClass("고유식별정보/외국인 식별자 후보", ("direct_identifier", "unique_identifier", "high_impact")),
    "FRN_VALID": PrivacyClass("고유식별정보/외국인 식별자", ("direct_identifier", "unique_identifier", "high_impact")),
    "PASSPORT": PrivacyClass("여권번호/고유식별정보 후보", ("direct_identifier", "unique_identifier", "high_impact")),
    "DRIVER_LICENSE": PrivacyClass("운전면허번호/고유식별정보 후보", ("direct_identifier", "unique_identifier", "high_impact")),
    "PERSONAL_CUSTOMS_CODE": PrivacyClass("개인통관고유부호/직접식별자 후보", ("direct_identifier", "service_identifier")),
    "CI": PrivacyClass("본인확인 연계정보/서비스 식별자", ("service_identifier", "linkable_identifier", "high_impact")),
    "DI": PrivacyClass("중복가입확인정보/서비스 식별자", ("service_identifier", "linkable_identifier", "high_impact")),
    "CREDIT_CARD": PrivacyClass("금융 식별정보", ("financial_identifier", "high_impact")),
    "BANK_ACCOUNT": PrivacyClass("계좌번호/금융 식별정보", ("financial_identifier", "high_impact")),
    "HEALTH_INSURANCE_ID": PrivacyClass("건강보험 식별자", ("health_identifier", "sensitive_context", "high_impact")),
    "PATIENT_ID": PrivacyClass("환자/진료 식별자", ("health_identifier", "sensitive_context")),
    "MEDICAL_INFO": PrivacyClass("건강/의료 민감정보 후보", ("sensitive_category", "health_context"), PIPC_UNSTRUCTURED_BASIS),
    "SENSITIVE_INFO": PrivacyClass("민감정보 후보", ("sensitive_category", "high_impact"), PIPC_UNSTRUCTURED_BASIS),
    "PERSON": PrivacyClass("성명/직접식별자", ("direct_identifier",)),
    "PHONE": PrivacyClass("연락처/직접식별자", ("direct_identifier", "contact")),
    "EMAIL": PrivacyClass("이메일/연락처 식별자", ("contact", "linkable_identifier")),
    "ADDRESS": PrivacyClass("주소/위치 식별자", ("contact", "location", "linkable_identifier")),
    "BIRTHDATE": PrivacyClass("생년월일/준식별자", ("quasi_identifier",)),
    "ACCOUNT_ID": PrivacyClass("회원/고객/학생/직원 식별자", ("service_identifier", "linkable_identifier")),
    "ORDER_ID": PrivacyClass("주문/예약 식별자", ("service_identifier", "activity_context")),
    "DEVICE_ID": PrivacyClass("기기/광고 식별자", ("device_identifier", "behavioral_context")),
    "IP_ADDRESS": PrivacyClass("접속기록/IP 식별자 후보", ("technical_identifier", "access_log")),
    "TIMESTAMP": PrivacyClass("시각 정보/행위 문맥", ("activity_context", "quasi_identifier")),
    "VEHICLE_NUMBER": PrivacyClass("차량번호/이동 식별자", ("location", "direct_identifier")),
    "LOCATION": PrivacyClass("위치정보 후보", ("location", "sensitive_context")),
    "BUSINESS_REGISTRATION": PrivacyClass("조직 식별정보/사업자등록번호", ("organization_identifier",)),
    "CORPORATE_REGISTRATION": PrivacyClass("조직 식별정보/법인등록번호", ("organization_identifier",)),
}

RULE_CLASSES: dict[str, PrivacyClass] = {
    "DYN_RESPONSE_PII_LEAK": PrivacyClass(
        "동적 응답 개인정보 노출 후보",
        ("dynamic_response", "combined_identifier", "exposure"),
        PIPC_UNSTRUCTURED_BASIS,
    ),
    "DYN_RESPONSE_PII_REVIEW": PrivacyClass(
        "동적 응답 연락처/개인정보 검토 후보",
        ("dynamic_response", "contact", "manual_review"),
        PIPC_UNSTRUCTURED_BASIS,
    ),
    "DYN_RESPONSE_SECRET_LEAK": PrivacyClass(
        "자격증명 노출 후보",
        ("credential", "system_access", "high_impact"),
        PIPC_CREDENTIAL_BASIS,
    ),
}


def metadata_for_label(label: str, *, audit_depth: int = 2) -> dict[str, object]:
    normalized = _normal_label(label)
    item = LABEL_CLASSES.get(normalized)
    if not item:
        item = PrivacyClass("개인정보 후보", ("contextual_identifier",))
    return {
        "privacy_class": item.name,
        "pipc_basis": item.basis,
        "audit_depth": audit_depth,
    }


def metadata_for_labels(labels: Iterable[str], *, audit_depth: int = 3) -> dict[str, object]:
    normalized = [_normal_label(label) for label in labels]
    classes = [LABEL_CLASSES.get(label, PrivacyClass("개인정보 후보", ("contextual_identifier",))) for label in normalized]
    names = _unique(item.name for item in classes)
    axes = set(axis for item in classes for axis in item.axes)
    if len(names) >= 2 or "sensitive_category" in axes or "combined_identifier" in axes:
        privacy_class = "결합 개인정보 위험: " + " + ".join(names[:4])
    else:
        privacy_class = names[0] if names else "개인정보 후보"
    basis = PIPC_UNSTRUCTURED_BASIS if "sensitive_category" in axes or len(names) >= 2 else PIPC_RISK_BASIS
    return {
        "privacy_class": privacy_class,
        "pipc_basis": basis,
        "audit_depth": audit_depth,
    }


def metadata_for_rule(rule_id: str, *, audit_depth: int | None = None) -> dict[str, object]:
    item = RULE_CLASSES.get(rule_id)
    if not item:
        return {}
    depth = audit_depth if audit_depth is not None else (3 if rule_id.startswith("DYN_RESPONSE_PII") else 2)
    return {
        "privacy_class": item.name,
        "pipc_basis": item.basis,
        "audit_depth": depth,
    }


def _normal_label(label: str) -> str:
    return "RRN" if label == "RRN_VALID" else label


def _unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
