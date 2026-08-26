from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from k_guard_mcp.detectors.pii import (
    PiiDetector,
    _valid_business_registration,
    _valid_corporate_registration,
    _valid_rrn,
)
from k_guard_mcp.governance import SENSITIVE_FIELDS
from k_guard_mcp.masking import mask_value
from k_guard_mcp.redaction import redact_text
from k_guard_mcp.reports import to_json
from k_guard_mcp.scanner import KGuardScanner
from k_guard_mcp.privacy_taxonomy import LABEL_CLASSES, metadata_for_label
from k_guard_mcp.recipes import recipe_for_rule
from k_guard_mcp.sensitive_vocabulary import (
    CONTEST_SENSITIVE_CONCEPT_PROBES,
    CONTEST_SENSITIVE_CONCEPT_TERMS,
    DETECTOR_KOREAN_SENSITIVE_CONCEPT_PROBES,
    DETECTOR_KOREAN_SENSITIVE_CONCEPT_TERMS,
    GOVERNANCE_DETECTOR_PARITY_PROBES,
    GOVERNANCE_SENSITIVE_FIELDS,
    INTENTIONAL_PARITY_EXCEPTION_PROBES,
    INTENTIONAL_PARITY_EXCEPTIONS,
    parity_contract_gaps,
    raw_text_has_sensitive_concept,
)

MEDICAL_GOVERNANCE_FIELDS = {
    "medical_record",
    "medical_info",
    "diagnosis",
    "prescription",
    "health_condition",
    "건강상태",
    "진료정보",
    "병력",
    "진단명",
    "처방정보",
}
HISTORICAL_IMPOSSIBLE_DATE_CRN = "999999-1234566"


VALID_BRN = "999-99-99997"
INVALID_BRN = "999-99-99990"
OFFICIAL_HISTORICAL_CRN = "110111-0062432"
INDEPENDENT_HISTORICAL_CRN = "220114-0012347"
CURRENT_UNVERIFIED_CRN = "110111-0000009"
INVALID_UNVERIFIED_CRN = "110111-0000008"
RRN_SHAPED_CRN = "110111-1000001"
VALID_FRN = "901225-5234564"
CARD_COLLISION_CRN = "411111-0000057"
VALID_CRN = OFFICIAL_HISTORICAL_CRN
VALID_RRN = "901225-1234563"

_HISTORICAL_WEIGHTS = (1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2)


def _historical_check_digit(digits: str) -> str:
    total = sum(int(digits[index]) * _HISTORICAL_WEIGHTS[index] for index in range(12))
    return str((10 - total % 10) % 10)

SENSITIVE_OR_MEDICAL = {"SENSITIVE_INFO", "MEDICAL_INFO"}
SENSITIVE_OR_MEDICAL_RULES = {
    "PII_SENSITIVE_INFO",
    "PII_MEDICAL_INFO",
    "KR_COMBO_SENSITIVE_DIRECT_IDENTIFIER",
    "KR_COMBO_MEDICAL_DIRECT_IDENTIFIER",
}


def _rule_ids(text: str, file: str = "fixture.txt") -> set[str]:
    return {finding.rule_id for finding in KGuardScanner().scan_text(text, file).findings}


def _labels(text: str, file: str | None = None) -> set[str]:
    return {entity.label for entity in PiiDetector().detect_entities(text, file)}


@pytest.mark.parametrize("term", CONTEST_SENSITIVE_CONCEPT_TERMS)
def test_contest_sensitive_terms_are_recognized(term: str) -> None:
    probe = CONTEST_SENSITIVE_CONCEPT_PROBES[term]
    assert "SENSITIVE_INFO" in _labels(probe)
    assert "PII_SENSITIVE_INFO" in _rule_ids(probe)


def test_sensitive_term_with_direct_identifier_is_composite() -> None:
    text = "name: 홍길동 장애정보=1급"
    rules = _rule_ids(text)
    assert "PII_SENSITIVE_INFO" in rules
    assert "KR_COMBO_SENSITIVE_DIRECT_IDENTIFIER" in rules


@pytest.mark.parametrize(
    "text",
    [
        "네트워크 장애가 발생했습니다",
        "서버 장애 복구가 완료되었습니다",
        "서버 장애: 복구 완료",
        "네트워크 장애 = 발생",
        "장애정보: 대시보드 링크",
        "장애물을 제거하세요",
        "파일 지문으로 무결성을 확인합니다",
        "디지털 지문을 비교합니다",
        "시스템 건강상태를 점검합니다",
        "홍채 모양의 꽃",
        "네트워크 장애정보 대시보드",
        "장애정보 알림 채널",
        "서버 장애코드 5xx",
        "장애인 접근성 가이드",
        "암호화",
        "사상 최대",
        "사상자",
        "이 지문을 읽고 답하시오",
        "수능 국어 지문 분석",
        "다음 지문을 참고하시오",
        "제시된 지문에서 근거를 찾으시오",
        "면접 지문 예시",
        "연극 대본 지문",
        "장애인 이동권 정책",
        "시각장애인용 음성안내 표준",
        "발달장애 지원 조례",
        "청각장애 관련 영화제",
        "장애인 주차구역 지침",
        "종교의 자유",
        "인종·민족 개념 설명",
        "노동조합법 토론",
        "유전정보 연구윤리 기사",
        "정치적 견해를 소개하는 칼럼",
    ],
)
def test_common_prose_is_not_sensitive_info(text: str) -> None:
    from k_guard_mcp.server import scan_text as mcp_scan_text

    assert not raw_text_has_sensitive_concept(text)
    assert "PII_SENSITIVE_INFO" not in _rule_ids(text)
    assert "PII_MEDICAL_INFO" not in _rule_ids(text)
    assert "SENSITIVE_INFO" not in _labels(text)
    mcp_rules = {item["rule_id"] for item in mcp_scan_text(text, "negative-probe.txt")["findings"]}
    assert "PII_SENSITIVE_INFO" not in mcp_rules
    assert "PII_MEDICAL_INFO" not in mcp_rules


@pytest.mark.parametrize(
    "text",
    [
        '"장애" = "청각"',
        "'장애' = '청각'",
        "`장애` = `청각`",
        '"장애": "시각"',
        "'장애': '시각'",
        "`장애`: `시각`",
    ],
)
def test_quoted_disability_field_assignments_are_sensitive(text: str) -> None:
    assert "PII_SENSITIVE_INFO" in _rule_ids(text)
    assert "SENSITIVE_INFO" in _labels(text)


@pytest.mark.parametrize(
    "text",
    [
        '"장애가 발생했습니다"',
        "'네트워크 장애를 복구했습니다'",
        "`장애물을 제거하세요`",
        '"장애"를 주제로 한 안내 문서',
        "'장애'에 대한 일반적인 설명",
        "`장애`라는 단어만 인용했습니다",
    ],
)
def test_quoted_disability_prose_is_not_a_field(text: str) -> None:
    assert "PII_SENSITIVE_INFO" not in _rule_ids(text)
    assert "SENSITIVE_INFO" not in _labels(text)


@pytest.mark.parametrize(
    "text",
    [
        "홍채=갈색",
        "홍채정보=수집됨",
        "홍채 등록",
        "name: 홍길동 홍채=갈색",
        '"홍채": "갈색"',
        "홍채인증=완료",
    ],
)
def test_iris_biometric_data_contexts_are_sensitive(text: str) -> None:
    assert "PII_SENSITIVE_INFO" in _rule_ids(text)
    assert "SENSITIVE_INFO" in _labels(text)


@pytest.mark.parametrize(
    "text",
    [
        "홍채 모양의 꽃",
        "정원에 핀 홍채를 그렸습니다",
        "홍채 무늬의 벽지 디자인",
        "홍채처럼 펼쳐진 꽃잎",
    ],
)
def test_iris_botanical_design_prose_is_not_sensitive(text: str) -> None:
    assert "PII_SENSITIVE_INFO" not in _rule_ids(text)
    assert "SENSITIVE_INFO" not in _labels(text)


def test_nested_json_sensitive_direct_identifier_composite() -> None:
    text = '{\n  "name": "홍길동",\n  "장애정보": "1급"\n}\n'
    result = KGuardScanner().scan_text(text, "profile.json")
    rules = {finding.rule_id for finding in result.findings}
    assert "KR_COMBO_SENSITIVE_DIRECT_IDENTIFIER" in rules
    payload = to_json(result)
    assert "홍길동" not in payload
    assert "1급" not in payload or "<redacted:" in payload


def test_csv_sensitive_header_composite_where_supported() -> None:
    text = "name,장애정보\n홍길동,1급\n"
    rules = _rule_ids(text, "members.csv")
    assert "KR_COMBO_SENSITIVE_DIRECT_IDENTIFIER" in rules


def test_valid_business_registration_is_org_identifier_not_rrn() -> None:
    assert _valid_business_registration(VALID_BRN.replace("-", ""))
    text = f"사업자등록번호={VALID_BRN}"
    result = KGuardScanner().scan_text(text, "vendor.yml")
    rules = {finding.rule_id for finding in result.findings}
    assert "KR_ORG_BUSINESS_REGISTRATION" in rules
    assert "PII_RRN" not in rules
    assert "PII_RRN_VALID" not in rules
    payload = to_json(result)
    assert VALID_BRN not in payload
    assert "9999999997" not in payload
    finding = next(item for item in result.findings if item.rule_id == "KR_ORG_BUSINESS_REGISTRATION")
    assert "조직 식별정보" in (finding.privacy_class or "")
    assert "고유식별정보" not in (finding.privacy_class or "")


def test_invalid_business_registration_checksum_is_ignored() -> None:
    assert not _valid_business_registration(INVALID_BRN.replace("-", ""))
    rules = _rule_ids(f"사업자등록번호={INVALID_BRN}")
    assert "KR_ORG_BUSINESS_REGISTRATION" not in rules
    assert "PII_RRN" not in rules


def test_historical_corporate_checksum_is_official_annex_algorithm() -> None:
    official = OFFICIAL_HISTORICAL_CRN.replace("-", "")
    independent = INDEPENDENT_HISTORICAL_CRN.replace("-", "")
    current = CURRENT_UNVERIFIED_CRN.replace("-", "")
    assert official[-1] == _historical_check_digit(official)
    assert independent[-1] == _historical_check_digit(independent)
    assert official != independent
    assert _valid_corporate_registration(official)
    assert _valid_corporate_registration(independent)
    assert current[-1] != _historical_check_digit(current)
    assert not _valid_corporate_registration(current)
    assert not _valid_rrn(official)
    assert not _valid_rrn(independent)


def test_valid_corporate_registration_is_org_identifier_not_rrn() -> None:
    for raw in (OFFICIAL_HISTORICAL_CRN, INDEPENDENT_HISTORICAL_CRN):
        digits = raw.replace("-", "")
        assert _valid_corporate_registration(digits)
        assert not _valid_rrn(digits)
        text = f"법인등록번호={raw}"
        result = KGuardScanner().scan_text(text, "corp.yml")
        rules = {finding.rule_id for finding in result.findings}
        assert "KR_ORG_CORPORATE_REGISTRATION" in rules
        assert "PII_RRN" not in rules
        assert "PII_RRN_VALID" not in rules
        payload = to_json(result)
        assert raw not in payload
        assert digits not in payload
        finding = next(item for item in result.findings if item.rule_id == "KR_ORG_CORPORATE_REGISTRATION")
        assert "unverified_syntax_context" not in finding.evidence
        assert "registry validation" not in finding.why_it_matters.lower() or "not registry" in finding.why_it_matters.lower()


def test_current_context_bound_corporate_is_unverified_syntax_not_registry() -> None:
    digits = CURRENT_UNVERIFIED_CRN.replace("-", "")
    assert not _valid_corporate_registration(digits)
    text = f"법인등록번호={CURRENT_UNVERIFIED_CRN}"
    result = KGuardScanner().scan_text(text, "corp.yml")
    rules = {finding.rule_id for finding in result.findings}
    assert "KR_ORG_CORPORATE_REGISTRATION" in rules
    assert "PII_RRN" not in rules
    assert "PII_CREDIT_CARD" not in rules
    finding = next(item for item in result.findings if item.rule_id == "KR_ORG_CORPORATE_REGISTRATION")
    assert "unverified_syntax_context" in finding.evidence
    assert "unverified syntax/context" in finding.why_it_matters.lower()
    assert "not registry validation" in finding.why_it_matters.lower()
    payload = to_json(result)
    assert CURRENT_UNVERIFIED_CRN not in payload
    assert digits not in payload


def test_invalid_unverified_context_bound_corporate_owns_span() -> None:
    digits = INVALID_UNVERIFIED_CRN.replace("-", "")
    assert not _valid_corporate_registration(digits)
    for text in (f"법인등록번호={INVALID_UNVERIFIED_CRN}", f"법인등록번호={digits}"):
        result = KGuardScanner().scan_text(text, "corp.yml")
        rules = {finding.rule_id for finding in result.findings}
        assert "KR_ORG_CORPORATE_REGISTRATION" in rules
        assert "PII_RRN" not in rules
        assert "PII_RRN_VALID" not in rules
        assert "PII_CREDIT_CARD" not in rules
        assert "PII_BANK_ACCOUNT" not in rules
        finding = next(item for item in result.findings if item.rule_id == "KR_ORG_CORPORATE_REGISTRATION")
        assert "unverified_syntax_context" in finding.evidence
        payload = to_json(result)
        assert INVALID_UNVERIFIED_CRN not in payload
        assert digits not in payload


def test_unlabeled_corporate_uses_historical_checksum_and_does_not_conflict_with_rrn() -> None:
    assert "KR_ORG_CORPORATE_REGISTRATION" in _rule_ids(OFFICIAL_HISTORICAL_CRN)
    assert "KR_ORG_CORPORATE_REGISTRATION" not in _rule_ids(CURRENT_UNVERIFIED_CRN)
    unlabeled = _rule_ids("110111-1234567")
    assert "KR_ORG_CORPORATE_REGISTRATION" not in unlabeled
    assert "PII_RRN" in unlabeled or "PII_RRN_VALID" in unlabeled
    valid_outside = _rule_ids(f"주민등록번호={VALID_RRN}")
    assert "PII_RRN_VALID" in valid_outside or "PII_RRN" in valid_outside
    assert "KR_ORG_CORPORATE_REGISTRATION" not in valid_outside


def test_rrn_shaped_value_under_corporate_label_is_privacy_first_rrn() -> None:
    digits = RRN_SHAPED_CRN.replace("-", "")
    assert _valid_corporate_registration(digits)
    assert not _valid_rrn(digits)
    rules = _rule_ids(f"법인등록번호={RRN_SHAPED_CRN}")
    assert "KR_ORG_CORPORATE_REGISTRATION" not in rules
    assert "PII_RRN" in rules or "PII_RRN_VALID" in rules


def test_valid_rrn_is_not_reclassified_as_corporate_registration() -> None:
    assert _valid_rrn(VALID_RRN.replace("-", ""))
    assert not _valid_corporate_registration(VALID_RRN.replace("-", ""))
    rules = _rule_ids(f"rrn={VALID_RRN}")
    assert "PII_RRN_VALID" in rules or "PII_RRN" in rules
    assert "KR_ORG_CORPORATE_REGISTRATION" not in rules
    assert "KR_ORG_BUSINESS_REGISTRATION" not in rules


def test_compact_org_numbers_require_context() -> None:
    compact_crn = OFFICIAL_HISTORICAL_CRN.replace("-", "")
    assert "KR_ORG_BUSINESS_REGISTRATION" not in _rule_ids("id=9999999997")
    assert "KR_ORG_BUSINESS_REGISTRATION" in _rule_ids("사업자등록번호=9999999997")
    assert "KR_ORG_CORPORATE_REGISTRATION" not in _rule_ids(f"id={compact_crn}")
    assert "KR_ORG_CORPORATE_REGISTRATION" in _rule_ids(f"법인등록번호={compact_crn}")


def test_json_nested_org_numbers_are_redacted() -> None:
    text = (
        '{\n  "vendor": {\n    "사업자등록번호": "999-99-99997",\n'
        f'    "법인등록번호": "{OFFICIAL_HISTORICAL_CRN}"\n  }}\n}}\n'
    )
    result = KGuardScanner().scan_text(text, "vendors.json")
    rules = {finding.rule_id for finding in result.findings}
    assert "KR_ORG_BUSINESS_REGISTRATION" in rules
    assert "KR_ORG_CORPORATE_REGISTRATION" in rules
    assert "PII_RRN" not in rules
    payload = to_json(result)
    assert "999-99-99997" not in payload
    assert OFFICIAL_HISTORICAL_CRN not in payload


def test_org_number_masking_hides_raw_values() -> None:
    for label, raw in (
        ("BUSINESS_REGISTRATION", VALID_BRN),
        ("CORPORATE_REGISTRATION", VALID_CRN),
    ):
        masked = mask_value(label, raw)
        assert "<redacted:" in masked
        assert raw not in masked


def test_context_bound_generic_redaction_does_not_label_corporate_as_rrn() -> None:
    bound = f"법인등록번호={INVALID_UNVERIFIED_CRN}"
    redacted = redact_text(bound)
    assert INVALID_UNVERIFIED_CRN not in redacted
    assert INVALID_UNVERIFIED_CRN.replace("-", "") not in redacted
    assert "<redacted:CORPORATE_REGISTRATION:" in redacted
    assert "<redacted:RRN:" not in redacted
    standalone = redact_text(f"주민등록번호={VALID_RRN}")
    assert VALID_RRN not in standalone
    assert "<redacted:RRN:" in standalone
    unlabeled = redact_text(VALID_RRN)
    assert VALID_RRN not in unlabeled
    assert "<redacted:RRN:" in unlabeled


def test_corporate_label_redaction_does_not_cross_newline_to_rrn() -> None:
    redacted = redact_text(f"법인등록번호:\n{VALID_RRN}")
    assert VALID_RRN not in redacted
    assert "<redacted:RRN:" in redacted
    assert "<redacted:CORPORATE_REGISTRATION:" not in redacted
    same_line = redact_text(f"법인등록번호={CURRENT_UNVERIFIED_CRN}")
    assert CURRENT_UNVERIFIED_CRN not in same_line
    assert "<redacted:CORPORATE_REGISTRATION:" in same_line
    assert "<redacted:RRN:" not in same_line


def test_csv_header_owns_corporate_and_business_values() -> None:
    compact = OFFICIAL_HISTORICAL_CRN.replace("-", "")
    compact_csv = f"법인등록번호,사업자등록번호\n{compact},{VALID_BRN}\n"
    compact_rules = _rule_ids(compact_csv, "vendors.csv")
    assert "KR_ORG_CORPORATE_REGISTRATION" in compact_rules
    assert "KR_ORG_BUSINESS_REGISTRATION" in compact_rules
    assert "PII_RRN" not in compact_rules
    assert "PII_CREDIT_CARD" not in compact_rules
    dashed_csv = f"법인등록번호,name\n{INVALID_UNVERIFIED_CRN},홍길동\n"
    dashed_result = KGuardScanner().scan_text(dashed_csv, "orgs.csv")
    dashed_rules = {finding.rule_id for finding in dashed_result.findings}
    assert "KR_ORG_CORPORATE_REGISTRATION" in dashed_rules
    assert "PII_RRN" not in dashed_rules
    assert "PII_RRN_VALID" not in dashed_rules
    payload = to_json(dashed_result)
    assert INVALID_UNVERIFIED_CRN not in payload
    redacted = redact_text(dashed_csv)
    assert INVALID_UNVERIFIED_CRN not in redacted
    assert "<redacted:CORPORATE_REGISTRATION:" in redacted
    assert "<redacted:RRN:" not in redacted


def test_csv_rrn_under_unrelated_header_is_not_corporate() -> None:
    text = f"name,rrn\n홍길동,{VALID_RRN}\n"
    rules = _rule_ids(text, "members.csv")
    assert "PII_RRN_VALID" in rules or "PII_RRN" in rules
    assert "KR_ORG_CORPORATE_REGISTRATION" not in rules
    redacted = redact_text(text)
    assert VALID_RRN not in redacted
    assert "<redacted:RRN:" in redacted
    assert "<redacted:CORPORATE_REGISTRATION:" not in redacted


def test_context_bound_org_ids_are_not_card_or_bank() -> None:
    card_text = f"법인등록번호={CARD_COLLISION_CRN}"
    card_rules = _rule_ids(card_text)
    assert "KR_ORG_CORPORATE_REGISTRATION" in card_rules
    assert "PII_CREDIT_CARD" not in card_rules
    compact_card = f"법인등록번호={CARD_COLLISION_CRN.replace('-', '')}"
    assert "PII_CREDIT_CARD" not in _rule_ids(compact_card)
    bank_text = f"계좌입금 사업자등록번호={VALID_BRN}"
    bank_rules = _rule_ids(bank_text)
    assert "KR_ORG_BUSINESS_REGISTRATION" in bank_rules
    assert "PII_BANK_ACCOUNT" not in bank_rules
    invalid_bank = _rule_ids(f"계좌입금 사업자등록번호={INVALID_BRN}")
    assert "KR_ORG_BUSINESS_REGISTRATION" not in invalid_bank
    assert "PII_BANK_ACCOUNT" not in invalid_bank


@pytest.mark.parametrize(
    "text",
    [
        "청각장애",
        "지체장애",
        "시각장애",
        "발달장애",
        "정신장애",
        "장애유무",
        "장애구분",
        "장애종류",
        "장애 등급",
        "<장애>청각</장애>",
        "| 장애 | 청각 |",
    ],
)
def test_disability_recall_forms_are_sensitive(text: str) -> None:
    assert "PII_SENSITIVE_INFO" in _rule_ids(text)
    assert "SENSITIVE_INFO" in _labels(text)


@pytest.mark.parametrize(
    "header",
    ["장애등급", "disability_type"],
)
def test_csv_disability_headers_are_sensitive(header: str) -> None:
    text = f"name,{header}\n홍길동,청각\n"
    rules = _rule_ids(text, "members.csv")
    assert "PII_SENSITIVE_INFO" in rules or "KR_COMBO_SENSITIVE_DIRECT_IDENTIFIER" in rules
    payload = to_json(KGuardScanner().scan_text(text, "members.csv"))
    assert "홍길동" not in payload


def test_governance_sensitive_fields_use_canonical_shared_source() -> None:
    assert SENSITIVE_FIELDS is GOVERNANCE_SENSITIVE_FIELDS
    assert set(CONTEST_SENSITIVE_CONCEPT_TERMS).issubset(GOVERNANCE_SENSITIVE_FIELDS)


def test_parity_contract_is_closed() -> None:
    assert parity_contract_gaps() == ()
    assert not (set(GOVERNANCE_DETECTOR_PARITY_PROBES) & set(INTENTIONAL_PARITY_EXCEPTIONS))
    assert set(GOVERNANCE_DETECTOR_PARITY_PROBES).issubset(GOVERNANCE_SENSITIVE_FIELDS)
    assert set(INTENTIONAL_PARITY_EXCEPTIONS).issubset(GOVERNANCE_SENSITIVE_FIELDS)
    assert set(DETECTOR_KOREAN_SENSITIVE_CONCEPT_PROBES) == set(DETECTOR_KOREAN_SENSITIVE_CONCEPT_TERMS)
    for term in CONTEST_SENSITIVE_CONCEPT_TERMS:
        assert term in GOVERNANCE_DETECTOR_PARITY_PROBES
        assert term in DETECTOR_KOREAN_SENSITIVE_CONCEPT_TERMS
        assert term in DETECTOR_KOREAN_SENSITIVE_CONCEPT_PROBES
    for english_term in INTENTIONAL_PARITY_EXCEPTIONS:
        assert english_term not in DETECTOR_KOREAN_SENSITIVE_CONCEPT_TERMS
    assert set(INTENTIONAL_PARITY_EXCEPTION_PROBES) == set(INTENTIONAL_PARITY_EXCEPTIONS)


@pytest.mark.parametrize("field,probe", sorted(GOVERNANCE_DETECTOR_PARITY_PROBES.items()))
def test_governance_sensitive_vocabulary_detector_parity(field: str, probe: str) -> None:
    from k_guard_mcp.server import scan_text as mcp_scan_text

    assert probe.strip(), field
    if field.isascii() and field.replace("_", "").isalnum():
        assert field in probe.replace("-", "_"), (field, probe)
    detector = PiiDetector()
    entities = detector.detect_entities(probe, "parity-probe.txt")
    findings, _ = detector.scan_text(probe, "parity-probe.txt")
    labels = {entity.label for entity in entities}
    detector_rules = {finding.rule_id for finding in findings}
    scanner_rules = _rule_ids(probe)
    mcp_rules = {item["rule_id"] for item in mcp_scan_text(probe, "parity-probe.txt")["findings"]}
    if field in MEDICAL_GOVERNANCE_FIELDS:
        assert labels & SENSITIVE_OR_MEDICAL, (field, probe, labels)
        assert detector_rules & SENSITIVE_OR_MEDICAL_RULES, (field, probe, detector_rules)
        assert scanner_rules & SENSITIVE_OR_MEDICAL_RULES, (field, probe, scanner_rules)
        assert mcp_rules & SENSITIVE_OR_MEDICAL_RULES, (field, probe, mcp_rules)
    else:
        assert "SENSITIVE_INFO" in labels, (field, probe, labels)
        assert "PII_SENSITIVE_INFO" in detector_rules, (field, probe, detector_rules)
        assert "PII_SENSITIVE_INFO" in scanner_rules, (field, probe, scanner_rules)
        assert "PII_SENSITIVE_INFO" in mcp_rules, (field, probe, mcp_rules)


@pytest.mark.parametrize("term,probe", sorted(DETECTOR_KOREAN_SENSITIVE_CONCEPT_PROBES.items()))
def test_detector_korean_sensitive_terms_have_behavioral_probes(term: str, probe: str) -> None:
    assert probe.strip(), term
    detector = PiiDetector()
    entities = detector.detect_entities(probe, "detector-probe.txt")
    findings, _ = detector.scan_text(probe, "detector-probe.txt")
    labels = {entity.label for entity in entities}
    detector_rules = {finding.rule_id for finding in findings}
    scanner_rules = _rule_ids(probe)
    assert labels & SENSITIVE_OR_MEDICAL, (term, probe, labels)
    assert detector_rules & SENSITIVE_OR_MEDICAL_RULES, (term, probe, detector_rules)
    assert scanner_rules & SENSITIVE_OR_MEDICAL_RULES, (term, probe, scanner_rules)


def test_contest_terms_are_reflected_across_contract_layers() -> None:
    sensitive_recipe = recipe_for_rule("KR_DATA_SENSITIVE_INFORMATION_CONTROL_GAP")
    org_recipe = recipe_for_rule("KR_ORG_CORPORATE_REGISTRATION")
    recipe_blob = json.dumps(sensitive_recipe, ensure_ascii=False)
    for term in CONTEST_SENSITIVE_CONCEPT_TERMS:
        assert term in GOVERNANCE_SENSITIVE_FIELDS
        assert "SENSITIVE_INFO" in LABEL_CLASSES
        assert term in recipe_blob
        probe = CONTEST_SENSITIVE_CONCEPT_PROBES[term]
        result = KGuardScanner().scan_text(probe, "contest-layer.txt")
        payload = to_json(result)
        redacted = redact_text(probe)
        assert "PII_SENSITIVE_INFO" in {finding.rule_id for finding in result.findings}
        assert "홍길동" not in payload
        assert "홍길동" not in redacted
        for finding in result.findings:
            if finding.rule_id == "PII_SENSITIVE_INFO":
                assert finding.evidence.startswith("sensitive-info:") or "<redacted:" in finding.evidence
        masked_person = mask_value("PERSON", "홍길동")
        assert "홍길동" not in masked_person
    org_blob = json.dumps(org_recipe, ensure_ascii=False)
    assert "unverified syntax/context" in org_blob
    assert "registry" in org_blob.lower()


def test_raw_api_and_mcp_detector_parity() -> None:
    from k_guard_mcp.server import scan_text as mcp_scan_text

    mixed_context_probes = (
        '{"fingerprint":"release-v1","\uc9c0\ubb38\uc815\ubcf4":"MINUTIAE-BASE64"}',
        '{"iris_style":"\ud64d\ucc44 \ubaa8\uc591","\ud64d\ucc44\uc815\ubcf4":"IRIS-CODE"}',
        "홍채 무늬 벽지, 지문정보=수집",
        '{"disability":"yes"}',
        '{"disability_type":"hearing"}',
        '{"sexual_orientation":"private"}',
    )
    for probe in mixed_context_probes:
        assert "SENSITIVE_INFO" in _labels(probe)
        assert "PII_SENSITIVE_INFO" in _rule_ids(probe, "mixed-context.json")
        assert "PII_SENSITIVE_INFO" in {
            item["rule_id"] for item in mcp_scan_text(probe, "mixed-context.json")["findings"]
        }

    text = "\n".join(
        [
            "장애정보=1급",
            "생체정보=수집",
            "지문=등록",
            "홍채=등록",
            "건강상태=양호",
            f"사업자등록번호={VALID_BRN}",
            f"법인등록번호={VALID_CRN}",
        ]
    )
    raw_labels = _labels(text)
    api_rules = _rule_ids(text, "inline-text")
    mcp_payload = mcp_scan_text(text, "inline-text")
    mcp_rules = {finding["rule_id"] for finding in mcp_payload["findings"]}
    expected_rules = {
        "PII_SENSITIVE_INFO",
        "KR_ORG_BUSINESS_REGISTRATION",
        "KR_ORG_CORPORATE_REGISTRATION",
    }
    assert "SENSITIVE_INFO" in raw_labels
    assert "BUSINESS_REGISTRATION" in raw_labels
    assert "CORPORATE_REGISTRATION" in raw_labels
    assert expected_rules.issubset(api_rules)
    assert expected_rules.issubset(mcp_rules)
    serialized = json.dumps(mcp_payload, ensure_ascii=False)
    assert VALID_BRN not in serialized
    assert VALID_CRN not in serialized


def test_governance_recognizes_korean_sensitive_schema_fields() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "schema.ts").write_text(
            'type Patient = { "장애정보": string; "생체정보": string; "건강상태": string; "지문": string; "홍채": string };\n',
            encoding="utf-8",
        )
        result = KGuardScanner().scan_workspace(root, include_flow=False)
    rules = {finding.rule_id for finding in result.findings}
    assert "KR_DATA_SENSITIVE_INFORMATION_CONTROL_GAP" in rules


def test_spaced_korean_org_label_is_recognized() -> None:
    text = f"법인 등록 번호: {CURRENT_UNVERIFIED_CRN}"
    result = KGuardScanner().scan_text(text, "corp.yml")
    rules = {finding.rule_id for finding in result.findings}
    assert "KR_ORG_CORPORATE_REGISTRATION" in rules
    assert "PII_RRN" not in rules
    assert "PII_CREDIT_CARD" not in rules
    payload = to_json(result)
    assert CURRENT_UNVERIFIED_CRN not in payload
    redacted = redact_text(text)
    assert CURRENT_UNVERIFIED_CRN not in redacted
    assert "<redacted:CORPORATE_REGISTRATION:" in redacted


def test_spaced_csv_org_headers_are_recognized() -> None:
    text = f"법인 등록 번호,사업자 등록 번호\n{CURRENT_UNVERIFIED_CRN},{VALID_BRN}\n"
    result = KGuardScanner().scan_text(text, "orgs.csv")
    rules = {finding.rule_id for finding in result.findings}
    assert "KR_ORG_CORPORATE_REGISTRATION" in rules
    assert "KR_ORG_BUSINESS_REGISTRATION" in rules
    assert "PII_RRN" not in rules
    payload = to_json(result)
    assert CURRENT_UNVERIFIED_CRN not in payload
    assert VALID_BRN not in payload
    redacted = redact_text(text)
    assert CURRENT_UNVERIFIED_CRN not in redacted
    assert VALID_BRN not in redacted
    assert "<redacted:CORPORATE_REGISTRATION:" in redacted
    assert "<redacted:BUSINESS_REGISTRATION:" in redacted


def test_split_json_corporate_value_is_owned_and_not_a_card() -> None:
    text = '{\n  "법인등록번호":\n  "%s"\n}\n' % CARD_COLLISION_CRN
    result = KGuardScanner().scan_text(text, "corp.json")
    labels = {entity.label for entity in PiiDetector().detect_entities(text, "corp.json")}
    rules = {finding.rule_id for finding in result.findings}
    assert "KR_ORG_CORPORATE_REGISTRATION" in rules
    assert "CORPORATE_REGISTRATION" in labels
    assert "PII_CREDIT_CARD" not in rules
    assert "CREDIT_CARD" not in labels
    payload = to_json(result)
    assert CARD_COLLISION_CRN not in payload
    redacted = redact_text(text)
    assert CARD_COLLISION_CRN not in redacted
    assert "<redacted:CORPORATE_REGISTRATION:" in redacted
    assert "<redacted:CREDIT_CARD:" not in redacted


def test_split_json_business_value_is_owned() -> None:
    text = '{\n  "사업자등록번호":\n  "%s"\n}\n' % VALID_BRN
    result = KGuardScanner().scan_text(text, "biz.json")
    rules = {finding.rule_id for finding in result.findings}
    assert "KR_ORG_BUSINESS_REGISTRATION" in rules
    assert "PII_BANK_ACCOUNT" not in rules
    payload = to_json(result)
    assert VALID_BRN not in payload
    redacted = redact_text(text)
    assert VALID_BRN not in redacted
    assert "<redacted:BUSINESS_REGISTRATION:" in redacted


def test_utf8_bom_csv_org_headers_are_recognized() -> None:
    corp_text = f"\ufeff법인등록번호,name\n{CURRENT_UNVERIFIED_CRN},홍길동\n"
    corp_result = KGuardScanner().scan_text(corp_text, "bom-corp.csv")
    assert "KR_ORG_CORPORATE_REGISTRATION" in {finding.rule_id for finding in corp_result.findings}
    biz_text = f"\ufeff사업자등록번호,name\n{VALID_BRN},홍길동\n"
    biz_result = KGuardScanner().scan_text(biz_text, "bom-biz.csv")
    assert "KR_ORG_BUSINESS_REGISTRATION" in {finding.rule_id for finding in biz_result.findings}
    for result, raw in ((corp_result, CURRENT_UNVERIFIED_CRN), (biz_result, VALID_BRN)):
        payload = to_json(result)
        assert raw not in payload


def test_one_line_nested_json_binds_adjacent_fields_only() -> None:
    text = '{"법인등록번호":"%s","주민등록번호":"%s"}' % (CURRENT_UNVERIFIED_CRN, VALID_RRN)
    entities = PiiDetector().detect_entities(text, "pair.json")
    corp = [entity for entity in entities if entity.label == "CORPORATE_REGISTRATION"]
    rrn = [entity for entity in entities if entity.label in {"RRN", "RRN_VALID"}]
    assert len(corp) == 1
    assert len(rrn) == 1
    rules = _rule_ids(text, "pair.json")
    assert "KR_ORG_CORPORATE_REGISTRATION" in rules
    assert "PII_RRN" in rules or "PII_RRN_VALID" in rules
    redacted = redact_text(text)
    assert CURRENT_UNVERIFIED_CRN not in redacted
    assert VALID_RRN not in redacted
    assert "<redacted:CORPORATE_REGISTRATION:" in redacted
    assert "<redacted:RRN:" in redacted


def test_plain_key_value_org_context_is_field_bound() -> None:
    text = f"법인등록번호={CURRENT_UNVERIFIED_CRN} 주민등록번호={VALID_RRN}"
    entities = PiiDetector().detect_entities(text, "fields.txt")
    corp = [entity for entity in entities if entity.label == "CORPORATE_REGISTRATION"]
    rrn = [entity for entity in entities if entity.label in {"RRN", "RRN_VALID"}]
    assert len(corp) == 1
    assert len(rrn) == 1
    redacted = redact_text(text)
    assert CURRENT_UNVERIFIED_CRN not in redacted
    assert VALID_RRN not in redacted
    assert "<redacted:CORPORATE_REGISTRATION:" in redacted
    assert "<redacted:RRN:" in redacted


def test_disability_status_english_schema_field_is_sensitive() -> None:
    text = "disability_status=registered"
    assert "SENSITIVE_INFO" in _labels(text)
    assert "PII_SENSITIVE_INFO" in _rule_ids(text)


def _assert_person_id_not_org(text: str, file: str, raw: str, rule: str) -> None:
    result = KGuardScanner().scan_text(text, file)
    rules = {finding.rule_id for finding in result.findings}
    assert rule in rules
    assert "KR_ORG_CORPORATE_REGISTRATION" not in rules
    assert "KR_ORG_BUSINESS_REGISTRATION" not in rules
    finding = next(item for item in result.findings if item.rule_id == rule)
    if rule in {"PII_RRN_VALID", "PII_FRN_VALID"}:
        assert finding.severity == "critical"
    payload = to_json(result)
    assert raw not in payload
    redacted = redact_text(text)
    assert raw not in redacted
    assert raw.replace("-", "") not in redacted
    assert "<redacted:RRN:" in redacted or "<redacted:FRN:" in redacted
    assert "<redacted:CORPORATE_REGISTRATION:" not in redacted
    assert not redacted.endswith("563")


@pytest.mark.parametrize(
    "text,file,raw,rule",
    [
        (f"법인등록번호={VALID_RRN}", "corp.yml", VALID_RRN, "PII_RRN_VALID"),
        (f"법인등록번호={VALID_RRN.replace('-', '')}", "corp.yml", VALID_RRN.replace("-", ""), "PII_RRN_VALID"),
        ('{\n  "법인등록번호":\n  "%s"\n}\n' % VALID_RRN, "corp.json", VALID_RRN, "PII_RRN_VALID"),
        (f"법인등록번호,name\n{VALID_RRN},홍길동\n", "orgs.csv", VALID_RRN, "PII_RRN_VALID"),
        (f'"법인등록번호","name"\n"{VALID_RRN}","홍길동"\n', "orgs.csv", VALID_RRN, "PII_RRN_VALID"),
        (f"사업자번호: {VALID_RRN.replace('-', '')}", "biz.yml", VALID_RRN.replace("-", ""), "PII_RRN_VALID"),
        (f"법인등록번호={VALID_FRN}", "frn.yml", VALID_FRN, "PII_FRN_VALID"),
    ],
)
def test_privacy_first_person_id_wins_over_org_labels(text: str, file: str, raw: str, rule: str) -> None:
    _assert_person_id_not_org(text, file, raw, rule)


def test_english_corporate_registration_no_is_current_context_corporate() -> None:
    compact = "1748110002028"
    text = f"corporate registration no: {compact}"
    rules = _rule_ids(text)
    assert "KR_ORG_CORPORATE_REGISTRATION" in rules
    assert "PII_RRN" not in rules
    assert "PII_CREDIT_CARD" not in rules


def test_camelcase_corporate_registration_number_json() -> None:
    text = '{"corporateRegistrationNumber":"284911-0003037"}'
    rules = _rule_ids(text, "current.json")
    assert "KR_ORG_CORPORATE_REGISTRATION" in rules
    assert "PII_CREDIT_CARD" not in rules
    redacted = redact_text(text)
    assert "284911-0003037" not in redacted
    assert "<redacted:CORPORATE_REGISTRATION:" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "회원 이서준의 장애 유형은 청각으로 기록됨",
        "장애 등록 판정=완료",
        "장애복지카드 발급 대상=yes",
        "생체정보 수집여부=true",
        "노동조합 가입여부=아니오",
        "장애등급: 1급 (장애 발생 이력 없음)",
        "sexual_orientation: gay",
        "sexual_life=비공개",
    ],
)
def test_structured_sensitive_fields_and_person_record_binding(text: str) -> None:
    assert "PII_SENSITIVE_INFO" in _rule_ids(text)
    assert "SENSITIVE_INFO" in _labels(text)


def test_system_health_status_is_not_sensitive() -> None:
    text = "시스템 건강상태: 정상"
    assert "PII_SENSITIVE_INFO" not in _rule_ids(text)
    assert "PII_MEDICAL_INFO" not in _rule_ids(text)


def test_intentional_english_exceptions_are_detector_negatives() -> None:
    from k_guard_mcp.server import scan_text as mcp_scan_text

    korean_substitutes = {"race": "인종=한국", "ethnicity": "민족=한민족", "ideology": "사상=명시", "belief": "신념=명시"}
    for field, probe in INTENTIONAL_PARITY_EXCEPTION_PROBES.items():
        assert "PII_SENSITIVE_INFO" not in _rule_ids(probe)
        assert "SENSITIVE_INFO" not in _labels(probe)
        mcp_rules = {item["rule_id"] for item in mcp_scan_text(probe, "exception.txt")["findings"]}
        assert "PII_SENSITIVE_INFO" not in mcp_rules
        substitute = korean_substitutes[field]
        assert "PII_SENSITIVE_INFO" in _rule_ids(substitute)


def test_frn_valid_is_critical_unique_identifier() -> None:
    result = KGuardScanner().scan_text(f"frn={VALID_FRN}", "alien.yml")
    finding = next(item for item in result.findings if item.rule_id == "PII_FRN_VALID")
    assert finding.severity == "critical"
    taxonomy = metadata_for_label("FRN_VALID")
    assert "고유식별정보" in str(taxonomy["privacy_class"])
    assert taxonomy["pipc_basis"]
    recipe = recipe_for_rule("PII_FRN_VALID")
    assert recipe["rule_id"] == "PII_FRN_VALID"
    implausible = _rule_ids("frn=901225-5234560")
    assert "PII_FRN_VALID" not in implausible
    assert "PII_FRN" in implausible


def test_person_bound_disability_survives_incident_or_obstacle_on_same_line() -> None:
    assert "PII_SENSITIVE_INFO" in _rule_ids("name: 김하늘 청각장애 2급 서버 장애 복구 완료")
    assert "PII_SENSITIVE_INFO" in _rule_ids("name: 김하늘 청각장애 2급 장애물 안내")
    assert "PII_SENSITIVE_INFO" not in _rule_ids("서버 장애 복구가 완료되었습니다")
    assert "PII_SENSITIVE_INFO" not in _rule_ids("서비스 장애 신고 접수건수와 장애율을 집계합니다")


def _assert_sensitive_raw_scanner_mcp(text: str, file: str = "positive-probe.txt") -> None:
    from k_guard_mcp.server import scan_text as mcp_scan_text

    assert raw_text_has_sensitive_concept(text)
    assert "SENSITIVE_INFO" in _labels(text)
    assert "PII_SENSITIVE_INFO" in _rule_ids(text, file)
    mcp_rules = {item["rule_id"] for item in mcp_scan_text(text, file)["findings"]}
    assert "PII_SENSITIVE_INFO" in mcp_rules


@pytest.mark.parametrize(
    "text",
    [
        "장애=청각",
        "회원 이서준의 장애 유형은 청각",
        "장애등급: 1급",
        "장애정보=1급",
        '"장애": "청각"',
        '{"장애정보":"1급"}',
        "지문=등록",
        "지문정보=수집",
        "지문 인증",
        "name: 홍길동 지문=등록",
        "회원 이서준의 지문 등록 기록",
        '"지문": "등록"',
    ],
)
def test_disability_and_fingerprint_structured_contexts_remain_sensitive(text: str) -> None:
    _assert_sensitive_raw_scanner_mcp(text)


def test_unlabeled_historical_corporate_impossible_date_is_not_redacted_as_rrn() -> None:
    digits = HISTORICAL_IMPOSSIBLE_DATE_CRN.replace("-", "")
    assert _valid_corporate_registration(digits)
    assert not _valid_rrn(digits)
    rules = _rule_ids(HISTORICAL_IMPOSSIBLE_DATE_CRN)
    assert "KR_ORG_CORPORATE_REGISTRATION" in rules
    assert "PII_RRN" not in rules
    assert "PII_RRN_VALID" not in rules
    redacted = redact_text(HISTORICAL_IMPOSSIBLE_DATE_CRN)
    assert HISTORICAL_IMPOSSIBLE_DATE_CRN not in redacted
    assert digits not in redacted
    assert "<redacted:CORPORATE_REGISTRATION:" in redacted
    assert "<redacted:RRN:" not in redacted
    payload = to_json(KGuardScanner().scan_text(HISTORICAL_IMPOSSIBLE_DATE_CRN, "corp.yml"))
    assert HISTORICAL_IMPOSSIBLE_DATE_CRN not in payload
    assert digits not in payload


def test_far_future_expiry_without_fixture_marker_stays_critical_card() -> None:
    text = "cardNum: 4716190207394368\nexpMonth: 2\nexpYear: 2081\n"
    rules = _rule_ids(text, "users.yml")
    assert "PII_CREDIT_CARD" in rules
    assert "PII_SYNTHETIC_CREDIT_CARD_FIXTURE" not in rules
    marked = "synthetic card fixture\n" + text
    marked_rules = _rule_ids(marked, "synthetic-card-fixture.yml")
    assert "PII_SYNTHETIC_CREDIT_CARD_FIXTURE" in marked_rules
