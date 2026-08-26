from __future__ import annotations

import csv
import io
import re
from datetime import date
from pathlib import Path

from k_guard_mcp.ids import IdFactory
from k_guard_mcp.masking import mask_value
from k_guard_mcp.models import Component, Entity, Finding
from k_guard_mcp.privacy_taxonomy import metadata_for_label
from k_guard_mcp.sensitive_vocabulary import (
    SENSITIVE_CSV_HEADERS,
    normalize_header_label,
    raw_text_has_sensitive_concept,
)


class PiiDetector:
    EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    PHONE = re.compile(r"\b(?:010|011|016|017|018|019|02|0[3-6][1-6]|070|080)[- ]?\d{3,4}[- ]?\d{4}\b")
    RRN = re.compile(r"\b(\d{6})[- ]?([1-4])(\d{6})\b")
    FRN = re.compile(r"\b(\d{6})[- ]?([5-8])(\d{6})\b")
    RRN_CONTEXT = re.compile(r"(?:\brrn\b|resident[_ -]?(?:registration|id)|주민(?:등록)?번호|주민등록)", re.IGNORECASE)
    FRN_CONTEXT = re.compile(r"(?:\bfrn\b|alien[_ -]?(?:registration|id)|foreigner[_ -]?(?:registration|id)|외국인(?:등록)?번호)", re.IGNORECASE)
    PASSPORT = re.compile(r"\b[MSROD][0-9]{8}\b")
    DRIVER_LICENSE = re.compile(r"\b\d{2}[- ]?\d{2}[- ]?\d{6}[- ]?\d{2}\b")
    DRIVER_CONTEXT = re.compile(r"(driver(?:[_\s-]?license)?|운전\s*면허|면허번호)", re.IGNORECASE)
    CUSTOMS = re.compile(r"\bP\d{12}\b")
    CI_FIELD = re.compile(r"(?:\bci\b|connecting[_ -]?info(?:rmation)?|연계정보)[\"'\s:=]+[\"']?([A-Za-z0-9+/=_-]{20,})", re.IGNORECASE)
    DI_FIELD = re.compile(r"(?:\bdi\b|duplication[_ -]?info(?:rmation)?|중복가입확인정보)[\"'\s:=]+[\"']?([A-Za-z0-9+/=_-]{20,})", re.IGNORECASE)
    HEALTH_INSURANCE_ID_FIELD = re.compile(r"(?:health[_ -]?insurance[_ -]?(?:id|no|number)|건강보험(?:증)?번호|보험증번호)[\"'\s:=#-]+([A-Za-z0-9_.-]{6,})", re.IGNORECASE)
    PATIENT_ID_FIELD = re.compile(r"(?:patient[_ -]?(?:id|no|number)|medical[_ -]?record[_ -]?(?:id|no|number)|환자번호|차트번호|진료번호|의무기록번호|병록번호)[\"'\s:=#-]+([A-Za-z0-9_.-]{4,})", re.IGNORECASE)
    SERVICE_ID_FIELD = re.compile(r"(?:student[_ -]?id|employee[_ -]?id|member[_ -]?(?:id|no|number)|customer[_ -]?(?:no|number)|학번|사번|회원번호|회원ID|고객번호|수험번호)[\"'\s:=#-]+([A-Za-z0-9_.-]{4,})", re.IGNORECASE)
    DEVICE_ID_FIELD = re.compile(r"(?:device[_ -]?id|deviceId|idfa|gaid|adid|advertising[_ -]?id|firebase[_ -]?installation[_ -]?id|installation[_ -]?id|기기ID|기기식별자)[\"'\s:=]+([A-Za-z0-9_.:-]{12,})", re.IGNORECASE)
    CREDIT_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
    CREDIT_CARD_CONTEXT = re.compile(r"(?:credit[_ -]?card|card[_ -]?(?:number|num|no)|\bpan\b|카드(?:번호)?)", re.IGNORECASE)
    BANK_ACCOUNT = re.compile(r"\b\d{2,6}[- ]\d{2,6}[- ]\d{2,8}(?:[- ]\d{1,4})?\b")
    BANK_ACCOUNT_FIELD = re.compile(
        r"(?:bank[_ -]?account(?:[_ -]?(?:number|no))?|account[_ -]?(?:number|no)|deposit[_ -]?account|"
        r"은행[_ -]?계좌(?:번호)?|입금[_ -]?계좌(?:번호)?|계좌번호)[\"'\s]*[:=]\s*[\"']?(\d{9,18})(?!\d)",
        re.IGNORECASE,
    )
    VEHICLE = re.compile(r"\b\d{2,3}[가-힣]\s?\d{4}\b")
    BIRTHDATE = re.compile(r"\b(?:19|20)\d{2}[-./]?(?:0[1-9]|1[0-2])[-./]?(?:0[1-9]|[12]\d|3[01])\b")
    BIRTH_CONTEXT = re.compile(r"(?:\bbirth(?:date|day)?\b|\bdate[_ -]?of[_ -]?birth\b|\bdob\b|생년월일|생일)", re.IGNORECASE)
    TIMESTAMP = re.compile(r"\b(?:19|20)\d{2}[-./]\d{2}[-./]\d{2}[ T]\d{2}:\d{2}(?::\d{2})?\b")
    PERSON_FIELD = re.compile(
        r"(?:name|user_name|customer_name|full_name|이름|성명|고객명|사용자명)[\"'\s:=]+[\"']?([가-힣]{2,4})",
        re.IGNORECASE,
    )
    ADDRESS_FIELD = re.compile(
        r"(?:address|addr|주소)[\"'\s:=]+[\"']?([가-힣A-Za-z0-9\s\-]+(?:시|도|구|군|동|로|길)[가-힣A-Za-z0-9\s\-]*)",
        re.IGNORECASE,
    )
    LOCATION_FIELD = re.compile(
        r"(?:location|loc|place|위치|장소)[\"'\s:=]+[\"']?([가-힣A-Za-z0-9\s\-]+(?:시|도|구|군|동|로|길|역|점)[가-힣A-Za-z0-9\s\-]*)",
        re.IGNORECASE,
    )
    MEDICAL = re.compile(
        r"(진료|처방|병력|진단명|질병|검사결과|혈압|당뇨|암(?!호)|수술|투약|"
        r"medical[_ -]?(?:record|info)|diagnosis|prescription)",
        re.IGNORECASE,
    )
    SENSITIVE_OTHER = re.compile(
        r"(정당\s*(?:가입|명|원)|전과|수형|정신질환|genetic[_ -]?data|criminal[_ -]?record|"
        r"religion|political[_ -]?opinion|union[_ -]?membership|labor\s+union|trade\s+union|"
        r"health[_ -]?condition|biometric[_ -]?data)",
        re.IGNORECASE,
    )
    BUSINESS_REG = re.compile(r"(?<!\d)\d{3}[- ]\d{2}[- ]\d{5}(?!\d)")
    BUSINESS_REG_COMPACT = re.compile(r"(?<!\d)\d{10}(?!\d)")
    BUSINESS_REG_CONTEXT = re.compile(
        r"(사업자[^\S\r\n]*등록[^\S\r\n]*번호|사업자[^\S\r\n]*번호|사업자번호|"
        r"biz[_ -]?(?:reg(?:istration)?|no|number)|\bbrn\b|"
        r"business[_ -]?registration(?:[_ -]?(?:no|num(?:ber)?))?)",
        re.IGNORECASE,
    )
    BUSINESS_LABELED_VALUE = re.compile(
        r"(?:사업자[^\S\r\n]*등록[^\S\r\n]*번호|사업자[^\S\r\n]*번호|사업자번호|"
        r"biz[_ -]?(?:reg(?:istration)?|no|number)|\bbrn\b|"
        r"business[_ -]?registration(?:[_ -]?(?:no|num(?:ber)?))?)"
        r"[^\S\r\n]*[\"'\t :=#-]*[\"']?(?P<value>(?<!\d)(?:\d{3}[- ]\d{2}[- ]\d{5}|\d{10})(?!\d))",
        re.IGNORECASE,
    )
    CORP_REG = re.compile(r"(?<!\d)\d{6}[- ]\d{7}(?!\d)")
    CORP_REG_COMPACT = re.compile(r"(?<!\d)\d{13}(?!\d)")
    CORP_REG_CONTEXT = re.compile(
        r"(법인[^\S\r\n]*등록[^\S\r\n]*번호|법인[^\S\r\n]*번호|법인번호|"
        r"corporate(?:[_ -]?registration)?(?:[_ -]?(?:no|num(?:ber)?))?|"
        r"corp[_ -]?(?:reg(?:istration)?|no|num(?:ber)?)|\bcrn\b)",
        re.IGNORECASE,
    )
    CORP_LABELED_VALUE = re.compile(
        r"(?:법인[^\S\r\n]*등록[^\S\r\n]*번호|법인[^\S\r\n]*번호|법인번호|"
        r"corporate(?:[_ -]?registration)?(?:[_ -]?(?:no|num(?:ber)?))?|"
        r"corp[_ -]?(?:reg(?:istration)?|no|num(?:ber)?)|\bcrn\b)"
        r"[^\S\r\n]*[\"'\t :=#-]*[\"']?(?P<value>(?<!\d)(?:\d{6}[- ]?\d{7}|\d{13})(?!\d))",
        re.IGNORECASE,
    )
    ORDER_ID = re.compile(r"\b(?:order|주문|reservation|예약|tracking|송장)[_-]?(?:id|no|번호)?[\"'\s:=#-]+([A-Za-z0-9-]{6,})", re.IGNORECASE)
    ACCOUNT_ID = re.compile(r"\b(?:account|user|customer)[_-]?id[\"'\s:=]+([A-Za-z0-9_.-]{4,})", re.IGNORECASE)
    IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    HINT = re.compile(
        r"[@\d가-힣]|"
        r"\b(?:ci|di|connecting|duplication|health|insurance|patient|medical|record|student|employee|member|"
        r"customer|device|idfa|gaid|adid|firebase|installation|driver|license|name|full_name|user_name|"
        r"address|addr|location|loc|place|order|reservation|tracking|account|user_id|customer_id|"
        r"diagnosis|prescription|genetic[_ -]?data|criminal[_ -]?record|"
        r"disability(?:_type|_status|_grade|_code)?|religion|political[_ -]?opinion|"
        r"union[_ -]?membership|labor\s+union|trade\s+union|sexual[_ -]?(?:orientation|life)|"
        r"corporate(?:_?registration)?|medical[_ -]?(?:record|info)|"
        r"biometric(?:_data)?|health_condition|biz|brn|crn)\b",
        re.IGNORECASE,
    )

    def __init__(self, id_factory: IdFactory | None = None) -> None:
        self.ids = id_factory or IdFactory()

    def detect_entities(self, text: str, file: str | None = None) -> list[Entity]:
        entities: list[Entity] = []
        lines = text.splitlines()
        contexts = _line_contexts(lines)
        csv_org_claims = _csv_org_claimed_spans(text, file)
        split_org_claims = _split_json_org_claims(lines)
        for idx, line in enumerate(lines, start=1):
            extra_labeled = split_org_claims.get(idx, [])
            extra_claimed = csv_org_claims.get(idx, [])
            if not self.HINT.search(line) and not extra_labeled and not extra_claimed:
                continue
            context = contexts.get(idx, f"line:{idx}")
            entities.extend(
                self._line_entities(
                    line,
                    idx,
                    context,
                    extra_claimed=extra_claimed,
                    extra_labeled=extra_labeled,
                )
            )
        entities.extend(self._csv_entities(text, file))
        return _dedupe_entities(entities)

    def scan_text(self, text: str, file: str | None = None) -> tuple[list[Finding], list[Entity]]:
        entities = self.detect_entities(text, file)
        synthetic_card_lines = _far_future_card_fixture_lines(text, file)
        findings: list[Finding] = []
        for entity in entities:
            severity = _standalone_severity(entity.label, entity.confidence)
            if severity == "info" and entity.confidence == "low":
                continue
            privacy_meta = metadata_for_label(entity.label, audit_depth=2)
            rule_id = f"PII_{entity.label}"
            title = f"{entity.label} detected"
            evidence = entity.evidence
            why = "Sensitive or identifying data is present in local code, logs, fixtures, or documents."
            recommendation = "Remove real data, replace it with synthetic fixtures, or mask it before storing/logging."
            if entity.label == "BUSINESS_REGISTRATION":
                rule_id = "KR_ORG_BUSINESS_REGISTRATION"
                title = "Korean business registration number detected"
                why = "A business registration number is an organization-sensitive identifier, not a natural-person resident registration number."
                recommendation = "Redact it in logs and fixtures, keep it in vendor records, and never classify it as PII_RRN."
            elif entity.label == "CORPORATE_REGISTRATION":
                rule_id = "KR_ORG_CORPORATE_REGISTRATION"
                title = "Korean corporate registration number detected"
                if "unverified_syntax_context" in entity.evidence:
                    why = (
                        "A 13-digit corporate-registration-shaped value was recognized from field context. "
                        "This is unverified syntax/context recognition, not registry validation."
                    )
                else:
                    why = (
                        "A corporate registration number is an organization-sensitive identifier, not a natural-person resident registration number. "
                        "Historical checksum matching is syntax validation only, not live registry verification."
                    )
                recommendation = "Redact it in logs and fixtures, keep it in organization records, and never classify it as PII_RRN."
            if entity.label == "CREDIT_CARD" and entity.line in synthetic_card_lines:
                rule_id = "PII_SYNTHETIC_CREDIT_CARD_FIXTURE"
                severity = "medium"
                title = "Card-shaped synthetic fixture has a far-future expiry"
                evidence = f"detector_subtype=far_future_expiry_synthetic_card {entity.evidence}"
                why = "A far-future expiry makes a live payment credential implausible, but realistic card fixtures can still normalize unsafe data handling."
                recommendation = "Use a documented payment-provider test number and mark the fixture as synthetic."
            findings.append(
                Finding(
                    id=self.ids.next(),
                    source="static",
                    rule_id=rule_id,
                    severity=severity,
                    confidence=entity.confidence,
                    title=title,
                    file=file,
                    line_start=entity.line,
                    line_end=entity.line,
                    evidence=evidence,
                    components=[Component(entity.label, entity.evidence, entity.line)],
                    why_it_matters=why,
                    recommendation=recommendation,
                    privacy_class=str(privacy_meta["privacy_class"]),
                    pipc_basis=str(privacy_meta["pipc_basis"]),
                    audit_depth=int(privacy_meta["audit_depth"]),
                    inspected_scope="정적 파일/텍스트 전체에서 개인정보 패턴과 필드 문맥을 검사했습니다.",
                    not_inspected="이 값이 실제 운영 데이터인지, 적법한 처리 근거가 있는지, 접근권한/보존기간이 맞는지는 사람 검토가 필요합니다.",
                )
            )
        return findings, entities

    def _line_entities(
        self,
        line: str,
        line_no: int,
        context: str,
        extra_claimed: list[tuple[int, int]] | None = None,
        extra_labeled: list[tuple[int, int, str, str]] | None = None,
    ) -> list[Entity]:
        entities: list[Entity] = []
        for match in self.EMAIL.finditer(line):
            entities.append(Entity("EMAIL", mask_value("EMAIL", match.group(0)), line_no, context, "high"))
        for match in self.PHONE.finditer(line):
            entities.append(Entity("PHONE", mask_value("PHONE", match.group(0)), line_no, context, "high"))
        org_entities, claimed_spans = _org_registration_entities(
            self, line, line_no, context, extra_labeled=extra_labeled
        )
        if extra_claimed:
            claimed_spans = list(claimed_spans) + list(extra_claimed)
        entities.extend(org_entities)
        for match in self.RRN.finditer(line):
            if _spans_overlap(match.span(), claimed_spans):
                continue
            raw = match.group(0)
            digits = re.sub(r"\D", "", raw)
            if not _plausible_identity_birthdate(digits):
                continue
            valid = _valid_rrn(digits)
            confidence = "high" if valid or self.RRN_CONTEXT.search(line) else "low"
            severity_hint = "RRN_VALID" if valid else "RRN"
            entities.append(Entity(severity_hint, mask_value("RRN", raw), line_no, context, confidence, _scope_from_context(context)))
        for match in self.FRN.finditer(line):
            if _spans_overlap(match.span(), claimed_spans):
                continue
            raw = match.group(0)
            digits = re.sub(r"\D", "", raw)
            if not _plausible_identity_birthdate(digits):
                continue
            valid = _valid_rrn(digits)
            confidence = "high" if valid or self.FRN_CONTEXT.search(line) else "low"
            label = "FRN_VALID" if valid else "FRN"
            entities.append(Entity(label, mask_value(label, raw), line_no, context, confidence, _scope_from_context(context)))
        for match in self.PASSPORT.finditer(line):
            entities.append(Entity("PASSPORT", mask_value("PASSPORT", match.group(0)), line_no, context, "medium", _scope_from_context(context)))
        for match in self.DRIVER_LICENSE.finditer(line):
            raw = match.group(0)
            if self.DRIVER_CONTEXT.search(line):
                entities.append(Entity("DRIVER_LICENSE", mask_value("DRIVER_LICENSE", raw), line_no, context, "medium", _scope_from_context(context)))
        for match in self.CUSTOMS.finditer(line):
            entities.append(Entity("PERSONAL_CUSTOMS_CODE", mask_value("PERSONAL_CUSTOMS_CODE", match.group(0)), line_no, context, "medium", _scope_from_context(context)))
        for match in self.CI_FIELD.finditer(line):
            entities.append(Entity("CI", mask_value("CI", match.group(1)), line_no, context, "medium", _scope_from_context(context)))
        for match in self.DI_FIELD.finditer(line):
            entities.append(Entity("DI", mask_value("DI", match.group(1)), line_no, context, "medium", _scope_from_context(context)))
        for match in self.HEALTH_INSURANCE_ID_FIELD.finditer(line):
            entities.append(Entity("HEALTH_INSURANCE_ID", mask_value("HEALTH_INSURANCE_ID", match.group(1)), line_no, context, "medium", _scope_from_context(context)))
        for match in self.PATIENT_ID_FIELD.finditer(line):
            entities.append(Entity("PATIENT_ID", mask_value("PATIENT_ID", match.group(1)), line_no, context, "medium", _scope_from_context(context)))
        for match in self.SERVICE_ID_FIELD.finditer(line):
            entities.append(Entity("ACCOUNT_ID", mask_value("ACCOUNT_ID", match.group(1)), line_no, context, "medium", _scope_from_context(context)))
        for match in self.DEVICE_ID_FIELD.finditer(line):
            entities.append(Entity("DEVICE_ID", mask_value("DEVICE_ID", match.group(1)), line_no, context, "low", _scope_from_context(context)))
        for match in self.CREDIT_CARD.finditer(line):
            if _spans_overlap(match.span(), claimed_spans):
                continue
            raw = match.group(0)
            digits = re.sub(r"\D", "", raw)
            separated = re.search(r"[ -]", raw.strip()) is not None
            contextual = self.CREDIT_CARD_CONTEXT.search(line) is not None
            plausible_issuer_prefix = digits[:1] in {"2", "3", "4", "5", "6"}
            if 13 <= len(digits) <= 19 and plausible_issuer_prefix and _luhn(digits) and (separated or contextual):
                entities.append(Entity("CREDIT_CARD", mask_value("CREDIT_CARD", raw), line_no, context, "high", _scope_from_context(context)))
        for match in self.BANK_ACCOUNT.finditer(line):
            if _spans_overlap(match.span(), claimed_spans):
                continue
            raw = match.group(0)
            digits = re.sub(r"\D", "", raw)
            bank_context = re.search(r"(account|bank|계좌|은행)", line, re.IGNORECASE)
            if bank_context and 9 <= len(digits) <= 18 and not _luhn(digits) and not self.PHONE.fullmatch(raw) and not self.DRIVER_LICENSE.fullmatch(raw):
                entities.append(Entity("BANK_ACCOUNT", mask_value("BANK_ACCOUNT", raw), line_no, context, "low", _scope_from_context(context)))
        for match in self.BANK_ACCOUNT_FIELD.finditer(line):
            if _spans_overlap(match.span(), claimed_spans):
                continue
            raw = match.group(1)
            if _valid_structured_bank_account(raw):
                entities.append(Entity("BANK_ACCOUNT", mask_value("BANK_ACCOUNT", raw), line_no, context, "medium", _scope_from_context(context)))
        for match in self.VEHICLE.finditer(line):
            entities.append(Entity("VEHICLE_NUMBER", mask_value("VEHICLE_NUMBER", match.group(0)), line_no, context, "medium", _scope_from_context(context)))
        for match in self.BIRTHDATE.finditer(line):
            if self.BIRTH_CONTEXT.search(line):
                entities.append(Entity("BIRTHDATE", mask_value("BIRTHDATE", match.group(0)), line_no, context, "medium", _scope_from_context(context)))
        for match in self.TIMESTAMP.finditer(line):
            entities.append(Entity("TIMESTAMP", mask_value("TIMESTAMP", match.group(0)), line_no, context, "medium", _scope_from_context(context)))
        for match in self.PERSON_FIELD.finditer(line):
            entities.append(Entity("PERSON", mask_value("PERSON", match.group(1)), line_no, context, "high", _scope_from_context(context)))
        for match in self.ADDRESS_FIELD.finditer(line):
            entities.append(Entity("ADDRESS", mask_value("ADDRESS", match.group(1)), line_no, context, "medium", _scope_from_context(context)))
        for match in self.LOCATION_FIELD.finditer(line):
            entities.append(Entity("LOCATION", mask_value("LOCATION", match.group(1)), line_no, context, "medium", _scope_from_context(context)))
        if self.MEDICAL.search(line):
            entities.append(Entity("MEDICAL_INFO", "medical-info:" + str(line_no), line_no, context, "medium", _scope_from_context(context)))
        if self.SENSITIVE_OTHER.search(line) or raw_text_has_sensitive_concept(line):
            entities.append(Entity("SENSITIVE_INFO", "sensitive-info:" + str(line_no), line_no, context, "medium", _scope_from_context(context)))
        for match in self.ORDER_ID.finditer(line):
            entities.append(Entity("ORDER_ID", mask_value("ORDER_ID", match.group(1)), line_no, context, "medium", _scope_from_context(context)))
        for match in self.ACCOUNT_ID.finditer(line):
            entities.append(Entity("ACCOUNT_ID", mask_value("ACCOUNT_ID", match.group(1)), line_no, context, "medium", _scope_from_context(context)))
        for match in self.IP.finditer(line):
            if _valid_ipv4(match.group(0)):
                entities.append(Entity("IP_ADDRESS", mask_value("IP_ADDRESS", match.group(0)), line_no, context, "medium", _scope_from_context(context)))
        return entities

    def _csv_entities(self, text: str, file: str | None) -> list[Entity]:
        parsed = _parse_csv_table(text, file)
        if parsed is None:
            return []
        headers, rows = parsed
        entities: list[Entity] = []
        for row_idx, row in enumerate(rows[1:], start=2):
            context = f"csv_row:{row_idx}"
            for col_idx, value in enumerate(row):
                header = headers[col_idx] if col_idx < len(headers) else ""
                entities.extend(_entities_from_field(header, value, row_idx, context))
        return entities


def _standalone_severity(label: str, confidence: str = "medium") -> str:
    if label in {"RRN_VALID", "FRN_VALID", "CREDIT_CARD"}:
        return "critical"
    if label in {"RRN", "FRN"}:
        return "high" if confidence == "high" else "medium"
    if label in {"PASSPORT", "DRIVER_LICENSE", "PERSONAL_CUSTOMS_CODE", "BANK_ACCOUNT", "CI", "DI", "HEALTH_INSURANCE_ID"}:
        return "high"
    if label in {"PHONE", "EMAIL", "ADDRESS", "VEHICLE_NUMBER", "MEDICAL_INFO", "PATIENT_ID", "SENSITIVE_INFO", "BUSINESS_REGISTRATION", "CORPORATE_REGISTRATION"}:
        return "medium"
    return "low"


_SYNTHETIC_CARD_MARKER = re.compile(
    r"(?:synthetic|test[_ -]?card|dummy[_ -]?(?:card|pan)|fixture[_ -]?card|\bfixture\b)",
    re.IGNORECASE,
)


def _far_future_card_fixture_lines(text: str, file: str | None = None) -> set[int]:
    """Downgrade only when an explicit synthetic/test/fixture marker is present.

    A far-future expiry by itself does not make a plausible live card a fixture.
    """
    file_marked = bool(file and re.search(r"fixture|synthetic|test.card", str(file), re.IGNORECASE))
    lines = text.splitlines()
    fixture_lines: set[int] = set()
    expiry = re.compile(r"\b(?:exp(?:iration)?[_ -]?(?:year|yr)|expYear)\b[^\d]*(?P<year>20\d{2})", re.IGNORECASE)
    for index, line in enumerate(lines):
        if PiiDetector.CREDIT_CARD_CONTEXT.search(line) is None or PiiDetector.CREDIT_CARD.search(line) is None:
            continue
        window = [line, *lines[index + 1 : index + 7]]
        marked = file_marked or any(_SYNTHETIC_CARD_MARKER.search(item) for item in window)
        if not marked:
            continue
        for following in lines[index + 1 : index + 7]:
            if PiiDetector.CREDIT_CARD_CONTEXT.search(following) and PiiDetector.CREDIT_CARD.search(following):
                break
            match = expiry.search(following)
            if match and int(match.group("year")) >= 2070:
                fixture_lines.add(index + 1)
                break
    return fixture_lines


def _valid_business_registration(digits: str) -> bool:
    if not re.fullmatch(r"\d{10}", digits):
        return False
    weights = [1, 3, 7, 1, 3, 7, 1, 3, 5]
    total = sum(int(digits[index]) * weights[index] for index in range(9))
    total += (int(digits[8]) * 5) // 10
    return (10 - (total % 10)) % 10 == int(digits[9])


def _valid_corporate_registration(digits: str) -> bool:
    """Historical (pre-2025-01-31) Korean corporate registration checksum.

    Weights 1,2 alternate on the first 12 digits; the check digit is
    (10 - sum(raw products) % 10) % 10. Current 13-digit numbers have no
    checksum and must not be treated as registry-validated here.
    """
    if not re.fullmatch(r"\d{13}", digits):
        return False
    weights = [1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2]
    total = sum(int(digits[index]) * weights[index] for index in range(12))
    return (10 - (total % 10)) % 10 == int(digits[12])


def _corporate_shape(digits: str) -> bool:
    return bool(re.fullmatch(r"\d{13}", digits))


_UNVERIFIED_CORPORATE_SUBTYPE = "unverified_syntax_context"
_HISTORICAL_CORPORATE_SUBTYPE = "historical_checksum_syntax"


def _corporate_evidence(raw: str, historical_valid: bool) -> str:
    masked = mask_value("CORPORATE_REGISTRATION", raw)
    subtype = _HISTORICAL_CORPORATE_SUBTYPE if historical_valid else _UNVERIFIED_CORPORATE_SUBTYPE
    return f"detector_subtype={subtype} {masked}"


def _corporate_entity(raw: str, line_no: int, context: str, historical_valid: bool) -> Entity:
    confidence = "high" if historical_valid else "medium"
    return Entity(
        "CORPORATE_REGISTRATION",
        _corporate_evidence(raw, historical_valid),
        line_no,
        context,
        confidence,
        _scope_from_context(context),
    )


def _spans_overlap(span: tuple[int, int], claimed: list[tuple[int, int]]) -> bool:
    start, end = span
    return any(not (end <= left or start >= right) for left, right in claimed)


def _org_registration_entities(
    detector: PiiDetector,
    line: str,
    line_no: int,
    context: str,
    extra_labeled: list[tuple[int, int, str, str]] | None = None,
) -> tuple[list[Entity], list[tuple[int, int]]]:
    # Privacy-first: a plausible RRN/FRN is never claimed as an organization ID.
    entities: list[Entity] = []
    claimed: list[tuple[int, int]] = []
    for start, end, kind, raw in extra_labeled or []:
        span = (start, end)
        if _spans_overlap(span, claimed):
            continue
        digits = re.sub(r"\D", "", raw)
        if kind == "corp":
            if _is_person_identity_digits(digits) or not _corporate_shape(digits):
                continue
            claimed.append(span)
            entities.append(_corporate_entity(raw, line_no, context, _valid_corporate_registration(digits)))
        elif kind == "biz":
            if len(digits) != 10:
                continue
            claimed.append(span)
            if _valid_business_registration(digits):
                entities.append(
                    Entity("BUSINESS_REGISTRATION", mask_value("BUSINESS_REGISTRATION", raw), line_no, context, "high", _scope_from_context(context))
                )
    for match in detector.BUSINESS_LABELED_VALUE.finditer(line):
        raw = match.group("value")
        span = match.span("value")
        if _spans_overlap(span, claimed):
            continue
        digits = re.sub(r"\D", "", raw)
        if len(digits) != 10:
            continue
        claimed.append(span)
        if _valid_business_registration(digits):
            entities.append(
                Entity("BUSINESS_REGISTRATION", mask_value("BUSINESS_REGISTRATION", raw), line_no, context, "high", _scope_from_context(context))
            )
    for match in detector.BUSINESS_REG.finditer(line):
        if _spans_overlap(match.span(), claimed):
            continue
        raw = match.group(0)
        digits = re.sub(r"\D", "", raw)
        if not _valid_business_registration(digits):
            continue
        entities.append(
            Entity("BUSINESS_REGISTRATION", mask_value("BUSINESS_REGISTRATION", raw), line_no, context, "high", _scope_from_context(context))
        )
        claimed.append(match.span())
    for match in detector.CORP_LABELED_VALUE.finditer(line):
        raw = match.group("value")
        span = match.span("value")
        if _spans_overlap(span, claimed):
            continue
        digits = re.sub(r"\D", "", raw)
        if not _corporate_shape(digits) or _is_person_identity_digits(digits):
            continue
        claimed.append(span)
        entities.append(_corporate_entity(raw, line_no, context, _valid_corporate_registration(digits)))
    for match in detector.CORP_REG.finditer(line):
        if _spans_overlap(match.span(), claimed):
            continue
        raw = match.group(0)
        digits = re.sub(r"\D", "", raw)
        if not _corporate_shape(digits):
            continue
        if not _valid_corporate_registration(digits):
            continue
        if _is_person_identity_digits(digits):
            continue
        entities.append(_corporate_entity(raw, line_no, context, True))
        claimed.append(match.span())
    return entities, claimed


def _valid_rrn(digits: str) -> bool:
    if len(digits) != 13 or not _plausible_identity_birthdate(digits):
        return False
    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = sum(int(digits[i]) * weights[i] for i in range(12))
    check = (11 - (total % 11)) % 10
    return check == int(digits[-1])


def _plausible_identity_birthdate(digits: str) -> bool:
    if not re.fullmatch(r"\d{13}", digits):
        return False
    century = 1900 if digits[6] in {"1", "2", "5", "6"} else 2000
    try:
        date(century + int(digits[:2]), int(digits[2:4]), int(digits[4:6]))
    except ValueError:
        return False
    return True


def _is_person_identity_digits(digits: str) -> bool:
    """Privacy-first: a plausible RRN/FRN is a natural-person ID, not an org number."""
    if not re.fullmatch(r"\d{13}", digits):
        return False
    if digits[6] not in {"1", "2", "3", "4", "5", "6", "7", "8"}:
        return False
    return _plausible_identity_birthdate(digits)


def _luhn(digits: str) -> bool:
    total = 0
    reverse = digits[::-1]
    for idx, char in enumerate(reverse):
        num = int(char)
        if idx % 2 == 1:
            num *= 2
            if num > 9:
                num -= 9
        total += num
    return total % 10 == 0


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def _valid_structured_bank_account(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not re.fullmatch(r"\d{9,18}", digits) or len(set(digits)) < 2:
        return False
    if PiiDetector.PHONE.fullmatch(digits) or PiiDetector.RRN.fullmatch(digits) or PiiDetector.FRN.fullmatch(digits):
        return False
    return True


def _line_contexts(lines: list[str]) -> dict[int, str]:
    contexts: dict[int, str] = {}
    block_id = 0
    depth = 0
    current = ""
    for idx, line in enumerate(lines, start=1):
        opens = line.count("{") + line.count("[")
        closes = line.count("}") + line.count("]")
        if depth == 0 and opens:
            block_id += 1
            current = f"jsonish_block:{block_id}"
        if current:
            contexts[idx] = current
        depth = max(0, depth + opens - closes)
        if depth == 0:
            current = ""
    return contexts


def _scope_from_context(context: str) -> str:
    if context.startswith("csv_row"):
        return "same_csv_row"
    if context.startswith("jsonish_block"):
        return "same_jsonish_block"
    return "line"


_BUSINESS_REG_HEADERS = frozenset(
    {
        "사업자등록번호",
        "사업자번호",
        "biz_no",
        "biz_number",
        "brn",
        "business_registration",
        "business_registration_number",
        "business_registration_no",
    }
)
_CORP_REG_HEADERS = frozenset(
    {
        "법인등록번호",
        "법인번호",
        "crn",
        "corp_reg",
        "corporate_registration",
        "corporate_registration_number",
        "corporate_registration_no",
    }
)
def _compact_header_key(header: str) -> str:
    return re.sub(r"[_-]+", "", normalize_header_label(header))


_NORMALIZED_BUSINESS_REG_HEADERS = frozenset(_compact_header_key(name) for name in _BUSINESS_REG_HEADERS)
_NORMALIZED_CORP_REG_HEADERS = frozenset(_compact_header_key(name) for name in _CORP_REG_HEADERS)
_NORMALIZED_SENSITIVE_CSV_HEADERS = frozenset(normalize_header_label(name) for name in SENSITIVE_CSV_HEADERS)
_SPLIT_JSON_KEY = re.compile(
    r"^[\[{,]?\s*[\"'](?P<key>[^\"']+)[\"']\s*:\s*[\"']?\s*$"
)
_SPLIT_JSON_CORP_VALUE = re.compile(r"(?<!\d)(\d{6}[- ]?\d{7}|\d{13})(?!\d)")
_SPLIT_JSON_BIZ_VALUE = re.compile(r"(?<!\d)(\d{3}[- ]\d{2}[- ]\d{5}|\d{10})(?!\d)")


def _org_header_kind(header: str) -> str | None:
    compact = _compact_header_key(header)
    if compact in _NORMALIZED_CORP_REG_HEADERS:
        return "corp"
    if compact in _NORMALIZED_BUSINESS_REG_HEADERS:
        return "biz"
    return None


def _pending_json_org_key(line: str) -> str | None:
    stripped = line.strip().rstrip(",")
    match = _SPLIT_JSON_KEY.match(stripped)
    if match is None:
        return None
    return _org_header_kind(match.group("key"))


def _extract_json_org_value(line: str, kind: str) -> tuple[tuple[int, int], str] | None:
    pattern = _SPLIT_JSON_CORP_VALUE if kind == "corp" else _SPLIT_JSON_BIZ_VALUE
    match = pattern.search(line)
    if match is None:
        return None
    return match.span(1), match.group(1)


def _split_json_org_claims(lines: list[str]) -> dict[int, list[tuple[int, int, str, str]]]:
    claims: dict[int, list[tuple[int, int, str, str]]] = {}
    pending: str | None = None
    for index, line in enumerate(lines, start=1):
        if pending is not None:
            extracted = _extract_json_org_value(line, pending)
            if extracted is not None:
                span, raw = extracted
                claims.setdefault(index, []).append((span[0], span[1], pending, raw))
            pending = None
        pending = _pending_json_org_key(line)
    return claims


def _parse_csv_table(text: str, file: str | None) -> tuple[list[str], list[list[str]]] | None:
    if file and Path(file).suffix.lower() not in {".csv", ".tsv"}:
        return None
    lines = text.splitlines()
    if not lines:
        return None
    suffix = Path(file).suffix.lower() if file else ""
    delimiter = "\t" if suffix == ".tsv" or ("\t" in lines[0] and "," not in lines[0]) else ","
    try:
        rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))
    except csv.Error:
        return None
    if len(rows) < 2:
        return None
    headers = [normalize_header_label(header) for header in rows[0]]
    return headers, rows


def _find_value_span(line: str, value: str, occupied: list[tuple[int, int]]) -> tuple[int, int] | None:
    if not value:
        return None
    start = 0
    while True:
        index = line.find(value, start)
        if index < 0:
            return None
        span = (index, index + len(value))
        if not _spans_overlap(span, occupied):
            return span
        start = index + 1


def _csv_org_claimed_spans(text: str, file: str | None) -> dict[int, list[tuple[int, int]]]:
    parsed = _parse_csv_table(text, file)
    if parsed is None:
        return {}
    headers, rows = parsed
    lines = text.splitlines()
    claims: dict[int, list[tuple[int, int]]] = {}
    for row_idx, row in enumerate(rows[1:], start=2):
        line = lines[row_idx - 1] if row_idx - 1 < len(lines) else ""
        occupied: list[tuple[int, int]] = []
        for col_idx, value in enumerate(row):
            header = headers[col_idx] if col_idx < len(headers) else ""
            cell = value.strip()
            digits = re.sub(r"\D", "", cell)
            kind = _org_header_kind(header)
            corp_cell = kind == "corp" and _corporate_shape(digits) and not _is_person_identity_digits(digits)
            business_cell = kind == "biz" and re.fullmatch(r"\d{10}", digits) is not None
            if not corp_cell and not business_cell:
                continue
            span = _find_value_span(line, cell, occupied)
            if span is None and cell != digits:
                span = _find_value_span(line, digits, occupied)
            if span is None:
                continue
            occupied.append(span)
            claims.setdefault(row_idx, []).append(span)
    return claims


def _entities_from_field(header: str, value: str, line: int, context: str) -> list[Entity]:
    value = value.strip()
    if not value:
        return []
    entities: list[Entity] = []
    if PiiDetector.EMAIL.fullmatch(value):
        entities.append(Entity("EMAIL", mask_value("EMAIL", value), line, context, "high", "same_csv_row"))
    if PiiDetector.PHONE.fullmatch(value):
        entities.append(Entity("PHONE", mask_value("PHONE", value), line, context, "high", "same_csv_row"))
    if PiiDetector.BIRTHDATE.fullmatch(value) and header in {"birth", "birthdate", "birthday", "date_of_birth", "dob", "생년월일", "생일"}:
        entities.append(Entity("BIRTHDATE", mask_value("BIRTHDATE", value), line, context, "medium", "same_csv_row"))
    if PiiDetector.VEHICLE.fullmatch(value):
        entities.append(Entity("VEHICLE_NUMBER", mask_value("VEHICLE_NUMBER", value), line, context, "medium", "same_csv_row"))
    if PiiDetector.TIMESTAMP.fullmatch(value):
        entities.append(Entity("TIMESTAMP", mask_value("TIMESTAMP", value), line, context, "medium", "same_csv_row"))
    if header in {"name", "user_name", "customer_name", "full_name", "이름", "성명", "고객명", "사용자명"} and re.fullmatch(r"[가-힣]{2,4}", value):
        entities.append(Entity("PERSON", mask_value("PERSON", value), line, context, "high", "same_csv_row"))
    if header in {"address", "addr", "주소"}:
        entities.append(Entity("ADDRESS", mask_value("ADDRESS", value), line, context, "medium", "same_csv_row"))
    if header in {"location", "loc", "place", "위치", "장소"}:
        entities.append(Entity("LOCATION", mask_value("LOCATION", value), line, context, "medium", "same_csv_row"))
    if header in {"account_id", "user_id", "customer_id", "userid", "customerid"}:
        entities.append(Entity("ACCOUNT_ID", mask_value("ACCOUNT_ID", value), line, context, "medium", "same_csv_row"))
    if header in {"ci", "connecting_info", "connecting_information", "연계정보"} and re.fullmatch(r"[A-Za-z0-9+/=_-]{20,}", value):
        entities.append(Entity("CI", mask_value("CI", value), line, context, "medium", "same_csv_row"))
    if header in {"di", "duplication_info", "duplication_information", "중복가입확인정보"} and re.fullmatch(r"[A-Za-z0-9+/=_-]{20,}", value):
        entities.append(Entity("DI", mask_value("DI", value), line, context, "medium", "same_csv_row"))
    if header in {"student_id", "employee_id", "member_id", "member_no", "customer_no", "학번", "사번", "회원번호", "고객번호", "수험번호"} and len(value) >= 4:
        entities.append(Entity("ACCOUNT_ID", mask_value("ACCOUNT_ID", value), line, context, "medium", "same_csv_row"))
    if header in {"patient_id", "patient_no", "medical_record_no", "환자번호", "차트번호", "진료번호", "의무기록번호", "병록번호"} and len(value) >= 4:
        entities.append(Entity("PATIENT_ID", mask_value("PATIENT_ID", value), line, context, "medium", "same_csv_row"))
    if header in {"health_insurance_id", "health_insurance_no", "건강보험번호", "건강보험증번호", "보험증번호"} and len(value) >= 6:
        entities.append(Entity("HEALTH_INSURANCE_ID", mask_value("HEALTH_INSURANCE_ID", value), line, context, "medium", "same_csv_row"))
    if header in {"device_id", "deviceid", "idfa", "gaid", "adid", "advertising_id", "firebase_installation_id", "installation_id", "기기id", "기기식별자"} and len(value) >= 12:
        entities.append(Entity("DEVICE_ID", mask_value("DEVICE_ID", value), line, context, "low", "same_csv_row"))
    if header in {"driver_license", "driver_license_no", "driver_license_number", "운전면허", "운전면허번호", "면허번호"} and PiiDetector.DRIVER_LICENSE.fullmatch(value):
        entities.append(Entity("DRIVER_LICENSE", mask_value("DRIVER_LICENSE", value), line, context, "medium", "same_csv_row"))
    if header in {
        "bank_account",
        "bank_account_no",
        "bank_account_number",
        "account_no",
        "account_number",
        "deposit_account",
        "계좌번호",
        "은행계좌",
        "은행계좌번호",
        "입금계좌",
        "입금계좌번호",
    } and _valid_structured_bank_account(value):
        entities.append(Entity("BANK_ACCOUNT", mask_value("BANK_ACCOUNT", value), line, context, "medium", "same_csv_row"))
    if normalize_header_label(header) in _NORMALIZED_SENSITIVE_CSV_HEADERS:
        entities.append(Entity("SENSITIVE_INFO", "sensitive-info:" + str(line), line, context, "medium", "same_csv_row"))
    digits = re.sub(r"\D", "", value)
    kind = _org_header_kind(header)
    if kind == "biz":
        if _valid_business_registration(digits):
            entities.append(Entity("BUSINESS_REGISTRATION", mask_value("BUSINESS_REGISTRATION", value), line, context, "high", "same_csv_row"))
    elif kind == "corp" and _corporate_shape(digits) and not _is_person_identity_digits(digits):
        entities.append(_corporate_entity(value, line, context, _valid_corporate_registration(digits)))
    return entities


def _dedupe_entities(entities: list[Entity]) -> list[Entity]:
    result: list[Entity] = []
    seen: set[tuple[str, str, int, str]] = set()
    for entity in entities:
        key = (entity.label, entity.evidence, entity.line, entity.context)
        if key in seen:
            continue
        seen.add(key)
        result.append(entity)
    return result
