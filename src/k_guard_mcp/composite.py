from __future__ import annotations

from dataclasses import dataclass

from k_guard_mcp.ids import IdFactory
from k_guard_mcp.models import Component, Entity, Finding
from k_guard_mcp.privacy_taxonomy import metadata_for_labels


@dataclass(frozen=True)
class CompositeRule:
    rule_id: str
    title: str
    labels: frozenset[str]
    severity: str
    confidence: str
    why: str
    recommendation: str


RULES = [
    CompositeRule("KR_COMBO_PERSON_PHONE", "Name and phone number combined", frozenset({"PERSON", "PHONE"}), "high", "high", "A name and phone number can identify a person directly.", "Use synthetic test data and mask phone numbers in logs and fixtures."),
    CompositeRule("KR_COMBO_PERSON_EMAIL", "Name and email combined", frozenset({"PERSON", "EMAIL"}), "high", "high", "A name and email can identify a person directly.", "Use synthetic emails or mask email addresses."),
    CompositeRule("KR_COMBO_PERSON_ADDRESS", "Name and address combined", frozenset({"PERSON", "ADDRESS"}), "high", "high", "A name and address can identify a person directly.", "Remove real addresses or replace them with synthetic addresses."),
    CompositeRule("KR_COMBO_PERSON_BIRTHDATE", "Name and birthdate combined", frozenset({"PERSON", "BIRTHDATE"}), "high", "high", "A name and birthdate increases identifiability.", "Avoid storing real birthdates in fixtures or logs."),
    CompositeRule("KR_COMBO_PERSON_RRN", "Name and resident registration number combined", frozenset({"PERSON", "RRN"}), "critical", "high", "A name combined with a resident registration number is a direct unique identifier exposure.", "Remove resident registration numbers from fixtures/logs and require a strict legal basis plus access control for production handling."),
    CompositeRule("KR_COMBO_PERSON_CI", "Name and CI combined", frozenset({"PERSON", "CI"}), "critical", "high", "A name combined with CI can link identity across service contexts.", "Do not expose CI with names outside approved identity-verification flows; mask or tokenize before logging."),
    CompositeRule("KR_COMBO_PERSON_DI", "Name and DI combined", frozenset({"PERSON", "DI"}), "critical", "high", "A name combined with DI can link identity inside membership workflows.", "Do not expose DI with names outside approved identity-verification flows; mask or tokenize before logging."),
    CompositeRule("KR_COMBO_PERSON_BANK_ACCOUNT", "Name and bank account combined", frozenset({"PERSON", "BANK_ACCOUNT"}), "critical", "high", "A name combined with a bank account number is high-impact financial personal data.", "Mask account numbers and separate account-holder names from financial identifiers in logs and exports."),
    CompositeRule("KR_COMBO_PERSON_CREDIT_CARD", "Name and card number combined", frozenset({"PERSON", "CREDIT_CARD"}), "critical", "high", "A name combined with a card number is high-impact financial personal data.", "Never store real card numbers in fixtures/logs; use payment tokens or test card numbers only."),
    CompositeRule("KR_COMBO_PERSON_HEALTH_INSURANCE", "Name and health insurance id combined", frozenset({"PERSON", "HEALTH_INSURANCE_ID"}), "critical", "high", "A name combined with a health-insurance identifier can identify a person in a sensitive healthcare context.", "Remove real health-insurance identifiers from exports and restrict healthcare identifiers to approved systems."),
    CompositeRule("KR_COMBO_PERSON_ACCOUNT_ID", "Name and service account id combined", frozenset({"PERSON", "ACCOUNT_ID"}), "high", "medium", "A name combined with a service identifier such as a student number, employee number, member number, or customer id can identify a real person inside a service.", "Mask service identifiers in fixtures and avoid returning them with direct names unless required."),
    CompositeRule("KR_COMBO_PERSON_PATIENT_ID", "Name and patient id combined", frozenset({"PERSON", "PATIENT_ID"}), "high", "high", "A name combined with a patient or medical-record number can identify a person in a healthcare context.", "Remove real patient identifiers from fixtures/logs and require strict access control for healthcare records."),
    CompositeRule("KR_COMBO_PHONE_ADDRESS", "Phone and address combined", frozenset({"PHONE", "ADDRESS"}), "high", "medium", "Phone plus address can identify a household or person.", "Separate or mask contact and address data."),
    CompositeRule("KR_COMBO_EMAIL_ORDER", "Email and order id combined", frozenset({"EMAIL", "ORDER_ID"}), "medium", "medium", "Contact and order data can expose service usage.", "Avoid logging contact and order identifiers together."),
    CompositeRule("KR_COMBO_IP_ACCOUNT_TIME", "IP, account, and timestamp combined", frozenset({"IP_ADDRESS", "ACCOUNT_ID", "TIMESTAMP"}), "high", "medium", "IP plus account and time context can identify access activity.", "Reduce retention and avoid broad exposure of access logs."),
    CompositeRule("KR_COMBO_VEHICLE_LOCATION_TIME", "Vehicle, location, and timestamp combined", frozenset({"VEHICLE_NUMBER", "LOCATION", "TIMESTAMP"}), "high", "medium", "Vehicle location at a timestamp can expose movement history.", "Avoid storing real vehicle/location histories in logs or fixtures."),
    CompositeRule("KR_COMBO_MEDICAL_DIRECT_IDENTIFIER", "Medical information with direct identifier", frozenset({"MEDICAL_INFO", "PERSON"}), "critical", "high", "Medical context combined with a person is sensitive personal information.", "Remove real medical data and strictly control access."),
    CompositeRule("KR_COMBO_MEDICAL_PATIENT_ID", "Medical information with patient id", frozenset({"MEDICAL_INFO", "PATIENT_ID"}), "critical", "high", "Medical context combined with a patient or chart number is sensitive personal information even without a visible name.", "Do not expose patient identifiers with medical context outside authenticated clinical workflows."),
    CompositeRule("KR_COMBO_SENSITIVE_DIRECT_IDENTIFIER", "Sensitive information with direct identifier", frozenset({"SENSITIVE_INFO", "PERSON"}), "critical", "high", "Sensitive categories such as religion, political opinion, union membership, disability, genetic, criminal, or similar data become high-risk when linked to a person.", "Remove real sensitive categories from fixtures/logs and strictly limit access in production."),
    CompositeRule("KR_COMBO_SENSITIVE_ACCOUNT_ID", "Sensitive information with service account id", frozenset({"SENSITIVE_INFO", "ACCOUNT_ID"}), "high", "medium", "Sensitive categories linked to an internal account or member id can still identify a person inside the service.", "Avoid storing sensitive categories next to service identifiers unless there is a clear purpose and access control."),
]


class CompositePiiEngine:
    def __init__(self, id_factory: IdFactory | None = None, window_lines: int = 3) -> None:
        self.ids = id_factory or IdFactory()
        self.window_lines = window_lines

    def scan_entities(self, entities: list[Entity], file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, tuple[tuple[str, int | None, str], ...]]] = set()
        for scope, group in _semantic_groups(entities).items():
            labels = {normal_label(other.label) for other in group}
            for rule in RULES:
                if rule.labels.issubset(labels):
                    selected = _select_components(group, rule.labels)
                    if not selected:
                        continue
                    key = (rule.rule_id, scope, tuple(sorted((component.label, component.line, component.evidence) for component in selected)))
                    if key in seen:
                        continue
                    seen.add(key)
                    line_start = min(component.line or 0 for component in selected)
                    line_end = max(component.line or 0 for component in selected)
                    privacy_meta = metadata_for_labels((component.label for component in selected), audit_depth=3)
                    findings.append(Finding(
                        id=self.ids.next(),
                        source="static",
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        confidence=_confidence_for_scope(rule.confidence, scope),
                        title=rule.title,
                        file=file,
                        line_start=line_start,
                        line_end=line_end,
                        scope=scope.split(":", 1)[0],
                        evidence=" + ".join(component.evidence for component in selected),
                        components=selected,
                        why_it_matters=rule.why,
                        recommendation=rule.recommendation,
                        privacy_class=str(privacy_meta["privacy_class"]),
                        pipc_basis=str(privacy_meta["pipc_basis"]),
                        audit_depth=int(privacy_meta["audit_depth"]),
                        inspected_scope="동일 줄/JSON 유사 블록/CSV 행 안에서 여러 개인정보 후보가 결합되는지 검사했습니다.",
                        not_inspected="업무상 필요한 결합인지, 동의/법령 근거와 접근권한이 적정한지는 사람 검토가 필요합니다.",
                    ))
        return findings


def normal_label(label: str) -> str:
    if label == "RRN_VALID":
        return "RRN"
    return label


def _select_components(entities: list[Entity], labels: frozenset[str]) -> list[Component]:
    selected: list[Component] = []
    used: set[str] = set()
    for entity in sorted(entities, key=lambda item: item.line):
        label = normal_label(entity.label)
        if label in labels and label not in used:
            selected.append(Component(label, entity.evidence, entity.line))
            used.add(label)
    return selected if used == set(labels) else []


def _semantic_groups(entities: list[Entity]) -> dict[str, list[Entity]]:
    groups: dict[str, list[Entity]] = {}
    for entity in entities:
        if entity.context.startswith(("csv_row:", "jsonish_block:")):
            key = entity.context
        else:
            key = f"same_line:{entity.line}"
        groups.setdefault(key, []).append(entity)
    return groups


def _confidence_for_scope(base: str, scope: str) -> str:
    if scope.startswith(("csv_row:", "jsonish_block:")):
        return base
    return "medium" if base == "high" else base
