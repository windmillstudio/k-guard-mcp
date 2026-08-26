from __future__ import annotations

import re

# Schema/field names inspected by Korean data governance. The raw/API/MCP PII
# detector must recognize each term unless it is listed as an intentional exception.
GOVERNANCE_SENSITIVE_FIELDS: tuple[str, ...] = (
    "medical_record",
    "medical_info",
    "diagnosis",
    "prescription",
    "health_condition",
    "건강상태",
    "disability",
    "religion",
    "race",
    "ethnicity",
    "ideology",
    "belief",
    "political_opinion",
    "union_membership",
    "genetic_data",
    "biometric_data",
    "criminal_record",
    "sexual_life",
    "sexual_orientation",
    "진료정보",
    "병력",
    "진단명",
    "처방정보",
    "장애정보",
    "장애",
    "종교",
    "인종",
    "민족",
    "사상",
    "신념",
    "정치적견해",
    "노동조합",
    "유전정보",
    "생체정보",
    "지문",
    "홍채",
    "범죄경력",
    "성생활",
    "성적지향",
)

# Contest-grade Korean sensitive concept/field terms that the detector must
# recognize with contextual and composite behavior.
CONTEST_SENSITIVE_CONCEPT_TERMS: tuple[str, ...] = (
    "장애",
    "장애정보",
    "생체정보",
    "지문",
    "홍채",
    "건강상태",
)

# Korean surfaces the detector is contracted to recognize. Includes the contest
# set plus the Korean names already declared in governance.
DETECTOR_KOREAN_SENSITIVE_CONCEPT_TERMS: tuple[str, ...] = (
    "장애",
    "장애정보",
    "생체정보",
    "지문",
    "홍채",
    "건강상태",
    "진료정보",
    "병력",
    "진단명",
    "처방정보",
    "종교",
    "인종",
    "민족",
    "사상",
    "신념",
    "정치적견해",
    "노동조합",
    "유전정보",
    "범죄경력",
    "성생활",
    "성적지향",
)

# Representative raw-text probes for governance terms that the PII detector must hit.
# Values are synthetic field/concept snippets, not live personal data.
GOVERNANCE_DETECTOR_PARITY_PROBES: dict[str, str] = {
    "medical_record": "medical_record=chart",
    "medical_info": "medical_info=note",
    "diagnosis": "diagnosis=flu",
    "prescription": "prescription=drug",
    "health_condition": "health_condition=stable",
    "건강상태": "건강상태=양호",
    "disability": "disability=yes",
    "religion": "religion=none",
    "political_opinion": "political_opinion=none",
    "union_membership": "union_membership=yes",
    "genetic_data": "genetic_data=stored",
    "biometric_data": "biometric_data=collected",
    "criminal_record": "criminal_record=none",
    "sexual_life": "sexual_life=private",
    "sexual_orientation": "sexual_orientation=unspecified",
    "진료정보": "진료정보=외래",
    "병력": "병력=없음",
    "진단명": "진단명=감기",
    "처방정보": "처방정보=있음",
    "장애정보": "장애정보=1급",
    "장애": "name: 홍길동 장애=1급",
    "종교": "종교=불교",
    "인종": "인종=한국",
    "민족": "민족=한민족",
    "사상": "사상=명시",
    "신념": "신념=명시",
    "정치적견해": "정치적견해=무당파",
    "노동조합": "노동조합=가입",
    "유전정보": "유전정보=수집",
    "생체정보": "생체정보=수집",
    "지문": "지문=등록",
    "홍채": "홍채=갈색",
    "범죄경력": "범죄경력=없음",
    "성생활": "성생활=비공개",
    "성적지향": "성적지향=비공개",
}

# English words that are valid schema field names but too noisy for raw-text
# detection. The Korean equivalents remain in the detector contract.
INTENTIONAL_PARITY_EXCEPTIONS: dict[str, str] = {
    "race": "English 'race' collides with race-condition and similar engineering prose; detector uses 인종.",
    "ethnicity": "English 'ethnicity' is left to 민족 to avoid noisy raw-text matches.",
    "ideology": "English 'ideology' is left to 사상 to avoid political-news false positives.",
    "belief": "English 'belief' is too generic for raw-text detection; detector uses 신념.",
}

INTENTIONAL_PARITY_EXCEPTION_PROBES: dict[str, str] = {
    "race": "race condition in the event loop",
    "ethnicity": "ethnicity column in the census extract",
    "ideology": "ideology coverage in the news brief",
    "belief": "belief in the compiler optimization",
}
if set(INTENTIONAL_PARITY_EXCEPTION_PROBES) != set(INTENTIONAL_PARITY_EXCEPTIONS):
    raise RuntimeError("intentional English exception probes must match INTENTIONAL_PARITY_EXCEPTIONS")

CONTEST_SENSITIVE_CONCEPT_PROBES: dict[str, str] = {
    "장애": "name: 홍길동 장애=1급",
    "장애정보": "장애정보=1급",
    "생체정보": "생체정보=수집",
    "지문": "지문=등록",
    "홍채": "홍채=갈색",
    "건강상태": "건강상태=양호",
}

# Fail closed at import if a contracted Korean detector term has no behavioral probe.
DETECTOR_KOREAN_SENSITIVE_CONCEPT_PROBES: dict[str, str] = {
    term: GOVERNANCE_DETECTOR_PARITY_PROBES[term] for term in DETECTOR_KOREAN_SENSITIVE_CONCEPT_TERMS
}

SENSITIVE_CSV_HEADERS: frozenset[str] = frozenset(
    {
        "장애",
        "장애정보",
        "생체정보",
        "지문",
        "홍채",
        "건강상태",
        "종교",
        "인종",
        "민족",
        "사상",
        "신념",
        "정치적견해",
        "노동조합",
        "유전정보",
        "범죄경력",
        "성생활",
        "성적지향",
        "disability",
        "disability_type",
        "disability_status",
        "religion",
        "biometric_data",
        "health_condition",
        "genetic_data",
        "criminal_record",
        "sexual_orientation",
        "장애등급",
        "장애유무",
        "장애구분",
        "장애종류",
        "장애여부",
        "장애유형",
    }
)

def normalize_header_label(header: str) -> str:
    """Normalize a CSV/JSON field name: strip a leading BOM and collapse spacing.

    Underscores stay so English schema names remain intact. This is header
    normalization only; callers must not strip BOM from arbitrary values.
    """
    cleaned = str(header).lstrip("\ufeff").strip().casefold()
    return re.sub(r"\s+", "", cleaned)


_PERSON_FIELD_HINT = re.compile(
    r"(?:name|user_name|customer_name|full_name|이름|성명|고객명|사용자명)[\"'\s:=]+[\"']?[가-힣]{2,4}",
    re.IGNORECASE,
)
_PERSON_RECORD_HINT = re.compile(
    r"(?:회원|고객|대상자|환자|근로자|직원|복지대상자)\s*[가-힣]{2,4}",
)
_DISABILITY_INCIDENT = re.compile(
    r"(네트워크|서버|시스템|서비스|장비|회선|트래픽|프로세스|인스턴스|클러스터|노드|애플리케이션|앱|인프라|데이터베이스|디비)\s*장애|"
    r"장애\s*[:=]?\s*(발생|조치|대응|복구|처리|현황|원인|구간|시간|알람|알림|로그|모니터링|전파|공지|티켓|코드|신고|접수|이력|건수|율)|"
    r"장애정보\s*[:=]?\s*(?:대시보드|알림|채널|모니터링|로그|현황|복구)|"
    r"장애코드|"
    r"장애인\s*접근성|"
    r"접근성\s*가이드"
)
_OBSTACLE = re.compile(r"장애물")
_DISABILITY_TYPES = ("청각장애", "지체장애", "시각장애", "발달장애", "정신장애")
_DISABILITY_FIELD_STANDALONE = (
    "장애",
    "장애정보",
    "장애유무",
    "장애구분",
    "장애종류",
    "장애등급",
    "장애여부",
    "장애유형",
    "장애 등급",
)
_DISABILITY_SPECIFIC_ASSIGNMENT = re.compile(
    r"['\"`]장애(?:정보|유무|구분|종류|등급|여부|유형)?['\"`]\s*[:=]|"
    r"(?:^|[^가-힣A-Za-z0-9_])장애(?:유무|구분|종류|등급|여부|유형)\s*[:=]|"
    r"장애\s*(?:등급|유형|종류|여부|유무)\s*[:=]|"
    r"장애\s*등록(?:\s*판정)?\s*[:=]|"
    r"장애복지(?:카드)?(?:\s*발급(?:\s*대상)?)?\s*[:=]"
)
_DISABILITY_GENERIC_ASSIGNMENT = re.compile(
    r"(?:^|[^가-힣A-Za-z0-9_\"'`])장애(?:정보)?\s*[:=]"
)
_DISABILITY_FIELD_MENTION = re.compile(r"장애\s*(?:유형|종류|등급|여부|유무|정보|등록|복지)")
_DISABILITY_TAG = re.compile(r"</?장애\s*>")
_DISABILITY_TABLE = re.compile(r"\|\s*장애\s*\|")
_DISABILITY_EN_FIELD = re.compile(
    r"['\"`]?\bdisability(?:_type|_status|_grade|_code)?['\"`]?\s*[:=]",
    re.IGNORECASE,
)
_KOREAN_SENSITIVE_ASSIGNMENT = re.compile(
    r"['\"`]?(?:종교|인종|민족|사상|신념|정치적\s*견해|유전정보|범죄경력|"
    r"성생활|성적\s*지향|건강상태|진료정보|병력|진단명|처방정보|"
    r"노동조합(?:\s*가입(?:여부)?)?|"
    r"생체정보(?:\s*수집(?:여부)?)?)['\"`]?\s*[:=]"
)
_EN_SEXUAL_FIELD = re.compile(
    r"['\"`]?\bsexual[_ -]?(?:orientation|life)['\"`]?\s*[:=]",
    re.IGNORECASE,
)
_KOREAN_SENSITIVE_STANDALONE = (
    "종교",
    "인종",
    "민족",
    "사상",
    "신념",
    "정치적견해",
    "정치적 견해",
    "노동조합",
    "유전정보",
    "범죄경력",
    "성생활",
    "성적지향",
    "생체정보",
    "건강상태",
    "진료정보",
    "병력",
    "진단명",
    "처방정보",
)
_IDEOLOGY_NEGATIVE = re.compile(r"사상자|사상\s*(?:최대|최다|최고|최초|유례|최저|최악)")
_FINGERPRINT_NEGATIVE = re.compile(
    r"(?:디지털|파일|코드|해시|인증서|브라우저|콘텐츠|문서|커밋|git|tls|ja3|sha-?1|sha-?256|md5|checksum|빌드|바이너리)\s*지문|"
    r"지문\s*(?:해시|알고리즘|검증|비교|분석)|"
    r"(?:수능|국어|독해|시험|문제|영어|논술|교과서).{0,12}지문|"
    r"(?:다음|제시된|해당|아래)\s*지문|"
    r"지문(?:을|에서)?\s*(?:참고|근거)|"
    r"(?:면접|대본|연극|스크립트)\s*지문|"
    r"이\s*지문을\s*읽|"
    r"지문을\s*읽고|"
    r"\bfingerprint\b",
    re.IGNORECASE,
)
_FINGERPRINT_POSITIVE = re.compile(r"지문(?:정보|데이터|패턴|인식|인증|등록|스캔|수집|생체|코드|값|템플릿)")
_FINGERPRINT_FIELD = re.compile(r"['\"`]지문(?:정보)?['\"`]\s*:|(?:^|[^가-힣A-Za-z0-9_])지문(?:정보)?\s*[:=]")
_FINGERPRINT_ACTION = re.compile(r"지문\s*(?:등록|인증|인식|수집|스캔|검증|채취|대조|저장|입력)")
_FINGERPRINT_STANDALONE = ("지문", "지문정보")
_HEALTH_NEGATIVE = re.compile(r"(?:시스템|서버|클러스터|서비스|인스턴스|노드|애플리케이션|앱)\s*건강상태")
_IRIS_POSITIVE = re.compile(r"홍채(?:정보|데이터|패턴|인식|인증|등록|스캔|수집|생체|코드|값)")
_IRIS_FIELD = re.compile(r"['\"`]홍채['\"`]\s*:|(?:^|[^가-힣A-Za-z0-9_])홍채\s*[:=]")
_IRIS_ACTION = re.compile(r"홍채\s*(?:등록|인증|인식|수집|스캔|검증|채취|대조)")
_IRIS_NEGATIVE = re.compile(
    r"홍채\s*(?:모양|무늬|문양|꽃|그림|장식|도안|잎)|"
    r"(?:꽃|식물|정원|창포|꽃잎)\s*홍채|"
    r"홍채처럼"
)


def _standalone_token(line: str, token: str) -> bool:
    return line.strip() == token


def _disability_structured(line: str) -> bool:
    stripped = line.strip()
    if stripped in _DISABILITY_TYPES or stripped in _DISABILITY_FIELD_STANDALONE:
        return True
    if _DISABILITY_SPECIFIC_ASSIGNMENT.search(line) is not None:
        return True
    if _DISABILITY_TAG.search(line) is not None or _DISABILITY_TABLE.search(line) is not None:
        return True
    if _DISABILITY_EN_FIELD.search(line) is not None:
        return True
    if (_PERSON_FIELD_HINT.search(line) is not None or _PERSON_RECORD_HINT.search(line) is not None) and (
        "장애" in line and _DISABILITY_FIELD_MENTION.search(line) is not None
        or _DISABILITY_SPECIFIC_ASSIGNMENT.search(line) is not None
    ):
        return True
    return False


def _disability_sensitive(line: str) -> bool:
    if _disability_structured(line):
        return True
    remainder = _DISABILITY_INCIDENT.sub(" ", line)
    remainder = _OBSTACLE.sub(" ", remainder)
    person_bound = _PERSON_FIELD_HINT.search(line) is not None or _PERSON_RECORD_HINT.search(line) is not None
    if person_bound and (
        any(token in remainder for token in _DISABILITY_TYPES)
        or ("장애" in remainder and _DISABILITY_FIELD_MENTION.search(remainder) is not None)
        or (_PERSON_FIELD_HINT.search(remainder) is not None and "장애" in remainder)
        or _DISABILITY_GENERIC_ASSIGNMENT.search(remainder) is not None
    ):
        return True
    if _DISABILITY_GENERIC_ASSIGNMENT.search(remainder) is not None:
        return True
    if _OBSTACLE.search(line) is not None or _DISABILITY_INCIDENT.search(line) is not None:
        return False
    if _PERSON_FIELD_HINT.search(line) is not None and "장애" in line:
        return True
    return False


def _korean_sensitive_binding(line: str) -> bool:
    if _IDEOLOGY_NEGATIVE.search(line) is not None and _KOREAN_SENSITIVE_ASSIGNMENT.search(line) is None:
        return False
    if _HEALTH_NEGATIVE.search(line) is not None:
        remainder = _HEALTH_NEGATIVE.sub(" ", line)
        if _KOREAN_SENSITIVE_ASSIGNMENT.search(remainder) is None and remainder.strip() not in _KOREAN_SENSITIVE_STANDALONE:
            return False
        line = remainder
    if _KOREAN_SENSITIVE_ASSIGNMENT.search(line) is not None:
        return True
    stripped = line.strip()
    if stripped in _KOREAN_SENSITIVE_STANDALONE:
        return True
    if _EN_SEXUAL_FIELD.search(line) is not None:
        return True
    return False


def _fingerprint_sensitive(line: str) -> bool:
    if "지문" not in line:
        return False
    if (
        _FINGERPRINT_POSITIVE.search(line) is not None
        or _FINGERPRINT_FIELD.search(line) is not None
        or _FINGERPRINT_ACTION.search(line) is not None
    ):
        return True
    if _FINGERPRINT_NEGATIVE.search(line) is not None:
        return False
    if _PERSON_FIELD_HINT.search(line) is not None or _PERSON_RECORD_HINT.search(line) is not None:
        return True
    return line.strip() in _FINGERPRINT_STANDALONE


def _iris_sensitive(line: str) -> bool:
    if "홍채" not in line:
        return False
    if (
        _IRIS_POSITIVE.search(line) is not None
        or _IRIS_FIELD.search(line) is not None
        or _IRIS_ACTION.search(line) is not None
    ):
        return True
    if _IRIS_NEGATIVE.search(line) is not None:
        return False
    return False


def raw_text_has_sensitive_concept(line: str) -> bool:
    """True when a line carries a sensitive field/concept after false-positive controls."""
    if _disability_sensitive(line):
        return True
    if _korean_sensitive_binding(line):
        return True
    if _EN_SEXUAL_FIELD.search(line) is not None:
        return True
    if _iris_sensitive(line):
        return True
    if _fingerprint_sensitive(line):
        return True
    return False


def parity_contract_gaps() -> tuple[str, ...]:
    """Governance terms that lack a detector probe and are not intentional exceptions."""
    covered = set(GOVERNANCE_DETECTOR_PARITY_PROBES) | set(INTENTIONAL_PARITY_EXCEPTIONS)
    return tuple(name for name in GOVERNANCE_SENSITIVE_FIELDS if name not in covered)
