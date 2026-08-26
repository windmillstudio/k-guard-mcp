# PIPC Reference Mapping

기준일: 2026-07-13

## 목적

K-Guard MCP의 개인정보 탐지는 단순 regex 목록이 아니라, 개보위/개인정보포털 자료에서 반복되는 판단 축을 제품 메타데이터로 반영한다.

이 문서는 법률 자문, 컴플라이언스 인증, 적법성 판정서가 아니다. 안경선배가 코드와 설정에서 추가 확인이 필요한 지점을 보수적으로 올리고, 사용자가 공식 원문과 전문가 검토로 이어가도록 돕는 engineering triage 기준표다.

## 현재 공식 기준 스냅샷

| 공식 기준 | 이 문서가 확인한 현행본 | 제품에서 연결하는 점검 축 |
| --- | --- | --- |
| 개인정보 보호법 | 2025-10-02 시행, 법률 제20897호 | 수집·이용 근거와 목적, 보유 종료 후 파기, 안전조치, 처리방침 |
| 개인정보 보호법 시행령 제30조 | 2026-05-19 시행, 대통령령 제36340호 | 접근권한, 인증, 접근통제, 암호화, 접속기록, 악성프로그램, 물리적 조치 |
| 개인정보의 안전성 확보조치 기준 | 2026-07-01 시행, 개인정보보호위원회고시 제2026-9호 | 개인정보처리시스템의 기술·관리적 통제 구현 흔적 |
| 개인정보 처리방침 작성지침 | 2026-04 개정 안내서 | 처리 목적, 항목, 보유기간, 제3자 제공·위탁 등 공개 문서와 코드의 불일치 후보 |

법령과 고시는 개정될 수 있다. 위 날짜 이후 배포본은 공식 원문을 다시 확인해야 하며, 탐지 결과만으로 법 위반이나 법 준수를 확정하지 않는다.

## 조문과 코드 점검의 연결

| 법적 판단 축 | 안경선배가 찾는 구현 신호 | 자동 판정하지 않는 것 |
| --- | --- | --- |
| 제15조 수집·이용 | 입력 필드, 동의·목적 표기, 서버 저장 흐름, 숨은 추가 수집 | 유효한 법적 근거의 최종 성립 여부 |
| 제21조 파기 | 만료·탈퇴 처리, 삭제 작업, 보유기간 설정, 백업 잔존 후보 | 조직 전체의 실제 파기 이행 |
| 제29조 및 시행령 제30조 안전조치 | 인증·인가, RLS/RBAC, 암호화, 비밀값, 로그, 외부 전송, 저장소 권한 | 물리 보안과 운영조직의 실제 통제 수준 |
| 제30조 처리방침 | 코드·스키마의 수집 항목과 처리방침·환경설정 간 차이 | 처리방침의 법률적 완전성 |

## 확인한 공개 자료

1. 국가법령정보센터 개인정보 보호법과 시행령
   - 현행 시행일과 조문 원문을 기준으로 수집·파기·안전조치·처리방침 축을 확인한다.
   - 시행령 제30조의 접근권한, 인증, 접근통제, 암호화, 접속기록 항목을 코드 감사 설명과 연결한다.

2. 국가법령정보센터 `개인정보의 안전성 확보조치 기준`
   - 2026-07-01 시행 고시 제2026-9호를 현재 스냅샷으로 기록한다.
   - 안경선배는 구현 흔적을 찾는 도구이므로 내부관리계획과 물리적 조치를 완료했다고 선언하지 않는다.

3. 개인정보보호위원회 `개인정보 처리방침 작성지침(2026.4.)`
   - 처리방침 텍스트와 실제 데이터 필드·흐름의 불일치 후보를 사람이 검토할 수 있게 연결한다.

4. `scvcoder/korean-privacy-law-mcp`
   - GitHub 공개 MCP.
   - README 기준 법제처 31개 도구, PIPC 공식 출처 인덱스, PIPC 공식 가이드 4종, 개인정보 포털 상담사례 1,745건, 총 2,432 chunks를 다룬다고 설명한다.
   - K-Guard는 이 저장소의 RAG 원문을 복사하지 않는다. 다만 "개보위 공식 자료를 자연어/도메인별로 검색하는 MCP가 이미 있다"는 비교/연동 후보로 본다.

5. 개보위 `가명정보 처리 가이드라인(2026.3 개정)`
   - 개보위 안내서 게시판의 현재 안내서.
   - K-Guard는 이 가이드라인의 방향을 "데이터 유형, 처리 목적, 처리 환경, 민감도, 결합 가능성을 함께 판단"하는 기준으로 반영한다.

6. 개보위 비정형데이터 가명처리 기준 보도자료
   - 이미지, 영상, 음성, 텍스트 등 비정형데이터에서 개인식별 가능성이 상황에 따라 달라질 수 있음을 강조한다.
   - K-Guard는 단건 이름/이메일보다 문맥, 결합, 뭉치, 흐름을 더 중요하게 본다.

7. 개보위 개발 협업도구 자격증명 관리 강화 보도참고
   - GitHub 등 개발 협업도구에 접근키, 비밀번호, API 토큰을 저장하지 않도록 관리할 필요가 있음을 강조한다.
   - K-Guard는 API key/secret 노출을 개인정보처리시스템 접근 위험으로 연결해 설명한다.

## K-Guard 분류 축

| 축 | 예시 | K-Guard 처리 |
| --- | --- | --- |
| 직접식별자 | 이름, 전화번호, 주민등록번호, 외국인번호, 여권, 면허 | 단건도 finding. 강한 식별자는 high/critical |
| 고유식별정보 후보 | 주민번호, 여권, 면허, 외국인번호 | 단건 high 이상, 응답 노출 시 leak tier |
| 금융/결제 식별자 | 카드번호, 계좌번호 | 단건 high/critical, 응답 노출 시 즉시 조치 |
| 서비스 식별자 | CI, DI, 회원번호, 고객번호, 학번, 사번, 주문번호 | 단건은 중간 위험, 이름/연락처/민감정보와 결합 시 상향 |
| 의료/건강 식별자 | 환자번호, 차트번호, 건강보험번호, 진료 문맥 | 결합 시 critical 후보 |
| 민감정보 후보 | 건강, 장애, 종교, 정치성향, 범죄경력, 유전정보 등 | 직접식별자/서비스 식별자와 결합 시 critical 후보 |
| 준식별자/행위 문맥 | 생년월일, IP, timestamp, 위치, 기기ID | 단건보다 결합/흐름/대량 노출에서 상향 |
| 자격증명 | API key, 접근키, 토큰, DB URL | 개인정보처리시스템 접근 위험으로 critical 후보 |

## 코드 반영

추가 모듈:

- `src/k_guard_mcp/privacy_taxonomy.py`

Finding에 추가된 메타데이터:

- `privacy_class`: 개인정보 분류
- `pipc_basis`: 개보위 자료에서 가져온 판단 축 설명
- `audit_depth`: 현재 finding이 어느 깊이까지 본 것인지
- `inspected_scope`: 무엇을 검사했는지
- `not_inspected`: 무엇을 검사하지 않았는지

적용 위치:

- 정적 PII detector: `PII_*` finding에 분류/근거/Depth 2 부여
- 결합 개인정보 detector: `KR_COMBO_*` finding에 결합위험/Depth 3 부여
- 동적 응답 PII/secret detector: `DYN_RESPONSE_PII_*`, `DYN_RESPONSE_SECRET_LEAK`에 동적 응답/자격증명 기준 부여
- 대시보드: 각 finding 카드에 개인정보 분류, 검사 깊이, 개보위 참고, 검사/미검사 범위 표시

## 다음 단계

1. `korean-privacy-law-mcp`와 선택 연동
   - 사용자가 법령/가이드 근거를 더 깊게 보고 싶을 때, K-Guard finding rule_id와 관련 가이드/상담사례 검색 질의를 연결한다.
   - 기본 스캔은 local-first로 유지하고, 외부 MCP/RAG 호출은 사용자가 켠 경우에만 수행한다.

2. PIPC 기준별 test fixture 확장
   - 의료기관, 약국, 학원, 인사/노무, 사회복지시설, 온라인 경품, 공공기관 도메인별 fixture 추가
   - "공개 안내 연락처"와 "실제 고객/환자/학생 데이터" 오탐 분리 강화

3. 내핵 감사 그래프 연결
   - source -> sink graph에 `privacy_class`를 표시한다.
   - 예: `회원가입 form(PERSON+PHONE)` -> `logger` -> `external http` -> `LLM prompt`

## Sources

- https://law.go.kr/LSW/lsInfoP.do?lsiSeq=270351
- https://law.go.kr/LSW/lsLinkCommonInfo.do?ancYnChk=&chrClsCd=010202&lsJoLnkSeq=1020398481
- https://www.law.go.kr/LSW/lsLinkCommonInfo.do?ancYnChk=&chrClsCd=010202&lsJoLnkSeq=1020398651
- https://www.law.go.kr/LSW/lsLawLinkInfo.do?chrClsCd=010202&lsJoLnkSeq=900079357
- https://law.go.kr/LSW/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1020398583
- https://www.law.go.kr/LSW/lsLawLinkInfo.do?chrClsCd=010202&lsJoLnkSeq=900079401
- https://www.law.go.kr/LSW/admRulLsInfoP.do?admRulNm=%EA%B0%9C%EC%9D%B8%EC%A0%95%EB%B3%B4%EC%9D%98+%EC%95%88%EC%A0%84%EC%84%B1+%ED%99%95%EB%B3%B4%EC%A1%B0%EC%B9%98+%EA%B8%B0%EC%A4%80&docType=JO&joNo=001300000&languageType=KO&paras=1
- https://www.pipc.go.kr/np/cop/bbs/selectBoardArticle.do?bbsId=BS217&mCode=&nttId=12018
- https://github.com/scvcoder/korean-privacy-law-mcp
- https://www.pipc.go.kr/np/cop/bbs/selectBoardArticle.do?bbsId=BS217&mCode=G010030000&nttId=11931
- https://www.pipc.go.kr/np/cop/bbs/selectBoardArticle.do?bbsId=BS074&mCode=C020010000&nttId=9899
- https://www.pipc.go.kr/np/cop/bbs/selectBoardArticle.do?bbsId=BS074&mCode=&nttId=12179
