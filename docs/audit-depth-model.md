# K-Guard MCP Audit Depth Model

작성일: 2026-07-06

## 북극성

K-Guard MCP의 목적은 단순히 "취약점 후보를 많이 띄우는 스캐너"가 아니다.

바이브코더가 자기 제품을 못 믿는 이유는 대개 다음 질문에 답하지 못하기 때문이다.

- 내 서비스가 개인정보를 어디서 받고 있는가?
- 그 값이 코드/서버/API/로그/외부 서비스/MCP tool/LLM 호출로 어디까지 흘러가는가?
- 공개 페이지에 나오는 회사 연락처와 실제 고객 데이터 노출을 구분할 수 있는가?
- 내가 무엇을 검사했고, 무엇을 검사하지 않았는지 설명할 수 있는가?
- 사고가 터지기 전에 "이 정도면 출시해도 된다/아직 안 된다"를 판단할 수 있는가?

따라서 K-Guard의 목표 깊이는 "표층 보안 스캔"이 아니라 "개인정보 데이터 흐름 감사"다.

## 깊이 단계

| 단계 | 비유 | 보는 것 | 한계 | K-Guard 목표 |
| --- | --- | --- | --- | --- |
| L0 | 표면 먼지 | 문자열 grep, 단순 secret/PII regex | 오탐/미탐 많음. 왜 문제인지 설명 약함 | 기본 탑재 |
| L1 | 표층 | env, config, source map, security headers, 공개 `/api`/`/admin` | 경로가 200인지까지만 보고 실제 기능/데이터 의미를 모름 | 기본 탑재 |
| L2 | 지각 | framework-aware route, OpenAPI, Next/Vite build artifact, dependency/SBOM | 코드와 실행 데이터 흐름 연결이 약함 | 기본 탑재 |
| L3 | 맨틀 | source-to-sink data flow: request/body/db/log/http/LLM/MCP/tool sink | 정적 추론이라 실제 런타임과 다를 수 있음 | 핵심 기능 |
| L4 | 외핵 | safe dynamic verification: 실제 앱에 비파괴 요청, 응답 전체 streaming 검사, audit log | 로그인/권한별 내부 화면은 사용자 세션 없이는 제한 | 핵심 기능 |
| L5 | 내핵 | privacy evidence graph: 데이터 항목, 수집 위치, 저장/로그/외부전송/보존/삭제/권한 경계까지 증거화 | 법적 인증은 아님. 사람 검토가 최종 필요 | 최종 목표 |

## "내핵까지 본다"의 의미

내핵 감사는 공격을 더 세게 하는 것이 아니다. 더 깊게 이해하고 증거를 남기는 것이다.

잘못된 방향:

- 무작위 경로 brute force
- 로그인 시도/비밀번호 추측
- form mutation/upload/delete
- exploit payload/fuzzing
- 타 origin 확장 스캔

K-Guard가 가야 할 방향:

- 같은 origin 안에서 허용된 요청만 수행
- body를 일부만 보지 않고 streaming으로 끝까지 검사
- raw body/value는 저장하지 않고 count/masked evidence만 저장
- 경로별로 "무엇을 봤고, 무엇이 없어서 통과했는지" audit log 기록
- 공개 안내 연락처와 고객/회원/환자/학생/직원 데이터 뭉치 노출을 구분
- 데이터가 request -> app code -> log/db/http/LLM/MCP sink로 흘러가는 경로를 그래프로 표시

## 내핵 감사 체크리스트

### 1. 데이터 재고

- 개인정보 후보 유형: 이름, 전화, 이메일, 주소, 생년월일, 주민등록번호, 여권, 운전면허, 외국인등록번호
- 한국 서비스 식별자: CI, DI, 회원번호, 고객번호, 주문번호, 학생번호, 사번, 환자번호, 건강보험 식별자
- 민감정보 후보: 건강/진료/장애/종교/정치성향/범죄/생체/위치/아동 관련 문맥
- 결합 개인정보: 이름+전화, 이름+이메일, 이름+주소, 환자번호+진료, 학생번호+이름, 고객번호+주문

### 2. 수집 지점

- HTML form
- API request body/query/header/cookie
- upload endpoint
- webhook
- MCP tool input
- LLM prompt/context
- third-party script/analytics

### 3. 저장 지점

- database model/schema/migration
- local file/cache
- browser localStorage/sessionStorage/indexedDB
- server session
- object storage
- backup/export

### 4. 출력 지점

- API response
- SSR/HTML render
- source map/build artifact
- log/console/error tracker
- analytics/event collector
- outbound HTTP/webhook
- email/SMS/Kakao/notification
- MCP tool output
- LLM response/tool call

### 5. 권한 경계

- 비로그인 사용자
- 로그인 사용자
- 본인 데이터
- 타인 데이터
- 관리자/운영자
- 파트너/외부 API
- MCP tool 권한

### 6. 보존/삭제

- 로그에 개인정보가 남는지
- 탈퇴/삭제 후 남는 데이터가 있는지
- error tracker/Sentry/analytics에 복제되는지
- export/download 기능이 과도한지
- 테스트/fixture/seed 데이터에 실제 값이 섞였는지

## 대시보드에서 보여줘야 할 방식

사용자는 "문제가 있다"보다 다음 설명을 원한다.

1. 내가 무엇을 봤는가
   - 예: `GET /api/users` 응답 전체를 streaming 검사했다.

2. 어떻게 판단했는가
   - 예: 같은 JSON 배열 안에서 `PERSON=12`, `EMAIL=12`, `PHONE=9`가 결합되어 bulk exposure로 판단했다.

3. 왜 위험한가
   - 예: 공개 회사 연락처 1개가 아니라 여러 사람의 연락처 목록으로 보인다.

4. 어떻게 고치는가
   - 예: 비로그인 응답 제거, auth guard 추가, 필요한 필드만 응답, 운영 로그 redaction, source map 비공개.

5. 무엇은 검사하지 않았는가
   - 예: 로그인 후 관리자 기능, 결제사 대시보드, 외부 origin, form mutation은 검사하지 않았다.

## K-Guard Depth Score

각 점검 결과는 깊이 점수를 가져야 한다.

| 점수 | 의미 |
| --- | --- |
| Depth 1 | 표층 신호만 확인했다. 예: header/source map/path status |
| Depth 2 | 응답/파일 전체를 검사했다. 예: streaming body scan complete |
| Depth 3 | 데이터 유형과 결합 정도를 해석했다. 예: 공개 연락처 vs 고객 목록 |
| Depth 4 | source-to-sink 흐름을 연결했다. 예: request body -> logger |
| Depth 5 | 권한/보존/외부전송까지 evidence graph로 연결했다 |

대시보드는 finding마다 다음을 표시한다.

- `검사 깊이`
- `검사 완료 여부`
- `검사한 데이터 범위`
- `검사하지 않은 범위`
- `근거 유형`
- `오탐 가능성`
- `수정 난이도`
- `우선순위`

## 경쟁 제품 대비 목표

많은 경쟁 MCP 스캐너는 다음 영역에 강하다.

- MCP tool poisoning
- hidden instruction
- exfiltration channel
- dangerous command
- dependency vulnerability
- SARIF/CI integration

K-Guard도 이 영역을 따라잡아야 한다. 하지만 월등해질 지점은 별도다.

K-Guard가 더 깊게 봐야 하는 영역:

- 한국 개인정보와 결합 개인정보
- 실제 웹 응답 전체 검사
- source-to-sink data flow
- log/external HTTP/LLM/MCP sink 추적
- 한국어 audit log와 쉬운 수정 가이드
- raw-free evidence graph

## 구현 로드맵

### Phase A: 표층에서 지각까지 안정화

- response body truncation 제거: streaming scanner로 끝까지 검사
- audit log에 "검사 완료"와 byte/count 범위 기록
- source map/OpenAPI/admin/API 판정의 오탐 tier 조정
- public contact vs bulk exposure 분리

### Phase B: 맨틀 data-flow

- Python/JS/TS source-to-sink heuristic 추가
- sinks: log, console, file, db, outbound HTTP, email/SMS, LLM call, MCP tool output
- sources: request, form, cookie, env, database, localStorage, MCP input, LLM context
- flow graph JSON schema 고정

### Phase C: 외핵 dynamic verification

- authorized same-origin probe만 수행
- GET/HEAD/OPTIONS 중심
- body 전체 streaming scan
- route별 pass/finding/review audit trail
- 로그인 세션 import는 사용자가 명시 제공한 경우만 read-only로 지원

### Phase D: 내핵 privacy evidence graph

- data inventory 자동 생성
- endpoint -> data type -> sink -> retention risk 연결
- finding마다 depth score 부여
- evidence pack export
- SARIF/GitHub Action/HTML report

### Phase E: MCP-native deep scan

- installed MCP config parser
- no-exec manifest/metadata scan
- tool description/prompt/resource hidden instruction 탐지
- exfil parameter/tool shadowing/cross-origin escalation 탐지
- MCP tool call 입력/출력의 개인정보 흐름 추적

## 제품 문구

K-Guard는 "해킹 도구"가 아니라 "출시 전 개인정보 흐름 감사관"이다.

권장 설명:

> K-Guard MCP는 바이브코딩으로 만든 웹앱과 MCP 구성을 대상으로 개인정보가 어디서 수집되고, 어디로 응답/로그/외부전송/LLM/MCP tool을 통해 흘러가는지 raw-free evidence graph로 보여주는 한국형 로컬 보안 감사 도구입니다.

금지 설명:

> 모든 취약점을 자동으로 찾아줍니다.
> 법적 컴플라이언스를 인증합니다.
> 임의 웹사이트를 공격적으로 스캔합니다.
> exploit/fuzzing으로 취약점을 증명합니다.
