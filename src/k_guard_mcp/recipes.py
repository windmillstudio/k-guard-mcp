from __future__ import annotations

from copy import deepcopy


Recipe = dict[str, object]


EXACT_RECIPES: dict[str, Recipe] = {
    "DYN_UNAUTH_ADMIN_ACCESS": {
        "title": "관리자 기능 인증 누락",
        "impact": "로그인하지 않은 사용자가 관리자 기능 또는 관리자 데이터에 접근할 수 있습니다.",
        "fix_steps": [
            "서버 middleware에서 세션과 관리자 권한을 확인합니다.",
            "프론트엔드 route guard만 믿지 말고 API/DB layer에서 다시 검증합니다.",
            "인증 실패는 401, 권한 부족은 403 또는 로그인 redirect로 처리합니다.",
        ],
        "test_suggestions": [
            "비로그인 GET /admin 요청이 401/403/302를 반환하는지 테스트합니다.",
            "일반 사용자 세션으로 관리자 API가 거부되는지 테스트합니다.",
        ],
        "verification": "동적 probe를 다시 실행해 DYN_UNAUTH_ADMIN_ACCESS가 사라졌는지 확인합니다.",
    },
    "DYN_UNAUTH_API_JSON": {
        "title": "인증 없는 API JSON 응답",
        "impact": "공개 의도가 없는 사용자/주문/관리 데이터가 API로 노출될 수 있습니다.",
        "fix_steps": [
            "공개 API인지 비공개 API인지 먼저 분류합니다.",
            "비공개 API라면 서버에서 session/JWT/API key를 검증합니다.",
            "목록 응답은 필요한 필드만 내려보내고 개인정보 필드는 마스킹합니다.",
        ],
        "test_suggestions": [
            "비로그인 API 요청이 401/403을 반환하는지 테스트합니다.",
            "다른 사용자 데이터 ID로 조회할 때 404/403이 반환되는지 테스트합니다.",
        ],
        "verification": "probe_http를 다시 실행해 비공개 API가 로그인 없이 JSON을 반환하지 않는지 확인합니다.",
    },
    "DYN_PUBLIC_API_JSON_REVIEW": {
        "title": "공개 API 의도 확인",
        "impact": "현재 응답에는 민감·비공개 레코드 단서가 없지만 공개 범위가 의도와 다르면 이후 필드 추가로 노출이 생길 수 있습니다.",
        "fix_steps": ["이 endpoint가 공개 API인지 manifest와 API 문서에 명시합니다.", "공개 응답 DTO를 allowlist로 고정하고 사용자·권한·내부 필드를 제외합니다."],
        "test_suggestions": ["비로그인 응답의 key 집합이 승인된 공개 DTO와 같은지 테스트합니다."],
        "verification": "동일 endpoint를 다시 probe하고 비공개 필드가 없는지 확인합니다.",
    },
    "DYN_EXPOSED_ENV_FILE": {
        "title": "환경파일 공개",
        "impact": "DB URL, API key, token 같은 운영 비밀이 웹에서 보일 수 있습니다.",
        "fix_steps": [
            "public web root에서 .env 파일을 제거합니다.",
            "웹서버/호스팅 설정에서 dotfile 접근을 403/404로 차단합니다.",
            "실제 secret이 있었다면 즉시 revoke/rotate 합니다.",
        ],
        "test_suggestions": ["GET /.env가 403 또는 404인지 테스트합니다."],
        "verification": "deep_active probe를 다시 실행해 DYN_EXPOSED_ENV_FILE이 사라졌는지 확인합니다.",
    },
    "DYN_EXPOSED_GIT_CONFIG": {
        "title": "Git metadata 공개",
        "impact": "저장소 remote, 구조, 객체 접근 단서가 노출될 수 있습니다.",
        "fix_steps": [
            "운영 배포물에서 .git 디렉터리를 제외합니다.",
            "웹서버에서 /.git/ 접근을 403/404로 차단합니다.",
        ],
        "test_suggestions": ["GET /.git/config가 403 또는 404인지 테스트합니다."],
        "verification": "deep_active probe를 다시 실행해 .git/config 노출이 사라졌는지 확인합니다.",
    },
    "DYN_EXPOSED_BACKUP_OR_DUMP": {
        "title": "백업/DB dump 공개",
        "impact": "DB dump 안의 개인정보와 secret이 통째로 노출될 수 있습니다.",
        "fix_steps": [
            "backup.sql, dump.sql, backup.zip을 public web root 밖으로 이동합니다.",
            "백업 저장소에 인증, 암호화, 수명 정책을 적용합니다.",
            "노출된 dump에 secret이 있었다면 관련 키를 회전합니다.",
        ],
        "test_suggestions": ["대표 backup/dump 경로가 403/404인지 테스트합니다."],
        "verification": "deep_active probe를 다시 실행해 백업/덤프 노출 룰이 사라졌는지 확인합니다.",
    },
    "DYN_PUBLIC_DEBUG_ENDPOINT": {
        "title": "디버그/런타임 endpoint 공개",
        "impact": "서버 상태, 환경, 내부 경로, dependency 정보가 외부에 노출될 수 있습니다.",
        "fix_steps": [
            "운영 환경에서 phpinfo/server-status/actuator/env/debug endpoint를 끕니다.",
            "운영자용 endpoint는 VPN, 사내망, IP allowlist, 관리자 인증 뒤로 이동합니다.",
        ],
        "test_suggestions": ["대표 debug endpoint가 외부에서 403/404인지 테스트합니다."],
        "verification": "deep_active probe를 다시 실행해 DYN_PUBLIC_DEBUG_ENDPOINT가 사라졌는지 확인합니다.",
    },
    "CONFIG_PUBLIC_ENV_SECRET": {
        "title": "클라이언트 공개 env 이름에 secret 의미 포함",
        "impact": "NEXT_PUBLIC/VITE/REACT_APP prefix를 통해 secret이 브라우저 번들로 들어갈 수 있습니다.",
        "fix_steps": [
            "secret은 server-only 환경변수로 옮깁니다.",
            "클라이언트에는 공개 가능한 anon/public key만 둡니다.",
            "노출 가능성이 있던 key는 rotate 합니다.",
        ],
        "test_suggestions": ["빌드 산출물에서 secret prefix가 검색되지 않는지 테스트합니다."],
        "verification": "scan_workspace를 다시 실행해 CONFIG_PUBLIC_ENV_SECRET이 사라졌는지 확인합니다.",
    },
    "MCP_TOOL_POISONING": {
        "title": "MCP tool poisoning",
        "impact": "도구 설명/스키마/프롬프트가 agent 행동을 숨은 지시로 오염시킬 수 있습니다.",
        "fix_steps": [
            "도구 metadata에서 숨은 지시, 사용자에게 숨기라는 문구, 외부 전송 지시를 제거합니다.",
            "MCP 서버 package/command/source를 검증하고 버전을 고정합니다.",
            "위험 서버는 승인 전 비활성화합니다.",
        ],
        "test_suggestions": ["scan_mcp_config를 실행해 MCP_TOOL_POISONING이 재발하지 않는지 확인합니다."],
        "verification": "scan_mcp_config 또는 scan_workspace를 다시 실행합니다.",
    },
    "JS_TS_INTERPROCEDURAL_ROUTE_SERVICE_IDOR": {
        "title": "JS/TS route-to-service IDOR 후보",
        "impact": "라우트가 요청 ID를 서비스/헬퍼 데이터 조회에 넘기고 양쪽 모두 소유자 범위를 보이지 않으면 다른 사용자의 객체를 조회하는 버그가 될 수 있습니다.",
        "fix_steps": [
            "route handler 첫 부분에서 session/JWT/API user를 확인합니다.",
            "service 함수 signature에 actor/user/tenant scope를 명시적으로 전달합니다.",
            "DB query에 id만 넣지 말고 userId/ownerId/tenantId/teamId 조건을 함께 넣습니다.",
            "다른 사용자 ID로 호출했을 때 403 또는 404가 반환되는 테스트를 추가합니다.",
        ],
        "test_suggestions": [
            "Next.js route 또는 Express handler 단위 테스트에서 params.id가 타 사용자 객체일 때 거부되는지 확인합니다.",
            "service 함수 테스트에서 actor scope 없이 객체가 반환되지 않는지 확인합니다.",
        ],
        "verification": "scan_workspace(include_flow=true)를 다시 실행해 JS_TS_INTERPROCEDURAL_ROUTE_SERVICE_IDOR가 사라졌는지 확인합니다.",
    },
}


PREFIX_RECIPES: list[tuple[str, Recipe]] = [
    (
        "WEB_",
        {
            "title": "웹 요청 입력 경계 위험",
            "impact": "요청 입력이 SQL, 명령 실행, 파일 경로, 외부 URL, HTML 같은 위험 sink로 직접 들어가면 주입·SSRF·경로조작·XSS로 이어질 수 있습니다.",
            "fix_steps": ["요청 값을 schema로 검증하고 허용값만 남깁니다.", "문자열 조립 대신 파라미터화 API와 고정 allowlist를 사용합니다.", "해당 경계에 공격 입력 회귀 테스트를 추가합니다."],
            "test_suggestions": ["대표 공격 입력이 실행되지 않고 4xx로 거부되는지 확인합니다."],
            "verification": "scan_workspace와 관련 단위/통합 테스트를 다시 실행합니다.",
        },
    ),
    (
        "API_",
        {
            "title": "API 권한·입력 계약 위험",
            "impact": "대량 할당, 공개 redirect, 약한 객체 소유권 검사는 다른 사용자 데이터나 권한 필드를 노출할 수 있습니다.",
            "fix_steps": ["API 입력 DTO를 명시적 allowlist로 제한합니다.", "actor/user/tenant 범위를 서버에서 파생해 query와 mutation에 포함합니다.", "비로그인·타 사용자·타 tenant 음성 테스트를 추가합니다."],
            "test_suggestions": ["금지 필드와 타 사용자 객체 ID가 403/404로 거부되는지 확인합니다."],
            "verification": "Guardian workspace 및 HTTP 검사를 같은 profile로 재실행합니다.",
        },
    ),
    (
        "AUTH_",
        {
            "title": "인증·세션 경계 위험",
            "impact": "평문 비밀번호, 검증 없는 JWT, 브라우저 저장 token, 약한 cookie flag는 계정 탈취와 권한 위조로 이어질 수 있습니다.",
            "fix_steps": ["검증된 인증 라이브러리와 서버 세션 경계를 사용합니다.", "비밀번호는 현대적 salted hash로만 보관합니다.", "cookie/JWT의 signature, issuer, audience, expiry와 보안 flag를 검증합니다."],
            "test_suggestions": ["위조·만료 token, 약한 cookie, 잘못된 비밀번호가 모두 거부되는지 확인합니다."],
            "verification": "정적 scan과 인증된 read-only HTTP probe를 재실행합니다.",
        },
    ),
    (
        "KR_ORG_",
        {
            "title": "한국 사업자·법인 식별번호",
            "impact": "사업자등록번호와 법인등록번호는 조직 식별정보입니다. 주민등록번호로 오분류하거나 로그/fixture에 원문을 남기면 잘못된 규제 대응과 유출이 생깁니다.",
            "fix_steps": ["원문을 마스킹하고 조직 마스터 데이터로만 보관합니다.", "주민등록번호 탐지/처리 경로와 분리합니다.", "공개가 필요한 경우에만 최소 자릿수를 남깁니다."],
            "test_suggestions": [
                "사업자등록번호는 checksum syntax validation만 사용합니다.",
                "역사적 법인등록번호는 구 Annex 가중치 1,2 합산 checksum을 검사합니다.",
                "2025-01-31 이후 4+2+7 현행 법인번호는 명시 필드 문맥의 unverified syntax/context recognition이며 live registry validation이 아닙니다.",
                "문맥이 붙은 사업자/법인 값은 checksum이 없거나 무효여도 PII_RRN/카드/계좌로 떨어지지 않는지 확인합니다.",
            ],
            "verification": "checksum-valid 사업자/역사적 법인은 KR_ORG_만 남고 PII_RRN이 없어야 합니다. 명시 문맥의 현행/미검증 13자리는 KR_ORG_로 남되 evidence에 unverified syntax/context recognition이라고 적혀야 하며 PII_RRN이 없어야 합니다.",
        },
    ),
    (
        "KR_DATA_",
        {
            "title": "한국 개인정보 기술 통제 공백",
            "impact": "고유식별정보와 장애, 장애정보, 생체정보, 지문, 홍채, 건강상태 같은 민감정보, 외부 처리 흐름에 목적, 암호화, 접근통제, 기록, 보존·파기 증거가 약하면 사고 영향이 커집니다.",
            "fix_steps": ["수집 목적과 필드 최소화를 명시합니다.", "고영향 필드를 암호화/토큰화하고 서버 권한 경계를 둡니다.", "원문을 남기지 않는 접근기록과 보존·파기 실행 경로를 검증합니다."],
            "test_suggestions": ["타 사용자/타 역할 접근 거부와 삭제 후 DB·로그 잔존 여부를 검증합니다."],
            "verification": "korean_senior Guardian profile의 data_management 영역을 다시 통과시킵니다.",
        },
    ),
    (
        "RELEASE_",
        {
            "title": "출하 운영 증거 공백",
            "impact": "dependency, CI, 권한 테스트, rate limit 증거가 없으면 감사 후 코드나 의존성이 바뀌거나 운영 부하에서 실패할 수 있습니다.",
            "fix_steps": ["lockfile과 고정 설치 모드를 사용합니다.", "Guardian fail-closed gate를 필수 CI에 연결합니다.", "인증 음성 테스트와 endpoint별 rate limit을 추가합니다."],
            "test_suggestions": ["깨끗한 환경의 재현 빌드와 CI release gate를 실행합니다."],
            "verification": "동일 commit에서 signed Guardian evidence bundle을 다시 생성합니다.",
        },
    ),
    (
        "SECRET_",
        {
            "title": "secret 노출",
            "impact": "API key, token, DB URL, private key가 노출되면 계정 탈취나 데이터 접근으로 이어질 수 있습니다.",
            "fix_steps": ["노출 값을 즉시 revoke/rotate 합니다.", "코드/fixture/log에서 제거하고 secret manager 또는 서버 환경변수로 옮깁니다.", "출력과 리포트에 평문 secret이 남지 않는지 확인합니다."],
            "test_suggestions": ["동일 scanner를 다시 실행해 secret 룰이 사라졌는지 확인합니다."],
            "verification": "scan_workspace 또는 scan_text를 다시 실행합니다.",
        },
    ),
    (
        "PII_",
        {
            "title": "개인정보 포함",
            "impact": "실제 개인정보가 코드, 로그, fixture, 응답에 남으면 유출 사고와 규제 리스크가 생깁니다.",
            "fix_steps": ["실제 값은 삭제하고 synthetic fixture로 교체합니다.", "운영 응답/로그에는 마스킹과 최소 필드 원칙을 적용합니다.", "한국형 개인정보 분류와 보존/삭제 정책을 문서화합니다."],
            "test_suggestions": ["한국형 fixture 및 실제 코드 scan을 다시 실행해 해당 PII 룰이 사라졌는지 확인합니다."],
            "verification": "score_fixture_corpus와 scan_workspace를 재실행합니다.",
        },
    ),
    (
        "KR_COMBO_",
        {
            "title": "결합 개인정보",
            "impact": "각 값이 약해 보여도 이름+전화, 이름+주소, 환자번호+진료정보처럼 결합되면 개인 식별성이 커집니다.",
            "fix_steps": ["응답/저장/로그에서 결합 필드를 최소화합니다.", "목록 API는 인증, 페이지네이션, 마스킹을 적용합니다.", "공개 안내 연락처와 사용자 데이터셋을 allowlist로 분리합니다."],
            "test_suggestions": ["결합 fixture와 실제 API 응답을 다시 검사합니다."],
            "verification": "scan_workspace 또는 probe_http를 재실행합니다.",
        },
    ),
    (
        "AST_TAINT_",
        {
            "title": "AST source-to-sink 흐름",
            "impact": "개인정보나 민감 입력이 로그, 응답, 외부 HTTP, LLM/MCP tool로 흐를 수 있습니다.",
            "fix_steps": ["sink 앞에서 데이터 최소화, 마스킹, 목적 검증을 추가합니다.", "LLM/MCP/external sink에는 별도 policy gate를 둡니다.", "로그에는 원문 대신 내부 ID 또는 hash만 남깁니다."],
            "test_suggestions": ["해당 sink를 호출하는 단위/통합 테스트에 마스킹 검증을 추가합니다."],
            "verification": "scan_workspace(include_flow=true)를 다시 실행합니다.",
        },
    ),
    (
        "JS_TS_TAINT_",
        {
            "title": "JS/TS source-to-sink 흐름",
            "impact": "프론트엔드/Node 경로에서 개인정보나 민감 입력이 로그, 응답, 외부 HTTP, LLM/MCP tool로 흐를 수 있습니다.",
            "fix_steps": ["sink 앞에서 데이터 최소화와 마스킹을 적용합니다.", "LLM/MCP/external sink에는 별도 policy gate를 둡니다.", "로그에는 원문 대신 내부 ID 또는 hash만 남깁니다."],
            "test_suggestions": ["해당 route/action/API handler에 마스킹과 권한 검증 테스트를 추가합니다."],
            "verification": "scan_workspace(include_flow=true)를 다시 실행합니다.",
        },
    ),
    (
        "RUNTIME_MCP_",
        {
            "title": "MCP runtime 흐름",
            "impact": "도구 결과가 agent context, 다른 MCP tool, 외부 전송으로 이어질 수 있습니다.",
            "fix_steps": ["tool result를 agent에 전달하기 전에 redact/block policy를 적용합니다.", "승인된 목적이 없는 LLM/MCP/external sink는 차단합니다.", "runtime event export 또는 stream observer를 재실행해 같은 흐름이 사라졌는지 확인합니다."],
            "test_suggestions": ["observe_mcp_events 또는 observe_mcp_event로 동일 이벤트 흐름을 재검증합니다."],
            "verification": "observe_mcp_events를 다시 실행합니다.",
        },
    ),
    (
        "MCP_",
        {
            "title": "MCP 구성/런타임 위험",
            "impact": "MCP 서버는 로컬 권한으로 실행되므로 악성 command, 숨은 지시, 과도한 파일 접근이 큰 피해로 이어질 수 있습니다.",
            "fix_steps": ["MCP command를 검증된 package/binary로 제한하고 버전을 pinning합니다.", "홈/SSH/cloud credential 디렉터리 접근을 차단합니다.", "도구 설명은 투명하고 최소화합니다."],
            "test_suggestions": ["scan_mcp_config와 observe_mcp_events를 실행합니다."],
            "verification": "scan_mcp_config를 다시 실행합니다.",
        },
    ),
    (
        "DYN_RESPONSE_",
        {
            "title": "동적 응답 민감정보",
            "impact": "실행 중인 앱 응답에 개인정보나 secret이 포함될 수 있습니다.",
            "fix_steps": ["비공개 데이터는 인증 뒤에서만 내려보냅니다.", "필요 없는 필드를 제거하고 목록 응답은 페이지네이션/마스킹합니다.", "secret은 응답에서 제거하고 rotate 합니다."],
            "test_suggestions": ["비로그인/로그인 상태를 나눠 probe_http를 재실행합니다."],
            "verification": "probe_http를 다시 실행합니다.",
        },
    ),
    (
        "CROSS_PLANE_",
        {
            "title": "cross-plane 개인정보 흐름",
            "impact": "개인정보 신호와 LLM/MCP/external/data-at-rest sink 신호가 같은 범위에서 결합되었습니다.",
            "fix_steps": ["데이터 목적, 최소화, 마스킹, 전송 승인 정책을 문서화합니다.", "LLM/MCP/external sink 앞에 redaction/policy gate를 추가합니다."],
            "test_suggestions": ["정적 scan, runtime observer, connector scan을 함께 재실행합니다."],
            "verification": "scan_workspace 또는 observe_mcp_events를 다시 실행합니다.",
        },
    ),
]


def recipe_for_rule(rule_id: str) -> Recipe:
    normalized = str(rule_id or "").strip()
    if normalized in EXACT_RECIPES:
        recipe = deepcopy(EXACT_RECIPES[normalized])
    else:
        recipe = None
        for prefix, candidate in PREFIX_RECIPES:
            if normalized.startswith(prefix):
                recipe = deepcopy(candidate)
                break
        if recipe is None:
            recipe = {
                "title": "일반 보안 finding",
                "impact": "현재 룰은 사람이 검토해야 하는 보안/개인정보 위험 신호입니다.",
                "fix_steps": ["finding의 evidence, file/url, recommendation을 기준으로 원인을 제거합니다.", "동일 scan을 재실행해 같은 rule_id가 사라졌는지 확인합니다."],
                "test_suggestions": ["회귀 테스트를 추가해 같은 위험이 다시 생기지 않게 합니다."],
                "verification": "동일 도구와 동일 옵션으로 재검사합니다.",
            }
    recipe["rule_id"] = normalized
    recipe["patch_policy"] = "K-Guard MCP는 기본적으로 dry-run/설명형 수정을 제안합니다. 자동 파일 수정은 별도 승인형 fixer에서만 허용해야 합니다."
    return recipe
