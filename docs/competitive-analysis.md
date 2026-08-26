# K-Guard MCP Competitive Analysis

작성일: 2026-07-06  
범위: GitHub 공개 저장소 중 MCP/AI-agent 보안 스캐너 계열, 대체로 50 stars 이상인 프로젝트를 우선 비교했다. AWS sample처럼 star 기준은 낮지만 구현 패턴 참고 가치가 있는 항목은 별도 참고군으로 포함했다.

## 결론

K-Guard MCP는 현재 범용 MCP/agent 위협 스캐너 전체 시장에서 Snyk, Cisco, Tencent, Ramparts처럼 넓은 생태계 커버리지와 대형 rule/engine을 가진 제품보다 월등하다고 말하기는 어렵다.

다만 K-Guard의 차별점은 매우 선명하다.

1. 한국 개인정보 탐지 특화: 주민등록번호, 휴대폰, 국내 주소, 카드, 계좌, 건강보험, 환자번호, 학번, 사번, 회원번호, 고객번호, 주문번호, 복합 식별 조합을 한국형 fixture로 검증한다. 사업자등록번호는 checksum syntax validation으로, 2025-01-31 이전 법인등록번호는 구 Annex 가중치 1,2 checksum으로 조직 식별정보로 잡는다. 그 이후 현행 법인번호는 4+2+7 자릿수에 checksum이 없으므로 명시 필드 문맥의 syntax/context recognition이며 live registry validation이 아니다. 문맥이 붙은 사업자/법인 값은 checksum이 무효·미검증이어도 주민등록번호·카드·계좌로 떨어지지 않게 막되, 사람 주민/외국인등록번호로 읽히는 13자리는 법인/사업자 라벨보다 우선한다. 근거는 합성·벤더 작성 fixture와 evaluator-authored holdout이며 독립 유효성 검증이나 현장 field validation이 아니다. 한국어 fixture scoreboard의 FPR 분모는 선언된 전체 `negative_count`가 아니라, `expected_absent`가 없는 clean negative인 `measurable_negative_count`다. 68건 holdout은 case마다 `must_all`과 `must_any` 그룹 중 하나 이상, `forbidden` 부재로 채점한다.
2. 바이브코딩 산출물 방어 UX: 보안 지식이 적은 사용자가 이해할 수 있도록 한국어 설명, 오탐 가능성, 확인 방법, 수정 방법을 대시보드에서 설명한다.
3. local-first / raw-free evidence: 원문 body/value를 저장하지 않고, 마스킹된 근거와 rule, 경로, 방법만 기록한다.
4. 정적 스캔 + 설정 스캔 + 안전한 동적 HTTP 점검 + 데이터 흐름 시각화를 한 제품 안에 묶는다.
5. 개인정보 후보가 "몇 개 흩어진 공개 연락처"인지, "한 경로에서 이름/메일/전화가 뭉텅이로 나온 데이터 노출"인지 구분하는 방향으로 설계되어 있다.

따라서 포지셔닝은 다음이 가장 강하다.

> Korean PII-first local MCP security auditor for vibe-coded apps, with safe dynamic verification and data-flow visualization.

## 주요 경쟁군

| 제품 | GitHub stars | 초점 | 강점 | K-Guard 대비 약점 |
| --- | ---: | --- | --- | --- |
| Tencent AI-Infra-Guard | 4,054 | AI infra red team / MCP 포함 | 매우 넓은 AI 보안 진단 범위, 대형 rule/data 기반 | 한국 개인정보 특화 UX는 약함 |
| Snyk Agent Scan | 2,747 | agent/MCP/skill 보안 스캔 | Claude/Cursor/Windsurf/Gemini 등 자동 탐색, prompt injection/tool poisoning/toxic flow 중심 | 분석 데이터가 Snyk로 공유될 수 있어 local-first 민감 데이터 검증에는 부담 |
| SPLX Agentic Radar | 993 | agentic workflow 분석/시각화 | agent workflow 시각화와 취약점 매핑 | 한국 PII와 웹 동적 검증은 핵심 초점이 아님 |
| Cisco MCP Scanner | 979 | MCP server/tool threat scan | YARA, LLM-as-judge, Cisco AI Defense, dependency scan, REST API | 엔터프라이즈 엔진 의존, 한국 개인정보 fixture/대시보드 UX는 별도 |
| AgentShield | 948 | Claude Code/agent config 보안 | 102 rules, GitHub Action/App, runtime/template/docs confidence 구분 | 한국형 개인정보/동적 웹 점검은 핵심 아님 |
| Pipelock | 741 | MCP/agent egress firewall | agent 실행 중 egress 제어, MCP firewall 개념 강함 | 사전 개인정보 탐지/한국어 remediation과는 결이 다름 |
| Semgrep MCP | 678 | Semgrep을 MCP로 노출 | 5,000+ Semgrep rule 활용 가능 | MCP 보안 스캐너라기보다 코드 스캐너를 MCP tool로 제공 |
| MCP-Shield | 555 | MCP server 보안 | tool poisoning, exfiltration channel, cross-origin escalation에 집중 | 개발 산출물/한국 PII/동적 웹 검증은 약함 |
| HOL Guard | 383 | AI antivirus for agents/plugins/MCP | 에이전트 플러그인/스킬/MCP 전반 검사 | 한국 웹앱 개인정보 검증은 중심 아님 |
| AgentSeal | 292 | local agent security toolkit | dangerous skills/MCP config, supply-chain, tool poisoning | 한국 PII/웹 동적 감사 UX는 별도 |
| AntGroup MCPScan | 225 | MCP code/metadata scanner | Semgrep taint, metadata monitoring, optional LLM flow risk | 개인정보/초보자 대시보드보다 MCP code risk에 집중 |
| mcp-watch | 135 | MCP server security scanner | MCP 서버 단위 경량 점검 | 커버리지와 UX가 작음 |
| Ramparts | 94 | MCP/agent skill scanner | YARA, LLM, OWASP MCP Top 10, SARIF, OSV, MCP server mode | 아직 star는 낮지만 기능 설계가 탄탄함. K-Guard는 SARIF/Top10 매핑 보강 필요 |

## K-Guard Dogfood 결과

K-Guard로 공개 경쟁 repo 13개를 직접 스캔했다. 이 결과는 확정 취약점이 아니라 "우리 탐지기가 어떤 신호를 잡는지"를 보는 도그푸딩 결과다. docs/examples/tests 안의 예시 IP, 이메일, CVE, 날짜가 포함될 수 있으므로 repo 자체의 취약점으로 단정하면 안 된다.

결과 파일: `competitive-dogfood-report.json`

| Repo | 파일 수 | 크기 MB | findings | 주요 신호 |
| --- | ---: | ---: | ---: | --- |
| Tencent/AI-Infra-Guard | 4,408 | 16.70 | 1,598 | IP, birthdate-like, sensitive info, medical info, email |
| snyk/agent-scan | 256 | 2.55 | 140 | birthdate-like, IP, order id, email, timestamp |
| cisco-ai-defense/mcp-scanner | 398 | 3.63 | 427 | IP, birthdate-like, PII-to-log flow, timestamp, email |
| affaan-m/agentshield | 195 | 2.28 | 266 | timestamp, email, IP, OpenAI-style key pattern |
| luckyPipewrench/pipelock | 2,520 | 27.13 | 4,142 | IP, timestamp, email, birthdate-like, order id |
| hashgraph-online/hol-guard | 1,105 | 15.91 | 4,040 | timestamp, IP, email, birthdate-like, device id |
| getagentseal/agentseal | 254 | 2.61 | 202 | timestamp, birthdate-like, sensitive-to-external-http flow |
| splx-ai/agentic-radar | 219 | 0.95 | 56 | birthdate-like, email, PII-to-log flow |
| highflame-ai/ramparts | 31 | 0.22 | 50 | timestamp, birthdate-like, IP, email, AWS key pattern |
| semgrep/mcp | 37 | 0.11 | 33 | birthdate-like, IP, email, sensitive info, PII-to-log flow |
| antgroup/MCPScan | 22 | 0.07 | 7 | sensitive-to-external-http flow, email, IP |
| riseandignite/mcp-shield | 15 | 0.14 | 4 | email, birthdate-like, order id |
| kapilduraphe/mcp-watch | 32 | 0.19 | 2 | source map config, IP |

도그푸딩 해석:

1. K-Guard는 경쟁 repo 내부의 fixture/docs/test/example에 있는 개인정보형 패턴과 data-flow 후보를 잘 잡는다.
2. 현재 K-Guard는 docs/examples/test fixture의 benign sample도 많이 세기 때문에 "runtimeConfidence" 또는 "sourceContext" 등급이 필요하다.
3. 경쟁 제품 중 AgentShield는 active runtime/template/docs/plugin-cache처럼 컨텍스트를 나누는 설계가 있어 참고 가치가 높다.
4. K-Guard의 강점은 탐지 자체보다 "한국 사용자가 이해하고 조치할 수 있는 설명"과 "raw-free evidence"다.

## K-Guard가 월등해지기 위한 보강 항목

우선순위 1: MCP-native 위협 분석

- installed MCP config parser: Claude/Cursor/Windsurf/Gemini/VS Code 계열 설정 자동 탐색
- no-exec safe mode: MCP command를 실행하지 않고 설정/manifest/metadata 먼저 분석
- tool poisoning detector: tool name/description/prompt/resource 안의 숨은 지시, 권한 상승, 사용자 파일 접근 유도 탐지
- tool shadowing detector: 정상 tool 이름과 유사한 이름/설명으로 사용자를 속이는 패턴 탐지
- exfiltration intent detector: 외부 전송, clipboard, shell, filesystem, browser/session/cookie 접근 목적 분석
- cross-origin escalation detector: 다른 MCP 서버나 외부 origin으로 데이터를 넘기는 흐름 탐지

우선순위 2: 오탐 제어

- sourceContext: runtime, config, source, test, fixture, docs, generated, vendor 구분
- runtimeConfidence: active runtime 경로에 가까울수록 우선순위 상향
- benignPublicContact tier: 회사 대표 이메일/전화/주소처럼 공개 안내일 가능성이 큰 단건은 info로 낮춤
- bulkExposure tier: 한 응답/파일/경로에서 이름+전화+이메일+주소가 다량 결합되면 high/critical로 상향
- route semantics: `/admin` 200만으로 critical 처리하지 않고 login page/html shell/API capability 여부로 분리

우선순위 3: 제출/상용 UX

- SARIF export
- GitHub Action
- HTML evidence pack
- CI fail policy: critical/high only, confidence threshold 선택
- allowlist/baseline 관리
- Korean privacy policy checklist: 개인정보처리방침, 수탁자, 보유기간, 파기, 접근권한, 로그 보관 항목 매핑

우선순위 4: 동적 점검 고도화

- body 전체 검사: truncation finding 대신 streaming scanner로 끝까지 검사하고 "검사 완료" 로그 표시
- probe audit log: 어떤 경로를, 어떤 method로, 왜 봤고, 어떤 기준으로 문제/정상 판단했는지 단계별 기록
- data-flow visualization: source -> transform -> sink 그래프를 대시보드에 표시
- safe boundary: 같은 origin만, GET/HEAD/OPTIONS 중심, no login/no mutation/no fuzzing 유지

## 최종 판정

현재 상태로는 "범용 MCP 위협 스캐너" 시장에서 압도적 1등은 아니다. Snyk/Cisco/Tencent/Ramparts는 MCP/agent threat modeling과 생태계 통합이 더 넓다.

하지만 "한국형 개인정보 + 바이브코딩 산출물 + 안전 동적 점검 + 데이터 흐름 설명"으로 좁히면 경쟁 제품군이 정면으로 다루지 않는 영역이다. 이 축에서는 K-Guard가 충분히 상용 작품으로 차별화될 수 있다.

상용 제출 전 필수 보강은 다음 3개다.

1. MCP-native threat detector 추가
2. sourceContext/runtimeConfidence 기반 오탐 제어
3. SARIF/GitHub Action/evidence pack export

## Sources

- https://github.com/Tencent/AI-Infra-Guard
- https://github.com/snyk/agent-scan
- https://github.com/splx-ai/agentic-radar
- https://github.com/cisco-ai-defense/mcp-scanner
- https://github.com/affaan-m/agentshield
- https://github.com/luckyPipewrench/pipelock
- https://github.com/semgrep/mcp
- https://github.com/riseandignite/mcp-shield
- https://github.com/hashgraph-online/hol-guard
- https://github.com/getagentseal/agentseal
- https://github.com/antgroup/MCPScan
- https://github.com/kapilduraphe/mcp-watch
- https://github.com/highflame-ai/ramparts
- https://github.com/aws-samples/sample-mcp-security-scanner
