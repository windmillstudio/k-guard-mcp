# 안경선배 전체 도그푸드 및 출하 판정

검증일: 2026-07-15  
검증 소스: `49a1a4d93da39039af277c9f2c9c766cbb93ce04`  
분석기 패키지 트리 SHA-256: `15096bd64efba1f876993edf360f8186e848dc66d6a2af3f23ad5617d38cac3f`

## 최종 판정

| 구분 | 판정 | 의미 |
|---|---|---|
| 설치 가능한 기술 베타 | `SHIP` | 격리 설치, MCP 연결, 28개 도구 열람, 재현 빌드, 제어 검증이 동작한다. |
| 참고용 사전 점검기 | `SHIP WITH LIMITS` | 사람이 결과를 검토한다는 조건으로 실제 프로젝트 점검에 사용할 수 있다. |
| 시니어 감사관 수준의 자동 출하 승인 | `HOLD` | 실제 앱 차단 조치의 적중률과 앱 단위 신뢰도가 잠근 기준에 못 미친다. |
| 공모전에서 탐지 정확도 입증 완료 주장 | `HOLD` | 공개 도전 세트는 통과하지 못했고 owned/partner 독립 실증도 비어 있다. |

전체 제품 판정은 `HOLD`다. 패키지는 배포 가능한 베타지만, `Guardian`을 사람이 재검토하지 않아도 되는 출하 권한으로 광고해서는 안 된다.

## 무엇을 실행했나

| 영역 | 결과 | 관찰 |
|---|---|---|
| 전체 테스트 | `1475 passed, 3 skipped, 0 failed` | 최신 작업트리의 전체 회귀 테스트가 통과했다. 실제 contest readiness 명령은 아래 네 가지 증거 blocker로 별도 실패한다. |
| 격리 wheel MCP | 통과 | 새 가상환경에서 wheel을 설치하고 stdio로 28개 도구를 열어 전체 호출 흐름을 완료했다. |
| 재현 빌드 | 통과 | 두 번 만든 wheel과 정규화 sdist가 각각 byte-identical이었다. |
| 아카이브 검사 | 통과 | wheel RECORD, sdist, README 문서 링크와 패키지 항목을 확인했다. |
| 정책 제어 | 통과 | 18개 JIT/JEA, SQL AST, RBAC, 격리 사례가 두 번 정확히 반복됐다. |
| Streamable HTTP | 통과 | POST, GET, DELETE, JSON, SSE, 세션 생성·삭제, allow, deny, 도구 필터가 두 번 반복됐다. |
| 9개 언어 개발팩 | 통과 | 합성 90건에서 TP 45, FN 0, FP 0, TN 45다. 필드 정확도 주장은 아니다. |
| 한국 개인정보 합성 코퍼스 | 통과 | 양성 500건, 음성 100건에서 recall 1.0, FPR 0이다. 실제 앱 실증은 아니다. |
| 잠금 의존성 감사 | 통과 | 실제 Python 릴리스 의존성 폐쇄에서 알려진 취약점 0건이다. |
| 저장소 전체 SCA | 실패 폐쇄 | 임시 경쟁·검증 자료까지 포함한 혼합 작업공간에서 `PYSEC-2026-2132` 한 건을 찾았고, 로컬 Go와 `govulncheck` 부재로 완료하지 못했다. |
| 자기 저장소 스캔 | 신호대잡음 부족 | 전체 7,579건 중 자동 차단 24건, 수동 보류 436건이었다. 규칙·테스트·증거가 자기 규칙에 잡히는 비중이 크다. |
| 대형 저장소 두 곳 | 실패 폐쇄 | 14/14,527개와 3/8,113개의 지원 파일을 끝까지 읽지 못했다. 조용히 통과하지는 않았지만 완료성과 속도가 부족하다. |
| 벤치마크 처리량 | 실패 | 합성 TypeScript 0.241 MB/s로 잠근 0.5 MB/s SLO를 충족하지 못했다. 임시 검증 자료가 자기 저장소 범위에 섞이는 문제도 확인됐다. |

실제 `contest_readiness.py`는 `package_ready=false`, `award_evidence_ready=false`와 종료 코드 1을 반환했다. 남은 blocker는 제출 보고서 attestation, 현재 소스 wheel stdio 증거, 현재 소스 공개 앱 replay, owned/partner 앱 12개 이상이다.

## 실제 앱 도전 결과

27개 공개 바이브 코딩 관련 저장소를 top, mid, long-tail로 나눠 각 두 번 실행했다. 모든 앱의 보고서 해시는 정확히 반복됐고, 25개 앱에서 고위험·치명적 자동 차단 후보 105개를 얻었다. 위치를 찾지 못한 후보는 없었다.

| 잠근 지표 | 요구 | 관찰 | 판정 |
|---|---:|---:|---|
| 자동 차단 조치 적중률 | 0.90 이상 | 0.704762 | 실패 |
| 적중률 Wilson 95% 하한 | 0.80 이상 | 0.611535 | 실패 |
| 모든 자동 차단이 맞은 앱 비율 | 0.90 이상 | 11/25, 0.44 | 실패 |
| 앱 비율 Wilson 95% 하한 | 0.80 이상 | 0.266656 | 실패 |
| 검토자 만장일치율 | 0.90 이상 | 0.571429 | 실패 |
| 판정 불가 | 0 | 3 | 실패 |
| 단일 규칙 후보 비중 | 0.50 이하 | 0.561905 | 실패 |
| 후보 수 | 100 이상 | 105 | 통과 |
| 후보 앱 수 | 20 이상 | 25 | 통과 |
| 반복·표본·라벨·위치 범위 | 1.0, 위치 누락 0 | 모두 충족 | 통과 |

세 검토자의 다수결은 true positive 74개, benign 28개, inconclusive 3개였다. 가장 큰 잡음원은 Docker socket 규칙이었다. 이 규칙의 42개 후보 중 다수결 true positive는 12개, benign은 27개, inconclusive는 3개였다. 현재 자동 차단 정책은 실제 개발 문맥을 충분히 구분하지 못한다.

이 표본은 위험 신호가 나올 가능성을 높인 공개 도전 세트다. 완전한 블라인드 표본, owned/partner 앱, 전체 취약점 recall, 실제 공격 가능성 검증이 아니다. 세 검토자도 서로 다른 세션이지만 같은 공급자 계열이므로 인간 또는 cross-vendor 독립 판정으로 부르지 않는다.

## GitHub 공개 제품 비교

하나의 종합 퍼센트는 만들지 않았다. 제품마다 측정 대상이 달라 72% 같은 수치는 근거 없는 정밀도로 보이기 때문이다.

| 기준 | 공개 기준선 | 안경선배의 현재 위치 |
|---|---|---|
| 다중 언어 정적 분석 | [Semgrep MCP](https://github.com/semgrep/mcp)는 본체 Semgrep으로 통합됐고 5,000개 이상의 규칙, 다중 언어 의미 분석, 사용자 규칙과 AST 도구를 제공한다. | 언어 폭과 엔진 깊이는 뒤처진다. 안경선배의 강점은 릴리스 판단과 한국 규칙의 결합이지 Semgrep 대체가 아니다. |
| MCP·에이전트 공급망 | [Snyk Agent Scan](https://github.com/snyk/agent-scan)은 MCP, 에이전트, skill 자동 발견과 prompt injection, tool poisoning, shadowing, toxic flow를 다룬다. [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner)는 YARA, LLM, Cisco API, 의존성, readiness, 소스 행동 분석을 결합한다. | 설정·도구·프롬프트 검사 기능은 있지만 자동 발견 범위와 전용 분석 깊이는 뒤처진다. |
| 런타임 강제 | [Pipelock](https://github.com/luckyPipewrench/pipelock)은 HTTP, WebSocket, MCP, A2A 프록시, DLP, SSRF, egress 제어, 서명된 action receipt와 배포 레시피를 제공한다. | 기본 proxy/interceptor와 반복 검증은 동작하지만 전송 범위, 배포 성숙도, 외부 서명 영수증은 뒤처진다. |
| AI 레드팀 | [Tencent AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)는 MCP, agent, skill, AI 인프라, jailbreak를 포괄하는 플랫폼이다. | 일반 AI 레드팀 폭은 뒤처진다. 안경선배는 바이브 코드 출하 감사에 더 좁게 집중한다. |
| 비밀정보 선제 차단 | [GitHub MCP secret scanning](https://docs.github.com/en/code-security/how-tos/use-ghas-with-ai-coding-agents/scan-for-secrets-with-github-mcp-server?tool=cli)은 remote MCP에서 pre-commit 비밀 검사를 제공하지만 결과는 세션 한정이며 system of record가 아니다. | 비밀 외에 코드, 데이터 흐름, 한국 개인정보, 릴리스 증거를 함께 본다는 범위는 넓다. 토큰 검증과 GitHub 생태계 성숙도는 GitHub가 앞선다. |
| 한국 개인정보와 출하 증거 | 직접 비교 가능한 상위 공개 MCP 기준선은 확인하지 못했다. | 주민등록번호, 외국인등록번호, 여권, 건강·계좌·개인정보 조합, 보존·파기와 PIPC 매핑은 분명한 차별점이다. 다만 현재 정확도 근거는 합성 데이터뿐이다. |

Semgrep CE 1.169.0의 `p/default`를 같은 OWASP BenchmarkPython 1,230건에 실행해 462개 결과를 얻었다. 파일의 공식 CWE와 결과 metadata CWE가 같은 경우만 적중으로 세는 단순 점수에서 precision 0.518182, recall 0.126106이었다. 안경선배의 366건 개발 범위 결과는 규칙 개발에 사용된 비블라인드 자료이므로 이 숫자로 Semgrep보다 우수하다고 주장할 수 없다. 설정과 범위가 다른 참고 실행일 뿐이다.

Cisco Scanner 4.7.6의 로컬 YARA 엔진은 격리 wheel의 안경선배 MCP 28개 도구를 모두 `SAFE`로 판정했다. 이는 도구 설명에 알려진 YARA형 오염 신호가 없고 stdio 상호운용이 된다는 근거다. Cisco API와 LLM 엔진, Snyk API는 키가 없어 실행하지 않았으므로 완전한 경쟁 검증으로 확대하지 않는다. Cisco 모듈 CLI에서 `--stdio-timeout` 사용 시 `UnboundLocalError`가 발생해 환경변수 우회도 필요했다.

## 한국 특화 평가

규칙과 제품 흐름은 한국 특화다. 한국 식별자, 복합 개인정보, 외부 전송, 저장, 로그, 보존과 파기, 동의·처리 목적 경계를 하나의 Guardian 보고서에 묶는다. 일반 정적 분석 MCP와 구별되는 실제 제품 방향이다.

입증 수준은 아직 합성 개발팩이다. 실제 국내 서비스에서 주민번호를 쓰지 않는 정상 화면, 마스킹된 운영 로그, 위탁 처리, 법정 보존, 탈퇴 후 분리 보관 같은 문맥을 독립 라벨링하지 않았다. 따라서 “한국 개인정보 규칙을 갖췄다”는 말은 가능하지만 “국내 상용 앱에서 검증된 최고 수준”이라는 말은 불가능하다.

## 외부 CTO 판정

동일한 수치와 경계를 Claude와 Grok CLI에 제공하고 기준을 낮추지 말라고 요청했다. 두 모델 모두 다음과 같이 판정했다.

| 검토자 | 기술 베타 | 출하 승인 권한 | 전체 |
|---|---|---|---|
| Claude | `SHIP` | `HOLD` | `HOLD` |
| Grok | 설치 가능 | 권한 불인정 | `HOLD` |
| Codex | `SHIP WITH LIMITS` | `HOLD` | `HOLD` |

외부 모델은 소스 후보를 새로 라벨링한 것이 아니라 동일한 집계 증거를 비판적으로 검토했다. 판정의 독립성을 과장하지 않는다.

## 출하 조건

지금 공개할 수 있는 제품 문구는 “설치 가능한 공개 베타, 사람이 최종 판단하는 출하 전 감사 도구”다. “자동 출하 승인”, “시니어 개발자 대체”, “90% 이상 적중 입증”, “상위 보안 MCP보다 우수”는 현재 증거로 말할 수 없다.

정식 출하 권한을 열려면 다음을 모두 완료해야 한다.

1. Docker socket과 mutable GitHub Action 규칙에 실행·권한·배포 문맥을 추가하고 새 holdout을 preregister한다.
2. 새 앱에서 100개 이상의 자동 차단 후보를 다시 모아 적중률 0.90과 Wilson 하한 0.80을 넘긴다.
3. 앱 단위 완전 적중률 0.90과 Wilson 하한 0.80을 넘기고 inconclusive를 0으로 만든다.
4. 서로 다른 공급자 또는 인간 검토자가 0.90 이상 일치하도록 판정 지침과 증거 문맥을 고친다.
5. owned/partner 국내 앱 12개 이상에서 개인정보 문맥을 독립 라벨링한다.
6. 대형 저장소의 지원 파일 누락을 0으로 만들고 처리량 SLO를 회복한다.
7. 새로운 소스 revision으로 wheel, current-source replay, 제출 attestation을 다시 묶어 contest readiness blocker를 0으로 만든다.

## 증거 위치

- 공개 R4 통계: `evidence/public/holdout/vibe-release-apps-27-r4/effectiveness-status.json`
- R4 후보와 판정: `evidence/public/holdout/vibe-release-apps-27-r4/`
- 전체 도그푸드 요약 산출물: `evidence/dogfood/2026-07-15/`
- 현재 의존성 감사: `audit-report.json`
- 동적 허가 하네스: `authorized-dynamic-harness-report.json`
- 처리량 결과: `benchmark-report.json`

이 판정은 실패를 감춘 출시 문서가 아니다. 안경선배가 실제로 잘하는 부분과 아직 출하 권한을 주면 안 되는 부분을 같은 기준으로 고정한 문서다.
