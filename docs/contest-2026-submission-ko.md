# 2026 오픈소스 개발자대회 출품 준비

확인 기준일: 2026-08-25

공식 안내: <https://www.oss.kr/pages/2>

## 출품 포지션

- 부문: 자유과제
- 분야: 인공지능, 보안·안전, 개발자 도구
- 한 문장: 바이브코딩 결과물을 사이트·API·데이터·운영 네 영역에서 끝까지 검수하고, 한국 개인정보 맥락과 출하 증거를 묶어 fail-closed로 판단하는 로컬 MCP 감사관
- 사용자 가치: 전문 검수 인력이 없는 개발자도 AI 코딩 도구 안에서 출하 전 시니어 검수 루틴을 실행한다.

공식 페이지는 참가 접수 6월 15일~7월 17일, 출품작 제출 8월 27일까지로 안내한다. 제출물은 결과보고서, 3분 시연영상, 소스코드이며 2차 평가에는 실제 기능 테스트와 라이선스 검증이 포함된다. 오리엔테이션에서 세부 평가 기준이 공개되면 이 문서를 다시 대조한다.

## 제품 핵심

1. 설치기가 현재 프로젝트를 private workspace binding으로 고정하고, 서버는 그 경계 밖의 경로를 high HOLD로 거부한다.
2. `check_my_app`은 전체 검수를 접수하고 `continue_review`가 terminal 상태가 될 때까지 완료 전 판정을 금지한다.
3. 완료 결과는 소스 스냅샷에 묶인 검수 영수증을 발급한다. 코드가 바뀌면 이전 영수증으로 출하 검수를 시작할 수 없다.
4. 출하 권한은 최신 검수 영수증을 요구하는 `start_review_before_ship`과 Guardian high 한 곳에만 있다.
5. 배포용 산출물, 읽지 못한 후보, oversized 파일, symlink·junction, 검사 중 소스 변경을 범위 미완료로 올려 HOLD한다.
6. 사이트, API, 한국 개인정보·데이터 흐름, 운영·릴리스 증거 중 하나라도 빠지면 finding 0개여도 SHIP하지 않는다.
7. stdio MCP proxy는 요청·응답·notification을 전달 전에 양방향 block/redact하며, batch/MCP wrapper 관찰 결과는 출하 집행으로 과장하지 않는다. 증거에는 원문 대신 keyed fingerprint와 위치·subtype·해시를 남긴다.
8. 설치 어댑터 대상은 ChatGPT/GPT, Grok, Codex, Antigravity 네 클라이언트다. 실제 호환성은 녹화된 tool-call process 증거가 있는 클라이언트만 검증 완료로 표시한다. 별도 review assertion은 self-attested이며 외부 독립 심사로 표현하지 않는다. Cursor, Claude Code, Cline은 설치 대상으로 표현하지 않는다.

## 3분 시연 구성

1. **제품 소개 18초**: AI로 만든 앱을 코딩 흐름 안에서 검수하고, 위험하면 보류한 뒤 같은 범위를 재검수하는 제품임을 설명한다.
2. **실제 연결 18초**: Grok, Codex, Antigravity CLI의 고정 process 녹화에서 도구 목록과 `check_my_app`, 재연결을 보여준다.
3. **네 검수 영역 12초**: 사이트, API, 한국 개인정보, 배포 준비를 한 화면에 정리한다.
4. **위험 발견 18초**: 고정 합성 fixture의 HOLD와 첫 조치 항목 `DYN_UNAUTH_API_JSON`을 보여준다.
5. **수정 18초**: 비밀값 제거, SQL 입력 분리, 개인정보 응답 최소화를 보여준다.
6. **재검수 16초**: 같은 범위에서 앱 차단 위험이 4건에서 0건으로 바뀐 결과를 보여준다.
7. **한국 개인정보 18초**: 합성 fixture 117건과 별도 holdout 68건을 섞지 않고 제시한다.
8. **제품 회귀 14초**: tested revision `add8fe38`, product source `72e2aea`의 최종 full-regression receipt(3,265 collected / 3,261 passed / 4 skipped / 0 failed·errors)를 보여주고, fresh-wheel 28 tools와 실제 stdio 5 calls를 함께 제시한다.
9. **배포 과정 16초**: 재현 빌드, CycloneDX SBOM, 의존성·라이선스 감사를 정리한다.
10. **마무리 20초**: 소스코드 제출본과 MIT 라이선스, 제품의 한 문장을 남긴다.

버전이 고정된 시연 자산과 명령 순서는 [`examples/contest-demo/v1`](../examples/contest-demo/v1/README.md)에 있다. 이 fixture는 로컬 합성 risk-blocked→clear→qualification-hold 흐름만 재현하며 실제 앱 정확도 근거로 집계하지 않는다.

## 제출물 대응

| 공식 제출·평가 항목 | K-Guard 준비물 |
|---|---|
| 결과보고서 | 문제, 북극성, 구조, 네 검수 영역, 한국 특화, 검증 수치, 한계와 로드맵 |
| 3분 시연영상 | 실제 PowerShell·공식 Python MCP 클라이언트·제품 CLI에서 공격 차단 → 앱 HOLD → 수정 → 같은 범위 재검수 → 한국 개인정보·출시 점검 단일 흐름 |
| 소스코드 | MIT 저장소, 고정 build/evidence lock, CI, 기여·행동강령·신고 문서 |
| 기능 테스트 | pytest, 500-target 로컬 제품 게이트, 동적 하네스, fresh-wheel MCP smoke |
| 라이선스 검증 | CycloneDX SBOM, active dependency closure 라이선스 보고서, 취약점 감사 |

## 현재 검증 스냅샷

2026-08-25 현재 고정 evidence와 단일 장비 측정 결과다. Codex, Grok, Antigravity의 process-level 연결은 현재 v6 sanitized replay와 self-attested review assertion으로 확인했다. 외부 심사자 신원·독립성이나 vendor UI 인증은 주장하지 않는다. 실제 파트너 앱 정확도는 별도 증거가 준비되기 전까지 완료로 표시하지 않는다. 최종 full-regression receipt는 tested revision `add8fe38decf05a75282bbfe1f49940a6e95e579`, product source `72e2aeaecf621c20356a6954d7f0fa78427937a1`에 결속됐다. Windows 일반 사용자 한 장비에서 3,265 collected / 3,261 passed / 4 skipped / 0 failed / 0 errors, 1,740.40초였으며 bounded product regression이지 detector accuracy가 아니다. 명시적으로 skip된 platform, real-Semgrep, Docker transport, release-only live replay lane은 실행했다고 주장하지 않는다. 공식 GitHub·YouTube는 **EXTERNAL URLS PENDING**이며 제출 package는 해당 URL 확정을 기다린다.

| 항목 | 결과 |
|---|---|
| pytest | tested revision `add8fe38`, product source `72e2aea`: 3,265 collected / 3,261 passed / 4 skipped / 0 failed / 0 errors, 1,740.40초. Windows normal-user bounded product regression이며 detector accuracy가 아님 |
| coverage | 최종 full-regression receipt는 테스트 결과를 결속하며 별도 coverage 수치를 주장하지 않음 |
| 단일 장비 합성 성능 | product source `72e2aea`, Windows/CPython 3.11.9 한 대의 synthetic all-benign low-signal 입력. cold scan p50/p95 1.422/1.502초, cold end-to-end p95 1.850초; warm p50/p95 1.401/1.413초. 10/50/100 MiB p50 13.980/70.279/140.724초, 처리량 0.715/0.711/0.711 MiB/s; 100 MiB peak RSS 155,209,728 bytes |
| 동시성 해석 | 한 CPython 프로세스 ThreadPoolExecutor 1/4/8 aggregate 0.713/0.697/0.691 MiB/s, speedup 1.000/0.978/0.969로 thread 이득을 주장하지 않음. 별도 fresh-child process 1/2/4 lane은 exact 64 KiB benign corpus에서 speedup 1.000/1.968/3.672, efficiency 1.000/0.984/0.918. 둘 다 단일 장비 합성 측정이며 운영 SLO·field accuracy·finding-dense·타 제품 비교가 아님 |
| 결과 지문 경계 | 모든 성능 입력이 finding 0건인 all-benign corpus여서 stable empty-result digest의 식별력은 제한적이며 finding-bearing 결과 불변성을 증명하지 않음 |
| 한국 fixture | 117건: positive TP 70/FN 0, clean-negative FP 0/TN 27, targeted-absence 20건 별도, workspace contract 5건 별도 |
| 한국 민감정보·조직번호 holdout | 고정 68건, TP 43, TN 25, FN 0, FP 0, 두 번 exact repeat. fixture와 합쳐 185회 separate-lane execution으로만 표기하며 pooled unique count와 combined confusion matrix는 주장하지 않음. 평가자 작성·구현 후 합성 점검이며 blind/field accuracy·실시간 등록 검증 아님 |
| 합성 한국 코퍼스 | positive 500, negative 100, recall 1.0, FPR 0.0 |
| 내부 제품 게이트 | 500 local loopback targets, required rule 누락 0, unexpected deep rule 0, exact pass rate 1.0 |
| 권한 있는 동적 하네스 | local-only, static/dynamic/MCP 누락 0, raw marker leak 0 |
| 공개 scorecard 무결성 | 전체 상태 FAIL. 한국 합성·현재 공개 앱·BenchmarkJava 최초·Juliet 최초 lane은 개별 무결성 PASS이나, 역사적 OWASP BenchmarkPython과 Juliet post-tuning replay는 제출 정확도 근거에서 제외 |
| OWASP BenchmarkJava CWE-89 최초 | 504건, TP 51/FN 221/FP 33/TN 199, recall 0.187500, precision 0.607143, specificity 0.857759. evidence integrity PASS, 성능 verdict HOLD |
| OWASP BenchmarkPython 역사 결과 | 내부 artifact digest·size mismatch로 integrity FAIL. 기록 수치는 현재 제출 정확도 근거로 사용 금지 |
| seeded mutation 회귀 | 25 TP/25 TN이지만 1 app·1 rule·1 operator라 `single_pattern_seeded_regression`; 실전 정확도 근거로 사용 금지 |
| 실제 AI 클라이언트 | Codex, Grok, Antigravity 3종의 현재 v6 process-level sanitized replay. fresh-wheel receipt로 product source `72e2aea`·package tree·wheel 결속; vendor UI 인증 아님. Grok 6개 K-Guard rawOutput 호출만 local-transcript receipt-backed이고 tools list는 별도 기록, 나머지는 structured self-report |
| 과거 공개 앱 AI 판정 | revision 9488898, 24회 exact repeat, high/critical 후보 31건, 동일 모델 계열 reviewer 3명이 31건 모두 TP로 일치; 사람 수동 판정이 아님. 현재 라벨로 전용하지 않음 |
| 현재 코드 공개 앱 재현 | 12개 앱 × 2회 exact repeat, 자동 release-blocking 후보 14건, 취약 probe 11 / 11, benign training fixture 1 / 1 탐지 |
| fresh-wheel MCP | 28개 tool, 실제 stdio 5회 호출, 초기·출하 review 종결, source snapshot 결박, invalid ID fail-closed |
| NIST Juliet Java CWE-89 첫 결과 | 420 unit, TP 180/FN 30/FP 0/TN 210, recall 0.857143, precision 1.000000, specificity 1.000000, exact repeat; evidence integrity PASS |
| NIST Juliet 수정 후 재생 | 기록상 TP 210/FN 0/FP 0/TN 210이나 first-result digest binding 불일치로 integrity FAIL. 새 독립 holdout이 아님. 현재 제출 정확도 근거로 사용 금지 |
| MCP 우회 합성 회귀 | positive 24/negative 20, raw line-only recall 0.166667 -> bounded normalization recall 1.0, FPR 0.0; field/경쟁제품 성능 근거로 사용 금지 |
| 라이선스 정책 | active dependency closure 41개, unknown 0, review-required 0, lock mismatch 0 |
| 취약점 감사 | `requirements-evidence.lock` 기준 알려진 취약점 0, 감사 도구 사용 가능 |
| SBOM | CycloneDX 1.5, component 41개 |
| 재현 가능한 빌드 | 고정 도구체인·epoch로 wheel/sdist 두 번 빌드 후 바이트 해시 일치 요구 |
| 배포 무결성 | 외부 `SHA256SUMS`와 GitHub OIDC/Sigstore SLSA provenance, CycloneDX SBOM attestation으로 wheel·sdist·evidence lock의 digest와 빌드 주체 고정 |

## 아직 닫지 않은 증거

- [x] [상호운용 실증 키트](client-interop-evidence-kit-ko.md)로 Grok/Codex/Antigravity 3개 실제 클라이언트의 설치·재시작·도구 목록·`check_my_app`·재연결 녹화 및 self-attested review assertion
- [x] 녹화 원본 3개를 `submission/client-interop/`에 게시하고 byte length와 SHA-256을 상태 레코드에 결속
- [x] current-source 공개 개발 앱 12개 재현 통과. 과거 동일 모델 계열 AI 판정과 분리하고 사람·cross-vendor 판정으로 확대하지 않음
- [ ] 12~20개 owned/partner 앱에서 역할 분리 서명, preregistered holdout, TP/FP/FN 수동 라벨과 scope assertion 확보
- [ ] GitHub Private Vulnerability Reporting 활성화와 유지관리자 비공개 연락 경로 확인
- [x] 시연 영상의 폰트, 이미지, 샘플 데이터 재배포 권리를 `submission/RIGHTS.md`에 기록. 현재 제출 시연은 180초 H.264 1920x1080, 전체 디코딩, VoxCPM2 한국어 나레이션 오디오 스트림 1
- [ ] 오리엔테이션에서 공개될 최종 평가 기준과 결과보고서 양식 대조

이 항목들은 제품 게이트를 조용히 통과시키지 않는다. 다만 외부 계정·파트너 데이터가 필요한 제출 운영 과제로서, 자동화된 내부 제품 검증과 분리해 보고한다.

결과보고서 본문은 [작성 초안](contest-2026-result-report-draft-ko.md)에 준비되어 있다. 실제 클라이언트 표는 `scripts/client_interop_evidence.py summarize`가 생성한 [상태표](client-interop-status-ko.md)를 사용한다.

## 주장 경계

| 주장 | 현재 근거 | 표현 |
|---|---|---|
| 내부 규칙·게이트가 재현됨 | 코퍼스와 500-target local product gate; tested revision `add8fe38`, product source `72e2aea` full-regression 3,261 passed / 4 skipped / 0 failed·errors | bounded product regression으로만 사용. detector accuracy가 아님 |
| 원문 비반환과 fail-closed 범위 처리 | redaction 100%, raw-free 검사, 범위·drift 회귀 테스트 | 사용 가능 |
| 네 영역 출하 게이트 | Guardian high와 canonical authority 계약 | 사용 가능 |
| 공개 정답셋 성능 | BenchmarkJava 최초 HOLD와 Juliet 최초 PASS를 분리 보존. 역사적 OWASP Python은 integrity FAIL | 무결성 PASS인 최초-result lane만 각 component 경계 안에서 한정 사용 가능 |
| 실제 클라이언트 상호운용 | 역사적 3종 process-level 녹화·해시 | 과거 증거로 한정 사용. 현재 버전 인증 아님 |
| 공개 앱 개발 실효성 | 과거 AI 판정과 current-source 12개 앱·24회 재현을 revision별 분리 | 개발 게이트 통과로 한정 사용. 사람 판정·전체 recall 아님 |
| NIST Juliet Java 단일 경계 | 최초 TP 180/FN 30/FP 0/TN 210은 integrity PASS; post-tuning replay는 binding FAIL | 최초 결과만 component 성능 근거로 사용. replay는 제출 정확도 근거에서 제외 |
| 실제 앱에서 인간 시니어급 정확도 | owned/partner TP/FP/FN 라벨 미확보 | 주장 금지 |
| 모든 취약점 탐지 또는 법적 적합성 | 근거 없음 | 사용 금지 |

## 최종 한 문장

**K-Guard MCP는 바이브코더의 속도를 늦추는 검사기가 아니라, 그 속도로 만든 결과물을 책임 있게 출하하도록 옆에서 끝까지 봐주는 안경선배다.**

현장 실증 상태: **field evidence pending / owned·partner field 0/12**. 공개 개발 결과로 이 빈칸을 대체하지 않는다.
