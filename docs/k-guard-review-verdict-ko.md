# K-Guard MCP 현재 제품 판정

이 문서는 과거 VibeSec 비교 메모와 당시 고정 테스트 수를 대체한다. 현재 릴리스 근거의 정확한 수치와 해시는 `contest-2026-submission-ko.md`에서만 관리한다.

## 한 줄 결론

K-Guard MCP는 바이브코딩 결과물을 출하 전에 집요하게 검수하는 한국 특화 시니어 감사관이다. 전지전능한 보증서가 아니라, 확인하지 못한 범위를 통과로 바꾸지 않는 fail-closed Guardian release gate다.

## 지원 클라이언트

정식 설치·연결 대상은 다음 네 개뿐이다.

- ChatGPT
- Grok
- Codex
- Antigravity

Cursor, Claude Code, Cline은 설치 대상이 아니다. 해당 도구가 만든 설정 파일은 코드 감사 입력으로만 읽을 수 있다.

## 대표 사용자 흐름

1. `check_my_app`으로 전체 workspace 검수를 시작한다.
2. `continue_review`를 `completed` 또는 `failed`까지 반복한다.
3. 발견 항목을 수정하고 같은 범위를 다시 검수한다.
4. 사업 목적, 데이터 종류, 사용자 범위, 공개 API, scope assertion을 명시한다.
5. `start_review_before_ship`을 실행하고 다시 `continue_review`를 terminal 상태까지 반복한다.
6. `guardian_gate.passed`와 `guardian_gate.canonical_release_authority`가 모두 `true`일 때만 SHIP으로 표현한다.

`queued`와 `running`은 통과가 아니다. `security_gate`, `scan --fail-on`, 개별 detector 결과도 출하 승인으로 확대 해석하지 않는다.

## 현재 구현 범위

| 영역 | 현재 구현 |
|---|---|
| 사이트 | 소스·설정·배포 산출물, 안전한 GET/OPTIONS, 허가된 bounded deep 노출 확인 |
| API | 인증 경계, IDOR/BOLA 후보, mass assignment, SSRF, 공개 endpoint 도달 증거 |
| 데이터 | 한국 개인정보·고유식별정보·결합정보, 저장·로그·보존·파기 marker, 외부 전달 후보 |
| 운영 | CI, lockfile, 인증 테스트, rate limit, MCP 설정, source snapshot, 증거 완결성 |
| MCP runtime | JSON/JSONL batch interceptor와 line-delimited stdio JSON-RPC proxy의 block/redact |
| 증거 | raw-free finding, 후보 인벤토리 해시, source snapshot, operator-keyed evidence bundle |

전체 검수는 테스트와 문서뿐 아니라 `dist`, `build`, `.next`의 지원되는 배포용 텍스트 후보도 포함한다. 5MiB를 넘는 지원 후보, 읽기 실패, 검사 중 후보 추가·삭제, 전후 source snapshot 차이는 high coverage gap으로 처리한다.

## 데이터 출하 계약

`data-release-gate`는 다음 항목을 모두 다시 확인한다.

- canonical Guardian `high` 보고서와 현재 manifest/source snapshot
- 단일 release app과 target-level intent/scope assertion
- 별도 primary/repeat validation-source Guardian 원본과 12~20개 owned/partner 앱의 역할 분리 서명·preregistered holdout·수동 TP/FP/FN 라벨
- 한국 개인정보 fixture 재계산 결과
- 실제 `mcp-intercept` forwarded JSONL
- interceptor schema, producer, app id, session id, Guardian report 결속
- 운영자 키로 서명된 interceptor와 release evidence bundle
- repeat Guardian의 다른 execution ID/bundle, 같은 toolchain/source snapshot, exact candidate set

임의로 조립한 interceptor JSON, 공개 기본키 서명, 다른 Guardian 보고서에 묶인 증거, 변경된 forwarded stream은 통과하지 못한다.

## 경계

- 앱의 사업 의도와 법적 적합성을 인간처럼 완전히 이해하지 않는다.
- TypeScript 타입·alias·middleware·RLS를 완전하게 증명하는 inter-procedural 분석기는 아니다.
- stdio JSON-RPC proxy와 Streamable HTTP POST/GET SSE/DELETE proxy가 구현되어 있다. binary framing과 모든 비표준 transport의 범용 proxy를 주장하지 않는다.
- 클라우드 IAM, 원격 DB 정책, 백업, 실제 파기 실행은 별도 운영 증거가 필요하다.
- 외부 대상 소유권과 partner scope는 운영자 assertion 경계다.
- 오탐·미탐 0, 법적 준수 보장, 인간 시니어 완전 대체를 주장하지 않는다.

## 검증 원칙

현재 코드와 같은 커밋에서 자동 테스트, coverage, archive closure, fresh-wheel 설치, MCP 실제 호출, release hygiene를 다시 실행한다. 외부 AI 이름만 적은 판정표는 증거로 사용하지 않으며, 명령 로그와 재현 가능한 지적·수정 내역이 있는 검토만 보조 근거로 기록한다.
