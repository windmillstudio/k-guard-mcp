# P8.2B Windows native supervisor transport 사전등록

작성일: 2026-07-25  
상태: `FIX_NARROW` - A-G 완료; P8.2A E 재기준선이 다음 단일 카드  
상위 카드: [목표 통제와 독립 검증 운영](release-program-goal-control-ko.md)

## 한 문장 목표

Windows npm shim의 `cmd.exe` 명령행 길이 제한 때문에 긴 raw-free review packet이 끊기지 않도록,
Claude와 Cline supervisor는 검증 가능한 같은 설치본의 native `.exe`를 선택하고 Grok은 기존 native
`.exe` 경로를 그대로 사용한다.

## 시작 전 관찰과 범위

P8.2A는 bare `claude`/`cline` shim 발견과 health r1/r2 repeatability를 해결했지만, P8.2A F1 r1의
review packet은 UTF-8 7,829 bytes이고 terminal schema·contract가 더해져 Windows `.cmd` invocation에서
Claude와 GLM이 같은 31-byte stderr/exit 1로 `BLOCKED_PROVIDER`가 됐다. Grok native `.exe`는 `GO`였다.

P8.2A의 F1 r1 및 이 진단은 삭제하지 않는다. 이 카드는 그 failure를 P8.2A의 성공 근거로 바꾸지
않고, native transport라는 새 가설만 별도로 검증한다.

## A: 결과 전 고정한 계약

| 항목 | 고정 내용 |
| --- | --- |
| 대상 | Windows에서 PATH가 npm `claude.cmd` 또는 `cline.cmd` shim을 반환하는 기본 supervisor 실행 경로 |
| positive | resolver는 shim parent 아래의 허용된 Claude/Cline native `.exe`만 선택한다. Grok의 resolved native `.exe`는 바꾸지 않는다. |
| explicit path | 명시된 existing native executable은 그대로 absolute path로 사용한다. native candidate를 찾지 못한 shim은 임의 shell wrapper, 다른 model, 다른 provider로 바꾸지 않는다. |
| length boundary | long review packet과 terminal schema는 native executable의 Windows process command line에서 전달한다. command transport가 실패하면 provider lane은 `BLOCKED_*`여야 한다. |
| negative | 허용 경로 밖 파일, 없는 native candidate, raw provider output persistence, prompt 내용 축소에 의한 증거 누락은 성공으로 취급하지 않는다. |
| replay | post-registration focused test, real long-packet transport r1/r2, semantic comparator, full regression, Claude/Grok/GLM F1/F2를 새 target에서 수행한다. |

## 명시적 비주장

이 카드는 Windows process transport와 reviewer invocation만 다룬다. Claude·Grok·GLM의 review
결론, provider 장기 가용성, 탐지 정확도, 제품 보안, API13, TP/FP/FN, H100, Guardian, 설치 완결성,
출하 승인을 증명하지 않는다.

## A-G gate

| Gate | 완료 조건 | 현재 |
| --- | --- | --- |
| A | 위 native candidate, positive/negative, claim boundary 사전등록 | `DONE` |
| B | provider-aware native resolver와 runner binding | `DONE` - `supervisor_executable_resolution.py`가 Claude/Cline npm `.cmd`의 허용 native `.exe`만 선택하고 review/health runner에 provider를 결속 |
| C | native/shim/explicit/missing/long-packet focused tests | `DONE` - transport probe/comparator와 resolver/review/health focused test 40 passed |
| D | real long-packet transport r1/r2와 semantic comparator | `DONE` - r1/r2 모두 Claude/Grok/GLM native `.exe` `GO`, Claude direct-file attested, comparator `FIX`; semantic fingerprint `8c9aabb5...45a345`, comparison SHA-256 `7b8647ba...577a3` |
| E | baseline, focused/full regression, target equality | `DONE` - baseline current validation, focused 52 passed, full 2,784 passed/5 skipped, all target equality/control error 없음 |
| F1/F2 | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 two-run review | `DONE` - r1/r2 모두 Claude/Grok/GLM `GO`, Claude 6-file direct attestation, supervisor comparator `FIX` |
| G | comparator hash와 non-claim 기록 | `DONE` - comparator SHA-256과 non-claim을 아래에 결속 |

## 재개 경계

P8.2B는 G까지 `FIX_NARROW`로 닫혔다. P8.2A는 native transport와 상태 전이 뒤 새 baseline부터
E를 다시 생성하고, API13은 P8.2A G 후 새 baseline부터 재개한다.

## D evidence

- r1: `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase8-p82b-windows-native-supervisor-transport-20260725-r1\\transport-probe.json`
  SHA-256 `48fec643e26bd96d58523ab50a31e50991b4c2bfea4bde8488cf93e509612942`
- r2: `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase8-p82b-windows-native-supervisor-transport-20260725-r2\\transport-probe.json`
  SHA-256 `48fec643e26bd96d58523ab50a31e50991b4c2bfea4bde8488cf93e509612942`
- comparator: `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase8-p82b-windows-native-supervisor-transport-20260725-r1-r2-comparison.json`
  SHA-256 `7b8647ba9320393357be8974598997be3a506802d28828b1eb926907d69577a3`

## E evidence

아래 첫 묶음은 A-D 상태 target에서 만든 E-0으로 보존한다. E-0 뒤 상태 marker가 A-E로 전이해
F1/F2에는 사용하지 않았다. 이 불일치를 숨기지 않고 E-1을 별도로 다시 실행했다.

- baseline: `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase8-p82b-windows-native-supervisor-transport-20260725-baseline.json`
  receipt `9b96fcf1b6401f2a6426f60f44efaa3061ccd43c2df0499d4b5fbbe0c84d4d7f`, file SHA-256
  `bcfb29f71794d7d513e27fc7bcc45282b975bfe3ab9f671ceded13dc1fdbd432`
- focused: `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase8-p82b-windows-native-supervisor-transport-20260725-focused\\regression-attestation.json`
  52 passed, receipt `fa06f0e05217b0dca641ff29bb436006431701a54f5ae7d8c3ade4b1e312e4fd`, file SHA-256
  `f620c5d1a6d59f4fad3a3f2c6f48b0543370996726d7c89502566a340aede9ee`
- full: `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase8-p82b-windows-native-supervisor-transport-20260725-full\\regression-attestation.json`
  2,784 passed / 5 skipped / 0 failed in 1,390,015 ms, receipt
  `8ab363ff89d9ec7289a6427cfb2216d46b7ebedc05295a73c9824ca04a44cf38`, file SHA-256
  `f2670be76c93b4068280f2ca3de9a16b6d10e08e211bf9ba487bcf78c6a8e0fe`

E-1은 A-E 상태 target으로 F1/F2에 실제 결속한 재실행이다.

- baseline: `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase8-p82b-windows-native-supervisor-transport-20260725-f1-baseline.json`
  receipt `62e2cade6dabf82a7daf9aeab35eddeb2a3a10a6fc88991b9f654506e8eac51f`, file SHA-256
  `9ba756741e8e3eeda6c389d3e6998a57bdf0939d111bcee6206934f17ae84f45`
- focused: `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase8-p82b-windows-native-supervisor-transport-20260725-f1-focused\\regression-attestation.json`
  52 passed, receipt `607949b724074b820dba28224ab439c3fa2d5424939ca5de64f37b511ecc8c95`, file SHA-256
  `20d01e6c16ecf6c1e78b91a1d1cfedaccc48ca29f738d89650df63f893954ae6`
- full: `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase8-p82b-windows-native-supervisor-transport-20260725-f1-full\\regression-attestation.json`
  2,784 passed / 5 skipped / 0 failed in 1,178,484 ms, receipt
  `7fb2f1e396a7b7adae3aee59b1234a250f7f3809f1f59de918b4a4135b6fc157`, file SHA-256
  `79fc2e5b9654f24fa652b868c385da584e979e052c4aee965434d6b2ec268d32`

## F/G evidence

- F1/F2 comparator: `<LOCAL_USER_HOME>\\Desktop\\mcp\\k-guard-live-evidence\\phase8-p82b-windows-native-supervisor-transport-20260725-supervisor-review-v1-r1-r2-comparison.json`
  status `FIX`, semantic fingerprint `99b1c9718bf823a7da129e28a690a840be9cda3553eedb29f8117101b8648919`,
  file SHA-256 `5847a5974336774413287aae7f0953804b67996154a09bc4de7df993f9a4a331`
- each review: all three models `GO`, `REPEATABILITY_GAP` exactly once as required for the unpromoted first/second
  packet, target unchanged, and Claude direct-file attestation count 6.

두 receipt가 같은 해시라는 사실은 입력 packet, target, terminal summary가 동일했음을 뜻한다. 이 증거는
native transport만 `FIX_NARROW`로 만들 수 있고, 제품 또는 출하 claim을 만들지 않는다.
