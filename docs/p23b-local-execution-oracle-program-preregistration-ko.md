# P2.3B 여섯 로컬 앱 execution oracle 프로그램 사전등록

작성일: 2026-07-23  
상태: `FIX_NARROW`  
상위 장부: [release-program-phase-ledger-ko.md](release-program-phase-ledger-ko.md) P2.3B

## 한 문장 목표

P2.3A에서 고정한 여섯 공개 source 각각에 대해 source-bound positive 실행 oracle과
negative control 하나를 독립적으로 재현한다. 각 앱은 다른 앱의 성공 증거나 과거
receipt를 재사용하지 않는다.

## 작업 분할과 순서

| 작업 | 대상 | 시작 조건 | 완료 기준 |
| --- | --- | --- | --- |
| P2.3B.1 | WebGoat | P2.3A source receipt | `FIX_NARROW` - IDOR positive와 source-mutated negative를 새 registry source에 다시 결속하고 두 run 비교 |
| P2.3B.2 | Juice Shop | P2.3B.1 `FIX_NARROW` | `FIX_NARROW` - [basket BOLA 사전등록](p23b2-juice-shop-basket-bola-preregistration-ko.md)의 upstream positive와 compiled source-mutated negative pair를 source-bound로 두 번 재현 |
| P2.3B.3 | NodeGoat | P2.3B.2 `FIX_NARROW` | upstream/official positive와 negative/reset pair를 source-bound로 재현 |
| P2.3B.4 | PyGoat | P2.3B.3 `FIX_NARROW` | upstream/official positive와 negative/reset pair를 source-bound로 재현 |
| P2.3B.5 | crAPI | P2.3B.4 `FIX_NARROW` | upstream/official positive와 negative/reset pair를 source-bound로 재현 |
| P2.3B.6 | WrongSecrets | P2.3B.5 `FIX_NARROW` | upstream/official positive와 negative/reset pair를 source-bound로 재현 |
| P2.3B.7 | aggregate | P2.3B.1-P2.3B.6 | six-app membership, positive/negative pair, source binding, repeat, coverage `HOLD`를 raw-free manifest로 결속 |

한 시점에는 이 표에서 하나만 `IN_PROGRESS`다. app에 공식 또는 source-derived
oracle을 찾지 못하면 대체 취약점이나 synthetic pass result로 바꾸지 않고 그 작업을
`HOLD`로 종료한다. 그 실패는 P2.3B.7 coverage에 그대로 포함한다.

## 공통 입력 계약

1. P2.3A clean source root의 immutable commit, tree, Git blob, root license, source
   receipt semantic hash와 일치해야 한다.
2. positive는 취약 상태를 실제 실행으로 판정하는 upstream test, 공식 challenge,
   upstream vulnerable/fixed revision 차분, 또는 기계 검증된 source-derived pair 중
   하나여야 한다.
3. negative는 같은 source receipt에 고정된 source-mutated control 또는 독립 upstream
   fixed revision이어야 한다. 단순히 종료 코드만 다른 실행은 negative가 아니다.
4. 실행 전후 source tree, container/image/volume ownership, network, privilege,
   read-only root, port lifetime, state reset을 receipt로 남긴다. 확인할 수 없는
   실행 환경 속성은 `PASS`가 아니라 `HOLD`다.
5. public evidence에는 source, secret, challenge payload, response body, absolute
   checkout path를 넣지 않는다. source-safe hash와 structured status만 남긴다.

## 각 작업의 A-G 완료 패킷

각 P2.3B.1-P2.3B.6은 아래 A-G를 충족해야 `FIX_NARROW`다. P2.3B.7은 별도
[aggregate 사전등록](p23b7-six-app-execution-aggregate-preregistration-ko.md)의 A-G를 적용한다.

| 칸 | 산출물 | 즉시 HOLD 조건 |
| --- | --- | --- |
| A | 앱별 oracle, source receipt, exclusion, claim boundary 사전등록 | oracle 선택이 실행 뒤에 바뀜 |
| B | replay 또는 evidence adapter 구현 | 다른 source 또는 과거 receipt를 무단 재사용 |
| C | focused fail-closed tests | missing evidence, mutation, cleanup, reset을 통과 처리 |
| D | 새 external output 두 개의 positive/negative repeat comparator | semantic result 또는 source binding 불일치 |
| E | 현재 target 전체 회귀 | shard 누락, failure, error, target drift |
| F | Claude Opus 4.8, Grok 4.5, Cline GLM 5.2 두 번 검토 | 한 lane HOLD/BLOCKED 또는 comparator 불일치 |
| G | 장부 승격 | runtime/oracle/metric 범위를 과장 |

## 고정 주장 경계

P2.3B의 각 `FIX_NARROW`는 한 앱의 한 positive/negative execution oracle과 그 실행
계약의 반복성만 뜻한다. 해당 앱의 모든 취약점, detector finding mapping, API 또는
데이터 보호 성능, TP/FP/FN/TN, recall, specificity, warning/block, Guardian, H100,
제품 release를 승인하지 않는다.

P2.3B.7은 이 여섯 앱의 historical component comparator를 6-app aggregate로 재검증한
카드일 뿐 새 실행이나 탐지 성능 증거가 아니다. 여섯 개 individual card와 aggregate가 모두
`FIX_NARROW`여도 이 프로그램은 제품 release를 승인하지 않는다.
