# P1.3 Raw-Free Candidate Receipt 사전등록

## 좁은 가설

공개 source candidate queue와 public-field 외부 AI 라벨 queue는 High/Critical 후보의
식별자, redacted fingerprint, detector subtype, 위치 종류, response hash 관계를
원문 없이 결속할 수 있어야 한다. source finding에는 response hash가 존재하지
않는다는 사실 자체를 `null`로 고정하고, response finding에는 body/header 위치와
64자리 response hash가 함께 있어야 한다.

## 고정 계약

1. candidate ID는 20자리 소문자 hex이고 redacted fingerprint는 정확히
   `sha256-truncated:<candidate_id>`다.
2. `detector_subtype`, `artifact_scope`, source location, scan report hash는 빈 값이나
   원문 위치가 될 수 없다.
3. `location.kind=source`이면 `location.source`는 source location과 같고,
   `body_or_header=null`, `response_hash=null`이어야 한다.
4. `location.kind=response`이면 `body_or_header`는 `body` 또는 `header`이고,
   response hash는 64자리 SHA-256이어야 한다.
5. public-field 독립 라벨의 candidate binding hash에는 response hash와 location
   object를 직접 포함한다. queue 전체 hash만으로 간접 결속하지 않는다.
6. 어떤 candidate라도 이 계약을 어기면 label assembly 또는 current public replay는
   fail-closed한다.

## 측정 경계

이 작업은 raw-free evidence 형태와 provenance를 검증한다. 탐지의 true positive,
false positive, recall, precision, 실제 웹 응답의 안전성, 사람 또는 AI의 판정 품질,
warning/block 승격, Guardian release, H100, 제품 출하를 증명하지 않는다.

## 검증 순서

1. r15 기준선에서 focused test를 실행한다.
2. pinned current public source replay candidate queue를 다시 검사한다.
3. 같은 입력을 두 번 실행해 receipt의 semantic projection을 비교한다.
4. 전체 2,428개 회귀를 새 target에서 실행한다.
5. Claude Opus 4.8 direct-file 검토와 Grok 4.5, Cline GLM 5.2 raw-free 검토를
   같은 packet으로 두 번 실행한다.
6. 세 모델의 두 review run comparator가 `FIX`일 때만 P1.3A를 `FIX_NARROW`로
   기록한다.

## 실패 처리

response hash가 source candidate에 붙거나 response candidate에서 빠지면 pass로
보정하지 않는다. 후보는 라벨링과 성능 분모에서 제외하지 않고 해당 실행을 `HOLD`로
남긴다.
