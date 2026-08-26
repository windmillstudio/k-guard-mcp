# H5A Maven XStream OSV Observe Preregistration

작성일: 2026-07-22

## 가설

K-Guard가 아직 Maven SCA를 지원하지 않는다는 사실을 숨기지 않는다. 먼저 공개된
WebGoat 소스의 `pom.xml`에서 XStream 1.4.5와 `CVE-2013-7285`의 기계 판정 쌍을
만든다. 원본 POM에서는 해당 CVE가 정확히 한 번 관측되고, 같은 POM의
`xstream.version` 하나만 1.4.7로 바꾼 음성 대조군에서는 해당 CVE가 관측되지 않아야
한다.

이 단계는 K-Guard의 탐지 규칙을 추가하거나 Guardian의 차단 정책을 바꾸지 않는다.
검증된 공개 OSV-Scanner를 외부 oracle로만 사용한다.

## 고정 입력과 판정

- 원본은 실행 시 지정한 SHA-256과 정확히 일치하는 WebGoat `pom.xml`이다.
- 음성 대조군은 `<xstream.version>1.4.5</xstream.version>` 한 곳을
  `<xstream.version>1.4.7</xstream.version>`으로 바꾼 임시 사본이다.
- `CVE-2013-7285`의 공개 설명은 XStream 1.4.6 이하가 영향을 받는다고 명시한다.
  OSV-Scanner JSON에서 ID 또는 alias가 이 CVE와 일치하는지만 본다.
- 관찰기는 OSV-Scanner 2.x의 `scan source --format json --no-resolve --lockfile`
  계약을 사용한다. 전이 의존성 해석, remediation, 소스 실행은 하지 않는다.
- OSV 설정 파일은 관찰기가 만든 빈 임시 설정 파일로 강제해 대상 저장소의 scanner
  설정이 판정에 개입하지 못하게 한다.
- 양성/음성 쌍을 두 번 독립 실행한다. 양성은 정확히 한 match, 음성은 0 match,
  두 실행의 정규화 projection은 모두 같아야 한다.

## 보존 경계

보고서에는 POM 본문, OSV 원문, 패키지명, 버전, 경로, stderr를 저장하지 않는다.
각 값은 SHA-256 참조, 바이트 수, 집계 수와 허용된 CVE ID로만 남긴다. 원문은
프로세스 메모리와 운영체제 임시 파일 수명 안에서만 사용된다.

OSV-Scanner 실행 파일 SHA-256과 정규화된 엔진 버전은 반드시 보고서에 결속한다.
실행 파일이 없거나, 출력 형식이 달라지거나, 원본 POM 해시가 달라지거나, 두 번의
결과가 다르면 조용히 통과하지 않고 `CONTROL_HOLD`로 끝낸다.

## 금지된 주장

- 이 결과는 Maven SCA 기능, K-Guard 탐지 정확도, TP/FP/FN, Guardian 통과를 뜻하지 않는다.
- 이 결과는 한 공개 CVE와 한 source-derived POM mutation의 oracle 준비도만 뜻한다.
- warning, block, release 승격은 모두 `false`로 고정한다.

## 다음 단계

H5A가 두 번 재현되고 외부 감독관이 이 좁은 claim boundary를 승인해도, 다음 H5B에서
K-Guard Maven adapter의 기존 baseline과 candidate A/B를 별도로 측정해야 한다. H5B도
observe-only이며, 다수의 독립 Maven oracle과 holdout을 통과하기 전에는 Guardian에
차단 finding으로 합류하지 않는다.
