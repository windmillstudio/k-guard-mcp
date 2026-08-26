# H4A Java Servlet XSS 관찰 가설

상태: 개발 표본 측정 전 고정. 이 문서는 H4A의 범위와 승격 금지를 먼저
명시한다. 측정 결과를 본 뒤 기준, 라벨, 규칙 범위를 바꾸지 않는다.

## 선택 근거

L1 공개 개발 기준선 `phase5-l1-full-baseline-20260722-r2`에서 Java의 XSS
매핑 결과는 `TP=0`, `FP=0`, `FN=246`, `TN=209`였다. 이 오류군은 해당 기준선의
가장 큰 단일 매핑 FN 군이므로 H4A로 선택했다. 이 공개 표본은 이미 선택과
설계에 사용됐으므로 독립 holdout이나 제품 정확도 증거가 아니다.

## 하나의 가설

`PolyglotRiskDetector`에 Java 전용, 같은 메서드 안의 제한된 관찰기를 둔다.
다음 신호가 모두 있을 때만 `WEB_UNTRUSTED_INPUT_TO_HTML` 후보를 낸다.

1. `HttpServletRequest`의 `getParameter`, `getParameterMap`, `getHeader`, 또는
   `getHeaders`가 출발점이다.
2. 단순 지역 대입만 따라간다. 컬렉션, reflection, writer alias, 함수 간 호출은
   모델링하지 않는다.
3. 같은 메서드에 명시적인 `response.setContentType("text/html...")`가 있다.
4. 같은 `HttpServletResponse`의 직접 `getWriter().print`, `println`, `write`,
   `format`, 또는 `printf` 출력까지 도달한다.
5. 정적 format 문자열은 실제 conversion이 있고 해당 출력 인자가 tainted일 때만
   후보가 된다. 출력하지 않는 정적 format 문자열은 후보가 아니다.

후보 메타데이터는 `severity=medium`, `confidence=medium`,
`detector_subtype=java_servlet_bounded_html_response_observe`로 고정한다.
따라서 현재 Guardian의 high 기준 출하 HOLD와 자동 차단에 들어가지 않는다. 이것은
`observe`이며 `warn`이나 `block`이 아니다.

## A/B 방법

`scripts/run_java_xss_observe_ab.py`는 고정된 L1 manifest와 Java source tree를
실행 전후 모두 검증한 다음, XSS Java 행만 두 번씩 측정한다.

- control: 같은 revision에서 observer를 명시적으로 끈 `PolyglotRiskDetector`
- candidate: 기본 observer를 켠 동일 detector
- score: 공식 `truth`와 H4A subtype 후보만으로 TP/FP/FN/TN을 기계적으로 계산
- evidence: case reference hash, line hash, detector subtype, rule, severity,
  confidence만 기록하고 source text, 경로, request 값은 기록하지 않음
- repeat: control과 candidate의 canonical projection hash가 각각 일치해야 함

실행은 새 외부 evidence 디렉터리에만 쓴다. 현재 source target을 다시 봉인한
baseline receipt가 필요하다.

```powershell
python scripts/run_java_xss_observe_ab.py `
  --manifest C:\evidence\l1-manifest.json `
  --benchmark-java C:\sources\BenchmarkJava `
  --baseline-receipt C:\evidence\baseline.json `
  --output-dir C:\evidence\h4a-java-xss-observe-<run-id>
```

## 미리 고정한 처분

이 실행이 성공해도 결과는 항상 `MEASURED_HOLD`다. H4A는 개발 표본에서 관찰 후보가
얼마나 늘었는지 보이는 단계일 뿐 다음을 증명하지 않는다.

- block precision 또는 block actionability
- 제품 전체 recall, specificity, FN 분포
- Java 일반 또는 XSS 일반에 대한 완전한 분석 깊이
- Guardian 출하 승인, H100, 실제 앱 성능

`warn` 승격에는 독립적으로 사전등록한 pair와 모든 후보의 TP/FP oracle, 반복성,
회귀 검사, Claude Opus·Grok·GLM의 같은 target 검토가 필요하다. `block` 승격에는
그 외에도 최종 비공개 H100과 제품 전체 합격선을 동시에 통과해야 한다.
