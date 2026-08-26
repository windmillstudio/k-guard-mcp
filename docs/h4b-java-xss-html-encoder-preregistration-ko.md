# H4B Java HTML Encoder 관찰 정교화 가설

상태: 개발 표본 측정 전 고정. H4A 결과를 본 뒤 선택한 단일 오류군이지만, H4B
실행 결과를 본 뒤에는 이 범위와 승격 기준을 바꾸지 않는다.

## 선택 근거

H4A 공개 개발 측정은 `TP=94`, `FP=63`, `FN=152`, `TN=146`이었다. FP 63개 중
28개는 같은 메서드에서 명시적인 HTML encoder를 호출한 뒤 응답에 쓰는 경우였다.
H4A의 단순 지역 대입 추적은 encoder 호출 자체를 taint 전파로 취급했다. H4A는
계속 observe-only HOLD이며, H4B는 그 관찰기의 한 오류 원인만 비교한다.

## 하나의 가설

다음 조건을 모두 만족한 **직접 지역 대입**만 taint를 끊는다.

1. encoder의 단일 인자가 이미 request-derived tainted local variable이다.
2. 대입 우변 전체가 알려진 HTML encoder 호출 하나다. 문자열 연결, 추가 request 값,
   조건문, wrapper, 함수 간 반환은 이 가설에서 인정하지 않는다.
3. callee는 아래 정확한 이름 중 하나다.
   - Spring `HtmlUtils.htmlEscape`
   - OWASP ESAPI `ESAPI.encoder().encodeForHTML`
   - OWASP Java Encoder `Encode.forHtml`
   - Apache `StringEscapeUtils.escapeHtml4`
   - Guava `HtmlEscapers.htmlEscaper().escape`

이외의 함수는 계속 tainted로 남긴다. 이 변경은 Java servlet XSS observer 이외의
SQL, command, IDOR, Spring authorization, Kotlin 분석을 바꾸지 않는다.

## A/B 방법

고정 manifest와 source tree에서 H4A observer는 양쪽 모두 켠다.

- control: `enable_java_servlet_xss_html_encoder_suppression=False`
- candidate: `enable_java_servlet_xss_html_encoder_suppression=True`
- 실행기: `scripts/run_java_xss_observe_ab.py --hypothesis H4B`
- source integrity: 전체 Java source tree와 expected-results, license를 전후 두 번 검증
- score: H4A subtype만 공식 XSS Java truth와 비교, 두 번의 canonical projection을 비교

H4A가 이미 개발 표본을 본 상태이므로 이 결과도 독립 holdout이나 제품 성능 증거가
아니다. 실행 receipt에는 redacted case reference, candidate line hash, subtype, rule,
severity, confidence만 남긴다.

```powershell
python scripts/run_java_xss_observe_ab.py `
  --hypothesis H4B `
  --manifest C:\evidence\l1-manifest.json `
  --benchmark-java C:\sources\BenchmarkJava `
  --baseline-receipt C:\evidence\baseline.json `
  --output-dir C:\evidence\h4b-java-xss-encoder-<run-id>
```

## 미리 고정한 처분

H4B의 성공 조건은 개발 측정에서 direct-known-encoder FP가 줄고, 반복성과 기존 회귀가
유지되는지 확인하는 데까지다. 결과는 항상 `MEASURED_HOLD`다.

`warn` 또는 `block` 승격에는 독립 pair, 모든 후보의 TP/FP oracle, 별도 holdout,
전체 제품 gate, 그리고 Claude Opus·Grok·GLM의 동일 target 검토가 추가로 필요하다.
H4B만으로 rule severity, release lane, block actionability, 제품 recall을 올리지 않는다.
