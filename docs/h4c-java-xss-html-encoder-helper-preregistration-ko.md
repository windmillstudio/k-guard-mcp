# H4C Java HTML Encoder Helper 관찰 정교화 가설

상태: 개발 표본 측정 전 고정. H4C는 H4B 이후 남은 FP의 한 원인만 다룬다.
실행 결과를 본 뒤 helper 범위나 판정 기준을 넓히지 않는다.

## 선택 근거

H4B 후 Java XSS observe 후보는 `TP=94`, `FP=53`, `FN=152`, `TN=156`이었다.
남은 FP 53개 중 14개는 같은 Java 파일의 작은 helper가 이미 알려진 HTML encoder를
호출하고 반환하는 경우였다. H4B는 직접 대입만 허용했기 때문에 이 helper 반환값을
계속 tainted로 보았다.

## 하나의 가설

helper를 일반적으로 따라가지 않는다. 아래 조건을 모두 충족하는 같은 파일의 helper
한 단계만 summary로 인정한다.

1. helper에는 return이 하나뿐이다.
2. return한 local 변수의 대입도 하나뿐이다.
3. 그 대입 우변 전체가 H4B에서 고정한 알려진 HTML encoder의 단일 parameter 호출이다.
4. helper 본문에는 `if`, `switch`, loop, `try/catch/finally`가 없다.
5. call site의 해당 인자는 이미 tainted local variable이다. 중첩 request source,
   변환식, custom wrapper, 재귀, overload ambiguity는 인정하지 않는다.

이 summary가 하나라도 불명확하면 값을 tainted로 유지한다. 이 변경은 Java servlet
XSS observer의 observe 단계만 바꾸며, release lane·severity·confidence·SQL·command·
IDOR·Kotlin 분석을 바꾸지 않는다.

## A/B 방법

H4B direct encoder suppression은 양쪽 모두 켠다.

- control: `enable_java_servlet_xss_html_encoder_helper_suppression=False`
- candidate: `enable_java_servlet_xss_html_encoder_helper_suppression=True`
- 실행기: `scripts/run_java_xss_observe_ab.py --hypothesis H4C`
- corpus integrity, XSS Java truth, redacted registry, 두 번의 canonical repeat 계약은
  H4A/H4B와 동일하다.

```powershell
python scripts/run_java_xss_observe_ab.py `
  --hypothesis H4C `
  --manifest C:\evidence\l1-manifest.json `
  --benchmark-java C:\sources\BenchmarkJava `
  --baseline-receipt C:\evidence\baseline.json `
  --output-dir C:\evidence\h4c-java-xss-helper-<run-id>
```

## 미리 고정한 처분

H4C 결과는 개발 표본의 한 observer FP 원인을 측정할 뿐이며 항상 `MEASURED_HOLD`다.
FP가 줄더라도 independent pair, candidate-level TP/FP oracle, blind holdout, 제품 전체
gate, Claude Opus·Grok·GLM의 동일 target 검토 없이는 `warn` 또는 `block`으로 승격하지
않는다.
