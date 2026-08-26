# H4E Java Static Switch 관찰 정교화 가설

상태: 개발 표본 측정 전 고정. H4E는 H4D 후 남은 Java XSS observe FP를 유형별로 다시
분류한 결과, 동일한 정적 의미를 가진 최대 단일 하위군만 다룬다.

## 선택 근거

H4D 후 Java XSS observe 후보는 `TP=94`, `FP=29`, `FN=152`, `TN=180`이었다. 잔여
FP에는 넓게 보면 collection 관련 코드가 19개 있었지만, 그 안에는 list index, map,
reflection, StringBuilder, switch가 섞여 있어 하나의 안전한 규칙으로 취급할 수 없다.

그중 7개는 모두 다음의 닫힌 패턴이었다.

1. same-file helper 안에서 ASCII 문자열 literal과 고정 `charAt(index)`로 switch selector를 만든다.
2. selector가 선택하는 `case`는 return variable에 문자열 literal을 대입하고 `break`한다.
3. request 값을 받더라도 선택된 branch는 그 값을 사용하지 않는다.

이 7개 외에는 이 가설의 측정 대상으로 포함하지 않는다.

## 하나의 가설

아래 범위만 지원한다.

1. method-local direct ASCII `String` literal, direct `char` literal, 또는 그 literal의
   `charAt(non-negative literal index)`만 selector 값으로 인정한다.
2. same-file helper는 switch가 정확히 하나여야 하며, nested brace, `if`, loop, exception
   handling, overload ambiguity가 있으면 summary에서 제외한다.
3. selector와 일치하는 `case` 안에 return variable의 문자열 literal 대입 하나와 `break`가
   동시에 있을 때만 helper 결과를 input-independent safe로 본다.
4. selector가 request/unknown 값이거나 선택 branch가 request/tainted value를 사용하면 기존
   observe 후보를 유지한다.
5. 다른 case, default, map/list/reflection, StringBuilder, escapeHtml legacy 호출은 이 변경에서
   다루지 않는다.

의미를 확정할 수 없으면 후보를 계속 남긴다. 이 변경은 Java servlet observer의 medium
후보만 정교화하며 severity, release lane, warning/block 승격, 다른 언어와 다른 취약점 rule을
바꾸지 않는다.

## A/B 방법

H4A/H4B/H4C/H4D 억제는 양쪽 모두 켠다.

- control: `enable_java_servlet_xss_static_switch_suppression=False`
- candidate: `enable_java_servlet_xss_static_switch_suppression=True`
- 실행기: `scripts/run_java_xss_observe_ab.py --hypothesis H4E`
- manifest, Java source tree, expected-results, license를 실행 전후 검증한다.
- 공식 Java XSS truth와 H4A subtype만 비교하며, control/candidate를 각각 두 번 실행한다.

```powershell
python scripts/run_java_xss_observe_ab.py `
  --hypothesis H4E `
  --manifest C:\evidence\l1-manifest.json `
  --benchmark-java C:\sources\BenchmarkJava `
  --baseline-receipt C:\evidence\baseline.json `
  --output-dir C:\evidence\h4e-java-xss-static-switch-<run-id>
```

## 미리 고정한 처분

H4E는 공개 개발 표본에서 observer FP 한 원인을 측정하는 단계이며 항상 `MEASURED_HOLD`다.
결과가 좋아도 independent oracle, blind holdout, 전체 product gate, 세 외부 감독관의 동일
target 반복 검토 없이는 `warn`, `block`, release claim으로 승격하지 않는다.
