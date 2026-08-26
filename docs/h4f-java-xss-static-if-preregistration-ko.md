# H4F Java Static If 관찰 정교화 가설

상태: 개발 표본 측정 전 고정. H4F는 H4E 후 남은 Java XSS observe FP를 다시 분해한 뒤,
닫힌 정적 의미가 확인되는 최대 단일 하위군만 다룬다.

## 선택 근거

H4E 후 Java XSS observe 후보는 `TP=94`, `FP=22`, `FN=152`, `TN=187`이었다. 남은 후보에는
list index, map, reflection, StringBuilder, legacy encoder가 섞여 있다. 이 중 5개는 모두
same-file helper의 numeric constant 조건이 literal branch를 선택하는 같은 패턴이다.

1. method-local primitive numeric 값만 사용해 `if` 조건이 확정된다.
2. 확정된 branch는 return variable에 문자열 literal을 대입한다.
3. 반대 branch는 request 값을 사용할 수 있지만 실제로 선택되지 않는다.

이 5개 외에는 H4F의 측정 대상으로 포함하지 않는다.

## 하나의 가설

아래 범위만 지원한다.

1. H4D의 AST whitelist가 평가할 수 있는 method-local numeric/boolean 조건만 허용한다.
2. helper는 `if`와 `else`가 각각 하나, `return variable`이 하나, 그 variable의 대입이 두 개여야
   하며 switch, loop, exception handling, brace body, overload ambiguity가 있으면 제외한다.
3. 선택된 branch의 대입이 문자열 literal이고 helper 끝이 곧 `return variable`일 때만 helper 결과를
   input-independent safe로 본다.
4. request/unknown condition, 선택된 tainted branch, 추가 대입, nested control flow는 기존 observe
   후보를 유지한다.
5. list/map/reflection/legacy `escapeHtml` 흐름은 이 변경에서 다루지 않는다.

의미를 확정할 수 없으면 후보를 계속 남긴다. 이 변경은 Java servlet observer의 medium 후보만
정교화하며 severity, release lane, warning/block 승격, 다른 언어와 다른 취약점 rule을 바꾸지 않는다.

## A/B 방법

H4A부터 H4E까지의 억제는 양쪽 모두 켠다.

- control: `enable_java_servlet_xss_static_if_suppression=False`
- candidate: `enable_java_servlet_xss_static_if_suppression=True`
- 실행기: `scripts/run_java_xss_observe_ab.py --hypothesis H4F`
- manifest, Java source tree, expected-results, license를 실행 전후 검증한다.
- 공식 Java XSS truth와 H4A subtype만 비교하며, control/candidate를 각각 두 번 실행한다.

## 미리 고정한 처분

H4F는 공개 개발 표본에서 observer FP 한 원인을 측정하는 단계이며 항상 `MEASURED_HOLD`다.
결과가 좋아도 independent oracle, blind holdout, 전체 product gate, 세 외부 감독관의 동일 target
반복 검토 없이는 `warn`, `block`, release claim으로 승격하지 않는다.
