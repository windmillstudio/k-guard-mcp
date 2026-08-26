# H4D Java Static Ternary 관찰 정교화 가설

상태: 개발 표본 측정 전 고정. H4D는 H4C 후 남은 FP 중 가장 큰 단일 패턴인
상수 조건 삼항식만 다룬다.

## 선택 근거

H4C 후 Java XSS observe 후보는 `TP=94`, `FP=39`, `FN=152`, `TN=170`이었다.
FP 39개 중 10개는 정수 상수와 닫힌 산술·비교식으로 이미 결정되는 삼항식에서,
선택되지 않는 request branch 때문에 값 전체를 tainted로 본 경우였다. 같은 패턴의
TP도 9개 존재하므로 조건을 무시하고 삼항식을 억제하면 안 된다.

## 하나의 가설

아래 범위만 지원한다.

1. method-local `byte`, `short`, `int`, `long`, `boolean` 상수 대입을 순서대로 기록한다.
2. 산술 `+ - * %`, unary sign, 비교, boolean `&& ||`만 AST whitelist로 평가한다.
   division, call, field access, cast, mutation, unknown name, overflow 의미는 평가하지 않는다.
3. 삼항 조건이 확실히 boolean이고 선택된 branch가 문자열 literal일 때만 그 대입을
   untainted로 기록한다.
4. 선택된 branch가 request/tainted local이면 기존처럼 tainted를 유지한다.
5. 같은 파일 helper는 return 하나, return variable 대입 하나, 제어문 없음, 정적
   삼항식의 literal branch 반환, overload ambiguity 없음일 때만 한 단계 summary로 인정한다.

의미를 확정할 수 없으면 후보를 계속 남긴다. 이 변경은 observer의 medium 후보만
정교화하며 severity, release lane, warning/block 승격, 다른 언어와 다른 취약점 rule을
바꾸지 않는다.

## A/B 방법

H4A/H4B/H4C 억제는 양쪽 모두 켠다.

- control: `enable_java_servlet_xss_constant_ternary_suppression=False`
- candidate: `enable_java_servlet_xss_constant_ternary_suppression=True`
- 실행기: `scripts/run_java_xss_observe_ab.py --hypothesis H4D`
- manifest·Java source tree·expected-results·license를 실행 전후 검증하고, 공식 XSS
  Java truth와 H4A subtype만 비교하며, control/candidate를 각각 두 번 실행한다.

```powershell
python scripts/run_java_xss_observe_ab.py `
  --hypothesis H4D `
  --manifest C:\evidence\l1-manifest.json `
  --benchmark-java C:\sources\BenchmarkJava `
  --baseline-receipt C:\evidence\baseline.json `
  --output-dir C:\evidence\h4d-java-xss-ternary-<run-id>
```

## 미리 고정한 처분

H4D는 개발 표본에서 한 observer FP 원인을 측정하는 단계이며 항상 `MEASURED_HOLD`다.
결과가 좋아도 independent oracle, blind holdout, 전체 product gate, 세 외부 감독관의
동일 target 검토 없이는 `warn`, `block`, release claim으로 승격하지 않는다.
