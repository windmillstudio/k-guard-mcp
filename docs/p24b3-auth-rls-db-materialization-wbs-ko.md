# P2.4B.3 auth-rls-db 19-slot source materialization WBS

작성일: 2026-07-24  
상태: `IN_PROGRESS` - `P2.4B.3.01`부터 `P2.4B.3.12`까지 `FIX_NARROW`; `P2.4B.3.13`은 새 target E 완료 후 F1 대기  
상위 카드: [P2.4B generated pair materialization WBS](p24b-generated-pair-materialization-wbs-ko.md)  
선행 완료: [P2.4B.2 source-flow aggregate](p24b220-source-flow-aggregate-preregistration-ko.md) `FIX_NARROW`

## 왜 19개를 다시 leaf로 나누는가

`auth-rls-db`는 API 권한, IDOR/BOLA, RLS, Firebase rule, 서비스 역할 키, 데이터 row filter가
섞여 있다. family 하나를 한 번에 materialize하면 어느 권한 경계가 실패했는지, primary와 reserve가
어떻게 결속됐는지, 또는 어느 framework가 문제인지 알 수 없다. 따라서 아래 19개는 각각 독립
`A-G + Claude/Grok/GLM F1/F2` 카드를 가진다.

## 고정 family contract

- blueprint SHA-256: `3489c9a802a960a1c31451cb12d3cd2976d8c87be0c4c37c7c9e7fcf8a05e2a6`
- denominator: slot `19`, candidate `38`, primary `19`, reserve `19`, source triplet `114`, source file `342`
- 순서: API `api-01`부터 `api-15`, data `data-01`, `data-02`, `data-10`, `data-12`
- 각 leaf는 source/license/tree identity만 증명한다. runtime authorization, IDOR/BOLA exploit,
  Supabase/Firebase 실제 service, DB RLS enforcement, scanner finding, TP/FP/FN, recall, H100,
  release는 증명하지 않는다.
- source, exploit input, secret, URL, provider raw output은 external evidence packet과 aggregate에 넣지 않는다.
- 누락 leaf, 잘못된 순서, primary/reserve drift, raw output, evidence path overlap, comparator `HOLD`는
  family aggregate를 fail-closed `HOLD`로 만든다.

## leaf queue

| 카드 | slot / framework | CWE / severity | 단 하나의 좁은 목표 | 현재 |
| --- | --- | --- | --- | --- |
| P2.4B.3.01 | api-01 / JavaScript Express | CWE-862 / High | route IDOR primary/reserve source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.02 | api-02 / TypeScript Next.js | CWE-639 / High | service IDOR source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.03 | api-03 / TypeScript Supabase | CWE-284 / Critical | missing RLS source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.04 | api-04 / TypeScript Firebase | CWE-284 / Critical | open rule source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.05 | api-05 / TypeScript Next.js | CWE-285 / Critical | admin boundary source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.06 | api-06 / JavaScript Express | CWE-915 / High | mass-assignment source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.07 | api-07 / TypeScript Supabase | CWE-798 / Critical | service-role key source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.08 | api-08 / TypeScript Firebase | CWE-284 / High | storage read rule source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.09 | api-09 / Python FastAPI | CWE-862 / High | dependency auth source-tree identity | `FIX_NARROW` - A-G와 3AI F1/F2 comparator `FIX` |
| P2.4B.3.10 | api-10 / Python Django REST | CWE-639 / High | object-owner source-tree identity | `FIX_NARROW` - A-G와 3AI F1/r3 comparator `FIX`; F2 timeout 보존 |
| P2.4B.3.11 | api-11 / Python Flask | CWE-285 / High | role-guard source-tree identity | `FIX_NARROW` - A-G와 3AI F1/r3 comparator `FIX`; r2 packet-diff `HOLD` 보존 |
| P2.4B.3.12 | api-12 / Java Spring | CWE-862 / High | method-auth source-tree identity | `FIX_NARROW` - A-G와 clarified r2/r3 3AI comparator `FIX`; initial GLM `HOLD` 보존 |
| P2.4B.3.13 | api-13 / Kotlin Ktor | CWE-639 / High | resource-owner source-tree identity | `ACTIVE` - A-E 완료, prior E/F1 `BLOCKED_PROVIDER` 보존; 새 target packet F1 |
| P2.4B.3.14 | api-14 / Go chi | CWE-639 / High | handler BOLA source-tree identity | `NOT_STARTED` |
| P2.4B.3.15 | api-15 / Go gin | CWE-862 / High | middleware auth source-tree identity | `NOT_STARTED` |
| P2.4B.3.16 | data-01 / TypeScript Supabase | CWE-284 / Critical | PostgreSQL RLS-disabled source-tree identity | `NOT_STARTED` |
| P2.4B.3.17 | data-02 / TypeScript Prisma | CWE-732 / High | broad grant source-tree identity | `NOT_STARTED` |
| P2.4B.3.18 | data-10 / Java Spring | CWE-284 / Critical | tenant policy source-tree identity | `NOT_STARTED` |
| P2.4B.3.19 | data-12 / Kotlin Ktor | CWE-284 / High | row-filter source-tree identity | `NOT_STARTED` |
| P2.4B.3.20 | all 19 slots | mixed | fixed-order raw-free family aggregate, exclusion `0` | `NOT_STARTED` |

## 모든 leaf의 종료 순서

1. A: slot, scenario/oracle, primary/reserve, source role, expected static boundary, exclusion, 비주장을 먼저 고정한다.
2. B: leaf-scoped materializer/validator를 current target에 결속한다.
3. C: positive/negative, role swap, source/receipt/path/raw/overwrite tamper test를 fail-closed로 통과한다.
4. D: external r1/r2 source-tree comparator를 `FIX`로 만든다.
5. E: baseline, focused, full regression 및 target equality를 기록한다.
6. F1/F2: Claude Opus 4.8, Grok 4.5, Cline GLM 5.2이 같은 raw-free packet을 두 번 검토한다.
7. G: supervisor comparator `FIX`와 비주장을 기록할 때만 leaf를 `FIX_NARROW`로 바꾼다.

`.01-.19` 전부가 G까지 닫히고 `.20` aggregate와 family phase F1/F2까지 닫히기 전에는
`P2.4B.3` 전체를 완료 또는 성능 증거로 말하지 않는다.
