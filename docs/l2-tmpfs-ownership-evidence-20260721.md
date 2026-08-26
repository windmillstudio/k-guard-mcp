# L2 Tmpfs Ownership Evidence Packet

## Artifact Binding

This packet is a raw-free index for independent reviewers whose sandbox cannot
read the external evidence directory directly. It does not replace the
canonical JSON receipts.

- Runtime materializer SHA-256:
  `2617e620f3a76e3c887c1525f81d4bda4a9a63067c87b4f85451a8c7e6c42d28`
- Focused test file SHA-256:
  `b50c6dccafa0c1c77ae652a1e6c4cf03175f326bd354999e6aa427abf72d6915`
- Runtime plan SHA-256:
  `b073c39a2586b3fc5197267cca8d7d1f66b87b62170cfb52b5a50efbe1ffee8e`
- External evidence root:
  `<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-runtime-juice-ownership-contract-20260721-r1`

## Current Receipts

| Artifact | File SHA-256 | Receipt SHA-256 | Run Nonce SHA-256 |
| --- | --- | --- | --- |
| `runtime-observation-r5-nonce-tool.json` | `a96ae28b8f375c1d50d7234f3051553ce14433611455f82820b66e87f207a771` | `5ca3d198bf9098eb7d37dde747b21ffa007221f4f18c061c016d4dd1ed7f6b04` | `48e62813e5f091b9d0ea50f1f1878c5a37b74ea705263844dd421e91ce91f906` |
| `runtime-observation-r6-nonce-tool.json` | `296082c2ccb38d7b4f54c19ae2ba8bd69db53ed990fa7c3e589cfc07c9a43c50` | `80e2417b77fa7c958d3e577497048a8bd40ec90f3e6cbe322780b99e613752be` | `ded2fb0c09d9121208c2b04cd10eddf177d6fb2e5eccf0a466484f5a96ff85bf` |

Both receipts validate with the current runtime materializer. Their six-app
status map is identical:

```text
crapi HOLD
juice-shop PASS
nodegoat HOLD
pygoat HOLD
webgoat HOLD
wrongsecrets HOLD
```

For Juice Shop, both receipts record `run_as: 65532:0`, hardened tmpfs,
read-only root filesystem, no host port publish, internal health status 200 on
attempt 2, denied external egress, and successful owned cleanup.

## Replay Result

`replay-comparison-r5-r6-nonce.json` has file SHA-256
`969c8f5ce36dc2992abef8213f28de1e2b1be5c44421a9dcae2df5374f0629c7`.
It records all of the following as true:

- source admission equality;
- runtime plan equality;
- tool provenance equality;
- app-status equality;
- decision-projection equality;
- distinct execution nonce;
- distinct receipt hash.

The comparison result is `replay_gate: PASS` with decision projection SHA-256
`11e51a8f1cf4342722e89c4eac8564e71780d5de59616e025626301fca574d20`.
Both underlying six-app runtime gates remain `HOLD`, and the comparison sets
`release_gate_passed: false`.

## Test Result

- `python -m pytest -q tests/test_materialize_l2_runtime.py`: `83 passed`.
- `python -m pytest -q`: `2154 passed, 5 skipped` in `736.71s`.

This packet supports the narrow runtime measurement claim only. It does not
claim detector accuracy, full L2 completion, or product release readiness.
