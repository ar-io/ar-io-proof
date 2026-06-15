# Cross-kernel agreement gate

A Python ⇄ TypeScript ⇄ Go agreement gate over the conformance corpus plus
adversarial cases. The three kernels (`src/ario_proof`, `ts/`, ar-io-agent
`pkg/proof`) must return **identical verdicts on identical bytes** — a verifier
that "accepts" a profile but mis-binds is worse than one that rejects it.

This complements the per-kernel byte-for-byte corpus conformance (each kernel
reproduces the vectors) with cross-kernel **verdict** agreement on
`verifyEnvelope` — the behavior the corpus alone doesn't pin: external-commitment
binding modes, mode confusion, missing/malformed `payload_hash` (§2), and
malformed `spec_version` minors (#13). It is the non-WASM sibling of the
proof-checker's JS↔WASM(Go) agreement gate, extended to the Python reference.

## Legs

| Leg | Source | Asserts |
|---|---|---|
| Python | in-repo `src/ario_proof` | the **reference** verdicts (full tri-state) |
| TypeScript | in-repo `ts/dist` | **full tri-state** match (`payloadHashOk` null/true/false) |
| Go | **vendored** ar-io-agent `pkg/proof` @ [`PIN`](PIN) | **verdict-level** match (`pkg/proof.VerifyEnvelope` is all-or-nothing) |

The Go leg builds the *same* kernel `ariod verify` runs, **vendored** under
[`vendor-agent/pkg/proof/`](vendor-agent/pkg/proof/VENDORING.md) at the pinned
commit (the MIT-carved-out kernel — `LICENSE` preserved). Vendoring (vs
token-cloning the private repo) means all three legs run on **public and fork
PRs** with no secret, so the tri-kernel gate is load-bearing for everyone.

## Run

```bash
bash cross-kernel/run.sh   # Python + TS + Go, no external checkout needed
```

`cases.json` is generated (never committed); changing any kernel re-baselines
it on the next run.

## Re-pin

To track a new ar-io-agent kernel: bump `PIN`'s `agent_commit` and re-sync the
vendored files (see [`vendor-agent/pkg/proof/VENDORING.md`](vendor-agent/pkg/proof/VENDORING.md)),
then commit. A deliberate act, never a floating HEAD.
