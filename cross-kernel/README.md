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
| Go | ar-io-agent `pkg/proof` @ [`PIN`](PIN) | **verdict-level** match (`pkg/proof.VerifyEnvelope` is all-or-nothing) |

The Go leg builds the *same* kernel `ariod verify` runs, materialized at the
pinned commit via a detached `git worktree` from a sibling `../ar-io-agent`
checkout — the proof-checker `wasm/PIN` pattern. It is **optional**: without an
available agent checkout it SKIPS loudly (so public-PR CI never fails on missing
private-repo access), but Python+TS always run.

## Run

```bash
bash cross-kernel/run.sh                          # Python + TS (+ Go if ../ar-io-agent present)
AGENT_SRC=/path/to/ar-io-agent bash cross-kernel/run.sh   # force a specific agent checkout
```

`cases.json` is generated (never committed); re-pinning the Go kernel (`PIN`)
or changing kernel behavior re-baselines it on the next run.

## Re-pin

Update `PIN`'s `agent_commit` to a new ar-io-agent commit, re-run, and commit
`PIN`. Re-pin is a deliberate act, never a floating HEAD.
