# ar.io Verification Stack — core architecture

> **Status: ratified v1.0 (2026-06-10).** Architecture standard. Defines how the stack is factored so new producers (agents) and connectors can be added without re-implementing or forking the cryptographic core. It sits beside [`../envelope-spec.md`](envelope-spec.md) (the *what* — the envelope contract) and explains the *how* — the code factoring that keeps that contract coherent across languages and products. No byte changes; this governs structure, not format. Key words MUST / MUST NOT / SHOULD / MAY per RFC 2119.
>
> **Ratification record.** Ratified as-is by the BDFL per [`governance.md`](governance.md) §1–§2 (v1.2 coordination decision D2, [`v1.2-coordination/README.md`](https://github.com/ar-io/ar-io-api-guard/blob/main/docs/stack/v1.2-coordination/README.md)). The normative content is: the kernel rules **K1–K5** (§3), the corpus rules **CORP1–CORP3** (§4), the connector rules **C1–C3 + C2a** (§6), the transport rules **T1–T2** (§7), and the verify boundary (§8). §12's remaining open decisions do not gate the standard; changes from here are additive = minor, breaking = major + 30-day RFC per governance.md.

## 0. Thesis

There is no shared "anchoring SDK." There is a **frozen cryptographic kernel** — canonicalize, hash, sign, verify, Merkle — that every producer and verifier reuses, plus a **conformance corpus** that keeps each language's kernel honest. Everything else (what you watch, what you emit, how you fund the upload, how you run) is per-product and per-language by design. The result: the crypto surface scales with the number of **languages** (≈3, stable), never with the number of **agents or connectors** (unbounded, cheap to add).

## 1. The factoring principle

Slice the system by **rate of change × language-coupling**, not by feature. Three layers fall out with sharply different sharing economics:

| Layer | What's in it | Changes | Language-coupled | Sharing rule |
|---|---|---|---|---|
| **Kernel** | JCS canonicalization, SHA-256, Ed25519 sign/verify, RFC-9162 Merkle, accepted-version registry | ~never | No (pure math) | **Single-sourced per language; frozen; corpus-gated.** Drift here is a security incident. |
| **Producer** | Profiles (event types/payloads), connectors, scheduler, state, lifecycle | constantly | Yes (native to each product) | **Not shared as code — shared as spec.** Sharing here builds a straitjacket. |
| **Transport** | ANS-104 data item, chain signer (Solana/Arweave), Turbo client | rarely | Yes (language crypto libs) | **Shared as spec + conformance.** Per-language impl at the edge; no FFI. |

"Anchor + verify in one SDK" conflates the kernel (verify) with the transport (anchor). They look adjacent but live in different layers with opposite economics. Keep them apart.

**Scope: this is the evidence plane only.** The control plane (`ar-io-api-guard` — auth, quotas, billing, fleet roster) is orthogonal to this factoring and **never sits in the trust path** ([`../envelope-spec.md` §1](envelope-spec.md)). Nothing below depends on it; a producer with no api-guard key still produces fully verifiable envelopes.

## 2. The scaling property

The thing that would explode an ecosystem — re-implementing crypto for every product — **does not happen** under this factoring, because:

- A **new connector** (GCS, Azure, HTTP, an MLflow-source, a DB-WAL watcher…) is a layer-2 plugin behind a stable interface (§6). It never touches the kernel. Add fifty; the kernel does not move.
- A **new agent/producer** is an *assembly*: `kernel + profile + connectors + runtime`. In an existing language it imports the existing kernel — zero new crypto.
- A **new language** is the only thing that adds a kernel. The stack ships in ~3 (Go, Python, browser JS/TS) and that set grows slowly, if ever.

> **Invariant.** Crypto implementations scale with *languages*, not with agents or connectors. Any design that violates this — e.g. a connector that reaches into signing, or a per-agent copy of the canonicalizer — is wrong by construction.

**"≈3" is a budgeted risk, not a law.** Each language kernel is ~weeks of work *plus* a permanent CI/drift liability, and the JCS-edge-case drift risk (§9) grows with the number of kernel pairs. The count is low today (Go, Python, JS/TS) but not self-limiting — notably, envelope-spec §8's strategy of sitting under .NET-centric governance platforms would add a 4th (C#). Treat a new language as a real cost with a budget; the model stays sound up to a handful of kernels and degrades beyond that. Two consequences worth pre-empting: (1) if the .NET play lands, plan kernel #4 explicitly; (2) **a non-language verifier** (hardware/HSM, a ZK circuit, a smart contract) can't necessarily re-run JCS, yet K3 defines conformance as "reproduces the corpus byte-for-byte." For those, the kernel's verify contract should be expressible as *"verify Ed25519 over a supplied canonical-bytes digest"* — so a fixed-function verifier consumes the already-canonicalized digest without implementing JCS — otherwise "verify everywhere" (§8) silently excludes the highest-assurance verifiers.

## 3. The kernel (normative)

The kernel is defined **by enumeration** — a closed set, deliberately tiny:

1. **Canonicalization** — RFC 8785 (JCS).
2. **Hashing** — SHA-256, lowercase hex.
3. **Signing / verifying** — Ed25519 over `JCS(envelope − signature)`; `payload_hash = SHA-256(JCS(payload))`; `public_key` embedded and in-scope.
4. **Merkle** — RFC 9162 binary tree (leaf `SHA-256(0x00‖b)`, node `SHA-256(0x01‖L‖R)`, pinned empty-tree root), inclusion-proof build + verify.
5. **Accepted-version registry** — the single fail-closed list of supported `spec_version` majors.

The reference Go surface already exists (**moved to public `ar-io-agent/pkg/{proof,merkle}` on 2026-06-10** — §11 move 1 done): `proof.CanonicalJSON`, `proof.SHA256Hex`, `proof.SignEnvelope`, `proof.VerifyEnvelope`, `proof.SupportedSpecMajor`; `merkle.{LeafHash,NodeHash,MTH,AuditPath,VerifyInclusion}`. That is the whole kernel — a few hundred lines of load-bearing code.

**Sign/verify operation, not key management.** The kernel performs Ed25519 signing and verifying given a key passed in; it does **not** load, persist, rotate, or choose keys, and it holds no key material. Key lifecycle (the signing key on disk, the funding wallet, rotation) is producer-runtime (§5) — so a small frozen kernel stays pure even though "signing" lives in it.

A tiny, frozen, enumerated kernel is also the stack's **audited surface**: reviewers (and customers' security teams) audit those few hundred lines *once*, not re-audit equivalent crypto per product. Minimal surface is a security property, not just a tidiness one.

**The kernel rules (the standard — these five are the architecture):**

- **K1.** The kernel is *exactly* the five primitives above. Nothing that does I/O, networking, state, chain signing, transport, or profile-specific payload logic may live in it.
- **K2.** The kernel MUST be a **published, importable package** per language — never `internal/` / private. (Privacy here forces copy-paste, which forces drift.)
- **K3.** Every language kernel MUST pass the **one** conformance corpus in its own CI. A kernel is "conformant" iff it reproduces the corpus byte-for-byte — no other definition counts.
- **K4.** The kernel is **frozen by default.** A change to it is a change to the envelope family contract ([`../envelope-spec.md`](envelope-spec.md)), reviewed at the spec layer with vector regeneration — not a casual refactor in one repo.
- **K5.** Adding a producer or a connector MUST NOT require a kernel *logic* change. The one exception is **data, not logic**: the accepted-`spec_version` set (primitive 5) is kernel-resident, so admitting a new profile adds one entry to that set — an additive, corpus-gated *data* change, never a verifier rewrite. (Better still, a kernel SHOULD let the accept-set be injected as config so even that entry lives in the producer; until then, treat the accept-set bump as the sole sanctioned kernel diff for onboarding a profile.) If anything *else* in the kernel appears to need changing for a new producer, the need is really a *spec* change (minor = additive, major = breaking), decided at the spec layer and landed in every kernel together.

## 4. Conformance corpus = the governance

A multi-producer ecosystem with N language kernels needs exactly one thing to stay coherent: **a single owned corpus, gated everywhere.**

- One source of truth: `test-vectors/` (envelope + Merkle vectors), today regenerated by `tools/gen-vectors/` and diff-checked in CI; the cross-product test runs Go envelopes through ar-io-mlflow's production verifier (and the reverse).
- **CORP1.** Vectors are **generated from a reference implementation**, never hand-edited — so two kernels cannot silently agree on a wrong answer.
- **CORP2.** The corpus has **one owner** and one home. Every kernel repo consumes it as a CI gate; none forks it.
- **CORP3.** A new profile (a new producer's event types) adds vectors; it does not get to weaken the accepted-version discipline (one registry entry, fail-closed on unknown majors).

The corpus, not a shared codebase, is what lets you add producers **without a central code bottleneck.** This is the quietly powerful part of the design and it already mostly exists — it needs ownership and ratification, not invention.

## 5. Producers (the assembly pattern)

A producer = **kernel + profile + connectors + runtime**:

- **Profile** — its event types and payload schemas; a registered profile of the envelope family (e.g. `ario.agent/v1`, `ario.mlflow/v1`). Profiles add fields and event types additively; consumers ignore unknown optional fields.
- **Connectors** — what it watches (§6).
- **Runtime** — lifecycle + state: a long-running daemon (agent), an in-process plugin (mlflow), a one-shot CLI, a serverless function. This is the most product-specific, fastest-moving layer and is **never shared as code.**

`ar-io-agent` is the reference **Go** producer-runtime; `ar-io-mlflow` is the reference **Python** one. Do **not** extract a generic "producer framework" until a *second* product in the same language needs ≥80% of an existing runtime — until then the reference producer *is* the framework, and premature extraction optimizes for a product that does not exist.

## 6. Connectors (horizontal scaling)

A connector is a layer-2 plugin **inside** a producer that turns "a thing worth watching" into hashes. The contract is three methods (already shipped for filesystem + S3):

- `Enumerate(group) -> []asset` — expand a glob/prefix into concrete assets.
- `Hash(asset) -> sha256 + metadata` — stream the bytes through SHA-256 (never a transport checksum like an S3 ETag — that's MD5-of-parts, not content).
- `Probe(asset) -> (exists, cheapDigest?)` — a stat-only shortcut; **tamper detection MUST NOT rely on Probe alone** — re-hashing is the truth.

**Connector rules:**

- **C1.** A connector MUST NOT touch the kernel, signing, or transport. It returns hashes and metadata; the producer runtime does everything else.
- **C2.** A connector is a **pull/watch** abstraction — `Enumerate` a corpus, `Hash` its bytes, `Probe` for cheap change-detection. The portable part is the **semantics** (content-hash-not-transport-checksum; re-hash-is-truth; the `scheme://…?version=…` URI shape; `required|preferred|ignore` versioning), *not* the Go signature — the interface itself leaks agent-specific types (`policy.AssetGroup`, `ConcreteAsset`) that are the agent's policy model, not a producer-neutral contract. So "portable" means "the watch-semantics translate," among **watch/poll producers only**.
- **C2a.** **Push-source producers are NOT connectors.** A producer that *emits* on an external event (the mlflow plugin on a training run; a CloudEvents governance sink ingesting pushed events) has nothing to `Enumerate` and nothing to `Probe` — `Probe` is meaningless for a one-shot `training_complete`. Those are a different ingestion shape (a one-method `Ingest`/`Emit` source), not the three-method pull connector. The north-star's "mlflow-source" and envelope-spec §8's "governance-event-sink" are *sources*, not connectors; don't conflate the two I/O directions under one word.
- **C3.** Credentials/SDKs for a connector load only when a policy actually references it (e.g. AWS config only when an `s3://` asset exists). New backends are added without expanding any other producer's dependency surface.

This is the axis you grow along most — for **pull/watch** backends: GCS, Azure Blob, generic HTTP, object-lock buckets, DB change-streams — each a self-contained plugin behind the same three methods. Push *sources* (mlflow, a CloudEvents sink) grow along a separate `Ingest` shape (C2a), not this one.

## 7. Transport (anchor stays at the edge)

Anchoring = ANS-104 data-item construction + a chain signer + a bundler (Turbo) client. It is language-coupled and changes rarely. It is **not** part of the kernel and **not** part of the auditor's trust path (auditors verify the Ed25519 *envelope* signature, never the data-item signature).

- **T1.** Transport is implemented per-language and bound by the **wire spec + a conformance check** (the ANS-104 data-item format in [`../artifact.md` §11](https://github.com/ar-io/ar-io-agent/blob/main/docs/artifact.md#11-arweave-tagging); the ANS-104 cross-product validates both Arweave sigType 1 and Solana sigType 2). Do **not** unify it across languages via FFI/WASM — a spec plus a per-language implementation plus the cross-product test is cheaper and clearer.
- **T2.** The funding chain is a transport detail (Solana default, Arweave supported, auto-detected from the wallet shape). It is invisible above this layer and never affects whether an envelope verifies.

## 8. Verify is the universal primitive

Every actor needs verify; almost none need anchor. Distribute the verify kernel **everywhere** from one source per language:

- **CLI** for humans/auditors (`ariod verify <file|tx_id>` today).
- **WASM** for the browser (the proof-checker; a Go kernel compiled to WASM gives "verify the verifier" — the tool is as tamper-evident as what it checks).
- **Library import** for producers and the evidence/reporting layer (`ario.evidence/v1`).

Anchor lives at one edge; verify lives at every edge. That asymmetry is why the kernel is scoped to verify-grade primitives and transport is not.

**Precisely what "verify" means here — and what is NOT in the kernel.** The kernel verifies exactly two things: a **single envelope** (signature + `payload_hash` binding) and a **single Merkle inclusion proof**. Everything an auditor loosely calls "verify" beyond that — walking a `previous_hash` chain, reconciling a checkpoint stream, running an anchor-enumeration completeness check — is **producer/runtime logic that *composes* kernel primitives**, not the kernel itself. This is true in both disclosure modes (the kernel treats the payload as an opaque blob and never reads `event_type`/`subject`/`previous_hash` — confirming K1), and it is why a WASM build of the kernel gives single-envelope verify in the browser but a *chain/timeline* view still needs the composed producer logic shipped alongside it. So the slogan is exact only as: **single-envelope verify is the universal kernel primitive; higher-order verify is composed above it.**

**A read-side gateway concern exists and is producer-runtime, not a new core layer.** Anchor-enumeration completeness (envelope-spec §5.1) needs a GraphQL *read* client against an untrusted gateway — distinct from §7 transport, which is the *write/anchor* path. It is not kernel (does I/O), not a connector (connectors enumerate local watched assets, not the chain), and not transport (that's write-side). It lives in **producer runtime** as an untrusted-gateway reader whose every result is re-verified by the kernel. Completeness is therefore **inherently cross-layer** (kernel primitives + producer orchestration + an untrusted gateway read), not a kernel property — the four-layer split organizes the *reusable* pieces, and completeness composition sits in the producer that owns it.

## 9. Anti-patterns (refuse these)

- **Kernel in `internal/`.** The most reusable, most stable code being unimportable forces copy-paste and guarantees eventual drift. (Resolved 2026-06-10: the Go kernel moved to `pkg/{proof,merkle}` — §11 move 1 done.)
- **Kernel fork.** Two language kernels silently disagreeing on a canonicalization edge case is the worst outcome in the system. Mitigated *only* by CORP1–CORP3.
- **Premature producer framework.** Extracting a generic agent runtime before a second same-language producer exists. YAGNI; the reference producer is the framework.
- **Over-shared transport.** FFI/WASM-ing the ANS-104 + chain signer across languages to "DRY it up." Wrong layer; spec + conformance is the right tool.
- **Connector reaching down.** A connector that signs, anchors, or canonicalizes. Connectors return hashes; nothing else.
- **Spec lagging code.** The family contract drifting behind the implementation turns the corpus into "a test suite without a law." The spec MUST be ratified and cited from each profile.

## 10. North star

```
        ┌───────────────────────────────────────────────┐
        │  envelope-spec (RATIFIED) + conformance corpus  │  law + enforcement
        │  one owner · generated vectors · CI-gated        │
        └───────────────────────────────────────────────┘
             ▲                ▲                 ▲
      ┌──────┴─────┐   ┌──────┴─────┐   ┌───────┴──────┐
      │ kernel-go  │   │ kernel-py  │   │ kernel-ts/   │   ≈3 forever
      │ verify +   │   │            │   │ wasm         │   scales with LANGUAGES,
      │ envelope + │   │            │   │ (browser)    │   not agents/connectors
      │ merkle     │   │            │   │              │
      └────┬───────┘   └─────┬──────┘   └──────┬───────┘
           │                 │                 │
  ┌────────┴─────┐   ┌───────┴──────┐    proof-checker · auditor CLI ·
  │ agent (Go)   │   │ mlflow (Py)  │    evidence renderer (ario.evidence/v1)
  │ profile      │   │ profile      │
  │ + connectors │   │ + connectors │
  │ + runtime    │   │              │
  └──────┬───────┘   └──────────────┘
         │
  ┌──────┴───────────────────────────────┐
  │ connectors (pull/watch): fs · s3 · gcs │  horizontal · layer-2 ·
  │ · azure · http · db-stream · …          │  never touch the kernel
  └────────────────────────────────────────┘
  (push sources — mlflow, CloudEvents sink — are a separate Ingest shape, §6 C2a)

  transport (ANS-104 + chain signer + Turbo): per-language, at the edge,
  spec-bound, OUT of the auditor trust path.
```

## 11. Rollout — cheap, ordered, high-leverage

1. **Extract the kernel.** ✅ Done for Go (2026-06-10, v1.2 Lane G): `pkg/{proof,merkle}` in `ar-io-agent`; Python = `ar-io-proof` (Lane C). Lift `internal/proof` + `internal/merkle` into a published package (a `pkg/` in a dedicated `ar-io-envelope` repo, or a public module); the agent imports it instead of `internal/`. Low risk — the code is stable and already corpus-tested. *This is the real "core SDK," scoped correctly to the kernel (K1–K2).*
2. **Make the corpus first-class.** One owner, one home, generated-not-edited, CI-gated in every kernel repo (CORP1–CORP3). Mostly exists as `test-vectors/` + cross-product — formalize ownership.
3. **Ratify `envelope-spec.md`** (its Phase 0) so the spec is the law, not a draft the code outruns. Each profile (`artifact.md`, mlflow) cites up to it.
4. **Ship the JS/TS (WASM) verifier** (envelope-spec Phase 3) — the third kernel; unblocks the browser proof-checker and a zero-install auditor path.
5. **Write the connector contract as a spec** (C2) so new connectors and new producers stay consistent without shared code.

Moves 1–3 are entirely in ar.io-owned code and gate nothing external. They are the foundation; do them first.

## 12. Open decisions

1. **Kernel home + name.** ~~A dedicated `ar-io-envelope` repo (kernel + spec + corpus together) vs a `pkg/` promoted inside `ar-io-agent`. Leaning toward a dedicated repo so no producer "owns" the shared core. Naming: `ario-envelope-{go,py,ts}`.~~ **Resolved at v1.2 coordination (D3 + Names, [`v1.2-coordination/README.md`](https://github.com/ar-io/ar-io-api-guard/blob/main/docs/stack/v1.2-coordination/README.md)):** Python = dedicated **`ar-io-proof`** repo (PyPI `ar-io-proof`, import `ario_proof`; Wave 1 Lane C); TS = **`@ar-io/proof`** (Wave 2 Lane H); Go = **`pkg/proof`** promoted inside `ar-io-agent` (Wave 2 Lane G), satisfying K2 via the public module path — full *outside-the-org* importability lands with Lane G's BSL + per-directory MIT carve-out flip; in the interim K2's anti-drift intent is met by the single in-repo import path. The existing `ar-io-sdk` is orthogonal and unchanged.
2. **Corpus owner.** ~~Which repo/team owns the generated corpus and the reference generator. (Today the generator lives in `ar-io-agent/tools/gen-vectors/`.)~~ **Resolved by [`governance.md`](governance.md) §4 (as amended v1.1, 2026-06-11):** the corpus and generator are homed in **`ar-io-proof`** (this repo) alongside the family specs — originally `ar-io-agent`, re-homed so the contract is public next to the reference verifier; the BDFL owns changes; downstreams pin `test-vectors-v1.x` tags; producers may keep vendored byte-identical copies for their CI gates.
3. **Kernel API stability policy.** SemVer on the published kernel package, and how a spec major maps to a kernel major.
4. **How far the kernel goes.** Strictly verify-grade primitives (recommended), or also the inclusion-proof *bundle* builder? Leaning: bundle build/verify is kernel-adjacent and shareable; the checkpoint *accumulation* (state) is producer runtime, not kernel.
5. **Transport thin-lib.** Whether a per-language anchor helper is worth publishing, or whether each producer keeps its own (status quo). Default: status quo until a second same-language producer needs it.
