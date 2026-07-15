# Evidence bundle — unified report/audit schema (`ario.evidence/v1`)

> **Status: ratified v1.0 (2026-06-10); revised v1.1 (2026-06-29, additive — `spec_version` unchanged at `ario.evidence/v1`).** The `ario.anchor.trace/v1` body verifier shipped 2026-06-22 ([`@ar.io/proof`](https://www.npmjs.com/package/@ar.io/proof) 0.2.1+, `npx @ar.io/proof verify`); v1.1 adds opt-in raw-log content disclosure (§5.1 `events[].content` + the verifier's `--logs` side input). A cross-tool wrapper that pulls every *report/audit bundle* in the ar.io verification stack into one signed, self-verifying, renderable family — so a single renderer (and the future [proof checker](https://github.com/ar-io/ar-io-agent/blob/main/docs/proof-checker.md)) can open an agent audit export, an mlflow lineage audit, an ar-io-verify run bundle, or an inclusion-proof bundle and show a consistent verdict. Cross-refs: [`docs/artifact.md`](https://github.com/ar-io/ar-io-agent/blob/main/docs/artifact.md) (the envelope spec this inherits from), [`docs/reporting-parity.md`](https://github.com/ar-io/ar-io-agent/blob/main/docs/reporting-parity.md) (the gap analysis that motivated this), [`docs/auditor-recipe.md`](https://github.com/ar-io/ar-io-agent/blob/main/docs/auditor-recipe.md), [`docs/proof-checker.md`](https://github.com/ar-io/ar-io-agent/blob/main/docs/proof-checker.md).
>
> **Ratification record.** Ratified by the BDFL per [`stack/governance.md`](governance.md) §1–§2 (v1.2 coordination decision D2); the §7 decisions are settled with their recommended defaults. Implementation has begun — Phase 1 (the `ario.anchor.trace/v1` emit + verify path) shipped 2026-06-22, extended with opt-in raw-log content disclosure in this v1.1 revision; Phases 2–5 (§8) remain roadmap work. **Once fully adopted, this folds into `artifact.md` as a new §17** (the inverse of how §4.6/§4.7 graduated from "outstanding question" to spec); it lives here until that graduation, and changes from here are additive = minor, breaking = major + 30-day RFC per governance.md.

## 0. The one-paragraph pitch

We already share a spec at the **envelope layer**: `artifact.md` says every byte the agent signs is accepted by `ar-io-mlflow`'s production `verify_record`, and the agent reused mlflow's primitives unchanged (JCS, SHA-256, Ed25519, `GENESIS`, key format, float rule). That discipline stops at the single signed event. The **report/bundle layer above it** — `ario.agent.audit-export/v1`, `ario.mlflow.audit/v1`, ar-io-verify's `VerificationBundleV1` — grew with no shared discipline at all: different case conventions, different version-field types, only one of the three is signed, only one has a rollup verdict, the agent's has no verdict. `ario.evidence/v1` extends the *existing* shared-envelope conventions up one level. It is **not a new convention** — it is the envelope's signing/canonicalization discipline applied to the bundle that summarizes envelopes.

## 1. Design principles (and what they rule out)

1. **Inherit, don't invent.** Same `spec_version` string form (`<namespace>/v<major>`), same `snake_case`, same JCS (RFC 8785) canonicalization, same "strip `signature`, JCS, verify" flow as the [`envelope-spec.md`](envelope-spec.md) §2 shared invariants (of which `artifact.md` §5–§6 is the agent profile), same embedded-`public_key` self-containment, same `GENESIS` chain convention. A verifier that already verifies a family envelope verifies an evidence bundle with the same primitives. (After ratification, `envelope-spec.md` is the authoritative shared-invariant source this layer points up to; `artifact.md` remains the byte-level agent detail.)
2. **Wrap, don't merge.** The three bundle *bodies* describe genuinely different things (a batch run vs. an agent's full register vs. an ML lineage). We unify the **outer envelope + the verdict vocabulary**, and leave each `body` intact. This is the single most important boundary — merging bodies would be parity-for-its-own-sake and would break each tool's existing consumers.
3. **Recompute, never trust the verdict.** `verdict.status` / `verdict.summary` are a *rendering convenience*. A conforming renderer MUST recompute the verdict from `body` (and re-verify the signature) before displaying it — exactly as the proof checker re-checks `payload.hash` rather than trusting the `Asset-Hash` tag (`artifact.md` §11), and as `artifact.md` §6 makes the signature load-bearing, not the gateway.
4. **No ar.io service in the trust path.** The bundle is self-verifying offline against the embedded `public_key`. `gateway` is named as the delivery surface, never trusted. Identity-binding of the key is out-of-band (api-guard roster / out-of-band attestation), same as `artifact.md` §6 step 5.
5. **Provenance ≠ endorsement.** The shared verdict vocabulary deliberately has **no "safe" / "approved" / "trusted" status.** It describes verification state only. (proof-checker.md §8 trust line, made structural.)
6. **Room for growth, paid for once.** Three explicit growth hooks (§4): `body_type` self-identifies the body so new producers need no schema change; `signature_alg` lets non-Ed25519 producers (ar-io-verify's RSA operator key) join without minting new keys; `body_ref` lets a large body live out-of-line behind a hash so the same wrapper works for a 4 KB proof and a 400 MB export.

> **This is the home for "export a portable evidence dossier."** Any producer's "package my proofs into one offline-verifiable, framework-mapped deliverable" feature (e.g. ar-io-mlflow's proposed `audit --export bundle.zip`) is an `ario.evidence/v1` producer — a new `body_type`, not a fourth bundle shape. Two inputs ride here rather than being reinvented: (a) the **completeness ticket** `{owner, app, date_start, date_end}` ([`envelope-spec.md` §5.1](envelope-spec.md)) and its `verified / unnotarized / missing` reconcile result travel as body fields, so a bundle can assert "we hid nothing in this window"; (b) **regulatory framework mapping** (EU AI Act Art. 12 / SR 11-7 / ISO 42001 → satisfying events) is a *renderer* concern over the verdict + body, never an envelope concern (`envelope-spec.md` §9) — the same recompute-don't-trust discipline (principle 3) applies. Meta-anchoring a dossier is just anchoring the wrapper (§4); chain-of-custody ("exported by X on Y") is `issuer` + `generated_at` + optional `previous_hash` over successive exports.

## 2. The wrapper

```json
{
  "spec_version": "ario.evidence/v1",
  "body_type": "ario.agent.audit-export/v1",
  "issuer": {
    "kind": "agent",
    "tenant_id": "acme-corp",
    "agent_id": "prod-ml-host-01"
  },
  "generated_at": "2026-05-26T18:00:00.000Z",
  "gateway": "https://turbo-gateway.com",
  "verdict": {
    "status": "verified",
    "summary": "All 412 tracked assets verified; 0 tampers across 11 checkpoints (last 11 days).",
    "counts": { "verified": 412, "tampered": 0, "unavailable": 0, "pending": 0 },
    "as_of": "2026-05-26T18:00:00.000Z"
  },
  "body": { /* the tool-specific bundle, unchanged — see §5 */ },
  "body_hash": "9a3b1c...e7f2",
  "previous_hash": "GENESIS",
  "signature_alg": "ed25519",
  "public_key": "8b1f...",
  "signature": "1234..."
}
```

| Field | Required | Type | Meaning |
|---|---|---|---|
| `spec_version` | Yes | string | Always `ario.evidence/v<major>`. Verifiers MUST reject unknown majors (same rule as `artifact.md` §13). |
| `body_type` | Yes | string | The producer's own bundle schema string — `ario.agent.audit-export/v1`, `ario.mlflow.audit/v1`, `verify.bundle.run/v1`, `ario.agent.proof/v1`, … Carries both namespace and major, so no separate `body_version`. This is the **growth hook**: a new producer adds a `body_type`, not a wrapper change. |
| `issuer` | Yes | object | Who produced the bundle. `kind` ∈ `agent` \| `operator` \| `mlflow-plugin` \| … `tenant_id` / `agent_id` optional, producer-dependent, same charset as `artifact.md` §3 `subject`. Carries identity *context*; the load-bearing key is the top-level `public_key`. |
| `generated_at` | Yes | RFC 3339 | When the bundle was produced. Advisory like `signed_at` (§6.1); witnessed time comes from Turbo/Arweave if the bundle is itself anchored. Unifies the divergent `exported_at` / `generatedAt` / `finishedAt`. |
| `gateway` | No | string \| null | The delivery surface the bundle was built against. **Named, not trusted.** Null when not applicable. |
| `verdict` | Yes | object | The shared rollup — see §3. `status` is the shared enum; `summary` is one plain-language sentence (the `PlainSummary` pattern, baked into data); `counts` optional for batch surfaces; `as_of` optional verdict-evaluation time. **Rendering convenience — recompute from `body` (principle 3).** |
| `body` | Cond. | object | The tool-specific bundle, structurally unchanged. Exactly one of `body` (inline) or `body_ref` MUST be present. |
| `body_ref` | Cond. | string (URI) | Out-of-line body location (`s3://…`, `https://…/raw/<tx>`, `local:/…`). Integrity is `body_hash`. Mirrors the leaf-manifest URI pattern (`artifact.md` §9). The growth hook for large bodies. |
| `body_hash` | Yes | sha256-hex | **Inline body:** `SHA-256(JCS(body))`. **Referenced body:** SHA-256 of the published bytes exactly as fetched from `body_ref` — **no re-canonicalization** (a referenced body need not be JSON). Commitment to the body, mirroring `payload_hash` (§5). Present in both cases — it's what makes `body_ref` safe. |
| `previous_hash` | No | sha256-hex \| `"GENESIS"` | Optional chain pointer over successive bundles from the same issuer (e.g. monthly audit exports), following the `artifact.md` §7 chain *convention* (`GENESIS` first-link) — but **here optional**, not the per-event required pointer §7 mandates: omit it (or set `GENESIS`) for one-off bundles. |
| `signature_alg` | Yes | enum | `ed25519` (conformance baseline, default) \| `rsa-pss-sha256`. The growth hook that lets ar-io-verify's RSA operator key sign a bundle without minting an Ed25519 key. Reference verifiers MUST implement `ed25519`; others are optional. **Note the cross-layer asymmetry:** this field is *active* at the bundle layer in v1 (verify's RSA key is a shipping use case), whereas the matching `signature_alg` in [`envelope-spec.md`](envelope-spec.md) §7 is *reserved, not active* — same field name and agility mechanism, different per-layer lifecycle. |
| `public_key` | Yes | hex | The issuer's verify key, encoding per `signature_alg`. Embedded for self-containment (§6). |
| `signature` | Yes | hex | Signature over `JCS(bundle_without_signature)` per `signature_alg`. Same strip-and-canonicalize flow as `artifact.md` §6. |

**Closes the agent's gap directly:** `ario.agent.audit-export/v1` is unsigned and verdict-less today (a compliance bundle weaker than the per-event envelopes it summarizes). Wrapping it makes it signed + self-verifying + summarizable *without touching the raw `assets`/`checkpoints`/`policy_history` body that compliance teams already pipe into their tools.*

## 3. Shared verdict vocabulary

One enum, six states, no "safe." Every bundle gets a `verdict.status`; a renderer maps it to a hero verdict + color once, for all producers.

| `status` | Meaning | Renders as |
|---|---|---|
| `verified` | Every in-scope item passed its full verification (signature + integrity). | green / "Verified" |
| `partial` | Integrity/commitment confirmed but full proof incomplete (e.g. hash matches, signature not checkable; anchored without attestation). | primary / "Partially verified" |
| `pending` | Found but not yet fully verifiable (indexing in progress; signed-locally, not anchored). | neutral / "Pending" |
| `failed` | A verification check failed — mismatch / bad signature / tamper. | red / "Failed" |
| `not_found` | The subject is absent on the queried surface(s). **Absence is not failure** — UI MUST NOT imply tamper (proof-checker.md §8). | grey / "Not found" |
| `mixed` | A batch/collection with more than one outcome (some verified, some failed/unavailable). Detail lives in `counts` + `body`. | per-`counts` |

Mapping from each existing surface (so adoption is mechanical, not a redesign):

| Shared `status` | ar-io-verify | ar-io-agent | ar-io-mlflow |
|---|---|---|---|
| `verified` | `level` 3 / `signature_verified` | all `ariod verify` rows pass | `Verified (Level ≥ threshold)` |
| `partial` | `level` 2 / `hash_verified` | record matches, signature pending | `Anchored` (no attestation) |
| `pending` | `level` 1 / existence-only | `?` row(s) | `Signed (local)` |
| `failed` | hash mismatch | any row fail / `tamper_detected` | `MISMATCH` |
| `not_found` | `existence.not_found` | gateway 404 across all | not anchored |
| `mixed` | batch with failures (`totals`) | export containing tampers | `overall_ok=false` across stages |

This also retires the "three strings for one concept" problem: `tampered` (verify `totals`), `tamper_detected` (agent event) and `MISMATCH` (mlflow) all surface as `failed` at the wrapper, while each body keeps its native term internally.

## 4. Canonicalization & signing

Identical to `artifact.md` §5–§6, applied to the wrapper:

**Producer:**
1. Build the wrapper with every field except `signature`. Set `body` (or `body_ref`).
2. `body_hash = sha256_hex(JCS(body))`. (If `body_ref`, hash the referenced bytes you're publishing.)
3. Compute `verdict` from `body` and set it.
4. `bundle_bytes = JCS(bundle_without_signature)`.
5. `signature = sign(bundle_bytes, private_key)` per `signature_alg`; hex-encode; set `signature`.
6. Serialize the **JCS-canonical bytes** of the complete bundle. (Same on-the-wire mandate as §6 — downstream re-hashers must not diverge.)

**Verifier / renderer:**
1. Parse. Reject unknown `spec_version` major.
2. If inline `body`: recompute `sha256_hex(JCS(body))`, reject on mismatch vs `body_hash`. If `body_ref`: fetch, hash, compare to `body_hash`.
3. Strip `signature`, `JCS`, verify against `public_key` per `signature_alg`. Reject on failure.
4. **Recompute the verdict from `body`**; if it disagrees with the asserted `verdict.status`, treat the bundle as failed/tampered (§6) — the displayed verdict is the recomputed one, never the asserted one.
5. (Optional) Bind `public_key` to a real identity out-of-band (§6 step 5).

A bundle MAY itself be anchored to Arweave (it's just signed JSON with tags), in which case Turbo/Arweave timestamps give it witnessed time per §6.1. Anchoring is optional — a bundle handed over as a file is fully verifiable offline.

## 5. Per-producer adoption (bodies unchanged)

| Producer | `body_type` | `body` is… | `signature_alg` | Net change |
|---|---|---|---|---|
| ar-io-agent `audit export` | `ario.agent.audit-export/v1` | existing `{assets,checkpoints,policy_history}` | `ed25519` | **+sign, +verdict, +issuer.** Body untouched. |
| ar-io-agent inclusion proof | `ario.agent.proof/v1` | existing §10 bundle | `ed25519` | Optional wrapper; §10 bundle already self-verifies. Lets it carry a verdict + render in the shared UI. |
| ar-io-mlflow `audit --format=json` | `ario.mlflow.audit/v1` | existing `{model,version,stages[],overall_ok,…}` | `ed25519` | **+sign, +issuer.** `overall_ok` → `verdict.status`. |
| ar-io-verify run bundle | `verify.bundle.run/v1` | existing `VerificationBundleV1` (renamed body, see note) | `rsa-pss-sha256` | Wrap its existing RSA-PSS-signed body; the wrapper signature can reuse the same operator key via `signature_alg`. `totals` → `verdict.counts`. |
| `@ar.io/anchor` SDK trace | `ario.anchor.trace/v1` | `{ checkpoints[], events[] }` (§5.1) | `ed25519` | A self-verifying serialization of `InclusionReceipt[]` — the SDK's per-event signed envelopes + their checkpoints + inclusion proofs in one portable, offline-verifiable file. New body, **not a new wrapper.** |
| ar-io-verify attested export | `ario.evidence.export/v1` | kernel verdict + **inline `ario.anchor.trace/v1`** source bundle (the only source shape in v1 scope) + embedded operator attestations | `ed25519` wrapper / embedded `rsa-pss-sha256` records | Issuer-composed, offline-verifiable **attested export**: a recomputable kernel verdict over a source anchor-trace bundle plus per-checkpoint RSA-PSS operator attestations, in one signed file. Other source `body_type`s and out-of-line `source_bundle_ref` are defined growth hooks, out of v1 scope. New body, **not a new wrapper.** Authoritative spec: [`evidence-export.md`](evidence-export.md) (source-body scope pinned in its §2.4). |

> Note on ar-io-verify: its body uses `camelCase` and an integer `version` internally. Those stay **inside the body** (no forced rewrite of a shipped product); the wrapper normalizes the *outer* contract. The body's internal RSA-PSS `signature` remains its own per-body attestation; the wrapper signature is the family-level one. This is the pragmatic "how far does verify bend" answer from `reporting-parity.md` §4.

### 5.1. `ario.anchor.trace/v1` — the anchor SDK trace body

`@ar.io/anchor` Merkle-batches high-frequency events into one Arweave write per window, handing each event back an `InclusionReceipt` (the event's signed `ario.events/v1` envelope + its committed record + its RFC 9162 inclusion proof + the checkpoint it lands in). A producer collects a set of these receipts and serializes them into a single, portable, self-verifying trace via `toEvidenceBundle(receipts)`. The result is an `ario.evidence/v1` wrapper (§2) whose `body_type` is `ario.anchor.trace/v1` and whose `body` is:

```json
{
  "checkpoints": [
    {
      "tx_id": "<arweave-txid>",
      "envelope": { /* the signed checkpoint ario.events/v1 envelope */ },
      "record_bytes": "<hex of JCS(checkpoint record)>",
      "merkle_root": "<hex>"
    }
  ],
  "events": [
    {
      "envelope": { /* the signed event ario.events/v1 envelope */ },
      "record_bytes": "<hex of JCS(event record)>",
      "inclusion": {
        "leaf_hash": "<hex>",
        "leaf_index": 0,
        "leaf_count": 3,
        "audit_path": ["<hex>", "…"],
        "checkpoint_tx_id": "<arweave-txid>"
      }
    }
  ]
}
```

| Field | Required | Type | Meaning |
|---|---|---|---|
| `checkpoints[]` | Yes | array | The window checkpoints the events land in. **De-duplicated:** events that share one anchored window reference one entry here, so the shared checkpoint envelope is carried once. |
| `checkpoints[].tx_id` | Yes | string | The Arweave TX the checkpoint envelope was anchored as. The on-chain re-fetch key. |
| `checkpoints[].envelope` | Yes | object | The signed checkpoint envelope (external commitment — its committed record is `record_bytes`). |
| `checkpoints[].record_bytes` | Yes | hex | Lowercase hex of `JCS(checkpoint record)`; binds to the checkpoint envelope's `payload_hash` and carries the committed `merkle_root` / `leaf_count`. |
| `checkpoints[].merkle_root` | Yes | hex | The Merkle root every event in this window proves inclusion against. A verifier **MUST** confirm it equals the `merkle_root` inside the committed `record_bytes` (recompute, don't trust). |
| `events[]` | Yes | array | The traced events. |
| `events[].envelope` | Yes | object | The event's signed envelope (external commitment — committed record is `record_bytes`). |
| `events[].record_bytes` | Yes | hex | Lowercase hex of `JCS(event record)`; binds to the event envelope's `payload_hash`. A withheld record (`record_bytes` omitted) leaves the binding **undetermined, not failed** (§3.1/§6.2). |
| `events[].content` | No | hex | Opt-in disclosed raw bytes whose SHA-256 MUST equal the committed `event.content_hash` inside `record_bytes`. Default-absent (minimal disclosure). Absent ⇒ **undetermined, not failed** (mirrors `record_bytes`). Requires `record_bytes` present to bind (the committed hash lives there). Lowercase hex, family convention. |
| `events[].inclusion` | Yes | object | The RFC 9162 inclusion proof binding this event's leaf to its checkpoint root. |
| `events[].inclusion.leaf_hash` | Yes | hex | `SHA-256(0x00 ‖ JCS(event envelope))` — the leaf is the event's signed envelope bytes (profile §6), not its record. |
| `events[].inclusion.leaf_index` / `leaf_count` | Yes | int | Position and tree size for the audit-path walk. |
| `events[].inclusion.audit_path[]` | Yes | hex[] | Bottom-up sibling hashes. |
| `events[].inclusion.checkpoint_tx_id` | Yes | string | Binds this event to exactly one entry in `checkpoints[]`. A verifier **MUST** resolve it to a present checkpoint and verify inclusion against *that* checkpoint's `merkle_root`. |

`Uint8Array` fields (`record_bytes`, every hash / audit-path entry) serialize as **lowercase hex**, the family convention. The wrapper is signed by the producer's Ed25519 key (the anchorer's signer); `body_hash = SHA-256(JCS(body))` commits to the whole trace. Verification (the inverse of `toEvidenceBundle`) re-checks each event's signature + payload binding + inclusion offline against the embedded `public_key`, with an optional on-chain re-fetch of each `checkpoint_tx_id`; the reference implementation is `verifyEvidenceBundle` in [`@ar.io/proof`](https://www.npmjs.com/package/@ar.io/proof) (`npx @ar.io/proof verify <bundle>`).

When raw bytes are disclosed, a verifier closes the final `rawLog → content_hash` link: it recomputes `SHA-256(disclosed bytes)` and confirms it equals the committed `event.content_hash` read out of `record_bytes` (for a promoted-disclosure envelope, a hash the envelope itself commits to — its inline `payload` — is used instead, since such an envelope has no record). Disclosed bytes resolve from the in-body `events[].content` **first**, then an out-of-band side input (`npx @ar.io/proof verify <bundle> --logs <file>`): in-body `content` rides **inside** the signed body (`body_hash` + the wrapper signature), so it is self-contained and tamper-evident; the out-of-band side input is authoritative only for events that disclose no in-body `content`, and an in-body-vs-side-input **disagreement is a verification failure**. Absent disclosure — or an absent committed `content_hash` (a withheld record, or a checkpoint/custom record with none) — is **undetermined, not failed**, exactly like a withheld `record_bytes`. A genuine mismatch fails the event (and the rollup).

## 6. Trust model (must hold for every consumer)

- **Self-verifying offline.** Embedded `public_key` + `signature`; no service call to verify. (`artifact.md` §6.)
- **Gateway untrusted.** `gateway` is delivery only; cross-check across gateways for anything load-bearing.
- **Verdict is recomputed, not trusted** (principle 3 / §4 step 4). A bundle whose asserted `verdict` disagrees with its recomputed verdict is treated as *failed/tampered*, not displayed at face value.
- **`body_ref` integrity is `body_hash`.** An out-of-line body is exactly as trustworthy as its hash commitment under the signature — a lying host is caught at §4 step 2.
- **Identity binding is out-of-band.** The signature proves "the holder of this key signed this bundle," never "this key is acme-corp's." Same bootstrapping as every other surface.
- **No status means "safe."** Renderers and marketing copy say *"has a verifiable history"* / *"verified against its anchored record,"* never *"safe / approved."* (proof-checker.md §8.)

## 7. Decisions (settled at the v1.0 ratification with the defaults below)

| # | Decision | Resolution (the former default recommendation, adopted as-is) |
|---|---|---|
| 1 | Wrapper namespace: `ario.evidence` vs `ario.report` vs `ario.bundle` | `ario.evidence` — it's evidence, and it's tool-neutral (not `ario.agent.*`). |
| 2 | One sig alg (mandate Ed25519, make verify mint a key) vs `signature_alg` discriminator | `signature_alg`, baseline Ed25519 — lower friction for verify, textbook growth hook. Revisit if a single-alg verifier is worth more than verify's convenience. |
| 3 | Is `verdict` required, or may a bundle be verdict-less (pure evidence)? | Required, but `mixed`/`pending` are always-valid escape hatches; a renderer must always have *something* to show. |
| 4 | Should the agent **anchor** its audit-export bundle on chain, or keep it a handed-over file? | File by default (cheap, offline-verifiable); anchoring optional for tamper-evident long-term retention. |
| 5 | Keep the body's own internal `schema`/`version` field, or drop it once wrapped? | Keep (harmless, backward-compatible); `body_type` is the wrapper's authoritative copy. |
| 6 | Does `previous_hash` chaining over successive exports earn its keep in v1? | Ship the field, leave it optional; agents that want a tamper-evident export history use it, others set `GENESIS`/omit. |
| 7 | Ratification owner per repo (who signs off the body→verdict mapping in mlflow & verify)? | **Resolved: BDFL** — Phil Mataras (@vilenarios) per [`stack/governance.md`](governance.md) §1; the per-repo body→verdict mapping sign-off is delegable at implementation time (governance.md §1). |

## 8. Phased rollout

| Phase | What ships | Repo | Effort |
|---|---|---|---|
| **0 — Ratify** | ✅ **Done (2026-06-10).** Reviewed; §7 decisions settled; ratified by the BDFL per [`stack/governance.md`](governance.md). Per-repo body→verdict mapping sign-off is delegated to each adoption phase below. | all | M (agreement, not code) |
| **1 — Spec graduates** | Fold ratified `ario.evidence/v1` into `artifact.md` §17 + add the wrapper to the test-vector corpus (a signed bundle vector per `body_type`). | ar-io-agent | S |
| **2 — Agent adoption** | Wrap `ariod audit export` (sign + verdict + issuer); add `verdict`/`summary` + signer-identity rows to `ariod verify`. | ar-io-agent | S–M |
| **3 — mlflow adoption** | Wrap `audit --format=json`; map `overall_ok` → verdict. | ar-io-mlflow | S |
| **4 — Shared renderer** | The proof checker (and a generic "drop any evidence bundle" viewer) renders `ario.evidence/v1` via ar-io-verify's card vocabulary. | ar-io-proof-checker / ar-io-verify | L |
| **5 — verify adoption** | Wrap `VerificationBundleV1` with `signature_alg: rsa-pss-sha256`. | ar-io-verify | M |

Phases 1–3 are cheap and land in ar.io-owned code. Phase 4 is the payoff (one renderer, every bundle) and is where the proof checker and ar-io-verify's components converge. Phase 5 is last because verify is a separate product and bending it is the highest-friction, lowest-marginal-value step.

---

*Ratified v1.0 (2026-06-10); §7 decisions settled, Phases 1–5 unblocked. Revisit when any producer's body schema changes (the wrapper should not need to), or per [`stack/governance.md`](governance.md) §2.*
