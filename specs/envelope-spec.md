# Verifiable Event Envelope — family specification

> **Status: ratified v1.0 (2026-06-10), amended to v1.1 (2026-06-11), v1.2 (2026-06-11 — `ario.events/v1` registered in §4 as *proposed*), v1.3 (2026-06-15 — `ario.events/v1` RATIFIED: admitted to the accept-set, all three kernels full-family), v1.4 (2026-07-15 — canonicalization depth bound, §2 invariant 7).** v1.1 is fully additive — every v1.0 envelope still validates, the `test-vectors-v1.0` corpus stays the conformance gate, downstream consumers do not need to re-pin a new corpus tag, and the wire format does not change. See **[Amendment log](#amendment-log-v10--v11-2026-06-11)** for the three changes. This is the producer-neutral *family contract* for the signed event envelope that the ar.io verification stack already shares in practice. It introduces **no new `spec_version` string and no breaking change** — every addition is relaxing or additive: a minimal-skeleton + per-profile **disclosure axis** (§2/§3.1, reclassifies three fields from required→conditional so privacy-focused profiles like `ario.mlflow/v2` conform), an optional `payload_ref` locator (§3), a RECOMMENDED payload-sectioning discipline (§3.2), a reserved `co_signatures` path (§7.1), an optional `environment` field for dev-vs-production marking inside the signed scope (§2), and a second completeness mechanism + portable ticket (§5.1). It names the common contract that [`artifact.md`](https://github.com/ar-io/ar-io-agent/blob/main/docs/artifact.md)'s `ario.agent/v1` and `ar-io-mlflow`'s `ario.mlflow/v1` are already conformant **profiles** of, so a third (and fourth) producer can join by writing a profile rather than reinventing the layer. Cross-refs: [`artifact.md`](https://github.com/ar-io/ar-io-agent/blob/main/docs/artifact.md) (the agent profile + the authoritative byte-level format); the **mlflow profile** lives in the sibling repo `ar-io-mlflow` (`ario_mlflow/proof.py` + `docs/verification.md`); [`evidence-bundle.md`](evidence-bundle.md) (`ario.evidence/v1`, the report layer that *wraps* envelopes); [`auditor-recipe.md`](https://github.com/ar-io/ar-io-agent/blob/main/docs/auditor-recipe.md); [`proof-checker.md`](https://github.com/ar-io/ar-io-agent/blob/main/docs/proof-checker.md).
>
> **The shared invariants here are now the normative reference that each profile doc points *up* to** (artifact.md keeps its byte-level agent detail; mlflow keeps its dialect detail; both cite this for the common contract — the Phase-1 "profiles cite up" edits are tracked in §11).
>
> **Conformance status.** Ratified at Phase 0 (§11) by the BDFL per [`stack/governance.md`](governance.md) §1–§2 (v1.2 coordination decision D2). The RFC 2119 keywords below are **binding**. Where the doc records a known implementation gap (e.g. the Go reference verifier is inline-only, §6.2), that is tracked work against a binding contract, not a soft spot in the contract. Changes from here: additive = minor, breaking = major + 30-day RFC per governance.md.

## Amendment log: v1.3 → v1.4 (2026-07-15)

Security-hardening amendment from the family adversarial pass: pins a cross-kernel canonicalization depth bound. Additive/minor (governance §2) — no new `spec_version` string, no wire change, existing corpus stays valid (every vector nests <15 levels); it only tightens verifier input-validation in a way no legitimate producer reaches.

| # | Where | Change | Rationale | Backward-compat |
|---|---|---|---|---|
| **A8** | §2 shared-invariant 7 (new) + §12 | **Bounded canonicalization nesting.** Canonicalization input MUST NOT nest JSON containers deeper than **128 levels**; a verifier MUST reject a deeper input as `malformed` *before* canonicalizing it. Pinned as a fixed constant, identically across kernels (TS `MAX_CANONICAL_DEPTH`, Python `MAX_CANONICAL_DEPTH`, and any Go kernel). | An unbounded recursive canonicalizer overflows at a runtime-specific depth (CPython's ~1000 stack frames vs V8's much larger stack), so the same deeply-nested bytes could verify on the TS kernel and `RecursionError`/crash on the Python kernel — a verdict that depends on which verifier you run, on a depth the byte-supplier fully controls. A shared fixed limit makes a too-deep input `malformed` everywhere. Discovered in the family adversarial pass alongside the RSA-exponent forgery (A-track). | No wire change · no new `spec_version` · every corpus vector nests <15 levels · only rejects pathological input no conformant producer emits |

## Amendment log: v1.2 → v1.3 (2026-06-15)

First profile to graduate from *proposed* to *ratified* through the §4 registry — the proof that "a third producer joins by writing a profile" (§0) holds end-to-end. Triggered by the kernel-ratification lane (full-family conformance + `ario.events/v1` ratify). Additive/minor (governance §2) — no new `spec_version` string, no wire change, existing corpus stays valid.

| # | Where | Change | Rationale | Backward-compat |
|---|---|---|---|---|
| **A5** | §4 registry + §5 accept-set | `ario.events/v1` *proposed → RATIFIED*: admitted to the baseline accept-set `{ ario.agent/v1, ario.mlflow/v1, ario.events/v1 }` in all three kernels (Python `ACCEPTED_SPEC_VERSIONS`, TS `ACCEPTED_SPEC_MAJORS`, Go `SupportedSpecMajor`). Its corpus vectors graduate from primitive-level gating to full-`verifyEnvelope` gating. | The profile's conformance vectors are in the corpus (`test-vectors-v1.1`), independently verified; the binding semantics are already-ratified family modes (§3 External Commitment + §3.1 Minimal), the same pairing `ario.mlflow/v1` uses — composition, not new design. | Additive accept-set entry · no skeleton/wire change · re-pinning the corpus tag is the downstream's explicit act |
| **A6** | §6.2 | The §6.2 "Go reference verifier is inline-only" / "Phase-2 full-family gap" is **CLOSED**: the TS and Go kernels now verify external-commitment envelopes (signature-only without the committed record → "signature-valid, semantics-undetermined" per §3.1/§6.2; full bind with it), matching the Python reference. A standing Python⇄TS⇄Go agreement gate over the corpus + adversarial cases pins it. | Kernel-ratification lane: the flagship write SDK's envelopes must verify through the flagship verifier. | No contract change — closes a tracked implementation gap against an unchanged contract |
| **A7** | §2 (clarification) | `payload_hash` absence is a hard reject in every mode in all three kernels (it was always §2-required; the Python reference's prior compare-only-if-present lenience is fixed). | §2 is binding; a verifier "cannot proceed without ... payload_hash and MUST reject their absence." | Clarification of existing §2 obligation; conformant producers always emit it |

## Amendment log: v1.1 → v1.2 (2026-06-11)

| # | Where | Change | Rationale | Backward-compat |
|---|---|---|---|---|
| **A4** | §4 registry | Add `ario.events/v1` *(proposed)* — the Anchoring SDK's profile (`@ar.io/anchor`, sibling repo `ar-io-anchor`): External commitment, **Minimal** disclosure, `environment` REQUIRED, open adapter-namespaced `event_type` vocabulary, `subject.type` `producer`. Registration only — accept-set admission stays gated on its corpus vectors (`test-vectors-v1.1`) + profile ratification, same discipline as `ario.mlflow/v2`. | [#11](https://github.com/ar-io/ar-io-agent/issues/11) Wave 3 T-SDK lane: the SDK is the third producer; the first new-profile exercise of the §4 registry mechanism, and the first registrant adopting the v1.1 A1/A2 amendments as written. | Pure registry add · no skeleton/wire change · no corpus re-tag · no accept-set change |

## Amendment log: v1.0 → v1.1 (2026-06-11)

First exercise of the async docs-PR amendment cadence ([`stack/governance.md`](governance.md) §2). Triggered by [issue #11](https://github.com/ar-io/ar-io-agent/issues/11) — competitive analysis vs AgentSystems Notary + SDK PRD review. Three changes, all additive:

| # | Where | Change | Rationale | Backward-compat |
|---|---|---|---|---|
| **A1** | §2 "Minimal signed skeleton" | New **optional** `environment` field in the signed scope, valid values `"dev" \| "production"` (absent ≡ unspecified). Profiles MAY require it; producers SHOULD set it on dev envelopes so a test proof can never be presented as production evidence. | Issue #11 PRD: structural dev/prod gate. Stamping `environment` inside the signed bytes makes "dev-only" cryptographically inseparable from the envelope it labels. | Optional → v1.0 envelopes parse unchanged. No corpus regen. |
| **A2** | §3.1 "Header disclosure modes" | New SHOULD: **new producer-side profiles default to Minimal disclosure** unless they have a specific need for Promoted (the agent does — chain recovery + discoverability for assets it owns; mlflow v1 does not, hence the proposed v2 Minimal profile). Existing Promoted profiles are unaffected. | Issue #11 PRD: SDK-anchored events are caller-owned; defaulting to Promoted leaks bucket/file names, event types, and identity by accident. Codifies the principle without forcing a profile-by-profile redesign. | No change to any current profile. |
| **A3** | §5.1 "Completeness ticket" + §10 row 10 | Drop the self-commitment to "shape stays aligned with the external `agentsystems-verify` ticket." The ticket shape (`scope_key` / `app` / `[from, to)`) remains exactly as specified; what's removed is our obligation to track their format. | Issue #11 PRD competitive analysis: AgentSystems Notary's architecture is materially weaker on every dimension we care about (no batching, no Merkle, hosted bundler in trust path, no formal family spec). Carrying an alignment commitment is debt we don't owe. | Removes our obligation only; no consumer relied on this alignment. No ticket-shape change. |

## 0. Why this exists

The agent and mlflow already share an envelope spec in practice — the cross-product tests prove each verifies the other's envelopes — but it is **only written down inside the agent's spec**, phrased as "always `ario.agent/v1`." No document says "here is the common Verifiable Event Envelope; these producers are profiles of it, and here is how a third conforms." This is that document — the envelope-layer companion to [`evidence-bundle.md`](evidence-bundle.md), which applies the same shared discipline one level up at the report/bundle layer.

## 1. Where this sits — and what it is not

The stack has four layers. This spec governs the second:

```
raw signed bytes on Arweave            ← what a gateway returns for /raw/<tx>
  └─ Verifiable Event Envelope         ← THIS SPEC: the atomic signed commitment
       └─ ario.evidence/v1 bundle      ← evidence-bundle.md: wraps envelopes + a verdict
            └─ renderer / proof-checker ← reporting-parity.md / proof-checker.md
```

**Control plane vs evidence plane.** The envelope is an *evidence-plane* artifact: it proves *what happened* — portably, permanently, and without trusting any ar.io service or the producer's own infrastructure. It is deliberately **not** a control-plane mechanism: it does not authorize, block, sandbox, or rate-limit anything. Governance platforms (e.g. Microsoft's Agent Governance Toolkit) occupy the control plane — they decide and enforce, then log. Those platforms' own audit logs are operator-hosted and self-attested (AGT's docs, for instance, note the audit store "can be modified by a compromised agent" and recommend an *external append-only sink for tamper-evidence*). A stream of ar.io envelopes provides such a sink: neutral, permanent, verifiable with no vendor in the trust path. Keeping the envelope strictly evidence-plane is what lets it sit beneath a governance platform rather than overlapping its control function (§8, §9).

## 2. The common envelope contract (normative)

The key words MUST, MUST NOT, SHOULD, and MAY are per RFC 2119.

Every conformant envelope, in every profile, MUST carry the **minimal signed skeleton** below. The three **disclosure fields** (`event_type`, `subject`, `previous_hash`) are *present per the profile's declared disclosure mode* (§3.1): a **Promoted** profile carries them in the envelope; a **Minimal** profile keeps them in the hash-committed payload only. **Whichever fields are present are inside the signed scope.** (A profile MAY add further fields; consumers MUST ignore unknown optional fields — additive changes are minor, never a major bump.)

**Cross-profile verification keys off the skeleton + `payload_hash` + `signature` only** — which is exactly why one verifier handles every profile and disclosure mode uniformly (§5).

**Minimal signed skeleton — REQUIRED in every profile, every mode:**

| Field | Type | Contract |
|---|---|---|
| `spec_version` | string | Grammar: `<namespace>/v<major>` optionally followed by `.<minor>`, where `<major>` and `<minor>` are `[0-9]+`. Identifies the profile (§4). The accept-check matches on the `v<major>` token boundary (so `ario.agent/v1` and `ario.agent/v1.3` are accepted by an `ario.agent/v1` verifier, `ario.agent/v10` is **not**); a non-numeric minor suffix is malformed. Verifiers MUST reject an unknown **major** (fail-closed). |
| `event_id` | UUID v4, lowercase | Globally unique per event. |
| `payload_hash` | sha256-hex | The commitment. Binds the envelope to its payload bytes (§3). Verifiers MUST recompute and reject on mismatch. |
| `signed_at` | RFC 3339 UTC, `Z` | **Advisory, not trusted.** Witnessed time comes from the Turbo receipt / Arweave block (§6.1 of artifact.md). |
| `environment` | string, **OPTIONAL** (v1.1+) | `"dev"` \| `"production"`. Absent ≡ unspecified (v1.0 envelopes parse unchanged). Inside the signed scope so it cannot be peeled off after the fact. Profiles MAY require it; producers SHOULD set it on dev envelopes so a test proof can never be presented as production evidence. A verifier MAY surface the value via `environment_marker` in its result; a profile MAY refuse to count dev-marked envelopes toward production evidence. |
| `public_key` | hex | The producer's verify key, embedded for self-containment. |
| `signature` | hex | Signature over `JCS(envelope_without_signature_and_without_co_signatures)`. The `co_signatures` carve-out matters only when that reserved field is present (§7.1); with the field absent it is exactly "all present fields except `signature`". |

> **"REQUIRED" is a producer-conformance obligation, distinct from what a verifier enforces.** A conformant *producer* MUST emit every skeleton field. A *verifier* cannot proceed without `spec_version` / `public_key` / `signature` / `payload_hash` and MUST reject their absence; for `event_id` / `signed_at` it SHOULD treat a missing field as **non-conformant** (flagged), not silently valid. (Today the Go `proof.VerifyEnvelope` enforces those four and does not assert `event_id`/`signed_at` presence — a lenience the conformance corpus should tighten, not a license for producers to omit them.)

**Disclosure fields — in the envelope iff the profile's disclosure mode is Promoted (§3.1); otherwise carried in the committed payload:**

| Field | Type | Contract |
|---|---|---|
| `event_type` | string (enum per profile) | Profile-defined. Adding a value is minor; renaming/removing is a major bump. |
| `subject` | object | Identifies the source. `type` is profile-defined; string fields ≤128 chars matching `^[A-Za-z0-9_.:-]+$`. Carries identity *context* only — the load-bearing key is `public_key`. |
| `previous_hash` | sha256-hex \| `"GENESIS"` | Per-chain pointer. `"GENESIS"` is the literal first-link sentinel. Chain semantics are profile-defined. In Minimal mode this pointer lives in the payload (§3.1). |

**Conditional / reserved fields:**

| Field | Type | Contract |
|---|---|---|
| `payload_ref` | string (URI), cond. | **External-commitment profiles only:** where the canonical payload bytes live, so the envelope self-describes (§3). Inline profiles omit it. Integrity is still `payload_hash` — a lying locator is caught by the hash, never trusted on its own. |
| `co_signatures` | array, reserved | **Reserved, default-absent** (§7.1): countersignatures over the same skeleton for multi-party / approver-co-signed events. Absence implies a single signer; a verifier MUST NOT treat absence as a failure. |

**Shared cryptographic invariants** (identical across all profiles; the cross-product guarantee depends on every one):

1. **Canonicalization** is RFC 8785 (JCS), UTF-8. Two distinct canonicalizations: the *envelope-for-signing* (**all present fields except `signature` and `co_signatures`** — absent fields are never injected; the `co_signatures` exclusion lets a countersignature be added without invalidating the primary, §7.1) and the *payload-for-hashing* (§3). Producers MUST upload the JCS-canonical bytes of the complete envelope; verifiers re-canonicalize defensively but MUST NOT rely on producers doing so.
2. **Hash** is SHA-256, lowercase hex, no `0x`.
3. **Signature** is Ed25519, lowercase hex, 32-byte key / 64-byte signature, in v1 (§7 on agility).
4. **Floats are not auto-normalized.** A profile field that could be a float MUST specify precision and the producer MUST round before serializing (JCS serializes floats per ECMA-262; unrounded floats diverge across machines). Inherited from `ario_mlflow.proof.normalize_floats`.
5. **Self-containment.** A verifier with the envelope bytes verifies the signature with no further lookup. Binding `public_key` to a real-world identity is out-of-band (an api-guard roster, an out-of-band attestation, a key-transparency proof) — never the envelope's job, never an ar.io service in the trust path.
6. **`GENESIS`** is the literal string used in place of a SHA-256 for the first link of any chain.
7. **Bounded nesting.** Canonicalization input MUST NOT nest JSON containers (objects/arrays) deeper than **128 levels**. A verifier MUST reject a deeper input as **malformed** *before* attempting to canonicalize it, and MUST NOT canonicalize it. The bound is a fixed constant (128), not implementation-defined: an unbounded input can exceed one kernel's native recursion limit (e.g. CPython's default ~1000 stack frames) while another canonicalizes it on a larger stack, splitting the verdict on a depth the *producer of the bytes* controls (a valid-envelope bytes-supplier, an untrusted gateway re-serving a checkpoint, or a `--logs` side input). Pinning the limit identically across kernels makes a too-deep input `malformed` everywhere. 128 sits far above any legitimate evidence structure (which nests <15 levels) and safely below the tightest kernel recursion limit.

## 3. Payload binding modes

The first of two profile axes (the second is header disclosure, §3.1) is *where the canonical payload bytes live*. Both modes bind identically through `payload_hash` + `signature`, which is precisely why a verifier that checks those two is profile-agnostic. A profile MUST declare which mode it uses.

| Mode | `payload` in envelope? | `payload_hash` commits to | Used by | Verifier obtains bytes from |
|---|---|---|---|---|
| **Inline** | Yes | `SHA-256(JCS(envelope.payload))` | `ario.agent/v1` | the envelope itself |
| **External commitment** | No | `SHA-256(canonical_bytes)` of an out-of-envelope artifact | `ario.mlflow/v1` | the `payload_ref` URI (§2); profile-named surface as fallback for envelopes that predate the field |

External-commitment mode is what keeps source data off-chain: the envelope on Arweave carries only the hash; the bytes stay in the producer's system of record. Inline mode is appropriate when the payload is itself small, non-sensitive provenance (an asset hash + URI). Both are first-class; neither is preferred.

> An external-commitment profile MUST make its canonical bytes locatable. The normative mechanism is the optional `payload_ref` field (§2) — adopting it makes the envelope self-describing rather than relying on profile prose + a known artifact path. The field is additive (a minor change), so existing profiles can adopt it without a major bump; `ario.mlflow/v1` SHOULD populate it going forward.

### 3.1 Header disclosure modes (normative)

Payload binding (§3) is one profile axis; **header disclosure is a second, orthogonal one.** It governs *how much semantic content the envelope reveals on-chain* — the privacy ↔ discoverability dial. A profile MUST declare its mode.

| Mode | Disclosure fields (`event_type`, `subject`, `previous_hash`) live… | On-chain observer learns | Used by |
|---|---|---|---|
| **Promoted** | in the envelope (and typically mirrored into queryable Arweave tags) | event type, subject identity, and the chain link | `ario.agent/v1` |
| **Minimal** | in the hash-committed payload only — **not** in the on-chain envelope | only "this key signed *some* bytes at this time" | `ario.mlflow/v2` *(proposed)* |

Both are first-class; the choice is a **per-profile** property of the producer's threat model. **New producer-side profiles SHOULD default to Minimal disclosure** (v1.1+) unless they have a specific need for Promoted — the agent does (chain recovery + discoverability for assets *it* owns), but the SDK-shaped profiles emerging on this contract (`ario.mlflow/v2` proposed, `ario.events/v1` proposed in [#11](https://github.com/ar-io/ar-io-agent/issues/11)) generally do not, because their events are caller-owned and Promoted leaks bucket/file names, event types, and identity into chain tags incidentally. The default is a SHOULD because the producer's threat model is the deciding voice; it is *not* a global default rewrite of existing profiles:

- **Promoted** is correct when on-chain discoverability is a feature, not a leak — e.g. the agent watches the customer's *own* assets, and needs to GraphQL-query "all tamper events for asset X" and rebuild state from chain (`ariod state recover`). It cannot strip identity without losing chain-recovery.
- **Minimal** is correct when the producer has its own system of record (e.g. MLflow holds the payload) and the on-chain bytes should reveal nothing about what was anchored. The chain pointer (`previous_hash`) moves into the payload, so chain-walking reads payloads (available via the bundle / `payload_ref`) rather than envelopes. A Minimal profile MAY carry one **opaque scope tag** — a hashed, rotation-capable namespace identifier — solely as a completeness-enumeration key (§5.1). It reveals no event semantics and no tenant identity, but it is by design a *linkability* handle (all anchors under one tag are correlatable to each other — that is what makes enumeration work), so it MUST be rotation-capable: if a tag is ever tied to a real tenant, rotating limits the linked set. It is the only on-chain value permitted to be producer-stable in Minimal mode.

**The skeleton (§2) is identical in both modes**, so *kernel-grade* verification (§5) and the conformance corpus (§6) are unaffected: it checks `spec_version` + `payload_hash` + `signature` and never assumes a disclosure field is present in the envelope. A verifier MUST NOT reject a Minimal-mode envelope for lacking `event_type` / `subject` / `previous_hash` at the envelope level.

**Mode is bound to the `spec_version` major, not asserted per-envelope.** Disclosure mode is an immutable property of a profile major, fixed in the registry (§4) and carried by the verifier's accept-set entry (§5). A verifier therefore learns the mode from the **signed** `spec_version` — never from an unsigned per-envelope flag or out-of-band prose — which closes mode-confusion/downgrade: you cannot relabel a Promoted envelope as Minimal (or vice-versa) without changing `spec_version`, which is inside the signed scope and fail-closed on an unrecognized major.

**Disclosure-field validation is a profile-layer step, layered on the kernel — not part of the universal verifier (reconciles with [architecture.md](architecture.md) K1).** The split:

- **Kernel (every mode, every profile):** signature valid over the skeleton + `payload_hash` binds the committed payload. This is the "verify is universal" primitive.
- **Profile layer (mode-aware):** validate the disclosure fields. **Promoted** → read them from the envelope; queryable Arweave tags that mirror them are *search hints outside the signed scope*, so any consumer (including chain-state recovery) MUST re-verify the envelope and treat a tag value as untrusted until the matching signed field confirms it. **Minimal** → the fields live in the committed payload's top-level core section (§3.2); a verifier obtains the payload bytes (inline, or via `payload_ref`/the bundle for external-commitment), confirms `payload_hash`, then reads them there. If the committed payload is unavailable, the result is **signature-valid, semantics-undetermined** — never "a valid event of unknown type."

This keeps §2.5 self-containment exact: the *signature* is always self-verifying from the envelope alone; *semantic and chain* validation may require the committed payload, which for external-commitment profiles is an explicit fetch.

> Reclassifying these three from *unconditionally required* to *disclosure-mode-dependent* is a **relaxing, backward-compatible** change: every existing (Promoted) envelope that carries them stays valid, and no byte the agent or mlflow-v1 emits changes.

### 3.2 Payload sectioning (recommended discipline)

§2 states the *rule* — additive changes are minor, consumers ignore unknown fields. This is the *structural discipline* that makes that rule safe to lean on forever. A profile SHOULD structure its canonical payload into owner-scoped sections so new fields can be added indefinitely without ever breaking verification of older proofs:

| Section | Owner | Rule |
|---|---|---|
| top-level core (`payload_version`, `spec_version`, the disclosure fields when Minimal-mode) | Plugin/profile | Never change, rename, or remove. |
| `event` | Profile, per `event_type` | Additive-only. New fields OK; never remove/rename. |
| `context` | Profile, cross-cutting | Additive-only; all optional. |
| `metadata` | **Caller** | Free-form. The profile MUST NOT read it for verification. |
| `extras` | Profile | Reserved namespace for future cross-cutting fields. |

The key property is **namespace isolation**: a caller writing `metadata: {"approver": "alice"}` today can never collide with a future profile-managed `event.approver` or `extras.approver_chain`, because the namespaces are distinct and the profile never reads caller `metadata` during verification. This is what lets a profile add structural fields (e.g. an approver record, extra artifact hashes) as *minor* changes — and it is the precondition for the co-signing reservation (§7.1). RECOMMENDED for all profiles; `ario.mlflow/v2` (proposed) adopts it, and `ario.agent/v1`'s per-event payloads are compatible with it.

## 4. Profile registry

A profile is a concrete `spec_version` namespace that fills in the contract: its payload mode, its `event_type` enum, its `subject.type`, its chain semantics, and its byte-level payload schemas. The family contract is stable; profiles evolve independently.

| Profile (`spec_version`) | Producer | Payload mode | Disclosure (§3.1) | `event_type`s | `subject.type` | Authoritative spec |
|---|---|---|---|---|---|---|
| `ario.agent/v1` | ar-io-agent (`ariod`) | Inline | Promoted | `asset_registered`, `tamper_detected`, `policy_changed`, `verification_checkpoint`, `asset_missing`, `key_retired` | `agent` | [`artifact.md`](https://github.com/ar-io/ar-io-agent/blob/main/docs/artifact.md) §3–§4 |
| `ario.mlflow/v1` | ar-io-mlflow plugin | External commitment | Promoted | `training_complete`, `model_registered`, `prediction` | `mlflow_run`, `mlflow_model_version`, `mlflow_prediction` | sibling repo `ar-io-mlflow`: `ario_mlflow/proof.py` + `docs/verification.md` |
| `ario.mlflow/v2` *(proposed — sibling repo)* | ar-io-mlflow plugin | External commitment | **Minimal** | `training_complete`, `model_registered`, `stage_transition`, `prediction`, `dataset` | `mlflow_run`, `mlflow_model_version`, `mlflow_prediction`, `mlflow_dataset` | sibling repo `ar-io-mlflow`: `docs/.../envelope-v2-identity-stripping-design.md` |
| `ario.events/v1` | `@ar.io/anchor` SDK (`ar-io-anchor`) | External commitment | **Minimal** | open, adapter-namespaced, grammar-constrained; profile-reserved: `event`, `checkpoint` | `producer` | sibling repo `ar-io-anchor`: `docs/profile-ario.events-v1.md` (ratified) |
| `ario.governance/v1` *(reserved, proposed)* | governance-event sink (§8) | External commitment | Minimal | mapped from CloudEvents `type` (Phase 4) | mapped from CloudEvents `source` (Phase 4) | this doc §8 — to be specified in Phase 4 (§11) |

> **`ario.mlflow/v2` reconciliation.** mlflow's in-flight "identity-stripping" v2 redesign (sibling repo) is the first **Minimal**-disclosure profile and the reason §3.1 exists: it moves `event_type` / `subject` / `previous_hash` out of the on-chain envelope into the committed payload. Under the pre-§3.1 contract (which made those fields unconditionally required) a v2 envelope would have been *non-conformant* and would have broken cross-product verification; §3.1 makes it a first-class profile instead. Admitting it is a one-row registry add + one accept-set entry (§5) — no skeleton change, no break to `ario.agent/v1` or `ario.mlflow/v1`. The two v2 tracks (this family contract and the mlflow design doc) MUST be confirmed byte-aligned before `ario.mlflow/v2` is admitted to any accept-set (it remained *proposed* at the family contract's v1.0 ratification, so the confirmation gates its admission, §5/§10 #9).

> **`ario.events/v1` reconciliation.** The Anchoring SDK's profile ([ar-io-agent#11](https://github.com/ar-io/ar-io-agent/issues/11)) is the first registrant to adopt the v1.1 amendments as written: Minimal disclosure per the A2 SHOULD-default (its events are caller-owned), and the optional `environment` field (A1) made **REQUIRED by the profile**. Minimal disclosure structurally implies external commitment for this profile — an inline payload would put the disclosure fields on-chain, defeating Minimal — so the committed payload is a caller-retained *event record* whose canonical bytes stay in the caller's system. Like `ario.mlflow/v2`, registration here does not admit it to any accept-set (§5): admission is gated on its conformance vectors landing in the corpus (`test-vectors-v1.1` candidate set) and profile-spec ratification.

**Profile-internal sub-namespaces** (e.g. `ario.agent.leaf/v1`, `ario.agent.policy/v1`, `ario.agent.proof/v1`) are governed by their owning profile, not by this family contract — they are not stand-alone signed event envelopes.

## 5. Cross-profile verification & the accepted-majors discipline (normative)

A verifier in the family verifies envelopes from *any* profile whose major it recognizes, using one set of primitives. The discipline (already implemented in `ar-io-mlflow`):

- **Recognized major** (in the verifier's configured accept-set; baseline `{ ario.mlflow/v1, ario.agent/v1, ario.events/v1 }` as of v1.3, growing to include `ario.mlflow/v2` when that profile ratifies) → verify normally. Because verification keys off the skeleton (§2/§3.1), admitting a Minimal-mode major is a one-entry accept-set change, not a verifier rewrite.
- **Absent `spec_version`** → *legacy*. Envelopes anchored before the field existed MUST still verify; the verifier SHOULD surface a `legacy_envelope` flag so callers can distinguish.
- **Present but unrecognized major** (e.g. `ario.mlflow/v99`, `ario.future/v1`) → MUST fail closed with reason `unsupported_spec_version`, even if the signature is otherwise valid.

The accept-set is the single place new profiles are admitted; it MUST live in one location per implementation (in `ar-io-mlflow` it is `ACCEPTED_SPEC_VERSIONS` in `proof.py`). This is what makes the family extensible without weakening fail-closed semantics: adding a profile is one entry, not a verifier rewrite. The reference proof of bidirectional conformance is `ar-io-mlflow`'s `tools/cross-product/` (agent envelope → mlflow `verify_record`) and `test_verify_commitment_accepts_cross_product_agent_envelope` (the reverse).

### 5.1 Completeness & gap-detection (scope)

Tamper-evidence (a recorded event cannot be silently altered) is necessary but not sufficient for audit-grade logging; auditors also require **completeness** — assurance that no event was silently *omitted*. This is in scope at two different strengths, and the difference MUST be understood by anyone making a completeness claim:

- **Routine verification stream — completeness IS cryptographically checkable** via the Merkle-checkpoint mechanism (detailed in the table below): a dropped leaf changes the root and a dropped window breaks the checkpoint chain, so omission in this stream is detectable from the bundle.
- **Envelope-level event stream — completeness is bounded, not absolute.** Headline events chain per-type via `previous_hash`, proving **integrity and ordering of the events that are present**, but cannot, from envelopes alone, prove a producer never *failed to emit* one (e.g. a suppressed `tamper_detected`). Detecting suppression relies on correlation with the routine stream (a withheld tamper still surfaces as a `tampered` leaf in the next checkpoint) or an out-of-band expectation (policy says asset X is watched; its absence from checkpoints is itself a signal).

**Two completeness mechanisms, profile-appropriate.** The *property* above is achieved by one of two concrete mechanisms; a profile declares which it offers, and they have different operational shapes:

| Mechanism | How | Self-contained? | Used by |
|---|---|---|---|
| **Merkle checkpoint** | Routine outcomes are Merkle leaves summarized by a `verification_checkpoint` envelope; checkpoints chain via `previous_checkpoint_hash` with `leaf_count`. A dropped leaf changes the root; a dropped window breaks the chain. | **Yes** — re-verifiable from the bundle alone, no gateway needed at audit time. *Scope:* it witnesses the **routine-leaf stream of policy-watched assets**; it is silent by construction about an event that never became a leaf (a never-checkpointed headline event, or an asset removed from / never added to policy). Catching *those* needs the out-of-band policy expectation (below), which a completeness claim MUST state as an input, not assume the root covers. | `ario.agent/v1` |
| **Anchor enumeration** | Enumerate the producer's anchors for a scope via gateway GraphQL, read each anchor's payload-hash tag, and reconcile against the bundle into **verified / unnotarized / missing** (defined below). Catches hidden and never-anchored events without revealing what they were. | **No** — needs a live GraphQL gateway, and is bounded by what an honest gateway has indexed (see limitations). | `ario.mlflow/v2` *(proposed)* |

**The enumeration key is disclosure-mode-dependent, and its choice determines soundness.** What scopes the query MUST be a non-forgeable, pinned, exhaustive identifier, or a dishonest producer simply anchors hidden events under an identifier outside the query:

- **Promoted profiles** enumerate by the producer's **signing-key tag** (the agent's `Public-Key` tag = the Ed25519 envelope key, which is *in the signed scope* and authoritative). This is sound: every conformant envelope carries it, so the query set is complete for that key. (This is what `ariod state recover` actually does — GraphQL by the `Public-Key`/`Tenant-Id`/`Agent-Id` tags, not by the on-chain `owners:` wallet.)
- **Minimal profiles** strip the identity tag, so they SHOULD carry an **opaque scope tag** (§3.1) — a hashed, rotation-capable namespace — and enumerate by it. Such a tag is on every anchor (so exhaustive for that scope) and pinnable, giving Minimal the same enumeration soundness as Promoted's signing-key tag while revealing nothing semantic. This is the AgentSystems pattern (a hashed namespace), and it is the recommended Minimal enumeration key. Because it can leak, it MUST be rotation-capable, and a rotation is handled exactly like a key rotation: the ticket's `scope_key.values` lists *every* scope tag in effect over the period.
- **Without a scope tag, a Minimal profile can only enumerate by the on-chain `owners:` (the funding wallet)** — a *different* key from the Ed25519 signer, off the trust path, and **not exhaustive**: a producer can fund from a second wallet (Turbo lets anyone fund; the agent auto-mints free-tier wallets) and that anchor never appears in an `owners: walletA` enumeration. This fallback is **the weakest enumeration key** — completeness is then only as strong as a pinned, exhaustive funding-wallet set — which is exactly why a scope tag is preferred.

**Scope by witnessed time, not the producer's date tag.** The query's time bound MUST be the **witnessed** block/receipt time (Arweave `block.timestamp` / `HEIGHT`), which the producer cannot forge — not the `signed_at`-style `Anchored-Date-UTC` tag, which a malicious producer can stamp with any day to drop an event out of a queried range. A profile MAY expose a calendar-day tag as a coarse pre-filter, but a verifier MUST treat any anchor whose date tag disagrees with its witnessed time as a finding, and MUST resolve the scope on witnessed time.

**Completeness ticket.** The portable, auditor-facing handle for an enumeration check:

```json
{ "scope_key": { "kind": "signing_key_tag | opaque_scope_tag | funding_owner",
                 "values": ["<Ed25519 public_key | hashed namespace | wallet>", "..."] },
  "app": "<App-Name / namespace>",
  "from": "<RFC 3339 UTC, inclusive>", "to": "<RFC 3339 UTC, exclusive>" }
```

- `scope_key.values` MUST be the **exhaustive** set for the period — every signing key (Promoted), scope tag (Minimal), or funding wallet (Minimal fallback) in effect over `[from, to)`, *including rotated-out ones*. A rotation that contributes only the latest value silently drops events under the prior one.
- `[from, to)` is **half-open, UTC**, resolved against witnessed time.
- The ticket carries **no** event semantics (consistent with Minimal disclosure). Its shape is specified here in full; v1.1 dropped a prior self-commitment to format-track an unrelated ticket schema (see [Amendment log A3](#amendment-log-v10--v11-2026-06-11)).

**Reconcile outcomes (set differences, worst-bucket-wins):** let `B` = payload-hashes in the bundle, `C` = payload-hashes enumerated on chain for the scope. `verified` = in `B ∩ C` and the fetched bytes re-verify (hash + signature). `unnotarized` = in `B` but not in `C` (the bundle claims an event with no on-chain anchor — suspicious, never benign). `missing` = in `C` but not in `B` (anchored but withheld from the bundle — the hidden-event signal). An anchor that re-verifies but is anomalous MUST surface as the **most severe** applicable bucket, never the most benign.

**Limitations (enumeration is strictly weaker than Merkle):**
1. **Withholding gateway.** Re-verifying each returned match only proves none were *forged*; it cannot prove none were *omitted*. A colluding or partially-indexed gateway returning a subset yields a false "nothing missing." Enumeration completeness therefore assumes **at least one honest, fully-indexed gateway**. A verifier asserting completeness SHOULD enumerate against **two or more independent, operator-disjoint gateways** and treat any disagreement in the returned anchor set as a finding (not a pass). Cross-checking is a SHOULD, not a MUST — a single-gateway reconcile is still useful and produces a real `verified`/`unnotarized`/`missing` result, but the completeness assertion is then **bounded by that one gateway's index** and MUST be reported as such ("complete *as indexed by gateway G*"), never as unqualified completeness. GraphQL tag-indexing is not itself a completeness guarantee of the index.
2. **Scope-key exhaustiveness** (above) is an assumption the ticket must pin; an unlisted key/wallet is undetectable.
Merkle-checkpoint completeness has neither limitation — it re-verifies from the bundle alone with no gateway and no owner-set assumption — which is why it is preferred wherever a profile can maintain a checkpoint stream.

**Resolution for v1:** completeness of the routine/checkpoint stream is a normative property; absolute envelope-level non-omission is an explicit **non-goal** of the envelope layer, mitigated by checkpoint correlation (Merkle profiles) or anchor-enumeration reconciliation (enumeration profiles) and recorded as a residual risk (§12). **The `previous_hash` chain is the sequence; the checkpoint stream or the enumeration reconcile is the completeness witness** — together they detect tampering, reordering, and deletion of present events, and bound suppression.

A required per-chain monotonic sequence number (`seq`) was **evaluated as a strengthening and rejected.** Its marginal value over the existing `previous_hash` chain is small (the chain already detects deletion and reordering); against that, a *required* `seq` would (a) reintroduce the per-chain compare-and-set race the mlflow profile deliberately removed on its high-frequency predict path, (b) turn a benign dropped/failed anchor into a *permanent, unfixable* false "gap" on the immutable ledger, and (c) force a coordinated `v2` wire-format cut across both producers — for what is mostly an ergonomic index. The decision is not to add it; profiles that want an explicit index MAY add an optional, non-load-bearing field locally, but it is not part of this contract and verifiers MUST NOT treat its absence (or a gap in it) as a verification failure.

## 6. Conformance

Cross-language, cross-producer conformance is a normative requirement, not an aspiration. This extends [`artifact.md` §15](https://github.com/ar-io/ar-io-agent/blob/main/docs/artifact.md) from "the agent's vectors" to "the family's corpus."

1. **Shared vector format.** Every profile MUST publish test vectors in the `artifact.md` §15.1 file format (fixed keypair, `envelope_pre_signature`, and the expected `payload_jcs_bytes_hex` / `payload_hash_hex` / `envelope_for_sig_jcs_bytes_hex` / `signature_hex`). A conformant verifier byte-compares every stage; any mismatch is a non-conforming primitive (almost always a JCS corner case).
2. **The cross-product corpus is the family suite.** The agent's vector set plus the mlflow plugin's envelopes form one corpus. A verifier MUST pass the corpus for **every payload mode (§3) and profile it accepts** — a verifier claiming *full-family* conformance MUST handle both inline and external-commitment. (Closed as of v1.3 (2026-06-15): all three reference kernels — Python `verify_envelope`, TS, and Go `proof.VerifyEnvelope` — verify both modes. An external-commitment envelope verifies signature-only without the committed record ("signature-valid, semantics-undetermined", §3.1) and binds fully with it; a standing Python⇄TS⇄Go agreement gate over the corpus + adversarial cases pins mutual agreement. The earlier Go/TS inline-only limitation was the Phase-2 gap, now done.)
3. **Reference verifiers.** Python (`ar-io-mlflow` `verify_record`) and Go (`ariod`) are the two reference implementations today, each conformant for the modes it implements (Python: external-commitment + inline cross-product; Go: inline). **A JavaScript/TypeScript reference verifier is a v1 family deliverable** (proposed) — the `canonicalize` JCS package + Ed25519 via WebCrypto — so browser/Node consumers (dashboards, the proof checker) verify without a Python or Go runtime. Third-party verifiers in any language are conformant iff they pass the corpus, unmodified, for the modes they accept.

## 7. Cryptographic agility & long-term validation

The goal is *permanent* evidence, so the primitives need both a present baseline and a path to outlive their own safety margins.

**v1 baseline (REQUIRED).** Ed25519 (RFC 8032; FIPS 186-5-approved since 2023) for signatures and SHA-256 (FIPS 180-4) for hashing are the only required algorithms; every conformant producer and verifier MUST implement them. Canonicalization is JCS (RFC 8785). These are pinned identically across all profiles — the cross-product guarantee (§5) depends on it.

**Reserved agility fields.** A future minor MAY introduce two optional discriminators, default-absent (absence implies the v1 baseline), so a producer migrates without a major bump or a verifier rewrite:

- `signature_alg` — `ed25519` (default) | `rsa-pss-sha256` | future post-quantum schemes. Aligned with [`evidence-bundle.md`](evidence-bundle.md) §4 so the two layers share **one** agility mechanism rather than inventing two. (Reserving the name lets ar-io-verify's RSA operator key, or a PQ signature, mint family-conformant *envelopes* later.)
- `hash_alg` — `sha-256` (default) | future. Reserved now because a permanent ledger will outlive SHA-256's safety margin; without a hash-agility path the only migration would be a major bump.

Both are **reserved, not active, in v1** — flagged so the field names are claimed and the layers stay aligned.

### 7.1 Multi-party signing (reserved)

The v1 envelope has exactly one signer (`public_key` + `signature`). Some events are inherently multi-party — most concretely, a model-stage promotion that an auditor wants to show *who approved*, extensible to a cryptographically **co-signed** promotion (the producer signs the event; an approver counter-signs the same bytes). To let that land additively rather than forcing a major bump, the contract reserves:

- `co_signatures` — an optional array, default-absent, of `{ public_key, signature, role? }` countersignatures over the **same** `JCS(envelope_without_signature_and_without_co_signatures)` bytes the primary `signature` covers. Absence implies a single signer; **a verifier MUST NOT treat its absence (or an empty array) as a failure**, and an unrecognized `role` is ignored, not rejected.

**Removal-resistance caveat (binding on activation).** The same property that makes adding a countersignature non-invalidating — `co_signatures` sits *outside* the primary signed scope — also means one can be **stripped without invalidating the primary signature**. Until that is addressed, the presence of a co-signature is not itself a tamper-evident claim. The minor that activates this field MUST define a removal-resistance mechanism before any consumer treats a co-signature as load-bearing — e.g. an in-scope payload commitment to the *expected* co-signer set (natural home: §3.2 sectioning), so a verifier detects "an expected countersignature is missing" rather than silently accepting the stripped envelope. Two activation prerequisites follow: reference verifiers MUST implement the scope carve-out (strip both `signature` and `co_signatures`) before any profile emits the field — all three kernels are conformant as of 2026-06-11 — the Go gap was closed via issue #12 per governance §6 — and the conformance corpus MUST gain a `co_signatures`-present vector in the activating minor.

Until activated, an approver's identity rides as ordinary additive payload data (e.g. `event.approver` under §3.2's sectioning) — which is already safe and needs nothing from this contract. `co_signatures` is reserved specifically for the stronger claim "a second key *cryptographically attested* this event," so the field name is claimed now and the single-signer baseline stays unchanged. Reserving it (rather than specifying it) keeps v1 simple while guaranteeing the upgrade path is additive.

**Long-term validation (LTV).** A signature verifiable today may use a deprecated primitive in twenty years. The migration strategy is **re-anchoring under a newer profile major**: as a primitive approaches end-of-life, producers anchor a fresh envelope (new `spec_version` major, new `*_alg`) that commits — via `payload_hash` / `previous_hash` — to the original, which remains on permanent storage with its witnessed timestamp (artifact.md §6.1). The witnessed time is what keeps a later-deprecated signature trustworthy: it was sound *when witnessed*. **Verifiers SHOULD treat a signature under a since-deprecated primitive as valid as of its witnessed timestamp, not as of verification time.** This mirrors the intent of ETSI EN 319 102-1 (AdES long-term validation) without adopting its container formats. The explicit re-anchoring linkage (`*_supersedes`) is deferred to the minor that activates `hash_alg`.

## 8. CloudEvents interop profile (proposed, non-normative)

Governance platforms commonly standardize audit/decision events on the **CloudEvents** envelope (e.g. Microsoft's Agent Governance Toolkit, emitted via an OpenTelemetry sink) and recommend an external tamper-evident sink they do not themselves provide. A CloudEvents mapping lets such a platform use ar.io as that sink: it turns a governance event into an anchorable ario envelope, and renders an ario envelope back as a CloudEvent for ingestion the other way.

| CloudEvents attribute | ario envelope field | Notes |
|---|---|---|
| `id` | `event_id` | UUID v4 either way. |
| `type` | `event_type` | Mapped per the `ario.governance/v1` profile (§4). |
| `source` | `subject` | Producer/tenant/agent identity. |
| `time` | `signed_at` | Advisory in both. |
| `data` / `dataschema` | committed payload | External-commitment mode: `payload_hash` commits to the (JCS-canonical) `data`; raw `data` stays in the producer's store. |
| `datacontenttype` | — | `application/json` for canonicalizable payloads. |
| *(extension)* `iopayloadhash` / `ioprevioushash` / `iopublickey` / `iosignature` | `payload_hash` / `previous_hash` / `public_key` / `signature` | ar.io fields ride as CloudEvents extension attributes so the event stays a valid CloudEvent. |

This is the concrete shape of the "external append-only sink": a governance-event-sink connector (a natural sibling to the agent's filesystem/S3 connectors) ingests CloudEvents, commits hash-only envelopes, and anchors them — Merkle-batched via the existing `verification_checkpoint` mechanism (§4.4 of artifact.md) so a high-frequency decision stream costs one Arweave write per window, not one per decision. Specifying the `ario.governance/v1` profile and this mapping is proposed v1.1 work, gated on ratifying the family contract first.

## 9. Relationship to the evidence layer & compliance frameworks

- **The envelope is the atomic evidence unit.** `ario.evidence/v1` ([`evidence-bundle.md`](evidence-bundle.md)) wraps *collections* of envelopes (or bundles derived from them) with a recomputable verdict; this spec governs the unit it wraps. The two share canonicalization/signing discipline by design.
- **Compliance mapping is a reporting-layer concern, not an envelope concern.** Mapping evidence to OWASP Agentic Top 10 / NIST AI RMF / EU AI Act / SOC 2 controls — and any coverage grade — belongs at the evidence/reporting layer, where the verdict vocabulary lives. The envelope stays a minimal, control-framework-agnostic proof so it can serve *any* framework without schema churn. (Where Microsoft's compliance mapping is hand-curated code-to-control prose, the ar.io path can make each anchored envelope the *runtime* evidence a control cites — but that machinery is built above the envelope, not in it.)
- **Provenance ≠ endorsement.** Mirroring `evidence-bundle.md` principle 5 and `proof-checker.md` §8: an envelope proves "this event happened and was signed by this key," never "this was safe / approved / authorized." The vocabulary at every layer says *"has a verifiable history,"* never *"is safe."*

## 10. Resolved positions

These were **resolved with the recommended defaults** and confirmed at the v1.0 ratification (2026-06-10); none remain open.

| # | Decision | Resolution |
|---|---|---|
| 1 | New `spec_version` string vs meta-spec | **Meta-spec, no new string.** A third shared version would violate "inherit, don't invent" and break the dialects. |
| 2 | Formalize `ario.governance/v1` + CloudEvents (§8) now vs later | **Later (Phase 4).** Ratify the family contract on the two existing profiles first; the governance profile is the first *new* profile that proves the registry. |
| 3 | JS/TS reference verifier owner/home (§6) | **Deferred to Phase 3**, owner assigned at ratification. Working assumption: a standalone package consumed by the proof checker. |
| 4 | External-commitment locator: normative field vs profile prose | **Resolved: optional `payload_ref` field** (§2, §3). Additive/minor — profiles adopt without a major bump; self-describing beats prose for composability. |
| 5 | Reserve `signature_alg` / `hash_alg` now | **Reserve the names now, keep absent** (implied baseline) until needed — see §7. |
| 6 | Completeness mechanism (§5.1) | **Resolved: no `seq` field.** `previous_hash` (ordering + deletion/reorder detection) + the checkpoint Merkle stream (completeness + suppression-bounding) are the mechanism. A required `seq` was evaluated and rejected — marginal value over the hash chain, reintroduces the mlflow predict-path race, and bakes benign dropped anchors into permanent false gaps on an immutable ledger (§5.1). |
| 7 | Ratification owner per repo | **Resolved: BDFL** — Phil Mataras (@vilenarios) per [`stack/governance.md`](governance.md) §1. All sibling repos share the owner, so the cross-repo sign-off collapses to the BDFL's ratification (same resolution as `evidence-bundle.md` §7 row 7). |
| 8 | Header disclosure: identity-rich vs stripped | **Per-profile disclosure axis, Promoted vs Minimal (§3.1).** Skeleton identical in both, so cross-product holds; relaxes the three disclosure fields from required → conditional (backward-compatible). |
| 9 | Reconcile `ario.mlflow/v2` (identity-stripping) | **Admit as the first Minimal profile** (§4 + §5, one entry each). It remained *proposed* at v1.0 ratification; the two v2 tracks MUST be confirmed byte-aligned before its accept-set admission (BDFL, delegable per governance.md §1). |
| 10 | Completeness for non-checkpoint profiles | **Two mechanisms (§5.1):** Merkle-checkpoint (self-contained) + anchor-enumeration (needs a gateway), with a portable ticket whose shape is specified in §5.1 (v1.1 dropped the prior format-alignment commitment to `agentsystems-verify`). |
| 11 | Multi-party / approver co-signing | **Reserve `co_signatures` (§7.1); single-signer baseline unchanged.** Approver identity rides as additive payload data until then. |
| 12 | Payload field-evolution discipline | **RECOMMEND owner-namespaced sectioning (§3.2)** — the structural guarantee behind §2's additive-minor rule; precondition for #11. |
| 13 | Verify boundary: kernel vs profile-layer | **Kernel verify = single-envelope (signature + `payload_hash`); disclosure/chain/completeness validation is profile-layer (§3.1, §5)**, reconciling with [architecture.md](architecture.md) K1. Disclosure mode is bound to the signed `spec_version` (closes mode-confusion). |
| 14 | Enumeration-completeness soundness | **Scope by a pinned, exhaustive key and by witnessed time, not producer tags (§5.1):** signing-key tag (Promoted), an opaque rotation-capable scope tag (Minimal, recommended — the AgentSystems hashed-namespace pattern), or the funding-wallet fallback (weakest). Documented as strictly weaker than Merkle; SHOULD cross-check ≥2 gateways; `verified/unnotarized/missing` defined as set differences. |

## 11. Phased rollout

| Phase | What ships | Repo | Effort |
|---|---|---|---|
| **0 — Ratify** | ✅ **Done (2026-06-10).** Reviewed; §10 decisions settled; ratified by the BDFL per [`stack/governance.md`](governance.md) (both existing profiles' conformance is already proven by the bidirectional cross-product tests, §5). | all | M (agreement, not code) |
| **1 — Profiles cite up** | `artifact.md` and `ar-io-mlflow`'s spec add a one-line "conformant profile of [envelope-spec]" pointer for the shared invariants; no byte changes. | ar-io-agent, ar-io-mlflow | S |
| **2 — Family corpus** | Publish the cross-product corpus as the named family conformance suite; both reference verifiers run it in CI. | ar-io-mlflow, ar-io-agent | S |
| **3 — JS/TS verifier** | Standalone reference verifier passing the corpus; unblocks browser/Node verification (proof checker). | owner assigned at Phase 0 (§10 #3) | M |
| **4 — Governance profile** | Specify `ario.governance/v1` + the CloudEvents mapping (§8); prototype the governance-event-sink connector with Merkle-batched anchoring. | ar-io-agent | M–L |

Phases 0–2 are cheap and entirely in ar.io-owned code. Phase 3 extends verification to browsers/Node. Phase 4 lets external governance platforms anchor to ar.io as their tamper-evident sink.

## 12. Security considerations

The envelope establishes **authenticity and integrity**, not truth or authority. Consumers MUST understand the residual risks.

- **Signed ≠ true.** A valid envelope proves the holder of `public_key` signed exactly these bytes and they are unmodified. It does **not** prove the asserted event occurred or that the payload is accurate — a compromised-but-authorized producer can sign false-yet-valid events. Detecting a lying producer is out of scope for this layer; it is mitigated by corroboration (the routine checkpoint stream, §5.1) and by securing the producer (the control plane, §1), not by the envelope.
- **Non-repudiation needs an out-of-band trust root.** The envelope binds events to a *key*, not a legal identity. Non-repudiation against an organization (NIST 800-53 **AU-10**) holds only when `public_key` is bound to that organization via a **specified** trust root. **The recommended default binding is the api-guard registration roster** (the producer registers its `public_key` against a tenant identity, and the roster is the authority for "whose key this is"). Named alternatives a deployment MAY use instead: **X.509/PKI**; a **key-transparency log**; or the **ar.io-native on-chain attestation** pattern — a wallet-signed attestation document that binds the signing key to a staked on-chain identity and is itself anchored on Arweave (the same two-key hierarchy ar.io gateways use to attest their RFC-9421 response-signing keys; see the *Verification and Accountability in the ar.io Network* white paper §6.2). The on-chain-attestation option is notable because it needs **no ar.io service in the trust path at verification time** — the attestation is permanent public data — making it the most self-contained of the four. A deployment claiming non-repudiation MUST name which of these is its trust root; `subject` identity in the envelope is advisory context, never the binding.
- **Key validity-at-time.** "Was this key authorized when it signed?" requires the witnessed timestamp (artifact.md §6.1) plus the key's status at that time. `key_retired` (artifact.md §4.7) provides a signed retirement cutoff; full cryptographic revocation is deferred (artifact.md §12.4), so validity-at-time today relies on witnessed time plus the out-of-band roster. Verifiers SHOULD reject envelopes whose witnessed time is after a key's `retired_at`.
- **Gateway is untrusted delivery — and this composes with the network's own delivery-verification layer.** A gateway can withhold or stale a response but cannot forge one undetectably — every load-bearing claim is re-checked against the signature/hash. No ar.io service sits in the trust path. This is the *same* untrusted-delivery posture the broader ar.io network formalizes for gateway responses (the *Verification and Accountability in the ar.io Network* white paper): the envelope is an **evidence-plane** artifact (it proves *what a producer committed*), and it travels over the **delivery plane** that the white paper hardens with RFC-9421 signed gateway claims, RFC-9530 `Content-Digest`, Wayfinder client-side verification, and the observer/slashing accountability protocol. The two planes compose cleanly and without duplication: a consumer fetching an envelope by `tx_id` and re-verifying it (auditor-recipe) is exactly Wayfinder's `SignatureVerificationStrategy` applied to an ario envelope — the gateway's own RFC-9530 `Content-Digest` / `X-AR-IO-*` headers are an available *additional* (still-untrusted, signed-but-not-truth) cross-check, never a substitute for re-verifying the envelope signature. The envelope layer assumes nothing about gateway honesty precisely because that honesty is a separate, independently-addressed problem.
- **Replay & uniqueness.** `event_id` (UUID v4) is unique per event; a replayed envelope is byte-identical and detectable by id. Chain pointers detect reordering within a chain.
- **Disclosure mode is a privacy choice, not a trust choice.** Minimal vs Promoted (§3.1) changes only what an on-chain observer learns — never what a verifier can *prove* (the skeleton, `payload_hash`, and signature are identical in both). A producer choosing Promoted should treat its tags as public forever; one choosing Minimal must hold the payload elsewhere (external-commitment, §3) to stay auditable.
- **Completeness residual.** Per §5.1, absolute envelope-level non-omission is a stated non-goal; enumeration completeness additionally carries a gateway *liveness* dependency (not a trust one — matches are still re-verified) and is weaker than Merkle.
- **Canonicalization is a hostile-input boundary.** A verifier canonicalizes attacker-influenced bytes (the envelope/body it is handed, an untrusted gateway's re-served checkpoint, a `--logs` side input). Two failure modes are pinned closed by §2 invariant 7: (a) **lone UTF-16 surrogates** are rejected, not passed through (RFC 8785 requires well-formed UTF-8; the sibling kernels cannot represent them identically); (b) **nesting depth is bounded to 128 levels** and a deeper input is `malformed` *before* canonicalization. The depth bound is as much a **cross-kernel-agreement** requirement as a DoS one — an unbounded recursive canonicalizer overflows at a runtime-specific depth, so without a shared fixed limit the same bytes could verify on one kernel and crash on another, which is itself an integrity failure (a verdict that depends on which verifier you run).

### 12.1 Data lifecycle, retention & erasure (GDPR)

The pure-commitment design makes this tractable rather than a conflict. Only a SHA-256 commitment (plus non-PII metadata) is anchored — never source data (external-commitment mode, §3), and in inline mode only the minimal non-sensitive provenance a profile defines.

- **Permanence satisfies retention.** The on-chain commitment is permanent (Arweave), exceeding e.g. EU AI Act Art. 26(6)'s ≥6-month log-retention floor, with no rotation policy to maintain (NIST 800-53 **AU-11**).
- **Erasure is unobstructed.** A hash is not personal data; a producer may delete the off-chain canonical bytes (GDPR right-to-erasure / data-residency) without invalidating any anchored proof. The proof becomes unverifiable-against-source while remaining signature-valid — the correct outcome: "this commitment existed at time T" survives erasure.
- Retention of the off-chain canonical bytes is the producer's policy, out of scope here.

### 12.2 Standards alignment (informative)

Mapping evidence to controls is the reporting layer's job (§9); this is an orientation pointer, not a conformance claim, and identifiers are indicative pending compliance-reviewer ratification. Envelope-layer artifacts are designed to *support* — among others — EU AI Act Art. 12 (record-keeping) & Art. 26(6) (retention); NIST 800-53 **AU-2** (event logging), **AU-9** (protection of audit information / tamper-evidence), **AU-10** (non-repudiation, *with* a trust root per §12), **AU-11** (retention); SOC 2 CC7 (system operations / monitoring); and the forthcoming prEN ISO/IEC 24970 (AI system event logging). The agent's per-framework crosswalk already lives in [`compliance.md`](https://github.com/ar-io/ar-io-agent/blob/main/docs/compliance.md); the mlflow-profile and family-contract equivalents are the companion work tracked alongside [`evidence-bundle.md`](evidence-bundle.md).

## 13. References

**Normative.** RFC 2119 + RFC 8174 (requirement keywords); RFC 8785 (JCS canonicalization); RFC 8032 (Ed25519 / EdDSA); FIPS 180-4 (SHA-256); FIPS 186-5 (Digital Signature Standard — Ed25519 approval); RFC 9162 (Certificate Transparency Merkle trees — checkpoint/Merkle profiles); RFC 3339 (timestamps); RFC 4648 (base64url, where a profile encodes identifiers).

**Informative.** [`artifact.md`](https://github.com/ar-io/ar-io-agent/blob/main/docs/artifact.md) (agent profile), [`evidence-bundle.md`](evidence-bundle.md) (`ario.evidence/v1`), [`auditor-recipe.md`](https://github.com/ar-io/ar-io-agent/blob/main/docs/auditor-recipe.md), [`compliance.md`](https://github.com/ar-io/ar-io-agent/blob/main/docs/compliance.md); EU AI Act (Reg. 2024/1689) Arts. 12 & 26(6); NIST SP 800-53 Rev. 5 (AU family); NIST AI RMF 1.0; ISO/IEC 42001:2023; SOC 2 (AICPA Trust Services Criteria); prEN ISO/IEC 24970 (AI system event logging, in development); ETSI EN 319 102-1 (AdES long-term validation — prior art for §7's LTV approach); *Verification and Accountability in the ar.io Network* (P. Mataras, ar.io Foundation, 2026 — the gateway delivery-verification architecture this evidence layer composes with: §4 commitment model, §6 RFC-9421 signed gateway claims, §7 Wayfinder); RFC 9421 (HTTP Message Signatures — gateway claim signing); RFC 9530 (Digest Fields — `Content-Digest` body integrity).

---

*Ratified v1.0 (2026-06-10) alongside [`evidence-bundle.md`](evidence-bundle.md) (the unit and the wrapper). Revisit when: a third producer wants to join the family (validates the registry + accept-set), or a change request lands per [`stack/governance.md`](governance.md) §2.*
