# Attested evidence export — issuer-signed export body (`ario.evidence.export/v1`)

> **Status: BDFL-ratified 2026-07-15 (Phil Mataras, per [`governance.md`](governance.md) §1); landing via this PR to `ar-io-proof/specs` as an additive minor (§2) — RFC-2119 keywords binding on merge.** A new `ario.evidence/v1` `body_type` for a portable, offline-verifiable **attested evidence export**: a kernel-recomputable verdict over a source anchor-trace bundle, plus embedded per-checkpoint **operator attestations** (RSA-PSS over the operator's Arweave wallet), assembled and signed by the ar-io-verify issuer. It extends [`evidence-bundle.md`](evidence-bundle.md)'s `ario.evidence/v1` wrapper (§2) with no wrapper change — this is a registry-add body, not a new wrapper — and inherits the family invariants from [`envelope-spec.md`](envelope-spec.md) (JCS · SHA-256 · Ed25519). Cross-refs: [`evidence-bundle.md`](evidence-bundle.md) (the wrapper this rides + the `ario.anchor.trace/v1` source body), [`envelope-spec.md`](envelope-spec.md) (family contract), [`architecture.md`](architecture.md) (kernel factoring — the RSA-PSS record primitive this adds), [`governance.md`](governance.md) (ratification path + corpus versioning).
>
> **Ratification context.** The BDFL ratified this spec on 2026-07-15 — the §8 decisions plus this implementing draft, with the sub-question dispositions settled (Appendix), the RSA-PSS salt seam resolved (§3.3), and the lone deferred call (A8 — issuer wrapper-key trust root) due before the first external export. It lands via this PR per [`governance.md`](governance.md) §1–§2; RFC-2119 keywords become binding on merge. Two things it introduces are net-new kernel capability, tracked as work against this contract, not soft spots in it: (1) an **RSA-PSS-SHA-256 verify primitive** in the TS and Python kernels (both are Ed25519-only today), and (2) a **Python `ario.evidence/v1` verifier**, which does not exist (the Python kernel verifies only `ario.agent.proof/v1`). Both are §5 / §7 items.

## 0. The one-paragraph pitch

The stack can already emit a kernel-verifiable source bundle (`@ar.io/anchor`'s `toEvidenceBundle` → `ario.evidence/v1` with `body_type` `ario.anchor.trace/v1`, [`evidence-bundle.md` §5.1](evidence-bundle.md)) and the ar-io-verify issuer can already produce a per-transaction **operator attestation** (RSA-PSS over `{txId, dataHash, blockHeight, operator, gateway, …}`, the operator key being the operator's Arweave wallet). What does not exist is the artifact an enterprise auditor actually wants: **one signed file** that binds a recomputable verification verdict to those operator attestations and to the source bundle it summarizes, and that a stranger can verify **offline** on a network-isolated machine with `proof verify`. `ario.evidence.export/v1` is that file. It is an `ario.evidence/v1` body — the issuer wraps the source bundle's verdict, embeds the operator attestations as records, and signs the whole export with an **Ed25519 wrapper the kernel verifies today**. The kernel verifies **both** the Ed25519 wrapper **and** every embedded RSA-PSS attestation. It is not a new convention; it is the evidence wrapper's discipline applied to an attested, issuer-composed export.

## 1. Design principles (inherited, restated for the export)

These are [`evidence-bundle.md` §1](evidence-bundle.md)'s principles, specialized. They are load-bearing here — the export is where an *issuer* (a distinct third party from the producer) signs, so the trust boundaries must be exact.

1. **Inherit, don't invent.** Same wrapper (`ario.evidence/v1`), same `spec_version` form, same `snake_case`, same JCS (RFC 8785), same "strip `signature`, JCS, verify" flow, same `GENESIS` chain convention as the wrapper (§2) and the family envelope ([`envelope-spec.md` §2](envelope-spec.md)). A verifier that verifies an `ario.anchor.trace/v1` bundle verifies this export's wrapper with the same primitives; the *only* new primitive is RSA-PSS for the embedded attestation records (§5).
2. **Wrap, don't merge.** The export does **not** rewrite the source anchor-trace body. It references it whole (inline or by hash, §2.4) and recomputes its verdict. The operator attestations ride as their own embedded records, not folded into the producer's body. This preserves the [`architecture.md` §5–§6](architecture.md) producer/issuer role boundary: the producer emits the anchor trace; the issuer attests and exports.
3. **Recompute, never trust the verdict.** The embedded `kernel_verdict` (§4) is a rendering convenience. A conforming verifier MUST recompute it from the source bundle and every embedded attestation before display, and MUST treat an export whose recomputed verdict disagrees with its embedded one as **failed/tampered** — exactly as [`evidence-bundle.md` §4 step 4](evidence-bundle.md) mandates for the wrapper verdict.
4. **No ar.io service in the trust path.** The export is self-verifying offline against embedded keys — the Ed25519 issuer key for the wrapper and the embedded RSA operator key(s) for the attestations. `gateway` values are named as the surface each attestation/checkpoint was built against, **never trusted**; on-chain re-fetch is an optional online cross-check (§4.2), not a verification dependency.
5. **Provenance ≠ endorsement.** The verdict vocabulary is unchanged from [`evidence-bundle.md` §3](evidence-bundle.md): six states, **no "safe"/"approved"**. An operator attestation proves "this operator's key signed this `{txId, dataHash, …}` claim," never "this data is safe."
6. **Attestation identity is out-of-band, but self-describing.** The embedded operator key binds to an Arweave wallet address by construction (`operator == base64url_nopad(SHA-256(public_key.n))`, §3.3), so the export proves "the holder of *this wallet* attested," offline. Binding that wallet to a *named gateway operator in the GAR* is online enrichment (§6, and an open sub-question — Appendix A3), never a verification gate in v1.

> **This is the home for "export an attested evidence dossier."** The issuer's "compose a bundle's verification + operator attestations into one offline-verifiable, family-shaped deliverable" feature is an `ario.evidence/v1` producer — a new `body_type`, not a fourth bundle shape. It reuses the wrapper's growth hooks: `signature_alg` lets the RSA operator attestations join without minting Ed25519 keys (they ride as embedded records, not as the wrapper signature); `body_ref` (as `source_bundle_ref`, §2.4) lets a large source bundle live out-of-line behind a hash; `previous_hash` carries chain-of-custody over successive exports (§2.3).

## 2. The export body (`body_type` = `ario.evidence.export/v1`)

### 2.1 How it rides the wrapper

The export is an `ario.evidence/v1` wrapper ([`evidence-bundle.md` §2](evidence-bundle.md)) with **no wrapper change**. The wrapper fields carry their normal meaning; the export-specific rules are:

| Wrapper field | Value for an export | Notes |
|---|---|---|
| `spec_version` | `ario.evidence/v1` | Unchanged. Verifiers reject unknown majors. |
| `body_type` | `ario.evidence.export/v1` | The new registry entry. The kernel dispatches on this to `verifyExportBody` (§5). |
| `issuer` | `{ "kind": "issuer", "issuer_id": "<ar-io-verify instance id>" }` | The composing issuer. `kind` gains the value `issuer`. Carries identity *context*; the load-bearing key is the top-level `public_key`. |
| `generated_at` | RFC 3339 | When the export was composed. Advisory (witnessed time comes from anchoring the export, §2.3 / §8 A2). |
| `gateway` | string \| null | Named delivery surface only. Not trusted. |
| `verdict` | the shared 6-state rollup (§3 of the wrapper) | Coarse family rollup, **derived from `body.kernel_verdict`**. Recompute-don't-trust. The detailed per-event / per-checkpoint / per-gateway object lives in `body.kernel_verdict` (§4). |
| `body` / `body_ref` | the export body (§2.2) | Inline `body` is the default (self-contained offline verify, §5). `body_ref` allowed for very large bodies. |
| `body_hash` | `SHA-256(JCS(body))` | Commitment to the export body. |
| `previous_hash` | sha256-hex \| `GENESIS` | Custody chain over successive exports (§2.3). |
| `signature_alg` | `ed25519` | **The wrapper is Ed25519-signed** (§8 A3). The kernel verifies it today with zero new crypto. RSA-PSS appears only inside `body.attestations[]` (§3). |
| `public_key` | hex | The issuer's Ed25519 verify key. Embedded for self-containment; identity binding is out-of-band (§6). |
| `signature` | hex | Ed25519 over `JCS(wrapper_without_signature)`. |

### 2.2 Body structure

```json
{
  "kernel_verdict": { /* the detailed verdict object — §4 (cached; recompute-don't-trust) */ },
  "source_bundle": { /* the full ario.evidence/v1 anchor-trace bundle, inline — §2.4 */ },
  "source_bundle_hash": "9a3b1c…e7f2",
  "attestations": [
    {
      "checkpoint_tx_id": "<arweave-txid>",
      "payload": { /* the JCS-canonical attestation payload — §3 */ },
      "signature_alg": "rsa-pss-sha256",
      "public_key": { "kty": "RSA", "n": "<base64url modulus>", "e": "AQAB" },
      "signature": "<lowercase-hex RSA-PSS signature over JCS(payload)>"
    }
  ],
  "export_schema": "ario.evidence.export/v1"
}
```

| Field | Required | Type | Meaning |
|---|---|---|---|
| `kernel_verdict` | Yes | object | The detailed, recomputable verdict object (§4) over the source bundle + embedded attestations. **Cached rendering convenience** — the verifier recomputes it (§5 step 5) and treats a disagreement as tamper (principle 3). |
| `source_bundle` | Cond. | object | The full source `ario.evidence/v1` bundle the export summarizes, **inline**. In v1 this MUST be an `ario.anchor.trace/v1` bundle — the only source `body_type` the kernel verifies (§2.4); other kernel-verifiable body types are a defined growth hook, out of v1 scope. Exactly one of `source_bundle` / `source_bundle_ref` MUST be present. Inline is REQUIRED for a self-contained offline export (§5). |
| `source_bundle_ref` | Cond. | string (URI) | Out-of-line source-bundle location, for a source too large to inline — a defined growth hook, **out of v1 scope** (§2.4). Integrity is `source_bundle_hash`. An export using `source_bundle_ref` is **not** verifiable on a network-isolated machine unless the referenced bytes are co-delivered; the v1 offline verifier does **not** auto-fetch it (§2.4 / §5 step 3, exit 3). |
| `source_bundle_hash` | Yes | sha256-hex | **Inline:** `SHA-256(JCS(source_bundle))`. **Referenced:** SHA-256 of the published bytes exactly as fetched (no re-canonicalization), mirroring the wrapper's `body_hash` rule ([`evidence-bundle.md` §2](evidence-bundle.md)). This is the source-bundle **linkage commitment** (§5 step 4). |
| `attestations` | Yes | array | Embedded operator attestation records (§3), one or more per source checkpoint. MAY be empty only for a content-blind / attestation-less export, in which case every checkpoint's attestation dimension is `undetermined`, never `verified`. |
| `attestations[].checkpoint_tx_id` | Yes | string | The source-bundle `checkpoints[].tx_id` this attestation binds to. A verifier MUST resolve it to a present checkpoint (§5 step 6). |
| `attestations[].payload` | Yes | object | The attestation payload (§3.1), JCS-canonicalized when signed. |
| `attestations[].signature_alg` | Yes | enum | `rsa-pss-sha256`. The only per-record alg in v1 (the operator key is intrinsically the operator's RSA Arweave wallet, §3.3). |
| `attestations[].public_key` | Yes | object (JWK) | The operator's RSA public key `{kty:"RSA", n, e}`. Embedded for self-containment; the kernel derives the operator address from it (§3.3). |
| `attestations[].signature` | Yes | hex | RSA-PSS-SHA-256 signature over `JCS(payload)`. Lowercase hex. |
| `export_schema` | No | string | Body-internal self-identifier, echoing `body_type`. Harmless and backward-compatible ([`evidence-bundle.md` §7 decision 5](evidence-bundle.md)); `body_type` is the wrapper's authoritative copy. |

### 2.3 `previous_hash` custody

Chain-of-custody over successive exports rides the **wrapper** `previous_hash` ([`evidence-bundle.md` §2](evidence-bundle.md)), following the `GENESIS`-first-link convention: a one-off export sets `GENESIS`; a monthly / re-issued export sets the SHA-256 of the prior export's canonical wrapper bytes (`SHA-256(JCS(prior_wrapper_without_signature))`, i.e. the hash a verifier recomputes for the prior export). The field is **optional** here, exactly as the wrapper makes it — it is *not* the per-event required pointer of [`envelope-spec.md` §2](envelope-spec.md). Custody-chain verification (walking `previous_hash` across exports) is out of scope for a single-file offline verify and requires the prior export(s) as additional inputs; a verifier that is given them SHOULD confirm the chain and surface a `custody_chain` result, and MUST treat a broken link as a finding, not silently ignore it.

### 2.4 Source-bundle reference

The source bundle is a complete, independently kernel-verifiable `ario.evidence/v1` bundle. The export does **not** re-canonicalize or rewrite it (principle 2). Default is inline (`source_bundle`) for a self-contained file; `source_bundle_ref` + `source_bundle_hash` is the growth hook for a source too large to inline, mirroring the wrapper `body`/`body_ref` split. Either way `source_bundle_hash` is the integrity commitment the export signature covers (it is inside `body`, hence inside `body_hash`, hence inside the wrapper signature).

**v1 scope (pinned once).** v1 supports exactly **one source shape: an inline `ario.anchor.trace/v1` bundle** (`source_bundle`). Other source `body_type`s and out-of-line `source_bundle_ref` are **defined growth hooks, out of v1 scope** — the v1 kernel fully verifies only the inline anchor-trace source (an unrecognized inline source body yields an *undetermined* source verdict at §5 step 4, and its embedded attestations resolve no checkpoint, so the export cannot reach `verified`). This is the single authoritative statement of source-body support; §2.2, §3, and [`evidence-bundle.md` §5](evidence-bundle.md)'s registration all refer here.

**`source_bundle_ref` and SSRF (offline-first).** A v1 offline verifier **MUST NOT** auto-fetch `source_bundle_ref`: the referenced bytes must be co-delivered as a side input, and their absence makes the source-dependent checks **undetermined → exit 3** (never a failure) — this is exactly what the reference kernels do (the source-dependent checks short-circuit to *undetermined* when the source is not inline; see §5 step 3). A deployment that *does* choose to fetch a `source_bundle_ref` (an out-of-v1 growth path) **MUST** treat the URI as untrusted input and defend against SSRF: restrict to safe schemes (e.g. `https:`/`local:`, never `file:`/`gopher:`/raw IP metadata endpoints), bound and vet redirects and destination hosts (deny-list link-local / RFC 1918 / loopback unless explicitly allowed), enforce connect/read timeouts and a response-size cap, and hash the **exact bytes received** against `source_bundle_hash` (SHA-256 of the fetched bytes as-is, no re-canonicalization — the referenced-body rule of §2.2). A hash mismatch is a hard failure (§5 step 3, exit 1); a fetch that cannot complete under these bounds is undetermined (exit 3), not a pass.

## 3. Embedded attestation records

An attestation record is a **portable, JCS-canonicalized, RSA-PSS-signed** claim by a gateway operator about one Arweave transaction. It is the ar-io-verify `/attestation` payload, migrated onto the family canon (§3.4) and carrying the new optional `subject_ref` (§3.2).

### 3.1 Attestation payload

The payload is a flat JSON object. Field names are the family `snake_case` form; the shipped issuer's `camelCase` names map 1:1 (§3.4).

```json
{
  "attested_at": "2026-07-15T18:00:00.000Z",
  "tx_id": "<arweave-txid>",
  "data_hash": "<sha256-hex of the tx data>",
  "data_size": 10485760,
  "block_height": 1512345,
  "block_timestamp": 1789000000,
  "operator": "<Arweave wallet address = base64url_nopad(SHA-256(public_key.n)), §3.3>",
  "owner_address": "<Arweave tx owner address>",
  "gateway": "https://operator-gateway.example",
  "signature_verified": true,
  "level": 3,
  "subject_ref": {
    "hash": "<sha256-hex of an external subject>",
    "type": "ap2.mandate | mlflow.run | document | …"
  },
  "attestation_version": "ario.evidence.attestation/v1"
}
```

| Field | Required | Type | Meaning |
|---|---|---|---|
| `attested_at` | Yes | RFC 3339 | When the operator produced the attestation. Advisory (witnessed time is `block_timestamp` / the anchored tx). |
| `tx_id` | Yes | string | The attested Arweave transaction. |
| `data_hash` | Yes | sha256-hex | SHA-256 of the attested transaction's on-chain data. **For an `ario.anchor.trace/v1` source this is `SHA-256(JCS(checkpoint.envelope))`** — the checkpoint tx's data is exactly the uploaded canonical envelope bytes (the same bytes §4.2's on-chain re-fetch compares), so it is offline-recomputable and identical across kernels. **Lowercase hex** (family convention); verifiers case-fold before comparison. A verifier MUST confirm `data_hash` equals that value for the resolved checkpoint (§5 step 6c). |
| `data_size` | Yes | int | Byte length of the attested data. |
| `block_height` | Yes | int | The block the tx is included in. |
| `block_timestamp` | Yes | int | Witnessed block time (Unix seconds). The non-forgeable time. |
| `operator` | Yes | string | The operator's Arweave wallet address. MUST equal `base64url_nopad(SHA-256(public_key.n))` derived from the record's `public_key` (byte rule pinned in §3.3) — this binds the signature to the wallet. |
| `owner_address` | Yes | string | The tx owner's Arweave address (the data's uploader). Distinct from `operator`. |
| `gateway` | Yes | string | The gateway surface the operator observed the tx on. **Named, not trusted.** |
| `signature_verified` | Yes | bool | Whether the operator verified the tx's own data-item signature. Feeds the attestation `level`. |
| `level` | Yes | int enum `1\|2\|3` | Existence (1) / Integrity (2) / Verified (3), per the issuer's L1/L2/L3 model. Advisory to the verdict; the kernel does not compute it, only surfaces it. |
| `subject_ref` | **No** | object | **D8, additive.** `{ hash: sha256-hex, type: string }` — a hash + type of an external subject the attestation is *about* (an AP2 mandate, an MLflow run, a document). Absent ⇒ the attestation is unbound to any external subject (backward-compatible). §3.2. |
| `attestation_version` | No | string | Body-internal self-identifier for the payload schema. Harmless; the record `signature_alg` + this doc are authoritative. |

The record's `public_key`, `signature_alg`, and `signature` (§2.2) are **not** part of the signed payload — the signature is over `JCS(payload)` only. This is the **post-migration** signing form required by this spec (§3.4): RFC 8785 `JCS(payload)` with the `snake_case` field names above, signed RSA-PSS-SHA-256 with a 32-byte (digest-length) salt (§3.3). It is **not** the shipped issuer's current `signPayload(buildAttestationPayload(...))` behavior — that signs a custom deep-sorted-key canon over `camelCase` fields with `RSA_PSS_SALTLEN_AUTO`, which §3.4 replaces. A verifier that follows this spec verifies only records signed in the post-migration form.

### 3.2 `subject_ref` (D8)

`subject_ref` is **additive and optional**. It lets an attestation point at an external subject by hash + type without disclosing the subject's bytes — e.g. an AP2 payment mandate, an MLflow run record, a contract document. Semantics:

- Absent ⇒ the attestation binds only to the on-chain tx (`tx_id` / `data_hash`); it makes no external-subject claim. Every pre-D8 attestation is valid unchanged.
- Present ⇒ `hash` is a lowercase `sha256-hex` and `type` is a caller-declared subject-type token (`^[a-z0-9.:-]+$`). **Pinned hashed bytes:** `subject_ref.hash` is `SHA-256` over the **exact raw bytes the relying party supplies as the subject** — the verifier hashes those bytes as-is and does **not** re-canonicalize them (any canonicalization of the subject is the *producer's* out-of-band responsibility, done before hashing; the verifier neither knows nor re-applies it). The verifier confirms the field is **well-formed** and that it is inside the signed payload (so it cannot be added or altered after signing); it does **not** fetch the external subject (that binding is out-of-band, the subject bytes are the relying party's to supply). A verifier MAY accept a supplied side-input subject file and confirm `SHA-256(raw supplied bytes) == subject_ref.hash`, surfacing the result — but a *missing* side input leaves `subject_ref` **undetermined, not failed** (mirrors disclosed-content handling, [`evidence-bundle.md` §5.1](evidence-bundle.md)). A `subject_ref` present but malformed (bad `hash`/`type` shape) is likewise `subject_ref_ok: null` — surfaced, non-gating; §5 step 6 gates only on signature, operator-address, and `data_hash` binding.

### 3.3 Canonicalization & signing (issuer)

Identical discipline to the wrapper ([`evidence-bundle.md` §4](evidence-bundle.md)) and the family envelope, with RSA-PSS in place of Ed25519 for the record:

**Operator (attestation producer):**
1. Build `payload` with every field except the record's signature fields.
2. `record_bytes = JCS(payload)` — **RFC 8785**, UTF-8 (the migration, §3.4).
3. `signature = RSA-PSS-SHA-256(record_bytes, operator_private_key)`; hex-encode.
4. Emit the record `{ checkpoint_tx_id, payload, signature_alg: "rsa-pss-sha256", public_key, signature }`.

**RSA-PSS parameters (pinned — cross-kernel byte-agreement depends on this):** hash = SHA-256; MGF1 with SHA-256; **salt length = digest length (32 bytes)** (`RSA_PSS_SALTLEN_DIGEST`); padding = PSS. These MUST be identical in the issuer, the TS kernel, and the Python kernel. **Resolved 2026-07-15 (against ar-io-verify `packages/server/src/utils/signing.ts`):** the shipped issuer signs attestations with `RSA_PSS_SALTLEN_AUTO`, which on *signing* resolves to the maximum (key-size-dependent) salt — not verifiable by WebCrypto or Python `cryptography`, neither of which auto-detects salt on verify. Because the JCS migration (§3.4) re-signs every attestation regardless, the issuer MUST switch to an explicit `RSA_PSS_SALTLEN_DIGEST` (32-byte) salt in the same change, matching this pin; WebCrypto (`saltLength: 32`) and Python (`salt_length = 32`) then verify natively. This is a migration action, not a value to read off the current default.

**Operator-address binding (pinned — cross-kernel byte-agreement depends on this).** `operator = base64url_nopad(SHA-256(M))`, where **M** is the base64url-decoded octet string of the record's `public_key.n` — the RSA modulus as an unsigned big-endian integer, **used exactly as decoded: no leading-zero octet is stripped or added, and the bytes are not re-padded to the key/modulus size.** `SHA-256(M)` is hashed over those raw octets directly, and `base64url_nopad` is RFC 4648 §5 base64url with trailing `=` padding removed (the Arweave wallet-address form). The kernel derives this from the embedded `public_key.n` and MUST reject the record if it does not equal `payload.operator` — this is what makes the embedded key self-describing (principle 6): the signature is bound to a specific Arweave wallet with no roster lookup. Both reference kernels implement exactly this (`deriveOperatorAddress` in `crypto.ts` — `bytesToBase64Url(SHA-256(base64UrlToBytes(n)))`; `derive_operator_address` in `rsa_pss.py` — `base64url(hashlib.sha256(base64url_decode(n)).digest())`); a third kernel MUST hash the decoded `n` octets as-is, since any leading-zero normalization would change the address.

**RSA public exponent (pinned — security-critical).** The operator key's public exponent MUST be **65537** (`public_key.e` = `AQAB`); a verifier MUST reject any attestation whose key has a different exponent (treat as an invalid signature — a failed attestation, exit 1). This is **load-bearing for the modulus-only address binding above**: the binding commits to `n` alone, which is safe only because `e` is fixed by the Arweave-wallet convention. Without this check, `e = 1` makes RSA verification the identity (`s¹ mod n = s`), so an attacker constructs a valid-looking RSA-PSS signature from a *victim operator's public modulus* with **no private key** — and the address binding still matches, since it never covered `e`. Both reference kernels enforce `e == 65537` in the RSA-PSS verify (`crypto.ts` / `rsa_pss.py`); a third kernel MUST do the same (many RSA libraries, incl. WebCrypto/OpenSSL, accept `e = 1` on import).

### 3.4 Migration note — breaking change for ar-io-verify

This is a **breaking change to the ar-io-verify issuer's attestation signature**, and it is intentional and time-sensitive:

- **Canon.** The shipped issuer signs over a **custom deep-sorted-key JSON canon**, not RFC 8785. This pass moves attestations to **JCS**, so the kernel verifies them with its existing canonicalizer (no second canon to maintain forever). Because the canon changes, the signature bytes change — **every attestation re-signed under this spec is incompatible with a verifier expecting the old canon, and vice-versa.**
- **Field names / case.** The shipped payload is `camelCase` (`attestedAt`, `blockHeight`, `dataHash`, `dataSize`, `blockTimestamp`, `ownerAddress`, `signatureVerified`, `txId`, `operator`, `gateway`, `version`). This spec uses `snake_case` to match the family. Since the signature breaks on the canon change regardless, `snake_case`-aligning is nearly free here and avoids a `camelCase` island the kernel would special-case (contrast [`evidence-bundle.md` §5](evidence-bundle.md), where `camelCase` was kept *only* to avoid rewriting a shipped, unbroken signature — that rationale does not apply once the signature breaks). Case-alignment is flagged as a migration sub-decision (Appendix A5).
- **Why now.** ar-io-verify is pre-launch (its HEAD predates the family standardization), so **few or no legacy attestations exist**. Migrating before the export ships is far cheaper than teaching the kernel a second canon permanently. This is the highest-leverage decision in the pass.
- **New fields.** `subject_ref` (§3.2), `signature_alg` (never emitted today — the alg is implicit), and `level` promoted into the signed payload.

## 4. The kernel verdict object (verdict-JSON)

The verdict object is the canonical result every renderer, the report/PDF, and the verify API consume. It is **recomputed** by the kernel from the source bundle + embedded attestations (§5); the copy cached in `body.kernel_verdict` is a rendering convenience only.

Field names are `snake_case` (family/spec-canonical). The shipped TS kernel's result type currently emits `camelCase` (`onChainOk`, `contentOk`, `CheckpointResult`); the mapping is 1:1 and the case-alignment of the shipped result type is flagged in Appendix A5. The object is **not** signed wire — it is a computed contract — so aligning it is non-breaking to any anchored artifact.

### 4.1 Structure

```json
{
  "schema_version": "ario.evidence.verdict/v1",
  "status": "verified",
  "summary": "Source bundle verified (412 events across 11 checkpoints); 22 operator attestations valid; on-chain confirmed on 2/2 gateways.",
  "counts": { "verified": 412, "failed": 0, "undetermined": 0 },
  "as_of": "2026-07-15T18:00:00.000Z",
  "events": [
    {
      "event_id": "…",
      "signature_ok": true,
      "payload_bound": true,
      "inclusion_ok": true,
      "content_ok": null,
      "status": "verified"
    }
  ],
  "checkpoints": [
    {
      "checkpoint_tx_id": "<arweave-txid>",
      "merkle_root_ok": true,
      "on_chain": {
        "rollup": "confirm",
        "on_chain_ok": true,
        "per_gateway": [
          { "gateway": "https://g1.example", "outcome": "confirm",    "block_height": 1512345 },
          { "gateway": "https://g2.example", "outcome": "unreachable" }
        ]
      },
      "attestations": [
        {
          "operator": "<wallet address>",
          "gateway": "https://operator-gateway.example",
          "signature_ok": true,
          "operator_address_bound": true,
          "data_hash_bound": true,
          "level": 3,
          "subject_ref_ok": null
        }
      ]
    }
  ],
  "custody_chain": null
}
```

- **`status`** is the shared 6-state family enum ([`evidence-bundle.md` §3](evidence-bundle.md)): `verified` | `partial` | `pending` | `failed` | `not_found` | `mixed`. No "safe."
- **`counts`** rolls up `events[]` (+ checkpoint attestations) into `verified` / `failed` / `undetermined`.
- **`events[]`** — per source-bundle event: `signature_ok` (envelope Ed25519), `payload_bound` (`true` bound, `null` when the committed record is withheld — "signature-valid, semantics-undetermined", never a silent pass), `inclusion_ok` (RFC 9162 Merkle inclusion against the checkpoint root), `content_ok` (§4.3), and a per-event `status`.
- **`checkpoints[]`** — per source-bundle checkpoint: `merkle_root_ok` (committed root == recomputed root), `on_chain` (§4.2), and `attestations[]` (each embedded operator attestation bound to this checkpoint: `signature_ok` RSA-PSS, `operator_address_bound` per §3.3, `data_hash_bound` the attestation `data_hash` == the checkpoint's committed content hash, `level`, `subject_ref_ok` §4.3-style tri-state).
- **`custody_chain`** — `true` | `false` | `null` when the prior export(s) were / were not supplied (§2.3).

### 4.2 Per-gateway on-chain outcomes (G2)

The single `on_chain_ok: boolean|null` per checkpoint is **replaced** by a per-gateway outcome array. On-chain re-fetch resolves each source `checkpoint_tx_id` against each configured gateway and records that gateway's individual outcome:

| `outcome` | Meaning |
|---|---|
| `confirm` | The gateway returned the checkpoint tx and its on-chain bytes match the committed record (root / content hash). |
| `mismatch` | The gateway returned the tx but the on-chain bytes disagree with the committed record — **a finding** (tamper / wrong tx). |
| `unreachable` | The gateway did not respond, timed out, or returned no such tx. Not a mismatch — an availability gap. |

**Rollup rule (worst-finding-wins, then best-evidence):** `mismatch` if **any** gateway is `mismatch`; else `confirm` if **any** gateway is `confirm`; else `unreachable` (all gateways unreachable). The derived `on_chain_ok` (retained for backward-compat with the collapsed field): `false` on rollup `mismatch`, `true` on rollup `confirm`, `null` on rollup `unreachable`. A checkpoint with `mismatch` drives the verdict to `failed`; a checkpoint whose only signal is `unreachable` is `undetermined` (exit 3, §5), never `failed`. Offline-only verification (no gateways configured) omits `per_gateway` and sets `on_chain: null` — the source bundle's inclusion proofs still verify from the file alone.

### 4.3 `content_ok` tri-state

`content_ok` is per-event (and `subject_ref_ok` per-attestation) and is **tri-state**:

- **`true`** — disclosed raw bytes (in-body `events[].content` or a `--logs` side input, [`evidence-bundle.md` §5.1](evidence-bundle.md)) hash to the committed `content_hash`.
- **`false`** — disclosed bytes **mismatch** the committed hash (or an in-body-vs-side-input disagreement). **Fails** the event and the rollup.
- **`null`** — **content-blind**: no content disclosed, or the content was stripped at a hosted edge (D11/G7 content-blind enforcement returns `content_ok: null` plus a client-side by-reference pointer), or there is no committed `content_hash` to bind. Undetermined, **not failed** — the correct outcome for minimal-disclosure evidence. (The by-reference resolution seam that would turn a hosted `null` into a `true`/`false` is reserved in this schema but not built — it is gated on T9 hosted retention; Appendix A6.)

### 4.4 JSON-Schema fragment (versioned)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://ar.io/specs/ario.evidence.verdict/v1.json",
  "title": "ario.evidence verdict object v1",
  "type": "object",
  "required": ["schema_version", "status", "counts", "events", "checkpoints"],
  "additionalProperties": false,
  "properties": {
    "schema_version": { "const": "ario.evidence.verdict/v1" },
    "status": { "enum": ["verified", "partial", "pending", "failed", "not_found", "mixed"] },
    "summary": { "type": "string" },
    "counts": {
      "type": "object",
      "required": ["verified", "failed", "undetermined"],
      "additionalProperties": false,
      "properties": {
        "verified": { "type": "integer", "minimum": 0 },
        "failed": { "type": "integer", "minimum": 0 },
        "undetermined": { "type": "integer", "minimum": 0 }
      }
    },
    "as_of": { "type": "string", "format": "date-time" },
    "events": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["signature_ok", "inclusion_ok", "status"],
        "additionalProperties": false,
        "properties": {
          "event_id": { "type": "string" },
          "signature_ok": { "type": "boolean" },
          "payload_bound": { "type": ["boolean", "null"] },
          "inclusion_ok": { "type": "boolean" },
          "content_ok": { "type": ["boolean", "null"] },
          "status": { "enum": ["verified", "partial", "pending", "failed", "not_found"] }
        }
      }
    },
    "checkpoints": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["checkpoint_tx_id", "merkle_root_ok"],
        "additionalProperties": false,
        "properties": {
          "checkpoint_tx_id": { "type": "string" },
          "merkle_root_ok": { "type": "boolean" },
          "on_chain": {
            "type": ["object", "null"],
            "additionalProperties": false,
            "properties": {
              "rollup": { "enum": ["confirm", "mismatch", "unreachable"] },
              "on_chain_ok": { "type": ["boolean", "null"] },
              "per_gateway": {
                "type": "array",
                "items": {
                  "type": "object",
                  "required": ["gateway", "outcome"],
                  "additionalProperties": false,
                  "properties": {
                    "gateway": { "type": "string" },
                    "outcome": { "enum": ["confirm", "mismatch", "unreachable"] },
                    "block_height": { "type": "integer", "minimum": 0 }
                  }
                }
              }
            }
          },
          "attestations": {
            "type": "array",
            "items": {
              "type": "object",
              "required": ["operator", "signature_ok", "operator_address_bound", "data_hash_bound"],
              "additionalProperties": false,
              "properties": {
                "operator": { "type": "string" },
                "gateway": { "type": "string" },
                "signature_ok": { "type": "boolean" },
                "operator_address_bound": { "type": "boolean" },
                "data_hash_bound": { "type": "boolean" },
                "level": { "enum": [1, 2, 3] },
                "subject_ref_ok": { "type": ["boolean", "null"] }
              }
            }
          }
        }
      }
    },
    "custody_chain": { "type": ["boolean", "null"] }
  }
}
```

### 4.5 Deterministic verdict rollup (cross-kernel critical)

The verdict object's derived fields — every per-event `status`, the `counts`, and the top-level `status` — are **deterministic functions of the recomputed dimensions**, pinned here so an independent kernel derives byte-identical rollups. Both reference kernels implement exactly these rules (TS `buildVerdictObject` / `verifyExportBody`; Python `_build_verdict_object` / `_verify_export_body`); the implementations agree and are authoritative.

**Per-event `status`** (`events[].status`). Call an event *gate-passing* iff `signature_ok` (its envelope Ed25519 signature verified) **and** `inclusion_ok` (RFC 9162 inclusion reconstructed its checkpoint root) **and** it bound to a present checkpoint **and** `content_ok !== false` (a disclosed-content **mismatch** is the only content state that fails the gate; `null` and `true` do not). Then:

- `failed` — not gate-passing.
- `partial` — gate-passing **and** `payload_bound == null` (the committed record was withheld: signature-valid, semantics-undetermined).
- `verified` — gate-passing **and** `payload_bound != null`.

The per-event enum the impl emits is **exactly `{verified, partial, failed}`** — **never `mixed`, `pending`, or `not_found`.** (`mixed` is a batch/collection-level family state, not a per-event value; the §4.4 schema's per-event `status` enum is a forward-compatible superset, but a v1 export emits only those three.)

**Per-attestation pass/fail.** An embedded attestation *passes* iff `signature_ok` (RSA-PSS-SHA-256 over `JCS(payload)`, §3.3) **and** `operator_address_bound` (§3.3) **and** `data_hash_bound` (§5 step 6c — which also implies its `checkpoint_tx_id` resolved to a present source checkpoint: an unresolved checkpoint leaves `data_hash_bound` false, so the three visible dimensions fully determine the outcome). **`subject_ref_ok` is NOT a gate** (§3.2): a `null` or well-formed-but-unchecked `subject_ref` never changes an attestation's pass/fail. There is **no separate per-checkpoint attestation status field**: attestations are grouped under `checkpoints[].attestations[]` by `checkpoint_tx_id` and feed `counts` and the export `status` directly, not a per-checkpoint rollup value.

**`counts`** (always emitted; three integer members, each ≥ 0). Tallies **events and attestations only** — checkpoints and the on-chain dimension are not counted here:

- each event, by its per-event `status`: `verified` → `verified++`, `partial` → `undetermined++`, `failed` → `failed++`;
- each attestation: pass → `verified++`, fail → `failed++` (an attestation is only ever `verified` or `failed`, never `undetermined`).

Because the impl always emits `counts` with all three members, the §4.4 schema requires them (and `counts` itself) — a conforming kernel MUST emit all three.

**Top-level / export `status`** (the verdict object's `status`, which drives the CLI exit). Derived **after all recomputation** (source verdict at §5 step 4 *and* the embedded attestations at §5 step 6 — see the §5 step-5 ordering note):

- `failed` — the source-bundle linkage broke (`source_bundle_hash` mismatch), the deterministic verdict agreement broke (§5 step 5), the recomputed **source** status is `failed` or `malformed`, **or** any embedded attestation failed.
- `partial` — none of the above **and** the recomputed source status is `partial` (a withheld record → still exit 0; an all-`unreachable` on-chain checkpoint → exit 3, keyed off the propagated `unreachable` note).
- `verified` — otherwise.

A v1 export therefore emits a top-level `status` of **exactly `{verified, partial, failed}`** (never `pending`/`not_found`/`mixed`). A **structurally unrenderable** export (missing required body field, unparseable RSA key, unsupported per-record `signature_alg`) is a distinct **result-level `malformed`** that carries **no** verdict object and maps to **exit 2** — it is not one of the verdict `status` values.

**Exit-code mapping** (the full table is §5 step 9): `verified`, or `partial` from a withheld record → **0**; `failed` → **1**; result-level `malformed` → **2**; `partial` whose only shortfall is an unreachable gateway or an offline-unavailable `source_bundle_ref` → **3**.

## 5. Offline verification algorithm

The algorithm a kernel runs on `proof verify <export>` — self-contained offline when the source bundle is inline (§2.2). It composes the existing single-envelope + Merkle kernel primitives ([`architecture.md` §8](architecture.md)) plus the one new primitive (RSA-PSS record verify, §7). Steps are ordered so nothing is trusted before the wrapper signature is checked.

1. **Parse & dispatch.** Parse the wrapper. Reject an unknown `spec_version` **major** → exit 2. Confirm `body_type == ario.evidence.export/v1`; an unrecognized `body_type` is not this algorithm (the kernel's generic wrapper handler yields `partial`, [`evidence-bundle.md`](evidence-bundle.md)).
2. **Wrapper integrity + signature.** Recompute `SHA-256(JCS(body))`; reject on mismatch vs `body_hash`. Confirm wrapper `signature_alg == ed25519`. Strip `signature`, `JCS`, verify Ed25519 against `public_key`. Any failure here → **exit 1** (the export is tampered or not issuer-signed). *No new crypto — the shipped kernel does this today.*
3. **Source-bundle linkage.** If inline: recompute `SHA-256(JCS(source_bundle))` and reject on mismatch vs `source_bundle_hash`. If `source_bundle_ref` (out of v1 scope, §2.4): the v1 offline verifier **does NOT auto-fetch** it — the referenced bytes must be co-delivered as a side input. When they are absent, the source-dependent checks (steps 4–6) are `undetermined` → **exit 3** (not a failure). When co-delivered (or when an out-of-v1 deployment fetches under the SSRF bounds of §2.4), hash the **exact received bytes** and compare to `source_bundle_hash`; a mismatch → **exit 1**.
4. **Recompute the source verdict.** Run the existing `verifyEvidenceBundle` path over `source_bundle`: for each event, Ed25519 envelope signature + `payload_hash` binding + RFC 9162 inclusion against its checkpoint's Merkle root; for each checkpoint, committed-root recompute; per-event `content_ok` (§4.3); optional on-chain per-gateway re-fetch (§4.2). This yields a fresh verdict object (§4).
5. **Verdict agreement.** *(Ordering: although numbered 5, this comparison runs **after** the embedded attestations are verified — step 6 below — because the freshly recomputed verdict it compares includes the per-attestation dimensions. The verifier recomputes the full §4 verdict object first (the source dimensions from step 4 **and** every attestation from step 6, §4.5), then performs this agreement check; both reference kernels compute attestations, build the verdict, then compare, in that order.)* Compare the freshly recomputed verdict to the export's cached `body.kernel_verdict` **over the deterministic, offline-recomputable dimensions only** — per-event `signature_ok` / `payload_bound` / `inclusion_ok` / `content_ok`, per-checkpoint `merkle_root_ok`, and per-attestation `signature_ok` / `operator_address_bound` / `data_hash_bound` / `subject_ref_ok` — with `event_id` / `operator` retained only as identity anchors to align list items. A disagreement on those → **exit 1** (recompute-don't-trust, principle 3). **Every other field is EXCLUDED** from the comparison — `status`, `counts`, `summary`, `as_of`, `custody_chain`, the per-attestation `level` / `gateway`, and (load-bearing) the entire **on-chain per-gateway block (§4.2)**: the issuer records it online at compose time, but an offline verifier does no re-fetch and legitimately recomputes it as `null`, so comparing it would fail every honest offline export — the verifier's own on-chain outcomes fold in only at step 7. The displayed verdict is always the recomputed one.
6. **Embedded attestation records.** For each `body.attestations[]` record: (a) verify the **RSA-PSS-SHA-256** signature over `JCS(payload)` against the embedded `public_key` with the pinned parameters (§3.3) — *new primitive*; (b) recompute `base64url_nopad(SHA-256(public_key.n))` (over the exact decoded modulus octets, §3.3) and confirm it equals `payload.operator` (operator-address binding); (c) resolve `checkpoint_tx_id` to a present source checkpoint and confirm `payload.data_hash` equals `SHA-256(JCS(checkpoint.envelope))` for that checkpoint (`data_hash_bound`, §3.1); (d) if `payload.subject_ref` is present, confirm it is well-formed and (given a side-input subject) that `SHA-256(raw supplied subject bytes) == subject_ref.hash` (§3.2 — hashed as-is, no re-canonicalization), else `subject_ref_ok = null` — a present-but-malformed or side-input-absent `subject_ref` yields `subject_ref_ok = null` (surfaced, non-gating), never an exit-1 trigger. A broken RSA-PSS signature, a failed operator-address binding, or a `data_hash` that does not bind → **exit 1**.
7. **Fold in per-gateway on-chain outcomes.** Merge step 4's per-gateway outcomes (§4.2) into the verdict. Any checkpoint `mismatch` → **exit 1**. A checkpoint whose on-chain dimension is only `unreachable` (all gateways) contributes `undetermined`.
8. **Custody chain (optional).** If prior export(s) were supplied, verify the `previous_hash` link(s) (§2.3); a broken link → **exit 1**. Absent inputs → `custody_chain = null` (not a failure).
9. **Exit code.** Map the rollup:

| Exit | Meaning | Trigger |
|---|---|---|
| **0** | verified | Every in-scope check passed; verdict `status = verified` (or `partial`/`pending` with no failure and no undetermined blocking dimension, per the CLI's `mapStatusToExit`). |
| **1** | failed / tampered | A verification check failed: wrapper signature, `body_hash`, `source_bundle_hash`, verdict disagreement, forged/mis-bound attestation, on-chain `mismatch`, disclosed-`content` mismatch, or a broken custody link. |
| **2** | malformed / usage error | The input could not be verified *as an export at all*: unparseable, unknown `spec_version` major, unrecognized `body_type`, unsupported `signature_alg`, unparseable RSA key, or a missing required field — the verifier could not render a verdict. |
| **3** | undetermined | A network-dependent check could not complete — specifically, no gateway was reachable for an on-chain re-fetch, or a `source_bundle_ref`/`--logs`/subject side input was unavailable. Distinct from `mismatch` (exit 1). An offline invocation over a fully-inline export never returns 3. |

This preserves the shipped CLI's `0/1/2/3` contract and its exit-3-keyed-to-unreachable-gateway behavior.

### 5.1 What the kernel must NEWLY implement

Net-new work per language kernel (Ed25519 wrapper handling and the envelope/Merkle path already exist in TS; the whole evidence layer is new in Python):

**TS (`@ar.io/proof`):**
- `ario.evidence.export/v1` `body_type` dispatch → a `verifyExportBody` (today `evidence.ts` dispatches only the anchor-trace body; an unknown body_type falls through to `partial`).
- An **RSA-PSS-SHA-256 verify primitive** (`crypto.ts` is Ed25519-only). Via WebCrypto `RSASSA-PSS` with the pinned salt length (§3.3). New crypto surface + operator-address derivation (`base64url_nopad(SHA-256(public_key.n))`, §3.3).
- Reuse the existing JCS canonicalizer for the attestation records (no new canon).
- **Per-gateway on-chain outcomes:** replace the single `onChainOk` in the checkpoint result with the `on_chain.per_gateway[]` array (§4.2) and the derived collapsed field — in both the anchor-trace path and the agent-proof path — and update the rollup / CLI render.
- Extend the CLI/verify result to emit the §4 verdict object (with `content_ok` tri-state and per-gateway outcomes) for exports.

**Python (`ar-io-proof`):**
- **An `ario.evidence/v1` verifier — from scratch.** The Python kernel has **no** evidence-bundle verifier today (it verifies only `ario.agent.proof/v1`). Reaching "TS and Python agree byte-for-byte on export vectors" requires first building the Python evidence-bundle verifier (envelope + Merkle + verdict recompute + `content_ok`), then the export body on top. This is the largest single unscoped item.
- An **RSA-PSS-SHA-256 verify primitive** (`verify.py` is PyNaCl Ed25519-only) — adds the `cryptography` dependency (a new package dependency, not a flag), with the same pinned parameters as TS + issuer.
- Per-gateway on-chain outcomes mirrored in the Python evidence verifier.

**Both:** the RSA-PSS parameters (salt length especially) MUST be pinned identically across issuer + both kernels; a cross-kernel unit that verifies the same fixed-key attestation the issuer's `signPayload` produced is the parity gate for the highest-risk seam (§7 / Appendix A4).

**Out of the kernel (issuer/producer side, for orientation — not a kernel deliverable):** the **composer** (a job whose input is `{source bundle, sidecar list}` → verify → collect operator attestations → assemble the export) and a **`proof export` CLI subcommand** are issuer/runtime work per [`architecture.md` §5–§7](architecture.md); the kernel only gains *verify* for the new body.

## 6. Trust model

Every consumer MUST hold these (they extend [`evidence-bundle.md` §6](evidence-bundle.md)):

- **Self-verifying offline.** Ed25519 issuer key verifies the wrapper; embedded RSA operator keys verify the attestations; the inline source bundle verifies from its own embedded keys. No service call at verification time.
- **Two distinct signers, two distinct roles.** The **wrapper** proves "the issuer composed and signed this export"; each **attestation** proves "this operator's wallet attested this tx." Neither proves the *other's* claim, and neither is trusted transitively — the kernel checks both directly.
- **Gateway untrusted.** `gateway` (wrapper and per-attestation) is delivery/observation surface only. On-chain re-fetch is a cross-check that yields per-gateway `confirm`/`mismatch`/`unreachable` (§4.2), never a trusted oracle; disagreement across gateways is a finding.
- **Verdict recomputed, not trusted** (principle 3). `body.kernel_verdict` disagreeing with the recomputed verdict ⇒ failed/tampered.
- **Operator identity binds to a wallet, not (yet) to a GAR gateway.** Offline verify proves the attesting key's Arweave wallet address (§3.3). Binding that wallet to a *named, staked gateway operator* requires a GAR snapshot — online state — and is **warn-not-fail** enrichment in v1 (Appendix A3), never an offline verification gate.
- **No status means "safe."** Renderers say *"verified against its anchored record"* / *"attested by operator X's wallet,"* never *"safe/approved."*

## 7. Governance, corpus & backward-compatibility

### 7.1 Where this rides governance — the decision

**Decided: a new spec file, `evidence-export.md`, in `ar-io-proof/specs/`, registered as an additive minor.** The new-file-vs-inline question is settled (rationale below); this is not an open recommendation. Ratification lands three things in one PR (#19) ([`governance.md` §2](governance.md), additive = minor, no 30-day RFC):

1. This file, `evidence-export.md`, at status `ratified` (BDFL-ratified 2026-07-15; RFC-2119 keywords binding on merge).
2. A one-row add to [`evidence-bundle.md` §5](evidence-bundle.md)'s per-producer table registering `body_type` `ario.evidence.export/v1` (issuer, `signature_alg` `ed25519` wrapper / embedded `rsa-pss-sha256` records), pointing to this file as the authoritative spec — exactly the shape of the `ario.anchor.trace/v1` registration.
3. A [`governance.md` §7](governance.md) amendment-log row.

**Why a new file, not an inline `evidence-bundle.md` §5.x subsection** (as `ario.anchor.trace/v1` got): the anchor-trace body was a self-contained serialization that inlined cleanly. This export carries a **full offline verification algorithm** (§5), a **versioned verdict-JSON schema** (§4), and an **attestation-record sub-spec with its own canon migration** (§3) — and it introduces a **new kernel primitive** (RSA-PSS). Inlining all of that would unbalance `evidence-bundle.md`. The precedent is [`envelope-spec.md`](envelope-spec.md) as the family contract with `artifact.md` holding byte-level profile detail: the wrapper stays thin; the heavy body detail gets its own discoverable home with an "authoritative spec" pointer.

### 7.2 Corpus implications

A **corpus minor bump `test-vectors-v1.2` → `test-vectors-v1.3`** is **planned to land with the kernel/corpus PR (#21), not this spec PR (#19).** The vectors and their `CORPUS-v1.md` manifest are generated conformance artifacts ([`governance.md` §4](governance.md); generated, never hand-edited, CORP1), so they land alongside the kernel that generates and gates them — #19 *declares and plans* the bump; #21 *commits* it. The planned **signed-export vectors**:

- **One positive:** kernel verdict + inline source anchor-trace bundle + ≥2 embedded RSA-PSS operator attestations + `previous_hash` custody + per-gateway on-chain outcomes (a `confirm`/`unreachable` mix) + one disclosed-raw-log event (`content_ok = true`) + one `subject_ref`.
- **One tampered vector per failure class:** wrapper-signature break, `body_hash` mismatch, `source_bundle_hash` mismatch, verdict disagreement, forged attestation RSA-PSS, operator-address-binding break, checkpoint on-chain `mismatch`, disclosed-`content` mismatch, `subject_ref` tamper.

The cross-kernel harness (`generate_cases.py` / `run.sh`) extends to drive `verifyEvidenceBundle`/export across **TS + Python** (Go later, P1) and assert **byte-for-byte identical verdicts** — the gate that forces the Python evidence verifier (§5.1) into existence and pins the RSA-PSS salt-length seam. That harness extension ships with the same corpus/kernel PR (#21). Once it lands, every conformant downstream re-pins `test-vectors-v1.3` as its own explicit act (K3); `test-vectors-v1.2` remains valid for consumers that do not need exports.

### 7.3 Backward-compatibility statement

- **Wrapper bytes unchanged.** `ario.evidence/v1` is not modified — no new `spec_version`, no field change. Existing `ario.anchor.trace/v1` and `ario.agent.proof/v1` bundles verify unchanged.
- **New primitive is default-absent.** RSA-PSS verify runs **only** when a body embeds `attestations[]` with `signature_alg: rsa-pss-sha256`. No existing vector's bytes change; adding the primitive is therefore **additive (minor)**, not a byte-affecting major.
- **`subject_ref` is additive-optional.** Absent on every pre-D8 attestation; its addition breaks nothing.
- **Per-gateway outcomes are additive** to the verdict object (a computed contract, not signed wire), with the collapsed `on_chain_ok` retained as a derived field for existing consumers.
- **The one breaking change is scoped to the issuer's own attestation signatures** (custom canon → JCS, §3.4) — a **pre-launch, issuer-internal** break that affects **no anchored family artifact and no ratified family contract**. It is not a family major bump.

## 8. Decisions ratified in this pass

| # | Decision | Resolution |
|---|---|---|
| A1 | Export shape: new `body_type` vs additive section on `ario.anchor.trace/v1` | **New issuer-owned `body_type` `ario.evidence.export/v1`.** Preserves the producer/issuer role boundary ([`architecture.md` §5](architecture.md)) and the registry philosophy "a new producer adds a `body_type`, not a wrapper change" ([`evidence-bundle.md` §2](evidence-bundle.md)); keeps `ario.anchor.trace/v1` byte-stable. The export references the source bundle by hash + inline (§2.4). |
| A2 | Operator attestations: fold into the body vs embedded records | **Embedded records** (`body.attestations[]`), each RSA-PSS-signed by the operator's wallet key, verified individually by the kernel. Isolates the unavoidable RSA-PSS work to record verification. |
| A3 | Wrapper `signature_alg` | **Ed25519**, signed by an issuer family key — kernel-ready today, zero new wrapper crypto. RSA-PSS appears only inside embedded records. |
| A4 | Attestation-record canonicalization | **RFC 8785 JCS**, migrating the issuer off its custom sorted-key canon (§3.4) so the kernel reuses its existing canonicalizer. Done now, pre-launch, before legacy attestations accrue. |
| A5 | `subject_ref` (D8) | **Additive-optional** `{hash, type}` on the attestation payload (§3.2). Absent ⇒ unbound. Defined once, in both the issuer `buildAttestationPayload` and the kernel record verifier. |
| A6 | On-chain outcome shape (G2) | **Per-gateway `confirm`/`mismatch`/`unreachable` per checkpoint** (§4.2), replacing the single `onChainOk`, with the collapsed field retained as derived (backward-compat). |
| A7 | RSA-PSS-in-kernel | **Accepted as net-new kernel capability** in TS and Python (§5.1) — a new primitive + a new Python dependency + a from-scratch Python evidence verifier, not a `signature_alg` flag flip. |

## 9. Phased rollout

| Phase | What ships | Repo | Effort |
|---|---|---|---|
| **0 — Ratify** | This spec + the `evidence-bundle.md` §5 registration + the `governance.md` amendment row. §8 decisions settled. | ar-io-proof | M (agreement) |
| **1 — Kernel export-verify** | `verifyExportBody` + RSA-PSS primitive + per-gateway outcomes in `@ar.io/proof`; the from-scratch Python evidence + export verifier; `test-vectors-v1.3` positive+tampered vectors; cross-kernel harness extension (TS+Python byte-agreement). | ar-io-proof | L |
| **2 — Issuer migration + composer** | Migrate attestations to JCS (§3.4); the composer job (`{source bundle, sidecars}` → export) + `proof export` CLI. | ar-io-verify / ar-io-anchor | M |
| **3 — Go/WASM parity** | `ario.evidence/v1` + export verify in the Go kernel (vendored envelope-only today); WASM for the browser renderer. | ar-io-proof / ar-io-agent | M–L |

---

*BDFL-ratified 2026-07-15 (Phil Mataras, per [`governance.md`](governance.md) §1), implementing the OQ-1+D8 shape; landing via PR #19 to `ar-io-proof/specs` as an additive minor (§2), RFC-2119 keywords binding on merge. Revisit when the issuer's attestation schema or the source-bundle body changes.*

---

# Appendix — deferred & tracked decisions

*Non-normative. Dispositioned at BDFL ratification (2026-07-15); kept for the reviewer trail.*

**Settled at ratification (2026-07-15):** A1 name = `ario.evidence.export/v1` · A2 file-by-default, anchoring optional · A4 RSA-PSS salt resolved (§3.3 — issuer migrates `AUTO` → `DIGEST`=32) · A5 `snake_case`-align the migrated attestation record + verdict · source bundle inline-by-default · operator key embedded as JWK `{kty,n,e}`.

**Tracked — non-blocking for ratification:**

- **A3 — GAR operator-identity binding.** Warn-not-fail in v1; online enrichment only; depends on T10 `producer:enroll` for tenant binding.
- **A6 — `content_ok` by-reference.** The schema reserves `content_ok: null` for content-blind hosted verification; the by-reference resolution seam is **gated on T9 hosted retention** and is not built for T8 V1.
- **A7 — TS accept-set omits `ario.mlflow/v1`** (vs [`envelope-spec.md`](envelope-spec.md) A5's "all three kernels admit three"). Does not affect exports; reconcile the TS accept-set *or* amend A5's wording as a separate minor.
- **A8 — issuer wrapper-key trust root** (api-guard roster vs on-chain attestation vs key-transparency, per [`envelope-spec.md` §12](envelope-spec.md)). The one open decision; **due before the first external export**, not before merge.
