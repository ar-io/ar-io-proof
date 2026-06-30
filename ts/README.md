# @ar.io/proof

Verify [ar.io verification-stack](https://github.com/ar-io) provenance records — **with no ar.io code or service in the trust path**.

This is the TypeScript verification kernel for the *Verifiable Event Envelope* family: the signed JSON records that tools like the [`ariod` verification agent](https://github.com/ar-io/ar-io-agent) and the [MLflow plugin](https://github.com/ar-io/ar-io-mlflow) anchor permanently to Arweave. Given an envelope (fetched from any Arweave gateway), this package answers: *is it authentic, and does it commit to the bytes I'm holding?*

- **RFC 8785 (JCS)** canonicalization
- **SHA-256** payload binding (WebCrypto)
- **Ed25519** signature verification ([`@noble/ed25519`](https://github.com/paulmillr/noble-ed25519))
- **RFC 9162** binary Merkle inclusion proofs (checkpoint leaves)
- Zero config, two small dependencies, ESM, browser + Node ≥ 20

## Install

```bash
npm install @ar.io/proof
```

## Verify an envelope

Fetch the raw transaction from any Arweave gateway and verify it client-side:

```ts
import { verifyEnvelope } from "@ar.io/proof";

const env = await (await fetch("https://arweave.net/raw/<tx_id>")).json();
const result = await verifyEnvelope(env);

result.ok;            // spec_version + payload_hash + Ed25519 all passed
result.signatureOk;   // Ed25519 over the signed scope, against env.public_key
result.payloadHashOk; // SHA-256(JCS(payload)) === env.payload_hash
result.errors;        // [] when ok — machine-readable reasons otherwise
```

`verifyEnvelope` never throws on hostile input — a malformed envelope (or a lying gateway) yields `ok: false` with reasons, not an exception.

## Bind an envelope to bytes you hold (reverse provenance)

The check that defeats a lying gateway: Arweave *tags* are unsigned search hints, so after finding a candidate envelope, confirm it actually commits to your artifact's hash:

```ts
import { sha256Hex, verifyEnvelope, contentHashes } from "@ar.io/proof";

const myHash = await sha256Hex(fileBytes); // 64-char lowercase hex

const result = await verifyEnvelope(env, myHash);
result.contentHashOk; // true ⇔ the envelope commits to exactly these bytes
result.contentRole;   // how it commits: e.g. the registered baseline,
                      // an observed (tampered) hash, …

contentHashes(env);   // all content hashes an envelope commits to, by event type
```

## Verify a whole trace bundle — one command

The `@ar.io/anchor` SDK hands a producer a set of `InclusionReceipt`s and can serialize them into one portable, self-verifying `ario.evidence/v1` bundle (`body_type: ario.anchor.trace/v1`). Verify the entire bundle — every event's signature + payload binding + Merkle inclusion, all offline — with the bundled CLI:

```bash
npx @ar.io/proof verify trace-bundle.json
# also re-fetch each checkpoint on-chain to confirm it's anchored:
npx @ar.io/proof verify trace-bundle.json https://arweave.net,https://permagate.io
```

It prints a per-event + rollup verdict and exits on a pinned code — `0` verified · `1` a real failure (bad signature / tamper / broken inclusion) · `2` malformed bundle · `3` gateway-unavailable when an on-chain re-fetch was requested. The producer's asserted `verdict` is shown but **never trusted** — the displayed verdict is always recomputed from the body. The same CLI also verifies the agent's `ario.agent.proof/v1` inclusion bundle (it sniffs `spec_version`), so one command covers anchor + agent.

> The `verify` CLI is live in `@ar.io/proof` ≥ 0.2.2 — `npx @ar.io/proof verify <bundle> [gateways]`. `verifyEvidenceBundle` is the programmatic API.

Programmatically:

```ts
import { verifyEvidenceBundle } from "@ar.io/proof";

const bundle = JSON.parse(await fs.readFile("trace-bundle.json", "utf8"));
const result = await verifyEvidenceBundle(bundle, { gateways: ["https://arweave.net"] });

result.status;       // "verified" | "partial" | "failed" | "malformed" (recomputed)
result.signatureOk;  // wrapper Ed25519 signature
result.bodyHashOk;   // body_hash === SHA-256(JCS(body))
result.checkpoints;  // per-checkpoint envelope / merkle-root / on-chain results
result.events;       // per-event signature / payload-binding / inclusion results
```

A withheld `record_bytes` (external commitment, record not disclosed) leaves that event's payload binding **undetermined** — surfaced, never failed (the bundle stays cryptographically sound).

### …including the raw logs, when the holder discloses them

The checks above prove the *stamps*. To also confirm a holder's **raw logs are the bytes whose hash was anchored**, the verifier closes the final `rawLog → content_hash` link: `SHA-256(disclosed bytes)` must equal the `content_hash` the event's record committed to.

A bundle a producer built with disclosure carries the bytes **in the signed body** (`events[].content`), so they're checked automatically — no flag, and the disclosure is itself covered by the wrapper signature:

```bash
npx @ar.io/proof verify trace-bundle.json          # in-body content verified inline
```

If the logs travel **alongside** a minimal bundle instead, pass them with `--logs` — a JSON object mapping `event_id` → bytes, where an even-length lowercase-hex string is read as hex and anything else as UTF-8 text:

```bash
npx @ar.io/proof verify trace-bundle.json --logs logs.json
```

Either way each event gains a `contentOk`: **`true`** match · **`false`** mismatch (the event *and* the rollup fail, exit `1`) · **`null`** undetermined — nothing disclosed, or no committed `content_hash` (a withheld record); never a failure, mirroring the payload-binding rule. The CLI prints a `logs ✓/✗/~` mark per event and a `logs: N/M disclosed verified` line.

Programmatically the same side input is `content`, keyed by `event_id` — a `Uint8Array` is used as-is, a `string` is hex:

```ts
const result = await verifyEvidenceBundle(bundle, {
  content: { [eventId]: rawLogBytes }, // Uint8Array, or a hex string
});
result.events[0].contentOk; // true | false | null
```

In-body `events[].content` (signed) takes precedence over the side input; if both are present for an event and disagree, the event fails.

## Verify a Merkle inclusion proof

Agents close daily checkpoints over per-cycle leaves (RFC 9162, §2.1 domain separation — not the Bitcoin duplicate-leaf variant). Verify a leaf's inclusion against an anchored root:

```ts
import { leafHash, verifyInclusion, hexToBytes } from "@ar.io/proof";

const ok = await verifyInclusion(
  await leafHash(leafBytes), // Uint8Array leaf hash
  leafIndex,                 // 0-based position
  totalLeaves,
  auditPath.map(hexToBytes), // sibling hashes, leaf → root
  hexToBytes(expectedRootHex),
);
```

## API

| Export | What it does |
|---|---|
| `verifyEnvelope(env, optionsOrContentHash?)` | The three load-bearing checks (spec-version registry, payload-hash recompute, Ed25519 over the signed scope) + optional content bind. Pass `{ payloadBytes }` for external-commitment envelopes. Returns `VerificationResult`. |
| `verifyEvidenceBundle(bundle, { gateways?, fetchImpl? })` | Verify a signed `ario.evidence/v1` / `ario.anchor.trace/v1` bundle: wrapper signature + `body_hash` + every checkpoint + every event's inclusion, offline (optional on-chain re-fetch). Returns `EvidenceBundleResult`. Powers the `npx @ar.io/proof verify` CLI. |
| `verifyAgentProofBundle(bundle, { gateways?, fetchImpl? })` / `isAgentProofSpec(v)` | Verify the agent's `ario.agent.proof/v1` inclusion bundle (artifact.md §10). |
| `contentHashes(env)` | The content hash(es) an envelope commits to, by event type — the reverse-provenance join keys. |
| `specVersionSupported(v)` | Fail-closed accept-check: `ario.agent/v1` and additive minors (`ario.agent/v1.<n>`). Unknown majors/profiles are rejected. |
| `jcs(value)` | RFC 8785 canonical JSON bytes. |
| `sha256Hex(bytes)` / `sha256Bytes(bytes)` | SHA-256 via WebCrypto. |
| `ed25519Verify(sig, msg, pubKey)` | Raw Ed25519 verification. |
| `leafHash` / `nodeHash` / `merkleRoot` / `auditPath` / `verifyInclusion` / `EMPTY_TREE_ROOT_HEX` | RFC 9162 binary Merkle tree primitives. |
| `utf8` / `bytesToHex` / `hexToBytes` | Encoding helpers. |
| `Envelope` / `VerificationResult` / `ContentRole` / `Subject` | Types. |

### Signed scope

The primary signature covers `JCS(envelope minus signature minus co_signatures)` ([envelope-spec](https://github.com/ar-io/ar-io-proof/blob/main/specs/envelope-spec.md) §2/§7.1). The reserved `co_signatures` carve-out lets countersignatures be added later without invalidating the primary signature.

## Why you can trust it (without trusting us)

Three **independent implementations** of this kernel exist — this package, the Python [`ar-io-proof`](https://pypi.org/project/ar-io-proof/) (PyPI), and the Go reference ([`ar-io-agent/pkg/proof`](https://github.com/ar-io/ar-io-agent/tree/main/pkg/proof), MIT-carved) — and every one is conformance-gated **byte-for-byte** in CI against the shared, frozen [`test-vectors-v1.2` corpus](https://github.com/ar-io/ar-io-proof/tree/main/test-vectors) (per-file SHA-256 pins). The [proof-checker web app](https://github.com/ar-io/ar-io-proof-checker) additionally runs this kernel and a WASM build of the Go reference against each other live, asserting identical verdicts across the corpus plus adversarial negatives.

That mutual gate is the point: anyone can verify ar.io provenance records with **no ar.io code in the trust path** — write your own verifier against the [public specs](https://github.com/ar-io/ar-io-proof/tree/main/specs) and the corpus will tell you if it's conformant.

## What this package deliberately does NOT do

- **Single-envelope scope.** Chain walking (`previous_hash`), checkpoint reconciliation, and gateway/transport logic are consumer-layer concerns composed above the kernel.
- **Provenance is history, not endorsement.** A verified envelope proves *these bytes have this signed, anchored history* — never "safe," "approved," or "currently in production."
- **Key identity is out-of-band.** The kernel proves the signature matches `env.public_key`; binding that key to a real-world identity is yours to establish.

## Requirements

ESM-only. Needs WebCrypto (`globalThis.crypto.subtle`): any modern browser, Node.js ≥ 20 (≥ 19 works), Deno, Bun, workers.

## License

MIT — verification must be open.
