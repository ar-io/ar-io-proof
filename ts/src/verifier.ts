// Independent client-side implementation of the ar.io agent envelope
// verification algorithm (ar-io-agent docs/artifact.md §6, docs/auditor-recipe.md
// Recipe 1). This is deliberately a second implementation of the same algorithm
// the Go agent runs — a second, conformance-tested verifier is what demonstrates
// the product's claim: verification needs no ar.io code in the trust path.
//
// Conformance is enforced by test/conformance.test.ts, which runs every
// ar-io-agent test vector through this code and asserts byte-for-byte agreement.

import canonicalize from "canonicalize";

import { ed25519Verify, sha256Hex, utf8 } from "./crypto.js";
import type { ContentRole, Envelope, VerificationResult, VerifyOptions } from "./types.js";

// Fail-closed accepted-profile registry (envelope-spec §2, artifact.md §13):
// exactly the accepted profile majors, nothing else. Minors within an accepted
// major ("ario.agent/v1.<minor>") are additive and tolerated — matching the Go
// reference kernel's semantics (pkg/proof isSupportedSpec) so the JS and
// WASM-Go verifiers agree. Accepting a new profile (e.g. ario.mlflow/v1) is a
// deliberate one-entry addition HERE and only here — mlflow-dialect behaviors
// (like its underscore-key strip) must never leak into the agent profile.
const ACCEPTED_SPEC_MAJORS = ["ario.agent/v1"];

// RFC 8785 (JCS) canonicalization. The `canonicalize` package is the reference
// JS implementation; correctness is pinned by the conformance vectors.
//
// Lone (unpaired) UTF-16 surrogates are REJECTED, never passed through: RFC
// 8785 requires well-formed UTF-8 output, JS strings can carry lone
// surrogates that `canonicalize` would emit as-is, and the sibling kernels
// cannot represent them (Python raises on encode; Go's JSON decoder replaces
// them). Reject-only is the one behavior all three kernels can share —
// pinned here and by the corpus lone-surrogate negative.
export function jcs(value: unknown): string {
  rejectLoneSurrogates(value);
  const canonical = canonicalize(value);
  if (typeof canonical !== "string") {
    throw new Error("jcs: canonicalize returned a non-string (input not JSON-serializable?)");
  }
  return canonical;
}

// Walk every string in the value (keys and values). The check must run on
// the INPUT: `canonicalize` escapes a lone surrogate as `\udXXX` text in its
// output, so the malformed code unit is invisible after serialization.
function rejectLoneSurrogates(value: unknown): void {
  if (typeof value === "string") {
    if (hasLoneSurrogate(value)) {
      throw new Error(
        "jcs: input contains a lone UTF-16 surrogate (not representable as UTF-8)",
      );
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const v of value) rejectLoneSurrogates(v);
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      rejectLoneSurrogates(k);
      rejectLoneSurrogates(v);
    }
  }
}

function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        i++; // valid pair
        continue;
      }
      return true; // high surrogate without a low
    }
    if (c >= 0xdc00 && c <= 0xdfff) return true; // low surrogate without a high
  }
  return false;
}

// Grammar-strict accept check (envelope-spec §2): `<major>` exactly, or
// `<major>.<minor>` where minor is `[0-9]+`. A non-numeric minor suffix is
// malformed, not a tolerated future version — matching the Python kernel's
// 0.1.1 semantics (ar-io-agent#13 closed the TS/Go fail-open lenience).
export function specVersionSupported(specVersion: string): boolean {
  if (typeof specVersion !== "string" || specVersion === "") return false;
  return ACCEPTED_SPEC_MAJORS.some((m) => {
    if (specVersion === m) return true;
    if (!specVersion.startsWith(`${m}.`)) return false;
    const minor = specVersion.slice(m.length + 1);
    return minor.length > 0 && /^[0-9]+$/.test(minor);
  });
}

// The content hash(es) an envelope commits to, by event type — the values a
// reverse lookup can match the user's in-browser file hash against.
//   asset_registered -> payload.hash            (the registered, known-good bytes)
//   asset_missing    -> payload.baseline.hash   (last known-good bytes that vanished)
//   tamper_detected  -> payload.observed.hash   (the tampered bytes that were flagged)
//                    -> payload.baseline.hash   (the known-good bytes it diverged from)
// Other event types commit to no asset content hash.
export function contentHashes(env: Envelope): { role: ContentRole; hash: string }[] {
  // Minimal-disclosure / external-commitment envelopes have no inline payload
  // (and no event_type) — they commit to no envelope-readable content hash.
  const p = (env.payload ?? {}) as {
    hash?: unknown;
    baseline?: { hash?: unknown };
    observed?: { hash?: unknown };
  };
  const asStr = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

  const out: { role: ContentRole; hash: string }[] = [];
  switch (env.event_type) {
    case "asset_registered": {
      const h = asStr(p.hash);
      if (h) out.push({ role: "asset", hash: h });
      break;
    }
    case "asset_missing": {
      const h = asStr(p.baseline?.hash);
      if (h) out.push({ role: "baseline", hash: h });
      break;
    }
    case "tamper_detected": {
      const obs = asStr(p.observed?.hash);
      if (obs) out.push({ role: "observed", hash: obs });
      const base = asStr(p.baseline?.hash);
      if (base) out.push({ role: "baseline", hash: base });
      break;
    }
  }
  return out;
}

// Verify an envelope — both binding modes (envelope-spec §3), one rule,
// mirroring the Python reference kernel exactly:
//
//   - envelope carries `payload`        → inline check: recompute
//     SHA-256(JCS(payload)) and compare to payload_hash
//   - caller supplies `payloadBytes`    → external check:
//     SHA-256(payloadBytes) must equal payload_hash
//   - both available                    → both must pass
//   - neither                           → payloadHashOk = null and the
//     verdict does NOT fail: "signature-valid, semantics-undetermined"
//     (§3.1/§6.2). The signature alone still proves who signed what bytes.
//
// Binding-mode detection is structural, not registry-driven: mode confusion
// is closed by the signed scope itself (an inline payload is INSIDE the
// signature, so stripping it to fake "external" — or injecting one to fake
// "inline" — breaks the signature).
//
// The second argument accepts the legacy `expectedContentHash` string form
// or a VerifyOptions object ({ payloadBytes, expectedContentHash }).
export async function verifyEnvelope(
  env: Envelope,
  optionsOrContentHash?: string | VerifyOptions,
): Promise<VerificationResult> {
  const opts: VerifyOptions =
    typeof optionsOrContentHash === "string"
      ? { expectedContentHash: optionsOrContentHash }
      : (optionsOrContentHash ?? {});
  const expectedContentHash = opts.expectedContentHash;
  const errors: string[] = [];

  // Guard a malformed input (null / non-object / array) up front — every field
  // access below assumes an object. A hostile gateway or a hand-edited report
  // can supply anything; treat it as "not verified," never a thrown exception.
  if (env === null || typeof env !== "object" || Array.isArray(env)) {
    return {
      ok: false,
      specVersionOk: false,
      payloadHashOk: false,
      signatureOk: false,
      contentHashOk: expectedContentHash === undefined ? null : false,
      contentRole: null,
      errors: ["envelope is not a JSON object"],
    };
  }

  const specVersionOk = specVersionSupported(env.spec_version);
  if (!specVersionOk) errors.push(`unsupported spec_version: ${JSON.stringify(env.spec_version)}`);

  // Check 1 — Payload binding (both modes; see header). Compare ONLY when
  // there is material to compare against, exactly like the Python reference:
  // a missing/malformed payload_hash with nothing to compare is left
  // undetermined (null), not failed — the signature still covers whatever
  // payload_hash is or isn't present. (envelope-spec §2 says a conformant
  // PRODUCER must emit payload_hash; the kernel-tighten of verifier-side
  // absence is a separate all-kernels question, escalated, not fixed
  // asymmetrically here.)
  const checks: boolean[] = [];
  if ("payload" in env && env.payload !== undefined) {
    try {
      const recomputed = await sha256Hex(utf8(jcs(env.payload)));
      checks.push(recomputed === env.payload_hash);
      if (recomputed !== env.payload_hash) {
        errors.push(
          `payload_hash mismatch: envelope=${env.payload_hash} recomputed=${recomputed}`,
        );
      }
    } catch (e) {
      checks.push(false);
      errors.push(`payload canonicalization failed: ${stringifyErr(e)}`);
    }
  }
  if (opts.payloadBytes !== undefined) {
    const external = await sha256Hex(opts.payloadBytes);
    checks.push(external === env.payload_hash);
    if (external !== env.payload_hash) {
      errors.push(
        `payload_hash does not match the committed bytes: envelope=${env.payload_hash} bytes=${external}`,
      );
    }
  }
  const payloadHashOk: boolean | null = checks.length > 0 ? checks.every(Boolean) : null;

  // Check 2 — Signature Confirmed: Ed25519 over the signed scope, which is
  // JCS(envelope minus `signature` minus `co_signatures`) per envelope-spec §2.
  // The co_signatures carve-out (§7.1) lets a countersignature be added without
  // invalidating the primary signature; the field is reserved/default-absent.
  // The corpus has no co-signed vectors, so this strip is pinned by an explicit
  // unit test rather than by conformance.
  let signatureOk = false;
  try {
    const { signature: _signature, co_signatures: _coSignatures, ...envelopeForSig } = env;
    signatureOk = await ed25519Verify(env.signature, utf8(jcs(envelopeForSig)), env.public_key);
    if (!signatureOk) errors.push("Ed25519 signature verification failed");
  } catch (e) {
    errors.push(`signature verification error: ${stringifyErr(e)}`);
  }

  // Check 3 (optional) — Content Bind: the user's bytes match a hash this
  // envelope commits to. The tag got us here; only this proves the bytes match.
  let contentHashOk: boolean | null = null;
  let contentRole: ContentRole | null = null;
  if (expectedContentHash !== undefined) {
    const want = expectedContentHash.toLowerCase();
    const match = contentHashes(env).find((c) => c.hash.toLowerCase() === want);
    contentHashOk = match !== undefined;
    contentRole = match ? match.role : null;
    if (!contentHashOk) {
      errors.push("provided content hash does not match any hash this envelope commits to");
    }
  }

  return {
    // null (binding not checkable) does not fail the verdict — Python-kernel
    // parity: ok = spec && sig && payloadHashOk is not False.
    ok: specVersionOk && signatureOk && payloadHashOk !== false,
    specVersionOk,
    payloadHashOk,
    signatureOk,
    contentHashOk,
    contentRole,
    errors,
  };
}

function stringifyErr(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
