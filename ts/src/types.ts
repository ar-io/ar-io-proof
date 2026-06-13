// Wire types for ar.io Verifiable Event Envelopes (ar-io-proof
// specs/envelope-spec.md). We model only the fields the verifier consumes;
// unknown fields are preserved by structural typing (envelopes are verified
// over their canonical bytes, not this interface).

export interface Subject {
  type: string;
  tenant_id?: string;
  agent_id?: string;
}

export interface Envelope {
  spec_version: string;
  event_id: string;
  payload_hash: string;
  signed_at: string;
  public_key: string;
  signature: string;
  // Inline-binding profiles (envelope-spec §3) carry the committed payload in
  // the envelope; external-commitment profiles do not — the caller supplies
  // the committed bytes to bind (verifyEnvelope's payloadBytes option).
  payload?: Record<string, unknown>;
  // Disclosure fields (§3.1): present on Promoted profiles, absent on Minimal
  // ones (they live inside the committed payload instead).
  event_type?: string;
  subject?: Subject;
  previous_hash?: string;
  // Optional v1.1+ fields: dev/production marking inside the signed scope,
  // and the external-commitment locator.
  environment?: string;
  payload_ref?: string;
  // Reserved, default-absent (envelope-spec §7.1): countersignatures over the
  // same skeleton. OUTSIDE the signed scope — the primary signature covers the
  // envelope minus `signature` AND minus `co_signatures`, so a countersignature
  // can be added without invalidating the primary. Absence implies a single
  // signer and MUST NOT be treated as a failure.
  co_signatures?: unknown[];
}

// Which payload field a matched content hash came from. tamper_detected commits
// to both the tampered ("observed") bytes and the known-good ("baseline") bytes.
export type ContentRole = "asset" | "baseline" | "observed";

export interface VerifyOptions {
  // External commitment (§3): the committed canonical payload bytes. When
  // supplied, SHA-256(payloadBytes) must equal the envelope's payload_hash.
  payloadBytes?: Uint8Array;
  // Content bind: the caller's own hash of an artifact (e.g. the in-browser
  // hash of a user's file) to match against the hashes the envelope commits to.
  expectedContentHash?: string;
}

export interface VerificationResult {
  // Cryptographic validity: spec_version ok, Ed25519 signature ok, and the
  // payload binding did not FAIL. payloadHashOk === null (binding not
  // checkable: external-commitment envelope, no payloadBytes supplied) does
  // not fail ok — that is the "signature-valid, semantics-undetermined"
  // outcome of envelope-spec §3.1/§6.2.
  ok: boolean;
  specVersionOk: boolean;
  // true: binding checked and matches (inline recompute, external bytes, or
  // both when both were available). false: a check failed, or payload_hash is
  // missing/malformed. null: no binding material to check against.
  payloadHashOk: boolean | null;
  signatureOk: boolean;
  // Content bind: did the hash the caller supplied match a hash this envelope
  // commits to? null when no hash was supplied. This is the check that defeats
  // a lying gateway — the tag only got us to the candidate.
  contentHashOk: boolean | null;
  contentRole: ContentRole | null;
  errors: string[];
}
