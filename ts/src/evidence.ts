// Evidence-bundle verification (ar-io-proof specs/evidence-bundle.md).
//
// An `ario.evidence/v1` bundle is a SIGNED wrapper around a producer-specific
// `body`. This module verifies the `ario.anchor.trace/v1` body — the
// @ar.io/anchor SDK trace: a self-verifying serialization of InclusionReceipt[]
// (per-event signed envelopes + their checkpoints + RFC 9162 inclusion proofs).
//
// The algorithm is the kernel discipline applied one level up (evidence-bundle
// §1, §4): inherit-don't-invent (same JCS, SHA-256, Ed25519), wrap-don't-merge
// (the body is opaque to the wrapper), recompute-don't-trust-the-verdict
// (every claim is re-derived from `body`, never read off `verdict.status`),
// reject-unknown-major. No ar.io service is in the trust path: the bundle is
// self-verifying offline against the embedded `public_key`; the optional
// gateway re-fetch only confirms the checkpoints are anchored on-chain.
//
// Scope: this verifies a SINGLE evidence bundle. Chain walking over
// `previous_hash` across successive exports is consumer-layer logic above it.

import {
  deriveOperatorAddress,
  ed25519Verify,
  hexToBytes,
  sha256Hex,
  utf8,
  verifyRsaPssSha256,
} from "./crypto.js";
import { leafHash, verifyInclusion } from "./merkle.js";
import {
  MAX_CANONICAL_DEPTH,
  contentHashes,
  exceedsDepth,
  jcs,
  verifyEnvelope,
} from "./verifier.js";
import type { Envelope } from "./types.js";

// Only the evidence-bundle major(s) this kernel verifies. A new major is a
// deliberate one-entry addition HERE — same fail-closed discipline as the
// envelope verifier's ACCEPTED_SPEC_MAJORS.
const ACCEPTED_EVIDENCE_MAJORS = ["ario.evidence/v1"];

// The body_type this module knows how to verify structurally. An unknown
// body_type is not a hard failure of the WRAPPER (the signature + body_hash
// still verify), but its body cannot be re-derived, so the per-body verdict is
// "undetermined" rather than "verified".
export const ANCHOR_TRACE_BODY_TYPE = "ario.anchor.trace/v1";

// The issuer-composed attested-evidence-export body (specs/evidence-export.md
// §2). The wrapper is unchanged (`ario.evidence/v1`, Ed25519-signed); this body
// carries a cached verdict + the inline source bundle + embedded RSA-PSS
// operator attestations. verifyEvidenceBundle dispatches on it to
// verifyExportBody (§5).
export const EXPORT_BODY_TYPE = "ario.evidence.export/v1";

// ---- Wire types (evidence-bundle.md §2 + §5.1) ------------------------------

export interface EvidenceIssuer {
  kind: string;
  tenant_id?: string;
  agent_id?: string;
  producer_id?: string;
  [k: string]: unknown;
}

export interface EvidenceVerdict {
  status: string;
  summary?: string;
  counts?: Record<string, number>;
  as_of?: string;
  [k: string]: unknown;
}

// `ario.anchor.trace/v1` body (§5.1). Uint8Array fields ride as lowercase hex.
export interface TraceCheckpoint {
  tx_id: string;
  envelope: Envelope;
  record_bytes: string; // hex of JCS(checkpoint record)
  merkle_root: string; // hex
}

export interface TraceInclusion {
  leaf_hash: string; // hex
  leaf_index: number;
  leaf_count: number;
  audit_path: string[]; // hex[]
  checkpoint_tx_id: string;
}

export interface TraceEvent {
  envelope: Envelope;
  record_bytes?: string; // hex of JCS(event record); omitted == record withheld
  // Opt-in disclosed raw bytes (lowercase hex) whose SHA-256 MUST equal the
  // committed event.content_hash inside record_bytes (evidence-bundle §5.1).
  // Default-absent (minimal disclosure); absent ⇒ undetermined, not failed.
  content?: string;
  inclusion: TraceInclusion;
}

export interface AnchorTraceBody {
  checkpoints: TraceCheckpoint[];
  events: TraceEvent[];
}

export interface EvidenceBundle {
  spec_version: string;
  body_type: string;
  issuer: EvidenceIssuer;
  generated_at: string;
  gateway?: string | null;
  verdict: EvidenceVerdict;
  body?: unknown;
  body_ref?: string;
  body_hash: string;
  previous_hash?: string;
  signature_alg: string;
  public_key: string;
  signature: string;
  [k: string]: unknown;
}

// ---- Verification result ----------------------------------------------------

export type EvidenceStatus =
  | "verified" // every in-scope item passed (sig + integrity + inclusion)
  | "partial" // integrity confirmed but full proof incomplete (e.g. records withheld)
  | "failed" // a check failed: bad wrapper sig / tamper / broken inclusion
  | "malformed"; // structurally unparseable / unknown major / body_hash mismatch

// Per-gateway on-chain outcome for one checkpoint tx (evidence-export.md §4.2).
// The on-chain re-fetch resolves each checkpoint_tx_id against EACH configured
// gateway and records that gateway's individual outcome:
//   confirm     — the gateway returned the tx and its bytes match the record.
//   mismatch    — the gateway returned the tx but its bytes disagree — a finding.
//   unreachable — no response / timeout / no such tx — an availability gap.
export type OnChainOutcome = "confirm" | "mismatch" | "unreachable";

export interface PerGatewayOutcome {
  gateway: string;
  outcome: OnChainOutcome;
}

export interface OnChainResult {
  // Rollup (worst-finding-wins, then best-evidence): mismatch if ANY gateway is
  // mismatch; else confirm if ANY is confirm; else unreachable.
  rollup: OnChainOutcome;
  // Derived collapsed field (retained for backward-compat with the pre-§4.2
  // single `onChainOk`): false on rollup mismatch, true on confirm, null on
  // all-unreachable.
  onChainOk: boolean | null;
  perGateway: PerGatewayOutcome[];
}

export interface CheckpointResult {
  txId: string;
  // The checkpoint envelope verified (signature + payload binding to its record).
  envelopeOk: boolean;
  // The committed record's merkle_root equals the checkpoint's claimed merkle_root.
  merkleRootOk: boolean;
  // If gateways were supplied: the on-chain bytes at tx_id matched the envelope.
  // null when no gateway re-fetch was requested. Derived collapse of `onChain`
  // (§4.2), retained so existing consumers keep the single-boolean field.
  onChainOk: boolean | null;
  // Per-gateway on-chain outcomes (§4.2), ADDITIVE to `onChainOk`. null when no
  // gateway re-fetch was requested (offline-only verification).
  onChain: OnChainResult | null;
  ok: boolean;
  errors: string[];
}

export interface EventResult {
  eventId: string;
  // The event envelope verified (signature ok; payload binding ok OR undetermined).
  envelopeOk: boolean;
  // payload binding: true matched the committed record, false mismatch,
  // null record withheld (semantics-undetermined — NOT a failure, §3.1/§6.2).
  payloadBindingOk: boolean | null;
  // RFC 9162 inclusion of this event's leaf in its checkpoint's root.
  inclusionOk: boolean;
  // The inclusion's checkpoint_tx_id resolved to a checkpoint in the bundle.
  checkpointBound: boolean;
  // Raw-log (content) binding: SHA-256 of the disclosed bytes equals the
  // committed event.content_hash (in record_bytes) — or, for a promoted
  // envelope, a hash it commits to. true matched, false mismatch (→ event
  // fails), null undetermined (nothing disclosed OR nothing committed OR record
  // withheld — NOT a failure, mirroring payloadBindingOk).
  contentOk: boolean | null;
  ok: boolean;
  errors: string[];
}

export interface EvidenceBundleResult {
  status: EvidenceStatus;
  // The wrapper: accepted major, body_hash recompute, Ed25519 wrapper signature.
  specVersionOk: boolean;
  bodyHashOk: boolean;
  signatureOk: boolean;
  bodyType: string | null;
  // null when no gateways were supplied (offline-only verification).
  onChainChecked: boolean;
  checkpoints: CheckpointResult[];
  events: EventResult[];
  // The producer's asserted verdict.status (for display only — never trusted).
  assertedStatus: string | null;
  // Present ONLY for an `ario.evidence.export/v1` body (evidence-export.md §5):
  // the export-specific dimensions (source linkage, verdict agreement, embedded
  // attestations, recomputed §4 verdict). The top-level `checkpoints`/`events`
  // above are the recomputed SOURCE-bundle results in that case. Absent for a
  // plain anchor-trace bundle — additive, backward-compatible.
  export?: ExportResult;
  errors: string[];
}

// ---- Attested-evidence-export wire + result types (evidence-export.md) -------

// One embedded operator attestation record (§2.2 / §3). RSA-PSS-SHA-256 over
// JCS(payload); the operator key is the operator's Arweave RSA wallet.
export interface AttestationRecord {
  checkpoint_tx_id: string;
  payload: AttestationPayload;
  signature_alg: string; // "rsa-pss-sha256"
  public_key: { kty: "RSA"; n: string; e: string };
  signature: string; // lowercase hex, RSA-PSS over JCS(payload)
  [k: string]: unknown;
}

export interface AttestationPayload {
  tx_id: string;
  data_hash: string; // sha256-hex of the tx data
  operator: string; // Arweave wallet == base64url(SHA-256(rsa modulus))
  subject_ref?: { hash: string; type: string };
  level?: number;
  gateway?: string;
  [k: string]: unknown;
}

// The export body (§2.2). Inline `source_bundle` is the default.
export interface ExportBody {
  kernel_verdict: VerdictObject;
  source_bundle?: EvidenceBundle;
  source_bundle_ref?: string;
  source_bundle_hash: string;
  attestations: AttestationRecord[];
  export_schema?: string;
  [k: string]: unknown;
}

// ---- The §4 kernel verdict object (snake_case, spec-canonical computed wire) --
// Recomputed by the kernel; the copy cached in body.kernel_verdict is a
// rendering convenience the verifier recomputes and (over its deterministic
// dimensions, §5 step 5) confirms.

export interface VerdictEvent {
  event_id: string;
  signature_ok: boolean;
  payload_bound: boolean | null;
  inclusion_ok: boolean;
  content_ok: boolean | null;
  status: string;
}

export interface VerdictOnChainGateway {
  gateway: string;
  outcome: OnChainOutcome;
  block_height?: number;
}

export interface VerdictOnChain {
  rollup: OnChainOutcome;
  on_chain_ok: boolean | null;
  per_gateway: VerdictOnChainGateway[];
}

export interface VerdictAttestation {
  operator: string;
  gateway?: string;
  signature_ok: boolean;
  operator_address_bound: boolean;
  data_hash_bound: boolean;
  level?: number;
  subject_ref_ok: boolean | null;
}

export interface VerdictCheckpoint {
  checkpoint_tx_id: string;
  merkle_root_ok: boolean;
  on_chain: VerdictOnChain | null;
  attestations: VerdictAttestation[];
}

export interface VerdictObject {
  schema_version: string; // "ario.evidence.verdict/v1"
  status: string;
  summary?: string;
  counts?: { verified: number; failed: number; undetermined: number };
  as_of?: string;
  events: VerdictEvent[];
  checkpoints: VerdictCheckpoint[];
  custody_chain: boolean | null;
  [k: string]: unknown;
}

export interface AttestationResult {
  checkpointTxId: string;
  operator: string;
  gateway: string | null;
  // The RSA-PSS-SHA-256 signature over JCS(payload) verified (§5 step 6a).
  signatureOk: boolean;
  // base64url(SHA-256(public_key.n)) == payload.operator (§3.3 / step 6b).
  operatorAddressBound: boolean;
  // payload.data_hash == the resolved source checkpoint's committed content hash
  // (SHA-256(JCS(checkpoint.envelope))) (§5 step 6c).
  dataHashBound: boolean;
  // checkpoint_tx_id resolved to a present source checkpoint.
  checkpointResolved: boolean;
  level: number | null;
  // subject_ref (§3.2) tri-state: null absent/undetermined, true/false only
  // against a supplied side-input subject. Never gates the attestation.
  subjectRefOk: boolean | null;
  ok: boolean;
  errors: string[];
}

export interface ExportResult {
  // SHA-256(JCS(source_bundle)) == source_bundle_hash (§5 step 3).
  sourceLinkageOk: boolean;
  // Recomputed source-bundle verdict status (verifyEvidenceBundle over the
  // inline source_bundle, §5 step 4).
  sourceStatus: EvidenceStatus;
  // Cached-vs-recomputed verdict agreement over the DETERMINISTIC, offline-
  // recomputable dimensions only (§5 step 5 + the on-chain-is-informational
  // erratum — see verifyExportBody). The on-chain per-gateway dimension is
  // environment/time-dependent and is EXCLUDED from this comparison.
  verdictAgreementOk: boolean;
  attestations: AttestationResult[];
  // The freshly recomputed §4 verdict object (snake_case) — what renderers and
  // the verify API display (never the cached copy).
  verdict: VerdictObject;
  // The export's own rollup status; drives the CLI exit code.
  status: EvidenceStatus;
}

export interface VerifyEvidenceOptions {
  // Gateways to re-fetch each checkpoint_tx_id from (first responsive wins).
  // When supplied, the on-chain bytes MUST byte-match the bundle's checkpoint
  // envelope, proving the proof is anchored, not just locally asserted.
  gateways?: string[];
  // Out-of-band disclosed raw bytes, keyed by event_id, to bind against each
  // event's committed content_hash (the rawLog → content_hash link). A
  // Uint8Array is used as-is; a string is parsed as lowercase hex. In-body
  // `events[].content` (signed) takes precedence over this side input; if both
  // are present for an event and disagree, the event fails (§5.1).
  content?: Record<string, Uint8Array | string>;
  // Injectable fetch (Node >=18 global `fetch` by default) — test seam.
  fetchImpl?: typeof fetch;
}

function isEvidenceMajorAccepted(specVersion: unknown): boolean {
  if (typeof specVersion !== "string" || specVersion === "") return false;
  return ACCEPTED_EVIDENCE_MAJORS.some((m) => {
    if (specVersion === m) return true;
    if (!specVersion.startsWith(`${m}.`)) return false;
    const minor = specVersion.slice(m.length + 1);
    return minor.length > 0 && /^[0-9]+$/.test(minor);
  });
}

function malformed(error: string, specVersionOk = false): EvidenceBundleResult {
  return {
    status: "malformed",
    specVersionOk,
    bodyHashOk: false,
    signatureOk: false,
    bodyType: null,
    onChainChecked: false,
    checkpoints: [],
    events: [],
    assertedStatus: null,
    errors: [error],
  };
}

function stringifyErr(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// Verify an `ario.evidence/v1` bundle carrying an `ario.anchor.trace/v1` body.
//
// Returns a structured per-checkpoint + per-event result and a recomputed
// rollup `status`. The producer's asserted `verdict.status` is surfaced
// (`assertedStatus`) but NEVER trusted — the displayed status is the one this
// function recomputes (evidence-bundle §1 principle 3 / §4 step 4).
export async function verifyEvidenceBundle(
  bundle: unknown,
  options: VerifyEvidenceOptions = {},
): Promise<EvidenceBundleResult> {
  // --- Step 1: parse + reject unknown spec_version major ---------------------
  if (bundle === null || typeof bundle !== "object" || Array.isArray(bundle)) {
    return malformed("evidence bundle is not a JSON object");
  }
  // Reject a pathologically deep bundle BEFORE any canonicalization (which
  // recurses). A fixed shared bound keeps this a `malformed` verdict in every
  // kernel rather than a stack-limit-dependent split verdict — see
  // MAX_CANONICAL_DEPTH.
  if (exceedsDepth(bundle, MAX_CANONICAL_DEPTH)) {
    return malformed(
      `evidence bundle nesting exceeds the ${MAX_CANONICAL_DEPTH}-level canonicalization depth bound`,
    );
  }
  const b = bundle as EvidenceBundle;
  const specVersionOk = isEvidenceMajorAccepted(b.spec_version);
  if (!specVersionOk) {
    return malformed(`unsupported evidence spec_version: ${JSON.stringify(b.spec_version)}`, false);
  }
  if (typeof b.signature_alg === "string" && b.signature_alg !== "ed25519") {
    // The reference verifier implements ed25519 only (evidence-bundle §2 +
    // decision #2); other algs are a deliberate future addition.
    return malformed(`unsupported signature_alg: ${JSON.stringify(b.signature_alg)}`, true);
  }
  if (typeof b.public_key !== "string" || typeof b.signature !== "string") {
    return malformed("evidence bundle is missing public_key/signature", true);
  }
  if (typeof b.body_hash !== "string") {
    return malformed("evidence bundle is missing body_hash", true);
  }
  if (b.body === undefined || b.body === null) {
    // body_ref (out-of-line body) is a defined growth hook but not part of the
    // anchor-trace use case — refuse rather than silently pass.
    return malformed("evidence bundle has no inline body (body_ref unsupported here)", true);
  }

  // --- Step 2: verify the wrapper signature + recompute body_hash ------------
  const errors: string[] = [];

  let bodyHashOk = false;
  try {
    const recomputed = await sha256Hex(utf8(jcs(b.body)));
    bodyHashOk = recomputed === b.body_hash;
    if (!bodyHashOk) {
      errors.push(`body_hash mismatch: bundle=${b.body_hash} recomputed=${recomputed}`);
    }
  } catch (e) {
    errors.push(`body canonicalization failed: ${stringifyErr(e)}`);
  }

  let signatureOk = false;
  try {
    const { signature: _sig, co_signatures: _co, ...bundleForSig } = b as EvidenceBundle & {
      co_signatures?: unknown;
    };
    signatureOk = await ed25519Verify(b.signature, utf8(jcs(bundleForSig)), b.public_key);
    if (!signatureOk) errors.push("wrapper Ed25519 signature verification failed");
  } catch (e) {
    errors.push(`wrapper signature verification error: ${stringifyErr(e)}`);
  }

  const assertedStatus = typeof b.verdict?.status === "string" ? b.verdict.status : null;

  // A broken wrapper (bad signature or tampered body) is a hard failure — the
  // body is untrustworthy, so we do not pretend to verify its contents.
  if (!signatureOk || !bodyHashOk) {
    return {
      status: "failed",
      specVersionOk,
      bodyHashOk,
      signatureOk,
      bodyType: typeof b.body_type === "string" ? b.body_type : null,
      onChainChecked: false,
      checkpoints: [],
      events: [],
      assertedStatus,
      errors,
    };
  }

  // --- Body dispatch ---------------------------------------------------------
  const bodyType = typeof b.body_type === "string" ? b.body_type : null;

  // Attested-evidence-export body (evidence-export.md §5). The wrapper is
  // authentic (Ed25519 issuer signature + body_hash verified above, §5 step 2);
  // hand off to the export verifier for steps 3–9.
  if (bodyType === EXPORT_BODY_TYPE) {
    return verifyExportBody(b, specVersionOk, assertedStatus, errors, options);
  }

  if (bodyType !== ANCHOR_TRACE_BODY_TYPE) {
    // The wrapper is authentic but we don't know this body's structure. Per
    // wrap-don't-merge, that is "partial" (cryptographically sound wrapper,
    // body verdict undetermined) — not a failure.
    errors.push(
      `body_type ${JSON.stringify(bodyType)} is not verifiable by this kernel ` +
        `(only ${ANCHOR_TRACE_BODY_TYPE}); wrapper verified, body undetermined`,
    );
    return {
      status: "partial",
      specVersionOk,
      bodyHashOk,
      signatureOk,
      bodyType,
      onChainChecked: false,
      checkpoints: [],
      events: [],
      assertedStatus,
      errors,
    };
  }

  return verifyAnchorTrace(b, bodyType, specVersionOk, assertedStatus, errors, options);
}

async function verifyAnchorTrace(
  b: EvidenceBundle,
  bodyType: string,
  specVersionOk: boolean,
  assertedStatus: string | null,
  errors: string[],
  options: VerifyEvidenceOptions,
): Promise<EvidenceBundleResult> {
  const body = b.body as AnchorTraceBody;
  if (!Array.isArray(body.checkpoints) || !Array.isArray(body.events)) {
    return malformed("ario.anchor.trace/v1 body must have checkpoints[] and events[]", true);
  }

  const gateways = options.gateways ?? [];
  const onChainChecked = gateways.length > 0;

  // --- Step 3: per-checkpoint -------------------------------------------------
  const byTxId = new Map<string, TraceCheckpoint>();
  const checkpointResults: CheckpointResult[] = [];
  for (const cp of body.checkpoints) {
    const cpErrors: string[] = [];
    let envelopeOk = false;
    let merkleRootOk = false;

    if (typeof cp.tx_id !== "string") {
      cpErrors.push("checkpoint missing tx_id");
    } else if (byTxId.has(cp.tx_id)) {
      cpErrors.push(`duplicate checkpoint tx_id ${cp.tx_id}`);
    } else {
      byTxId.set(cp.tx_id, cp);
    }

    // Verify the checkpoint envelope against its committed record (external
    // commitment — the record is the payload these external envelopes bind to).
    let recordBytes: Uint8Array | undefined;
    try {
      if (typeof cp.record_bytes === "string") recordBytes = hexToBytes(cp.record_bytes);
    } catch (e) {
      cpErrors.push(`checkpoint record_bytes is not hex: ${stringifyErr(e)}`);
    }
    try {
      const res = await verifyEnvelope(
        cp.envelope,
        recordBytes !== undefined ? { payloadBytes: recordBytes } : {},
      );
      // A checkpoint must fully bind: signature + the committed record matching
      // payload_hash. An undetermined binding (no record) is not enough to
      // anchor the events' inclusion claims to a trustworthy root.
      envelopeOk = res.ok && res.payloadHashOk === true;
      if (!res.signatureOk) cpErrors.push("checkpoint envelope signature failed");
      if (res.payloadHashOk === false) cpErrors.push("checkpoint record does not bind to payload_hash");
      if (res.payloadHashOk === null) cpErrors.push("checkpoint record_bytes missing — root untrusted");
    } catch (e) {
      cpErrors.push(`checkpoint envelope verify error: ${stringifyErr(e)}`);
    }

    // The committed record's merkle_root must equal the checkpoint's claimed
    // merkle_root (recompute, don't trust the bundle's top-level claim).
    if (recordBytes !== undefined) {
      try {
        const record = JSON.parse(new TextDecoder().decode(recordBytes)) as {
          event?: { merkle_root?: unknown };
        };
        const committedRoot = record.event?.merkle_root;
        merkleRootOk = typeof committedRoot === "string" && committedRoot === cp.merkle_root;
        if (!merkleRootOk) {
          cpErrors.push(
            `checkpoint merkle_root mismatch: claimed=${cp.merkle_root} committed=${String(committedRoot)}`,
          );
        }
      } catch (e) {
        cpErrors.push(`checkpoint record is not JSON: ${stringifyErr(e)}`);
      }
    }

    checkpointResults.push({
      txId: typeof cp.tx_id === "string" ? cp.tx_id : "",
      envelopeOk,
      merkleRootOk,
      onChainOk: null, // filled in step 5 if a gateway re-fetch was requested
      onChain: null, // per-gateway (§4.2), filled in step 5
      ok: envelopeOk && merkleRootOk,
      errors: cpErrors,
    });
  }

  // --- Step 4: per-event ------------------------------------------------------
  const eventResults: EventResult[] = [];
  for (const ev of body.events) {
    const evErrors: string[] = [];
    const eventId = getEventId(ev.envelope);
    let envelopeOk = false;
    let payloadBindingOk: boolean | null = null;

    let recordBytes: Uint8Array | undefined;
    try {
      if (typeof ev.record_bytes === "string") recordBytes = hexToBytes(ev.record_bytes);
    } catch (e) {
      evErrors.push(`event record_bytes is not hex: ${stringifyErr(e)}`);
    }
    try {
      const res = await verifyEnvelope(
        ev.envelope,
        recordBytes !== undefined ? { payloadBytes: recordBytes } : {},
      );
      envelopeOk = res.ok; // ok tolerates an undetermined binding (withheld record)
      payloadBindingOk = res.payloadHashOk;
      if (!res.signatureOk) evErrors.push("event envelope signature failed");
      if (res.payloadHashOk === false) evErrors.push("event record does not bind to payload_hash");
    } catch (e) {
      evErrors.push(`event envelope verify error: ${stringifyErr(e)}`);
    }

    // Bind the event to exactly one checkpoint in the bundle, then verify
    // RFC 9162 inclusion against THAT checkpoint's merkle_root.
    const incl = ev.inclusion;
    const cp = incl && typeof incl.checkpoint_tx_id === "string" ? byTxId.get(incl.checkpoint_tx_id) : undefined;
    const checkpointBound = cp !== undefined;
    if (!incl || typeof incl !== "object") {
      evErrors.push("event missing inclusion proof");
    } else if (!checkpointBound) {
      evErrors.push(
        `event inclusion.checkpoint_tx_id ${JSON.stringify(incl.checkpoint_tx_id)} resolves to no checkpoint`,
      );
    }

    let inclusionOk = false;
    if (incl && checkpointBound && cp) {
      try {
        inclusionOk = await verifyInclusion(
          hexToBytes(incl.leaf_hash),
          incl.leaf_index,
          incl.leaf_count,
          (incl.audit_path ?? []).map((h) => hexToBytes(h)),
          hexToBytes(cp.merkle_root),
        );
        if (!inclusionOk) evErrors.push("RFC 9162 inclusion proof did not reconstruct the checkpoint root");

        // Defense in depth: the claimed leaf_hash MUST be the hash of the
        // event's own signed envelope bytes (profile §6) — otherwise a valid
        // inclusion proof for an UNRELATED leaf could be smuggled in.
        const expectedLeaf = await leafHash(utf8(jcs(ev.envelope)));
        const expectedLeafHex = toHex(expectedLeaf);
        if (expectedLeafHex !== (incl.leaf_hash ?? "").toLowerCase()) {
          inclusionOk = false;
          evErrors.push(
            `inclusion leaf_hash does not match SHA-256(0x00 || JCS(event envelope))`,
          );
        }
      } catch (e) {
        evErrors.push(`inclusion verify error: ${stringifyErr(e)}`);
      }
    }

    // Content (raw-log) binding — the rawLog → content_hash link the rest of
    // the chain (content_hash → record → payload_hash → signature → leaf →
    // root) already covers. The committed hash lives in the RECORD
    // (record.event.content_hash, minimal disclosure); for a promoted-disclosure
    // envelope it falls back to the envelope's own committed hashes
    // (contentHashes — NOT verifyEnvelope's path, which reads payload/event_type
    // and yields nothing for an ario.events/v1 envelope). Disclosed bytes come
    // from the signed in-body `ev.content` FIRST, then the out-of-band
    // options.content side input. Undetermined (null) when nothing is disclosed
    // or nothing is committed; false ONLY on a real mismatch or an in-body vs
    // side-input disagreement — mirroring payloadBindingOk's never-fail-on-absent
    // discipline.
    let contentOk: boolean | null = null;
    {
      const committed: string[] = [];
      let recordContentHash: string | undefined;
      if (recordBytes !== undefined) {
        try {
          const record = JSON.parse(new TextDecoder().decode(recordBytes)) as {
            event?: { content_hash?: unknown };
          };
          const ch = record.event?.content_hash;
          if (typeof ch === "string" && ch) recordContentHash = ch.toLowerCase();
        } catch {
          // record not JSON — the payload binding already reflects that; content
          // stays undetermined rather than throwing.
        }
      }
      if (recordContentHash !== undefined) {
        committed.push(recordContentHash);
      } else if (ev.envelope && typeof ev.envelope === "object") {
        // Promoted fallback. Guarded: contentHashes() dereferences env.payload,
        // which throws on a null/non-object envelope — a verifier must never
        // raise on adversarial input (such an event already fails via envelopeOk).
        for (const c of contentHashes(ev.envelope)) committed.push(c.hash.toLowerCase());
      }

      // Disclosed bytes, precedence: in-body (signed) → side input. A string
      // side input is hex; a Uint8Array is used as-is.
      let inBody: Uint8Array | undefined;
      if (typeof ev.content === "string") {
        try {
          inBody = hexToBytes(ev.content);
        } catch (e) {
          evErrors.push(`event content is not hex: ${stringifyErr(e)}`);
        }
      }
      let side: Uint8Array | undefined;
      const sideRaw = options.content?.[eventId];
      if (sideRaw instanceof Uint8Array) {
        side = sideRaw;
      } else if (typeof sideRaw === "string") {
        try {
          side = hexToBytes(sideRaw);
        } catch (e) {
          evErrors.push(`supplied content for ${eventId} is not hex: ${stringifyErr(e)}`);
        }
      }

      if (inBody !== undefined && side !== undefined && !bytesEqual(inBody, side)) {
        // Two disclosures that disagree: a genuine conflict, not undetermined.
        contentOk = false;
        evErrors.push(
          "disclosed content disagreement: in-body events[].content and the supplied content differ",
        );
      } else {
        const disclosed = inBody ?? side;
        if (disclosed === undefined || committed.length === 0) {
          contentOk = null;
          if (disclosed !== undefined && committed.length === 0) {
            evErrors.push(
              "disclosed content present but no committed content_hash to bind to " +
                "(record withheld or record has no event.content_hash) — undetermined",
            );
          }
        } else {
          const got = await sha256Hex(disclosed);
          contentOk = committed.includes(got);
          if (!contentOk) {
            evErrors.push(
              "disclosed content does not match the committed content_hash: " +
                `sha256(disclosed)=${got} committed=${committed.join("|")}`,
            );
          }
        }
      }
    }

    eventResults.push({
      eventId,
      envelopeOk,
      payloadBindingOk,
      inclusionOk,
      checkpointBound,
      contentOk,
      // An event is "ok" when its envelope is authentic (signature + binding
      // not-failed), its inclusion proof reconstructs the root, it binds to a
      // present checkpoint, and its disclosed content did not MISMATCH. A
      // withheld record or undisclosed content (binding/content null) does not
      // fail it.
      ok: envelopeOk && inclusionOk && checkpointBound && contentOk !== false,
      errors: evErrors,
    });
  }

  // --- Step 5: optional on-chain re-fetch ------------------------------------
  const fetchImpl = options.fetchImpl ?? (globalThis.fetch as typeof fetch | undefined);
  let gatewayUnavailable = false;
  if (onChainChecked) {
    if (typeof fetchImpl !== "function") {
      gatewayUnavailable = true;
      errors.push("on-chain re-fetch requested but no fetch implementation is available");
    } else {
      for (const cpr of checkpointResults) {
        const cp = byTxId.get(cpr.txId);
        if (!cp) continue;
        const outcome = await refetchCheckpoint(cp, gateways, fetchImpl);
        cpr.onChain = outcome.onChain;
        cpr.onChainOk = outcome.onChain.onChainOk;
        if (outcome.unavailable) gatewayUnavailable = true;
        if (outcome.error) cpr.errors.push(outcome.error);
        // Fold the on-chain dimension in: a MISMATCH (false) fails the
        // checkpoint — the proof was not anchored as claimed. An UNREACHABLE
        // gateway (null) leaves the offline-sound checkpoint ok; the run
        // downgrades to "partial" (exit 3) via gatewayUnavailable, not a hard
        // failure. A match (true) keeps it ok.
        cpr.ok = cpr.envelopeOk && cpr.merkleRootOk && cpr.onChainOk !== false;
      }
    }
  }

  // --- Rollup ----------------------------------------------------------------
  const allCheckpointsOk = checkpointResults.length > 0 && checkpointResults.every((c) => c.ok);
  const allEventsOk = eventResults.every((e) => e.ok);
  const anyHardFailure =
    checkpointResults.some((c) => !c.ok) || eventResults.some((e) => !e.ok);
  const anyWithheldRecord = eventResults.some((e) => e.payloadBindingOk === null);

  let status: EvidenceStatus;
  if (anyHardFailure) {
    status = "failed";
  } else if (gatewayUnavailable) {
    // Every offline check passed and nothing MISMATCHED, but a requested
    // on-chain confirmation could not be made — the bundle is offline-sound,
    // its anchored state unconfirmed. "partial" + a note the CLI maps to exit 3.
    status = "partial";
    errors.push("one or more checkpoints could not be re-fetched from the supplied gateways");
  } else if (anyWithheldRecord) {
    // Everything that COULD be checked passed; some record bytes were withheld
    // so their semantic binding is undetermined (not a failure) — "partial".
    status = "partial";
  } else if (allCheckpointsOk && allEventsOk) {
    status = "verified";
  } else {
    status = "partial";
  }

  return {
    status,
    specVersionOk,
    bodyHashOk: true,
    signatureOk: true,
    bodyType,
    onChainChecked,
    checkpoints: checkpointResults,
    events: eventResults,
    assertedStatus,
    errors,
  };
}

// ===========================================================================
// Attested-evidence-export verification (evidence-export.md §5, steps 3–9).
// Reached from verifyEvidenceBundle AFTER the wrapper (Ed25519 issuer signature
// + body_hash) has already verified (steps 1–2). This composes the existing
// evidence path (recompute the inline source verdict) with the one new
// primitive (embedded RSA-PSS operator attestations, verifyRsaPssSha256).
// ===========================================================================
async function verifyExportBody(
  b: EvidenceBundle,
  specVersionOk: boolean,
  assertedStatus: string | null,
  errors: string[],
  options: VerifyEvidenceOptions,
): Promise<EvidenceBundleResult> {
  // Malformed-as-an-export (§5 exit 2): a required field is missing or a key is
  // unparseable — the wrapper verified, but no verdict can be rendered. The
  // wrapper fields stay true (they DID verify) for any consumer that inspects
  // them; the CLI's malformed branch shows the errors and exits 2.
  const exportMalformed = (error: string): EvidenceBundleResult => ({
    status: "malformed",
    specVersionOk,
    bodyHashOk: true,
    signatureOk: true,
    bodyType: EXPORT_BODY_TYPE,
    onChainChecked: false,
    checkpoints: [],
    events: [],
    assertedStatus,
    errors: [...errors, error],
  });

  const body = b.body as ExportBody;
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return exportMalformed("export body is not a JSON object");
  }
  if (typeof body.source_bundle_hash !== "string") {
    return exportMalformed("export body missing source_bundle_hash");
  }
  if (!Array.isArray(body.attestations)) {
    return exportMalformed("export body missing attestations[]");
  }
  if (
    body.kernel_verdict === null ||
    typeof body.kernel_verdict !== "object" ||
    Array.isArray(body.kernel_verdict)
  ) {
    return exportMalformed("export body missing kernel_verdict");
  }

  // --- Step 3: source-bundle linkage ----------------------------------------
  const inline = body.source_bundle;
  if (inline === undefined || inline === null) {
    // source_bundle_ref (out-of-line) is not verifiable on a network-isolated
    // machine unless the referenced bytes are co-delivered — the source-
    // dependent checks are UNDETERMINED (exit 3), NOT a failure (§5 step 3).
    return {
      status: "partial",
      specVersionOk,
      bodyHashOk: true,
      signatureOk: true,
      bodyType: EXPORT_BODY_TYPE,
      onChainChecked: false,
      checkpoints: [],
      events: [],
      assertedStatus,
      errors: [
        ...errors,
        "source_bundle is not inline (source_bundle_ref) — bytes unavailable offline; " +
          "source-dependent checks undetermined",
      ],
    };
  }

  let sourceLinkageOk = false;
  try {
    const recomputed = await sha256Hex(utf8(jcs(inline)));
    sourceLinkageOk = recomputed === body.source_bundle_hash;
    if (!sourceLinkageOk) {
      errors.push(
        `source_bundle_hash mismatch: body=${body.source_bundle_hash} recomputed=${recomputed}`,
      );
    }
  } catch (e) {
    errors.push(`source_bundle canonicalization failed: ${stringifyErr(e)}`);
  }

  // --- Step 4: recompute the source verdict ---------------------------------
  // The existing evidence path over the inline source bundle — same primitives
  // (Ed25519 envelopes, payload binding, RFC 9162 inclusion, merkle roots,
  // content_ok, and the optional per-gateway on-chain re-fetch, §4.2 / step 7).
  const sourceResult = await verifyEvidenceBundle(inline, options);

  // Map source checkpoints by tx_id for attestation data_hash binding (§5 6c).
  const sourceCheckpoints = new Map<string, TraceCheckpoint>();
  const sb = inline.body as AnchorTraceBody | undefined;
  if (sb && typeof sb === "object" && Array.isArray(sb.checkpoints)) {
    for (const cp of sb.checkpoints) {
      if (cp && typeof cp.tx_id === "string") sourceCheckpoints.set(cp.tx_id, cp);
    }
  }

  // --- Step 6: embedded attestation records ---------------------------------
  const attestations: AttestationResult[] = [];
  for (const rec of body.attestations) {
    const r = await verifyAttestation(rec, sourceCheckpoints);
    if (r.malformed !== undefined) return exportMalformed(r.malformed);
    attestations.push(r.result);
  }

  // --- Build the recomputed §4 verdict object -------------------------------
  const verdict = buildVerdictObject(sourceResult, attestations);
  if (typeof b.generated_at === "string") verdict.as_of = b.generated_at;

  // --- Step 5: verdict agreement (DETERMINISTIC dimensions only) ------------
  // The cached body.kernel_verdict is recompute-don't-trust (principle 3). But
  // agreement compares ONLY the deterministic, offline-recomputable dimensions:
  // per-event signature/payload-binding/inclusion/content, per-checkpoint
  // merkle roots, and per-attestation signature/operator-address/data_hash
  // binding. The on-chain per-gateway dimension is environment/time-dependent —
  // the issuer observed it online at compose time; an offline verifier
  // legitimately sees `null` — so it is INFORMATIONAL and MUST NOT by itself
  // trigger an exit-1 tamper verdict (the verifier's own on-chain outcomes fold
  // in at step 7 only if it re-fetches). Advisory rollups (status / counts /
  // summary / as_of / custody_chain) are derived, not compared. See the §5
  // step-5 erratum flagged in the slice report.
  let verdictAgreementOk = false;
  try {
    const cachedProjection = jcs(projectVerdictForAgreement(body.kernel_verdict));
    const freshProjection = jcs(projectVerdictForAgreement(verdict));
    verdictAgreementOk = cachedProjection === freshProjection;
    if (!verdictAgreementOk) {
      errors.push(
        "recomputed verdict disagrees with the cached kernel_verdict " +
          "(deterministic dimensions) — recompute-don't-trust",
      );
    }
  } catch (e) {
    errors.push(`verdict agreement comparison failed: ${stringifyErr(e)}`);
  }

  // --- Step 7 already folded in by the source recompute ---------------------
  // (verifyEvidenceBundle merged per-gateway outcomes into sourceResult.status:
  // a checkpoint `mismatch` made it "failed"; an all-`unreachable` checkpoint
  // made it "partial" + an unreachable note → exit 3.)

  // Propagate the source recompute's notes so the auditor — and the CLI's
  // exit-3 detection (which keys off "unreachable") — see them.
  for (const e of sourceResult.errors) errors.push(`source: ${e}`);

  // --- Step 9: export rollup + exit -----------------------------------------
  const anyAttestationFailed = attestations.some((a) => !a.ok);
  let status: EvidenceStatus;
  if (
    !sourceLinkageOk ||
    !verdictAgreementOk ||
    sourceResult.status === "failed" ||
    sourceResult.status === "malformed" ||
    anyAttestationFailed
  ) {
    status = "failed";
  } else if (sourceResult.status === "partial") {
    // Undetermined source (withheld record → exit 0; gateway-unreachable →
    // exit 3 via the propagated "unreachable" note). Never a failure.
    status = "partial";
  } else {
    status = "verified";
  }

  // The DISPLAYED verdict reflects the full recompute (incl. attestations).
  verdict.status = status;
  verdict.summary = summarizeExport(status, sourceResult, attestations);

  return {
    status,
    specVersionOk,
    bodyHashOk: true,
    signatureOk: true,
    bodyType: EXPORT_BODY_TYPE,
    onChainChecked: sourceResult.onChainChecked,
    // The top-level per-checkpoint / per-event results ARE the recomputed source
    // results, so the CLI's existing rendering shows them unchanged.
    checkpoints: sourceResult.checkpoints,
    events: sourceResult.events,
    assertedStatus,
    export: {
      sourceLinkageOk,
      sourceStatus: sourceResult.status,
      verdictAgreementOk,
      attestations,
      verdict,
      status,
    },
    errors,
  };
}

// ===========================================================================
// Compose-side verdict recompute (evidence-export.md §5 steps 4 + 6, minus the
// wrapper). The `proof export` composer must embed a cached `kernel_verdict`
// (§4) whose deterministic dimensions BYTE-AGREE with what verifyExportBody will
// later recompute over the same inline source bundle + attestation records (§5
// step 5). Rather than reimplement that recompute, this reuses the EXACT verify
// primitives verifyExportBody uses — verifyEvidenceBundle over the source,
// verifyAttestation per record, then buildVerdictObject — so the composed cache
// and the verifier's recompute cannot drift. Offline/pure: no gateways, so the
// on-chain dimension is null (excluded from agreement anyway, §5 step 5).
//
// Throws on a malformed attestation record (unparseable RSA key, wrong
// signature_alg, missing field) — a composer INPUT error the caller surfaces,
// mirroring verifyExportBody's malformed→exit-2 for the same conditions.
// ===========================================================================
export interface ComposeVerdictResult {
  // The §4 verdict object to embed as body.kernel_verdict (status/summary/as_of
  // finalized exactly as verifyExportBody would render them).
  verdict: VerdictObject;
  // The recomputed inline-source-bundle status (verifyEvidenceBundle).
  sourceStatus: EvidenceStatus;
  // The export rollup status (§4.5 / §5 step 9) — verified | partial | failed.
  status: EvidenceStatus;
  // Per-attestation results (each already bound to a source checkpoint).
  attestations: AttestationResult[];
}

export async function recomputeExportVerdict(
  sourceBundle: EvidenceBundle,
  attestationRecords: AttestationRecord[],
  generatedAt: string,
  options: VerifyEvidenceOptions = {},
): Promise<ComposeVerdictResult> {
  const sourceResult = await verifyEvidenceBundle(sourceBundle, options);

  // Map source checkpoints by tx_id for attestation data_hash binding (§5 6c) —
  // identical to verifyExportBody's map construction.
  const sourceCheckpoints = new Map<string, TraceCheckpoint>();
  const sb = sourceBundle.body as AnchorTraceBody | undefined;
  if (sb && typeof sb === "object" && Array.isArray(sb.checkpoints)) {
    for (const cp of sb.checkpoints) {
      if (cp && typeof cp.tx_id === "string") sourceCheckpoints.set(cp.tx_id, cp);
    }
  }

  const attestations: AttestationResult[] = [];
  for (const rec of attestationRecords) {
    const r = await verifyAttestation(rec, sourceCheckpoints);
    if (r.malformed !== undefined) {
      throw new Error(`attestation record is malformed: ${r.malformed}`);
    }
    attestations.push(r.result);
  }

  const verdict = buildVerdictObject(sourceResult, attestations);
  verdict.as_of = generatedAt;

  // Export rollup (§5 step 9). Source linkage and verdict agreement are always
  // satisfied at compose time (the composer computes the source hash itself and
  // there is no prior cached verdict to disagree with), so the only failure
  // inputs here are the recomputed source status and any failed attestation.
  const anyAttestationFailed = attestations.some((a) => !a.ok);
  let status: EvidenceStatus;
  if (
    sourceResult.status === "failed" ||
    sourceResult.status === "malformed" ||
    anyAttestationFailed
  ) {
    status = "failed";
  } else if (sourceResult.status === "partial") {
    status = "partial";
  } else {
    status = "verified";
  }
  verdict.status = status;
  verdict.summary = summarizeExport(status, sourceResult, attestations);

  return { verdict, sourceStatus: sourceResult.status, status, attestations };
}

// Verify one embedded attestation record (§5 step 6a–d). Returns `malformed`
// (→ exit 2) for an unparseable RSA key / signature hex or a missing required
// field; otherwise a per-dimension AttestationResult whose `ok` gates on the
// three binding checks (sig / operator-address / data_hash). subject_ref is
// undetermined-tolerant and never gates.
async function verifyAttestation(
  rec: AttestationRecord,
  sourceCheckpoints: Map<string, TraceCheckpoint>,
): Promise<{ result: AttestationResult; malformed?: string }> {
  const errs: string[] = [];
  const result: AttestationResult = {
    checkpointTxId:
      rec && typeof rec.checkpoint_tx_id === "string" ? rec.checkpoint_tx_id : "",
    operator: "",
    gateway: null,
    signatureOk: false,
    operatorAddressBound: false,
    dataHashBound: false,
    checkpointResolved: false,
    level: null,
    subjectRefOk: null,
    ok: false,
    errors: errs,
  };

  if (rec === null || typeof rec !== "object" || Array.isArray(rec)) {
    return { result, malformed: "attestation record is not a JSON object" };
  }
  const payload = rec.payload;
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return { result, malformed: "attestation record missing payload" };
  }
  if (rec.signature_alg !== "rsa-pss-sha256") {
    return {
      result,
      malformed: `unsupported attestation signature_alg: ${JSON.stringify(rec.signature_alg)}`,
    };
  }
  const pub = rec.public_key as { kty?: unknown; n?: unknown; e?: unknown } | null;
  if (
    pub === null ||
    typeof pub !== "object" ||
    pub.kty !== "RSA" ||
    typeof pub.n !== "string" ||
    typeof pub.e !== "string"
  ) {
    return { result, malformed: "attestation record missing/invalid RSA public_key JWK" };
  }
  if (typeof rec.signature !== "string") {
    return { result, malformed: "attestation record missing signature" };
  }
  const rsaKey = { kty: "RSA" as const, n: pub.n, e: pub.e };

  result.operator = typeof payload.operator === "string" ? payload.operator : "";
  result.gateway = typeof payload.gateway === "string" ? payload.gateway : null;
  result.level = typeof payload.level === "number" ? payload.level : null;

  // (a) RSA-PSS-SHA-256 signature over JCS(payload). A malformed sig hex or
  // unimportable key THROWS (malformed → exit 2); a well-formed key that simply
  // fails to verify returns false (→ exit 1).
  let payloadBytes: Uint8Array;
  try {
    payloadBytes = utf8(jcs(payload));
  } catch (e) {
    return { result, malformed: `attestation payload canonicalization failed: ${stringifyErr(e)}` };
  }
  try {
    result.signatureOk = await verifyRsaPssSha256(payloadBytes, rec.signature, rsaKey);
    if (!result.signatureOk) errs.push("attestation RSA-PSS signature verification failed");
  } catch (e) {
    return { result, malformed: `attestation ${stringifyErr(e)}` };
  }

  // (b) operator-address binding: base64url(SHA-256(modulus)) == payload.operator.
  try {
    const derived = await deriveOperatorAddress(pub.n);
    result.operatorAddressBound = result.operator !== "" && derived === result.operator;
    if (!result.operatorAddressBound) {
      errs.push(
        `operator-address binding failed: derived=${derived} payload.operator=${result.operator}`,
      );
    }
  } catch (e) {
    return { result, malformed: `attestation operator key: ${stringifyErr(e)}` };
  }

  // (c) checkpoint resolution + data_hash binding. The checkpoint tx data IS the
  // uploaded JCS(envelope) bytes (the same bytes the on-chain re-fetch compares
  // against, §4.2), so the checkpoint's committed content hash is
  // SHA-256(JCS(checkpoint.envelope)).
  const cp = sourceCheckpoints.get(result.checkpointTxId);
  result.checkpointResolved = cp !== undefined;
  if (!cp) {
    errs.push(
      `attestation checkpoint_tx_id ${JSON.stringify(result.checkpointTxId)} resolves to no source checkpoint`,
    );
  } else {
    try {
      const committed = await sha256Hex(utf8(jcs(cp.envelope)));
      const dataHash = typeof payload.data_hash === "string" ? payload.data_hash.toLowerCase() : "";
      result.dataHashBound = dataHash !== "" && dataHash === committed;
      if (!result.dataHashBound) {
        errs.push(
          `data_hash does not bind to the checkpoint's committed content hash: ` +
            `data_hash=${dataHash} committed=${committed}`,
        );
      }
    } catch (e) {
      errs.push(`cannot recompute checkpoint content hash: ${stringifyErr(e)}`);
    }
  }

  // (d) subject_ref (§3.2) — well-formedness only (no side-input subject channel
  // in v1); undetermined (null), never a hard failure.
  result.subjectRefOk = evaluateSubjectRef(payload.subject_ref, errs);

  result.ok =
    result.signatureOk &&
    result.operatorAddressBound &&
    result.dataHashBound &&
    result.checkpointResolved;
  return { result };
}

// subject_ref (§3.2): absent → null (unbound). Present + well-formed but no
// side-input subject supplied → null (undetermined, mirrors disclosed-content).
// Present + malformed → null + a surfaced note (never gates the attestation).
function evaluateSubjectRef(subjectRef: unknown, errs: string[]): boolean | null {
  if (subjectRef === undefined || subjectRef === null) return null;
  if (typeof subjectRef !== "object" || Array.isArray(subjectRef)) {
    errs.push("subject_ref is present but is not an object");
    return null;
  }
  const sr = subjectRef as { hash?: unknown; type?: unknown };
  const hashOk = typeof sr.hash === "string" && /^[0-9a-f]{64}$/.test(sr.hash);
  const typeOk = typeof sr.type === "string" && /^[a-z0-9.:-]+$/.test(sr.type);
  if (!hashOk || !typeOk) {
    errs.push("subject_ref is present but not well-formed ({hash: sha256-hex, type: token})");
    return null;
  }
  return null; // well-formed, no side input → undetermined
}

// Build the §4 verdict object (snake_case, spec-canonical) from the recomputed
// source result + the attestation results. This is the recomputed copy the
// renderer/verify-API display; it is compared (over its deterministic subset)
// to the cached body.kernel_verdict in step 5.
function buildVerdictObject(
  source: EvidenceBundleResult,
  attestations: AttestationResult[],
): VerdictObject {
  const attByCheckpoint = new Map<string, VerdictAttestation[]>();
  for (const a of attestations) {
    const list = attByCheckpoint.get(a.checkpointTxId) ?? [];
    list.push({
      operator: a.operator,
      ...(a.gateway ? { gateway: a.gateway } : {}),
      signature_ok: a.signatureOk,
      operator_address_bound: a.operatorAddressBound,
      data_hash_bound: a.dataHashBound,
      ...(a.level !== null ? { level: a.level } : {}),
      subject_ref_ok: a.subjectRefOk,
    });
    attByCheckpoint.set(a.checkpointTxId, list);
  }

  const events: VerdictEvent[] = source.events.map((e) => ({
    event_id: e.eventId,
    signature_ok: e.envelopeOk,
    payload_bound: e.payloadBindingOk,
    inclusion_ok: e.inclusionOk,
    content_ok: e.contentOk,
    status: eventVerdictStatus(e),
  }));

  const checkpoints: VerdictCheckpoint[] = source.checkpoints.map((c) => ({
    checkpoint_tx_id: c.txId,
    merkle_root_ok: c.merkleRootOk,
    on_chain: c.onChain ? toVerdictOnChain(c.onChain) : null,
    attestations: attByCheckpoint.get(c.txId) ?? [],
  }));

  let verified = 0;
  let failed = 0;
  let undetermined = 0;
  for (const e of events) {
    if (e.status === "failed") failed++;
    else if (e.status === "verified") verified++;
    else undetermined++;
  }
  for (const a of attestations) {
    if (a.ok) verified++;
    else failed++;
  }

  return {
    schema_version: "ario.evidence.verdict/v1",
    status: source.status === "malformed" ? "failed" : source.status,
    counts: { verified, failed, undetermined },
    events,
    checkpoints,
    custody_chain: null,
  };
}

function toVerdictOnChain(o: OnChainResult): VerdictOnChain {
  return {
    rollup: o.rollup,
    on_chain_ok: o.onChainOk,
    // The kernel emits {gateway, outcome}; block_height is issuer-side
    // enrichment (optional in the §4.4 schema) the offline verifier does not
    // recompute.
    per_gateway: o.perGateway.map((g) => ({ gateway: g.gateway, outcome: g.outcome })),
  };
}

function eventVerdictStatus(e: EventResult): string {
  if (!e.ok) return "failed";
  if (e.payloadBindingOk === null) return "partial"; // withheld record — undetermined
  return "verified";
}

// The §5 step-5 agreement projection: strip every environment/time-dependent
// and derived dimension, leaving only what an offline verifier deterministically
// recomputes. Tolerant of a hostile/garbled cached verdict (optional chaining +
// nullish normalization) — a structural difference surfaces as disagreement,
// which is the correct tamper signal. Works on both the cached snake_case JSON
// and the freshly built VerdictObject.
function projectVerdictForAgreement(v: unknown): unknown {
  const o = (v ?? {}) as VerdictObject;
  const events = Array.isArray(o.events) ? o.events : [];
  const checkpoints = Array.isArray(o.checkpoints) ? o.checkpoints : [];
  return {
    schema_version: typeof o.schema_version === "string" ? o.schema_version : null,
    events: events.map((e) => {
      const ev = (e ?? {}) as VerdictEvent;
      return {
        event_id: ev.event_id ?? null,
        signature_ok: ev.signature_ok ?? null,
        payload_bound: ev.payload_bound ?? null,
        inclusion_ok: ev.inclusion_ok ?? null,
        content_ok: ev.content_ok ?? null,
      };
    }),
    checkpoints: checkpoints.map((c) => {
      const cp = (c ?? {}) as VerdictCheckpoint;
      const atts = Array.isArray(cp.attestations) ? cp.attestations : [];
      return {
        checkpoint_tx_id: cp.checkpoint_tx_id ?? null,
        merkle_root_ok: cp.merkle_root_ok ?? null,
        // on_chain DELIBERATELY OMITTED — environment/time-dependent (see step 5).
        attestations: atts.map((a) => {
          const at = (a ?? {}) as VerdictAttestation;
          return {
            operator: at.operator ?? null,
            signature_ok: at.signature_ok ?? null,
            operator_address_bound: at.operator_address_bound ?? null,
            data_hash_bound: at.data_hash_bound ?? null,
            subject_ref_ok: at.subject_ref_ok ?? null,
          };
        }),
      };
    }),
  };
}

function summarizeExport(
  status: EvidenceStatus,
  source: EvidenceBundleResult,
  attestations: AttestationResult[],
): string {
  const attOk = attestations.filter((a) => a.ok).length;
  return (
    `Export ${status}: source bundle ${source.status} ` +
    `(${source.events.length} event(s) across ${source.checkpoints.length} checkpoint(s)); ` +
    `${attOk}/${attestations.length} operator attestation(s) valid.`
  );
}

// Re-fetch a checkpoint's raw bytes from EACH gateway and classify every
// gateway's individual outcome (evidence-export.md §4.2), then roll them up
// worst-finding-wins. Unlike the pre-§4.2 first-responsive-wins collapse, this
// records a per-gateway array so a confirm/mismatch/unreachable MIX across
// gateways is preserved; the derived collapsed `onChainOk` reproduces the old
// single-boolean exactly for a single gateway.
async function refetchCheckpoint(
  cp: TraceCheckpoint,
  gateways: string[],
  fetchImpl: typeof fetch,
): Promise<{ onChain: OnChainResult; unavailable: boolean; error?: string }> {
  let expectedHex: string | undefined;
  try {
    expectedHex = toHex(utf8(jcs(cp.envelope)));
  } catch {
    // Cannot canonicalize the checkpoint envelope — every gateway is a mismatch
    // (we can never confirm bytes we cannot compute).
    expectedHex = undefined;
  }

  const perGateway: PerGatewayOutcome[] = [];
  for (const gw of gateways) {
    perGateway.push({ gateway: gw, outcome: await probeGateway(cp, gw, expectedHex, fetchImpl) });
  }

  const onChain = rollupOnChain(perGateway);
  let error: string | undefined;
  if (onChain.rollup === "mismatch") {
    error = `on-chain bytes at ${cp.tx_id} do not match the bundle's checkpoint envelope`;
  } else if (onChain.rollup === "unreachable") {
    error = `checkpoint ${cp.tx_id} unreachable on all gateways`;
  }
  return { onChain, unavailable: onChain.rollup === "unreachable", error };
}

// One gateway's outcome for one checkpoint tx: confirm (bytes match), mismatch
// (bytes disagree), or unreachable (no response / !ok / network error).
async function probeGateway(
  cp: TraceCheckpoint,
  gateway: string,
  expectedHex: string | undefined,
  fetchImpl: typeof fetch,
): Promise<OnChainOutcome> {
  const url = `${gateway.replace(/\/+$/, "")}/${cp.tx_id}`;
  let resp: Awaited<ReturnType<typeof fetch>>;
  try {
    resp = await fetchImpl(url);
  } catch {
    return "unreachable"; // network error / timeout
  }
  if (!resp.ok) return "unreachable"; // no such tx / gateway error
  let onChainBytes: Uint8Array;
  try {
    onChainBytes = new Uint8Array(await resp.arrayBuffer());
  } catch {
    return "unreachable";
  }
  if (expectedHex === undefined) return "mismatch";
  // The on-chain bytes are the uploaded envelope bytes (JCS-canonical, per the
  // family upload invariant). Compare structurally too, so a gateway that
  // re-pretty-prints does not spuriously fail — but the canonical re-hash is
  // the load-bearing check.
  if (toHex(onChainBytes) === expectedHex) return "confirm";
  try {
    const parsed = JSON.parse(new TextDecoder().decode(onChainBytes));
    if (toHex(utf8(jcs(parsed))) === expectedHex) return "confirm";
  } catch {
    // not JSON / not parseable — a genuine mismatch
  }
  return "mismatch";
}

// Rollup rule (§4.2): mismatch if ANY gateway is mismatch; else confirm if ANY
// is confirm; else unreachable. The collapsed `onChainOk`: false on mismatch,
// true on confirm, null on all-unreachable. An empty gateway list is treated as
// all-unreachable (no signal).
function rollupOnChain(perGateway: PerGatewayOutcome[]): OnChainResult {
  let rollup: OnChainOutcome = "unreachable";
  if (perGateway.some((g) => g.outcome === "mismatch")) rollup = "mismatch";
  else if (perGateway.some((g) => g.outcome === "confirm")) rollup = "confirm";
  const onChainOk = rollup === "mismatch" ? false : rollup === "confirm" ? true : null;
  return { rollup, onChainOk, perGateway };
}

function getEventId(env: unknown): string {
  if (env && typeof env === "object" && typeof (env as Envelope).event_id === "string") {
    return (env as Envelope).event_id;
  }
  return "<unknown>";
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const x of bytes) out += x.toString(16).padStart(2, "0");
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
