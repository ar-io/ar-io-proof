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

import { ed25519Verify, hexToBytes, sha256Hex, utf8 } from "./crypto.js";
import { leafHash, verifyInclusion } from "./merkle.js";
import { jcs, verifyEnvelope } from "./verifier.js";
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

export interface CheckpointResult {
  txId: string;
  // The checkpoint envelope verified (signature + payload binding to its record).
  envelopeOk: boolean;
  // The committed record's merkle_root equals the checkpoint's claimed merkle_root.
  merkleRootOk: boolean;
  // If gateways were supplied: the on-chain bytes at tx_id matched the envelope.
  // null when no gateway re-fetch was requested.
  onChainOk: boolean | null;
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
  errors: string[];
}

export interface VerifyEvidenceOptions {
  // Gateways to re-fetch each checkpoint_tx_id from (first responsive wins).
  // When supplied, the on-chain bytes MUST byte-match the bundle's checkpoint
  // envelope, proving the proof is anchored, not just locally asserted.
  gateways?: string[];
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
      ok: envelopeOk && merkleRootOk,
      errors: cpErrors,
    });
  }

  // --- Step 4: per-event ------------------------------------------------------
  const eventResults: EventResult[] = [];
  for (const ev of body.events) {
    const evErrors: string[] = [];
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

    eventResults.push({
      eventId: getEventId(ev.envelope),
      envelopeOk,
      payloadBindingOk,
      inclusionOk,
      checkpointBound,
      // An event is "ok" when its envelope is authentic (signature + binding
      // not-failed), its inclusion proof reconstructs the root, and it binds to
      // a present checkpoint. A withheld record (binding null) does not fail it.
      ok: envelopeOk && inclusionOk && checkpointBound,
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
        cpr.onChainOk = outcome.ok;
        if (outcome.unavailable) gatewayUnavailable = true;
        if (outcome.error) cpr.errors.push(outcome.error);
        // Fold the on-chain dimension in: a MISMATCH (false) fails the
        // checkpoint — the proof was not anchored as claimed. An UNREACHABLE
        // gateway (null) leaves the offline-sound checkpoint ok; the run
        // downgrades to "partial" (exit 3) via gatewayUnavailable, not a hard
        // failure. A match (true) keeps it ok.
        cpr.ok = cpr.envelopeOk && cpr.merkleRootOk && outcome.ok !== false;
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

// Re-fetch a checkpoint's raw bytes from the first responsive gateway and
// confirm they byte-match the bundle's checkpoint envelope (its JCS bytes).
async function refetchCheckpoint(
  cp: TraceCheckpoint,
  gateways: string[],
  fetchImpl: typeof fetch,
): Promise<{ ok: boolean | null; unavailable: boolean; error?: string }> {
  let expected: Uint8Array;
  try {
    expected = utf8(jcs(cp.envelope));
  } catch (e) {
    return { ok: false, unavailable: false, error: `cannot canonicalize checkpoint envelope: ${stringifyErr(e)}` };
  }
  const expectedHex = toHex(expected);

  let anyReachable = false;
  for (const gw of gateways) {
    const url = `${gw.replace(/\/+$/, "")}/${cp.tx_id}`;
    try {
      const resp = await fetchImpl(url);
      if (!resp.ok) continue; // try the next gateway
      anyReachable = true;
      const onChain = new Uint8Array(await resp.arrayBuffer());
      // The on-chain bytes are the uploaded envelope bytes (JCS-canonical, per
      // the family upload invariant). Compare structurally too, so a gateway
      // that re-pretty-prints does not spuriously fail — but the canonical
      // re-hash is the load-bearing check.
      if (toHex(onChain) === expectedHex) return { ok: true, unavailable: false };
      try {
        const parsed = JSON.parse(new TextDecoder().decode(onChain));
        if (toHex(utf8(jcs(parsed))) === expectedHex) return { ok: true, unavailable: false };
      } catch {
        // not JSON / not parseable — fall through to mismatch
      }
      return {
        ok: false,
        unavailable: false,
        error: `on-chain bytes at ${cp.tx_id} do not match the bundle's checkpoint envelope`,
      };
    } catch {
      // network error on this gateway — try the next
    }
  }
  if (anyReachable) {
    return { ok: false, unavailable: false, error: `checkpoint ${cp.tx_id} mismatched on every gateway` };
  }
  return { ok: null, unavailable: true, error: `checkpoint ${cp.tx_id} unreachable on all gateways` };
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
