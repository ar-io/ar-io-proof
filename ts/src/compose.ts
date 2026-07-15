// Attested-evidence-export composer (`proof export`, evidence-export.md §5,
// phase 2). The last-mile issuer/runtime job the kernel does NOT own (§5.1
// "Out of the kernel"): take a source `ario.anchor.trace/v1` bundle + a set of
// operator attestation records + an exporter Ed25519 key, and PRODUCE one signed,
// offline-verifiable `ario.evidence.export/v1` artifact — exactly the bytes the
// kernel's verifyExportBody round-trip-verifies.
//
// This is the inverse of evidence.ts's verifyExportBody, and it is deliberately
// thin: it never reimplements the verdict recompute (it calls the kernel's own
// recomputeExportVerdict, which reuses verifyEvidenceBundle + verifyAttestation +
// buildVerdictObject), so the cached kernel_verdict it embeds cannot drift from
// what the verifier recomputes (§5 step 5). Pure/offline — no network in this
// slice; a `--sidecar <url>` attestation fetch is a documented follow-up (§5.1),
// not built here.
//
// Trust boundary (P-4, "anyone can export"): the WRAPPER is Ed25519-signed by the
// exporter's key; the embedded operator attestations keep their own RSA-PSS
// signatures untouched (the composer never re-signs them — it is not the
// operator). The only per-record transformation is a boundary transcode of the
// attestation `signature` to the lowercase hex §2.2 stores; that field is OUTSIDE
// the signed attestation payload (JCS(payload)), so re-encoding it is safe and
// does not invalidate the operator signature.

import {
  EXPORT_BODY_TYPE,
  recomputeExportVerdict,
} from "./evidence.js";
import type {
  AttestationRecord,
  EvidenceBundle,
  EvidenceStatus,
  ExportBody,
} from "./evidence.js";
import {
  base64UrlToBytes,
  bytesToHex,
  ed25519PublicKey,
  ed25519Sign,
  sha256Hex,
  utf8,
} from "./crypto.js";
import { jcs } from "./verifier.js";

// The exporter's Ed25519 wrapper-signing key. `privateKey` is a 32-byte seed as
// lowercase hex (the @noble/ed25519 / stack convention, e.g. the fixtures'
// SEED_HEX). `publicKey` is derived from it when omitted.
export interface ExporterKey {
  privateKey: string;
  publicKey?: string;
}

export interface ComposeExportOptions {
  // The composing issuer's instance id → wrapper issuer.issuer_id (§2.1).
  // Identity CONTEXT only; the load-bearing key is the wrapper public_key.
  issuerId?: string;
  // Named delivery surface for the wrapper (§2.1). Not trusted. Default null.
  gateway?: string | null;
  // Wrapper custody pointer (§2.3): GENESIS for a one-off export (default), or
  // SHA-256(JCS(prior wrapper without signature)) for a re-issued chain link.
  previousHash?: string;
  // RFC 3339 compose time → wrapper generated_at + verdict as_of (§2.1). Default
  // new Date().toISOString().
  generatedAt?: string;
}

export interface ComposeExportResult {
  // The signed, offline-verifiable ario.evidence.export/v1 artifact.
  bundle: EvidenceBundle;
  // The export rollup the embedded kernel_verdict carries (verified|partial|failed).
  status: EvidenceStatus;
  // SHA-256(JCS(source_bundle)) linkage commitment (§2.2), for logging.
  sourceBundleHash: string;
  // Count of embedded attestations that fully bound (sig + operator + data_hash).
  boundAttestations: number;
}

const GENESIS = "GENESIS";
const EXPORT_SCHEMA = "ario.evidence.export/v1";

// Transcode an attestation `signature` to the lowercase hex §2.2 mandates. The
// issuer emits either lowercase-hex or unpadded base64url; §2.2 stores hex, so
// this is the composer's boundary normalization. Heuristic mirrors the repo's
// existing hex-vs-text discriminator (cli.ts decodeLogValue): an even-length,
// all-hex-digit string is already hex (lowercased); anything else is decoded as
// base64url and hex-encoded. A 256-byte RSA signature is 512 hex chars vs ~342
// base64url chars, so the two never collide in practice. Throws on a value that
// is neither.
export function attestationSignatureToHex(signature: string): string {
  if (signature.length > 0 && signature.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(signature)) {
    return signature.toLowerCase();
  }
  return bytesToHex(base64UrlToBytes(signature));
}

// Normalize one attestation record for embedding: deep-clone (never mutate the
// caller's input) and transcode its signature to lowercase hex. Everything else
// — payload, public_key, signature_alg, checkpoint_tx_id — rides verbatim so the
// operator's RSA-PSS signature over JCS(payload) remains valid.
function normalizeAttestation(rec: AttestationRecord): AttestationRecord {
  const cloned = JSON.parse(JSON.stringify(rec)) as AttestationRecord;
  if (typeof cloned.signature !== "string") {
    throw new Error("attestation record missing a string `signature`");
  }
  cloned.signature = attestationSignatureToHex(cloned.signature);
  return cloned;
}

// Compose an attested evidence export (evidence-export.md §5).
//
// 1. Normalize + transcode the attestation records (boundary hex, above).
// 2. Recompute the §4 kernel_verdict over the source bundle + attestations,
//    reusing the kernel's own verify path (recomputeExportVerdict) so the cached
//    copy byte-agrees with the verifier's later recompute (§5 step 5).
// 3. Assemble the export body: kernel_verdict + inline source_bundle +
//    source_bundle_hash = SHA-256(JCS(source_bundle)) + attestations[] + schema.
// 4. Build the ario.evidence/v1 wrapper (body_type export, Ed25519), strip
//    signature, JCS, Ed25519-sign with the exporter key, attach.
//
// Returns the signed artifact + a small compose summary.
export async function composeExport(
  sourceBundle: EvidenceBundle,
  attestations: AttestationRecord[],
  exporterKey: ExporterKey,
  options: ComposeExportOptions = {},
): Promise<ComposeExportResult> {
  if (sourceBundle === null || typeof sourceBundle !== "object" || Array.isArray(sourceBundle)) {
    throw new Error("composeExport: source bundle must be a JSON object");
  }
  if (!Array.isArray(attestations)) {
    throw new Error("composeExport: attestations must be an array");
  }
  if (typeof exporterKey?.privateKey !== "string" || exporterKey.privateKey.length === 0) {
    throw new Error("composeExport: exporterKey.privateKey (32-byte hex seed) is required");
  }

  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const previousHash = options.previousHash ?? GENESIS;
  const issuerId = options.issuerId ?? "ar-io-verify";
  const gateway = options.gateway ?? null;

  // (1) boundary-transcode the attestation signatures to hex.
  const records = attestations.map(normalizeAttestation);

  // (2) recompute the §4 verdict via the KERNEL's own verify path (no reimpl).
  const composed = await recomputeExportVerdict(sourceBundle, records, generatedAt);

  // (3) assemble the export body. source_bundle_hash is SHA-256(JCS(source)) —
  // the linkage commitment the wrapper signature transitively covers (§2.4).
  const sourceBundleHash = await sha256Hex(utf8(jcs(sourceBundle)));
  const body: ExportBody = {
    kernel_verdict: composed.verdict,
    source_bundle: sourceBundle,
    source_bundle_hash: sourceBundleHash,
    attestations: records,
    export_schema: EXPORT_SCHEMA,
  };

  // (4) build + sign the ario.evidence/v1 wrapper. The wrapper `verdict` is the
  // coarse family rollup DERIVED from body.kernel_verdict (display context, never
  // trusted — the verifier recomputes). body_hash = SHA-256(JCS(body)).
  const publicKey = exporterKey.publicKey ?? (await ed25519PublicKey(exporterKey.privateKey));
  const wrapperPre = {
    spec_version: "ario.evidence/v1",
    body_type: EXPORT_BODY_TYPE,
    issuer: { kind: "issuer", issuer_id: issuerId },
    generated_at: generatedAt,
    gateway,
    verdict: {
      status: composed.verdict.status,
      ...(composed.verdict.summary !== undefined ? { summary: composed.verdict.summary } : {}),
      ...(composed.verdict.counts !== undefined ? { counts: composed.verdict.counts } : {}),
      as_of: generatedAt,
    },
    body,
    body_hash: await sha256Hex(utf8(jcs(body))),
    previous_hash: previousHash,
    signature_alg: "ed25519",
    public_key: publicKey,
  };
  const signature = await ed25519Sign(utf8(jcs(wrapperPre)), exporterKey.privateKey);
  const bundle: EvidenceBundle = { ...wrapperPre, signature };

  return {
    bundle,
    status: composed.status,
    sourceBundleHash,
    boundAttestations: composed.attestations.filter((a) => a.ok).length,
  };
}
