// @ar.io/proof — TypeScript kernel of the ar.io verification stack.
//
// The verification primitives for the Verifiable Event Envelope family
// (ar-io-agent docs/envelope-spec.md), ario.agent/v1 profile: RFC 8785 (JCS)
// canonicalization, SHA-256, Ed25519 envelope verification, and the
// content-hash extraction used for reverse provenance lookup. Sibling of the
// Python `ar-io-proof` kernel and the Go `pkg/proof` reference; conformance
// is byte-for-byte against the shared `test-vectors-v1.0` corpus.
//
// Scope boundary (envelope-spec §10 #13): this package verifies a SINGLE
// envelope. Chain walking (previous_hash), checkpoint reconciliation, and
// gateway/transport concerns are consumer-layer logic composed above it.

export { contentHashes, jcs, specVersionSupported, verifyEnvelope } from "./verifier.js";
export {
  bytesToHex,
  deriveOperatorAddress,
  ed25519Verify,
  hexToBytes,
  sha256Bytes,
  sha256Hex,
  utf8,
  verifyRsaPssSha256,
} from "./crypto.js";
export {
  EMPTY_TREE_ROOT_HEX,
  auditPath,
  leafHash,
  merkleRoot,
  nodeHash,
  verifyInclusion,
} from "./merkle.js";
export type { ContentRole, Envelope, Subject, VerificationResult, VerifyOptions } from "./types.js";

// Evidence-bundle verification (specs/evidence-bundle.md): the signed
// ario.evidence/v1 wrapper carrying the ario.anchor.trace/v1 body. The CLI
// (`npx @ar.io/proof verify`) is built on this. The same path dispatches on the
// issuer-composed ario.evidence.export/v1 body (specs/evidence-export.md) to
// verifyExportBody (embedded RSA-PSS operator attestations + a recomputed §4
// verdict object with per-gateway on-chain outcomes).
export { ANCHOR_TRACE_BODY_TYPE, EXPORT_BODY_TYPE, verifyEvidenceBundle } from "./evidence.js";
export type {
  AnchorTraceBody,
  AttestationPayload,
  AttestationRecord,
  AttestationResult,
  CheckpointResult,
  EvidenceBundle,
  EvidenceBundleResult,
  EvidenceIssuer,
  EvidenceStatus,
  EvidenceVerdict,
  EventResult,
  ExportBody,
  ExportResult,
  OnChainOutcome,
  OnChainResult,
  PerGatewayOutcome,
  TraceCheckpoint,
  TraceEvent,
  TraceInclusion,
  VerdictAttestation,
  VerdictCheckpoint,
  VerdictEvent,
  VerdictObject,
  VerdictOnChain,
  VerdictOnChainGateway,
  VerifyEvidenceOptions,
} from "./evidence.js";

// Agent inclusion-proof bundle verification (ar-io-agent artifact.md §10): the
// ario.agent.proof/v1 bundle. The CLI sniffs spec_version and routes here so
// one verifier covers both agent and anchor bundles.
export { AGENT_PROOF_SPEC_PREFIX, isAgentProofSpec, verifyAgentProofBundle } from "./agent-proof.js";
export type {
  AgentProofBundle,
  AgentProofResult,
  VerifyAgentProofOptions,
} from "./agent-proof.js";
