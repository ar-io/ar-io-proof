// Agent inclusion-proof bundle verification (ar-io-agent artifact.md §10).
//
// The `ario.agent.proof/v1` bundle is the agent's ~1.4 KB self-contained
// inclusion proof: a signed checkpoint envelope (ario.agent/v1, INLINE payload)
// plus a single leaf object and its RFC 9162 audit path. Verifying it is the
// inverse of `ariod proof`. The CLI sniffs `spec_version` and routes here so
// ONE verifier covers both the agent (this) and the anchor SDK (evidence.ts).
//
// Algorithm (artifact.md §10):
//   1. Verify the checkpoint envelope (signature + inline payload_hash bind).
//   2. leaf_hash = SHA-256(0x00 || JCS(leaf)).
//   3. Walk audit_path with leaf_index + leaf_count (from the checkpoint
//      payload) to reconstruct the root.
//   4. Confirm the reconstructed root == checkpoint_envelope.payload.merkle_root.
//   5. (optional) Re-fetch checkpoint_tx_id from a gateway and byte-compare.

import { hexToBytes, utf8 } from "./crypto.js";
import { leafHash, verifyInclusion } from "./merkle.js";
import { jcs, verifyEnvelope } from "./verifier.js";
import type { Envelope } from "./types.js";

export const AGENT_PROOF_SPEC_PREFIX = "ario.agent.proof/v1";

export interface AgentProofBundle {
  spec_version: string;
  checkpoint_envelope: Envelope;
  checkpoint_tx_id: string;
  leaf: Record<string, unknown>;
  leaf_index: number;
  audit_path: string[];
  [k: string]: unknown;
}

export interface AgentProofResult {
  status: "verified" | "failed" | "partial" | "malformed";
  // The checkpoint envelope is authentic (signature + inline payload bind).
  checkpointOk: boolean;
  // The leaf's RFC 9162 audit path reconstructs the checkpoint's merkle_root.
  inclusionOk: boolean;
  // On-chain re-fetch matched (null when not requested).
  onChainOk: boolean | null;
  onChainChecked: boolean;
  leafIndex: number;
  leafCount: number | null;
  checkpointTxId: string | null;
  errors: string[];
}

export interface VerifyAgentProofOptions {
  gateways?: string[];
  fetchImpl?: typeof fetch;
}

function stringifyErr(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const x of bytes) out += x.toString(16).padStart(2, "0");
  return out;
}

export function isAgentProofSpec(specVersion: unknown): boolean {
  if (typeof specVersion !== "string") return false;
  return specVersion === AGENT_PROOF_SPEC_PREFIX || specVersion.startsWith(`${AGENT_PROOF_SPEC_PREFIX}.`);
}

export async function verifyAgentProofBundle(
  bundle: unknown,
  options: VerifyAgentProofOptions = {},
): Promise<AgentProofResult> {
  const fail = (error: string): AgentProofResult => ({
    status: "malformed",
    checkpointOk: false,
    inclusionOk: false,
    onChainOk: null,
    onChainChecked: false,
    leafIndex: -1,
    leafCount: null,
    checkpointTxId: null,
    errors: [error],
  });

  if (bundle === null || typeof bundle !== "object" || Array.isArray(bundle)) {
    return fail("agent proof bundle is not a JSON object");
  }
  const b = bundle as AgentProofBundle;
  if (!isAgentProofSpec(b.spec_version)) {
    return fail(`unsupported agent-proof spec_version: ${JSON.stringify(b.spec_version)}`);
  }
  if (b.checkpoint_envelope === null || typeof b.checkpoint_envelope !== "object") {
    return fail("agent proof bundle missing checkpoint_envelope");
  }
  if (b.leaf === null || typeof b.leaf !== "object") {
    return fail("agent proof bundle missing leaf");
  }
  if (!Array.isArray(b.audit_path)) {
    return fail("agent proof bundle missing audit_path[]");
  }

  const errors: string[] = [];

  // Step 1: verify the checkpoint envelope (inline payload — no payloadBytes).
  let checkpointOk = false;
  let merkleRoot: string | undefined;
  let leafCount: number | undefined;
  try {
    const res = await verifyEnvelope(b.checkpoint_envelope);
    checkpointOk = res.ok && res.payloadHashOk === true;
    if (!res.signatureOk) errors.push("checkpoint envelope signature failed");
    if (res.payloadHashOk !== true) errors.push("checkpoint envelope payload binding failed");
    const payload = (b.checkpoint_envelope.payload ?? {}) as {
      merkle_root?: unknown;
      leaf_count?: unknown;
    };
    if (typeof payload.merkle_root === "string") merkleRoot = payload.merkle_root;
    if (typeof payload.leaf_count === "number") leafCount = payload.leaf_count;
    if (merkleRoot === undefined) errors.push("checkpoint payload missing merkle_root");
    if (leafCount === undefined) errors.push("checkpoint payload missing leaf_count");
  } catch (e) {
    errors.push(`checkpoint verify error: ${stringifyErr(e)}`);
  }

  // Steps 2-4: leaf hash, audit-path walk, root match.
  let inclusionOk = false;
  if (merkleRoot !== undefined && leafCount !== undefined) {
    try {
      const lh = await leafHash(utf8(jcs(b.leaf)));
      inclusionOk = await verifyInclusion(
        lh,
        b.leaf_index,
        leafCount,
        b.audit_path.map((h) => hexToBytes(h)),
        hexToBytes(merkleRoot),
      );
      if (!inclusionOk) errors.push("RFC 9162 inclusion proof did not reconstruct merkle_root");
    } catch (e) {
      errors.push(`inclusion verify error: ${stringifyErr(e)}`);
    }
  }

  // Step 5: optional on-chain re-fetch.
  const gateways = options.gateways ?? [];
  const onChainChecked = gateways.length > 0;
  let onChainOk: boolean | null = null;
  let gatewayUnavailable = false;
  if (onChainChecked) {
    const fetchImpl = options.fetchImpl ?? (globalThis.fetch as typeof fetch | undefined);
    if (typeof fetchImpl !== "function") {
      gatewayUnavailable = true;
      errors.push("on-chain re-fetch requested but no fetch implementation is available");
    } else {
      const outcome = await refetch(b.checkpoint_envelope, b.checkpoint_tx_id, gateways, fetchImpl);
      onChainOk = outcome.ok;
      if (outcome.unavailable) gatewayUnavailable = true;
      if (outcome.error) errors.push(outcome.error);
    }
  }

  let status: AgentProofResult["status"];
  if (!checkpointOk || !inclusionOk || onChainOk === false) {
    status = "failed";
  } else if (gatewayUnavailable) {
    status = "partial";
  } else {
    status = "verified";
  }

  return {
    status,
    checkpointOk,
    inclusionOk,
    onChainOk,
    onChainChecked,
    leafIndex: typeof b.leaf_index === "number" ? b.leaf_index : -1,
    leafCount: leafCount ?? null,
    checkpointTxId: typeof b.checkpoint_tx_id === "string" ? b.checkpoint_tx_id : null,
    errors,
  };
}

async function refetch(
  envelope: Envelope,
  txId: string,
  gateways: string[],
  fetchImpl: typeof fetch,
): Promise<{ ok: boolean | null; unavailable: boolean; error?: string }> {
  let expectedHex: string;
  try {
    expectedHex = toHex(utf8(jcs(envelope)));
  } catch (e) {
    return { ok: false, unavailable: false, error: `cannot canonicalize checkpoint envelope: ${stringifyErr(e)}` };
  }
  let anyReachable = false;
  for (const gw of gateways) {
    const url = `${gw.replace(/\/+$/, "")}/${txId}`;
    try {
      const resp = await fetchImpl(url);
      if (!resp.ok) continue;
      anyReachable = true;
      const onChain = new Uint8Array(await resp.arrayBuffer());
      if (toHex(onChain) === expectedHex) return { ok: true, unavailable: false };
      try {
        const parsed = JSON.parse(new TextDecoder().decode(onChain));
        if (toHex(utf8(jcs(parsed))) === expectedHex) return { ok: true, unavailable: false };
      } catch {
        // fall through
      }
      return {
        ok: false,
        unavailable: false,
        error: `on-chain bytes at ${txId} do not match the checkpoint envelope`,
      };
    } catch {
      // try next gateway
    }
  }
  if (anyReachable) return { ok: false, unavailable: false, error: `checkpoint ${txId} mismatched on every gateway` };
  return { ok: null, unavailable: true, error: `checkpoint ${txId} unreachable on all gateways` };
}
