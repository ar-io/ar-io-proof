// Agent inclusion-proof bundle verification (ar-io-agent artifact.md §10,
// ario.agent.proof/v1). Built in-test from the kernel primitives: an INLINE
// ario.agent/v1 checkpoint envelope (payload carries merkle_root + leaf_count)
// plus a leaf object and its RFC 9162 audit path. The CLI sniffs spec_version
// and routes here, so one verifier covers both agent and anchor bundles.

import * as ed from "@noble/ed25519";
import { describe, expect, it } from "vitest";

import { bytesToHex, sha256Hex, utf8 } from "../src/crypto.js";
import { auditPath, leafHash, merkleRoot } from "../src/merkle.js";
import { jcs } from "../src/verifier.js";
import { isAgentProofSpec, verifyAgentProofBundle } from "../src/agent-proof.js";
import type { AgentProofBundle } from "../src/agent-proof.js";

const SEED_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
function seed(): Uint8Array {
  return Uint8Array.from(Buffer.from(SEED_HEX, "hex"));
}
async function pubHex(): Promise<string> {
  return bytesToHex(await ed.getPublicKeyAsync(seed()));
}

// Sign an INLINE ario.agent/v1 envelope (payload is part of the signed scope).
async function signInlineEnvelope(payload: unknown): Promise<Record<string, unknown>> {
  const payloadHash = await sha256Hex(utf8(jcs(payload)));
  const pre: Record<string, unknown> = {
    spec_version: "ario.agent/v1",
    event_id: "11111111-1111-4111-8111-111111111111",
    event_type: "verification_checkpoint",
    subject: { type: "checkpoint", tenant_id: "acme", agent_id: "host-01" },
    payload,
    payload_hash: payloadHash,
    previous_hash: "GENESIS",
    signed_at: "2026-06-22T00:00:00Z",
    public_key: await pubHex(),
  };
  const sig = await ed.signAsync(utf8(jcs(pre)), seed());
  return { ...pre, signature: bytesToHex(sig) };
}

// Build a full ario.agent.proof/v1 bundle for the leaf at `proveIndex`.
async function buildAgentProofBundle(
  leaves: Record<string, unknown>[],
  proveIndex: number,
): Promise<AgentProofBundle> {
  const leafHashes = await Promise.all(leaves.map((l) => leafHash(utf8(jcs(l)))));
  const root = await merkleRoot(leafHashes);
  const checkpointEnvelope = await signInlineEnvelope({
    merkle_root: bytesToHex(root),
    leaf_count: leaves.length,
    window_start: "2026-06-22T00:00:00Z",
  });
  return {
    spec_version: "ario.agent.proof/v1",
    checkpoint_envelope: checkpointEnvelope as unknown as AgentProofBundle["checkpoint_envelope"],
    checkpoint_tx_id: "agent-checkpoint-tx-0001",
    leaf: leaves[proveIndex]!,
    leaf_index: proveIndex,
    audit_path: (await auditPath(proveIndex, leafHashes)).map(bytesToHex),
  };
}

const LEAVES = [
  { asset_id: "a", outcome: "verified" },
  { asset_id: "b", outcome: "verified" },
  { asset_id: "c", outcome: "tampered" },
  { asset_id: "d", outcome: "verified" },
  { asset_id: "e", outcome: "verified" },
];

describe("isAgentProofSpec", () => {
  it("recognizes the agent proof spec (and minors)", () => {
    expect(isAgentProofSpec("ario.agent.proof/v1")).toBe(true);
    expect(isAgentProofSpec("ario.agent.proof/v1.2")).toBe(true);
    expect(isAgentProofSpec("ario.evidence/v1")).toBe(false);
    expect(isAgentProofSpec(undefined)).toBe(false);
  });
});

describe("verifyAgentProofBundle", () => {
  it("verifies a well-formed inclusion proof for each leaf", async () => {
    for (let i = 0; i < LEAVES.length; i++) {
      const bundle = await buildAgentProofBundle(LEAVES, i);
      const r = await verifyAgentProofBundle(bundle);
      expect(r.status, `leaf ${i}`).toBe("verified");
      expect(r.checkpointOk).toBe(true);
      expect(r.inclusionOk).toBe(true);
      expect(r.leafCount).toBe(5);
      expect(r.leafIndex).toBe(i);
    }
  });

  it("fails when the leaf is mutated (no longer the committed leaf)", async () => {
    const bundle = await buildAgentProofBundle(LEAVES, 2);
    (bundle.leaf as { outcome: string }).outcome = "verified"; // flip c's outcome
    const r = await verifyAgentProofBundle(bundle);
    expect(r.status).toBe("failed");
    expect(r.inclusionOk).toBe(false);
  });

  it("fails when an audit_path entry is tampered", async () => {
    const bundle = await buildAgentProofBundle(LEAVES, 0);
    const ap = bundle.audit_path;
    ap[0] = ap[0]!.slice(0, -1) + (ap[0]!.endsWith("0") ? "1" : "0");
    const r = await verifyAgentProofBundle(bundle);
    expect(r.status).toBe("failed");
    expect(r.inclusionOk).toBe(false);
  });

  it("fails when the checkpoint envelope signature is forged", async () => {
    const bundle = await buildAgentProofBundle(LEAVES, 0);
    (bundle.checkpoint_envelope as { signature: string }).signature = (
      bundle.checkpoint_envelope as { signature: string }
    ).signature.replace(/^../, "00");
    const r = await verifyAgentProofBundle(bundle);
    expect(r.status).toBe("failed");
    expect(r.checkpointOk).toBe(false);
  });

  it("malformed when spec_version is wrong / structure is missing", async () => {
    const good = await buildAgentProofBundle(LEAVES, 0);
    expect((await verifyAgentProofBundle({ ...good, spec_version: "nope" })).status).toBe("malformed");
    expect((await verifyAgentProofBundle(null)).status).toBe("malformed");
    const { leaf: _leaf, ...noLeaf } = good;
    expect((await verifyAgentProofBundle(noLeaf)).status).toBe("malformed");
  });

  it("confirms verified on a matching on-chain re-fetch", async () => {
    const bundle = await buildAgentProofBundle(LEAVES, 1);
    const onChain = utf8(jcs(bundle.checkpoint_envelope));
    const fetchImpl = (async () =>
      new Response(onChain as unknown as BodyInit, { status: 200 })) as unknown as typeof fetch;
    const r = await verifyAgentProofBundle(bundle, { gateways: ["https://gw.example"], fetchImpl });
    expect(r.status).toBe("verified");
    expect(r.onChainOk).toBe(true);
  });

  it("partial (gateway-unavailable) when no gateway responds", async () => {
    const bundle = await buildAgentProofBundle(LEAVES, 1);
    const fetchImpl = (async () => {
      throw new Error("down");
    }) as unknown as typeof fetch;
    const r = await verifyAgentProofBundle(bundle, { gateways: ["https://down"], fetchImpl });
    expect(r.status).toBe("partial");
    expect(r.onChainOk).toBe(null);
  });
});
