// Evidence-bundle verification (specs/evidence-bundle.md §5.1,
// ario.anchor.trace/v1). We build a REAL trace bundle in-test from the kernel's
// own primitives + @noble/ed25519 (the same primitives @ar.io/anchor uses), so
// the round-trip exercises actual signatures, payload binding, RFC 9162
// inclusion, body_hash, and the wrapper signature — no mocks of the crypto.
//
// The wrap-don't-merge / recompute-don't-trust / reject-unknown-major
// discipline is pinned by the negative cases: a flipped record byte fails its
// event (and the rollup), a withheld record yields payload-undetermined (NOT a
// failure), a tampered audit-path entry breaks inclusion, a forged wrapper
// signature is a hard failure, and an unknown major is malformed.

import * as ed from "@noble/ed25519";
import { describe, expect, it } from "vitest";

import { bytesToHex, sha256Hex, utf8 } from "../src/crypto.js";
import { auditPath, leafHash, merkleRoot } from "../src/merkle.js";
import { jcs } from "../src/verifier.js";
import { verifyEvidenceBundle } from "../src/evidence.js";
import type { EvidenceBundle } from "../src/evidence.js";

const SEED_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
function seed(): Uint8Array {
  return Uint8Array.from(Buffer.from(SEED_HEX, "hex"));
}
async function pubHex(): Promise<string> {
  return bytesToHex(await ed.getPublicKeyAsync(seed()));
}

// Build a signed ario.events/v1 external-commitment envelope over a record.
async function signEventEnvelope(
  record: unknown,
  eventId: string,
): Promise<{ envelope: Record<string, unknown>; recordBytes: Uint8Array }> {
  const recordBytes = utf8(jcs(record));
  const payloadHash = await sha256Hex(recordBytes);
  const pre: Record<string, unknown> = {
    spec_version: "ario.events/v1",
    event_id: eventId,
    payload_hash: payloadHash,
    signed_at: "2026-06-22T00:00:00Z",
    environment: "dev",
    public_key: await pubHex(),
  };
  const sig = await ed.signAsync(utf8(jcs(pre)), seed());
  return { envelope: { ...pre, signature: bytesToHex(sig) }, recordBytes };
}

// Build a full ario.anchor.trace/v1 evidence bundle from N events in one window.
async function buildTraceBundle(
  eventRecords: unknown[],
  opts: { withholdRecordOf?: number; assertedStatus?: string } = {},
): Promise<EvidenceBundle> {
  // 1. Per-event leaf envelopes (leaf = SHA-256(0x00 || JCS(envelope))).
  const events: {
    envelope: Record<string, unknown>;
    recordBytes: Uint8Array;
    leaf: Uint8Array;
  }[] = [];
  for (let i = 0; i < eventRecords.length; i++) {
    const { envelope, recordBytes } = await signEventEnvelope(
      eventRecords[i],
      `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`,
    );
    events.push({ envelope, recordBytes, leaf: await leafHash(utf8(jcs(envelope))) });
  }

  // 2. Merkle tree + checkpoint record/envelope (external commitment).
  const leaves = events.map((e) => e.leaf);
  const root = await merkleRoot(leaves);
  const rootHex = bytesToHex(root);
  const checkpointRecord = {
    payload_version: 1,
    spec_version: "ario.events/v1",
    event_type: "checkpoint",
    subject: { type: "producer" },
    previous_hash: "GENESIS",
    event: { merkle_root: rootHex, leaf_count: leaves.length },
    context: { chain_key: "batcher:test" },
    metadata: {},
    extras: {},
  };
  const { envelope: checkpointEnvelope, recordBytes: cpRecordBytes } = await signEventEnvelope(
    checkpointRecord,
    "00000000-0000-4000-8000-ffffffffffff",
  );
  const txId = "checkpoint-tx-0001";

  // 3. Assemble the body.
  const body = {
    checkpoints: [
      {
        tx_id: txId,
        envelope: checkpointEnvelope,
        record_bytes: bytesToHex(cpRecordBytes),
        merkle_root: rootHex,
      },
    ],
    events: await Promise.all(
      events.map(async (e, i) => ({
        envelope: e.envelope,
        ...(opts.withholdRecordOf === i ? {} : { record_bytes: bytesToHex(e.recordBytes) }),
        inclusion: {
          leaf_hash: bytesToHex(e.leaf),
          leaf_index: i,
          leaf_count: leaves.length,
          audit_path: (await auditPath(i, leaves)).map(bytesToHex),
          checkpoint_tx_id: txId,
        },
      })),
    ),
  };

  // 4. Sign the wrapper.
  const bodyHash = await sha256Hex(utf8(jcs(body)));
  const pre: Record<string, unknown> = {
    spec_version: "ario.evidence/v1",
    body_type: "ario.anchor.trace/v1",
    issuer: { kind: "producer" },
    generated_at: "2026-06-22T00:00:00Z",
    gateway: null,
    verdict: { status: opts.assertedStatus ?? "verified" },
    body,
    body_hash: bodyHash,
    previous_hash: "GENESIS",
    signature_alg: "ed25519",
    public_key: await pubHex(),
  };
  const sig = await ed.signAsync(utf8(jcs(pre)), seed());
  return { ...pre, signature: bytesToHex(sig) } as unknown as EvidenceBundle;
}

const R0 = { kind: "llm.call", model: "claude", value: 0 };
const R1 = { kind: "llm.call", model: "claude", value: 1 };
const R2 = { kind: "llm.call", model: "claude", value: 2 };

describe("verifyEvidenceBundle — round trip (the good path)", () => {
  it("a freshly built 3-event trace bundle verifies fully green", async () => {
    const bundle = await buildTraceBundle([R0, R1, R2]);
    const r = await verifyEvidenceBundle(bundle);

    expect(r.status).toBe("verified");
    expect(r.signatureOk).toBe(true);
    expect(r.bodyHashOk).toBe(true);
    expect(r.specVersionOk).toBe(true);
    expect(r.bodyType).toBe("ario.anchor.trace/v1");
    expect(r.checkpoints).toHaveLength(1);
    expect(r.checkpoints[0]!.ok).toBe(true);
    expect(r.checkpoints[0]!.merkleRootOk).toBe(true);
    expect(r.events).toHaveLength(3);
    for (const ev of r.events) {
      expect(ev.ok).toBe(true);
      expect(ev.payloadBindingOk).toBe(true);
      expect(ev.inclusionOk).toBe(true);
      expect(ev.checkpointBound).toBe(true);
    }
  });

  it("a single-event window verifies (empty audit path)", async () => {
    const bundle = await buildTraceBundle([R0]);
    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("verified");
    expect(r.events[0]!.inclusionOk).toBe(true);
  });
});

describe("verifyEvidenceBundle — tamper is caught", () => {
  it("flipping one byte of a record_bytes fails that event (and the rollup)", async () => {
    const bundle = await buildTraceBundle([R0, R1, R2]);
    const body = bundle.body as { events: { record_bytes: string }[] };
    // Flip the last hex nibble of event 1's committed record.
    const rb = body.events[1]!.record_bytes;
    body.events[1]!.record_bytes = rb.slice(0, -1) + (rb.endsWith("0") ? "1" : "0");
    // Re-sign the wrapper so we're testing the BODY tamper, not the wrapper sig.
    await reSignWrapper(bundle);

    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("failed");
    expect(r.events[1]!.payloadBindingOk).toBe(false);
    expect(r.events[1]!.ok).toBe(false);
    // The untouched events still verify individually.
    expect(r.events[0]!.ok).toBe(true);
    expect(r.events[2]!.ok).toBe(true);
  });

  it("flipping an audit_path entry breaks that event's inclusion proof", async () => {
    const bundle = await buildTraceBundle([R0, R1, R2]);
    const body = bundle.body as { events: { inclusion: { audit_path: string[] } }[] };
    const ap = body.events[2]!.inclusion.audit_path;
    ap[0] = ap[0]!.slice(0, -1) + (ap[0]!.endsWith("0") ? "1" : "0");
    await reSignWrapper(bundle);

    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("failed");
    expect(r.events[2]!.inclusionOk).toBe(false);
    expect(r.events[2]!.ok).toBe(false);
  });

  it("a forged wrapper signature is a hard failure (body not trusted)", async () => {
    const bundle = await buildTraceBundle([R0, R1]);
    bundle.signature = bundle.signature.replace(/^../, "00");
    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("failed");
    expect(r.signatureOk).toBe(false);
    expect(r.checkpoints).toHaveLength(0); // we don't pretend to verify a tampered body
  });

  it("a mutated body without re-signing the wrapper is caught by body_hash + signature", async () => {
    const bundle = await buildTraceBundle([R0, R1]);
    (bundle.body as { events: { record_bytes: string }[] }).events[0]!.record_bytes = "ab".repeat(8);
    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("failed");
    // body_hash no longer matches AND the wrapper signature no longer matches.
    expect(r.bodyHashOk).toBe(false);
    expect(r.signatureOk).toBe(false);
  });

  it("an event pointing at a non-existent checkpoint_tx_id fails to bind", async () => {
    const bundle = await buildTraceBundle([R0, R1]);
    (bundle.body as { events: { inclusion: { checkpoint_tx_id: string } }[] }).events[0]!.inclusion.checkpoint_tx_id =
      "no-such-tx";
    await reSignWrapper(bundle);
    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("failed");
    expect(r.events[0]!.checkpointBound).toBe(false);
    expect(r.events[0]!.ok).toBe(false);
  });
});

describe("verifyEvidenceBundle — withheld record is undetermined, not failed", () => {
  it("a withheld record_bytes yields payload-undetermined and a partial (still exit-0) verdict", async () => {
    const bundle = await buildTraceBundle([R0, R1, R2], { withholdRecordOf: 1 });
    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("partial");
    expect(r.events[1]!.payloadBindingOk).toBe(null); // semantics-undetermined
    expect(r.events[1]!.ok).toBe(true); // signature + inclusion still hold
    // The bundle is cryptographically sound — every check that COULD run passed.
    expect(r.events[0]!.payloadBindingOk).toBe(true);
    expect(r.events[2]!.payloadBindingOk).toBe(true);
  });
});

describe("verifyEvidenceBundle — wrapper discipline", () => {
  it("rejects an unknown spec_version major as malformed", async () => {
    const bundle = await buildTraceBundle([R0]);
    bundle.spec_version = "ario.evidence/v2";
    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("malformed");
  });

  it("rejects a non-ed25519 signature_alg as malformed (reference is ed25519-only)", async () => {
    const bundle = await buildTraceBundle([R0]);
    bundle.signature_alg = "rsa-pss-sha256";
    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("malformed");
  });

  it("rejects non-object input without throwing", async () => {
    for (const bad of [null, undefined, 42, "x", []] as unknown[]) {
      const r = await verifyEvidenceBundle(bad);
      expect(r.status).toBe("malformed");
    }
  });

  it("surfaces the producer's asserted status but recomputes the real one", async () => {
    // Producer LIES and claims "verified" on a tampered bundle.
    const bundle = await buildTraceBundle([R0, R1], { assertedStatus: "verified" });
    const body = bundle.body as { events: { record_bytes: string }[] };
    body.events[0]!.record_bytes = body.events[0]!.record_bytes.slice(0, -1) + "0";
    await reSignWrapper(bundle);
    const r = await verifyEvidenceBundle(bundle);
    expect(r.assertedStatus).toBe("verified"); // surfaced
    expect(r.status).toBe("failed"); // recomputed — recomputed wins
  });
});

describe("verifyEvidenceBundle — optional on-chain re-fetch", () => {
  it("confirms verified when the gateway returns the exact checkpoint bytes", async () => {
    const bundle = await buildTraceBundle([R0, R1]);
    const cp = (bundle.body as { checkpoints: { envelope: unknown }[] }).checkpoints[0]!;
    const onChainBytes = utf8(jcs(cp.envelope));
    const fetchImpl = (async () =>
      new Response(onChainBytes as unknown as BodyInit, { status: 200 })) as unknown as typeof fetch;

    const r = await verifyEvidenceBundle(bundle, { gateways: ["https://gw.example"], fetchImpl });
    expect(r.status).toBe("verified");
    expect(r.onChainChecked).toBe(true);
    expect(r.checkpoints[0]!.onChainOk).toBe(true);
  });

  it("fails when the gateway returns different bytes (not anchored as claimed)", async () => {
    const bundle = await buildTraceBundle([R0, R1]);
    const fetchImpl = (async () =>
      new Response(utf8(JSON.stringify({ different: "bytes" })) as unknown as BodyInit, {
        status: 200,
      })) as unknown as typeof fetch;
    const r = await verifyEvidenceBundle(bundle, { gateways: ["https://gw.example"], fetchImpl });
    expect(r.status).toBe("failed");
    expect(r.checkpoints[0]!.onChainOk).toBe(false);
  });

  it("reports gateway-unavailable (exit-3 shape) when every gateway is unreachable", async () => {
    const bundle = await buildTraceBundle([R0]);
    const fetchImpl = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    const r = await verifyEvidenceBundle(bundle, { gateways: ["https://down.example"], fetchImpl });
    // Offline checks all passed; only the requested on-chain confirmation could
    // not run → partial with an "unreachable" note (the CLI maps that to exit 3).
    expect(r.status).toBe("partial");
    expect(r.checkpoints[0]!.onChainOk).toBe(null);
    expect(r.errors.join(" ")).toMatch(/unreachable|could not be re-fetched/);
  });
});

// Re-sign the wrapper over the (mutated) body so a test isolates a BODY tamper
// from the wrapper signature. Mirrors the producer's signing flow.
async function reSignWrapper(bundle: EvidenceBundle): Promise<void> {
  bundle.body_hash = await sha256Hex(utf8(jcs(bundle.body)));
  const { signature: _s, ...pre } = bundle;
  bundle.public_key = await pubHex();
  bundle.signature = bytesToHex(await ed.signAsync(utf8(jcs(pre)), seed()));
}
