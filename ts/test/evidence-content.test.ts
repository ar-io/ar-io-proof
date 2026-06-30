// Content (raw-log) verification for the ario.anchor.trace/v1 body
// (evidence-bundle.md §5.1 `events[].content`). The chain the rest of
// verifyEvidenceBundle already pins is content_hash → record → payload_hash →
// signature → leaf → root; THIS file pins the one remaining link, rawLog →
// sha256 → record.event.content_hash, plus its undetermined/disagreement edges.
//
// As in evidence.test.ts we build REAL signed bundles from the kernel's own
// primitives, so every signature / hash / inclusion is genuine — only the
// disclosed bytes are varied. The committed content hash lives in the RECORD,
// NOT in verifyEnvelope's payload/event_type path (which is empty for an
// ario.events/v1 envelope) — the promoted-disclosure case proves the fallback.

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

// Sign an external-commitment ario.events/v1 envelope over a record.
async function signEvent(
  record: unknown,
  eventId: string,
): Promise<{ envelope: Record<string, unknown>; recordBytes: Uint8Array }> {
  const recordBytes = utf8(jcs(record));
  const pre: Record<string, unknown> = {
    spec_version: "ario.events/v1",
    event_id: eventId,
    payload_hash: await sha256Hex(recordBytes),
    signed_at: "2026-06-22T00:00:00Z",
    environment: "dev",
    public_key: await pubHex(),
  };
  const sig = await ed.signAsync(utf8(jcs(pre)), seed());
  return { envelope: { ...pre, signature: bytesToHex(sig) }, recordBytes };
}

// A minimal-disclosure event record carrying a committed content_hash.
async function logRecord(rawLog: Uint8Array, seq: number): Promise<Record<string, unknown>> {
  return {
    payload_version: 1,
    spec_version: "ario.events/v1",
    event_type: "log",
    subject: { type: "producer" },
    previous_hash: "GENESIS",
    event: { content_hash: await sha256Hex(rawLog), seq },
    context: {},
    metadata: {},
    extras: {},
  };
}

interface EventEntry {
  envelope: Record<string, unknown>;
  recordBytes?: Uint8Array; // omit to withhold the record
  content?: Uint8Array; // in-body disclosed bytes (hex-encoded into the body)
}

// Assemble a full signed trace bundle from pre-built event entries.
async function buildBundle(entries: EventEntry[]): Promise<EvidenceBundle> {
  const leaves = await Promise.all(entries.map((e) => leafHash(utf8(jcs(e.envelope)))));
  const rootHex = bytesToHex(await merkleRoot(leaves));
  const cpRecord = {
    payload_version: 1,
    spec_version: "ario.events/v1",
    event_type: "checkpoint",
    subject: { type: "producer" },
    previous_hash: "GENESIS",
    event: { merkle_root: rootHex, leaf_count: leaves.length },
    context: {},
    metadata: {},
    extras: {},
  };
  const { envelope: cpEnv, recordBytes: cpBytes } = await signEvent(
    cpRecord,
    "00000000-0000-4000-8000-ffffffffffff",
  );
  const txId = "content-tx-1";
  const body = {
    checkpoints: [
      { tx_id: txId, envelope: cpEnv, record_bytes: bytesToHex(cpBytes), merkle_root: rootHex },
    ],
    events: await Promise.all(
      entries.map(async (e, i) => ({
        envelope: e.envelope,
        ...(e.recordBytes ? { record_bytes: bytesToHex(e.recordBytes) } : {}),
        ...(e.content ? { content: bytesToHex(e.content) } : {}),
        inclusion: {
          leaf_hash: bytesToHex(leaves[i]!),
          leaf_index: i,
          leaf_count: leaves.length,
          audit_path: (await auditPath(i, leaves)).map(bytesToHex),
          checkpoint_tx_id: txId,
        },
      })),
    ),
  };
  return signWrapper(body);
}

// Sign an ario.evidence/v1 wrapper over an arbitrary (possibly hostile) body.
async function signWrapper(body: unknown): Promise<EvidenceBundle> {
  const pre: Record<string, unknown> = {
    spec_version: "ario.evidence/v1",
    body_type: "ario.anchor.trace/v1",
    issuer: { kind: "producer" },
    generated_at: "2026-06-22T00:00:00Z",
    gateway: null,
    verdict: { status: "verified" },
    body,
    body_hash: await sha256Hex(utf8(jcs(body))),
    previous_hash: "GENESIS",
    signature_alg: "ed25519",
    public_key: await pubHex(),
  };
  const sig = await ed.signAsync(utf8(jcs(pre)), seed());
  return { ...pre, signature: bytesToHex(sig) } as unknown as EvidenceBundle;
}

const EID = "00000000-0000-4000-8000-000000000000";
function eid(i: number): string {
  return `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`;
}

// Re-sign the wrapper after a deliberate in-body mutation, so a test isolates a
// body-content edge from the wrapper signature (mirrors the producer flow).
async function reSign(bundle: EvidenceBundle): Promise<void> {
  bundle.body_hash = await sha256Hex(utf8(jcs(bundle.body)));
  const { signature: _s, ...pre } = bundle;
  bundle.public_key = await pubHex();
  bundle.signature = bytesToHex(await ed.signAsync(utf8(jcs(pre)), seed()));
}

describe("evidence content — in-body disclosure", () => {
  it("genuine in-body content verifies (contentOk:true, status verified)", async () => {
    const raw = utf8("the genuine raw log line");
    const { envelope, recordBytes } = await signEvent(await logRecord(raw, 0), EID);
    const bundle = await buildBundle([{ envelope, recordBytes, content: raw }]);

    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("verified");
    expect(r.events[0]!.contentOk).toBe(true);
    expect(r.events[0]!.ok).toBe(true);
    expect(r.events[0]!.payloadBindingOk).toBe(true);
  });

  it("tampered in-body content fails the event (contentOk:false, status failed)", async () => {
    const raw = utf8("the genuine raw log line");
    const wrong = utf8("a DIFFERENT raw log line"); // disclosed bytes != committed hash
    const { envelope, recordBytes } = await signEvent(await logRecord(raw, 0), EID);
    // The producer signed a body that discloses the WRONG bytes — wrapper is
    // valid, but content doesn't bind to record.event.content_hash.
    const bundle = await buildBundle([{ envelope, recordBytes, content: wrong }]);

    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("failed");
    expect(r.events[0]!.contentOk).toBe(false);
    expect(r.events[0]!.ok).toBe(false);
    expect(r.events[0]!.errors.join(" ")).toMatch(/content/i);
  });

  it("no disclosed content (today's bundle) leaves contentOk:null, behavior unchanged", async () => {
    const raw = utf8("committed but never disclosed");
    const { envelope, recordBytes } = await signEvent(await logRecord(raw, 0), EID);
    const bundle = await buildBundle([{ envelope, recordBytes }]); // no content field

    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("verified");
    expect(r.events[0]!.contentOk).toBe(null);
    expect(r.events[0]!.ok).toBe(true);
  });
});

describe("evidence content — side-input (options.content)", () => {
  it("matching side-input bytes verify (contentOk:true)", async () => {
    const raw = utf8("disclosed out of band");
    const { envelope, recordBytes } = await signEvent(await logRecord(raw, 0), EID);
    const bundle = await buildBundle([{ envelope, recordBytes }]); // no in-body content

    const r = await verifyEvidenceBundle(bundle, { content: { [EID]: raw } });
    expect(r.status).toBe("verified");
    expect(r.events[0]!.contentOk).toBe(true);
  });

  it("side-input as a hex STRING is parsed as hex", async () => {
    const raw = utf8("hex-encoded side input");
    const { envelope, recordBytes } = await signEvent(await logRecord(raw, 0), EID);
    const bundle = await buildBundle([{ envelope, recordBytes }]);

    const r = await verifyEvidenceBundle(bundle, { content: { [EID]: bytesToHex(raw) } });
    expect(r.events[0]!.contentOk).toBe(true);
  });

  it("a mismatched side-input fails (contentOk:false)", async () => {
    const raw = utf8("the committed bytes");
    const { envelope, recordBytes } = await signEvent(await logRecord(raw, 0), EID);
    const bundle = await buildBundle([{ envelope, recordBytes }]);

    const r = await verifyEvidenceBundle(bundle, { content: { [EID]: utf8("not the bytes") } });
    expect(r.status).toBe("failed");
    expect(r.events[0]!.contentOk).toBe(false);
  });

  it("side-input supplied but record_bytes WITHHELD ⇒ contentOk:null + reason (never a fail)", async () => {
    const raw = utf8("disclosed but unbindable");
    const { envelope } = await signEvent(await logRecord(raw, 0), EID);
    const bundle = await buildBundle([{ envelope, content: undefined }]); // record withheld

    const r = await verifyEvidenceBundle(bundle, { content: { [EID]: raw } });
    expect(r.events[0]!.contentOk).toBe(null); // nothing committed to bind to
    expect(r.events[0]!.ok).toBe(true); // not a failure
    expect(r.status).toBe("partial"); // withheld record ⇒ undetermined binding
    expect(r.events[0]!.errors.join(" ")).toMatch(/no committed content_hash|undetermined/i);
  });
});

describe("evidence content — undetermined edges", () => {
  it("record present but no event.content_hash ⇒ contentOk:null (even with disclosure)", async () => {
    // A record with an `event` block that carries NO content_hash.
    const record = {
      payload_version: 1,
      spec_version: "ario.events/v1",
      event_type: "checkpoint",
      subject: { type: "producer" },
      previous_hash: "GENESIS",
      event: { note: "no content hash here" },
      context: {},
      metadata: {},
      extras: {},
    };
    const { envelope, recordBytes } = await signEvent(record, EID);
    const bundle = await buildBundle([{ envelope, recordBytes, content: utf8("anything") }]);

    const r = await verifyEvidenceBundle(bundle);
    expect(r.events[0]!.contentOk).toBe(null);
    expect(r.events[0]!.ok).toBe(true);
    expect(r.status).toBe("verified"); // record still binds; content just N/A
  });

  it("in-body and side-input DISAGREE ⇒ contentOk:false (hard fail)", async () => {
    const raw = utf8("the in-body genuine bytes");
    const { envelope, recordBytes } = await signEvent(await logRecord(raw, 0), EID);
    // In-body content is the genuine, signed disclosure; the side input differs.
    const bundle = await buildBundle([{ envelope, recordBytes, content: raw }]);

    const r = await verifyEvidenceBundle(bundle, {
      content: { [EID]: utf8("a conflicting side disclosure") },
    });
    expect(r.status).toBe("failed");
    expect(r.events[0]!.contentOk).toBe(false);
    expect(r.events[0]!.errors.join(" ")).toMatch(/disagree/i);
  });

  it("in-body and side-input AGREE ⇒ contentOk:true", async () => {
    const raw = utf8("identical on both sides");
    const { envelope, recordBytes } = await signEvent(await logRecord(raw, 0), EID);
    const bundle = await buildBundle([{ envelope, recordBytes, content: raw }]);

    const r = await verifyEvidenceBundle(bundle, { content: { [EID]: raw } });
    expect(r.status).toBe("verified");
    expect(r.events[0]!.contentOk).toBe(true);
  });
});

describe("evidence content — promoted-disclosure resolver branch", () => {
  it("a promoted ario.agent/v1 event binds content via contentHashes() (no record_bytes)", async () => {
    // Promoted disclosure: the committed hash is in the envelope's inline
    // payload (asset_registered → payload.hash), NOT in a record. This is the
    // branch that contentHashes() — not verifyEnvelope's path — must resolve.
    const raw = utf8("the registered asset bytes");
    const assetHash = await sha256Hex(raw);
    const payload = { hash: assetHash, name: "model.pkl" };
    const pre: Record<string, unknown> = {
      spec_version: "ario.agent/v1",
      event_id: EID,
      event_type: "asset_registered",
      subject: { type: "asset", tenant_id: "acme", agent_id: "host-01" },
      payload,
      payload_hash: await sha256Hex(utf8(jcs(payload))),
      previous_hash: "GENESIS",
      signed_at: "2026-06-22T00:00:00Z",
      public_key: await pubHex(),
    };
    const sig = await ed.signAsync(utf8(jcs(pre)), seed());
    const envelope = { ...pre, signature: bytesToHex(sig) };
    // No record_bytes — promoted profiles carry the payload inline.
    const bundle = await buildBundle([{ envelope, content: raw }]);

    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("verified");
    expect(r.events[0]!.contentOk).toBe(true);
    expect(r.events[0]!.payloadBindingOk).toBe(true); // inline payload recompute
  });

  it("a promoted event whose disclosed bytes don't match its payload.hash fails", async () => {
    const raw = utf8("the registered asset bytes");
    const assetHash = await sha256Hex(raw);
    const payload = { hash: assetHash, name: "model.pkl" };
    const pre: Record<string, unknown> = {
      spec_version: "ario.agent/v1",
      event_id: EID,
      event_type: "asset_registered",
      subject: { type: "asset" },
      payload,
      payload_hash: await sha256Hex(utf8(jcs(payload))),
      previous_hash: "GENESIS",
      signed_at: "2026-06-22T00:00:00Z",
      public_key: await pubHex(),
    };
    const sig = await ed.signAsync(utf8(jcs(pre)), seed());
    const envelope = { ...pre, signature: bytesToHex(sig) };
    const bundle = await buildBundle([{ envelope, content: utf8("WRONG asset bytes") }]);

    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("failed");
    expect(r.events[0]!.contentOk).toBe(false);
  });
});

describe("evidence content — adversarial & mixed", () => {
  it("a null event envelope does NOT throw (never-raise) — contentOk:null, event fails", async () => {
    // Regression: the promoted fallback calls contentHashes(env), which
    // dereferences env.payload and would throw on a null envelope. A verifier
    // must never raise on adversarial input; the event still fails via envelopeOk.
    const body = {
      checkpoints: [],
      events: [
        {
          envelope: null,
          content: "deadbeef",
          inclusion: { checkpoint_tx_id: "x", leaf_hash: "00", leaf_index: 0, leaf_count: 1, audit_path: [] },
        },
      ],
    };
    const bundle = await signWrapper(body);
    const r = await verifyEvidenceBundle(bundle); // must resolve, not throw
    expect(r.events[0]!.contentOk).toBe(null);
    expect(r.events[0]!.envelopeOk).toBe(false);
    expect(r.events[0]!.ok).toBe(false);
    expect(r.status).toBe("failed");
  });

  it("invalid-hex in-body content does not throw — error surfaced, contentOk:null", async () => {
    const raw = utf8("the genuine bytes");
    const e = await signEvent(await logRecord(raw, 0), EID);
    // A signed body whose `content` is not valid hex (a producer bug, not a
    // tamper — tampering breaks body_hash+sig). Must not raise; content stays
    // undetermined and the event still verifies on signature + binding.
    const bundle = await buildBundle([{ envelope: e.envelope, recordBytes: e.recordBytes }]);
    (bundle.body as { events: { content?: string }[] }).events[0]!.content = "nothex!!";
    await reSign(bundle);

    const r = await verifyEvidenceBundle(bundle); // must resolve, not throw
    expect(r.events[0]!.contentOk).toBe(null);
    expect(r.events[0]!.ok).toBe(true);
    expect(r.events[0]!.errors.join(" ")).toMatch(/content is not hex/i);
  });

  it("mixed disclosure across events: one content-verified, one undisclosed", async () => {
    const raw0 = utf8("disclosed event zero");
    const raw1 = utf8("undisclosed event one");
    const e0 = await signEvent(await logRecord(raw0, 0), eid(0));
    const e1 = await signEvent(await logRecord(raw1, 1), eid(1));
    const bundle = await buildBundle([
      { envelope: e0.envelope, recordBytes: e0.recordBytes, content: raw0 },
      { envelope: e1.envelope, recordBytes: e1.recordBytes }, // no content
    ]);

    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("verified");
    expect(r.events[0]!.contentOk).toBe(true);
    expect(r.events[1]!.contentOk).toBe(null);
    expect(r.events.every((e) => e.ok)).toBe(true);
  });

  it("a record that binds but is not JSON does not throw — content undetermined", async () => {
    // record_bytes hashes to payload_hash (binds) but isn't JSON, so the
    // committed content_hash can't be read. The JSON.parse catch must keep
    // content undetermined (null), never raise; the event still verifies.
    const recordBytes = utf8("this is not json at all");
    const pre: Record<string, unknown> = {
      spec_version: "ario.events/v1",
      event_id: EID,
      payload_hash: await sha256Hex(recordBytes),
      signed_at: "2026-06-22T00:00:00Z",
      environment: "dev",
      public_key: await pubHex(),
    };
    const sig = await ed.signAsync(utf8(jcs(pre)), seed());
    const envelope = { ...pre, signature: bytesToHex(sig) };
    const bundle = await buildBundle([{ envelope, recordBytes, content: utf8("anything") }]);

    const r = await verifyEvidenceBundle(bundle); // must resolve, not throw
    expect(r.events[0]!.payloadBindingOk).toBe(true); // bytes still bind
    expect(r.events[0]!.contentOk).toBe(null);
    expect(r.events[0]!.ok).toBe(true);
  });

  it("a non-hex STRING side input does not throw — error surfaced, contentOk:null", async () => {
    // options.content accepts Uint8Array | string(hex); a malformed (non-hex)
    // string must be handled gracefully (hexToBytes catch), not thrown.
    const raw = utf8("committed bytes");
    const { envelope, recordBytes } = await signEvent(await logRecord(raw, 0), EID);
    const bundle = await buildBundle([{ envelope, recordBytes }]);

    const r = await verifyEvidenceBundle(bundle, { content: { [EID]: "not-hex-zz" } });
    expect(r.events[0]!.contentOk).toBe(null); // no usable disclosed bytes
    expect(r.events[0]!.ok).toBe(true);
    expect(r.events[0]!.errors.join(" ")).toMatch(/not hex/i);
  });
});
