// Conformance gate. Runs every envelope vector from this repo's AUTHORITATIVE
// test-vectors/ corpus (../../test-vectors — the same corpus the Python kernel
// gates against; no vendored copy) through the verifier and asserts
// byte-for-byte agreement with the expected canonical bytes, hashes, and
// signature — plus a passing verdict. A single mismatch fails CI. This is the
// contract that keeps the TS kernel in lockstep with the Go + Python references.

import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { bytesToHex, ed25519Verify, hexToBytes, sha256Hex, utf8 } from "../src/crypto";
import {
  EMPTY_TREE_ROOT_HEX,
  auditPath,
  leafHash,
  merkleRoot,
  verifyInclusion,
} from "../src/merkle";
import { contentHashes, jcs, verifyEnvelope } from "../src/verifier";
import type { Envelope } from "../src/types";

interface Vector {
  vector_id: string;
  inputs: { envelope_pre_signature: Record<string, unknown> };
  fixed_keypair: { ed25519_public_hex: string };
  expected_outputs: {
    payload_jcs_bytes_hex: string;
    payload_hash_hex: string;
    envelope_for_sig_jcs_bytes_hex: string;
    signature_hex: string;
  };
}

const vectorsDir = fileURLToPath(new URL("../../test-vectors/", import.meta.url));

// Pinned from test-vectors/CORPUS-v1.md (corpus tag test-vectors-v1.0). A
// drifted corpus fails here before any crypto runs. Identical table to the
// Python kernel's tests/test_conformance.py — both kernels in one repo gate
// the one authoritative corpus.
const CORPUS_SHA256: Record<string, string> = {
  "envelope-asset-missing-01.json": "fecb29289df2b6ea210b51737e6cdf10438ec996add050b053247cc567fe2e27",
  "envelope-asset-registered-01.json": "3b99fc850edba7775a4df970e406fcb2d787fc10594cd7f969936938b881b9a9",
  "envelope-key-retired-01.json": "2e89bc2b1986e3545d0aae94f850d675f9f16fc384b311cc75090a5e275eaf33",
  "envelope-policy-changed-01.json": "62a460fb4e0e49c2ef28acc73ddea1163f801ccef6c0e247679e65e6c655509c",
  "envelope-tamper-detected-01.json": "5f4b8b1dab9c50ca97ff0349e39481ee33f9a19991632d13fb71fd940a88fcd0",
  "envelope-verification-checkpoint-01.json": "393c04e411807481587c591ccb1e637cb072f40940cbc9d25e53dd29253bb56d",
  "merkle-tree-00-leaves.json": "705adf82ce9cc46d0e45fce216cb205d5755e2d41975b66444f1765a982faa95",
  "merkle-tree-01-leaves.json": "bdbb57ad29272054c5dcc655c2279c4debec9c4c67ea85f17490760a19b52923",
  "merkle-tree-02-leaves.json": "9c33d0fcb57655729a0e657b8b4313de806e397949465d310338db5dd56a573b",
  "merkle-tree-03-leaves.json": "f4cc12cd11cb3a49225edff2c18ab9f516992f8d6c13e7baadb627f1c7efe8eb",
  "merkle-tree-07-leaves.json": "8372c63f3d5a61c8dfc0939fb5776b8041960313df4f9334e620d398326bdd1c",
  "merkle-tree-1024-leaves.json": "e732c755539b84e20b80d15e5a7989e2d6736153d9d78c944ed6e7ee98627254",
  "merkle-tree-16-leaves.json": "b58b31340bef317fd32734be7e3ff58b0d4a4d0cb03a7b16f08056161c7ae72c",
  "README.md": "7d21d23fcbf9996e9e7a710099bb59b4cb501720ded57aac65edde43de10ef44",
};

function loadVectors(): Vector[] {
  return readdirSync(vectorsDir)
    .filter((f) => f.startsWith("envelope-") && f.endsWith(".json"))
    .sort()
    .map((f) => JSON.parse(readFileSync(`${vectorsDir}${f}`, "utf8")) as Vector);
}

// Reconstruct the full signed envelope exactly as it would appear on-chain:
// the pre-signature envelope plus the three fields the signer adds.
function reconstruct(v: Vector): Envelope {
  return {
    ...(v.inputs.envelope_pre_signature as unknown as Envelope),
    payload_hash: v.expected_outputs.payload_hash_hex,
    public_key: v.fixed_keypair.ed25519_public_hex,
    signature: v.expected_outputs.signature_hex,
  };
}

const vectors = loadVectors();

// The gate before the gate: the vendored corpus must BE test-vectors-v1.0,
// byte-for-byte, before any conformance claim means anything.
describe("corpus integrity (test-vectors-v1.0)", () => {
  for (const [name, expected] of Object.entries(CORPUS_SHA256)) {
    it(`${name} matches its pinned digest`, () => {
      const digest = createHash("sha256").update(readFileSync(`${vectorsDir}${name}`)).digest("hex");
      expect(digest, `vendored ${name} drifted from test-vectors-v1.0`).toBe(expected);
    });
  }

  it("the corpus is complete — no missing or extra vector files", () => {
    const onDisk = readdirSync(vectorsDir).filter((f) => f.endsWith(".json")).sort();
    const pinned = Object.keys(CORPUS_SHA256).filter((f) => f.endsWith(".json")).sort();
    expect(onDisk).toEqual(pinned);
    expect(onDisk.filter((f) => f.startsWith("envelope-"))).toHaveLength(6);
    expect(onDisk.filter((f) => f.startsWith("merkle-tree-"))).toHaveLength(7);
  });
});

describe("envelope conformance vs ar-io-agent test-vectors", () => {
  it("loads the vendored corpus", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(6);
  });

  for (const v of vectors) {
    describe(v.vector_id, () => {
      const env = reconstruct(v);

      it("JCS(payload) matches expected canonical bytes", () => {
        expect(bytesToHex(utf8(jcs(env.payload)))).toBe(v.expected_outputs.payload_jcs_bytes_hex);
      });

      it("SHA-256(JCS(payload)) matches payload_hash", async () => {
        expect(await sha256Hex(utf8(jcs(env.payload)))).toBe(v.expected_outputs.payload_hash_hex);
        expect(env.payload_hash).toBe(v.expected_outputs.payload_hash_hex);
      });

      it("JCS(envelope minus signature) matches expected canonical bytes", () => {
        const { signature: _sig, ...forSig } = env;
        expect(bytesToHex(utf8(jcs(forSig)))).toBe(v.expected_outputs.envelope_for_sig_jcs_bytes_hex);
      });

      it("verifies (spec_version + payload_hash + Ed25519 signature)", async () => {
        const result = await verifyEnvelope(env);
        expect(result.errors).toEqual([]);
        expect(result.specVersionOk).toBe(true);
        expect(result.payloadHashOk).toBe(true);
        expect(result.signatureOk).toBe(true);
        expect(result.ok).toBe(true);
      });

      it("binds each committed content hash back to the envelope", async () => {
        for (const { role, hash } of contentHashes(env)) {
          const result = await verifyEnvelope(env, hash);
          expect(result.ok).toBe(true);
          expect(result.contentHashOk).toBe(true);
          expect(result.contentRole).toBe(role);
        }
      });
    });
  }
});

// --- RFC 9162 Merkle conformance (the 7 merkle-tree-* vectors) --------------

interface MerkleVector {
  vector_id: string;
  expected_root_hex: string;
  leaf_count: number;
  leaves: { leaf_hash_hex: string; leaf_object: Record<string, unknown> }[];
  inclusion_proofs: { leaf_index: number; audit_path_hex: string[] }[];
}

function loadMerkleVectors(): MerkleVector[] {
  return readdirSync(vectorsDir)
    .filter((f) => f.startsWith("merkle-tree-") && f.endsWith(".json"))
    .sort()
    .map((f) => JSON.parse(readFileSync(`${vectorsDir}${f}`, "utf8")) as MerkleVector);
}

describe("merkle conformance vs ar-io-agent test-vectors", () => {
  const merkleVectors = loadMerkleVectors();

  it("has all 7 merkle vectors; the empty tree pins SHA-256('')", () => {
    expect(merkleVectors).toHaveLength(7);
    const empty = merkleVectors.find((v) => v.leaf_count === 0)!;
    expect(empty.expected_root_hex).toBe(EMPTY_TREE_ROOT_HEX);
  });

  for (const v of loadMerkleVectors()) {
    describe(v.vector_id, () => {
      const hashes = v.leaves.map((l) => hexToBytes(l.leaf_hash_hex));

      it("leaf hashes reproduce from JCS(leaf_object) with the 0x00 prefix", async () => {
        for (const leaf of v.leaves) {
          expect(bytesToHex(await leafHash(utf8(jcs(leaf.leaf_object))))).toBe(leaf.leaf_hash_hex);
        }
      });

      it("the root reconstructs byte-for-byte", async () => {
        expect(bytesToHex(await merkleRoot(hashes))).toBe(v.expected_root_hex);
      });

      it("pinned inclusion proofs verify, reproduce, and fail for the wrong leaf", async () => {
        const root = hexToBytes(v.expected_root_hex);
        for (const proof of v.inclusion_proofs) {
          const i = proof.leaf_index;
          const pinned = proof.audit_path_hex.map(hexToBytes);
          // The pinned audit path verifies...
          expect(await verifyInclusion(hashes[i], i, v.leaf_count, pinned, root)).toBe(true);
          // ...and our generator reproduces it byte-for-byte.
          expect((await auditPath(i, hashes)).map(bytesToHex)).toEqual(proof.audit_path_hex);
          // Negative: the same path must not verify for a different leaf index.
          if (v.leaf_count > 1) {
            const other = (i + 1) % v.leaf_count;
            expect(await verifyInclusion(hashes[other], other, v.leaf_count, pinned, root)).toBe(false);
          }
        }
      });
    });
  }

  it("verifyInclusion is fail-closed on malformed inputs (never throws)", async () => {
    const v = loadMerkleVectors().find((x) => x.leaf_count === 7)!;
    const hashes = v.leaves.map((l) => hexToBytes(l.leaf_hash_hex));
    const root = hexToBytes(v.expected_root_hex);
    const good = v.inclusion_proofs[0];
    const pinned = good.audit_path_hex.map(hexToBytes);
    // Out-of-range / inconsistent tree shapes.
    expect(await verifyInclusion(hashes[0], -1, 7, pinned, root)).toBe(false);
    expect(await verifyInclusion(hashes[0], 7, 7, pinned, root)).toBe(false);
    expect(await verifyInclusion(hashes[0], 0, 0, [], root)).toBe(false);
    // Path longer than the tree depth.
    expect(await verifyInclusion(hashes[0], good.leaf_index, 7, [...pinned, ...pinned], root)).toBe(false);
    // Truncated path.
    expect(await verifyInclusion(hashes[good.leaf_index], good.leaf_index, 7, pinned.slice(0, 1), root)).toBe(false);
  });

  it("auditPath rejects an out-of-range index", async () => {
    await expect(auditPath(5, [new Uint8Array(32)])).rejects.toThrow(/out of range/);
  });
});

// --- ario.events/v1 conformance (corpus v1.1 additive set) ------------------
//
// The Anchoring SDK's profile (envelope-spec v1.3, ratified). Gated at the
// PRIMITIVE level (canonical bytes + payload hash + Ed25519 + RFC 9162 Merkle)
// AND through verifyEnvelope now that the profile is in the accept-set: full
// bind with the committed record bytes, undetermined (signature-only) without
// them — the external-commitment contract (envelope-spec §3/§3.1/§6.2). The
// committed payload is the external `event_record`; the on-wire envelope
// carries only its payload_hash + a payload_ref locator. Python reproduces
// signatures from the seed; TS independently verifies them — cross-language.
const CORPUS_EVENTS_SHA256: Record<string, string> = {
  "events-event-01.json": "ac4f81cf4be28da92ac49fe2461084598dde876a28d252bf997005f34b8903e4",
  "events-event-02.json": "d1ab4b6f3cb6ab1f5f33e345a2c6f80c99bedbf10c9ec482ff8a45279e49fb27",
  "events-checkpoint-01.json": "ae133294320974611c3952befa7f09ac58e6236027bd59cc82f5ab4f01d4bc12",
};
// test-vectors-v1.2 additive SHAs (kernel-ratification lane, Scope D).
const CORPUS_EVENTS_V12_SHA256: Record<string, string> = {
  "events-checkpoint-chain-01.json": "71a099143d17b6583f12ce132840c1f802951613b7e456d98703bc87625c7f54",
};
const CORPUS_NEGATIVES_SHA256: Record<string, string> = {
  "negative-malformed-minor-00.json": "31758aa41471bd17521a94c16d44057b7415eb905d1c7852e0086852fd5f39c1",
  "negative-malformed-minor-01.json": "6d3f22d01c4a0f2dc8979dae2aef3ae9c0821a990fc26eca344ac78b75d7c30f",
  "negative-malformed-minor-02.json": "b437b44ea6d793bb4b5a0483e046fc08219b5a3b40dc2f2db2c7ead6132b0f3c",
  "negative-lone-surrogate-00.json": "c89a558c5efc6b0bbf9e82c104dd29d0315bfbefcc56c7ccaea8b81c60e848ed",
  "negative-missing-payload-hash-00.json": "a2818add7d61e0de56b2782e91b3a69275e3ec07b81f258aff7c65657cb999cb",
};
const eventsDir = fileURLToPath(new URL("../../test-vectors/ario.events-v1/", import.meta.url));
const negativesDir = fileURLToPath(new URL("../../test-vectors/negatives/", import.meta.url));

interface EventsVector {
  vector_id: string;
  spec_version: string;
  inputs: {
    envelope_pre_signature: Record<string, unknown>;
    event_record: Record<string, unknown>;
  };
  fixed_keypair: { ed25519_public_hex: string };
  expected_outputs: {
    payload_jcs_bytes_hex: string;
    payload_hash_hex: string;
    envelope_for_sig_jcs_bytes_hex: string;
    signature_hex: string;
    envelope_jcs_bytes_hex: string;
  };
  merkle?: {
    expected_root_hex: string;
    leaves: { envelope_jcs_bytes_hex: string; leaf_hash_hex: string }[];
    inclusion_proofs: { leaf_index: number; audit_path_hex: string[] }[];
  };
}

function loadEvents(prefix: string): EventsVector[] {
  return readdirSync(eventsDir)
    .filter((f) => f.startsWith(prefix) && f.endsWith(".json") && !f.includes("-chain-"))
    .sort()
    .map((f) => JSON.parse(readFileSync(`${eventsDir}${f}`, "utf8")) as EventsVector);
}

async function gateEventsEnvelope(v: EventsVector): Promise<void> {
  const out = v.expected_outputs;
  const pub = v.fixed_keypair.ed25519_public_hex;
  // payload = the external event_record (Minimal → external commitment).
  expect(bytesToHex(utf8(jcs(v.inputs.event_record)))).toBe(out.payload_jcs_bytes_hex);
  expect(await sha256Hex(utf8(jcs(v.inputs.event_record)))).toBe(out.payload_hash_hex);
  // signer injects payload_hash + public_key; vectors must not pre-bake them.
  const pre = v.inputs.envelope_pre_signature;
  expect("payload" in pre || "payload_hash" in pre || "public_key" in pre).toBe(false);
  const forSig = { ...pre, payload_hash: out.payload_hash_hex, public_key: pub };
  expect(bytesToHex(utf8(jcs(forSig)))).toBe(out.envelope_for_sig_jcs_bytes_hex);
  // signature verifies over the for-sig bytes; tamper + forgery both fail.
  const msg = hexToBytes(out.envelope_for_sig_jcs_bytes_hex);
  expect(await ed25519Verify(out.signature_hex, msg, pub)).toBe(true);
  expect(await ed25519Verify(out.signature_hex, utf8(bytesToHex(msg) + "00"), pub)).toBe(false);
  const forged = out.signature_hex.slice(0, -2) + (out.signature_hex.slice(-2) === "00" ? "ff" : "00");
  expect(await ed25519Verify(forged, msg, pub)).toBe(false);

  // Full-family gate (ratified, envelope-spec v1.3): the COMPLETE signed
  // envelope verifies through verifyEnvelope in external-commitment mode.
  const complete = JSON.parse(
    new TextDecoder().decode(hexToBytes(out.envelope_jcs_bytes_hex)),
  ) as Envelope;
  const recordBytes = utf8(jcs(v.inputs.event_record));
  const bound = await verifyEnvelope(complete, { payloadBytes: recordBytes });
  expect(bound.ok).toBe(true);
  expect(bound.signatureOk).toBe(true);
  expect(bound.payloadHashOk).toBe(true); // committed bytes match
  // Signature-only (no committed bytes): valid but semantics-undetermined.
  const undetermined = await verifyEnvelope(complete);
  expect(undetermined.ok).toBe(true);
  expect(undetermined.payloadHashOk).toBe(null);
  // Wrong committed bytes must fail the bind.
  expect((await verifyEnvelope(complete, { payloadBytes: utf8("wrong") })).ok).toBe(false);
}

describe("corpus integrity (ario.events/v1)", () => {
  const allEvents = { ...CORPUS_EVENTS_SHA256, ...CORPUS_EVENTS_V12_SHA256 };
  for (const [name, expected] of Object.entries(allEvents)) {
    it(`${name} matches its pinned digest`, () => {
      const digest = createHash("sha256").update(readFileSync(`${eventsDir}${name}`)).digest("hex");
      expect(digest, `events vector ${name} drifted from its pinned corpus tag`).toBe(expected);
    });
  }
  it("the events set is complete — no missing or extra files", () => {
    const onDisk = readdirSync(eventsDir).filter((f) => f.endsWith(".json")).sort();
    expect(onDisk).toEqual(Object.keys(allEvents).sort());
  });
});

describe("ario.events/v1 event conformance", () => {
  const events = loadEvents("events-event-");
  it("has both event vectors", () => expect(events).toHaveLength(2));
  for (const v of events) {
    it(`${v.vector_id} re-derives + verifies`, async () => {
      expect(v.spec_version).toBe("ario.events/v1");
      await gateEventsEnvelope(v);
    });
  }
});

describe("ario.events/v1 checkpoint conformance (RFC 9162 Merkle)", () => {
  for (const v of loadEvents("events-checkpoint-")) {
    describe(v.vector_id, () => {
      it("the checkpoint record is a valid signed envelope", async () => {
        expect(v.spec_version).toBe("ario.events/v1");
        await gateEventsEnvelope(v);
      });
      it("leaf hashes, root, and inclusion proofs reconstruct", async () => {
        const m = v.merkle!;
        const hashes: Uint8Array[] = [];
        for (const leaf of m.leaves) {
          const h = await leafHash(hexToBytes(leaf.envelope_jcs_bytes_hex));
          expect(bytesToHex(h)).toBe(leaf.leaf_hash_hex);
          hashes.push(h);
        }
        expect(bytesToHex(await merkleRoot(hashes))).toBe(m.expected_root_hex);
        const root = hexToBytes(m.expected_root_hex);
        for (const proof of m.inclusion_proofs) {
          const i = proof.leaf_index;
          const pinned = proof.audit_path_hex.map(hexToBytes);
          expect(await verifyInclusion(hashes[i], i, hashes.length, pinned, root)).toBe(true);
          expect((await auditPath(i, hashes)).map(bytesToHex)).toEqual(proof.audit_path_hex);
          if (hashes.length > 1) {
            const other = (i + 1) % hashes.length;
            expect(await verifyInclusion(hashes[other], other, hashes.length, pinned, root)).toBe(false);
          }
        }
      });
    });
  }
});

// --- test-vectors-v1.2 additive: chained checkpoint + negatives ------------

interface CheckpointWindow {
  inputs: { event_record: Record<string, unknown> };
  expected_outputs: { payload_hash_hex: string; envelope_jcs_bytes_hex: string };
  merkle: {
    expected_root_hex: string;
    leaves: { envelope_jcs_bytes_hex: string; leaf_hash_hex: string }[];
    inclusion_proofs: { leaf_index: number; audit_path_hex: string[] }[];
  };
}
interface ChainVector {
  vector_id: string;
  spec_version: string;
  chain_key: string;
  windows: CheckpointWindow[];
  chain_link: { window1_record_hash: string; window2_previous_hash: string };
}

describe("ario.events/v1 checkpoint chain (test-vectors-v1.2)", () => {
  const chainPath = `${eventsDir}events-checkpoint-chain-01.json`;
  const v = JSON.parse(readFileSync(chainPath, "utf8")) as ChainVector;
  const [w1, w2] = v.windows;

  it("integrity digest is pinned", () => {
    const digest = createHash("sha256").update(readFileSync(chainPath)).digest("hex");
    expect(digest).toBe(CORPUS_EVENTS_V12_SHA256["events-checkpoint-chain-01.json"]);
  });

  it("window-2 previous_hash equals SHA-256(JCS(window-1 checkpoint record))", async () => {
    expect(v.spec_version).toBe("ario.events/v1");
    const w1RecordHash = await sha256Hex(utf8(jcs(w1.inputs.event_record)));
    expect(w1RecordHash).toBe(w1.expected_outputs.payload_hash_hex);
    expect((w2.inputs.event_record as { previous_hash: string }).previous_hash).toBe(w1RecordHash);
    expect(v.chain_link.window2_previous_hash).toBe(w1RecordHash);
    expect((w1.inputs.event_record.context as { chain_key: string }).chain_key).toBe(v.chain_key);
    expect((w2.inputs.event_record.context as { chain_key: string }).chain_key).toBe(v.chain_key);
  });

  for (const [i, w] of v.windows.entries()) {
    it(`window ${i + 1} verifies full-family + merkle/inclusion`, async () => {
      const complete = JSON.parse(
        new TextDecoder().decode(hexToBytes(w.expected_outputs.envelope_jcs_bytes_hex)),
      ) as Envelope;
      const recordBytes = utf8(jcs(w.inputs.event_record));
      const bound = await verifyEnvelope(complete, { payloadBytes: recordBytes });
      expect(bound.ok).toBe(true);
      expect(bound.payloadHashOk).toBe(true);
      expect((await verifyEnvelope(complete)).payloadHashOk).toBe(null); // signature-only

      const hashes: Uint8Array[] = [];
      for (const leaf of w.merkle.leaves) {
        const h = await leafHash(hexToBytes(leaf.envelope_jcs_bytes_hex));
        expect(bytesToHex(h)).toBe(leaf.leaf_hash_hex);
        hashes.push(h);
      }
      expect(bytesToHex(await merkleRoot(hashes))).toBe(w.merkle.expected_root_hex);
      expect((w.inputs.event_record.event as { merkle_root: string }).merkle_root).toBe(
        w.merkle.expected_root_hex,
      );
      const root = hexToBytes(w.merkle.expected_root_hex);
      for (const proof of w.merkle.inclusion_proofs) {
        const idx = proof.leaf_index;
        const pinned = proof.audit_path_hex.map(hexToBytes);
        expect(await verifyInclusion(hashes[idx], idx, hashes.length, pinned, root)).toBe(true);
      }
    });
  }
});

interface NegativeVector {
  vector_id: string;
  category: string;
  envelope_bytes_hex: string;
  expect: { accepts: boolean; reason: string };
}

describe("negative vectors must be rejected (test-vectors-v1.2)", () => {
  const files = readdirSync(negativesDir)
    .filter((f) => f.endsWith(".json"))
    .sort();

  it("the negatives set is complete with pinned digests", () => {
    expect(files).toEqual(Object.keys(CORPUS_NEGATIVES_SHA256).sort());
    for (const f of files) {
      const digest = createHash("sha256").update(readFileSync(`${negativesDir}${f}`)).digest("hex");
      expect(digest, `${f} drifted`).toBe(CORPUS_NEGATIVES_SHA256[f]);
    }
  });

  for (const f of files) {
    const n = JSON.parse(readFileSync(`${negativesDir}${f}`, "utf8")) as NegativeVector;
    it(`${n.vector_id} (${n.category}) does not verify`, async () => {
      expect(n.expect.accepts).toBe(false);
      const raw = hexToBytes(n.envelope_bytes_hex);
      let rejected = false;
      try {
        const env = JSON.parse(new TextDecoder().decode(raw)) as Envelope;
        rejected = !(await verifyEnvelope(env)).ok;
      } catch {
        rejected = true; // unparseable (lone surrogate) is a valid rejection
      }
      expect(rejected, `${n.vector_id} was not rejected`).toBe(true);
    });
  }
});
