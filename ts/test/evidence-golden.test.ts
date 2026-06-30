// Cross-repo golden-fixture conformance: a REAL ario.evidence/v1 /
// ario.anchor.trace/v1 bundle, emitted by @ar.io/anchor's toEvidenceBundle over
// an actual anchored batch (scripts/gen-evidence-fixture.mjs in ar-io-anchor),
// committed here as frozen producer bytes. This pins emit↔verify agreement
// WITHOUT a runtime cross-link between the two packages: the anchor SDK wrote
// the file once; this kernel verifies the exact bytes forever.
//
// (Kickoff Phase-4 conformance check, realized as a ts-test fixture. Promoting
// it to the formal test-vectors corpus is a follow-up governance bump per
// ar-io-proof/specs/governance.md §4 — additive vector = minor tag bump.)
//
// The discipline the negatives pin: a tampered copy of the SAME frozen bytes
// fails. Each surface is flipped independently (wrapper sig, body_hash,
// record_bytes, audit_path, leaf_index) so the golden file's green verdict is
// not a fluke of one weak check.

import * as ed from "@noble/ed25519";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { bytesToHex, sha256Hex, utf8 } from "../src/crypto.js";
import { jcs } from "../src/verifier.js";
import { verifyEvidenceBundle } from "../src/evidence.js";
import type { EvidenceBundle } from "../src/evidence.js";

const FIXTURE = fileURLToPath(
  new URL("./fixtures/anchor-trace-bundle.golden.json", import.meta.url),
);

// The generator (ar-io-anchor scripts/gen-evidence-fixture.mjs) signs the
// fixture with the stack's well-known test seed. Re-signing the wrapper here
// lets a tamper test ISOLATE an inner-proof break (audit_path / leaf_index)
// from the wrapper signature — otherwise any body edit trips the wrapper sig
// first and the verifier never reaches the inclusion check. (Verbatim-bytes
// tamper — the realistic auditor case — is covered separately below.)
const SEED_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
function seed(): Uint8Array {
  return Uint8Array.from(Buffer.from(SEED_HEX, "hex"));
}

async function loadGolden(): Promise<EvidenceBundle> {
  return JSON.parse(await readFile(FIXTURE, "utf8")) as EvidenceBundle;
}

// Re-sign the wrapper over the (mutated) body with the fixture's own key.
async function reSignWrapper(bundle: EvidenceBundle): Promise<void> {
  bundle.body_hash = await sha256Hex(utf8(jcs(bundle.body)));
  const { signature: _s, ...pre } = bundle;
  bundle.public_key = bytesToHex(await ed.getPublicKeyAsync(seed()));
  bundle.signature = bytesToHex(await ed.signAsync(utf8(jcs(pre)), seed()));
}

// Deep clone so each tamper test mutates an isolated copy of the frozen bytes.
function clone(b: EvidenceBundle): EvidenceBundle {
  return JSON.parse(JSON.stringify(b)) as EvidenceBundle;
}

function flipLastNibble(hex: string): string {
  return hex.slice(0, -1) + (hex.endsWith("0") ? "1" : "0");
}

describe("golden ario.anchor.trace/v1 fixture — emitted by @ar.io/anchor", () => {
  it("the committed fixture verifies fully green under this kernel", async () => {
    const bundle = await loadGolden();
    const r = await verifyEvidenceBundle(bundle);

    expect(r.status).toBe("verified");
    expect(r.specVersionOk).toBe(true);
    expect(r.signatureOk).toBe(true);
    expect(r.bodyHashOk).toBe(true);
    expect(r.bodyType).toBe("ario.anchor.trace/v1");
    expect(r.checkpoints.length).toBeGreaterThan(0);
    expect(r.checkpoints.every((c) => c.ok)).toBe(true);
    expect(r.events.length).toBeGreaterThan(0);
    expect(r.events.every((e) => e.ok)).toBe(true);
    // The real producer disclosed every record → every binding is determined.
    expect(r.events.every((e) => e.payloadBindingOk === true)).toBe(true);
  });

  it("the producer's asserted verdict is surfaced and matches the recompute", async () => {
    const bundle = await loadGolden();
    const r = await verifyEvidenceBundle(bundle);
    // The emitter asserts "verified"; the kernel recomputes "verified". Surfaced,
    // but it's the recompute that's authoritative.
    expect(r.assertedStatus).toBe("verified");
    expect(r.status).toBe("verified");
  });

  it("the disclosed event binds contentOk:true; undisclosed events stay null", async () => {
    const bundle = await loadGolden();
    const r = await verifyEvidenceBundle(bundle);
    // Event 0 disclosed its raw bytes in-body (events[].content) — the kernel
    // hashes them and confirms they ARE the bytes whose hash was anchored.
    expect(r.events[0]!.contentOk).toBe(true);
    // Events 1 & 2 disclosed no content: undetermined, NOT a failure (mirrors a
    // withheld record's payloadBindingOk:null).
    expect(r.events[1]!.contentOk).toBe(null);
    expect(r.events[2]!.contentOk).toBe(null);
    // Content disclosure neither breaks the rollup nor any event.
    expect(r.status).toBe("verified");
    expect(r.events.every((e) => e.ok)).toBe(true);
  });
});

describe("golden fixture — a tampered copy of the SAME bytes fails", () => {
  it("flipping a record_bytes byte fails the event and the rollup", async () => {
    const bundle = clone(await loadGolden());
    const ev = (bundle.body as { events: { record_bytes: string }[] }).events[0]!;
    ev.record_bytes = flipLastNibble(ev.record_bytes);
    // No wrapper re-sign: this is a verbatim-bytes tamper an auditor would see.
    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("failed");
    // body_hash + wrapper signature both break under a body edit.
    expect(r.bodyHashOk).toBe(false);
    expect(r.signatureOk).toBe(false);
  });

  it("forging the wrapper signature is a hard failure", async () => {
    const bundle = clone(await loadGolden());
    bundle.signature = flipLastNibble(bundle.signature);
    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("failed");
    expect(r.signatureOk).toBe(false);
    // We do not pretend to verify a body under a broken wrapper.
    expect(r.checkpoints).toHaveLength(0);
  });

  it("tampering body_hash alone is caught (mismatch)", async () => {
    const bundle = clone(await loadGolden());
    bundle.body_hash = flipLastNibble(bundle.body_hash);
    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("failed");
    expect(r.bodyHashOk).toBe(false);
  });

  it("flipping an audit_path entry breaks that event's inclusion proof", async () => {
    const bundle = clone(await loadGolden());
    const incl = (bundle.body as { events: { inclusion: { audit_path: string[] } }[] }).events[1]!
      .inclusion;
    // A single-event window has an empty audit path; the fixture has 3 events so
    // every leaf has at least one sibling — guard anyway.
    expect(incl.audit_path.length).toBeGreaterThan(0);
    incl.audit_path[0] = flipLastNibble(incl.audit_path[0]!);
    // Re-sign so the wrapper stays valid and the verifier REACHES the inclusion
    // check — isolating the inner-proof break from the wrapper signature.
    await reSignWrapper(bundle);
    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("failed");
    expect(r.signatureOk).toBe(true); // wrapper authentic; the BODY's proof is broken
    expect(r.events[1]!.inclusionOk).toBe(false);
    expect(r.events[1]!.ok).toBe(false);
  });

  it("a wrong leaf_index breaks the inclusion proof", async () => {
    const bundle = clone(await loadGolden());
    const incl = (bundle.body as { events: { inclusion: { leaf_index: number } }[] }).events[2]!
      .inclusion;
    incl.leaf_index = incl.leaf_index === 0 ? 1 : 0;
    await reSignWrapper(bundle);
    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("failed");
    expect(r.signatureOk).toBe(true);
    expect(r.events[2]!.inclusionOk).toBe(false);
    expect(r.events[2]!.ok).toBe(false);
  });

  it("a tampered disclosed content fails the event (isolated from the wrapper sig)", async () => {
    const bundle = clone(await loadGolden());
    const ev = (bundle.body as { events: { content?: string }[] }).events[0]!;
    // Event 0 is the disclosed one — flip a byte of its content (still valid hex).
    expect(typeof ev.content).toBe("string");
    ev.content = flipLastNibble(ev.content!);
    // Re-sign so the wrapper stays valid and the verifier REACHES the content
    // check — isolating the disclosed-bytes lie from the wrapper signature.
    await reSignWrapper(bundle);
    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("failed");
    expect(r.signatureOk).toBe(true); // wrapper authentic; the disclosed bytes lie
    expect(r.events[0]!.contentOk).toBe(false);
    expect(r.events[0]!.ok).toBe(false);
  });
});
