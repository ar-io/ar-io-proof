// External-commitment verification (envelope-spec §3, §2.5/§6.2) — the
// kernel lane's Scope A. Behavior must mirror the Python reference
// (ar_io_proof.envelope.verify_envelope) exactly:
//   payload present  -> inline check; payloadBytes given -> external check;
//   both -> both; neither -> payloadHashOk null, verdict NOT failed.
// Mode confusion is closed by the signed scope — both negatives pinned here.

import * as ed from "@noble/ed25519";
import { describe, expect, it } from "vitest";

import { bytesToHex, sha256Hex, utf8 } from "../src/crypto.js";
import { jcs, verifyEnvelope } from "../src/verifier.js";
import type { Envelope } from "../src/types.js";

// Corpus fixture seed (test-only, published).
const SEED_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

function seedBytes(): Uint8Array {
  return Uint8Array.from(Buffer.from(SEED_HEX, "hex"));
}

// Build a signed envelope in-test. spec_version stays ario.agent/v1 — the
// kernel's binding handling is structural and profile-agnostic, and
// ario.events/v1 is not in the accept-set until ratification (Scope B).
async function signedEnvelope(
  fields: Record<string, unknown>,
  payloadForHash?: unknown,
): Promise<Envelope> {
  const env: Record<string, unknown> = { ...fields };
  if (payloadForHash !== undefined && env.payload_hash === undefined) {
    env.payload_hash = await sha256Hex(utf8(jcs(payloadForHash)));
  }
  env.public_key = bytesToHex(await ed.getPublicKeyAsync(seedBytes()));
  const sig = await ed.signAsync(utf8(jcs(env)), seedBytes());
  return { ...env, signature: bytesToHex(sig) } as unknown as Envelope;
}

const RECORD = { kind: "external-record", value: 42 };

function minimalFields(): Record<string, unknown> {
  return {
    spec_version: "ario.agent/v1",
    event_id: "1f0e9a4c-3b2d-4d5e-8f6a-7b8c9d0e1f2a",
    signed_at: "2026-06-12T00:00:00Z",
  };
}

describe("external commitment", () => {
  it("without the record: signature-valid, semantics-undetermined (ok, payloadHashOk null)", async () => {
    const env = await signedEnvelope(minimalFields(), RECORD);
    const r = await verifyEnvelope(env);
    expect(r.signatureOk).toBe(true);
    expect(r.payloadHashOk).toBe(null);
    expect(r.ok).toBe(true);
  });

  it("with the committed bytes: fully bound", async () => {
    const env = await signedEnvelope(minimalFields(), RECORD);
    const r = await verifyEnvelope(env, { payloadBytes: utf8(jcs(RECORD)) });
    expect(r.payloadHashOk).toBe(true);
    expect(r.ok).toBe(true);
  });

  it("with the WRONG bytes: binding fails the verdict", async () => {
    const env = await signedEnvelope(minimalFields(), RECORD);
    const r = await verifyEnvelope(env, { payloadBytes: utf8("not the record") });
    expect(r.payloadHashOk).toBe(false);
    expect(r.ok).toBe(false);
    expect(r.signatureOk).toBe(true); // the signature itself is still good
  });

  it("rejects a missing payload_hash field outright (envelope-spec §2)", async () => {
    // §2 is binding: absence of payload_hash is a hard reject in every mode,
    // regardless of whether there is material to compare it against.
    const noHash = await signedEnvelope(minimalFields());
    const r1 = await verifyEnvelope(noHash);
    expect(r1.payloadHashOk).toBe(false);
    expect(r1.ok).toBe(false);
    expect(r1.signatureOk).toBe(true); // the signature itself is fine

    // Present but compared against the wrong material still fails the bind.
    const badHash = await signedEnvelope({ ...minimalFields(), payload_hash: "ZZ" });
    const r2 = await verifyEnvelope(badHash, { payloadBytes: utf8("anything") });
    expect(r2.payloadHashOk).toBe(false);
    expect(r2.ok).toBe(false);
  });

  it("inline + external together: both must pass", async () => {
    const env = await signedEnvelope({ ...minimalFields(), payload: RECORD }, RECORD);
    const good = await verifyEnvelope(env, { payloadBytes: utf8(jcs(RECORD)) });
    expect(good.payloadHashOk).toBe(true);
    expect(good.ok).toBe(true);

    const bad = await verifyEnvelope(env, { payloadBytes: utf8("wrong") });
    expect(bad.payloadHashOk).toBe(false);
    expect(bad.ok).toBe(false);
  });

  it("legacy string second argument still means expectedContentHash", async () => {
    const payload = { hash: "a".repeat(64) };
    const env = await signedEnvelope(
      { ...minimalFields(), event_type: "asset_registered", payload },
      payload,
    );
    const r = await verifyEnvelope(env, "a".repeat(64));
    expect(r.contentHashOk).toBe(true);
    expect(r.contentRole).toBe("asset");
  });
});

describe("mode confusion is closed by the signed scope", () => {
  it("fake-external: stripping an inline payload breaks the signature", async () => {
    const env = await signedEnvelope({ ...minimalFields(), payload: RECORD }, RECORD);
    const { payload: _stripped, ...rest } = env as unknown as Record<string, unknown>;
    const r = await verifyEnvelope(rest as unknown as Envelope);
    expect(r.signatureOk).toBe(false); // payload was inside the signed scope
    expect(r.ok).toBe(false);
  });

  it("fake-inline: injecting a payload into an external envelope fails twice", async () => {
    const env = await signedEnvelope(minimalFields(), RECORD);
    const tampered = { ...env, payload: { forged: true } } as unknown as Envelope;
    const r = await verifyEnvelope(tampered);
    expect(r.signatureOk).toBe(false); // unsigned field injected
    expect(r.payloadHashOk).toBe(false); // and the inline recompute mismatches
    expect(r.ok).toBe(false);
  });
});

describe("kernel tighten (Scope C)", () => {
  it("rejects malformed minor suffixes (ar-io-agent#13), accepts numeric ones", async () => {
    const base = { ...minimalFields() };
    for (const v of ["ario.agent/v1.3", "ario.agent/v1.10"]) {
      const env = await signedEnvelope({ ...base, spec_version: v }, RECORD);
      expect((await verifyEnvelope(env)).specVersionOk, v).toBe(true);
    }
    for (const v of ["ario.agent/v1.x", "ario.agent/v1.3abc", "ario.agent/v1.", "ario.agent/v10"]) {
      const env = await signedEnvelope({ ...base, spec_version: v }, RECORD);
      expect((await verifyEnvelope(env)).specVersionOk, v).toBe(false);
    }
  });

  it("rejects lone UTF-16 surrogates in JCS input (reject-only, all kernels)", async () => {
    expect(() => jcs({ a: "ok \u{1F600} pair" })).not.toThrow(); // valid pair fine
    expect(() => jcs({ a: "lone \ud800 high" })).toThrow(/surrogate/);
    expect(() => jcs({ a: "lone \udc00 low" })).toThrow(/surrogate/);
    expect(() => jcs({ "\ud800key": 1 })).toThrow(/surrogate/);

    // Through the verifier: a hostile envelope whose inline payload carries a
    // lone surrogate must fail verification, never pass or crash. (Built by
    // hand — a conformant producer can no longer sign such bytes at all.)
    const hostile = {
      ...minimalFields(),
      payload: { text: "bad \ud800" },
      payload_hash: "a".repeat(64),
      public_key: "e".repeat(64),
      signature: "f".repeat(128),
    } as unknown as Envelope;
    const r = await verifyEnvelope(hostile);
    expect(r.payloadHashOk).toBe(false);
    expect(r.signatureOk).toBe(false);
    expect(r.ok).toBe(false);
  });
});
