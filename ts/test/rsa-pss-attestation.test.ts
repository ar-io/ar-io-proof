// RSA-PSS operator-attestation crypto (ario.evidence.export/v1). Pins the
// interop-critical primitive the attested-evidence-export body rests on:
// verify RSA-PSS-SHA-256 over the JCS-canonical attestation payload with the
// salt-length = 32 (RSA_PSS_SALTLEN_DIGEST) pin, and derive the operator's
// Arweave address from the embedded RSA modulus.
//
// The golden fixture (test/fixtures/rsa-pss-attestation.golden.json, emitted by
// scripts/gen-rsa-attestation-fixture.mjs) freezes a real RSA-2048 key, a
// snake_case attestation payload, the salt=32 signature, AND a second signature
// over max/auto salt — so the salt pin is proven to round-trip and the
// unverifiable AUTO-salt trap is proven to fail. No green without vectors.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { deriveOperatorAddress, utf8, verifyRsaPssSha256 } from "../src/crypto.js";
import { jcs } from "../src/verifier.js";

interface RsaPssFixture {
  algorithm: string;
  salt_length: number;
  public_key: { kty: "RSA"; n: string; e: string };
  operator_address: string;
  payload: Record<string, unknown>;
  signature_hex: string;
  signature_wrong_salt_hex: string;
}

const FIXTURE = fileURLToPath(
  new URL("./fixtures/rsa-pss-attestation.golden.json", import.meta.url),
);

async function loadFixture(): Promise<RsaPssFixture> {
  return JSON.parse(await readFile(FIXTURE, "utf8")) as RsaPssFixture;
}

// The signed bytes are the raw JCS canonicalization of the payload — recompute
// them here so the round-trip also pins jcs↔signature agreement.
function payloadBytes(f: RsaPssFixture): Uint8Array {
  return utf8(jcs(f.payload));
}

function flipLastNibble(hex: string): string {
  return hex.slice(0, -1) + (hex.endsWith("0") ? "1" : "0");
}

describe("verifyRsaPssSha256 — golden fixture (salt=32 pin)", () => {
  it("(a) the committed salt=32 signature verifies true", async () => {
    const f = await loadFixture();
    expect(f.salt_length).toBe(32); // documents the pin the fixture was signed under
    const ok = await verifyRsaPssSha256(payloadBytes(f), f.signature_hex, f.public_key);
    expect(ok).toBe(true);
  });

  it("(b) a tampered signature (one flipped byte) verifies false", async () => {
    const f = await loadFixture();
    const tampered = flipLastNibble(f.signature_hex);
    expect(tampered).not.toBe(f.signature_hex);
    const ok = await verifyRsaPssSha256(payloadBytes(f), tampered, f.public_key);
    expect(ok).toBe(false);
  });

  it("(c) a tampered payload verifies false", async () => {
    const f = await loadFixture();
    const mutated = { ...f.payload, data_size: (f.payload.data_size as number) + 1 };
    const ok = await verifyRsaPssSha256(utf8(jcs(mutated)), f.signature_hex, f.public_key);
    expect(ok).toBe(false);
  });

  it("(d) a WRONG salt length (max/auto) signature verifies false — the interop trap", async () => {
    const f = await loadFixture();
    // Same key, same JCS bytes, only the salt differs (AUTO → max on signing).
    // WebCrypto cannot auto-detect salt on verify, so the salt=32 pin rejects it.
    const ok = await verifyRsaPssSha256(payloadBytes(f), f.signature_wrong_salt_hex, f.public_key);
    expect(ok).toBe(false);
  });

  it("malformed signature hex throws (malformed input, not a failed verify)", async () => {
    const f = await loadFixture();
    await expect(
      verifyRsaPssSha256(payloadBytes(f), "not-hex!!", f.public_key),
    ).rejects.toThrow(/malformed signature hex/);
  });

  it("a malformed RSA public key throws (malformed input, not a failed verify)", async () => {
    const f = await loadFixture();
    // WebCrypto is lenient about modulus CONTENT (garbage `n` imports and just
    // fails to verify), but rejects a structurally-invalid JWK — here a wrong
    // `kty` — which is the malformed-key throw path. Cast because a hostile
    // record can carry any runtime shape behind the declared JWK type.
    const badKey = { kty: "oct", n: f.public_key.n, e: f.public_key.e } as unknown as {
      kty: "RSA";
      n: string;
      e: string;
    };
    await expect(
      verifyRsaPssSha256(payloadBytes(f), f.signature_hex, badKey),
    ).rejects.toThrow(/malformed RSA public key/);
  });
});

describe("deriveOperatorAddress — key→wallet binding", () => {
  it("(e) reproduces the fixture's operator address from the modulus", async () => {
    const f = await loadFixture();
    const addr = await deriveOperatorAddress(f.public_key.n);
    expect(addr).toBe(f.operator_address);
    // Spec §3.3 self-consistency: the signed payload's `operator` == the address
    // derived from the embedded key.
    expect(addr).toBe(f.payload.operator);
  });

  it("a wrong modulus derives a different address", async () => {
    const f = await loadFixture();
    // Flip the leading base64url char (charset-safe, length-preserving) → a
    // different modulus → a different address.
    const wrongN = (f.public_key.n[0] === "x" ? "y" : "x") + f.public_key.n.slice(1);
    expect(wrongN).not.toBe(f.public_key.n);
    const addr = await deriveOperatorAddress(wrongN);
    expect(addr).not.toBe(f.operator_address);
  });

  it("produces unpadded base64url (Arweave address form)", async () => {
    const f = await loadFixture();
    const addr = await deriveOperatorAddress(f.public_key.n);
    expect(addr).toMatch(/^[A-Za-z0-9_-]+$/); // no '=' padding, no '+'/'/'
  });

  it("throws on a non-base64url modulus", async () => {
    await expect(deriveOperatorAddress("has spaces and +/=")).rejects.toThrow(/base64url/);
  });
});
