// Regression: the RSA e=1 "identity" attestation forgery (red-team RT1).
//
// An attacker takes a REAL operator's PUBLIC modulus (public — it's the owner
// field of every tx they sign), sets the exponent e=1 (making RSA verification
// the identity, s^1 mod n = s), and builds a PSS "signature" equal to the
// EMSA-PSS encoded message — NO private key. Before the exponent guard, the
// shipped verifier reported VERIFIED / exit 0 on a fully fabricated attestation
// attributed to a real operator, because the operator-address binding commits
// to n alone and never covered e. Both kernels now enforce e == 65537.
//
// `attestation-exponent-forgery.export.json` is the exact artifact the red-team
// produced; it MUST verify as `failed`.
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { utf8, verifyRsaPssSha256 } from "../src/crypto.js";
import { jcs } from "../src/verifier.js";
import { verifyEvidenceBundle } from "../src/evidence.js";

async function load(name: string): Promise<Record<string, unknown>> {
  const p = fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
  return JSON.parse(await readFile(p, "utf8")) as Record<string, unknown>;
}

// The authoritative forgery regression lives in the cross-kernel corpus (not a
// local fixture, which could drift from the vector both kernels verify).
async function loadForgery(): Promise<Record<string, unknown>> {
  const p = fileURLToPath(
    new URL(
      "../../test-vectors/evidence-export/negatives/attestation-exponent-forgery.json",
      import.meta.url,
    ),
  );
  return JSON.parse(await readFile(p, "utf8")) as Record<string, unknown>;
}

describe("RSA exponent guard — e=1 attestation-forgery regression (RT1)", () => {
  it("the full forged export (real operator address, e=1, no private key) verifies as FAILED", async () => {
    const forged = await loadForgery();
    const r = await verifyEvidenceBundle(forged as never);
    expect(r.status).toBe("failed");
    // the forged attestation specifically does not bind (its signature is rejected)
    expect(r.export!.attestations.some((a) => a.signatureOk === false)).toBe(true);
  });

  it("verifyRsaPssSha256 rejects the forged export's e=1 attestation directly", async () => {
    const forged = await loadForgery();
    const att = (forged.body as { attestations: Array<Record<string, never>> }).attestations[0]!;
    const pk = att.public_key as unknown as { kty: "RSA"; n: string; e: string };
    expect(pk.e).not.toBe("AQAB"); // it's e=1 ("AQ"), not 65537
    const ok = await verifyRsaPssSha256(
      utf8(jcs(att.payload)),
      att.signature as unknown as string,
      pk,
    );
    expect(ok).toBe(false);
  });

  it("rejects an EVEN exponent (e=2) as a clean FAILED, not malformed — the cross-kernel case", async () => {
    // Even exponents are where the underlying libraries DIVERGE: pyca rejects
    // even e at key construction ("e must be >= 3 and < n") → the Python kernel
    // would report `malformed`, while WebCrypto imports it → the TS kernel would
    // report a `failed` verify. The exponent guard short-circuits BOTH kernels
    // to `false` (a clean FAILED) BEFORE key import, so e=2 agrees cross-kernel.
    // It MUST resolve `false`, never throw — throwing is the malformed signal
    // this guard exists to keep the kernels from diverging on. Mirrors
    // tests/test_attestation_exponent_forgery.py::test_exponent_guard_rejects_even_e.
    const pk = { kty: "RSA" as const, n: "sQ", e: "Ag" }; // e = 2 (even)
    await expect(verifyRsaPssSha256(utf8("any bytes"), "00", pk)).resolves.toBe(false);
  });

  it("an empty exponent is malformed (exit 2), not a failed verify", async () => {
    // CodeRabbit regression: an empty `e` decodes to 0 and must be treated as a
    // MALFORMED key (importKey throws) — not as "e != 65537" (which returns false).
    const forged = await loadForgery();
    const att = (forged.body as { attestations: Array<Record<string, never>> })
      .attestations[0]!;
    const pk = { ...(att.public_key as object), e: "" } as {
      kty: "RSA";
      n: string;
      e: string;
    };
    await expect(
      verifyRsaPssSha256(utf8(jcs(att.payload)), att.signature as unknown as string, pk),
    ).rejects.toThrow(/malformed/);
  });

  it("regression control: the legitimate golden export (e=65537) still verifies", async () => {
    // This fixture wraps the actual export under `.export` (+ tamper helpers).
    const golden = await load("evidence-export-bundle.golden.json");
    const r = await verifyEvidenceBundle((golden as { export: unknown }).export as never);
    expect(r.status).toBe("verified");
  });
});
