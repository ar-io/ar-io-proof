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

describe("RSA exponent guard — e=1 attestation-forgery regression (RT1)", () => {
  it("the full forged export (real operator address, e=1, no private key) verifies as FAILED", async () => {
    const forged = await load("attestation-exponent-forgery.export.json");
    const r = await verifyEvidenceBundle(forged as never);
    expect(r.status).toBe("failed");
    // the forged attestation specifically does not bind (its signature is rejected)
    expect(r.export!.attestations.some((a) => a.signatureOk === false)).toBe(true);
  });

  it("verifyRsaPssSha256 rejects the forged export's e=1 attestation directly", async () => {
    const forged = await load("attestation-exponent-forgery.export.json");
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

  it("regression control: the legitimate golden export (e=65537) still verifies", async () => {
    // This fixture wraps the actual export under `.export` (+ tamper helpers).
    const golden = await load("evidence-export-bundle.golden.json");
    const r = await verifyEvidenceBundle((golden as { export: unknown }).export as never);
    expect(r.status).toBe("verified");
  });
});
