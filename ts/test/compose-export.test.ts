// `proof export` composer (evidence-export.md §5, phase 2) — the produce leg of
// the Moment-2 demo. The kernel already VERIFIES an ario.evidence.export/v1
// artifact (verifyExportBody); this exercises the inverse: composeExport() takes
// a source ario.anchor.trace/v1 bundle + operator attestations + an exporter
// Ed25519 key and PRODUCES the signed artifact — and the ground-truth assertion
// is that the produced bytes round-trip through the existing verifyEvidenceBundle
// path to exit 0, verdict `verified`, ≥2 attestations bound.
//
// The definition of done (§1 demo): produce → verify (exit 0) → tamper (exit 1)
// → offline (no network). Each is a case below. The composer reuses the KERNEL's
// own recompute (recomputeExportVerdict → buildVerdictObject) for the cached
// kernel_verdict, so verdict agreement (§5 step 5) is structurally guaranteed —
// asserted here directly.

import * as ed from "@noble/ed25519";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { bytesToHex } from "../src/crypto.js";
import { verifyEvidenceBundle } from "../src/evidence.js";
import type { AttestationRecord, EvidenceBundle } from "../src/evidence.js";
import { attestationSignatureToHex, composeExport } from "../src/compose.js";

const FIXTURE = fileURLToPath(
  new URL("./fixtures/evidence-export-bundle.golden.json", import.meta.url),
);

interface Golden {
  export: EvidenceBundle;
  operator_addresses: { op1: string; op2: string };
}

async function loadInputs(): Promise<{
  source: EvidenceBundle;
  attestations: AttestationRecord[];
  operators: { op1: string; op2: string };
}> {
  const g = JSON.parse(await readFile(FIXTURE, "utf8")) as Golden;
  const body = g.export.body as {
    source_bundle: EvidenceBundle;
    attestations: AttestationRecord[];
  };
  // The composer's inputs are the SOURCE bundle + the raw operator attestation
  // records — exactly what a real composer receives (the golden's source +
  // attestations, reused per the slice brief). Deep-clone so tests are isolated.
  return {
    source: clone(body.source_bundle),
    attestations: clone(body.attestations),
    operators: g.operator_addresses,
  };
}

function clone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x)) as T;
}
function flip(hex: string): string {
  return hex.slice(0, -1) + (hex.endsWith("0") ? "1" : "0");
}

// A fresh exporter key that is NOT the source bundle's signer — demonstrating P-4
// ("anyone can export"): the wrapper signer is a distinct party from the producer.
function exporterSeed(): string {
  return bytesToHex(ed.utils.randomPrivateKey());
}

// A fetch that THROWS if the network is ever touched — proves offline purity.
const noNetwork = (async () => {
  throw new Error("network access is forbidden in an offline verify");
}) as unknown as typeof fetch;

describe("composeExport — the produce→verify round-trip (§1 demo)", () => {
  it("produces an export that verifies to exit 0 / verified with ≥2 attestations bound", async () => {
    const { source, attestations, operators } = await loadInputs();
    const seed = exporterSeed();

    const composed = await composeExport(
      source,
      attestations,
      { privateKey: seed },
      { issuerId: "ar-io-verify:test", generatedAt: "2026-07-15T12:00:00Z" },
    );

    expect(composed.status).toBe("verified");
    expect(composed.boundAttestations).toBe(2);

    // Round-trip through the EXISTING verify path (ground truth).
    const r = await verifyEvidenceBundle(composed.bundle);
    expect(r.status).toBe("verified");
    expect(r.bodyType).toBe("ario.evidence.export/v1");
    expect(r.signatureOk).toBe(true);
    expect(r.bodyHashOk).toBe(true);

    const exp = r.export!;
    expect(exp.status).toBe("verified");
    expect(exp.sourceLinkageOk).toBe(true);
    // recompute-don't-trust: the cached kernel_verdict the composer embedded
    // AGREES with the verifier's fresh recompute over the deterministic dims.
    expect(exp.verdictAgreementOk).toBe(true);
    expect(exp.attestations).toHaveLength(2);
    expect(exp.attestations.every((a) => a.ok)).toBe(true);
    expect(exp.attestations.every((a) => a.signatureOk && a.operatorAddressBound && a.dataHashBound)).toBe(true);
    expect(exp.attestations.map((a) => a.operator)).toEqual([operators.op1, operators.op2]);
  });

  it("wraps with the exporter's key (distinct from the source producer) — P-4", async () => {
    const { source, attestations } = await loadInputs();
    const seed = exporterSeed();
    const pub = await ed.getPublicKeyAsync(Uint8Array.from(Buffer.from(seed, "hex")));
    const composed = await composeExport(source, attestations, { privateKey: seed });

    // Wrapper embeds the exporter's Ed25519 public key; the source bundle keeps
    // its own producer key — two distinct signers, two roles (§6).
    expect(composed.bundle.public_key).toBe(bytesToHex(pub));
    expect(composed.bundle.public_key).not.toBe(source.public_key);
    expect((composed.bundle.body as { source_bundle: EvidenceBundle }).source_bundle.public_key).toBe(
      source.public_key,
    );
    expect(composed.bundle.issuer.kind).toBe("issuer");
  });

  it("verifies fully OFFLINE — the produced export touches no network", async () => {
    const { source, attestations } = await loadInputs();
    const composed = await composeExport(source, attestations, { privateKey: exporterSeed() });
    // A fetchImpl that throws on any call; verified means it was never invoked.
    const r = await verifyEvidenceBundle(composed.bundle, { fetchImpl: noNetwork });
    expect(r.status).toBe("verified");
    expect(r.export!.status).toBe("verified");
  });

  it("does not mutate the caller's attestation input", async () => {
    const { source, attestations } = await loadInputs();
    const before = clone(attestations);
    await composeExport(source, attestations, { privateKey: exporterSeed() });
    expect(attestations).toEqual(before);
  });

  it("is deterministic for a fixed key + generated_at", async () => {
    const { source, attestations } = await loadInputs();
    const seed = exporterSeed();
    const a = await composeExport(source, attestations, { privateKey: seed }, { generatedAt: "2026-07-15T00:00:00Z" });
    const b = await composeExport(source, clone(attestations), { privateKey: seed }, { generatedAt: "2026-07-15T00:00:00Z" });
    expect(JSON.stringify(a.bundle)).toBe(JSON.stringify(b.bundle));
  });
});

describe("composeExport — tamper (§1 demo): a mutated export re-verifies to exit 1", () => {
  it("flipping an embedded attestation byte → failed", async () => {
    const { source, attestations } = await loadInputs();
    const composed = await composeExport(source, attestations, { privateKey: exporterSeed() });
    const tampered = clone(composed.bundle);
    const att = (tampered.body as { attestations: { signature: string }[] }).attestations[0]!;
    att.signature = flip(att.signature);
    const r = await verifyEvidenceBundle(tampered);
    expect(r.status).toBe("failed");
    // The wrapper signature no longer covers the mutated body → body_hash break.
    expect(r.signatureOk === false || r.bodyHashOk === false).toBe(true);
  });

  it("flipping a source-bundle byte → failed (source linkage / wrapper break)", async () => {
    const { source, attestations } = await loadInputs();
    const composed = await composeExport(source, attestations, { privateKey: exporterSeed() });
    const tampered = clone(composed.bundle);
    const sb = (tampered.body as { source_bundle: { body: { events: { record_bytes: string }[] } } })
      .source_bundle.body.events[0]!;
    sb.record_bytes = flip(sb.record_bytes);
    const r = await verifyEvidenceBundle(tampered);
    expect(r.status).toBe("failed");
  });
});

describe("composeExport — attestation signature boundary transcode (§2.2)", () => {
  it("accepts base64url signatures and stores them as lowercase hex", async () => {
    const { source, attestations } = await loadInputs();
    // Re-encode the issuer's hex signatures as unpadded base64url (the alternate
    // form the issuer may emit) — the composer must transcode to §2.2 hex.
    const b64Atts = clone(attestations).map((a) => ({
      ...a,
      signature: Buffer.from(a.signature as string, "hex").toString("base64url"),
    }));
    const composed = await composeExport(source, b64Atts, { privateKey: exporterSeed() });
    const outSigs = (composed.bundle.body as { attestations: { signature: string }[] }).attestations.map(
      (a) => a.signature,
    );
    for (const s of outSigs) expect(s).toMatch(/^[0-9a-f]+$/); // lowercase hex, no b64url chars
    // And the transcoded record still verifies (the signature bytes are identical,
    // only the encoding changed — the RSA-PSS payload signature is untouched).
    const r = await verifyEvidenceBundle(composed.bundle);
    expect(r.status).toBe("verified");
    expect(r.export!.attestations.every((a) => a.ok)).toBe(true);
  });

  it("attestationSignatureToHex: hex passthrough (lowercased) and base64url decode", () => {
    expect(attestationSignatureToHex("DEADbeef")).toBe("deadbeef");
    const bytes = Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0x01]);
    const b64url = Buffer.from(bytes).toString("base64url"); // odd length → not hex-shaped
    expect(attestationSignatureToHex(b64url)).toBe("deadbeef01");
  });
});

describe("composeExport — refuses to green-stamp failing evidence", () => {
  it("a broken source bundle yields a composed status of failed", async () => {
    const { source, attestations } = await loadInputs();
    // Corrupt a source event's committed record BEFORE composing.
    const evs = (source.body as { events: { record_bytes: string }[] }).events;
    evs[0]!.record_bytes = flip(evs[0]!.record_bytes);
    const composed = await composeExport(source, attestations, { privateKey: exporterSeed() });
    expect(composed.status).toBe("failed");
    // The emitted artifact is internally consistent (wrapper verifies) but its
    // recomputed verdict is failed — the verifier agrees.
    const r = await verifyEvidenceBundle(composed.bundle);
    expect(r.status).toBe("failed");
  });

  it("a malformed attestation record (bad RSA key) throws at compose time", async () => {
    const { source, attestations } = await loadInputs();
    const bad = clone(attestations);
    (bad[0] as { public_key: { kty: string } }).public_key.kty = "oct";
    await expect(composeExport(source, bad, { privateKey: exporterSeed() })).rejects.toThrow(/malformed/i);
  });
});
