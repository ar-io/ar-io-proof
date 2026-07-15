// Attested-evidence-export verification (evidence-export.md §5). A REAL frozen
// `ario.evidence.export/v1` golden — an Ed25519 issuer-signed wrapper (the
// stack's well-known test seed) over an inline `ario.anchor.trace/v1` source
// bundle + 2 salt=32 RSA-PSS operator attestations + a cached kernel_verdict
// with a per-gateway confirm/unreachable on-chain mix — emitted by
// scripts/gen-export-fixture.mjs and committed here as frozen bytes.
//
// The positive pins the whole §5 algorithm end to end (wrapper sig + body_hash,
// source linkage, source-verdict recompute, verdict agreement, embedded
// RSA-PSS attestations + operator/data_hash binding, per-gateway fold-in). The
// per-class negatives pin exactly which exit each failure earns: the four
// wrapper/linkage/verdict classes → exit 1, the four attestation classes →
// exit 1, an on-chain `mismatch` → exit 1, but an all-`unreachable` export
// still verifies OFFLINE (exit 0) and only becomes exit 3 when a re-fetch is
// actually requested against a down gateway. The step-5 nuance — an on-chain-
// dimension-only difference in the cached verdict is INFORMATIONAL and must NOT
// trigger a tamper verdict — gets its own case.

import * as ed from "@noble/ed25519";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it } from "vitest";

import { bytesToHex, sha256Hex, utf8 } from "../src/crypto.js";
import { jcs } from "../src/verifier.js";
import { verifyEvidenceBundle } from "../src/evidence.js";
import type { EvidenceBundle } from "../src/evidence.js";
import { runCli } from "../src/cli.js";

const FIXTURE = fileURLToPath(
  new URL("./fixtures/evidence-export-bundle.golden.json", import.meta.url),
);

// The stack's well-known test seed — the issuer key the fixture wrapper (and its
// inline source bundle) are signed with, so a tamper test can re-sign a mutated
// wrapper and ISOLATE an inner check from the wrapper signature.
const SEED_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
function seed(): Uint8Array {
  return Uint8Array.from(Buffer.from(SEED_HEX, "hex"));
}

interface ExportFixture {
  seed_hex: string;
  checkpoint_tx_id: string;
  checkpoint_content_hash: string;
  operator_addresses: { op1: string; op2: string };
  export: EvidenceBundle;
  _tamper: {
    att0_mis_salt_sig: string;
    wrong_operator_attestation: Record<string, unknown>;
    wrong_data_hash_attestation: Record<string, unknown>;
  };
}

async function load(): Promise<ExportFixture> {
  return JSON.parse(await readFile(FIXTURE, "utf8")) as ExportFixture;
}
function clone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x)) as T;
}
function flip(hex: string): string {
  return hex.slice(0, -1) + (hex.endsWith("0") ? "1" : "0");
}

// Re-sign the wrapper over the (mutated) body with the fixture's own key, so a
// body tamper is isolated from the wrapper signature. Mirrors the issuer flow.
async function reSignWrapper(b: EvidenceBundle): Promise<void> {
  b.body_hash = await sha256Hex(utf8(jcs(b.body)));
  const { signature: _s, ...pre } = b as EvidenceBundle & { signature?: string };
  b.public_key = bytesToHex(await ed.getPublicKeyAsync(seed()));
  b.signature = bytesToHex(await ed.signAsync(utf8(jcs(pre)), seed()));
}

// Typed accessors into the export body (the fixture is opaque JSON).
function body(b: EvidenceBundle): {
  kernel_verdict: Record<string, unknown>;
  source_bundle: EvidenceBundle;
  source_bundle_hash: string;
  attestations: Record<string, unknown>[];
} {
  return b.body as never;
}
function checkpointEnvelope(b: EvidenceBundle): unknown {
  return (
    body(b).source_bundle.body as {
      checkpoints: { envelope: unknown }[];
    }
  ).checkpoints[0]!.envelope;
}

// A CLI harness: write the (possibly mutated) export to a temp file and run the
// real CLI dispatch, capturing the pinned exit code + rendered output.
let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "proof-export-"));
});
async function cli(
  bundle: unknown,
  args: string[] = [],
  fetchImpl?: typeof fetch,
): Promise<{ code: number; out: string; err: string }> {
  const p = join(dir, "export.json");
  await writeFile(p, JSON.stringify(bundle, null, 2), "utf8");
  const out: string[] = [];
  const err: string[] = [];
  const io = {
    out: (s: string) => out.push(s),
    err: (s: string) => err.push(s),
    ...(fetchImpl ? { fetchImpl } : {}),
  };
  const code = await runCli(["verify", p, ...args], io);
  return { code, out: out.join("\n"), err: err.join("\n") };
}

// A fetchImpl that returns the exact checkpoint bytes for g1 and is down
// elsewhere (reproduces the issuer's confirm/unreachable observation).
function mixFetch(cpEnv: unknown): typeof fetch {
  return (async (url: string | URL) => {
    if (String(url).includes("g1")) {
      return new Response(utf8(jcs(cpEnv)) as unknown as BodyInit, { status: 200 });
    }
    throw new Error("ECONNREFUSED");
  }) as unknown as typeof fetch;
}

describe("evidence-export golden — the positive vector", () => {
  it("the fixture is signed with the well-known stack seed", async () => {
    const f = await load();
    expect(f.seed_hex).toBe(SEED_HEX);
  });

  it("verifies fully green OFFLINE → exit 0, recomputed verdict agrees with cached", async () => {
    const f = await load();
    const r = await verifyEvidenceBundle(f.export);

    expect(r.status).toBe("verified");
    expect(r.bodyType).toBe("ario.evidence.export/v1");
    expect(r.signatureOk).toBe(true);
    expect(r.bodyHashOk).toBe(true);
    expect(r.specVersionOk).toBe(true);

    const exp = r.export!;
    expect(exp.sourceLinkageOk).toBe(true);
    expect(exp.sourceStatus).toBe("verified");
    // recompute-don't-trust: the fresh verdict AGREES with the cached one over
    // the deterministic (offline-recomputable) dimensions.
    expect(exp.verdictAgreementOk).toBe(true);
    expect(exp.status).toBe("verified");

    // Two embedded operator attestations, both fully bound.
    expect(exp.attestations).toHaveLength(2);
    for (const a of exp.attestations) {
      expect(a.signatureOk).toBe(true);
      expect(a.operatorAddressBound).toBe(true);
      expect(a.dataHashBound).toBe(true);
      expect(a.checkpointResolved).toBe(true);
      expect(a.ok).toBe(true);
    }
    expect(exp.attestations[0]!.operator).toBe(f.operator_addresses.op1);
    expect(exp.attestations[1]!.operator).toBe(f.operator_addresses.op2);
    // subject_ref present on att0 (well-formed, no side input) → undetermined.
    expect(exp.attestations[0]!.subjectRefOk).toBe(null);
  });

  it("recomputes the §4 verdict object (content_ok tri-state; one disclosed log)", async () => {
    const f = await load();
    const r = await verifyEvidenceBundle(f.export);
    const v = r.export!.verdict;

    expect(v.schema_version).toBe("ario.evidence.verdict/v1");
    // Event 0 disclosed its raw bytes in-body → content_ok true; 1 & 2 undisclosed
    // → null (content-blind, NOT a failure).
    expect(v.events.map((e) => e.content_ok)).toEqual([true, null, null]);
    expect(v.events.every((e) => e.signature_ok && e.inclusion_ok)).toBe(true);
    // The recomputed per-attestation bindings match the cached kernel_verdict's.
    const cached = f.export.body as { kernel_verdict: { checkpoints: { attestations: unknown[] }[] } };
    expect(v.checkpoints[0]!.attestations).toEqual(cached.kernel_verdict.checkpoints[0]!.attestations);
    // Offline: no gateway re-fetch → the on_chain dimension is null (the cached
    // copy carries the issuer's confirm/unreachable observation; §5 step 5
    // excludes it from agreement).
    expect(v.checkpoints[0]!.on_chain).toBe(null);
  });

  it("CLI: exit 0 and renders the attested-export block", async () => {
    const f = await load();
    const { code, out } = await cli(f.export);
    expect(code).toBe(0);
    expect(out).toMatch(/VERIFIED/);
    expect(out).toMatch(/Attested export/);
    expect(out).toMatch(/Operator attestations/);
  });
});

describe("evidence-export — per-gateway on-chain outcomes (§4.2, additive)", () => {
  it("confirm/mismatch/unreachable each collapse to the retained onChainOk", async () => {
    const f = await load();
    const cpEnv = checkpointEnvelope(f.export);

    const confirm = (async () =>
      new Response(utf8(jcs(cpEnv)) as unknown as BodyInit, { status: 200 })) as unknown as typeof fetch;
    let r = await verifyEvidenceBundle(f.export, { gateways: ["https://g.example"], fetchImpl: confirm });
    expect(r.checkpoints[0]!.onChain!.rollup).toBe("confirm");
    expect(r.checkpoints[0]!.onChainOk).toBe(true); // collapsed field retained
    expect(r.status).toBe("verified");

    const mismatch = (async () =>
      new Response(utf8(JSON.stringify({ other: "bytes" })) as unknown as BodyInit, {
        status: 200,
      })) as unknown as typeof fetch;
    r = await verifyEvidenceBundle(f.export, { gateways: ["https://g.example"], fetchImpl: mismatch });
    expect(r.checkpoints[0]!.onChain!.rollup).toBe("mismatch");
    expect(r.checkpoints[0]!.onChainOk).toBe(false);
    expect(r.status).toBe("failed");

    const down = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    r = await verifyEvidenceBundle(f.export, { gateways: ["https://g.example"], fetchImpl: down });
    expect(r.checkpoints[0]!.onChain!.rollup).toBe("unreachable");
    expect(r.checkpoints[0]!.onChainOk).toBe(null);
    expect(r.status).toBe("partial");
  });

  it("a confirm/unreachable MIX preserves the per-gateway array (worst-finding rollup)", async () => {
    const f = await load();
    const r = await verifyEvidenceBundle(f.export, {
      gateways: ["https://g1.example", "https://g2.example"],
      fetchImpl: mixFetch(checkpointEnvelope(f.export)),
    });
    const oc = r.checkpoints[0]!.onChain!;
    expect(oc.perGateway).toEqual([
      { gateway: "https://g1.example", outcome: "confirm" },
      { gateway: "https://g2.example", outcome: "unreachable" },
    ]);
    expect(oc.rollup).toBe("confirm"); // best-evidence after no mismatch
    expect(oc.onChainOk).toBe(true);
    expect(r.status).toBe("verified");
  });
});

describe("evidence-export — tampered-per-class negatives (each earns its exit)", () => {
  it("wrapper-signature break → exit 1 (no export block; body not trusted)", async () => {
    const f = await load();
    const e = clone(f.export);
    e.signature = flip(e.signature);
    const r = await verifyEvidenceBundle(e);
    expect(r.status).toBe("failed");
    expect(r.signatureOk).toBe(false);
    expect(r.export).toBeUndefined();
    expect((await cli(e)).code).toBe(1);
  });

  it("body_hash mismatch → exit 1", async () => {
    const f = await load();
    const e = clone(f.export);
    e.body_hash = flip(e.body_hash);
    const r = await verifyEvidenceBundle(e);
    expect(r.status).toBe("failed");
    expect(r.bodyHashOk).toBe(false);
    expect((await cli(e)).code).toBe(1);
  });

  it("source_bundle_hash mismatch → exit 1 (source linkage broken)", async () => {
    const f = await load();
    const e = clone(f.export);
    body(e).source_bundle_hash = flip(body(e).source_bundle_hash);
    await reSignWrapper(e);
    const r = await verifyEvidenceBundle(e);
    expect(r.status).toBe("failed");
    expect(r.signatureOk).toBe(true); // wrapper authentic; the LINKAGE is broken
    expect(r.export!.sourceLinkageOk).toBe(false);
    expect((await cli(e)).code).toBe(1);
  });

  it("verdict disagreement (mutate cached verdict) → exit 1", async () => {
    const f = await load();
    const e = clone(f.export);
    // Flip a cached deterministic finding the recompute contradicts.
    (body(e).kernel_verdict as { events: { signature_ok: boolean }[] }).events[0]!.signature_ok = false;
    await reSignWrapper(e);
    const r = await verifyEvidenceBundle(e);
    expect(r.status).toBe("failed");
    expect(r.signatureOk).toBe(true);
    expect(r.export!.verdictAgreementOk).toBe(false);
    expect((await cli(e)).code).toBe(1);
  });

  it("forged attestation signature (one flipped byte) → exit 1", async () => {
    const f = await load();
    const e = clone(f.export);
    const att = body(e).attestations[0] as { signature: string };
    att.signature = flip(att.signature);
    await reSignWrapper(e);
    const r = await verifyEvidenceBundle(e);
    expect(r.status).toBe("failed");
    expect(r.signatureOk).toBe(true);
    expect(r.export!.attestations[0]!.signatureOk).toBe(false);
    expect(r.export!.attestations[0]!.ok).toBe(false);
    expect((await cli(e)).code).toBe(1);
  });

  it("mis-salted attestation signature (max/auto salt) → exit 1 (the salt=32 pin)", async () => {
    const f = await load();
    const e = clone(f.export);
    (body(e).attestations[0] as { signature: string }).signature = f._tamper.att0_mis_salt_sig;
    await reSignWrapper(e);
    const r = await verifyEvidenceBundle(e);
    expect(r.status).toBe("failed");
    // WebCrypto cannot auto-detect salt on verify → the max-salt signature over
    // the SAME payload+key is rejected by the salt=32 pin.
    expect(r.export!.attestations[0]!.signatureOk).toBe(false);
    expect((await cli(e)).code).toBe(1);
  });

  it("operator-address-binding break → exit 1 (sig valid, binding fails)", async () => {
    const f = await load();
    const e = clone(f.export);
    // A record signed by op2 whose payload still claims op1's address.
    body(e).attestations[0] = f._tamper.wrong_operator_attestation;
    await reSignWrapper(e);
    const r = await verifyEvidenceBundle(e);
    expect(r.status).toBe("failed");
    const a = r.export!.attestations[0]!;
    expect(a.signatureOk).toBe(true); // op2 really signed it
    expect(a.operatorAddressBound).toBe(false); // but base64url(SHA-256(op2.n)) != op1
    expect(a.ok).toBe(false);
    expect((await cli(e)).code).toBe(1);
  });

  it("a data_hash that does not bind the checkpoint → exit 1 (sig + operator valid)", async () => {
    const f = await load();
    const e = clone(f.export);
    body(e).attestations[0] = f._tamper.wrong_data_hash_attestation;
    await reSignWrapper(e);
    const r = await verifyEvidenceBundle(e);
    expect(r.status).toBe("failed");
    const a = r.export!.attestations[0]!;
    expect(a.signatureOk).toBe(true);
    expect(a.operatorAddressBound).toBe(true);
    expect(a.dataHashBound).toBe(false); // data_hash != SHA-256(JCS(checkpoint envelope))
    expect(a.ok).toBe(false);
    expect((await cli(e)).code).toBe(1);
  });

  it("a checkpoint on-chain MISMATCH (re-fetch) → exit 1", async () => {
    const f = await load();
    const mismatch = (async () =>
      new Response(utf8(JSON.stringify({ tampered: true })) as unknown as BodyInit, {
        status: 200,
      })) as unknown as typeof fetch;
    const r = await verifyEvidenceBundle(f.export, {
      gateways: ["https://g.example"],
      fetchImpl: mismatch,
    });
    expect(r.status).toBe("failed");
    expect(r.export!.status).toBe("failed");
    expect((await cli(f.export, ["https://g.example"], mismatch)).code).toBe(1);
  });
});

describe("evidence-export — undetermined is NOT failed (§5 step-5 nuance + exit 3)", () => {
  it("an all-unreachable export still verifies OFFLINE → exit 0", async () => {
    // The cached verdict carries the issuer's on-chain observation, but an
    // offline verifier does no re-fetch — the inline inclusion proofs still
    // verify from the file alone. The environment-dependent on-chain dimension
    // must NOT drag the verdict to failed.
    const f = await load();
    const r = await verifyEvidenceBundle(f.export);
    expect(r.status).toBe("verified");
    expect((await cli(f.export)).code).toBe(0);
  });

  it("an on-chain-dimension-only difference in the cached verdict does NOT trigger exit 1", async () => {
    // The KEY nuance: mutate ONLY the cached on_chain block (a dimension the
    // offline verifier legitimately sees as null). Agreement compares only the
    // deterministic dimensions, so this stays verified — an on-chain-only cache
    // discrepancy is informational, never tamper.
    const f = await load();
    const e = clone(f.export);
    const cp = (body(e).kernel_verdict as {
      checkpoints: { on_chain: { on_chain_ok: unknown; rollup: string; per_gateway: unknown[] } }[];
    }).checkpoints[0]!;
    cp.on_chain.on_chain_ok = false;
    cp.on_chain.rollup = "unreachable";
    cp.on_chain.per_gateway = [{ gateway: "https://elsewhere.example", outcome: "unreachable" }];
    await reSignWrapper(e);
    const r = await verifyEvidenceBundle(e);
    expect(r.export!.verdictAgreementOk).toBe(true); // on_chain excluded from agreement
    expect(r.status).toBe("verified");
    expect((await cli(e)).code).toBe(0);
  });

  it("a re-fetch against a down gateway → exit 3 (undetermined, not failed)", async () => {
    const f = await load();
    const down = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    const r = await verifyEvidenceBundle(f.export, { gateways: ["https://down.example"], fetchImpl: down });
    expect(r.status).toBe("partial");
    expect((await cli(f.export, ["https://down.example"], down)).code).toBe(3);
  });
});

describe("evidence-export — malformed inputs (exit 2)", () => {
  it("an unparseable embedded RSA key is malformed → exit 2", async () => {
    const f = await load();
    const e = clone(f.export);
    // A structurally-invalid JWK (wrong kty) throws on import — malformed input,
    // not a failed verify (mirrors the crypto slice's malformed-vs-failed split).
    (body(e).attestations[0] as { public_key: { kty: string } }).public_key.kty = "oct";
    await reSignWrapper(e);
    const r = await verifyEvidenceBundle(e);
    expect(r.status).toBe("malformed");
    expect((await cli(e)).code).toBe(2);
  });

  it("an unsupported attestation signature_alg is malformed → exit 2", async () => {
    const f = await load();
    const e = clone(f.export);
    (body(e).attestations[0] as { signature_alg: string }).signature_alg = "ed25519";
    await reSignWrapper(e);
    const r = await verifyEvidenceBundle(e);
    expect(r.status).toBe("malformed");
    expect((await cli(e)).code).toBe(2);
  });

  it("a source_bundle_ref (no inline source) is undetermined offline → exit 3", async () => {
    const f = await load();
    const e = clone(f.export);
    const eb = body(e) as unknown as {
      source_bundle?: unknown;
      source_bundle_ref?: string;
    };
    delete eb.source_bundle;
    eb.source_bundle_ref = "ar://some-large-source-bundle-txid";
    await reSignWrapper(e);
    const r = await verifyEvidenceBundle(e);
    expect(r.status).toBe("partial"); // bytes unavailable offline — NOT a failure
    expect((await cli(e)).code).toBe(3);
  });
});
