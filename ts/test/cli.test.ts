// CLI exit-code contract (mirrors `ariod verify-status`):
//   0 verified · 1 failed · 2 malformed · 3 gateway-unavailable.
// runCli is exported with injectable io (out/err capture) + fetch, so the
// pinned codes and the pretty output are tested without spawning a process.

import * as ed from "@noble/ed25519";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { bytesToHex, sha256Hex, utf8 } from "../src/crypto.js";
import { auditPath, leafHash, merkleRoot } from "../src/merkle.js";
import { jcs } from "../src/verifier.js";
import { runCli } from "../src/cli.js";

const SEED_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
function seed(): Uint8Array {
  return Uint8Array.from(Buffer.from(SEED_HEX, "hex"));
}
async function pubHex(): Promise<string> {
  return bytesToHex(await ed.getPublicKeyAsync(seed()));
}

async function signEvent(record: unknown, id: string) {
  const recordBytes = utf8(jcs(record));
  const pre: Record<string, unknown> = {
    spec_version: "ario.events/v1",
    event_id: id,
    payload_hash: await sha256Hex(recordBytes),
    signed_at: "2026-06-22T00:00:00Z",
    environment: "dev",
    public_key: await pubHex(),
  };
  const sig = await ed.signAsync(utf8(jcs(pre)), seed());
  return { envelope: { ...pre, signature: bytesToHex(sig) }, recordBytes };
}

async function buildBundle(): Promise<Record<string, unknown>> {
  const recs = [{ v: 0 }, { v: 1 }, { v: 2 }];
  const evs = [];
  for (let i = 0; i < recs.length; i++) {
    const { envelope, recordBytes } = await signEvent(recs[i], `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`);
    evs.push({ envelope, recordBytes, leaf: await leafHash(utf8(jcs(envelope))) });
  }
  const leaves = evs.map((e) => e.leaf);
  const root = bytesToHex(await merkleRoot(leaves));
  const cpRecord = {
    payload_version: 1,
    spec_version: "ario.events/v1",
    event_type: "checkpoint",
    subject: { type: "producer" },
    previous_hash: "GENESIS",
    event: { merkle_root: root, leaf_count: leaves.length },
    context: {},
    metadata: {},
    extras: {},
  };
  const { envelope: cpEnv, recordBytes: cpBytes } = await signEvent(cpRecord, "00000000-0000-4000-8000-ffffffffffff");
  const body = {
    checkpoints: [{ tx_id: "tx-1", envelope: cpEnv, record_bytes: bytesToHex(cpBytes), merkle_root: root }],
    events: await Promise.all(
      evs.map(async (e, i) => ({
        envelope: e.envelope,
        record_bytes: bytesToHex(e.recordBytes),
        inclusion: {
          leaf_hash: bytesToHex(e.leaf),
          leaf_index: i,
          leaf_count: leaves.length,
          audit_path: (await auditPath(i, leaves)).map(bytesToHex),
          checkpoint_tx_id: "tx-1",
        },
      })),
    ),
  };
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
  return { ...pre, signature: bytesToHex(sig) };
}

let dir: string;
let out: string[];
let err: string[];
const io = {
  out: (s: string) => out.push(s),
  err: (s: string) => err.push(s),
};

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "proof-cli-"));
  out = [];
  err = [];
});
afterEach(() => {
  // best-effort; OS cleans tmp
});

async function writeFixture(name: string, obj: unknown): Promise<string> {
  const p = join(dir, name);
  await writeFile(p, JSON.stringify(obj, null, 2), "utf8");
  return p;
}

describe("runCli exit codes", () => {
  it("exit 0 on a good evidence bundle and prints VERIFIED", async () => {
    const p = await writeFixture("good.json", await buildBundle());
    const code = await runCli(["verify", p], io);
    expect(code).toBe(0);
    expect(out.join("\n")).toMatch(/VERIFIED/);
  });

  it("exit 1 on a tampered bundle and prints FAILED", async () => {
    const bundle = await buildBundle();
    // Flip a record byte AND its event will fail to bind; body_hash + sig also break.
    (bundle.body as { events: { record_bytes: string }[] }).events[0]!.record_bytes = "ab".repeat(8);
    const p = await writeFixture("bad.json", bundle);
    const code = await runCli(["verify", p], io);
    expect(code).toBe(1);
    expect(out.join("\n")).toMatch(/FAILED/);
  });

  it("exit 2 on an unknown spec_version major", async () => {
    const bundle = await buildBundle();
    bundle.spec_version = "ario.evidence/v9";
    const p = await writeFixture("unknown.json", bundle);
    const code = await runCli(["verify", p], io);
    expect(code).toBe(2);
  });

  it("exit 2 on non-JSON input", async () => {
    const p = join(dir, "garbage.json");
    await writeFile(p, "not json at all", "utf8");
    const code = await runCli(["verify", p], io);
    expect(code).toBe(2);
  });

  it("exit 2 when the file is missing", async () => {
    const code = await runCli(["verify", join(dir, "nope.json")], io);
    expect(code).toBe(2);
  });

  it("exit 3 when on-chain was requested but the gateway is unreachable", async () => {
    const p = await writeFixture("good2.json", await buildBundle());
    const fetchImpl = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    const code = await runCli(["verify", p, "https://down.example"], { ...io, fetchImpl });
    expect(code).toBe(3);
  });

  it("exit 0 on a good bundle WITH a reachable gateway", async () => {
    const bundle = await buildBundle();
    const cpEnv = (bundle.body as { checkpoints: { envelope: unknown }[] }).checkpoints[0]!.envelope;
    const onChain = utf8(jcs(cpEnv));
    const fetchImpl = (async () =>
      new Response(onChain as unknown as BodyInit, { status: 200 })) as unknown as typeof fetch;
    const p = await writeFixture("good3.json", bundle);
    const code = await runCli(["verify", p, "https://gw.example"], { ...io, fetchImpl });
    expect(code).toBe(0);
    expect(out.join("\n")).toMatch(/on-chain/);
  });

  it("verify with no path is malformed (exit 2)", async () => {
    const code = await runCli(["verify"], io);
    expect(code).toBe(2);
  });

  it("help exits 0", async () => {
    const code = await runCli(["help"], io);
    expect(code).toBe(0);
    expect(out.join("\n")).toMatch(/Usage/);
  });
});
