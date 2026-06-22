// CLI end-to-end: spawn the BUILT dist/cli.js as a real subprocess (not just
// call runCli) and assert stdout + the pinned exit codes the kickoff fixes:
//   0 verified · 1 real failure · 2 malformed · 3 gateway-unavailable-when-requested
//
// This is the contract a CI/shell consumer branches on (`npx @ar.io/proof
// verify … ; case $? in …`). Spawning the binary exercises the real argv
// parsing, file read, JSON parse, spec sniff, the global fetch (no injected
// fetchImpl across the process boundary), and process.exitCode plumbing — none
// of which the in-process cli.test.ts can reach.
//
// Requires `npm run build` first (dist/cli.js). The test self-skips with a loud
// message if dist is missing, rather than silently passing.

import * as ed from "@noble/ed25519";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { bytesToHex, sha256Hex, utf8 } from "../src/crypto.js";
import { auditPath, leafHash, merkleRoot } from "../src/merkle.js";
import { jcs } from "../src/verifier.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "..", "dist", "cli.js");
const GOLDEN = join(HERE, "fixtures", "anchor-trace-bundle.golden.json");

const SEED_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
function seed(): Uint8Array {
  return Uint8Array.from(Buffer.from(SEED_HEX, "hex"));
}
async function pubHex(): Promise<string> {
  return bytesToHex(await ed.getPublicKeyAsync(seed()));
}

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

// Run the built CLI as a subprocess; resolve its exit code + captured streams.
function runCliProcess(args: string[]): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, NO_COLOR: "1" }, // deterministic, un-escaped output
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? -1, stdout, stderr }));
  });
}

// ---- bundle builders (mirror the producer flows) ----------------------------

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

// An evidence bundle with optional withheld record on one event.
async function buildEvidenceBundle(opts: { withholdRecordOf?: number } = {}): Promise<{
  bundle: Record<string, unknown>;
  checkpointEnvelope: unknown;
  checkpointTxId: string;
}> {
  const recs = [{ v: 0 }, { v: 1 }, { v: 2 }];
  const evs = [];
  for (let i = 0; i < recs.length; i++) {
    const { envelope, recordBytes } = await signEvent(
      recs[i],
      `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`,
    );
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
  const { envelope: cpEnv, recordBytes: cpBytes } = await signEvent(
    cpRecord,
    "00000000-0000-4000-8000-ffffffffffff",
  );
  const txId = "tx-cli-e2e-1";
  const body = {
    checkpoints: [{ tx_id: txId, envelope: cpEnv, record_bytes: bytesToHex(cpBytes), merkle_root: root }],
    events: await Promise.all(
      evs.map(async (e, i) => ({
        envelope: e.envelope,
        ...(opts.withholdRecordOf === i ? {} : { record_bytes: bytesToHex(e.recordBytes) }),
        inclusion: {
          leaf_hash: bytesToHex(e.leaf),
          leaf_index: i,
          leaf_count: leaves.length,
          audit_path: (await auditPath(i, leaves)).map(bytesToHex),
          checkpoint_tx_id: txId,
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
  return { bundle: { ...pre, signature: bytesToHex(sig) }, checkpointEnvelope: cpEnv, checkpointTxId: txId };
}

// An ario.agent.proof/v1 inclusion bundle (the CLI must verify this too).
async function buildAgentProofBundle(): Promise<Record<string, unknown>> {
  const leaves = [
    { asset_id: "a", outcome: "verified" },
    { asset_id: "b", outcome: "verified" },
    { asset_id: "c", outcome: "verified" },
  ];
  const leafHashes = await Promise.all(leaves.map((l) => leafHash(utf8(jcs(l)))));
  const root = await merkleRoot(leafHashes);
  const payload = {
    merkle_root: bytesToHex(root),
    leaf_count: leaves.length,
    window_start: "2026-06-22T00:00:00Z",
  };
  const pre: Record<string, unknown> = {
    spec_version: "ario.agent/v1",
    event_id: "11111111-1111-4111-8111-111111111111",
    event_type: "verification_checkpoint",
    subject: { type: "checkpoint", tenant_id: "acme", agent_id: "host-01" },
    payload,
    payload_hash: await sha256Hex(utf8(jcs(payload))),
    previous_hash: "GENESIS",
    signed_at: "2026-06-22T00:00:00Z",
    public_key: await pubHex(),
  };
  const sig = await ed.signAsync(utf8(jcs(pre)), seed());
  const checkpointEnvelope = { ...pre, signature: bytesToHex(sig) };
  return {
    spec_version: "ario.agent.proof/v1",
    checkpoint_envelope: checkpointEnvelope,
    checkpoint_tx_id: "agent-checkpoint-tx-0001",
    leaf: leaves[1],
    leaf_index: 1,
    audit_path: (await auditPath(1, leafHashes)).map(bytesToHex),
  };
}

let dir: string;
async function writeFixture(name: string, obj: unknown): Promise<string> {
  const p = join(dir, name);
  await writeFile(p, JSON.stringify(obj, null, 2), "utf8");
  return p;
}

beforeAll(() => {
  if (!existsSync(CLI)) {
    throw new Error(
      `dist/cli.js not found at ${CLI} — run \`npm run build\` before the CLI e2e test`,
    );
  }
});
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "proof-cli-e2e-"));
});
afterEach(() => {
  // OS cleans tmp.
});

describe("CLI subprocess — pinned exit codes (evidence bundle)", () => {
  it("exit 0 + VERIFIED on the committed golden fixture", async () => {
    const r = await runCliProcess(["verify", GOLDEN]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED/);
    expect(r.stdout).toMatch(/ario\.anchor\.trace\/v1/);
  });

  it("exit 0 + VERIFIED on a freshly built evidence bundle", async () => {
    const { bundle } = await buildEvidenceBundle();
    const p = await writeFixture("good.json", bundle);
    const r = await runCliProcess(["verify", p]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED/);
  });

  it("exit 1 + FAILED on a tampered record byte", async () => {
    const { bundle } = await buildEvidenceBundle();
    const ev = (bundle.body as { events: { record_bytes: string }[] }).events[0]!;
    ev.record_bytes = ev.record_bytes.slice(0, -1) + (ev.record_bytes.endsWith("0") ? "1" : "0");
    const p = await writeFixture("tampered.json", bundle);
    const r = await runCliProcess(["verify", p]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
  });

  it("exit 2 + MALFORMED on an unknown spec_version major", async () => {
    const { bundle } = await buildEvidenceBundle();
    bundle.spec_version = "ario.evidence/v9";
    const p = await writeFixture("unknown.json", bundle);
    const r = await runCliProcess(["verify", p]);
    expect(r.code).toBe(2);
    expect(r.stderr + r.stdout).toMatch(/MALFORMED|unsupported/i);
  });

  it("exit 2 on non-JSON input", async () => {
    const p = join(dir, "garbage.json");
    await writeFile(p, "definitely not json", "utf8");
    const r = await runCliProcess(["verify", p]);
    expect(r.code).toBe(2);
  });

  it("exit 2 on a missing file", async () => {
    const r = await runCliProcess(["verify", join(dir, "nope.json")]);
    expect(r.code).toBe(2);
  });

  it("exit 2 when verify is given no path", async () => {
    const r = await runCliProcess(["verify"]);
    expect(r.code).toBe(2);
  });

  it("exit 0 with a withheld record (semantics-undetermined, not a failure)", async () => {
    const { bundle } = await buildEvidenceBundle({ withholdRecordOf: 1 });
    const p = await writeFixture("withheld.json", bundle);
    const r = await runCliProcess(["verify", p]);
    // A withheld record is surfaced (~ / "record withheld") but does NOT fail.
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/record withheld/i);
  });
});

describe("CLI subprocess — gateway re-fetch (real fetch across the process boundary)", () => {
  it("exit 3 when on-chain is requested but every gateway is unreachable", async () => {
    const p = await writeFixture("good-gw.json", (await buildEvidenceBundle()).bundle);
    // 127.0.0.1:1 — a port nothing listens on: connection refused, deterministic.
    const r = await runCliProcess(["verify", p, "http://127.0.0.1:1"]);
    expect(r.code).toBe(3);
  });

  it("exit 0 when a reachable gateway returns the exact checkpoint bytes", async () => {
    const { bundle, checkpointEnvelope, checkpointTxId } = await buildEvidenceBundle();
    const onChain = utf8(jcs(checkpointEnvelope));
    // A tiny real HTTP server returns the canonical checkpoint bytes at /<txId>.
    const server = createServer((req, res) => {
      if (req.url === `/${checkpointTxId}`) {
        res.writeHead(200, { "content-type": "application/octet-stream" });
        res.end(Buffer.from(onChain));
      } else {
        res.writeHead(404);
        res.end();
      }
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    try {
      const p = await writeFixture("good-gw2.json", bundle);
      const r = await runCliProcess(["verify", p, `http://127.0.0.1:${port}`]);
      expect(r.code).toBe(0);
      expect(r.stdout).toMatch(/on-chain/);
      expect(r.stdout).toMatch(/VERIFIED/);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

describe("CLI subprocess — agent inclusion proof sniff path", () => {
  it("exit 0 + verifies an ario.agent.proof/v1 bundle (one CLI covers both)", async () => {
    const p = await writeFixture("agent-proof.json", await buildAgentProofBundle());
    const r = await runCliProcess(["verify", p]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/Agent inclusion proof/);
    expect(r.stdout).toMatch(/VERIFIED/);
  });

  it("exit 1 + FAILED on a tampered agent-proof leaf", async () => {
    const ap = await buildAgentProofBundle();
    (ap.leaf as { outcome: string }).outcome = "tampered-value";
    const p = await writeFixture("agent-proof-bad.json", ap);
    const r = await runCliProcess(["verify", p]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
  });
});

describe("CLI subprocess — usage", () => {
  it("help exits 0 and prints usage", async () => {
    const r = await runCliProcess(["help"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/Usage/);
    expect(r.stdout).toMatch(/Exit codes/);
  });

  it("no command exits 2 (malformed usage)", async () => {
    const r = await runCliProcess([]);
    expect(r.code).toBe(2);
  });

  // Sanity: the committed golden fixture and the freshly built bundle are the
  // same shape, so the same CLI verb handles both — drift guard.
  it("the golden fixture is well-formed JSON the CLI accepts", async () => {
    const raw = await readFile(GOLDEN, "utf8");
    expect(() => JSON.parse(raw)).not.toThrow();
  });
});
