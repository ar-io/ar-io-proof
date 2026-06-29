// CLI content (raw-log) verification, end-to-end against the BUILT dist/cli.js.
// Covers both disclosure surfaces the verifier exposes:
//   - in-body  events[].content  → verified automatically (no flag)
//   - out-of-band --logs <file>  → JSON { event_id: bytes }, hex-or-utf8
// and the pinned exit codes the rest of the CLI fixes (0 verified · 1 failed ·
// 2 malformed). A content mismatch reaches exit 1 via the failed rollup — no
// new exit code. Requires `npm run build` first (CI builds before test).

import * as ed from "@noble/ed25519";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

import { bytesToHex, sha256Hex, utf8 } from "../src/crypto.js";
import { auditPath, leafHash, merkleRoot } from "../src/merkle.js";
import { jcs } from "../src/verifier.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "..", "dist", "cli.js");

const SEED_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
function seed(): Uint8Array {
  return Uint8Array.from(Buffer.from(SEED_HEX, "hex"));
}
async function pubHex(): Promise<string> {
  return bytesToHex(await ed.getPublicKeyAsync(seed()));
}

// The two events' raw log bytes are fixed so tests can disclose the matching
// (or deliberately wrong) bytes without threading them out of the builder.
const RAW: Uint8Array[] = [utf8("raw-log-line-zero!"), utf8("raw-log-line-one!!")];
const EVENT_IDS = RAW.map((_, i) => `00000000-0000-4000-8000-00000000000${i}`);

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}
function runCliProcess(args: string[]): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, NO_COLOR: "1" },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? -1, stdout, stderr }));
  });
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

async function logRecord(rawLog: Uint8Array, seq: number) {
  return {
    payload_version: 1,
    spec_version: "ario.events/v1",
    event_type: "log",
    subject: { type: "producer" },
    previous_hash: "GENESIS",
    event: { content_hash: await sha256Hex(rawLog), seq },
    context: {},
    metadata: {},
    extras: {},
  };
}

// Build a 2-event bundle over the fixed RAW logs, with optional in-body content
// (genuine or tampered) per index.
async function buildContentBundle(
  inBodyContent: Record<number, Uint8Array> = {},
): Promise<Record<string, unknown>> {
  const evs = [];
  for (let i = 0; i < RAW.length; i++) {
    const { envelope, recordBytes } = await signEvent(await logRecord(RAW[i]!, i), EVENT_IDS[i]!);
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
  const txId = "tx-content-e2e-1";
  const body = {
    checkpoints: [{ tx_id: txId, envelope: cpEnv, record_bytes: bytesToHex(cpBytes), merkle_root: root }],
    events: await Promise.all(
      evs.map(async (e, i) => {
        const inBody = inBodyContent[i];
        return {
          envelope: e.envelope,
          record_bytes: bytesToHex(e.recordBytes),
          ...(inBody ? { content: bytesToHex(inBody) } : {}),
          inclusion: {
            leaf_hash: bytesToHex(e.leaf),
            leaf_index: i,
            leaf_count: leaves.length,
            audit_path: (await auditPath(i, leaves)).map(bytesToHex),
            checkpoint_tx_id: txId,
          },
        };
      }),
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

// A valid ario.agent.proof/v1 inclusion bundle (the sniff path --logs ignores).
async function buildAgentProofBundle(): Promise<Record<string, unknown>> {
  const leaves = [
    { asset_id: "a", outcome: "verified" },
    { asset_id: "b", outcome: "verified" },
  ];
  const leafHashes = await Promise.all(leaves.map((l) => leafHash(utf8(jcs(l)))));
  const root = await merkleRoot(leafHashes);
  const payload = { merkle_root: bytesToHex(root), leaf_count: leaves.length, window_start: "2026-06-22T00:00:00Z" };
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
  return {
    spec_version: "ario.agent.proof/v1",
    checkpoint_envelope: { ...pre, signature: bytesToHex(sig) },
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
    throw new Error(`dist/cli.js not found at ${CLI} — run \`npm run build\` before this test`);
  }
});
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "proof-cli-content-"));
});

describe("CLI content — in-body events[].content (no flag)", () => {
  it("exit 0 + VERIFIED + logs ✓ when in-body content is genuine", async () => {
    const bundle = await buildContentBundle({ 0: RAW[0]! });
    const p = await writeFixture("inbody-good.json", bundle);
    const r = await runCliProcess(["verify", p]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED/);
    expect(r.stdout).toMatch(/logs ✓/);
    expect(r.stdout).toMatch(/logs: 1\/1 disclosed verified/);
  });

  it("exit 1 + FAILED when in-body content is tampered", async () => {
    const bundle = await buildContentBundle({ 0: utf8("TAMPERED bytes") });
    const p = await writeFixture("inbody-bad.json", bundle);
    const r = await runCliProcess(["verify", p]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
    expect(r.stdout).toMatch(/logs ✗/);
  });
});

describe("CLI content — --logs side input", () => {
  it("exit 0 when --logs supplies matching bytes (utf8 + hex forms)", async () => {
    const bundle = await buildContentBundle();
    const p = await writeFixture("logs-good.json", bundle);
    // event 0 disclosed as utf8 text; event 1 disclosed as lowercase hex.
    const logs = {
      [EVENT_IDS[0]!]: new TextDecoder().decode(RAW[0]!),
      [EVENT_IDS[1]!]: bytesToHex(RAW[1]!),
    };
    const logsPath = await writeFixture("logs-good.logs.json", logs);
    const r = await runCliProcess(["verify", p, "--logs", logsPath]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED/);
    expect(r.stdout).toMatch(/logs: 2\/2 disclosed verified/);
  });

  it("exit 1 + FAILED when --logs supplies the wrong bytes for one event", async () => {
    const bundle = await buildContentBundle();
    const p = await writeFixture("logs-bad.json", bundle);
    const logs = { [EVENT_IDS[0]!]: "these are not the committed bytes" };
    const logsPath = await writeFixture("logs-bad.logs.json", logs);
    const r = await runCliProcess(["verify", p, "--logs", logsPath]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
    expect(r.stdout).toMatch(/logs ✗/);
  });

  it("mixed: one event matches, one mismatches ⇒ exit 1 + 'logs: 1/2 disclosed verified'", async () => {
    const bundle = await buildContentBundle();
    const p = await writeFixture("logs-mixed.json", bundle);
    const logs = {
      [EVENT_IDS[0]!]: bytesToHex(RAW[0]!), // correct
      [EVENT_IDS[1]!]: "totally wrong bytes here", // mismatch
    };
    const logsPath = await writeFixture("logs-mixed.logs.json", logs);
    const r = await runCliProcess(["verify", p, "--logs", logsPath]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
    expect(r.stdout).toMatch(/logs: 1\/2 disclosed verified/);
  });

  it("exit 2 when --logs points at a missing file", async () => {
    const bundle = await buildContentBundle();
    const p = await writeFixture("logs-missing.json", bundle);
    const r = await runCliProcess(["verify", p, "--logs", join(dir, "nope.json")]);
    expect(r.code).toBe(2);
  });

  it("usage mentions --logs", async () => {
    const r = await runCliProcess(["help"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/--logs/);
  });

  it("--logs on an ario.agent.proof/v1 bundle is ignored with a note (still verifies)", async () => {
    const p = await writeFixture("agent-proof.json", await buildAgentProofBundle());
    const logsPath = await writeFixture("ignored.logs.json", { whatever: "abcd" });
    const r = await runCliProcess(["verify", p, "--logs", logsPath]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/Agent inclusion proof/);
    expect(r.stderr).toMatch(/--logs has no effect/);
  });
});
