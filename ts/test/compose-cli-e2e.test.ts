// `proof export` CLI end-to-end — spawn the BUILT dist/cli.js and drive the full
// demo shell flow a consumer runs:
//
//   proof export <source> --attestations <f> --key <f> -o <out>   # produce
//   proof verify <out>                                            # → exit 0
//   (tamper <out>) ; proof verify <tampered>                      # → exit 1
//
// This is the process-boundary contract (real argv parse, file read/write, JSON
// parse, exporter-key load, exit-code plumbing) the in-process compose test can't
// reach. Requires `npm run build` first; self-skips loudly if dist is missing.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "..", "dist", "cli.js");
const GOLDEN = join(HERE, "fixtures", "evidence-export-bundle.golden.json");

// A well-known exporter seed (32-byte hex) — distinct from the source producer's.
const EXPORTER_SEED = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

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

let dir: string;
async function write(name: string, s: string): Promise<string> {
  const p = join(dir, name);
  await writeFile(p, s, "utf8");
  return p;
}
function flip(hex: string): string {
  return hex.slice(0, -1) + (hex.endsWith("0") ? "1" : "0");
}

// Split the golden into the composer's raw inputs: the inline source bundle and
// its attestation records (what a real composer is handed).
async function inputs(): Promise<{ sourcePath: string; attsPath: string; keyPath: string }> {
  const g = JSON.parse(await readFile(GOLDEN, "utf8")) as {
    export: { body: { source_bundle: unknown; attestations: unknown } };
  };
  const sourcePath = await write("source.json", JSON.stringify(g.export.body.source_bundle));
  const attsPath = await write("attestations.json", JSON.stringify(g.export.body.attestations));
  const keyPath = await write("exporter.key", EXPORTER_SEED);
  return { sourcePath, attsPath, keyPath };
}

beforeAll(() => {
  if (!existsSync(CLI)) {
    throw new Error(`dist/cli.js not found at ${CLI} — run \`npm run build\` before the compose CLI e2e test`);
  }
});
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "proof-export-e2e-"));
});

describe("proof export CLI — produce → verify → tamper (the demo, over the process boundary)", () => {
  it("export writes a file, verify → exit 0 + VERIFIED, tamper → exit 1 + FAILED", async () => {
    const { sourcePath, attsPath, keyPath } = await inputs();
    const outPath = join(dir, "export.json");

    // 1) produce
    const exp = await runCliProcess([
      "export",
      sourcePath,
      "--attestations",
      attsPath,
      "--key",
      keyPath,
      "-o",
      outPath,
    ]);
    expect(exp.code).toBe(0);
    expect(exp.stdout).toMatch(/exported/);
    expect(exp.stdout).toMatch(/2\/2 bound/);
    expect(existsSync(outPath)).toBe(true);

    // 2) verify the produced file → exit 0
    const ver = await runCliProcess(["verify", outPath]);
    expect(ver.code).toBe(0);
    expect(ver.stdout).toMatch(/VERIFIED/);
    expect(ver.stdout).toMatch(/Attested export/);

    // 3) tamper a byte of the produced export → verify → exit 1
    const produced = JSON.parse(await readFile(outPath, "utf8")) as {
      body: { attestations: { signature: string }[] };
    };
    produced.body.attestations[0]!.signature = flip(produced.body.attestations[0]!.signature);
    const tamperedPath = await write("tampered.json", JSON.stringify(produced, null, 2));
    const bad = await runCliProcess(["verify", tamperedPath]);
    expect(bad.code).toBe(1);
    expect(bad.stdout).toMatch(/FAILED/);
  });

  it("export to stdout (no -o) emits JSON that verify accepts via a pipe-to-file", async () => {
    const { sourcePath, attsPath, keyPath } = await inputs();
    const exp = await runCliProcess(["export", sourcePath, "--attestations", attsPath, "--key", keyPath]);
    expect(exp.code).toBe(0);
    const bundle = JSON.parse(exp.stdout);
    expect(bundle.body_type).toBe("ario.evidence.export/v1");
    const p = await write("piped.json", JSON.stringify(bundle));
    const ver = await runCliProcess(["verify", p]);
    expect(ver.code).toBe(0);
    expect(ver.stdout).toMatch(/VERIFIED/);
  });

  it("accepts a JSON exporter key file ({privateKey: <hex>})", async () => {
    const { sourcePath, attsPath } = await inputs();
    const keyPath = await write("exporter.json", JSON.stringify({ privateKey: EXPORTER_SEED }));
    const outPath = join(dir, "export2.json");
    const exp = await runCliProcess([
      "export",
      sourcePath,
      "--attestations",
      attsPath,
      "--key",
      keyPath,
      "-o",
      outPath,
    ]);
    expect(exp.code).toBe(0);
    const ver = await runCliProcess(["verify", outPath]);
    expect(ver.code).toBe(0);
  });

  it("exit 2 on a bad exporter key (not a 32-byte hex seed)", async () => {
    const { sourcePath, attsPath } = await inputs();
    const keyPath = await write("bad.key", "not-a-valid-seed");
    const r = await runCliProcess(["export", sourcePath, "--attestations", attsPath, "--key", keyPath]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/seed/i);
  });

  it("exit 2 when --attestations is missing", async () => {
    const { sourcePath, keyPath } = await inputs();
    const r = await runCliProcess(["export", sourcePath, "--key", keyPath]);
    expect(r.code).toBe(2);
    expect(r.stderr + r.stdout).toMatch(/attestations/i);
  });
});
