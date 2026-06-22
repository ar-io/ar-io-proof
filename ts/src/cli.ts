#!/usr/bin/env node
// npx @ar.io/proof verify <bundle.json> [comma,sep,gateways]
//
// One turnkey verifier for both producer bundles in the stack:
//   - ario.evidence/v1 (body ario.anchor.trace/v1)  — the @ar.io/anchor SDK trace
//   - ario.agent.proof/v1                            — the agent inclusion proof
// Dispatch is by sniffed spec_version; no flag tells the CLI which it is.
//
// Pinned exit codes (mirror `ariod verify-status`):
//   0  verified
//   1  a real verification failure (bad signature / tamper / broken inclusion)
//   2  malformed bundle (unparseable, unknown spec major, body_hash mismatch)
//   3  gateway-unavailable when an on-chain re-fetch was requested
// `payloadHashOk === null` (a withheld record) is semantics-undetermined and
// surfaces as a per-event note — it does NOT fail the run.

import { readFile } from "node:fs/promises";

import { isAgentProofSpec, verifyAgentProofBundle } from "./agent-proof.js";
import type { AgentProofResult } from "./agent-proof.js";
import { verifyEvidenceBundle } from "./evidence.js";
import type { EvidenceBundleResult } from "./evidence.js";

const EXIT_VERIFIED = 0;
const EXIT_FAILED = 1;
const EXIT_MALFORMED = 2;
const EXIT_GATEWAY_UNAVAILABLE = 3;

interface Cli {
  out: (s: string) => void;
  err: (s: string) => void;
  fetchImpl?: typeof fetch;
}

const G = "\x1b[32m";
const R = "\x1b[31m";
const Y = "\x1b[33m";
const DIM = "\x1b[2m";
const B = "\x1b[1m";
const X = "\x1b[0m";

function useColor(): boolean {
  // Honor NO_COLOR; otherwise color only a TTY.
  if (process.env.NO_COLOR) return false;
  return Boolean(process.stdout.isTTY);
}

function mark(ok: boolean | null): string {
  const c = useColor();
  if (ok === null) return c ? `${Y}~${X}` : "~";
  if (ok) return c ? `${G}✓${X}` : "✓";
  return c ? `${R}✗${X}` : "✗";
}

function paint(s: string, c: string): string {
  return useColor() ? `${c}${s}${X}` : s;
}

export async function runCli(argv: string[], io: Cli): Promise<number> {
  const [command, ...rest] = argv;

  if (command === undefined || command === "help" || command === "--help" || command === "-h") {
    printUsage(io);
    return command === undefined ? EXIT_MALFORMED : EXIT_VERIFIED;
  }
  if (command === "version" || command === "--version" || command === "-v") {
    io.out("@ar.io/proof verify CLI");
    return EXIT_VERIFIED;
  }
  if (command !== "verify") {
    io.err(`unknown command: ${command}`);
    printUsage(io);
    return EXIT_MALFORMED;
  }

  const [bundlePath, gatewayArg] = rest;
  if (!bundlePath) {
    io.err("verify: a bundle file path is required");
    printUsage(io);
    return EXIT_MALFORMED;
  }
  const gateways = (gatewayArg ?? "")
    .split(",")
    .map((g) => g.trim())
    .filter((g) => g.length > 0);

  let raw: string;
  try {
    raw = await readFile(bundlePath, "utf8");
  } catch (e) {
    io.err(`cannot read ${bundlePath}: ${e instanceof Error ? e.message : String(e)}`);
    return EXIT_MALFORMED;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    io.err(`${bundlePath} is not valid JSON: ${e instanceof Error ? e.message : String(e)}`);
    return EXIT_MALFORMED;
  }

  const specVersion =
    parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as { spec_version?: unknown }).spec_version
      : undefined;

  if (isAgentProofSpec(specVersion)) {
    const result = await verifyAgentProofBundle(parsed, {
      gateways,
      ...(io.fetchImpl ? { fetchImpl: io.fetchImpl } : {}),
    });
    return reportAgentProof(result, bundlePath, gateways, io);
  }

  // Default: treat anything else as an evidence bundle. verifyEvidenceBundle
  // rejects an unknown major as "malformed" so a genuinely unknown shape still
  // exits 2 with a clear message.
  const result = await verifyEvidenceBundle(parsed, {
    gateways,
    ...(io.fetchImpl ? { fetchImpl: io.fetchImpl } : {}),
  });
  return reportEvidence(result, bundlePath, gateways, io);
}

function printUsage(io: Cli): void {
  io.out("Usage: npx @ar.io/proof verify <bundle.json> [gateway1,gateway2,...]");
  io.out("");
  io.out("Verify an ario.evidence/v1 (ario.anchor.trace/v1) bundle or an");
  io.out("ario.agent.proof/v1 inclusion bundle, fully offline. Supply a");
  io.out("comma-separated gateway list to also re-fetch each checkpoint on-chain.");
  io.out("");
  io.out("Exit codes: 0 verified · 1 failed · 2 malformed · 3 gateway-unavailable");
}

function reportEvidence(
  result: EvidenceBundleResult,
  path: string,
  gateways: string[],
  io: Cli,
): number {
  if (result.status === "malformed") {
    io.err(paint("MALFORMED", R) + `  ${path}`);
    for (const e of result.errors) io.err(`  - ${e}`);
    return EXIT_MALFORMED;
  }

  io.out(paint("Evidence bundle", B) + `  ${path}`);
  io.out(`  body_type     ${result.bodyType ?? "<unknown>"}`);
  io.out(
    `  wrapper       sig ${mark(result.signatureOk)}  body_hash ${mark(result.bodyHashOk)}  spec ${mark(result.specVersionOk)}`,
  );

  if (result.checkpoints.length > 0) {
    io.out("");
    io.out(paint("  Checkpoints", DIM));
    for (const cp of result.checkpoints) {
      const onChain = cp.onChainOk === null ? "" : `  on-chain ${mark(cp.onChainOk)}`;
      io.out(
        `    ${mark(cp.ok)} ${shortTx(cp.txId)}  envelope ${mark(cp.envelopeOk)}  root ${mark(cp.merkleRootOk)}${onChain}`,
      );
      for (const e of cp.errors) io.out(paint(`        - ${e}`, R));
    }
  }

  if (result.events.length > 0) {
    io.out("");
    io.out(paint("  Events", DIM));
    for (const ev of result.events) {
      const binding =
        ev.payloadBindingOk === null
          ? paint("~ record withheld", Y)
          : `record ${mark(ev.payloadBindingOk)}`;
      io.out(
        `    ${mark(ev.ok)} ${shortId(ev.eventId)}  sig ${mark(ev.envelopeOk)}  ${binding}  inclusion ${mark(ev.inclusionOk)}`,
      );
      for (const e of ev.errors) io.out(paint(`        - ${e}`, R));
    }
  }

  io.out("");
  printRollup(result.status, result.assertedStatus, gateways, result.onChainChecked, io);
  for (const e of result.errors) io.out(paint(`  note: ${e}`, DIM));

  return mapStatusToExit(result.status, result.errors);
}

function reportAgentProof(
  result: AgentProofResult,
  path: string,
  gateways: string[],
  io: Cli,
): number {
  if (result.status === "malformed") {
    io.err(paint("MALFORMED", R) + `  ${path}`);
    for (const e of result.errors) io.err(`  - ${e}`);
    return EXIT_MALFORMED;
  }

  io.out(paint("Agent inclusion proof", B) + `  ${path}`);
  io.out(`  spec_version  ario.agent.proof/v1`);
  io.out(`  checkpoint    ${shortTx(result.checkpointTxId ?? "")}  envelope ${mark(result.checkpointOk)}`);
  const onChain = result.onChainOk === null ? "" : `  on-chain ${mark(result.onChainOk)}`;
  io.out(
    `  leaf          index ${result.leafIndex} / ${result.leafCount ?? "?"}  inclusion ${mark(result.inclusionOk)}${onChain}`,
  );
  io.out("");
  printRollup(result.status, null, gateways, result.onChainChecked, io);
  for (const e of result.errors) io.out(paint(`  note: ${e}`, DIM));

  return mapStatusToExit(result.status, result.errors);
}

function printRollup(
  status: string,
  asserted: string | null,
  gateways: string[],
  onChainChecked: boolean,
  io: Cli,
): void {
  const scope = onChainChecked
    ? `verified offline + on-chain against ${gateways.length} gateway(s)`
    : "verified offline (no gateway re-fetch requested)";
  let head: string;
  switch (status) {
    case "verified":
      head = paint("VERIFIED", G);
      break;
    case "partial":
      head = paint("PARTIAL", Y);
      break;
    case "failed":
      head = paint("FAILED", R);
      break;
    default:
      head = paint(status.toUpperCase(), R);
  }
  io.out(`${head}  ${paint(scope, DIM)}`);
  if (asserted && asserted !== status) {
    io.out(
      paint(
        `  (producer asserted "${asserted}"; recomputed verdict is "${status}" — recomputed wins)`,
        DIM,
      ),
    );
  }
}

function mapStatusToExit(status: string, errors: string[]): number {
  if (status === "failed") return EXIT_FAILED;
  if (status === "malformed") return EXIT_MALFORMED;
  // "partial" caused specifically by an unreachable gateway maps to exit 3.
  if (status === "partial" && errors.some((e) => /unreachable|could not be re-fetched/.test(e))) {
    return EXIT_GATEWAY_UNAVAILABLE;
  }
  // "verified" → 0. "partial" from a withheld record (semantics-undetermined,
  // not a failure) also exits 0 — the bundle is cryptographically sound.
  return EXIT_VERIFIED;
}

function shortTx(tx: string): string {
  if (tx.length <= 16) return tx;
  return `${tx.slice(0, 8)}…${tx.slice(-4)}`;
}

function shortId(id: string): string {
  if (id.length <= 12) return id;
  return `${id.slice(0, 8)}…`;
}

// Entry point when run as a binary (not when imported by tests).
const isMain = (() => {
  try {
    const invoked = process.argv[1] ? new URL(`file://${process.argv[1]}`).href : "";
    return import.meta.url === invoked || (process.argv[1]?.endsWith("cli.js") ?? false);
  } catch {
    return false;
  }
})();

if (isMain) {
  runCli(process.argv.slice(2), {
    out: (s) => process.stdout.write(s + "\n"),
    err: (s) => process.stderr.write(s + "\n"),
  })
    .then((code) => {
      process.exitCode = code;
    })
    .catch((e) => {
      process.stderr.write(`fatal: ${e instanceof Error ? e.stack ?? e.message : String(e)}\n`);
      process.exitCode = EXIT_MALFORMED;
    });
}
