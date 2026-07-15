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

import { readFile, writeFile } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { isAgentProofSpec, verifyAgentProofBundle } from "./agent-proof.js";
import type { AgentProofResult } from "./agent-proof.js";
import { composeExport } from "./compose.js";
import type { ComposeExportOptions } from "./compose.js";
import { utf8 } from "./crypto.js";
import { verifyEvidenceBundle } from "./evidence.js";
import type { AttestationRecord, EvidenceBundle, EvidenceBundleResult, ExportResult } from "./evidence.js";

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
  if (command === "export") {
    return runExport(rest, io);
  }
  if (command !== "verify") {
    io.err(`unknown command: ${command}`);
    printUsage(io);
    return EXIT_MALFORMED;
  }

  // Pull the optional `--logs <file>` flag out of the args; the rest are
  // positional (<bundle> [gateways]). --logs feeds disclosed raw-log bytes for
  // content verification (the evidence-bundle path only).
  let logsPath: string | undefined;
  const positional: string[] = [];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a === "--logs") {
      const next = rest[i + 1];
      if (next === undefined) {
        io.err("verify: --logs requires a file path");
        printUsage(io);
        return EXIT_MALFORMED;
      }
      logsPath = next;
      i++;
      continue;
    }
    positional.push(a);
  }

  const [bundlePath, gatewayArg] = positional;
  if (!bundlePath) {
    io.err("verify: a bundle file path is required");
    printUsage(io);
    return EXIT_MALFORMED;
  }
  const gateways = (gatewayArg ?? "")
    .split(",")
    .map((g) => g.trim())
    .filter((g) => g.length > 0);

  let content: Record<string, Uint8Array | string> | undefined;
  if (logsPath !== undefined) {
    let logsRaw: string;
    try {
      logsRaw = await readFile(logsPath, "utf8");
    } catch (e) {
      io.err(`cannot read --logs ${logsPath}: ${e instanceof Error ? e.message : String(e)}`);
      return EXIT_MALFORMED;
    }
    let logsParsed: unknown;
    try {
      logsParsed = JSON.parse(logsRaw);
    } catch (e) {
      io.err(`--logs ${logsPath} is not valid JSON: ${e instanceof Error ? e.message : String(e)}`);
      return EXIT_MALFORMED;
    }
    if (logsParsed === null || typeof logsParsed !== "object" || Array.isArray(logsParsed)) {
      io.err(`--logs ${logsPath} must be a JSON object mapping event_id → disclosed bytes`);
      return EXIT_MALFORMED;
    }
    content = {};
    for (const [k, v] of Object.entries(logsParsed as Record<string, unknown>)) {
      if (typeof v === "string") content[k] = decodeLogValue(v);
    }
  }

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
    if (content) {
      // --logs binds raw logs to anchor-trace events; an agent inclusion proof
      // has no such per-event content. Say so rather than silently ignoring it.
      io.err("note: --logs has no effect on an ario.agent.proof/v1 bundle (ignored)");
    }
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
    ...(content ? { content } : {}),
    ...(io.fetchImpl ? { fetchImpl: io.fetchImpl } : {}),
  });
  return reportEvidence(result, bundlePath, gateways, io);
}

// `proof export <source-bundle.json> --attestations <f> --key <f> [-o <out>]`
//
// Compose a signed, offline-verifiable ario.evidence.export/v1 artifact from a
// source ario.anchor.trace/v1 bundle + operator attestation records + an exporter
// Ed25519 key (evidence-export.md §5, composer). Writes the export to `-o <out>`
// (or stdout when omitted, so it can be piped straight into `proof verify`).
//
// Exit codes: 0 composed OK · 1 the recomputed export is FAILED (a bad source or
// forged/mis-bound attestation — the composer refuses to emit a green artifact
// over failing evidence) · 2 usage / malformed input (missing flag, unreadable
// or non-JSON input, bad exporter key, malformed attestation record).
async function runExport(rest: string[], io: Cli): Promise<number> {
  let attestationsPath: string | undefined;
  let keyPath: string | undefined;
  let outPath: string | undefined;
  const opts: ComposeExportOptions = {};
  const positional: string[] = [];

  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    const takeNext = (flag: string): string | undefined => {
      const next = rest[i + 1];
      if (next === undefined) {
        io.err(`export: ${flag} requires a value`);
        return undefined;
      }
      i++;
      return next;
    };
    if (a === "--attestations" || a === "-a") {
      const v = takeNext(a);
      if (v === undefined) return usageExport(io);
      attestationsPath = v;
    } else if (a === "--key" || a === "-k") {
      const v = takeNext(a);
      if (v === undefined) return usageExport(io);
      keyPath = v;
    } else if (a === "--out" || a === "-o") {
      const v = takeNext(a);
      if (v === undefined) return usageExport(io);
      outPath = v;
    } else if (a === "--issuer-id") {
      const v = takeNext(a);
      if (v === undefined) return usageExport(io);
      opts.issuerId = v;
    } else if (a === "--gateway") {
      const v = takeNext(a);
      if (v === undefined) return usageExport(io);
      opts.gateway = v;
    } else if (a === "--previous-hash") {
      const v = takeNext(a);
      if (v === undefined) return usageExport(io);
      opts.previousHash = v;
    } else if (a === "--generated-at") {
      const v = takeNext(a);
      if (v === undefined) return usageExport(io);
      opts.generatedAt = v;
    } else {
      positional.push(a);
    }
  }

  const [bundlePath] = positional;
  if (!bundlePath) {
    io.err("export: a source bundle file path is required");
    return usageExport(io);
  }
  if (!attestationsPath) {
    io.err("export: --attestations <file> is required");
    return usageExport(io);
  }
  if (!keyPath) {
    io.err("export: --key <file> is required");
    return usageExport(io);
  }

  const sourceBundle = await readJson<EvidenceBundle>(bundlePath, io);
  if (sourceBundle === undefined) return EXIT_MALFORMED;
  const attestationsRaw = await readJson<unknown>(attestationsPath, io);
  if (attestationsRaw === undefined) return EXIT_MALFORMED;
  const attestations = coerceAttestations(attestationsRaw);
  if (attestations === undefined) {
    io.err(`export: ${attestationsPath} must be a JSON array of attestation records ` +
      `(or an object with an "attestations" array)`);
    return EXIT_MALFORMED;
  }

  const privateKey = await readExporterKey(keyPath, io);
  if (privateKey === undefined) return EXIT_MALFORMED;

  let composed;
  try {
    composed = await composeExport(sourceBundle, attestations, { privateKey }, opts);
  } catch (e) {
    io.err(`export: cannot compose — ${e instanceof Error ? e.message : String(e)}`);
    return EXIT_MALFORMED;
  }

  // The composer refuses to hand back a green artifact over failing evidence: a
  // FAILED recompute (bad source / forged / mis-bound attestation) exits 1 and
  // still writes the artifact so the caller can inspect it.
  const serialized = JSON.stringify(composed.bundle, null, 2) + "\n";
  if (outPath) {
    try {
      await writeFile(outPath, serialized, "utf8");
    } catch (e) {
      io.err(`export: cannot write ${outPath}: ${e instanceof Error ? e.message : String(e)}`);
      return EXIT_MALFORMED;
    }
    io.out(
      `${paint("exported", composed.status === "failed" ? R : G)} ${outPath}  ` +
        `status ${composed.status}  ` +
        `attestations ${composed.boundAttestations}/${attestations.length} bound`,
    );
  } else {
    io.out(serialized.replace(/\n$/, ""));
  }
  return composed.status === "failed" ? EXIT_FAILED : EXIT_VERIFIED;
}

function usageExport(io: Cli): number {
  io.out(
    "Usage: npx @ar.io/proof export <source-bundle.json> --attestations <file> --key <file> [-o <out.json>]",
  );
  io.out("");
  io.out("Compose a signed, offline-verifiable ario.evidence.export/v1 artifact from an");
  io.out("ario.anchor.trace/v1 source bundle + operator attestation records + an exporter");
  io.out("Ed25519 key. The output verifies with `proof verify <out.json>`.");
  io.out("");
  io.out("--attestations <file>  JSON array of attestation records (or {attestations:[...]}).");
  io.out("--key <file>           Exporter Ed25519 key: a 32-byte hex seed, or JSON");
  io.out('                       {"privateKey":"<hex>"} / {"seed":"<hex>"}.');
  io.out("-o, --out <file>       Write the export here (default: stdout).");
  io.out("--issuer-id <id>       Wrapper issuer.issuer_id (default ar-io-verify).");
  io.out("--gateway <url>        Named delivery surface (not trusted).");
  io.out("--previous-hash <h>    Custody pointer (default GENESIS).");
  io.out("--generated-at <ts>    RFC 3339 compose time (default now).");
  return EXIT_MALFORMED;
}

// Read + parse a JSON file; report a clear error and return undefined on any
// failure (mirrors the verify path's read/parse error handling → exit 2).
async function readJson<T>(path: string, io: Cli): Promise<T | undefined> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (e) {
    io.err(`cannot read ${path}: ${e instanceof Error ? e.message : String(e)}`);
    return undefined;
  }
  try {
    return JSON.parse(raw) as T;
  } catch (e) {
    io.err(`${path} is not valid JSON: ${e instanceof Error ? e.message : String(e)}`);
    return undefined;
  }
}

// Accept either a bare array of attestation records or an object wrapping one
// under `attestations`. Returns undefined for anything else.
function coerceAttestations(raw: unknown): AttestationRecord[] | undefined {
  if (Array.isArray(raw)) return raw as AttestationRecord[];
  if (raw !== null && typeof raw === "object") {
    const inner = (raw as { attestations?: unknown }).attestations;
    if (Array.isArray(inner)) return inner as AttestationRecord[];
  }
  return undefined;
}

// Read the exporter Ed25519 key: a file that is either a bare 32-byte hex seed
// (whitespace-trimmed) or a JSON object carrying it under `privateKey` / `seed` /
// `private_key`. Validates the 64-hex-char (32-byte) shape.
async function readExporterKey(path: string, io: Cli): Promise<string | undefined> {
  let raw: string;
  try {
    raw = (await readFile(path, "utf8")).trim();
  } catch (e) {
    io.err(`export: cannot read --key ${path}: ${e instanceof Error ? e.message : String(e)}`);
    return undefined;
  }
  let seed = raw;
  if (raw.startsWith("{")) {
    try {
      const obj = JSON.parse(raw) as Record<string, unknown>;
      const found = obj.privateKey ?? obj.seed ?? obj.private_key;
      if (typeof found !== "string") {
        io.err(`export: --key ${path} JSON needs a string "privateKey"/"seed" field`);
        return undefined;
      }
      seed = found.trim();
    } catch (e) {
      io.err(`export: --key ${path} is not valid JSON: ${e instanceof Error ? e.message : String(e)}`);
      return undefined;
    }
  }
  if (!/^[0-9a-fA-F]{64}$/.test(seed)) {
    io.err(`export: --key must be a 32-byte (64 hex char) Ed25519 seed`);
    return undefined;
  }
  return seed.toLowerCase();
}

// The --logs side-input lane decides each disclosed value's encoding: a clean,
// even-length, lowercase-hex string is hex bytes; anything else is utf8 text.
// (The verifier itself only distinguishes "string ⇒ hex" from "Uint8Array ⇒
// raw bytes" — the human-facing encoding choice is made here.)
function decodeLogValue(v: string): Uint8Array | string {
  if (v.length > 0 && v.length % 2 === 0 && /^[0-9a-f]+$/.test(v)) return v; // hex passthrough
  return utf8(v); // raw utf8 bytes
}

function printUsage(io: Cli): void {
  io.out("Usage: npx @ar.io/proof <command> [args]");
  io.out("");
  io.out("Commands:");
  io.out("  verify <bundle.json> [gateways] [--logs <logs.json>]   Verify a bundle/export");
  io.out("  export <source.json> --attestations <f> --key <f> [-o] Compose an attested export");
  io.out("");
  io.out("Verify an ario.evidence/v1 (ario.anchor.trace/v1) bundle, an");
  io.out("ario.evidence.export/v1 attested export, or an ario.agent.proof/v1");
  io.out("inclusion bundle, fully offline. Supply a comma-separated gateway list");
  io.out("to also re-fetch each checkpoint on-chain.");
  io.out("");
  io.out("--logs <logs.json>  Bind disclosed raw logs to each event's committed");
  io.out("                    content_hash. JSON object mapping event_id → bytes");
  io.out("                    (even-length lowercase hex ⇒ hex, else utf8 text).");
  io.out("                    In-body events[].content is verified automatically.");
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
      // Show the content (logs) segment only when content was disclosed and
      // evaluated (non-null) — undisclosed content is the default and would just
      // be noise on every line.
      const logs = ev.contentOk === null ? "" : `  logs ${mark(ev.contentOk)}`;
      io.out(
        `    ${mark(ev.ok)} ${shortId(ev.eventId)}  sig ${mark(ev.envelopeOk)}  ${binding}  inclusion ${mark(ev.inclusionOk)}${logs}`,
      );
      for (const e of ev.errors) io.out(paint(`        - ${e}`, R));
    }
  }

  if (result.export) {
    reportExport(result.export, io);
  }

  io.out("");
  printRollup(result.status, result.assertedStatus, gateways, result.onChainChecked, io);
  for (const e of result.errors) io.out(paint(`  note: ${e}`, DIM));

  const disclosed = result.events.filter((e) => e.contentOk !== null);
  if (disclosed.length > 0) {
    const verified = disclosed.filter((e) => e.contentOk === true).length;
    io.out(paint(`  logs: ${verified}/${disclosed.length} disclosed verified`, DIM));
  }

  return mapStatusToExit(result.status, result.errors);
}

// Render the export-specific block (evidence-export.md §5): source-bundle
// linkage, cached-vs-recomputed verdict agreement, and each embedded operator
// attestation (RSA-PSS sig · operator-address binding · data_hash binding).
function reportExport(exp: ExportResult, io: Cli): void {
  io.out("");
  io.out(paint("  Attested export", DIM));
  io.out(
    `    source linkage ${mark(exp.sourceLinkageOk)}  verdict agreement ${mark(exp.verdictAgreementOk)}`,
  );
  if (exp.attestations.length > 0) {
    io.out(paint("    Operator attestations", DIM));
    for (const a of exp.attestations) {
      const subj = a.subjectRefOk === null ? "" : `  subject ${mark(a.subjectRefOk)}`;
      io.out(
        `      ${mark(a.ok)} ${shortId(a.operator)}  sig ${mark(a.signatureOk)}` +
          `  operator ${mark(a.operatorAddressBound)}  data_hash ${mark(a.dataHashBound)}${subj}`,
      );
      for (const e of a.errors) io.out(paint(`          - ${e}`, R));
    }
  }
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
  // "partial" caused specifically by an unreachable gateway — or an export
  // source_bundle_ref whose bytes are unavailable offline (evidence-export.md
  // §5 step 3) — maps to exit 3 (undetermined, network-dependent).
  if (
    status === "partial" &&
    errors.some((e) => /unreachable|could not be re-fetched|unavailable offline/.test(e))
  ) {
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
    if (!process.argv[1]) return false;
    // realpath BOTH sides: when run via a bin symlink (npx / node_modules/.bin/proof
    // -> dist/cli.js), process.argv[1] is the symlink and import.meta.url is the target,
    // so a naive compare skips main(). Resolving both to the real path makes them match.
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
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
