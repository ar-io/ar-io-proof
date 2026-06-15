// TS leg of the cross-kernel agreement gate: re-verify every case through the
// TypeScript kernel (ts/dist) and compare its verdict to the Python reference
// recorded in cases.json. Exits non-zero on any disagreement.
//
//   node ts_leg.mjs cases.json
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const verifierUrl = new URL("../ts/dist/verifier.js", import.meta.url);
const { verifyEnvelope } = await import(fileURLToPath(verifierUrl));

const casesPath = process.argv[2] ?? "cases.json";
const cases = JSON.parse(readFileSync(casesPath, "utf8"));

let mismatches = 0;
for (const c of cases) {
  let ts;
  if (c.envelope_bytes_hex !== undefined) {
    // Negative: verify the raw bytes; a parse failure mirrors Python's
    // exception fallback (all-false). The verdict must be ok:false either way.
    try {
      const env = JSON.parse(Buffer.from(c.envelope_bytes_hex, "hex").toString("utf8"));
      const r = await verifyEnvelope(env);
      ts = { ok: r.ok, phk: r.payloadHashOk, sig: r.signatureOk, spec: r.specVersionOk };
    } catch {
      ts = { ok: false, phk: false, sig: false, spec: false };
    }
  } else {
    const opts = {};
    if (c.payload_b64 !== null) opts.payloadBytes = Uint8Array.from(Buffer.from(c.payload_b64, "base64"));
    const r = await verifyEnvelope(c.envelope, opts);
    ts = { ok: r.ok, phk: r.payloadHashOk, sig: r.signatureOk, spec: r.specVersionOk };
  }
  // Full tri-state comparison — TS exposes payloadHashOk, so it must match
  // Python's None/true/false exactly, not just the boolean verdict.
  if (JSON.stringify(ts) !== JSON.stringify(c.py)) {
    console.error(`MISMATCH ${c.id}: ts=${JSON.stringify(ts)} py=${JSON.stringify(c.py)}`);
    mismatches++;
  }
}

if (mismatches > 0) {
  console.error(`TS vs Python: ${mismatches} mismatch(es) over ${cases.length} cases`);
  process.exit(1);
}
console.log(`TS vs Python: ALL MATCH (${cases.length} cases, full tri-state)`);
