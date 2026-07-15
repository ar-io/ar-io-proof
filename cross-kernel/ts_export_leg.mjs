// TS leg of the ario.evidence.export/v1 cross-kernel agreement gate: re-verify
// every export case through the TypeScript kernel (ts/dist) and compare its
// verdict to the Python reference recorded in export-cases.json. Exits non-zero
// on any disagreement.
//
// The comparison is the full normalized verdict record — top-level wrapper
// flags, the pinned CLI exit code (0/1/2/3), the export dimensions, each
// embedded attestation's per-check booleans, AND verdict_jcs_sha256 =
// SHA-256(JCS(recomputed §4 verdict object)). Reproducing that hash is the
// byte-identical-verdict gate: the two kernels emit the SAME §4 verdict bytes.
//
//   node ts_export_leg.mjs export-cases.json
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const evidenceUrl = new URL("../ts/dist/evidence.js", import.meta.url);
const cryptoUrl = new URL("../ts/dist/crypto.js", import.meta.url);
const verifierUrl = new URL("../ts/dist/verifier.js", import.meta.url);
const { verifyEvidenceBundle } = await import(fileURLToPath(evidenceUrl));
const { utf8 } = await import(fileURLToPath(cryptoUrl));
const { jcs } = await import(fileURLToPath(verifierUrl));

const casesPath = process.argv[2] ?? "export-cases.json";
const cases = JSON.parse(readFileSync(casesPath, "utf8"));

// The pinned exit-code mapping — identical to the TS CLI's mapStatusToExit and
// the Python kernel's EvidenceBundleResult.exit_code(). Kept in lockstep here so
// the gate compares the exit both kernels would return.
function mapStatusToExit(status, errors) {
  if (status === "failed") return 1;
  if (status === "malformed") return 2;
  if (
    status === "partial" &&
    errors.some((e) => /unreachable|could not be re-fetched|unavailable offline/.test(e))
  ) {
    return 3;
  }
  return 0;
}

function record(result) {
  const rec = {
    status: result.status,
    exit: mapStatusToExit(result.status, result.errors),
    spec_version_ok: result.specVersionOk,
    signature_ok: result.signatureOk,
    body_hash_ok: result.bodyHashOk,
    body_type: result.bodyType,
    export: null,
  };
  if (result.export) {
    const e = result.export;
    rec.export = {
      source_linkage_ok: e.sourceLinkageOk,
      source_status: e.sourceStatus,
      verdict_agreement_ok: e.verdictAgreementOk,
      status: e.status,
      attestations: e.attestations.map((a) => ({
        signature_ok: a.signatureOk,
        operator_address_bound: a.operatorAddressBound,
        data_hash_bound: a.dataHashBound,
        checkpoint_resolved: a.checkpointResolved,
        subject_ref_ok: a.subjectRefOk,
        ok: a.ok,
      })),
      verdict_jcs_sha256: createHash("sha256").update(utf8(jcs(e.verdict))).digest("hex"),
    };
  }
  return rec;
}

let mismatches = 0;
for (const c of cases) {
  const result = await verifyEvidenceBundle(c.bundle);
  const ts = record(result);
  // Deep, order-independent comparison via sorted-key JSON (the records are
  // flat/nested plain objects + arrays — jcs gives a canonical string).
  if (jcs(ts) !== jcs(c.py)) {
    console.error(`MISMATCH ${c.id}:`);
    console.error(`  ts = ${JSON.stringify(ts)}`);
    console.error(`  py = ${JSON.stringify(c.py)}`);
    mismatches++;
  }
}

if (mismatches > 0) {
  console.error(`TS vs Python (export): ${mismatches} mismatch(es) over ${cases.length} cases`);
  process.exit(1);
}
console.log(
  `TS vs Python (export): ALL MATCH (${cases.length} cases; verdict JCS byte-identical)`,
);
