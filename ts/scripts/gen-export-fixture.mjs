#!/usr/bin/env node
// Generate the frozen attested-evidence-export golden fixture consumed by
// test/evidence-export.test.ts. Committed output is
// test/fixtures/evidence-export-bundle.golden.json.
//
// This is the positive vector for kernel slice 2 (verifyExportBody,
// evidence-export.md §5): ONE real inline `ario.evidence.export/v1` export —
//   - a real Ed25519-signed WRAPPER (the issuer key is the stack's well-known
//     test seed, so the negative tests can re-sign the wrapper after a tamper),
//   - over a real source `ario.anchor.trace/v1` bundle (3 events, one with a
//     disclosed raw log → content_ok:true; a 1-checkpoint merkle window),
//   - with 2 embedded RSA-PSS-SHA-256 operator attestations (salt=32 pin, §3.3)
//     bound to the real checkpoint tx (data_hash == SHA-256(JCS(checkpoint
//     envelope)); operator == base64url(SHA-256(rsa modulus))), one carrying a
//     subject_ref (§3.2),
//   - a per-gateway confirm/unreachable on-chain mix in the cached verdict (§4.2),
//   - and a matching cached `kernel_verdict` (§4) the kernel recomputes and
//     confirms over its deterministic dimensions (§5 step 5).
//
// It also emits a compact `_tamper` block of pre-signed replacement pieces so
// the private-key-free negative tests can exercise the attestation-signature and
// binding failure classes (mis-salted sig, wrong-operator, wrong-data_hash)
// without an RSA private key — mirroring slice 1's signature_wrong_salt_hex.
//
// Requires a current build (imports the kernel's own JCS + merkle primitives so
// the fixture is byte-identical to what the verifier recomputes):
//   npm run build && node scripts/gen-export-fixture.mjs
// The RSA keypairs are random per run; the Ed25519 wrapper key is the fixed
// stack seed. The committed fixture pins whatever bytes are generated.

import { generateKeyPairSync, sign, constants, createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";

import { jcs } from "../dist/verifier.js";
import { auditPath, leafHash, merkleRoot } from "../dist/merkle.js";
import { bytesToHex, sha256Hex, utf8 } from "../dist/crypto.js";

// @noble/ed25519 v2 needs SHA-512 wired for signing (WebCrypto/Node parity).
ed.etc.sha512Async = async (...msgs) =>
  new Uint8Array(createHash("sha512").update(Buffer.concat(msgs.map((m) => Buffer.from(m)))).digest());

const OUT = fileURLToPath(
  new URL("../test/fixtures/evidence-export-bundle.golden.json", import.meta.url),
);

// The stack's well-known test seed (same as evidence.test.ts / evidence-golden).
// The wrapper AND the source bundle are Ed25519-signed with it, so the tamper
// tests can re-sign a mutated wrapper with the known seed.
const SEED_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const seed = Uint8Array.from(Buffer.from(SEED_HEX, "hex"));
const pubHex = bytesToHex(await ed.getPublicKeyAsync(seed));

const GENERATED_AT = "2026-07-15T00:00:00Z";

function sha256hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
async function edSign(obj) {
  return bytesToHex(await ed.signAsync(utf8(jcs(obj)), seed));
}

// Sign an external-commitment ario.events/v1 envelope over a record.
async function signEventEnvelope(record, eventId) {
  const recordBytes = utf8(jcs(record));
  const pre = {
    spec_version: "ario.events/v1",
    event_id: eventId,
    payload_hash: await sha256Hex(recordBytes),
    signed_at: "2026-07-15T00:00:00Z",
    environment: "dev",
    public_key: pubHex,
  };
  const signature = bytesToHex(await ed.signAsync(utf8(jcs(pre)), seed));
  return { envelope: { ...pre, signature }, recordBytes };
}

// ---- 1. Build the source ario.anchor.trace/v1 bundle ------------------------

// Three event raw logs; event 0's bytes are disclosed in-body (content_ok:true).
const rawLogs = [
  utf8("export-fixture raw log line 0 — disclosed"),
  utf8("export-fixture raw log line 1 — withheld"),
  utf8("export-fixture raw log line 2 — withheld"),
];
const eventRecords = rawLogs.map((raw, i) => ({
  payload_version: 1,
  spec_version: "ario.events/v1",
  event_type: "log.line",
  subject: { type: "producer", producer_id: "export-fixture-producer" },
  previous_hash: "GENESIS",
  event: { content_hash: sha256hex(raw), index: i },
  context: { chain_key: "batcher:export-fixture" },
  metadata: {},
  extras: {},
}));

const events = [];
for (let i = 0; i < eventRecords.length; i++) {
  const { envelope, recordBytes } = await signEventEnvelope(
    eventRecords[i],
    `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`,
  );
  events.push({ envelope, recordBytes, leaf: await leafHash(utf8(jcs(envelope))) });
}

const leaves = events.map((e) => e.leaf);
const rootHex = bytesToHex(await merkleRoot(leaves));

const checkpointRecord = {
  payload_version: 1,
  spec_version: "ario.events/v1",
  event_type: "checkpoint",
  subject: { type: "producer", producer_id: "export-fixture-producer" },
  previous_hash: "GENESIS",
  event: { merkle_root: rootHex, leaf_count: leaves.length },
  context: { chain_key: "batcher:export-fixture" },
  metadata: {},
  extras: {},
};
const { envelope: checkpointEnvelope } = await signEventEnvelope(
  checkpointRecord,
  "00000000-0000-4000-8000-ffffffffffff",
);
const checkpointTxId = "eKpT-eXpOrT-fIxTuRe-cHeCkPoInT-tX-000000001";

const sourceBody = {
  checkpoints: [
    {
      tx_id: checkpointTxId,
      envelope: checkpointEnvelope,
      record_bytes: bytesToHex(utf8(jcs(checkpointRecord))),
      merkle_root: rootHex,
    },
  ],
  events: await Promise.all(
    events.map(async (e, i) => ({
      envelope: e.envelope,
      record_bytes: bytesToHex(e.recordBytes),
      ...(i === 0 ? { content: bytesToHex(rawLogs[0]) } : {}),
      inclusion: {
        leaf_hash: bytesToHex(e.leaf),
        leaf_index: i,
        leaf_count: leaves.length,
        audit_path: (await auditPath(i, leaves)).map(bytesToHex),
        checkpoint_tx_id: checkpointTxId,
      },
    })),
  ),
};

const sourceWrapperPre = {
  spec_version: "ario.evidence/v1",
  body_type: "ario.anchor.trace/v1",
  issuer: { kind: "producer", producer_id: "export-fixture-producer" },
  generated_at: GENERATED_AT,
  gateway: null,
  verdict: { status: "verified", summary: "3 event(s) across 1 checkpoint(s)" },
  body: sourceBody,
  body_hash: await sha256Hex(utf8(jcs(sourceBody))),
  previous_hash: "GENESIS",
  signature_alg: "ed25519",
  public_key: pubHex,
};
const sourceBundle = { ...sourceWrapperPre, signature: await edSign(sourceWrapperPre) };

// The checkpoint's committed content hash: the checkpoint tx data IS the
// uploaded JCS(envelope) bytes (what the on-chain re-fetch compares), so
// data_hash for an attestation about this checkpoint = SHA-256(JCS(envelope)).
const checkpointContentHash = sha256hex(utf8(jcs(checkpointEnvelope)));

// ---- 2. Two operator RSA keys + embedded attestations -----------------------

function rsaOperator() {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  const publicJwk = { kty: jwk.kty, n: jwk.n, e: jwk.e };
  const address = createHash("sha256").update(Buffer.from(publicJwk.n, "base64url")).digest("base64url");
  return { privateKey, publicJwk, address };
}
const op1 = rsaOperator();
const op2 = rsaOperator();

// RSA-PSS / SHA-256 / MGF1-SHA-256 / salt = 32 (RSA_PSS_SALTLEN_DIGEST). The pin.
function rsaPssSign(privateKey, payload) {
  return sign("sha256", utf8(jcs(payload)), {
    key: privateKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
  }).toString("hex");
}
// The interop trap: max/auto salt — the shipped issuer's former default. Same
// key + bytes; a saltLength=32 verify MUST reject it.
function rsaPssSignMaxSalt(privateKey, payload) {
  return sign("sha256", utf8(jcs(payload)), {
    key: privateKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_MAX_SIGN,
  }).toString("hex");
}

const att0Payload = {
  attested_at: "2026-07-15T00:00:00.000Z",
  tx_id: checkpointTxId,
  data_hash: checkpointContentHash,
  data_size: 4096,
  block_height: 1_512_345,
  block_timestamp: 1_752_537_600,
  operator: op1.address,
  owner_address: "b3duZXJfYWRkcmVzc19wbGFjZWhvbGRlcl9fMDAwMDAwMDAwMDA",
  gateway: "https://g1.example",
  signature_verified: true,
  level: 3,
  subject_ref: { hash: sha256hex(utf8("external-subject-mandate-bytes")), type: "document" },
  attestation_version: "ario.evidence.attestation/v1",
};
const att1Payload = {
  attested_at: "2026-07-15T00:05:00.000Z",
  tx_id: checkpointTxId,
  data_hash: checkpointContentHash,
  data_size: 4096,
  block_height: 1_512_345,
  block_timestamp: 1_752_537_600,
  operator: op2.address,
  owner_address: "b3duZXJfYWRkcmVzc19wbGFjZWhvbGRlcl9fMDAwMDAwMDAwMDA",
  gateway: "https://g2.example",
  signature_verified: true,
  level: 2,
  attestation_version: "ario.evidence.attestation/v1",
};

const attestations = [
  {
    checkpoint_tx_id: checkpointTxId,
    payload: att0Payload,
    signature_alg: "rsa-pss-sha256",
    public_key: op1.publicJwk,
    signature: rsaPssSign(op1.privateKey, att0Payload),
  },
  {
    checkpoint_tx_id: checkpointTxId,
    payload: att1Payload,
    signature_alg: "rsa-pss-sha256",
    public_key: op2.publicJwk,
    signature: rsaPssSign(op2.privateKey, att1Payload),
  },
];

// ---- 3. Cached kernel_verdict (§4) — what the kernel recomputes --------------

const kernelVerdict = {
  schema_version: "ario.evidence.verdict/v1",
  status: "verified",
  summary:
    "Source bundle verified (3 events across 1 checkpoint); 2 operator attestations valid; on-chain confirmed on 1/2 gateways.",
  counts: { verified: 5, failed: 0, undetermined: 0 },
  as_of: GENERATED_AT,
  events: events.map((e, i) => ({
    event_id: e.envelope.event_id,
    signature_ok: true,
    payload_bound: true,
    inclusion_ok: true,
    content_ok: i === 0 ? true : null,
    status: "verified",
  })),
  checkpoints: [
    {
      checkpoint_tx_id: checkpointTxId,
      merkle_root_ok: true,
      on_chain: {
        rollup: "confirm",
        on_chain_ok: true,
        per_gateway: [
          { gateway: "https://g1.example", outcome: "confirm", block_height: 1_512_345 },
          { gateway: "https://g2.example", outcome: "unreachable" },
        ],
      },
      attestations: [
        {
          operator: op1.address,
          gateway: "https://g1.example",
          signature_ok: true,
          operator_address_bound: true,
          data_hash_bound: true,
          level: 3,
          subject_ref_ok: null,
        },
        {
          operator: op2.address,
          gateway: "https://g2.example",
          signature_ok: true,
          operator_address_bound: true,
          data_hash_bound: true,
          level: 2,
          subject_ref_ok: null,
        },
      ],
    },
  ],
  custody_chain: null,
};

// ---- 4. Assemble + sign the export wrapper ----------------------------------

const exportBody = {
  kernel_verdict: kernelVerdict,
  source_bundle: sourceBundle,
  source_bundle_hash: await sha256Hex(utf8(jcs(sourceBundle))),
  attestations,
  export_schema: "ario.evidence.export/v1",
};

const wrapperPre = {
  spec_version: "ario.evidence/v1",
  body_type: "ario.evidence.export/v1",
  issuer: { kind: "issuer", issuer_id: "ar-io-verify:fixture-instance" },
  generated_at: GENERATED_AT,
  gateway: null,
  verdict: {
    status: "verified",
    summary: kernelVerdict.summary,
    counts: kernelVerdict.counts,
    as_of: GENERATED_AT,
  },
  body: exportBody,
  body_hash: await sha256Hex(utf8(jcs(exportBody))),
  previous_hash: "GENESIS",
  signature_alg: "ed25519",
  public_key: pubHex,
};
const exportBundle = { ...wrapperPre, signature: await edSign(wrapperPre) };

// ---- 5. Private-key-free tamper helpers (attestation classes) ---------------

// (i) mis-salted signature over att0's SAME payload+key: salt=32 verify rejects.
const att0MisSaltSig = rsaPssSignMaxSalt(op1.privateKey, att0Payload);

// (ii) wrong-operator: signed by op2 but payload.operator == op1.address. The
// RSA-PSS sig VERIFIES (op2 signed it) yet operator-address binding FAILS
// (base64url(SHA-256(op2.n)) != op1.address). data_hash still binds — isolates
// the operator-binding break from the signature and data_hash dimensions.
const wrongOperatorPayload = { ...att1Payload, operator: op1.address };
const wrongOperatorAttestation = {
  checkpoint_tx_id: checkpointTxId,
  payload: wrongOperatorPayload,
  signature_alg: "rsa-pss-sha256",
  public_key: op2.publicJwk,
  signature: rsaPssSign(op2.privateKey, wrongOperatorPayload),
};

// (iii) wrong-data_hash: signed by op1 (operator binding holds) but data_hash is
// a hash that is NOT the checkpoint's committed content hash — isolates the
// data_hash binding break.
const wrongDataHashPayload = {
  ...att0Payload,
  data_hash: sha256hex(utf8("a-transaction-that-is-not-the-checkpoint")),
};
const wrongDataHashAttestation = {
  checkpoint_tx_id: checkpointTxId,
  payload: wrongDataHashPayload,
  signature_alg: "rsa-pss-sha256",
  public_key: op1.publicJwk,
  signature: rsaPssSign(op1.privateKey, wrongDataHashPayload),
};

const fixture = {
  _comment:
    "Frozen ario.evidence.export/v1 golden fixture (kernel slice 2). Regenerate with scripts/gen-export-fixture.mjs (requires npm run build first). `export` is the positive vector: an Ed25519 issuer-signed wrapper (well-known stack seed) over an inline ario.anchor.trace/v1 source bundle + 2 salt=32 RSA-PSS operator attestations + a cached kernel_verdict with a per-gateway confirm/unreachable on-chain mix. `_tamper` holds pre-signed replacement pieces for the private-key-free attestation-class negatives.",
  seed_hex: SEED_HEX,
  checkpoint_tx_id: checkpointTxId,
  checkpoint_content_hash: checkpointContentHash,
  operator_addresses: { op1: op1.address, op2: op2.address },
  export: exportBundle,
  _tamper: {
    att0_mis_salt_sig: att0MisSaltSig,
    wrong_operator_attestation: wrongOperatorAttestation,
    wrong_data_hash_attestation: wrongDataHashAttestation,
  },
};

writeFileSync(OUT, JSON.stringify(fixture, null, 2) + "\n");
console.log(`wrote ${OUT}`);
console.log(`checkpoint_tx_id      = ${checkpointTxId}`);
console.log(`op1 / op2 addresses   = ${op1.address} / ${op2.address}`);
console.log(`source_bundle_hash    = ${exportBody.source_bundle_hash}`);
console.log(`export body_hash      = ${wrapperPre.body_hash}`);
