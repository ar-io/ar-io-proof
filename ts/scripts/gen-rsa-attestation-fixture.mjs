#!/usr/bin/env node
// Generate the frozen RSA-PSS operator-attestation golden fixture consumed by
// test/rsa-pss-attestation.test.ts. Committed output is
// test/fixtures/rsa-pss-attestation.golden.json.
//
// This proves the interop pin that the whole export-verify slice rests on: the
// issuer signs the JCS-canonical attestation payload with RSA-PSS-SHA-256 and
// salt length EXPLICITLY = 32 (RSA_PSS_SALTLEN_DIGEST), so WebCrypto
// (`saltLength: 32`) verifies it natively. It also emits a SECOND signature over
// the same bytes with the maximum salt (RSA_PSS_SALTLEN_MAX_SIGN, the shipped
// issuer's former RSA_PSS_SALTLEN_AUTO) to document the trap: WebCrypto rejects
// it, because it cannot auto-detect salt on verify.
//
// Run: node scripts/gen-rsa-attestation-fixture.mjs
// The RSA keypair is random per run; the committed fixture is regenerated only
// deliberately (the tests verify whatever bytes are committed, not a fixed key).

import { generateKeyPairSync, sign, constants, createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import canonicalize from "canonicalize";

const OUT = fileURLToPath(new URL("../test/fixtures/rsa-pss-attestation.golden.json", import.meta.url));

// A committed, deterministic key would be ideal, but RSA keygen is not seedable
// via node:crypto; freezing whatever we generate here is equivalent for a
// golden fixture (the tests pin the committed bytes, not a known key).
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });

const jwk = publicKey.export({ format: "jwk" }); // { kty:'RSA', n, e }
const publicJwk = { kty: jwk.kty, n: jwk.n, e: jwk.e };

// Operator address = base64url(SHA-256(rawModulusBytes)); rawModulus = decoded
// base64url `n`. Same owner→address derivation arweave-js uses. Unpadded.
const rawModulus = Buffer.from(publicJwk.n, "base64url");
const operatorAddress = createHash("sha256").update(rawModulus).digest("base64url");

// A representative ario.evidence.attestation/v1 payload (snake_case, family
// canon). Exact field values don't matter to the crypto slice — what matters is
// that JCS(payload) is the signed byte string and `operator` == derived address.
const payload = {
  tx_id: "Zm9vYmFyX3R4X2lkX3BsYWNlaG9sZGVyX18wMDAwMDAwMQ",
  data_hash: createHash("sha256").update("attested-transaction-data").digest("hex"),
  data_size: 4096,
  block_height: 1_500_123,
  block_timestamp: 1_752_537_600,
  attested_at: "2026-07-15T00:00:00Z",
  operator: operatorAddress,
  owner_address: "b3duZXJfYWRkcmVzc19wbGFjZWhvbGRlcl9fMDAwMDAwMDAwMDA",
  gateway: "https://operator-gateway.example",
  signature_verified: true,
  attestation_version: "ario.evidence.attestation/v1",
};

const jcsBytes = Buffer.from(canonicalize(payload), "utf8");

// Pinned: RSA-PSS / SHA-256 / MGF1-SHA-256 / salt = 32 (DIGEST). Verifiable by
// WebCrypto with saltLength: 32.
const signatureHex = sign("sha256", jcsBytes, {
  key: privateKey,
  padding: constants.RSA_PKCS1_PSS_PADDING,
  saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
}).toString("hex");

// The interop trap: maximum/auto salt (the issuer's former default). Same key,
// same bytes — WebCrypto verify with saltLength 32 MUST reject this.
const signatureWrongSaltHex = sign("sha256", jcsBytes, {
  key: privateKey,
  padding: constants.RSA_PKCS1_PSS_PADDING,
  saltLength: constants.RSA_PSS_SALTLEN_MAX_SIGN,
}).toString("hex");

const fixture = {
  _comment:
    "Frozen RSA-PSS-SHA-256 operator-attestation golden fixture. Regenerate with scripts/gen-rsa-attestation-fixture.mjs. signature_hex is over utf8(JCS(payload)) with salt length = 32 (RSA_PSS_SALTLEN_DIGEST); signature_wrong_salt_hex is the same over max salt (the un-verifiable RSA_PSS_SALTLEN_AUTO trap).",
  algorithm: "rsa-pss-sha256",
  salt_length: 32,
  public_key: publicJwk,
  operator_address: operatorAddress,
  payload,
  signature_hex: signatureHex,
  signature_wrong_salt_hex: signatureWrongSaltHex,
};

writeFileSync(OUT, JSON.stringify(fixture, null, 2) + "\n");
console.log(`wrote ${OUT}`);
console.log(`operator_address = ${operatorAddress}`);
console.log(`signature_hex len = ${signatureHex.length / 2} bytes`);
