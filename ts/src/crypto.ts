// Low-level cryptographic primitives for the verifier. Deliberately thin: the
// only third-party crypto dependency is @noble/ed25519 (single-file, audited,
// zero-dependency). SHA-256 and SHA-512 come from WebCrypto — no extra hashing
// library to trust.

import * as ed from "@noble/ed25519";

// @noble/ed25519 needs SHA-512 to verify. Wire it to WebCrypto rather than
// pulling in @noble/hashes. globalThis.crypto.subtle exists in every modern
// browser and in Node >= 19, so the same code path runs in the app and in tests.
ed.etc.sha512Async = async (...msgs: Uint8Array[]): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest("SHA-512", asBufferSource(ed.etc.concatBytes(...msgs))));

// WebCrypto's digest() wants a BufferSource backed by a (non-shared) ArrayBuffer.
// Our byte arrays always are; this keeps TS 5.7's stricter Uint8Array<ArrayBufferLike>
// typing satisfied without a runtime copy.
function asBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hexToBytes: odd-length string");
  // Full validation: parseInt() partially parses ("1g" -> 1), which would let
  // malformed hex through. A strict charset check closes that.
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error("hexToBytes: non-hex characters");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export async function sha256Bytes(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", asBufferSource(bytes)));
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return bytesToHex(await sha256Bytes(bytes));
}

// Verify an Ed25519 signature. Inputs are hex (signature, public key) as they
// appear in the envelope; message is raw bytes. Never throws — a malformed
// signature or key is "not verified," not an exception, so a hostile envelope
// can't crash the checker.
export async function ed25519Verify(
  signatureHex: string,
  message: Uint8Array,
  publicKeyHex: string,
): Promise<boolean> {
  try {
    // zip215:false → strict RFC-8032 verification, matching the Go agent's
    // crypto/ed25519 exactly (noble defaults to the more lenient zip215:true).
    return await ed.verifyAsync(hexToBytes(signatureHex), message, hexToBytes(publicKeyHex), {
      zip215: false,
    });
  } catch {
    return false;
  }
}

// Ed25519 SIGN the raw `message` bytes with a 32-byte private-key seed (lowercase
// hex). Returns the signature as lowercase hex. The signing counterpart to
// ed25519Verify — the ONE signing primitive the composer (`proof export`,
// evidence-export.md §5) needs to Ed25519-sign the export wrapper with the
// exporter's key ("anyone can export", P-4). The @noble sha512Async hook wired at
// module load serves signing and verification alike, so this stays WebCrypto-only.
export async function ed25519Sign(message: Uint8Array, privateKeyHex: string): Promise<string> {
  return bytesToHex(await ed.signAsync(message, hexToBytes(privateKeyHex)));
}

// Derive the Ed25519 public key (lowercase hex) from a 32-byte private-key seed
// (lowercase hex) — the wrapper's embedded `public_key` when composing an export.
export async function ed25519PublicKey(privateKeyHex: string): Promise<string> {
  return bytesToHex(await ed.getPublicKeyAsync(hexToBytes(privateKeyHex)));
}

// ---------------------------------------------------------------------------
// RSA-PSS operator-attestation crypto (ario.evidence.export/v1)
//
// The attested-evidence-export body embeds operator attestations signed with
// RSA-PSS-SHA-256 over the JCS-canonical attestation payload; the operator key
// is the operator's Arweave RSA wallet. These two pure functions are the only
// new primitive that body needs and the only RSA in the kernel: verify one
// attestation signature, and derive the operator's Arweave address from the
// embedded modulus (the self-describing key→wallet binding).
//
// RSA-PSS parameters are PINNED for cross-kernel byte-agreement between the
// issuer, the TS kernel, and the Python kernel: hash = SHA-256; MGF1 with
// SHA-256; salt length = 32 (the SHA-256 digest length, i.e. OpenSSL's
// RSA_PSS_SALTLEN_DIGEST); padding = PSS. saltLength=32 is load-bearing — the
// shipped issuer's former RSA_PSS_SALTLEN_AUTO (which resolves to the maximum,
// key-size-dependent salt on signing) is NOT verifiable by WebCrypto, which
// does not auto-detect salt on verify. The pin is what makes these round-trip.
const RSA_PSS_SALT_LENGTH = 32;

// Verify an RSA-PSS-SHA-256 signature over `payloadBytes` (the raw JCS bytes of
// the attestation payload) with the JWK RSA public key `{kty:"RSA", n, e}`
// (`n`/`e` base64url) and a lowercase-hex `signatureHex`.
//
// Malformed-vs-failed follows the kernel's split: a malformed key (JWK that
// won't import) or malformed signature hex is a caller/input error and THROWS a
// prefixed Error — the same "malformed" signal hexToBytes raises and the CLI
// buckets as exit-2. A well-formed key + signature that simply does not verify
// (wrong signer, tampered payload, wrong salt length) returns `false` and never
// throws, so a hostile attestation can't crash the checker (same contract as
// ed25519Verify above).
export async function verifyRsaPssSha256(
  payloadBytes: Uint8Array,
  signatureHex: string,
  publicKey: { kty: "RSA"; n: string; e: string },
): Promise<boolean> {
  let signature: Uint8Array;
  try {
    signature = hexToBytes(signatureHex);
  } catch (e) {
    throw new Error(`verifyRsaPssSha256: malformed signature hex: ${stringifyErr(e)}`);
  }

  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "jwk",
      { kty: publicKey.kty, n: publicKey.n, e: publicKey.e, ext: true },
      { name: "RSA-PSS", hash: "SHA-256" },
      false,
      ["verify"],
    );
  } catch (e) {
    throw new Error(`verifyRsaPssSha256: malformed RSA public key: ${stringifyErr(e)}`);
  }

  try {
    return await crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: RSA_PSS_SALT_LENGTH },
      key,
      asBufferSource(signature),
      asBufferSource(payloadBytes),
    );
  } catch {
    // Some engines throw (rather than return false) on a wrong-length RSA
    // signature. That is still just "not verified," not a malformed-input
    // condition — the signature parsed as hex fine; it's the wrong signature.
    return false;
  }
}

// Derive an operator's Arweave wallet address from the base64url JWK modulus
// `n`: address = base64url(SHA-256(rawModulusBytes)), where rawModulusBytes is
// the decoded base64url `n`. This is the same owner→address derivation
// arweave-js uses (SHA-256 over the modulus octets, base64url without padding),
// so it binds an embedded RSA key to a specific wallet with no roster lookup.
//
// Async because the kernel takes SHA-256 from WebCrypto (crypto.subtle.digest),
// which is Promise-based — the module is deliberately WebCrypto-only with no
// second hashing library and no node:crypto, so it stays browser-portable.
// Throws a prefixed Error on a malformed (non-base64url) `n`.
export async function deriveOperatorAddress(nBase64url: string): Promise<string> {
  const modulus = base64UrlToBytes(nBase64url);
  const digest = await sha256Bytes(modulus);
  return bytesToBase64Url(digest);
}

// base64url (RFC 4648 §5, unpadded) codecs. Kept WebCrypto/browser-portable —
// atob/btoa exist in browsers and in Node >= 16 — so the kernel stays free of
// node:Buffer. Arweave and JWK both use unpadded base64url. Exported because the
// composer transcodes an issuer-emitted base64url attestation signature to the
// lowercase hex §2.2 stores (evidence-export.md §2.2 — the composer's boundary job).
export function base64UrlToBytes(b64url: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(b64url)) {
    throw new Error("base64url: non-base64url characters");
  }
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const rem = b64.length % 4;
  if (rem === 1) throw new Error("base64url: invalid length");
  if (rem === 2) b64 += "==";
  else if (rem === 3) b64 += "=";
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function stringifyErr(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
