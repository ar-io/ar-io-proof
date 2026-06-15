// Package proof is the Go cryptographic kernel of the ar.io verification
// stack (docs/stack/architecture.md §3, primitives 1-3 and 5). It implements
// the primitives used to produce and verify on-chain envelopes per
// docs/artifact.md (the ario.agent/v1 profile of docs/envelope-spec.md):
//
//   - CanonicalJSON: RFC 8785 (JCS) canonicalization
//   - SHA256Hex:     hex-encoded SHA-256
//   - SignEnvelope / VerifyEnvelope: Ed25519 signing of envelope-minus-signature,
//     with payload_hash committed via SHA-256(JCS(payload))
//   - SupportedSpecMajor: the fail-closed accepted-majors registry
//
// This package is public and importable (architecture.md K2) and is the
// stack's audited surface: external consumers (the proof-checker's WASM-Go
// verifier, future producers in Go) import it rather than re-implementing
// crypto. It is MIT-licensed via the LICENSE file in this directory — an
// explicit carve-out from the repository's BSL 1.1 — so third-party
// verifiers carry no BSL terms.
//
// The kernel is frozen by default (K4): a change here is a change to the
// envelope family contract, reviewed at the spec layer with test-vector
// regeneration and cross-language sync (Python, JS/TS) — never a casual
// refactor. Conformance is defined byte-for-byte (K3) against
// ../../test-vectors/ (locked at the test-vectors-v1.0 tag; governed by
// docs/stack/governance.md §4): every kernel must produce byte-identical
// JCS output, hashes, and signatures for the same fixed Ed25519 seed.
//
// Scope boundary (architecture.md §8, envelope-spec §10 #13): this package
// verifies a SINGLE envelope — signature over the skeleton plus the
// payload_hash binding. Chain walking (previous_hash), checkpoint
// reconciliation, and completeness checks are producer-layer logic composed
// above the kernel, and key lifecycle (load/persist/rotate) lives in the
// producer runtime — keys are passed in, never managed here.
package proof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

// SupportedSpecMajor is the accepted envelope spec major-versions this build
// verifies. Per docs/artifact.md §13, verifiers MUST reject envelopes whose
// spec_version major is unknown. Adding a profile is a deliberate one-entry
// addition (envelope-spec §5): ario.events/v1 (external commitment + Minimal
// disclosure; ratified envelope-spec v1.3) is verified through the SAME
// primitives — signature over envelope-minus-signature-minus-co_signatures,
// payload binding via VerifyEnvelope (signature-only) / VerifyEnvelopeWithPayload
// (committed record bytes). This build ALSO produces only ario.agent/v1.
var SupportedSpecMajor = []string{"ario.agent/v1", "ario.events/v1"}

// ErrUnsupportedSpecVersion is returned by VerifyEnvelope when the envelope's
// spec_version is missing or its major version is not in SupportedSpecMajor.
var ErrUnsupportedSpecVersion = errors.New("proof: unsupported spec_version")

// CanonicalJSON returns the RFC 8785 (JCS) canonical bytes of v.
// v MUST be JSON-marshalable (no functions, channels, etc.). The result is
// deterministic UTF-8 bytes that any RFC-8785 verifier in any language
// reproduces byte-for-byte.
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("proof: marshal: %w", err)
	}
	out, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("proof: jcs transform: %w", err)
	}
	return out, nil
}

// SHA256Hex returns the lowercase hex-encoded SHA-256 of b.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SignEnvelope produces the canonical, signed envelope bytes ready for
// upload to Turbo per artifact.md §6.
//
// The input envelope MUST already include the "payload" field. The input
// map is NOT mutated; SignEnvelope works on an internal copy. The function:
//
//  1. Sets payload_hash = SHA-256(JCS(payload)).
//  2. Sets public_key = hex(pub) (becomes part of the signed scope).
//  3. Canonicalizes the envelope minus signature and minus co_signatures
//     (the reserved countersignature field is outside the primary signed
//     scope per envelope-spec.md v1.1 §2/§7.1, so one can be added without
//     invalidating the primary signature).
//  4. Signs those bytes with Ed25519 (priv).
//  5. Sets signature = hex(sig) and returns the canonical bytes of the complete
//     envelope (which DOES include co_signatures when present).
//
// The returned bytes are what should be uploaded to Turbo. Per artifact.md
// §6 the uploaded bytes MUST be JCS-canonical.
func SignEnvelope(envelope map[string]any, priv ed25519.PrivateKey) ([]byte, error) {
	if envelope == nil {
		return nil, errors.New("proof: nil envelope")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("proof: bad private key length: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if _, ok := envelope["payload"]; !ok {
		return nil, errors.New("proof: envelope missing 'payload'")
	}

	// Operate on a shallow copy so the caller's map is untouched. The
	// payload's nested structure is shared by reference, but we never mutate
	// anything below the top level.
	work := make(map[string]any, len(envelope)+2)
	for k, v := range envelope {
		if k == "signature" {
			continue // never carry a stale signature into the new scope
		}
		work[k] = v
	}

	payloadBytes, err := CanonicalJSON(work["payload"])
	if err != nil {
		return nil, fmt.Errorf("proof: canonicalize payload: %w", err)
	}
	work["payload_hash"] = SHA256Hex(payloadBytes)
	work["public_key"] = hex.EncodeToString(priv.Public().(ed25519.PublicKey))

	// The signing scope excludes co_signatures (envelope-spec v1.1 §2/§7.1);
	// the field still rides in the final envelope below.
	forSig := work
	if _, present := work["co_signatures"]; present {
		forSig = make(map[string]any, len(work))
		for k, v := range work {
			if k == "co_signatures" {
				continue
			}
			forSig[k] = v
		}
	}
	scope, err := CanonicalJSON(forSig)
	if err != nil {
		return nil, fmt.Errorf("proof: canonicalize envelope-for-sig: %w", err)
	}
	sig := ed25519.Sign(priv, scope)
	work["signature"] = hex.EncodeToString(sig)

	out, err := CanonicalJSON(work)
	if err != nil {
		return nil, fmt.Errorf("proof: canonicalize signed envelope: %w", err)
	}
	return out, nil
}

// VerifyEnvelope parses and verifies a complete envelope per
// envelope-spec.md §2/§3. It performs these checks in order:
//
//  1. Parse the envelope JSON (rejecting invalid UTF-8 and lone UTF-16
//     surrogate escapes — see rejectMalformedText).
//  2. Reject if spec_version's major is not in SupportedSpecMajor.
//  3. Payload binding, detected STRUCTURALLY (envelope-spec §3; design
//     signed off in the kernel-ratification lane): when the envelope
//     carries an inline payload, recompute SHA-256(JCS(payload)) and
//     confirm it equals payload_hash. When it does not (an
//     external-commitment profile, e.g. ario.mlflow/v1, ario.events/v1),
//     there is nothing in-envelope to bind: the envelope verifies
//     signature-only — "signature-valid, semantics-undetermined"
//     (§3.1/§6.2). Use VerifyEnvelopeWithPayload to bind the committed
//     bytes; callers can distinguish the two outcomes by the presence of
//     the "payload" key in the returned envelope. Mode confusion is
//     closed by the signed scope itself: stripping an inline payload (or
//     injecting one) breaks the signature. payload_hash MUST be present (a
//     string) in every mode — its absence is rejected per envelope-spec §2,
//     independent of whether there is material to compare it against.
//  4. Verify the Ed25519 signature over JCS(envelope minus signature and
//     minus co_signatures) against envelope.public_key — the reserved
//     countersignature field is outside the primary signed scope per
//     envelope-spec.md v1.1 §2/§7.1, and its absence (or an empty array)
//     is never a failure. Nothing else is stripped.
//
// On success returns the parsed envelope. On any failure returns a non-nil
// error indicating which check failed. Unknown-spec-version failures wrap
// ErrUnsupportedSpecVersion so callers can distinguish them.
func VerifyEnvelope(envelopeJSON []byte) (map[string]any, error) {
	return verifyEnvelope(envelopeJSON, nil)
}

// VerifyEnvelopeWithPayload verifies an envelope AND binds the supplied
// committed payload bytes: SHA-256(payloadBytes) must equal the envelope's
// payload_hash (external commitment, envelope-spec §3). When the envelope
// also carries an inline payload, both bindings must hold. payloadBytes are
// the producer-retained canonical record bytes — e.g. @ar.io/anchor's
// recordBytes or an mlflow run's committed artifact bytes.
func VerifyEnvelopeWithPayload(envelopeJSON, payloadBytes []byte) (map[string]any, error) {
	if payloadBytes == nil {
		return nil, errors.New("proof: payloadBytes required (use VerifyEnvelope for signature-only)")
	}
	return verifyEnvelope(envelopeJSON, payloadBytes)
}

func verifyEnvelope(envelopeJSON, externalPayload []byte) (map[string]any, error) {
	if err := rejectMalformedText(envelopeJSON); err != nil {
		return nil, err
	}
	var envelope map[string]any
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		return nil, fmt.Errorf("proof: parse envelope: %w", err)
	}

	// 1. spec_version major check. MUST be present and recognized.
	specV, _ := envelope["spec_version"].(string)
	if !isSupportedSpec(specV) {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedSpecVersion, specV)
	}

	// 2. Payload binding (structural; see VerifyEnvelope doc). payload_hash
	// MUST be present (a string) in every mode — envelope-spec §2: a verifier
	// "cannot proceed without ... payload_hash and MUST reject their absence."
	// When present, it is COMPARED only against material that exists: inline
	// check iff the envelope carries a payload; external check iff the caller
	// supplied the committed bytes; both when both are available; neither →
	// signature-only ("signature-valid, semantics-undetermined").
	want, ok := envelope["payload_hash"].(string)
	if !ok {
		return nil, errors.New("proof: missing payload_hash (required in every profile)")
	}
	if payload, ok := envelope["payload"]; ok {
		payloadBytes, err := CanonicalJSON(payload)
		if err != nil {
			return nil, fmt.Errorf("proof: canonicalize payload: %w", err)
		}
		if got := SHA256Hex(payloadBytes); got != want {
			return nil, fmt.Errorf("proof: payload_hash mismatch: have=%s want=%s", got, want)
		}
	}
	if externalPayload != nil {
		if got := SHA256Hex(externalPayload); got != want {
			return nil, fmt.Errorf("proof: payload_hash does not match the committed bytes: have=%s want=%s", got, want)
		}
	}

	// 3. Signature verify.
	sigHex, _ := envelope["signature"].(string)
	pubHex, _ := envelope["public_key"].(string)
	if sigHex == "" || pubHex == "" {
		return nil, errors.New("proof: missing signature or public_key")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, fmt.Errorf("proof: decode signature: %w", err)
	}
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, fmt.Errorf("proof: decode public_key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("proof: public_key wrong length: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	// Reconstruct the signed scope: envelope minus signature and minus
	// co_signatures (envelope-spec v1.1 §2/§7.1) — and nothing else.
	scopeMap := make(map[string]any, len(envelope))
	for k, v := range envelope {
		if k == "signature" || k == "co_signatures" {
			continue
		}
		scopeMap[k] = v
	}
	scope, err := CanonicalJSON(scopeMap)
	if err != nil {
		return nil, fmt.Errorf("proof: canonicalize envelope-for-sig: %w", err)
	}

	if !ed25519.Verify(pub, scope, sig) {
		return nil, errors.New("proof: signature invalid")
	}
	return envelope, nil
}

// isSupportedSpec checks whether v matches one of SupportedSpecMajor by
// prefix match: "ario.agent/v1" supports "ario.agent/v1" and any
// "ario.agent/v1.<minor>" (additive minor changes are allowed within a
// major). Unknown majors are rejected.
func isSupportedSpec(v string) bool {
	if v == "" {
		return false
	}
	for _, sup := range SupportedSpecMajor {
		if v == sup {
			return true
		}
		// Additive minors within an accepted major are tolerated, but the
		// minor token must be numeric (envelope-spec §2 grammar; a
		// non-numeric suffix is malformed, not a future version) — matching
		// the Python kernel's 0.1.1 semantics (ar-io-agent#13).
		if minor, found := strings.CutPrefix(v, sup+"."); found {
			if minor != "" && isDigits(minor) {
				return true
			}
		}
	}
	return false
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// rejectMalformedText rejects envelope JSON whose text content cannot be
// represented identically across the family's kernels: invalid UTF-8 bytes
// and lone (unpaired) UTF-16 surrogate escapes. encoding/json silently
// substitutes both with U+FFFD, which would canonicalize to DIFFERENT bytes
// than the JS kernel sees — reject-only is the one behavior all three
// kernels can share (the TS kernel rejects in jcs(); Python raises on
// UTF-8 encode). Pinned by the corpus lone-surrogate negative.
func rejectMalformedText(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("proof: envelope JSON is not valid UTF-8")
	}
	// Scan for \uD800-\uDFFF escape sequences, honoring backslash escaping
	// and requiring high/low pairing.
	inString := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 >= len(raw) {
				return errors.New("proof: truncated escape in JSON string")
			}
			if raw[i+1] != 'u' {
				i++ // simple escape (\" \\ \/ \b \f \n \r \t)
				continue
			}
			cp, ok := hex4(raw, i+2)
			if !ok {
				return errors.New("proof: malformed \\u escape in JSON string")
			}
			switch {
			case cp >= 0xDC00 && cp <= 0xDFFF:
				return errors.New("proof: lone low surrogate escape in JSON string")
			case cp >= 0xD800 && cp <= 0xDBFF:
				// Must be followed immediately by a low-surrogate escape.
				j := i + 6
				if j+1 < len(raw) && raw[j] == '\\' && raw[j+1] == 'u' {
					if lo, ok2 := hex4(raw, j+2); ok2 && lo >= 0xDC00 && lo <= 0xDFFF {
						i = j + 5 // consume the pair
						continue
					}
				}
				return errors.New("proof: lone high surrogate escape in JSON string")
			}
			i += 5 // consume \uXXXX (non-surrogate)
		}
	}
	return nil
}

// hex4 decodes raw[pos:pos+4] as 4 hex digits.
func hex4(raw []byte, pos int) (int, bool) {
	if pos+4 > len(raw) {
		return 0, false
	}
	v := 0
	for _, c := range raw[pos : pos+4] {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= int(c - '0')
		case c >= 'a' && c <= 'f':
			v |= int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= int(c-'A') + 10
		default:
			return 0, false
		}
	}
	return v, true
}
