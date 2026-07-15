#!/usr/bin/env python3
"""Generate the ``test-vectors-v1.3`` attested-evidence-export corpus.

CORP1 (``specs/governance.md`` §4): **generated, never hand-edited.** Reads the
frozen shared golden export (``test-vectors/evidence-export/evidence-export-bundle.golden.json``)
and writes one self-describing vector per failure class into
``test-vectors/evidence-export/`` — the positive plus every tampered / malformed
/ undetermined class from evidence-export.md §7.2. Each vector's ``expected``
block is computed by the Python reference kernel (``ario_proof.evidence``), so
re-running this tool is the only way the expected outputs change.

The positive's ``expected.verdict_jcs_sha256`` is the byte-agreement anchor: the
SHA-256 of the JCS-canonical §4 verdict object the kernel recomputes — the TS
kernel reproduces the same hash (the cross-kernel export gate).

Usage:
    python3 gen_export_vectors.py <repo-root>     # writes into <repo-root>/test-vectors/evidence-export
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

# Reference kernel + the shared vector builder (same dir).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from export_vectors import build_cases, load_fixture  # noqa: E402

_REPO_ROOT = (
    Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[2]
)
sys.path.insert(0, str(_REPO_ROOT / "src"))
from ario_proof.canonicalize import canonical_json  # noqa: E402
from ario_proof.evidence import verify_evidence_bundle  # noqa: E402

DESCRIPTIONS = {
    "positive": (
        "POSITIVE. Ed25519 issuer-signed wrapper over an inline ario.anchor.trace/v1 "
        "source bundle (3 events, event 0 discloses its raw log -> content_ok:true; "
        "1-checkpoint merkle window) + 2 salt=32 RSA-PSS operator attestations "
        "(one carrying a subject_ref) + a cached kernel_verdict with a per-gateway "
        "confirm/unreachable on-chain mix. Verifies fully OFFLINE -> exit 0; the "
        "recomputed §4 verdict agrees with the cached one over the deterministic "
        "dimensions and is byte-identical across the TS and Python kernels."
    ),
    "wrapper-signature-break": (
        "Wrapper Ed25519 signature byte-flipped (verbatim-bytes tamper, no re-sign). "
        "The body is untrustworthy -> failed, no export block. Exit 1."
    ),
    "body-hash-mismatch": (
        "Wrapper body_hash byte-flipped. Recompute != claim -> failed. Exit 1."
    ),
    "source-bundle-hash-mismatch": (
        "body.source_bundle_hash byte-flipped, wrapper re-signed. Wrapper authentic; "
        "the source-bundle linkage is broken -> failed. Exit 1."
    ),
    "verdict-disagreement": (
        "A cached deterministic finding (kernel_verdict.events[0].signature_ok) flipped "
        "to false, wrapper re-signed. The recompute contradicts the cache "
        "(recompute-don't-trust) -> failed. Exit 1."
    ),
    "forged-attestation-signature": (
        "attestations[0].signature byte-flipped, wrapper re-signed. The RSA-PSS "
        "signature no longer verifies -> attestation fails -> failed. Exit 1."
    ),
    "mis-salted-attestation": (
        "attestations[0].signature replaced with a max/auto-salt RSA-PSS signature over "
        "the SAME payload+key (the shipped issuer's former default), wrapper re-signed. "
        "The salt=32 pin rejects it -> failed. Exit 1. THE salt-length pin."
    ),
    "operator-address-binding-break": (
        "attestations[0] replaced with an op2-signed record whose payload still claims "
        "op1's address, wrapper re-signed. The RSA-PSS sig verifies but "
        "base64url(SHA-256(op2.n)) != payload.operator -> failed. Exit 1."
    ),
    "data-hash-binding-break": (
        "attestations[0] replaced with an op1-signed record whose data_hash is not "
        "SHA-256(JCS(checkpoint.envelope)), wrapper re-signed. Sig + operator bind, "
        "data_hash does not -> failed. Exit 1."
    ),
    "disclosed-content-mismatch": (
        "Source event 0's in-body disclosed content byte-flipped; source bundle + "
        "export wrapper re-signed. The disclosed bytes no longer hash to the committed "
        "content_hash -> event fails -> failed. Exit 1."
    ),
    "subject-ref-tamper": (
        "attestations[0].payload.subject_ref.hash byte-flipped, wrapper re-signed. "
        "subject_ref lives INSIDE the RSA-signed payload, so altering it breaks the "
        "attestation signature -> failed. Exit 1."
    ),
    "malformed-rsa-key": (
        "attestations[0].public_key.kty set to 'oct' (won't import), wrapper re-signed. "
        "MALFORMED input -> no verdict renderable. Exit 2."
    ),
    "malformed-signature-alg": (
        "attestations[0].signature_alg set to 'ed25519' (unsupported per-record alg), "
        "wrapper re-signed. MALFORMED input. Exit 2."
    ),
    "source-bundle-ref-offline": (
        "Inline source_bundle removed, replaced by a source_bundle_ref, wrapper re-signed. "
        "The referenced bytes are unavailable offline -> source-dependent checks "
        "UNDETERMINED (not a failure). Exit 3."
    ),
}


def expected_block(bundle: dict) -> dict:
    r = verify_evidence_bundle(bundle)
    exp: dict = {
        "status": r.status,
        "exit_code": r.exit_code(),
        "signature_ok": r.signature_ok,
        "body_hash_ok": r.body_hash_ok,
    }
    if r.export is not None:
        e = r.export
        exp["source_linkage_ok"] = e.source_linkage_ok
        exp["verdict_agreement_ok"] = e.verdict_agreement_ok
        exp["source_status"] = e.source_status
        exp["attestations"] = [
            {
                "signature_ok": a.signature_ok,
                "operator_address_bound": a.operator_address_bound,
                "data_hash_bound": a.data_hash_bound,
                "checkpoint_resolved": a.checkpoint_resolved,
                "subject_ref_ok": a.subject_ref_ok,
                "ok": a.ok,
            }
            for a in e.attestations
        ]
        exp["verdict_jcs_sha256"] = hashlib.sha256(
            canonical_json(e.verdict)
        ).hexdigest()
    return exp


def main() -> int:
    out_dir = _REPO_ROOT / "test-vectors" / "evidence-export"
    out_dir.mkdir(parents=True, exist_ok=True)
    fixture = load_fixture(_REPO_ROOT)

    manifest: list[tuple[str, str]] = []
    for c in build_cases(fixture):
        vector = {
            "vector_id": c["id"],
            "class": c["klass"],
            "description": DESCRIPTIONS[c["klass"]],
            "expected": expected_block(c["bundle"]),
            "bundle": c["bundle"],
        }
        text = json.dumps(vector, indent=2) + "\n"
        path = out_dir / f"{c['id']}.json"
        path.write_text(text, encoding="utf-8")
        manifest.append((path.name, hashlib.sha256(text.encode("utf-8")).hexdigest()))

    # The frozen shared golden fixture is part of the corpus too.
    golden = out_dir / "evidence-export-bundle.golden.json"
    manifest.insert(
        0,
        (golden.name, hashlib.sha256(golden.read_bytes()).hexdigest()),
    )

    print(f"wrote {len(manifest) - 1} vectors + 1 golden fixture to {out_dir}")
    print("\nSHA-256 manifest (for CORPUS-v1.md):\n")
    for name, digest in manifest:
        print(f"| `evidence-export/{name}` | `{digest}` |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
