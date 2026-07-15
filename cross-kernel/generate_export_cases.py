#!/usr/bin/env python3
"""Generate the ``ario.evidence.export/v1`` cross-kernel agreement case set +
record Python-reference verdicts.

The export sibling of ``generate_cases.py``. Where that gate drives
``verifyEnvelope`` across the kernels, this one drives the full
``verifyEvidenceBundle`` / ``verifyExportBody`` path (evidence-export.md §5) —
the attested-evidence-export verify — over the frozen shared golden export and
its programmatically-tampered classes (``tools/gen-vectors/export_vectors.py``).

The Python kernel is the reference. For each case it records a normalized
verdict record — top-level wrapper flags, the CLI exit code (0/1/2/3), and, for
a well-formed export, the export-specific dimensions PLUS
``verdict_jcs_sha256`` = ``SHA-256(JCS(recomputed §4 verdict object))``. That
last field is the **byte-identical-verdict** proof: the TS leg
(``ts_export_leg.mjs``) re-verifies the same bytes and MUST reproduce the whole
record — same booleans, same nulls, same verdict JCS hash.

Deterministic: fixed seed, no clock, no network (offline verify), sorted output.

    python3 generate_export_cases.py <repo-root> > export-cases.json
"""

import hashlib
import json
import sys
from pathlib import Path

# The shared vector builder lives in tools/gen-vectors (single source of truth
# for the mutations, also used by the committed corpus generator).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "gen-vectors"))

from export_vectors import build_cases, load_fixture  # noqa: E402

from ario_proof.canonicalize import canonical_json  # noqa: E402
from ario_proof.evidence import verify_evidence_bundle  # noqa: E402


def verdict_record(bundle: dict) -> dict:
    """Normalized cross-kernel verdict record for one export bundle — exactly
    the fields the TS leg reproduces byte-for-byte."""
    r = verify_evidence_bundle(bundle)
    rec = {
        "status": r.status,
        "exit": r.exit_code(),
        "spec_version_ok": r.spec_version_ok,
        "signature_ok": r.signature_ok,
        "body_hash_ok": r.body_hash_ok,
        "body_type": r.body_type,
        "export": None,
    }
    if r.export is not None:
        e = r.export
        rec["export"] = {
            "source_linkage_ok": e.source_linkage_ok,
            "source_status": e.source_status,
            "verdict_agreement_ok": e.verdict_agreement_ok,
            "status": e.status,
            "attestations": [
                {
                    "signature_ok": a.signature_ok,
                    "operator_address_bound": a.operator_address_bound,
                    "data_hash_bound": a.data_hash_bound,
                    "checkpoint_resolved": a.checkpoint_resolved,
                    "subject_ref_ok": a.subject_ref_ok,
                    "ok": a.ok,
                }
                for a in e.attestations
            ],
            # The byte-identical-verdict proof: SHA-256 of the JCS-canonical §4
            # verdict object both kernels recompute.
            "verdict_jcs_sha256": hashlib.sha256(canonical_json(e.verdict)).hexdigest(),
        }
    return rec


def main() -> int:
    repo_root = (
        Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    )
    fixture = load_fixture(repo_root)
    out = []
    for c in build_cases(fixture):
        out.append(
            {
                "id": c["id"],
                "klass": c["klass"],
                "expected_exit": c["expected_exit"],
                "bundle": c["bundle"],
                "py": verdict_record(c["bundle"]),
            }
        )
    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
