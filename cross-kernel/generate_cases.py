#!/usr/bin/env python3
"""Generate the cross-kernel agreement case set + record Python-reference verdicts.

Two case sources, both verified by every kernel's ``verifyEnvelope``:

1. **Corpus** — every ``test-vectors/`` envelope vector, reconstructed into a
   complete signed envelope (the same bytes ``ariod verify`` would see).
   Includes the ``ario.events-v1/`` external-commitment vectors (verified
   with their committed record bytes).
2. **Adversarial** — synthetic cases for behavior the corpus does not yet
   pin: external-commitment binding modes, mode confusion (fake-external /
   fake-inline), missing/malformed ``payload_hash`` (§2), and malformed
   ``spec_version`` minors (#13).

Emits ``cases.json``: a list of
``{id, envelope, payload_b64?, py:{ok,phk,sig,spec}}``. The Python kernel is
the reference (``payload_hash_ok`` tri-state ``True``/``False``/``None``).
The TS and Go legs re-verify the same inputs and must agree.

Deterministic: fixed seed, no clock, sorted output.

    python3 generate_cases.py <repo-root> > cases.json
"""
import base64
import json
import sys
from pathlib import Path

import jcs
from nacl.signing import SigningKey

from ario_proof.canonicalize import canonical_json
from ario_proof.hash import sha256_hex
from ario_proof.envelope import verify_envelope

SEED = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
SK = SigningKey(SEED)
PUB = SK.verify_key.encode().hex()


def sign(env: dict) -> dict:
    """Sign env (which must omit signature) over JCS(env); return complete env."""
    return {**env, "signature": SK.sign(canonical_json(env)).signature.hex()}


def base(extra: dict) -> dict:
    return {
        "spec_version": "ario.agent/v1",
        "event_id": "1f0e9a4c-3b2d-4d5e-8f6a-7b8c9d0e1f2a",
        "signed_at": "2026-06-12T00:00:00Z",
        "public_key": PUB,
        **extra,
    }


def adversarial_cases() -> list[dict]:
    record = {"kind": "external-record", "value": 42}
    record_bytes = canonical_json(record)
    record_hash = sha256_hex(record_bytes)
    inline = sign(base({"payload": record, "payload_hash": record_hash}))
    ext = sign(base({"payload_hash": record_hash}))

    cases = [
        {"id": "adv-inline-valid", "envelope": inline, "payload_bytes": None},
        {"id": "adv-external-signature-only", "envelope": ext, "payload_bytes": None},
        {"id": "adv-external-bound", "envelope": ext, "payload_bytes": record_bytes},
        {"id": "adv-external-wrong-bytes", "envelope": ext, "payload_bytes": b"not the record"},
        # mode confusion: stripping an inline payload breaks the signature
        {
            "id": "adv-fake-external-stripped",
            "envelope": {k: v for k, v in inline.items() if k != "payload"},
            "payload_bytes": None,
        },
        # mode confusion: injecting an unsigned payload into an external envelope
        {"id": "adv-fake-inline-injected", "envelope": {**ext, "payload": {"forged": True}}, "payload_bytes": None},
        # §2: missing payload_hash is a hard reject in every mode
        {"id": "adv-missing-hash-no-material", "envelope": sign(base({})), "payload_bytes": None},
        {"id": "adv-missing-hash-with-bytes", "envelope": sign(base({})), "payload_bytes": b"some bytes"},
        # present hash, no material -> undetermined (not a reject)
        {"id": "adv-present-hash-no-material", "envelope": ext, "payload_bytes": None},
        # inline tamper -> payload mismatch + signature fail
        {
            "id": "adv-inline-tampered",
            "envelope": {**inline, "payload": {"kind": "external-record", "value": 999}},
            "payload_bytes": None,
        },
    ]
    # #13 malformed minors (rejected) and accepted numeric minors
    for v in ["ario.agent/v1.x", "ario.agent/v1.3abc", "ario.agent/v1.", "ario.agent/v10"]:
        cases.append(
            {
                "id": f"adv-badminor::{v}",
                "envelope": sign(base({"payload": record, "payload_hash": record_hash, "spec_version": v})),
                "payload_bytes": None,
            }
        )
    for v in ["ario.agent/v1.3", "ario.agent/v1.10"]:
        cases.append(
            {
                "id": f"adv-okminor::{v}",
                "envelope": sign(base({"payload": record, "payload_hash": record_hash, "spec_version": v})),
                "payload_bytes": None,
            }
        )
    return cases


def corpus_cases(repo_root: Path) -> list[dict]:
    """Reconstruct each corpus envelope vector into a complete signed envelope."""
    vectors_dir = repo_root / "test-vectors"
    cases: list[dict] = []

    # ario.agent/v1 inline vectors (top-level envelope-*.json).
    for path in sorted(vectors_dir.glob("envelope-*.json")):
        v = json.loads(path.read_text())
        pre = v["inputs"]["envelope_pre_signature"]
        out = v["expected_outputs"]
        env = {
            **pre,
            "payload_hash": out["payload_hash_hex"],
            "public_key": v["fixed_keypair"]["ed25519_public_hex"],
            "signature": out["signature_hex"],
        }
        cases.append({"id": f"corpus-{path.stem}", "envelope": env, "payload_bytes": None})

    # ario.events/v1 external-commitment vectors (verified WITH committed bytes).
    events_dir = vectors_dir / "ario.events-v1"
    if events_dir.is_dir():
        for path in sorted(events_dir.glob("events-*.json")):
            v = json.loads(path.read_text())
            out = v["expected_outputs"]
            env = json.loads(bytes.fromhex(out["envelope_jcs_bytes_hex"]))
            record_bytes = bytes.fromhex(out["payload_jcs_bytes_hex"])
            cases.append(
                {
                    "id": f"corpus-events-{path.stem}",
                    "envelope": env,
                    "payload_bytes": record_bytes,
                }
            )
    return cases


def main() -> int:
    repo_root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    cases = corpus_cases(repo_root) + adversarial_cases()

    for c in cases:
        pb = c.pop("payload_bytes")
        # allow_legacy=False everywhere; the events profile is not yet accepted,
        # so its corpus cases verify as rejections — agreement on rejection is
        # still agreement. (Flip to accepted at ratification + re-baseline.)
        res = verify_envelope(c["envelope"], payload_bytes=pb)
        c["py"] = {
            "ok": res.ok,
            "phk": res.payload_hash_ok,
            "sig": res.signature_ok,
            "spec": res.spec_version_ok,
        }
        c["payload_b64"] = base64.b64encode(pb).decode() if pb is not None else None

    json.dump(cases, sys.stdout, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
