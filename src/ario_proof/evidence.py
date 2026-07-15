"""Evidence-bundle + attested-evidence-export verification.

An ``ario.evidence/v1`` bundle is a SIGNED wrapper around a producer-specific
``body`` (``specs/evidence-bundle.md``). This module verifies two bodies:

- ``ario.anchor.trace/v1`` — the ``@ar.io/anchor`` SDK trace: per-event signed
  envelopes + their checkpoints + RFC 9162 inclusion proofs.
- ``ario.evidence.export/v1`` — the issuer-composed **attested evidence export**
  (``specs/evidence-export.md``): a cached §4 verdict + the inline source
  anchor-trace bundle + embedded per-checkpoint RSA-PSS **operator
  attestations**, all under an Ed25519 issuer wrapper. The kernel verifies the
  Ed25519 wrapper AND every embedded RSA-PSS attestation, recomputes the source
  verdict, and confirms it agrees with the cached copy over the deterministic
  dimensions (recompute-don't-trust).

This is the Python sibling of the TS kernel's ``evidence.ts`` — the same
algorithm and the same tri-state semantics, so the two kernels reach
byte-identical verdicts on the same vectors (the cross-kernel export gate). It
composes the existing single-envelope + Merkle primitives
(:mod:`ario_proof.envelope`, :mod:`ario_proof.merkle`) plus the one new
primitive (RSA-PSS record verify, :mod:`ario_proof.rsa_pss`).

Verification never raises on adversarial input: a broken bundle yields a failed
:class:`EvidenceBundleResult`; a structurally unrenderable one yields
``status = "malformed"``.
"""

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from .canonicalize import canonical_json
from .envelope import content_hashes, verify_envelope
from .hash import sha256_hex
from .merkle import leaf_hash, verify_inclusion
from .rsa_pss import (
    MalformedRsaError,
    derive_operator_address,
    verify_rsa_pss_sha256,
)
from .verify import verify_signature

__all__ = [
    "ACCEPTED_EVIDENCE_MAJORS",
    "ANCHOR_TRACE_BODY_TYPE",
    "EXPORT_BODY_TYPE",
    "VERDICT_SCHEMA_VERSION",
    "PerGatewayOutcome",
    "OnChainResult",
    "CheckpointResult",
    "EventResult",
    "AttestationResult",
    "ExportResult",
    "EvidenceBundleResult",
    "verify_evidence_bundle",
]

# The evidence-bundle major(s) this kernel verifies. A new major is a deliberate
# one-entry addition HERE — the same fail-closed discipline as the envelope
# verifier's ACCEPTED_SPEC_VERSIONS.
ACCEPTED_EVIDENCE_MAJORS = frozenset({"ario.evidence/v1"})

# The two body_types this module dispatches. An unknown body_type is not a hard
# WRAPPER failure (signature + body_hash still verify), but its body cannot be
# re-derived, so the per-body verdict is "partial" (undetermined), not verified.
ANCHOR_TRACE_BODY_TYPE = "ario.anchor.trace/v1"
EXPORT_BODY_TYPE = "ario.evidence.export/v1"

VERDICT_SCHEMA_VERSION = "ario.evidence.verdict/v1"


# --------------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------------- #


@dataclass
class PerGatewayOutcome:
    """One gateway's on-chain outcome for one checkpoint tx (§4.2):
    ``confirm`` / ``mismatch`` / ``unreachable``."""

    gateway: str
    outcome: str


@dataclass
class OnChainResult:
    """Per-checkpoint on-chain rollup (§4.2). ``rollup`` is worst-finding-wins
    (mismatch if any gateway mismatch; else confirm if any confirm; else
    unreachable). ``on_chain_ok`` is the retained collapsed boolean."""

    rollup: str
    on_chain_ok: bool | None
    per_gateway: list[PerGatewayOutcome]


@dataclass
class CheckpointResult:
    tx_id: str
    envelope_ok: bool
    merkle_root_ok: bool
    # Collapsed on-chain field; None when no gateway re-fetch was requested.
    on_chain_ok: bool | None
    # Per-gateway on-chain outcomes (§4.2); None when offline-only.
    on_chain: OnChainResult | None
    ok: bool
    errors: list[str]


@dataclass
class EventResult:
    event_id: str
    envelope_ok: bool
    # True bound, False mismatch, None record withheld (undetermined, not a fail).
    payload_binding_ok: bool | None
    inclusion_ok: bool
    checkpoint_bound: bool
    # True matched, False mismatch (fails the event), None undetermined (§4.3).
    content_ok: bool | None
    ok: bool
    errors: list[str]


@dataclass
class AttestationResult:
    checkpoint_tx_id: str
    operator: str
    gateway: str | None
    # RSA-PSS-SHA-256 over JCS(payload) verified (§5 step 6a).
    signature_ok: bool
    # base64url(SHA-256(public_key.n)) == payload.operator (§3.3 / step 6b).
    operator_address_bound: bool
    # payload.data_hash == SHA-256(JCS(checkpoint.envelope)) (§5 step 6c).
    data_hash_bound: bool
    # checkpoint_tx_id resolved to a present source checkpoint.
    checkpoint_resolved: bool
    level: int | None
    # subject_ref (§3.2) tri-state; never gates the attestation.
    subject_ref_ok: bool | None
    ok: bool
    errors: list[str]


@dataclass
class ExportResult:
    # SHA-256(JCS(source_bundle)) == source_bundle_hash (§5 step 3).
    source_linkage_ok: bool
    # Recomputed source-bundle verdict status (§5 step 4).
    source_status: str
    # Cached-vs-recomputed agreement over the DETERMINISTIC dimensions (§5 step 5);
    # the on-chain per-gateway dimension is EXCLUDED.
    verdict_agreement_ok: bool
    attestations: list[AttestationResult]
    # The freshly recomputed §4 verdict object (snake_case dict) — what renderers
    # and the verify API display (never the cached copy).
    verdict: dict[str, Any]
    # The export's own rollup status; drives the CLI exit code.
    status: str


# Exit-3 detection keys off these substrings in the notes (mirrors the TS CLI's
# mapStatusToExit regex): a network-dependent check that could not complete.
_UNDETERMINED_MARKERS = (
    "unreachable",
    "could not be re-fetched",
    "unavailable offline",
)


@dataclass
class EvidenceBundleResult:
    status: str  # verified | partial | failed | malformed
    spec_version_ok: bool
    body_hash_ok: bool
    signature_ok: bool
    body_type: str | None
    on_chain_checked: bool
    checkpoints: list[CheckpointResult]
    events: list[EventResult]
    # The producer's asserted verdict.status (display only — never trusted).
    asserted_status: str | None
    # Present ONLY for an ario.evidence.export/v1 body (§5). Absent (None) for a
    # plain anchor-trace bundle — additive, backward-compatible.
    export: ExportResult | None = None
    errors: list[str] = field(default_factory=list)

    def exit_code(self) -> int:
        """Map the rollup to the pinned CLI exit code 0/1/2/3
        (evidence-export.md §5; identical to the TS CLI's mapStatusToExit).

        - ``failed`` → 1, ``malformed`` → 2.
        - ``partial`` caused by an unreachable gateway / offline-unavailable
          source-bundle-ref → 3 (undetermined, network-dependent).
        - ``verified``, or ``partial`` from a withheld record (semantics-
          undetermined, cryptographically sound) → 0.
        """
        if self.status == "failed":
            return 1
        if self.status == "malformed":
            return 2
        if self.status == "partial" and any(
            marker in e for e in self.errors for marker in _UNDETERMINED_MARKERS
        ):
            return 3
        return 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _matches_evidence_major(spec_version: Any) -> bool:
    """True iff spec_version is an accepted evidence major exactly, or a major
    plus a numeric ``.<minor>`` (envelope-spec §2 token-boundary semantics)."""
    if not isinstance(spec_version, str) or spec_version == "":
        return False
    for major in ACCEPTED_EVIDENCE_MAJORS:
        if spec_version == major:
            return True
        prefix = major + "."
        if spec_version.startswith(prefix):
            minor = spec_version[len(prefix) :]
            if minor and all(c in "0123456789" for c in minor):
                return True
    return False


def _malformed(error: str, spec_version_ok: bool = False) -> EvidenceBundleResult:
    return EvidenceBundleResult(
        status="malformed",
        spec_version_ok=spec_version_ok,
        body_hash_ok=False,
        signature_ok=False,
        body_type=None,
        on_chain_checked=False,
        checkpoints=[],
        events=[],
        asserted_status=None,
        export=None,
        errors=[error],
    )


def _get_event_id(env: Any) -> str:
    if isinstance(env, dict) and isinstance(env.get("event_id"), str):
        return env["event_id"]
    return "<unknown>"


def _hex_to_bytes(h: Any) -> bytes:
    """Strict hex → bytes; raises ValueError on odd length / non-hex."""
    if not isinstance(h, str) or len(h) % 2 != 0:
        raise ValueError("not even-length hex")
    return bytes.fromhex(h)


# --------------------------------------------------------------------------- #
# Public entry point + dispatch
# --------------------------------------------------------------------------- #


def verify_evidence_bundle(
    bundle: Any,
    *,
    gateways: list[str] | None = None,
    content: dict[str, bytes | str] | None = None,
    fetch_impl: Callable[[str], bytes] | None = None,
) -> EvidenceBundleResult:
    """Verify an ``ario.evidence/v1`` bundle (anchor-trace or attested export).

    The producer's asserted ``verdict.status`` is surfaced
    (``asserted_status``) but NEVER trusted — the displayed status is the one
    this function recomputes (evidence-bundle §1 principle 3).

    ``gateways`` + ``fetch_impl`` enable the optional on-chain re-fetch (§4.2):
    ``fetch_impl(url)`` returns the on-chain bytes, or raises / returns ``None``
    for an unreachable gateway. ``content`` maps ``event_id`` → disclosed raw
    bytes (``bytes`` used as-is, ``str`` parsed as lowercase hex) for content
    binding.
    """
    gateways = gateways or []
    content = content or {}

    # --- Step 1: parse + reject unknown spec_version major ---------------------
    if not isinstance(bundle, dict):
        return _malformed("evidence bundle is not a JSON object")
    b = bundle
    spec_version_ok = _matches_evidence_major(b.get("spec_version"))
    if not spec_version_ok:
        return _malformed(
            f"unsupported evidence spec_version: {b.get('spec_version')!r}", False
        )
    signature_alg = b.get("signature_alg")
    if isinstance(signature_alg, str) and signature_alg != "ed25519":
        return _malformed(f"unsupported signature_alg: {signature_alg!r}", True)
    if not isinstance(b.get("public_key"), str) or not isinstance(
        b.get("signature"), str
    ):
        return _malformed("evidence bundle is missing public_key/signature", True)
    if not isinstance(b.get("body_hash"), str):
        return _malformed("evidence bundle is missing body_hash", True)
    if b.get("body") is None:
        return _malformed(
            "evidence bundle has no inline body (body_ref unsupported here)", True
        )

    # --- Step 2: verify the wrapper signature + recompute body_hash ------------
    errors: list[str] = []

    body_hash_ok = False
    try:
        recomputed = sha256_hex(canonical_json(b["body"]))
        body_hash_ok = recomputed == b["body_hash"]
        if not body_hash_ok:
            errors.append(
                f"body_hash mismatch: bundle={b['body_hash']} recomputed={recomputed}"
            )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"body canonicalization failed: {exc}")

    signature_ok = False
    try:
        bundle_for_sig = {
            k: v for k, v in b.items() if k not in ("signature", "co_signatures")
        }
        signature_ok = verify_signature(
            canonical_json(bundle_for_sig), b["signature"], b["public_key"]
        )
        if not signature_ok:
            errors.append("wrapper Ed25519 signature verification failed")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"wrapper signature verification error: {exc}")

    verdict = b.get("verdict")
    asserted_status = (
        verdict.get("status")
        if isinstance(verdict, dict) and isinstance(verdict.get("status"), str)
        else None
    )

    body_type = b.get("body_type") if isinstance(b.get("body_type"), str) else None

    # A broken wrapper (bad signature or tampered body) is a hard failure — the
    # body is untrustworthy, so we do not pretend to verify its contents.
    if not signature_ok or not body_hash_ok:
        return EvidenceBundleResult(
            status="failed",
            spec_version_ok=spec_version_ok,
            body_hash_ok=body_hash_ok,
            signature_ok=signature_ok,
            body_type=body_type,
            on_chain_checked=False,
            checkpoints=[],
            events=[],
            asserted_status=asserted_status,
            export=None,
            errors=errors,
        )

    # --- Body dispatch ---------------------------------------------------------
    if body_type == EXPORT_BODY_TYPE:
        return _verify_export_body(
            b, spec_version_ok, asserted_status, errors, gateways, content, fetch_impl
        )

    if body_type != ANCHOR_TRACE_BODY_TYPE:
        errors.append(
            f"body_type {body_type!r} is not verifiable by this kernel "
            f"(only {ANCHOR_TRACE_BODY_TYPE}); wrapper verified, body undetermined"
        )
        return EvidenceBundleResult(
            status="partial",
            spec_version_ok=spec_version_ok,
            body_hash_ok=True,
            signature_ok=True,
            body_type=body_type,
            on_chain_checked=False,
            checkpoints=[],
            events=[],
            asserted_status=asserted_status,
            export=None,
            errors=errors,
        )

    return _verify_anchor_trace(
        b,
        body_type,
        spec_version_ok,
        asserted_status,
        errors,
        gateways,
        content,
        fetch_impl,
    )


# --------------------------------------------------------------------------- #
# ario.anchor.trace/v1 body
# --------------------------------------------------------------------------- #


def _verify_anchor_trace(
    b: dict,
    body_type: str,
    spec_version_ok: bool,
    asserted_status: str | None,
    errors: list[str],
    gateways: list[str],
    content: dict[str, bytes | str],
    fetch_impl: Callable[[str], bytes] | None,
) -> EvidenceBundleResult:
    body = b["body"]
    if not isinstance(body.get("checkpoints"), list) or not isinstance(
        body.get("events"), list
    ):
        return _malformed(
            "ario.anchor.trace/v1 body must have checkpoints[] and events[]", True
        )

    on_chain_checked = len(gateways) > 0

    # --- per-checkpoint --------------------------------------------------------
    by_tx_id: dict[str, dict] = {}
    checkpoint_results: list[CheckpointResult] = []
    for cp in body["checkpoints"]:
        cp_errors: list[str] = []
        envelope_ok = False
        merkle_root_ok = False

        tx_id = cp.get("tx_id")
        if not isinstance(tx_id, str):
            cp_errors.append("checkpoint missing tx_id")
        elif tx_id in by_tx_id:
            cp_errors.append(f"duplicate checkpoint tx_id {tx_id}")
        else:
            by_tx_id[tx_id] = cp

        record_bytes: bytes | None = None
        try:
            if isinstance(cp.get("record_bytes"), str):
                record_bytes = _hex_to_bytes(cp["record_bytes"])
        except Exception as exc:  # noqa: BLE001
            cp_errors.append(f"checkpoint record_bytes is not hex: {exc}")

        try:
            res = verify_envelope(cp.get("envelope"), payload_bytes=record_bytes)
            envelope_ok = res.ok and res.payload_hash_ok is True
            if not res.signature_ok:
                cp_errors.append("checkpoint envelope signature failed")
            if res.payload_hash_ok is False:
                cp_errors.append("checkpoint record does not bind to payload_hash")
            if res.payload_hash_ok is None:
                cp_errors.append("checkpoint record_bytes missing — root untrusted")
        except Exception as exc:  # noqa: BLE001
            cp_errors.append(f"checkpoint envelope verify error: {exc}")

        if record_bytes is not None:
            try:
                record = json.loads(record_bytes)
                committed_root = (
                    record.get("event", {}).get("merkle_root")
                    if isinstance(record, dict)
                    and isinstance(record.get("event"), dict)
                    else None
                )
                merkle_root_ok = isinstance(
                    committed_root, str
                ) and committed_root == cp.get("merkle_root")
                if not merkle_root_ok:
                    cp_errors.append(
                        f"checkpoint merkle_root mismatch: claimed={cp.get('merkle_root')} "
                        f"committed={committed_root}"
                    )
            except Exception as exc:  # noqa: BLE001
                cp_errors.append(f"checkpoint record is not JSON: {exc}")

        checkpoint_results.append(
            CheckpointResult(
                tx_id=tx_id if isinstance(tx_id, str) else "",
                envelope_ok=envelope_ok,
                merkle_root_ok=merkle_root_ok,
                on_chain_ok=None,
                on_chain=None,
                ok=envelope_ok and merkle_root_ok,
                errors=cp_errors,
            )
        )

    # --- per-event -------------------------------------------------------------
    event_results: list[EventResult] = []
    for ev in body["events"]:
        ev_errors: list[str] = []
        event_id = _get_event_id(ev.get("envelope"))
        envelope_ok = False
        payload_binding_ok: bool | None = None

        record_bytes = None
        try:
            if isinstance(ev.get("record_bytes"), str):
                record_bytes = _hex_to_bytes(ev["record_bytes"])
        except Exception as exc:  # noqa: BLE001
            ev_errors.append(f"event record_bytes is not hex: {exc}")

        try:
            res = verify_envelope(ev.get("envelope"), payload_bytes=record_bytes)
            envelope_ok = res.ok  # tolerates an undetermined binding (withheld record)
            payload_binding_ok = res.payload_hash_ok
            if not res.signature_ok:
                ev_errors.append("event envelope signature failed")
            if res.payload_hash_ok is False:
                ev_errors.append("event record does not bind to payload_hash")
        except Exception as exc:  # noqa: BLE001
            ev_errors.append(f"event envelope verify error: {exc}")

        incl = ev.get("inclusion")
        cp = (
            by_tx_id.get(incl.get("checkpoint_tx_id"))
            if isinstance(incl, dict) and isinstance(incl.get("checkpoint_tx_id"), str)
            else None
        )
        checkpoint_bound = cp is not None
        if not isinstance(incl, dict):
            ev_errors.append("event missing inclusion proof")
        elif not checkpoint_bound:
            ev_errors.append(
                f"event inclusion.checkpoint_tx_id "
                f"{incl.get('checkpoint_tx_id')!r} resolves to no checkpoint"
            )

        inclusion_ok = False
        if isinstance(incl, dict) and checkpoint_bound and cp is not None:
            try:
                inclusion_ok = verify_inclusion(
                    _hex_to_bytes(incl.get("leaf_hash")),
                    incl.get("leaf_index"),
                    incl.get("leaf_count"),
                    [_hex_to_bytes(h) for h in (incl.get("audit_path") or [])],
                    _hex_to_bytes(cp.get("merkle_root")),
                )
                if not inclusion_ok:
                    ev_errors.append(
                        "RFC 9162 inclusion proof did not reconstruct the checkpoint root"
                    )
                # Defense in depth: the claimed leaf_hash MUST be the hash of the
                # event's own signed envelope bytes — otherwise a valid inclusion
                # proof for an UNRELATED leaf could be smuggled in.
                expected_leaf_hex = leaf_hash(canonical_json(ev.get("envelope"))).hex()
                if expected_leaf_hex != (incl.get("leaf_hash") or "").lower():
                    inclusion_ok = False
                    ev_errors.append(
                        "inclusion leaf_hash does not match SHA-256(0x00 || JCS(event envelope))"
                    )
            except Exception as exc:  # noqa: BLE001
                ev_errors.append(f"inclusion verify error: {exc}")

        content_ok = _evaluate_content(ev, record_bytes, event_id, content, ev_errors)

        event_results.append(
            EventResult(
                event_id=event_id,
                envelope_ok=envelope_ok,
                payload_binding_ok=payload_binding_ok,
                inclusion_ok=inclusion_ok,
                checkpoint_bound=checkpoint_bound,
                content_ok=content_ok,
                ok=envelope_ok
                and inclusion_ok
                and checkpoint_bound
                and content_ok is not False,
                errors=ev_errors,
            )
        )

    # --- optional on-chain re-fetch --------------------------------------------
    gateway_unavailable = False
    if on_chain_checked:
        if not callable(fetch_impl):
            gateway_unavailable = True
            errors.append(
                "on-chain re-fetch requested but no fetch implementation is available"
            )
        else:
            for cpr in checkpoint_results:
                cp = by_tx_id.get(cpr.tx_id)
                if cp is None:
                    continue
                on_chain, unavailable, error = _refetch_checkpoint(
                    cp, gateways, fetch_impl
                )
                cpr.on_chain = on_chain
                cpr.on_chain_ok = on_chain.on_chain_ok
                if unavailable:
                    gateway_unavailable = True
                if error:
                    cpr.errors.append(error)
                cpr.ok = (
                    cpr.envelope_ok
                    and cpr.merkle_root_ok
                    and cpr.on_chain_ok is not False
                )

    # --- rollup ----------------------------------------------------------------
    all_checkpoints_ok = len(checkpoint_results) > 0 and all(
        c.ok for c in checkpoint_results
    )
    all_events_ok = all(e.ok for e in event_results)
    any_hard_failure = any(not c.ok for c in checkpoint_results) or any(
        not e.ok for e in event_results
    )
    any_withheld_record = any(e.payload_binding_ok is None for e in event_results)

    if any_hard_failure:
        status = "failed"
    elif gateway_unavailable:
        status = "partial"
        errors.append(
            "one or more checkpoints could not be re-fetched from the supplied gateways"
        )
    elif any_withheld_record:
        status = "partial"
    elif all_checkpoints_ok and all_events_ok:
        status = "verified"
    else:
        status = "partial"

    return EvidenceBundleResult(
        status=status,
        spec_version_ok=spec_version_ok,
        body_hash_ok=True,
        signature_ok=True,
        body_type=body_type,
        on_chain_checked=on_chain_checked,
        checkpoints=checkpoint_results,
        events=event_results,
        asserted_status=asserted_status,
        export=None,
        errors=errors,
    )


def _evaluate_content(
    ev: dict,
    record_bytes: bytes | None,
    event_id: str,
    side_content: dict[str, bytes | str],
    ev_errors: list[str],
) -> bool | None:
    """Content (raw-log) binding, tri-state (§4.3). Committed hash comes from the
    RECORD (record.event.content_hash), else the envelope's committed hashes.
    Disclosed bytes come from in-body ``ev.content`` FIRST, then the side input.
    None when nothing disclosed or nothing committed; False only on a real
    mismatch or an in-body-vs-side-input disagreement."""
    committed: list[str] = []
    record_content_hash: str | None = None
    if record_bytes is not None:
        try:
            record = json.loads(record_bytes)
            ch = (
                record.get("event", {}).get("content_hash")
                if isinstance(record, dict) and isinstance(record.get("event"), dict)
                else None
            )
            if isinstance(ch, str) and ch:
                record_content_hash = ch.lower()
        except Exception:  # noqa: BLE001
            pass
    if record_content_hash is not None:
        committed.append(record_content_hash)
    elif isinstance(ev.get("envelope"), dict):
        for _role, h in content_hashes(ev["envelope"]):
            committed.append(h.lower())

    in_body: bytes | None = None
    if isinstance(ev.get("content"), str):
        try:
            in_body = _hex_to_bytes(ev["content"])
        except Exception as exc:  # noqa: BLE001
            ev_errors.append(f"event content is not hex: {exc}")

    side: bytes | None = None
    side_raw = side_content.get(event_id)
    if isinstance(side_raw, (bytes, bytearray)):
        side = bytes(side_raw)
    elif isinstance(side_raw, str):
        try:
            side = _hex_to_bytes(side_raw)
        except Exception as exc:  # noqa: BLE001
            ev_errors.append(f"supplied content for {event_id} is not hex: {exc}")

    if in_body is not None and side is not None and in_body != side:
        ev_errors.append(
            "disclosed content disagreement: in-body events[].content and the supplied content differ"
        )
        return False

    disclosed = in_body if in_body is not None else side
    if disclosed is None or len(committed) == 0:
        if disclosed is not None and len(committed) == 0:
            ev_errors.append(
                "disclosed content present but no committed content_hash to bind to "
                "(record withheld or record has no event.content_hash) — undetermined"
            )
        return None
    got = sha256_hex(disclosed)
    if got in committed:
        return True
    ev_errors.append(
        "disclosed content does not match the committed content_hash: "
        f"sha256(disclosed)={got} committed={'|'.join(committed)}"
    )
    return False


# --------------------------------------------------------------------------- #
# ario.evidence.export/v1 body (evidence-export.md §5, steps 3–9)
# --------------------------------------------------------------------------- #


def _verify_export_body(
    b: dict,
    spec_version_ok: bool,
    asserted_status: str | None,
    errors: list[str],
    gateways: list[str],
    content: dict[str, bytes | str],
    fetch_impl: Callable[[str], bytes] | None,
) -> EvidenceBundleResult:
    def export_malformed(error: str) -> EvidenceBundleResult:
        # Malformed-as-an-export (§5 exit 2): the wrapper verified (fields stay
        # true) but no verdict can be rendered.
        return EvidenceBundleResult(
            status="malformed",
            spec_version_ok=spec_version_ok,
            body_hash_ok=True,
            signature_ok=True,
            body_type=EXPORT_BODY_TYPE,
            on_chain_checked=False,
            checkpoints=[],
            events=[],
            asserted_status=asserted_status,
            export=None,
            errors=[*errors, error],
        )

    body = b["body"]
    if not isinstance(body, dict):
        return export_malformed("export body is not a JSON object")
    if not isinstance(body.get("source_bundle_hash"), str):
        return export_malformed("export body missing source_bundle_hash")
    if not isinstance(body.get("attestations"), list):
        return export_malformed("export body missing attestations[]")
    if not isinstance(body.get("kernel_verdict"), dict):
        return export_malformed("export body missing kernel_verdict")

    # --- Step 3: source-bundle linkage -----------------------------------------
    inline = body.get("source_bundle")
    if inline is None:
        # source_bundle_ref (out-of-line) is not verifiable on a network-isolated
        # machine — the source-dependent checks are UNDETERMINED (exit 3).
        return EvidenceBundleResult(
            status="partial",
            spec_version_ok=spec_version_ok,
            body_hash_ok=True,
            signature_ok=True,
            body_type=EXPORT_BODY_TYPE,
            on_chain_checked=False,
            checkpoints=[],
            events=[],
            asserted_status=asserted_status,
            export=None,
            errors=[
                *errors,
                "source_bundle is not inline (source_bundle_ref) — bytes unavailable "
                "offline; source-dependent checks undetermined",
            ],
        )

    source_linkage_ok = False
    try:
        recomputed = sha256_hex(canonical_json(inline))
        source_linkage_ok = recomputed == body["source_bundle_hash"]
        if not source_linkage_ok:
            errors.append(
                f"source_bundle_hash mismatch: body={body['source_bundle_hash']} "
                f"recomputed={recomputed}"
            )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"source_bundle canonicalization failed: {exc}")

    # --- Step 4: recompute the source verdict ----------------------------------
    source_result = verify_evidence_bundle(
        inline, gateways=gateways, content=content, fetch_impl=fetch_impl
    )

    # Map source checkpoints by tx_id for attestation data_hash binding (§5 6c).
    source_checkpoints: dict[str, dict] = {}
    sb = inline.get("body") if isinstance(inline, dict) else None
    if isinstance(sb, dict) and isinstance(sb.get("checkpoints"), list):
        for cp in sb["checkpoints"]:
            if isinstance(cp, dict) and isinstance(cp.get("tx_id"), str):
                source_checkpoints[cp["tx_id"]] = cp

    # --- Step 6: embedded attestation records ----------------------------------
    attestations: list[AttestationResult] = []
    for rec in body["attestations"]:
        result, malformed_msg = _verify_attestation(rec, source_checkpoints)
        if malformed_msg is not None:
            return export_malformed(malformed_msg)
        attestations.append(result)

    # --- Build the recomputed §4 verdict object --------------------------------
    verdict = _build_verdict_object(source_result, attestations)
    if isinstance(b.get("generated_at"), str):
        verdict["as_of"] = b["generated_at"]

    # --- Step 5: verdict agreement (DETERMINISTIC dimensions only) --------------
    verdict_agreement_ok = False
    try:
        cached_projection = canonical_json(
            _project_verdict_for_agreement(body["kernel_verdict"])
        )
        fresh_projection = canonical_json(_project_verdict_for_agreement(verdict))
        verdict_agreement_ok = cached_projection == fresh_projection
        if not verdict_agreement_ok:
            errors.append(
                "recomputed verdict disagrees with the cached kernel_verdict "
                "(deterministic dimensions) — recompute-don't-trust"
            )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"verdict agreement comparison failed: {exc}")

    # Propagate the source recompute's notes so the auditor — and the exit-3
    # detection (which keys off "unreachable") — see them.
    for e in source_result.errors:
        errors.append(f"source: {e}")

    # --- Step 9: export rollup + exit ------------------------------------------
    any_attestation_failed = any(not a.ok for a in attestations)
    if (
        not source_linkage_ok
        or not verdict_agreement_ok
        or source_result.status in ("failed", "malformed")
        or any_attestation_failed
    ):
        status = "failed"
    elif source_result.status == "partial":
        status = "partial"
    else:
        status = "verified"

    # The DISPLAYED verdict reflects the full recompute (incl. attestations).
    verdict["status"] = status
    verdict["summary"] = _summarize_export(status, source_result, attestations)

    return EvidenceBundleResult(
        status=status,
        spec_version_ok=spec_version_ok,
        body_hash_ok=True,
        signature_ok=True,
        body_type=EXPORT_BODY_TYPE,
        on_chain_checked=source_result.on_chain_checked,
        # The top-level per-checkpoint / per-event results ARE the recomputed
        # source results.
        checkpoints=source_result.checkpoints,
        events=source_result.events,
        asserted_status=asserted_status,
        export=ExportResult(
            source_linkage_ok=source_linkage_ok,
            source_status=source_result.status,
            verdict_agreement_ok=verdict_agreement_ok,
            attestations=attestations,
            verdict=verdict,
            status=status,
        ),
        errors=errors,
    )


def _verify_attestation(
    rec: Any, source_checkpoints: dict[str, dict]
) -> tuple[AttestationResult, str | None]:
    """Verify one embedded attestation record (§5 step 6a–d). Returns
    ``(result, malformed_msg)``: ``malformed_msg`` non-None (→ exit 2) for an
    unparseable RSA key / signature hex or a missing required field; otherwise
    a per-dimension result whose ``ok`` gates on sig / operator-address /
    data_hash bindings + checkpoint resolution. subject_ref never gates."""
    errs: list[str] = []
    result = AttestationResult(
        checkpoint_tx_id=(
            rec["checkpoint_tx_id"]
            if isinstance(rec, dict) and isinstance(rec.get("checkpoint_tx_id"), str)
            else ""
        ),
        operator="",
        gateway=None,
        signature_ok=False,
        operator_address_bound=False,
        data_hash_bound=False,
        checkpoint_resolved=False,
        level=None,
        subject_ref_ok=None,
        ok=False,
        errors=errs,
    )

    if not isinstance(rec, dict):
        return result, "attestation record is not a JSON object"
    payload = rec.get("payload")
    if not isinstance(payload, dict):
        return result, "attestation record missing payload"
    if rec.get("signature_alg") != "rsa-pss-sha256":
        return (
            result,
            f"unsupported attestation signature_alg: {rec.get('signature_alg')!r}",
        )
    pub = rec.get("public_key")
    if (
        not isinstance(pub, dict)
        or pub.get("kty") != "RSA"
        or not isinstance(pub.get("n"), str)
        or not isinstance(pub.get("e"), str)
    ):
        return result, "attestation record missing/invalid RSA public_key JWK"
    if not isinstance(rec.get("signature"), str):
        return result, "attestation record missing signature"

    result.operator = (
        payload["operator"] if isinstance(payload.get("operator"), str) else ""
    )
    result.gateway = (
        payload["gateway"] if isinstance(payload.get("gateway"), str) else None
    )
    result.level = (
        payload["level"]
        if isinstance(payload.get("level"), int)
        and not isinstance(payload.get("level"), bool)
        else None
    )

    # (a) RSA-PSS-SHA-256 signature over JCS(payload).
    try:
        payload_bytes = canonical_json(payload)
    except Exception as exc:  # noqa: BLE001
        return result, f"attestation payload canonicalization failed: {exc}"
    try:
        result.signature_ok = verify_rsa_pss_sha256(
            payload_bytes, rec["signature"], pub
        )
        if not result.signature_ok:
            errs.append("attestation RSA-PSS signature verification failed")
    except MalformedRsaError as exc:
        return result, f"attestation {exc}"

    # (b) operator-address binding: base64url(SHA-256(modulus)) == payload.operator.
    try:
        derived = derive_operator_address(pub["n"])
        result.operator_address_bound = (
            result.operator != "" and derived == result.operator
        )
        if not result.operator_address_bound:
            errs.append(
                f"operator-address binding failed: derived={derived} "
                f"payload.operator={result.operator}"
            )
    except MalformedRsaError as exc:
        return result, f"attestation operator key: {exc}"

    # (c) checkpoint resolution + data_hash binding: data IS the uploaded
    # JCS(envelope) bytes, so the committed content hash is SHA-256(JCS(envelope)).
    cp = source_checkpoints.get(result.checkpoint_tx_id)
    result.checkpoint_resolved = cp is not None
    if cp is None:
        errs.append(
            f"attestation checkpoint_tx_id {result.checkpoint_tx_id!r} "
            "resolves to no source checkpoint"
        )
    else:
        try:
            committed = sha256_hex(canonical_json(cp.get("envelope")))
            data_hash = (
                payload["data_hash"].lower()
                if isinstance(payload.get("data_hash"), str)
                else ""
            )
            result.data_hash_bound = data_hash != "" and data_hash == committed
            if not result.data_hash_bound:
                errs.append(
                    "data_hash does not bind to the checkpoint's committed content hash: "
                    f"data_hash={data_hash} committed={committed}"
                )
        except Exception as exc:  # noqa: BLE001
            errs.append(f"cannot recompute checkpoint content hash: {exc}")

    # (d) subject_ref (§3.2) — well-formedness only; undetermined (None).
    result.subject_ref_ok = _evaluate_subject_ref(payload.get("subject_ref"), errs)

    result.ok = (
        result.signature_ok
        and result.operator_address_bound
        and result.data_hash_bound
        and result.checkpoint_resolved
    )
    return result, None


def _evaluate_subject_ref(subject_ref: Any, errs: list[str]) -> bool | None:
    """subject_ref (§3.2): absent → None (unbound). Present + well-formed but no
    side-input subject → None (undetermined). Present + malformed → None + a
    surfaced note. Never gates the attestation."""
    if subject_ref is None:
        return None
    if not isinstance(subject_ref, dict):
        errs.append("subject_ref is present but is not an object")
        return None
    h = subject_ref.get("hash")
    t = subject_ref.get("type")
    hash_ok = isinstance(h, str) and _is_sha256_hex(h)
    type_ok = isinstance(t, str) and _is_subject_type_token(t)
    if not hash_ok or not type_ok:
        errs.append(
            "subject_ref is present but not well-formed ({hash: sha256-hex, type: token})"
        )
        return None
    return None  # well-formed, no side input → undetermined


def _is_sha256_hex(s: str) -> bool:
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def _is_subject_type_token(s: str) -> bool:
    # Strict-ASCII, mirroring the TS regex ^[a-z0-9.:-]+$ exactly (subject_ref_ok
    # is always tri-state None either way — this only shapes the surfaced note).
    return len(s) > 0 and all(c in "0123456789abcdefghijklmnopqrstuvwxyz.:-" for c in s)


# --------------------------------------------------------------------------- #
# §4 verdict object (snake_case dict — the computed wire)
# --------------------------------------------------------------------------- #


def _build_verdict_object(
    source: EvidenceBundleResult, attestations: list[AttestationResult]
) -> dict[str, Any]:
    att_by_checkpoint: dict[str, list[dict]] = {}
    for a in attestations:
        entry: dict[str, Any] = {"operator": a.operator}
        if a.gateway:
            entry["gateway"] = a.gateway
        entry["signature_ok"] = a.signature_ok
        entry["operator_address_bound"] = a.operator_address_bound
        entry["data_hash_bound"] = a.data_hash_bound
        if a.level is not None:
            entry["level"] = a.level
        entry["subject_ref_ok"] = a.subject_ref_ok
        att_by_checkpoint.setdefault(a.checkpoint_tx_id, []).append(entry)

    events = [
        {
            "event_id": e.event_id,
            "signature_ok": e.envelope_ok,
            "payload_bound": e.payload_binding_ok,
            "inclusion_ok": e.inclusion_ok,
            "content_ok": e.content_ok,
            "status": _event_verdict_status(e),
        }
        for e in source.events
    ]

    checkpoints = [
        {
            "checkpoint_tx_id": c.tx_id,
            "merkle_root_ok": c.merkle_root_ok,
            "on_chain": _to_verdict_on_chain(c.on_chain) if c.on_chain else None,
            "attestations": att_by_checkpoint.get(c.tx_id, []),
        }
        for c in source.checkpoints
    ]

    verified = 0
    failed = 0
    undetermined = 0
    for e in events:
        if e["status"] == "failed":
            failed += 1
        elif e["status"] == "verified":
            verified += 1
        else:
            undetermined += 1
    for a in attestations:
        if a.ok:
            verified += 1
        else:
            failed += 1

    return {
        "schema_version": VERDICT_SCHEMA_VERSION,
        "status": "failed" if source.status == "malformed" else source.status,
        "counts": {
            "verified": verified,
            "failed": failed,
            "undetermined": undetermined,
        },
        "events": events,
        "checkpoints": checkpoints,
        "custody_chain": None,
    }


def _to_verdict_on_chain(o: OnChainResult) -> dict[str, Any]:
    return {
        "rollup": o.rollup,
        "on_chain_ok": o.on_chain_ok,
        "per_gateway": [
            {"gateway": g.gateway, "outcome": g.outcome} for g in o.per_gateway
        ],
    }


def _event_verdict_status(e: EventResult) -> str:
    if not e.ok:
        return "failed"
    if e.payload_binding_ok is None:
        return "partial"  # withheld record — undetermined
    return "verified"


def _project_verdict_for_agreement(v: Any) -> dict[str, Any]:
    """The §5 step-5 agreement projection: strip every environment/time-dependent
    and derived dimension, leaving only what an offline verifier deterministically
    recomputes. Tolerant of a hostile/garbled cached verdict (a structural
    difference surfaces as disagreement — the correct tamper signal). Works on
    both the cached snake_case dict and the freshly built verdict."""
    o = v if isinstance(v, dict) else {}
    events = o.get("events") if isinstance(o.get("events"), list) else []
    checkpoints = o.get("checkpoints") if isinstance(o.get("checkpoints"), list) else []
    return {
        "schema_version": (
            o.get("schema_version")
            if isinstance(o.get("schema_version"), str)
            else None
        ),
        "events": [
            {
                "event_id": _g(e, "event_id"),
                "signature_ok": _g(e, "signature_ok"),
                "payload_bound": _g(e, "payload_bound"),
                "inclusion_ok": _g(e, "inclusion_ok"),
                "content_ok": _g(e, "content_ok"),
            }
            for e in events
        ],
        "checkpoints": [
            {
                "checkpoint_tx_id": _g(c, "checkpoint_tx_id"),
                "merkle_root_ok": _g(c, "merkle_root_ok"),
                # on_chain DELIBERATELY OMITTED — environment/time-dependent.
                "attestations": [
                    {
                        "operator": _g(a, "operator"),
                        "signature_ok": _g(a, "signature_ok"),
                        "operator_address_bound": _g(a, "operator_address_bound"),
                        "data_hash_bound": _g(a, "data_hash_bound"),
                        "subject_ref_ok": _g(a, "subject_ref_ok"),
                    }
                    for a in (
                        c.get("attestations")
                        if isinstance(c, dict)
                        and isinstance(c.get("attestations"), list)
                        else []
                    )
                ],
            }
            for c in checkpoints
        ],
    }


def _g(d: Any, key: str) -> Any:
    """Nullish get: the value if the mapping has it (including False/None),
    else None — mirroring the TS ``?? null`` normalization."""
    return d.get(key) if isinstance(d, dict) else None


def _summarize_export(
    status: str, source: EvidenceBundleResult, attestations: list[AttestationResult]
) -> str:
    att_ok = sum(1 for a in attestations if a.ok)
    return (
        f"Export {status}: source bundle {source.status} "
        f"({len(source.events)} event(s) across {len(source.checkpoints)} checkpoint(s)); "
        f"{att_ok}/{len(attestations)} operator attestation(s) valid."
    )


# --------------------------------------------------------------------------- #
# Optional on-chain re-fetch (§4.2)
# --------------------------------------------------------------------------- #


def _refetch_checkpoint(
    cp: dict, gateways: list[str], fetch_impl: Callable[[str], bytes]
) -> tuple[OnChainResult, bool, str | None]:
    try:
        expected_hex: str | None = canonical_json(cp.get("envelope")).hex()
    except Exception:  # noqa: BLE001
        expected_hex = None

    per_gateway = [
        PerGatewayOutcome(gw, _probe_gateway(cp, gw, expected_hex, fetch_impl))
        for gw in gateways
    ]
    on_chain = _rollup_on_chain(per_gateway)
    error: str | None = None
    if on_chain.rollup == "mismatch":
        error = f"on-chain bytes at {cp.get('tx_id')} do not match the bundle's checkpoint envelope"
    elif on_chain.rollup == "unreachable":
        error = f"checkpoint {cp.get('tx_id')} unreachable on all gateways"
    return on_chain, on_chain.rollup == "unreachable", error


def _probe_gateway(
    cp: dict, gateway: str, expected_hex: str | None, fetch_impl: Callable[[str], bytes]
) -> str:
    url = gateway.rstrip("/") + "/" + str(cp.get("tx_id", ""))
    try:
        on_chain_bytes = fetch_impl(url)
    except Exception:  # noqa: BLE001
        return "unreachable"
    if on_chain_bytes is None:
        return "unreachable"
    if expected_hex is None:
        return "mismatch"
    if on_chain_bytes.hex() == expected_hex:
        return "confirm"
    try:
        parsed = json.loads(on_chain_bytes)
        if canonical_json(parsed).hex() == expected_hex:
            return "confirm"
    except Exception:  # noqa: BLE001
        pass
    return "mismatch"


def _rollup_on_chain(per_gateway: list[PerGatewayOutcome]) -> OnChainResult:
    rollup = "unreachable"
    if any(g.outcome == "mismatch" for g in per_gateway):
        rollup = "mismatch"
    elif any(g.outcome == "confirm" for g in per_gateway):
        rollup = "confirm"
    on_chain_ok: bool | None = (
        False if rollup == "mismatch" else True if rollup == "confirm" else None
    )
    return OnChainResult(
        rollup=rollup, on_chain_ok=on_chain_ok, per_gateway=per_gateway
    )
