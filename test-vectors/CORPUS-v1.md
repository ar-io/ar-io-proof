# Conformance corpus — v1.0 (+ v1.1, v1.2, v1.3 additive sets)

> **Corpus tag: `test-vectors-v1.0`**, extended additively by **`test-vectors-v1.1`** (the `ario.events/v1` set in [§ Contents added at v1.1](#contents-added-at-v11)), **`test-vectors-v1.2`** (the chained two-checkpoint vector + must-reject `negatives/` in [§ Contents added at v1.2](#contents-added-at-v12)), and **`test-vectors-v1.3`** (the attested-evidence-export set in [§ Contents added at v1.3](#contents-added-at-v13)). Locked at the standards ratification of 2026-06-10 per [`docs/stack/governance.md`](../docs/stack/governance.md) §4: corpus changes from here are minor bumps (`test-vectors-v1.x`); any change to the bytes of a file listed below is major (`test-vectors-v2.0`, 30-day RFC). Every conformant downstream pins a corpus tag and records which. Each minor is **purely additive** — every earlier vector is byte-unchanged, so an older pin stays valid; downstreams adopt a newer tag only to gate the vectors it adds.

## Scope

This corpus is the **`ario.agent/v1` profile vectors** (signed-envelope + RFC-9162 Merkle), generated — never hand-edited — by `tools/gen-vectors/gen_vectors.py` from a fixed Ed25519 seed, in the [`docs/artifact.md` §15](../docs/artifact.md) file format. It is the agent half of the family conformance suite defined in [`docs/envelope-spec.md` §6](../docs/envelope-spec.md) (ratified v1.0); the mlflow-profile half (external-commitment envelopes exercised by the bidirectional cross-product tests) lives in the sibling `ar-io-mlflow` repo. A kernel is conformant for the modes it accepts iff it reproduces its pinned corpus byte-for-byte ([`docs/stack/architecture.md`](../docs/stack/architecture.md) K3).

## Contents at v1.0 (14 files)

| File | SHA-256 |
|---|---|
| `envelope-asset-missing-01.json` | `fecb29289df2b6ea210b51737e6cdf10438ec996add050b053247cc567fe2e27` |
| `envelope-asset-registered-01.json` | `3b99fc850edba7775a4df970e406fcb2d787fc10594cd7f969936938b881b9a9` |
| `envelope-key-retired-01.json` | `2e89bc2b1986e3545d0aae94f850d675f9f16fc384b311cc75090a5e275eaf33` |
| `envelope-policy-changed-01.json` | `62a460fb4e0e49c2ef28acc73ddea1163f801ccef6c0e247679e65e6c655509c` |
| `envelope-tamper-detected-01.json` | `5f4b8b1dab9c50ca97ff0349e39481ee33f9a19991632d13fb71fd940a88fcd0` |
| `envelope-verification-checkpoint-01.json` | `393c04e411807481587c591ccb1e637cb072f40940cbc9d25e53dd29253bb56d` |
| `merkle-tree-00-leaves.json` | `705adf82ce9cc46d0e45fce216cb205d5755e2d41975b66444f1765a982faa95` |
| `merkle-tree-01-leaves.json` | `bdbb57ad29272054c5dcc655c2279c4debec9c4c67ea85f17490760a19b52923` |
| `merkle-tree-02-leaves.json` | `9c33d0fcb57655729a0e657b8b4313de806e397949465d310338db5dd56a573b` |
| `merkle-tree-03-leaves.json` | `f4cc12cd11cb3a49225edff2c18ab9f516992f8d6c13e7baadb627f1c7efe8eb` |
| `merkle-tree-07-leaves.json` | `8372c63f3d5a61c8dfc0939fb5776b8041960313df4f9334e620d398326bdd1c` |
| `merkle-tree-1024-leaves.json` | `e732c755539b84e20b80d15e5a7989e2d6736153d9d78c944ed6e7ee98627254` |
| `merkle-tree-16-leaves.json` | `b58b31340bef317fd32734be7e3ff58b0d4a4d0cb03a7b16f08056161c7ae72c` |
| `README.md` | `7d21d23fcbf9996e9e7a710099bb59b4cb501720ded57aac65edde43de10ef44` |

One envelope vector per `ario.agent/v1` event type (six), plus Merkle trees at leaf counts 0, 1, 2, 3, 7, 16, and 1024 (each with inclusion proofs).

## Contents added at v1.1

> **Corpus tag: `test-vectors-v1.1`** — additive over v1.0. The **`ario.events/v1` profile vectors** (the Anchoring SDK's profile, `@ar.io/anchor` / sibling repo `ar-io-anchor`; registered *proposed* in [`specs/envelope-spec.md`](../specs/envelope-spec.md) §4 at v1.2), homed in the `ario.events-v1/` subdirectory. This profile is **Minimal disclosure + external commitment**: the committed payload is a caller-retained `event_record` whose canonical bytes stay off-chain, so the on-wire envelope carries only its `payload_hash` and a `payload_ref` locator. Because the profile is `proposed` and not in any accept-set, conformant kernels gate these vectors at the **primitive level** (JCS canonical bytes + SHA-256 payload hash + Ed25519 + RFC 9162 Merkle), never through the full profile accept-gate.

| File | SHA-256 |
|---|---|
| `ario.events-v1/events-event-01.json` | `ac4f81cf4be28da92ac49fe2461084598dde876a28d252bf997005f34b8903e4` |
| `ario.events-v1/events-event-02.json` | `d1ab4b6f3cb6ab1f5f33e345a2c6f80c99bedbf10c9ec482ff8a45279e49fb27` |
| `ario.events-v1/events-checkpoint-01.json` | `ae133294320974611c3952befa7f09ac58e6236027bd59cc82f5ab4f01d4bc12` |

Two unchained event vectors (`environment` dev + production; one exercising unicode/`payload_ref`) plus one Merkle checkpoint (three signed leaf envelopes, RFC 9162 leaf hashes over the complete leaf-envelope JCS bytes, root + per-leaf inclusion proofs). Gated byte-for-byte by both kernels in this repo (`tests/test_conformance.py`, `ts/test/conformance.test.ts`).

## Contents added at v1.2

> **Corpus tag: `test-vectors-v1.2`** — additive over v1.1 (kernel-ratification lane, Scope D). `ario.events/v1` is now **ratified** (envelope-spec v1.3), so its vectors gate through `verifyEnvelope` in all three kernels. Two new artifacts: a **chained two-checkpoint** vector (per-batcher continuity across windows — window-2's checkpoint record `previous_hash` = SHA-256(JCS(window-1 checkpoint record))), and a **`negatives/`** category — inputs a conformant verifier MUST reject, each carrying the complete envelope bytes + the expected rejection.

| File | SHA-256 |
|---|---|
| `ario.events-v1/events-checkpoint-chain-01.json` | `71a099143d17b6583f12ce132840c1f802951613b7e456d98703bc87625c7f54` |
| `negatives/negative-malformed-minor-00.json` | `31758aa41471bd17521a94c16d44057b7415eb905d1c7852e0086852fd5f39c1` |
| `negatives/negative-malformed-minor-01.json` | `6d3f22d01c4a0f2dc8979dae2aef3ae9c0821a990fc26eca344ac78b75d7c30f` |
| `negatives/negative-malformed-minor-02.json` | `b437b44ea6d793bb4b5a0483e046fc08219b5a3b40dc2f2db2c7ead6132b0f3c` |
| `negatives/negative-lone-surrogate-00.json` | `c89a558c5efc6b0bbf9e82c104dd29d0315bfbefcc56c7ccaea8b81c60e848ed` |
| `negatives/negative-missing-payload-hash-00.json` | `a2818add7d61e0de56b2782e91b3a69275e3ec07b81f258aff7c65657cb999cb` |

The chained vector's two checkpoints each verify full-family through `verifyEnvelope`; the negatives cover malformed `spec_version` minors (#13), a lone UTF-16 surrogate (JCS reject-only), and a missing `payload_hash` (§2). Folded into both kernels' conformance + the agent's vendored copy at this tag.

## Contents added at v1.3

> **Corpus tag: `test-vectors-v1.3`** — additive over v1.2 (Evidence-Labs export lane). The **attested-evidence-export vectors** (`ario.evidence.export/v1`, [`specs/evidence-export.md`](../specs/evidence-export.md)), homed in the `evidence-export/` subdirectory. This body rides the unchanged `ario.evidence/v1` Ed25519 wrapper but adds the kernel's one new primitive — **RSA-PSS-SHA-256 operator-attestation verify** (salt = 32, MGF1-SHA-256, §3.3) — plus source-bundle linkage, cached-vs-recomputed verdict agreement, and the §4 verdict object. Generated — never hand-edited — by `tools/gen-vectors/gen_export_vectors.py` from the frozen shared golden export; each tampered vector is a programmatic byte-flip / pre-signed `_tamper` swap-in / field delete, re-signed with the published Ed25519 seed where the wrapper must stay valid. The RSA-PSS operator keys are random per fixture generation but the committed golden is frozen (the RSA signatures cannot be re-derived offline, so the three RSA failure classes reuse the golden's `_tamper` block).

| File | SHA-256 |
|---|---|
| `evidence-export/evidence-export-bundle.golden.json` | `9f93e0876ba763074254ffb74bdea70d91914fee647552fa3d1aa6b2b1f84a92` |
| `evidence-export/rsa-pss-attestation.golden.json` | `cefac2ae0fb90216047bae77ba6552fde91fe503ab650ea51e5582c17d643c59` |
| `evidence-export/evidence-export-positive-01.json` | `336de89bad8d10ca48ab1fc988df57ab79cd80bb201c474af63a61898dbec12f` |
| `evidence-export/evidence-export-tamper-wrapper-signature.json` | `b987aa17a347a18fd2c9452c508e34bdf066d16d9a8a5cc7c266d06430226c2f` |
| `evidence-export/evidence-export-tamper-body-hash.json` | `8110f53a062c08baf1ace71183afd1b22103f929c74a70b562dbc1ad93cf63d1` |
| `evidence-export/evidence-export-tamper-source-linkage.json` | `4d1a48feef2b9e3c39b4cb255aa1bf2da535c616caa7358d55e2683d3fc53775` |
| `evidence-export/evidence-export-tamper-verdict-disagreement.json` | `c3189ea3821af5c5bb36da4cfe453d50eac3f91873d8b9789b4b81f0b51136ed` |
| `evidence-export/evidence-export-tamper-attestation-signature.json` | `09c5f1204e8e2f26bdf760c806948e0370bc1bfb0a39f44624ed17d2ad93872b` |
| `evidence-export/evidence-export-tamper-mis-salt.json` | `69c2232779b615a141db4b4d932d67213c5c50dfcac4d35d42994ee4b0be188b` |
| `evidence-export/evidence-export-tamper-operator-binding.json` | `299a48c92a023779d0bad3c0b4235603115ffe47e7169c3ecf34f7343e1d923f` |
| `evidence-export/evidence-export-tamper-data-hash-binding.json` | `6cb353d974cc63ca2bd13c35bd2f1a1dc52ee79574781aaee95db1ce0d8ff105` |
| `evidence-export/evidence-export-tamper-disclosed-content.json` | `482879109008e57bcd058d225c03d04c8c4623bed4c83493132769d1c902e3ef` |
| `evidence-export/evidence-export-tamper-subject-ref.json` | `d3190c0905dd26991ff2fd2f35618cb80712796f6496210139e7eb3ef9d0a7d1` |
| `evidence-export/evidence-export-malformed-rsa-key.json` | `3d896847d58095783b3f9d5bb6e27a7bb7bd4d698ea1a2fcd8cdbd7600bd2ea7` |
| `evidence-export/evidence-export-malformed-signature-alg.json` | `709198452adce89506537570655aa41f67e45c0e54b8c2560c0b5753a1e132ae` |
| `evidence-export/evidence-export-source-bundle-ref.json` | `5d552072af413faebb70cb4de2035c1940181d3d997f3b147aba21635bb7ab53` |

One positive (exit 0) + thirteen negative/undetermined classes: wrapper-signature break, `body_hash` mismatch, `source_bundle_hash` mismatch, verdict disagreement, forged attestation RSA-PSS, mis-salted attestation (the salt=32 pin), operator-address-binding break, `data_hash`-binding break, disclosed-`content` mismatch, `subject_ref` tamper (all exit 1), malformed RSA key + unsupported record `signature_alg` (exit 2), and an offline `source_bundle_ref` (exit 3). The positive's `expected.verdict_jcs_sha256` is the byte-agreement anchor — the TS and Python kernels recompute the **same** JCS-canonical §4 verdict object (`738663f32ccec765743ed7d53f79b09254af2f11656e7d9955e521c4edeab8cb`). `rsa-pss-attestation.golden.json` is the bare RSA-PSS-SHA-256 primitive vector (a frozen RSA-2048 key, a snake_case attestation payload, the salt=32 signature, AND a max/auto-salt signature over the SAME payload+key so the salt pin is proven to round-trip AND to reject the un-verifiable auto-salt trap) + the `operator == base64url(SHA-256(n))` derivation. Gated Python⇄TS by `cross-kernel/run_export.sh`; the primitive is pinned in both kernels' unit suites.

## Verifying a vendored copy

```bash
sha256sum envelope-*.json merkle-*.json README.md   # compare against the table above
```

Known downstream pins: `ar-io-proof` (Python + TS kernels, gate at `test-vectors-v1.2`), `ar-io-proof-checker` (JS verifier conformance gate), `ar-io-anchor` (vendors the `ario.events/v1` set at `test-vectors-v1.1`), `ar-io-mlflow` cross-product, `tools/ans104-conformance`.
