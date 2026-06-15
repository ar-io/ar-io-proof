# Vendored — do not edit in place

`proof.go` + `LICENSE` here are vendored **byte-for-byte** from
[`ar-io-agent`](https://github.com/ar-io/ar-io-agent) `pkg/proof/` at the
commit pinned in [`../../PIN`](../../PIN). This is the MIT-carved-out Go
verification kernel (an explicit per-directory exception to the agent repo's
BSL 1.1 — the `LICENSE` file is preserved). Publishing it in this public,
MIT-licensed repo is intended and owner-blessed: it lets the Go leg of the
cross-kernel agreement gate run on public and fork PRs with no private-repo
access.

**Never edit these files here.** They exist only so the gate can build the
*same* kernel `ariod verify` runs and assert it agrees with the Python and TS
kernels. To update: re-pin (`../../PIN`) to a new ar-io-agent commit and
re-sync:

```bash
# from the ar-io-proof repo root, with a sibling ../ar-io-agent checkout:
pin=$(grep '^agent_commit=' cross-kernel/PIN | cut -d= -f2)
git -C ../ar-io-agent show "$pin:pkg/proof/proof.go" > cross-kernel/vendor-agent/pkg/proof/proof.go
git -C ../ar-io-agent show "$pin:pkg/proof/LICENSE"  > cross-kernel/vendor-agent/pkg/proof/LICENSE
```

Only `proof.go` + `LICENSE` are vendored — the Go leg imports nothing else
from `pkg/proof` (no `pkg/merkle`; only stdlib + `gowebpki/jcs`).
