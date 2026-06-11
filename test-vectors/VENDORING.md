# Corpus home (authoritative as of 2026-06-11)

**This directory is the authoritative home of the conformance corpus** — see
[`specs/governance.md`](../specs/governance.md) §4 (CORP2, amended v1.1). It was
originally vendored byte-for-byte from `ar-io-agent/test-vectors/` at the annotated git
tag **`test-vectors-v1.0`** (tag object `b5e7df690b4e2840f483927b3758c8b5c24f4601`, commit
`133761633b76f158a22524eb8effbb57a89343de`); on 2026-06-11 the standards layer (family
specs + corpus + `tools/gen-vectors/`) moved here, and authority moved with it. The
corpus bytes are unchanged across the move — `test-vectors-v1.0` in THIS repo is issued
over the identical tree, and the original `ar-io-agent` tag remains valid for
already-pinned downstreams.

The corpus is **generated, never hand-edited** (CORP1): regenerate via
[`tools/gen-vectors/`](../tools/gen-vectors/). Per-file SHA-256 digests are pinned in
[`CORPUS-v1.md`](CORPUS-v1.md); `tests/test_conformance.py` re-verifies every digest on
each test run, so any drift fails CI.

## Change governance

Per [`specs/governance.md`](../specs/governance.md) §4: additive corpus changes are minor
tags (`test-vectors-v1.x`); byte changes to existing vectors are a major tag
(`test-vectors-v2.0`) + 30-day RFC. The BDFL blesses all corpus changes.

## Downstream copies

Producer repos may keep vendored byte-identical copies for their own CI gates
(`ar-io-agent/test-vectors/` is one); vendored copies sync FROM here and are never edited
in place:

```bash
git -C ../ar-io-proof archive <tag> test-vectors | tar -x -C .
```
