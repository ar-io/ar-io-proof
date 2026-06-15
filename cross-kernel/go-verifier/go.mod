module github.com/ar-io/ar-io-proof/cross-kernel/go-verifier

go 1.25.0

require github.com/ar-io/ar-io-agent v0.0.0

require github.com/gowebpki/jcs v1.0.1 // indirect

// The agent source is materialized at the commit pinned in ../PIN by run.sh
// (a detached git worktree from a sibling ../ar-io-agent checkout — the same
// pattern as the proof-checker's WASM toggle). Never points at a live HEAD.
replace github.com/ar-io/ar-io-agent => ./agent-src
