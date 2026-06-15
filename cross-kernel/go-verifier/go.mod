module github.com/ar-io/ar-io-proof/cross-kernel/go-verifier

go 1.25.0

require github.com/ar-io/ar-io-agent v0.0.0

require github.com/gowebpki/jcs v1.0.1 // indirect

// The Go leg builds against the VENDORED ar-io-agent pkg/proof (MIT carve-out)
// pinned in ../PIN — see ../vendor-agent/pkg/proof/VENDORING.md. Vendoring (vs
// token-cloning the private repo) makes this leg run on public/fork PRs with
// no secret, so the tri-kernel gate is load-bearing for everyone.
replace github.com/ar-io/ar-io-agent => ../vendor-agent
