// Vendored ar-io-agent module shim for the Go leg of the cross-kernel
// agreement gate. Provides exactly pkg/proof (the MIT-carved-out kernel) at
// the pinned commit. See ../PIN and pkg/proof/VENDORING.md.
module github.com/ar-io/ar-io-agent

go 1.25.0

require github.com/gowebpki/jcs v1.0.1
