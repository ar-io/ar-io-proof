// Go leg of the cross-kernel agreement gate: re-verify every case through the
// ar-io-agent pkg/proof kernel (the SAME kernel `ariod verify` runs), built
// at the commit pinned in ../PIN, and compare its verdict to the Python
// reference recorded in cases.json. Exits non-zero on any disagreement.
//
// pkg/proof.VerifyEnvelope is all-or-nothing (error = failure), so the Go leg
// asserts verdict-level agreement (ok == !err); the full tri-state is asserted
// by the TS leg. Mode is chosen by the presence of committed bytes, mirroring
// the kernel's VerifyEnvelope vs VerifyEnvelopeWithPayload split.
//
//	go run . cases.json
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ar-io/ar-io-agent/pkg/proof"
)

type kase struct {
	ID         string         `json:"id"`
	Envelope   map[string]any `json:"envelope"`
	PayloadB64 *string        `json:"payload_b64"`
	Py         struct {
		OK bool `json:"ok"`
	} `json:"py"`
}

func main() {
	path := "cases.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var cases []kase
	if err := json.Unmarshal(raw, &cases); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	mismatches := 0
	for _, c := range cases {
		envJSON, _ := json.Marshal(c.Envelope)
		var verr error
		if c.PayloadB64 != nil {
			pb, _ := base64.StdEncoding.DecodeString(*c.PayloadB64)
			_, verr = proof.VerifyEnvelopeWithPayload(envJSON, pb)
		} else {
			_, verr = proof.VerifyEnvelope(envJSON)
		}
		goOK := verr == nil
		if goOK != c.Py.OK {
			fmt.Fprintf(os.Stderr, "MISMATCH %s: goOk=%v pyOk=%v (err=%v)\n", c.ID, goOK, c.Py.OK, verr)
			mismatches++
		}
	}

	if mismatches > 0 {
		fmt.Fprintf(os.Stderr, "Go vs Python: %d mismatch(es) over %d cases\n", mismatches, len(cases))
		os.Exit(1)
	}
	fmt.Printf("Go vs Python: ALL MATCH (%d cases, verdict-level)\n", len(cases))
}
