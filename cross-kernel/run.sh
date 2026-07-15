#!/usr/bin/env bash
# Cross-kernel agreement gate: Python (reference) vs TypeScript vs Go, over the
# conformance corpus + adversarial cases. A verifier that "accepts" a profile
# but mis-binds is worse than one that rejects it (kernel-ratify lane non-
# negotiable), so all three must return identical verdicts on identical bytes.
#
#   Python leg : native (in-repo src/ario_proof)        — the reference
#   TS leg     : native (in-repo ts/dist)               — full tri-state match
#   Go leg     : VENDORED ar-io-agent pkg/proof @ PIN   — verdict-level match
#
# The Go leg builds the vendored MIT pkg/proof (vendor-agent/, pinned in PIN) —
# no private-repo access, so all three legs run on public and fork PRs.
#
#   bash cross-kernel/run.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"
cases="$here/cases.json"

echo "== generating cases + Python reference verdicts =="
python3 "$here/generate_cases.py" "$repo_root" > "$cases"
n=$(python3 -c "import json;print(len(json.load(open('$cases')))) ")
echo "   $n cases (corpus + adversarial)"

echo "== TS leg =="
(cd "$repo_root/ts" && npm run --silent build >/dev/null)
node "$here/ts_leg.mjs" "$cases"

echo "== export leg (ario.evidence.export/v1, Python vs TS byte-identical verdicts) =="
bash "$here/run_export.sh"

echo "== Go leg (vendored pkg/proof @ PIN) =="
if ! command -v go >/dev/null 2>&1; then
  echo "   go toolchain not found" >&2
  exit 1
fi
(cd "$here/go-verifier" && go run . "$cases")

echo "== cross-kernel agreement: OK =="
