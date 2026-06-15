#!/usr/bin/env bash
# Cross-kernel agreement gate: Python (reference) vs TypeScript vs Go, over the
# conformance corpus + adversarial cases. A verifier that "accepts" a profile
# but mis-binds is worse than one that rejects it (kernel-ratify lane non-
# negotiable), so all three must return identical verdicts on identical bytes.
#
#   Python leg : native (in-repo src/ario_proof)        — the reference
#   TS leg     : native (in-repo ts/dist)               — full tri-state match
#   Go leg     : ar-io-agent pkg/proof @ PIN            — verdict-level match
#
# The Go leg is OPTIONAL: it runs only when a sibling ar-io-agent checkout
# containing the pinned commit is available (AGENT_SRC, default ../../ar-io-agent
# relative to this dir, i.e. a sibling of the ar-io-proof repo). Without it the
# script runs Python+TS and prints a loud SKIP for Go (so public-PR CI without
# private-repo access never fails, but a missing Go leg is never silent).
#
#   bash cross-kernel/run.sh
#   AGENT_SRC=/path/to/ar-io-agent bash cross-kernel/run.sh
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

echo "== Go leg =="
AGENT_SRC="${AGENT_SRC:-$repo_root/../ar-io-agent}"
pin_commit="$(grep '^agent_commit=' "$here/PIN" | cut -d= -f2)"
if [ -z "$pin_commit" ]; then
  echo "   no agent_commit in PIN" >&2; exit 1
fi
if ! command -v go >/dev/null 2>&1; then
  echo "   SKIP: go toolchain not found"
elif [ ! -d "$AGENT_SRC/.git" ] || ! git -C "$AGENT_SRC" rev-parse --verify "${pin_commit}^{commit}" >/dev/null 2>&1; then
  echo "   SKIP: ar-io-agent @ $pin_commit not available at AGENT_SRC=$AGENT_SRC"
  echo "         (set AGENT_SRC to a checkout containing the pinned commit to run the Go leg)"
else
  rm -rf "$here/go-verifier/agent-src"
  git -C "$AGENT_SRC" worktree add --detach "$here/go-verifier/agent-src" "$pin_commit" >/dev/null
  trap 'git -C "$AGENT_SRC" worktree remove --force "$here/go-verifier/agent-src" >/dev/null 2>&1 || true' EXIT
  (cd "$here/go-verifier" && go run . "$cases")
fi

echo "== cross-kernel agreement: OK =="
