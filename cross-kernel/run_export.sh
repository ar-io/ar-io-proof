#!/usr/bin/env bash
# ario.evidence.export/v1 cross-kernel agreement gate: Python (reference) vs
# TypeScript, over the frozen shared golden export + its programmatically-
# tampered classes. Both kernels must return IDENTICAL verdicts on identical
# bytes — same wrapper flags, same exit code (0/1/2/3), same per-attestation
# bindings, and a BYTE-IDENTICAL recomputed §4 verdict object (compared by
# SHA-256(JCS(verdict))).
#
#   Python leg : native (in-repo src/ario_proof)  — the reference
#   TS leg     : native (in-repo ts/dist)          — full verdict-record match
#
# The Go leg is intentionally absent: the Go kernel is envelope-only and gains
# ario.evidence/v1 export verify later (evidence-export.md §9, phase 3 / P1), so
# this gate is Python⇄TS today (matching the spec's "TS + Python (Go later, P1)").
#
#   bash cross-kernel/run_export.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"
cases="$here/export-cases.json"

echo "== generating export cases + Python reference verdicts =="
PYTHONPATH="$repo_root/src${PYTHONPATH:+:$PYTHONPATH}" \
  python3 "$here/generate_export_cases.py" "$repo_root" > "$cases"
n=$(python3 -c "import json;print(len(json.load(open('$cases'))))")
echo "   $n cases (1 positive + tampered/malformed/undetermined classes)"

echo "== TS leg (build + re-verify + byte-identical verdict compare) =="
(cd "$repo_root/ts" && npm run --silent build >/dev/null)
node "$here/ts_export_leg.mjs" "$cases"

echo "== cross-kernel export agreement: OK =="
