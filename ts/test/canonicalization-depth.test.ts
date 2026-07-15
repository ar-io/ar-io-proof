// Regression: the cross-kernel canonicalization deep-nesting divergence.
//
// An unbounded recursive canonicalizer overflows at a runtime-specific depth,
// so the same deeply-nested bytes could verify on the TS kernel (large V8
// stack) while the Python kernel hits CPython's ~1000-frame recursion limit —
// a verdict that depends on which verifier you run, on a depth the byte-supplier
// controls. Both kernels now bound canonicalization nesting to
// MAX_CANONICAL_DEPTH and reject a deeper input as `malformed`
// (envelope-spec §2 invariant 7). The shared corpus vector `deep-nesting.json`
// MUST verify as `malformed` here AND in the Python kernel
// (tests/test_canonicalization_depth.py) — same bytes, same verdict.
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { MAX_CANONICAL_DEPTH, exceedsDepth, jcs } from "../src/verifier.js";
import { verifyEvidenceBundle } from "../src/evidence.js";

async function loadDeepNesting(): Promise<unknown> {
  const p = fileURLToPath(
    new URL(
      "../../test-vectors/evidence-export/negatives/deep-nesting.json",
      import.meta.url,
    ),
  );
  return JSON.parse(await readFile(p, "utf8"));
}

// Build a value nested `levels` wrappers deep around a scalar leaf; the deepest
// container sits at depth `levels + 1` (the leaf object is the innermost one).
function nest(levels: number): unknown {
  let node: unknown = { end: 0 };
  for (let i = 0; i < levels; i++) node = { nest: node };
  return node;
}

describe("canonicalization depth bound (envelope-spec §2 invariant 7)", () => {
  it("the deeply-nested corpus bundle verifies as MALFORMED (not a split verdict)", async () => {
    const bundle = await loadDeepNesting();
    const r = await verifyEvidenceBundle(bundle);
    expect(r.status).toBe("malformed");
    expect(r.errors.some((e) => /nesting exceeds/.test(e))).toBe(true);
  });

  it("exceedsDepth is exact at the bound", () => {
    // nest(k) puts the deepest container at depth k+1. So k = MAX-1 → deepest
    // MAX (allowed); k = MAX → deepest MAX+1 (over).
    expect(exceedsDepth(nest(MAX_CANONICAL_DEPTH - 1), MAX_CANONICAL_DEPTH)).toBe(false);
    expect(exceedsDepth(nest(MAX_CANONICAL_DEPTH), MAX_CANONICAL_DEPTH)).toBe(true);
  });

  it("exceedsDepth handles input far past any native call-stack (iterative, no overflow)", () => {
    // A recursive depth-walk would RangeError here; the iterative guard returns
    // cleanly after short-circuiting at the bound.
    expect(exceedsDepth(nest(50_000), MAX_CANONICAL_DEPTH)).toBe(true);
  });

  it("jcs throws the malformed signal on an over-deep input, before canonicalizing", () => {
    expect(() => jcs(nest(50_000))).toThrow(/nesting exceeds/);
  });

  it("jcs still canonicalizes a legitimately-shallow value", () => {
    expect(jcs({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });
});
