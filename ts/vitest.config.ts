import { defineConfig } from "vitest/config";

// Standalone test runner for the TS kernel. In its previous home (the
// proof-checker workspace) these tests ran off the app's root runner; here the
// package owns its own config. Node environment — the kernel is pure
// (WebCrypto + @noble/ed25519), no DOM needed.
export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
  },
});
