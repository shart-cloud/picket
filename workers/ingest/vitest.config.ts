import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "cloudflare:workers": new URL("./src/cloudflare-workers-test-shim.ts", import.meta.url).pathname
    }
  },
  test: {
    include: ["src/**/*.test.ts"]
  }
});
