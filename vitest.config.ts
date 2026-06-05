import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Only run this package's own tests. The reference libraries under
    // lib-no-usar/ ship their own suites and are not part of this package.
    include: ["src/**/*.test.ts"],
  },
});
