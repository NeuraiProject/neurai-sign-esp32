import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoot = mkdtempSync(join(tmpdir(), "neurai-sign-esp32-package-"));

try {
  const packResult = JSON.parse(execFileSync(
    "npm",
    ["pack", "--json", "--pack-destination", temporaryRoot],
    { cwd: packageRoot, encoding: "utf8" }
  ))[0];
  const forbidden = packResult.files
    .map((entry) => entry.path)
    .filter((path) => /^(?:tmp|src|test|scripts)\//.test(path));
  if (forbidden.length > 0) {
    throw new Error(`Package contains internal files: ${forbidden.join(", ")}`);
  }

  const tarball = join(temporaryRoot, packResult.filename);
  writeFileSync(join(temporaryRoot, "package.json"), JSON.stringify({
    private: true,
    type: "module",
    dependencies: { "@neuraiproject/neurai-sign-esp32": `file:${tarball}` },
  }));
  execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund"], {
    cwd: temporaryRoot,
    stdio: "pipe",
  });

  execFileSync("node", ["--input-type=module", "--eval", `
    import { createRequire } from "node:module";
    import * as esm from "@neuraiproject/neurai-sign-esp32";
    import * as browser from "@neuraiproject/neurai-sign-esp32/browser";
    import * as reactNative from "@neuraiproject/neurai-sign-esp32/react-native";
    const cjs = createRequire(import.meta.url)("@neuraiproject/neurai-sign-esp32");
    for (const surface of [esm, cjs, browser, reactNative]) {
      if (typeof surface.createDepinDeviceIdentity !== "function") throw new Error("adapter export missing");
      if (typeof surface.DepinDeviceIdentityError !== "function") throw new Error("error export missing");
    }
  `], { cwd: temporaryRoot, stdio: "pipe" });

  const installedRoot = join(
    temporaryRoot,
    "node_modules",
    "@neuraiproject",
    "neurai-sign-esp32"
  );
  const globalCode = readFileSync(join(installedRoot, "dist", "NeuraiSignESP32.global.js"), "utf8");
  const context = {
    TextEncoder,
    TextDecoder,
    crypto: globalThis.crypto,
    setTimeout,
    clearTimeout,
  };
  context.globalThis = context;
  vm.runInNewContext(globalCode, context);
  if (typeof context.NeuraiSignESP32?.createDepinDeviceIdentity !== "function") {
    throw new Error("IIFE adapter export missing");
  }

  writeFileSync(join(temporaryRoot, "consumer.ts"), `
    import {
      createDepinDeviceIdentity,
      type DepinSessionPermission,
      type IDepinSignAuthResponse,
      type IDepinSessionStatusResponse,
    } from "@neuraiproject/neurai-sign-esp32";
    const permission: DepinSessionPermission = "receive";
    const response = null as unknown as IDepinSignAuthResponse;
    const status = null as unknown as IDepinSessionStatusResponse;
    void createDepinDeviceIdentity; void permission; void response; void status;
  `);
  writeFileSync(join(temporaryRoot, "tsconfig.json"), JSON.stringify({
    compilerOptions: {
      target: "ES2020",
      module: "NodeNext",
      moduleResolution: "NodeNext",
      strict: true,
      noEmit: true,
      skipLibCheck: false,
    },
    files: ["consumer.ts"],
  }));
  execFileSync(
    "node",
    [join(packageRoot, "node_modules", "typescript", "bin", "tsc")],
    { cwd: temporaryRoot, stdio: "pipe" }
  );

  console.log("package gate: ESM, CJS, browser, React Native, IIFE and NodeNext types passed");
} finally {
  rmSync(temporaryRoot, { recursive: true, force: true });
}
