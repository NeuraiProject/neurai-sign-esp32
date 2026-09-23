import commonjs from "@rollup/plugin-commonjs";
import resolve from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";
import { dts } from "rollup-plugin-dts";

const extensions = [".ts", ".js"];

/**
 * bitcoinjs-lib only ships ESM declarations (its "types" is read as ESM under
 * `require` too), so a CommonJS declaration file cannot import them plainly
 * (TS1479). In dist/index.d.cts they become type-only imports with the
 * `resolution-mode: "import"` attribute (TypeScript 5.3+).
 */
function esmOnlyTypeImports(packages) {
  return {
    name: "esm-only-type-imports",
    renderChunk(code) {
      let out = code;
      for (const name of packages) {
        const plain = new RegExp(`^import (?!type )(.+) from '${name}';$`, "gm");
        out = out.replace(plain, `import type $1 from '${name}' with { "resolution-mode": "import" };`);
        if (new RegExp(`from '${name}';$`, "m").test(out)) {
          throw new Error(`esm-only-type-imports: unexpected import of ${name} left in the CommonJS declarations`);
        }
      }
      return { code: out, map: null };
    },
  };
}

function createTsPlugin() {
  return typescript({
    tsconfig: "./tsconfig.json",
    declaration: false,
    declarationMap: false,
    sourceMap: false,
    exclude: [
      "src/**/*.test.ts",
      "src/**/*.spec.ts",
      "examples/**",
    ],
  });
}

export default [
  {
    input: "src/index.ts",
    output: [
      {
        file: "dist/index.js",
        format: "esm",
        sourcemap: false,
      },
      {
        file: "dist/index.cjs",
        format: "cjs",
        exports: "named",
        sourcemap: false,
      },
    ],
    plugins: [
      resolve({
        browser: true,
        preferBuiltins: false,
        extensions,
      }),
      commonjs(),
      createTsPlugin(),
    ],
  },
  {
    input: "src/browser.ts",
    output: {
      file: "dist/browser.js",
      format: "esm",
      sourcemap: false,
    },
    plugins: [
      resolve({
        browser: true,
        preferBuiltins: false,
        extensions,
      }),
      commonjs(),
      createTsPlugin(),
    ],
  },
  {
    input: "src/react-native.ts",
    output: {
      file: "dist/react-native.js",
      format: "esm",
      sourcemap: false,
    },
    plugins: [
      resolve({
        browser: false,
        preferBuiltins: false,
        extensions,
      }),
      commonjs(),
      createTsPlugin(),
    ],
  },
  {
    input: "src/global.ts",
    output: {
      file: "dist/NeuraiSignESP32.global.js",
      format: "iife",
      name: "NeuraiSignESP32Bundle",
      sourcemap: false,
    },
    plugins: [
      resolve({
        browser: true,
        preferBuiltins: false,
        extensions,
      }),
      commonjs(),
      createTsPlugin(),
    ],
  },
  {
    input: "src/index.ts",
    // The same self-contained declarations serve both entry points: ESM
    // (index.d.ts, for index.js) and CommonJS (index.d.cts, for index.cjs,
    // which exports the same values). In this "type": "module" package
    // TypeScript reads index.d.ts as ESM, which a CommonJS consumer resolving
    // with moduleResolution node16 cannot use (TS1471).
    output: [
      { file: "dist/index.d.ts", format: "esm" },
      {
        file: "dist/index.d.cts",
        format: "esm",
        plugins: [esmOnlyTypeImports(["bitcoinjs-lib"])],
      },
    ],
    plugins: [dts()],
  },
  {
    input: "src/react-native.ts",
    output: {
      file: "dist/react-native.d.ts",
      format: "esm",
    },
    plugins: [dts()],
  },
];
