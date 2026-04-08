import commonjs from "@rollup/plugin-commonjs";
import resolve from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";
import { dts } from "rollup-plugin-dts";

const extensions = [".ts", ".js"];

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
    output: {
      file: "dist/index.d.ts",
      format: "esm",
    },
    plugins: [dts()],
  },
];
