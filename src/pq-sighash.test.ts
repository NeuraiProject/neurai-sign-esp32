import { describe, expect, it } from "vitest";
import { pqAuthScriptSighash } from "./pq-sighash.js";

// Firmware oracle vector (uNeurai/tests/test_sighash_authscript.cpp):
// raw tx + witnessScript=OP_TRUE + amount 100_000_000 + authType 0x01 + SIGHASH_ALL.
const RAW_TX_HEX =
  "0200000001" +
  "1111111111111111111111111111111111111111111111111111111111111111" +
  "00000000" + // vout 0
  "00" + // empty scriptSig
  "fdffffff" + // sequence
  "01" + // outputs
  "f0b9f50500000000" + // 99_990_000 sat
  "1976a914abababababababababababababababababababab88ac" +
  "00000000"; // locktime

const EXPECTED_SIGHASH =
  "5072b85972bb57bd5a9b4a3728121cc8b8e3dee8db647ae9b3a5bf2efdd6b968";

describe("pqAuthScriptSighash (firmware oracle vector)", () => {
  it("matches the device sigHashAuthScript", () => {
    const h = pqAuthScriptSighash({
      tx: RAW_TX_HEX,
      inputIndex: 0,
      amount: 100_000_000,
      witnessScript: "51",
      authType: 0x01,
    });
    expect(h.toString("hex")).toBe(EXPECTED_SIGHASH);
  });

  it("differs from a non-PQ authType (the authType byte enters the preimage)", () => {
    const pq = pqAuthScriptSighash({ tx: RAW_TX_HEX, inputIndex: 0, amount: 100_000_000, authType: 0x01 });
    const other = pqAuthScriptSighash({ tx: RAW_TX_HEX, inputIndex: 0, amount: 100_000_000, authType: 0x02 });
    expect(pq.toString("hex")).not.toBe(other.toString("hex"));
  });
});
