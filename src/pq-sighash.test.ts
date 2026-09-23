import { describe, expect, it } from "vitest";
import { Buffer } from "buffer";
import * as bitcoin from "bitcoinjs-lib";
import { ECPairFactory } from "ecpair";
import ecc from "@bitcoinerlab/secp256k1";
import { pqAuthScriptSighash, strictAuthScriptSighash } from "./pq-sighash.js";
import { getNetwork } from "./networks.js";
import {
  NODE_EC_PUBKEY_HEX,
  NODE_EC_WIF,
  NODE_PREVOUT_AMOUNT,
  NODE_V1_SIGHASH,
  NODE_V1_UNSIGNED_TX,
  NODE_V2_SIGHASH,
  NODE_V2_UNSIGNED_TX,
  NODE_V3_SIGHASH,
  NODE_V3_SIGNED_TX,
  NODE_V3_UNSIGNED_TX,
} from "./pq-address.fixtures.js";

const ECPair = ECPairFactory(ecc);

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

// Spends a Neurai-DePIN regtest node accepted (testmempoolaccept), signed by
// uNeurai over these sighashes (see pq-address.fixtures.ts).
describe("AuthScript sighash (regtest node vectors)", () => {
  it("matches the generic v1 spend", () => {
    const h = pqAuthScriptSighash({ tx: NODE_V1_UNSIGNED_TX, inputIndex: 0, amount: NODE_PREVOUT_AMOUNT });
    expect(h.toString("hex")).toBe(NODE_V1_SIGHASH);
  });

  it("matches the strict PQ v2 spend", () => {
    const h = strictAuthScriptSighash({
      tx: NODE_V2_UNSIGNED_TX,
      inputIndex: 0,
      amount: NODE_PREVOUT_AMOUNT,
      witnessVersion: 2,
    });
    expect(h.toString("hex")).toBe(NODE_V2_SIGHASH);
    // Same through the generic entry point with an explicit witness version.
    expect(
      pqAuthScriptSighash({ tx: NODE_V2_UNSIGNED_TX, inputIndex: 0, amount: NODE_PREVOUT_AMOUNT, witnessVersion: 2 })
        .toString("hex")
    ).toBe(NODE_V2_SIGHASH);
    // A v1-style hash of the same input differs (the witness version byte).
    expect(
      pqAuthScriptSighash({ tx: NODE_V2_UNSIGNED_TX, inputIndex: 0, amount: NODE_PREVOUT_AMOUNT }).toString("hex")
    ).not.toBe(NODE_V2_SIGHASH);
  });

  it("matches the strict ECDSA v3 spend and reproduces its signature", () => {
    const h = strictAuthScriptSighash({
      tx: NODE_V3_UNSIGNED_TX,
      inputIndex: 0,
      amount: NODE_PREVOUT_AMOUNT,
      witnessVersion: 3,
    });
    expect(h.toString("hex")).toBe(NODE_V3_SIGHASH);

    // RFC 6979 is deterministic: signing like the device gives the node-accepted tx.
    const key = ECPair.fromWIF(NODE_EC_WIF, { ...getNetwork("xna-test"), bech32: "" });
    const tx = bitcoin.Transaction.fromHex(NODE_V3_UNSIGNED_TX);
    tx.ins[0].witness = [
      Buffer.from([0x02]),
      Buffer.from(bitcoin.script.signature.encode(key.sign(h), 0x01)),
      Buffer.from(NODE_EC_PUBKEY_HEX, "hex"),
      Buffer.from([0x51]),
    ];
    expect(tx.toHex()).toBe(NODE_V3_SIGNED_TX);
  });

  it("rejects inconsistent strict parameters", () => {
    const base = { tx: NODE_V3_UNSIGNED_TX, inputIndex: 0, amount: NODE_PREVOUT_AMOUNT };
    expect(() => pqAuthScriptSighash({ ...base, witnessVersion: 3, authType: 0x01 })).toThrow(/requires authType/);
    expect(() => pqAuthScriptSighash({ ...base, witnessVersion: 2, witnessScript: "52" })).toThrow(/OP_TRUE/);
    expect(() => pqAuthScriptSighash({ ...base, witnessVersion: 4 as 3 })).toThrow(/witness version/);
    expect(() => pqAuthScriptSighash({ ...base, sighashType: 0x81 })).toThrow(/SIGHASH_ALL/);
  });

  it("rejects version-3 transactions (NIP-014 reference inputs)", () => {
    const tx = bitcoin.Transaction.fromHex(NODE_V3_UNSIGNED_TX);
    tx.version = 3;
    expect(() => strictAuthScriptSighash({ tx, inputIndex: 0, amount: 1n, witnessVersion: 3 })).toThrow(/version 3/);
    expect(() => pqAuthScriptSighash({ tx, inputIndex: 0, amount: 1n })).toThrow(/version 3/);
  });
});
