import { describe, expect, it } from "vitest";
import * as bitcoin from "bitcoinjs-lib";
import {
  MAX_PQ_INPUTS,
  buildUnsignedPQTransaction,
  parseSignedPQTransaction,
} from "./pq-tx.js";
import type { IPQUTXO } from "./types.js";
import {
  ORACLE_PQ_ADDRESS_TESTNET,
  ORACLE_PQ_COMMITMENT_HEX,
} from "./pq-address.fixtures.js";

const PQ_SCRIPT = "5120" + ORACLE_PQ_COMMITMENT_HEX;

function utxo(overrides: Partial<IPQUTXO> = {}): IPQUTXO {
  return {
    txid: "a".repeat(64),
    vout: 0,
    satoshis: 1_000_000,
    scriptPubKey: PQ_SCRIPT,
    type: "pq",
    ...overrides,
  };
}

describe("buildUnsignedPQTransaction", () => {
  it("builds an unsigned tx with change and per-input metadata", () => {
    const { rawTxHex, inputs } = buildUnsignedPQTransaction({
      utxos: [utxo()],
      outputs: [{ address: ORACLE_PQ_ADDRESS_TESTNET, value: 100_000 }],
      changeAddress: ORACLE_PQ_ADDRESS_TESTNET,
      feeRate: 1,
    });

    const tx = bitcoin.Transaction.fromHex(rawTxHex);
    expect(tx.ins).toHaveLength(1);
    // empty scriptSig (unsigned)
    expect(tx.ins[0].script.length).toBe(0);
    // destination + change
    expect(tx.outs).toHaveLength(2);
    expect(Buffer.from(tx.outs[0].script).toString("hex")).toBe(PQ_SCRIPT);

    expect(inputs).toEqual([
      { index: 0, amount: 1_000_000, script_pub_key: PQ_SCRIPT },
    ]);
  });

  it("uses sighashAmount override (0 for asset inputs)", () => {
    const { inputs } = buildUnsignedPQTransaction({
      utxos: [utxo({ sighashAmount: 0 })],
      outputs: [{ address: ORACLE_PQ_ADDRESS_TESTNET, value: 100_000 }],
      changeAddress: ORACLE_PQ_ADDRESS_TESTNET,
      feeRate: 1,
    });
    expect(inputs[0].amount).toBe(0);
  });

  it("rejects more than MAX_PQ_INPUTS inputs", () => {
    const utxos = Array.from({ length: MAX_PQ_INPUTS + 1 }, (_, i) =>
      utxo({ vout: i })
    );
    expect(() =>
      buildUnsignedPQTransaction({
        utxos,
        outputs: [{ address: ORACLE_PQ_ADDRESS_TESTNET, value: 100 }],
        changeAddress: ORACLE_PQ_ADDRESS_TESTNET,
        feeRate: 1,
      })
    ).toThrow(/Too many PQ inputs/);
  });

  it("throws on insufficient funds", () => {
    expect(() =>
      buildUnsignedPQTransaction({
        utxos: [utxo({ satoshis: 1000 })],
        outputs: [{ address: ORACLE_PQ_ADDRESS_TESTNET, value: 1000 }],
        changeAddress: ORACLE_PQ_ADDRESS_TESTNET,
        feeRate: 1000,
      })
    ).toThrow(/Insufficient funds/);
  });
});

describe("parseSignedPQTransaction", () => {
  it("computes the txid from a signed tx hex", () => {
    const { rawTxHex } = buildUnsignedPQTransaction({
      utxos: [utxo()],
      outputs: [{ address: ORACLE_PQ_ADDRESS_TESTNET, value: 100_000 }],
      changeAddress: ORACLE_PQ_ADDRESS_TESTNET,
      feeRate: 1,
    });
    const { txHex, txId } = parseSignedPQTransaction(rawTxHex);
    expect(txHex).toBe(rawTxHex);
    expect(txId).toHaveLength(64);
  });
});
