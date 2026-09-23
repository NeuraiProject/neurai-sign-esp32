import { Buffer } from "buffer";
import * as secp from "@bitcoinerlab/secp256k1";
import * as bitcoin from "bitcoinjs-lib";
import ECPairFactory from "ecpair";
import { describe, expect, it } from "vitest";
import {
  buildPSBT,
  buildPSBTFromRawTransaction,
  finalizeSignedPSBT,
  getNetwork,
  strictAuthScriptSighash,
  validatePSBT,
} from "./index.js";
import {
  NODE_EC_PUBKEY_HEX,
  NODE_EC_V3_ADDRESS,
  NODE_EC_V3_MAINNET,
  NODE_EC_V3_SPK,
  NODE_EC_WIF,
  NODE_PQ_V1_MAINNET,
  NODE_PQ_V1_SPK,
  NODE_PQ_V2_MAINNET,
  NODE_PQ_V2_SPK,
  NODE_V1_ADDRESS,
  NODE_V1_SPK,
} from "./pq-address.fixtures.js";

bitcoin.initEccLib(secp);

const ECPair = ECPairFactory(secp);
const TEST_NETWORK = "xna" as const;
const TEST_PATH = "m/44'/1900'/0'/0/0";
const TEST_FINGERPRINT = "deadbeef";

function createSignedFixture() {
  const network = getNetwork(TEST_NETWORK);
  const keyPair = ECPair.makeRandom();
  const payment = bitcoin.payments.p2pkh({
    pubkey: keyPair.publicKey,
    network,
  });

  if (!payment.address || !payment.output) {
    throw new Error("Failed to create P2PKH fixture");
  }

  const previousTx = new bitcoin.Transaction();
  previousTx.version = 2;
  previousTx.addInput(Buffer.alloc(32), 0xffffffff);
  previousTx.addOutput(payment.output, 500000n);

  const originalPsbt = buildPSBT({
    network: TEST_NETWORK,
    utxos: [
      {
        txid: previousTx.getId(),
        vout: 0,
        scriptPubKey: Buffer.from(payment.output).toString("hex"),
        satoshis: 500000,
        rawTxHex: previousTx.toHex(),
      },
    ],
    outputs: [
      {
        address: payment.address,
        value: 100000,
      },
    ],
    changeAddress: payment.address,
    pubkey: Buffer.from(keyPair.publicKey).toString("hex"),
    masterFingerprint: TEST_FINGERPRINT,
    derivationPath: TEST_PATH,
    feeRate: 1,
  });

  const psbt = bitcoin.Psbt.fromBase64(originalPsbt, { network });
  psbt.signInput(0, keyPair);

  return {
    address: payment.address,
    network,
    originalPsbt,
    previousTx,
    signedPsbt: psbt.toBase64(),
  };
}

describe("PSBT helpers", () => {
  it("builds a valid PSBT", () => {
    const fixture = createSignedFixture();

    expect(validatePSBT(fixture.originalPsbt, TEST_NETWORK)).toBe(true);
  });

  it("finalizes a standard signed PSBT", () => {
    const fixture = createSignedFixture();

    const result = finalizeSignedPSBT(
      fixture.originalPsbt,
      fixture.signedPsbt,
      TEST_NETWORK
    );

    expect(result.txId).toHaveLength(64);
    expect(result.txHex.length).toBeGreaterThan(0);
  });

  it("fails when funds are insufficient", () => {
    const network = getNetwork(TEST_NETWORK);
    const keyPair = ECPair.makeRandom();
    const payment = bitcoin.payments.p2pkh({
      pubkey: keyPair.publicKey,
      network,
    });

    if (!payment.address || !payment.output) {
      throw new Error("Failed to create P2PKH fixture");
    }
    // Capture into consts so the narrowing survives inside the closure below
    // (TypeScript drops property narrowing across function boundaries).
    const paymentOutput = payment.output;
    const paymentAddress = payment.address;

    const previousTx = new bitcoin.Transaction();
    previousTx.version = 2;
    previousTx.addInput(Buffer.alloc(32), 0xffffffff);
    previousTx.addOutput(paymentOutput, 1000n);

    expect(() =>
      buildPSBT({
        network: TEST_NETWORK,
        utxos: [
          {
            txid: previousTx.getId(),
            vout: 0,
            scriptPubKey: Buffer.from(paymentOutput).toString("hex"),
            satoshis: 1000,
            rawTxHex: previousTx.toHex(),
          },
        ],
        outputs: [
          {
            address: paymentAddress,
            value: 1000,
          },
        ],
        changeAddress: paymentAddress,
        pubkey: Buffer.from(keyPair.publicKey).toString("hex"),
        masterFingerprint: TEST_FINGERPRINT,
        derivationPath: TEST_PATH,
        feeRate: 10,
      })
    ).toThrow(/Insufficient funds/);
  });

  it("sends to a PQ destination address (output encoded as AuthScript)", () => {
    const fixture = createSignedFixture();
    // A PQ destination address (firmware oracle vector, mainnet form: the PSBT
    // network is "xna"). Spending legacy ECDSA inputs while paying to a PQ
    // address must work with the standard flow.
    const pqAddress =
      "nc1pdsj0aztvgwv3rwgml360stpyp228zrggyga6n4sdenmetm6wv3tq3qxdae";
    const expectedScript =
      "5120" +
      "6c24fe896c439911b91bfc74f82c240a94710d08223ba9d60dccf795ef4e6456";

    const psbtBase64 = buildPSBT({
      network: TEST_NETWORK,
      utxos: [
        {
          txid: fixture.previousTx.getId(),
          vout: 0,
          scriptPubKey: Buffer.from(
            fixture.previousTx.outs[0].script
          ).toString("hex"),
          satoshis: 500000,
          rawTxHex: fixture.previousTx.toHex(),
        },
      ],
      outputs: [{ address: pqAddress, value: 100000 }],
      changeAddress: fixture.address,
      pubkey: "02".padEnd(66, "0"),
      masterFingerprint: TEST_FINGERPRINT,
      derivationPath: TEST_PATH,
      feeRate: 1,
    });

    const psbt = bitcoin.Psbt.fromBase64(psbtBase64, { network: fixture.network });
    const out = psbt.txOutputs.find((o) => o.value === 100000n);
    expect(out).toBeDefined();
    expect(Buffer.from(out!.script).toString("hex")).toBe(expectedScript);
  });

  it("sends to every AuthScript family (OP_1 / OP_2 / OP_3)", () => {
    const fixture = createSignedFixture();
    const psbtBase64 = buildPSBT({
      network: TEST_NETWORK,
      utxos: [
        {
          txid: fixture.previousTx.getId(),
          vout: 0,
          scriptPubKey: Buffer.from(fixture.previousTx.outs[0].script).toString("hex"),
          satoshis: 500000,
          rawTxHex: fixture.previousTx.toHex(),
        },
      ],
      outputs: [
        { address: NODE_PQ_V1_MAINNET, value: 10001 },
        { address: NODE_PQ_V2_MAINNET, value: 10002 },
        { address: NODE_EC_V3_MAINNET, value: 10003 },
      ],
      changeAddress: fixture.address,
      pubkey: "02".padEnd(66, "0"),
      masterFingerprint: TEST_FINGERPRINT,
      derivationPath: TEST_PATH,
      feeRate: 1,
    });
    const psbt = bitcoin.Psbt.fromBase64(psbtBase64, { network: fixture.network });
    const scripts = psbt.txOutputs.slice(0, 3).map((o) => Buffer.from(o.script).toString("hex"));
    expect(scripts).toEqual([NODE_PQ_V1_SPK, NODE_PQ_V2_SPK, NODE_EC_V3_SPK]);
  });

  it("rejects a witness destination of the other chain", () => {
    const fixture = createSignedFixture();
    expect(() =>
      buildPSBT({
        network: TEST_NETWORK,
        utxos: [
          {
            txid: fixture.previousTx.getId(),
            vout: 0,
            scriptPubKey: Buffer.from(fixture.previousTx.outs[0].script).toString("hex"),
            satoshis: 500000,
            rawTxHex: fixture.previousTx.toHex(),
          },
        ],
        outputs: [{ address: NODE_EC_V3_ADDRESS, value: 100000 }],
        changeAddress: fixture.address,
        pubkey: "02".padEnd(66, "0"),
        masterFingerprint: TEST_FINGERPRINT,
        derivationPath: TEST_PATH,
        feeRate: 1,
      })
    ).toThrow(/testnet address but the PSBT network is xna/);
  });

  it("finalizes a strict ECDSA witness v3 input signed with the strict sighash", () => {
    const network = getNetwork("xna-test");
    const key = ECPair.fromWIF(NODE_EC_WIF, { ...network, bech32: "" });
    const pubkey = Buffer.from(key.publicKey);

    // A prevout paying 10 XNA to the key's tnq1r… address at vout 1.
    const previousTx = new bitcoin.Transaction();
    previousTx.version = 2;
    previousTx.addInput(Buffer.alloc(32, 7), 0, 0xfffffffe);
    previousTx.addOutput(Buffer.from("76a914" + "00".repeat(20) + "88ac", "hex"), 1n);
    previousTx.addOutput(Buffer.from(NODE_EC_V3_SPK, "hex"), 1_000_000_000n);

    const original = buildPSBT({
      network: "xna-test",
      utxos: [
        {
          txid: previousTx.getId(),
          vout: 1,
          scriptPubKey: NODE_EC_V3_SPK,
          satoshis: 1_000_000_000,
          rawTxHex: previousTx.toHex(),
        },
      ],
      outputs: [{ address: NODE_V1_ADDRESS, value: 900_000_000 }],
      changeAddress: NODE_EC_V3_ADDRESS,
      pubkey: pubkey.toString("hex"),
      masterFingerprint: TEST_FINGERPRINT,
      derivationPath: "m/84'/1'/0'/0/0",
      feeRate: 1024,
    });

    // Emulate the device (uNeurai >= 0.2.0 PSBT::sign): strict v3 sighash.
    const signedPsbt = bitcoin.Psbt.fromBase64(original, { network });
    const unsignedTx = bitcoin.Transaction.fromBuffer(signedPsbt.data.getTransaction());
    const sighash = strictAuthScriptSighash({
      tx: unsignedTx,
      inputIndex: 0,
      amount: 1_000_000_000n,
      witnessVersion: 3,
    });
    const der = bitcoin.script.signature.encode(key.sign(sighash), 0x01);
    signedPsbt.updateInput(0, { partialSig: [{ pubkey, signature: der }] });

    const { txHex } = finalizeSignedPSBT(original, signedPsbt.toBase64(), "xna-test");
    const tx = bitcoin.Transaction.fromHex(txHex);
    expect(tx.ins[0].script.length).toBe(0);
    expect(tx.ins[0].witness.map((w) => Buffer.from(w).toString("hex"))).toEqual([
      "02",
      Buffer.from(der).toString("hex"),
      NODE_EC_PUBKEY_HEX,
      "51",
    ]);
    // Change goes back to the v3 address; the v3 input is estimated at 69 vB.
    expect(Buffer.from(tx.outs[1].script).toString("hex")).toBe(NODE_EC_V3_SPK);
    expect(tx.outs[1].value).toBe(1_000_000_000n - 900_000_000n - 1024n * 165n);
    expect(key.verify(sighash, bitcoin.script.signature.decode(tx.ins[0].witness[1]).signature)).toBe(true);
  });

  it("refuses to finalize an AuthScript v1 input through a PSBT", () => {
    const network = getNetwork("xna-test");
    const key = ECPair.makeRandom();
    const previousTx = new bitcoin.Transaction();
    previousTx.version = 2;
    previousTx.addInput(Buffer.alloc(32, 9), 0, 0xfffffffe);
    previousTx.addOutput(Buffer.from(NODE_V1_SPK, "hex"), 1_000_000_000n);
    const original = buildPSBT({
      network: "xna-test",
      utxos: [
        {
          txid: previousTx.getId(),
          vout: 0,
          scriptPubKey: NODE_V1_SPK,
          satoshis: 1_000_000_000,
          rawTxHex: previousTx.toHex(),
        },
      ],
      outputs: [{ address: NODE_V1_ADDRESS, value: 900_000_000 }],
      changeAddress: NODE_V1_ADDRESS,
      pubkey: Buffer.from(key.publicKey).toString("hex"),
      masterFingerprint: TEST_FINGERPRINT,
      derivationPath: TEST_PATH,
      feeRate: 1,
    });
    const signedPsbt = bitcoin.Psbt.fromBase64(original, { network });
    signedPsbt.updateInput(0, {
      partialSig: [
        {
          pubkey: Buffer.from(key.publicKey),
          signature: bitcoin.script.signature.encode(key.sign(Buffer.alloc(32, 1)), 0x01),
        },
      ],
    });
    expect(() => finalizeSignedPSBT(original, signedPsbt.toBase64(), "xna-test")).toThrow(
      /witness v1 output, which cannot be signed through a PSBT/
    );
  });

  it("builds a PSBT from a raw unsigned transaction", () => {
    const fixture = createSignedFixture();
    const unsignedTx = new bitcoin.Transaction();
    unsignedTx.version = 2;
    unsignedTx.addInput(Buffer.from(fixture.previousTx.getHash()), 0);
    unsignedTx.addOutput(
      bitcoin.address.toOutputScript(fixture.address, fixture.network),
      100000n
    );

    const psbt = buildPSBTFromRawTransaction({
      network: TEST_NETWORK,
      rawUnsignedTransaction: unsignedTx.toHex(),
      inputs: [
        {
          txid: fixture.previousTx.getId(),
          vout: 0,
          rawTxHex: fixture.previousTx.toHex(),
          pubkey: Buffer.from(
            bitcoin.Transaction.fromHex(fixture.previousTx.toHex()).outs[0].script
          ).toString("hex"),
        },
      ],
    });

    expect(validatePSBT(psbt, TEST_NETWORK)).toBe(true);
  });
});
