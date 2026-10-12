import { Buffer } from "buffer";
import * as secp from "@bitcoinerlab/secp256k1";
import { computeTxid, decodePsbt, serializeTransaction } from "@neuraiproject/neurai-create-transaction";
import * as bitcoin from "bitcoinjs-lib";
import ECPairFactory from "ecpair";
import { describe, expect, it } from "vitest";
import {
  assertDeviceCanSignPSBT,
  buildPSBT,
  buildPSBTFromRawTransaction,
  finalizePSBT,
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
      /an AuthScript v1 input is finalized by its signer/
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

// A version-3 testnet transaction (XNAP#POOL state thread, block 3002): two
// outputs, an empty NIP-014 reference-input list. bitcoinjs-lib rejects it.
const TESTNET_V3_TXID = "33c257664ed140e519accf642ca4f1937eade63be9a86eb0be93ca87db9786ac";
const TESTNET_V3_TX =
  "03000000029aba27aa998d37aa5bab819749bdb2e3185bfee56403c262e48ed86c1e647668030000" +
  "006a4730440220730f319abcda10937f4e18f59f7ada126f8141a3c8d27b3fe9219096cd841bff02" +
  "203ba3f54bcf9cbbc1668f46cdedc9012e803cfbb40b2e65c477ba4eb46f57d83b0121022a3da050" +
  "32a6c02841fb3e463c854123ba66bf8e4dda3e4a9ec6a72b34e98a36ffffffff94b80b69762a8e7a" +
  "cf98508358b771efd52d7ad1e37be99a4df0abc2e1a1f087020000006b483045022100bb5aa64225" +
  "367ed7b6d2f5eab5bba9542f40428438ab2b617e6ce5a583b9048602206391e0fc54f0c01d9361dc" +
  "952558f318a50cefe737ae7fa9ab296efc87d4fdab0121025a12b3d607ba66844f4c049ba7d062d9" +
  "a96ffa6a1b3c26bd6d06cb0d0d513128ffffffff0200000000000000005d5120d8080884df059105" +
  "aec1247cf24c9d8242222435454b1c7ca27a8aa64b65d15ec038786e617409584e415023504f4f4c" +
  "00e1f5050000000054200db2113b3f2a947e4abff06ed52f52979e8b454efb5f030c9d2ca388edf6" +
  "4bf9757cb99705000000001976a914ae7684230a461dfb6db8a67ec0bd44ab2cc1718288ac000000" +
  "0000";

/** A version-3 transaction paying `script`, with one NIP-014 reference input. */
function version3PreviousTx(script: Uint8Array, valueSats: bigint) {
  const hex = serializeTransaction({
    version: 3,
    inputs: [{ txid: "11".repeat(32), vout: 0, scriptSigHex: "", sequence: 0xffffffff }],
    outputs: [{ valueSats, scriptPubKeyHex: Buffer.from(script).toString("hex") }],
    vrefin: [{ txid: "22".repeat(32), vout: 1 }],
    locktime: 0,
  });
  return { hex, txid: computeTxid(hex) };
}

/** Sign input 0 the way NeuraiWallet / the device does: no bitcoinjs-lib `signInput`. */
function signLegacyInput(psbtBase64: string, keyPair: ReturnType<typeof ECPair.makeRandom>, prevScript: Uint8Array) {
  const network = getNetwork(TEST_NETWORK);
  const psbt = bitcoin.Psbt.fromBase64(psbtBase64, { network });
  const unsigned = bitcoin.Transaction.fromBuffer(psbt.data.globalMap.unsignedTx.toBuffer());
  const sighash = unsigned.hashForSignature(0, prevScript, bitcoin.Transaction.SIGHASH_ALL);
  const signature = bitcoin.script.signature.encode(Buffer.from(keyPair.sign(sighash)), bitcoin.Transaction.SIGHASH_ALL);
  psbt.updateInput(0, { partialSig: [{ pubkey: Buffer.from(keyPair.publicKey), signature: Buffer.from(signature) }] });
  return { signedBase64: psbt.toBase64(), signature };
}

describe("previous transactions of every Neurai version", () => {
  it("bitcoinjs-lib cannot read a Neurai version-3 transaction", () => {
    expect(computeTxid(TESTNET_V3_TX)).toBe(TESTNET_V3_TXID);
    expect(() => bitcoin.Transaction.fromHex(TESTNET_V3_TX)).toThrow(/unexpected data/);
  });

  it("builds a PSBT spending the testnet version-3 transaction", () => {
    const unsigned = new bitcoin.Transaction();
    unsigned.version = 2;
    unsigned.addInput(Buffer.from(TESTNET_V3_TXID, "hex").reverse(), 1);
    unsigned.addOutput(Buffer.from("76a914" + "00".repeat(20) + "88ac", "hex"), 1000n);
    const psbt = buildPSBTFromRawTransaction({
      network: "xna-test",
      rawUnsignedTransaction: unsigned.toHex(),
      inputs: [{ txid: TESTNET_V3_TXID, vout: 1, rawTxHex: TESTNET_V3_TX }],
    });
    const decoded = bitcoin.Psbt.fromBase64(psbt, { network: getNetwork("xna-test") });
    expect(Buffer.from(decoded.data.inputs[0].nonWitnessUtxo!).toString("hex")).toBe(TESTNET_V3_TX);
  });

  it("signs and finalizes a P2PKH input whose previous transaction is version 3", () => {
    const network = getNetwork(TEST_NETWORK);
    const keyPair = ECPair.makeRandom();
    const payment = bitcoin.payments.p2pkh({ pubkey: keyPair.publicKey, network });
    const prev = version3PreviousTx(payment.output!, 500000n);

    const unsigned = new bitcoin.Transaction();
    unsigned.version = 2;
    unsigned.addInput(Buffer.from(prev.txid, "hex").reverse(), 0);
    unsigned.addOutput(payment.output!, 400000n);
    const original = buildPSBTFromRawTransaction({
      network: TEST_NETWORK,
      rawUnsignedTransaction: unsigned.toHex(),
      inputs: [{ txid: prev.txid, vout: 0, rawTxHex: prev.hex }],
    });

    const { signedBase64, signature } = signLegacyInput(original, keyPair, payment.output!);
    const final = finalizeSignedPSBT(original, signedBase64, TEST_NETWORK);
    const tx = bitcoin.Transaction.fromHex(final.txHex);
    const chunks = (bitcoin.script.decompile(tx.ins[0].script) ?? []).map((c) => Buffer.from(c as Uint8Array).toString("hex"));
    expect(chunks).toEqual([Buffer.from(signature).toString("hex"), Buffer.from(keyPair.publicKey).toString("hex")]);
    expect(final.txId).toBe(tx.getId());
  });

  it("finalizes a device-signed PSBT built from UTXOs whose previous transaction is version 3", () => {
    const network = getNetwork(TEST_NETWORK);
    const keyPair = ECPair.makeRandom();
    const payment = bitcoin.payments.p2pkh({ pubkey: keyPair.publicKey, network });
    const prev = version3PreviousTx(payment.output!, 500000n);
    const original = buildPSBT({
      network: TEST_NETWORK,
      utxos: [{ txid: prev.txid, vout: 0, scriptPubKey: Buffer.from(payment.output!).toString("hex"), satoshis: 500000, rawTxHex: prev.hex }],
      outputs: [{ address: payment.address!, value: 100000 }],
      changeAddress: payment.address!,
      pubkey: Buffer.from(keyPair.publicKey).toString("hex"),
      masterFingerprint: TEST_FINGERPRINT,
      derivationPath: TEST_PATH,
      feeRate: 1,
    });
    const { signedBase64 } = signLegacyInput(original, keyPair, payment.output!);
    const final = finalizePSBT(signedBase64, TEST_NETWORK);
    expect(bitcoin.Transaction.fromHex(final.txHex).ins[0].script.length).toBeGreaterThan(0);
  });

  it("refuses a previous transaction that is not the one the input spends", () => {
    const keyPair = ECPair.makeRandom();
    const payment = bitcoin.payments.p2pkh({ pubkey: keyPair.publicKey, network: getNetwork(TEST_NETWORK) });
    const prev = version3PreviousTx(payment.output!, 500000n);
    const unsigned = new bitcoin.Transaction();
    unsigned.version = 2;
    unsigned.addInput(Buffer.from(prev.txid, "hex").reverse(), 0);
    unsigned.addOutput(payment.output!, 1000n);
    expect(() =>
      buildPSBTFromRawTransaction({
        network: TEST_NETWORK,
        rawUnsignedTransaction: unsigned.toHex(),
        inputs: [{ txid: prev.txid, vout: 0, rawTxHex: TESTNET_V3_TX }],
      })
    ).toThrow(/the previous transaction is [0-9a-f]{64}, but the input spends/);
  });

  it("carries a version-3 transaction to sign (Neurai Connect), which the device refuses", () => {
    const prev = version3PreviousTx(Buffer.from("76a914" + "00".repeat(20) + "88ac", "hex"), 1000n);
    const spend = serializeTransaction({
      version: 3,
      inputs: [{ txid: prev.txid, vout: 0, scriptSigHex: "", sequence: 0xffffffff }],
      outputs: [{ valueSats: 900n, scriptPubKeyHex: "76a914" + "00".repeat(20) + "88ac" }],
      vrefin: [{ txid: "33".repeat(32), vout: 0 }],
      locktime: 0,
    });
    const psbt = buildPSBTFromRawTransaction({
      network: TEST_NETWORK,
      rawUnsignedTransaction: spend,
      inputs: [{ txid: prev.txid, vout: 0, rawTxHex: prev.hex }],
    });
    expect(decodePsbt(psbt).unsignedTx.version).toBe(3);
    expect(decodePsbt(psbt).unsignedTx.vrefin).toEqual([{ txid: "33".repeat(32), vout: 0 }]);
    expect(() => assertDeviceCanSignPSBT(psbt)).toThrow(/cannot sign a version-3 transaction/);
  });
});
