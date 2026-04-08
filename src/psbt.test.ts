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
  validatePSBT,
} from "./index.js";

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

    const previousTx = new bitcoin.Transaction();
    previousTx.version = 2;
    previousTx.addInput(Buffer.alloc(32), 0xffffffff);
    previousTx.addOutput(payment.output, 1000n);

    expect(() =>
      buildPSBT({
        network: TEST_NETWORK,
        utxos: [
          {
            txid: previousTx.getId(),
            vout: 0,
            scriptPubKey: Buffer.from(payment.output).toString("hex"),
            satoshis: 1000,
            rawTxHex: previousTx.toHex(),
          },
        ],
        outputs: [
          {
            address: payment.address,
            value: 1000,
          },
        ],
        changeAddress: payment.address,
        pubkey: Buffer.from(keyPair.publicKey).toString("hex"),
        masterFingerprint: TEST_FINGERPRINT,
        derivationPath: TEST_PATH,
        feeRate: 10,
      })
    ).toThrow(/Insufficient funds/);
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
