// The PSBT round trip with the NeuraiHW device: what is sent (and what is
// refused before sending), and how its answer is merged. The device is
// emulated the way uNeurai `PSBT::sign` / `PSBT::to_stream` behave: it signs
// every input carrying its key path with the input's PSBT_IN_SIGHASH_TYPE
// (SIGHASH_ALL when absent) and answers with a minimal PSBT: the unsigned
// transaction, then per input only its sighash type and partial signatures,
// then empty output maps.
import { Buffer } from "buffer";
import * as secp from "@bitcoinerlab/secp256k1";
import { computeTxid, decodePsbt, serializeTransaction, updatePsbtInput } from "@neuraiproject/neurai-create-transaction";
import * as bitcoin from "bitcoinjs-lib";
import ECPairFactory from "ecpair";
import { describe, expect, it } from "vitest";
import { NeuraiESP32 } from "./NeuraiESP32.js";
import { assertDeviceCanSignPSBT, buildPSBTFromRawTransaction, finalizeSignedPSBT, getNetwork } from "./index.js";
import type { DeviceResponse, INeuraiTransport } from "./types.js";

const ECPair = ECPairFactory(secp);
const NETWORK = "xna-test" as const;
const FINGERPRINT = "deadbeef";
const PATH = "m/44'/1'/0'/0/0";
const key = ECPair.fromPrivateKey(Buffer.alloc(32, 0x11), { network: getNetwork(NETWORK) });
const pubkeyHex = Buffer.from(key.publicKey).toString("hex");
const p2pkh = Buffer.from(bitcoin.payments.p2pkh({ pubkey: key.publicKey }).output!);

function previousTx(script: Uint8Array, version = 2) {
  const hex = serializeTransaction({
    version,
    inputs: [{ txid: "44".repeat(32), vout: 0, scriptSigHex: "", sequence: 0xffffffff }],
    outputs: [{ valueSats: 500000n, scriptPubKeyHex: Buffer.from(script).toString("hex") }],
    vrefin: version === 3 ? [{ txid: "55".repeat(32), vout: 0 }] : [],
    locktime: 0,
  });
  return { hex, txid: computeTxid(hex) };
}

function psbtFor(prev: { hex: string; txid: string }, extra: { sighashType?: number; witnessScript?: string } = {}) {
  const raw = serializeTransaction({
    version: 2,
    inputs: [{ txid: prev.txid, vout: 0, scriptSigHex: "", sequence: 0xffffffff }],
    outputs: [{ valueSats: 400000n, scriptPubKeyHex: p2pkh.toString("hex") }],
    vrefin: [],
    locktime: 0,
  });
  const psbt = buildPSBTFromRawTransaction({
    network: NETWORK,
    rawUnsignedTransaction: raw,
    inputs: [
      {
        txid: prev.txid,
        vout: 0,
        rawTxHex: prev.hex,
        pubkey: pubkeyHex,
        masterFingerprint: FINGERPRINT,
        derivationPath: PATH,
        ...extra,
      },
    ],
  });
  return { raw, psbt };
}

const varint = (n: number) => Buffer.from([n]);
const entry = (key: Buffer, value: Buffer) => Buffer.concat([varint(key.length), key, varint(value.length), value]);

/** The device's answer: uNeurai PSBT::to_stream of the signed PSBT. */
function deviceAnswer(
  psbtBase64: string,
  options: { tx?: string; signWith?: number; withOutputs?: boolean; extraInputEntry?: Buffer } = {}
): string {
  const decoded = decodePsbt(psbtBase64);
  const txHex = options.tx ?? serializeTransaction(decoded.unsignedTx, { includeWitness: false });
  const input = decoded.inputs[0];
  const sighashType = options.signWith ?? input.sighashType ?? bitcoin.Transaction.SIGHASH_ALL;
  const unsigned = bitcoin.Transaction.fromHex(txHex);
  const signature = bitcoin.script.signature.encode(
    Buffer.from(key.sign(unsigned.hashForSignature(0, p2pkh, sighashType))),
    sighashType
  );
  const tx = Buffer.from(txHex, "hex");
  const sighashEntry =
    input.sighashType !== undefined
      ? entry(Buffer.from([0x03]), Buffer.from(Uint32Array.of(input.sighashType).buffer))
      : Buffer.alloc(0);
  const parts = [
    Buffer.from("70736274ff", "hex"),
    entry(Buffer.from([0x00]), tx),
    Buffer.from([0]),
    sighashEntry,
    options.extraInputEntry ?? Buffer.alloc(0),
    entry(Buffer.concat([Buffer.from([0x02]), Buffer.from(key.publicKey)]), Buffer.from(signature)),
    Buffer.from([0]),
    ...(options.withOutputs === false ? [] : decoded.outputs.map(() => Buffer.from([0]))),
  ];
  return Buffer.concat(parts).toString("base64");
}

function scriptSigOf(txHex: string): string[] {
  const tx = bitcoin.Transaction.fromHex(txHex);
  return (bitcoin.script.decompile(tx.ins[0].script) ?? []).map((chunk) => Buffer.from(chunk as Uint8Array).toString("hex"));
}

function deviceWith(replies: DeviceResponse[]) {
  const sent: Record<string, unknown>[] = [];
  const transport: INeuraiTransport = {
    connected: true,
    async open() {},
    async close() {},
    async sendCommand(command) {
      sent.push(command);
      const next = replies.shift();
      if (!next) throw new Error("Mock transport: no scripted reply left");
      return next;
    },
    async sendCommandFinal(command) {
      return this.sendCommand(command);
    },
    async sendCommandHeartbeat(command) {
      return this.sendCommand(command);
    },
  };
  return { device: new NeuraiESP32({ transport }), sent };
}

describe("the device's answer", () => {
  it("takes the signatures of the firmware's minimal PSBT, with or without output maps", () => {
    const { psbt } = psbtFor(previousTx(p2pkh));
    const full = finalizeSignedPSBT(psbt, deviceAnswer(psbt), NETWORK);
    const minimal = finalizeSignedPSBT(psbt, deviceAnswer(psbt, { withOutputs: false }), NETWORK);
    expect(minimal).toEqual(full);
    expect(scriptSigOf(full.txHex)).toEqual([expect.stringMatching(/^30.*01$/), pubkeyHex]);
  });

  it("rejects an answer for a different transaction, whichever way it is read", () => {
    const { psbt, raw } = psbtFor(previousTx(p2pkh));
    const other = raw.slice(0, -8) + "01000000"; // locktime 1
    expect(() => finalizeSignedPSBT(psbt, deviceAnswer(psbt, { tx: other }), NETWORK)).toThrow(
      /different transactions/
    );
    expect(() => finalizeSignedPSBT(psbt, deviceAnswer(psbt, { tx: other, withOutputs: false }), NETWORK)).toThrow(
      /different transaction than the one it was sent/
    );
  });

  it("rejects an answer that conflicts with the original instead of falling back", () => {
    const { psbt } = psbtFor(previousTx(p2pkh), { sighashType: 0x01 });
    // A readable PSBT whose sighash type differs: a conflict, never the minimal path.
    const answer = Buffer.from(deviceAnswer(psbt), "base64");
    const at = answer.indexOf(Buffer.from("0103" + "04" + "01000000", "hex"));
    answer.writeUInt32LE(0x83, at + 3);
    expect(() => finalizeSignedPSBT(psbt, answer.toString("base64"), NETWORK)).toThrow(
      /conflict in input 0: sighash type/
    );
    // A second, different signature for the same key.
    const { psbt: plain } = psbtFor(previousTx(p2pkh));
    const stale = bitcoin.script.signature.encode(Buffer.from(key.sign(Buffer.alloc(32, 1))), 0x01);
    const withStale = updatePsbtInput(plain, 0, {
      partialSig: [{ pubkeyHex, signatureHex: Buffer.from(stale).toString("hex") }],
    });
    expect(() => finalizeSignedPSBT(withStale, deviceAnswer(withStale), NETWORK)).toThrow(
      new RegExp(`conflict in input 0: partial signature ${pubkeyHex}`)
    );
  });

  it("rejects unexpected fields in a minimal answer", () => {
    const { psbt } = psbtFor(previousTx(p2pkh));
    const extra = entry(Buffer.from([0x05]), Buffer.from("51", "hex"));
    expect(() =>
      finalizeSignedPSBT(psbt, deviceAnswer(psbt, { withOutputs: false, extraInputEntry: extra }), NETWORK)
    ).toThrow(/unexpected field \(key 05\)/);
  });

  it("does not adjust the sighash type: a signature of another type is an error", () => {
    const { psbt } = psbtFor(previousTx(p2pkh), { sighashType: 0x83 });
    expect(() => finalizeSignedPSBT(psbt, deviceAnswer(psbt, { signWith: 0x01 }), NETWORK)).toThrow(
      /uses sighash 0x01, but the input asks for 0x83/
    );
    const ok = finalizeSignedPSBT(psbt, deviceAnswer(psbt), NETWORK);
    expect(scriptSigOf(ok.txHex)[0].endsWith("83")).toBe(true);
  });
});

describe("what is sent to the device", () => {
  it("rejects metadata that does not describe the transaction's input", () => {
    const prev = previousTx(p2pkh);
    const { raw } = psbtFor(prev);
    expect(() =>
      buildPSBTFromRawTransaction({
        network: NETWORK,
        rawUnsignedTransaction: raw,
        inputs: [{ txid: prev.txid, vout: 1, rawTxHex: prev.hex }],
      })
    ).toThrow(/the metadata describes .*:1, but the transaction spends .*:0/);
  });

  it("drops the unlocking data of the raw transaction", () => {
    const prev = previousTx(p2pkh);
    const signedRaw = serializeTransaction({
      version: 2,
      inputs: [{ txid: prev.txid, vout: 0, scriptSigHex: "0101", sequence: 0xffffffff, witness: ["aa"] }],
      outputs: [{ valueSats: 1n, scriptPubKeyHex: "51" }],
      vrefin: [],
      locktime: 0,
    });
    const psbt = buildPSBTFromRawTransaction({
      network: NETWORK,
      rawUnsignedTransaction: signedRaw,
      inputs: [{ txid: prev.txid, vout: 0, rawTxHex: prev.hex }],
    });
    expect(decodePsbt(psbt).unsignedTx.inputs[0]).toEqual({ txid: prev.txid, vout: 0, scriptSigHex: "", sequence: 0xffffffff });
  });

  it("carries a covenant witnessScript, which the device refuses", () => {
    const covenant = "c0ffee";
    const { psbt } = psbtFor(previousTx(p2pkh), { witnessScript: covenant });
    expect(decodePsbt(psbt).inputs[0].witnessScript).toBe(covenant);
    expect(() => assertDeviceCanSignPSBT(psbt)).toThrow(/input #0: it carries a witnessScript/);
  });

  it("refuses before sending what the firmware cannot sign, and sends the rest", async () => {
    const v3 = psbtFor(previousTx(p2pkh, 3)).psbt;
    const withCovenant = psbtFor(previousTx(p2pkh), { witnessScript: "c0ffee" }).psbt;
    const supported = psbtFor(previousTx(p2pkh)).psbt;
    const { device, sent } = deviceWith([{ status: "success", psbt: deviceAnswer(supported), signed_inputs: 1 } as DeviceResponse]);

    await expect(device.signPsbt(v3)).rejects.toThrow(/previous transaction of input #0 is version 3/);
    await expect(device.signPsbt(withCovenant)).rejects.toThrow(/witnessScript/);
    expect(sent).toEqual([]);

    const response = await device.signPsbt(supported);
    expect(sent).toEqual([{ action: "sign_psbt", psbt: supported }]);
    expect(finalizeSignedPSBT(supported, response.psbt, NETWORK).txId).toHaveLength(64);
  });
});
