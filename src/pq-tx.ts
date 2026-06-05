/**
 * Raw-transaction builder for the Post-Quantum (ML-DSA-44 / AuthScript) signing
 * path. PSBT cannot represent AuthScript witness v1 inputs, so spending from PQ
 * addresses uses an unsigned raw transaction + per-input metadata sent to the
 * device via the `sign_tx` action. See docs/pq-protocol-design.md §4.
 */

import { Buffer } from "buffer";
import * as bitcoin from "bitcoinjs-lib";
import { encodeDestinationScript } from "./pq-address.js";
import type { IPQUTXO, ITxOutput } from "./types.js";

/** Phase-1 payload limits (docs §4). */
export const MAX_PQ_INPUTS = 4;
export const MAX_OUTPUTS = 16;

const DEFAULT_FEE_RATE = 1024;
const TX_OVERHEAD = 10;
/** Worst-case vbytes for a PQ AuthScript input (auth type + ~2421B sig + ~1313B pubkey). */
const PQ_INPUT_VBYTES = 977;
const DUST_THRESHOLD = 546;

/** One entry of the `sign_tx` request `inputs[]` array. */
export interface IPQSignInput {
  index: number;
  amount: number;
  script_pub_key: string;
}

export interface IBuildUnsignedPQTxOptions {
  utxos: IPQUTXO[];
  outputs: ITxOutput[];
  /** Change address (defaults to the device's own PQ address). */
  changeAddress: string;
  /** Fee rate in satoshis per byte (default: 1024). */
  feeRate?: number;
  /** Transaction version (default: 2). */
  version?: number;
}

export interface IUnsignedPQTx {
  /** Raw unsigned transaction hex (no scriptSigs, no witnesses). */
  rawTxHex: string;
  /** Per-input metadata for the `sign_tx` request. */
  inputs: IPQSignInput[];
}

function outputVbytes(script: Buffer): number {
  // value(8) + scriptLen varint(1 for <253) + script
  return 8 + 1 + script.length;
}

/**
 * Build an unsigned raw transaction spending PQ UTXOs, plus the per-input
 * metadata the device needs to sign it. Performs fee/change calculation.
 */
export function buildUnsignedPQTransaction(
  options: IBuildUnsignedPQTxOptions
): IUnsignedPQTx {
  const { utxos, outputs, changeAddress, feeRate = DEFAULT_FEE_RATE } = options;

  if (utxos.length === 0) throw new Error("No UTXOs provided");
  if (outputs.length === 0) throw new Error("No outputs provided");
  if (utxos.length > MAX_PQ_INPUTS) {
    throw new Error(
      `Too many PQ inputs (${utxos.length}); max ${MAX_PQ_INPUTS} in phase 1. Split the spend into multiple transactions.`
    );
  }
  if (outputs.length + 1 > MAX_OUTPUTS) {
    throw new Error(`Too many outputs (${outputs.length}); max ${MAX_OUTPUTS - 1} plus change in phase 1.`);
  }

  const tx = new bitcoin.Transaction();
  tx.version = options.version ?? 2;

  for (const utxo of utxos) {
    tx.addInput(Buffer.from(utxo.txid, "hex").reverse(), utxo.vout, 0xffffffff);
  }

  const outputScripts = outputs.map((o) => encodeDestinationScript(o.address));
  let outputsVbytes = 0;
  for (let i = 0; i < outputs.length; i += 1) {
    tx.addOutput(outputScripts[i], BigInt(outputs[i].value));
    outputsVbytes += outputVbytes(outputScripts[i]);
  }

  const totalInputValue = utxos.reduce((sum, u) => sum + u.satoshis, 0);
  const totalOutputValue = outputs.reduce((sum, o) => sum + o.value, 0);

  const changeScript = encodeDestinationScript(changeAddress);
  const estimatedSize =
    TX_OVERHEAD +
    utxos.length * PQ_INPUT_VBYTES +
    outputsVbytes +
    outputVbytes(changeScript);
  const fee = estimatedSize * feeRate;
  const change = totalInputValue - totalOutputValue - fee;

  if (change < 0) {
    throw new Error(
      `Insufficient funds: inputs=${totalInputValue}, outputs=${totalOutputValue}, fee=${fee}`
    );
  }

  if (change >= DUST_THRESHOLD) {
    tx.addOutput(changeScript, BigInt(change));
  }

  const inputs: IPQSignInput[] = utxos.map((utxo, index) => ({
    index,
    amount: utxo.sighashAmount ?? utxo.satoshis,
    script_pub_key: utxo.scriptPubKey,
  }));

  return { rawTxHex: tx.toHex(), inputs };
}

/** The decoded AuthScript witness stack of a signed PQ input. */
export interface IPQWitness {
  authType: number;
  /** ML-DSA-44 signature (hashType byte stripped). */
  signature: Buffer;
  /** The trailing sighash flag byte. */
  hashType: number;
  /** Raw ML-DSA-44 public key (1312 B, the 0x05 prefix stripped). */
  pubkey: Buffer;
  /** witnessScript bytes (phase 1: OP_TRUE). */
  witnessScript: Buffer;
}

/**
 * Extract and decode the AuthScript witness stack of a signed PQ input:
 *   [authType] [sig||hashType] [0x05||pubkey] [witnessScript]
 */
export function extractPQWitness(
  signedTxHex: string,
  inputIndex = 0
): IPQWitness {
  const tx = bitcoin.Transaction.fromHex(signedTxHex);
  const w = tx.ins[inputIndex]?.witness;
  if (!w || w.length < 4) {
    throw new Error(`Input #${inputIndex} has no AuthScript witness`);
  }
  const sigWithType = Buffer.from(w[1]);
  const serPub = Buffer.from(w[2]);
  return {
    authType: w[0][0],
    signature: Buffer.from(sigWithType.subarray(0, sigWithType.length - 1)),
    hashType: sigWithType[sigWithType.length - 1],
    pubkey: Buffer.from(serPub.subarray(1)), // strip 0x05 prefix
    witnessScript: Buffer.from(w[3]),
  };
}

/**
 * Parse the fully-signed transaction the device returns and compute its id.
 * The device is authoritative over the signed bytes (WYSIWYS); the host parses
 * to validate and to surface the txid.
 */
export function parseSignedPQTransaction(signedTxHex: string): {
  txHex: string;
  txId: string;
} {
  const tx = bitcoin.Transaction.fromHex(signedTxHex);
  return { txHex: signedTxHex, txId: tx.getId() };
}
