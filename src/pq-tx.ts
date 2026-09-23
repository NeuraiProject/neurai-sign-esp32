/**
 * Raw-transaction builder for the Post-Quantum (ML-DSA-44 / AuthScript) signing
 * path. PSBT cannot represent AuthScript witness v1 inputs, so spending from PQ
 * addresses uses an unsigned raw transaction + per-input metadata sent to the
 * device via the `sign_tx` action. See docs/pq-protocol-design.md §4.
 *
 * The firmware signs these inputs as generic AuthScript witness v1 (`nc1p…` /
 * `tnc1p…`, scriptPubKey `5120<C>`). Strict PQ v2 (`pq1z…`) and strict ECDSA v3
 * (`nq1r…`) prevouts need a different sighash, so they are rejected here
 * instead of producing a signature the node refuses. Outputs may pay to any
 * address type.
 */

import { estimateFee, rawAmountForDevice, toRawAmount, type DecimalAmount } from "./amounts.js";
import { Buffer } from "buffer";
import * as bitcoin from "bitcoinjs-lib";
import { authScriptWitnessVersionOfScript, encodeDestinationScript } from "./pq-address.js";
import type { IPQUTXO, ITxOutput } from "./types.js";

/** Phase-1 payload limits (docs §4). */
export const MAX_PQ_INPUTS = 4;
export const MAX_OUTPUTS = 16;

const DEFAULT_FEE_RATE = 1024;
const TX_OVERHEAD = 10;
/** Worst-case vbytes for a PQ AuthScript input (auth type + ~2421B sig + ~1313B pubkey). */
const PQ_INPUT_VBYTES = 977;
const DUST_THRESHOLD = 546n;

/** One entry of the `sign_tx` request `inputs[]` array. */
export interface IPQSignInput {
  index: number;
  /** Exact JSON integer: safe number or integer text. */
  amount: number | string;
  script_pub_key: string;
}

export interface IBuildUnsignedPQTxOptions {
  utxos: IPQUTXO[];
  outputs: ITxOutput[];
  /** Change address (defaults to the device's own PQ address). */
  changeAddress: string;
  /** Fee rate in satoshis per byte (default: 1024). */
  feeRate?: DecimalAmount;
  /** Transaction version (default: 2). */
  version?: number;
}

export interface IUnsignedPQTx {
  /** Raw unsigned transaction hex (no scriptSigs, no witnesses). */
  rawTxHex: string;
  /** Per-input metadata for the `sign_tx` request. */
  inputs: IPQSignInput[];
}

/**
 * Throw if a prevout scriptPubKey is a strict AuthScript program (OP_2 / OP_3):
 * `sign_tx` signs witness v1 only. Unknown or empty scripts pass (the device
 * checks what it can); the old check-free behaviour is kept for them.
 */
export function assertSignTxPrevoutScript(scriptPubKey: string | undefined, index: number): void {
  if (!scriptPubKey) return;
  const version = authScriptWitnessVersionOfScript(scriptPubKey);
  if (version === 2 || version === 3) {
    throw new Error(
      `Input #${index} spends a strict AuthScript witness v${version} output ` +
        `(${version === 2 ? "pq1z…" : "nq1r…"}); the NeuraiHW sign_tx flow signs witness v1 (nc1p…) inputs only`
    );
  }
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

  utxos.forEach((utxo, index) => assertSignTxPrevoutScript(utxo.scriptPubKey, index));

  const tx = new bitcoin.Transaction();
  tx.version = options.version ?? 2;
  if (tx.version === 3) {
    throw new Error("Transaction version 3 (NIP-014 reference inputs) is not supported");
  }

  for (const utxo of utxos) {
    tx.addInput(Buffer.from(utxo.txid, "hex").reverse(), utxo.vout, 0xffffffff);
  }

  const outputScripts = outputs.map((o) => encodeDestinationScript(o.address));
  let outputsVbytes = 0;
  for (let i = 0; i < outputs.length; i += 1) {
    tx.addOutput(outputScripts[i], toRawAmount(outputs[i].value, "output.value"));
    outputsVbytes += outputVbytes(outputScripts[i]);
  }

  const inputAmounts = utxos.map(u => {
    toRawAmount(u.satoshis, "utxo.satoshis");
    // Asset quantities must never fund XNA outputs or fees. Their prevout value is zero.
    return toRawAmount(u.sighashAmount ?? u.satoshis, "prevout amount");
  });
  const totalInputValue = toRawAmount(inputAmounts.reduce((sum, value) => sum + value, 0n), "total inputs");
  const totalOutputValue = toRawAmount(outputs.reduce((sum, o) => sum + toRawAmount(o.value, "output.value"), 0n), "total outputs");

  const changeScript = encodeDestinationScript(changeAddress);
  const estimatedSize =
    TX_OVERHEAD +
    utxos.length * PQ_INPUT_VBYTES +
    outputsVbytes +
    outputVbytes(changeScript);
  const fee = estimateFee(estimatedSize, feeRate);
  const change = totalInputValue - totalOutputValue - fee;

  if (change < 0n) {
    throw new Error(
      `Insufficient funds: inputs=${totalInputValue}, outputs=${totalOutputValue}, fee=${fee}`
    );
  }

  if (change >= DUST_THRESHOLD) {
    tx.addOutput(changeScript, change);
  }

  const inputs: IPQSignInput[] = utxos.map((utxo, index) => ({
    index,
    amount: rawAmountForDevice(inputAmounts[index]),
    script_pub_key: utxo.scriptPubKey,
  }));

  return { rawTxHex: tx.toHex(), inputs };
}

/** The decoded AuthScript witness stack of a signed PQ input (v1 or strict v2). */
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
 * (the same layout for generic v1 and strict PQ v2 inputs).
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
