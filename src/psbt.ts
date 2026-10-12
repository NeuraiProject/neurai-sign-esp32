/**
 * PSBT helpers for Neurai transactions, on the Neurai PSBT profile of
 * `@neuraiproject/neurai-create-transaction` (BIP-174 version 0 whose
 * transactions use the Neurai serialization).
 *
 * This package supports two build paths:
 * - high-level build from UTXOs + outputs + fee estimation
 * - low-level build from an already-created raw unsigned transaction
 *
 * The second path matches the webwallet integration, where coin selection
 * and fee calculation already happen elsewhere. It accepts any Neurai
 * transaction (version 3 with NIP-014 reference inputs included) and any
 * input, with the covenant behind an AuthScript input as `witnessScript`:
 * Neurai Connect signers handle those. The NeuraiHW firmware does not, and
 * `assertDeviceCanSignPSBT` (called by `NeuraiESP32.signPsbt`) rejects them
 * before anything reaches the device.
 *
 * Outputs may pay to any Neurai address type (P2PKH, `nc1p…`, `pq1z…`,
 * `nq1r…`). Inputs signed with a `partialSig` are P2PKH, or strict ECDSA
 * witness v3 (`nq1r…`) prevouts signed by firmware built with uNeurai >= 0.2.0,
 * whose `PSBT::sign` uses the strict sighash for them; the finalizer then
 * builds the witness `[0x02, sig, pubkey, 0x51]`. Generic AuthScript v1 and
 * strict PQ v2 inputs are not signed with a `partialSig` (see
 * `buildUnsignedPQTransaction` / `sign_tx` for v1).
 *
 * Previous transactions (`nonWitnessUtxo`) may be any Neurai transaction,
 * version 3 included, and must hash to the txid the input spends.
 */

import { estimateFee, toRawAmount } from "./amounts.js";
import { Buffer } from "buffer";
import * as bitcoin from "bitcoinjs-lib";
import {
  combinePsbts,
  createPsbt,
  decodePsbt,
  extractPsbtTransaction,
  finalizePsbt,
  parseTransaction,
  serializeTransaction,
  updatePsbtInput,
  type DecodedTransaction,
  type PsbtBip32Derivation,
  type PsbtInputFields,
  type PsbtPartialSig,
} from "@neuraiproject/neurai-create-transaction";
import { getNetwork } from "./networks.js";
import {
  authScriptWitnessVersionOfScript,
  decodeAddress,
  encodeDestinationScript,
} from "./pq-address.js";
import type {
  IBuildPSBTFromRawOptions,
  IBuildPSBTOptions,
  NetworkType,
} from "./types.js";

const DEFAULT_FEE_RATE = 1024;
const TX_OVERHEAD = 10;
const INPUT_SIZE = 148;
/** Strict ECDSA v3 input: 41 B non-witness + ~112 WU witness (+ marker/flag). */
const ECDSA_V3_INPUT_SIZE = 69;
const OUTPUT_SIZE = 34;
/** AuthScript output: value(8) + len(1) + OP_n 0x20 <32>. */
const AUTHSCRIPT_OUTPUT_SIZE = 43;
const DUST_THRESHOLD = 546n;
const PSBT_IN_PARTIAL_SIG = 0x02;
const PSBT_IN_SIGHASH_TYPE = 0x03;

/** Estimated size of a P2PKH (148) or strict ECDSA v3 (69) input. */
function inputSize(scriptPubKeyHex: string | undefined): number {
  return scriptPubKeyHex && authScriptWitnessVersionOfScript(scriptPubKeyHex) === 3
    ? ECDSA_V3_INPUT_SIZE
    : INPUT_SIZE;
}

/** Estimated size of a P2PKH (34) or AuthScript (43) output. */
function outputSize(address: string): number {
  return decodeAddress(address).type === "pq" ? AUTHSCRIPT_OUTPUT_SIZE : OUTPUT_SIZE;
}

function parseMasterFingerprint(hex: string): string {
  if (hex.length !== 8) {
    throw new Error(
      `Invalid master fingerprint: expected 8 hex chars, got ${hex.length}`
    );
  }
  return hex;
}

/**
 * scriptPubKey (hex) of a destination address. AuthScript (Bech32m: `nc1p…`,
 * `pq1z…`, `nq1r…`) addresses are checked against the network's chain here;
 * legacy addresses go through bitcoinjs-lib, which checks their version byte.
 */
function outputScript(address: string, network: NetworkType): string {
  const decoded = decodeAddress(address);
  if (decoded.type === "pq") {
    const psbtIsTestnet = network.endsWith("-test");
    if ((decoded.network === "testnet") !== psbtIsTestnet) {
      throw new Error(
        `Address ${address} is a ${decoded.network} address but the PSBT network is ${network}`
      );
    }
    return encodeDestinationScript(address).toString("hex");
  }
  return Buffer.from(bitcoin.address.toOutputScript(address, getNetwork(network))).toString("hex");
}

export function buildPSBT(options: IBuildPSBTOptions): string {
  const {
    network,
    utxos,
    outputs,
    changeAddress,
    pubkey,
    masterFingerprint,
    derivationPath,
    feeRate = DEFAULT_FEE_RATE,
  } = options;

  if (utxos.length === 0) {
    throw new Error("No UTXOs provided");
  }
  if (outputs.length === 0) {
    throw new Error("No outputs provided");
  }

  const outputValues = outputs.map(output => toRawAmount(output.value, "output.value"));
  const totalOutputValue = toRawAmount(outputValues.reduce((sum, value) => sum + value, 0n), "total outputs");
  const inputValues = utxos.map(utxo => toRawAmount(utxo.satoshis, "utxo.satoshis"));
  const totalInputValue = toRawAmount(inputValues.reduce((sum, value) => sum + value, 0n), "total inputs");
  const estimatedSize =
    TX_OVERHEAD +
    utxos.reduce((sum, utxo) => sum + inputSize(utxo.scriptPubKey), 0) +
    outputs.reduce((sum, output) => sum + outputSize(output.address), 0) +
    outputSize(changeAddress);
  const fee = estimateFee(estimatedSize, feeRate);
  const change = totalInputValue - totalOutputValue - fee;

  if (change < 0n) {
    throw new Error(
      `Insufficient funds: inputs=${totalInputValue}, outputs=${totalOutputValue}, fee=${fee}`
    );
  }

  const bip32Derivation: PsbtBip32Derivation[] = [
    {
      masterFingerprintHex: parseMasterFingerprint(masterFingerprint),
      path: derivationPath,
      pubkeyHex: pubkey,
    },
  ];
  const withChange = change >= DUST_THRESHOLD;
  const unsignedTx: DecodedTransaction = {
    version: 2,
    inputs: utxos.map((utxo) => ({ txid: utxo.txid, vout: utxo.vout, scriptSigHex: "", sequence: 0xffffffff })),
    outputs: [
      ...outputs.map((output, index) => ({
        valueSats: outputValues[index],
        scriptPubKeyHex: outputScript(output.address, network),
      })),
      ...(withChange ? [{ valueSats: change, scriptPubKeyHex: outputScript(changeAddress, network) }] : []),
    ],
    vrefin: [],
    locktime: 0,
  };

  return createPsbt({
    unsignedTx,
    inputs: utxos.map((utxo) => ({ previousTx: utxo.rawTxHex, bip32Derivation })),
    // The change output carries the device's key path, so it is shown as change.
    outputs: withChange ? [...outputs.map(() => undefined), { bip32Derivation }] : [],
  });
}

/**
 * PSBT of an already-built transaction. Unlocking data present in it
 * (scriptSig, witness) is not carried: the PSBT transaction is unsigned.
 * `inputs[i]` describes input i, which must spend `txid:vout`.
 */
export function buildPSBTFromRawTransaction(options: IBuildPSBTFromRawOptions): string {
  getNetwork(options.network);
  const tx = parseTransaction(options.rawUnsignedTransaction);
  const inputs: PsbtInputFields[] = [];

  const unsignedTx: DecodedTransaction = {
    ...tx,
    inputs: tx.inputs.map((input, index) => {
      const metadata = options.inputs[index];
      if (!metadata) {
        throw new Error(`Missing input metadata for input #${index}`);
      }
      if (metadata.txid.toLowerCase() !== input.txid || metadata.vout !== input.vout) {
        throw new Error(
          `Input #${index}: the metadata describes ${metadata.txid}:${metadata.vout}, ` +
            `but the transaction spends ${input.txid}:${input.vout}`
        );
      }

      const fields: PsbtInputFields = { previousTx: metadata.rawTxHex };
      if (metadata.masterFingerprint && metadata.derivationPath && metadata.pubkey) {
        fields.bip32Derivation = [
          {
            masterFingerprintHex: parseMasterFingerprint(metadata.masterFingerprint),
            path: metadata.derivationPath,
            pubkeyHex: metadata.pubkey,
          },
        ];
      }
      if (metadata.sighashType !== undefined) fields.sighashType = metadata.sighashType;
      if (metadata.witnessScript !== undefined) fields.witnessScript = metadata.witnessScript;
      inputs.push(fields);

      return { txid: input.txid, vout: input.vout, scriptSigHex: "", sequence: metadata.sequence ?? input.sequence };
    }),
  };

  return createPsbt({ unsignedTx, inputs });
}

/** Finalize every input of a signed PSBT and extract the transaction. */
export function finalizePSBT(
  signedPsbtBase64: string,
  network: NetworkType
): { txHex: string; txId: string } {
  getNetwork(network);
  const { hex, txid } = extractPsbtTransaction(finalizePsbt(signedPsbtBase64));
  return { txHex: hex, txId: txid };
}

/**
 * Merge a signer's PSBT (the device's, or a Neurai Connect wallet's) into the
 * original, finalize the inputs it signed and extract the transaction; inputs
 * nobody signed are left empty. A signature whose sighash differs from the
 * input's `sighashType`, or any field the two PSBTs disagree on, is an error.
 */
export function finalizeSignedPSBT(
  originalPsbtBase64: string,
  signedPsbtBase64: string,
  network: NetworkType
): { txHex: string; txId: string } {
  getNetwork(network);
  const merged = mergeSignerPsbt(originalPsbtBase64, signedPsbtBase64);
  const signedInputs = decodePsbt(merged).inputs.flatMap((input, index) =>
    input.partialSig.length > 0 || input.finalScriptSig !== undefined || input.finalScriptWitness !== undefined
      ? [index]
      : []
  );
  const finalized = signedInputs.length > 0 ? finalizePsbt(merged, { inputs: signedInputs }) : merged;
  const { hex, txid } = extractPsbtTransaction(finalized, { allowIncomplete: true });
  return { txHex: hex, txId: txid };
}

export function validatePSBT(psbtBase64: string, network: NetworkType): boolean {
  try {
    getNetwork(network);
    decodePsbt(psbtBase64);
    return true;
  } catch {
    return false;
  }
}

/**
 * Reject, before anything reaches the device, what the NeuraiHW firmware
 * (uNeurai `PSBT`) cannot sign: a version-3 transaction or previous
 * transaction (it does not read NIP-014 reference inputs) and inputs with a
 * `witnessScript` (it would sign them with a Bitcoin segwit sighash).
 */
export function assertDeviceCanSignPSBT(psbtBase64: string): void {
  const decoded = decodePsbt(psbtBase64);
  if (decoded.unsignedTx.version === 3) {
    throw new Error(
      "NeuraiHW cannot sign a version-3 transaction: its firmware does not read NIP-014 reference inputs"
    );
  }
  decoded.inputs.forEach((input, index) => {
    if (input.previousTx !== undefined && parseTransaction(input.previousTx).version === 3) {
      throw new Error(
        `NeuraiHW cannot sign this transaction: the previous transaction of input #${index} is version 3, ` +
          "which its firmware cannot read"
      );
    }
    if (input.witnessScript !== undefined) {
      throw new Error(
        `NeuraiHW cannot sign input #${index}: it carries a witnessScript (an AuthScript covenant), ` +
          "which its firmware does not sign"
      );
    }
  });
}

/**
 * A signer's PSBT merged into the original. A standard PSBT is combined
 * (conflicts and a different transaction are errors). Only a response that is
 * not a readable PSBT is tried as the firmware's minimal form.
 */
function mergeSignerPsbt(originalPsbtBase64: string, signedPsbtBase64: string): string {
  let readable = true;
  try {
    decodePsbt(signedPsbtBase64);
  } catch {
    readable = false;
  }
  return readable
    ? combinePsbts(originalPsbtBase64, signedPsbtBase64)
    : applyMinimalDevicePsbt(originalPsbtBase64, signedPsbtBase64);
}

/**
 * The firmware's minimal PSBT (uNeurai `PSBT::to_stream`): a global map with
 * only the unsigned transaction, input maps with only PSBT_IN_SIGHASH_TYPE and
 * PSBT_IN_PARTIAL_SIG, and empty output maps, which may be missing. The
 * transaction must be byte for byte the one of the original PSBT before any
 * signature is taken; the signatures then go through `updatePsbtInput`.
 */
function applyMinimalDevicePsbt(originalPsbtBase64: string, signedPsbtBase64: string): string {
  const original = decodePsbt(originalPsbtBase64);
  const originalTx = serializeTransaction(original.unsignedTx, { includeWitness: false });
  const buffer = Buffer.from(signedPsbtBase64, "base64");
  if (buffer.length < 5 || buffer.toString("ascii", 0, 4) !== "psbt" || buffer[4] !== 0xff) {
    throw new Error("NeuraiHW returned an invalid PSBT header");
  }

  let offset = 5;
  const readMap = (): { key: Buffer; value: Buffer }[] => {
    const entries: { key: Buffer; value: Buffer }[] = [];
    for (;;) {
      const keyLen = readPsbtVarInt(buffer, offset);
      offset += keyLen.size;
      if (keyLen.value === 0) return entries;
      const key = readBytes(keyLen.value);
      const valueLen = readPsbtVarInt(buffer, offset);
      offset += valueLen.size;
      entries.push({ key, value: readBytes(valueLen.value) });
    }
  };
  const readBytes = (length: number): Buffer => {
    if (offset + length > buffer.length) throw new Error("Format Error: Unexpected End of PSBT");
    const bytes = buffer.subarray(offset, offset + length);
    offset += length;
    return bytes;
  };

  const global = readMap();
  if (global.length !== 1 || global[0].key.length !== 1 || global[0].key[0] !== 0x00) {
    throw new Error("NeuraiHW returned a PSBT whose global map is not just the unsigned transaction");
  }
  if (global[0].value.toString("hex") !== originalTx) {
    throw new Error("NeuraiHW returned a PSBT for a different transaction than the one it was sent");
  }

  let merged = originalPsbtBase64;
  original.inputs.forEach((input, index) => {
    const partialSig: PsbtPartialSig[] = [];
    for (const { key, value } of readMap()) {
      if (key[0] === PSBT_IN_PARTIAL_SIG && key.length > 1) {
        partialSig.push({ pubkeyHex: key.subarray(1).toString("hex"), signatureHex: value.toString("hex") });
      } else if (key.length === 1 && key[0] === PSBT_IN_SIGHASH_TYPE && value.length === 4) {
        if (value.readUInt32LE(0) !== input.sighashType) {
          throw new Error(`NeuraiHW returned input #${index} with a sighash type the original PSBT does not have`);
        }
      } else {
        throw new Error(`NeuraiHW returned input #${index} with an unexpected field (key ${key.toString("hex")})`);
      }
    }
    if (partialSig.length > 0) merged = updatePsbtInput(merged, index, { partialSig });
  });

  // Output maps: empty, or not written at all.
  const rest = buffer.subarray(offset);
  if (rest.length > original.outputs.length || rest.some((byte) => byte !== 0)) {
    throw new Error("NeuraiHW returned a PSBT with unexpected data after its inputs");
  }
  return merged;
}

function readPsbtVarInt(buffer: Buffer, offset: number) {
  if (offset >= buffer.length) {
    throw new Error("Format Error: Unexpected End of PSBT");
  }

  const first = buffer[offset];
  if (first < 0xfd) {
    return { value: first, size: 1 };
  }
  if (first === 0xfd) {
    if (offset + 2 >= buffer.length) {
      throw new Error("Format Error: Unexpected End of PSBT");
    }
    return { value: buffer.readUInt16LE(offset + 1), size: 3 };
  }
  if (first === 0xfe) {
    if (offset + 4 >= buffer.length) {
      throw new Error("Format Error: Unexpected End of PSBT");
    }
    return { value: buffer.readUInt32LE(offset + 1), size: 5 };
  }
  throw new Error("PSBT values larger than 32 bits are not supported");
}
