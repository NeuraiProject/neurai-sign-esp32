/**
 * PSBT helpers for Neurai P2PKH transactions (and strict ECDSA witness v3
 * inputs, see below).
 *
 * This package supports two build paths:
 * - high-level build from UTXOs + outputs + fee estimation
 * - low-level build from an already-created raw unsigned transaction
 *
 * The second path matches the webwallet integration, where coin selection
 * and fee calculation already happen elsewhere.
 *
 * Outputs may pay to any Neurai address type (P2PKH, `nc1p…`, `pq1z…`,
 * `nq1r…`). Inputs are P2PKH, or strict ECDSA witness v3 (`nq1r…`) prevouts
 * signed by firmware built with uNeurai >= 0.2.0, whose `PSBT::sign` uses the
 * strict sighash for them; the finalizer then builds the witness
 * `[0x02, sig, pubkey, 0x51]`. Generic AuthScript v1 and strict PQ v2 inputs
 * cannot be signed through a PSBT (see `buildUnsignedPQTransaction` /
 * `sign_tx` for v1).
 *
 * Previous transactions (`nonWitnessUtxo`) may be any Neurai transaction,
 * version 3 included. bitcoinjs-lib cannot read those (see `previousOutput`),
 * so this module never lets it parse a `nonWitnessUtxo`: inputs get it through
 * the bip174 layer and are finalized without `Psbt.finalizeInput`.
 */

import { estimateFee, toRawAmount } from "./amounts.js";
import { Buffer } from "buffer";
import * as bitcoin from "bitcoinjs-lib";
import { computeTxid, parseTransaction } from "@neuraiproject/neurai-create-transaction";
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

type PsbtInput = bitcoin.Psbt['data']['inputs'][number];
type PsbtCache = {
  __TX?: bitcoin.Transaction;
  __EXTRACTED_TX?: bitcoin.Transaction;
  __FEE?: bigint;
  __FEE_RATE?: number;
};

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

function parseMasterFingerprint(hex: string): Buffer {
  if (hex.length !== 8) {
    throw new Error(
      `Invalid master fingerprint: expected 8 hex chars, got ${hex.length}`
    );
  }
  return Buffer.from(hex, "hex");
}

/**
 * Build a PSBT output descriptor for a destination address. AuthScript
 * (Bech32m: `nc1p…`, `pq1z…`, `nq1r…`) addresses are not understood by
 * bitcoinjs-lib, so they are encoded to a raw scriptPubKey here (after checking
 * that their chain matches `network`); legacy addresses are passed through by
 * address so bitcoinjs-lib checks their version byte.
 */
function addressOutput(
  address: string,
  value: bigint,
  network: NetworkType
): { address: string; value: bigint } | { script: Buffer; value: bigint } {
  const decoded = decodeAddress(address);
  if (decoded.type === "pq") {
    const psbtIsTestnet = network.endsWith("-test");
    if ((decoded.network === "testnet") !== psbtIsTestnet) {
      throw new Error(
        `Address ${address} is a ${decoded.network} address but the PSBT network is ${network}`
      );
    }
    return { script: encodeDestinationScript(address), value };
  }
  return { address, value };
}

function getSignatureHashType(signature: Uint8Array): number {
  return signature[signature.length - 1] ?? 1;
}

function checkPartialSigSighashes(input: PsbtInput) {
  if (!input.sighashType || !input.partialSig) return;

  let normalizedSighashType = input.sighashType;
  input.partialSig.forEach((pSig) => {
    const hashType = getSignatureHashType(pSig.signature);
    if (normalizedSighashType !== hashType) {
      console.warn("[NeuraiSignESP32] Adjusting input sighashType to match returned signature", {
        previousSighashType: normalizedSighashType,
        returnedHashType: hashType,
      });
      normalizedSighashType = hashType;
    }
  });
  input.sighashType = normalizedSighashType;
}

/** Display-order (RPC) txid of a bitcoinjs input hash. */
function displayTxid(hash: Uint8Array): string {
  return Buffer.from(hash).reverse().toString("hex");
}

/**
 * The output an input spends, read from its `nonWitnessUtxo` with the Neurai
 * transaction codec. bitcoinjs-lib cannot read Neurai version-3 transactions:
 * NIP-014 serializes their reference inputs (`vrefin`), even an empty list,
 * after the outputs, and bitcoinjs-lib rejects the leftover bytes with
 * "Transaction has unexpected data". The previous transaction must hash to the
 * txid the input spends, so its amounts are the real ones. Returns null when
 * it has no output `vout`.
 */
function previousOutput(
  rawTx: Uint8Array,
  txid: string,
  vout: number,
  inputIndex: number
): { script: Buffer; value: bigint } | null {
  const hex = Buffer.from(rawTx).toString("hex");
  if (computeTxid(hex) !== txid.toLowerCase()) {
    throw new Error(`Input #${inputIndex}: the previous transaction is not ${txid}`);
  }
  const output = parseTransaction(hex).outputs[vout];
  return output ? { script: Buffer.from(output.scriptPubKeyHex, "hex"), value: output.valueSats } : null;
}

/**
 * `psbt.addInput` with its previous transaction. The `nonWitnessUtxo` goes in
 * through the bip174 layer: bitcoinjs-lib's `addInput` would parse it, which
 * fails for version-3 transactions (see `previousOutput`, which checks it).
 */
function addInputWithPreviousTx(
  psbt: bitcoin.Psbt,
  inputData: Parameters<bitcoin.Psbt["addInput"]>[0],
  rawTxHex: string
): void {
  const inputIndex = psbt.inputCount;
  const nonWitnessUtxo = Buffer.from(rawTxHex, "hex");
  // bitcoinjs-lib takes the hash as a display txid or in internal byte order.
  const txid = typeof inputData.hash === "string" ? inputData.hash : displayTxid(inputData.hash);
  if (!previousOutput(nonWitnessUtxo, txid, inputData.index, inputIndex)) {
    throw new Error(`Input #${inputIndex}: the previous transaction has no output ${inputData.index}`);
  }
  psbt.addInput(inputData);
  psbt.data.updateInput(inputIndex, { nonWitnessUtxo });
}

/**
 * Set the final scripts of an input and drop its signing data, as
 * `Psbt.finalizeInput` does, without letting bitcoinjs-lib parse the input's
 * `nonWitnessUtxo` (see `previousOutput`).
 */
function setFinalScripts(
  psbt: bitcoin.Psbt,
  inputIndex: number,
  finalScripts: { finalScriptSig: Buffer } | { finalScriptWitness: Buffer }
): void {
  psbt.data.updateInput(inputIndex, finalScripts);
  psbt.data.clearFinalizedInput(inputIndex);
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

  const psbt = new bitcoin.Psbt({ network: getNetwork(network) });
  const bip32Derivation = [
    {
      masterFingerprint: parseMasterFingerprint(masterFingerprint),
      path: derivationPath,
      pubkey: Buffer.from(pubkey, "hex"),
    },
  ];

  for (const utxo of utxos) {
    addInputWithPreviousTx(psbt, { hash: utxo.txid, index: utxo.vout, bip32Derivation }, utxo.rawTxHex);
  }

  for (const output of outputs) {
    psbt.addOutput(addressOutput(output.address, toRawAmount(output.value, "output.value"), network));
  }

  const DUST_THRESHOLD = 546n;
  if (change >= DUST_THRESHOLD) {
    psbt.addOutput({
      ...addressOutput(changeAddress, change, network),
      bip32Derivation,
    });
  }

  return psbt.toBase64();
}

export function buildPSBTFromRawTransaction(options: IBuildPSBTFromRawOptions): string {
  const network = getNetwork(options.network);
  if (parseTransaction(options.rawUnsignedTransaction).version === 3) {
    throw new Error(
      "A version-3 transaction cannot be signed through a PSBT: its NIP-014 reference inputs have no PSBT field"
    );
  }
  const tx = bitcoin.Transaction.fromHex(options.rawUnsignedTransaction);
  const psbt = new bitcoin.Psbt({ network });

  psbt.setVersion(tx.version);
  psbt.setLocktime(tx.locktime);

  for (let index = 0; index < tx.ins.length; index += 1) {
    const input = tx.ins[index];
    const metadata = options.inputs[index];

    if (!metadata) {
      throw new Error(`Missing input metadata for input #${index}`);
    }

    const inputData: Parameters<typeof psbt.addInput>[0] = {
      hash: metadata.txid,
      index: metadata.vout,
      sequence: metadata.sequence ?? input.sequence,
    };

    if (metadata.masterFingerprint && metadata.derivationPath && metadata.pubkey) {
      inputData.bip32Derivation = [
        {
          masterFingerprint: parseMasterFingerprint(metadata.masterFingerprint),
          path: metadata.derivationPath,
          pubkey: Buffer.from(metadata.pubkey, "hex"),
        },
      ];
    }

    if (metadata.sighashType !== undefined) {
      inputData.sighashType = metadata.sighashType;
    }

    addInputWithPreviousTx(psbt, inputData, metadata.rawTxHex);
  }

  for (const output of tx.outs) {
    psbt.addOutput({
      script: Buffer.from(output.script),
      value: output.value,
    });
  }

  return psbt.toBase64();
}

export function finalizePSBT(
  signedPsbtBase64: string,
  network: NetworkType
): { txHex: string; txId: string } {
  const psbt = bitcoin.Psbt.fromBase64(signedPsbtBase64, {
    network: getNetwork(network),
  });

  finalizeNeuraiP2pkhInputs(psbt, true);

  const tx = extractFinalizableTransaction(psbt, true);
  return {
    txHex: tx.toHex(),
    txId: tx.getId(),
  };
}

export function finalizeSignedPSBT(
  originalPsbtBase64: string,
  signedPsbtBase64: string,
  network: NetworkType
): { txHex: string; txId: string } {
  const net = getNetwork(network);
  const psbt = bitcoin.Psbt.fromBase64(originalPsbtBase64, { network: net });

  let mergedWithStandardPsbt = false;
  try {
    const signedPsbt = bitcoin.Psbt.fromBase64(signedPsbtBase64, { network: net });
    psbt.combine(signedPsbt);
    mergedWithStandardPsbt = true;
  } catch {
    // uNeurai can return a minimal signed PSBT that bitcoinjs-lib cannot fully parse.
  }

  if (!mergedWithStandardPsbt) {
    const partialSigsByInput = extractPartialSigsFromUNeuraiPsbt(
      originalPsbtBase64,
      signedPsbtBase64,
      psbt.inputCount
    );

    partialSigsByInput.forEach((partialSig, index) => {
      if (partialSig.length === 0) {
        return;
      }
      psbt.updateInput(index, { partialSig });
    });
  }

  psbt.data.inputs.forEach((input) => checkPartialSigSighashes(input));
  finalizeNeuraiP2pkhInputs(psbt, false);

  const tx = extractFinalizableTransaction(psbt, false);
  return {
    txHex: tx.toHex(),
    txId: tx.getId(),
  };
}

export function validatePSBT(psbtBase64: string, network: NetworkType): boolean {
  try {
    bitcoin.Psbt.fromBase64(psbtBase64, { network: getNetwork(network) });
    return true;
  } catch {
    return false;
  }
}

function extractPartialSigsFromUNeuraiPsbt(
  originalBase64: string,
  signedBase64: string,
  inputCount: number
) {
  const originalBuffer = Buffer.from(originalBase64, "base64");
  const buffer = Buffer.from(signedBase64, "base64");
  const partialSigsByInput: { pubkey: Buffer; signature: Buffer }[][] = Array.from(
    { length: inputCount },
    () => []
  );

  if (buffer.length < 5 || buffer.toString("ascii", 0, 4) !== "psbt" || buffer[4] !== 0xff) {
    throw new Error("NeuraiHW returned an invalid PSBT header");
  }

  let offset = getFirstInputSectionOffset(originalBuffer);

  for (let inputIndex = 0; inputIndex < inputCount; inputIndex += 1) {
    while (offset < buffer.length) {
      const keyLen = readPsbtVarInt(buffer, offset);
      offset += keyLen.size;

      if (keyLen.value === 0) {
        break;
      }

      const key = buffer.subarray(offset, offset + keyLen.value);
      offset += keyLen.value;

      const valueLen = readPsbtVarInt(buffer, offset);
      offset += valueLen.size;
      const value = buffer.subarray(offset, offset + valueLen.value);
      offset += valueLen.value;

      if (key.length > 1 && key[0] === 0x02) {
        partialSigsByInput[inputIndex].push({
          pubkey: Buffer.from(key.subarray(1)),
          signature: Buffer.from(value),
        });
      }
    }
  }

  return partialSigsByInput;
}

function getFirstInputSectionOffset(buffer: Buffer) {
  if (buffer.length < 5 || buffer.toString("ascii", 0, 4) !== "psbt" || buffer[4] !== 0xff) {
    throw new Error("Invalid original PSBT header");
  }

  let offset = 5;

  const globalKeyLen = readPsbtVarInt(buffer, offset);
  offset += globalKeyLen.size + globalKeyLen.value;

  const globalValueLen = readPsbtVarInt(buffer, offset);
  offset += globalValueLen.size + globalValueLen.value;

  if (offset >= buffer.length || buffer[offset] !== 0x00) {
    throw new Error("Invalid original PSBT global section");
  }

  return offset + 1;
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

/** Serialize a witness stack the way PSBT_IN_FINAL_SCRIPTWITNESS stores it. */
function witnessStackToScriptWitness(stack: Buffer[]): Buffer {
  const varint = (n: number): Buffer => {
    if (n < 0xfd) return Buffer.from([n]);
    if (n <= 0xffff) {
      const b = Buffer.alloc(3);
      b[0] = 0xfd;
      b.writeUInt16LE(n, 1);
      return b;
    }
    const b = Buffer.alloc(5);
    b[0] = 0xfe;
    b.writeUInt32LE(n, 1);
    return b;
  };
  return Buffer.concat([
    varint(stack.length),
    ...stack.flatMap((item) => [varint(item.length), item]),
  ]);
}

/**
 * Finalize the device-signed inputs: P2PKH (scriptSig `<sig> <pubkey>`) and
 * strict ECDSA witness v3 (witness `[0x02, sig, pubkey, 0x51]`).
 */
function finalizeNeuraiP2pkhInputs(psbt: bitcoin.Psbt, requireAllInputs: boolean) {
  let finalizedCount = 0;

  for (let index = 0; index < psbt.inputCount; index += 1) {
    const input = psbt.data.inputs[index];
    if (input.finalScriptSig || input.finalScriptWitness) {
      finalizedCount += 1;
      continue;
    }

    const partialSig = input.partialSig?.[0];
    const nonWitnessUtxo = input.nonWitnessUtxo;
    const txInput = psbt.txInputs[index];

    if (!partialSig || !nonWitnessUtxo || !txInput) {
      if (requireAllInputs) {
        throw new Error(`Missing data to finalize input #${index}`);
      }
      continue;
    }

    const prevOut = previousOutput(nonWitnessUtxo, displayTxid(txInput.hash), txInput.index, index);
    if (!prevOut) {
      if (requireAllInputs) {
        throw new Error(`Missing prevout to finalize input #${index}`);
      }
      continue;
    }

    // The check Psbt.finalizeInput made before this module stopped using it.
    if (input.sighashType !== undefined && getSignatureHashType(partialSig.signature) !== input.sighashType) {
      throw new Error(`Input #${index}: the signature sighash does not match the input sighash type`);
    }

    const witnessVersion = authScriptWitnessVersionOfScript(prevOut.script);
    if (witnessVersion === 3) {
      // Strict ECDSA witness v3: the consensus template is exactly
      // [authType 0x02, sig||hashType, compressed pubkey, witnessScript OP_TRUE].
      const pubkey = Buffer.from(partialSig.pubkey);
      if (pubkey.length !== 33) {
        throw new Error(`Input #${index}: strict ECDSA inputs need a compressed public key`);
      }
      setFinalScripts(psbt, index, {
        finalScriptWitness: witnessStackToScriptWitness([
          Buffer.from([0x02]),
          Buffer.from(partialSig.signature),
          pubkey,
          Buffer.from([0x51]),
        ]),
      });
      finalizedCount += 1;
      continue;
    }
    if (witnessVersion === 1 || witnessVersion === 2) {
      throw new Error(
        `Input #${index} spends an AuthScript witness v${witnessVersion} output, which cannot be ` +
          "signed through a PSBT (use sign_tx for witness v1)"
      );
    }

    setFinalScripts(psbt, index, {
      finalScriptSig: Buffer.from(bitcoin.script.compile([
        partialSig.signature,
        partialSig.pubkey,
      ])),
    });
    finalizedCount += 1;
  }

  if (requireAllInputs && finalizedCount !== psbt.inputCount) {
    throw new Error(`Not all inputs were finalized (${finalizedCount}/${psbt.inputCount})`);
  }
}

function extractFinalizableTransaction(
  psbt: bitcoin.Psbt,
  requireAllInputs: boolean
): bitcoin.Transaction {
  const cache = (psbt as any).__CACHE as PsbtCache | undefined;
  const baseTx = cache?.__TX;
  if (!baseTx || !cache) {
    if (requireAllInputs) {
      return psbt.extractTransaction(true);
    }
    return psbt.extractTransaction();
  }

  const tx = baseTx.clone();
  inputFinalizeGetAmtsPartial(psbt.data.inputs, tx, cache, requireAllInputs);
  return tx;
}

function inputFinalizeGetAmtsPartial(
  inputs: PsbtInput[],
  tx: bitcoin.Transaction,
  cache: PsbtCache,
  requireAllInputs: boolean
) {
  let inputAmount = 0n;

  inputs.forEach((input, idx) => {
    if (input.finalScriptSig) {
      tx.ins[idx].script = input.finalScriptSig;
    }
    if (input.finalScriptWitness) {
      tx.ins[idx].witness = scriptWitnessToWitnessStack(input.finalScriptWitness);
    }
    if (input.witnessUtxo) {
      inputAmount += input.witnessUtxo.value;
      return;
    }
    if (input.nonWitnessUtxo) {
      const out = previousOutput(input.nonWitnessUtxo, displayTxid(tx.ins[idx].hash), tx.ins[idx].index, idx);
      if (!out) {
        if (requireAllInputs) {
          throw new Error(`Missing prevout amount for input #${idx}`);
        }
        return;
      }
      inputAmount += out.value;
      return;
    }
    if (requireAllInputs) {
      throw new Error(`Missing UTXO data for input #${idx}`);
    }
  });

  const outputAmount = tx.outs.reduce((total, o) => total + o.value, 0n);
  const fee = inputAmount - outputAmount;
  cache.__FEE = fee >= 0n ? fee : 0n;
  cache.__EXTRACTED_TX = tx;
  const feeRate = fee > 0n ? fee / BigInt(tx.virtualSize()) : 0n;
  if (feeRate > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("Fee rate exceeds the safe numeric range");
  cache.__FEE_RATE = Number(feeRate);
}

function scriptWitnessToWitnessStack(finalScriptWitness: Uint8Array): Uint8Array[] {
  const buffer = Buffer.from(finalScriptWitness);
  let offset = 0;
  const count = readPsbtVarInt(buffer, offset);
  offset += count.size;
  const stack: Uint8Array[] = [];

  for (let i = 0; i < count.value; i += 1) {
    const itemLen = readPsbtVarInt(buffer, offset);
    offset += itemLen.size;
    stack.push(buffer.subarray(offset, offset + itemLen.value));
    offset += itemLen.value;
  }

  return stack;
}
