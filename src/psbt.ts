/**
 * PSBT helpers for Neurai P2PKH transactions.
 *
 * This package supports two build paths:
 * - high-level build from UTXOs + outputs + fee estimation
 * - low-level build from an already-created raw unsigned transaction
 *
 * The second path matches the webwallet integration, where coin selection
 * and fee calculation already happen elsewhere.
 */

import { Buffer } from "buffer";
import * as bitcoin from "bitcoinjs-lib";
import { getNetwork } from "./networks.js";
import type {
  IBuildPSBTFromRawOptions,
  IBuildPSBTOptions,
  NetworkType,
} from "./types.js";

const DEFAULT_FEE_RATE = 1024;
const TX_OVERHEAD = 10;
const INPUT_SIZE = 148;
const OUTPUT_SIZE = 34;

type PsbtInput = bitcoin.Psbt['data']['inputs'][number];
type PsbtCache = {
  __TX?: bitcoin.Transaction;
  __EXTRACTED_TX?: bitcoin.Transaction;
  __FEE?: bigint;
  __FEE_RATE?: number;
  __NON_WITNESS_UTXO_TX_CACHE?: Record<number, bitcoin.Transaction>;
};

function estimateTxSize(inputCount: number, outputCount: number): number {
  return TX_OVERHEAD + inputCount * INPUT_SIZE + outputCount * OUTPUT_SIZE;
}

function parseMasterFingerprint(hex: string): Buffer {
  if (hex.length !== 8) {
    throw new Error(
      `Invalid master fingerprint: expected 8 hex chars, got ${hex.length}`
    );
  }
  return Buffer.from(hex, "hex");
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

function nonWitnessUtxoTxFromCache(cache: PsbtCache, input: PsbtInput, inputIndex: number) {
  const existing = cache.__NON_WITNESS_UTXO_TX_CACHE?.[inputIndex];
  if (existing) {
    return existing;
  }

  if (!input.nonWitnessUtxo) {
    throw new Error(`Missing nonWitnessUtxo for input #${inputIndex}`);
  }

  const tx = bitcoin.Transaction.fromBuffer(input.nonWitnessUtxo);
  cache.__NON_WITNESS_UTXO_TX_CACHE ??= {};
  cache.__NON_WITNESS_UTXO_TX_CACHE[inputIndex] = tx;
  return tx;
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

  const totalOutputValue = outputs.reduce((sum, output) => sum + output.value, 0);
  const totalInputValue = utxos.reduce((sum, utxo) => sum + utxo.satoshis, 0);
  const estimatedSize = estimateTxSize(utxos.length, outputs.length + 1);
  const fee = estimatedSize * feeRate;
  const change = totalInputValue - totalOutputValue - fee;

  if (change < 0) {
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
    psbt.addInput({
      hash: utxo.txid,
      index: utxo.vout,
      nonWitnessUtxo: Buffer.from(utxo.rawTxHex, "hex"),
      bip32Derivation,
    });
  }

  for (const output of outputs) {
    psbt.addOutput({
      address: output.address,
      value: BigInt(output.value),
    });
  }

  const DUST_THRESHOLD = 546;
  if (change >= DUST_THRESHOLD) {
    psbt.addOutput({
      address: changeAddress,
      value: BigInt(change),
      bip32Derivation,
    });
  }

  return psbt.toBase64();
}

export function buildPSBTFromRawTransaction(options: IBuildPSBTFromRawOptions): string {
  const network = getNetwork(options.network);
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
      nonWitnessUtxo: Buffer.from(metadata.rawTxHex, "hex"),
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

    psbt.addInput(inputData);
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

    const prevTx = bitcoin.Transaction.fromBuffer(nonWitnessUtxo);
    const prevOut = prevTx.outs[txInput.index];
    if (!prevOut) {
      if (requireAllInputs) {
        throw new Error(`Missing prevout to finalize input #${index}`);
      }
      continue;
    }

    psbt.finalizeInput(index, () => ({
      finalScriptSig: bitcoin.script.compile([
        partialSig.signature,
        partialSig.pubkey,
      ]),
      finalScriptWitness: undefined,
    }));
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
      const nwTx = nonWitnessUtxoTxFromCache(cache, input, idx);
      const vout = tx.ins[idx].index;
      const out = nwTx.outs[vout];
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
  cache.__FEE_RATE = fee > 0n ? Math.floor(Number(fee / BigInt(tx.virtualSize()))) : 0;
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
