/**
 * PSBT builder for Neurai P2PKH transactions.
 *
 * Creates unsigned PSBTs compatible with the NeuraiHW ESP32 firmware.
 * The ESP32 signs inputs that match its BIP32 derivation path and
 * master fingerprint.
 *
 * Requirements for each UTXO:
 * - rawTxHex: Full raw transaction hex (P2PKH needs nonWitnessUtxo)
 * - scriptPubKey: The output script being spent
 *
 * The PSBT includes BIP32 derivation metadata so the ESP32 can
 * verify and locate the correct signing key.
 */

import * as bitcoin from "bitcoinjs-lib";
import { ECPairFactory } from "ecpair";
import ecc from "@bitcoinerlab/secp256k1";
import { getNetwork } from "./networks.js";
import type { IBuildPSBTOptions, IUTXO } from "./types.js";

const ECPair = ECPairFactory(ecc);

const DEFAULT_FEE_RATE = 1024; // sat/byte

// Estimated P2PKH tx sizes for fee calculation
const TX_OVERHEAD = 10;       // version(4) + locktime(4) + varint(2)
const INPUT_SIZE = 148;       // P2PKH input with signature
const OUTPUT_SIZE = 34;       // P2PKH output

/**
 * Estimate transaction size in bytes for P2PKH.
 */
function estimateTxSize(inputCount: number, outputCount: number): number {
  return TX_OVERHEAD + inputCount * INPUT_SIZE + outputCount * OUTPUT_SIZE;
}

/**
 * Parse a master fingerprint hex string (8 chars) into a 4-byte Buffer.
 */
function parseMasterFingerprint(hex: string): Buffer {
  if (hex.length !== 8) {
    throw new Error(
      `Invalid master fingerprint: expected 8 hex chars, got ${hex.length}`
    );
  }
  return Buffer.from(hex, "hex");
}

/**
 * Parse a BIP44 derivation path string into an array of uint32 indices.
 * e.g. "m/44'/1900'/0'/0/0" → [0x8000002C, 0x8000076C, 0x80000000, 0, 0]
 */
function parseDerivationPath(path: string): number[] {
  return path
    .replace(/^m\//, "")
    .split("/")
    .map((part) => {
      const hardened = part.endsWith("'");
      const index = parseInt(hardened ? part.slice(0, -1) : part, 10);
      return hardened ? index + 0x80000000 : index;
    });
}

/**
 * Build an unsigned PSBT for Neurai P2PKH, ready to send to the ESP32.
 *
 * @returns Base64-encoded PSBT string
 */
export function buildPSBT(options: IBuildPSBTOptions): string {
  const {
    network: networkType,
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

  const network = getNetwork(networkType);
  const pubkeyBuffer = Buffer.from(pubkey, "hex");
  const fingerprintBuffer = parseMasterFingerprint(masterFingerprint);
  const bip32Path = parseDerivationPath(derivationPath);

  // Calculate total output amount
  const totalOutputValue = outputs.reduce((sum, o) => sum + o.value, 0);

  // Select UTXOs (use all provided — caller is responsible for UTXO selection)
  const totalInputValue = utxos.reduce((sum, u) => sum + u.satoshis, 0);

  // Estimate fee: outputs + possible change output
  const estimatedSize = estimateTxSize(utxos.length, outputs.length + 1);
  const fee = estimatedSize * feeRate;

  const change = totalInputValue - totalOutputValue - fee;

  if (change < 0) {
    throw new Error(
      `Insufficient funds: inputs=${totalInputValue}, outputs=${totalOutputValue}, fee=${fee}`
    );
  }

  // Build PSBT
  const psbt = new bitcoin.Psbt({ network });

  // BIP32 derivation metadata (same for all inputs from this device)
  const bip32Derivation = [
    {
      masterFingerprint: fingerprintBuffer,
      path: derivationPath,
      pubkey: pubkeyBuffer,
    },
  ];

  // Add inputs
  for (const utxo of utxos) {
    psbt.addInput({
      hash: utxo.txid,
      index: utxo.vout,
      nonWitnessUtxo: Buffer.from(utxo.rawTxHex, "hex"),
      bip32Derivation,
    });
  }

  // Add destination outputs
  for (const output of outputs) {
    psbt.addOutput({
      address: output.address,
      value: BigInt(output.value),
    });
  }

  // Add change output (if change > dust threshold)
  const DUST_THRESHOLD = 546; // standard dust for P2PKH
  if (change >= DUST_THRESHOLD) {
    psbt.addOutput({
      address: changeAddress,
      value: BigInt(change),
      bip32Derivation,
    });
  }

  return psbt.toBase64();
}

/**
 * Finalize a signed PSBT and extract the raw transaction.
 *
 * Call this after receiving the signed PSBT back from the ESP32.
 *
 * @param signedPsbtBase64 - Base64-encoded signed PSBT from the device
 * @param network - Network type
 * @returns Object with txHex (raw tx for broadcast) and txId
 */
export function finalizePSBT(
  signedPsbtBase64: string,
  network: "xna" | "xna-test" | "xna-legacy" | "xna-legacy-test"
): { txHex: string; txId: string } {
  const net = getNetwork(network);
  const psbt = bitcoin.Psbt.fromBase64(signedPsbtBase64, { network: net });

  psbt.finalizeAllInputs();

  const tx = psbt.extractTransaction();
  return {
    txHex: tx.toHex(),
    txId: tx.getId(),
  };
}

/**
 * Validate that a PSBT base64 string is parseable.
 */
export function validatePSBT(
  psbtBase64: string,
  network: "xna" | "xna-test" | "xna-legacy" | "xna-legacy-test"
): boolean {
  try {
    const net = getNetwork(network);
    bitcoin.Psbt.fromBase64(psbtBase64, { network: net });
    return true;
  } catch {
    return false;
  }
}
