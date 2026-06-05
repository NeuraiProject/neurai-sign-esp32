/**
 * Address utilities for Neurai legacy (P2PKH) and Post-Quantum (ML-DSA-44 /
 * AuthScript witness v1) addresses.
 *
 * This module is pure (no device / no secret material). It covers:
 * - detecting and decoding both address families,
 * - encoding destination scriptPubKeys (for outputs / sending to PQ),
 * - deriving an address from the public key the device exposes (`get_address`).
 *
 * The AuthScript construction mirrors the firmware exactly (uNeurai/NeuraiPQ):
 *   auth_descriptor = 0x01 || HASH160(0x05 || pqPubKey1312)
 *   commitment      = taggedHash("NeuraiAuthScript",
 *                       0x01 || auth_descriptor || SHA256(witnessScript))
 *   scriptPubKey    = OP_1 (0x51) || 0x20 || commitment
 *   address         = bech32m(hrp, witnessVersion=1, commitment)
 *
 * See docs/pq-protocol-design.md.
 */

import { Buffer } from "buffer";
import * as bitcoin from "bitcoinjs-lib";
import { bech32m } from "bech32";
import {
  getNetwork,
  getPQNetworkParams,
  resolveNetwork,
  type PQNetworkParams,
} from "./networks.js";
import type { Network, KeyType } from "./types.js";

// ─── AuthScript constants (match firmware) ───────────────────────────────────

const AUTHSCRIPT_TAG = "NeuraiAuthScript";
const AUTHSCRIPT_VERSION = 0x01;
const PQ_AUTH_TYPE = 0x01;
const PQ_PUBLIC_KEY_HEADER = 0x05;
const OP_1 = 0x51;
/** Default witnessScript for phase-1 single-sig PQ addresses: OP_TRUE. */
export const DEFAULT_WITNESS_SCRIPT_HEX = "51";

// ─── Small helpers ───────────────────────────────────────────────────────────

function toBuffer(input: Buffer | Uint8Array | string): Buffer {
  if (typeof input === "string") return Buffer.from(input, "hex");
  return Buffer.from(input);
}

function sha256(data: Buffer): Buffer {
  return Buffer.from(bitcoin.crypto.sha256(data));
}

function hash160(data: Buffer): Buffer {
  return Buffer.from(bitcoin.crypto.hash160(data));
}

/** taggedHash(tag, data) = SHA256(SHA256(tag) || SHA256(tag) || data). */
function taggedHash(tag: string, data: Buffer): Buffer {
  const tagHash = sha256(Buffer.from(tag, "utf8"));
  return sha256(Buffer.concat([tagHash, tagHash, data]));
}

/** Minimal script data push (covers 20/32-byte payloads; supports up to PUSHDATA1). */
function pushData(data: Buffer): Buffer {
  if (data.length < 0x4c) {
    return Buffer.concat([Buffer.from([data.length]), data]);
  }
  if (data.length <= 0xff) {
    return Buffer.concat([Buffer.from([0x4c, data.length]), data]);
  }
  throw new Error("pushData: payload too large for this helper");
}

// ─── PQ AuthScript primitives ────────────────────────────────────────────────

/** auth_descriptor = 0x01 || HASH160(0x05 || pqPubKey). */
export function pqAuthDescriptor(pqPubkey: Buffer | Uint8Array | string): Buffer {
  const pubkey = toBuffer(pqPubkey);
  return Buffer.concat([
    Buffer.from([PQ_AUTH_TYPE]),
    hash160(Buffer.concat([Buffer.from([PQ_PUBLIC_KEY_HEADER]), pubkey])),
  ]);
}

/**
 * commitment (32B) = taggedHash("NeuraiAuthScript",
 *   0x01 || auth_descriptor || SHA256(witnessScript)).
 */
export function pqCommitment(
  pqPubkey: Buffer | Uint8Array | string,
  witnessScriptHex: string = DEFAULT_WITNESS_SCRIPT_HEX
): Buffer {
  const authDescriptor = pqAuthDescriptor(pqPubkey);
  const witnessScriptHash = sha256(Buffer.from(witnessScriptHex, "hex"));
  return taggedHash(
    AUTHSCRIPT_TAG,
    Buffer.concat([
      Buffer.from([AUTHSCRIPT_VERSION]),
      authDescriptor,
      witnessScriptHash,
    ])
  );
}

/** Encode a PQ address (bech32m, witness v1) from a raw ML-DSA-44 public key. */
export function pqAddressFromPublicKey(
  pqPubkey: Buffer | Uint8Array | string,
  params: PQNetworkParams,
  witnessScriptHex: string = DEFAULT_WITNESS_SCRIPT_HEX
): string {
  const commitment = pqCommitment(pqPubkey, witnessScriptHex);
  const words = [params.witnessVersion, ...bech32m.toWords(commitment)];
  return bech32m.encode(params.hrp, words);
}

// ─── Address detection / decoding ────────────────────────────────────────────

export type DecodedAddress =
  | { type: "pq"; address: string; commitment: Buffer; witnessVersion: number; hrp: string }
  | { type: "legacy"; address: string; hash: Buffer; version: number };

/** True if `address` is a Neurai PQ (AuthScript bech32m) address (nq1…/tnq1…). */
export function isPQAddress(address: string): boolean {
  const lowered = address.trim().toLowerCase();
  return lowered.startsWith("nq1") || lowered.startsWith("tnq1");
}

/** Decode a legacy P2PKH or PQ AuthScript address. */
export function decodeAddress(address: string): DecodedAddress {
  const normalized = address.trim();
  if (!normalized) throw new Error("Address is required");

  if (isPQAddress(normalized)) {
    const decoded = bech32m.decode(normalized);
    const witnessVersion = decoded.words[0];
    const commitment = Buffer.from(bech32m.fromWords(decoded.words.slice(1)));
    if (witnessVersion !== 1 || commitment.length !== 32) {
      throw new Error(`Unsupported AuthScript address program for ${address}`);
    }
    return {
      type: "pq",
      address: normalized,
      commitment,
      witnessVersion,
      hrp: decoded.prefix,
    };
  }

  const { version, hash } = bitcoin.address.fromBase58Check(normalized);
  return { type: "legacy", address: normalized, hash: Buffer.from(hash), version };
}

// ─── Destination scriptPubKey encoding (for outputs) ─────────────────────────

/** AuthScript output scriptPubKey: OP_1 || 0x20 || commitment (34 bytes). */
export function encodeAuthScriptDestination(address: string): Buffer {
  const decoded = decodeAddress(address);
  if (decoded.type !== "pq") {
    throw new Error(`Address ${address} is not a PQ AuthScript address`);
  }
  return Buffer.concat([Buffer.from([OP_1]), pushData(decoded.commitment)]);
}

/** Legacy P2PKH output scriptPubKey: OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG. */
export function encodeP2PKHDestination(address: string): Buffer {
  const decoded = decodeAddress(address);
  if (decoded.type !== "legacy") {
    throw new Error(`Address ${address} is not a legacy P2PKH address`);
  }
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    decoded.hash,
    Buffer.from([0x88, 0xac]),
  ]);
}

/** Encode the scriptPubKey for any supported destination address. */
export function encodeDestinationScript(address: string): Buffer {
  return isPQAddress(address)
    ? encodeAuthScriptDestination(address)
    : encodeP2PKHDestination(address);
}

// ─── Public key → address (what the device exposes via get_address) ──────────

/**
 * Derive a Neurai address from the public key the device exposes plus the mode.
 * - legacy: base58check(versionByte || HASH160(compressed secp256k1 pubkey))
 * - pq:     AuthScript bech32m address (see pqAddressFromPublicKey)
 */
export function publicKeyToAddress(
  pubkeyHex: string,
  opts: { network: Network; keyType: KeyType; witnessScript?: string }
): string {
  const pubkey = Buffer.from(pubkeyHex, "hex");
  if (opts.keyType === "pq") {
    return pqAddressFromPublicKey(
      pubkey,
      getPQNetworkParams(opts.network),
      opts.witnessScript ?? DEFAULT_WITNESS_SCRIPT_HEX
    );
  }
  const bjs = getNetwork(resolveNetwork(opts.network, "legacy"));
  return bitcoin.address.toBase58Check(hash160(pubkey), bjs.pubKeyHash);
}
