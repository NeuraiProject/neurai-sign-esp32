/**
 * Address utilities for Neurai legacy (P2PKH) and AuthScript (Bech32m witness)
 * addresses.
 *
 * This module is pure (no device / no secret material). It covers:
 * - detecting and decoding every Neurai address type,
 * - encoding destination scriptPubKeys (for outputs / sending to any type),
 * - deriving an address from the public key the device exposes (`get_address`).
 *
 * Address families (node base58.cpp; only these HRP/version pairs are valid):
 *
 *   family       witver  HRP (main / test)  scriptPubKey    authType  witnessScript
 *   authscript     1     nc   / tnc         OP_1 0x20 <C>   any       any
 *   pq (strict)    2     pq   / tpq         OP_2 0x20 <C>   0x01      0x51 (fixed)
 *   ecdsa (strict) 3     nq   / tnq         OP_3 0x20 <C>   0x02      0x51 (fixed)
 *
 * The AuthScript construction mirrors the firmware exactly (uNeurai/NeuraiPQ):
 *   auth_descriptor = 0x01 || HASH160(0x05 || pqPubKey1312)       (PQ key)
 *                   | 0x02 || HASH160(compressedSecp256k1Pubkey)  (ECDSA key)
 *   commitment      = taggedHash("NeuraiAuthScript",
 *                       witnessVersion || auth_descriptor || SHA256(witnessScript))
 *   scriptPubKey    = OP_n (0x50 + witnessVersion) || 0x20 || commitment
 *   address         = bech32m(hrp, witnessVersion, commitment)
 *
 * The device's PQ mode uses the generic family (witness v1, authType 0x01,
 * witnessScript OP_TRUE): `nc1p…` / `tnc1p…`. Up to 0.6.x those addresses were
 * encoded as `nq1p…` / `tnq1p…`, which the node now rejects (`nq` / `tnq`
 * belong to the strict ECDSA family); the scriptPubKey is unchanged.
 *
 * See docs/pq-protocol-design.md.
 */

import { Buffer } from "buffer";
import * as bitcoin from "bitcoinjs-lib";
import { bech32m } from "bech32";
import {
  AUTHSCRIPT_FAMILIES,
  authScriptFamilyByHrp,
  authScriptFamilyByVersion,
  getNetwork,
  getPQNetworkParams,
  resolveNetwork,
  type AuthScriptFamily,
  type PQNetworkParams,
} from "./networks.js";
import type { Network, KeyType } from "./types.js";

// ─── AuthScript constants (match firmware) ───────────────────────────────────

const AUTHSCRIPT_TAG = "NeuraiAuthScript";
const PQ_AUTH_TYPE = 0x01;
const ECDSA_AUTH_TYPE = 0x02;
const PQ_PUBLIC_KEY_HEADER = 0x05;
/** Longest Bech32 string the node's decoder accepts (bech32.cpp). */
const BECH32M_MAX_LENGTH = 90;
const AUTHSCRIPT_PROGRAM_LENGTH = 32;
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

function assertCompressedPublicKey(pubkey: Buffer): void {
  if (pubkey.length !== 33 || (pubkey[0] !== 0x02 && pubkey[0] !== 0x03)) {
    throw new Error("The strict ECDSA family (witness v3) needs a 33-byte compressed secp256k1 public key");
  }
}

// ─── AuthScript primitives ───────────────────────────────────────────────────

/** auth_descriptor = 0x01 || HASH160(0x05 || pqPubKey). */
export function pqAuthDescriptor(pqPubkey: Buffer | Uint8Array | string): Buffer {
  const pubkey = toBuffer(pqPubkey);
  return Buffer.concat([
    Buffer.from([PQ_AUTH_TYPE]),
    hash160(Buffer.concat([Buffer.from([PQ_PUBLIC_KEY_HEADER]), pubkey])),
  ]);
}

/** auth_descriptor = 0x02 || HASH160(compressed secp256k1 pubkey). */
export function ecdsaAuthDescriptor(pubkey: Buffer | Uint8Array | string): Buffer {
  return Buffer.concat([Buffer.from([ECDSA_AUTH_TYPE]), hash160(toBuffer(pubkey))]);
}

export interface IAuthScriptCommitmentOptions {
  /** Witness version (1, 2 or 3): the commitment preimage lead byte. */
  witnessVersion: 1 | 2 | 3;
  /** 0x01 (PQ key) or 0x02 (secp256k1 key). Fixed by v2 (0x01) and v3 (0x02). */
  authType: 0x01 | 0x02;
  /** Raw ML-DSA-44 key (1312 B, no 0x05 prefix) or compressed secp256k1 key (33 B). */
  publicKey: Buffer | Uint8Array | string;
  /** witnessScript hex (default "51" = OP_TRUE; the strict families require it). */
  witnessScript?: string;
}

/**
 * commitment (32B) = taggedHash("NeuraiAuthScript",
 *   witnessVersion || auth_descriptor || SHA256(witnessScript)).
 * The strict families enforce their consensus template (authType bound to the
 * version, witnessScript OP_TRUE, compressed key for ECDSA) so an unspendable
 * program is never produced.
 */
export function authScriptCommitment(options: IAuthScriptCommitmentOptions): Buffer {
  const { witnessVersion, authType } = options;
  const witnessScriptHex = options.witnessScript ?? DEFAULT_WITNESS_SCRIPT_HEX;
  const family = authScriptFamilyByVersion(witnessVersion);
  if (!family) {
    throw new Error(`Unsupported AuthScript witness version ${witnessVersion}`);
  }
  if (family.authType !== undefined) {
    if (authType !== family.authType) {
      throw new Error(
        `Witness v${witnessVersion} requires authType 0x0${family.authType} (got 0x0${authType})`
      );
    }
    if (witnessScriptHex.toLowerCase() !== DEFAULT_WITNESS_SCRIPT_HEX) {
      throw new Error(`Witness v${witnessVersion} requires the OP_TRUE witnessScript ("51")`);
    }
  }
  const pubkey = toBuffer(options.publicKey);
  let authDescriptor: Buffer;
  if (authType === PQ_AUTH_TYPE) {
    authDescriptor = pqAuthDescriptor(pubkey);
  } else if (authType === ECDSA_AUTH_TYPE) {
    if (witnessVersion === 3) assertCompressedPublicKey(pubkey);
    authDescriptor = ecdsaAuthDescriptor(pubkey);
  } else {
    throw new Error(`Unsupported authType ${authType}`);
  }
  const witnessScriptHash = sha256(Buffer.from(witnessScriptHex, "hex"));
  return taggedHash(
    AUTHSCRIPT_TAG,
    Buffer.concat([Buffer.from([witnessVersion]), authDescriptor, witnessScriptHash])
  );
}

/**
 * PQ-key commitment. `witnessVersion` 1 (default) is the device's generic
 * AuthScript flow; 2 is strict PQ (witnessScript must stay OP_TRUE):
 *   taggedHash("NeuraiAuthScript", witnessVersion || auth_descriptor || SHA256(witnessScript)).
 */
export function pqCommitment(
  pqPubkey: Buffer | Uint8Array | string,
  witnessScriptHex: string = DEFAULT_WITNESS_SCRIPT_HEX,
  witnessVersion: 1 | 2 = 1
): Buffer {
  return authScriptCommitment({
    witnessVersion,
    authType: PQ_AUTH_TYPE,
    publicKey: pqPubkey,
    witnessScript: witnessScriptHex,
  });
}

/** Strict ECDSA (witness v3) commitment of a compressed secp256k1 key. */
export function ecdsaCommitment(pubkey: Buffer | Uint8Array | string): Buffer {
  return authScriptCommitment({ witnessVersion: 3, authType: ECDSA_AUTH_TYPE, publicKey: pubkey });
}

/** Encode a 32-byte program as the canonical address of its family on `network`. */
export function authScriptAddressFromProgram(
  witnessVersion: 1 | 2 | 3,
  network: Network,
  program: Buffer | Uint8Array | string
): string {
  const family = authScriptFamilyByVersion(witnessVersion);
  if (!family) throw new Error(`Unsupported AuthScript witness version ${witnessVersion}`);
  const bytes = toBuffer(program);
  if (bytes.length !== AUTHSCRIPT_PROGRAM_LENGTH) {
    throw new Error(`AuthScript program must be ${AUTHSCRIPT_PROGRAM_LENGTH} bytes`);
  }
  const hrp = network === "testnet" ? family.hrp.testnet : family.hrp.mainnet;
  return bech32m.encode(hrp, [witnessVersion, ...bech32m.toWords(bytes)]);
}

/**
 * Encode a PQ address (bech32m) from a raw ML-DSA-44 public key. The family
 * follows `params`: {@link neuraiPQTestnet}-style params (default of
 * `getPQNetworkParams`) give the generic v1 address (`tnc1p…`), the strict
 * params give `tpq1z…`. The commitment lead byte is `params.witnessVersion`.
 */
export function pqAddressFromPublicKey(
  pqPubkey: Buffer | Uint8Array | string,
  params: PQNetworkParams,
  witnessScriptHex: string = DEFAULT_WITNESS_SCRIPT_HEX
): string {
  if (params.witnessVersion !== 1 && params.witnessVersion !== 2) {
    throw new Error(`PQ addresses use witness v1 or v2 (got v${params.witnessVersion})`);
  }
  const commitment = pqCommitment(pqPubkey, witnessScriptHex, params.witnessVersion);
  const words = [params.witnessVersion, ...bech32m.toWords(commitment)];
  return bech32m.encode(params.hrp, words);
}

/**
 * Strict ECDSA witness v3 address (`nq1r…` / `tnq1r…`) of a compressed
 * secp256k1 key — neurai-key 5 network `xna` / `xna-test`
 * (m/84'/1900'/account'/change/index).
 */
export function ecdsaAddressFromPublicKey(
  pubkey: Buffer | Uint8Array | string,
  network: Network
): string {
  return authScriptAddressFromProgram(3, network, ecdsaCommitment(pubkey));
}

// ─── Address detection / decoding ────────────────────────────────────────────

/** Every Neurai address type: Base58 P2PKH or one of the Bech32m families. */
export type AddressFamily = "legacy" | AuthScriptFamily;

/**
 * A decoded address. `type: "pq"` is kept for every Bech32m AuthScript address
 * (it was the only witness family before 0.7.0 and callers use it to route to
 * a raw scriptPubKey); use `family` for the exact kind.
 */
export type DecodedAddress =
  | {
      type: "pq";
      /** authscript (v1, nc/tnc), pq (strict v2, pq/tpq) or ecdsa (strict v3, nq/tnq). */
      family: AuthScriptFamily;
      address: string;
      /** The 32-byte witness program (the AuthScript commitment). */
      commitment: Buffer;
      witnessVersion: 1 | 2 | 3;
      hrp: string;
      network: Network;
    }
  | { type: "legacy"; family: "legacy"; address: string; hash: Buffer; version: number };

type Bech32mParts = { prefix: string; words: number[] };

function tryBech32mDecode(address: string): Bech32mParts | null {
  try {
    const { prefix, words } = bech32m.decode(address, BECH32M_MAX_LENGTH);
    return { prefix: prefix.toLowerCase(), words };
  } catch {
    return null;
  }
}

function decodeWitnessAddress(address: string, parts: Bech32mParts): DecodedAddress {
  const owner = authScriptFamilyByHrp(parts.prefix);
  if (!owner) {
    throw new Error(`Unsupported Bech32m prefix "${parts.prefix}" for ${address}`);
  }
  if (parts.words.length === 0) {
    throw new Error(`Empty witness program in ${address}`);
  }
  const witnessVersion = parts.words[0];
  const { params, network } = owner;
  if (witnessVersion !== params.witnessVersion) {
    const actual = authScriptFamilyByVersion(witnessVersion);
    const hint = actual
      ? `; witness v${witnessVersion} addresses use the "${actual.hrp[network]}" prefix`
      : "";
    const legacyHint =
      params.family === "ecdsa" && witnessVersion === 1
        ? " Generic AuthScript v1 addresses are now encoded as nc1p… / tnc1p… (same scriptPubKey): " +
          "regenerate the address."
        : "";
    throw new Error(
      `Address ${address}: the "${parts.prefix}" prefix only encodes witness v${params.witnessVersion}, ` +
        `not v${witnessVersion}${hint}.${legacyHint}`
    );
  }
  let commitment: Buffer;
  try {
    commitment = Buffer.from(bech32m.fromWords(parts.words.slice(1)));
  } catch {
    throw new Error(`Invalid witness program padding in ${address}`);
  }
  if (commitment.length !== AUTHSCRIPT_PROGRAM_LENGTH) {
    throw new Error(
      `Unsupported AuthScript program length ${commitment.length} for ${address} (expected ${AUTHSCRIPT_PROGRAM_LENGTH})`
    );
  }
  return {
    type: "pq",
    family: params.family,
    address,
    commitment,
    witnessVersion: params.witnessVersion,
    hrp: parts.prefix,
    network,
  };
}

/**
 * Decode any Neurai address the way the node does: Bech32m first (any case;
 * canonical HRP/version pairs only), Base58Check P2PKH otherwise. The old
 * `nq1p…` / `tnq1p…` witness-v1 encoding is rejected with a hint to use the
 * `nc1p…` / `tnc1p…` form.
 *
 * The decoder does not know whether the strict families (v2/v3) are active on
 * the target chain: before activation an OP_2/OP_3 output is anyone-can-spend.
 */
export function decodeAddress(address: string): DecodedAddress {
  const normalized = address.trim();
  if (!normalized) throw new Error("Address is required");

  const parts = tryBech32mDecode(normalized);
  if (parts) {
    return decodeWitnessAddress(normalized, parts);
  }

  try {
    const { version, hash } = bitcoin.address.fromBase58Check(normalized);
    return { type: "legacy", family: "legacy", address: normalized, hash: Buffer.from(hash), version };
  } catch (legacyError) {
    // Not Base58 either. With a known Bech32m prefix the Bech32m failure
    // (checksum, case, character) is the useful diagnosis.
    const separator = normalized.lastIndexOf("1");
    const hrp = separator > 0 ? normalized.slice(0, separator) : "";
    if (authScriptFamilyByHrp(hrp)) {
      throw new Error(`Invalid Bech32m address ${normalized} (checksum, case or character error)`);
    }
    throw legacyError;
  }
}

/**
 * True if `address` is a valid Neurai Bech32m AuthScript address of any family
 * (`nc1p…`, `pq1z…`, `nq1r…` and their testnet forms). Base58 addresses that
 * merely start with such a prefix (e.g. `NQ1…`) are not.
 */
export function isWitnessAddress(address: string): boolean {
  try {
    return decodeAddress(address).type === "pq";
  } catch {
    return false;
  }
}

/**
 * @deprecated Use {@link isWitnessAddress} (same result) or
 * {@link getAddressFamily}. Kept for compatibility: it has always meant "a
 * Bech32m AuthScript address that needs a raw scriptPubKey", so it is true for
 * every family (`nc1p…`, `pq1z…`, `nq1r…`), not only for ML-DSA keys. Since
 * 0.7.0 it validates the address instead of matching the `nq1`/`tnq1` prefix.
 */
export function isPQAddress(address: string): boolean {
  return isWitnessAddress(address);
}

/** Address family of a valid address (throws like {@link decodeAddress}). */
export function getAddressFamily(address: string): AddressFamily {
  return decodeAddress(address).family;
}

/**
 * Witness version (1, 2 or 3) of an AuthScript scriptPubKey `OP_n 0x20 <32>`,
 * optionally followed by an asset payload (`… OP_XNA_ASSET …`); 0 otherwise.
 */
export function authScriptWitnessVersionOfScript(script: Buffer | Uint8Array | string): 0 | 1 | 2 | 3 {
  const bytes = toBuffer(script);
  if (bytes.length < 34 || bytes[1] !== 0x20) return 0;
  if (bytes.length > 34 && bytes[34] !== 0xc0) return 0;
  if (bytes[0] === 0x51) return 1;
  if (bytes[0] === 0x52) return 2;
  if (bytes[0] === 0x53) return 3;
  return 0;
}

/**
 * Re-encode an address reported by a device running firmware built against
 * uNeurai < 0.2.0, which renders generic AuthScript v1 as `nq1p…` / `tnq1p…`,
 * into the `nc1p…` / `tnc1p…` form the node accepts. The scriptPubKey does not
 * change. Any other string is returned unchanged. Only meant for addresses the
 * device derived from its own key; user input should go through
 * {@link decodeAddress}, which rejects the old form like the node.
 */
export function normalizeDeviceAuthScriptAddress(address: string): string {
  const trimmed = address.trim();
  const parts = tryBech32mDecode(trimmed);
  if (!parts || parts.words[0] !== 1) return address;
  if (parts.prefix !== "nq" && parts.prefix !== "tnq") return address;
  const hrp = parts.prefix === "tnq"
    ? AUTHSCRIPT_FAMILIES.authscript.hrp.testnet
    : AUTHSCRIPT_FAMILIES.authscript.hrp.mainnet;
  return bech32m.encode(hrp, parts.words);
}

// ─── Destination scriptPubKey encoding (for outputs) ─────────────────────────

/**
 * AuthScript output scriptPubKey (34 bytes): OP_n || 0x20 || commitment with
 * OP_n = OP_1 / OP_2 / OP_3 for `nc1p…` / `pq1z…` / `nq1r…` addresses.
 */
export function encodeAuthScriptDestination(address: string): Buffer {
  const decoded = decodeAddress(address);
  if (decoded.type !== "pq") {
    throw new Error(`Address ${address} is not an AuthScript (Bech32m) address`);
  }
  return Buffer.concat([Buffer.from([0x50 + decoded.witnessVersion]), pushData(decoded.commitment)]);
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
  return decodeAddress(address).type === "pq"
    ? encodeAuthScriptDestination(address)
    : encodeP2PKHDestination(address);
}

// ─── Public key → address (what the device exposes via get_address) ──────────

/**
 * Derive a Neurai address from the public key the device exposes plus the mode.
 * - legacy: base58check(versionByte || HASH160(compressed secp256k1 pubkey))
 * - pq:     AuthScript bech32m address (see pqAddressFromPublicKey) — generic
 *           v1 `nc1p…` / `tnc1p…` by default, strict v2 `pq1z…` with
 *           `witnessVersion: 2` (witnessScript must then stay "51").
 */
export function publicKeyToAddress(
  pubkeyHex: string,
  opts: { network: Network; keyType: KeyType; witnessScript?: string; witnessVersion?: 1 | 2 }
): string {
  const pubkey = Buffer.from(pubkeyHex, "hex");
  if (opts.keyType === "pq") {
    return pqAddressFromPublicKey(
      pubkey,
      getPQNetworkParams(opts.network, opts.witnessVersion ?? 1),
      opts.witnessScript ?? DEFAULT_WITNESS_SCRIPT_HEX
    );
  }
  const bjs = getNetwork(resolveNetwork(opts.network, "legacy"));
  return bitcoin.address.toBase58Check(hash160(pubkey), bjs.pubKeyHash);
}
