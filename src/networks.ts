/**
 * Neurai network configurations for bitcoinjs-lib
 *
 * Defines all Neurai networks (mainnet, testnet, legacy variants)
 * in the format required by bitcoinjs-lib v7.
 */

import type { Network as BjsNetwork } from "bitcoinjs-lib";
import type { KeyType, Network, NetworkType } from "./types.js";

// ─── Neurai Mainnet (coin type 1900) ────────────────────────────────────────

export const neuraiMainnet: BjsNetwork = {
  messagePrefix: "Neurai Signed Message:\n",
  bech32: "",
  bip32: {
    public: 76067358,
    private: 76066276,
  },
  pubKeyHash: 53,   // 0x35 → prefix "N"
  scriptHash: 117,  // 0x75
  wif: 128,         // 0x80
};

// ─── Neurai Testnet ──────────────────────────────────────────────────────────

export const neuraiTestnet: BjsNetwork = {
  messagePrefix: "Neurai Signed Message:\n",
  bech32: "",
  bip32: {
    public: 70617039,
    private: 70615956,
  },
  pubKeyHash: 127,  // 0x7f
  scriptHash: 196,  // 0xc4
  wif: 239,         // 0xef
};

// ─── Neurai Legacy Mainnet (coin type 0) ─────────────────────────────────────

export const neuraiLegacyMainnet: BjsNetwork = {
  messagePrefix: "Neurai Signed Message:\n",
  bech32: "",
  bip32: {
    public: 76067358,
    private: 76066276,
  },
  pubKeyHash: 53,
  scriptHash: 117,
  wif: 128,
};

// ─── Neurai Legacy Testnet ───────────────────────────────────────────────────

export const neuraiLegacyTestnet: BjsNetwork = {
  messagePrefix: "Neurai Signed Message:\n",
  bech32: "",
  bip32: {
    public: 70617039,
    private: 70615956,
  },
  pubKeyHash: 127,
  scriptHash: 196,
  wif: 239,
};

// ─── Network map ─────────────────────────────────────────────────────────────

// PQ networks reuse the base secp256k1 params (used only when a PQ flow needs a
// bitcoinjs-lib Network for non-PQ outputs/change); PQ addresses themselves are
// bech32m and encoded separately (see pq-address.ts).
const neuraiPQMainnetBjs: BjsNetwork = { ...neuraiMainnet, bech32: "nq" };
const neuraiPQTestnetBjs: BjsNetwork = { ...neuraiTestnet, bech32: "tnq" };

const networkMap: Record<NetworkType, BjsNetwork> = {
  xna: neuraiMainnet,
  "xna-test": neuraiTestnet,
  "xna-legacy": neuraiLegacyMainnet,
  "xna-legacy-test": neuraiLegacyTestnet,
  "xna-pq": neuraiPQMainnetBjs,
  "xna-pq-test": neuraiPQTestnetBjs,
};

/**
 * Get the bitcoinjs-lib Network object for a given Neurai network type.
 */
export function getNetwork(network: NetworkType): BjsNetwork {
  const net = networkMap[network];
  if (!net) {
    throw new Error(`Unknown network: ${network}`);
  }
  return net;
}

// ─── Post-Quantum (ML-DSA-44 / AuthScript) network parameters ────────────────

/** Parameters for a Neurai PQ (NIP-022 / AuthScript witness v1) network. */
export interface PQNetworkParams {
  /** bech32m human-readable part: "nq" (mainnet) / "tnq" (testnet). */
  hrp: string;
  /** Witness version embedded in the address (always 1 in phase 1). */
  witnessVersion: number;
  /** BIP-32 coin type: 1900 (mainnet) / 1 (testnet). */
  coinType: number;
  /** BIP-32 purpose (NIP-022): 100. */
  purpose: number;
}

export const neuraiPQMainnet: PQNetworkParams = {
  hrp: "nq",
  witnessVersion: 1,
  coinType: 1900,
  purpose: 100,
};

export const neuraiPQTestnet: PQNetworkParams = {
  hrp: "tnq",
  witnessVersion: 1,
  coinType: 1,
  purpose: 100,
};

/**
 * Resolve the (Network, KeyType) public axes to the internal NetworkType.
 *
 * `KeyType: "legacy"` maps to the standard secp256k1 networks (coin type
 * 1900/1). The coin-type-0 `xna-legacy*` networks are a separate concern and
 * are not produced here.
 */
export function resolveNetwork(network: Network, keyType: KeyType): NetworkType {
  if (keyType === "pq") {
    return network === "testnet" ? "xna-pq-test" : "xna-pq";
  }
  return network === "testnet" ? "xna-test" : "xna";
}

/** PQ network params for a given public Network. */
export function getPQNetworkParams(network: Network): PQNetworkParams {
  return network === "testnet" ? neuraiPQTestnet : neuraiPQMainnet;
}
