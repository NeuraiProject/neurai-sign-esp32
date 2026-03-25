/**
 * Neurai network configurations for bitcoinjs-lib
 *
 * Defines all Neurai networks (mainnet, testnet, legacy variants)
 * in the format required by bitcoinjs-lib v7.
 */

import type { Network } from "bitcoinjs-lib";
import type { NetworkType } from "./types.js";

// ─── Neurai Mainnet (coin type 1900) ────────────────────────────────────────

export const neuraiMainnet: Network = {
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

export const neuraiTestnet: Network = {
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

export const neuraiLegacyMainnet: Network = {
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

export const neuraiLegacyTestnet: Network = {
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

const networkMap: Record<NetworkType, Network> = {
  xna: neuraiMainnet,
  "xna-test": neuraiTestnet,
  "xna-legacy": neuraiLegacyMainnet,
  "xna-legacy-test": neuraiLegacyTestnet,
};

/**
 * Get the bitcoinjs-lib Network object for a given Neurai network type.
 */
export function getNetwork(network: NetworkType): Network {
  const net = networkMap[network];
  if (!net) {
    throw new Error(`Unknown network: ${network}`);
  }
  return net;
}
