/**
 * Neurai network configurations for bitcoinjs-lib
 *
 * Defines all Neurai networks (mainnet, testnet, legacy variants)
 * in the format required by bitcoinjs-lib v7.
 */

import type { Network as BjsNetwork } from "bitcoinjs-lib";
import type { KeyType, Network, NetworkType } from "./types.js";

// ─── Neurai Mainnet (coin type 1900) ────────────────────────────────────────
// NetworkType "xna": Legacy P2PKH m/44'/1900'/… (neurai-key 5: "xna-legacy").

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
// NetworkType "xna-test": Legacy P2PKH m/44'/1'/… (neurai-key 5: "xna-legacy-test").

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
// NetworkType "xna-legacy": Legacy P2PKH m/44'/0'/… (neurai-key 5: "xna-old-legacy").

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
// bech32m and encoded separately (see pq-address.ts). The `bech32` field is the
// HRP of the family the device's PQ flow uses: generic AuthScript v1.
const neuraiPQMainnetBjs: BjsNetwork = { ...neuraiMainnet, bech32: "nc" };
const neuraiPQTestnetBjs: BjsNetwork = { ...neuraiTestnet, bech32: "tnc" };

const networkMap: Record<NetworkType, BjsNetwork> = {
  xna: neuraiMainnet,
  "xna-test": neuraiTestnet,
  "xna-legacy": neuraiLegacyMainnet,
  "xna-legacy-test": neuraiLegacyTestnet,
  "xna-pq": neuraiPQMainnetBjs,
  "xna-pq-test": neuraiPQTestnetBjs,
};

/**
 * Network names of `@neuraiproject/neurai-key` 5 that mean the same thing here
 * and are therefore accepted by {@link getNetwork} as aliases.
 *
 * The other key-5 names collide with names of this package and keep this
 * package's meaning (see {@link fromNeuraiKeyNetwork} and the README):
 *
 * | name              | neurai-sign-esp32              | neurai-key 5                  |
 * |-------------------|--------------------------------|-------------------------------|
 * | `xna`             | Legacy P2PKH, coin type 1900   | strict ECDSA witness v3 (nq1r)|
 * | `xna-legacy`      | Legacy P2PKH, coin type 0      | Legacy P2PKH, coin type 1900  |
 * | `xna-pq`          | AuthScript v1 + PQ key (nc1p)  | strict PQ witness v2 (pq1z)   |
 */
export type NeuraiKeyNetworkAlias =
  | "xna-old-legacy"
  | "xna-authscript"
  | "xna-authscript-test";

const NEURAI_KEY_ALIASES: Record<NeuraiKeyNetworkAlias, NetworkType> = {
  "xna-old-legacy": "xna-legacy",
  "xna-authscript": "xna-pq",
  "xna-authscript-test": "xna-pq-test",
};

/**
 * Get the bitcoinjs-lib Network object for a given Neurai network type.
 * Also accepts the unambiguous neurai-key 5 names {@link NeuraiKeyNetworkAlias}.
 */
export function getNetwork(network: NetworkType | NeuraiKeyNetworkAlias): BjsNetwork {
  const resolved =
    (NEURAI_KEY_ALIASES as Record<string, NetworkType>)[network] ?? network;
  const net = networkMap[resolved as NetworkType];
  if (!net) {
    throw new Error(`Unknown network: ${network}`);
  }
  return net;
}

/**
 * Translate a `@neuraiproject/neurai-key` 5 network name into this package's
 * {@link NetworkType}, interpreting the name with key-5 semantics:
 *
 * - `xna-legacy` / `xna-legacy-test` → `xna` / `xna-test` (P2PKH, coin 1900 / 1)
 * - `xna-old-legacy` → `xna-legacy` (P2PKH, coin type 0)
 * - `xna-authscript` / `xna-authscript-test` → `xna-pq` / `xna-pq-test`
 *   (AuthScript v1, the device's PQ flow)
 *
 * Throws for the key-5 families the NeuraiHW `sign_psbt` / `sign_tx` flows do
 * not produce: `xna` / `xna-test` (strict ECDSA witness v3) and `xna-pq` /
 * `xna-pq-test` (strict PQ witness v2). Sending TO those addresses works with
 * any network (see `encodeDestinationScript`).
 */
export function fromNeuraiKeyNetwork(name: string): NetworkType {
  switch (name) {
    case "xna-legacy":
      return "xna";
    case "xna-legacy-test":
      return "xna-test";
    case "xna-old-legacy":
      return "xna-legacy";
    case "xna-authscript":
      return "xna-pq";
    case "xna-authscript-test":
      return "xna-pq-test";
    case "xna":
    case "xna-test":
      throw new Error(
        `neurai-key 5 network "${name}" is the strict ECDSA witness v3 family (nq1r… / tnq1r…); ` +
          'it has no NeuraiHW network here. For Legacy P2PKH use neurai-key "xna-legacy" (this package: "xna").'
      );
    case "xna-pq":
    case "xna-pq-test":
      throw new Error(
        `neurai-key 5 network "${name}" is the strict PQ witness v2 family (pq1z… / tpq1z…), which the ` +
          'NeuraiHW firmware does not sign yet. Its PQ flow is AuthScript v1: neurai-key "xna-authscript" ' +
          '(this package: "xna-pq").'
      );
    default:
      throw new Error(`Unknown neurai-key network: ${name}`);
  }
}

// ─── AuthScript address families (Bech32m) ───────────────────────────────────

/** The three Bech32m AuthScript address families the node accepts. */
export type AuthScriptFamily = "authscript" | "pq" | "ecdsa";

export interface AuthScriptFamilyParams {
  family: AuthScriptFamily;
  /** Witness version, also the lead byte of the commitment preimage. */
  witnessVersion: 1 | 2 | 3;
  /** authType fixed by the strict families (v2: 0x01, v3: 0x02); undefined for v1. */
  authType?: 0x01 | 0x02;
  /** HRP per chain (regtest uses the testnet HRP). */
  hrp: { mainnet: string; testnet: string };
}

/**
 * Canonical HRP / witness-version pairs (node base58.cpp DecodeDestination).
 * Any other combination is invalid, including the old `nq1p…` / `tnq1p…`
 * encoding of witness v1.
 *
 * - `authscript`: generic AuthScript v1, `nc1p…` / `tnc1p…`, any authType and
 *   witnessScript (the NeuraiHW PQ flow: authType 0x01, witnessScript OP_TRUE).
 * - `pq`: strict PQ witness v2, `pq1z…` / `tpq1z…`.
 * - `ecdsa`: strict ECDSA witness v3, `nq1r…` / `tnq1r…`.
 *
 * The strict families (v2/v3) are only active where the node activated them
 * (regtest today). Before activation an OP_2/OP_3 output is anyone-can-spend,
 * and this library cannot know the activation state of the target chain.
 */
export const AUTHSCRIPT_FAMILIES: Readonly<Record<AuthScriptFamily, AuthScriptFamilyParams>> = {
  authscript: { family: "authscript", witnessVersion: 1, hrp: { mainnet: "nc", testnet: "tnc" } },
  pq: { family: "pq", witnessVersion: 2, authType: 0x01, hrp: { mainnet: "pq", testnet: "tpq" } },
  ecdsa: { family: "ecdsa", witnessVersion: 3, authType: 0x02, hrp: { mainnet: "nq", testnet: "tnq" } },
};

/** Family bound to a witness version (1, 2 or 3), or undefined. */
export function authScriptFamilyByVersion(witnessVersion: number): AuthScriptFamilyParams | undefined {
  return Object.values(AUTHSCRIPT_FAMILIES).find((f) => f.witnessVersion === witnessVersion);
}

/** Family and chain of a (lower-case) HRP, or undefined for a foreign HRP. */
export function authScriptFamilyByHrp(
  hrp: string
): { params: AuthScriptFamilyParams; network: Network } | undefined {
  const lowered = hrp.toLowerCase();
  for (const params of Object.values(AUTHSCRIPT_FAMILIES)) {
    if (params.hrp.mainnet === lowered) return { params, network: "mainnet" };
    if (params.hrp.testnet === lowered) return { params, network: "testnet" };
  }
  return undefined;
}

// ─── Post-Quantum (ML-DSA-44 / AuthScript) network parameters ────────────────

/** Parameters for an AuthScript address family that carries an ML-DSA-44 key. */
export interface PQNetworkParams {
  /** bech32m human-readable part: "nc"/"tnc" (v1) or "pq"/"tpq" (strict v2). */
  hrp: string;
  /** Witness version of the address and lead byte of its commitment (1 or 2). */
  witnessVersion: number;
  /** BIP-32 coin type: 1900 (mainnet) / 1 (testnet). */
  coinType: number;
  /** BIP-32 purpose (NIP-022): 100. */
  purpose: number;
}

/**
 * Generic AuthScript v1 with a PQ key — the family the NeuraiHW firmware's PQ
 * mode uses (`nc1p…`). Up to 0.6.x the HRP was "nq" (`nq1p…`), which the node
 * now rejects; the scriptPubKey and commitment are unchanged.
 */
export const neuraiPQMainnet: PQNetworkParams = {
  hrp: "nc",
  witnessVersion: 1,
  coinType: 1900,
  purpose: 100,
};

export const neuraiPQTestnet: PQNetworkParams = {
  hrp: "tnc",
  witnessVersion: 1,
  coinType: 1,
  purpose: 100,
};

/** Strict PQ witness v2 (`pq1z…` / `tpq1z…`), neurai-key 5 `xna-pq`. */
export const neuraiPQStrictMainnet: PQNetworkParams = {
  hrp: "pq",
  witnessVersion: 2,
  coinType: 1900,
  purpose: 100,
};

export const neuraiPQStrictTestnet: PQNetworkParams = {
  hrp: "tpq",
  witnessVersion: 2,
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

/**
 * PQ network params for a given public Network. `witnessVersion` 1 (default)
 * is the device's generic AuthScript flow (`nc1p…`); 2 is strict PQ (`pq1z…`).
 */
export function getPQNetworkParams(network: Network, witnessVersion: 1 | 2 = 1): PQNetworkParams {
  if (witnessVersion === 2) {
    return network === "testnet" ? neuraiPQStrictTestnet : neuraiPQStrictMainnet;
  }
  return network === "testnet" ? neuraiPQTestnet : neuraiPQMainnet;
}
