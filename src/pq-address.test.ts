import { describe, expect, it } from "vitest";
import { Buffer } from "buffer";
import { ECPairFactory } from "ecpair";
import ecc from "@bitcoinerlab/secp256k1";
import {
  authScriptAddressFromProgram,
  authScriptCommitment,
  authScriptWitnessVersionOfScript,
  decodeAddress,
  ecdsaAddressFromPublicKey,
  ecdsaCommitment,
  encodeAuthScriptDestination,
  encodeDestinationScript,
  getAddressFamily,
  isPQAddress,
  isWitnessAddress,
  normalizeDeviceAuthScriptAddress,
  pqAddressFromPublicKey,
  pqAuthDescriptor,
  pqCommitment,
  publicKeyToAddress,
} from "./pq-address.js";
import {
  getNetwork,
  getPQNetworkParams,
  neuraiPQStrictTestnet,
  neuraiPQTestnet,
} from "./networks.js";
import {
  NODE_EC_P2PKH,
  NODE_EC_PUBKEY_HEX,
  NODE_EC_V3_ADDRESS,
  NODE_EC_V3_MAINNET,
  NODE_EC_V3_SPK,
  NODE_EC_WIF,
  NODE_INVALID_ADDRESSES,
  NODE_PQ_PUBKEY_HEX,
  NODE_PQ_V1_ADDRESS,
  NODE_PQ_V1_MAINNET,
  NODE_PQ_V1_SPK,
  NODE_PQ_V2_ADDRESS,
  NODE_PQ_V2_MAINNET,
  NODE_PQ_V2_SPK,
  NODE_V1_ADDRESS,
  NODE_V1_SPK,
  ORACLE_PQ_ADDRESS_MAINNET,
  ORACLE_PQ_ADDRESS_TESTNET,
  ORACLE_PQ_ADDRESS_TESTNET_OLD,
  ORACLE_PQ_COMMITMENT_HEX,
  ORACLE_PQ_PUBKEY_HEX,
  ORACLE_PQ_V2_ADDRESS_TESTNET,
  ORACLE_PQ_V2_COMMITMENT_HEX,
  P2PKH_NC1_LOOKALIKE,
  P2PKH_NQ1_LOOKALIKE,
} from "./pq-address.fixtures.js";

const ECPair = ECPairFactory(ecc);

describe("PQ address derivation (firmware oracle vector)", () => {
  it("derives the commitment from the public key", () => {
    expect(pqCommitment(ORACLE_PQ_PUBKEY_HEX).toString("hex")).toBe(
      ORACLE_PQ_COMMITMENT_HEX
    );
  });

  it("derives the testnet address from the public key", () => {
    expect(
      publicKeyToAddress(ORACLE_PQ_PUBKEY_HEX, {
        network: "testnet",
        keyType: "pq",
      })
    ).toBe(ORACLE_PQ_ADDRESS_TESTNET);
    expect(
      publicKeyToAddress(ORACLE_PQ_PUBKEY_HEX, {
        network: "mainnet",
        keyType: "pq",
      })
    ).toBe(ORACLE_PQ_ADDRESS_MAINNET);
  });

  it("derives the strict v2 address and commitment of the same key", () => {
    expect(pqCommitment(ORACLE_PQ_PUBKEY_HEX, "51", 2).toString("hex")).toBe(
      ORACLE_PQ_V2_COMMITMENT_HEX
    );
    expect(pqAddressFromPublicKey(ORACLE_PQ_PUBKEY_HEX, neuraiPQStrictTestnet)).toBe(
      ORACLE_PQ_V2_ADDRESS_TESTNET
    );
    expect(
      publicKeyToAddress(ORACLE_PQ_PUBKEY_HEX, { network: "testnet", keyType: "pq", witnessVersion: 2 })
    ).toBe(ORACLE_PQ_V2_ADDRESS_TESTNET);
  });

  it("builds a 21-byte PQ auth descriptor (0x01 || hash160)", () => {
    const desc = pqAuthDescriptor(ORACLE_PQ_PUBKEY_HEX);
    expect(desc.length).toBe(21);
    expect(desc[0]).toBe(0x01);
  });
});

describe("address families (regtest node vectors)", () => {
  it("derives the node's v1 and v2 addresses of a PQ key", () => {
    expect(pqAddressFromPublicKey(NODE_PQ_PUBKEY_HEX, neuraiPQTestnet)).toBe(NODE_PQ_V1_ADDRESS);
    expect(pqAddressFromPublicKey(NODE_PQ_PUBKEY_HEX, getPQNetworkParams("mainnet"))).toBe(NODE_PQ_V1_MAINNET);
    expect(pqAddressFromPublicKey(NODE_PQ_PUBKEY_HEX, getPQNetworkParams("testnet", 2))).toBe(NODE_PQ_V2_ADDRESS);
    expect(pqAddressFromPublicKey(NODE_PQ_PUBKEY_HEX, getPQNetworkParams("mainnet", 2))).toBe(NODE_PQ_V2_MAINNET);
  });

  it("derives the node's strict ECDSA v3 address of a secp256k1 key", () => {
    const key = ECPair.fromWIF(NODE_EC_WIF, { ...getNetwork("xna-test"), bech32: "" });
    const pubkey = Buffer.from(key.publicKey);
    expect(pubkey.toString("hex")).toBe(NODE_EC_PUBKEY_HEX);
    expect(ecdsaAddressFromPublicKey(pubkey, "testnet")).toBe(NODE_EC_V3_ADDRESS);
    expect(ecdsaAddressFromPublicKey(NODE_EC_PUBKEY_HEX, "mainnet")).toBe(NODE_EC_V3_MAINNET);
    expect("5320" + ecdsaCommitment(pubkey).toString("hex")).toBe(NODE_EC_V3_SPK);
    expect(publicKeyToAddress(NODE_EC_PUBKEY_HEX, { network: "testnet", keyType: "legacy" })).toBe(
      NODE_EC_P2PKH
    );
  });

  it.each([
    [NODE_V1_ADDRESS, NODE_V1_SPK, "authscript", 1, "testnet"],
    [NODE_PQ_V1_MAINNET, NODE_PQ_V1_SPK, "authscript", 1, "mainnet"],
    [NODE_PQ_V2_ADDRESS, NODE_PQ_V2_SPK, "pq", 2, "testnet"],
    [NODE_PQ_V2_MAINNET, NODE_PQ_V2_SPK, "pq", 2, "mainnet"],
    [NODE_EC_V3_ADDRESS, NODE_EC_V3_SPK, "ecdsa", 3, "testnet"],
    [NODE_EC_V3_MAINNET, NODE_EC_V3_SPK, "ecdsa", 3, "mainnet"],
  ] as const)("decodes %s", (address, spk, family, witnessVersion, network) => {
    const decoded = decodeAddress(address);
    expect(decoded.type).toBe("pq");
    if (decoded.type !== "pq") throw new Error("expected a witness address");
    expect(decoded.family).toBe(family);
    expect(decoded.witnessVersion).toBe(witnessVersion);
    expect(decoded.network).toBe(network);
    expect(decoded.commitment.toString("hex")).toBe(spk.slice(4));
    expect(encodeDestinationScript(address).toString("hex")).toBe(spk);
    expect(encodeAuthScriptDestination(address.toUpperCase()).toString("hex")).toBe(spk);
    expect(authScriptWitnessVersionOfScript(spk)).toBe(witnessVersion);
    expect(authScriptAddressFromProgram(witnessVersion, network, decoded.commitment)).toBe(address);
    expect(getAddressFamily(address)).toBe(family);
    expect(isWitnessAddress(address)).toBe(true);
  });

  it.each(NODE_INVALID_ADDRESSES)("rejects the non-canonical pair %s", (address) => {
    expect(() => decodeAddress(address)).toThrow(/prefix only encodes witness/);
    expect(() => encodeDestinationScript(address)).toThrow();
    expect(isWitnessAddress(address)).toBe(false);
    expect(isPQAddress(address)).toBe(false);
  });

  it("explains the old nq1p… / tnq1p… encoding", () => {
    expect(() => decodeAddress(ORACLE_PQ_ADDRESS_TESTNET_OLD)).toThrow(/nc1p… \/ tnc1p…/);
  });

  it("reports a checksum error for a corrupted Bech32m address", () => {
    const corrupted = NODE_EC_V3_ADDRESS.slice(0, -1) + (NODE_EC_V3_ADDRESS.endsWith("q") ? "p" : "q");
    expect(() => decodeAddress(corrupted)).toThrow(/Invalid Bech32m address/);
  });

  it("keeps Base58 look-alikes (NQ1…, Nc1…) as P2PKH", () => {
    for (const address of [P2PKH_NQ1_LOOKALIKE, P2PKH_NC1_LOOKALIKE]) {
      const decoded = decodeAddress(address);
      expect(decoded.type).toBe("legacy");
      expect(decoded.family).toBe("legacy");
      expect(isPQAddress(address)).toBe(false);
      expect(encodeDestinationScript(address).toString("hex")).toMatch(/^76a914[0-9a-f]{40}88ac$/);
    }
  });
});

describe("authScriptCommitment", () => {
  it("enforces the strict templates", () => {
    expect(() =>
      authScriptCommitment({ witnessVersion: 2, authType: 0x02, publicKey: NODE_EC_PUBKEY_HEX })
    ).toThrow(/requires authType/);
    expect(() =>
      authScriptCommitment({ witnessVersion: 2, authType: 0x01, publicKey: ORACLE_PQ_PUBKEY_HEX, witnessScript: "52" })
    ).toThrow(/OP_TRUE/);
    expect(() =>
      authScriptCommitment({ witnessVersion: 3, authType: 0x02, publicKey: "04" + "11".repeat(32) })
    ).toThrow(/compressed/);
    expect(() => pqCommitment(ORACLE_PQ_PUBKEY_HEX, "52", 2)).toThrow(/OP_TRUE/);
  });

  it("allows any witnessScript for the generic family", () => {
    const c = authScriptCommitment({
      witnessVersion: 1,
      authType: 0x01,
      publicKey: ORACLE_PQ_PUBKEY_HEX,
      witnessScript: "52",
    });
    expect(c.length).toBe(32);
    expect(c.toString("hex")).not.toBe(ORACLE_PQ_COMMITMENT_HEX);
  });
});

describe("isPQAddress (deprecated alias of isWitnessAddress)", () => {
  it("recognises every AuthScript family", () => {
    expect(isPQAddress(ORACLE_PQ_ADDRESS_TESTNET)).toBe(true);
    expect(isPQAddress(ORACLE_PQ_V2_ADDRESS_TESTNET)).toBe(true);
    expect(isPQAddress(NODE_EC_V3_ADDRESS)).toBe(true);
    expect(isPQAddress(ORACLE_PQ_ADDRESS_TESTNET.toUpperCase())).toBe(true);
  });

  it("rejects legacy and malformed addresses", () => {
    expect(isPQAddress("NXyz123")).toBe(false);
    expect(isPQAddress("n1notpq")).toBe(false);
    expect(isPQAddress("nq1qexample")).toBe(false);
    expect(isPQAddress(NODE_EC_P2PKH)).toBe(false);
  });
});

describe("decodeAddress", () => {
  it("decodes a PQ address to its 32-byte commitment", () => {
    const decoded = decodeAddress(ORACLE_PQ_ADDRESS_TESTNET);
    expect(decoded.type).toBe("pq");
    if (decoded.type !== "pq") throw new Error("expected pq");
    expect(decoded.witnessVersion).toBe(1);
    expect(decoded.family).toBe("authscript");
    expect(decoded.hrp).toBe("tnc");
    expect(decoded.commitment.toString("hex")).toBe(ORACLE_PQ_COMMITMENT_HEX);
  });
});

describe("encodeDestinationScript", () => {
  it("encodes a PQ destination as OP_1 || 0x20 || commitment", () => {
    const script = encodeDestinationScript(ORACLE_PQ_ADDRESS_TESTNET);
    expect(script.toString("hex")).toBe("5120" + ORACLE_PQ_COMMITMENT_HEX);
  });

  it("encodes a strict PQ destination as OP_2 || 0x20 || commitment", () => {
    const script = encodeDestinationScript(ORACLE_PQ_V2_ADDRESS_TESTNET);
    expect(script.toString("hex")).toBe("5220" + ORACLE_PQ_V2_COMMITMENT_HEX);
  });
});

describe("authScriptWitnessVersionOfScript", () => {
  it("accepts asset-wrapped programs and rejects other scripts", () => {
    expect(authScriptWitnessVersionOfScript(NODE_EC_V3_SPK + "c016786e6174")).toBe(3);
    expect(authScriptWitnessVersionOfScript(NODE_EC_V3_SPK + "75")).toBe(0);
    expect(authScriptWitnessVersionOfScript("5420" + "00".repeat(32))).toBe(0);
    expect(authScriptWitnessVersionOfScript("76a914" + "00".repeat(20) + "88ac")).toBe(0);
  });
});

describe("normalizeDeviceAuthScriptAddress", () => {
  it("re-encodes the pre-0.2.0 firmware v1 address", () => {
    expect(normalizeDeviceAuthScriptAddress(ORACLE_PQ_ADDRESS_TESTNET_OLD)).toBe(ORACLE_PQ_ADDRESS_TESTNET);
  });

  it("leaves every other address untouched", () => {
    for (const address of [ORACLE_PQ_ADDRESS_TESTNET, NODE_EC_V3_ADDRESS, NODE_PQ_V2_ADDRESS, NODE_EC_P2PKH, ""]) {
      expect(normalizeDeviceAuthScriptAddress(address)).toBe(address);
    }
  });
});

describe("publicKeyToAddress (legacy)", () => {
  it("derives a P2PKH address from a compressed secp256k1 pubkey", () => {
    // Compressed pubkey for private key = 1 (well-known secp256k1 generator G).
    const G =
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const mainnet = publicKeyToAddress(G, { network: "mainnet", keyType: "legacy" });
    const testnet = publicKeyToAddress(G, { network: "testnet", keyType: "legacy" });
    expect(mainnet.startsWith("N")).toBe(true);
    // Round-trips back to the same hash160 via decode.
    expect(decodeAddress(mainnet).type).toBe("legacy");
    expect(decodeAddress(testnet).type).toBe("legacy");
  });
});
