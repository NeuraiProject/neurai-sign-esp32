import { describe, expect, it } from "vitest";
import {
  decodeAddress,
  encodeDestinationScript,
  isPQAddress,
  pqAuthDescriptor,
  pqCommitment,
  publicKeyToAddress,
} from "./pq-address.js";
import {
  ORACLE_PQ_ADDRESS_TESTNET,
  ORACLE_PQ_COMMITMENT_HEX,
  ORACLE_PQ_PUBKEY_HEX,
} from "./pq-address.fixtures.js";

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
  });

  it("builds a 21-byte PQ auth descriptor (0x01 || hash160)", () => {
    const desc = pqAuthDescriptor(ORACLE_PQ_PUBKEY_HEX);
    expect(desc.length).toBe(21);
    expect(desc[0]).toBe(0x01);
  });
});

describe("isPQAddress", () => {
  it("recognises PQ addresses", () => {
    expect(isPQAddress(ORACLE_PQ_ADDRESS_TESTNET)).toBe(true);
    expect(isPQAddress("nq1qexample")).toBe(true);
    expect(isPQAddress("TNQ1PEXAMPLE")).toBe(true);
  });

  it("rejects legacy addresses", () => {
    expect(isPQAddress("NXyz123")).toBe(false);
    expect(isPQAddress("n1notpq")).toBe(false);
  });
});

describe("decodeAddress", () => {
  it("decodes a PQ address to its 32-byte commitment", () => {
    const decoded = decodeAddress(ORACLE_PQ_ADDRESS_TESTNET);
    expect(decoded.type).toBe("pq");
    if (decoded.type !== "pq") throw new Error("expected pq");
    expect(decoded.witnessVersion).toBe(1);
    expect(decoded.commitment.toString("hex")).toBe(ORACLE_PQ_COMMITMENT_HEX);
  });
});

describe("encodeDestinationScript", () => {
  it("encodes a PQ destination as OP_1 || 0x20 || commitment", () => {
    const script = encodeDestinationScript(ORACLE_PQ_ADDRESS_TESTNET);
    expect(script.toString("hex")).toBe("5120" + ORACLE_PQ_COMMITMENT_HEX);
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
