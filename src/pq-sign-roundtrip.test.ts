import { Buffer } from "buffer";
import { describe, expect, it } from "vitest";
import * as bitcoin from "bitcoinjs-lib";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { buildUnsignedPQTransaction, extractPQWitness } from "./pq-tx.js";
import { pqAuthScriptSighash } from "./pq-sighash.js";
import { encodeDestinationScript, publicKeyToAddress } from "./pq-address.js";

// Full host-side PQ signing pipeline, with @noble standing in for the device's
// ML-DSA-44 backend. Proves: build → sighash → (sign) → witness assembly →
// extraction → re-derived sighash → signature verification all agree. If the
// real device signs over the same sighash, its signature verifies identically.
describe("PQ signing round-trip (noble emulates the device)", () => {
  it("produces a verifiable ML-DSA-44 signature over the AuthScript sighash", () => {
    const seed = new Uint8Array(32).fill(3);
    const { publicKey, secretKey } = ml_dsa44.keygen(seed);
    const pubHex = Buffer.from(publicKey).toString("hex");

    const address = publicKeyToAddress(pubHex, { network: "testnet", keyType: "pq" });
    const scriptPubKey = encodeDestinationScript(address).toString("hex");
    const amount = 100_000_000;

    const { rawTxHex, inputs } = buildUnsignedPQTransaction({
      utxos: [{ txid: "11".repeat(32), vout: 0, satoshis: amount, scriptPubKey, type: "pq" }],
      outputs: [{ address, value: 50_000_000 }],
      changeAddress: address,
      feeRate: 1,
    });

    // ── Emulate the device: sign the AuthScript sighash with ML-DSA-44 ──
    const sighash = pqAuthScriptSighash({
      tx: rawTxHex,
      inputIndex: 0,
      amount: inputs[0].amount,
      witnessScript: "51",
      authType: 1,
    });
    const sig = ml_dsa44.sign(Uint8Array.from(sighash), secretKey, { extraEntropy: false });
    const witness = [
      Buffer.from([0x01]), // authType
      Buffer.concat([Buffer.from(sig), Buffer.from([0x01])]), // sig || SIGHASH_ALL
      Buffer.concat([Buffer.from([0x05]), Buffer.from(publicKey)]), // 0x05 || pubkey
      Buffer.from([0x51]), // witnessScript = OP_TRUE
    ];
    const tx = bitcoin.Transaction.fromHex(rawTxHex);
    tx.ins[0].witness = witness;
    const signedHex = tx.toHex();

    // ── Host: extract + verify ──
    const w = extractPQWitness(signedHex, 0);
    expect(w.authType).toBe(1);
    expect(w.hashType).toBe(0x01);
    expect(w.pubkey.toString("hex")).toBe(pubHex);
    expect(w.signature.length).toBe(2420);

    const recomputed = pqAuthScriptSighash({
      tx: signedHex,
      inputIndex: 0,
      amount,
      witnessScript: "51",
      authType: 1,
    });
    expect(recomputed.toString("hex")).toBe(sighash.toString("hex"));

    // verify(signature, message, publicKey)
    const ok = ml_dsa44.verify(
      Uint8Array.from(w.signature),
      Uint8Array.from(recomputed),
      Uint8Array.from(w.pubkey)
    );
    expect(ok).toBe(true);
  });
});
