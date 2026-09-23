/**
 * Opt-in end-to-end check against a running Neurai-DePIN regtest node (one that
 * knows the nc / pq / nq address families; the strict families are active on
 * regtest). Skipped unless NEURAI_REGTEST_CLI is set to the neurai-cli command
 * of that node, split on whitespace, e.g.
 *
 *   NEURAI_REGTEST_CLI="docker exec -i my-node neurai-cli -regtest -datadir=/tmp/rt -rpcport=18443 -rpcuser=u -rpcpassword=p" \
 *     npx vitest run src/node-regtest.integration.test.ts
 *
 * The node wallet must be able to mine (generatetoaddress) and pay. Every
 * spend below is BUILT and SIGNED by this library, with software keys
 * standing in for the device (@noble ML-DSA-44 for PQ, ecpair for ECDSA), and
 * then submitted to `testmempoolaccept` only (nothing is broadcast):
 *
 * - generic AuthScript v1 (the firmware's sign_tx flow): buildUnsignedPQTransaction
 *   + pqAuthScriptSighash;
 * - strict PQ v2: strictAuthScriptSighash(…, 2);
 * - strict ECDSA v3: buildPSBT + strict sighash (uNeurai >= 0.2.0 PSBT::sign)
 *   + finalizeSignedPSBT;
 * - negative control: a v2 input signed with the v1 sighash is rejected.
 */
import { execFileSync } from "node:child_process";
import { Buffer } from "buffer";
import * as bitcoin from "bitcoinjs-lib";
import { ECPairFactory } from "ecpair";
import ecc from "@bitcoinerlab/secp256k1";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { beforeAll, describe, expect, it } from "vitest";
import {
  ecdsaAddressFromPublicKey,
  encodeDestinationScript,
  pqAddressFromPublicKey,
} from "./pq-address.js";
import { getNetwork, getPQNetworkParams } from "./networks.js";
import { pqAuthScriptSighash, strictAuthScriptSighash } from "./pq-sighash.js";
import { buildUnsignedPQTransaction } from "./pq-tx.js";
import { buildPSBT, finalizeSignedPSBT } from "./psbt.js";

const CLI = (process.env.NEURAI_REGTEST_CLI ?? "").trim().split(/\s+/).filter(Boolean);
const ECPair = ECPairFactory(ecc);
const FUND_XNA = 10;
const FUND_SATS = 1_000_000_000n;

function cli(...args: string[]): string {
  const [bin, ...prefix] = CLI;
  return execFileSync(bin, [...prefix, ...args], { encoding: "utf8", maxBuffer: 64 << 20 }).trim();
}

function mempoolAccept(txHex: string): { allowed: boolean | number; "reject-reason"?: string } {
  return JSON.parse(cli("testmempoolaccept", JSON.stringify([txHex])))[0];
}

/** Fund `address` with 10 XNA and return the outpoint + funding tx hex. */
function fund(address: string, minerAddress: string) {
  const txid = cli("sendtoaddress", address, String(FUND_XNA));
  cli("generatetoaddress", "1", minerAddress);
  const rawTxHex = cli("getrawtransaction", txid);
  const script = encodeDestinationScript(address);
  const vout = bitcoin.Transaction.fromHex(rawTxHex).outs.findIndex(
    (o) => Buffer.from(o.script).equals(script) && o.value === FUND_SATS
  );
  expect(vout).toBeGreaterThanOrEqual(0);
  return { txid, vout, rawTxHex, scriptPubKey: script.toString("hex") };
}

function pqWitness(sig: Uint8Array, publicKey: Uint8Array): Buffer[] {
  return [
    Buffer.from([0x01]),
    Buffer.concat([Buffer.from(sig), Buffer.from([0x01])]),
    Buffer.concat([Buffer.from([0x05]), Buffer.from(publicKey)]),
    Buffer.from([0x51]),
  ];
}

describe.skipIf(CLI.length === 0)("regtest node: spends built and signed by this library", () => {
  const pq = ml_dsa44.keygen(new Uint8Array(32).fill(0x5a));
  const ecKey = ECPair.fromPrivateKey(Buffer.alloc(32, 0x42), { network: { ...getNetwork("xna-test"), bech32: "" } });
  const v1Address = pqAddressFromPublicKey(pq.publicKey, getPQNetworkParams("testnet"));
  const v2Address = pqAddressFromPublicKey(pq.publicKey, getPQNetworkParams("testnet", 2));
  const v3Address = ecdsaAddressFromPublicKey(Buffer.from(ecKey.publicKey), "testnet");
  let miner = "";

  beforeAll(() => {
    miner = cli("getnewaddress");
    if (Number(cli("getbalance")) < 100) {
      cli("generatetoaddress", "101", miner);
    }
  });

  it("the node accepts the addresses the library derives", () => {
    for (const [address, family] of [
      [v1Address, "authscript"],
      [v2Address, "pq"],
      [v3Address, "ecdsa"],
    ]) {
      const info = JSON.parse(cli("validateaddress", address));
      expect(info.isvalid).toBe(true);
      expect(info.family).toBe(family);
      expect(info.scriptPubKey).toBe(encodeDestinationScript(address).toString("hex"));
    }
  });

  it("accepts a generic AuthScript v1 spend (sign_tx flow)", () => {
    const utxo = fund(v1Address, miner);
    const { rawTxHex, inputs } = buildUnsignedPQTransaction({
      utxos: [{ txid: utxo.txid, vout: utxo.vout, satoshis: FUND_SATS, scriptPubKey: utxo.scriptPubKey, type: "pq" }],
      outputs: [{ address: miner, value: 500_000_000 }],
      changeAddress: v1Address,
    });
    const sighash = pqAuthScriptSighash({ tx: rawTxHex, inputIndex: 0, amount: inputs[0].amount });
    const tx = bitcoin.Transaction.fromHex(rawTxHex);
    tx.ins[0].witness = pqWitness(ml_dsa44.sign(Uint8Array.from(sighash), pq.secretKey), pq.publicKey);
    const result = mempoolAccept(tx.toHex());
    expect(result["reject-reason"]).toBeUndefined();
    expect(Boolean(result.allowed)).toBe(true);
  });

  it("accepts a strict PQ v2 spend and rejects a v1-style signature for it", () => {
    const utxo = fund(v2Address, miner);
    const tx = new bitcoin.Transaction();
    tx.version = 2;
    tx.addInput(Buffer.from(utxo.txid, "hex").reverse(), utxo.vout, 0xfffffffd);
    tx.addOutput(encodeDestinationScript(v1Address), FUND_SATS - 5_000_000n);

    const v1Style = pqAuthScriptSighash({ tx, inputIndex: 0, amount: FUND_SATS });
    tx.ins[0].witness = pqWitness(ml_dsa44.sign(Uint8Array.from(v1Style), pq.secretKey), pq.publicKey);
    expect(Boolean(mempoolAccept(tx.toHex()).allowed)).toBe(false);

    const strict = strictAuthScriptSighash({ tx, inputIndex: 0, amount: FUND_SATS, witnessVersion: 2 });
    tx.ins[0].witness = pqWitness(ml_dsa44.sign(Uint8Array.from(strict), pq.secretKey), pq.publicKey);
    const result = mempoolAccept(tx.toHex());
    expect(result["reject-reason"]).toBeUndefined();
    expect(Boolean(result.allowed)).toBe(true);
  });

  it("accepts a strict ECDSA v3 spend built and finalized through a PSBT", () => {
    const utxo = fund(v3Address, miner);
    const pubkey = Buffer.from(ecKey.publicKey);
    const original = buildPSBT({
      network: "xna-test",
      utxos: [{ ...utxo, satoshis: FUND_SATS }],
      outputs: [{ address: miner, value: 500_000_000 }],
      changeAddress: v3Address,
      pubkey: pubkey.toString("hex"),
      masterFingerprint: "00000000",
      derivationPath: "m/84'/1'/0'/0/0",
    });
    // Device stand-in: what uNeurai >= 0.2.0 PSBT::sign does for a v3 prevout.
    const psbt = bitcoin.Psbt.fromBase64(original, { network: getNetwork("xna-test") });
    const unsigned = bitcoin.Transaction.fromBuffer(psbt.data.getTransaction());
    const sighash = strictAuthScriptSighash({ tx: unsigned, inputIndex: 0, amount: FUND_SATS, witnessVersion: 3 });
    psbt.updateInput(0, {
      partialSig: [{ pubkey, signature: bitcoin.script.signature.encode(ecKey.sign(sighash), 0x01) }],
    });
    const { txHex } = finalizeSignedPSBT(original, psbt.toBase64(), "xna-test");
    const result = mempoolAccept(txHex);
    expect(result["reject-reason"]).toBeUndefined();
    expect(Boolean(result.allowed)).toBe(true);
  });
});
