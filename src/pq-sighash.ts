/**
 * AuthScript sighash, matching the firmware (uNeurai `Tx::sigHashAuthScript` /
 * `Tx::sigHashAuthScriptStrict`) and the node's `SignatureHash` exactly: a
 * BIP143-style preimage with extra bytes between `locktime` and `hashType`:
 *
 * - generic AuthScript (witness v1, `nc1p…`): `… locktime || authType || hashType`
 *   with the witnessScript as scriptCode (SIGVERSION_AUTHSCRIPT);
 * - strict families (witness v2 `pq1z…`, v3 `nq1r…`):
 *   `… locktime || witnessVersion || authType || hashType` with the fixed
 *   OP_TRUE witnessScript as scriptCode (SIGVERSION_AUTHSCRIPT_STRICT).
 *
 * A signature over one form never verifies for the other.
 *
 * Pure (no secret material). Used to independently recompute the message the
 * device signed, so a host can verify the returned signature.
 * See docs/pq-protocol-design.md §1 and uNeurai Transaction.cpp.
 */

import { toRawAmount, type RawAmount } from "./amounts.js";
import { Buffer } from "buffer";
import * as bitcoin from "bitcoinjs-lib";

export const SIGHASH_ALL = 0x01;
export const PQ_AUTH_TYPE = 0x01;
export const ECDSA_AUTH_TYPE = 0x02;

/** authType bound to each strict witness version (node interpreter.h). */
const STRICT_AUTH_TYPE: Record<2 | 3, number> = { 2: PQ_AUTH_TYPE, 3: ECDSA_AUTH_TYPE };

function hash256(data: Buffer): Buffer {
  return Buffer.from(bitcoin.crypto.hash256(data));
}

function encodeVarint(n: number): Buffer {
  if (n < 0xfd) return Buffer.from([n]);
  if (n <= 0xffff) {
    const b = Buffer.alloc(3);
    b[0] = 0xfd;
    b.writeUInt16LE(n, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = 0xfe;
  b.writeUInt32LE(n, 1);
  return b;
}

/** varint(len) || bytes */
function varSlice(bytes: Buffer): Buffer {
  return Buffer.concat([encodeVarint(bytes.length), bytes]);
}

function uint32LE(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
}

function uint64LE(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n, 0);
  return b;
}

export interface IPQSighashOptions {
  /** The transaction (unsigned, or signed — its witnesses are ignored here). */
  tx: string | bitcoin.Transaction;
  /** Index of the input being signed. */
  inputIndex: number;
  /** Prevout amount in satoshis (use 0 for asset-wrapped outputs). */
  amount: RawAmount;
  /** witnessScript hex (phase 1: "51" = OP_TRUE; the strict families require "51"). */
  witnessScript?: string;
  /** AuthScript auth type (default 0x01 = PQ; implied by the strict versions). */
  authType?: number;
  /** Sighash flag (default SIGHASH_ALL, the only one supported). */
  sighashType?: number;
  /**
   * Witness version of the prevout: 1 (default, generic AuthScript `nc1p…`),
   * 2 (strict PQ `pq1z…`) or 3 (strict ECDSA `nq1r…`). The strict versions add
   * the witness version byte to the preimage and fix authType (v2: 0x01,
   * v3: 0x02) and the witnessScript (OP_TRUE).
   */
  witnessVersion?: 1 | 2 | 3;
}

/**
 * Compute the 32-byte AuthScript sighash for an input. SIGHASH_ALL only
 * (phase 1): all prevouts/sequences/outputs are committed. Witness v1 by
 * default; pass `witnessVersion: 2 | 3` (or use {@link strictAuthScriptSighash})
 * for the strict families.
 *
 * Transactions with version 3 (NIP-014 reference inputs, which also enter the
 * preimage) are not supported and throw.
 */
export function pqAuthScriptSighash(options: IPQSighashOptions): Buffer {
  const tx =
    typeof options.tx === "string"
      ? bitcoin.Transaction.fromHex(options.tx)
      : options.tx;

  const witnessVersion = options.witnessVersion ?? 1;
  if (witnessVersion !== 1 && witnessVersion !== 2 && witnessVersion !== 3) {
    throw new Error(`Unsupported AuthScript witness version ${witnessVersion}`);
  }
  const strict = witnessVersion !== 1;
  const witnessScriptHex = options.witnessScript ?? "51";
  const authType = options.authType ?? (strict ? STRICT_AUTH_TYPE[witnessVersion] : PQ_AUTH_TYPE);
  if (strict) {
    if (authType !== STRICT_AUTH_TYPE[witnessVersion]) {
      throw new Error(
        `Witness v${witnessVersion} requires authType ${STRICT_AUTH_TYPE[witnessVersion]} (got ${authType})`
      );
    }
    if (witnessScriptHex.toLowerCase() !== "51") {
      throw new Error(`Witness v${witnessVersion} requires the OP_TRUE witnessScript ("51")`);
    }
  }
  const witnessScript = Buffer.from(witnessScriptHex, "hex");
  const sighashType = options.sighashType ?? SIGHASH_ALL;
  if (sighashType !== SIGHASH_ALL) {
    throw new Error(`Only SIGHASH_ALL is supported (got ${sighashType})`);
  }
  if (tx.version === 3) {
    throw new Error("Transaction version 3 (NIP-014 reference inputs) is not supported");
  }
  const amount = toRawAmount(options.amount, "prevout amount");

  const outpointOf = (i: { hash: Uint8Array; index: number }): Buffer => {
    const b = Buffer.alloc(36);
    Buffer.from(i.hash).copy(b, 0);
    b.writeUInt32LE(i.index >>> 0, 32);
    return b;
  };

  const hashPrevouts = hash256(Buffer.concat(tx.ins.map(outpointOf)));
  const hashSequence = hash256(
    Buffer.concat(tx.ins.map((i) => uint32LE(i.sequence)))
  );
  const hashOutputs = hash256(
    Buffer.concat(
      tx.outs.map((o) =>
        Buffer.concat([uint64LE(BigInt(o.value)), varSlice(Buffer.from(o.script))])
      )
    )
  );

  const input = tx.ins[options.inputIndex];
  if (!input) throw new Error(`No input at index ${options.inputIndex}`);

  const preimage = Buffer.concat([
    (() => {
      const v = Buffer.alloc(4);
      v.writeInt32LE(tx.version, 0);
      return v;
    })(),
    hashPrevouts,
    hashSequence,
    outpointOf(input),
    varSlice(witnessScript),
    uint64LE(amount),
    uint32LE(input.sequence),
    hashOutputs,
    uint32LE(tx.locktime),
    // Strict families: the witness version bound to authType, then authType.
    strict ? Buffer.from([witnessVersion, authType]) : Buffer.from([authType]),
    uint32LE(sighashType),
  ]);

  return hash256(preimage);
}

export interface IStrictSighashOptions {
  /** The transaction (unsigned, or signed — its witnesses are ignored here). */
  tx: string | bitcoin.Transaction;
  /** Index of the input being signed. */
  inputIndex: number;
  /** Prevout amount in satoshis (use 0 for asset-wrapped outputs). */
  amount: RawAmount;
  /** 2 (strict PQ, `pq1z…`) or 3 (strict ECDSA, `nq1r…`). */
  witnessVersion: 2 | 3;
  /** Sighash flag (default SIGHASH_ALL, the only one supported). */
  sighashType?: number;
}

/**
 * Sighash of a strict AuthScript input (node SIGVERSION_AUTHSCRIPT_STRICT):
 * the witness-v1 preimage with scriptCode OP_TRUE and
 * `witnessVersion || authType` before the hashType. The witness spending such
 * an input is exactly `[authType, sig||hashType, pubkey, 0x51]`.
 *
 * The NeuraiHW firmware signs witness v1 only today; this is for hosts that
 * verify or build strict spends (and for future firmware).
 */
export function strictAuthScriptSighash(options: IStrictSighashOptions): Buffer {
  return pqAuthScriptSighash({
    tx: options.tx,
    inputIndex: options.inputIndex,
    amount: options.amount,
    sighashType: options.sighashType,
    witnessVersion: options.witnessVersion,
  });
}
