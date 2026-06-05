/**
 * AuthScript (witness v1 / ML-DSA-44) sighash, matching the firmware's
 * `Tx::sigHashAuthScript` exactly: a BIP143-style preimage with an extra
 * `authType` byte inserted between `locktime` and `hashType`.
 *
 * Pure (no secret material). Used to independently recompute the message the
 * device signed, so a host can verify the returned ML-DSA-44 signature.
 * See docs/pq-protocol-design.md §1 and uNeurai Transaction.cpp:757.
 */

import { Buffer } from "buffer";
import * as bitcoin from "bitcoinjs-lib";

export const SIGHASH_ALL = 0x01;
export const PQ_AUTH_TYPE = 0x01;

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
  amount: number | bigint;
  /** witnessScript hex (phase 1: "51" = OP_TRUE). */
  witnessScript?: string;
  /** AuthScript auth type (default 0x01 = PQ). */
  authType?: number;
  /** Sighash flag (default SIGHASH_ALL). */
  sighashType?: number;
}

/**
 * Compute the 32-byte AuthScript sighash for a PQ input. SIGHASH_ALL only
 * (phase 1): all prevouts/sequences/outputs are committed.
 */
export function pqAuthScriptSighash(options: IPQSighashOptions): Buffer {
  const tx =
    typeof options.tx === "string"
      ? bitcoin.Transaction.fromHex(options.tx)
      : options.tx;

  const witnessScript = Buffer.from(options.witnessScript ?? "51", "hex");
  const authType = options.authType ?? PQ_AUTH_TYPE;
  const sighashType = options.sighashType ?? SIGHASH_ALL;
  const amount = BigInt(options.amount);

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
    Buffer.from([authType]),
    uint32LE(sighashType),
  ]);

  return hash256(preimage);
}
