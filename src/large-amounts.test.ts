import { Buffer } from 'buffer';
import * as bitcoin from 'bitcoinjs-lib';
import * as secp from '@bitcoinerlab/secp256k1';
import ECPairFactory from 'ecpair';
import { describe, expect, it } from 'vitest';
import { buildPSBT, buildPSBTFromRawTransaction, finalizeSignedPSBT } from './psbt.js';
import { buildUnsignedPQTransaction } from './pq-tx.js';
import { pqAuthScriptSighash } from './pq-sighash.js';
import { getNetwork } from './networks.js';
import { ORACLE_PQ_ADDRESS_TESTNET, ORACLE_PQ_COMMITMENT_HEX } from './pq-address.fixtures.js';
import { NeuraiESP32 } from './NeuraiESP32.js';
import type { DeviceResponse, INeuraiTransport } from './types.js';
import type { RawAmount } from './index.js';

bitcoin.initEccLib(secp);
const network = getNetwork('xna-test');
const key = ECPairFactory(secp).fromPrivateKey(Buffer.alloc(32, 1));
const payment = bitcoin.payments.p2pkh({ pubkey: key.publicKey, network });
const pqScript = '5120' + ORACLE_PQ_COMMITMENT_HEX;

function legacyOptions(raw: bigint) {
  const prev = new bitcoin.Transaction();
  prev.addInput(Buffer.alloc(32), 0xffffffff);
  prev.addOutput(payment.output!, raw);
  return {
    network: 'xna-test' as const,
    utxos: [{ txid: prev.getId(), vout: 0, satoshis: raw as RawAmount, scriptPubKey: Buffer.from(payment.output!).toString('hex'), rawTxHex: prev.toHex() }],
    outputs: [{ address: payment.address!, value: 10000000000000001n as RawAmount }],
    changeAddress: payment.address!, pubkey: Buffer.from(key.publicKey).toString('hex'),
    masterFingerprint: '01020304', derivationPath: "m/44'/1'/0'/0/0", feeRate: '1.1',
  };
}
function pqOptions() {
  return {
    utxos: [{ txid: '11'.repeat(32), vout: 0, satoshis: '10000000000100001' as RawAmount, scriptPubKey: pqScript, type: 'pq' as const }],
    outputs: [{ address: ORACLE_PQ_ADDRESS_TESTNET, value: 10000000000000001n as RawAmount }],
    changeAddress: ORACLE_PQ_ADDRESS_TESTNET, feeRate: '0.1',
  };
}

describe('large amounts across signing paths', () => {
  it('builds, signs and finalizes legacy outputs and change exactly', () => {
    const options = legacyOptions(10000000000100001n);
    options.utxos[0].satoshis = '10000000000100001';
    const unsigned = buildPSBT(options);
    const psbt = bitcoin.Psbt.fromBase64(unsigned, { network });
    expect(psbt.txOutputs.map(o => o.value)).toEqual([10000000000000001n, 99751n]);
    psbt.signInput(0, key);
    const signed = finalizeSignedPSBT(unsigned, psbt.toBase64(), 'xna-test');
    const tx = bitcoin.Transaction.fromHex(signed.txHex);
    expect(tx.outs.reduce((sum, o) => sum + o.value, 249n)).toBe(10000000000100001n);
  });
  it('sums individually safe UTXOs beyond the safe number boundary', () => {
    const options = legacyOptions(6000000000000001n);
    const other = legacyOptions(6000000000000002n).utxos[0];
    options.utxos.push(other);
    options.utxos.forEach(u => { u.satoshis = Number(u.satoshis); });
    const psbt = bitcoin.Psbt.fromBase64(buildPSBT(options), { network });
    expect(psbt.txOutputs.reduce((sum, o) => sum + o.value, 412n)).toBe(12000000000000003n);
  });
  it('preserves PQ values and emits JSON-safe exact prevout metadata', () => {
    const built = buildUnsignedPQTransaction(pqOptions());
    const tx = bitcoin.Transaction.fromHex(built.rawTxHex);
    expect(tx.outs.map(o => o.value)).toEqual([10000000000000001n, 99892n]);
    expect(JSON.parse(JSON.stringify(built.inputs))[0].amount).toBe('10000000000100001');
    const opts = { tx, inputIndex: 0, amount: '10000000000100001' };
    const digest = pqAuthScriptSighash(opts);
    expect(pqAuthScriptSighash({ ...opts, amount: 10000000000100001n })).toEqual(digest);
    expect(pqAuthScriptSighash({ ...opts, amount: '10000000000100000' })).not.toEqual(digest);
    expect(() => pqAuthScriptSighash({ ...opts, amount: Number(opts.amount) })).toThrow(/safe integer/);
  });
  it('rejects unsafe numeric inputs and outputs before constructing either format', () => {
    for (const input of [true, false]) {
      const legacy = legacyOptions(10000000000100001n);
      const pq = pqOptions();
      if (input) { legacy.utxos[0].satoshis = 10000000000100000; pq.utxos[0].satoshis = 10000000000100000; }
      else { legacy.outputs[0].value = 10000000000000000; pq.outputs[0].value = 10000000000000000; }
      expect(() => buildPSBT(legacy)).toThrow(/safe integer/);
      expect(() => buildUnsignedPQTransaction(pq)).toThrow(/safe integer/);
    }
  });
  it('reports a one-satoshi shortfall exactly', () => {
    const opts = legacyOptions(10000000000000249n);
    expect(() => buildPSBT(opts)).toThrow('inputs=10000000000000249, outputs=10000000000000001, fee=249');
  });
  it('preserves an asset payload with a large quantity through raw PSBT signing', () => {
    const opts = legacyOptions(1000000n);
    const quantity = Buffer.alloc(8);
    quantity.writeBigUInt64LE(10000000000000001n);
    const payload = Buffer.concat([Buffer.from('xnat', 'ascii'), Buffer.from([5]), Buffer.from('LARGE'), quantity]);
    const assetScript = Buffer.concat([Buffer.from(payment.output!), Buffer.from([0xc0, payload.length]), payload, Buffer.from([0x75])]);
    const raw = new bitcoin.Transaction();
    raw.addInput(Buffer.from(opts.utxos[0].txid, 'hex').reverse(), 0);
    raw.addOutput(assetScript, 0n);
    raw.addOutput(payment.output!, 999000n);
    const base64 = buildPSBTFromRawTransaction({ network: 'xna-test', rawUnsignedTransaction: raw.toHex(), inputs: opts.utxos });
    const psbt = bitcoin.Psbt.fromBase64(base64, { network });
    psbt.signInput(0, key);
    const signed = finalizeSignedPSBT(base64, psbt.toBase64(), 'xna-test');
    expect(Buffer.from(bitcoin.Transaction.fromHex(signed.txHex).outs[0].script)).toEqual(assetScript);
  });
  it('does not count an asset quantity as XNA funding', () => {
    const options = pqOptions();
    const assetInput = { ...options.utxos[0], sighashAmount: 0n };
    expect(() => buildUnsignedPQTransaction({ ...options, utxos: [assetInput] })).toThrow(/Insufficient funds: inputs=0/);
    const coinInput = { ...options.utxos[0], txid: '22'.repeat(32) };
    const built = buildUnsignedPQTransaction({ ...options, utxos: [assetInput, coinInput] });
    expect(built.inputs[0].amount).toBe(0);
    expect(bitcoin.Transaction.fromHex(built.rawTxHex).outs.reduce((sum, o) => sum + o.value, 205n)).toBe(10000000000100001n);
  });
  it('normalizes raw PQ metadata before handing it to any transport', async () => {
    const tx = buildUnsignedPQTransaction(pqOptions()).rawTxHex;
    const commands: Record<string, unknown>[] = [];
    const transport: INeuraiTransport = {
      connected: true, async open() {}, async close() {},
      async sendCommand(command): Promise<DeviceResponse> {
        commands.push(JSON.parse(JSON.stringify(command)));
        return { status: 'ok', tx, signed_inputs: 2 };
      },
      async sendCommandFinal(command) { return this.sendCommand(command); },
      async sendCommandHeartbeat(command) { return this.sendCommand(command); },
    };
    const device = new NeuraiESP32({ transport });
    await device.signPqRawTransaction({ txHex: tx, inputs: [{ index: 0, amount: 10000000000000001n }, { index: 1, amount: 0n }] });
    expect(commands[0].inputs).toEqual([{ index: 0, amount: '10000000000000001' }, { index: 1, amount: 0 }]);
    await expect(device.signPqRawTransaction({ txHex: tx, inputs: [{ index: 0, amount: 10000000000000000 }] })).rejects.toThrow(/safe integer/);
    expect(commands).toHaveLength(1);
  });
});
