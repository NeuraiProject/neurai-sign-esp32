import { describe, expect, it } from 'vitest';
import { estimateFee, formatDisplayAmount, MAX_MONEY, rawAmountForDevice, toRawAmount } from './amounts.js';

describe('exact monetary boundaries', () => {
  it.each([0n, 1n, 9007199254740991n, 9007199254740992n, 9007199254740993n, 10000000000000001n, MAX_MONEY])('preserves %s through raw normalization and device JSON', raw => {
    expect(toRawAmount(raw)).toBe(raw);
    expect(toRawAmount(raw.toString())).toBe(raw);
    const wire = JSON.parse(JSON.stringify({ amount: rawAmountForDevice(raw) }));
    expect(BigInt(wire.amount)).toBe(raw);
    expect(typeof wire.amount).toBe(raw <= 9007199254740991n ? 'number' : 'string');
  });
  it.each([9007199254740992, NaN, Infinity, -1, 1.5, '', '1e8', '-1', '1.0', null, MAX_MONEY + 1n])('rejects invalid raw input %s', value => {
    expect(() => toRawAmount(value as never)).toThrow();
  });
  it('computes fractional fee rates with exact upward rounding', () => {
    expect(estimateFee(226, '1.1')).toBe(249n);
    expect(estimateFee(1073, 0.1)).toBe(108n);
    expect(estimateFee(226, 0)).toBe(0n);
    for (const value of [-1, NaN, Infinity, '', '1e999']) expect(() => estimateFee(226, value)).toThrow();
  });
  it('keeps large decimal text and formats small numbers without binary rounding', () => {
    expect(formatDisplayAmount('100000000.00000001')).toBe('100000000.00000001');
    expect(formatDisplayAmount('1.5000')).toBe('1.5000');
    expect(formatDisplayAmount(1e-8)).toBe('0.00000001');
    expect(formatDisplayAmount(1.23)).toBe('1.23000000');
    expect(formatDisplayAmount(21000000000)).toBe('21000000000.00000000');
    for (const value of [100000000.00000001, NaN, Infinity, -1, 1e-9, '1.123456789', '21000000000.00000001', '1e8']) {
      expect(() => formatDisplayAmount(value)).toThrow();
    }
  });
});
