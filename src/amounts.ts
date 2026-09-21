/** Exact monetary boundaries. Raw values are always 10^8-scaled protocol units. */
export type RawAmount = bigint | string | number;
export type DecimalAmount = string | number;
export const MAX_MONEY = 2100000000000000000n;
const SCALE = 100000000n;

/** Reject numbers whose original low bits may already have been lost. */
export function toRawAmount(value: RawAmount, label = 'amount'): bigint {
  let raw: bigint;
  if (typeof value === 'bigint') raw = value;
  else if (typeof value === 'number' && Number.isSafeInteger(value)) raw = BigInt(value);
  else if (typeof value === 'string' && /^\d{1,19}$/.test(value)) raw = BigInt(value);
  else throw new Error(`${label}: expected bigint, integer text or a safe integer number`);
  if (raw < 0n || raw > MAX_MONEY) throw new Error(`${label}: outside Neurai monetary range`);
  return raw;
}

/** JSON compatibility: numeric safe integers, decimal integer text otherwise. */
export function rawAmountForDevice(value: RawAmount): number | string {
  const raw = toRawAmount(value);
  return raw <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(raw) : raw.toString();
}

function decimalRatio(value: DecimalAmount, label: string): [bigint, bigint] {
  if (typeof value !== 'string' && typeof value !== 'number') throw new Error(`${label}: expected decimal text or number`);
  if (typeof value === 'number' && (!Number.isFinite(value) || value < 0 || value > Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${label}: expected a finite non-negative safe number`);
  }
  const text = String(value);
  if (text.length > 100) throw new Error(`${label}: decimal text is too long`);
  const match = /^(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(text);
  if (!match) throw new Error(`${label}: invalid non-negative decimal`);
  const exponent = Number(match[3] ?? 0);
  if (!Number.isSafeInteger(exponent) || Math.abs(exponent) > 100) throw new Error(`${label}: exponent is out of range`);
  const fraction = match[2] ?? '';
  const shift = exponent - fraction.length;
  const digits = BigInt(match[1] + fraction);
  return shift >= 0 ? [digits * 10n ** BigInt(shift), 1n] : [digits, 10n ** BigInt(-shift)];
}

/** Round a fractional sat/byte fee upward once, using integer arithmetic. */
export function estimateFee(size: number, rate: DecimalAmount): bigint {
  if (!Number.isSafeInteger(size) || size < 0) throw new Error('Invalid transaction size');
  const [numerator, denominator] = decimalRatio(rate, 'feeRate');
  return toRawAmount((BigInt(size) * numerator + denominator - 1n) / denominator, 'fee');
}

/** Validate display units; keep caller-provided plain decimal text unchanged. */
export function formatDisplayAmount(value: DecimalAmount): string {
  if (typeof value === 'string' && !/^\d+(?:\.\d{1,8})?$/.test(value)) {
    throw new Error('Display amount must be plain decimal text with at most eight decimals');
  }
  const [numerator, denominator] = decimalRatio(value, 'display amount');
  if (numerator * SCALE % denominator !== 0n) throw new Error('Display amount exceeds eight decimals');
  const raw = toRawAmount(numerator * SCALE / denominator, 'display amount');
  if (typeof value === 'number' && raw > BigInt(Number.MAX_SAFE_INTEGER) && !Number.isSafeInteger(value)) {
    throw new Error('Large fractional display amounts must be supplied as decimal text');
  }
  if (typeof value === 'string') return value;
  return `${raw / SCALE}.${(raw % SCALE).toString().padStart(8, '0')}`;
}
