import { describe, it, expect } from '@jest/globals';

// We can't import from tiny-secp256k1.ts directly because it imports
// native modules at the top level. Instead we test the pure logic
// by extracting the functions inline from the source constants.

// secp256k1 N/2 — must match the constant in tiny-secp256k1.ts
// prettier-ignore
const N_HALF = new Uint8Array([
  0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
  0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
]);

function isHighS(sig: Uint8Array): boolean {
  for (let i = 0; i < 32; i++) {
    const a = sig[32 + i] as number;
    const b = N_HALF[i] as number;
    if (a > b) return true;
    if (a < b) return false;
  }
  return false;
}

function isValidPubkeyBytes(p: Uint8Array): boolean {
  if (p.length === 33) return p[0] === 0x02 || p[0] === 0x03;
  if (p.length === 65) return p[0] === 0x04;
  return false;
}

describe('isHighS', () => {
  function makeSig(sBytes: Uint8Array): Uint8Array {
    const sig = new Uint8Array(64);
    sig.set(sBytes, 32);
    return sig;
  }

  it('returns false for zero S', () => {
    expect(isHighS(makeSig(new Uint8Array(32)))).toBe(false);
  });

  it('returns false for S = 1', () => {
    const s = new Uint8Array(32);
    s[31] = 1;
    expect(isHighS(makeSig(s))).toBe(false);
  });

  it('returns false for S = N/2 (boundary, accepted as low-S)', () => {
    expect(isHighS(makeSig(N_HALF))).toBe(false);
  });

  it('returns true for S = N/2 + 1', () => {
    const s = N_HALF.slice();
    s[31]! += 1;
    expect(isHighS(makeSig(s))).toBe(true);
  });

  it('returns true for S = 0xff...ff', () => {
    expect(isHighS(makeSig(new Uint8Array(32).fill(0xff)))).toBe(true);
  });

  it('returns true when first byte exceeds N_HALF', () => {
    const s = new Uint8Array(32);
    s[0] = 0x80; // > 0x7f
    expect(isHighS(makeSig(s))).toBe(true);
  });

  it('returns false when first byte is below N_HALF', () => {
    const s = new Uint8Array(32);
    s[0] = 0x7e; // < 0x7f
    expect(isHighS(makeSig(s))).toBe(false);
  });
});

describe('isValidPubkeyBytes', () => {
  it('accepts 33 bytes with 0x02 prefix', () => {
    const p = new Uint8Array(33);
    p[0] = 0x02;
    expect(isValidPubkeyBytes(p)).toBe(true);
  });

  it('accepts 33 bytes with 0x03 prefix', () => {
    const p = new Uint8Array(33);
    p[0] = 0x03;
    expect(isValidPubkeyBytes(p)).toBe(true);
  });

  it('rejects 33 bytes with 0x04 prefix', () => {
    const p = new Uint8Array(33);
    p[0] = 0x04;
    expect(isValidPubkeyBytes(p)).toBe(false);
  });

  it('accepts 65 bytes with 0x04 prefix', () => {
    const p = new Uint8Array(65);
    p[0] = 0x04;
    expect(isValidPubkeyBytes(p)).toBe(true);
  });

  it('rejects 65 bytes with 0x02 prefix', () => {
    const p = new Uint8Array(65);
    p[0] = 0x02;
    expect(isValidPubkeyBytes(p)).toBe(false);
  });

  it('rejects wrong length', () => {
    expect(isValidPubkeyBytes(new Uint8Array(32))).toBe(false);
    expect(isValidPubkeyBytes(new Uint8Array(0))).toBe(false);
    expect(isValidPubkeyBytes(new Uint8Array(64))).toBe(false);
  });

  it('rejects 33 bytes with 0x00 prefix', () => {
    expect(isValidPubkeyBytes(new Uint8Array(33))).toBe(false);
  });
});
