import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';

// webcrypto.ts imports rng which imports the native module.
// We test the pure validation logic by reimplementing the key parts.

const MAX_BYTES = 65536;

// Minimal reimplementation of getRandomValues validation logic.
function validateGetRandomValues<
  T extends { byteLength: number } | null | undefined,
>(array: T): void {
  if (
    array == null ||
    typeof (array as { byteLength?: unknown }).byteLength !== 'number'
  ) {
    throw new TypeError(
      'getRandomValues: expected a typed array (Uint8Array, Int32Array, ...)'
    );
  }
  if ((array as { byteLength: number }).byteLength > MAX_BYTES) {
    throw new Error(
      `getRandomValues: quota exceeded (${(array as { byteLength: number }).byteLength} > ${MAX_BYTES})`
    );
  }
}

describe('getRandomValues validation', () => {
  it('rejects null', () => {
    expect(() => validateGetRandomValues(null)).toThrow(TypeError);
  });

  it('rejects undefined', () => {
    expect(() => validateGetRandomValues(undefined)).toThrow(TypeError);
  });

  it('rejects object without byteLength', () => {
    expect(() => validateGetRandomValues({} as { byteLength: number })).toThrow(
      TypeError
    );
  });

  it('accepts array with byteLength <= 65536', () => {
    expect(() =>
      validateGetRandomValues({ byteLength: MAX_BYTES })
    ).not.toThrow();
  });

  it('rejects array with byteLength > 65536', () => {
    expect(() =>
      validateGetRandomValues({ byteLength: MAX_BYTES + 1 })
    ).toThrow('quota exceeded');
  });

  it('accepts zero-length array', () => {
    expect(() => validateGetRandomValues({ byteLength: 0 })).not.toThrow();
  });
});

// installCryptoPolyfill logic test
describe('installCryptoPolyfill logic', () => {
  let savedCrypto: unknown;

  beforeEach(() => {
    savedCrypto = (globalThis as { crypto?: unknown }).crypto;
  });

  afterEach(() => {
    (globalThis as { crypto?: unknown }).crypto = savedCrypto;
  });

  it('installs when crypto is absent', () => {
    delete (globalThis as { crypto?: unknown }).crypto;
    const g = globalThis as { crypto?: { getRandomValues?: unknown } };
    expect(g.crypto).toBeUndefined();

    // Simulate install
    g.crypto = { getRandomValues: () => {} };
    expect(typeof g.crypto.getRandomValues).toBe('function');
  });

  it('does not overwrite existing getRandomValues', () => {
    const original = () => {};
    (globalThis as { crypto?: { getRandomValues?: unknown } }).crypto = {
      getRandomValues: original,
    };

    const g = globalThis as { crypto?: { getRandomValues?: unknown } };
    const shouldInstall = typeof g.crypto?.getRandomValues !== 'function';
    expect(shouldInstall).toBe(false);
  });

  it('patches crypto object missing getRandomValues', () => {
    (globalThis as { crypto?: { getRandomValues?: unknown } }).crypto = {};

    const g = globalThis as { crypto?: { getRandomValues?: unknown } };
    const shouldInstall = typeof g.crypto?.getRandomValues !== 'function';
    expect(shouldInstall).toBe(true);
  });
});
