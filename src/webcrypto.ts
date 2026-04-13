// WebCrypto-compatible `getRandomValues` backed by our native CSPRNG.
//
// React Native / Hermes doesn't ship `globalThis.crypto.getRandomValues`,
// which breaks any package that expects a browser-like `crypto` global
// (@noble/*, uuid v4, ethers, bitcoinjs-lib in some paths, tweetnacl…).
//
// Usage — install once at app startup, before any of those packages
// is imported:
//
//   import { installCryptoPolyfill } from '@fintoda/react-native-crypto-lib';
//   installCryptoPolyfill();
//
// …or wire up the bare function yourself if you already manage the
// `crypto` global elsewhere:
//
//   import { getRandomValues } from '@fintoda/react-native-crypto-lib';
//   globalThis.crypto = { getRandomValues };

import { rng } from './rng';

type IntegerTypedArray =
  | Int8Array
  | Uint8Array
  | Uint8ClampedArray
  | Int16Array
  | Uint16Array
  | Int32Array
  | Uint32Array
  | BigInt64Array
  | BigUint64Array;

// WebCrypto caps a single call at 65536 bytes.
const MAX_BYTES = 65536;

export function getRandomValues<T extends IntegerTypedArray>(array: T): T {
  if (array == null || typeof array.byteLength !== 'number') {
    throw new TypeError(
      'getRandomValues: expected a typed array (Uint8Array, Int32Array, …)'
    );
  }
  if (array.byteLength > MAX_BYTES) {
    throw new Error(
      `getRandomValues: quota exceeded (${array.byteLength} > ${MAX_BYTES})`
    );
  }
  const bytes = rng.bytes(array.byteLength);
  new Uint8Array(array.buffer, array.byteOffset, array.byteLength).set(bytes);
  return array;
}

/**
 * Assigns `getRandomValues` onto `globalThis.crypto`. Safe to call
 * multiple times — never overwrites an existing implementation.
 * Returns `true` if the polyfill was installed, `false` if a native
 * `crypto.getRandomValues` was already present.
 */
export function installCryptoPolyfill(): boolean {
  const g = globalThis as unknown as { crypto?: { getRandomValues?: unknown } };
  if (!g.crypto) {
    g.crypto = { getRandomValues };
    return true;
  }
  if (typeof g.crypto.getRandomValues !== 'function') {
    (g.crypto as { getRandomValues: typeof getRandomValues }).getRandomValues =
      getRandomValues;
    return true;
  }
  return false;
}
