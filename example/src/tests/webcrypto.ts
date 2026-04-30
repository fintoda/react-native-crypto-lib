// WebCrypto polyfill — only `crypto.getRandomValues` is provided.

import {
  installCryptoPolyfill,
  getRandomValues,
} from '@fintoda/react-native-crypto-lib';
import { check, type TestGroup } from './harness';

export const webcryptoGroup: TestGroup = {
  id: 'webcrypto',
  title: 'webcrypto polyfill',
  description: 'globalThis.crypto.getRandomValues shim',
  build: () => [
    check('installCryptoPolyfill registers globalThis.crypto', () => {
      installCryptoPolyfill();
      const g = globalThis as unknown as {
        crypto?: { getRandomValues?: unknown };
      };
      return typeof g.crypto?.getRandomValues === 'function';
    }),
    check('getRandomValues fills 16-byte buffer', () => {
      const buf = new Uint8Array(16);
      getRandomValues(buf);
      return buf.some((b) => b !== 0);
    }),
    check('getRandomValues returns the same buffer', () => {
      const buf = new Uint8Array(8);
      const r = getRandomValues(buf);
      return r === buf;
    }),
    check('getRandomValues fills Uint32Array element-wise', () => {
      const buf = new Uint32Array(4);
      getRandomValues(buf);
      return buf.some((v) => v !== 0);
    }),
    check('getRandomValues handles 1024-byte buffer', () => {
      const buf = new Uint8Array(1024);
      getRandomValues(buf);
      let nonzero = 0;
      for (const b of buf) if (b !== 0) nonzero++;
      // CSPRNG should produce roughly 99.6% non-zero bytes.
      return nonzero > 900 || `nonzero=${nonzero}/1024`;
    }),
  ],
};
