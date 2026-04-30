// RNG sanity checks — entropy can't be tested formally without statistical
// suites, so these are smoke checks: never returns all zeros, returns
// distinct outputs across calls, uniform() hits the requested range, and
// invalid inputs throw.

import { rng } from '@fintoda/react-native-crypto-lib';
import { check, eq, throws, type TestGroup } from './harness';

export const rngGroup: TestGroup = {
  id: 'rng',
  title: 'rng',
  description: 'rng.bytes / uint32 / uniform',
  build: () => [
    check('bytes(0) is empty', () => rng.bytes(0).length === 0),
    check('bytes(1) length=1', () => rng.bytes(1).length === 1),
    check('bytes(32) length=32', () => rng.bytes(32).length === 32),
    check('bytes(1024) length=1024', () => rng.bytes(1024).length === 1024),
    check('bytes(32) not all zeros', () => rng.bytes(32).some((b) => b !== 0)),
    check(
      'bytes(32) two calls differ',
      () => !eq(rng.bytes(32), rng.bytes(32))
    ),
    check('bytes(64) covers value space', () => {
      const b = rng.bytes(64);
      // With 64 bytes from a CSPRNG we expect at least ~30 distinct values.
      const set = new Set<number>();
      for (let i = 0; i < b.length; i++) set.add(b[i]!);
      return set.size > 16 || `unique=${set.size}`;
    }),

    check('uint32() integer', () => Number.isInteger(rng.uint32())),
    check('uint32() in [0, 2^32)', () => {
      const v = rng.uint32();
      return v >= 0 && v <= 0xffffffff;
    }),
    check('uint32() varies', () => {
      const samples = new Set<number>();
      for (let i = 0; i < 16; i++) samples.add(rng.uint32());
      return samples.size > 8 || `unique=${samples.size}`;
    }),

    check('uniform(1) always 0', () => rng.uniform(1) === 0),
    check('uniform(2) hits both 0 and 1 in 64 trials', () => {
      const seen = new Set<number>();
      for (let i = 0; i < 64; i++) seen.add(rng.uniform(2));
      return seen.size === 2 || `seen=${[...seen].join(',')}`;
    }),
    check('uniform(100) in [0,100)', () => {
      for (let i = 0; i < 64; i++) {
        const v = rng.uniform(100);
        if (v < 0 || v >= 100) return `oob ${v}`;
      }
      return true;
    }),
    check('uniform(2^31) integer in range', () => {
      const v = rng.uniform(0x7fffffff);
      return Number.isInteger(v) && v >= 0 && v < 0x7fffffff;
    }),

    throws('uniform(0) throws', () => rng.uniform(0)),
    throws('uniform(-1) throws', () => rng.uniform(-1)),
  ],
};
