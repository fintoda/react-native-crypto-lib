// Smoke tests for the Promise-returning variants of heavy ops. Each test
// runs the async helper and compares its output against the sync helper.
// This is really verifying the worker-thread / finishWork JSI plumbing
// for each return shape (ArrayBuffer, string[], string[][]).

import { bip39, kdf, slip39 } from '@fintoda/react-native-crypto-lib';
import { ascii, check, eq, fromHex, toHex, type TestGroup } from './harness';

export const asyncOpsGroup: TestGroup = {
  id: 'asyncOps',
  title: 'async ops vs sync',
  description: 'PBKDF2, BIP-39 seed, SLIP-39 — async equals sync',
  build: () => {
    const pwd = ascii('password');
    const salt = ascii('salt');

    return [
      check('async pbkdf2_sha256 == sync', async () => {
        const a = await kdf.pbkdf2_sha256(pwd, salt, 1000, 32);
        const s = kdf.pbkdf2_sha256Sync(pwd, salt, 1000, 32);
        return eq(a, s) || `async=${toHex(a)} sync=${toHex(s)}`;
      }),
      check('async pbkdf2_sha512 == sync', async () => {
        const a = await kdf.pbkdf2_sha512(pwd, salt, 1000, 64);
        const s = kdf.pbkdf2_sha512Sync(pwd, salt, 1000, 64);
        return eq(a, s) || `async=${toHex(a)} sync=${toHex(s)}`;
      }),
      check('async bip39.toSeed == sync', async () => {
        const m =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
        const a = await bip39.toSeed(m, 'TREZOR');
        const s = bip39.toSeedSync(m, 'TREZOR');
        return eq(a, s) || `async=${toHex(a)} sync=${toHex(s)}`;
      }),
      check('async slip39.generate + combine round-trip', async () => {
        const secret = fromHex('0123456789abcdef0123456789abcdef');
        const shares = await slip39.generate(secret, 'pp', 2, 3, 0);
        if (!Array.isArray(shares) || shares.length !== 3) {
          return `expected 3 shares, got ${shares.length}`;
        }
        const recovered = await slip39.combine([shares[0]!, shares[2]!], 'pp');
        return eq(recovered, secret) || `recovered ${toHex(recovered)}`;
      }),
      check('async slip39.generateGroups + combine', async () => {
        const secret = fromHex('0123456789abcdef0123456789abcdef');
        const groups = await slip39.generateGroups(
          secret,
          '',
          2,
          [
            { threshold: 1, count: 1 },
            { threshold: 2, count: 3 },
          ],
          0
        );
        if (groups.length !== 2) return `groups=${groups.length}`;
        if (groups[0]!.length !== 1) return `g0=${groups[0]!.length}`;
        if (groups[1]!.length !== 3) return `g1=${groups[1]!.length}`;
        const recovered = await slip39.combine(
          [groups[0]![0]!, groups[1]![0]!, groups[1]![1]!],
          ''
        );
        return eq(recovered, secret) || `recovered ${toHex(recovered)}`;
      }),
      // Concurrency: kicking off several heavy ops in parallel must not
      // deadlock or interleave results.
      check('parallel pbkdf2 jobs all complete', async () => {
        const jobs: Promise<Uint8Array>[] = [];
        for (let i = 0; i < 4; i++) {
          jobs.push(kdf.pbkdf2_sha256(pwd, ascii(`s${i}`), 500, 32));
        }
        const out = await Promise.all(jobs);
        return out.every((b) => b.length === 32);
      }),
    ];
  },
};
