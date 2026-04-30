// SLIP-39 Shamir Secret Sharing — round-trips and validation.

import { slip39 } from '@fintoda/react-native-crypto-lib';
import { check, eq, fromHex, throws, toHex, type TestGroup } from './harness';

export const slip39Group: TestGroup = {
  id: 'slip39',
  title: 'slip39',
  description: 'Shamir share generate / combine / validate',
  build: () => [
    // 16-byte secret, 2-of-3
    check('round-trip 2-of-3 (16B secret)', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece');
      const shares = slip39.generateSync(secret, '', 2, 3, 0);
      if (shares.length !== 3) return `${shares.length} shares`;
      const recovered = slip39.combineSync([shares[0]!, shares[1]!], '');
      return eq(recovered, secret) || `got ${toHex(recovered)}`;
    }),
    check('round-trip with different share pair', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece');
      const shares = slip39.generateSync(secret, '', 2, 3, 0);
      const recovered = slip39.combineSync([shares[0]!, shares[2]!], '');
      return eq(recovered, secret) || `got ${toHex(recovered)}`;
    }),

    // 32-byte secret, 3-of-5
    check('round-trip 3-of-5 (32B secret)', () => {
      const secret = fromHex(
        'bb54aac4b89dc868ba37d9cc21b2cece' + 'e25053423dba16c395a0e8a1bd04e656'
      );
      const shares = slip39.generateSync(secret, '', 3, 5, 0);
      if (shares.length !== 5) return `${shares.length} shares`;
      const recovered = slip39.combineSync(
        [shares[0]!, shares[2]!, shares[4]!],
        ''
      );
      return eq(recovered, secret) || `got ${toHex(recovered)}`;
    }),

    // Threshold 1 — every share recovers
    check('threshold 1-of-3: every share recovers', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece');
      const shares = slip39.generateSync(secret, '', 1, 3, 0);
      const r0 = slip39.combineSync([shares[0]!], '');
      const r1 = slip39.combineSync([shares[1]!], '');
      const r2 = slip39.combineSync([shares[2]!], '');
      return (
        (eq(r0, secret) && eq(r1, secret) && eq(r2, secret)) ||
        'mismatch among single-share recoveries'
      );
    }),

    // Passphrase
    check('passphrase changes recovered secret', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece');
      const shares = slip39.generateSync(secret, 'test', 2, 3, 0);
      const correct = slip39.combineSync([shares[0]!, shares[1]!], 'test');
      const wrong = slip39.combineSync([shares[0]!, shares[1]!], 'wrong');
      return eq(correct, secret) && !eq(wrong, secret);
    }),

    // Validate
    check('validateMnemonic: accepts valid', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece');
      const shares = slip39.generateSync(secret, '', 2, 2, 0);
      return slip39.validateMnemonic(shares[0]!);
    }),
    check('validateMnemonic: rejects corrupted word', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece');
      const shares = slip39.generateSync(secret, '', 2, 2, 0);
      const words = shares[0]!.split(' ');
      words[5] = words[5] === 'academic' ? 'acid' : 'academic';
      return !slip39.validateMnemonic(words.join(' '));
    }),
    check(
      'validateMnemonic: rejects garbage',
      () => !slip39.validateMnemonic('not actually mnemonic words at all here')
    ),

    // Insufficient shares
    throws('insufficient shares throws', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece');
      const shares = slip39.generateSync(secret, '', 3, 5, 0);
      slip39.combineSync([shares[0]!, shares[1]!], '');
    }),

    // Multi-group (2 of 3 groups, mixed sizes)
    check('multi-group 2-of-3 with mixed thresholds', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece');
      const groups = slip39.generateGroupsSync(
        secret,
        '',
        2,
        [
          { threshold: 2, count: 3 },
          { threshold: 2, count: 3 },
          { threshold: 1, count: 2 },
        ],
        0
      );
      if (groups.length !== 3) return `groups=${groups.length}`;
      const recovered = slip39.combineSync(
        [groups[0]![0]!, groups[0]![1]!, groups[2]![0]!],
        ''
      );
      return eq(recovered, secret) || `got ${toHex(recovered)}`;
    }),

    // Distinct shares — no two shares from one group should be identical
    check('shares are distinct within a group', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece');
      const shares = slip39.generateSync(secret, '', 3, 5, 0);
      const seen = new Set<string>();
      for (const s of shares) seen.add(s);
      return (
        seen.size === shares.length || `dupes (${seen.size}/${shares.length})`
      );
    }),
  ],
};
