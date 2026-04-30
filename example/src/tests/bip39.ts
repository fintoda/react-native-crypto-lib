// BIP-39 mnemonic generation, validation, seed derivation.

import { bip39 } from '@fintoda/react-native-crypto-lib';
import { check, eq, hexCheck, throws, type TestGroup } from './harness';

export const bip39Group: TestGroup = {
  id: 'bip39',
  title: 'bip39',
  description: 'mnemonic generation, validation, PBKDF2 seed derivation',
  build: () => {
    const allZeros16 = new Uint8Array(16);
    const allZeros32 = new Uint8Array(32);
    const expectedMnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const expectedSeedEmpty =
      '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4';
    const expectedSeedTrezor =
      'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04';

    return [
      // Canonical fixture
      check(
        'fromEntropy(16 zeros) == "abandon ... about"',
        () => bip39.fromEntropy(allZeros16) === expectedMnemonic
      ),
      check('validate(canonical) true', () => bip39.validate(expectedMnemonic)),
      check(
        'validate(garbage) false',
        () => !bip39.validate('abandon abandon abandon')
      ),
      check('validate(swapped checksum) false', () => {
        // Replace last word with a valid wordlist entry — checksum fails.
        const words = expectedMnemonic.split(' ');
        words[words.length - 1] = 'ability';
        return !bip39.validate(words.join(' '));
      }),

      hexCheck(
        'toSeedSync(canonical, "")',
        bip39.toSeedSync(expectedMnemonic, ''),
        expectedSeedEmpty
      ),
      hexCheck(
        'toSeedSync(canonical, "TREZOR")',
        bip39.toSeedSync(expectedMnemonic, 'TREZOR'),
        expectedSeedTrezor
      ),
      check('toSeedSync passphrase matters', () => {
        const a = bip39.toSeedSync(expectedMnemonic, '');
        const b = bip39.toSeedSync(expectedMnemonic, 'TREZOR');
        return !eq(a, b);
      }),
      check(
        'toSeedSync output length 64',
        () => bip39.toSeedSync(expectedMnemonic, '').length === 64
      ),

      // generate(strength)
      check(
        'generate(128) -> 12 words',
        () => bip39.generate(128).split(' ').length === 12
      ),
      check(
        'generate(160) -> 15 words',
        () => bip39.generate(160).split(' ').length === 15
      ),
      check(
        'generate(192) -> 18 words',
        () => bip39.generate(192).split(' ').length === 18
      ),
      check(
        'generate(224) -> 21 words',
        () => bip39.generate(224).split(' ').length === 21
      ),
      check(
        'generate(256) -> 24 words',
        () => bip39.generate(256).split(' ').length === 24
      ),
      check('generate validates own output', () =>
        bip39.validate(bip39.generate())
      ),

      // fromEntropy strength variations
      check(
        'fromEntropy(32 zeros) -> 24 words',
        () => bip39.fromEntropy(allZeros32).split(' ').length === 24
      ),

      // Bad inputs
      throws('fromEntropy(15 bytes) throws', () =>
        bip39.fromEntropy(new Uint8Array(15))
      ),
      throws('fromEntropy(33 bytes) throws', () =>
        bip39.fromEntropy(new Uint8Array(33))
      ),
    ];
  },
};
