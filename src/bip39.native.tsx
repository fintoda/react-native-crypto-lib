import { raw, toArrayBuffer } from './buffer';
import { wrapNative, wrapNativeAsync } from './errors';

export type Bip39Strength = 128 | 160 | 192 | 224 | 256;

export const bip39 = {
  generate: wrapNative((strength: Bip39Strength = 128): string =>
    raw.bip39_generate(strength)
  ),
  fromEntropy: wrapNative((entropy: Uint8Array): string =>
    raw.bip39_from_entropy(toArrayBuffer(entropy))
  ),
  validate: wrapNative((mnemonic: string): boolean =>
    raw.bip39_check(mnemonic)
  ),
  /**
   * Derive a 64-byte BIP-39 seed from a mnemonic + optional passphrase
   * (PBKDF2-HMAC-SHA512×2048). Async — runs on a worker thread.
   * Use `toSeedSync` if you need a synchronous return.
   */
  toSeed: wrapNativeAsync(
    async (mnemonic: string, passphrase: string = ''): Promise<Uint8Array> =>
      new Uint8Array(await raw.bip39_to_seed_async(mnemonic, passphrase))
  ),
  /** Synchronous variant of `toSeed`. Blocks the JS thread for ~10-50ms. */
  toSeedSync: wrapNative(
    (mnemonic: string, passphrase: string = ''): Uint8Array =>
      new Uint8Array(raw.bip39_to_seed(mnemonic, passphrase))
  ),
};
