import { raw, toArrayBuffer } from './buffer';
import { wrapNative } from './errors';

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
  toSeed: wrapNative(
    (mnemonic: string, passphrase: string = ''): Uint8Array =>
      new Uint8Array(raw.bip39_to_seed(mnemonic, passphrase))
  ),
};
