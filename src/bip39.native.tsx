import ReactNativeCryptoLib, {
  type RawSpec,
} from './NativeReactNativeCryptoLib';

const raw = ReactNativeCryptoLib as unknown as RawSpec;

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  return data.byteOffset === 0 && data.byteLength === data.buffer.byteLength
    ? (data.buffer as ArrayBuffer)
    : (data.slice().buffer as ArrayBuffer);
}

export type Bip39Strength = 128 | 160 | 192 | 224 | 256;

export const bip39 = {
  /** Returns an English BIP-39 mnemonic for the given entropy strength. */
  generate(strength: Bip39Strength = 128): string {
    return raw.bip39_generate(strength);
  },
  /** Builds a mnemonic from caller-provided entropy (16/20/24/28/32 bytes). */
  fromEntropy(entropy: Uint8Array): string {
    return raw.bip39_from_entropy(toArrayBuffer(entropy));
  },
  /** BIP-39 checksum + wordlist validation. */
  validate(mnemonic: string): boolean {
    return raw.bip39_check(mnemonic);
  },
  /** PBKDF2-HMAC-SHA512, 2048 rounds. Returns a 64-byte seed. */
  toSeed(mnemonic: string, passphrase: string = ''): Uint8Array {
    return new Uint8Array(raw.bip39_to_seed(mnemonic, passphrase));
  },
};
