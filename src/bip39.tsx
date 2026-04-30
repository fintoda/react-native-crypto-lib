const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export type Bip39Strength = 128 | 160 | 192 | 224 | 256;

export const bip39 = {
  generate: (_strength?: Bip39Strength): string => unsupported(),
  fromEntropy: (_entropy: Uint8Array): string => unsupported(),
  validate: (_mnemonic: string): boolean => unsupported(),
  toSeed: (_mnemonic: string, _passphrase?: string): Promise<Uint8Array> =>
    unsupported(),
  toSeedSync: (_mnemonic: string, _passphrase?: string): Uint8Array =>
    unsupported(),
};
