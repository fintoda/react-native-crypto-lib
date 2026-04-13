const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export interface Slip39Group {
  threshold: number;
  count: number;
}

export const slip39 = {
  generate: (
    _masterSecret: Uint8Array,
    _passphrase: string = '',
    _threshold: number,
    _shareCount: number,
    _iterationExponent: number = 1
  ): string[] => unsupported(),
  generateGroups: (
    _masterSecret: Uint8Array,
    _passphrase: string = '',
    _groupThreshold: number,
    _groups: Slip39Group[],
    _iterationExponent: number = 1
  ): string[][] => unsupported(),
  combine: (_mnemonics: string[], _passphrase: string = ''): Uint8Array =>
    unsupported(),
  validateMnemonic: (_mnemonic: string): boolean => unsupported(),
};
