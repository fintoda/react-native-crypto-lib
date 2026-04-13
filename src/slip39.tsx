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
  /** Split a master secret into SLIP-39 mnemonic shares (single group). */
  generate: (
    _masterSecret: Uint8Array,
    _passphrase: string = '',
    _threshold: number,
    _shareCount: number,
    _iterationExponent: number = 1
  ): string[] => unsupported(),
  /** Split a master secret into multiple groups of shares. */
  generateGroups: (
    _masterSecret: Uint8Array,
    _passphrase: string = '',
    _groupThreshold: number,
    _groups: Slip39Group[],
    _iterationExponent: number = 1
  ): string[][] => unsupported(),
  /** Recover the master secret from a set of mnemonic shares. */
  combine: (_mnemonics: string[], _passphrase: string = ''): Uint8Array =>
    unsupported(),
  /** Validate a single SLIP-39 mnemonic (checksum + wordlist). */
  validateMnemonic: (_mnemonic: string): boolean => unsupported(),
};
