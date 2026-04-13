import { raw, toArrayBuffer } from './buffer';

export interface Slip39Group {
  threshold: number;
  count: number;
}

export const slip39 = {
  /** Split a master secret into SLIP-39 mnemonic shares (single group). */
  generate(
    masterSecret: Uint8Array,
    passphrase: string = '',
    threshold: number,
    shareCount: number,
    iterationExponent: number = 1
  ): string[] {
    return raw.slip39_generate(
      toArrayBuffer(masterSecret),
      passphrase,
      threshold,
      shareCount,
      iterationExponent
    );
  },

  /** Split a master secret into multiple groups of shares. */
  generateGroups(
    masterSecret: Uint8Array,
    passphrase: string = '',
    groupThreshold: number,
    groups: Slip39Group[],
    iterationExponent: number = 1
  ): string[][] {
    const packed = new Uint8Array(groups.length * 2);
    for (let i = 0; i < groups.length; i++) {
      packed[i * 2] = groups[i]!.threshold;
      packed[i * 2 + 1] = groups[i]!.count;
    }
    return raw.slip39_generate_groups(
      toArrayBuffer(masterSecret),
      passphrase,
      groupThreshold,
      toArrayBuffer(packed),
      iterationExponent
    );
  },

  /** Recover the master secret from a set of mnemonic shares. */
  combine(mnemonics: string[], passphrase: string = ''): Uint8Array {
    return new Uint8Array(raw.slip39_combine(mnemonics.join('\n'), passphrase));
  },

  /** Validate a single SLIP-39 mnemonic (checksum + wordlist). */
  validateMnemonic(mnemonic: string): boolean {
    return raw.slip39_validate_mnemonic(mnemonic);
  },
};
