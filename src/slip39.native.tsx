import { raw, toArrayBuffer } from './buffer';
import { wrapNative } from './errors';

export interface Slip39Group {
  threshold: number;
  count: number;
}

export const slip39 = {
  generate: wrapNative(
    (
      masterSecret: Uint8Array,
      passphrase: string = '',
      threshold: number,
      shareCount: number,
      iterationExponent: number = 1
    ): string[] =>
      raw.slip39_generate(
        toArrayBuffer(masterSecret),
        passphrase,
        threshold,
        shareCount,
        iterationExponent
      )
  ),

  generateGroups: wrapNative(
    (
      masterSecret: Uint8Array,
      passphrase: string = '',
      groupThreshold: number,
      groups: Slip39Group[],
      iterationExponent: number = 1
    ): string[][] => {
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
    }
  ),

  combine: wrapNative(
    (mnemonics: string[], passphrase: string = ''): Uint8Array =>
      new Uint8Array(raw.slip39_combine(mnemonics.join('\n'), passphrase))
  ),

  validateMnemonic: wrapNative((mnemonic: string): boolean =>
    raw.slip39_validate_mnemonic(mnemonic)
  ),
};
