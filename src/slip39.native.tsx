import { raw, toArrayBuffer } from './buffer';
import { wrapNative, wrapNativeAsync } from './errors';

export interface Slip39Group {
  threshold: number;
  count: number;
}

// Pack `Slip39Group[]` into the [threshold, count, ...] uint8 byte format
// expected by the native side. Shared by sync + async wrappers.
function packGroups(groups: Slip39Group[]): Uint8Array {
  const packed = new Uint8Array(groups.length * 2);
  for (let i = 0; i < groups.length; i++) {
    packed[i * 2] = groups[i]!.threshold;
    packed[i * 2 + 1] = groups[i]!.count;
  }
  return packed;
}

export const slip39 = {
  /**
   * Split a 16..32-byte master secret into `shareCount` SLIP-39 mnemonics
   * with a `threshold`-of-`shareCount` recovery policy. Async — internal
   * PBKDF2 + Feistel rounds run on a worker thread so the JS thread stays
   * responsive (50-200ms+ on real devices).
   * @throws {CryptoError} on invalid parameters
   */
  generate: wrapNativeAsync(
    async (
      masterSecret: Uint8Array,
      passphrase: string = '',
      threshold: number,
      shareCount: number,
      iterationExponent: number = 1
    ): Promise<string[]> =>
      raw.slip39_generate_async(
        toArrayBuffer(masterSecret),
        passphrase,
        threshold,
        shareCount,
        iterationExponent
      )
  ),
  /** Synchronous variant of `generate`. Blocks the JS thread. */
  generateSync: wrapNative(
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
  /**
   * Multi-group SLIP-39: split master secret across `groups`, each group
   * having its own threshold-of-count member shares. Async — see notes
   * on `generate`.
   */
  generateGroups: wrapNativeAsync(
    async (
      masterSecret: Uint8Array,
      passphrase: string = '',
      groupThreshold: number,
      groups: Slip39Group[],
      iterationExponent: number = 1
    ): Promise<string[][]> =>
      raw.slip39_generate_groups_async(
        toArrayBuffer(masterSecret),
        passphrase,
        groupThreshold,
        toArrayBuffer(packGroups(groups)),
        iterationExponent
      )
  ),
  /** Synchronous variant of `generateGroups`. */
  generateGroupsSync: wrapNative(
    (
      masterSecret: Uint8Array,
      passphrase: string = '',
      groupThreshold: number,
      groups: Slip39Group[],
      iterationExponent: number = 1
    ): string[][] =>
      raw.slip39_generate_groups(
        toArrayBuffer(masterSecret),
        passphrase,
        groupThreshold,
        toArrayBuffer(packGroups(groups)),
        iterationExponent
      )
  ),
  /**
   * Recover the master secret from a sufficient set of SLIP-39 mnemonics
   * (group + member thresholds must be met). Async.
   */
  combine: wrapNativeAsync(
    async (mnemonics: string[], passphrase: string = ''): Promise<Uint8Array> =>
      new Uint8Array(
        await raw.slip39_combine_async(mnemonics.join('\n'), passphrase)
      )
  ),
  /** Synchronous variant of `combine`. */
  combineSync: wrapNative(
    (mnemonics: string[], passphrase: string = ''): Uint8Array =>
      new Uint8Array(raw.slip39_combine(mnemonics.join('\n'), passphrase))
  ),
  /** Validate mnemonic word list and RS1024 checksum. Sync — sub-ms. */
  validateMnemonic: wrapNative((mnemonic: string): boolean =>
    raw.slip39_validate_mnemonic(mnemonic)
  ),
};
