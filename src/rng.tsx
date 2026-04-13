const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export const rng = {
  /**
   * Generates cryptographically secure random bytes.
   * @param count - number of bytes (max 1 MiB)
   * @returns random bytes
   * @throws {CryptoError} if count exceeds limit
   */
  bytes: (_count: number): Uint8Array => unsupported(),
  /** Returns a cryptographically secure random 32-bit unsigned integer. @returns random uint32 */
  uint32: (): number => unsupported(),
  /**
   * Returns a uniform random integer in [0, max) without modulo bias.
   * @param max - exclusive upper bound, integer in [1, 2^32]
   * @returns random integer in [0, max)
   * @throws {RangeError} if max is out of range
   */
  uniform: (_max: number): number => unsupported(),
};
