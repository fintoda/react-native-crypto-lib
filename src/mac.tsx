const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export const mac = {
  /**
   * Computes HMAC-SHA256.
   * @param key - HMAC key
   * @param msg - message to authenticate
   * @returns 32-byte MAC
   * @throws {CryptoError} if key exceeds 64 bytes
   */
  hmac_sha256: (_key: Uint8Array, _msg: Uint8Array): Uint8Array =>
    unsupported(),
  /**
   * Computes HMAC-SHA512.
   * @param key - HMAC key
   * @param msg - message to authenticate
   * @returns 64-byte MAC
   * @throws {CryptoError} if key exceeds 128 bytes
   */
  hmac_sha512: (_key: Uint8Array, _msg: Uint8Array): Uint8Array =>
    unsupported(),
};
