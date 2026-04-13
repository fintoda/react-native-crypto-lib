const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export const kdf = {
  /**
   * Derives a key using PBKDF2 with HMAC-SHA256.
   * @param password - input password
   * @param salt - random salt
   * @param iterations - round count (min 1)
   * @param length - desired output length in bytes
   * @returns derived key
   * @throws {CryptoError} on invalid parameters
   */
  pbkdf2_sha256: (
    _password: Uint8Array,
    _salt: Uint8Array,
    _iterations: number,
    _length: number
  ): Uint8Array => unsupported(),
  /**
   * Derives a key using PBKDF2 with HMAC-SHA512.
   * @param password - input password
   * @param salt - random salt
   * @param iterations - round count (min 1)
   * @param length - desired output length in bytes
   * @returns derived key
   * @throws {CryptoError} on invalid parameters
   */
  pbkdf2_sha512: (
    _password: Uint8Array,
    _salt: Uint8Array,
    _iterations: number,
    _length: number
  ): Uint8Array => unsupported(),
  /**
   * Derives a key using HKDF with SHA-256 (RFC 5869).
   * @param ikm - input keying material
   * @param salt - optional salt
   * @param info - context/application info
   * @param length - desired output length in bytes
   * @returns derived key
   * @throws {CryptoError} on invalid parameters
   */
  hkdf_sha256: (
    _ikm: Uint8Array,
    _salt: Uint8Array,
    _info: Uint8Array,
    _length: number
  ): Uint8Array => unsupported(),
  /**
   * Derives a key using HKDF with SHA-512 (RFC 5869).
   * @param ikm - input keying material
   * @param salt - optional salt
   * @param info - context/application info
   * @param length - desired output length in bytes
   * @returns derived key
   * @throws {CryptoError} on invalid parameters
   */
  hkdf_sha512: (
    _ikm: Uint8Array,
    _salt: Uint8Array,
    _info: Uint8Array,
    _length: number
  ): Uint8Array => unsupported(),
};
