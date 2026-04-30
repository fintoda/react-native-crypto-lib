const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export const kdf = {
  /**
   * Derives a key using PBKDF2 with HMAC-SHA256 (async, runs on a worker
   * thread on native).
   * @throws {CryptoError} on invalid parameters
   */
  pbkdf2_sha256: (
    _password: Uint8Array,
    _salt: Uint8Array,
    _iterations: number,
    _length: number
  ): Promise<Uint8Array> => unsupported(),
  /** Synchronous PBKDF2-HMAC-SHA256 (blocks the JS thread on native). */
  pbkdf2_sha256Sync: (
    _password: Uint8Array,
    _salt: Uint8Array,
    _iterations: number,
    _length: number
  ): Uint8Array => unsupported(),
  /**
   * Derives a key using PBKDF2 with HMAC-SHA512 (async).
   */
  pbkdf2_sha512: (
    _password: Uint8Array,
    _salt: Uint8Array,
    _iterations: number,
    _length: number
  ): Promise<Uint8Array> => unsupported(),
  /** Synchronous PBKDF2-HMAC-SHA512. */
  pbkdf2_sha512Sync: (
    _password: Uint8Array,
    _salt: Uint8Array,
    _iterations: number,
    _length: number
  ): Uint8Array => unsupported(),
  /**
   * Derives a key using HKDF with SHA-256 (RFC 5869).
   */
  hkdf_sha256: (
    _ikm: Uint8Array,
    _salt: Uint8Array,
    _info: Uint8Array,
    _length: number
  ): Uint8Array => unsupported(),
  /**
   * Derives a key using HKDF with SHA-512 (RFC 5869).
   */
  hkdf_sha512: (
    _ikm: Uint8Array,
    _salt: Uint8Array,
    _info: Uint8Array,
    _length: number
  ): Uint8Array => unsupported(),
};
