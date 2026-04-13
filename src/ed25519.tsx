const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export const ed25519 = {
  /** Derives an Ed25519 public key. @param priv - 32-byte private key @returns 32-byte public key @throws {CryptoError} on invalid key */
  getPublic: (_priv: Uint8Array): Uint8Array => unsupported(),
  /** Signs a message with Ed25519 (RFC 8032). @param priv - 32-byte private key @param msg - arbitrary-length message @returns 64-byte signature @throws {CryptoError} on invalid key */
  sign: (_priv: Uint8Array, _msg: Uint8Array): Uint8Array => unsupported(),
  /** Verifies an Ed25519 signature. @param pub - 32-byte public key @param sig - 64-byte signature @param msg - original message @returns true if valid */
  verify: (_pub: Uint8Array, _sig: Uint8Array, _msg: Uint8Array): boolean =>
    unsupported(),
};

export const x25519 = {
  /** Derives an X25519 public key. @param priv - 32-byte private key @returns 32-byte public key */
  getPublic: (_priv: Uint8Array): Uint8Array => unsupported(),
  /** Performs X25519 Diffie-Hellman. @param priv - 32-byte private key @param pub - counterparty's 32-byte public key @returns 32-byte shared secret @throws {CryptoError} on invalid inputs */
  scalarmult: (_priv: Uint8Array, _pub: Uint8Array): Uint8Array =>
    unsupported(),
};
