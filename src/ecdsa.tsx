const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export type Curve = 'secp256k1' | 'nist256p1';

export type EcdsaSignature = {
  signature: Uint8Array;
  recId: number;
};

export const ecdsa = {
  /** Generates a random valid private key. @param curve - elliptic curve (default secp256k1) @returns 32-byte private key */
  randomPrivate: (_curve?: Curve): Uint8Array => unsupported(),
  /** Checks whether a 32-byte buffer is a valid private key for the given curve. @param priv - private key candidate @param curve - elliptic curve (default secp256k1) @returns true if valid */
  validatePrivate: (_priv: Uint8Array, _curve?: Curve): boolean =>
    unsupported(),
  /** Derives the public key from a private key. @param priv - 32-byte private key @param compact - return 33-byte compressed (default) or 65-byte uncompressed @param curve - elliptic curve (default secp256k1) @returns public key @throws {CryptoError} on invalid private key */
  getPublic: (
    _priv: Uint8Array,
    _compact?: boolean,
    _curve?: Curve
  ): Uint8Array => unsupported(),
  /** Converts between compressed and uncompressed public key formats. @param pub - input public key (33 or 65 bytes) @param compact - output format @param curve - elliptic curve (default secp256k1) @returns re-encoded public key @throws {CryptoError} on invalid public key */
  readPublic: (
    _pub: Uint8Array,
    _compact?: boolean,
    _curve?: Curve
  ): Uint8Array => unsupported(),
  /** Validates a public key. @param pub - public key (33 or 65 bytes) @param curve - elliptic curve (default secp256k1) @returns true if the point is on the curve */
  validatePublic: (_pub: Uint8Array, _curve?: Curve): boolean => unsupported(),
  /** Signs a 32-byte digest using deterministic ECDSA (RFC 6979). @param priv - 32-byte private key @param digest - 32-byte message hash @param curve - elliptic curve (default secp256k1) @returns signature (64 bytes, low-S) and recovery id @throws {CryptoError} on invalid inputs */
  sign: (
    _priv: Uint8Array,
    _digest: Uint8Array,
    _curve?: Curve
  ): EcdsaSignature => unsupported(),
  /** Verifies an ECDSA signature. @param pub - signer's public key @param sig - 64-byte signature @param digest - 32-byte message hash @param curve - elliptic curve (default secp256k1) @returns true if the signature is valid */
  verify: (
    _pub: Uint8Array,
    _sig: Uint8Array,
    _digest: Uint8Array,
    _curve?: Curve
  ): boolean => unsupported(),
  /** Recovers the public key from a signature and recovery id. @param sig - 64-byte signature @param digest - 32-byte message hash @param recId - recovery id (0-3) @param curve - elliptic curve (default secp256k1) @returns 65-byte uncompressed public key @throws {CryptoError} on recovery failure */
  recover: (
    _sig: Uint8Array,
    _digest: Uint8Array,
    _recId: number,
    _curve?: Curve
  ): Uint8Array => unsupported(),
  /** Computes an ECDH shared secret. @param priv - 32-byte private key @param pub - counterparty's public key @param curve - elliptic curve (default secp256k1) @returns 32-byte shared secret @throws {CryptoError} on invalid inputs */
  ecdh: (_priv: Uint8Array, _pub: Uint8Array, _curve?: Curve): Uint8Array =>
    unsupported(),
  /** Encodes a 64-byte compact signature to DER format. @param sig - 64-byte compact signature @returns DER-encoded signature @throws {CryptoError} on invalid signature */
  sigToDer: (_sig: Uint8Array): Uint8Array => unsupported(),
  /** Decodes a DER-encoded signature to 64-byte compact format. @param der - DER-encoded signature @returns 64-byte compact signature @throws {CryptoError} on invalid DER */
  sigFromDer: (_der: Uint8Array): Uint8Array => unsupported(),
};
