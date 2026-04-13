const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export type TweakedPublicKey = {
  pub: Uint8Array;
  parity: 0 | 1;
};

export const schnorr = {
  /** Derives an x-only (32-byte) Schnorr public key from a private key. @param priv - 32-byte private key @returns 32-byte x-only public key @throws {CryptoError} on invalid key */
  getPublic: (_priv: Uint8Array): Uint8Array => unsupported(),
  /** Validates a 32-byte x-only public key. @param pub - 32-byte x-only public key @returns true if valid */
  verifyPublic: (_pub: Uint8Array): boolean => unsupported(),
  /** Creates a BIP-340 Schnorr signature. @param priv - 32-byte private key @param digest - 32-byte message hash @param aux - optional 32-byte auxiliary randomness @returns 64-byte Schnorr signature @throws {CryptoError} on invalid inputs */
  sign: (
    _priv: Uint8Array,
    _digest: Uint8Array,
    _aux?: Uint8Array
  ): Uint8Array => unsupported(),
  /** Verifies a BIP-340 Schnorr signature. @param pub - 32-byte x-only public key @param sig - 64-byte signature @param digest - 32-byte message hash @returns true if valid */
  verify: (_pub: Uint8Array, _sig: Uint8Array, _digest: Uint8Array): boolean =>
    unsupported(),
  /** Applies a taproot tweak to a public key. @param pub - 32-byte x-only public key @param merkleRoot - optional 32-byte merkle root @returns tweaked public key and output parity @throws {CryptoError} on tweak failure */
  tweakPublic: (_pub: Uint8Array, _merkleRoot?: Uint8Array): TweakedPublicKey =>
    unsupported(),
  /** Applies a taproot tweak to a private key. @param priv - 32-byte private key @param merkleRoot - optional 32-byte merkle root @returns 32-byte tweaked private key @throws {CryptoError} on tweak failure */
  tweakPrivate: (_priv: Uint8Array, _merkleRoot?: Uint8Array): Uint8Array =>
    unsupported(),
};
