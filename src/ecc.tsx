const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export type XOnlyTweakResult = {
  parity: 0 | 1;
  xOnlyPubkey: Uint8Array;
};

export const ecc = {
  /** Adds two elliptic curve points (secp256k1). @param a - first point (33 or 65 bytes) @param b - second point (33 or 65 bytes) @param compressed - output format (default true) @returns resulting point, or null if result is point at infinity */
  pointAdd: (
    _a: Uint8Array,
    _b: Uint8Array,
    _compressed?: boolean
  ): Uint8Array | null => unsupported(),
  /** Adds a scalar tweak to a point. @param p - point (33 or 65 bytes) @param tweak - 32-byte scalar @param compressed - output format (default true) @returns tweaked point, or null if result is invalid */
  pointAddScalar: (
    _p: Uint8Array,
    _tweak: Uint8Array,
    _compressed?: boolean
  ): Uint8Array | null => unsupported(),
  /** Multiplies a point by a scalar. @param p - point (33 or 65 bytes) @param tweak - 32-byte scalar @param compressed - output format (default true) @returns resulting point, or null if result is invalid */
  pointMultiply: (
    _p: Uint8Array,
    _tweak: Uint8Array,
    _compressed?: boolean
  ): Uint8Array | null => unsupported(),
  /** Adds two private keys (mod curve order). @param d - 32-byte private key @param tweak - 32-byte tweak @returns resulting key, or null if out of range */
  privateAdd: (_d: Uint8Array, _tweak: Uint8Array): Uint8Array | null =>
    unsupported(),
  /** Subtracts a tweak from a private key (mod curve order). @param d - 32-byte private key @param tweak - 32-byte tweak @returns resulting key, or null if out of range */
  privateSub: (_d: Uint8Array, _tweak: Uint8Array): Uint8Array | null =>
    unsupported(),
  /** Negates a private key (mod curve order). @param d - 32-byte private key @returns negated key */
  privateNegate: (_d: Uint8Array): Uint8Array => unsupported(),
  /** Adds a scalar tweak to an x-only point (BIP-340). @param p - 32-byte x-only public key @param tweak - 32-byte scalar @returns tweaked x-only key and parity, or null if invalid */
  xOnlyPointAddTweak: (
    _p: Uint8Array,
    _tweak: Uint8Array
  ): XOnlyTweakResult | null => unsupported(),
};
