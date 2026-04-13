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
  getPublic: (_priv: Uint8Array): Uint8Array => unsupported(),
  verifyPublic: (_pub: Uint8Array): boolean => unsupported(),
  sign: (
    _priv: Uint8Array,
    _digest: Uint8Array,
    _aux?: Uint8Array
  ): Uint8Array => unsupported(),
  verify: (_pub: Uint8Array, _sig: Uint8Array, _digest: Uint8Array): boolean =>
    unsupported(),
  tweakPublic: (_pub: Uint8Array, _merkleRoot?: Uint8Array): TweakedPublicKey =>
    unsupported(),
  tweakPrivate: (_priv: Uint8Array, _merkleRoot?: Uint8Array): Uint8Array =>
    unsupported(),
};
