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
  pointAdd: (
    _a: Uint8Array,
    _b: Uint8Array,
    _compressed?: boolean
  ): Uint8Array | null => unsupported(),
  pointAddScalar: (
    _p: Uint8Array,
    _tweak: Uint8Array,
    _compressed?: boolean
  ): Uint8Array | null => unsupported(),
  pointMultiply: (
    _p: Uint8Array,
    _tweak: Uint8Array,
    _compressed?: boolean
  ): Uint8Array | null => unsupported(),
  privateAdd: (_d: Uint8Array, _tweak: Uint8Array): Uint8Array | null =>
    unsupported(),
  privateSub: (_d: Uint8Array, _tweak: Uint8Array): Uint8Array | null =>
    unsupported(),
  privateNegate: (_d: Uint8Array): Uint8Array => unsupported(),
  xOnlyPointAddTweak: (
    _p: Uint8Array,
    _tweak: Uint8Array
  ): XOnlyTweakResult | null => unsupported(),
};
