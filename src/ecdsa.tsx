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
  randomPrivate: (_curve?: Curve): Uint8Array => unsupported(),
  validatePrivate: (_priv: Uint8Array, _curve?: Curve): boolean =>
    unsupported(),
  getPublic: (
    _priv: Uint8Array,
    _compact?: boolean,
    _curve?: Curve
  ): Uint8Array => unsupported(),
  readPublic: (
    _pub: Uint8Array,
    _compact?: boolean,
    _curve?: Curve
  ): Uint8Array => unsupported(),
  validatePublic: (_pub: Uint8Array, _curve?: Curve): boolean => unsupported(),
  sign: (
    _priv: Uint8Array,
    _digest: Uint8Array,
    _curve?: Curve
  ): EcdsaSignature => unsupported(),
  verify: (
    _pub: Uint8Array,
    _sig: Uint8Array,
    _digest: Uint8Array,
    _curve?: Curve
  ): boolean => unsupported(),
  recover: (
    _sig: Uint8Array,
    _digest: Uint8Array,
    _recId: number,
    _curve?: Curve
  ): Uint8Array => unsupported(),
  ecdh: (_priv: Uint8Array, _pub: Uint8Array, _curve?: Curve): Uint8Array =>
    unsupported(),
  sigToDer: (_sig: Uint8Array): Uint8Array => unsupported(),
  sigFromDer: (_der: Uint8Array): Uint8Array => unsupported(),
};
