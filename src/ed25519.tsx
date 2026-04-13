const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export const ed25519 = {
  getPublic: (_priv: Uint8Array): Uint8Array => unsupported(),
  sign: (_priv: Uint8Array, _msg: Uint8Array): Uint8Array => unsupported(),
  verify: (_pub: Uint8Array, _sig: Uint8Array, _msg: Uint8Array): boolean =>
    unsupported(),
};

export const x25519 = {
  getPublic: (_priv: Uint8Array): Uint8Array => unsupported(),
  scalarmult: (_priv: Uint8Array, _pub: Uint8Array): Uint8Array =>
    unsupported(),
};
