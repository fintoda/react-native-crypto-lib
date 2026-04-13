const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export const mac = {
  hmac_sha256: (_key: Uint8Array, _msg: Uint8Array): Uint8Array =>
    unsupported(),
  hmac_sha512: (_key: Uint8Array, _msg: Uint8Array): Uint8Array =>
    unsupported(),
};
