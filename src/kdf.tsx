const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export const kdf = {
  pbkdf2_sha256: (
    _password: Uint8Array,
    _salt: Uint8Array,
    _iterations: number,
    _length: number
  ): Uint8Array => unsupported(),
  pbkdf2_sha512: (
    _password: Uint8Array,
    _salt: Uint8Array,
    _iterations: number,
    _length: number
  ): Uint8Array => unsupported(),
  hkdf_sha256: (
    _ikm: Uint8Array,
    _salt: Uint8Array,
    _info: Uint8Array,
    _length: number
  ): Uint8Array => unsupported(),
  hkdf_sha512: (
    _ikm: Uint8Array,
    _salt: Uint8Array,
    _info: Uint8Array,
    _length: number
  ): Uint8Array => unsupported(),
};
