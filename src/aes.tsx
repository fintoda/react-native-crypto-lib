const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export type CbcPadding = 'pkcs7' | 'none';

export const aes = {
  cbc: {
    encrypt: (
      _key: Uint8Array,
      _iv: Uint8Array,
      _data: Uint8Array,
      _padding?: CbcPadding
    ): Uint8Array => unsupported(),
    decrypt: (
      _key: Uint8Array,
      _iv: Uint8Array,
      _data: Uint8Array,
      _padding?: CbcPadding
    ): Uint8Array => unsupported(),
  },
  ctr: {
    crypt: (_key: Uint8Array, _iv: Uint8Array, _data: Uint8Array): Uint8Array =>
      unsupported(),
  },
  gcm: {
    encrypt: (
      _key: Uint8Array,
      _nonce: Uint8Array,
      _plaintext: Uint8Array,
      _aad?: Uint8Array
    ): Uint8Array => unsupported(),
    decrypt: (
      _key: Uint8Array,
      _nonce: Uint8Array,
      _sealed: Uint8Array,
      _aad?: Uint8Array
    ): Uint8Array => unsupported(),
  },
};
