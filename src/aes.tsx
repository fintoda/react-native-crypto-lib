const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export type CbcPadding = 'pkcs7' | 'none';

export const aes = {
  cbc: {
    /** Encrypts data with AES-256-CBC. @param key - 32-byte key @param iv - 16-byte initialization vector @param data - plaintext @param padding - 'pkcs7' (default) or 'none' @returns ciphertext @throws {CryptoError} on invalid key/IV size */
    encrypt: (
      _key: Uint8Array,
      _iv: Uint8Array,
      _data: Uint8Array,
      _padding?: CbcPadding
    ): Uint8Array => unsupported(),
    /** Decrypts AES-256-CBC ciphertext. @param key - 32-byte key @param iv - 16-byte initialization vector @param data - ciphertext @param padding - 'pkcs7' (default) or 'none' @returns plaintext @throws {CryptoError} on invalid key/IV size or padding error */
    decrypt: (
      _key: Uint8Array,
      _iv: Uint8Array,
      _data: Uint8Array,
      _padding?: CbcPadding
    ): Uint8Array => unsupported(),
  },
  ctr: {
    /** Encrypts or decrypts with AES-256-CTR (symmetric operation). @param key - 32-byte key @param iv - 16-byte nonce/counter @param data - input data @returns output data @throws {CryptoError} on invalid key/IV size */
    crypt: (_key: Uint8Array, _iv: Uint8Array, _data: Uint8Array): Uint8Array =>
      unsupported(),
  },
  gcm: {
    /** Encrypts with AES-256-GCM. Output is ciphertext + 16-byte tag. @param key - 32-byte key @param nonce - 12-byte nonce @param plaintext - data to encrypt @param aad - optional additional authenticated data @returns ciphertext || tag @throws {CryptoError} on invalid key/nonce size */
    encrypt: (
      _key: Uint8Array,
      _nonce: Uint8Array,
      _plaintext: Uint8Array,
      _aad?: Uint8Array
    ): Uint8Array => unsupported(),
    /** Decrypts AES-256-GCM. Input is ciphertext + 16-byte tag. @param key - 32-byte key @param nonce - 12-byte nonce @param sealed - ciphertext || tag @param aad - optional additional authenticated data @returns plaintext @throws {CryptoError} on authentication failure or invalid sizes */
    decrypt: (
      _key: Uint8Array,
      _nonce: Uint8Array,
      _sealed: Uint8Array,
      _aad?: Uint8Array
    ): Uint8Array => unsupported(),
  },
};
