import { raw, toArrayBuffer } from './buffer';
import { wrapNative } from './errors';

export type CbcPadding = 'pkcs7' | 'none';

function toOptionalAB(data?: Uint8Array): ArrayBuffer | null {
  return data ? toArrayBuffer(data) : null;
}

export const aes = {
  cbc: {
    /** Encrypts data with AES-256-CBC. @param key - 32-byte key @param iv - 16-byte initialization vector @param data - plaintext @param padding - 'pkcs7' (default) or 'none' @returns ciphertext @throws {CryptoError} on invalid key/IV size */
    encrypt: wrapNative(
      (
        key: Uint8Array,
        iv: Uint8Array,
        data: Uint8Array,
        padding: CbcPadding = 'pkcs7'
      ): Uint8Array =>
        new Uint8Array(
          raw.aes_256_cbc_encrypt(
            toArrayBuffer(key),
            toArrayBuffer(iv),
            toArrayBuffer(data),
            padding
          )
        )
    ),
    /** Decrypts AES-256-CBC ciphertext. @param key - 32-byte key @param iv - 16-byte initialization vector @param data - ciphertext @param padding - 'pkcs7' (default) or 'none' @returns plaintext @throws {CryptoError} on invalid key/IV size or padding error */
    decrypt: wrapNative(
      (
        key: Uint8Array,
        iv: Uint8Array,
        data: Uint8Array,
        padding: CbcPadding = 'pkcs7'
      ): Uint8Array =>
        new Uint8Array(
          raw.aes_256_cbc_decrypt(
            toArrayBuffer(key),
            toArrayBuffer(iv),
            toArrayBuffer(data),
            padding
          )
        )
    ),
  },
  ctr: {
    /** Encrypts or decrypts with AES-256-CTR (symmetric operation). @param key - 32-byte key @param iv - 16-byte nonce/counter @param data - input data @returns output data @throws {CryptoError} on invalid key/IV size */
    crypt: wrapNative(
      (key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array =>
        new Uint8Array(
          raw.aes_256_ctr_crypt(
            toArrayBuffer(key),
            toArrayBuffer(iv),
            toArrayBuffer(data)
          )
        )
    ),
  },
  gcm: {
    /** Encrypts with AES-256-GCM. Output is ciphertext + 16-byte tag. @param key - 32-byte key @param nonce - 12-byte nonce @param plaintext - data to encrypt @param aad - optional additional authenticated data @returns ciphertext || tag @throws {CryptoError} on invalid key/nonce size */
    encrypt: wrapNative(
      (
        key: Uint8Array,
        nonce: Uint8Array,
        plaintext: Uint8Array,
        aad?: Uint8Array
      ): Uint8Array =>
        new Uint8Array(
          raw.aes_256_gcm_encrypt(
            toArrayBuffer(key),
            toArrayBuffer(nonce),
            toArrayBuffer(plaintext),
            toOptionalAB(aad)
          )
        )
    ),
    /** Decrypts AES-256-GCM. Input is ciphertext + 16-byte tag. @param key - 32-byte key @param nonce - 12-byte nonce @param sealed - ciphertext || tag @param aad - optional additional authenticated data @returns plaintext @throws {CryptoError} on authentication failure or invalid sizes */
    decrypt: wrapNative(
      (
        key: Uint8Array,
        nonce: Uint8Array,
        sealed: Uint8Array,
        aad?: Uint8Array
      ): Uint8Array =>
        new Uint8Array(
          raw.aes_256_gcm_decrypt(
            toArrayBuffer(key),
            toArrayBuffer(nonce),
            toArrayBuffer(sealed),
            toOptionalAB(aad)
          )
        )
    ),
  },
};
