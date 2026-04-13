import { raw, toArrayBuffer } from './buffer';
import { wrapNative } from './errors';

export const kdf = {
  /**
   * Derives a key using PBKDF2 with HMAC-SHA256.
   * @param password - input password
   * @param salt - random salt
   * @param iterations - round count (min 1)
   * @param length - desired output length in bytes
   * @returns derived key
   * @throws {CryptoError} on invalid parameters
   */
  pbkdf2_sha256: wrapNative(
    (
      password: Uint8Array,
      salt: Uint8Array,
      iterations: number,
      length: number
    ): Uint8Array =>
      new Uint8Array(
        raw.kdf_pbkdf2_sha256(
          toArrayBuffer(password),
          toArrayBuffer(salt),
          iterations,
          length
        )
      )
  ),
  /**
   * Derives a key using PBKDF2 with HMAC-SHA512.
   * @param password - input password
   * @param salt - random salt
   * @param iterations - round count (min 1)
   * @param length - desired output length in bytes
   * @returns derived key
   * @throws {CryptoError} on invalid parameters
   */
  pbkdf2_sha512: wrapNative(
    (
      password: Uint8Array,
      salt: Uint8Array,
      iterations: number,
      length: number
    ): Uint8Array =>
      new Uint8Array(
        raw.kdf_pbkdf2_sha512(
          toArrayBuffer(password),
          toArrayBuffer(salt),
          iterations,
          length
        )
      )
  ),
  /**
   * Derives a key using HKDF with SHA-256 (RFC 5869).
   * @param ikm - input keying material
   * @param salt - optional salt
   * @param info - context/application info
   * @param length - desired output length in bytes
   * @returns derived key
   * @throws {CryptoError} on invalid parameters
   */
  hkdf_sha256: wrapNative(
    (
      ikm: Uint8Array,
      salt: Uint8Array,
      info: Uint8Array,
      length: number
    ): Uint8Array =>
      new Uint8Array(
        raw.kdf_hkdf_sha256(
          toArrayBuffer(ikm),
          toArrayBuffer(salt),
          toArrayBuffer(info),
          length
        )
      )
  ),
  /**
   * Derives a key using HKDF with SHA-512 (RFC 5869).
   * @param ikm - input keying material
   * @param salt - optional salt
   * @param info - context/application info
   * @param length - desired output length in bytes
   * @returns derived key
   * @throws {CryptoError} on invalid parameters
   */
  hkdf_sha512: wrapNative(
    (
      ikm: Uint8Array,
      salt: Uint8Array,
      info: Uint8Array,
      length: number
    ): Uint8Array =>
      new Uint8Array(
        raw.kdf_hkdf_sha512(
          toArrayBuffer(ikm),
          toArrayBuffer(salt),
          toArrayBuffer(info),
          length
        )
      )
  ),
};
