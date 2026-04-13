import { raw, toArrayBuffer } from './buffer';
import { wrapNative } from './errors';

export const mac = {
  /**
   * Computes HMAC-SHA256.
   * @param key - HMAC key
   * @param msg - message to authenticate
   * @returns 32-byte MAC
   * @throws {CryptoError} if key exceeds 64 bytes
   */
  hmac_sha256: wrapNative(
    (key: Uint8Array, msg: Uint8Array): Uint8Array =>
      new Uint8Array(
        raw.mac_hmac_sha256(toArrayBuffer(key), toArrayBuffer(msg))
      )
  ),
  /**
   * Computes HMAC-SHA512.
   * @param key - HMAC key
   * @param msg - message to authenticate
   * @returns 64-byte MAC
   * @throws {CryptoError} if key exceeds 128 bytes
   */
  hmac_sha512: wrapNative(
    (key: Uint8Array, msg: Uint8Array): Uint8Array =>
      new Uint8Array(
        raw.mac_hmac_sha512(toArrayBuffer(key), toArrayBuffer(msg))
      )
  ),
};
