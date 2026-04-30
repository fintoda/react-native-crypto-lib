import { raw, toArrayBuffer } from './buffer';
import { wrapNative, wrapNativeAsync } from './errors';

export const kdf = {
  /**
   * Derives a key using PBKDF2 with HMAC-SHA256.
   *
   * Async — runs on a worker thread so the JS thread stays responsive.
   * Iteration counts of 100k+ otherwise drop frames on real devices.
   * Use `pbkdf2_sha256Sync` if you need a synchronous return (e.g. inside
   * a tight C++ loop or non-UI worker).
   *
   * @param password - input password
   * @param salt - random salt
   * @param iterations - round count (min 1)
   * @param length - desired output length in bytes
   * @returns derived key
   * @throws {CryptoError} on invalid parameters
   */
  pbkdf2_sha256: wrapNativeAsync(
    async (
      password: Uint8Array,
      salt: Uint8Array,
      iterations: number,
      length: number
    ): Promise<Uint8Array> =>
      new Uint8Array(
        await raw.kdf_pbkdf2_sha256_async(
          toArrayBuffer(password),
          toArrayBuffer(salt),
          iterations,
          length
        )
      )
  ),
  /**
   * Synchronous PBKDF2-HMAC-SHA256. Blocks the JS thread for the duration
   * of the derivation; prefer `pbkdf2_sha256` for large iteration counts.
   */
  pbkdf2_sha256Sync: wrapNative(
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
   * Derives a key using PBKDF2 with HMAC-SHA512. Async — see notes on
   * `pbkdf2_sha256`.
   */
  pbkdf2_sha512: wrapNativeAsync(
    async (
      password: Uint8Array,
      salt: Uint8Array,
      iterations: number,
      length: number
    ): Promise<Uint8Array> =>
      new Uint8Array(
        await raw.kdf_pbkdf2_sha512_async(
          toArrayBuffer(password),
          toArrayBuffer(salt),
          iterations,
          length
        )
      )
  ),
  /** Synchronous PBKDF2-HMAC-SHA512. See `pbkdf2_sha256Sync`. */
  pbkdf2_sha512Sync: wrapNative(
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
   * Derives a key using HKDF with SHA-256 (RFC 5869). Sync — HKDF is
   * fast (sub-ms even at the 255*HashLen output cap), so async dispatch
   * would be pure overhead.
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
  /** Derives a key using HKDF with SHA-512 (RFC 5869). Sync — see `hkdf_sha256`. */
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
