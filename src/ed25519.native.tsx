import { raw, toArrayBuffer } from './buffer';
import { wrapNative } from './errors';

export const ed25519 = {
  /** Derives an Ed25519 public key. @param priv - 32-byte private key @returns 32-byte public key @throws {CryptoError} on invalid key */
  getPublic: wrapNative(
    (priv: Uint8Array): Uint8Array =>
      new Uint8Array(raw.ed25519_get_public(toArrayBuffer(priv)))
  ),
  /** Signs a message with Ed25519 (RFC 8032). @param priv - 32-byte private key @param msg - arbitrary-length message @returns 64-byte signature @throws {CryptoError} on invalid key */
  sign: wrapNative(
    (priv: Uint8Array, msg: Uint8Array): Uint8Array =>
      new Uint8Array(raw.ed25519_sign(toArrayBuffer(priv), toArrayBuffer(msg)))
  ),
  /** Verifies an Ed25519 signature. @param pub - 32-byte public key @param sig - 64-byte signature @param msg - original message @returns true if valid */
  verify: wrapNative(
    (pub: Uint8Array, sig: Uint8Array, msg: Uint8Array): boolean =>
      raw.ed25519_verify(
        toArrayBuffer(pub),
        toArrayBuffer(sig),
        toArrayBuffer(msg)
      )
  ),
};

export const x25519 = {
  /** Derives an X25519 public key. @param priv - 32-byte private key @returns 32-byte public key */
  getPublic: wrapNative(
    (priv: Uint8Array): Uint8Array =>
      new Uint8Array(raw.x25519_get_public(toArrayBuffer(priv)))
  ),
  /** Performs X25519 Diffie-Hellman. @param priv - 32-byte private key @param pub - counterparty's 32-byte public key @returns 32-byte shared secret @throws {CryptoError} on invalid inputs */
  scalarmult: wrapNative(
    (priv: Uint8Array, pub: Uint8Array): Uint8Array =>
      new Uint8Array(
        raw.x25519_scalarmult(toArrayBuffer(priv), toArrayBuffer(pub))
      )
  ),
};
