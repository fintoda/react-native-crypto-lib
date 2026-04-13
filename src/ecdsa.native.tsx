import { raw, toArrayBuffer } from './buffer';
import { wrapNative } from './errors';

export type Curve = 'secp256k1' | 'nist256p1';

export type EcdsaSignature = {
  signature: Uint8Array;
  recId: number;
};

export const ecdsa = {
  /** Generates a random valid private key. @param curve - elliptic curve (default secp256k1) @returns 32-byte private key */
  randomPrivate: wrapNative(
    (curve: Curve = 'secp256k1'): Uint8Array =>
      new Uint8Array(raw.ecdsa_random_private(curve))
  ),
  /** Checks whether a 32-byte buffer is a valid private key for the given curve. @param priv - private key candidate @param curve - elliptic curve (default secp256k1) @returns true if valid */
  validatePrivate: wrapNative(
    (priv: Uint8Array, curve: Curve = 'secp256k1'): boolean =>
      raw.ecdsa_validate_private(curve, toArrayBuffer(priv))
  ),
  /** Derives the public key from a private key. @param priv - 32-byte private key @param compact - return 33-byte compressed (default) or 65-byte uncompressed @param curve - elliptic curve (default secp256k1) @returns public key @throws {CryptoError} on invalid private key */
  getPublic: wrapNative(
    (
      priv: Uint8Array,
      compact: boolean = true,
      curve: Curve = 'secp256k1'
    ): Uint8Array =>
      new Uint8Array(raw.ecdsa_get_public(curve, toArrayBuffer(priv), compact))
  ),
  /** Converts between compressed and uncompressed public key formats. @param pub - input public key (33 or 65 bytes) @param compact - output format @param curve - elliptic curve (default secp256k1) @returns re-encoded public key @throws {CryptoError} on invalid public key */
  readPublic: wrapNative(
    (
      pub: Uint8Array,
      compact: boolean = true,
      curve: Curve = 'secp256k1'
    ): Uint8Array =>
      new Uint8Array(raw.ecdsa_read_public(curve, toArrayBuffer(pub), compact))
  ),
  /** Validates a public key. @param pub - public key (33 or 65 bytes) @param curve - elliptic curve (default secp256k1) @returns true if the point is on the curve */
  validatePublic: wrapNative(
    (pub: Uint8Array, curve: Curve = 'secp256k1'): boolean =>
      raw.ecdsa_validate_public(curve, toArrayBuffer(pub))
  ),
  /** Signs a 32-byte digest using deterministic ECDSA (RFC 6979). @param priv - 32-byte private key @param digest - 32-byte message hash @param curve - elliptic curve (default secp256k1) @returns signature (64 bytes, low-S) and recovery id @throws {CryptoError} on invalid inputs */
  sign: wrapNative(
    (
      priv: Uint8Array,
      digest: Uint8Array,
      curve: Curve = 'secp256k1'
    ): EcdsaSignature => {
      // Native returns 65 bytes: [recId, ...sig64]. Slice off the tag byte
      // without allocating a new buffer beyond the returned view.
      const res = new Uint8Array(
        raw.ecdsa_sign(curve, toArrayBuffer(priv), toArrayBuffer(digest))
      );
      return { signature: res.slice(1), recId: res[0] as number };
    }
  ),
  /** Verifies an ECDSA signature. @param pub - signer's public key @param sig - 64-byte signature @param digest - 32-byte message hash @param curve - elliptic curve (default secp256k1) @returns true if the signature is valid */
  verify: wrapNative(
    (
      pub: Uint8Array,
      sig: Uint8Array,
      digest: Uint8Array,
      curve: Curve = 'secp256k1'
    ): boolean =>
      raw.ecdsa_verify(
        curve,
        toArrayBuffer(pub),
        toArrayBuffer(sig),
        toArrayBuffer(digest)
      )
  ),
  /** Recovers the public key from a signature and recovery id. @param sig - 64-byte signature @param digest - 32-byte message hash @param recId - recovery id (0-3) @param curve - elliptic curve (default secp256k1) @returns 65-byte uncompressed public key @throws {CryptoError} on recovery failure */
  recover: wrapNative(
    (
      sig: Uint8Array,
      digest: Uint8Array,
      recId: number,
      curve: Curve = 'secp256k1'
    ): Uint8Array =>
      new Uint8Array(
        raw.ecdsa_recover(
          curve,
          toArrayBuffer(sig),
          toArrayBuffer(digest),
          recId
        )
      )
  ),
  /** Computes an ECDH shared secret. @param priv - 32-byte private key @param pub - counterparty's public key @param curve - elliptic curve (default secp256k1) @returns 32-byte shared secret @throws {CryptoError} on invalid inputs */
  ecdh: wrapNative(
    (
      priv: Uint8Array,
      pub: Uint8Array,
      curve: Curve = 'secp256k1'
    ): Uint8Array =>
      new Uint8Array(
        raw.ecdsa_ecdh(curve, toArrayBuffer(priv), toArrayBuffer(pub))
      )
  ),
  /** Encodes a 64-byte compact signature to DER format. @param sig - 64-byte compact signature @returns DER-encoded signature @throws {CryptoError} on invalid signature */
  sigToDer: wrapNative(
    (sig: Uint8Array): Uint8Array =>
      new Uint8Array(raw.ecdsa_sig_to_der(toArrayBuffer(sig)))
  ),
  /** Decodes a DER-encoded signature to 64-byte compact format. @param der - DER-encoded signature @returns 64-byte compact signature @throws {CryptoError} on invalid DER */
  sigFromDer: wrapNative(
    (der: Uint8Array): Uint8Array =>
      new Uint8Array(raw.ecdsa_sig_from_der(toArrayBuffer(der)))
  ),
};
