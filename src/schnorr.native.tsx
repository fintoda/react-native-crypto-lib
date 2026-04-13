import { raw, toArrayBuffer } from './buffer';
import { wrapNative } from './errors';

export type TweakedPublicKey = {
  pub: Uint8Array;
  parity: 0 | 1;
};

function toOptionalAB(data?: Uint8Array): ArrayBuffer | null {
  return data ? toArrayBuffer(data) : null;
}

export const schnorr = {
  /** Derives an x-only (32-byte) Schnorr public key from a private key. @param priv - 32-byte private key @returns 32-byte x-only public key @throws {CryptoError} on invalid key */
  getPublic: wrapNative(
    (priv: Uint8Array): Uint8Array =>
      new Uint8Array(raw.schnorr_get_public(toArrayBuffer(priv)))
  ),
  /** Validates a 32-byte x-only public key. @param pub - 32-byte x-only public key @returns true if valid */
  verifyPublic: wrapNative((pub: Uint8Array): boolean =>
    raw.schnorr_verify_public(toArrayBuffer(pub))
  ),
  /** Creates a BIP-340 Schnorr signature. @param priv - 32-byte private key @param digest - 32-byte message hash @param aux - optional 32-byte auxiliary randomness @returns 64-byte Schnorr signature @throws {CryptoError} on invalid inputs */
  sign: wrapNative(
    (priv: Uint8Array, digest: Uint8Array, aux?: Uint8Array): Uint8Array =>
      new Uint8Array(
        raw.schnorr_sign(
          toArrayBuffer(priv),
          toArrayBuffer(digest),
          toOptionalAB(aux)
        )
      )
  ),
  /** Verifies a BIP-340 Schnorr signature. @param pub - 32-byte x-only public key @param sig - 64-byte signature @param digest - 32-byte message hash @returns true if valid */
  verify: wrapNative(
    (pub: Uint8Array, sig: Uint8Array, digest: Uint8Array): boolean =>
      raw.schnorr_verify(
        toArrayBuffer(pub),
        toArrayBuffer(sig),
        toArrayBuffer(digest)
      )
  ),
  /** Applies a taproot tweak to a public key. @param pub - 32-byte x-only public key @param merkleRoot - optional 32-byte merkle root @returns tweaked public key and output parity @throws {CryptoError} on tweak failure */
  tweakPublic: wrapNative(
    (pub: Uint8Array, merkleRoot?: Uint8Array): TweakedPublicKey => {
      // Native packs [tweaked_x(32), parity(1)] into one buffer so we only
      // cross the JSI boundary once.
      const out = new Uint8Array(
        raw.schnorr_tweak_public(toArrayBuffer(pub), toOptionalAB(merkleRoot))
      );
      return { pub: out.slice(0, 32), parity: out[32] as 0 | 1 };
    }
  ),
  /** Applies a taproot tweak to a private key. @param priv - 32-byte private key @param merkleRoot - optional 32-byte merkle root @returns 32-byte tweaked private key @throws {CryptoError} on tweak failure */
  tweakPrivate: wrapNative(
    (priv: Uint8Array, merkleRoot?: Uint8Array): Uint8Array =>
      new Uint8Array(
        raw.schnorr_tweak_private(toArrayBuffer(priv), toOptionalAB(merkleRoot))
      )
  ),
};
