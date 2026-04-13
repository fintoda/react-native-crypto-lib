import { raw, toArrayBuffer } from './buffer';
import { wrapNative } from './errors';

// Native returns an empty ArrayBuffer to signal "null" (infinity /
// out-of-range scalar). A real result is always non-empty.
function orNull(buf: ArrayBuffer): Uint8Array | null {
  return buf.byteLength === 0 ? null : new Uint8Array(buf);
}

export type XOnlyTweakResult = {
  parity: 0 | 1;
  xOnlyPubkey: Uint8Array;
};

export const ecc = {
  /** Adds two elliptic curve points (secp256k1). @param a - first point (33 or 65 bytes) @param b - second point (33 or 65 bytes) @param compressed - output format (default true) @returns resulting point, or null if result is point at infinity */
  pointAdd: wrapNative(
    (
      a: Uint8Array,
      b: Uint8Array,
      compressed: boolean = true
    ): Uint8Array | null =>
      orNull(raw.ecc_point_add(toArrayBuffer(a), toArrayBuffer(b), compressed))
  ),
  /** Adds a scalar tweak to a point. @param p - point (33 or 65 bytes) @param tweak - 32-byte scalar @param compressed - output format (default true) @returns tweaked point, or null if result is invalid */
  pointAddScalar: wrapNative(
    (
      p: Uint8Array,
      tweak: Uint8Array,
      compressed: boolean = true
    ): Uint8Array | null =>
      orNull(
        raw.ecc_point_add_scalar(
          toArrayBuffer(p),
          toArrayBuffer(tweak),
          compressed
        )
      )
  ),
  /** Multiplies a point by a scalar. @param p - point (33 or 65 bytes) @param tweak - 32-byte scalar @param compressed - output format (default true) @returns resulting point, or null if result is invalid */
  pointMultiply: wrapNative(
    (
      p: Uint8Array,
      tweak: Uint8Array,
      compressed: boolean = true
    ): Uint8Array | null =>
      orNull(
        raw.ecc_point_multiply(
          toArrayBuffer(p),
          toArrayBuffer(tweak),
          compressed
        )
      )
  ),
  /** Adds two private keys (mod curve order). @param d - 32-byte private key @param tweak - 32-byte tweak @returns resulting key, or null if out of range */
  privateAdd: wrapNative(
    (d: Uint8Array, tweak: Uint8Array): Uint8Array | null =>
      orNull(raw.ecc_private_add(toArrayBuffer(d), toArrayBuffer(tweak)))
  ),
  /** Subtracts a tweak from a private key (mod curve order). @param d - 32-byte private key @param tweak - 32-byte tweak @returns resulting key, or null if out of range */
  privateSub: wrapNative(
    (d: Uint8Array, tweak: Uint8Array): Uint8Array | null =>
      orNull(raw.ecc_private_sub(toArrayBuffer(d), toArrayBuffer(tweak)))
  ),
  /** Negates a private key (mod curve order). @param d - 32-byte private key @returns negated key */
  privateNegate: wrapNative(
    (d: Uint8Array): Uint8Array =>
      new Uint8Array(raw.ecc_private_negate(toArrayBuffer(d)))
  ),
  /** Adds a scalar tweak to an x-only point (BIP-340). @param p - 32-byte x-only public key @param tweak - 32-byte scalar @returns tweaked x-only key and parity, or null if invalid */
  xOnlyPointAddTweak: wrapNative(
    (p: Uint8Array, tweak: Uint8Array): XOnlyTweakResult | null => {
      const out = raw.ecc_xonly_point_add_tweak(
        toArrayBuffer(p),
        toArrayBuffer(tweak)
      );
      if (out.byteLength === 0) return null;
      const bytes = new Uint8Array(out);
      return {
        xOnlyPubkey: bytes.slice(0, 32),
        parity: bytes[32] as 0 | 1,
      };
    }
  ),
};
