import { raw, toArrayBuffer } from './buffer';

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
  pointAdd(
    a: Uint8Array,
    b: Uint8Array,
    compressed: boolean = true
  ): Uint8Array | null {
    return orNull(
      raw.ecc_point_add(toArrayBuffer(a), toArrayBuffer(b), compressed)
    );
  },
  pointAddScalar(
    p: Uint8Array,
    tweak: Uint8Array,
    compressed: boolean = true
  ): Uint8Array | null {
    return orNull(
      raw.ecc_point_add_scalar(
        toArrayBuffer(p),
        toArrayBuffer(tweak),
        compressed
      )
    );
  },
  pointMultiply(
    p: Uint8Array,
    tweak: Uint8Array,
    compressed: boolean = true
  ): Uint8Array | null {
    return orNull(
      raw.ecc_point_multiply(toArrayBuffer(p), toArrayBuffer(tweak), compressed)
    );
  },
  privateAdd(d: Uint8Array, tweak: Uint8Array): Uint8Array | null {
    return orNull(raw.ecc_private_add(toArrayBuffer(d), toArrayBuffer(tweak)));
  },
  privateSub(d: Uint8Array, tweak: Uint8Array): Uint8Array | null {
    return orNull(raw.ecc_private_sub(toArrayBuffer(d), toArrayBuffer(tweak)));
  },
  privateNegate(d: Uint8Array): Uint8Array {
    return new Uint8Array(raw.ecc_private_negate(toArrayBuffer(d)));
  },
  xOnlyPointAddTweak(
    p: Uint8Array,
    tweak: Uint8Array
  ): XOnlyTweakResult | null {
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
  },
};
