import { raw, toArrayBuffer } from './buffer';

export type TweakedPublicKey = {
  pub: Uint8Array;
  parity: 0 | 1;
};

function toOptionalAB(data?: Uint8Array): ArrayBuffer | null {
  return data ? toArrayBuffer(data) : null;
}

export const schnorr = {
  getPublic(priv: Uint8Array): Uint8Array {
    return new Uint8Array(raw.schnorr_get_public(toArrayBuffer(priv)));
  },
  verifyPublic(pub: Uint8Array): boolean {
    return raw.schnorr_verify_public(toArrayBuffer(pub));
  },
  sign(priv: Uint8Array, digest: Uint8Array, aux?: Uint8Array): Uint8Array {
    return new Uint8Array(
      raw.schnorr_sign(
        toArrayBuffer(priv),
        toArrayBuffer(digest),
        toOptionalAB(aux)
      )
    );
  },
  verify(pub: Uint8Array, sig: Uint8Array, digest: Uint8Array): boolean {
    return raw.schnorr_verify(
      toArrayBuffer(pub),
      toArrayBuffer(sig),
      toArrayBuffer(digest)
    );
  },
  tweakPublic(pub: Uint8Array, merkleRoot?: Uint8Array): TweakedPublicKey {
    // Native packs [tweaked_x(32), parity(1)] into one buffer so we only
    // cross the JSI boundary once.
    const out = new Uint8Array(
      raw.schnorr_tweak_public(toArrayBuffer(pub), toOptionalAB(merkleRoot))
    );
    return { pub: out.slice(0, 32), parity: out[32] as 0 | 1 };
  },
  tweakPrivate(priv: Uint8Array, merkleRoot?: Uint8Array): Uint8Array {
    return new Uint8Array(
      raw.schnorr_tweak_private(toArrayBuffer(priv), toOptionalAB(merkleRoot))
    );
  },
};
