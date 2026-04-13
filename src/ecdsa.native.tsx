import { raw, toArrayBuffer } from './buffer';

export type Curve = 'secp256k1' | 'nist256p1';

export type EcdsaSignature = {
  signature: Uint8Array;
  recId: number;
};

export const ecdsa = {
  randomPrivate(curve: Curve = 'secp256k1'): Uint8Array {
    return new Uint8Array(raw.ecdsa_random_private(curve));
  },
  validatePrivate(priv: Uint8Array, curve: Curve = 'secp256k1'): boolean {
    return raw.ecdsa_validate_private(curve, toArrayBuffer(priv));
  },
  getPublic(
    priv: Uint8Array,
    compact: boolean = true,
    curve: Curve = 'secp256k1'
  ): Uint8Array {
    return new Uint8Array(
      raw.ecdsa_get_public(curve, toArrayBuffer(priv), compact)
    );
  },
  readPublic(
    pub: Uint8Array,
    compact: boolean = true,
    curve: Curve = 'secp256k1'
  ): Uint8Array {
    return new Uint8Array(
      raw.ecdsa_read_public(curve, toArrayBuffer(pub), compact)
    );
  },
  validatePublic(pub: Uint8Array, curve: Curve = 'secp256k1'): boolean {
    return raw.ecdsa_validate_public(curve, toArrayBuffer(pub));
  },
  sign(
    priv: Uint8Array,
    digest: Uint8Array,
    curve: Curve = 'secp256k1'
  ): EcdsaSignature {
    // Native returns 65 bytes: [recId, ...sig64]. Slice off the tag byte
    // without allocating a new buffer beyond the returned view.
    const res = new Uint8Array(
      raw.ecdsa_sign(curve, toArrayBuffer(priv), toArrayBuffer(digest))
    );
    return { signature: res.slice(1), recId: res[0] as number };
  },
  verify(
    pub: Uint8Array,
    sig: Uint8Array,
    digest: Uint8Array,
    curve: Curve = 'secp256k1'
  ): boolean {
    return raw.ecdsa_verify(
      curve,
      toArrayBuffer(pub),
      toArrayBuffer(sig),
      toArrayBuffer(digest)
    );
  },
  recover(
    sig: Uint8Array,
    digest: Uint8Array,
    recId: number,
    curve: Curve = 'secp256k1'
  ): Uint8Array {
    return new Uint8Array(
      raw.ecdsa_recover(curve, toArrayBuffer(sig), toArrayBuffer(digest), recId)
    );
  },
  ecdh(
    priv: Uint8Array,
    pub: Uint8Array,
    curve: Curve = 'secp256k1'
  ): Uint8Array {
    return new Uint8Array(
      raw.ecdsa_ecdh(curve, toArrayBuffer(priv), toArrayBuffer(pub))
    );
  },
  sigToDer(sig: Uint8Array): Uint8Array {
    return new Uint8Array(raw.ecdsa_sig_to_der(toArrayBuffer(sig)));
  },
  sigFromDer(der: Uint8Array): Uint8Array {
    return new Uint8Array(raw.ecdsa_sig_from_der(toArrayBuffer(der)));
  },
};
