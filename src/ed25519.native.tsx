import { raw, toArrayBuffer } from './buffer';

export const ed25519 = {
  getPublic(priv: Uint8Array): Uint8Array {
    return new Uint8Array(raw.ed25519_get_public(toArrayBuffer(priv)));
  },
  sign(priv: Uint8Array, msg: Uint8Array): Uint8Array {
    return new Uint8Array(
      raw.ed25519_sign(toArrayBuffer(priv), toArrayBuffer(msg))
    );
  },
  verify(pub: Uint8Array, sig: Uint8Array, msg: Uint8Array): boolean {
    return raw.ed25519_verify(
      toArrayBuffer(pub),
      toArrayBuffer(sig),
      toArrayBuffer(msg)
    );
  },
};

export const x25519 = {
  getPublic(priv: Uint8Array): Uint8Array {
    return new Uint8Array(raw.x25519_get_public(toArrayBuffer(priv)));
  },
  scalarmult(priv: Uint8Array, pub: Uint8Array): Uint8Array {
    return new Uint8Array(
      raw.x25519_scalarmult(toArrayBuffer(priv), toArrayBuffer(pub))
    );
  },
};
