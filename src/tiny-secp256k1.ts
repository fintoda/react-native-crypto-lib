// Adapter for `tiny-secp256k1@2.x` — the interface consumed by
// bitcoinjs-lib / ecpair / bip32. Implemented on top of our ecdsa +
// schnorr + ecc modules so bitcoinjs can use this library as an
// `eccLib` drop-in without pulling in a WASM build.
//
// Every method here is stateless and delegates to the native layer;
// this file just reshapes inputs / outputs to match the tiny-secp256k1
// signatures.

import { ecdsa } from './ecdsa';
import { schnorr } from './schnorr';
import { ecc } from './ecc';

export type TweakParity = 0 | 1;

export type RecoveryIdType = 0 | 1 | 2 | 3;

export type RecoverableSignature = {
  signature: Uint8Array;
  recoveryId: RecoveryIdType;
};

export type XOnlyPointAddTweakResult = {
  parity: TweakParity;
  xOnlyPubkey: Uint8Array;
};

// secp256k1 group order divided by 2 — used for the strict low-S check
// in verify(). Lexicographic comparison on 32-byte BE integers is
// equivalent to numeric comparison, so Uint8Array byte-by-byte is fine.
// prettier-ignore
const N_HALF = new Uint8Array([
  0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
  0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
]);

function isHighS(sig: Uint8Array): boolean {
  // Compare the 32-byte s (sig[32..64]) against N/2.
  for (let i = 0; i < 32; i++) {
    const a = sig[32 + i] as number;
    const b = N_HALF[i] as number;
    if (a > b) return true;
    if (a < b) return false;
  }
  // s === N/2 is accepted as low-S.
  return false;
}

function isValidPubkeyBytes(p: Uint8Array): boolean {
  if (p.length === 33) return p[0] === 0x02 || p[0] === 0x03;
  if (p.length === 65) return p[0] === 0x04;
  return false;
}

export const tinySecp256k1 = {
  // --- validation ---------------------------------------------------------

  isPoint(p: Uint8Array): boolean {
    if (!isValidPubkeyBytes(p)) return false;
    return ecdsa.validatePublic(p);
  },

  isPointCompressed(p: Uint8Array): boolean {
    if (p.length !== 33) return false;
    if (p[0] !== 0x02 && p[0] !== 0x03) return false;
    return ecdsa.validatePublic(p);
  },

  isXOnlyPoint(p: Uint8Array): boolean {
    if (p.length !== 32) return false;
    return schnorr.verifyPublic(p);
  },

  isPrivate(d: Uint8Array): boolean {
    if (d.length !== 32) return false;
    return ecdsa.validatePrivate(d);
  },

  // --- point ops ----------------------------------------------------------

  pointAdd(
    a: Uint8Array,
    b: Uint8Array,
    compressed: boolean = true
  ): Uint8Array | null {
    return ecc.pointAdd(a, b, compressed);
  },

  pointAddScalar(
    p: Uint8Array,
    tweak: Uint8Array,
    compressed: boolean = true
  ): Uint8Array | null {
    return ecc.pointAddScalar(p, tweak, compressed);
  },

  pointMultiply(
    p: Uint8Array,
    tweak: Uint8Array,
    compressed: boolean = true
  ): Uint8Array | null {
    return ecc.pointMultiply(p, tweak, compressed);
  },

  pointFromScalar(
    d: Uint8Array,
    compressed: boolean = true
  ): Uint8Array | null {
    if (!ecdsa.validatePrivate(d)) return null;
    return ecdsa.getPublic(d, compressed);
  },

  pointCompress(p: Uint8Array, compressed: boolean = true): Uint8Array {
    return ecdsa.readPublic(p, compressed);
  },

  // --- x-only -------------------------------------------------------------

  xOnlyPointFromScalar(d: Uint8Array): Uint8Array {
    return schnorr.getPublic(d);
  },

  xOnlyPointFromPoint(p: Uint8Array): Uint8Array {
    // For any valid P, both P and -P share the same x coordinate, so we
    // can just strip the parity byte from the compressed form without
    // caring whether lift_x of the result would pick an even or odd y.
    const compressed =
      p.length === 33 ? p : ecdsa.readPublic(p, /* compact */ true);
    return compressed.slice(1, 33);
  },

  xOnlyPointAddTweak(
    p: Uint8Array,
    tweak: Uint8Array
  ): XOnlyPointAddTweakResult | null {
    const res = ecc.xOnlyPointAddTweak(p, tweak);
    if (!res) return null;
    return { parity: res.parity, xOnlyPubkey: res.xOnlyPubkey };
  },

  xOnlyPointAddTweakCheck(
    point: Uint8Array,
    tweak: Uint8Array,
    resultToCheck: Uint8Array,
    tweakParity?: TweakParity
  ): boolean {
    const res = ecc.xOnlyPointAddTweak(point, tweak);
    if (!res) return false;
    // Constant-time-ish byte compare; length is always 32 here.
    if (res.xOnlyPubkey.length !== resultToCheck.length) return false;
    let diff = 0;
    for (let i = 0; i < res.xOnlyPubkey.length; i++) {
      diff |= (res.xOnlyPubkey[i] as number) ^ (resultToCheck[i] as number);
    }
    if (diff !== 0) return false;
    if (tweakParity !== undefined && tweakParity !== res.parity) return false;
    return true;
  },

  // --- private scalar ops -------------------------------------------------

  privateAdd(d: Uint8Array, tweak: Uint8Array): Uint8Array | null {
    return ecc.privateAdd(d, tweak);
  },

  privateSub(d: Uint8Array, tweak: Uint8Array): Uint8Array | null {
    return ecc.privateSub(d, tweak);
  },

  privateNegate(d: Uint8Array): Uint8Array {
    return ecc.privateNegate(d);
  },

  // --- ECDSA --------------------------------------------------------------
  //
  // The third `entropy` argument (`e`) is the RFC 6979 extra entropy
  // parameter. Our native backend is pure deterministic RFC 6979 and
  // does not plumb it through; silently ignoring it matches bitcoinjs
  // expectations for a deterministic signer.

  sign(h: Uint8Array, d: Uint8Array, _e?: Uint8Array): Uint8Array {
    return ecdsa.sign(d, h).signature;
  },

  signRecoverable(
    h: Uint8Array,
    d: Uint8Array,
    _e?: Uint8Array
  ): RecoverableSignature {
    const { signature, recId } = ecdsa.sign(d, h);
    return { signature, recoveryId: recId as RecoveryIdType };
  },

  verify(
    h: Uint8Array,
    Q: Uint8Array,
    signature: Uint8Array,
    strict: boolean = false
  ): boolean {
    if (strict && isHighS(signature)) return false;
    return ecdsa.verify(Q, signature, h);
  },

  recover(
    h: Uint8Array,
    signature: Uint8Array,
    recoveryId: RecoveryIdType,
    compressed: boolean = true
  ): Uint8Array | null {
    try {
      const pub65 = ecdsa.recover(signature, h, recoveryId);
      return compressed ? ecdsa.readPublic(pub65, true) : pub65;
    } catch {
      return null;
    }
  },

  // --- Schnorr / BIP-340 --------------------------------------------------

  signSchnorr(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array {
    return schnorr.sign(d, h, e);
  },

  verifySchnorr(h: Uint8Array, Q: Uint8Array, signature: Uint8Array): boolean {
    return schnorr.verify(Q, signature, h);
  },
};
