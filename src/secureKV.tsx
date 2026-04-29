import { type Bip32Curve } from './bip32-utils';
import { type Curve, type EcdsaSignature } from './ecdsa';

/**
 * Access-control gating for `secureKV.set`. Reserved for forward
 * compatibility — only `'none'` is accepted today.
 */
export type AccessControl = 'none';

const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

/** Hardware-backed key/value store with native-only signing. Native-only. */
export const secureKV = {
  set: unsupported as (
    key: string,
    value: Uint8Array,
    accessControl?: AccessControl
  ) => void,
  get: unsupported as (key: string) => Uint8Array | null,
  has: unsupported as (key: string) => boolean,
  delete: unsupported as (key: string) => void,
  list: unsupported as () => string[],
  clear: unsupported as () => void,
  isHardwareBacked: unsupported as () => boolean,

  bip32: {
    setSeed: unsupported as (alias: string, seed: Uint8Array) => void,
    fingerprint: unsupported as (
      alias: string,
      path: string | number[],
      curve: Bip32Curve
    ) => number,
    getPublicKey: unsupported as (
      alias: string,
      path: string | number[],
      curve: Bip32Curve,
      compact?: boolean
    ) => Uint8Array,
    signEcdsa: unsupported as (
      alias: string,
      path: string | number[],
      digest: Uint8Array,
      curve: Curve
    ) => EcdsaSignature,
    signSchnorr: unsupported as (
      alias: string,
      path: string | number[],
      digest: Uint8Array,
      aux?: Uint8Array
    ) => Uint8Array,
    signSchnorrTaproot: unsupported as (
      alias: string,
      path: string | number[],
      digest: Uint8Array,
      merkleRoot?: Uint8Array
    ) => Uint8Array,
    signEd25519: unsupported as (
      alias: string,
      path: string | number[],
      msg: Uint8Array
    ) => Uint8Array,
    ecdh: unsupported as (
      alias: string,
      path: string | number[],
      peerPub: Uint8Array,
      curve: Curve
    ) => Uint8Array,
  },

  raw: {
    setPrivate: unsupported as (
      alias: string,
      priv: Uint8Array,
      curve: Bip32Curve
    ) => void,
    getPublicKey: unsupported as (
      alias: string,
      compact?: boolean
    ) => Uint8Array,
    signEcdsa: unsupported as (
      alias: string,
      digest: Uint8Array
    ) => EcdsaSignature,
    signSchnorr: unsupported as (
      alias: string,
      digest: Uint8Array,
      aux?: Uint8Array
    ) => Uint8Array,
    signSchnorrTaproot: unsupported as (
      alias: string,
      digest: Uint8Array,
      merkleRoot?: Uint8Array
    ) => Uint8Array,
    signEd25519: unsupported as (alias: string, msg: Uint8Array) => Uint8Array,
    ecdh: unsupported as (alias: string, peerPub: Uint8Array) => Uint8Array,
  },
};
