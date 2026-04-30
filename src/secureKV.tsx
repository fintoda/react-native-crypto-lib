import { type Bip32Curve } from './bip32-utils';
import { type BiometricAuthenticateOptions } from './biometric';
import { type Curve, type EcdsaSignature } from './ecdsa';

export type BiometricPromptOptions = BiometricAuthenticateOptions;

/**
 * Per-item access-control gating. See `secureKV.native.tsx` for the
 * full doc — `'none'` is always allowed; `'biometric'` is iOS-only in
 * Phase 1. Discriminated union for forward compatibility.
 */
export type AccessControlOptions =
  | { accessControl: 'none' }
  | { accessControl: 'biometric'; validityWindow?: number };

export type AccessControl = AccessControlOptions['accessControl'];

export type BiometricStatus =
  | 'available'
  | 'no_hardware'
  | 'not_enrolled'
  | 'hardware_unavailable'
  | 'security_update_required'
  | 'unsupported_os';

const unsupported = async (): Promise<never> => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

/** Hardware-backed key/value store with native-only signing. Native-only. */
export const secureKV = {
  set: unsupported as (
    key: string,
    value: Uint8Array,
    options?: AccessControlOptions,
    prompt?: BiometricPromptOptions
  ) => Promise<void>,
  get: unsupported as (
    key: string,
    prompt?: BiometricPromptOptions
  ) => Promise<Uint8Array | null>,
  has: unsupported as (key: string) => Promise<boolean>,
  delete: unsupported as (key: string) => Promise<void>,
  list: unsupported as () => Promise<string[]>,
  clear: unsupported as () => Promise<void>,
  isHardwareBacked: unsupported as () => Promise<boolean>,
  biometricStatus: unsupported as () => Promise<BiometricStatus>,
  invalidateBiometricSession: unsupported as (alias?: string) => Promise<void>,

  bip32: {
    setSeed: unsupported as (
      alias: string,
      seed: Uint8Array,
      options?: AccessControlOptions,
      prompt?: BiometricPromptOptions
    ) => Promise<void>,
    fingerprint: unsupported as (
      alias: string,
      path: string | number[],
      curve: Bip32Curve,
      prompt?: BiometricPromptOptions
    ) => Promise<number>,
    getPublicKey: unsupported as (
      alias: string,
      path: string | number[],
      curve: Bip32Curve,
      compact?: boolean,
      prompt?: BiometricPromptOptions
    ) => Promise<Uint8Array>,
    signEcdsa: unsupported as (
      alias: string,
      path: string | number[],
      digest: Uint8Array,
      curve: Curve,
      prompt?: BiometricPromptOptions
    ) => Promise<EcdsaSignature>,
    signSchnorr: unsupported as (
      alias: string,
      path: string | number[],
      digest: Uint8Array,
      aux?: Uint8Array,
      prompt?: BiometricPromptOptions
    ) => Promise<Uint8Array>,
    signSchnorrTaproot: unsupported as (
      alias: string,
      path: string | number[],
      digest: Uint8Array,
      merkleRoot?: Uint8Array,
      prompt?: BiometricPromptOptions
    ) => Promise<Uint8Array>,
    signEd25519: unsupported as (
      alias: string,
      path: string | number[],
      msg: Uint8Array,
      prompt?: BiometricPromptOptions
    ) => Promise<Uint8Array>,
    ecdh: unsupported as (
      alias: string,
      path: string | number[],
      peerPub: Uint8Array,
      curve: Curve,
      prompt?: BiometricPromptOptions
    ) => Promise<Uint8Array>,
  },

  raw: {
    setPrivate: unsupported as (
      alias: string,
      priv: Uint8Array,
      curve: Bip32Curve,
      options?: AccessControlOptions,
      prompt?: BiometricPromptOptions
    ) => Promise<void>,
    getPublicKey: unsupported as (
      alias: string,
      compact?: boolean,
      prompt?: BiometricPromptOptions
    ) => Promise<Uint8Array>,
    signEcdsa: unsupported as (
      alias: string,
      digest: Uint8Array,
      prompt?: BiometricPromptOptions
    ) => Promise<EcdsaSignature>,
    signSchnorr: unsupported as (
      alias: string,
      digest: Uint8Array,
      aux?: Uint8Array,
      prompt?: BiometricPromptOptions
    ) => Promise<Uint8Array>,
    signSchnorrTaproot: unsupported as (
      alias: string,
      digest: Uint8Array,
      merkleRoot?: Uint8Array,
      prompt?: BiometricPromptOptions
    ) => Promise<Uint8Array>,
    signEd25519: unsupported as (
      alias: string,
      msg: Uint8Array,
      prompt?: BiometricPromptOptions
    ) => Promise<Uint8Array>,
    ecdh: unsupported as (
      alias: string,
      peerPub: Uint8Array,
      prompt?: BiometricPromptOptions
    ) => Promise<Uint8Array>,
  },
};
