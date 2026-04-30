import { type Bip32Curve } from './bip32-utils';
import { type BiometricAuthenticateOptions } from './biometric';
import { type Curve, type EcdsaSignature } from './ecdsa';

export type BiometricPromptOptions = BiometricAuthenticateOptions;

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

export type SecureKVReadOptions = {
  passphrase?: string;
  prompt?: BiometricPromptOptions;
};

export type SecureKVWriteOptions = {
  accessControl?: AccessControl;
  validityWindow?: number;
  passphrase?: string;
  passphraseIterations?: number;
  prompt?: BiometricPromptOptions;
};

export type SecureKVItemMetadata = {
  exists: boolean;
  accessControl?: AccessControl;
  validityWindow?: number;
  hasPassphrase?: boolean;
  slotKind?: 'BLOB' | 'SEED' | 'RAW' | 'WRAPPED' | 'UNKNOWN';
};

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
    options?: SecureKVWriteOptions
  ) => Promise<void>,
  get: unsupported as (
    key: string,
    options?: SecureKVReadOptions
  ) => Promise<Uint8Array | null>,
  has: unsupported as (key: string) => Promise<boolean>,
  delete: unsupported as (key: string) => Promise<void>,
  list: unsupported as () => Promise<string[]>,
  clear: unsupported as () => Promise<void>,
  isHardwareBacked: unsupported as () => Promise<boolean>,
  biometricStatus: unsupported as () => Promise<BiometricStatus>,
  metadata: unsupported as (key: string) => Promise<SecureKVItemMetadata>,
  changePassphrase: unsupported as (
    key: string,
    oldPassphrase: string,
    newPassphrase: string,
    options?: { iterations?: number; prompt?: BiometricPromptOptions }
  ) => Promise<void>,
  changeAccessControl: unsupported as (
    key: string,
    newAccessControl: AccessControlOptions,
    options?: { prompt?: BiometricPromptOptions }
  ) => Promise<void>,
  invalidateBiometricSession: unsupported as (alias?: string) => Promise<void>,

  bip32: {
    setSeed: unsupported as (
      alias: string,
      seed: Uint8Array,
      options?: SecureKVWriteOptions
    ) => Promise<void>,
    fingerprint: unsupported as (
      alias: string,
      path: string | number[],
      curve: Bip32Curve,
      options?: SecureKVReadOptions
    ) => Promise<number>,
    getPublicKey: unsupported as (
      alias: string,
      path: string | number[],
      curve: Bip32Curve,
      compact?: boolean,
      options?: SecureKVReadOptions
    ) => Promise<Uint8Array>,
    signEcdsa: unsupported as (
      alias: string,
      path: string | number[],
      digest: Uint8Array,
      curve: Curve,
      options?: SecureKVReadOptions
    ) => Promise<EcdsaSignature>,
    signSchnorr: unsupported as (
      alias: string,
      path: string | number[],
      digest: Uint8Array,
      aux?: Uint8Array,
      options?: SecureKVReadOptions
    ) => Promise<Uint8Array>,
    signSchnorrTaproot: unsupported as (
      alias: string,
      path: string | number[],
      digest: Uint8Array,
      merkleRoot?: Uint8Array,
      options?: SecureKVReadOptions
    ) => Promise<Uint8Array>,
    signEd25519: unsupported as (
      alias: string,
      path: string | number[],
      msg: Uint8Array,
      options?: SecureKVReadOptions
    ) => Promise<Uint8Array>,
    ecdh: unsupported as (
      alias: string,
      path: string | number[],
      peerPub: Uint8Array,
      curve: Curve,
      options?: SecureKVReadOptions
    ) => Promise<Uint8Array>,
    exportEncryptedSeed: unsupported as (
      alias: string,
      exportPassphrase: string,
      options?: SecureKVReadOptions & { passphraseIterations?: number }
    ) => Promise<Uint8Array>,
    importEncryptedSeed: unsupported as (
      newAlias: string,
      envelope: Uint8Array,
      exportPassphrase: string,
      options?: SecureKVWriteOptions
    ) => Promise<void>,
  },

  raw: {
    setPrivate: unsupported as (
      alias: string,
      priv: Uint8Array,
      curve: Bip32Curve,
      options?: SecureKVWriteOptions
    ) => Promise<void>,
    getPublicKey: unsupported as (
      alias: string,
      compact?: boolean,
      options?: SecureKVReadOptions
    ) => Promise<Uint8Array>,
    signEcdsa: unsupported as (
      alias: string,
      digest: Uint8Array,
      options?: SecureKVReadOptions
    ) => Promise<EcdsaSignature>,
    signSchnorr: unsupported as (
      alias: string,
      digest: Uint8Array,
      aux?: Uint8Array,
      options?: SecureKVReadOptions
    ) => Promise<Uint8Array>,
    signSchnorrTaproot: unsupported as (
      alias: string,
      digest: Uint8Array,
      merkleRoot?: Uint8Array,
      options?: SecureKVReadOptions
    ) => Promise<Uint8Array>,
    signEd25519: unsupported as (
      alias: string,
      msg: Uint8Array,
      options?: SecureKVReadOptions
    ) => Promise<Uint8Array>,
    ecdh: unsupported as (
      alias: string,
      peerPub: Uint8Array,
      options?: SecureKVReadOptions
    ) => Promise<Uint8Array>,
  },
};
