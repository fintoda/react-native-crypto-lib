import {
  HARDENED_OFFSET,
  CURVE_TAG,
  type Bip32Curve,
  type HDNode,
} from './bip32-utils';

export type { Bip32Curve, HDNode } from './bip32-utils';

const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export const bip32 = {
  /** Creates a master HD node from a seed. @param seed - BIP-39 seed (16-64 bytes) @param curve - derivation curve (default secp256k1) @returns root HD node @throws {CryptoError} on invalid seed */
  fromSeed: (_seed: Uint8Array, _curve?: Bip32Curve): HDNode => unsupported(),
  /** Derives a child HD node (hardened or normal). @param node - parent HD node @param path - BIP-32 path string (e.g. "m/44'/0'/0'") or array of indices @returns derived HD node @throws {CryptoError} on invalid path or derivation failure */
  derive: (_node: HDNode, _path: string | number[]): HDNode => unsupported(),
  /** Derives a child HD node using only the public key (normal derivation only). @param node - parent HD node @param path - BIP-32 path string or array of indices (no hardened steps) @returns derived HD node @throws {CryptoError} if hardened derivation is attempted or node has no public key */
  derivePublic: (_node: HDNode, _path: string | number[]): HDNode =>
    unsupported(),
  /** Strips the private key while keeping chain code / pubkey. */
  neuter: (_node: HDNode): HDNode => unsupported(),
  /** Serializes an HD node to Base58Check (xpub/xprv). @param node - HD node @param version - 4-byte version prefix @param isPrivate - include private key @returns Base58Check-encoded string @throws {CryptoError} on serialization failure */
  serialize: (_node: HDNode, _version: number, _isPrivate: boolean): string =>
    unsupported(),
  /** Deserializes a Base58Check HD node. @param str - encoded string @param version - expected version prefix @param curve - key curve @param isPrivate - expect private key @returns HD node @throws {CryptoError} on invalid input */
  deserialize: (
    _str: string,
    _version: number,
    _curve: Bip32Curve,
    _isPrivate: boolean
  ): HDNode => unsupported(),
  /** Computes the 4-byte fingerprint of an HD node (first 4 bytes of Hash160 of public key). @param node - HD node @returns fingerprint as a 32-bit integer */
  fingerprint: (_node: HDNode): number => unsupported(),
  HARDENED_OFFSET,
  CURVE_TAG,
};
