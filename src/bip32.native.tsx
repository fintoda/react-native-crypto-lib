import { raw, toArrayBuffer } from './buffer';
import { wrapNative } from './errors';
import {
  HARDENED_OFFSET,
  CURVE_TAG,
  encodePath,
  packPath,
  parseNode,
  type Bip32Curve,
  type HDNode,
} from './bip32-utils';

export type { Bip32Curve, HDNode } from './bip32-utils';

export const bip32 = {
  /** Creates a master HD node from a seed. @param seed - BIP-39 seed (16-64 bytes) @param curve - derivation curve (default secp256k1) @returns root HD node @throws {CryptoError} on invalid seed */
  fromSeed: wrapNative(
    (seed: Uint8Array, curve: Bip32Curve = 'secp256k1'): HDNode =>
      parseNode(new Uint8Array(raw.bip32_from_seed(toArrayBuffer(seed), curve)))
  ),
  /** Derives a child HD node (hardened or normal). @param node - parent HD node @param path - BIP-32 path string (e.g. "m/44'/0'/0'") or array of indices @returns derived HD node @throws {CryptoError} on invalid path or derivation failure */
  derive: wrapNative((node: HDNode, path: string | number[]): HDNode => {
    const pathBuf =
      typeof path === 'string' ? encodePath(path) : packPath(path);
    return parseNode(
      new Uint8Array(raw.bip32_derive(toArrayBuffer(node.raw), pathBuf))
    );
  }),
  /** Derives a child HD node using only the public key (normal derivation only). @param node - parent HD node @param path - BIP-32 path string or array of indices (no hardened steps) @returns derived HD node @throws {CryptoError} if hardened derivation is attempted or node has no public key */
  derivePublic: wrapNative((node: HDNode, path: string | number[]): HDNode => {
    const pathBuf =
      typeof path === 'string' ? encodePath(path) : packPath(path);
    return parseNode(
      new Uint8Array(raw.bip32_derive_public(toArrayBuffer(node.raw), pathBuf))
    );
  }),
  /** Strips the private key while keeping chain code / pubkey. */
  neuter(node: HDNode): HDNode {
    const out = node.raw.slice();
    out[1] = 0;
    out.fill(0, 43, 75);
    return parseNode(out);
  },
  /** Serializes an HD node to Base58Check (xpub/xprv). @param node - HD node @param version - 4-byte version prefix @param isPrivate - include private key @returns Base58Check-encoded string @throws {CryptoError} on serialization failure */
  serialize: wrapNative(
    (node: HDNode, version: number, isPrivate: boolean): string =>
      raw.bip32_serialize(toArrayBuffer(node.raw), version, isPrivate)
  ),
  /** Deserializes a Base58Check HD node. @param str - encoded string @param version - expected version prefix @param curve - key curve @param isPrivate - expect private key @returns HD node @throws {CryptoError} on invalid input */
  deserialize: wrapNative(
    (
      str: string,
      version: number,
      curve: Bip32Curve,
      isPrivate: boolean
    ): HDNode =>
      parseNode(
        new Uint8Array(raw.bip32_deserialize(str, version, curve, isPrivate))
      )
  ),
  /** Computes the 4-byte fingerprint of an HD node (first 4 bytes of Hash160 of public key). @param node - HD node @returns fingerprint as a 32-bit integer */
  fingerprint: wrapNative((node: HDNode): number =>
    raw.bip32_fingerprint(toArrayBuffer(node.raw))
  ),
  /** Convenience: HARDENED_OFFSET for building numeric index paths. */
  HARDENED_OFFSET,
  CURVE_TAG,
};
