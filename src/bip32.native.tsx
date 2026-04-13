import ReactNativeCryptoLib, {
  type RawSpec,
} from './NativeReactNativeCryptoLib';
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

const raw = ReactNativeCryptoLib as unknown as RawSpec;

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  return data.byteOffset === 0 && data.byteLength === data.buffer.byteLength
    ? (data.buffer as ArrayBuffer)
    : (data.slice().buffer as ArrayBuffer);
}

export const bip32 = {
  fromSeed(seed: Uint8Array, curve: Bip32Curve = 'secp256k1'): HDNode {
    return parseNode(
      new Uint8Array(raw.bip32_from_seed(toArrayBuffer(seed), curve))
    );
  },
  derive(node: HDNode, path: string | number[]): HDNode {
    const pathBuf =
      typeof path === 'string' ? encodePath(path) : packPath(path);
    return parseNode(
      new Uint8Array(raw.bip32_derive(toArrayBuffer(node.raw), pathBuf))
    );
  },
  derivePublic(node: HDNode, path: string | number[]): HDNode {
    const pathBuf =
      typeof path === 'string' ? encodePath(path) : packPath(path);
    return parseNode(
      new Uint8Array(raw.bip32_derive_public(toArrayBuffer(node.raw), pathBuf))
    );
  },
  /** Strips the private key while keeping chain code / pubkey. */
  neuter(node: HDNode): HDNode {
    const out = node.raw.slice();
    out[1] = 0;
    out.fill(0, 43, 75);
    return parseNode(out);
  },
  serialize(node: HDNode, version: number, isPrivate: boolean): string {
    return raw.bip32_serialize(toArrayBuffer(node.raw), version, isPrivate);
  },
  deserialize(
    str: string,
    version: number,
    curve: Bip32Curve,
    isPrivate: boolean
  ): HDNode {
    return parseNode(
      new Uint8Array(raw.bip32_deserialize(str, version, curve, isPrivate))
    );
  },
  fingerprint(node: HDNode): number {
    return raw.bip32_fingerprint(toArrayBuffer(node.raw));
  },
  /** Convenience: HARDENED_OFFSET for building numeric index paths. */
  HARDENED_OFFSET,
  CURVE_TAG,
};
