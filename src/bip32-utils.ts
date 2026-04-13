// Pure-JS helpers for BIP-32 path parsing and node serialization.
// Extracted so they can be unit-tested without the native runtime.

export type Bip32Curve = 'secp256k1' | 'nist256p1' | 'ed25519';

export const CURVE_TAG: Record<Bip32Curve, number> = {
  secp256k1: 0,
  nist256p1: 1,
  ed25519: 2,
};

export const CURVE_FROM_TAG: readonly Bip32Curve[] = [
  'secp256k1',
  'nist256p1',
  'ed25519',
];

export const NODE_SIZE = 108;
export const HARDENED_OFFSET = 0x80000000;

export function readBeU32(bytes: Uint8Array, offset: number): number {
  // Use multiplication for the high byte so the intermediate stays a
  // JS number and doesn't coerce to int32 (which would make values
  // >= 2**31 come back negative). DataView would be nicer but creating
  // one per read adds allocation noise in the hot derive path.
  /* eslint-disable no-bitwise */
  return (
    bytes[offset]! * 0x1000000 +
    ((bytes[offset + 1]! << 16) |
      (bytes[offset + 2]! << 8) |
      bytes[offset + 3]!)
  );
  /* eslint-enable no-bitwise */
}

export type HDNode = {
  curve: Bip32Curve;
  depth: number;
  parentFingerprint: number;
  childNumber: number;
  chainCode: Uint8Array;
  privateKey: Uint8Array | null;
  publicKey: Uint8Array;
  /** Opaque serialized form passed back to native derive calls. */
  raw: Uint8Array;
};

export function parseNode(bytes: Uint8Array): HDNode {
  if (bytes.length !== NODE_SIZE) {
    throw new Error(`bip32: expected ${NODE_SIZE}-byte node blob`);
  }
  const curve = CURVE_FROM_TAG[bytes[0]!];
  if (!curve) throw new Error('bip32: unknown curve tag');
  const hasPrivate = bytes[1] === 1;
  return {
    curve,
    depth: bytes[2]!,
    parentFingerprint: readBeU32(bytes, 3),
    childNumber: readBeU32(bytes, 7),
    chainCode: bytes.slice(11, 43),
    privateKey: hasPrivate ? bytes.slice(43, 75) : null,
    publicKey: bytes.slice(75, 108),
    raw: bytes,
  };
}

// Converts a "m/44'/0'/0'/0/0" style path into a packed ArrayBuffer of
// big-endian u32 indices that cpp/Bip32.cpp's derive methods consume.
export function encodePath(path: string): ArrayBuffer {
  const parts = path.trim().split('/').filter(Boolean);
  if (parts[0] === 'm' || parts[0] === 'M') parts.shift();
  const buf = new ArrayBuffer(parts.length * 4);
  const view = new DataView(buf);
  parts.forEach((part, i) => {
    const hardened = part.endsWith("'") || part.endsWith('h');
    const n = hardened ? Number(part.slice(0, -1)) : Number(part);
    if (!Number.isInteger(n) || n < 0 || n >= HARDENED_OFFSET) {
      throw new Error(`bip32: invalid path component "${part}"`);
    }
    view.setUint32(i * 4, hardened ? n + HARDENED_OFFSET : n, false);
  });
  return buf;
}

export function packPath(indices: number[]): ArrayBuffer {
  const buf = new ArrayBuffer(indices.length * 4);
  const view = new DataView(buf);
  indices.forEach((i, k) => {
    if (!Number.isInteger(i) || i < 0 || i > 0xffffffff) {
      throw new Error(`bip32: invalid path index ${i}`);
    }
    // eslint-disable-next-line no-bitwise
    view.setUint32(k * 4, i >>> 0, false);
  });
  return buf;
}
