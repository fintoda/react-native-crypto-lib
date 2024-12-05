import { NativeModules } from 'react-native';
import { base64Encode } from './utils';

export type Bip32Curve =
  | 'secp256k1'
  | 'secp256k1-decred'
  | 'secp256k1-groestl'
  | 'secp256k1-smart'
  | 'nist256p1'
  | 'ed25519'
  | 'ed25519-sha3'
  | 'ed25519-keccak'
  | 'curve25519';

export type HDNode = {
  depth: number;
  child_num: number;
  chain_code: string;
  private_key?: string;
  public_key?: string;
  fingerprint: number;
  curve: Bip32Curve;
  private_derive: boolean;
};

// @ts-expect-error
const isTurboModuleEnabled = global.__turboModuleProxy != null;

const CryptoLibNative = isTurboModuleEnabled
  ? require('./NativeCryptoLib').default
  : NativeModules.CryptoLib;

const HIGHEST_BIT = 0x80000000;
const UINT31_MAX = Math.pow(2, 31) - 1;

function BIP32Path(value: string): Boolean {
  return value.match(/^(m\/)?(\d+'?\/)*\d+'?$/) !== null;
}

function UInt31(value: number): Boolean {
  return value >= 0 && value <= UINT31_MAX;
}

export const hdNodeFromSeed = (curve: Bip32Curve, seed: Uint8Array): HDNode => {
  return CryptoLibNative.hdNodeFromSeed(curve, base64Encode(seed));
};

export const hdNodeDerive = (node: HDNode, path: number[]): HDNode => {
  return CryptoLibNative.hdNodeDerive(node, path);
};

export const derivePath = (node: HDNode, path: string): HDNode => {
  if (!BIP32Path(path)) {
    throw new TypeError('Missing BIP32 path');
  }

  const path_items: string[] = path.split('/');
  const path_indexes: number[] = [];

  for (let item of path_items) {
    if (item === 'm') {
      if (node.depth !== 0) {
        throw new TypeError('Expected master, got child');
      }
      continue;
    }

    if (item.slice(-1) === `'`) {
      const index = parseInt(item.slice(0, -1), 10);
      if (!UInt31(index)) {
        throw new TypeError('Missing index uint31');
      }
      path_indexes.push(HIGHEST_BIT + index);
    } else {
      const index = parseInt(item, 10);
      if (!UInt31(index)) {
        throw new TypeError('Missing index uint31');
      }
      path_indexes.push(index);
    }
  }

  return hdNodeDerive(node, path_indexes);
};
