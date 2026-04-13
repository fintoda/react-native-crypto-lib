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
  fromSeed: (_seed: Uint8Array, _curve?: Bip32Curve): HDNode => unsupported(),
  derive: (_node: HDNode, _path: string | number[]): HDNode => unsupported(),
  derivePublic: (_node: HDNode, _path: string | number[]): HDNode =>
    unsupported(),
  neuter: (_node: HDNode): HDNode => unsupported(),
  serialize: (_node: HDNode, _version: number, _isPrivate: boolean): string =>
    unsupported(),
  deserialize: (
    _str: string,
    _version: number,
    _curve: Bip32Curve,
    _isPrivate: boolean
  ): HDNode => unsupported(),
  fingerprint: (_node: HDNode): number => unsupported(),
  HARDENED_OFFSET,
  CURVE_TAG,
};
