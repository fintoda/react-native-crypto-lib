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

export interface XOnlyPointAddTweakResult {
  parity: 1 | 0;
  xOnlyPubkey: Uint8Array;
}

export interface TinySecp256k1Interface {
  isPoint(p: Uint8Array): boolean;
  isXOnlyPoint(p: Uint8Array): boolean;
  xOnlyPointAddTweak(
    p: Uint8Array,
    tweak: Uint8Array
  ): XOnlyPointAddTweakResult | null;
}
