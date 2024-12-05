import { NativeModules } from 'react-native';

import * as ecdsa from './ecdsa';
import * as schnorr from './schnorr';
import { base64Decode, base64Encode } from './utils';

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

// @ts-expect-error
const isTurboModuleEnabled = global.__turboModuleProxy != null;

const CryptoLibNative = isTurboModuleEnabled
  ? require('./NativeCryptoLib').default
  : NativeModules.CryptoLib;

export default {
  isPoint: (pub: Uint8Array): boolean => {
    if (pub.length === 33 || pub.length === 65) {
      return ecdsa.ecdsaValidatePublic(pub);
    }

    if (pub.length === 32) {
      return schnorr.verifyPublic(pub);
    }

    return false;
  },
  isXOnlyPoint: (pub: Uint8Array): boolean => {
    if (pub.length === 32) {
      return schnorr.verifyPublic(pub);
    }

    return false;
  },
  xOnlyPointAddTweak: (
    pub: Uint8Array,
    tweak: Uint8Array
  ): XOnlyPointAddTweakResult | null => {
    if (pub.length !== 32 || tweak.length !== 32) {
      return null;
    }

    const res = CryptoLibNative.xOnlyPointAddTweak(
      base64Encode(pub),
      base64Encode(tweak)
    );

    if (!res) {
      return null;
    }

    return {
      parity: res.parity as number,
      xOnlyPubkey: base64Decode(res.xOnlyPubkey),
    } as XOnlyPointAddTweakResult;
  },
} as TinySecp256k1Interface;
