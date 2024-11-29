import { NativeModules } from 'react-native';
import { base64Decode, base64Encode } from './utils';

// @ts-expect-error
const isTurboModuleEnabled = global.__turboModuleProxy != null;

const CryptoLibNative = isTurboModuleEnabled
  ? require('./NativeCryptoLib').default
  : NativeModules.CryptoLib;

export function getPublic(priv: Uint8Array): Uint8Array {
  return base64Decode(CryptoLibNative.schnorrGetPublic(base64Encode(priv)));
}

export function sign(priv: Uint8Array, digest: Uint8Array): Uint8Array {
  return base64Decode(
    CryptoLibNative.schnorrSign(base64Encode(priv), base64Encode(digest))
  );
}

export async function signAsync(
  priv: Uint8Array,
  digest: Uint8Array
): Promise<Uint8Array> {
  return base64Decode(
    await CryptoLibNative.schnorrSignAsync(
      base64Encode(priv),
      base64Encode(digest)
    )
  );
}

export function verify(
  pub: Uint8Array,
  sig: Uint8Array,
  digest: Uint8Array
): boolean {
  return (
    CryptoLibNative.schnorrVerify(
      base64Encode(pub),
      base64Encode(sig),
      base64Encode(digest)
    ) === 1
  );
}

export function tweakPublicKey(pub: Uint8Array, root?: Uint8Array): Uint8Array {
  return base64Decode(
    CryptoLibNative.schnorrTweakPublic(
      base64Encode(pub),
      root ? base64Encode(root) : ''
    )
  );
}

export function tweakPrivateKey(
  priv: Uint8Array,
  root?: Uint8Array
): Uint8Array {
  return base64Decode(
    CryptoLibNative.schnorrTweakPrivate(
      base64Encode(priv),
      root ? base64Encode(root) : ''
    )
  );
}

export function verifyPublic(pub: Uint8Array): boolean {
  if (pub.length !== 32) {
    return false;
  }

  return CryptoLibNative.schnorrVerifyPub(base64Encode(pub)) === 1;
}
