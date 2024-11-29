import { NativeModules } from 'react-native';
import { base64Decode, base64Encode } from './utils';

export enum PADDING_MODE {
  ZERO = 0,
  PKCS7 = 1,
}

// @ts-expect-error
const isTurboModuleEnabled = global.__turboModuleProxy != null;

const CryptoLibNative = isTurboModuleEnabled
  ? require('./NativeCryptoLib').default
  : NativeModules.CryptoLib;

export async function encrypt(
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
  mode: PADDING_MODE = PADDING_MODE.PKCS7
): Promise<Uint8Array> {
  const result = await CryptoLibNative.encrypt(
    base64Encode(key),
    base64Encode(iv),
    base64Encode(data),
    mode
  );

  return base64Decode(result);
}

export async function decrypt(
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
  mode: PADDING_MODE = PADDING_MODE.PKCS7
): Promise<Uint8Array> {
  const result = await CryptoLibNative.decrypt(
    base64Encode(key),
    base64Encode(iv),
    base64Encode(data),
    mode
  );

  return base64Decode(result);
}
