import { NativeModules } from 'react-native';
import { base64Decode } from './utils';

const CryptoLibNative = NativeModules.CryptoLib;

export const randomNumber: () => Promise<number> = CryptoLibNative.randomNumber;

export const randomBytes = async (length: number): Promise<Uint8Array> => {
  return base64Decode(await CryptoLibNative.randomBytes(length));
};

export const randomBytesSync = (length: number): Uint8Array => {
  return base64Decode(CryptoLibNative.randomBytesSync(length));
};
