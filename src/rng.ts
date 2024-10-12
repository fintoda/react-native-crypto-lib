import { NativeModules } from 'react-native';
import { base64Decode } from './utils';

const CryptoLib = NativeModules.CryptoLib;

export const randomNumber: () => Promise<number> = CryptoLib.randomNumber;

export const randomBytes = async (length: number): Promise<Uint8Array> => {
  return base64Decode(await CryptoLib.randomBytes(length));
};
