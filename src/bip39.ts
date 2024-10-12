import { NativeModules } from 'react-native';
import { base64Decode } from './utils';

const { CryptoLib: CryptoLibNative } = NativeModules;

export const mnemonicToSeed = (
  mnemonic: string,
  passphrase: string = ''
): Promise<Uint8Array> => {
  return CryptoLibNative.mnemonicToSeed(mnemonic, passphrase).then(
    (result: string) => {
      return base64Decode(result);
    }
  );
};

export const generateMnemonic = (strength: number = 128): Promise<string> => {
  if (strength % 32 || strength < 128 || strength > 256) {
    throw new Error('strength % 32 || strength < 128 || strength > 256');
  }
  return CryptoLibNative.generateMnemonic(strength);
};

export const validateMnemonic = (mnemonic: string): Promise<boolean> => {
  return CryptoLibNative.validateMnemonic(mnemonic).then((valid: number) => {
    return valid === 1;
  });
};
