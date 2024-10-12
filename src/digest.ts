import { NativeModules } from 'react-native';
import { base64Decode, base64Encode } from './utils';

export enum HASH {
  SHA1 = 0,
  SHA256 = 1,
  SHA512 = 2,
  SHA3_256 = 3,
  SHA3_512 = 4,
  KECCAK256 = 5,
  KECCAK512 = 6,
  RIPEMD160 = 7,
  HASH256 = 8,
  HASH160 = 9,
}

export enum HMAC_HASH {
  SHA256 = 1,
  SHA512 = 2,
}

export enum PBKDF2_HASH {
  SHA256 = 1,
  SHA512 = 2,
}

const { CryptoLib: CryptoLibNative } = NativeModules;

export const createHash = (type: HASH, data: Uint8Array): Uint8Array => {
  return base64Decode(CryptoLibNative.hash(type, base64Encode(data)));
};

export const createHmac = (
  type: HMAC_HASH,
  key: Uint8Array,
  data: Uint8Array
): Uint8Array => {
  return base64Decode(
    CryptoLibNative.hmac(type, base64Encode(key), base64Encode(data))
  );
};

export const pbkdf2 = (
  pass: string | Uint8Array,
  salt: string | Uint8Array,
  iterations = 100_000,
  keyLength = 32,
  digest = PBKDF2_HASH.SHA256
): Promise<Uint8Array> => {
  return CryptoLibNative.pbkdf2(
    digest,
    base64Encode(pass),
    base64Encode(salt),
    iterations,
    keyLength
  ).then((hash: string) => {
    return base64Decode(hash);
  });
};
