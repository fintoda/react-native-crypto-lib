import { NativeModules } from 'react-native';
import { createHash, HASH } from './digest';
import { base64Decode, base64Encode } from './utils';

// @ts-expect-error
const isTurboModuleEnabled = global.__turboModuleProxy != null;

const CryptoLibNative = isTurboModuleEnabled
  ? require('./NativeCryptoLib').default
  : NativeModules.CryptoLib;

type SignResult = {
  signature: Uint8Array;
  recId: number;
};

export const ecdsaRandomPrivate = async (): Promise<Uint8Array> => {
  return base64Decode(await CryptoLibNative.ecdsaRandomPrivate());
};

export const ecdsaValidatePrivate = (pk: Uint8Array): boolean => {
  const valid = CryptoLibNative.ecdsaValidatePrivate(
    base64Encode(pk)
  ) as number;
  return valid === 1;
};

export const ecdsaGetPublic = (pk: Uint8Array, compact = true): Uint8Array => {
  return base64Decode(
    CryptoLibNative.ecdsaGetPublic(base64Encode(pk), compact)
  );
};

export const ecdsaReadPublic = (
  pub: Uint8Array,
  compact = true
): Uint8Array => {
  return base64Decode(
    CryptoLibNative.ecdsaReadPublic(base64Encode(pub), compact)
  );
};

export const ecdsaValidatePublic = (pub: Uint8Array): boolean => {
  if (pub.length !== 33 && pub.length !== 65) {
    return false;
  }
  const valid = CryptoLibNative.ecdsaValidatePublic(
    base64Encode(pub)
  ) as number;
  return valid === 1;
};

export const ecdsaRecover = (
  sign: Uint8Array,
  recId: number,
  digest: Uint8Array
): Uint8Array => {
  return base64Decode(
    CryptoLibNative.ecdsaRecover(
      base64Encode(sign),
      recId,
      base64Encode(digest)
    )
  );
};

export const ecdsaEcdh = (
  pub: Uint8Array,
  priv: Uint8Array,
  compact = true,
  hash: HASH | null = HASH.SHA256
): Uint8Array => {
  const ecdh = base64Decode(
    CryptoLibNative.ecdsaEcdh(base64Encode(pub), base64Encode(priv), compact)
  );

  if (hash === null) {
    return ecdh;
  }

  return createHash(hash, ecdh);
};

export const ecdsaVerify = (
  pub: Uint8Array,
  sign: Uint8Array,
  digest: Uint8Array
): boolean => {
  const valid = CryptoLibNative.ecdsaVerify(
    base64Encode(pub),
    base64Encode(sign),
    base64Encode(digest)
  ) as number;
  return valid === 1;
};

export const ecdsaSign = (priv: Uint8Array, digest: Uint8Array): SignResult => {
  const res = base64Decode(
    CryptoLibNative.ecdsaSign(base64Encode(priv), base64Encode(digest))
  );

  return {
    signature: res.slice(1),
    recId: Number(res[0]),
  };
};

export const ecdsaSignAsync = async (
  priv: Uint8Array,
  digest: Uint8Array
): Promise<SignResult> => {
  const res = base64Decode(
    await CryptoLibNative.ecdsaSignAsync(
      base64Encode(priv),
      base64Encode(digest)
    )
  );

  return {
    signature: res.slice(1),
    recId: Number(res[0]),
  };
};
