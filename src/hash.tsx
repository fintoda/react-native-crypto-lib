const unsupported = (_: Uint8Array): Uint8Array => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

/** One-shot cryptographic digest functions. Each accepts arbitrary-length data and returns a fixed-size hash. */
export const hash = {
  sha1: unsupported,
  sha256: unsupported,
  sha384: unsupported,
  sha512: unsupported,
  sha3_256: unsupported,
  sha3_512: unsupported,
  keccak_256: unsupported,
  keccak_512: unsupported,
  ripemd160: unsupported,
  blake256: unsupported,
  blake2b: unsupported,
  blake2s: unsupported,
  groestl512: unsupported,
  sha256d: unsupported,
  hash160: unsupported,
};
