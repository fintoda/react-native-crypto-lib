import ReactNativeCryptoLib, {
  type RawSpec,
} from './NativeReactNativeCryptoLib';

const raw = ReactNativeCryptoLib as unknown as RawSpec;

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  return data.byteOffset === 0 && data.byteLength === data.buffer.byteLength
    ? (data.buffer as ArrayBuffer)
    : (data.slice().buffer as ArrayBuffer);
}

const wrap =
  (fn: (data: ArrayBuffer) => ArrayBuffer) =>
  (data: Uint8Array): Uint8Array =>
    new Uint8Array(fn(toArrayBuffer(data)));

export const hash = {
  sha1: wrap(raw.hash_sha1.bind(raw)),
  sha256: wrap(raw.hash_sha256.bind(raw)),
  sha384: wrap(raw.hash_sha384.bind(raw)),
  sha512: wrap(raw.hash_sha512.bind(raw)),
  sha3_256: wrap(raw.hash_sha3_256.bind(raw)),
  sha3_512: wrap(raw.hash_sha3_512.bind(raw)),
  keccak_256: wrap(raw.hash_keccak_256.bind(raw)),
  keccak_512: wrap(raw.hash_keccak_512.bind(raw)),
  ripemd160: wrap(raw.hash_ripemd160.bind(raw)),
  blake256: wrap(raw.hash_blake256.bind(raw)),
  blake2b: wrap(raw.hash_blake2b.bind(raw)),
  blake2s: wrap(raw.hash_blake2s.bind(raw)),
  groestl512: wrap(raw.hash_groestl512.bind(raw)),
  sha256d: wrap(raw.hash_sha256d.bind(raw)),
  hash160: wrap(raw.hash_hash160.bind(raw)),
};
