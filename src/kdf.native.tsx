import { raw, toArrayBuffer } from './buffer';

export const kdf = {
  pbkdf2_sha256(
    password: Uint8Array,
    salt: Uint8Array,
    iterations: number,
    length: number
  ): Uint8Array {
    return new Uint8Array(
      raw.kdf_pbkdf2_sha256(
        toArrayBuffer(password),
        toArrayBuffer(salt),
        iterations,
        length
      )
    );
  },
  pbkdf2_sha512(
    password: Uint8Array,
    salt: Uint8Array,
    iterations: number,
    length: number
  ): Uint8Array {
    return new Uint8Array(
      raw.kdf_pbkdf2_sha512(
        toArrayBuffer(password),
        toArrayBuffer(salt),
        iterations,
        length
      )
    );
  },
  hkdf_sha256(
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length: number
  ): Uint8Array {
    return new Uint8Array(
      raw.kdf_hkdf_sha256(
        toArrayBuffer(ikm),
        toArrayBuffer(salt),
        toArrayBuffer(info),
        length
      )
    );
  },
  hkdf_sha512(
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length: number
  ): Uint8Array {
    return new Uint8Array(
      raw.kdf_hkdf_sha512(
        toArrayBuffer(ikm),
        toArrayBuffer(salt),
        toArrayBuffer(info),
        length
      )
    );
  },
};
