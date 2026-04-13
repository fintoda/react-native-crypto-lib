import ReactNativeCryptoLib, {
  type RawSpec,
} from './NativeReactNativeCryptoLib';

const raw = ReactNativeCryptoLib as unknown as RawSpec;

export type CbcPadding = 'pkcs7' | 'none';

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  return data.byteOffset === 0 && data.byteLength === data.buffer.byteLength
    ? (data.buffer as ArrayBuffer)
    : (data.slice().buffer as ArrayBuffer);
}

function toOptionalAB(data?: Uint8Array): ArrayBuffer | null {
  return data ? toArrayBuffer(data) : null;
}

export const aes = {
  cbc: {
    encrypt(
      key: Uint8Array,
      iv: Uint8Array,
      data: Uint8Array,
      padding: CbcPadding = 'pkcs7'
    ): Uint8Array {
      return new Uint8Array(
        raw.aes_256_cbc_encrypt(
          toArrayBuffer(key),
          toArrayBuffer(iv),
          toArrayBuffer(data),
          padding
        )
      );
    },
    decrypt(
      key: Uint8Array,
      iv: Uint8Array,
      data: Uint8Array,
      padding: CbcPadding = 'pkcs7'
    ): Uint8Array {
      return new Uint8Array(
        raw.aes_256_cbc_decrypt(
          toArrayBuffer(key),
          toArrayBuffer(iv),
          toArrayBuffer(data),
          padding
        )
      );
    },
  },
  ctr: {
    // CTR is symmetric: same primitive encrypts and decrypts.
    crypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
      return new Uint8Array(
        raw.aes_256_ctr_crypt(
          toArrayBuffer(key),
          toArrayBuffer(iv),
          toArrayBuffer(data)
        )
      );
    },
  },
  gcm: {
    // Output layout matches WebCrypto / node:crypto: ciphertext followed
    // by a 16-byte tag, packed into a single ArrayBuffer so the JSI hop
    // is one call.
    encrypt(
      key: Uint8Array,
      nonce: Uint8Array,
      plaintext: Uint8Array,
      aad?: Uint8Array
    ): Uint8Array {
      return new Uint8Array(
        raw.aes_256_gcm_encrypt(
          toArrayBuffer(key),
          toArrayBuffer(nonce),
          toArrayBuffer(plaintext),
          toOptionalAB(aad)
        )
      );
    },
    decrypt(
      key: Uint8Array,
      nonce: Uint8Array,
      sealed: Uint8Array,
      aad?: Uint8Array
    ): Uint8Array {
      return new Uint8Array(
        raw.aes_256_gcm_decrypt(
          toArrayBuffer(key),
          toArrayBuffer(nonce),
          toArrayBuffer(sealed),
          toOptionalAB(aad)
        )
      );
    },
  },
};
