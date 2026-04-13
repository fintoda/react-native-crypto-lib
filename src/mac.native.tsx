import { raw, toArrayBuffer } from './buffer';

export const mac = {
  hmac_sha256(key: Uint8Array, msg: Uint8Array): Uint8Array {
    return new Uint8Array(
      raw.mac_hmac_sha256(toArrayBuffer(key), toArrayBuffer(msg))
    );
  },
  hmac_sha512(key: Uint8Array, msg: Uint8Array): Uint8Array {
    return new Uint8Array(
      raw.mac_hmac_sha512(toArrayBuffer(key), toArrayBuffer(msg))
    );
  },
};
