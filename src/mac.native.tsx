import ReactNativeCryptoLib, {
  type RawSpec,
} from './NativeReactNativeCryptoLib';

const raw = ReactNativeCryptoLib as unknown as RawSpec;

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  return data.byteOffset === 0 && data.byteLength === data.buffer.byteLength
    ? (data.buffer as ArrayBuffer)
    : (data.slice().buffer as ArrayBuffer);
}

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
