import ReactNativeCryptoLib, {
  type RawSpec,
} from './NativeReactNativeCryptoLib';

export const raw = ReactNativeCryptoLib as unknown as RawSpec;

/** Zero-copy when the Uint8Array spans its entire backing buffer; defensive
 *  copy otherwise. Safe because JSI calls are synchronous — native code never
 *  retains the pointer past the call boundary. */
export function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  return data.byteOffset === 0 && data.byteLength === data.buffer.byteLength
    ? (data.buffer as ArrayBuffer)
    : (data.slice().buffer as ArrayBuffer);
}
