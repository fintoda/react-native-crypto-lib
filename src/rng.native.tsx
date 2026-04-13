import ReactNativeCryptoLib, {
  type RawSpec,
} from './NativeReactNativeCryptoLib';

const raw = ReactNativeCryptoLib as unknown as RawSpec;

function bytes(count: number): Uint8Array {
  return new Uint8Array(raw.rng_bytes(count));
}

function uint32(): number {
  const b = bytes(4);
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(0, true);
}

// Uniform integer in [0, max) without modulo bias, via rejection sampling
// over the uint32 range. max must be an integer in [1, 2^32].
function uniform(max: number): number {
  if (!Number.isInteger(max) || max < 1 || max > 0x1_0000_0000) {
    throw new RangeError('rng.uniform: max must be an integer in [1, 2^32]');
  }
  if (max === 1) return 0;
  // Largest multiple of `max` that fits into uint32; values >= limit are
  // rejected so the remaining range divides evenly by `max`.
  const limit = Math.floor(0x1_0000_0000 / max) * max;
  for (;;) {
    const r = uint32();
    if (r < limit) return r % max;
  }
}

export const rng = { bytes, uint32, uniform };
