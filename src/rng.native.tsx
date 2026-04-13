import { raw } from './buffer';
import { wrapNative } from './errors';

/**
 * Generates cryptographically secure random bytes.
 * @param count - number of bytes (max 1 MiB)
 * @returns random bytes
 * @throws {CryptoError} if count exceeds limit
 */
const bytes = wrapNative(
  (count: number): Uint8Array => new Uint8Array(raw.rng_bytes(count))
);

/** Returns a cryptographically secure random 32-bit unsigned integer. @returns random uint32 */
function uint32(): number {
  const b = bytes(4);
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(0, true);
}

/**
 * Returns a uniform random integer in [0, max) without modulo bias.
 * @param max - exclusive upper bound, integer in [1, 2^32]
 * @returns random integer in [0, max)
 * @throws {RangeError} if max is out of range
 */
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
