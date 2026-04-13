/**
 * Structured error thrown by native crypto operations.
 *
 * C++ native methods throw strings in the format `"function_name: reason"`.
 * This class parses that format and exposes structured fields for
 * programmatic error handling.
 */
export class CryptoError extends Error {
  /** The native function that threw (e.g. `"ecdsa_sign"`). */
  readonly function: string;
  /** Human-readable reason (e.g. `"digest must be 32 bytes"`). */
  readonly reason: string;

  constructor(fn: string, reason: string) {
    super(`${fn}: ${reason}`);
    this.name = 'CryptoError';
    this.function = fn;
    this.reason = reason;
  }
}

/**
 * Wraps a function so that native JSI errors (thrown as strings matching
 * `"function: reason"`) are re-thrown as `CryptoError` instances.
 */
export function wrapNative<A extends unknown[], R>(
  fn: (...args: A) => R
): (...args: A) => R {
  return (...args: A): R => {
    try {
      return fn(...args);
    } catch (e: unknown) {
      const msg =
        e instanceof Error ? e.message : typeof e === 'string' ? e : '';
      const idx = msg.indexOf(': ');
      if (idx > 0) {
        throw new CryptoError(msg.slice(0, idx), msg.slice(idx + 2));
      }
      throw e;
    }
  };
}
