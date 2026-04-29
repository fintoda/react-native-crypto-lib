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
 * Thrown by `secureKV.*` when the OS-managed master key for our store has
 * become unusable — typically after a factory reset, screen-lock removal
 * on older Android, or device-to-device migration. Existing blobs cannot
 * be decrypted; the application should treat them as lost and re-derive
 * its secrets.
 */
export class SecureKVUnavailableError extends CryptoError {
  constructor(fn: string, reason: string) {
    super(fn, reason);
    this.name = 'SecureKVUnavailableError';
  }
}

/**
 * Re-shapes a raw native error into a structured `CryptoError` (or
 * `SecureKVUnavailableError` for the secureKV master-key-gone case).
 * Used by both the sync and async wrappers below.
 */
function upgradeNativeError(e: unknown): never {
  const msg = e instanceof Error ? e.message : typeof e === 'string' ? e : '';
  const idx = msg.indexOf(': ');
  if (idx > 0) {
    const nativeFn = msg.slice(0, idx);
    const reason = msg.slice(idx + 2);
    if (nativeFn.startsWith('secure_kv_') && reason.startsWith('unavailable')) {
      throw new SecureKVUnavailableError(nativeFn, reason);
    }
    throw new CryptoError(nativeFn, reason);
  }
  throw e;
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
      upgradeNativeError(e);
    }
  };
}

/**
 * Async variant: awaits the wrapped function and upgrades rejections to
 * `CryptoError` / `SecureKVUnavailableError`. secureKV uses this because
 * its native methods return Promises.
 */
export function wrapNativeAsync<A extends unknown[], R>(
  fn: (...args: A) => Promise<R>
): (...args: A) => Promise<R> {
  return async (...args: A): Promise<R> => {
    try {
      return await fn(...args);
    } catch (e: unknown) {
      upgradeNativeError(e);
    }
  };
}
