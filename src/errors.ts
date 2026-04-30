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
 * Thrown when the user dismisses a biometric prompt — covers both the
 * standalone `biometric.authenticate` flow and the secureKV biometric
 * paths. Distinguished from `CryptoError` so callers can branch on
 * cancellation without parsing the reason string.
 *
 * Native methods report cancellation with a reason of
 * `"user canceled: <details>"`; this wrapper class catches the prefix.
 */
export class BiometricCanceledError extends CryptoError {
  constructor(fn: string, reason: string) {
    super(fn, reason);
    this.name = 'BiometricCanceledError';
  }
}

/**
 * Thrown when a passphrase-wrapped item is read with the wrong
 * passphrase. The KCV verifier in the envelope catches this *before*
 * the AES-GCM decrypt attempt, so this error is distinct from data
 * corruption — see `BackupFormatError` for the latter.
 *
 * Native reason starts with `"passphrase: wrong"`.
 */
export class WrongPassphraseError extends CryptoError {
  constructor(fn: string, reason: string) {
    super(fn, reason);
    this.name = 'WrongPassphraseError';
  }
}

/**
 * Thrown when an item is passphrase-wrapped but the read call did not
 * supply a passphrase. The caller should prompt the user and retry the
 * operation with the entered passphrase.
 *
 * Native reason starts with `"passphrase: required"`.
 */
export class PassphraseRequiredError extends CryptoError {
  constructor(fn: string, reason: string) {
    super(fn, reason);
    this.name = 'PassphraseRequiredError';
  }
}

/**
 * Thrown when a backup envelope or passphrase-wrapped slot fails to
 * parse, or its AES-GCM authentication fails *after* a successful KCV
 * check (indicating data corruption rather than a wrong passphrase).
 *
 * Native reason starts with `"backup: "` (malformed input) or
 * `"backup: data integrity check failed"` (post-verifier GCM failure).
 */
export class BackupFormatError extends CryptoError {
  constructor(fn: string, reason: string) {
    super(fn, reason);
    this.name = 'BackupFormatError';
  }
}

/**
 * Re-shapes a raw native error into a structured `CryptoError` (or one
 * of its specialised subclasses). Used by both the sync and async
 * wrappers below.
 *
 * Order matters: cancellation is checked first because it can occur on
 * both `secure_kv_*` and `biometric_*` functions and would otherwise
 * fall through to the generic `CryptoError` branch.
 */
function upgradeNativeError(e: unknown): never {
  const msg = e instanceof Error ? e.message : typeof e === 'string' ? e : '';
  const idx = msg.indexOf(': ');
  if (idx > 0) {
    const nativeFn = msg.slice(0, idx);
    const reason = msg.slice(idx + 2);
    // Order matters: more specific reasons first so they don't fall
    // through to the generic `unavailable` / `CryptoError` branches.
    if (reason.startsWith('user canceled')) {
      throw new BiometricCanceledError(nativeFn, reason);
    }
    if (reason.startsWith('passphrase: wrong')) {
      throw new WrongPassphraseError(nativeFn, reason);
    }
    if (reason.startsWith('passphrase: required')) {
      throw new PassphraseRequiredError(nativeFn, reason);
    }
    if (reason.startsWith('backup:')) {
      throw new BackupFormatError(nativeFn, reason);
    }
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
