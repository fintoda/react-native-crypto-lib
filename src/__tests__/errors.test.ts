import { describe, expect, it } from '@jest/globals';
import {
  BiometricCanceledError,
  CryptoError,
  SecureKVUnavailableError,
  wrapNative,
  wrapNativeAsync,
} from '../errors';

// Sanity checks for the native-error → typed-error mapping. Order of
// pattern checks matters: `user canceled` is detected on any function
// (it can fire on both secureKV and standalone biometric paths), and
// must be checked before `secure_kv_* unavailable`.

function nativeThrow(msg: string): never {
  throw new Error(msg);
}

describe('upgradeNativeError', () => {
  it('returns BiometricCanceledError for "user canceled" on secure_kv_*', () => {
    const wrapped = wrapNative(() =>
      nativeThrow('secure_kv_bip32_sign_ecdsa: user canceled: prompt dismissed')
    );
    let caught: unknown;
    try {
      wrapped();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(BiometricCanceledError);
    expect(caught).toBeInstanceOf(CryptoError);
    expect((caught as BiometricCanceledError).name).toBe(
      'BiometricCanceledError'
    );
    expect((caught as BiometricCanceledError).function).toBe(
      'secure_kv_bip32_sign_ecdsa'
    );
    expect((caught as BiometricCanceledError).reason).toBe(
      'user canceled: prompt dismissed'
    );
  });

  it('returns BiometricCanceledError for "user canceled" on biometric_*', () => {
    const wrapped = wrapNative(() =>
      nativeThrow('biometric_authenticate: user canceled: code -2')
    );
    let caught: unknown;
    try {
      wrapped();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(BiometricCanceledError);
  });

  it('returns SecureKVUnavailableError for "unavailable" on secure_kv_*', () => {
    const wrapped = wrapNative(() =>
      nativeThrow('secure_kv_get: unavailable: Key user not authenticated')
    );
    let caught: unknown;
    try {
      wrapped();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(SecureKVUnavailableError);
    expect(caught).not.toBeInstanceOf(BiometricCanceledError);
    expect(
      (caught as SecureKVUnavailableError).reason.startsWith('unavailable')
    ).toBe(true);
  });

  it('returns plain CryptoError for other reasons', () => {
    const wrapped = wrapNative(() =>
      nativeThrow('ecdsa_sign: digest must be 32 bytes')
    );
    let caught: unknown;
    try {
      wrapped();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(CryptoError);
    expect(caught).not.toBeInstanceOf(SecureKVUnavailableError);
    expect(caught).not.toBeInstanceOf(BiometricCanceledError);
    expect((caught as CryptoError).function).toBe('ecdsa_sign');
  });

  it('propagates async rejections through wrapNativeAsync', async () => {
    const wrapped = wrapNativeAsync(async () =>
      nativeThrow('biometric_authenticate: user canceled: tapped Cancel')
    );
    await expect(wrapped()).rejects.toBeInstanceOf(BiometricCanceledError);
  });
});
