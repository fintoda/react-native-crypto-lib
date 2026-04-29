import { raw } from './buffer';
import { wrapNativeAsync } from './errors';
import { type BiometricStatus } from './secureKV';

export type { BiometricStatus };

/**
 * Per-prompt copy. All fields are optional and fall back to neutral
 * platform defaults if omitted (or empty).
 *
 * - `title`    — Android: BiometricPrompt title. iOS: ignored unless
 *                `subtitle` is empty, in which case `title` is used as
 *                `LAContext.localizedReason`. iOS has no separate title
 *                slot — the system always renders the app name.
 * - `subtitle` — Android: BiometricPrompt subtitle (one line below the
 *                title). iOS: `LAContext.localizedReason` (the prompt's
 *                main user-facing message).
 * - `cancelLabel` — Android: negative button text (default "Cancel").
 *                iOS: `LAContext.localizedCancelTitle`.
 */
export type BiometricAuthenticateOptions = {
  title?: string;
  subtitle?: string;
  cancelLabel?: string;
};

const status = wrapNativeAsync(
  async (): Promise<BiometricStatus> =>
    (await raw.biometric_status()) as BiometricStatus
);

const authenticate = wrapNativeAsync(
  async (options?: BiometricAuthenticateOptions): Promise<void> => {
    await raw.biometric_authenticate(
      options?.title ?? '',
      options?.subtitle ?? '',
      options?.cancelLabel ?? ''
    );
  }
);

/**
 * Standalone biometric API. **UX gate, not a security gate** — a
 * successful return only means the OS biometric prompt resolved. For
 * high-assurance flows use `secureKV.bip32.sign*` /
 * `secureKV.raw.sign*`, where authentication is bound to a Keystore
 * (Android) or Keychain (iOS) operation.
 *
 * - `biometric.status()` — check availability before calling
 *   `authenticate()`. Same underlying check as
 *   `secureKV.biometricStatus()` (and shares its return type).
 * - `biometric.authenticate(options?)` — show a system biometric
 *   prompt and resolve on success. On user cancel or hard failure
 *   the Promise rejects with a `CryptoError`; the reason starts with
 *   `'user canceled: '` for dismissals or `'biometric failed: '`
 *   for everything else.
 */
export const biometric = {
  status,
  authenticate,
};
