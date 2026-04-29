import { type BiometricStatus } from './secureKV';

export type { BiometricStatus };

/** See `biometric.native.tsx` for full docs. */
export type BiometricAuthenticateOptions = {
  title?: string;
  subtitle?: string;
  cancelLabel?: string;
};

const unsupported = async (): Promise<never> => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

/** Native-only fallback. See `biometric.native.tsx` for the real API. */
export const biometric = {
  status: unsupported as () => Promise<BiometricStatus>,
  authenticate: unsupported as (
    options?: BiometricAuthenticateOptions
  ) => Promise<void>,
};
