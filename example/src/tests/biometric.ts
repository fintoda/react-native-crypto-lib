// Non-interactive biometric checks. The full prompt flow lives in the
// dedicated Biometric screen (interactive, requires user taps).

import { biometric, secureKV } from '@fintoda/react-native-crypto-lib';
import { check, type TestGroup } from './harness';

const KNOWN_STATUS = [
  'available',
  'no_hardware',
  'not_enrolled',
  'hardware_unavailable',
  'security_update_required',
  'unsupported_os',
];

export const biometricGroup: TestGroup = {
  id: 'biometric',
  title: 'biometric (non-interactive)',
  description: 'status snapshots; live prompts live in the Biometric screen',
  build: () => [
    check('biometric.status() returns a known enum value', async () => {
      const s = await biometric.status();
      return KNOWN_STATUS.includes(s) || `status=${s}`;
    }),
    check('biometric.status() == secureKV.biometricStatus()', async () => {
      const a = await biometric.status();
      const b = await secureKV.biometricStatus();
      return a === b || `${a} vs ${b}`;
    }),
    check('biometric.status() is idempotent', async () => {
      const a = await biometric.status();
      const b = await biometric.status();
      return a === b;
    }),
  ],
};
