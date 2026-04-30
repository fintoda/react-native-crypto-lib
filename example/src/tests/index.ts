// Master list of test groups in the order they should appear in the menu.
// Order is roughly: pure crypto (no I/O), heavy CPU async, secure storage,
// biometrics. Each entry is a `TestGroup` (see ./harness.ts).

import { hashGroup } from './hash';
import { macGroup } from './mac';
import { kdfGroup } from './kdf';
import { rngGroup } from './rng';
import { ecdsaGroup } from './ecdsa';
import { schnorrGroup } from './schnorr';
import { ed25519Group } from './ed25519';
import { aesGroup } from './aes';
import { bip39Group } from './bip39';
import { bip32Group } from './bip32';
import { slip39Group } from './slip39';
import { eccGroup } from './ecc';
import { webcryptoGroup } from './webcrypto';
import { asyncOpsGroup } from './asyncOps';
import { secureKVGroup } from './secureKV';
import { secureKVSignGroup } from './secureKVSign';
import { biometricGroup } from './biometric';

import type { TestGroup } from './harness';

export const TEST_GROUPS: TestGroup[] = [
  hashGroup,
  macGroup,
  kdfGroup,
  rngGroup,
  ecdsaGroup,
  schnorrGroup,
  ed25519Group,
  aesGroup,
  bip39Group,
  bip32Group,
  slip39Group,
  eccGroup,
  webcryptoGroup,
  asyncOpsGroup,
  secureKVGroup,
  secureKVSignGroup,
  biometricGroup,
];

export type { TestCase, TestGroup, TestResult } from './harness';
