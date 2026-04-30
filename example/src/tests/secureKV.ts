// secureKV — generic key/value store on Keychain (iOS) / AndroidKeystore.
// Tests run against the real native store, so the suite clears at the
// start and end. No biometric paths here — those live in the interactive
// Biometric screen.

import { secureKV } from '@fintoda/react-native-crypto-lib';
import {
  ascii,
  check,
  eq,
  fromHex,
  throws,
  throwsWithName,
  toHex,
  type TestCase,
  type TestGroup,
} from './harness';

const k = (s: string) => `tv.${s}`;

export const secureKVGroup: TestGroup = {
  id: 'secureKV',
  title: 'secureKV',
  description: 'storage round-trip, metadata, validation, cleanup',
  build: async (): Promise<TestCase[]> => {
    try {
      await secureKV.clear();
    } catch {
      // ignore — individual tests will surface store failures
    }

    return [
      // ---- core round-trip ------------------------------------------------
      check('round-trip 32-byte payload', async () => {
        const v = fromHex(
          'a1b2c3d4e5f60718' +
            '293a4b5c6d7e8f90' +
            '1122334455667788' +
            '99aabbccddeeff00'
        );
        await secureKV.set(k('seed'), v);
        const got = await secureKV.get(k('seed'));
        return (got !== null && eq(got, v)) || `got ${got && toHex(got)}`;
      }),
      check(
        'get(unknown) returns null',
        async () => (await secureKV.get(k('does-not-exist'))) === null
      ),
      check('has true after set, false after delete', async () => {
        await secureKV.set(k('flag'), ascii('1'));
        if (!(await secureKV.has(k('flag'))))
          return 'has=false right after set';
        await secureKV.delete(k('flag'));
        return !(await secureKV.has(k('flag')));
      }),
      check('overwrite returns the second value', async () => {
        await secureKV.set(k('over'), ascii('first'));
        await secureKV.set(k('over'), ascii('second'));
        const got = await secureKV.get(k('over'));
        return (got !== null && eq(got, ascii('second'))) || 'mismatch';
      }),
      check('delete is idempotent on unknown key', async () => {
        await secureKV.delete(k('never-existed'));
        return true;
      }),

      // ---- size limits ----------------------------------------------------
      check('empty value round-trips', async () => {
        await secureKV.set(k('empty'), new Uint8Array(0));
        const got = await secureKV.get(k('empty'));
        return got !== null && got.length === 0;
      }),
      check('value at 64 KiB limit succeeds', async () => {
        const big = new Uint8Array(65536);
        for (let i = 0; i < big.length; i++) big[i] = i & 0xff;
        await secureKV.set(k('big'), big);
        const got = await secureKV.get(k('big'));
        return (got !== null && eq(got, big)) || 'mismatch';
      }),
      throws('value over 64 KiB throws', async () => {
        await secureKV.set(k('toobig'), new Uint8Array(65537));
      }),

      // ---- key validation -------------------------------------------------
      throws('empty key throws', async () => {
        await secureKV.set('', ascii('x'));
      }),
      throws('key with invalid char throws', async () => {
        await secureKV.set('bad/key', ascii('x'));
      }),
      throws('key over 128 chars throws', async () => {
        await secureKV.set('a'.repeat(129), ascii('x'));
      }),

      // ---- list / clear ---------------------------------------------------
      check('list returns set keys; clear empties store', async () => {
        await secureKV.clear();
        await secureKV.set(k('a'), ascii('1'));
        await secureKV.set(k('b'), ascii('2'));
        await secureKV.set(k('c'), ascii('3'));
        const all = (await secureKV.list()).sort();
        const expected = [k('a'), k('b'), k('c')].sort();
        if (
          all.length !== 3 ||
          all[0] !== expected[0] ||
          all[1] !== expected[1] ||
          all[2] !== expected[2]
        ) {
          return `list=${JSON.stringify(all)}`;
        }
        await secureKV.clear();
        return (await secureKV.list()).length === 0;
      }),

      check('isHardwareBacked returns boolean', async () => {
        const v = await secureKV.isHardwareBacked();
        return typeof v === 'boolean';
      }),

      // ---- metadata -------------------------------------------------------
      check('metadata reports missing key with exists=false', async () => {
        const m = await secureKV.metadata(k('mdmissing'));
        return m.exists === false;
      }),
      check('metadata reports plain BLOB without prompt', async () => {
        await secureKV.set(k('md.plain'), ascii('hi'));
        const m = await secureKV.metadata(k('md.plain'));
        if (!m.exists) return 'metadata reported missing';
        if (m.accessControl !== 'none') return `ac=${m.accessControl}`;
        if (m.hasPassphrase !== false) return 'expected hasPassphrase=false';
        if (m.slotKind !== 'BLOB') return `slotKind=${m.slotKind}`;
        return true;
      }),

      // ---- passphrase wrap (no biometric) --------------------------------
      check('passphrase round-trip on blob slot', async () => {
        const v = ascii('secret payload');
        await secureKV.set(k('pp.blob'), v, { passphrase: 'pw1' });
        const got = await secureKV.get(k('pp.blob'), { passphrase: 'pw1' });
        return (got !== null && eq(got, v)) || `got ${got && toHex(got)}`;
      }),
      check(
        'metadata for wrapped item: hasPassphrase + slotKind=WRAPPED',
        async () => {
          const m = await secureKV.metadata(k('pp.blob'));
          if (!m.exists) return 'missing';
          if (m.hasPassphrase !== true) return 'expected hasPassphrase=true';
          if (m.slotKind !== 'WRAPPED') return `slotKind=${m.slotKind}`;
          return true;
        }
      ),
      throwsWithName(
        'get with wrong passphrase rejects with WrongPassphraseError',
        'WrongPassphraseError',
        async () => {
          await secureKV.get(k('pp.blob'), { passphrase: 'wrong' });
        }
      ),
      throwsWithName(
        'get without passphrase on wrapped item -> PassphraseRequiredError',
        'PassphraseRequiredError',
        async () => {
          await secureKV.get(k('pp.blob'));
        }
      ),

      // Larger payloads behind passphrase wrap (envelope adds 66 bytes;
      // make sure we don't trip the 64 KiB ceiling at the wrap layer).
      check('passphrase wrap on 8 KiB blob', async () => {
        const big = new Uint8Array(8192);
        for (let i = 0; i < big.length; i++) big[i] = (i * 31) & 0xff;
        await secureKV.set(k('pp.big'), big, { passphrase: 'long-pw' });
        const got = await secureKV.get(k('pp.big'), { passphrase: 'long-pw' });
        return (got !== null && eq(got, big)) || 'mismatch';
      }),

      // ---- changePassphrase: add / rotate / remove -----------------------
      check('changePassphrase: add wrap', async () => {
        await secureKV.set(k('cp'), ascii('value'));
        await secureKV.changePassphrase(k('cp'), '', 'pp1');
        const m = await secureKV.metadata(k('cp'));
        if (!m.hasPassphrase) return 'metadata still hasPassphrase=false';
        const v = await secureKV.get(k('cp'), { passphrase: 'pp1' });
        return (v !== null && eq(v, ascii('value'))) || 'value mismatch';
      }),
      check('changePassphrase: rotate', async () => {
        await secureKV.changePassphrase(k('cp'), 'pp1', 'pp2');
        const v = await secureKV.get(k('cp'), { passphrase: 'pp2' });
        if (v === null || !eq(v, ascii('value'))) return 'mismatch with new pp';
        try {
          await secureKV.get(k('cp'), { passphrase: 'pp1' });
          return 'old passphrase still works';
        } catch (e: unknown) {
          const name = (e as { name?: string }).name ?? '';
          return name === 'WrongPassphraseError' || `got ${name}`;
        }
      }),
      check('changePassphrase: remove wrap', async () => {
        await secureKV.changePassphrase(k('cp'), 'pp2', '');
        const m = await secureKV.metadata(k('cp'));
        if (m.hasPassphrase !== false) return 'metadata still wrapped';
        const v = await secureKV.get(k('cp'));
        return (v !== null && eq(v, ascii('value'))) || 'mismatch';
      }),
      check('changePassphrase: wrong old leaves item intact', async () => {
        await secureKV.set(k('cp.bad'), ascii('x'), { passphrase: 'right' });
        try {
          await secureKV.changePassphrase(k('cp.bad'), 'wrong', 'new');
          return 'expected throw';
        } catch (e: unknown) {
          const name = (e as { name?: string }).name ?? '';
          if (name !== 'WrongPassphraseError') return `got ${name}`;
        }
        const v = await secureKV.get(k('cp.bad'), { passphrase: 'right' });
        return (v !== null && eq(v, ascii('x'))) || 'item disturbed';
      }),

      // ---- bip32 export / import seed ------------------------------------
      check(
        'bip32.exportEncryptedSeed + importEncryptedSeed round-trip',
        async () => {
          const seed = fromHex('000102030405060708090a0b0c0d0e0f');
          await secureKV.bip32.setSeed(k('exp.src'), seed);
          const fpSrc = await secureKV.bip32.fingerprint(
            k('exp.src'),
            'm',
            'secp256k1'
          );
          const env = await secureKV.bip32.exportEncryptedSeed(
            k('exp.src'),
            'export-pw'
          );
          if (!(env instanceof Uint8Array) || env.length < 50) {
            return `envelope too short (${env.length})`;
          }
          await secureKV.bip32.importEncryptedSeed(
            k('exp.dst'),
            env,
            'export-pw'
          );
          const fpDst = await secureKV.bip32.fingerprint(
            k('exp.dst'),
            'm',
            'secp256k1'
          );
          return fpSrc === fpDst || `fp ${fpSrc} != ${fpDst}`;
        }
      ),
      throwsWithName(
        'importEncryptedSeed wrong passphrase -> WrongPassphraseError',
        'WrongPassphraseError',
        async () => {
          const seed = fromHex('000102030405060708090a0b0c0d0e0f');
          await secureKV.bip32.setSeed(k('exp.bad'), seed);
          const env = await secureKV.bip32.exportEncryptedSeed(
            k('exp.bad'),
            'good-pw'
          );
          await secureKV.bip32.importEncryptedSeed(
            k('exp.bad2'),
            env,
            'wrong-pw'
          );
        }
      ),
      throwsWithName(
        'importEncryptedSeed malformed envelope -> BackupFormatError',
        'BackupFormatError',
        async () => {
          await secureKV.bip32.importEncryptedSeed(
            k('exp.malformed'),
            new Uint8Array([0x42, 0x42, 0x42]),
            'pw'
          );
        }
      ),

      // ---- accessControl validation --------------------------------------
      throws('set unknown accessControl rejected', async () => {
        await secureKV.set(k('ac'), ascii('x'), {
          accessControl: 'foo' as never,
        });
      }),

      // ---- biometricStatus exposes a known enum value --------------------
      check('biometricStatus returns a known enum value', async () => {
        const status = await secureKV.biometricStatus();
        const known = [
          'available',
          'no_hardware',
          'not_enrolled',
          'hardware_unavailable',
          'security_update_required',
          'unsupported_os',
        ];
        return known.includes(status) || `status=${status}`;
      }),

      // Cleanup so the next launch starts blank.
      check('final cleanup', async () => {
        await secureKV.clear();
        return (await secureKV.list()).length === 0;
      }),
    ];
  },
};
