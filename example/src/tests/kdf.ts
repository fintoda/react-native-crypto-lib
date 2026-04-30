// HKDF — RFC 5869, PBKDF2 — RFC 6070 / RFC 7914.
// Sync variant only here; the async path is exercised in the asyncOps group
// to keep the comparison apples-to-apples.

import { kdf } from '@fintoda/react-native-crypto-lib';
import { ascii, check, eq, fromHex, hexCheck, type TestGroup } from './harness';

export const kdfGroup: TestGroup = {
  id: 'kdf',
  title: 'kdf',
  description: 'HKDF-SHA256/512 (RFC 5869) + PBKDF2-SHA256/512 (RFC 6070)',
  build: () => {
    const ikm1 = new Uint8Array(22).fill(0x0b);
    const salt1 = fromHex('000102030405060708090a0b0c');
    const info1 = fromHex('f0f1f2f3f4f5f6f7f8f9');
    const ikm3 = new Uint8Array(22).fill(0x0b);
    const empty = new Uint8Array(0);

    // RFC 5869 case #2 — long IKM/salt/info
    const ikm2 = fromHex(
      '000102030405060708090a0b0c0d0e0f' +
        '101112131415161718191a1b1c1d1e1f' +
        '202122232425262728292a2b2c2d2e2f' +
        '303132333435363738393a3b3c3d3e3f' +
        '404142434445464748494a4b4c4d4e4f'
    );
    const salt2 = fromHex(
      '606162636465666768696a6b6c6d6e6f' +
        '707172737475767778797a7b7c7d7e7f' +
        '808182838485868788898a8b8c8d8e8f' +
        '909192939495969798999a9b9c9d9e9f' +
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'
    );
    const info2 = fromHex(
      'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
        'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' +
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
        'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
    );

    const pwd = ascii('password');
    const salt = ascii('salt');

    return [
      // HKDF-SHA256
      hexCheck(
        'hkdf_sha256(RFC5869 #1, 42B)',
        kdf.hkdf_sha256(ikm1, salt1, info1, 42),
        '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
      ),
      hexCheck(
        'hkdf_sha256(RFC5869 #2, 82B long inputs)',
        kdf.hkdf_sha256(ikm2, salt2, info2, 82),
        'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87'
      ),
      hexCheck(
        'hkdf_sha256(RFC5869 #3, empty salt+info)',
        kdf.hkdf_sha256(ikm3, empty, empty, 42),
        '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8'
      ),

      // HKDF-SHA512 — vector by reference, locked here for regression
      hexCheck(
        'hkdf_sha512(case #1)',
        kdf.hkdf_sha512(ikm1, salt1, info1, 42),
        '832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb'
      ),

      // Variable output sizes
      check(
        'hkdf_sha256 length 1',
        () => kdf.hkdf_sha256(ikm1, salt1, info1, 1).length === 1
      ),
      check(
        'hkdf_sha256 length 32',
        () => kdf.hkdf_sha256(ikm1, salt1, info1, 32).length === 32
      ),
      check(
        'hkdf_sha256 length 8160 (max)',
        () => kdf.hkdf_sha256(ikm1, salt1, info1, 8160).length === 8160
      ),

      // PBKDF2-SHA256 (well-known fixtures cross-checked against OpenSSL)
      hexCheck(
        'pbkdf2_sha256("password","salt",1,32)',
        kdf.pbkdf2_sha256Sync(pwd, salt, 1, 32),
        '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'
      ),
      hexCheck(
        'pbkdf2_sha256("password","salt",4096,32)',
        kdf.pbkdf2_sha256Sync(pwd, salt, 4096, 32),
        'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a'
      ),

      // PBKDF2-SHA512
      hexCheck(
        'pbkdf2_sha512("password","salt",1,64)',
        kdf.pbkdf2_sha512Sync(pwd, salt, 1, 64),
        '867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce'
      ),

      // Multi-block (dkLen > digest size forces multiple derivation rounds)
      check(
        'pbkdf2_sha256(dkLen=64) length',
        () => kdf.pbkdf2_sha256Sync(pwd, salt, 1, 64).length === 64
      ),
      check(
        'pbkdf2_sha512(dkLen=128) length',
        () => kdf.pbkdf2_sha512Sync(pwd, salt, 1, 128).length === 128
      ),

      // Determinism
      check('pbkdf2_sha256 deterministic', () =>
        eq(
          kdf.pbkdf2_sha256Sync(pwd, salt, 100, 32),
          kdf.pbkdf2_sha256Sync(pwd, salt, 100, 32)
        )
      ),
      // Different passwords → different output
      check('pbkdf2_sha256 password-sensitive', () => {
        const a = kdf.pbkdf2_sha256Sync(pwd, salt, 100, 32);
        const b = kdf.pbkdf2_sha256Sync(ascii('Password'), salt, 100, 32);
        return !eq(a, b);
      }),
      // Different salts → different output
      check('pbkdf2_sha256 salt-sensitive', () => {
        const a = kdf.pbkdf2_sha256Sync(pwd, salt, 100, 32);
        const b = kdf.pbkdf2_sha256Sync(pwd, ascii('SALT'), 100, 32);
        return !eq(a, b);
      }),
    ];
  },
};
