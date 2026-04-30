// HMAC vectors — RFC 4231 cases #1, #2, #4, #6 cover key sizes both
// shorter and longer than the underlying digest's block size.

import { mac } from '@fintoda/react-native-crypto-lib';
import { ascii, check, eq, hexCheck, fromHex, type TestGroup } from './harness';

export const macGroup: TestGroup = {
  id: 'mac',
  title: 'mac',
  description: 'HMAC-SHA256 / HMAC-SHA512 RFC 4231 vectors',
  build: () => {
    // RFC 4231 #1 — key=20*0x0b, msg="Hi There"
    const key1 = new Uint8Array(20).fill(0x0b);
    const msg1 = ascii('Hi There');
    // #2 — key="Jefe", msg="what do ya want for nothing?"
    const key2 = ascii('Jefe');
    const msg2 = ascii('what do ya want for nothing?');
    // #4 — key=0x01..0x19, msg=50*0xcd
    const key4 = fromHex('0102030405060708090a0b0c0d0e0f10111213141516171819');
    const msg4 = new Uint8Array(50).fill(0xcd);
    // #6 — key=131*0xaa (longer than SHA-256/SHA-512 block size)
    const key6 = new Uint8Array(131).fill(0xaa);
    const msg6 = ascii(
      'Test Using Larger Than Block-Size Key - Hash Key First'
    );

    return [
      hexCheck(
        'hmac_sha256(RFC4231 #1)',
        mac.hmac_sha256(key1, msg1),
        'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
      ),
      hexCheck(
        'hmac_sha256(RFC4231 #2)',
        mac.hmac_sha256(key2, msg2),
        '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'
      ),
      hexCheck(
        'hmac_sha256(RFC4231 #4)',
        mac.hmac_sha256(key4, msg4),
        '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b'
      ),
      hexCheck(
        'hmac_sha256(RFC4231 #6, oversize key)',
        mac.hmac_sha256(key6, msg6),
        '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54'
      ),
      hexCheck(
        'hmac_sha512(RFC4231 #1)',
        mac.hmac_sha512(key1, msg1),
        '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854'
      ),
      hexCheck(
        'hmac_sha512(RFC4231 #2)',
        mac.hmac_sha512(key2, msg2),
        '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737'
      ),
      hexCheck(
        'hmac_sha512(RFC4231 #4)',
        mac.hmac_sha512(key4, msg4),
        'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd'
      ),
      hexCheck(
        'hmac_sha512(RFC4231 #6, oversize key)',
        mac.hmac_sha512(key6, msg6),
        '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598'
      ),

      // Boundary
      check('hmac_sha256 empty key/msg has 32-byte output', () => {
        const t = mac.hmac_sha256(new Uint8Array(0), new Uint8Array(0));
        return t.length === 32;
      }),
      check('hmac_sha512 empty key/msg has 64-byte output', () => {
        const t = mac.hmac_sha512(new Uint8Array(0), new Uint8Array(0));
        return t.length === 64;
      }),
      check('hmac_sha256 deterministic', () =>
        eq(mac.hmac_sha256(key1, msg1), mac.hmac_sha256(key1, msg1))
      ),
      check('hmac_sha256 differs from hmac_sha512', () => {
        const a = mac.hmac_sha256(key1, msg1);
        const b = mac.hmac_sha512(key1, msg1).slice(0, 32);
        return !eq(a, b);
      }),
    ];
  },
};
