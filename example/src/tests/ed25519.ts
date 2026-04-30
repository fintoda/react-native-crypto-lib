// RFC 8032 Ed25519 vectors and RFC 7748 X25519 (curve25519) DH.

import { ed25519, x25519 } from '@fintoda/react-native-crypto-lib';
import { ascii, check, eq, fromHex, hexCheck, type TestGroup } from './harness';

export const ed25519Group: TestGroup = {
  id: 'ed25519',
  title: 'ed25519 / x25519',
  description: 'RFC 8032 Ed25519 + RFC 7748 X25519',
  build: () => {
    // RFC 8032 Test 1
    const sk1 = fromHex(
      '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
    );
    const expPub1 =
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
    const expSig1 =
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';

    // RFC 8032 Test 2
    const sk2 = fromHex(
      '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'
    );
    const msg2 = new Uint8Array([0x72]);
    const expPub2 =
      '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';
    const expSig2 =
      '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00';

    // RFC 8032 Test 3
    const sk3 = fromHex(
      'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7'
    );
    const msg3 = fromHex('af82');
    const expPub3 =
      'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025';
    const expSig3 =
      '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a';

    const empty = new Uint8Array(0);
    const pub1 = ed25519.getPublic(sk1);
    const sig1 = ed25519.sign(sk1, empty);
    const pub2 = ed25519.getPublic(sk2);
    const sig2 = ed25519.sign(sk2, msg2);
    const pub3 = ed25519.getPublic(sk3);
    const sig3 = ed25519.sign(sk3, msg3);

    return [
      // Ed25519
      hexCheck('ed25519 pub(#1)', pub1, expPub1),
      hexCheck('ed25519 sig(#1, empty msg)', sig1, expSig1),
      check('ed25519 verify(#1)', () => ed25519.verify(pub1, sig1, empty)),
      check('ed25519 sign(#1) deterministic', () =>
        eq(sig1, ed25519.sign(sk1, empty))
      ),

      hexCheck('ed25519 pub(#2)', pub2, expPub2),
      hexCheck('ed25519 sig(#2)', sig2, expSig2),
      check('ed25519 verify(#2)', () => ed25519.verify(pub2, sig2, msg2)),

      hexCheck('ed25519 pub(#3)', pub3, expPub3),
      hexCheck('ed25519 sig(#3)', sig3, expSig3),
      check('ed25519 verify(#3)', () => ed25519.verify(pub3, sig3, msg3)),

      // Tampering
      check('ed25519 verify rejects bit-flipped sig', () => {
        const bad = sig1.slice();
        bad[0]! ^= 1;
        return !ed25519.verify(pub1, bad, empty);
      }),
      check(
        'ed25519 verify rejects sig under wrong pub',
        () => !ed25519.verify(pub2, sig1, empty)
      ),
      check('ed25519 verify rejects bit-flipped msg', () => {
        const bad = msg2.slice();
        bad[0]! ^= 1;
        return !ed25519.verify(pub2, sig2, bad);
      }),

      // 1023-byte message — exercises blocked SHA-512 path
      check('ed25519 1023-byte msg round-trip', () => {
        const sk = fromHex('00'.repeat(31) + '01');
        const pub = ed25519.getPublic(sk);
        const msg = new Uint8Array(1023);
        for (let i = 0; i < msg.length; i++) msg[i] = i & 0xff;
        const s = ed25519.sign(sk, msg);
        return ed25519.verify(pub, s, msg);
      }),

      // Sizes
      check('ed25519 pub length=32', () => pub1.length === 32),
      check('ed25519 sig length=64', () => sig1.length === 64),

      // ---- X25519 ---------------------------------------------------------
      // RFC 7748 §6.1
      hexCheck(
        'x25519 pub(scalar=9)',
        x25519.getPublic(fromHex('09' + '00'.repeat(31))),
        '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079'
      ),
      check('x25519 ECDH commutativity', () => {
        const a = new Uint8Array(32).fill(0x11);
        const b = new Uint8Array(32).fill(0x22);
        return eq(
          x25519.scalarmult(a, x25519.getPublic(b)),
          x25519.scalarmult(b, x25519.getPublic(a))
        );
      }),
      check(
        'x25519 getPublic length=32',
        () => x25519.getPublic(new Uint8Array(32).fill(1)).length === 32
      ),
      check('x25519 scalarmult length=32', () => {
        const a = new Uint8Array(32).fill(0x33);
        const b = x25519.getPublic(new Uint8Array(32).fill(0x44));
        return x25519.scalarmult(a, b).length === 32;
      }),

      // ascii sanity (avoids unused-import warnings; the helper is generally useful)
      check('ascii("hi") length 2', () => ascii('hi').length === 2),
    ];
  },
};
