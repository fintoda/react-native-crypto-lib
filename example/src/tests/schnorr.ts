// BIP-340 Schnorr — official test vectors plus tweak round-trips.

import { hash, schnorr } from '@fintoda/react-native-crypto-lib';
import { ascii, check, eq, fromHex, hexCheck, type TestGroup } from './harness';

export const schnorrGroup: TestGroup = {
  id: 'schnorr',
  title: 'schnorr',
  description: 'BIP-340 sign/verify + taproot tweak',
  build: () => {
    // BIP-340 vector 0
    const sk0 = fromHex('00'.repeat(31) + '03');
    const msg0 = new Uint8Array(32);
    const aux0 = new Uint8Array(32);
    const expPub0 =
      'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
    const expSig0 =
      'e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0';

    const sk1 = fromHex(
      'b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef'
    );
    const msg1 = fromHex(
      '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89'
    );
    const aux1 = fromHex('00'.repeat(31) + '01');

    const sk2 = fromHex(
      'c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9'
    );
    const msg2 = fromHex(
      '7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c'
    );
    const aux2 = fromHex(
      'c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906'
    );

    const pub0 = schnorr.getPublic(sk0);
    const sig0 = schnorr.sign(sk0, msg0, aux0);
    const pub1 = schnorr.getPublic(sk1);
    const sig1 = schnorr.sign(sk1, msg1, aux1);
    const pub2 = schnorr.getPublic(sk2);
    const sig2 = schnorr.sign(sk2, msg2, aux2);

    return [
      // Vector 0
      hexCheck('pub(BIP340 #0)', pub0, expPub0),
      hexCheck('sig(BIP340 #0)', sig0, expSig0),
      check('verify(BIP340 #0)', () => schnorr.verify(pub0, sig0, msg0)),

      // Vector 1
      check('#1 pub length 32', () => pub1.length === 32),
      check('#1 sign/verify', () => schnorr.verify(pub1, sig1, msg1)),
      check('#1 deterministic', () => eq(sig1, schnorr.sign(sk1, msg1, aux1))),

      // Vector 2
      check('#2 pub length 32', () => pub2.length === 32),
      check('#2 sign/verify', () => schnorr.verify(pub2, sig2, msg2)),
      check('#2 deterministic', () => eq(sig2, schnorr.sign(sk2, msg2, aux2))),

      // Tampering
      check('verify rejects tampered sig (bit flip)', () => {
        const bad = sig0.slice();
        bad[0]! ^= 1;
        return !schnorr.verify(pub0, bad, msg0);
      }),
      check('verify rejects tampered msg', () => {
        const bad = msg0.slice();
        bad[0]! ^= 1;
        return !schnorr.verify(pub0, sig0, bad);
      }),
      check(
        'verify rejects sig under wrong pub',
        () => !schnorr.verify(pub1, sig0, msg0)
      ),

      // verifyPublic — only x-only points on the curve are accepted.
      check('verifyPublic(valid)', () => schnorr.verifyPublic(pub0)),
      check(
        'verifyPublic(0xff..) false',
        () => !schnorr.verifyPublic(new Uint8Array(32).fill(0xff))
      ),
      check(
        'verifyPublic(zero) false',
        () => !schnorr.verifyPublic(new Uint8Array(32))
      ),

      // Taproot tweak (BIP-341 / BIP-86 plumbing)
      check('tweakPublic length 32 + parity in {0,1}', () => {
        const tw = schnorr.tweakPublic(pub0);
        return tw.pub.length === 32 && (tw.parity === 0 || tw.parity === 1);
      }),
      check('tweakPrivate -> tweakPublic consistency', () => {
        const tweakedPub = schnorr.tweakPublic(pub0);
        const tweakedPriv = schnorr.tweakPrivate(sk0);
        const derivedPub = schnorr.getPublic(tweakedPriv);
        return eq(tweakedPub.pub, derivedPub);
      }),
      check('tweakPublic with merkle root differs from no-merkle', () => {
        const root = hash.sha256(ascii('tap root'));
        const a = schnorr.tweakPublic(pub0).pub;
        const b = schnorr.tweakPublic(pub0, root).pub;
        return !eq(a, b);
      }),
      check('tweakPublic+tweakPrivate sign verifies under tweaked pub', () => {
        const merkleRoot = hash.sha256(ascii('script root'));
        const tweakedPub = schnorr.tweakPublic(pub0, merkleRoot);
        const tweakedPriv = schnorr.tweakPrivate(sk0, merkleRoot);
        const sig = schnorr.sign(tweakedPriv, msg0, aux0);
        return schnorr.verify(tweakedPub.pub, sig, msg0);
      }),
    ];
  },
};
