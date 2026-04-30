// Low-level secp256k1 primitives: point/scalar arithmetic and the
// tiny-secp256k1 wrapper surface.

import {
  ecc,
  ecdsa,
  hash,
  tinySecp256k1,
} from '@fintoda/react-native-crypto-lib';
import { ascii, check, eq, fromHex, type TestGroup } from './harness';

export const eccGroup: TestGroup = {
  id: 'ecc',
  title: 'ecc / tiny-secp256k1',
  description: 'point + scalar arithmetic and tiny-secp256k1 adapter',
  build: () => {
    const priv = fromHex(
      '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'
    );
    const pub = ecdsa.getPublic(priv);
    const pub65 = ecdsa.getPublic(priv, false);
    const tweak = new Uint8Array(32).fill(0x07);
    const digest = hash.sha256(ascii('ecc test'));
    const one = new Uint8Array(32);
    one[31] = 1;

    return [
      // ---- ecc primitives ------------------------------------------------
      check('pointAdd compressed', () => {
        const sum = ecc.pointAdd(pub, pub);
        return sum !== null && sum.length === 33;
      }),
      check('pointAdd uncompressed', () => {
        const sum = ecc.pointAdd(pub, pub, false);
        return sum !== null && sum.length === 65;
      }),
      check('pointAdd P + (-P) === null', () => {
        const neg = ecc.privateNegate(priv);
        const negPub = ecdsa.getPublic(neg);
        return ecc.pointAdd(pub, negPub) === null;
      }),
      check('pointAddScalar matches privateAdd', () => {
        const tweaked = ecc.pointAddScalar(pub, tweak);
        const privTweaked = ecc.privateAdd(priv, tweak);
        return (
          tweaked !== null &&
          privTweaked !== null &&
          eq(tweaked, ecdsa.getPublic(privTweaked))
        );
      }),
      check('pointMultiply(pub, 1) == pub', () => {
        const r = ecc.pointMultiply(pub, one);
        return r !== null && eq(r, pub);
      }),
      check('privateAdd then privateSub returns priv', () => {
        const added = ecc.privateAdd(priv, tweak);
        if (!added) return false;
        const back = ecc.privateSub(added, tweak);
        return back !== null && eq(back, priv);
      }),
      check('privateNegate(privateNegate(x)) == x', () =>
        eq(ecc.privateNegate(ecc.privateNegate(priv)), priv)
      ),
      check('privateAdd(priv, -priv) === null (zero scalar)', () => {
        const neg = ecc.privateNegate(priv);
        return ecc.privateAdd(priv, neg) === null;
      }),
      check('xOnlyPointAddTweak yields 32-byte x-only', () => {
        const xonly = pub.slice(1);
        const tw = ecc.xOnlyPointAddTweak(xonly, tweak);
        return tw !== null && tw.xOnlyPubkey.length === 32;
      }),

      // ---- tiny-secp256k1 ------------------------------------------------
      check('tiny.isPoint compressed', () => tinySecp256k1.isPoint(pub)),
      check('tiny.isPoint uncompressed', () => tinySecp256k1.isPoint(pub65)),
      check(
        'tiny.isPoint(garbage) false',
        () => !tinySecp256k1.isPoint(new Uint8Array(33).fill(0xff))
      ),
      check(
        'tiny.isPointCompressed compressed/decompressed',
        () =>
          tinySecp256k1.isPointCompressed(pub) &&
          !tinySecp256k1.isPointCompressed(pub65)
      ),
      check('tiny.isXOnlyPoint length=32 valid', () =>
        tinySecp256k1.isXOnlyPoint(pub.slice(1))
      ),
      check('tiny.isPrivate(valid)', () => tinySecp256k1.isPrivate(priv)),
      check(
        'tiny.isPrivate(zero) false',
        () => !tinySecp256k1.isPrivate(new Uint8Array(32))
      ),
      check(
        'tiny.isPrivate(all-ff) false',
        () => !tinySecp256k1.isPrivate(new Uint8Array(32).fill(0xff))
      ),
      check('tiny.pointFromScalar matches getPublic', () => {
        const p = tinySecp256k1.pointFromScalar(priv);
        return p !== null && eq(p, pub);
      }),
      check(
        'tiny.pointCompress (decompress)',
        () =>
          eq(tinySecp256k1.pointCompress(pub65, true), pub) &&
          eq(tinySecp256k1.pointCompress(pub, false), pub65)
      ),
      check('tiny.pointMultiply(pub, 1) == pub', () => {
        const r = tinySecp256k1.pointMultiply(pub, one);
        return r !== null && eq(r, pub);
      }),
      check('tiny.privateAdd/Sub round-trip', () => {
        const added = tinySecp256k1.privateAdd(priv, tweak);
        if (!added) return false;
        const back = tinySecp256k1.privateSub(added, tweak);
        return back !== null && eq(back, priv);
      }),
      check('tiny.privateNegate involution', () =>
        eq(tinySecp256k1.privateNegate(tinySecp256k1.privateNegate(priv)), priv)
      ),

      check('tiny.sign/verify', () => {
        const s = tinySecp256k1.sign(digest, priv);
        return tinySecp256k1.verify(digest, pub, s);
      }),
      check('tiny.verify strict (low-S)', () => {
        const s = tinySecp256k1.sign(digest, priv);
        return tinySecp256k1.verify(digest, pub, s, true);
      }),
      check('tiny.verify rejects flipped sig', () => {
        const s = tinySecp256k1.sign(digest, priv);
        const bad = s.slice();
        bad[5]! ^= 1;
        return !tinySecp256k1.verify(digest, pub, bad);
      }),
      check('tiny.signRecoverable + recover', () => {
        const r = tinySecp256k1.signRecoverable(digest, priv);
        const rec = tinySecp256k1.recover(digest, r.signature, r.recoveryId);
        return rec !== null && eq(rec, pub);
      }),
      check('tiny.recover(uncompressed) length=65', () => {
        const r = tinySecp256k1.signRecoverable(digest, priv);
        const rec = tinySecp256k1.recover(
          digest,
          r.signature,
          r.recoveryId,
          false
        );
        return rec !== null && rec.length === 65;
      }),

      check(
        'tiny.xOnlyPointFromScalar length=32',
        () => tinySecp256k1.xOnlyPointFromScalar(priv).length === 32
      ),
      check('tiny.xOnlyPointFromPoint matches slice(1)', () => {
        const x = tinySecp256k1.xOnlyPointFromPoint(pub);
        return x.length === 32 && eq(x, pub.slice(1));
      }),
      check('tiny.xOnlyPointAddTweakCheck (correct parity)', () => {
        const x = tinySecp256k1.xOnlyPointFromPoint(pub);
        const tw = tinySecp256k1.xOnlyPointAddTweak(x, tweak);
        if (!tw) return false;
        return tinySecp256k1.xOnlyPointAddTweakCheck(
          x,
          tweak,
          tw.xOnlyPubkey,
          tw.parity
        );
      }),
      check('tiny.xOnlyPointAddTweakCheck rejects wrong parity', () => {
        const x = tinySecp256k1.xOnlyPointFromPoint(pub);
        const tw = tinySecp256k1.xOnlyPointAddTweak(x, tweak);
        if (!tw) return false;
        const wrong: 0 | 1 = tw.parity === 0 ? 1 : 0;
        return !tinySecp256k1.xOnlyPointAddTweakCheck(
          x,
          tweak,
          tw.xOnlyPubkey,
          wrong
        );
      }),
      check('tiny.signSchnorr/verifySchnorr', () => {
        const s = tinySecp256k1.signSchnorr(digest, priv);
        const x = tinySecp256k1.xOnlyPointFromScalar(priv);
        return s.length === 64 && tinySecp256k1.verifySchnorr(digest, x, s);
      }),
    ];
  },
};
