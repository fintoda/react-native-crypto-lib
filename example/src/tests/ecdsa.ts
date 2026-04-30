// ECDSA over secp256k1 + nist256p1.
// Sign/verify round-trips, deterministic-k determinism (RFC 6979),
// recovery, DER (de)serialisation, ECDH commutativity, cross-curve
// rejection, and a hand-picked set of tampering checks.

import { ecdsa, hash } from '@fintoda/react-native-crypto-lib';
import { ascii, check, eq, fromHex, throws, type TestGroup } from './harness';

export const ecdsaGroup: TestGroup = {
  id: 'ecdsa',
  title: 'ecdsa',
  description: 'secp256k1 + nist256p1 sign/verify/recover/ECDH',
  build: () => {
    const priv = fromHex(
      '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'
    );
    const priv2 = fromHex('aa'.repeat(32));
    const digest = hash.sha256(ascii('hello, ecdsa'));
    const pub = ecdsa.getPublic(priv);
    const pub65 = ecdsa.getPublic(priv, false);
    const sig = ecdsa.sign(priv, digest);
    const recovered = ecdsa.recover(sig.signature, digest, sig.recId);
    const der = ecdsa.sigToDer(sig.signature);
    const fromDer = ecdsa.sigFromDer(der);
    const pub2 = ecdsa.getPublic(priv2);

    const nistPub = ecdsa.getPublic(priv, true, 'nist256p1');
    const nistPub65 = ecdsa.getPublic(priv, false, 'nist256p1');
    const nistSig = ecdsa.sign(priv, digest, 'nist256p1');

    return [
      // ---- secp256k1 ------------------------------------------------------
      check('getPublic compressed length=33', () => pub.length === 33),
      check(
        'getPublic compressed prefix 02|03',
        () => pub[0] === 0x02 || pub[0] === 0x03
      ),
      check('getPublic uncompressed length=65', () => pub65.length === 65),
      check('getPublic uncompressed prefix=04', () => pub65[0] === 0x04),
      check('readPublic compress', () =>
        eq(ecdsa.readPublic(pub65, true), pub)
      ),
      check('readPublic decompress', () =>
        eq(ecdsa.readPublic(pub, false), pub65)
      ),

      check('validatePrivate(valid)', () => ecdsa.validatePrivate(priv)),
      check(
        'validatePrivate(zero) false',
        () => !ecdsa.validatePrivate(new Uint8Array(32))
      ),
      check(
        'validatePrivate(short=16) false',
        () => !ecdsa.validatePrivate(new Uint8Array(16))
      ),
      check(
        'validatePrivate(all 0xff) false (over curve order)',
        () => !ecdsa.validatePrivate(new Uint8Array(32).fill(0xff))
      ),

      check('validatePublic compressed', () => ecdsa.validatePublic(pub)),
      check('validatePublic uncompressed', () => ecdsa.validatePublic(pub65)),
      check('validatePublic bad prefix=05 false', () => {
        const bad = pub.slice();
        bad[0] = 0x05;
        return !ecdsa.validatePublic(bad);
      }),
      check(
        'validatePublic bad-length 32 false',
        () => !ecdsa.validatePublic(new Uint8Array(32).fill(0x02))
      ),

      check('sign/verify', () => ecdsa.verify(pub, sig.signature, digest)),
      check('verify rejects tampered sig', () => {
        const bad = sig.signature.slice();
        bad[10]! ^= 1;
        return !ecdsa.verify(pub, bad, digest);
      }),
      check(
        'verify rejects wrong digest',
        () => !ecdsa.verify(pub, sig.signature, hash.sha256(ascii('wrong')))
      ),
      check(
        'verify rejects swapped pub',
        () => !ecdsa.verify(pub2, sig.signature, digest)
      ),

      // RFC 6979 deterministic-k: the same input must produce identical sigs.
      check('sign deterministic (RFC 6979)', () => {
        const a = ecdsa.sign(priv, digest);
        const b = ecdsa.sign(priv, digest);
        return eq(a.signature, b.signature) && a.recId === b.recId;
      }),

      // recId enumeration must produce a value that can be pub-compared.
      check('recover yields the original pub', () =>
        eq(ecdsa.readPublic(recovered, true), pub)
      ),

      check('sigToDer/sigFromDer round-trip', () => eq(fromDer, sig.signature)),
      check('sigToDer length 70±2', () => der.length >= 68 && der.length <= 72),
      check('sigFromDer rejects garbage', () => {
        try {
          ecdsa.sigFromDer(new Uint8Array([0xde, 0xad]));
          return false;
        } catch {
          return true;
        }
      }),

      check('ecdh commutativity', () =>
        eq(ecdsa.ecdh(priv, pub2), ecdsa.ecdh(priv2, pub))
      ),
      check('ecdh produces 33-byte compressed shared point', () => {
        const s = ecdsa.ecdh(priv, pub2);
        return (
          (s.length === 33 && (s[0] === 0x02 || s[0] === 0x03)) ||
          `len=${s.length} prefix=${s[0]}`
        );
      }),

      check('randomPrivate is valid', () => {
        const rp = ecdsa.randomPrivate();
        return rp.length === 32 && ecdsa.validatePrivate(rp);
      }),
      check('randomPrivate two calls differ', () => {
        const a = ecdsa.randomPrivate();
        const b = ecdsa.randomPrivate();
        return !eq(a, b);
      }),

      // ---- nist256p1 ------------------------------------------------------
      check('nist256p1 getPublic length=33', () => nistPub.length === 33),
      check(
        'nist256p1 getPublic uncompressed length=65',
        () => nistPub65.length === 65
      ),
      check('nist256p1 sign/verify', () =>
        ecdsa.verify(nistPub, nistSig.signature, digest, 'nist256p1')
      ),
      check(
        'nist256p1 cross-curve sigs differ',
        () => !eq(sig.signature, nistSig.signature)
      ),
      check(
        'nist256p1 cross-curve verify rejects',
        () => !ecdsa.verify(pub, nistSig.signature, digest)
      ),
      check('nist256p1 randomPrivate valid', () => {
        const rp = ecdsa.randomPrivate('nist256p1');
        return rp.length === 32 && ecdsa.validatePrivate(rp, 'nist256p1');
      }),

      // Bad lengths
      throws('sign rejects 31-byte digest', () =>
        ecdsa.sign(priv, new Uint8Array(31))
      ),
      throws('sign rejects 31-byte priv', () =>
        ecdsa.sign(new Uint8Array(31), digest)
      ),
    ];
  },
};
