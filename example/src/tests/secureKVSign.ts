// secureKV signing surface — bip32 derivations on stored seeds and raw
// private-key slots. Verifies BIP-32 vec1 reaches the correct leaf,
// BIP-86 taproot tweak round-trips, ed25519 SLIP-10, ECDH parity with
// the standalone API, and slot-kind cross-rejection rules.

import {
  bip32,
  ecdsa,
  ed25519,
  hash,
  rng,
  schnorr,
  secureKV,
} from '@fintoda/react-native-crypto-lib';
import {
  ascii,
  check,
  eq,
  fromHex,
  throws,
  toHex,
  type TestCase,
  type TestGroup,
} from './harness';

const k = (s: string) => `tvs.${s}`;

export const secureKVSignGroup: TestGroup = {
  id: 'secureKVSign',
  title: 'secureKV signing',
  description: 'BIP-32 / BIP-86 / raw key signing on stored slots',
  build: async (): Promise<TestCase[]> => {
    try {
      await secureKV.clear();
    } catch {
      // ignore
    }

    // BIP-32 test vector 1
    const bip32Seed = fromHex('000102030405060708090a0b0c0d0e0f');
    const bip32MasterPubCompressed =
      '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2';
    const bip32LeafPath = "m/0'/1/2'/2/1000000000";
    const bip32LeafPubCompressed =
      '022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011';
    const bip32LeafPriv =
      '471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8';

    // BIP-86 Taproot
    const bip86Seed = fromHex(
      '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1' +
        '9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4'
    );
    const bip86Path = "m/86'/0'/0'/0/0";
    const bip86InternalXOnly =
      'cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115';
    const bip86OutputXOnly =
      'a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c';

    const digest = hash.sha256(ascii('the quick brown fox'));

    return [
      // ---- BIP-32 derivation correctness ---------------------------------
      check('bip32.getPublicKey(master) == BIP-32 vec1', async () => {
        await secureKV.bip32.setSeed(k('vec1'), bip32Seed);
        const got = await secureKV.bip32.getPublicKey(
          k('vec1'),
          'm',
          'secp256k1'
        );
        return toHex(got) === bip32MasterPubCompressed || `got ${toHex(got)}`;
      }),
      check('bip32.getPublicKey(deep path) == vec1', async () => {
        const got = await secureKV.bip32.getPublicKey(
          k('vec1'),
          bip32LeafPath,
          'secp256k1'
        );
        return toHex(got) === bip32LeafPubCompressed || `got ${toHex(got)}`;
      }),
      check('bip32.getPublicKey accepts numeric path', async () => {
        const numeric = await secureKV.bip32.getPublicKey(
          k('vec1'),
          [0x80000000],
          'secp256k1'
        );
        const stringy = await secureKV.bip32.getPublicKey(
          k('vec1'),
          "m/0'",
          'secp256k1'
        );
        return eq(numeric, stringy) || 'numeric vs string mismatch';
      }),
      check('bip32.signEcdsa verifies under derived pub', async () => {
        const sig = await secureKV.bip32.signEcdsa(
          k('vec1'),
          bip32LeafPath,
          digest,
          'secp256k1'
        );
        const pub = fromHex(bip32LeafPubCompressed);
        return ecdsa.verify(pub, sig.signature, digest);
      }),
      check(
        'bip32.signEcdsa == standalone ecdsa.sign(derivedPriv)',
        async () => {
          const sig = await secureKV.bip32.signEcdsa(
            k('vec1'),
            bip32LeafPath,
            digest,
            'secp256k1'
          );
          const refSig = ecdsa.sign(
            fromHex(bip32LeafPriv),
            digest,
            'secp256k1'
          );
          return eq(sig.signature, refSig.signature);
        }
      ),
      check(
        'bip32.fingerprint(master) == hash160(masterPub)[0..4]',
        async () => {
          const fp = await secureKV.bip32.fingerprint(
            k('vec1'),
            'm',
            'secp256k1'
          );
          const masterPub = fromHex(bip32MasterPubCompressed);
          const h = hash.hash160(masterPub);
          const expected =
            ((h[0]! << 24) >>> 0) |
            ((h[1]! << 16) >>> 0) |
            ((h[2]! << 8) >>> 0) |
            h[3]!;
          return fp >>> 0 === expected >>> 0 || `fp=${fp} exp=${expected}`;
        }
      ),

      // ---- Schnorr (BIP-340) on bip32 slot -------------------------------
      check('bip32.signSchnorr verifies under derived x-only', async () => {
        await secureKV.bip32.setSeed(k('bip86'), bip86Seed);
        const compressed = await secureKV.bip32.getPublicKey(
          k('bip86'),
          bip86Path,
          'secp256k1'
        );
        const xOnly = compressed.slice(1, 33);
        if (toHex(xOnly) !== bip86InternalXOnly) {
          return `derived x-only mismatch: ${toHex(xOnly)}`;
        }
        const sig = await secureKV.bip32.signSchnorr(
          k('bip86'),
          bip86Path,
          digest,
          new Uint8Array(32)
        );
        return schnorr.verify(fromHex(bip86InternalXOnly), sig, digest);
      }),
      check('bip32.signSchnorr non-zero aux verifies', async () => {
        const aux = rng.bytes(32);
        const compressed = await secureKV.bip32.getPublicKey(
          k('bip86'),
          bip86Path,
          'secp256k1'
        );
        const xOnly = compressed.slice(1, 33);
        const sig = await secureKV.bip32.signSchnorr(
          k('bip86'),
          bip86Path,
          digest,
          aux
        );
        return schnorr.verify(xOnly, sig, digest);
      }),

      // ---- Taproot (BIP-86) key-spend ------------------------------------
      check('bip32.signSchnorrTaproot verifies (BIP-86)', async () => {
        const sig = await secureKV.bip32.signSchnorrTaproot(
          k('bip86'),
          bip86Path,
          digest
        );
        return schnorr.verify(fromHex(bip86OutputXOnly), sig, digest);
      }),
      check('bip32.signSchnorrTaproot with merkleRoot verifies', async () => {
        const merkleRoot = hash.sha256(ascii('dummy script tree root'));
        const compressed = await secureKV.bip32.getPublicKey(
          k('bip86'),
          bip86Path,
          'secp256k1'
        );
        const xOnly = compressed.slice(1, 33);
        const tweaked = schnorr.tweakPublic(xOnly, merkleRoot).pub;
        const sig = await secureKV.bip32.signSchnorrTaproot(
          k('bip86'),
          bip86Path,
          digest,
          merkleRoot
        );
        return schnorr.verify(tweaked, sig, digest);
      }),

      // ---- BIP-32 ed25519 (SLIP-10) --------------------------------------
      check(
        'bip32.signEd25519 verifies under derived ed25519 pub',
        async () => {
          const path = "m/44'/60'/0'";
          const pub = await secureKV.bip32.getPublicKey(
            k('vec1'),
            path,
            'ed25519'
          );
          if (pub.length !== 32) return `pub length ${pub.length}`;
          const msg = ascii('hello ed25519');
          const sig = await secureKV.bip32.signEd25519(k('vec1'), path, msg);
          return ed25519.verify(pub, sig, msg);
        }
      ),

      // ---- bip32 ECDH ----------------------------------------------------
      check('bip32.ecdh matches standalone ecdsa.ecdh', async () => {
        const counterPriv = ecdsa.randomPrivate('secp256k1');
        const counterPub = ecdsa.getPublic(counterPriv, true, 'secp256k1');
        const sharedFromKV = await secureKV.bip32.ecdh(
          k('vec1'),
          bip32LeafPath,
          counterPub,
          'secp256k1'
        );
        const sharedFromRef = ecdsa.ecdh(
          fromHex(bip32LeafPriv),
          counterPub,
          'secp256k1'
        );
        return eq(sharedFromKV, sharedFromRef);
      }),

      // ---- bip32 nist256p1 ------------------------------------------------
      check('bip32 nist256p1 matches standalone bip32+ecdsa', async () => {
        const path = "m/0'/1";
        const root = bip32.fromSeed(bip32Seed, 'nist256p1');
        const node = bip32.derive(root, path);
        const refPub = ecdsa.getPublic(node.privateKey!, true, 'nist256p1');
        const kvPub = await secureKV.bip32.getPublicKey(
          k('vec1'),
          path,
          'nist256p1'
        );
        if (!eq(kvPub, refPub)) return `pub mismatch: ${toHex(kvPub)}`;
        const sig = await secureKV.bip32.signEcdsa(
          k('vec1'),
          path,
          digest,
          'nist256p1'
        );
        return ecdsa.verify(refPub, sig.signature, digest, 'nist256p1');
      }),

      // ---- uncompressed pubkeys ------------------------------------------
      check('bip32.getPublicKey compact=false returns 65 bytes', async () => {
        const uncompressed = await secureKV.bip32.getPublicKey(
          k('vec1'),
          bip32LeafPath,
          'secp256k1',
          false
        );
        if (uncompressed.length !== 65) return `length=${uncompressed.length}`;
        if (uncompressed[0] !== 0x04) return `prefix=${uncompressed[0]}`;
        const recompressed = ecdsa.readPublic(uncompressed, true, 'secp256k1');
        return toHex(recompressed) === bip32LeafPubCompressed;
      }),

      // ---- raw secp256k1 -------------------------------------------------
      check('raw.signEcdsa secp256k1 verifies', async () => {
        const priv = ecdsa.randomPrivate('secp256k1');
        const pub = ecdsa.getPublic(priv, true, 'secp256k1');
        await secureKV.raw.setPrivate(k('rawk1'), priv, 'secp256k1');
        const got = await secureKV.raw.getPublicKey(k('rawk1'));
        if (!eq(got, pub)) return `pub mismatch: ${toHex(got)}`;
        const sig = await secureKV.raw.signEcdsa(k('rawk1'), digest);
        return ecdsa.verify(pub, sig.signature, digest);
      }),
      check('raw.signEcdsa nist256p1 verifies', async () => {
        const priv = ecdsa.randomPrivate('nist256p1');
        const pub = ecdsa.getPublic(priv, true, 'nist256p1');
        await secureKV.raw.setPrivate(k('rawn'), priv, 'nist256p1');
        const sig = await secureKV.raw.signEcdsa(k('rawn'), digest);
        return ecdsa.verify(pub, sig.signature, digest, 'nist256p1');
      }),
      check('raw.signEd25519 verifies', async () => {
        const seed = rng.bytes(32);
        const pub = ed25519.getPublic(seed);
        await secureKV.raw.setPrivate(k('rawed'), seed, 'ed25519');
        const got = await secureKV.raw.getPublicKey(k('rawed'));
        if (!eq(got, pub)) return 'pub mismatch';
        const msg = ascii('raw ed25519 round-trip');
        const sig = await secureKV.raw.signEd25519(k('rawed'), msg);
        return ed25519.verify(pub, sig, msg);
      }),
      check('raw.signSchnorrTaproot verifies under tweaked pub', async () => {
        const priv = ecdsa.randomPrivate('secp256k1');
        const pubCompressed = ecdsa.getPublic(priv, true, 'secp256k1');
        const xOnly = pubCompressed.slice(1, 33);
        const tweaked = schnorr.tweakPublic(xOnly).pub;
        await secureKV.raw.setPrivate(k('rawtap'), priv, 'secp256k1');
        const sig = await secureKV.raw.signSchnorrTaproot(k('rawtap'), digest);
        return schnorr.verify(tweaked, sig, digest);
      }),
      check('raw.signSchnorr verifies under x-only pub', async () => {
        const priv = ecdsa.randomPrivate('secp256k1');
        const xOnly = ecdsa.getPublic(priv, true, 'secp256k1').slice(1, 33);
        await secureKV.raw.setPrivate(k('rawschnorr'), priv, 'secp256k1');
        const sig = await secureKV.raw.signSchnorr(
          k('rawschnorr'),
          digest,
          new Uint8Array(32)
        );
        return schnorr.verify(xOnly, sig, digest);
      }),
      check('raw.ecdh matches standalone ecdsa.ecdh', async () => {
        const priv = ecdsa.randomPrivate('secp256k1');
        const counterPriv = ecdsa.randomPrivate('secp256k1');
        const counterPub = ecdsa.getPublic(counterPriv, true, 'secp256k1');
        await secureKV.raw.setPrivate(k('rawecdh'), priv, 'secp256k1');
        const sharedFromKV = await secureKV.raw.ecdh(k('rawecdh'), counterPub);
        const sharedFromRef = ecdsa.ecdh(priv, counterPub, 'secp256k1');
        return eq(sharedFromKV, sharedFromRef);
      }),
      check('raw.getPublicKey compact=false returns 65 bytes', async () => {
        const priv = ecdsa.randomPrivate('secp256k1');
        await secureKV.raw.setPrivate(k('rawunc'), priv, 'secp256k1');
        const compact = await secureKV.raw.getPublicKey(k('rawunc'));
        const uncompressed = await secureKV.raw.getPublicKey(
          k('rawunc'),
          false
        );
        if (uncompressed.length !== 65) return `length=${uncompressed.length}`;
        const recompressed = ecdsa.readPublic(uncompressed, true, 'secp256k1');
        return eq(recompressed, compact);
      }),

      // ---- cross-slot mismatches -----------------------------------------
      throws('bip32 op on a generic blob slot throws', async () => {
        await secureKV.set(k('blob'), ascii('x'));
        await secureKV.bip32.getPublicKey(k('blob'), 'm', 'secp256k1');
      }),
      throws('get on a SEED slot throws', async () => {
        await secureKV.bip32.setSeed(k('seedslot'), bip86Seed);
        await secureKV.get(k('seedslot'));
      }),
      throws('raw op on a SEED slot throws', async () => {
        await secureKV.bip32.setSeed(k('seedslot2'), bip86Seed);
        await secureKV.raw.signEcdsa(k('seedslot2'), digest);
      }),
      throws('raw op on a generic blob slot throws', async () => {
        await secureKV.set(k('blob2'), ascii('x'));
        await secureKV.raw.signEcdsa(k('blob2'), digest);
      }),
      throws('bip32 op on a RAW slot throws', async () => {
        const priv = ecdsa.randomPrivate('secp256k1');
        await secureKV.raw.setPrivate(k('rawXbip'), priv, 'secp256k1');
        await secureKV.bip32.getPublicKey(k('rawXbip'), 'm', 'secp256k1');
      }),
      throws('get on a RAW slot throws', async () => {
        const priv = ecdsa.randomPrivate('secp256k1');
        await secureKV.raw.setPrivate(k('rawXget'), priv, 'secp256k1');
        await secureKV.get(k('rawXget'));
      }),
      throws('raw.signEd25519 on secp256k1 slot throws', async () => {
        const priv = ecdsa.randomPrivate('secp256k1');
        await secureKV.raw.setPrivate(k('rawk1b'), priv, 'secp256k1');
        await secureKV.raw.signEd25519(k('rawk1b'), ascii('x'));
      }),
      throws('raw.signSchnorr on ed25519 slot throws', async () => {
        await secureKV.raw.setPrivate(k('rawedb'), rng.bytes(32), 'ed25519');
        await secureKV.raw.signSchnorr(k('rawedb'), digest);
      }),

      // ---- size / format validation --------------------------------------
      throws('bip32.setSeed below 16 bytes throws', async () => {
        await secureKV.bip32.setSeed(k('badseed'), new Uint8Array(8));
      }),
      throws('bip32.setSeed above 64 bytes throws', async () => {
        await secureKV.bip32.setSeed(k('badseed'), new Uint8Array(65));
      }),
      throws('raw.setPrivate wrong size throws', async () => {
        await secureKV.raw.setPrivate(
          k('badpriv'),
          new Uint8Array(31),
          'secp256k1'
        );
      }),
      throws('bip32.signEcdsa missing slot throws', async () => {
        await secureKV.bip32.signEcdsa(k('nope'), 'm', digest, 'secp256k1');
      }),
      throws('raw.setPrivate zero scalar rejected (secp256k1)', async () => {
        await secureKV.raw.setPrivate(
          k('zero'),
          new Uint8Array(32),
          'secp256k1'
        );
      }),
      throws(
        'raw.setPrivate out-of-range scalar rejected (secp256k1)',
        async () => {
          await secureKV.raw.setPrivate(
            k('toobig'),
            new Uint8Array(32).fill(0xff),
            'secp256k1'
          );
        }
      ),

      // Cleanup
      check('final cleanup', async () => {
        await secureKV.clear();
        return (await secureKV.list()).length === 0;
      }),
    ];
  },
};
