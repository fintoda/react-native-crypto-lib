// BIP-32 hierarchical deterministic key derivation. Vector 1 from the spec
// covers serialise/deserialise + 5-level hardened/normal mix; ed25519
// (SLIP-10) is exercised via fromSeed + derive.

import { bip32, ecdsa, hash } from '@fintoda/react-native-crypto-lib';
import { ascii, check, eq, fromHex, throws, type TestGroup } from './harness';

const XPUB = 0x0488b21e;
const XPRV = 0x0488ade4;

export const bip32Group: TestGroup = {
  id: 'bip32',
  title: 'bip32',
  description: 'BIP-32 master / derive / serialize, ed25519 SLIP-10',
  build: () => {
    // BIP-32 test vector 1
    const seed1 = fromHex('000102030405060708090a0b0c0d0e0f');
    const master = bip32.fromSeed(seed1);

    const expectedXpub =
      'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
    const expectedXprv =
      'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi';

    const path = "m/0'/1/2'/2/1000000000";
    const leaf = bip32.derive(master, path);

    return [
      // Master invariants
      check('master depth=0', () => master.depth === 0),
      check('master childNumber=0', () => master.childNumber === 0),
      check('master parentFingerprint=0', () => master.parentFingerprint === 0),
      check('master pub length=33', () => master.publicKey.length === 33),
      check('master priv length=32', () => master.privateKey?.length === 32),

      // Vector 1 serialisation
      check(
        'serialize xpub == vec1',
        () => bip32.serialize(master, XPUB, false) === expectedXpub
      ),
      check(
        'serialize xprv == vec1',
        () => bip32.serialize(master, XPRV, true) === expectedXprv
      ),

      // 5-level path
      check('derive depth=5', () => leaf.depth === 5),
      check('leaf sign/verify', () => {
        const d = hash.sha256(ascii('bip32 leaf'));
        const s = ecdsa.sign(leaf.privateKey!, d);
        return ecdsa.verify(ecdsa.getPublic(leaf.privateKey!), s.signature, d);
      }),

      // neuter
      check('neuter strips private key', () => {
        const pub = bip32.neuter(master);
        return pub.privateKey === null && eq(pub.publicKey, master.publicKey);
      }),

      // Round-trip
      check('serialize/deserialize xprv round-trip', () => {
        const xprv = bip32.serialize(master, XPRV, true);
        const restored = bip32.deserialize(xprv, XPRV, 'secp256k1', true);
        return restored.depth === 0 && eq(restored.publicKey, master.publicKey);
      }),
      check('serialize/deserialize xpub round-trip', () => {
        const xpub = bip32.serialize(master, XPUB, false);
        const restored = bip32.deserialize(xpub, XPUB, 'secp256k1', false);
        return (
          restored.privateKey === null &&
          eq(restored.publicKey, master.publicKey)
        );
      }),
      throws('deserialize wrong version throws', () => {
        const xpub = bip32.serialize(master, XPUB, false);
        bip32.deserialize(xpub, XPRV, 'secp256k1', true);
      }),

      // fingerprint determinism
      check('fingerprint deterministic + numeric', () => {
        const a = bip32.fingerprint(master);
        const b = bip32.fingerprint(master);
        return a === b && typeof a === 'number';
      }),

      // derivePublic equals neuter+derive on the public chain
      check('derivePublic matches private chain pub', () => {
        const neutered = bip32.neuter(master);
        const pubChild = bip32.derivePublic(neutered, 'm/0/1');
        const privChild = bip32.derive(master, 'm/0/1');
        return eq(pubChild.publicKey, privChild.publicKey);
      }),
      throws('derivePublic on hardened path throws', () =>
        bip32.derivePublic(bip32.neuter(master), "m/0'/1")
      ),

      // ed25519 SLIP-10
      check('ed25519 SLIP-10 master derives child', () => {
        const edMaster = bip32.fromSeed(seed1, 'ed25519');
        const edLeaf = bip32.derive(edMaster, "m/0'");
        return edLeaf.privateKey !== null && edLeaf.depth === 1;
      }),
      check('ed25519 SLIP-10 derive deterministic', () => {
        const edMaster = bip32.fromSeed(seed1, 'ed25519');
        const a = bip32.derive(edMaster, "m/44'/60'/0'");
        const b = bip32.derive(edMaster, "m/44'/60'/0'");
        return eq(a.publicKey, b.publicKey);
      }),

      // nist256p1
      check('nist256p1 fromSeed derives leaf', () => {
        const root = bip32.fromSeed(seed1, 'nist256p1');
        const node = bip32.derive(root, "m/0'/1");
        return node.privateKey !== null && node.depth === 2;
      }),

      // Bad path strings
      throws('derive("m/abc") rejects non-numeric component', () =>
        bip32.derive(master, 'm/abc')
      ),
      throws('derive negative index throws', () => bip32.derive(master, [-1])),
    ];
  },
};
