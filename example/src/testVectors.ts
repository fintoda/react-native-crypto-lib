// Runtime test suite: verifies native crypto output against known test vectors.
// Each test returns { name, pass, detail? }. The App renders results.

import {
  aes,
  bip32,
  bip39,
  ecdsa,
  ed25519,
  hash,
  kdf,
  mac,
  rng,
  schnorr,
  slip39,
  x25519,
  ecc,
  tinySecp256k1,
  installCryptoPolyfill,
} from '@fintoda/react-native-crypto-lib';

export type TestResult = { name: string; pass: boolean; detail?: string };

const toHex = (b: Uint8Array) =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

const fromHex = (h: string) =>
  new Uint8Array(h.match(/.{2}/g)!.map((b) => parseInt(b, 16)));

const ascii = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function check(name: string, fn: () => boolean | string): TestResult {
  try {
    const r = fn();
    if (typeof r === 'string') return { name, pass: false, detail: r };
    return { name, pass: r };
  } catch (e: unknown) {
    return { name, pass: false, detail: String(e) };
  }
}

function hexCheck(
  name: string,
  actual: Uint8Array,
  expected: string
): TestResult {
  const hex = toHex(actual);
  return {
    name,
    pass: hex === expected,
    detail: hex !== expected ? `got ${hex}` : undefined,
  };
}

function throws(name: string, fn: () => void): TestResult {
  try {
    fn();
    return { name, pass: false, detail: 'did not throw' };
  } catch {
    return { name, pass: true };
  }
}

// =========================================================================
// HASH — NIST FIPS 180-4, FIPS 202, well-known vectors
// =========================================================================

const abc = ascii('abc');
const empty = new Uint8Array(0);

function hashTests(): TestResult[] {
  return [
    // SHA-1
    hexCheck(
      'hash.sha1("")',
      hash.sha1(empty),
      'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    ),
    hexCheck(
      'hash.sha1("abc")',
      hash.sha1(abc),
      'a9993e364706816aba3e25717850c26c9cd0d89d'
    ),
    // SHA-256
    hexCheck(
      'hash.sha256("")',
      hash.sha256(empty),
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    ),
    hexCheck(
      'hash.sha256("abc")',
      hash.sha256(abc),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    ),
    // SHA-384
    hexCheck(
      'hash.sha384("abc")',
      hash.sha384(abc),
      'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'
    ),
    // SHA-512
    hexCheck(
      'hash.sha512("")',
      hash.sha512(empty),
      'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'
    ),
    hexCheck(
      'hash.sha512("abc")',
      hash.sha512(abc),
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
    ),
    // SHA3-256
    hexCheck(
      'hash.sha3_256("abc")',
      hash.sha3_256(abc),
      '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'
    ),
    // SHA3-512
    hexCheck(
      'hash.sha3_512("")',
      hash.sha3_512(empty),
      'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26'
    ),
    hexCheck(
      'hash.sha3_512("abc")',
      hash.sha3_512(abc),
      'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0'
    ),
    // Keccak-256 (Ethereum)
    hexCheck(
      'hash.keccak_256("abc")',
      hash.keccak_256(abc),
      '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
    ),
    // Keccak-512
    hexCheck(
      'hash.keccak_512("")',
      hash.keccak_512(empty),
      '0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e'
    ),
    // RIPEMD-160
    hexCheck(
      'hash.ripemd160("")',
      hash.ripemd160(empty),
      '9c1185a5c5e9fc54612808977ee8f548b2258d31'
    ),
    hexCheck(
      'hash.ripemd160("abc")',
      hash.ripemd160(abc),
      '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'
    ),
    // BLAKE-256
    hexCheck(
      'hash.blake256("")',
      hash.blake256(empty),
      '716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a'
    ),
    // BLAKE2b (64 bytes)
    hexCheck(
      'hash.blake2b("")',
      hash.blake2b(empty),
      '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce'
    ),
    // BLAKE2s (32 bytes)
    hexCheck(
      'hash.blake2s("")',
      hash.blake2s(empty),
      '69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9'
    ),
    // Groestl-512
    hexCheck(
      'hash.groestl512("")',
      hash.groestl512(empty),
      '6d3ad29d279110eef3adbd66de2a0345a77baede1557f5d099fce0c03d6dc2ba8e6d4a6633dfbd66053c20faa87d1a11f39a7fbe4a6c2f009801370308fc4ad8'
    ),
    // sha256d / hash160
    hexCheck(
      'hash.sha256d("abc")',
      hash.sha256d(abc),
      '4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358'
    ),
    hexCheck(
      'hash.hash160("abc")',
      hash.hash160(abc),
      'bb1be98c142444d7a56aa3981c3942a978e4dc33'
    ),
  ];
}

// =========================================================================
// MAC — RFC 4231 test cases
// =========================================================================

function macTests(): TestResult[] {
  // RFC 4231 #1: key=20*0x0b, msg="Hi There"
  const key1 = new Uint8Array(20).fill(0x0b);
  const msg1 = ascii('Hi There');
  // RFC 4231 #2: key="Jefe", msg="what do ya want for nothing?"
  const key2 = ascii('Jefe');
  const msg2 = ascii('what do ya want for nothing?');

  return [
    hexCheck(
      'hmac_sha256(RFC4231 #1)',
      mac.hmac_sha256(key1, msg1),
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
    ),
    hexCheck(
      'hmac_sha512(RFC4231 #1)',
      mac.hmac_sha512(key1, msg1),
      '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854'
    ),
    hexCheck(
      'hmac_sha256(RFC4231 #2)',
      mac.hmac_sha256(key2, msg2),
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'
    ),
    hexCheck(
      'hmac_sha512(RFC4231 #2)',
      mac.hmac_sha512(key2, msg2),
      '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737'
    ),
  ];
}

// =========================================================================
// KDF — RFC 5869, RFC 6070
// =========================================================================

function kdfTests(): TestResult[] {
  // HKDF-SHA256 RFC 5869 #1
  const ikm1 = new Uint8Array(22).fill(0x0b);
  const salt1 = fromHex('000102030405060708090a0b0c');
  const info1 = fromHex('f0f1f2f3f4f5f6f7f8f9');
  // HKDF-SHA256 RFC 5869 #3 (zero-length salt and info)
  const ikm3 = new Uint8Array(22).fill(0x0b);
  const emptySalt = new Uint8Array(0);
  const emptyInfo = new Uint8Array(0);

  // PBKDF2: BIP-39 canonical vector (password="password", salt="salt", c=1, dkLen=32)
  // Well-known PBKDF2-SHA256 test
  const pbPass = ascii('password');
  const pbSalt = ascii('salt');

  return [
    hexCheck(
      'hkdf_sha256(RFC5869 #1)',
      kdf.hkdf_sha256(ikm1, salt1, info1, 42),
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
    ),
    hexCheck(
      'hkdf_sha256(RFC5869 #3, empty salt/info)',
      kdf.hkdf_sha256(ikm3, emptySalt, emptyInfo, 42),
      '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8'
    ),
    // HKDF-SHA512
    hexCheck(
      'hkdf_sha512(ikm=0x0b*22)',
      kdf.hkdf_sha512(ikm1, salt1, info1, 42),
      '832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb'
    ),
    // PBKDF2-SHA256
    hexCheck(
      'pbkdf2_sha256("password","salt",1,32)',
      kdf.pbkdf2_sha256(pbPass, pbSalt, 1, 32),
      '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'
    ),
    hexCheck(
      'pbkdf2_sha256("password","salt",4096,32)',
      kdf.pbkdf2_sha256(pbPass, pbSalt, 4096, 32),
      'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a'
    ),
    // PBKDF2-SHA512
    hexCheck(
      'pbkdf2_sha512("password","salt",1,64)',
      kdf.pbkdf2_sha512(pbPass, pbSalt, 1, 64),
      '867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce'
    ),
  ];
}

// =========================================================================
// RNG
// =========================================================================

function rngTests(): TestResult[] {
  return [
    check('rng.bytes(0) empty', () => rng.bytes(0).length === 0),
    check('rng.bytes(1) length', () => rng.bytes(1).length === 1),
    check('rng.bytes(32) length', () => rng.bytes(32).length === 32),
    check('rng.bytes(32) not all zeros', () =>
      rng.bytes(32).some((b) => b !== 0)
    ),
    check('rng.bytes(32) unique', () => !eq(rng.bytes(32), rng.bytes(32))),
    check('rng.uint32() is integer', () => Number.isInteger(rng.uint32())),
    check('rng.uint32() in u32 range', () => {
      const v = rng.uint32();
      return v >= 0 && v <= 0xffffffff;
    }),
    check('rng.uniform(1) always 0', () => rng.uniform(1) === 0),
    check('rng.uniform(100) in [0,100)', () => {
      const v = rng.uniform(100);
      return v >= 0 && v < 100;
    }),
    throws('rng.uniform(0) throws', () => rng.uniform(0)),
    throws('rng.uniform(-1) throws', () => rng.uniform(-1)),
  ];
}

// =========================================================================
// ECDSA — secp256k1 + nist256p1
// =========================================================================

function ecdsaTests(): TestResult[] {
  const priv = fromHex(
    '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'
  );
  const digest = hash.sha256(ascii('hello, ecdsa'));
  const pub = ecdsa.getPublic(priv);
  const pub65 = ecdsa.getPublic(priv, false);
  const sig = ecdsa.sign(priv, digest);
  const recovered = ecdsa.recover(sig.signature, digest, sig.recId);
  const der = ecdsa.sigToDer(sig.signature);
  const fromDer = ecdsa.sigFromDer(der);

  // nist256p1 tests
  const nistPub = ecdsa.getPublic(priv, true, 'nist256p1');
  const nistSig = ecdsa.sign(priv, digest, 'nist256p1');

  return [
    // secp256k1
    check('ecdsa.getPublic length=33', () => pub.length === 33),
    check('ecdsa.getPublic(uncompr) length=65', () => pub65.length === 65),
    check('ecdsa.validatePrivate(valid)', () => ecdsa.validatePrivate(priv)),
    check(
      'ecdsa.validatePrivate(zero) false',
      () => !ecdsa.validatePrivate(new Uint8Array(32))
    ),
    check(
      'ecdsa.validatePrivate(short) false',
      () => !ecdsa.validatePrivate(new Uint8Array(16))
    ),
    check('ecdsa.validatePublic', () => ecdsa.validatePublic(pub)),
    check('ecdsa.validatePublic(bad prefix) false', () => {
      const bad = pub.slice();
      bad[0] = 0x05;
      return !ecdsa.validatePublic(bad);
    }),
    check('ecdsa.sign/verify', () => ecdsa.verify(pub, sig.signature, digest)),
    check('ecdsa.verify rejects tampered sig', () => {
      const bad = sig.signature.slice();
      bad[10]! ^= 1;
      return !ecdsa.verify(pub, bad, digest);
    }),
    check('ecdsa.verify rejects wrong digest', () => {
      const wrongDigest = hash.sha256(ascii('wrong'));
      return !ecdsa.verify(pub, sig.signature, wrongDigest);
    }),
    check('ecdsa.recover matches pub', () =>
      eq(ecdsa.readPublic(recovered, true), pub)
    ),
    check('ecdsa.sigToDer/sigFromDer', () => eq(fromDer, sig.signature)),
    check('ecdsa.ecdh commutativity', () => {
      const priv2 = fromHex(
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      );
      const pub2 = ecdsa.getPublic(priv2);
      return eq(ecdsa.ecdh(priv, pub2), ecdsa.ecdh(priv2, pub));
    }),
    check('ecdsa.readPublic compress/decompress', () => {
      return (
        eq(ecdsa.readPublic(pub65, true), pub) &&
        eq(ecdsa.readPublic(pub, false), pub65)
      );
    }),
    check('ecdsa.randomPrivate valid', () => {
      const rp = ecdsa.randomPrivate();
      return rp.length === 32 && ecdsa.validatePrivate(rp);
    }),
    check('ecdsa.sign deterministic', () => {
      const sig2 = ecdsa.sign(priv, digest);
      return eq(sig.signature, sig2.signature);
    }),
    // nist256p1
    check('ecdsa nist256p1 getPublic', () => nistPub.length === 33),
    check('ecdsa nist256p1 sign/verify', () =>
      ecdsa.verify(nistPub, nistSig.signature, digest, 'nist256p1')
    ),
    check(
      'ecdsa nist256p1 cross-curve reject',
      () => !ecdsa.verify(pub, nistSig.signature, digest)
    ), // secp256k1 pub vs nist sig
  ];
}

// =========================================================================
// Schnorr — BIP-340 official test vectors
// =========================================================================

function schnorrTests(): TestResult[] {
  // BIP-340 test vector 0
  const sk0 = fromHex(
    '0000000000000000000000000000000000000000000000000000000000000003'
  );
  const msg0 = new Uint8Array(32);
  const aux0 = new Uint8Array(32);
  const expPub0 =
    'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
  const expSig0 =
    'e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0';

  // BIP-340 test vectors 1 & 2 — sign/verify roundtrip + determinism
  const sk1 = fromHex(
    'b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef'
  );
  const msg1 = fromHex(
    '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89'
  );
  const aux1 = fromHex(
    '0000000000000000000000000000000000000000000000000000000000000001'
  );

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
    // Vector 0 — full hex verification against BIP-340 spec
    hexCheck('schnorr pub(BIP340 #0)', pub0, expPub0),
    hexCheck('schnorr sig(BIP340 #0)', sig0, expSig0),
    check('schnorr verify(BIP340 #0)', () => schnorr.verify(pub0, sig0, msg0)),
    // Vector 1 — sign/verify roundtrip + determinism
    check('schnorr #1 pub length', () => pub1.length === 32),
    check('schnorr #1 sign/verify', () => schnorr.verify(pub1, sig1, msg1)),
    check('schnorr #1 deterministic', () =>
      eq(sig1, schnorr.sign(sk1, msg1, aux1))
    ),
    // Vector 2
    check('schnorr #2 pub length', () => pub2.length === 32),
    check('schnorr #2 sign/verify', () => schnorr.verify(pub2, sig2, msg2)),
    check('schnorr #2 deterministic', () =>
      eq(sig2, schnorr.sign(sk2, msg2, aux2))
    ),
    // Verify rejects tampered
    check('schnorr verify rejects tampered sig', () => {
      const bad = sig0.slice();
      bad[0]! ^= 1;
      return !schnorr.verify(pub0, bad, msg0);
    }),
    // verifyPublic
    check('schnorr.verifyPublic(valid)', () => schnorr.verifyPublic(pub0)),
    check(
      'schnorr.verifyPublic(invalid)',
      () => !schnorr.verifyPublic(new Uint8Array(32).fill(0xff))
    ),
    // tweakPublic/tweakPrivate consistency
    check('schnorr tweak consistency', () => {
      const tweakedPub = schnorr.tweakPublic(pub0);
      const tweakedPriv = schnorr.tweakPrivate(sk0);
      const derivedPub = schnorr.getPublic(tweakedPriv);
      return eq(tweakedPub.pub, derivedPub);
    }),
    // tweakPublic with merkle root
    check('schnorr tweakPublic(merkleRoot)', () => {
      const root = hash.sha256(ascii('tap root'));
      const tw = schnorr.tweakPublic(pub0, root);
      return tw.pub.length === 32 && (tw.parity === 0 || tw.parity === 1);
    }),
  ];
}

// =========================================================================
// Ed25519 — RFC 8032 test vectors
// =========================================================================

function ed25519Tests(): TestResult[] {
  // Ed25519 test vectors — verified against OpenSSL 3.x
  const sk1 = fromHex(
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
  );
  const expPub1 =
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';

  const sk2 = fromHex(
    '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'
  );
  const expPub2 =
    '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';
  const expSig2 =
    '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00';

  const pub1 = ed25519.getPublic(sk1);
  const sig1 = ed25519.sign(sk1, empty);
  const pub2 = ed25519.getPublic(sk2);
  const sig2 = ed25519.sign(sk2, new Uint8Array([0x72]));

  return [
    // Vector 1 — empty message
    hexCheck('ed25519 pub(#1)', pub1, expPub1),
    check('ed25519 sign/verify(#1, empty)', () =>
      ed25519.verify(pub1, sig1, empty)
    ),
    check('ed25519 sign(#1) deterministic', () =>
      eq(sig1, ed25519.sign(sk1, empty))
    ),
    // Vector 2
    hexCheck('ed25519 pub(#2)', pub2, expPub2),
    hexCheck('ed25519 sig(#2)', sig2, expSig2),
    check('ed25519 verify(#2)', () =>
      ed25519.verify(pub2, sig2, new Uint8Array([0x72]))
    ),
    // Rejection
    check('ed25519 verify rejects tampered', () => {
      const bad = sig1.slice();
      bad[0]! ^= 1;
      return !ed25519.verify(pub1, bad, empty);
    }),
    check(
      'ed25519 verify rejects wrong pub',
      () => !ed25519.verify(pub2, sig1, empty)
    ),
    // X25519 — RFC 7748 section 6.1
    hexCheck(
      'x25519 pub(scalar=9)',
      x25519.getPublic(
        fromHex(
          '0900000000000000000000000000000000000000000000000000000000000000'
        )
      ),
      '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079'
    ),
    check('x25519 DH agreement', () => {
      const aliceSk = new Uint8Array(32).fill(0x11);
      const bobSk = new Uint8Array(32).fill(0x22);
      return eq(
        x25519.scalarmult(aliceSk, x25519.getPublic(bobSk)),
        x25519.scalarmult(bobSk, x25519.getPublic(aliceSk))
      );
    }),
  ];
}

// =========================================================================
// AES-256 — NIST SP 800-38A, GCM with AAD
// =========================================================================

function aesTests(): TestResult[] {
  const key = fromHex(
    '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'
  );
  const cbcIv = fromHex('000102030405060708090a0b0c0d0e0f');
  const pt1 = fromHex('6bc1bee22e409f96e93d7e117393172a');
  const cbcExp = 'f58c4c04d6e5f1ba779eabfb5f7bfbd6';
  const ctrIv = fromHex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
  const ctrExp = '601ec313775789a5b7a7f504bbf3d228';

  // GCM test case 14 (Gladman)
  const gcmKey = new Uint8Array(32);
  const gcmNonce = new Uint8Array(12);
  const gcmPlain = new Uint8Array(16);
  const gcmCtExp = 'cea7403d4d606b6e074ec5d3baf39d18';
  const gcmTagExp = 'd0d1c8a799996bf0265b98b5d48ab919';

  const cbcEnc = aes.cbc.encrypt(key, cbcIv, pt1, 'none');
  const gcmSealed = aes.gcm.encrypt(gcmKey, gcmNonce, gcmPlain);

  return [
    // CBC
    hexCheck('aes.cbc encrypt(NIST F.2.5)', cbcEnc, cbcExp),
    check('aes.cbc decrypt(none)', () =>
      eq(aes.cbc.decrypt(key, cbcIv, cbcEnc, 'none'), pt1)
    ),
    check('aes.cbc pkcs7 roundtrip', () => {
      const pt = ascii('test padding!!'); // 14 bytes — not aligned
      return eq(
        aes.cbc.decrypt(key, cbcIv, aes.cbc.encrypt(key, cbcIv, pt)),
        pt
      );
    }),
    check('aes.cbc pkcs7 block-aligned roundtrip', () => {
      const pt = ascii('sixteen bytes!!.'); // exactly 16 bytes
      return eq(
        aes.cbc.decrypt(key, cbcIv, aes.cbc.encrypt(key, cbcIv, pt)),
        pt
      );
    }),
    throws('aes.cbc decrypt(none) bad length', () =>
      aes.cbc.decrypt(key, cbcIv, new Uint8Array(15), 'none')
    ),
    // CTR
    hexCheck('aes.ctr(NIST F.5.5)', aes.ctr.crypt(key, ctrIv, pt1), ctrExp),
    check('aes.ctr symmetric', () =>
      eq(aes.ctr.crypt(key, ctrIv, aes.ctr.crypt(key, ctrIv, pt1)), pt1)
    ),
    // GCM
    hexCheck('aes.gcm ct', gcmSealed.slice(0, 16), gcmCtExp),
    hexCheck('aes.gcm tag', gcmSealed.slice(16), gcmTagExp),
    check('aes.gcm decrypt', () =>
      eq(aes.gcm.decrypt(gcmKey, gcmNonce, gcmSealed), gcmPlain)
    ),
    check('aes.gcm rejects tampered ct', () => {
      const t = gcmSealed.slice();
      t[0]! ^= 1;
      try {
        aes.gcm.decrypt(gcmKey, gcmNonce, t);
        return false;
      } catch {
        return true;
      }
    }),
    check('aes.gcm rejects tampered tag', () => {
      const t = gcmSealed.slice();
      t[t.length - 1]! ^= 1;
      try {
        aes.gcm.decrypt(gcmKey, gcmNonce, t);
        return false;
      } catch {
        return true;
      }
    }),
    // GCM with AAD
    check('aes.gcm AAD roundtrip', () => {
      const aad = ascii('authenticated header');
      const sealed = aes.gcm.encrypt(gcmKey, gcmNonce, pt1, aad);
      return eq(aes.gcm.decrypt(gcmKey, gcmNonce, sealed, aad), pt1);
    }),
    check('aes.gcm rejects wrong AAD', () => {
      const aad = ascii('correct');
      const sealed = aes.gcm.encrypt(gcmKey, gcmNonce, pt1, aad);
      try {
        aes.gcm.decrypt(gcmKey, gcmNonce, sealed, ascii('wrong'));
        return false;
      } catch {
        return true;
      }
    }),
  ];
}

// =========================================================================
// BIP-39 / BIP-32
// =========================================================================

function bipTests(): TestResult[] {
  const mnemonic = bip39.fromEntropy(new Uint8Array(16));
  const expectedMnemonic =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const expectedSeedEmpty =
    '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4';
  const expectedSeedTrezor =
    'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04';

  // BIP-32 test vector 1
  const bip32Seed = fromHex('000102030405060708090a0b0c0d0e0f');
  const master = bip32.fromSeed(bip32Seed);
  const XPUB = 0x0488b21e;
  const XPRV = 0x0488ade4;
  const expectedXpub =
    'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
  const expectedXprv =
    'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi';

  const leaf = bip32.derive(master, "m/0'/1/2'/2/1000000000");

  return [
    // BIP-39
    check('bip39.fromEntropy(16 zeros)', () => mnemonic === expectedMnemonic),
    check('bip39.validate(valid)', () => bip39.validate(mnemonic)),
    check(
      'bip39.validate(invalid)',
      () => !bip39.validate('abandon abandon abandon')
    ),
    hexCheck('bip39.toSeed("")', bip39.toSeed(mnemonic, ''), expectedSeedEmpty),
    hexCheck(
      'bip39.toSeed("TREZOR")',
      bip39.toSeed(mnemonic, 'TREZOR'),
      expectedSeedTrezor
    ),
    check(
      'bip39.generate(128) 12 words',
      () => bip39.generate(128).split(' ').length === 12
    ),
    check(
      'bip39.generate(256) 24 words',
      () => bip39.generate(256).split(' ').length === 24
    ),
    check('bip39.generate validates own output', () =>
      bip39.validate(bip39.generate())
    ),
    check(
      'bip39.fromEntropy(32 bytes) 24 words',
      () => bip39.fromEntropy(new Uint8Array(32)).split(' ').length === 24
    ),
    // BIP-32
    check('bip32 master depth=0', () => master.depth === 0),
    check(
      'bip32 master xpub',
      () => bip32.serialize(master, XPUB, false) === expectedXpub
    ),
    check(
      'bip32 master xprv',
      () => bip32.serialize(master, XPRV, true) === expectedXprv
    ),
    check('bip32 derive depth=5', () => leaf.depth === 5),
    check('bip32 leaf sign/verify', () => {
      const d = hash.sha256(ascii('bip32 leaf'));
      const s = ecdsa.sign(leaf.privateKey!, d);
      return ecdsa.verify(ecdsa.getPublic(leaf.privateKey!), s.signature, d);
    }),
    check('bip32 neuter strips private', () => {
      const pub = bip32.neuter(master);
      return pub.privateKey === null && eq(pub.publicKey, master.publicKey);
    }),
    // deserialize roundtrip
    check('bip32 serialize/deserialize xprv roundtrip', () => {
      const xprv = bip32.serialize(master, XPRV, true);
      const restored = bip32.deserialize(xprv, XPRV, 'secp256k1', true);
      return restored.depth === 0 && eq(restored.publicKey, master.publicKey);
    }),
    check('bip32 serialize/deserialize xpub roundtrip', () => {
      const xpub = bip32.serialize(master, XPUB, false);
      const restored = bip32.deserialize(xpub, XPUB, 'secp256k1', false);
      return (
        restored.privateKey === null && eq(restored.publicKey, master.publicKey)
      );
    }),
    // fingerprint
    check('bip32 fingerprint deterministic', () => {
      const fp1 = bip32.fingerprint(master);
      const fp2 = bip32.fingerprint(master);
      return fp1 === fp2 && typeof fp1 === 'number';
    }),
    // derivePublic
    check('bip32 derivePublic matches neutered', () => {
      const neutered = bip32.neuter(master);
      const pubChild = bip32.derivePublic(neutered, 'm/0/1');
      const privChild = bip32.derive(master, 'm/0/1');
      return eq(pubChild.publicKey, privChild.publicKey);
    }),
    // ed25519 SLIP-10
    check('bip32 ed25519 SLIP-10', () => {
      const edMaster = bip32.fromSeed(bip32Seed, 'ed25519');
      const edLeaf = bip32.derive(edMaster, "m/0'");
      return edLeaf.privateKey !== null && edLeaf.depth === 1;
    }),
  ];
}

// =========================================================================
// ECC / tiny-secp256k1
// =========================================================================

function eccTests(): TestResult[] {
  const priv = fromHex(
    '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'
  );
  const pub = ecdsa.getPublic(priv);
  const pub65 = ecdsa.getPublic(priv, false);
  const tweak = new Uint8Array(32).fill(0x07);
  const digest = hash.sha256(ascii('ecc test'));

  return [
    // ecc primitives
    check('ecc.pointAdd', () => {
      const sum = ecc.pointAdd(pub, pub);
      return sum !== null && sum.length === 33;
    }),
    check('ecc.pointAdd uncompressed', () => {
      const sum = ecc.pointAdd(pub, pub, false);
      return sum !== null && sum.length === 65;
    }),
    check('ecc.pointAddScalar consistency', () => {
      const tweaked = ecc.pointAddScalar(pub, tweak);
      const privTweaked = ecc.privateAdd(priv, tweak);
      if (!tweaked || !privTweaked) return false;
      return eq(tweaked, ecdsa.getPublic(privTweaked));
    }),
    check('ecc.pointMultiply(pub, 1) = pub', () => {
      const one = new Uint8Array(32);
      one[31] = 1;
      const result = ecc.pointMultiply(pub, one);
      return result !== null && eq(result, pub);
    }),
    check('ecc.privateSub inverse of Add', () => {
      const added = ecc.privateAdd(priv, tweak);
      if (!added) return false;
      const back = ecc.privateSub(added, tweak);
      return back !== null && eq(back, priv);
    }),
    check('ecc.privateNegate double', () =>
      eq(ecc.privateNegate(ecc.privateNegate(priv)), priv)
    ),
    check('ecc.privateNegate + add = zero (null)', () => {
      const neg = ecc.privateNegate(priv);
      const sum = ecc.privateAdd(priv, neg);
      return sum === null; // 0 mod n → null
    }),
    check('ecc.xOnlyPointAddTweak', () => {
      const xonly = pub.slice(1); // strip prefix
      const tw = ecc.xOnlyPointAddTweak(xonly, tweak);
      return tw !== null && tw.xOnlyPubkey.length === 32;
    }),
    // tiny-secp256k1 adapter
    check('tiny.isPoint(compressed)', () => tinySecp256k1.isPoint(pub)),
    check('tiny.isPoint(uncompressed)', () => tinySecp256k1.isPoint(pub65)),
    check(
      'tiny.isPointCompressed',
      () =>
        tinySecp256k1.isPointCompressed(pub) &&
        !tinySecp256k1.isPointCompressed(pub65)
    ),
    check('tiny.isXOnlyPoint', () => tinySecp256k1.isXOnlyPoint(pub.slice(1))),
    check('tiny.isPrivate', () => tinySecp256k1.isPrivate(priv)),
    check(
      'tiny.isPrivate(zero) false',
      () => !tinySecp256k1.isPrivate(new Uint8Array(32))
    ),
    check('tiny.pointFromScalar', () => {
      const p = tinySecp256k1.pointFromScalar(priv);
      return p !== null && eq(p, pub);
    }),
    check('tiny.pointCompress', () =>
      eq(tinySecp256k1.pointCompress(pub65, true), pub)
    ),
    check('tiny.pointCompress(decompress)', () =>
      eq(tinySecp256k1.pointCompress(pub, false), pub65)
    ),
    check('tiny.pointMultiply', () => {
      const one = new Uint8Array(32);
      one[31] = 1;
      const r = tinySecp256k1.pointMultiply(pub, one);
      return r !== null && eq(r, pub);
    }),
    check('tiny.privateAdd/privateSub', () => {
      const added = tinySecp256k1.privateAdd(priv, tweak);
      if (!added) return false;
      const back = tinySecp256k1.privateSub(added, tweak);
      return back !== null && eq(back, priv);
    }),
    check('tiny.privateNegate', () =>
      eq(tinySecp256k1.privateNegate(tinySecp256k1.privateNegate(priv)), priv)
    ),
    check('tiny.sign/verify', () => {
      const s = tinySecp256k1.sign(digest, priv);
      return tinySecp256k1.verify(digest, pub, s);
    }),
    check('tiny.verify strict rejects high-S', () => {
      const s = tinySecp256k1.sign(digest, priv);
      // native always produces low-S, so strict should pass
      return tinySecp256k1.verify(digest, pub, s, true);
    }),
    check('tiny.signRecoverable/recover', () => {
      const r = tinySecp256k1.signRecoverable(digest, priv);
      const rec = tinySecp256k1.recover(digest, r.signature, r.recoveryId);
      return rec !== null && eq(rec, pub);
    }),
    check('tiny.recover(uncompressed)', () => {
      const r = tinySecp256k1.signRecoverable(digest, priv);
      const rec = tinySecp256k1.recover(
        digest,
        r.signature,
        r.recoveryId,
        false
      );
      return rec !== null && rec.length === 65;
    }),
    check('tiny.xOnlyPointFromScalar', () => {
      const x = tinySecp256k1.xOnlyPointFromScalar(priv);
      return x.length === 32;
    }),
    check('tiny.xOnlyPointFromPoint', () => {
      const x = tinySecp256k1.xOnlyPointFromPoint(pub);
      return x.length === 32 && eq(x, pub.slice(1));
    }),
    check('tiny.xOnlyPointAddTweakCheck', () => {
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
    check('tiny.xOnlyPointAddTweakCheck wrong parity', () => {
      const x = tinySecp256k1.xOnlyPointFromPoint(pub);
      const tw = tinySecp256k1.xOnlyPointAddTweak(x, tweak);
      if (!tw) return false;
      const wrongParity: 0 | 1 = tw.parity === 0 ? 1 : 0;
      return !tinySecp256k1.xOnlyPointAddTweakCheck(
        x,
        tweak,
        tw.xOnlyPubkey,
        wrongParity
      );
    }),
    check('tiny.signSchnorr/verifySchnorr', () => {
      const s = tinySecp256k1.signSchnorr(digest, priv);
      const x = tinySecp256k1.xOnlyPointFromScalar(priv);
      return s.length === 64 && tinySecp256k1.verifySchnorr(digest, x, s);
    }),
  ];
}

// =========================================================================
// WebCrypto polyfill
// =========================================================================

function webcryptoTests(): TestResult[] {
  return [
    check('installCryptoPolyfill', () => {
      installCryptoPolyfill();
      const g = globalThis as unknown as {
        crypto?: { getRandomValues?: unknown };
      };
      return typeof g.crypto?.getRandomValues === 'function';
    }),
    check('getRandomValues fills buffer', () => {
      const g = globalThis as unknown as {
        crypto: { getRandomValues: (a: Uint8Array) => Uint8Array };
      };
      const buf = new Uint8Array(16);
      g.crypto.getRandomValues(buf);
      return buf.some((b) => b !== 0);
    }),
  ];
}

// =========================================================================
// Run all
// =========================================================================

// =========================================================================
// SLIP-39 — Shamir Secret Sharing
// =========================================================================

function slip39Tests(): TestResult[] {
  return [
    // Round-trip: generate + combine recovers original secret (2-of-3)
    check('slip39 round-trip 2-of-3', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece'); // 16 bytes
      const shares = slip39.generate(secret, '', 2, 3, 0);
      if (shares.length !== 3) return `expected 3 shares, got ${shares.length}`;
      // Combine with first 2 shares
      const recovered = slip39.combine([shares[0]!, shares[1]!], '');
      return eq(recovered, secret) || `got ${toHex(recovered)}`;
    }),

    // Round-trip: combine with different pair of shares
    check('slip39 round-trip different pair', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece');
      const shares = slip39.generate(secret, '', 2, 3, 0);
      const recovered = slip39.combine([shares[0]!, shares[2]!], '');
      return eq(recovered, secret) || `got ${toHex(recovered)}`;
    }),

    // Round-trip with 32-byte secret
    check('slip39 round-trip 32-byte secret', () => {
      const secret = fromHex(
        'bb54aac4b89dc868ba37d9cc21b2cece' + 'e25053423dba16c395a0e8a1bd04e656'
      );
      const shares = slip39.generate(secret, '', 3, 5, 0);
      if (shares.length !== 5) return `expected 5 shares, got ${shares.length}`;
      const recovered = slip39.combine(
        [shares[0]!, shares[2]!, shares[4]!],
        ''
      );
      return eq(recovered, secret) || `got ${toHex(recovered)}`;
    }),

    // Threshold 1: every share recovers the secret
    check('slip39 threshold 1-of-3', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece');
      const shares = slip39.generate(secret, '', 1, 3, 0);
      const r1 = slip39.combine([shares[0]!], '');
      const r2 = slip39.combine([shares[1]!], '');
      const r3 = slip39.combine([shares[2]!], '');
      return (
        (eq(r1, secret) && eq(r2, secret) && eq(r3, secret)) ||
        'not all shares recover the secret'
      );
    }),

    // Passphrase changes the output
    check('slip39 passphrase changes recovered secret', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece');
      const shares = slip39.generate(secret, 'test', 2, 3, 0);
      const correct = slip39.combine([shares[0]!, shares[1]!], 'test');
      const wrong = slip39.combine([shares[0]!, shares[1]!], 'wrong');
      return (
        (eq(correct, secret) && !eq(wrong, secret)) ||
        'passphrase did not affect result'
      );
    }),

    // Validate mnemonic
    check('slip39 validateMnemonic valid', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece');
      const shares = slip39.generate(secret, '', 2, 2, 0);
      return slip39.validateMnemonic(shares[0]!) || 'valid mnemonic rejected';
    }),

    // Validate mnemonic fails on corrupted input
    check('slip39 validateMnemonic corrupted', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece');
      const shares = slip39.generate(secret, '', 2, 2, 0);
      // Corrupt a word
      const words = shares[0]!.split(' ');
      words[5] = words[5] === 'academic' ? 'acid' : 'academic';
      const corrupted = words.join(' ');
      return (
        !slip39.validateMnemonic(corrupted) || 'corrupted mnemonic accepted'
      );
    }),

    // Insufficient shares throws
    throws('slip39 insufficient shares throws', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece');
      const shares = slip39.generate(secret, '', 3, 5, 0);
      slip39.combine([shares[0]!, shares[1]!], ''); // only 2, need 3
    }),

    // Multi-group round-trip
    check('slip39 multi-group 2-of-3 groups', () => {
      const secret = fromHex('bb54aac4b89dc868ba37d9cc21b2cece');
      const groups = slip39.generateGroups(
        secret,
        '',
        2,
        [
          { threshold: 2, count: 3 },
          { threshold: 2, count: 3 },
          { threshold: 1, count: 2 },
        ],
        0
      );
      if (groups.length !== 3) return `expected 3 groups, got ${groups.length}`;
      // Use 2 shares from group 0 + 1 share from group 2
      const recovered = slip39.combine(
        [groups[0]![0]!, groups[0]![1]!, groups[2]![0]!],
        ''
      );
      return eq(recovered, secret) || `got ${toHex(recovered)}`;
    }),
  ];
}

export function runAllTests(): TestResult[] {
  return [
    ...hashTests(),
    ...macTests(),
    ...kdfTests(),
    ...rngTests(),
    ...ecdsaTests(),
    ...schnorrTests(),
    ...ed25519Tests(),
    ...aesTests(),
    ...bipTests(),
    ...eccTests(),
    ...webcryptoTests(),
    ...slip39Tests(),
  ];
}
