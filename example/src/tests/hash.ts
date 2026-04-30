// Hash function vectors — NIST FIPS 180-4 / FIPS 202, RIPEMD spec, BLAKE
// reference outputs. Adds composite-hash sanity (sha256d, hash160) and
// determinism / variable-length checks alongside the canonical fixtures.

import { hash } from '@fintoda/react-native-crypto-lib';
import {
  ascii,
  check,
  eq,
  hexCheck,
  fromHex,
  type TestCase,
  type TestGroup,
} from './harness';

const empty = new Uint8Array(0);
const abc = ascii('abc');

// 1 million 'a' characters — NIST canonical long-message vector for SHA-1
// and SHA-256. We materialise it lazily inside individual tests rather than
// at module load to avoid a 1MB allocation when the menu opens.

export const hashGroup: TestGroup = {
  id: 'hash',
  title: 'hash',
  description: 'SHA-1/2/3, Keccak, RIPEMD-160, BLAKE, Groestl + composites',
  build: (): TestCase[] => [
    // SHA-1
    hexCheck(
      'sha1("")',
      hash.sha1(empty),
      'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    ),
    hexCheck(
      'sha1("abc")',
      hash.sha1(abc),
      'a9993e364706816aba3e25717850c26c9cd0d89d'
    ),
    hexCheck(
      'sha1(56-byte msg)',
      hash.sha1(
        ascii('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')
      ),
      '84983e441c3bd26ebaae4aa1f95129e5e54670f1'
    ),

    // SHA-256
    hexCheck(
      'sha256("")',
      hash.sha256(empty),
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    ),
    hexCheck(
      'sha256("abc")',
      hash.sha256(abc),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    ),
    hexCheck(
      'sha256(56-byte msg)',
      hash.sha256(
        ascii('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')
      ),
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'
    ),
    hexCheck(
      'sha256(1MB of "a")',
      hash.sha256(new Uint8Array(1_000_000).fill(0x61)),
      'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0'
    ),

    // SHA-384
    hexCheck(
      'sha384("")',
      hash.sha384(empty),
      '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b'
    ),
    hexCheck(
      'sha384("abc")',
      hash.sha384(abc),
      'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'
    ),

    // SHA-512
    hexCheck(
      'sha512("")',
      hash.sha512(empty),
      'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'
    ),
    hexCheck(
      'sha512("abc")',
      hash.sha512(abc),
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
    ),

    // SHA-3 (FIPS 202)
    hexCheck(
      'sha3_256("")',
      hash.sha3_256(empty),
      'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'
    ),
    hexCheck(
      'sha3_256("abc")',
      hash.sha3_256(abc),
      '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'
    ),
    hexCheck(
      'sha3_512("")',
      hash.sha3_512(empty),
      'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26'
    ),
    hexCheck(
      'sha3_512("abc")',
      hash.sha3_512(abc),
      'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0'
    ),

    // Keccak (Ethereum padding) — pre-FIPS variant
    hexCheck(
      'keccak_256("")',
      hash.keccak_256(empty),
      'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    ),
    hexCheck(
      'keccak_256("abc")',
      hash.keccak_256(abc),
      '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
    ),
    hexCheck(
      'keccak_512("")',
      hash.keccak_512(empty),
      '0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e'
    ),

    // RIPEMD-160 — three reference vectors from the spec
    hexCheck(
      'ripemd160("")',
      hash.ripemd160(empty),
      '9c1185a5c5e9fc54612808977ee8f548b2258d31'
    ),
    hexCheck(
      'ripemd160("abc")',
      hash.ripemd160(abc),
      '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'
    ),
    hexCheck(
      'ripemd160("message digest")',
      hash.ripemd160(ascii('message digest')),
      '5d0689ef49d2fae572b881b123a85ffa21595f36'
    ),

    // BLAKE family
    hexCheck(
      'blake256("")',
      hash.blake256(empty),
      '716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a'
    ),
    hexCheck(
      'blake2b("")',
      hash.blake2b(empty),
      '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce'
    ),
    hexCheck(
      'blake2s("")',
      hash.blake2s(empty),
      '69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9'
    ),

    // Groestl-512
    hexCheck(
      'groestl512("")',
      hash.groestl512(empty),
      '6d3ad29d279110eef3adbd66de2a0345a77baede1557f5d099fce0c03d6dc2ba8e6d4a6633dfbd66053c20faa87d1a11f39a7fbe4a6c2f009801370308fc4ad8'
    ),

    // Composite hashes (Bitcoin-style)
    hexCheck(
      'sha256d("abc")',
      hash.sha256d(abc),
      '4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358'
    ),
    check('sha256d == sha256(sha256(x))', () =>
      eq(hash.sha256d(abc), hash.sha256(hash.sha256(abc)))
    ),
    hexCheck(
      'hash160("abc")',
      hash.hash160(abc),
      'bb1be98c142444d7a56aa3981c3942a978e4dc33'
    ),
    check('hash160 == ripemd160(sha256(x))', () =>
      eq(hash.hash160(abc), hash.ripemd160(hash.sha256(abc)))
    ),

    // Determinism + variable length
    check('sha256 deterministic', () => eq(hash.sha256(abc), hash.sha256(abc))),
    check(
      'sha256 differs across inputs',
      () => !eq(hash.sha256(abc), hash.sha256(ascii('abd')))
    ),
    check('sha256 size invariants', () => {
      for (const n of [0, 1, 31, 32, 33, 63, 64, 65, 127, 128, 129]) {
        const out = hash.sha256(new Uint8Array(n).fill(0xa5));
        if (out.length !== 32) return `len(${n}) -> ${out.length}`;
      }
      return true;
    }),
    check('blake2b output length 64', () => hash.blake2b(abc).length === 64),
    check('blake2s output length 32', () => hash.blake2s(abc).length === 32),
    check(
      'keccak_256 differs from sha3_256',
      () => !eq(hash.keccak_256(abc), hash.sha3_256(abc))
    ),

    // Byte-precision sanity: a single bit flip in input changes every byte
    // category (avalanche heuristic — at least 100 bits should differ).
    check('sha256 avalanche on 1-bit flip', () => {
      const a = hash.sha256(fromHex('00'.repeat(32)));
      const b = hash.sha256(fromHex('80' + '00'.repeat(31)));
      let diff = 0;
      for (let i = 0; i < 32; i++) {
        let x = (a[i]! ^ b[i]!) & 0xff;
        while (x) {
          diff += x & 1;
          x >>= 1;
        }
      }
      return diff >= 100 || `only ${diff} bits differ`;
    }),
  ],
};
