# @fintoda/react-native-crypto-lib

A comprehensive cryptography library for React Native, backed by a vendored
[trezor-crypto](https://github.com/trezor/trezor-firmware/tree/main/crypto)
C core and exposed as a synchronous JSI / Turbo Module. Zero-copy
`ArrayBuffer` transfers, no base64 bridge hops, no promises for operations
that don't need them.

- **Hashes**: SHA-1/256/384/512, SHA3-256/512, Keccak-256/512, RIPEMD-160,
  BLAKE-256, BLAKE2b, BLAKE2s, Groestl-512, SHA-256d, Hash160.
- **MAC / KDF**: HMAC-SHA256/512, PBKDF2-SHA256/512, HKDF-SHA256/512.
- **RNG**: cryptographically secure random bytes backed by
  the OS CSPRNG (`arc4random_buf` on iOS / Android NDK).
- **ECDSA** on secp256k1 and nist256p1: deterministic RFC 6979 signing,
  low-S normalisation, public-key recovery, ECDH, DER encode/decode.
- **Schnorr / BIP-340**: sign, verify, x-only keys, taproot tweak.
- **Ed25519** (RFC 8032) and **X25519** key exchange.
- **AES-256**: CBC (PKCS#7 or no padding), CTR, GCM with AAD.
- **BIP-39** mnemonics and **BIP-32 / SLIP-10** HD derivation on
  secp256k1, nist256p1, and ed25519.
- **`tiny-secp256k1@2.x` adapter** so `bitcoinjs-lib`, `bip32`, `ecpair`
  work out of the box without a WASM build.
- **WebCrypto `getRandomValues` polyfill** for packages that expect a
  browser-style `crypto` global (`@noble/*`, `uuid`, `ethers`, …).

## Requirements

- React Native with the **new architecture** enabled — the library is
  implemented as a C++ Turbo Module and does not register under the old
  bridge.
- **Hermes** JS engine.
- Developed and tested against **React Native 0.85**. Earlier versions
  down to 0.76 (the first release with stable C++ Turbo Module codegen)
  may work but are not tested; older than 0.76 definitely will not.
- iOS and Android minimums are whatever the host React Native version
  requires — this library adds no extra floor on top.

## Installation

```sh
yarn add @fintoda/react-native-crypto-lib
cd ios && pod install
```

No extra Metro / Babel configuration needed.

## Quick start

```ts
import {
  hash,
  ecdsa,
  bip39,
  bip32,
  installCryptoPolyfill,
} from '@fintoda/react-native-crypto-lib';

// Install the WebCrypto polyfill once, at app startup, so any library
// that pokes at globalThis.crypto.getRandomValues keeps working.
installCryptoPolyfill();

// BIP-39 → BIP-32 → ECDSA signing:
const mnemonic = bip39.generate(128);
const seed = bip39.toSeed(mnemonic, '');
const root = bip32.fromSeed(seed, 'secp256k1');
const leaf = bip32.derive(root, "m/44'/0'/0'/0/0");

const msg = hash.sha256(new TextEncoder().encode('hello'));
const { signature, recId } = ecdsa.sign(leaf.privateKey!, msg);
const ok = ecdsa.verify(leaf.publicKey, signature, msg);
```

All `Uint8Array` inputs are consumed zero-copy when they cover the whole
underlying buffer; otherwise the wrapper makes one defensive slice.

## Table of contents

- [hash](#hash) — one-shot digests
- [mac](#mac) — HMAC
- [kdf](#kdf) — PBKDF2 / HKDF
- [rng](#rng) — secure random
- [ecdsa](#ecdsa) — secp256k1 / nist256p1
- [schnorr](#schnorr) — BIP-340
- [ed25519 / x25519](#ed25519--x25519)
- [ecc](#ecc) — low-level secp256k1 primitives
- [tinySecp256k1](#tinysecp256k1) — bitcoinjs adapter
- [aes](#aes) — AES-256 CBC / CTR / GCM
- [bip39](#bip39) — mnemonics
- [bip32](#bip32) — HD derivation (SLIP-10)
- [webcrypto](#webcrypto) — getRandomValues polyfill
- [Compatibility notes](#compatibility-notes)

---

## hash

One-shot digest functions. Each returns a fresh `Uint8Array`.

```ts
import { hash } from '@fintoda/react-native-crypto-lib';
```

| function | output bytes | notes |
|---|---|---|
| `hash.sha1(data)` | 20 | legacy; not recommended |
| `hash.sha256(data)` | 32 | |
| `hash.sha384(data)` | 48 | |
| `hash.sha512(data)` | 64 | |
| `hash.sha3_256(data)` | 32 | NIST SHA3 |
| `hash.sha3_512(data)` | 64 | NIST SHA3 |
| `hash.keccak_256(data)` | 32 | pre-NIST Keccak (Ethereum) |
| `hash.keccak_512(data)` | 64 | pre-NIST Keccak |
| `hash.ripemd160(data)` | 20 | |
| `hash.blake256(data)` | 32 | |
| `hash.blake2b(data)` | 64 | |
| `hash.blake2s(data)` | 32 | |
| `hash.groestl512(data)` | 64 | |
| `hash.sha256d(data)` | 32 | SHA256(SHA256(x)), Bitcoin |
| `hash.hash160(data)` | 20 | RIPEMD160(SHA256(x)) |

All take a `Uint8Array` and return a `Uint8Array`.

## mac

```ts
import { mac } from '@fintoda/react-native-crypto-lib';
```

| function | output |
|---|---|
| `mac.hmac_sha256(key, msg)` | 32 bytes |
| `mac.hmac_sha512(key, msg)` | 64 bytes |

## kdf

```ts
import { kdf } from '@fintoda/react-native-crypto-lib';
```

- `kdf.pbkdf2_sha256(password, salt, iterations, length)` → `Uint8Array(length)`
- `kdf.pbkdf2_sha512(password, salt, iterations, length)` → `Uint8Array(length)`
- `kdf.hkdf_sha256(ikm, salt, info, length)` → `Uint8Array(length)`
- `kdf.hkdf_sha512(ikm, salt, info, length)` → `Uint8Array(length)`

`length` is capped at `255 * hashLen` per RFC 5869 / the PBKDF2 reference
impl. `iterations` is capped at 10,000,000 as a sanity check.

## rng

```ts
import { rng } from '@fintoda/react-native-crypto-lib';
```

- `rng.bytes(count)` → `Uint8Array` — cryptographically secure random
  bytes. `count` is capped at 1 MiB per call.
- `rng.uint32()` → `number` — unsigned 32-bit integer.
- `rng.uniform(max)` → `number` — uniform random integer in `[0, max)`,
  no modulo bias. `max` must be a positive integer.

## ecdsa

```ts
import { ecdsa, type Curve } from '@fintoda/react-native-crypto-lib';
```

`Curve` is `'secp256k1' | 'nist256p1'`. All functions default to
`secp256k1` when the argument is omitted.

- `ecdsa.randomPrivate(curve?)` → `Uint8Array(32)` — uniform in `[1, n-1]`.
- `ecdsa.validatePrivate(priv, curve?)` → `boolean`.
- `ecdsa.getPublic(priv, compact = true, curve?)` →
  `Uint8Array` (33 bytes compressed or 65 bytes uncompressed).
- `ecdsa.readPublic(pub, compact = true, curve?)` → re-serialises a
  public key into the requested form. Validates it on the way.
- `ecdsa.validatePublic(pub, curve?)` → `boolean`.
- `ecdsa.sign(priv, digest, curve?)` →
  `{ signature: Uint8Array(64), recId: 0 | 1 | 2 | 3 }`.
  RFC 6979 deterministic, output is low-S.
- `ecdsa.verify(pub, sig64, digest, curve?)` → `boolean`. Accepts both
  low-S and high-S signatures; use `tinySecp256k1.verify(..., true)` for
  strict BIP-62 low-S enforcement.
- `ecdsa.recover(sig64, digest, recId, curve?)` → `Uint8Array(65)`
  uncompressed.
- `ecdsa.ecdh(priv, pub, curve?)` → `Uint8Array(33)` compressed shared
  point. If you want the legacy `SHA256(x)` behaviour, do
  `hash.sha256(ecdh(priv, pub).slice(1))`.
- `ecdsa.sigToDer(sig64)` / `ecdsa.sigFromDer(der)`.

## schnorr

BIP-340 Schnorr on secp256k1, x-only keys.

```ts
import { schnorr } from '@fintoda/react-native-crypto-lib';
```

- `schnorr.getPublic(priv)` → `Uint8Array(32)` x-only pubkey.
- `schnorr.verifyPublic(pub32)` → `boolean`.
- `schnorr.sign(priv, digest, aux?)` → `Uint8Array(64)`. `aux` is the
  optional 32-byte auxiliary randomness; when omitted, 32 zero bytes are
  used (spec-compliant).
- `schnorr.verify(pub32, sig64, digest)` → `boolean`.
- `schnorr.tweakPublic(pub32, merkleRoot?)` →
  `{ pub: Uint8Array(32), parity: 0 | 1 }`. Implements the BIP-341
  TapTweak: if `merkleRoot` is omitted or zero-length, the key-spend
  tweak `H_TapTweak(pub)` is used.
- `schnorr.tweakPrivate(priv, merkleRoot?)` → `Uint8Array(32)`.

## ed25519 / x25519

Vanilla Ed25519 (RFC 8032, SHA-512) and X25519 ECDH.

```ts
import { ed25519, x25519 } from '@fintoda/react-native-crypto-lib';
```

- `ed25519.getPublic(priv32)` → `Uint8Array(32)` pubkey from a 32-byte seed.
- `ed25519.sign(priv32, msg)` → `Uint8Array(64)` signature over the raw
  message (Ed25519 hashes the message internally).
- `ed25519.verify(pub32, sig64, msg)` → `boolean`.
- `x25519.getPublic(priv32)` → `Uint8Array(32)`.
- `x25519.scalarmult(priv32, pub32)` → `Uint8Array(32)` shared secret.

## ecc

Low-level secp256k1 point / scalar primitives used by the
`tinySecp256k1` adapter but also exported directly. All return `null` on
operations that collapse to the point at infinity / an out-of-range
scalar; malformed inputs throw.

```ts
import { ecc } from '@fintoda/react-native-crypto-lib';
```

- `ecc.pointAdd(a, b, compressed = true)` → `Uint8Array | null`.
- `ecc.pointAddScalar(p, tweak, compressed = true)` → `Uint8Array | null`.
- `ecc.pointMultiply(p, tweak, compressed = true)` → `Uint8Array | null`.
- `ecc.privateAdd(d, tweak)` → `Uint8Array | null`.
- `ecc.privateSub(d, tweak)` → `Uint8Array | null`.
- `ecc.privateNegate(d)` → `Uint8Array`.
- `ecc.xOnlyPointAddTweak(p32, tweak32)` →
  `{ parity: 0 | 1, xOnlyPubkey: Uint8Array(32) } | null`. This is the
  **bare** scalar tweak, not the BIP-341 TapTweak — use
  `schnorr.tweakPublic` for the latter.

## tinySecp256k1

Drop-in implementation of the `TinySecp256k1Interface` consumed by
`bitcoinjs-lib`, `ecpair` and `bip32`. Wire it up wherever those packages
expect an `eccLib`:

```ts
import { tinySecp256k1 } from '@fintoda/react-native-crypto-lib';
import BIP32Factory from 'bip32';
import ECPairFactory from 'ecpair';

const bip32Factory = BIP32Factory(tinySecp256k1);
const ECPair = ECPairFactory(tinySecp256k1);
```

Full method list (`tiny-secp256k1@2.x`):

- Validation: `isPoint`, `isPointCompressed`, `isXOnlyPoint`, `isPrivate`.
- Point ops: `pointAdd`, `pointAddScalar`, `pointMultiply`,
  `pointFromScalar`, `pointCompress`.
- X-only: `xOnlyPointFromScalar`, `xOnlyPointFromPoint`,
  `xOnlyPointAddTweak`, `xOnlyPointAddTweakCheck`.
- Scalars: `privateAdd`, `privateSub`, `privateNegate`.
- ECDSA: `sign(h, d, e?)`, `signRecoverable(h, d, e?)`,
  `verify(h, Q, sig, strict?)`, `recover(h, sig, recId, compressed?)`.
- Schnorr: `signSchnorr(h, d, e?)`, `verifySchnorr(h, Q, sig)`.

Notes:

- The optional `e` / extra-entropy argument on ECDSA/Schnorr is ignored
  for ECDSA (we're RFC 6979 deterministic) and forwarded as `aux_rand`
  for Schnorr.
- `verify(..., strict = true)` enforces BIP-62 low-S; the default
  (`false`) accepts high-S, matching tiny-secp256k1.

## aes

AES-256 with caller-provided IV / nonce. Key is always 32 bytes.

```ts
import { aes, type CbcPadding } from '@fintoda/react-native-crypto-lib';
```

### CBC

- `aes.cbc.encrypt(key32, iv16, data, padding = 'pkcs7')` → ciphertext.
- `aes.cbc.decrypt(key32, iv16, data, padding = 'pkcs7')` → plaintext.
  Throws on invalid PKCS#7 padding.
- `padding` is `'pkcs7' | 'none'`. With `'none'` the input length must
  be a multiple of 16.

### CTR

- `aes.ctr.crypt(key32, iv16, data)` → same-length buffer. Symmetric:
  the same call encrypts and decrypts.

### GCM

- `aes.gcm.encrypt(key32, nonce, plaintext, aad?)` →
  `Uint8Array(plaintext.length + 16)`. The trailing 16 bytes are the
  authentication tag (WebCrypto / `node:crypto` layout).
- `aes.gcm.decrypt(key32, nonce, sealed, aad?)` → plaintext.
  Throws `aes_256_gcm_decrypt: authentication failed` if the tag does
  not match.
- `nonce` length is validated as non-empty; 12 bytes is recommended.

## bip39

```ts
import { bip39, type Bip39Strength } from '@fintoda/react-native-crypto-lib';
```

- `bip39.generate(strength = 128)` → `string`. `strength` is one of
  `128 | 160 | 192 | 224 | 256` (12 / 15 / 18 / 21 / 24 words).
- `bip39.fromEntropy(entropy)` → `string`. Entropy length must be
  16, 20, 24, 28 or 32 bytes.
- `bip39.validate(mnemonic)` → `boolean`. Verifies the checksum and
  wordlist membership.
- `bip39.toSeed(mnemonic, passphrase = '')` → `Uint8Array(64)`.
  PBKDF2-HMAC-SHA512, 2048 rounds, salt = `"mnemonic" + passphrase`.

## bip32

BIP-32 / SLIP-10 HD key derivation on three curves. The JS `HDNode`
carries a 108-byte opaque `raw` blob that all native derive calls take
as input — one JSI hop per full path:

```ts
import { bip32, type Bip32Curve, type HDNode } from '@fintoda/react-native-crypto-lib';
```

- `bip32.fromSeed(seed, curve = 'secp256k1')` → `HDNode`. `curve` is
  `'secp256k1' | 'nist256p1' | 'ed25519'`.
- `bip32.derive(node, path)` → `HDNode`. `path` is either a BIP-32
  string (`"m/44'/0'/0'/0/0"`) or a numeric index array (hardened
  indices must have the `0x80000000` bit set).
- `bip32.derivePublic(node, path)` → `HDNode` — public-only derivation;
  throws on hardened indices and on ed25519 (SLIP-10 public derivation
  is undefined for ed25519).
- `bip32.neuter(node)` → `HDNode` — returns a copy with the private key
  stripped.
- `bip32.serialize(node, version, isPrivate)` → xprv / xpub string.
  Typical Bitcoin mainnet versions: `0x0488ADE4` (xprv), `0x0488B21E`
  (xpub).
- `bip32.deserialize(str, version, curve, isPrivate)` → `HDNode`.
- `bip32.fingerprint(node)` → `number` — this node's own fingerprint.
- `bip32.HARDENED_OFFSET` = `0x80000000`.

`HDNode` shape:

```ts
type HDNode = {
  curve: Bip32Curve;
  depth: number;
  parentFingerprint: number;
  childNumber: number;
  chainCode: Uint8Array;   // 32 bytes
  privateKey: Uint8Array | null; // 32 bytes or null when neutered
  publicKey: Uint8Array;   // 33 bytes, compressed (or SLIP-10 ed25519 pub)
  raw: Uint8Array;         // 108-byte opaque blob passed back to derive()
};
```

### SLIP-10 notes

- On `ed25519`, every child must be hardened. Non-hardened derivation
  throws.
- On `ed25519`, the 33-byte `publicKey` has a leading `0x00` tag byte
  followed by 32 bytes of the Ed25519 public key — the same convention
  trezor-crypto uses. You typically pass `privateKey` into
  `ed25519.sign` rather than using the 33-byte form directly.

## webcrypto

React Native / Hermes doesn't ship `globalThis.crypto.getRandomValues`,
which breaks any library that expects it (`@noble/*`, `uuid@v4`,
`ethers`, `bitcoinjs-lib` in some paths, `tweetnacl`, …). This module
plugs the hole:

```ts
import {
  getRandomValues,
  installCryptoPolyfill,
} from '@fintoda/react-native-crypto-lib';
```

- `installCryptoPolyfill()` → `boolean`. Assigns `getRandomValues` onto
  `globalThis.crypto` when it's missing. Idempotent — if a native
  `crypto.getRandomValues` already exists, it is not overwritten.
  Returns `true` if the polyfill was installed. Call this once at app
  startup, **before** importing any package that touches `crypto`.
- `getRandomValues(typedArray)` → the same typed array, filled with
  CSPRNG bytes. Throws a `QuotaExceededError`-equivalent on requests
  larger than 65,536 bytes (the WebCrypto cap). Accepts any integer
  typed array view (`Uint8Array`, `Int32Array`, …).

```ts
// index.js (very top of the app)
import { installCryptoPolyfill } from '@fintoda/react-native-crypto-lib';
installCryptoPolyfill();
```

## Compatibility notes

- All public APIs are **synchronous**. No promises, no awaits.
- Inputs are always `Uint8Array`; outputs are always fresh
  `Uint8Array` views. Nothing is base64 at the edge.
- Key formats match the wider ecosystem: compressed (33 B) and
  uncompressed (65 B) for secp256k1 / nist256p1, x-only (32 B) for
  BIP-340 Schnorr, raw 32-byte seeds for Ed25519 / X25519.
- The library is **not a complete drop-in** for earlier `CryptoLib`
  versions: function names are grouped into namespaces (`hash.*`,
  `ecdsa.*`, `bip32.*` …), signing is sync, HDNode fields use
  `Uint8Array` instead of base64 strings. A mechanical migration is
  straightforward.

## Contributing

- [Development workflow](CONTRIBUTING.md#development-workflow)
- [Sending a pull request](CONTRIBUTING.md#sending-a-pull-request)
- [Code of conduct](CODE_OF_CONDUCT.md)

## License

MIT. Vendored trezor-crypto is under its own MIT license; see
`vendor/trezor-crypto/crypto/LICENSE`.
