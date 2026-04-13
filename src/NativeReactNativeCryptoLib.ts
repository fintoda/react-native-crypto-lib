import { TurboModuleRegistry, type TurboModule } from 'react-native';

// The codegen Spec must be empty (well, almost) because RN 0.85 codegen
// does not support ArrayBuffer in TurboModule specs. All real native
// methods that take or return binary data are registered manually into
// methodMap_ from the C++ Impl constructor and typed via RawSpec below.
export interface Spec extends TurboModule {}

export interface RawSpec {
  hash_sha1(data: ArrayBuffer): ArrayBuffer;
  hash_sha256(data: ArrayBuffer): ArrayBuffer;
  hash_sha384(data: ArrayBuffer): ArrayBuffer;
  hash_sha512(data: ArrayBuffer): ArrayBuffer;
  hash_sha3_256(data: ArrayBuffer): ArrayBuffer;
  hash_sha3_512(data: ArrayBuffer): ArrayBuffer;
  hash_keccak_256(data: ArrayBuffer): ArrayBuffer;
  hash_keccak_512(data: ArrayBuffer): ArrayBuffer;
  hash_ripemd160(data: ArrayBuffer): ArrayBuffer;
  hash_blake256(data: ArrayBuffer): ArrayBuffer;
  hash_blake2b(data: ArrayBuffer): ArrayBuffer;
  hash_blake2s(data: ArrayBuffer): ArrayBuffer;
  hash_groestl512(data: ArrayBuffer): ArrayBuffer;
  hash_sha256d(data: ArrayBuffer): ArrayBuffer;
  hash_hash160(data: ArrayBuffer): ArrayBuffer;

  mac_hmac_sha256(key: ArrayBuffer, msg: ArrayBuffer): ArrayBuffer;
  mac_hmac_sha512(key: ArrayBuffer, msg: ArrayBuffer): ArrayBuffer;

  kdf_pbkdf2_sha256(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    iterations: number,
    length: number
  ): ArrayBuffer;
  kdf_pbkdf2_sha512(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    iterations: number,
    length: number
  ): ArrayBuffer;
  kdf_hkdf_sha256(
    ikm: ArrayBuffer,
    salt: ArrayBuffer,
    info: ArrayBuffer,
    length: number
  ): ArrayBuffer;
  kdf_hkdf_sha512(
    ikm: ArrayBuffer,
    salt: ArrayBuffer,
    info: ArrayBuffer,
    length: number
  ): ArrayBuffer;

  rng_bytes(count: number): ArrayBuffer;

  ecdsa_random_private(curve: string): ArrayBuffer;
  ecdsa_validate_private(curve: string, priv: ArrayBuffer): boolean;
  ecdsa_get_public(
    curve: string,
    priv: ArrayBuffer,
    compact: boolean
  ): ArrayBuffer;
  ecdsa_read_public(
    curve: string,
    pub: ArrayBuffer,
    compact: boolean
  ): ArrayBuffer;
  ecdsa_validate_public(curve: string, pub: ArrayBuffer): boolean;
  /** Returns 65 bytes: [recid, sig[0..64]] (signature is low-S). */
  ecdsa_sign(
    curve: string,
    priv: ArrayBuffer,
    digest: ArrayBuffer
  ): ArrayBuffer;
  ecdsa_verify(
    curve: string,
    pub: ArrayBuffer,
    sig: ArrayBuffer,
    digest: ArrayBuffer
  ): boolean;
  /** Returns 65-byte uncompressed public key. */
  ecdsa_recover(
    curve: string,
    sig: ArrayBuffer,
    digest: ArrayBuffer,
    recid: number
  ): ArrayBuffer;
  /** Returns 33-byte compressed shared public key. */
  ecdsa_ecdh(curve: string, priv: ArrayBuffer, pub: ArrayBuffer): ArrayBuffer;
  ecdsa_sig_to_der(sig: ArrayBuffer): ArrayBuffer;
  ecdsa_sig_from_der(der: ArrayBuffer): ArrayBuffer;

  /** BIP-340 Schnorr (secp256k1) — all keys are 32-byte x-only. */
  schnorr_get_public(priv: ArrayBuffer): ArrayBuffer;
  schnorr_verify_public(pub: ArrayBuffer): boolean;
  schnorr_sign(
    priv: ArrayBuffer,
    digest: ArrayBuffer,
    aux: ArrayBuffer | null
  ): ArrayBuffer;
  schnorr_verify(
    pub: ArrayBuffer,
    sig: ArrayBuffer,
    digest: ArrayBuffer
  ): boolean;
  /** Returns 33 bytes: tweaked_x(32) || parity(1). */
  schnorr_tweak_public(
    pub: ArrayBuffer,
    merkleRoot: ArrayBuffer | null
  ): ArrayBuffer;
  schnorr_tweak_private(
    priv: ArrayBuffer,
    merkleRoot: ArrayBuffer | null
  ): ArrayBuffer;

  /** Ed25519 (RFC 8032, SHA-512) on 32-byte seeds; signs raw messages. */
  ed25519_get_public(priv: ArrayBuffer): ArrayBuffer;
  ed25519_sign(priv: ArrayBuffer, msg: ArrayBuffer): ArrayBuffer;
  ed25519_verify(pub: ArrayBuffer, sig: ArrayBuffer, msg: ArrayBuffer): boolean;

  /** X25519 (curve25519) key-exchange. */
  x25519_get_public(priv: ArrayBuffer): ArrayBuffer;
  x25519_scalarmult(priv: ArrayBuffer, pub: ArrayBuffer): ArrayBuffer;

  /**
   * Low-level secp256k1 point / scalar primitives used by the
   * tiny-secp256k1 adapter. Empty ArrayBuffer return means "null"
   * (operation produced point at infinity / invalid scalar).
   */
  ecc_point_add(
    a: ArrayBuffer,
    b: ArrayBuffer,
    compressed: boolean
  ): ArrayBuffer;
  ecc_point_add_scalar(
    p: ArrayBuffer,
    tweak: ArrayBuffer,
    compressed: boolean
  ): ArrayBuffer;
  ecc_point_multiply(
    p: ArrayBuffer,
    tweak: ArrayBuffer,
    compressed: boolean
  ): ArrayBuffer;
  ecc_private_add(d: ArrayBuffer, tweak: ArrayBuffer): ArrayBuffer;
  ecc_private_sub(d: ArrayBuffer, tweak: ArrayBuffer): ArrayBuffer;
  ecc_private_negate(d: ArrayBuffer): ArrayBuffer;
  /** Returns 33 bytes: tweaked_x(32) || parity(1); empty on infinity. */
  ecc_xonly_point_add_tweak(p: ArrayBuffer, tweak: ArrayBuffer): ArrayBuffer;

  /**
   * AES-256. key is always 32 bytes; iv/nonce is caller-generated.
   * GCM encrypt returns ciphertext||tag(16), decrypt takes the same
   * layout. padding for CBC is "pkcs7" | "none".
   */
  aes_256_cbc_encrypt(
    key: ArrayBuffer,
    iv: ArrayBuffer,
    data: ArrayBuffer,
    padding: string
  ): ArrayBuffer;
  aes_256_cbc_decrypt(
    key: ArrayBuffer,
    iv: ArrayBuffer,
    data: ArrayBuffer,
    padding: string
  ): ArrayBuffer;
  aes_256_ctr_crypt(
    key: ArrayBuffer,
    iv: ArrayBuffer,
    data: ArrayBuffer
  ): ArrayBuffer;
  aes_256_gcm_encrypt(
    key: ArrayBuffer,
    nonce: ArrayBuffer,
    plaintext: ArrayBuffer,
    aad: ArrayBuffer | null
  ): ArrayBuffer;
  aes_256_gcm_decrypt(
    key: ArrayBuffer,
    nonce: ArrayBuffer,
    sealed: ArrayBuffer,
    aad: ArrayBuffer | null
  ): ArrayBuffer;

  /** BIP-39 mnemonic handling. strength must be 128/160/192/224/256. */
  bip39_generate(strength: number): string;
  bip39_from_entropy(entropy: ArrayBuffer): string;
  bip39_check(mnemonic: string): boolean;
  bip39_to_seed(mnemonic: string, passphrase: string): ArrayBuffer;

  /**
   * BIP-32 / SLIP-10 HD key derivation. HDNode is serialized as a fixed
   * 108-byte binary blob: curve_tag(1) | has_private(1) | depth(1) |
   * parent_fp(4 BE) | child_num(4 BE) | chain_code(32) | private_key(32) |
   * public_key(33). Curve is "secp256k1" | "nist256p1" | "ed25519".
   */
  bip32_from_seed(seed: ArrayBuffer, curve: string): ArrayBuffer;
  /** path is N big-endian u32 indices packed as 4*N bytes. */
  bip32_derive(node: ArrayBuffer, path: ArrayBuffer): ArrayBuffer;
  bip32_derive_public(node: ArrayBuffer, path: ArrayBuffer): ArrayBuffer;
  bip32_serialize(
    node: ArrayBuffer,
    version: number,
    isPrivate: boolean
  ): string;
  bip32_deserialize(
    str: string,
    version: number,
    curve: string,
    isPrivate: boolean
  ): ArrayBuffer;
  bip32_fingerprint(node: ArrayBuffer): number;
}

export default TurboModuleRegistry.getEnforcing<Spec>('ReactNativeCryptoLib');
