import { type Bip32Curve, encodePath, packPath } from './bip32-utils';
import { raw, toArrayBuffer } from './buffer';
import { type Curve, type EcdsaSignature } from './ecdsa';
import { wrapNative } from './errors';

/**
 * Access-control gating for `secureKV.set`. Reserved for forward
 * compatibility — only `'none'` is accepted today. Future versions will
 * add `'biometric'` etc. without breaking call sites that already pass
 * (or omit) the third argument.
 */
export type AccessControl = 'none';

// --- generic blob slot (tag 0x00) ------------------------------------------

const set = wrapNative(
  (
    key: string,
    value: Uint8Array,
    accessControl: AccessControl = 'none'
  ): void => {
    if (accessControl !== 'none') {
      throw new Error(
        `secureKV.set: accessControl='${accessControl}' is not yet supported`
      );
    }
    raw.secure_kv_set(key, toArrayBuffer(value));
  }
);

const get = wrapNative((key: string): Uint8Array | null => {
  const buf = raw.secure_kv_get(key);
  return buf === null ? null : new Uint8Array(buf);
});

const has = wrapNative((key: string): boolean => raw.secure_kv_has(key));

const remove = wrapNative((key: string): void => raw.secure_kv_delete(key));

const list = wrapNative((): string[] => raw.secure_kv_list());

const clear = wrapNative((): void => raw.secure_kv_clear());

const isHardwareBacked = wrapNative((): boolean =>
  raw.secure_kv_is_hardware_backed()
);

// --- BIP-32 / SLIP-10 derivation slot (tag 0x01) ---------------------------

function pathBuf(path: string | number[]): ArrayBuffer {
  return typeof path === 'string' ? encodePath(path) : packPath(path);
}

const bip32_setSeed = wrapNative((alias: string, seed: Uint8Array): void => {
  raw.secure_kv_bip32_set_seed(alias, toArrayBuffer(seed));
});

const bip32_fingerprint = wrapNative(
  (alias: string, path: string | number[], curve: Bip32Curve): number =>
    raw.secure_kv_bip32_fingerprint(alias, pathBuf(path), curve)
);

const bip32_getPublicKey = wrapNative(
  (
    alias: string,
    path: string | number[],
    curve: Bip32Curve,
    compact: boolean = true
  ): Uint8Array =>
    new Uint8Array(
      raw.secure_kv_bip32_get_public(alias, pathBuf(path), curve, compact)
    )
);

const bip32_signEcdsa = wrapNative(
  (
    alias: string,
    path: string | number[],
    digest: Uint8Array,
    curve: Curve
  ): EcdsaSignature => {
    const res = new Uint8Array(
      raw.secure_kv_bip32_sign_ecdsa(
        alias,
        pathBuf(path),
        toArrayBuffer(digest),
        curve
      )
    );
    return { signature: res.slice(1), recId: res[0] as number };
  }
);

const bip32_signSchnorr = wrapNative(
  (
    alias: string,
    path: string | number[],
    digest: Uint8Array,
    aux?: Uint8Array
  ): Uint8Array =>
    new Uint8Array(
      raw.secure_kv_bip32_sign_schnorr(
        alias,
        pathBuf(path),
        toArrayBuffer(digest),
        aux ? toArrayBuffer(aux) : null
      )
    )
);

const bip32_signSchnorrTaproot = wrapNative(
  (
    alias: string,
    path: string | number[],
    digest: Uint8Array,
    merkleRoot?: Uint8Array
  ): Uint8Array =>
    new Uint8Array(
      raw.secure_kv_bip32_sign_schnorr_taproot(
        alias,
        pathBuf(path),
        toArrayBuffer(digest),
        merkleRoot ? toArrayBuffer(merkleRoot) : null
      )
    )
);

const bip32_signEd25519 = wrapNative(
  (alias: string, path: string | number[], msg: Uint8Array): Uint8Array =>
    new Uint8Array(
      raw.secure_kv_bip32_sign_ed25519(alias, pathBuf(path), toArrayBuffer(msg))
    )
);

const bip32_ecdh = wrapNative(
  (
    alias: string,
    path: string | number[],
    peerPub: Uint8Array,
    curve: Curve
  ): Uint8Array =>
    new Uint8Array(
      raw.secure_kv_bip32_ecdh(
        alias,
        pathBuf(path),
        toArrayBuffer(peerPub),
        curve
      )
    )
);

// --- raw 32-byte private key slot (tag 0x02) -------------------------------

const raw_setPrivate = wrapNative(
  (alias: string, priv: Uint8Array, curve: Bip32Curve): void => {
    raw.secure_kv_raw_set_private(alias, toArrayBuffer(priv), curve);
  }
);

const raw_getPublicKey = wrapNative(
  (alias: string, compact: boolean = true): Uint8Array =>
    new Uint8Array(raw.secure_kv_raw_get_public(alias, compact))
);

const raw_signEcdsa = wrapNative(
  (alias: string, digest: Uint8Array): EcdsaSignature => {
    const res = new Uint8Array(
      raw.secure_kv_raw_sign_ecdsa(alias, toArrayBuffer(digest))
    );
    return { signature: res.slice(1), recId: res[0] as number };
  }
);

const raw_signSchnorr = wrapNative(
  (alias: string, digest: Uint8Array, aux?: Uint8Array): Uint8Array =>
    new Uint8Array(
      raw.secure_kv_raw_sign_schnorr(
        alias,
        toArrayBuffer(digest),
        aux ? toArrayBuffer(aux) : null
      )
    )
);

const raw_signSchnorrTaproot = wrapNative(
  (alias: string, digest: Uint8Array, merkleRoot?: Uint8Array): Uint8Array =>
    new Uint8Array(
      raw.secure_kv_raw_sign_schnorr_taproot(
        alias,
        toArrayBuffer(digest),
        merkleRoot ? toArrayBuffer(merkleRoot) : null
      )
    )
);

const raw_signEd25519 = wrapNative(
  (alias: string, msg: Uint8Array): Uint8Array =>
    new Uint8Array(raw.secure_kv_raw_sign_ed25519(alias, toArrayBuffer(msg)))
);

const raw_ecdh = wrapNative(
  (alias: string, peerPub: Uint8Array): Uint8Array =>
    new Uint8Array(raw.secure_kv_raw_ecdh(alias, toArrayBuffer(peerPub)))
);

/**
 * Hardware-backed key/value store, with optional native-only signing
 * primitives layered on top.
 *
 * Three slot families backed by the same encrypted storage:
 *
 * - **Generic blob** (default `set` / `get` / etc.) — opaque user bytes.
 *   Values are `Uint8Array`; keys match `[A-Za-z0-9._-]` (≤128 chars).
 *   Values are capped at 64 KiB.
 * - **`secureKV.bip32`** — provision a 64-byte BIP-39 seed, then
 *   `signEcdsa` / `signSchnorr[Taproot]` / `signEd25519` / `ecdh` / etc.
 *   derive a child key on the fly and sign without ever returning the
 *   private scalar to JS.
 * - **`secureKV.raw`** — provision a single 32-byte private key bound
 *   to a curve, sign with it directly. No derivation.
 *
 * Storage is device-local: never iCloud-synced on iOS, and excluded
 * from Google Drive auto-backup on Android when the host opts in via
 * the bundled `data_extraction_rules.xml`. Blobs are wiped on
 * uninstall or factory reset — see README "secureKV — durability".
 *
 * `get`, `list`, and the sign / derive methods throw
 * {@link SecureKVUnavailableError} when the OS-managed master key has
 * been invalidated. Treat existing secrets as lost and re-derive them.
 */
export const secureKV = {
  set,
  get,
  has,
  delete: remove,
  list,
  clear,
  isHardwareBacked,

  bip32: {
    setSeed: bip32_setSeed,
    fingerprint: bip32_fingerprint,
    getPublicKey: bip32_getPublicKey,
    signEcdsa: bip32_signEcdsa,
    signSchnorr: bip32_signSchnorr,
    signSchnorrTaproot: bip32_signSchnorrTaproot,
    signEd25519: bip32_signEd25519,
    ecdh: bip32_ecdh,
  },

  raw: {
    setPrivate: raw_setPrivate,
    getPublicKey: raw_getPublicKey,
    signEcdsa: raw_signEcdsa,
    signSchnorr: raw_signSchnorr,
    signSchnorrTaproot: raw_signSchnorrTaproot,
    signEd25519: raw_signEd25519,
    ecdh: raw_ecdh,
  },
};
