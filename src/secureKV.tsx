/**
 * Access-control gating for `secureKV.set`. Reserved for forward
 * compatibility — only `'none'` is accepted today.
 */
export type AccessControl = 'none';

const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

/** Hardware-backed key/value store. Native-only. */
export const secureKV = {
  set: unsupported as (
    key: string,
    value: Uint8Array,
    accessControl?: AccessControl
  ) => void,
  get: unsupported as (key: string) => Uint8Array | null,
  has: unsupported as (key: string) => boolean,
  delete: unsupported as (key: string) => void,
  list: unsupported as () => string[],
  clear: unsupported as () => void,
  isHardwareBacked: unsupported as () => boolean,
};
