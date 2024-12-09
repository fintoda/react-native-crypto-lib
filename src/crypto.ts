import { randomBytesSync } from './rng';

class QuotaExceededError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'QuotaExceededError';
  }
}

export const getRandomValues = <
  T extends
    | Int8Array
    | Uint8Array
    | Int16Array
    | Uint16Array
    | Int32Array
    | Uint32Array,
>(
  typedArray: T
): T => {
  if (
    !(
      typedArray instanceof Int8Array ||
      typedArray instanceof Uint8Array ||
      typedArray instanceof Int16Array ||
      typedArray instanceof Uint16Array ||
      typedArray instanceof Int32Array ||
      typedArray instanceof Uint32Array
    )
  ) {
    throw new TypeError(
      'Expected an instance of Int8Array, Uint8Array, Int16Array, Uint16Array, Int32Array, or Uint32Array'
    );
  }

  if (typedArray.length > 65536) {
    throw new QuotaExceededError(
      'The requested array length exceeds the maximum (65536).'
    );
  }

  const bytes = randomBytesSync(typedArray.length);

  for (let i = 0; i < typedArray.length; i++) {
    typedArray[i] = bytes[i] as number;
  }

  return typedArray;
};
