const unsupported = (): never => {
  throw new Error(
    "'@fintoda/react-native-crypto-lib' is only supported on native platforms."
  );
};

export const rng = {
  bytes: (_count: number): Uint8Array => unsupported(),
  uint32: (): number => unsupported(),
  uniform: (_max: number): number => unsupported(),
};
