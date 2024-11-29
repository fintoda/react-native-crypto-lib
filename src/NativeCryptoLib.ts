import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';

interface HDNode {
  depth: number;
  child_num: number;
  chain_code: string;
  private_key: string;
  public_key: string;
  fingerprint: number;
  curve: string;
  private_derive: boolean;
}

export interface Spec extends TurboModule {
  randomNumber(): Promise<number>;
  randomBytes(length: number): Promise<number>;

  hash(algorithm: number, data: string): string;
  hmac(algorithm: number, key: string, data: string): string;
  pbkdf2(
    algorithm: number,
    pass: string,
    salt: string,
    iterations: number,
    keyLength: number
  ): Promise<string>;

  mnemonicToSeed(mnemonic: string, passphrase: string): Promise<string>;
  generateMnemonic(strength: number): Promise<string>;
  validateMnemonic(mnemonic: string): Promise<number>;

  hdNodeFromSeed(curve: string, seed: string): HDNode;
  hdNodeDerive(data: HDNode, path: number[]): HDNode;

  ecdsaRandomPrivate(): Promise<string>;
  ecdsaValidatePrivate(priv: string): number;
  ecdsaGetPublic(priv: string, compact: boolean): string;
  ecdsaReadPublic(pub: string, compact: boolean): string;
  ecdsaValidatePublic(pub: string): number;
  ecdsaRecover(sig: string, recId: number, digest: string): string;
  ecdsaEcdh(pub: string, priv: string, compact: boolean): string;
  ecdsaVerify(pub: string, sign: string, digest: string): number;
  ecdsaSign(priv: string, digest: string): string;
  ecdsaSignAsync(priv: string, digest: string): Promise<string>;

  encrypt(
    key: string,
    iv: string,
    data: string,
    paddingMode: number
  ): Promise<string>;
  decrypt(
    key: string,
    iv: string,
    data: string,
    paddingMode: number
  ): Promise<string>;

  schnorrGetPublic(priv: string): string;
  schnorrSign(priv: string, digest: string): string;
  schnorrSignAsync(priv: string, digest: string): Promise<string>;
  schnorrVerify(pub: string, sign: string, digest: string): number;
  schnorrTweakPublic(pub: string, root: string): string;
  schnorrTweakPrivate(priv: string, root: string): string;
  schnorrVerifyPub(pub: string): number;
  xOnlyPointAddTweak(
    pub: string,
    tweak: string
  ): {
    parity: number;
    xOnlyPubkey: string;
  } | null;
}

export default TurboModuleRegistry.getEnforcing<Spec>('CryptoLib');
