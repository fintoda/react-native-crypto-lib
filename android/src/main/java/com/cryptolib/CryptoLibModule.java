package com.cryptolib;

import androidx.annotation.NonNull;
import android.util.Base64;
import android.os.AsyncTask;
import android.util.Log;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.module.annotations.ReactModule;

@ReactModule(name = CryptoLibModule.NAME)
public class CryptoLibModule extends ReactContextBaseJavaModule {
  public static final String NAME = "CryptoLib";

  public CryptoLibModule(ReactApplicationContext reactContext) {
    super(reactContext);
  }

  @Override
  @NonNull
  public String getName() {
    return NAME;
  }

  static {
    System.loadLibrary("cryptolib");
  }

  private static native double nativeRandomNumber();
  private static native byte[] nativeRandomBytes(int length);
  private static native byte[] nativeHash(int type, byte[] data);
  private static native byte[] nativeHmac(int type, byte[] key, byte[] data);
  private static native byte[] nativePbkdf2(int type, byte[] pass, byte[] salt, int iterations, int keyLength);
  
  private static native byte[] nativeMnemonicToSeed(String mnemonic, String passphrase);
  private static native String nativeGenerateMnemonic(int strength);
  private static native int nativeValidateMnemonic(String mnemonic);
  
  private static native CryptoLibHDNode nativeHdNodeFromSeed(String curve, byte[] seed);
  private static native CryptoLibHDNode nativeHdNodeDerive(CryptoLibHDNode data, double[] index);

  private static native byte[] nativeEcdsaRandomPrivate();
  private static native boolean nativeEcdsaValidatePrivate(byte[] priv);
  private static native byte[] nativeEcdsaGetPublic(byte[] priv, boolean compact);
  private static native byte[] nativeEcdsaReadPublic(byte[] pub, boolean compact);
  private static native boolean nativeEcdsaValidatePublic(byte[] pub);
  private static native byte[] nativeEcdsaRecover(byte[] sig, int recId, byte[] digest);
  private static native byte[] nativeEcdsaEcdh(byte[] pub, byte[] priv, boolean compact);
  private static native boolean nativeEcdsaVerify(byte[] pub, byte[] sig, byte[] digest);
  private static native byte[] nativeEcdsaSign(byte[] priv, byte[] digest);

  private static native byte[] nativeEncrypt(byte[] key, byte[] iv, byte[] data, int paddingMode);
  private static native byte[] nativeDecrypt(byte[] key, byte[] iv, byte[] data, int paddingMode);

  private static native byte[] nativeSchnorrGetPublic(byte[] priv);
  private static native byte[] nativeSchnorrSign(byte[] priv, byte[] digest);
  private static native boolean nativeSchnorrVerify(byte[] pub, byte[] sig, byte[] digest);
  private static native byte[] nativeSchnorrTweakPublic(byte[] pub, byte[] root);
  private static native byte[] nativeSchnorrTweakPrivate(byte[] priv, byte[] root);
  private static native boolean nativeSchnorrVerifyPub(byte[] pub);
  private static native CryptoLibXOnlyPointAddTweak nativeXOnlyPointAddTweak(byte[] pub, byte[] tweak);

  @ReactMethod
  public void randomNumber(Promise promise) {
    promise.resolve(nativeRandomNumber());
  }

  @ReactMethod
  public void randomBytes(int length, Promise promise) {
    try {
      byte[] bytes = nativeRandomBytes(length);

      promise.resolve(Base64.encodeToString(bytes, Base64.NO_WRAP));
    } catch (Exception ex) {
      ex.printStackTrace();
      promise.reject("Error", ex.toString());
    }
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String hash(final int type, final String data) {
    byte[] bytes = Base64.decode(data, Base64.NO_PADDING);
    byte[] hash = nativeHash(type, bytes);
    return Base64.encodeToString(hash, Base64.NO_WRAP);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String hmac(final int type, final String key, final String data) {
    byte[] keyBytes = Base64.decode(key, Base64.NO_PADDING);
    byte[] dataBytes = Base64.decode(data, Base64.NO_PADDING);
    byte[] hash = nativeHmac(type, keyBytes, dataBytes);
    return Base64.encodeToString(hash, Base64.NO_WRAP);
  }

  @ReactMethod
  public void pbkdf2(
    final int type,
    final String pass,
    final String salt,
    final int iterations,
    final int keyLength,
    Promise promise
  ) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          byte[] raw_pass = Base64.decode(pass, Base64.NO_PADDING);
          byte[] raw_salt = Base64.decode(salt, Base64.NO_PADDING);
          byte[] hash = nativePbkdf2(type, raw_pass, raw_salt, iterations, keyLength);

          promise.resolve(Base64.encodeToString(hash, Base64.NO_WRAP));
        } catch (Exception ex) {
          ex.printStackTrace();
          promise.reject("Error", ex.toString());
        }
      }
    });
  }

  @ReactMethod
  public void mnemonicToSeed(
    final String mnemonic,
    final String passphrase,
    Promise promise
  ) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          byte[] seed = nativeMnemonicToSeed(mnemonic, passphrase);
          promise.resolve(Base64.encodeToString(seed, Base64.NO_WRAP));
        } catch (Exception ex) {
          ex.printStackTrace();
          promise.reject("Error", ex.toString());
        }
      }
    });
  }

  @ReactMethod
  public void generateMnemonic(
    final int strength,
    Promise promise
  ) {
    promise.resolve(nativeGenerateMnemonic(strength));
  }

  @ReactMethod
  public void validateMnemonic(
    final String mnemonic,
    Promise promise
  ) {
    promise.resolve(nativeValidateMnemonic(mnemonic));
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableMap hdNodeFromSeed(final String curve, final String seed) {
    byte[] seedBytes = Base64.decode(seed, Base64.NO_PADDING);
    CryptoLibHDNode node = nativeHdNodeFromSeed(curve, seedBytes);
    return node.getMap();
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableMap hdNodeDerive(final ReadableMap data, final ReadableArray path) {
    double[] path_items = new double[path.size()];

    for (int i = 0; i < path.size(); i++) {
      path_items[i] = path.getDouble(i);
    }

    CryptoLibHDNode node = CryptoLibHDNode.createNode(data);
    CryptoLibHDNode out = nativeHdNodeDerive(node, path_items);
    return out.getMap();
  }

  @ReactMethod()
  public void ecdsaRandomPrivate(Promise promise) {
    byte[] priv = nativeEcdsaRandomPrivate();
    promise.resolve(Base64.encodeToString(priv, Base64.NO_WRAP));
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public int ecdsaValidatePrivate(final String priv) {
    byte[] priv_bytes = Base64.decode(priv, Base64.NO_PADDING);
    if (!nativeEcdsaValidatePrivate(priv_bytes)) {
      return 0;
    }
    return 1;
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String ecdsaGetPublic(final String priv, final boolean compact) {
    byte[] priv_bytes = Base64.decode(priv, Base64.NO_PADDING);
    byte[] pub = nativeEcdsaGetPublic(priv_bytes, compact);
    return Base64.encodeToString(pub, Base64.NO_WRAP);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String ecdsaReadPublic(final String pub, final boolean compact) {
    byte[] pub_bytes = Base64.decode(pub, Base64.NO_PADDING);
    byte[] out_pub = nativeEcdsaReadPublic(pub_bytes, compact);
    return Base64.encodeToString(out_pub, Base64.NO_WRAP);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public int ecdsaValidatePublic(final String pub) {
    byte[] pub_bytes = Base64.decode(pub, Base64.NO_PADDING);
    if (!nativeEcdsaValidatePublic(pub_bytes)) {
      return 0;
    }
    return 1;
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String ecdsaRecover(final String sig, final int recId, final String digest) {
    byte[] sig_bytes = Base64.decode(sig, Base64.NO_PADDING);
    byte[] digest_bytes = Base64.decode(digest, Base64.NO_PADDING);

    byte[] pub = nativeEcdsaRecover(sig_bytes, recId, digest_bytes);

    return Base64.encodeToString(pub, Base64.NO_WRAP);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String ecdsaEcdh(final String pub, final String priv, final boolean compact) {
    byte[] pub_bytes = Base64.decode(pub, Base64.NO_PADDING);
    byte[] priv_bytes = Base64.decode(priv, Base64.NO_PADDING);

    byte[] ecdh = nativeEcdsaEcdh(pub_bytes, priv_bytes, compact);

    return Base64.encodeToString(ecdh, Base64.NO_WRAP);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public int ecdsaVerify(final String pub, final String sign, final String digest) {
    byte[] pub_bytes = Base64.decode(pub, Base64.NO_PADDING);
    byte[] sign_bytes = Base64.decode(sign, Base64.NO_PADDING);
    byte[] digest_bytes = Base64.decode(digest, Base64.NO_PADDING);

    if (!nativeEcdsaVerify(pub_bytes, sign_bytes, digest_bytes)) {
      return 0;
    }
    return 1;
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String ecdsaSign(final String priv, final String digest) {
    byte[] priv_bytes = Base64.decode(priv, Base64.NO_PADDING);
    byte[] digest_bytes = Base64.decode(digest, Base64.NO_PADDING);

    byte[] sign = nativeEcdsaSign(priv_bytes, digest_bytes);

    return Base64.encodeToString(sign, Base64.NO_WRAP);
  }

  @ReactMethod
  public void ecdsaSignAsync(
    final String priv,
    final String digest,
    Promise promise
  ) {
    byte[] priv_bytes = Base64.decode(priv, Base64.NO_PADDING);
    byte[] digest_bytes = Base64.decode(digest, Base64.NO_PADDING);

    byte[] sign = nativeEcdsaSign(priv_bytes, digest_bytes);

    if (sign == null) {
      promise.reject("Error", "sign error");
      return;
    }

    promise.resolve(Base64.encodeToString(sign, Base64.NO_WRAP));
  }

  @ReactMethod
  public void encrypt(
    final String key,
    final String iv,
    final String data,
    final int paddingMode,
    Promise promise
  ) {
    byte[] key_bytes = Base64.decode(key, Base64.NO_PADDING);
    byte[] iv_bytes = Base64.decode(iv, Base64.NO_PADDING);
    byte[] data_bytes = Base64.decode(data, Base64.NO_PADDING);

    byte[] result = nativeEncrypt(key_bytes, iv_bytes, data_bytes, paddingMode);

    if (result == null) {
      promise.reject("Error", "encrypt error");
      return;
    }

    promise.resolve(Base64.encodeToString(result, Base64.NO_WRAP));
  }

  @ReactMethod
  public void decrypt(
          final String key,
          final String iv,
          final String data,
          final int paddingMode,
          Promise promise
  ) {
    byte[] key_bytes = Base64.decode(key, Base64.NO_PADDING);
    byte[] iv_bytes = Base64.decode(iv, Base64.NO_PADDING);
    byte[] data_bytes = Base64.decode(data, Base64.NO_PADDING);

    byte[] result = nativeDecrypt(key_bytes, iv_bytes, data_bytes, paddingMode);

    if (result == null) {
      promise.reject("Error", "decrypt error");
      return;
    }

    promise.resolve(Base64.encodeToString(result, Base64.NO_WRAP));
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String schnorrGetPublic(final String priv) {
    byte[] priv_bytes = Base64.decode(priv, Base64.NO_PADDING);

    byte[] pub = nativeSchnorrGetPublic(priv_bytes);

    return Base64.encodeToString(pub, Base64.NO_WRAP);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String schnorrSign(final String priv, final String digest) {
    byte[] priv_bytes = Base64.decode(priv, Base64.NO_PADDING);
    byte[] digest_bytes = Base64.decode(digest, Base64.NO_PADDING);

    byte[] sign = nativeSchnorrSign(priv_bytes, digest_bytes);

    return Base64.encodeToString(sign, Base64.NO_WRAP);
  }

  @ReactMethod()
  public void schnorrSignAsync(
    final String priv,
    final String digest,
    Promise promise
  ) {
    byte[] priv_bytes = Base64.decode(priv, Base64.NO_PADDING);
    byte[] digest_bytes = Base64.decode(digest, Base64.NO_PADDING);

    byte[] sign = nativeSchnorrSign(priv_bytes, digest_bytes);

    if (sign == null) {
      promise.reject("Error", "sign error");
      return;
    }
    
    promise.resolve(Base64.encodeToString(sign, Base64.NO_WRAP));
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public int schnorrVerify(final String pub, final String sign, final String digest) {
    byte[] pub_bytes = Base64.decode(pub, Base64.NO_PADDING);
    byte[] sign_bytes = Base64.decode(sign, Base64.NO_PADDING);
    byte[] digest_bytes = Base64.decode(digest, Base64.NO_PADDING);

    if (!nativeSchnorrVerify(pub_bytes, sign_bytes, digest_bytes)) {
      return 0;
    }
    return 1;
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String schnorrTweakPublic(final String pub, final String root) {
    byte[] pub_bytes = Base64.decode(pub, Base64.NO_PADDING);
    byte[] root_bytes = null;

    if (root != null && !root.isEmpty()) {
      root_bytes = Base64.decode(root, Base64.NO_PADDING);
    }

    byte[] tweak = nativeSchnorrTweakPublic(pub_bytes, root_bytes);

    return Base64.encodeToString(tweak, Base64.NO_WRAP);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String schnorrTweakPrivate(final String priv, final String root) {
    byte[] priv_bytes = Base64.decode(priv, Base64.NO_PADDING);
    byte[] root_bytes = null;

    if (root != null && !root.isEmpty()) {
      root_bytes = Base64.decode(root, Base64.NO_PADDING);
    }

    byte[] tweak = nativeSchnorrTweakPrivate(priv_bytes, root_bytes);

    return Base64.encodeToString(tweak, Base64.NO_WRAP);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public int schnorrVerifyPub(final String pub) {
    byte[] pub_bytes = Base64.decode(pub, Base64.NO_PADDING);

    if (!nativeSchnorrVerifyPub(pub_bytes)) {
      return 0;
    }
    return 1;
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableMap xOnlyPointAddTweak(final String pub, final String tweak) {
    byte[] pub_bytes = Base64.decode(pub, Base64.NO_PADDING);
    byte[] tweak_bytes = Base64.decode(tweak, Base64.NO_PADDING);

    CryptoLibXOnlyPointAddTweak node = nativeXOnlyPointAddTweak(pub_bytes, tweak_bytes);

    if (node == null) {
      return null;
    }

    return node.getMap();
  }
}
