package com.cryptolib;

import android.util.Base64;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;

public class CryptoLibXOnlyPointAddTweak {
  public double parity;
  public byte[] xOnlyPubkey;

  public WritableMap getMap() {
    WritableMap result = Arguments.createMap();

    result.putDouble("parity", parity);
    result.putString("xOnlyPubkey", Base64.encodeToString(xOnlyPubkey, Base64.NO_WRAP));

    return result;
  }
}
