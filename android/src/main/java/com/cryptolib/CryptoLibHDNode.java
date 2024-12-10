package com.cryptolib;

import android.util.Base64;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;

public class CryptoLibHDNode {
  public double depth;
  public double child_num;
  public byte[] chain_code;
  public byte[] private_key;
  public byte[] public_key;
  public double fingerprint;
  public String curve;
  public boolean private_derive;

  public static CryptoLibHDNode createNode(ReadableMap data) {
    CryptoLibHDNode node = new CryptoLibHDNode();

    if (data.hasKey("depth")) {
      node.depth = data.getDouble("depth");
    }
    if (data.hasKey("child_num")) {
      node.child_num = data.getDouble("child_num");
    }
    if (data.hasKey("chain_code")) {
      node.chain_code = Base64.decode(data.getString("chain_code"), Base64.NO_PADDING);
    }
    if (data.hasKey("private_key")) {
      node.private_key = Base64.decode(data.getString("private_key"), Base64.NO_PADDING);
    }
    if (data.hasKey("public_key")) {
      node.public_key = Base64.decode(data.getString("public_key"), Base64.NO_PADDING);
    }
    if (data.hasKey("fingerprint")) {
      node.fingerprint = data.getDouble("fingerprint");
    }
    if (data.hasKey("curve")) {
      node.curve = data.getString("curve");
    }
    if (data.hasKey("private_derive")) {
      node.private_derive = data.getBoolean("private_derive");
    }

    return node;
  }

  public WritableMap getMap() {
    WritableMap result = Arguments.createMap();

    result.putDouble("depth", depth);
    result.putDouble("child_num", child_num);
    result.putString("chain_code", Base64.encodeToString(chain_code, Base64.NO_WRAP));
    result.putString("private_key", Base64.encodeToString(private_key, Base64.NO_WRAP));
    result.putString("public_key", Base64.encodeToString(public_key, Base64.NO_WRAP));
    result.putDouble("fingerprint", fingerprint);
    result.putString("curve", curve);
    result.putBoolean("private_derive", private_derive);

    return result;
  }
}
