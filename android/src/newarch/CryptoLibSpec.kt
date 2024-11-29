package com.cryptolib

import com.facebook.react.bridge.ReactApplicationContext

abstract class CryptoLibSpec internal constructor(context: ReactApplicationContext) :
  NativeCryptoLibSpec(context) {
}
