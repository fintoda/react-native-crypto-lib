#include <jni.h>
#include "react-native-crypto-lib.h"

extern "C"
JNIEXPORT jdouble JNICALL
Java_com_cryptolib_CryptoLibModule_nativeMultiply(JNIEnv *env, jclass type, jdouble a, jdouble b) {
    return cryptolib::multiply(a, b);
}
