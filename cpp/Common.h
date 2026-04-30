#pragma once

#include <ReactNativeCryptoLibSpecJSI.h>
#include <ReactCommon/CallInvoker.h>

#include <atomic>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace facebook::react::cryptolib {

// Signature of a JSI method thunk, matching TurboModule::MethodMetadata
// but defined here so domain modules don't need access to TurboModule's
// protected inner class. Impl.cpp repackages these into MethodMetadata
// entries on the real methodMap_.
using MethodFn =
  jsi::Value (*)(jsi::Runtime&, TurboModule&, const jsi::Value*, size_t);

struct MethodEntry {
  const char* name;
  size_t argCount;
  MethodFn fn;
};

using MethodMap = std::vector<MethodEntry>;

// Owns an std::vector<uint8_t> behind a jsi::MutableBuffer so native code
// can hand ArrayBuffers back to JS without copying.
class VectorBuffer : public jsi::MutableBuffer {
public:
  explicit VectorBuffer(std::vector<uint8_t>&& data)
    : data_(std::move(data)) {}
  size_t size() const override { return data_.size(); }
  uint8_t* data() override { return data_.data(); }

private:
  std::vector<uint8_t> data_;
};

// Returns a non-NULL pointer for ArrayBuffer data, even when size is 0.
// Some trezor-crypto functions (ripemd160, blake2b, etc.) assert(p != NULL)
// even when length is 0. JSI's ArrayBuffer::data() may return NULL for
// zero-length buffers on some platforms.
inline const uint8_t* safeData(jsi::Runtime& rt, const jsi::ArrayBuffer& buf) {
  static const uint8_t kEmpty = 0;
  return buf.size(rt) == 0 ? &kEmpty : buf.data(rt);
}

inline jsi::Value wrapDigest(jsi::Runtime& rt, std::vector<uint8_t>&& digest) {
  return jsi::ArrayBuffer(rt, std::make_shared<VectorBuffer>(std::move(digest)));
}

inline jsi::ArrayBuffer requireArrayBuffer(
  jsi::Runtime& rt,
  const char* methodName,
  const jsi::Value* args,
  size_t count
) {
  if (count < 1 || !args[0].isObject()) {
    throw jsi::JSError(
      rt, std::string(methodName) + ": expected ArrayBuffer argument");
  }
  auto obj = args[0].asObject(rt);
  if (!obj.isArrayBuffer(rt)) {
    throw jsi::JSError(
      rt, std::string(methodName) + ": argument must be an ArrayBuffer");
  }
  return obj.getArrayBuffer(rt);
}

inline jsi::ArrayBuffer requireArrayBufferAt(
  jsi::Runtime& rt,
  const char* methodName,
  const char* argName,
  const jsi::Value* args,
  size_t count,
  size_t index
) {
  if (count <= index || !args[index].isObject()) {
    throw jsi::JSError(
      rt,
      std::string(methodName) + ": " + argName + " must be an ArrayBuffer");
  }
  auto obj = args[index].asObject(rt);
  if (!obj.isArrayBuffer(rt)) {
    throw jsi::JSError(
      rt,
      std::string(methodName) + ": " + argName + " must be an ArrayBuffer");
  }
  return obj.getArrayBuffer(rt);
}

inline double requireIntAt(
  jsi::Runtime& rt,
  const char* methodName,
  const char* argName,
  const jsi::Value* args,
  size_t count,
  size_t index,
  double minValue,
  double maxValue
) {
  if (count <= index || !args[index].isNumber()) {
    throw jsi::JSError(
      rt, std::string(methodName) + ": " + argName + " must be a number");
  }
  double v = args[index].asNumber();
  if (v < minValue || v > maxValue ||
      v != static_cast<double>(static_cast<int64_t>(v))) {
    throw jsi::JSError(
      rt, std::string(methodName) + ": " + argName + " out of range");
  }
  return v;
}

inline bool requireBoolAt(
  jsi::Runtime& rt,
  const char* methodName,
  const char* argName,
  const jsi::Value* args,
  size_t count,
  size_t index
) {
  if (count <= index || !args[index].isBool()) {
    throw jsi::JSError(
      rt, std::string(methodName) + ": " + argName + " must be a boolean");
  }
  return args[index].getBool();
}

inline std::string requireStringAt(
  jsi::Runtime& rt,
  const char* methodName,
  const char* argName,
  const jsi::Value* args,
  size_t count,
  size_t index
) {
  if (count <= index || !args[index].isString()) {
    throw jsi::JSError(
      rt, std::string(methodName) + ": " + argName + " must be a string");
  }
  return args[index].getString(rt).utf8(rt);
}

// Process-wide handle to the JS thread's CallInvoker. Set once at
// TurboModule construction (cpp/ReactNativeCryptoLibImpl.cpp) and read
// from inside thunks that need to dispatch a result back to JS from a
// worker thread. Stored in a std::shared_ptr so concurrent reads from
// any thread are safe even while the cxx module is being torn down on
// the JS side.
inline std::shared_ptr<CallInvoker>& globalJsInvokerSlot() {
  static std::shared_ptr<CallInvoker> slot;
  return slot;
}

inline void setGlobalJsInvoker(std::shared_ptr<CallInvoker> invoker) {
  globalJsInvokerSlot() = std::move(invoker);
}

inline std::shared_ptr<CallInvoker> globalJsInvoker() {
  return globalJsInvokerSlot();
}

// Wraps a synchronous unit of work in a JS Promise. The executor runs
// synchronously while the Promise is being constructed, so any
// validation throws inside `work` surface as Promise rejections at the
// same JS microtask boundary — callers only ever see async errors.
//
// This sync variant is kept for thunks that don't need to leave the
// JS thread (e.g. pure validation / metadata reads). secureKV's
// crypto-touching paths use makePromiseAsync below.
inline jsi::Value makePromise(
  jsi::Runtime& rt, std::function<jsi::Value(jsi::Runtime&)> work
) {
  auto executor = jsi::Function::createFromHostFunction(
    rt,
    jsi::PropNameID::forAscii(rt, "promiseExecutor"),
    2,
    [work = std::move(work)](
      jsi::Runtime& rt,
      const jsi::Value&,
      const jsi::Value* execArgs,
      size_t
    ) -> jsi::Value {
      auto resolve = execArgs[0].asObject(rt).asFunction(rt);
      auto reject = execArgs[1].asObject(rt).asFunction(rt);
      try {
        resolve.call(rt, work(rt));
      } catch (const jsi::JSError& e) {
        reject.call(rt, e.value());
      } catch (const std::exception& e) {
        reject.call(rt, jsi::JSError(rt, e.what()).value());
      }
      return jsi::Value::undefined();
    }
  );
  return rt.global()
    .getPropertyAsFunction(rt, "Promise")
    .callAsConstructor(rt, std::move(executor));
}

// State shared between the Promise executor (JS thread) and the bg
// thread's invokeAsync continuation. Holds the JS-callable resolve /
// reject so they can fire from the JS thread when the bg work finishes.
struct AsyncPromiseState {
  std::shared_ptr<jsi::Function> resolve;
  std::shared_ptr<jsi::Function> reject;
};

// Wraps a Promise-returning thunk so that synchronous `jsi::JSError`
// throws from Phase 1 (validation, before makePromiseAsync sets up its
// own try/catch) surface as Promise rejections instead of synchronous
// JS throws. Without this, callers using `.catch()` instead of
// `try/await` would miss validation errors — a behavioural regression
// vs the sync `makePromise` path, where the entire work runs inside
// the Promise executor's try-catch.
//
// Usage: each Promise-returning thunk wraps its body in
//   return safeAsyncThunk(rt, [&] { ... existing body ... });
// The body is called immediately, exactly once.
template <typename Body>
jsi::Value safeAsyncThunk(jsi::Runtime& rt, Body body) {
  try {
    return body();
  } catch (const jsi::JSError& e) {
    auto promiseObj = rt.global().getPropertyAsObject(rt, "Promise");
    auto rejectFn = promiseObj.getPropertyAsFunction(rt, "reject");
    // jsi::Value is move-only; clone the JSError's value for the call.
    jsi::Value errVal(rt, e.value());
    return rejectFn.callWithThis(rt, promiseObj, std::move(errVal));
  } catch (const std::exception& e) {
    auto promiseObj = rt.global().getPropertyAsObject(rt, "Promise");
    auto rejectFn = promiseObj.getPropertyAsFunction(rt, "reject");
    return rejectFn.callWithThis(
      rt, promiseObj, jsi::JSError(rt, e.what()).value());
  }
}

// Three-phase async promise scaffolding for thunks whose work must
// leave the JS thread (Keychain / Keystore / biometric prompt paths).
//
// Phase 1 (caller, JS thread): the thunk validates JSI args and
//   prepares C++-typed inputs. This step happens *before* makePromiseAsync
//   is called — synchronous JSError throws from validation surface as
//   immediate Promise rejections via the executor's catch.
//
// Phase 2 (`bgWork`, background thread): runs the platform backend
//   call. May throw std::exception with a `"<op>: reason"` message;
//   the catch path forwards the message to JS as a rejection.
//
// Phase 3 (`finishWork`, JS thread): wraps the BgResult into a
//   jsi::Value (e.g. ArrayBuffer, string, number) and the Promise
//   resolves with it. Only this phase touches jsi::Runtime.
//
// CallInvoker is taken from the global slot set by
// ReactNativeCryptoLibImpl's constructor; this avoids plumbing it
// through every MethodFn signature.
//
// `op` is the JSI-level method name (e.g. "secure_kv_bip32_sign_ecdsa")
// used as the rejection prefix on background failures, matching the
// "<op>: <reason>" shape that errors.ts parses on the JS side.
template <typename BgResult>
jsi::Value makePromiseAsync(
  jsi::Runtime& rt,
  const char* op,
  std::function<BgResult()> bgWork,
  std::function<jsi::Value(jsi::Runtime&, BgResult&&)> finishWork
) {
  auto jsInvoker = globalJsInvoker();
  if (!jsInvoker) {
    throw jsi::JSError(
      rt,
      std::string(op) +
        ": JS invoker not initialised — TurboModule constructor "
        "must run before any cryptolib JS call");
  }

  auto state = std::make_shared<AsyncPromiseState>();

  auto executor = jsi::Function::createFromHostFunction(
    rt,
    jsi::PropNameID::forAscii(rt, "promiseExecutorAsync"),
    2,
    [state](
      jsi::Runtime& rt,
      const jsi::Value&,
      const jsi::Value* execArgs,
      size_t
    ) -> jsi::Value {
      state->resolve = std::make_shared<jsi::Function>(
        execArgs[0].asObject(rt).asFunction(rt));
      state->reject = std::make_shared<jsi::Function>(
        execArgs[1].asObject(rt).asFunction(rt));
      return jsi::Value::undefined();
    });

  auto promise = rt.global()
    .getPropertyAsFunction(rt, "Promise")
    .callAsConstructor(rt, std::move(executor));

  // Spawn a detached thread for the backend call. We pay an OS thread
  // creation per call — acceptable for biometric-tier ops (rare,
  // user-driven, dwarfed by prompt latency) and avoids the complexity
  // of a managed thread pool on multiple platforms. If contention
  // becomes measurable, swap to a static executor.
  std::thread([
    bgWork = std::move(bgWork),
    finishWork = std::move(finishWork),
    state,
    jsInvoker,
    opStr = std::string(op)
  ]() mutable {
    auto resultBox = std::make_shared<BgResult>();
    auto okBox = std::make_shared<bool>(false);
    auto errBox = std::make_shared<std::string>();
    try {
      *resultBox = bgWork();
      *okBox = true;
    } catch (const std::exception& e) {
      *errBox = opStr + ": " + e.what();
    } catch (...) {
      *errBox = opStr + ": unknown error";
    }

    // Hop back to the JS thread to call resolve / reject and (only on
    // success) finishWork — finishWork touches jsi::Runtime to wrap the
    // result in a jsi::Value, so it must run there.
    jsInvoker->invokeAsync([
      state,
      okBox,
      errBox,
      resultBox,
      finishWork = std::move(finishWork)
    ](jsi::Runtime& rt) mutable {
      if (!state->resolve || !state->reject) return;
      if (*okBox) {
        try {
          jsi::Value wrapped = finishWork(rt, std::move(*resultBox));
          state->resolve->call(rt, std::move(wrapped));
        } catch (const jsi::JSError& e) {
          state->reject->call(rt, e.value());
        } catch (const std::exception& e) {
          state->reject->call(rt, jsi::JSError(rt, e.what()).value());
        }
      } else {
        state->reject->call(rt, jsi::JSError(rt, *errBox).value());
      }
    });
  }).detach();

  return promise;
}

// Each domain module (Hash, Mac, Kdf, Rng, Ecdsa, Schnorr) exposes one of
// these from its .cpp. The main Impl constructor calls them all so it can
// stay a thin orchestration layer.
void registerHashMethods(MethodMap& map);
void registerMacMethods(MethodMap& map);
void registerKdfMethods(MethodMap& map);
void registerRngMethods(MethodMap& map);
void registerEcdsaMethods(MethodMap& map);
void registerSchnorrMethods(MethodMap& map);
void registerEd25519Methods(MethodMap& map);
void registerEccMethods(MethodMap& map);
void registerAesMethods(MethodMap& map);
void registerBip39Methods(MethodMap& map);
void registerBip32Methods(MethodMap& map);
void registerSlip39Methods(MethodMap& map);
void registerSecureKVMethods(MethodMap& map);
void registerSecureKVSignMethods(MethodMap& map);
void registerBiometricMethods(MethodMap& map);

}
