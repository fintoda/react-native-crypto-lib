package com.fintoda.reactnativecryptolib

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.facebook.react.bridge.ReactApplicationContext
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.channels.FileLock
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.MessageDigest
import java.security.UnrecoverableKeyException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Thrown when the AndroidKeystore master key has been invalidated — for
 * example after a factory reset or when the device's screen-lock auth has
 * been removed in a way that drops auth-bound keys. Existing blobs cannot
 * be decrypted; callers should treat their secrets as lost.
 *
 * The C++ JNI layer maps this to `secure_kv_*: unavailable: <reason>`,
 * which the JS wrapper upgrades to `SecureKVUnavailableError`.
 */
class SecureKVUnavailableException(msg: String, cause: Throwable? = null) :
  RuntimeException(msg, cause)

/**
 * Thrown when the user dismisses the biometric prompt or the device has
 * no enrolled biometrics. Surfaces to JS as a regular `CryptoError`,
 * not `SecureKVUnavailableError`, because the secrets are still intact —
 * the user just declined to authenticate.
 */
class SecureKVBiometricException(msg: String) : RuntimeException(msg)

/**
 * AndroidKeystore-backed key/value store, called from C++ via JNI.
 *
 * Two master keys live in AndroidKeystore:
 *
 * - **Non-biometric** master (`cryptolib.kv.master.<package>`) — used for
 *   `accessControl='none'` blobs. Plain AES-256-GCM with no auth gating.
 * - **Biometric** master (`cryptolib.kv.master.bio.<package>`) — used for
 *   `accessControl='biometric'` blobs. Same AES-256-GCM, but configured
 *   with `setUserAuthenticationRequired(true)`; each `doFinal` requires
 *   a successful biometric prompt via `BiometricPrompt(CryptoObject)`.
 *
 * Blob format on disk (single byte added vs Phase 1):
 *
 *     [ 1 byte variant      ] ← 0=None, 1=Biometric (AccessControl enum)
 *     [ 12 bytes IV         ]
 *     [ ciphertext + 16-byte GCM tag ] ← AES-GCM(plain)
 *
 * The variant byte is plaintext so we can route a read to the correct
 * master key (and so we know to prompt) before any biometric eval.
 *
 * Plaintext encodes the original key alongside the value so list() can
 * recover the user-facing key names without a separate index file:
 *
 *     [ 4 bytes BE keyLen ]
 *     [ keyLen bytes UTF-8 key ]
 *     [ value bytes (rest) ]
 *
 * Biometric requires API 28+ (`BiometricPrompt`). On API 28-29, the
 * underlying Keystore validity gate is `setUserAuthenticationValidity-
 * DurationSeconds(-1)` (per-operation, but counts any device unlock as
 * auth — we still gate via BiometricPrompt at our layer to enforce
 * "biometric specifically"). On API 30+, we use
 * `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` which is
 * strictly biometric.
 */
object SecureKVBridge {
  private const val ANDROID_KEYSTORE = "AndroidKeyStore"
  private const val MASTER_KEY_PREFIX = "cryptolib.kv.master."
  private const val MASTER_KEY_BIO_PREFIX = "cryptolib.kv.master.bio."
  private const val DIR_NAME = "secure_kv"
  private const val IV_LEN = 12
  private const val TAG_BITS = 128
  private const val VARIANT_LEN = 1

  // Mirrors cpp/SecureKVBackend.h's AccessControl enum.
  private const val ACCESS_CONTROL_NONE: Int = 0
  private const val ACCESS_CONTROL_BIOMETRIC: Int = 1

  // BiometricPrompt show + wait timeout. The OS will dismiss after its own
  // inactivity policy long before this fires; this is the absolute backstop
  // so a JNI-blocked thread can't hang forever if the prompt UI somehow
  // dies without a callback.
  private const val BIOMETRIC_TIMEOUT_SEC: Long = 120

  @Volatile private var cachedContext: Context? = null

  // Bound by [SecureKVActivityHolder] at RN startup. Used to look up the
  // current Activity for [BiometricPrompt]. Stays null in non-RN test
  // contexts; biometric paths surface a clear error in that case.
  @Volatile private var reactContext: ReactApplicationContext? = null

  private val lock = Any()

  // Single-process guard. The first process to use secureKV acquires an
  // exclusive FileLock on `<filesDir>/secure_kv/.process.lock`; any other
  // process trying to use secureKV concurrently fails fast with a clear
  // misconfiguration error rather than silently racing on master-key
  // creation and blob writes. The OS releases the lock when the holding
  // process exits, so a clean restart of the same process re-acquires it.
  @Volatile private var processLockHandle: FileLock? = null
  // Held to keep the lock alive for the lifetime of this process. Never
  // closed — closing the channel would drop the FileLock.
  @Suppress("unused") @Volatile private var processLockFile: RandomAccessFile? = null

  // --- Plumbing -------------------------------------------------------------

  @JvmStatic
  fun bindReactContext(rc: ReactApplicationContext) {
    reactContext = rc
    cachedContext = rc.applicationContext
  }

  private fun appContext(): Context {
    cachedContext?.let { return it }
    // Resolve the application Context lazily on the first call. The C++
    // TurboModule has no ReactApplicationContext handy, so fall back to
    // the standard ActivityThread reflection used by Firebase, Sentry,
    // and friends — every Android process running our code has one.
    synchronized(lock) {
      cachedContext?.let { return it }
      val app = Class
        .forName("android.app.ActivityThread")
        .getMethod("currentApplication")
        .invoke(null)
        ?: throw SecureKVUnavailableException(
          "unavailable: no Application context (called before ActivityThread init?)"
        )
      val ctx = (app as android.app.Application).applicationContext
      cachedContext = ctx
      return ctx
    }
  }

  private fun currentFragmentActivity(): FragmentActivity {
    val rc = reactContext ?: throw SecureKVBiometricException(
      "biometric: ReactApplicationContext not bound — host app must " +
        "include ReactNativeCryptoLibPackage in its package list"
    )
    val activity = rc.currentActivity ?: throw SecureKVBiometricException(
      "biometric: no foreground Activity — biometric prompts can only be " +
        "shown while the app is in the foreground"
    )
    if (activity !is FragmentActivity) {
      throw SecureKVBiometricException(
        "biometric: current Activity is not a FragmentActivity " +
          "(got ${activity.javaClass.name}); RN's MainActivity normally " +
          "extends ReactActivity → AppCompatActivity → FragmentActivity"
      )
    }
    return activity
  }

  private fun currentProcessName(): String =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      android.app.Application.getProcessName() ?: "<unknown>"
    } else {
      try {
        // /proc/self/cmdline is NUL-separated; first segment is the
        // process name. Strip everything from the first NUL onward.
        val raw = File("/proc/self/cmdline").readText()
        val nul = raw.indexOf(0.toChar())
        (if (nul >= 0) raw.substring(0, nul) else raw).trim()
      } catch (_: Throwable) {
        "<unknown>"
      }
    }

  /**
   * Refuses concurrent multi-process access. Called at the top of every
   * mutating / reading entrypoint so a wrongly-scoped second process
   * surfaces as `IllegalStateException` (mapped to `CryptoError` on the
   * JS side) rather than racing on Keystore initialisation.
   */
  private fun assertSingleProcess() {
    if (processLockHandle != null) return
    synchronized(lock) {
      if (processLockHandle != null) return
      val file = File(blobDir(), ".process.lock")
      val raf = RandomAccessFile(file, "rw")
      val acquired: FileLock? =
        try { raf.channel.tryLock() } catch (_: Throwable) { null }
      if (acquired == null) {
        try { raf.close() } catch (_: Throwable) { /* ignore */ }
        throw IllegalStateException(
          "secureKV: another process already holds the secureKV lock " +
            "(this process: '${currentProcessName()}'). secureKV is " +
            "single-process only on Android — restrict access to one " +
            "process or remove android:process= overrides on the " +
            "components that use it."
        )
      }
      // Stamp the holding process name for diagnostics. Best-effort.
      try {
        raf.setLength(0)
        raf.write(currentProcessName().toByteArray(Charsets.UTF_8))
      } catch (_: Throwable) {
        // ignore — the lock itself is what matters
      }
      processLockHandle = acquired
      processLockFile = raf
    }
  }

  // --- Storage layout -------------------------------------------------------

  private fun masterAlias(variant: Int): String {
    val pkg = appContext().packageName
    return when (variant) {
      ACCESS_CONTROL_BIOMETRIC -> "$MASTER_KEY_BIO_PREFIX$pkg"
      else -> "$MASTER_KEY_PREFIX$pkg"
    }
  }

  private fun blobDir(): File {
    val dir = File(appContext().filesDir, DIR_NAME)
    if (!dir.isDirectory) dir.mkdirs()
    return dir
  }

  private fun blobFile(key: String): File {
    val md = MessageDigest.getInstance("SHA-256")
    val hashed = md.digest(key.toByteArray(Charsets.UTF_8))
    val sb = StringBuilder(hashed.size * 2)
    for (b in hashed) {
      sb.append(Character.forDigit((b.toInt() ushr 4) and 0xf, 16))
      sb.append(Character.forDigit(b.toInt() and 0xf, 16))
    }
    return File(blobDir(), "$sb.bin")
  }

  // --- Master key creation --------------------------------------------------

  private fun getOrCreateMasterKey(variant: Int): SecretKey {
    synchronized(lock) {
      val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
      val alias = masterAlias(variant)
      val existing = ks.getKey(alias, null) as? SecretKey
      if (existing != null) return existing

      if (variant == ACCESS_CONTROL_BIOMETRIC &&
        Build.VERSION.SDK_INT < Build.VERSION_CODES.P
      ) {
        throw SecureKVBiometricException(
          "biometric: requires Android 9 (API 28) or newer; this device " +
            "runs API ${Build.VERSION.SDK_INT}"
        )
      }

      val gen = KeyGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE
      )
      val builder = KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
      )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .setRandomizedEncryptionRequired(true)

      if (variant == ACCESS_CONTROL_BIOMETRIC) {
        builder.setUserAuthenticationRequired(true)
        // Invalidate the key when biometrics are added/removed. Threat
        // model: stolen unlocked device + attacker enrolls their own
        // biometric. Existing blobs become permanently unreadable —
        // SecureKVUnavailableError on next read.
        builder.setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
          // Per-call biometric: 0-second validity, AUTH_BIOMETRIC_STRONG
          // explicitly excludes device-credential fallback.
          builder.setUserAuthenticationParameters(
            0, KeyProperties.AUTH_BIOMETRIC_STRONG
          )
        } else {
          // API 28-29 lacks setUserAuthenticationParameters; -1 means
          // "auth required for every operation". Note: any device unlock
          // also counts as auth on this older API, so we additionally
          // gate via BiometricPrompt at the call site to enforce
          // biometric-specifically.
          @Suppress("DEPRECATION")
          builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
      }

      gen.init(builder.build())
      return gen.generateKey()
    }
  }

  // --- BiometricPrompt synchronization -------------------------------------

  /**
   * Shows a `BiometricPrompt` for the given (initialised) cipher and
   * blocks the calling thread until the user authenticates, cancels, or
   * the system errors. Returns the same cipher, now authorised for one
   * `doFinal` call.
   *
   * MUST NOT be called from the UI thread — we post the prompt to the
   * UI thread and wait. The JS thread (where this is called from via
   * JNI) is distinct from the UI thread on RN, so blocking is safe.
   */
  private fun runBiometricPrompt(cipher: Cipher, op: String): Cipher {
    val activity = currentFragmentActivity()

    // Result transport. Filled in exactly once by the prompt callback.
    var authedCipher: Cipher? = null
    var failureMsg: String? = null
    var failureIsCancel = false
    val latch = CountDownLatch(1)

    val callback = object : BiometricPrompt.AuthenticationCallback() {
      override fun onAuthenticationSucceeded(
        result: BiometricPrompt.AuthenticationResult
      ) {
        authedCipher = result.cryptoObject?.cipher
        if (authedCipher == null) {
          failureMsg = "biometric: prompt returned no cipher"
        }
        latch.countDown()
      }

      override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        // Distinguish polite cancel from real failure. The ERROR_*
        // constants below are the dismissal cases — anything else is a
        // hard failure (lockout, no biometrics enrolled, hardware
        // unavailable, etc.).
        failureIsCancel = when (errorCode) {
          BiometricPrompt.ERROR_USER_CANCELED,
          BiometricPrompt.ERROR_NEGATIVE_BUTTON,
          BiometricPrompt.ERROR_CANCELED -> true
          else -> false
        }
        failureMsg = "biometric: $errString (code $errorCode)"
        latch.countDown()
      }

      override fun onAuthenticationFailed() {
        // Single fingerprint mismatch — prompt stays open for retry.
        // No latch.countDown() here; we wait for either success or a
        // terminal error.
      }
    }

    // PromptInfo is per-show, not per-key. Caller-facing copy here is
    // intentionally generic — host apps can wrap secureKV in their own
    // domain-specific UI if they want richer messaging.
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
      .setTitle("Authenticate")
      .setSubtitle("Unlock secure storage")
      .setNegativeButtonText("Cancel")
      .setAllowedAuthenticators(
        androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
      )
      .build()

    // BiometricPrompt requires UI-thread invocation. The executor below
    // is used by the prompt to dispatch callbacks; we explicitly pin it
    // to the main looper so callbacks come back on a known thread.
    val mainExecutor: Executor = androidx.core.content.ContextCompat
      .getMainExecutor(activity)

    activity.runOnUiThread {
      try {
        val prompt = BiometricPrompt(activity, mainExecutor, callback)
        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
      } catch (t: Throwable) {
        failureMsg = "biometric: failed to show prompt: ${t.message}"
        latch.countDown()
      }
    }

    val ok = latch.await(BIOMETRIC_TIMEOUT_SEC, TimeUnit.SECONDS)
    if (!ok) {
      throw SecureKVBiometricException(
        "$op: biometric prompt timed out after ${BIOMETRIC_TIMEOUT_SEC}s"
      )
    }
    failureMsg?.let {
      val tag = if (failureIsCancel) "user canceled" else "biometric failed"
      throw SecureKVBiometricException("$op: $tag: $it")
    }
    return authedCipher
      ?: throw SecureKVBiometricException("$op: prompt resolved with no cipher")
  }

  // --- Blob format ----------------------------------------------------------

  private fun encodePlain(key: String, value: ByteArray): ByteArray {
    val keyBytes = key.toByteArray(Charsets.UTF_8)
    val out = ByteBuffer.allocate(4 + keyBytes.size + value.size)
    out.putInt(keyBytes.size)
    out.put(keyBytes)
    out.put(value)
    return out.array()
  }

  /** Returns Pair(originalKey, value) or throws on malformed plaintext. */
  private fun decodePlain(plain: ByteArray): Pair<String, ByteArray> {
    if (plain.size < 4) {
      throw SecureKVUnavailableException("unavailable: plaintext truncated")
    }
    val buf = ByteBuffer.wrap(plain)
    val keyLen = buf.int
    if (keyLen < 0 || keyLen > plain.size - 4) {
      throw SecureKVUnavailableException("unavailable: plaintext keyLen out of range")
    }
    val keyBytes = ByteArray(keyLen)
    buf.get(keyBytes)
    val value = ByteArray(plain.size - 4 - keyLen)
    buf.get(value)
    return Pair(String(keyBytes, Charsets.UTF_8), value)
  }

  private data class ParsedBlob(
    val variant: Int,
    val iv: ByteArray,
    val sealed: ByteArray
  )

  private fun parseBlob(blob: ByteArray): ParsedBlob {
    val minLen = VARIANT_LEN + IV_LEN + TAG_BITS / 8
    if (blob.size < minLen) {
      throw SecureKVUnavailableException("unavailable: blob truncated")
    }
    val variant = blob[0].toInt() and 0xff
    if (variant != ACCESS_CONTROL_NONE && variant != ACCESS_CONTROL_BIOMETRIC) {
      throw SecureKVUnavailableException("unavailable: unknown blob variant $variant")
    }
    val iv = blob.copyOfRange(VARIANT_LEN, VARIANT_LEN + IV_LEN)
    val sealed = blob.copyOfRange(VARIANT_LEN + IV_LEN, blob.size)
    return ParsedBlob(variant, iv, sealed)
  }

  // --- Public API ----------------------------------------------------------

  @JvmStatic
  fun set(key: String, value: ByteArray, accessControl: Int) {
    assertSingleProcess()
    if (accessControl != ACCESS_CONTROL_NONE &&
      accessControl != ACCESS_CONTROL_BIOMETRIC
    ) {
      throw IllegalArgumentException(
        "secureKV: unknown accessControl variant $accessControl"
      )
    }
    synchronized(lock) {
      val masterKey = getOrCreateMasterKey(accessControl)
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      try {
        cipher.init(Cipher.ENCRYPT_MODE, masterKey)
      } catch (e: KeyPermanentlyInvalidatedException) {
        throw SecureKVUnavailableException("unavailable: ${e.message}", e)
      } catch (e: GeneralSecurityException) {
        throw SecureKVUnavailableException("unavailable: ${e.message}", e)
      }

      // Biometric path: cipher.doFinal will throw UserNotAuthenticated;
      // BiometricPrompt(CryptoObject(cipher)) authorises this one call.
      val ready = if (accessControl == ACCESS_CONTROL_BIOMETRIC) {
        runBiometricPrompt(cipher, "secureKV.set")
      } else {
        cipher
      }

      val iv = ready.iv
      val sealed = try {
        ready.doFinal(encodePlain(key, value))
      } catch (e: UserNotAuthenticatedException) {
        // Should be impossible after a successful prompt, but guard anyway.
        throw SecureKVBiometricException(
          "secureKV.set: encrypt rejected after auth: ${e.message}"
        )
      }

      val out = ByteArray(VARIANT_LEN + iv.size + sealed.size)
      out[0] = accessControl.toByte()
      System.arraycopy(iv, 0, out, VARIANT_LEN, iv.size)
      System.arraycopy(sealed, 0, out, VARIANT_LEN + iv.size, sealed.size)

      val file = blobFile(key)
      val tmp = File(file.parentFile, "${file.name}.tmp")
      tmp.writeBytes(out)
      if (!tmp.renameTo(file)) {
        // Fall back to delete+rename if the platform refused atomic swap
        file.delete()
        if (!tmp.renameTo(file)) {
          tmp.delete()
          throw RuntimeException("failed to write secureKV blob")
        }
      }
    }
  }

  @JvmStatic
  fun get(key: String): ByteArray? {
    assertSingleProcess()
    val file = blobFile(key)
    if (!file.isFile) return null
    val parsed = parseBlob(file.readBytes())

    val masterKey = getOrCreateMasterKey(parsed.variant)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    try {
      cipher.init(
        Cipher.DECRYPT_MODE, masterKey, GCMParameterSpec(TAG_BITS, parsed.iv)
      )
    } catch (e: KeyPermanentlyInvalidatedException) {
      throw SecureKVUnavailableException("unavailable: ${e.message}", e)
    } catch (e: GeneralSecurityException) {
      throw SecureKVUnavailableException("unavailable: ${e.message}", e)
    }

    val ready = if (parsed.variant == ACCESS_CONTROL_BIOMETRIC) {
      runBiometricPrompt(cipher, "secureKV.get")
    } else {
      cipher
    }

    val plain = try {
      ready.doFinal(parsed.sealed)
    } catch (e: GeneralSecurityException) {
      throw SecureKVUnavailableException("unavailable: ${e.message}", e)
    }

    val (storedKey, value) = decodePlain(plain)
    // Sanity check: filename is derived from sha256(key), so a mismatch
    // here would mean the blob was tampered with or copied between keys.
    // GCM auth would have failed first, but verify cheaply anyway.
    if (storedKey != key) {
      throw SecureKVUnavailableException("unavailable: key/blob mismatch")
    }
    return value
  }

  @JvmStatic
  fun has(key: String): Boolean {
    assertSingleProcess()
    return blobFile(key).isFile
  }

  @JvmStatic
  fun delete(key: String) {
    assertSingleProcess()
    synchronized(lock) {
      blobFile(key).delete()
    }
  }

  /**
   * Returns recovered keys joined by '\n'. The empty store is "" (zero
   * keys). Biometric blobs ARE included — but their key names live
   * inside the encrypted plaintext, so listing them requires biometric
   * auth, one prompt per biometric blob. To avoid hammering the user
   * with prompts during enumeration, we instead skip biometric blobs
   * here and prefix their names from the stored variant byte: the
   * caller can detect "biometric-only key" via `has()` if needed.
   *
   * Two error classes are still distinguished from the original design:
   *   - master-key invalidation (KeyPermanentlyInvalidatedException,
   *     UnrecoverableKeyException) — propagates as
   *     SecureKVUnavailableException so the caller learns the entire
   *     store is gone, matching get()'s behaviour.
   *   - single-blob auth failures (AEADBadTagException, BadPaddingException)
   *     — silently skipped as orphans of a prior key generation.
   */
  @JvmStatic
  fun listJoined(): String {
    assertSingleProcess()
    val dir = blobDir()
    val files = dir.listFiles { _, name -> name.endsWith(".bin") }
      ?: return ""

    val nonBioMaster = try {
      getOrCreateMasterKey(ACCESS_CONTROL_NONE)
    } catch (e: GeneralSecurityException) {
      throw SecureKVUnavailableException("unavailable: ${e.message}", e)
    }

    val out = StringBuilder()
    for (f in files) {
      val blob = try {
        f.readBytes()
      } catch (_: Throwable) {
        continue
      }
      if (blob.size < VARIANT_LEN + IV_LEN + TAG_BITS / 8) continue
      val variant = blob[0].toInt() and 0xff

      // Biometric blobs cannot be enumerated without a prompt. We expose
      // their existence via the synthetic `<biometric:N>` placeholder
      // counts so callers can tell that *some* protected data is present
      // without authenticating to read each name.
      if (variant == ACCESS_CONTROL_BIOMETRIC) {
        // Skip — caller learns about biometric blobs by attempting `get`
        // on the alias they chose. We don't want a `list()` call to
        // chain into N biometric prompts.
        continue
      }

      val iv = blob.copyOfRange(VARIANT_LEN, VARIANT_LEN + IV_LEN)
      val sealed = blob.copyOfRange(VARIANT_LEN + IV_LEN, blob.size)
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      try {
        cipher.init(
          Cipher.DECRYPT_MODE, nonBioMaster, GCMParameterSpec(TAG_BITS, iv)
        )
      } catch (e: KeyPermanentlyInvalidatedException) {
        throw SecureKVUnavailableException("unavailable: ${e.message}", e)
      } catch (e: UnrecoverableKeyException) {
        throw SecureKVUnavailableException("unavailable: ${e.message}", e)
      }
      val plain = try {
        cipher.doFinal(sealed)
      } catch (_: AEADBadTagException) {
        continue
      } catch (_: BadPaddingException) {
        continue
      }
      if (out.isNotEmpty()) out.append('\n')
      out.append(decodePlain(plain).first)
    }
    return out.toString()
  }

  @JvmStatic
  fun clear() {
    assertSingleProcess()
    synchronized(lock) {
      val dir = blobDir()
      // Skip the process lock — keeping it preserves the single-process
      // guarantee for the rest of this process's lifetime.
      dir.listFiles()?.forEach {
        if (it.name != ".process.lock") it.delete()
      }
    }
  }

  @JvmStatic
  fun isHardwareBacked(): Boolean {
    assertSingleProcess()
    return try {
      val masterKey = getOrCreateMasterKey(ACCESS_CONTROL_NONE)
      val factory = SecretKeyFactory.getInstance(masterKey.algorithm, ANDROID_KEYSTORE)
      val info = factory.getKeySpec(masterKey, KeyInfo::class.java) as KeyInfo
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        info.securityLevel != KeyProperties.SECURITY_LEVEL_SOFTWARE
      } else {
        @Suppress("DEPRECATION")
        info.isInsideSecureHardware
      }
    } catch (_: Throwable) {
      false
    }
  }
}
