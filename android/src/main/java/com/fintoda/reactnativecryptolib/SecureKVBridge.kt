package com.fintoda.reactnativecryptolib

import android.app.Activity
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricManager
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
import java.util.concurrent.atomic.AtomicBoolean
import android.util.Log
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
 * Blob format on disk. The leading variant byte both identifies the
 * access-control kind and pins the on-disk layout.
 *
 *   Non-biometric (variant=0):
 *     [ 1 byte variant=0    ]
 *     [ 12 bytes IV         ]
 *     [ ciphertext + 16-byte GCM tag ] ← AES-GCM(plain)
 *
 *   Biometric (variant=1):
 *     [ 1 byte variant=1    ]
 *     [ 4 bytes window BE   ]
 *     [ 2 bytes keyLen BE   ]
 *     [ keyLen bytes UTF-8 key ]   ← plaintext, lets list() enumerate
 *     [ 12 bytes IV         ]
 *     [ ciphertext + 16-byte GCM tag ]
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
  // Biometric master keys are sub-keyed by validity window (seconds).
  // E.g. "cryptolib.kv.master.bio.0." for per-call, "...bio.60." for
  // 60-second sessions. Lazy-create on first use of each window.
  private const val MASTER_KEY_BIO_PREFIX = "cryptolib.kv.master.bio."
  private const val DIR_NAME = "secure_kv"
  private const val IV_LEN = 12
  private const val TAG_BITS = 128
  private const val VARIANT_LEN = 1
  // Plaintext metadata after the variant byte: [hasPp 1B][slotKind 1B].
  // Read by metadata() without AES decrypt; lets the JS layer answer
  // "is this passphrase-wrapped" / "what kind of slot is it" without
  // triggering a biometric prompt.
  private const val META_LEN = 2
  // Biometric blobs additionally carry a 4-byte BE window (seconds)
  // immediately after the variant + meta bytes. Non-biometric blobs do not.
  private const val WINDOW_LEN = 4
  // Biometric blobs carry a 2-byte BE plaintext key length + the UTF-8
  // key bytes immediately after the window. This lets `list()` enumerate
  // biometric items without prompting per blob (the encrypted plaintext
  // also carries a copy of the key for tamper-detection — see decodePlain).
  private const val KEY_PREFIX_LEN_LEN = 2
  // Practical cap mirroring the JSI-side validation; the actual cap
  // is enforced by requireValidKey() in cpp/SecureKVCommon.h.
  private const val KEY_PREFIX_MAX = 1024

  // Mirrors cpp/SecureKVBackend.h's AccessControl enum used at the
  // C++/JNI boundary. The on-disk blob's leading byte uses the same
  // numeric values, so AccessControl and BLOB_VARIANT_* are kept in sync.
  private const val ACCESS_CONTROL_NONE: Int = 0
  private const val ACCESS_CONTROL_BIOMETRIC: Int = 1

  // On-disk blob variants — kept identical to the AccessControl values
  // above so the read path can map disk → access-control with no extra
  // table.
  // - 0 = non-biometric (no prompt, no plaintext header)
  // - 1 = biometric: [variant][window 4B][keyLen 2B][key UTF-8][IV][cipher+tag]
  private const val BLOB_VARIANT_NONE: Int = 0
  private const val BLOB_VARIANT_BIOMETRIC: Int = 1

  // SlotKind enum values mirrored from cpp/SecureKVSlot.h. Stored in the
  // plaintext blob header so metadata() can return slotKind without an
  // AES decrypt. WRAPPED implies the inner kind is hidden behind a
  // passphrase — list() / metadata() can't peek beneath it by design.
  private const val BLOB_SLOT_KIND_BLOB: Int = 0x00
  private const val BLOB_SLOT_KIND_SEED: Int = 0x01
  private const val BLOB_SLOT_KIND_RAW: Int = 0x02
  private const val BLOB_SLOT_KIND_WRAPPED: Int = 0x03

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

  // One-shot guard for the API 28-29 validity-window downgrade warning.
  // Avoids spamming logcat when the host calls `set()` repeatedly with
  // a window > 0 on legacy devices.
  private val legacyWindowWarned = AtomicBoolean(false)

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
    // Prefer the bound RAC if we have it (faster, no reflection). Falls
    // through to ActivityThread reflection if SecureKVActivityHolder
    // hasn't been constructed yet — RN's New Architecture doesn't always
    // honour `needsEagerInit` for legacy NativeModules, so we cannot
    // rely on the RAC-binding path.
    val activity: Activity = reactContext?.currentActivity
      ?: currentActivityFromActivityThread()
      ?: throw SecureKVBiometricException(
        "biometric: no foreground Activity — biometric prompts can only " +
          "be shown while the app is in the foreground"
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

  /**
   * Walks `ActivityThread.mActivities` to find the resumed (non-paused)
   * Activity. Used as a fallback when [reactContext] hasn't been bound
   * — same technique as Sentry, Apollo, ChuckerInterceptor and friends.
   * Returns null on any reflection failure; the caller then surfaces a
   * "no foreground Activity" error.
   */
  private fun currentActivityFromActivityThread(): Activity? {
    return try {
      val atClass = Class.forName("android.app.ActivityThread")
      val at = atClass.getMethod("currentActivityThread").invoke(null)
        ?: return null
      val activitiesField = atClass.getDeclaredField("mActivities")
        .apply { isAccessible = true }
      val activities = activitiesField.get(at) as? Map<*, *> ?: return null
      for (v in activities.values) {
        val recordClass = v?.javaClass ?: continue
        val pausedField = try {
          recordClass.getDeclaredField("paused").apply { isAccessible = true }
        } catch (_: NoSuchFieldException) {
          continue
        }
        if (!pausedField.getBoolean(v)) {
          val activityField = recordClass.getDeclaredField("activity")
            .apply { isAccessible = true }
          return activityField.get(v) as? Activity
        }
      }
      null
    } catch (_: Throwable) {
      null
    }
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

  private fun masterAlias(variant: Int, validityWindowSec: Int): String {
    val pkg = appContext().packageName
    return when (variant) {
      ACCESS_CONTROL_BIOMETRIC ->
        "$MASTER_KEY_BIO_PREFIX$validityWindowSec.$pkg"
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

  /**
   * Checks that the device can actually run a biometric prompt before we
   * try to create an auth-required Keystore key. Without this, the
   * underlying `KeyGenerator.init()` throws a confusing
   * `IllegalStateException: "At least one biometric must be enrolled..."`
   * with no friendly hook for the caller to react to.
   */
  private fun assertBiometricAvailable() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
      throw SecureKVBiometricException(
        "biometric: requires Android 9 (API 28) or newer; this device " +
          "runs API ${Build.VERSION.SDK_INT}"
      )
    }
    val bm = BiometricManager.from(appContext())
    val status = bm.canAuthenticate(
      BiometricManager.Authenticators.BIOMETRIC_STRONG
    )
    when (status) {
      BiometricManager.BIOMETRIC_SUCCESS -> return
      BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
        throw SecureKVBiometricException(
          "biometric: no biometric enrolled — open Settings > Security " +
            "and add a fingerprint or face before using accessControl='biometric'"
        )
      BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
        throw SecureKVBiometricException(
          "biometric: device has no biometric hardware (Class 3 / strong)"
        )
      BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
        throw SecureKVBiometricException(
          "biometric: hardware temporarily unavailable; try again"
        )
      BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ->
        throw SecureKVBiometricException(
          "biometric: a system security update is required before " +
            "biometric auth can be used"
        )
      else ->
        throw SecureKVBiometricException(
          "biometric: not available (status code $status)"
        )
    }
  }

  private fun getOrCreateMasterKey(
    variant: Int,
    validityWindowSec: Int
  ): SecretKey {
    synchronized(lock) {
      val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
      val alias = masterAlias(variant, validityWindowSec)
      val existing = ks.getKey(alias, null) as? SecretKey
      if (existing != null) return existing

      if (variant == ACCESS_CONTROL_BIOMETRIC) {
        assertBiometricAvailable()
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
          // validityWindowSec=0 → per-call. >0 → after one prompt the
          // key is usable for that many seconds without re-auth.
          // AUTH_BIOMETRIC_STRONG excludes device-credential fallback.
          builder.setUserAuthenticationParameters(
            validityWindowSec, KeyProperties.AUTH_BIOMETRIC_STRONG
          )
        } else {
          // API 28-29 lacks setUserAuthenticationParameters. The
          // closest legacy equivalent is
          // setUserAuthenticationValidityDurationSeconds(N): N=-1 means
          // per-operation, N>0 means "any device unlock counts as auth
          // for N seconds". The latter is laxer than what we want
          // (biometric-only) but it's the best Keystore can do here;
          // we still gate the actual unlocking event via BiometricPrompt
          // so the prompt itself is biometric.
          @Suppress("DEPRECATION")
          if (validityWindowSec <= 0) {
            builder.setUserAuthenticationValidityDurationSeconds(-1)
          } else {
            builder.setUserAuthenticationValidityDurationSeconds(
              validityWindowSec
            )
          }
        }
      }

      try {
        gen.init(builder.build())
        return gen.generateKey()
      } catch (e: IllegalStateException) {
        // Belt-and-braces: BiometricManager said SUCCESS, but Keystore
        // still rejected because biometrics were unenrolled mid-flight,
        // or the OEM's Keystore implementation is stricter. Surface as
        // our biometric exception so the caller doesn't see a raw
        // 'At least one biometric must be enrolled' stack trace.
        if (variant == ACCESS_CONTROL_BIOMETRIC) {
          throw SecureKVBiometricException(
            "biometric: Keystore rejected key creation: ${e.message}"
          )
        }
        throw e
      }
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
  private fun runBiometricPrompt(cipher: Cipher, op: String): Cipher =
    runBiometricPromptInternal(
      cipher, op, "Authenticate", "Unlock secure storage", "Cancel"
    )

  private fun runBiometricPromptInternal(
    cipher: Cipher,
    op: String,
    title: String,
    subtitle: String,
    cancelLabel: String
  ): Cipher {
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

    // PromptInfo is per-show, not per-key. Labels come from the
    // caller's BiometricPromptOptions; runBiometricPromptWithLabels
    // applies platform defaults for any empty field before reaching
    // here, so we can use them directly.
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
      .setTitle(title)
      .setSubtitle(subtitle)
      .setNegativeButtonText(cancelLabel)
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

  /**
   * Shows a `BiometricPrompt` *without* a `CryptoObject`. Used for
   * windowed keys, where the cipher cannot be initialised before
   * authentication (Keystore rejects `Cipher.init` itself with
   * `UserNotAuthenticatedException` if no recent auth exists). After
   * a successful prompt here, Keystore considers the user authenticated
   * for the duration of the key's validity window, and any subsequent
   * `Cipher.init`/`doFinal` on auth-required keys gated by
   * BIOMETRIC_STRONG within that window will succeed without further
   * prompting.
   *
   * Also reused by [biometricAuthenticate] — same prompt shape, just
   * with caller-supplied labels and no Keystore key bound to it.
   *
   * Per-call keys (`validityWindow == 0`) cannot use this form — their
   * auth must be tied to a specific cipher via `CryptoObject`; see
   * [runBiometricPrompt].
   */
  private fun runBiometricPromptDeviceUnlock(
    title: String,
    subtitle: String,
    cancelLabel: String,
    op: String
  ) {
    val activity = currentFragmentActivity()
    var failureMsg: String? = null
    var failureIsCancel = false
    val latch = CountDownLatch(1)

    val callback = object : BiometricPrompt.AuthenticationCallback() {
      override fun onAuthenticationSucceeded(
        result: BiometricPrompt.AuthenticationResult
      ) {
        latch.countDown()
      }

      override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        failureIsCancel = when (errorCode) {
          BiometricPrompt.ERROR_USER_CANCELED,
          BiometricPrompt.ERROR_NEGATIVE_BUTTON,
          BiometricPrompt.ERROR_CANCELED -> true
          else -> false
        }
        failureMsg = "biometric: $errString (code $errorCode)"
        latch.countDown()
      }

      override fun onAuthenticationFailed() { /* prompt stays open */ }
    }

    val promptInfo = BiometricPrompt.PromptInfo.Builder()
      .setTitle(title)
      .setSubtitle(subtitle)
      .setNegativeButtonText(cancelLabel)
      .setAllowedAuthenticators(
        androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
      )
      .build()

    val mainExecutor: Executor = androidx.core.content.ContextCompat
      .getMainExecutor(activity)

    activity.runOnUiThread {
      try {
        val prompt = BiometricPrompt(activity, mainExecutor, callback)
        prompt.authenticate(promptInfo)
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
  }

  // Default labels used by the secureKV biometric paths when the host
  // didn't supply BiometricPromptOptions. Host apps that want
  // per-operation copy pass non-empty title/subtitle/cancelLabel into
  // `set()` / `get()`; empty strings fall back to these defaults.
  private fun runBiometricPromptDeviceUnlock(op: String) {
    runBiometricPromptDeviceUnlockWithLabels(op, "", "", "")
  }

  // Caller-supplied labels variant. Empty strings fall back to platform
  // defaults so cross-platform code can pass `""` to mean "use system
  // default copy".
  private fun runBiometricPromptDeviceUnlockWithLabels(
    op: String,
    title: String,
    subtitle: String,
    cancelLabel: String
  ) {
    val t = if (title.isEmpty()) "Authenticate" else title
    val s = if (subtitle.isEmpty()) "Unlock secure storage" else subtitle
    val c = if (cancelLabel.isEmpty()) "Cancel" else cancelLabel
    runBiometricPromptDeviceUnlock(t, s, c, op)
  }

  // CryptoObject-bound prompt with caller-supplied labels. Falls back to
  // the same defaults as runBiometricPromptDeviceUnlock for any empty
  // field so callers can pass `""` to mean "use platform default".
  private fun runBiometricPromptWithLabels(
    cipher: Cipher,
    op: String,
    title: String,
    subtitle: String,
    cancelLabel: String
  ): Cipher {
    val t = if (title.isEmpty()) "Authenticate" else title
    val s = if (subtitle.isEmpty()) "Unlock secure storage" else subtitle
    val c = if (cancelLabel.isEmpty()) "Cancel" else cancelLabel
    return runBiometricPromptInternal(cipher, op, t, s, c)
  }

  /**
   * Walks the exception cause chain looking for a "needs biometric
   * re-auth" signal. Android wraps this differently across versions:
   * sometimes as `UserNotAuthenticatedException` directly (init path,
   * or some OEMs from doFinal), but more commonly during `doFinal` as
   * an `IllegalBlockSizeException` whose cause is
   * `android.security.KeyStoreException("Key user not authenticated")`
   * — that wrapper is **not** a subclass of `GeneralSecurityException`,
   * so a naive catch sees an opaque "GeneralSecurityException: Key
   * user not authenticated" and treats the master key as invalidated.
   *
   * The message wording isn't perfectly stable across versions, so
   * match `not authenticated` substring (case-insensitive) — this
   * covers AOSP's "Key user not authenticated", the JCA-side
   * "User not authenticated", and any minor rewordings.
   */
  private fun isUserNotAuthenticated(t: Throwable?): Boolean {
    var cur: Throwable? = t
    val seen = HashSet<Throwable>()
    while (cur != null && seen.add(cur)) {
      if (cur is UserNotAuthenticatedException) return true
      val msg = cur.message ?: ""
      if (msg.contains("not authenticated", ignoreCase = true)) return true
      cur = cur.cause
    }
    return false
  }

  /**
   * Decrypts a biometric-protected blob.
   *
   * Two distinct prompt patterns, picked by the per-key validity
   * window — both shapes are required by AndroidKeystore:
   *
   * - **window = 0 (per-call)** — Keystore allows `Cipher.init` to
   *   succeed without auth, but `doFinal` requires a `CryptoObject`-
   *   bound BiometricPrompt that authorises *that exact cipher* for
   *   one operation. Use [runBiometricPrompt].
   * - **window > 0 (session)** — Keystore checks recent auth at
   *   `Cipher.init` time. If the window has expired we cannot
   *   produce an initialised cipher to wrap in a `CryptoObject`, so
   *   we use [runBiometricPromptDeviceUnlock] (no `CryptoObject`).
   *   That auth then satisfies any auth-required, BIOMETRIC_STRONG
   *   key for its full validity window — at which point a *fresh*
   *   `Cipher.init` + `doFinal` succeeds without further prompting.
   */
  private fun decryptBiometric(
    masterKey: SecretKey,
    iv: ByteArray,
    sealed: ByteArray,
    validityWindowSec: Int,
    promptTitle: String,
    promptSubtitle: String,
    promptCancel: String
  ): ByteArray {
    fun freshInit(): Cipher {
      val c = Cipher.getInstance("AES/GCM/NoPadding")
      c.init(Cipher.DECRYPT_MODE, masterKey, GCMParameterSpec(TAG_BITS, iv))
      return c
    }

    fun mapInitFailure(e: GeneralSecurityException): Nothing {
      if (e is KeyPermanentlyInvalidatedException) {
        throw SecureKVUnavailableException("unavailable: ${e.message}", e)
      }
      throw SecureKVUnavailableException("unavailable: ${e.message}", e)
    }

    if (validityWindowSec <= 0) {
      // Per-call. init() succeeds; CryptoObject prompt authorises
      // exactly one doFinal on the supplied cipher.
      val cipher = try {
        freshInit()
      } catch (e: GeneralSecurityException) {
        mapInitFailure(e)
      }
      val authed = runBiometricPromptWithLabels(
        cipher, "secureKV.get", promptTitle, promptSubtitle, promptCancel
      )
      return try {
        authed.doFinal(sealed)
      } catch (e: GeneralSecurityException) {
        throw SecureKVUnavailableException("unavailable: ${e.message}", e)
      }
    }

    // Windowed (window > 0). Try the fast-path first; on auth failure
    // anywhere (init or doFinal), prompt without CryptoObject to
    // re-arm the validity window, then retry with a fresh cipher.
    fun retryAfterPromptUnlock(): ByteArray {
      runBiometricPromptDeviceUnlockWithLabels(
        "secureKV.get", promptTitle, promptSubtitle, promptCancel
      )
      val c = try {
        freshInit()
      } catch (e: GeneralSecurityException) {
        mapInitFailure(e)
      }
      return try {
        c.doFinal(sealed)
      } catch (e: GeneralSecurityException) {
        throw SecureKVUnavailableException("unavailable: ${e.message}", e)
      }
    }

    val firstAttempt = try {
      freshInit()
    } catch (e: KeyPermanentlyInvalidatedException) {
      throw SecureKVUnavailableException("unavailable: ${e.message}", e)
    } catch (e: GeneralSecurityException) {
      if (isUserNotAuthenticated(e)) return retryAfterPromptUnlock()
      throw SecureKVUnavailableException("unavailable: ${e.message}", e)
    }
    return try {
      firstAttempt.doFinal(sealed)
    } catch (e: KeyPermanentlyInvalidatedException) {
      throw SecureKVUnavailableException("unavailable: ${e.message}", e)
    } catch (e: GeneralSecurityException) {
      if (isUserNotAuthenticated(e)) retryAfterPromptUnlock()
      else throw SecureKVUnavailableException("unavailable: ${e.message}", e)
    }
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
    // The AccessControl value (0 = none, 1 = biometric) that the read
    // path needs in order to pick the right master key. Same numeric
    // value as the on-disk variant byte (the two enums are kept in sync).
    val accessControl: Int,
    val validityWindowSec: Int,  // 0 for non-biometric
    val iv: ByteArray,
    val sealed: ByteArray,
    // Biometric blobs only — null for non-biometric. list() surfaces
    // this name without prompting.
    val plaintextKey: String?,
    // Plaintext metadata bytes (variant byte + 1B hasPp + 1B slotKind).
    // Surfaced via metadata() without AES decrypt.
    val hasPassphrase: Boolean,
    val slotKind: Int
  )

  private fun parseBlob(blob: ByteArray): ParsedBlob {
    if (blob.size < VARIANT_LEN + META_LEN + IV_LEN + TAG_BITS / 8) {
      throw SecureKVUnavailableException("unavailable: blob truncated")
    }
    val variant = blob[0].toInt() and 0xff
    val hasPp = (blob[1].toInt() and 0xff) != 0
    val slotKindByte = blob[2].toInt() and 0xff
    when (variant) {
      BLOB_VARIANT_NONE -> {
        val iv = blob.copyOfRange(
          VARIANT_LEN + META_LEN, VARIANT_LEN + META_LEN + IV_LEN)
        val sealed = blob.copyOfRange(VARIANT_LEN + META_LEN + IV_LEN, blob.size)
        return ParsedBlob(
          accessControl = ACCESS_CONTROL_NONE,
          validityWindowSec = 0,
          iv = iv,
          sealed = sealed,
          plaintextKey = null,
          hasPassphrase = hasPp,
          slotKind = slotKindByte
        )
      }
      BLOB_VARIANT_BIOMETRIC -> {
        // [variant][hasPp 1B][slotKind 1B][window 4B]
        // [keyLen 2B BE][key UTF-8][IV 12B][cipher+tag]
        val minLen =
          VARIANT_LEN + META_LEN + WINDOW_LEN + KEY_PREFIX_LEN_LEN +
            IV_LEN + TAG_BITS / 8
        if (blob.size < minLen) {
          throw SecureKVUnavailableException(
            "unavailable: biometric blob truncated"
          )
        }
        val window = readBeU32(blob, VARIANT_LEN + META_LEN)
        val keyLenOff = VARIANT_LEN + META_LEN + WINDOW_LEN
        val keyLen =
          ((blob[keyLenOff].toInt() and 0xff) shl 8) or
            (blob[keyLenOff + 1].toInt() and 0xff)
        if (keyLen < 1 || keyLen > KEY_PREFIX_MAX) {
          throw SecureKVUnavailableException(
            "unavailable: biometric keyLen out of range ($keyLen)"
          )
        }
        val keyStart = keyLenOff + KEY_PREFIX_LEN_LEN
        val ivStart = keyStart + keyLen
        if (blob.size < ivStart + IV_LEN + TAG_BITS / 8) {
          throw SecureKVUnavailableException(
            "unavailable: biometric blob too short for declared keyLen"
          )
        }
        val plaintextKey =
          String(blob.copyOfRange(keyStart, ivStart), Charsets.UTF_8)
        val iv = blob.copyOfRange(ivStart, ivStart + IV_LEN)
        val sealed = blob.copyOfRange(ivStart + IV_LEN, blob.size)
        return ParsedBlob(
          accessControl = ACCESS_CONTROL_BIOMETRIC,
          validityWindowSec = window,
          iv = iv,
          sealed = sealed,
          hasPassphrase = hasPp,
          slotKind = slotKindByte,
          plaintextKey = plaintextKey
        )
      }
      else ->
        throw SecureKVUnavailableException(
          "unavailable: unknown blob variant $variant"
        )
    }
  }

  private fun readBeU32(b: ByteArray, off: Int): Int {
    return ((b[off].toInt() and 0xff) shl 24) or
      ((b[off + 1].toInt() and 0xff) shl 16) or
      ((b[off + 2].toInt() and 0xff) shl 8) or
      (b[off + 3].toInt() and 0xff)
  }

  // --- Public API ----------------------------------------------------------

  @JvmStatic
  fun set(
    key: String,
    value: ByteArray,
    accessControl: Int,
    validityWindowSec: Int,
    slotKind: Int,
    promptTitle: String,
    promptSubtitle: String,
    promptCancel: String
  ) {
    assertSingleProcess()
    if (accessControl != ACCESS_CONTROL_NONE &&
      accessControl != ACCESS_CONTROL_BIOMETRIC
    ) {
      throw IllegalArgumentException(
        "secureKV: unknown accessControl variant $accessControl"
      )
    }
    val window = if (accessControl == ACCESS_CONTROL_BIOMETRIC) {
      if (validityWindowSec < 0) {
        throw IllegalArgumentException(
          "secureKV: validityWindow must be >= 0 (got $validityWindowSec)"
        )
      }
      // On API 28-29, Keystore expresses windowed auth via
      // setUserAuthenticationValidityDurationSeconds, which considers
      // ANY device unlock (PIN/pattern included) as a fresh auth event.
      // That breaks the "biometric-only" guarantee, so downgrade to
      // per-call (window=0) where the CryptoObject-bound BiometricPrompt
      // is strictly biometric. Logged once per process to flag the
      // implicit semantic change without spamming logcat.
      if (validityWindowSec > 0 &&
        Build.VERSION.SDK_INT < Build.VERSION_CODES.R
      ) {
        if (legacyWindowWarned.compareAndSet(false, true)) {
          Log.w(
            "secureKV",
            "validityWindow=$validityWindowSec downgraded to 0 on " +
              "API ${Build.VERSION.SDK_INT}: legacy Keystore counts " +
              "any device unlock as auth, which would weaken " +
              "biometric-only enforcement. Per-call BiometricPrompt " +
              "is used instead. Upgrade to API 30+ for true windowed " +
              "biometric sessions."
          )
        }
        0
      } else {
        validityWindowSec
      }
    } else {
      0
    }
    synchronized(lock) {
      val masterKey = getOrCreateMasterKey(accessControl, window)
      val plain = encodePlain(key, value)

      fun freshInit(): Cipher {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, masterKey)
        return c
      }

      // Pair of (iv, sealed). Path differs per access-control variant:
      //
      // - none: plain init + doFinal.
      // - biometric, window=0 (per-call): init + CryptoObject prompt
      //   authorises one doFinal on that cipher.
      // - biometric, window>0 (session): init may itself throw
      //   UserNotAuthenticatedException — Keystore checks recent auth
      //   *at init time* for windowed keys. We can't wrap a non-init'd
      //   cipher in a CryptoObject, so we run a CryptoObject-less
      //   prompt to satisfy the window, then re-init + doFinal.
      val (iv, sealed) = when {
        accessControl == ACCESS_CONTROL_NONE -> {
          val c = try {
            freshInit()
          } catch (e: KeyPermanentlyInvalidatedException) {
            throw SecureKVUnavailableException("unavailable: ${e.message}", e)
          } catch (e: GeneralSecurityException) {
            throw SecureKVUnavailableException("unavailable: ${e.message}", e)
          }
          Pair(c.iv, c.doFinal(plain))
        }
        window == 0 -> {
          val c = try {
            freshInit()
          } catch (e: KeyPermanentlyInvalidatedException) {
            throw SecureKVUnavailableException("unavailable: ${e.message}", e)
          } catch (e: GeneralSecurityException) {
            throw SecureKVUnavailableException("unavailable: ${e.message}", e)
          }
          val authed = runBiometricPromptWithLabels(
            c, "secureKV.set", promptTitle, promptSubtitle, promptCancel
          )
          val out = try {
            authed.doFinal(plain)
          } catch (e: UserNotAuthenticatedException) {
            throw SecureKVBiometricException(
              "secureKV.set: encrypt rejected after auth: ${e.message}"
            )
          }
          Pair(authed.iv, out)
        }
        else -> {
          fun retryAfterPromptUnlock(): Pair<ByteArray, ByteArray> {
            runBiometricPromptDeviceUnlockWithLabels(
              "secureKV.set", promptTitle, promptSubtitle, promptCancel
            )
            val c = try {
              freshInit()
            } catch (e: GeneralSecurityException) {
              // After a successful prompt, init still failing for
              // "not authenticated" means the validity window expired
              // between the prompt and this init — surface as a
              // biometric retry rather than master-key invalidation.
              if (isUserNotAuthenticated(e)) {
                throw SecureKVBiometricException(
                  "secureKV.set: validity window expired between prompt " +
                    "and operation; retry"
                )
              }
              throw SecureKVUnavailableException("unavailable: ${e.message}", e)
            }
            val out = try {
              c.doFinal(plain)
            } catch (e: GeneralSecurityException) {
              if (isUserNotAuthenticated(e)) {
                throw SecureKVBiometricException(
                  "secureKV.set: validity window expired between prompt " +
                    "and operation; retry"
                )
              }
              throw SecureKVUnavailableException("unavailable: ${e.message}", e)
            }
            return Pair(c.iv, out)
          }

          val firstAttempt = try {
            freshInit()
          } catch (e: KeyPermanentlyInvalidatedException) {
            throw SecureKVUnavailableException("unavailable: ${e.message}", e)
          } catch (e: GeneralSecurityException) {
            if (isUserNotAuthenticated(e)) {
              null
            } else {
              throw SecureKVUnavailableException("unavailable: ${e.message}", e)
            }
          }
          if (firstAttempt == null) {
            retryAfterPromptUnlock()
          } else {
            try {
              Pair(firstAttempt.iv, firstAttempt.doFinal(plain))
            } catch (e: KeyPermanentlyInvalidatedException) {
              throw SecureKVUnavailableException("unavailable: ${e.message}", e)
            } catch (e: GeneralSecurityException) {
              if (isUserNotAuthenticated(e)) retryAfterPromptUnlock()
              else throw SecureKVUnavailableException(
                "unavailable: ${e.message}", e
              )
            }
          }
        }
      }

      // Layout:
      //   none      : [variant=0][hasPp 1B][slotKind 1B][IV][cipher+tag]
      //   biometric : [variant=1][hasPp 1B][slotKind 1B][window BE]
      //               [2B keyLen BE][key UTF-8][IV][cipher+tag]
      // The hasPp + slotKind bytes are plaintext metadata so `metadata()`
      // can answer "is this passphrase-wrapped, what kind of slot is it"
      // without an AES decrypt or biometric prompt. The plaintext key in
      // the biometric header lets list() enumerate bio items without
      // prompting per blob — names are not secrets.
      val hasPp: Byte = if (slotKind == BLOB_SLOT_KIND_WRAPPED) 1 else 0
      val keyBytes = if (accessControl == ACCESS_CONTROL_BIOMETRIC) {
        val kb = key.toByteArray(Charsets.UTF_8)
        if (kb.size > KEY_PREFIX_MAX) {
          throw IllegalArgumentException(
            "secureKV: key UTF-8 length ${kb.size} exceeds blob format cap " +
              "($KEY_PREFIX_MAX)"
          )
        }
        kb
      } else null
      val headerLen =
        if (accessControl == ACCESS_CONTROL_BIOMETRIC)
          VARIANT_LEN + META_LEN + WINDOW_LEN + KEY_PREFIX_LEN_LEN +
            (keyBytes?.size ?: 0)
        else VARIANT_LEN + META_LEN
      val out = ByteArray(headerLen + iv.size + sealed.size)
      out[0] = if (accessControl == ACCESS_CONTROL_BIOMETRIC)
        BLOB_VARIANT_BIOMETRIC.toByte()
      else
        BLOB_VARIANT_NONE.toByte()
      out[1] = hasPp
      out[2] = (slotKind and 0xff).toByte()
      if (accessControl == ACCESS_CONTROL_BIOMETRIC && keyBytes != null) {
        out[3] = ((window ushr 24) and 0xff).toByte()
        out[4] = ((window ushr 16) and 0xff).toByte()
        out[5] = ((window ushr 8) and 0xff).toByte()
        out[6] = (window and 0xff).toByte()
        out[7] = ((keyBytes.size ushr 8) and 0xff).toByte()
        out[8] = (keyBytes.size and 0xff).toByte()
        System.arraycopy(
          keyBytes, 0, out,
          VARIANT_LEN + META_LEN + WINDOW_LEN + KEY_PREFIX_LEN_LEN,
          keyBytes.size
        )
      }
      System.arraycopy(iv, 0, out, headerLen, iv.size)
      System.arraycopy(sealed, 0, out, headerLen + iv.size, sealed.size)

      val file = blobFile(key)
      val tmp = File(file.parentFile, "${file.name}.tmp")
      // fsync the tmp file before rename so a power loss after the
      // rename can never expose a half-written blob. Without this,
      // ext4/f2fs may delay the data flush until after the metadata
      // (rename) commit, and a crash in the gap leaves a sealed-but-
      // truncated blob — GCM auth would catch it on next read, but the
      // user sees SecureKVUnavailableError instead of "still old value".
      RandomAccessFile(tmp, "rw").use { raf ->
        raf.write(out)
        try { raf.fd.sync() } catch (_: Throwable) { /* best effort */ }
      }
      if (!tmp.renameTo(file)) {
        // Fall back to delete+rename if the platform refused atomic swap
        file.delete()
        if (!tmp.renameTo(file)) {
          tmp.delete()
          throw RuntimeException("failed to write secureKV blob")
        }
      }
      // Best-effort directory fsync so the rename survives a crash.
      // Not all FS / Android versions honour this; ignore failures.
      try {
        RandomAccessFile(file.parentFile, "r").use { it.fd.sync() }
      } catch (_: Throwable) { /* best effort */ }
    }
  }

  @JvmStatic
  fun get(
    key: String,
    promptTitle: String,
    promptSubtitle: String,
    promptCancel: String
  ): ByteArray? {
    assertSingleProcess()
    val file = blobFile(key)
    if (!file.isFile) return null
    val parsed = parseBlob(file.readBytes())

    val masterKey = getOrCreateMasterKey(
      parsed.accessControl, parsed.validityWindowSec
    )

    val plain = if (parsed.accessControl == ACCESS_CONTROL_BIOMETRIC) {
      decryptBiometric(
        masterKey, parsed.iv, parsed.sealed, parsed.validityWindowSec,
        promptTitle, promptSubtitle, promptCancel
      )
    } else {
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      try {
        cipher.init(
          Cipher.DECRYPT_MODE, masterKey,
          GCMParameterSpec(TAG_BITS, parsed.iv)
        )
        cipher.doFinal(parsed.sealed)
      } catch (e: KeyPermanentlyInvalidatedException) {
        throw SecureKVUnavailableException("unavailable: ${e.message}", e)
      } catch (e: GeneralSecurityException) {
        throw SecureKVUnavailableException("unavailable: ${e.message}", e)
      }
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
   * keys). Both non-biometric and biometric blobs are enumerated:
   *
   * - Non-biometric blobs decrypt without auth (the master key has no
   *   user-auth gate); the key name comes from the encrypted plaintext.
   * - Biometric blobs carry the key name in the plaintext header so
   *   `list()` does not prompt per blob.
   *
   * Two error classes are still distinguished:
   *   - master-key invalidation (KeyPermanentlyInvalidatedException,
   *     UnrecoverableKeyException) — propagates as
   *     SecureKVUnavailableException so the caller learns the entire
   *     store is gone, matching get()'s behaviour.
   *   - single-blob auth failures (AEADBadTagException, BadPaddingException)
   *     — silently skipped as orphans of a prior key generation.
   */
  /**
   * Returns plaintext metadata for `key` without any auth or AES decrypt.
   * Result is `IntArray(5)`:
   *   [0] = exists (0/1)
   *   [1] = accessControl (0=none, 1=biometric)
   *   [2] = validityWindowSec
   *   [3] = hasPassphrase (0/1)
   *   [4] = slotKind (outer slot tag)
   * For missing keys returns `[0,0,0,0,0]`. Read directly from the
   * plaintext blob header — never triggers a biometric prompt or
   * touches the master key.
   */
  @JvmStatic
  fun metadata(key: String): IntArray {
    assertSingleProcess()
    val file = blobFile(key)
    if (!file.isFile) return intArrayOf(0, 0, 0, 0, 0)
    // Only need the first few bytes of the header. Read up to 9 to cover
    // both non-bio (3 bytes) and biometric (9 bytes including window).
    val needed = VARIANT_LEN + META_LEN + WINDOW_LEN
    val head = ByteArray(needed)
    val read = try {
      RandomAccessFile(file, "r").use { raf ->
        val n = raf.read(head)
        if (n < 0) 0 else n
      }
    } catch (_: Throwable) {
      return intArrayOf(0, 0, 0, 0, 0)
    }
    if (read < VARIANT_LEN + META_LEN) return intArrayOf(0, 0, 0, 0, 0)

    val variant = head[0].toInt() and 0xff
    val hasPp = if ((head[1].toInt() and 0xff) != 0) 1 else 0
    val slotKind = head[2].toInt() and 0xff
    val window = when (variant) {
      BLOB_VARIANT_BIOMETRIC -> {
        if (read < needed) 0 else readBeU32(head, VARIANT_LEN + META_LEN)
      }
      else -> 0
    }
    val accessControl = when (variant) {
      BLOB_VARIANT_BIOMETRIC -> ACCESS_CONTROL_BIOMETRIC
      else -> ACCESS_CONTROL_NONE
    }
    return intArrayOf(1, accessControl, window, hasPp, slotKind)
  }

  @JvmStatic
  fun listJoined(): String {
    assertSingleProcess()
    val dir = blobDir()
    val files = dir.listFiles { _, name -> name.endsWith(".bin") }
      ?: return ""

    // Lazily-resolved non-bio master key — only built if we actually
    // see a non-bio blob. Avoids touching Keystore at all for stores
    // that contain only biometric items (relevant on first install,
    // tests, etc.).
    var nonBioMaster: SecretKey? = null
    fun nonBioMasterOrCreate(): SecretKey {
      nonBioMaster?.let { return it }
      val k = try {
        getOrCreateMasterKey(ACCESS_CONTROL_NONE, 0)
      } catch (e: GeneralSecurityException) {
        throw SecureKVUnavailableException("unavailable: ${e.message}", e)
      }
      nonBioMaster = k
      return k
    }

    val out = StringBuilder()
    for (f in files) {
      val blob = try {
        f.readBytes()
      } catch (_: Throwable) {
        continue
      }
      if (blob.size < VARIANT_LEN + META_LEN + IV_LEN + TAG_BITS / 8) continue
      val variant = blob[0].toInt() and 0xff

      val name: String? = when (variant) {
        BLOB_VARIANT_NONE -> {
          val iv = blob.copyOfRange(
            VARIANT_LEN + META_LEN, VARIANT_LEN + META_LEN + IV_LEN)
          val sealed = blob.copyOfRange(VARIANT_LEN + META_LEN + IV_LEN, blob.size)
          val cipher = Cipher.getInstance("AES/GCM/NoPadding")
          try {
            cipher.init(
              Cipher.DECRYPT_MODE, nonBioMasterOrCreate(),
              GCMParameterSpec(TAG_BITS, iv)
            )
          } catch (e: KeyPermanentlyInvalidatedException) {
            throw SecureKVUnavailableException("unavailable: ${e.message}", e)
          } catch (e: UnrecoverableKeyException) {
            throw SecureKVUnavailableException("unavailable: ${e.message}", e)
          }
          val plain = try {
            cipher.doFinal(sealed)
          } catch (_: AEADBadTagException) { null }
            catch (_: BadPaddingException) { null }
          plain?.let { decodePlain(it).first }
        }
        BLOB_VARIANT_BIOMETRIC -> {
          // Plaintext key prefix lets us enumerate without touching
          // Keystore or prompting. parseBlob enforces the length range.
          val parsed = try {
            parseBlob(blob)
          } catch (_: SecureKVUnavailableException) {
            null
          }
          parsed?.plaintextKey
        }
        else -> null
      }

      if (name != null) {
        if (out.isNotEmpty()) out.append('\n')
        out.append(name)
      }
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
      // Rotate master keys too — the caller asked for a wipe, and
      // leftover Keystore aliases (especially per-window biometric ones,
      // `cryptolib.kv.master.bio.<N>.<pkg>`) accumulate over time as
      // hosts experiment with different validityWindow values. Best
      // effort: some OEM Keystore impls reject deletion of in-use keys
      // — swallow those.
      try {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val pkg = appContext().packageName
        val mainAlias = "$MASTER_KEY_PREFIX$pkg"
        val bioSuffix = ".$pkg"
        val toDelete = ks.aliases().toList().filter { alias ->
          alias == mainAlias ||
            (alias.startsWith(MASTER_KEY_BIO_PREFIX) &&
              alias.endsWith(bioSuffix))
        }
        for (alias in toDelete) {
          try { ks.deleteEntry(alias) } catch (_: Throwable) { /* best effort */ }
        }
      } catch (_: Throwable) {
        // Keystore unreachable — blobs are already gone, that's the
        // important part.
      }
    }
  }

  /**
   * Snapshot of biometric availability. Codes match
   * `BiometricStatus` in cpp/SecureKVBackend.h:
   *  - 0 Available
   *  - 1 NoHardware
   *  - 2 NotEnrolled
   *  - 3 HardwareUnavailable
   *  - 4 SecurityUpdateRequired
   *  - 5 UnsupportedOs (API < 28)
   * Does NOT acquire the process lock — it's safe to call from any
   * process at any time, e.g. during app startup before the host has
   * decided whether to even load the secureKV-using screen.
   */
  /**
   * UX-only biometric gate. Shows a system biometric prompt and
   * returns when the user authenticates. Not bound to any
   * cryptographic operation — this is the entrypoint for
   * `biometric.authenticate(...)` from JS, distinct from secureKV's
   * crypto-bound prompts.
   *
   * Empty label arguments are replaced with neutral defaults so the
   * prompt always renders. Skips the secureKV process lock — this
   * call doesn't touch any secureKV state.
   */
  @JvmStatic
  fun biometricAuthenticate(
    title: String,
    subtitle: String,
    cancelLabel: String
  ) {
    val t = if (title.isEmpty()) "Authenticate" else title
    val c = if (cancelLabel.isEmpty()) "Cancel" else cancelLabel
    runBiometricPromptDeviceUnlock(t, subtitle, c, "biometric.authenticate")
  }

  @JvmStatic
  fun biometricStatusCode(): Int {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return 5
    val bm = BiometricManager.from(appContext())
    return when (bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
      BiometricManager.BIOMETRIC_SUCCESS -> 0
      BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> 1
      BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> 2
      BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> 3
      BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> 4
      else -> 3
    }
  }

  @JvmStatic
  fun isHardwareBacked(): Boolean {
    assertSingleProcess()
    return try {
      val masterKey = getOrCreateMasterKey(ACCESS_CONTROL_NONE, 0)
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
