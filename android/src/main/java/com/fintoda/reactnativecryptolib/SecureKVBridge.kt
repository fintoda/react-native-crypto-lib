package com.fintoda.reactnativecryptolib

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.io.File
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.MessageDigest
import java.security.UnrecoverableKeyException
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
 * AndroidKeystore-backed key/value store, called from C++ via JNI.
 *
 * Layout: a single hardware-backed AES-256-GCM master key (alias derived
 * from `applicationId`) wraps each value into a freestanding blob stored
 * at `<filesDir>/secure_kv/<sha256(key)>.bin`. Blob format:
 *
 *     [ 12 bytes IV ]
 *     [ ciphertext + 16-byte GCM tag ] ← AES-GCM(plain)
 *
 * Plaintext encodes the original key alongside the value so list() can
 * recover the user-facing key names without a separate index file:
 *
 *     [ 4 bytes BE keyLen ]
 *     [ keyLen bytes UTF-8 key ]
 *     [ value bytes (rest) ]
 *
 * No biometric / user-auth requirement is set on the master key — first
 * version is a synchronous, no-prompt store. Auth gating will be opt-in
 * via `accessControl` later.
 */
object SecureKVBridge {
  private const val ANDROID_KEYSTORE = "AndroidKeyStore"
  private const val MASTER_KEY_PREFIX = "cryptolib.kv.master."
  private const val DIR_NAME = "secure_kv"
  private const val IV_LEN = 12
  private const val TAG_BITS = 128

  @Volatile private var cachedContext: Context? = null
  private val lock = Any()

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

  private fun masterAlias(): String =
    "$MASTER_KEY_PREFIX${appContext().packageName}"

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

  private fun getOrCreateMasterKey(): SecretKey {
    synchronized(lock) {
      val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
      val alias = masterAlias()
      val existing = ks.getKey(alias, null) as? SecretKey
      if (existing != null) return existing
      val gen = KeyGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE
      )
      val spec = KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
      )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .setRandomizedEncryptionRequired(true)
        .build()
      gen.init(spec)
      return gen.generateKey()
    }
  }

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

  @JvmStatic
  fun set(key: String, value: ByteArray) {
    synchronized(lock) {
      val masterKey = getOrCreateMasterKey()
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      try {
        cipher.init(Cipher.ENCRYPT_MODE, masterKey)
      } catch (e: GeneralSecurityException) {
        throw SecureKVUnavailableException("unavailable: ${e.message}", e)
      }
      val iv = cipher.iv
      val sealed = cipher.doFinal(encodePlain(key, value))

      val out = ByteArray(iv.size + sealed.size)
      System.arraycopy(iv, 0, out, 0, iv.size)
      System.arraycopy(sealed, 0, out, iv.size, sealed.size)

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
    val file = blobFile(key)
    if (!file.isFile) return null
    val blob = file.readBytes()
    if (blob.size < IV_LEN + TAG_BITS / 8) {
      throw SecureKVUnavailableException("unavailable: blob truncated")
    }
    val iv = blob.copyOfRange(0, IV_LEN)
    val sealed = blob.copyOfRange(IV_LEN, blob.size)

    val masterKey = getOrCreateMasterKey()
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    try {
      cipher.init(Cipher.DECRYPT_MODE, masterKey, GCMParameterSpec(TAG_BITS, iv))
    } catch (e: GeneralSecurityException) {
      throw SecureKVUnavailableException("unavailable: ${e.message}", e)
    }
    val plain = try {
      cipher.doFinal(sealed)
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
  fun has(key: String): Boolean = blobFile(key).isFile

  @JvmStatic
  fun delete(key: String) {
    synchronized(lock) {
      blobFile(key).delete()
    }
  }

  /**
   * Returns recovered keys joined by '\n'. The empty store is "" (zero
   * keys). Same delimiter trick used by slip39_combine — keeps the JNI
   * surface to a single jstring rather than a String[].
   *
   * Distinguishes two error classes:
   *   - master-key invalidation (KeyPermanentlyInvalidatedException,
   *     UnrecoverableKeyException) — propagates as
   *     SecureKVUnavailableException so the caller learns the entire
   *     store is gone, matching get()'s behaviour.
   *   - single-blob auth failures (AEADBadTagException, BadPaddingException)
   *     — silently skipped as orphans of a prior key generation. The
   *     enumeration of healthy blobs continues.
   */
  @JvmStatic
  fun listJoined(): String {
    val dir = blobDir()
    val files = dir.listFiles { _, name -> name.endsWith(".bin") }
      ?: return ""
    val masterKey = try {
      getOrCreateMasterKey()
    } catch (e: GeneralSecurityException) {
      throw SecureKVUnavailableException("unavailable: ${e.message}", e)
    }
    val out = StringBuilder()
    for (f in files) {
      val blob = f.readBytes()
      if (blob.size < IV_LEN + TAG_BITS / 8) continue
      val iv = blob.copyOfRange(0, IV_LEN)
      val sealed = blob.copyOfRange(IV_LEN, blob.size)
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      try {
        cipher.init(Cipher.DECRYPT_MODE, masterKey, GCMParameterSpec(TAG_BITS, iv))
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
    synchronized(lock) {
      val dir = blobDir()
      dir.listFiles()?.forEach { it.delete() }
    }
  }

  @JvmStatic
  fun isHardwareBacked(): Boolean {
    return try {
      val masterKey = getOrCreateMasterKey()
      val factory = SecretKeyFactory.getInstance(masterKey.algorithm, ANDROID_KEYSTORE)
      val info = factory.getKeySpec(masterKey, KeyInfo::class.java) as KeyInfo
      if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
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
