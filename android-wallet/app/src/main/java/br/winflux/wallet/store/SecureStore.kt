package br.winflux.wallet.store

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores the master seed encrypted with AES-256-GCM, using a NON-exportable Android Keystore key
 * (StrongBox when the device has it). The seed is never written in the clear. No cloud backup (see the manifest).
 * Honest limit: it protects against reading the app's files; it does not protect against a rooted device + a malicious
 * app running, nor does it replace the recovery key the user wrote down.
 */
class SecureStore(context: Context) {
    private val prefs = context.getSharedPreferences("winflux_wallet", Context.MODE_PRIVATE)

    fun hasWallet() = prefs.contains(K_MASTER)

    var nodeUrl: String
        get() = prefs.getString(K_NODE, DEFAULT_NODE) ?: DEFAULT_NODE
        set(v) { prefs.edit().putString(K_NODE, v).apply() }

    var nextIndex: Int
        get() = prefs.getInt(K_INDEX, 0)
        set(v) { prefs.edit().putInt(K_INDEX, v).apply() }

    fun saveMaster(master: ByteArray) {
        require(master.size == 32)
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.ENCRYPT_MODE, key())
        val ct = c.doFinal(master)
        prefs.edit().putString(K_MASTER, Base64.encodeToString(c.iv + ct, Base64.NO_WRAP)).apply()
    }

    fun loadMaster(): ByteArray? {
        val blob = prefs.getString(K_MASTER, null) ?: return null
        val raw = Base64.decode(blob, Base64.NO_WRAP)
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, raw.copyOfRange(0, 12)))
        return c.doFinal(raw.copyOfRange(12, raw.size))
    }

    fun wipe() {
        prefs.edit().clear().apply()
        KeyStore.getInstance(ANDROID_KS).apply { load(null) }.deleteEntry(ALIAS)
    }

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KS).apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KS)
        try { gen.init(spec(true)) } catch (e: Exception) { gen.init(spec(false)) }   // sem StrongBox: TEE/software
        return gen.generateKey()
    }

    companion object {
        const val DEFAULT_NODE = "http://10.0.2.2:8081"   // emulator -> node on the PC; on the phone, use the PC's IP on the Wi-Fi
        private const val ANDROID_KS = "AndroidKeyStore"
        private const val ALIAS = "winflux_wallet_master_key"
        private const val TRANSFORM = "AES/GCM/NoPadding"
        private const val K_MASTER = "master_enc"
        private const val K_NODE = "node_url"
        private const val K_INDEX = "next_index"
    }
}
