package br.winflux.wallet.core

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Hash primitives. Identical to the Python node's (winflux/crypto/hashing.py). */
object Hashing {
    fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        parts.forEach { md.update(it) }
        return md.digest()
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** HKDF-SHA256 (RFC 5869), like `cryptography.hazmat...HKDF` used in wallet/hd.py. */
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int = 32): ByteArray {
        require(length in 1..255 * 32 && salt.isNotEmpty())
        val prk = hmacSha256(salt, ikm)
        var t = ByteArray(0)
        val out = java.io.ByteArrayOutputStream()
        var i = 1
        while (out.size() < length) {
            t = hmacSha256(prk, t + info + byteArrayOf(i.toByte()))
            out.write(t)
            i++
        }
        return out.toByteArray().copyOf(length)
    }
}

private const val HEX = "0123456789abcdef"

fun ByteArray.toHex(): String {
    val sb = StringBuilder(size * 2)
    for (b in this) { sb.append(HEX[(b.toInt() shr 4) and 15]); sb.append(HEX[b.toInt() and 15]) }
    return sb.toString()
}

fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0 && all { it in HEX }) { "invalid hex" }
    return ByteArray(length / 2) { ((HEX.indexOf(this[2 * it]) shl 4) or HEX.indexOf(this[2 * it + 1])).toByte() }
}
