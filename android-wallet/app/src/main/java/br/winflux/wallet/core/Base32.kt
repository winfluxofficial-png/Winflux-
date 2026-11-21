package br.winflux.wallet.core

/** Base32 RFC 4648, lowercase, no padding (like `base64.b32encode(...).lower().rstrip("=")`). */
object Base32 {
    private const val ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"

    fun encode(data: ByteArray): String {
        val sb = StringBuilder()
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) { sb.append(ALPHABET[(buffer shr (bits - 5)) and 31]); bits -= 5 }
            buffer = buffer and ((1 shl bits) - 1)
        }
        if (bits > 0) sb.append(ALPHABET[(buffer shl (5 - bits)) and 31])
        return sb.toString()
    }

    /** null if there is a character outside the alphabet or an impossible length. The caller checks the canonical form. */
    fun decode(s: String): ByteArray? {
        if (s.any { it !in ALPHABET }) return null
        if ((s.length * 5) % 8 >= 5) return null
        val out = java.io.ByteArrayOutputStream()
        var buffer = 0
        var bits = 0
        for (c in s) {
            buffer = (buffer shl 5) or ALPHABET.indexOf(c)
            bits += 5
            if (bits >= 8) { out.write((buffer shr (bits - 8)) and 0xFF); bits -= 8 }
            buffer = buffer and ((1 shl bits) - 1)
        }
        return out.toByteArray()
    }
}
