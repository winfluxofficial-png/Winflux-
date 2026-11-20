package br.winflux.wallet.core

/** Endereços `wflx1…` (winflux/crypto/address.py): base32(SHA-256(pubkey)[:20] ‖ checksum(4)). */
object Address {
    const val PREFIX = "wflx1"

    private fun checksum(h: ByteArray) = Hashing.sha256("WFLX-ADDR-V1".toByteArray(Charsets.US_ASCII), h).copyOf(4)

    private fun encode(h20: ByteArray): String = PREFIX + Base32.encode(h20 + checksum(h20))

    fun fromPubkey(pub: ByteArray): String {
        require(pub.size == 32) { "chave pública deve ter 32 bytes" }
        return encode(Hashing.sha256(pub).copyOf(20))
    }

    /** Só a forma canônica é válida (minúsculas, checksum correto, sem bits sobrando). */
    fun isValid(addr: String): Boolean {
        if (!addr.startsWith(PREFIX)) return false
        val raw = Base32.decode(addr.substring(PREFIX.length)) ?: return false
        if (raw.size != 24) return false
        val h = raw.copyOf(20)
        if (!raw.copyOfRange(20, 24).contentEquals(checksum(h))) return false
        return encode(h) == addr
    }
}
