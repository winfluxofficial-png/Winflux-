package br.winflux.wallet.core

/** Carteira HD determinística, compatível com `winflux/wallet/hd.py` (mesma chave de recuperação, mesmos endereços). */
class HdWallet(master: ByteArray, private val ed: Ed25519) {
    private val master = master.copyOf()

    init { require(master.size == 32) { "semente-mestra deve ter 32 bytes" } }

    class Key(val index: Int, val seed: ByteArray, val pub: ByteArray, val address: String)

    private val cache = HashMap<Int, Key>()

    fun key(index: Int): Key = cache.getOrPut(index) {
        require(index in 0 until Int.MAX_VALUE)
        val seed = Hashing.hkdfSha256(
            master, "WFLX-HD-SALT-V1".toByteArray(Charsets.US_ASCII),
            "WFLX-HD-V1/".toByteArray(Charsets.US_ASCII) + java.nio.ByteBuffer.allocate(4).putInt(index).array())
        val pub = ed.publicKey(seed)
        Key(index, seed, pub, Address.fromPubkey(pub))
    }

    fun address(index: Int) = key(index).address

    fun sign(index: Int, message: ByteArray) = ed.sign(key(index).seed, message)

    fun masterCopy(): ByteArray = master.copyOf()

    fun recoveryKey(): String = encodeRecoveryKey(master)

    companion object {
        const val RECOVERY_PREFIX = "wflxk1-"

        fun generate(ed: Ed25519): HdWallet = HdWallet(ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }, ed)

        fun fromRecoveryKey(text: String, ed: Ed25519) = HdWallet(decodeRecoveryKey(text), ed)

        private fun tag(seed: ByteArray) = Hashing.sha256("WFLX-RECOVERY-V1".toByteArray(Charsets.US_ASCII), seed).copyOf(4)

        fun encodeRecoveryKey(seed: ByteArray): String {
            require(seed.size == 32)
            val b32 = Base32.encode(seed + tag(seed))
            return RECOVERY_PREFIX + b32.chunked(4).joinToString("-")
        }

        /** Tolera hífens, espaços e maiúsculas. Lança IllegalArgumentException se inválida (erro de digitação etc.). */
        fun decodeRecoveryKey(text: String): ByteArray {
            val t = text.lowercase().filter { !it.isWhitespace() && it != '-' }
            val prefix = RECOVERY_PREFIX.trimEnd('-')
            require(t.startsWith(prefix)) { "chave de recuperação com prefixo inválido" }
            val body = t.substring(prefix.length)
            val raw = Base32.decode(body) ?: throw IllegalArgumentException("chave de recuperação malformada")
            require(raw.size == 36 && Base32.encode(raw) == body && raw.copyOfRange(32, 36).contentEquals(tag(raw.copyOf(32)))) {
                "chave de recuperação inválida (erro de digitação?)"
            }
            return raw.copyOf(32)
        }
    }
}
