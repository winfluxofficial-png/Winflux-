package br.winflux.wallet.core

/** Ed25519 behind an interface: BouncyCastle in the app (`BcEd25519`), the JDK in the JVM tests. */
interface Ed25519 {
    fun publicKey(seed: ByteArray): ByteArray
    fun sign(seed: ByteArray, message: ByteArray): ByteArray
}
