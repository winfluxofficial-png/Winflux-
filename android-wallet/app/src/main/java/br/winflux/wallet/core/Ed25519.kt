package br.winflux.wallet.core

/** Ed25519 atrás de uma interface: BouncyCastle no app (`BcEd25519`), JDK nos testes de JVM. */
interface Ed25519 {
    fun publicKey(seed: ByteArray): ByteArray
    fun sign(seed: ByteArray, message: ByteArray): ByteArray
}
