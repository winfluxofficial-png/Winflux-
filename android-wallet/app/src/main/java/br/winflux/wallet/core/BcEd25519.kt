package br.winflux.wallet.core

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/** Pure Ed25519 (RFC 8032), deterministic, like the `cryptography` library the node uses. */
object BcEd25519 : Ed25519 {
    override fun publicKey(seed: ByteArray): ByteArray {
        require(seed.size == 32)
        return Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
    }

    override fun sign(seed: ByteArray, message: ByteArray): ByteArray {
        require(seed.size == 32)
        val s = Ed25519Signer()
        s.init(true, Ed25519PrivateKeyParameters(seed, 0))
        s.update(message, 0, message.size)
        return s.generateSignature()
    }
}
