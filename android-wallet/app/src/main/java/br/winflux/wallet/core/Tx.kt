package br.winflux.wallet.core

data class Utxo(val txid: String, val index: Int, val value: Long, val address: String)
data class TxIn(val txid: String, val index: Int, val pubkey: String, val signature: String)
data class TxOut(val value: Long, val address: String)

/** Transferência comum assinada (kind = "transfer"). Formato e txid idênticos aos de winflux/blockchain/transaction.py. */
class SignedTx(val chainId: String, val inputs: List<TxIn>, val outputs: List<TxOut>) {
    /** Corpo que define o txid: SEM assinaturas. */
    private fun body(): Map<String, Any?> = mapOf(
        "version" to 1, "chain_id" to chainId, "coinbase_height" to null, "kind" to "transfer", "payload" to null,
        "inputs" to inputs.map { mapOf("txid" to it.txid, "index" to it.index, "pubkey" to it.pubkey) },
        "outputs" to outputs.map { mapOf("value" to it.value, "address" to it.address) })

    val txid: String get() = txidOf(chainId, inputs, outputs)

    fun toMap(): Map<String, Any?> = body().toMutableMap().also { m ->
        m["inputs"] = inputs.map { mapOf("txid" to it.txid, "index" to it.index, "pubkey" to it.pubkey, "signature" to it.signature) }
    }

    fun toJson(): String = CanonicalJson.encode(toMap())

    /** Tamanho usado pela taxa por byte: JSON canônico COM assinaturas (ASCII => 1 byte por caractere). */
    fun size(): Int = toJson().length

    companion object {
        fun txidOf(chainId: String, inputs: List<TxIn>, outputs: List<TxOut>): String {
            val tx = SignedTx(chainId, inputs, outputs)
            return Hashing.sha256("WFLX-TXID-V1".toByteArray(Charsets.US_ASCII),
                CanonicalJson.encode(tx.body()).toByteArray(Charsets.US_ASCII)).toHex()
        }
        fun signingMessage(txid: String): ByteArray = "WFLX-TX-SIGN-V1".toByteArray(Charsets.US_ASCII) + txid.hexToBytes()
    }
}

class WalletException(message: String) : Exception(message)
class InsufficientFunds(message: String) : Exception(message)

data class FeeRules(val minFee: Long, val minFeePerByte: Long, val maxTxSize: Int, val maxInputs: Int, val maxOutputs: Int)

/** Coin selection e assinatura (maiores primeiro), como `build_payment` do nó de referência. */
object TxBuilder {
    /** `owner(address)` devolve o índice HD que controla o endereço, ou null. */
    fun build(
        wallet: HdWallet, owner: (String) -> Int?, utxos: List<Utxo>, to: String, amount: Long, change: String,
        chainId: String, rules: FeeRules,
    ): SignedTx {
        if (!Address.isValid(to) || !Address.isValid(change)) throw WalletException("endereço inválido")
        if (amount <= 0) throw WalletException("valor inválido")
        var trial = rules.minFee
        repeat(8) {
            val tx = assemble(wallet, owner, utxos, to, amount, change, chainId, trial, rules)
            val need = maxOf(rules.minFee, rules.minFeePerByte * tx.size())
            if (tx.size() > rules.maxTxSize) throw WalletException("transação grande demais: consolide as moedas")
            if (trial >= need) return tx
            trial = need
        }
        throw WalletException("não foi possível estimar a taxa")
    }

    fun feeOf(tx: SignedTx, utxos: List<Utxo>): Long {
        val byOp = utxos.associateBy { it.txid to it.index }
        return tx.inputs.sumOf { byOp.getValue(it.txid to it.index).value } - tx.outputs.sumOf { it.value }
    }

    private fun assemble(
        wallet: HdWallet, owner: (String) -> Int?, utxos: List<Utxo>, to: String, amount: Long, change: String,
        chainId: String, fee: Long, rules: FeeRules,
    ): SignedTx {
        val need = Math.addExact(amount, fee)
        val chosen = ArrayList<Utxo>()
        var total = 0L
        for (u in utxos.sortedWith(compareBy<Utxo>({ -it.value }, { it.txid }, { it.index }))) {
            chosen.add(u); total += u.value
            if (total >= need) break
        }
        if (total < need) throw InsufficientFunds("saldo insuficiente: tem $total, precisa $need")
        if (chosen.size > rules.maxInputs) throw WalletException("muitas entradas: consolide as moedas antes")
        val outputs = ArrayList<TxOut>().apply {
            add(TxOut(amount, to))
            if (total - need > 0) add(TxOut(total - need, change))
        }
        if (outputs.size > rules.maxOutputs) throw WalletException("saídas demais")
        val idx = chosen.map { owner(it.address) ?: throw WalletException("sem chave para um dos endereços de origem") }
        val unsigned = chosen.mapIndexed { i, u -> TxIn(u.txid, u.index, wallet.key(idx[i]).pub.toHex(), "") }
        val msg = SignedTx.signingMessage(SignedTx.txidOf(chainId, unsigned, outputs))
        val signed = unsigned.mapIndexed { i, inp -> inp.copy(signature = wallet.sign(idx[i], msg).toHex()) }
        return SignedTx(chainId, signed, outputs)
    }
}
