package br.winflux.wallet.core

data class NodeParams(
    val chainId: String, val symbol: String, val decimals: Int, val minFee: Long, val minFeePerByte: Long,
    val maxTxSize: Int, val maxTxInputs: Int, val maxTxOutputs: Int, val coinbaseMaturity: Int,
)
data class AddrUtxo(val txid: String, val index: Int, val value: Long, val spendableAt: Long)
data class AddrInfo(val address: String, val balance: Long, val seen: Boolean, val height: Long, val utxos: List<AddrUtxo>)

/** Conexão com um nó (qualquer nó serve: a API não tem contas). Bloqueante; o app chama fora da thread principal. */
interface Node {
    fun params(): NodeParams
    fun address(address: String): AddrInfo
    fun submit(txJson: String): String
}

data class Snapshot(val balance: Long, val spendable: Long, val height: Long, val receiveAddress: String, val nextIndex: Int)
data class Prepared(val tx: SignedTx, val fee: Long, val amount: Long, val to: String, val change: String?, val nextIndexAfter: Int)

/** Lógica da carteira sobre um nó: descoberta de endereços (gap 20), saldo, preparo e envio. Sem Android. */
class WalletEngine(val hd: HdWallet, private val node: Node, nextIndex: Int = 0) {
    var nextIndex: Int = nextIndex
        private set
    private var params: NodeParams? = null
    private val scanned = ArrayList<Pair<Int, AddrInfo>>()
    private val pendingSpent = HashSet<Pair<String, Int>>()
    private var height = 0L

    fun params(): NodeParams = params ?: node.params().also { params = it }

    /** Varre os endereços até 20 vazios seguidos; atualiza saldo, UTXOs e o próximo endereço de recebimento. */
    fun refresh(gap: Int = GAP_LIMIT): Snapshot {
        params = node.params()
        scanned.clear()
        var i = 0; var misses = 0; var lastUsed = -1
        while (misses < gap || i < nextIndex) {      // até `gap` vazios seguidos E além dos endereços já entregues
            val info = node.address(hd.address(i))
            scanned.add(i to info)
            if (info.seen) { lastUsed = i; misses = 0 } else misses++
            i++
        }
        nextIndex = maxOf(nextIndex, lastUsed + 1)
        height = scanned.maxOfOrNull { it.second.height } ?: 0
        val live = scanned.flatMap { (_, a) -> a.utxos.map { it.txid to it.index } }.toSet()
        pendingSpent.retainAll(live)                 // o que já saiu do UTXO set deixa de ser "pendente"
        val spendable = spendableUtxos().sumOf { it.value }
        return Snapshot(scanned.sumOf { it.second.balance }, spendable, height, receiveAddress(), nextIndex)
    }

    /** Primeiro endereço (≥ nextIndex) ainda não visto na cadeia: nunca reutiliza. */
    fun receiveAddress(): String {
        var i = nextIndex
        while (scanned.any { it.first == i && it.second.seen }) i++
        return hd.address(i)
    }

    private fun spendableUtxos(): List<Utxo> {
        val next = height + 1                         // altura do próximo bloco (maturidade das recompensas)
        return scanned.flatMap { (_, a) ->
            a.utxos.filter { it.spendableAt <= next && (it.txid to it.index) !in pendingSpent }
                .map { Utxo(it.txid, it.index, it.value, a.address) }
        }
    }

    fun prepare(to: String, amount: Long): Prepared {
        if (scanned.isEmpty()) refresh()
        val p = params()
        val owner = scanned.associate { it.second.address to it.first }
        var ci = nextIndex
        while (scanned.any { it.first == ci && it.second.seen }) ci++
        val change = hd.address(ci)
        val utxos = spendableUtxos()
        val rules = FeeRules(p.minFee, p.minFeePerByte, p.maxTxSize, p.maxTxInputs, p.maxTxOutputs)
        val tx = TxBuilder.build(hd, { owner[it] }, utxos, to, amount, change, p.chainId, rules)
        val usesChange = tx.outputs.any { it.address == change }
        return Prepared(tx, TxBuilder.feeOf(tx, utxos), amount, to, if (usesChange) change else null, if (usesChange) ci + 1 else nextIndex)
    }

    /** Envia e marca as moedas como pendentes (evita reutilizá-las antes da inclusão em bloco). */
    fun send(p: Prepared): String {
        val txid = node.submit(p.tx.toJson())
        p.tx.inputs.forEach { pendingSpent.add(it.txid to it.index) }
        nextIndex = maxOf(nextIndex, p.nextIndexAfter)
        return txid
    }

    companion object { const val GAP_LIMIT = 20 }
}
