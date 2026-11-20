package br.winflux.wallet.net

import br.winflux.wallet.core.AddrInfo
import br.winflux.wallet.core.AddrUtxo
import br.winflux.wallet.core.Node
import br.winflux.wallet.core.NodeParams
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class NodeException(message: String) : Exception(message)

/** Cliente HTTP/JSON da API do nó (winflux/api/server.py). Bloqueante: chame fora da thread principal. */
class NodeApi(private val baseUrl: String) : Node {
    private fun call(method: String, path: String, body: String? = null): JSONObject {
        val c = URL(baseUrl + path).openConnection() as HttpURLConnection
        try {
            c.requestMethod = method
            c.connectTimeout = 8000
            c.readTimeout = 15000
            if (body != null) {
                c.doOutput = true
                c.setRequestProperty("Content-Type", "application/json")
                c.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val code = c.responseCode
            val text = (if (code in 200..299) c.inputStream else c.errorStream)?.bufferedReader()?.use { it.readText() } ?: ""
            val obj = try { JSONObject(text) } catch (e: Exception) { throw NodeException("resposta inválida do nó (HTTP $code)") }
            if (code !in 200..299) throw NodeException(obj.optString("error", "erro HTTP $code"))
            return obj
        } catch (e: NodeException) {
            throw e
        } catch (e: Exception) {
            throw NodeException("não foi possível falar com o nó: ${e.message}")
        } finally {
            c.disconnect()
        }
    }

    override fun params(): NodeParams {
        val o = call("GET", "/api/params")
        return NodeParams(
            chainId = o.getString("chain_id"), symbol = o.getString("symbol"), decimals = o.getInt("decimals"),
            minFee = o.getLong("min_fee"), minFeePerByte = o.getLong("min_fee_per_byte"),
            maxTxSize = o.getInt("max_tx_size"), maxTxInputs = o.getInt("max_tx_inputs"),
            maxTxOutputs = o.getInt("max_tx_outputs"), coinbaseMaturity = o.getInt("coinbase_maturity"))
    }

    override fun address(address: String): AddrInfo {
        val o = call("GET", "/api/address/$address")
        val arr = o.getJSONArray("utxos")
        val utxos = (0 until arr.length()).map {
            val u = arr.getJSONObject(it)
            AddrUtxo(u.getString("txid"), u.getInt("index"), u.getLong("value"), u.getLong("spendable_at_height"))
        }
        return AddrInfo(o.getString("address"), o.getLong("balance"), o.getBoolean("seen"), o.getLong("height"), utxos)
    }

    override fun submit(txJson: String): String = call("POST", "/api/tx", txJson).getString("txid")
}
