package br.winflux.wallet.ui

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import br.winflux.wallet.core.BcEd25519
import br.winflux.wallet.core.HdWallet
import br.winflux.wallet.core.NodeUrl
import br.winflux.wallet.core.Prepared
import br.winflux.wallet.core.Snapshot
import br.winflux.wallet.core.Units
import br.winflux.wallet.core.WalletEngine
import br.winflux.wallet.net.NodeApi
import br.winflux.wallet.store.SecureStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class Screen { WELCOME, BACKUP, HOME }

class WalletViewModel(app: Application) : AndroidViewModel(app) {
    private val store = SecureStore(app)
    private var engine: WalletEngine? = null

    var screen by mutableStateOf(if (store.hasWallet()) Screen.HOME else Screen.WELCOME)
        private set
    var busy by mutableStateOf(false)
        private set
    var message by mutableStateOf<String?>(null)
    var snapshot by mutableStateOf<Snapshot?>(null); private set
    var recoveryKey by mutableStateOf<String?>(null); private set
    var prepared by mutableStateOf<Prepared?>(null); private set
    var lastTxid by mutableStateOf<String?>(null)
    var nodeUrl by mutableStateOf(store.nodeUrl)
        private set

    init { if (store.hasWallet()) unlock() }

    private fun unlock() {
        val master = store.loadMaster()
        if (master == null) { screen = Screen.WELCOME; return }
        engine = WalletEngine(HdWallet(master, BcEd25519), NodeApi(nodeUrl), store.nextIndex)
        refresh()
    }

    fun createWallet() {
        val hd = HdWallet.generate(BcEd25519)
        store.saveMaster(hd.masterCopy())
        store.nextIndex = 0
        recoveryKey = hd.recoveryKey()
        engine = WalletEngine(hd, NodeApi(nodeUrl), 0)
        screen = Screen.BACKUP
    }

    fun restoreWallet(text: String) {
        try {
            val hd = HdWallet.fromRecoveryKey(text, BcEd25519)
            store.saveMaster(hd.masterCopy())
            store.nextIndex = 0
            engine = WalletEngine(hd, NodeApi(nodeUrl), 0)
            screen = Screen.HOME
            refresh()                                   // discovers the addresses already used (gap 20)
        } catch (e: IllegalArgumentException) {
            message = e.message
        }
    }

    fun confirmBackup() { recoveryKey = null; screen = Screen.HOME; refresh() }

    fun refresh() {
        val e = engine ?: return
        launchIo {
            val s = e.refresh()
            store.nextIndex = e.nextIndex
            snapshot = s
        }
    }

    fun setNode(url: String) {
        val n = NodeUrl.normalize(url)
        if (n == null) { message = "Use https://… or http:// only with a local IP (e.g.: http://192.168.0.10:8081)"; return }
        store.nodeUrl = n; nodeUrl = n
        val master = store.loadMaster() ?: return
        engine = WalletEngine(HdWallet(master, BcEd25519), NodeApi(n), store.nextIndex)
        refresh()
    }

    fun prepareSend(to: String, amountText: String) {
        val e = engine ?: return
        val amount = Units.parse(amountText)
        if (amount == null || amount <= 0) { message = "Invalid amount (up to 8 decimal places)"; return }
        launchIo { prepared = e.prepare(to.trim(), amount) }
    }

    fun cancelSend() { prepared = null }

    fun confirmSend() {
        val e = engine ?: return
        val p = prepared ?: return
        launchIo {
            lastTxid = e.send(p)
            prepared = null
            store.nextIndex = e.nextIndex
            snapshot = e.refresh()
        }
    }

    fun deleteWallet() { store.wipe(); engine = null; snapshot = null; screen = Screen.WELCOME }

    private fun launchIo(block: () -> Unit) {
        viewModelScope.launch {
            busy = true
            try { withContext(Dispatchers.IO) { block() } }
            catch (e: Exception) { message = e.message ?: "error" }   // InsufficientFunds, NodeException, WalletException…
            finally { busy = false }
        }
    }
}
