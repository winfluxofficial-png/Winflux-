package br.winflux.wallet.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import br.winflux.wallet.core.Units

@Composable
fun WalletApp(vm: WalletViewModel) {
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(vm.message) { vm.message?.let { snackbar.showSnackbar(it); vm.message = null } }
    Scaffold(snackbarHost = { SnackbarHost(snackbar) }) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            when (vm.screen) {
                Screen.WELCOME -> Welcome(vm)
                Screen.BACKUP -> Backup(vm)
                Screen.HOME -> Home(vm)
            }
            if (vm.busy) LinearProgressIndicator(Modifier.fillMaxWidth().align(Alignment.TopCenter))
        }
    }
}

@Composable
private fun Page(content: @Composable ColumnScope.() -> Unit) =
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp), content = content)

@Composable
private fun Welcome(vm: WalletViewModel) {
    var restore by remember { mutableStateOf(false) }
    var text by remember { mutableStateOf("") }
    Page {
        Text("Winflux", fontSize = 32.sp, fontWeight = FontWeight.Bold)
        Text("TESTNET wallet. Do not use with real money: the network has not been audited yet.", color = MaterialTheme.colorScheme.error)
        if (!restore) {
            Button(onClick = { vm.createWallet() }, Modifier.fillMaxWidth()) { Text("Create wallet") }
            OutlinedButton(onClick = { restore = true }, Modifier.fillMaxWidth()) { Text("Restore with recovery key") }
        } else {
            OutlinedTextField(text, { text = it }, label = { Text("wflxk1-…") }, modifier = Modifier.fillMaxWidth(), minLines = 3)
            Button(onClick = { vm.restoreWallet(text) }, Modifier.fillMaxWidth()) { Text("Restore") }
            TextButton(onClick = { restore = false }) { Text("Back") }
        }
        NodeField(vm)
    }
}

@Composable
private fun Backup(vm: WalletViewModel) {
    var saved by remember { mutableStateOf(false) }
    Page {
        Text("Write down your recovery key", fontSize = 22.sp, fontWeight = FontWeight.Bold)
        Text("It is the ONLY way to recover your funds if you lose the phone. Whoever has this key controls the wallet. " +
            "Write it on paper, keep it offline and never send it by message or photo.")
        SelectionContainer { Text(vm.recoveryKey ?: "", fontFamily = FontFamily.Monospace, fontSize = 16.sp) }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(saved, { saved = it }); Text("I wrote the key down in a safe place")
        }
        Button(onClick = { vm.confirmBackup() }, enabled = saved, modifier = Modifier.fillMaxWidth()) { Text("Continuar") }
    }
}

@Composable
private fun Home(vm: WalletViewModel) {
    val ctx = LocalContext.current
    val s = vm.snapshot
    var dialog by remember { mutableStateOf<String?>(null) }
    var to by remember { mutableStateOf("") }
    var amount by remember { mutableStateOf("") }
    Page {
        Text("Balance", color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(if (s == null) "…" else "${Units.format(s.balance)} WFLX", fontSize = 34.sp, fontWeight = FontWeight.Bold)
        if (s != null && s.spendable != s.balance)
            Text("Available to spend: ${Units.format(s.spendable)} WFLX (the rest is pending or maturing)", fontSize = 13.sp)
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = { dialog = "send" }, enabled = s != null) { Text("Send") }
            OutlinedButton(onClick = { dialog = "receive" }, enabled = s != null) { Text("Receber") }
            OutlinedButton(onClick = { vm.refresh() }) { Text("Atualizar") }
        }
        vm.lastTxid?.let { Text("Enviado. txid: $it", fontFamily = FontFamily.Monospace, fontSize = 12.sp) }
        HorizontalDivider()
        NodeField(vm)
        TextButton(onClick = { dialog = "delete" }) { Text("Delete wallet from this device", color = MaterialTheme.colorScheme.error) }
    }

    when (dialog) {
        "receive" -> AlertDialog(onDismissRequest = { dialog = null }, confirmButton = { TextButton({ dialog = null }) { Text("Close") } },
            title = { Text("Receber") }, text = {
                val addr = s?.receiveAddress ?: ""
                Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Image(remember(addr) { qrBitmap(addr).asImageBitmap() }, "Address QR code", Modifier.size(220.dp))
                    SelectionContainer { Text(addr, fontFamily = FontFamily.Monospace, fontSize = 12.sp) }
                    TextButton(onClick = {
                        (ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("address", addr))
                    }) { Text("Copy address") }
                    Text("Each receipt uses a new address (more privacy).", fontSize = 12.sp)
                }
            })
        "send" -> {
            val p = vm.prepared
            if (p == null) AlertDialog(onDismissRequest = { dialog = null },
                title = { Text("Send") },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(to, { to = it }, label = { Text("Address wflx1…") }, singleLine = true)
                        OutlinedTextField(amount, { amount = it }, label = { Text("Amount in WFLX") }, singleLine = true)
                    }
                },
                confirmButton = { TextButton({ vm.prepareSend(to, amount) }) { Text("Revisar") } },
                dismissButton = { TextButton({ dialog = null }) { Text("Cancelar") } })
            else AlertDialog(onDismissRequest = { vm.cancelSend() },
                title = { Text("Confirm sending") },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("To:"); Text(p.to, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                        Text("Amount: ${Units.format(p.amount)} WFLX")
                        Text("Fee: ${Units.format(p.fee)} WFLX")
                        Text("Total: ${Units.format(p.amount + p.fee)} WFLX", fontWeight = FontWeight.Bold)
                        Text("Transactions cannot be undone.", fontSize = 12.sp)
                    }
                },
                confirmButton = { TextButton({ vm.confirmSend(); dialog = null; to = ""; amount = "" }) { Text("Send") } },
                dismissButton = { TextButton({ vm.cancelSend() }) { Text("Back") } })
        }
        "delete" -> AlertDialog(onDismissRequest = { dialog = null },
            title = { Text("Delete wallet?") },
            text = { Text("Without the recovery key written down, the funds will be lost forever.") },
            confirmButton = { TextButton({ vm.deleteWallet(); dialog = null }) { Text("Apagar", color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton({ dialog = null }) { Text("Cancelar") } })
    }
}

@Composable
private fun NodeField(vm: WalletViewModel) {
    var url by remember(vm.nodeUrl) { mutableStateOf(vm.nodeUrl) }
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        OutlinedTextField(url, { url = it }, label = { Text("Node (API)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedButton(onClick = { vm.setNode(url) }) { Text("Use this node") }
    }
}
