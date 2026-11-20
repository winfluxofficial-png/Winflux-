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
        Text("Carteira de TESTNET. Não use com dinheiro real: a rede ainda não passou por auditoria.", color = MaterialTheme.colorScheme.error)
        if (!restore) {
            Button(onClick = { vm.createWallet() }, Modifier.fillMaxWidth()) { Text("Criar carteira") }
            OutlinedButton(onClick = { restore = true }, Modifier.fillMaxWidth()) { Text("Restaurar com chave de recuperação") }
        } else {
            OutlinedTextField(text, { text = it }, label = { Text("wflxk1-…") }, modifier = Modifier.fillMaxWidth(), minLines = 3)
            Button(onClick = { vm.restoreWallet(text) }, Modifier.fillMaxWidth()) { Text("Restaurar") }
            TextButton(onClick = { restore = false }) { Text("Voltar") }
        }
        NodeField(vm)
    }
}

@Composable
private fun Backup(vm: WalletViewModel) {
    var saved by remember { mutableStateOf(false) }
    Page {
        Text("Anote sua chave de recuperação", fontSize = 22.sp, fontWeight = FontWeight.Bold)
        Text("É a ÚNICA forma de recuperar seus fundos se perder o celular. Quem tiver esta chave controla a carteira. " +
            "Escreva em papel, guarde offline e nunca envie por mensagem ou foto.")
        SelectionContainer { Text(vm.recoveryKey ?: "", fontFamily = FontFamily.Monospace, fontSize = 16.sp) }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(saved, { saved = it }); Text("Anotei a chave em local seguro")
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
        Text("Saldo", color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(if (s == null) "…" else "${Units.format(s.balance)} WFLX", fontSize = 34.sp, fontWeight = FontWeight.Bold)
        if (s != null && s.spendable != s.balance)
            Text("Disponível para gastar: ${Units.format(s.spendable)} WFLX (o resto está pendente ou maturando)", fontSize = 13.sp)
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = { dialog = "send" }, enabled = s != null) { Text("Enviar") }
            OutlinedButton(onClick = { dialog = "receive" }, enabled = s != null) { Text("Receber") }
            OutlinedButton(onClick = { vm.refresh() }) { Text("Atualizar") }
        }
        vm.lastTxid?.let { Text("Enviado. txid: $it", fontFamily = FontFamily.Monospace, fontSize = 12.sp) }
        HorizontalDivider()
        NodeField(vm)
        TextButton(onClick = { dialog = "delete" }) { Text("Apagar carteira deste aparelho", color = MaterialTheme.colorScheme.error) }
    }

    when (dialog) {
        "receive" -> AlertDialog(onDismissRequest = { dialog = null }, confirmButton = { TextButton({ dialog = null }) { Text("Fechar") } },
            title = { Text("Receber") }, text = {
                val addr = s?.receiveAddress ?: ""
                Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Image(remember(addr) { qrBitmap(addr).asImageBitmap() }, "QR do endereço", Modifier.size(220.dp))
                    SelectionContainer { Text(addr, fontFamily = FontFamily.Monospace, fontSize = 12.sp) }
                    TextButton(onClick = {
                        (ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("endereço", addr))
                    }) { Text("Copiar endereço") }
                    Text("Cada recebimento usa um endereço novo (mais privacidade).", fontSize = 12.sp)
                }
            })
        "send" -> {
            val p = vm.prepared
            if (p == null) AlertDialog(onDismissRequest = { dialog = null },
                title = { Text("Enviar") },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(to, { to = it }, label = { Text("Endereço wflx1…") }, singleLine = true)
                        OutlinedTextField(amount, { amount = it }, label = { Text("Valor em WFLX") }, singleLine = true)
                    }
                },
                confirmButton = { TextButton({ vm.prepareSend(to, amount) }) { Text("Revisar") } },
                dismissButton = { TextButton({ dialog = null }) { Text("Cancelar") } })
            else AlertDialog(onDismissRequest = { vm.cancelSend() },
                title = { Text("Confirmar envio") },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("Para:"); Text(p.to, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                        Text("Valor: ${Units.format(p.amount)} WFLX")
                        Text("Taxa: ${Units.format(p.fee)} WFLX")
                        Text("Total: ${Units.format(p.amount + p.fee)} WFLX", fontWeight = FontWeight.Bold)
                        Text("Transações não podem ser desfeitas.", fontSize = 12.sp)
                    }
                },
                confirmButton = { TextButton({ vm.confirmSend(); dialog = null; to = ""; amount = "" }) { Text("Enviar") } },
                dismissButton = { TextButton({ vm.cancelSend() }) { Text("Voltar") } })
        }
        "delete" -> AlertDialog(onDismissRequest = { dialog = null },
            title = { Text("Apagar carteira?") },
            text = { Text("Sem a chave de recuperação anotada, os fundos serão perdidos para sempre.") },
            confirmButton = { TextButton({ vm.deleteWallet(); dialog = null }) { Text("Apagar", color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton({ dialog = null }) { Text("Cancelar") } })
    }
}

@Composable
private fun NodeField(vm: WalletViewModel) {
    var url by remember(vm.nodeUrl) { mutableStateOf(vm.nodeUrl) }
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        OutlinedTextField(url, { url = it }, label = { Text("Nó (API)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedButton(onClick = { vm.setNode(url) }) { Text("Usar este nó") }
    }
}
