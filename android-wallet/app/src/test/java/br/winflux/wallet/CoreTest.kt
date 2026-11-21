package br.winflux.wallet

import br.winflux.wallet.core.*
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Byte-for-byte compatibility with the Python node: addresses, HD, recovery key, canonical JSON, txid and signatures. */
class CoreTest {
    private val master = Vectors.MASTER.hexToBytes()
    private fun hd() = HdWallet(master, testEd)

    private fun expectFail(f: () -> Unit) {
        try { f() } catch (e: Exception) { return }
        fail("should have failed")
    }

    @Test fun hdKeysAndAddressesMatchPython() {
        val w = hd()
        Vectors.KEYS.forEachIndexed { i, (pub, addr) ->
            assertEquals(pub, w.key(i).pub.toHex()); assertEquals(addr, w.address(i))
            assertTrue(Address.isValid(addr))
        }
    }

    @Test fun recoveryKeyMatchesPythonAndToleratesFormatting() {
        assertEquals(Vectors.RECOVERY, hd().recoveryKey())
        assertEquals(Vectors.MASTER, HdWallet.decodeRecoveryKey(Vectors.RECOVERY).toHex())
        assertEquals(Vectors.MASTER, HdWallet.decodeRecoveryKey(Vectors.RECOVERY.uppercase()).toHex())
        assertEquals(Vectors.MASTER, HdWallet.decodeRecoveryKey(Vectors.RECOVERY.replace("-", " ")).toHex())
        assertEquals(Vectors.KEYS[5].second, HdWallet.fromRecoveryKey(Vectors.RECOVERY, testEd).address(5))
    }

    @Test fun recoveryKeyRejectsTyposAndGarbage() {
        val r = Vectors.RECOVERY
        val i = r.length - 3
        expectFail { HdWallet.decodeRecoveryKey(r.substring(0, i) + (if (r[i] == 'a') 'b' else 'a') + r.substring(i + 1)) }
        expectFail { HdWallet.decodeRecoveryKey(r.dropLast(1)) }
        expectFail { HdWallet.decodeRecoveryKey("xxxx" + r) }
        expectFail { HdWallet.decodeRecoveryKey("wflxk1-!!!!") }
        expectFail { HdWallet.decodeRecoveryKey("") }
    }

    @Test fun addressValidationIsStrict() {
        val a = Vectors.KEYS[0].second
        assertTrue(Address.isValid(a))
        assertFalse(Address.isValid(a.uppercase()))
        assertFalse(Address.isValid(a + "a"))
        assertFalse(Address.isValid(a.dropLast(1)))
        assertFalse(Address.isValid("x" + a.drop(1)))
        assertFalse(Address.isValid(""))
        assertFalse(Address.isValid("wflx1"))
        for (pos in 5 until a.length) {                         // swapping any character breaks the checksum
            val c = if (a[pos] == 'a') 'b' else 'a'
            assertFalse(Address.isValid(a.substring(0, pos) + c + a.substring(pos + 1)))
        }
    }

    @Test fun canonicalJsonMatchesPython() {
        val v = mapOf("b" to listOf(1, null, true), "a" to "x\"\\\n\t\u00e9\u007f\uD83D\uDE00\u0001")
        assertEquals(Vectors.ESCAPE_EXPECTED, CanonicalJson.encode(v))
    }

    // ---------------------------------------------------------------- transactions
    private val rules = FeeRules(1000, 1, 100_000, 256, 256)
    private val utxos = Vectors.UTXOS.map { Utxo(it[0] as String, it[1] as Int, it[2] as Long, it[3] as String) }

    private fun build(rules: FeeRules, list: List<Utxo> = utxos, amount: Long = 600_000_000L): SignedTx {
        val w = hd()
        val owner = (0 until 5).associate { w.address(it) to it }
        return TxBuilder.build(w, { owner[it] }, list, Vectors.DEST, amount, w.address(2), "winflux-test-1", rules)
    }

    @Test fun transferMatchesPythonByteForByte() {
        val tx = build(rules)
        assertEquals(Vectors.TX_JSON, tx.toJson())
        assertEquals(Vectors.TX_TXID, tx.txid)
        assertEquals(Vectors.TX_FEE, TxBuilder.feeOf(tx, utxos))
    }

    @Test fun perByteFeeLoopMatchesPython() {
        val tx = build(rules.copy(minFeePerByte = 3))
        assertEquals(Vectors.TX_PER_BYTE3_JSON, tx.toJson())
        assertEquals(Vectors.TX_PER_BYTE3_TXID, tx.txid)
        assertEquals(Vectors.TX_PER_BYTE3_FEE, TxBuilder.feeOf(tx, utxos))
        assertTrue(TxBuilder.feeOf(tx, utxos) >= 3L * tx.size())
    }

    @Test fun builderRejectsBadRequests() {
        expectFail { build(rules, amount = 0) }
        expectFail { build(rules, amount = 10_000_000_000L) }                 // insufficient funds
        expectFail { build(rules, list = emptyList()) }
        expectFail { build(rules.copy(maxInputs = 1)) }                        // would need 2 inputs
        val w = hd()
        expectFail { TxBuilder.build(w, { 0 }, utxos, "wflx1invalido", 1, w.address(2), "c", rules) }
        expectFail { TxBuilder.build(w, { null }, utxos, Vectors.DEST, 600_000_000L, w.address(2), "c", rules) }   // no key
    }

    @Test fun signaturesVerifyAgainstTheTxid() {
        val tx = build(rules)
        val msg = SignedTx.signingMessage(tx.txid)
        tx.inputs.forEach { assertEquals(128, it.signature.length) }
        // The txid does not depend on the signatures
        assertEquals(tx.txid, SignedTx.txidOf(tx.chainId, tx.inputs.map { it.copy(signature = "") }, tx.outputs))
        assertEquals(15 + 32, msg.size)
    }

    // ---------------------------------------------------------------- engine (wallet on top of a fake node)
    private class FakeNode(val height: Long = 100) : Node {
        val byAddr = HashMap<String, MutableList<AddrUtxo>>()
        val submitted = ArrayList<String>()
        override fun params() = NodeParams("winflux-test-1", "WFLX", 8, 1000, 1, 100_000, 256, 256, 0)
        override fun address(address: String): AddrInfo {
            val l = byAddr[address] ?: mutableListOf()
            return AddrInfo(address, l.sumOf { it.value }, l.isNotEmpty(), height, l)
        }
        override fun submit(txJson: String): String { submitted.add(txJson); return "ab".repeat(32) }
    }

    private fun fake(): FakeNode = FakeNode().also { n ->
        utxos.forEach { n.byAddr.getOrPut(it.address) { mutableListOf() }.add(AddrUtxo(it.txid, it.index, it.value, 0)) }
    }

    @Test fun engineDiscoversBalanceAndFreshReceiveAddress() {
        val e = WalletEngine(hd(), fake())
        val s = e.refresh()
        assertEquals(900_000_000L, s.balance)
        assertEquals(900_000_000L, s.spendable)
        assertEquals(2, s.nextIndex)                                   // addresses 0 and 1 used
        assertEquals(hd().address(2), s.receiveAddress)                // the next receiving address is new
    }

    @Test fun enginePreparesTheSameTxAsPythonAndNeverReusesCoins() {
        val node = fake()
        val e = WalletEngine(hd(), node)
        e.refresh()
        val p = e.prepare(Vectors.DEST, 600_000_000L)
        assertEquals(Vectors.TX_TXID, p.tx.txid)
        assertEquals(Vectors.TX_JSON, p.tx.toJson())
        assertEquals(Vectors.TX_FEE, p.fee)
        e.send(p)
        assertEquals(1, node.submitted.size)
        assertEquals(Vectors.TX_JSON, node.submitted[0])
        expectFail { e.prepare(Vectors.DEST, 600_000_000L) }           // the large coins are pending: no balance
        val small = e.prepare(Vectors.DEST, 50_000_000L)               // the 1 WFLX coin is left
        assertEquals(1, small.tx.inputs.size)
    }

    @Test fun immatureOutputsAreNotSpent() {
        val node = FakeNode(height = 100)
        val a0 = hd().address(0)
        node.byAddr[a0] = mutableListOf(AddrUtxo("11".repeat(32), 0, 500_000_000L, 150), AddrUtxo("22".repeat(32), 0, 100_000_000L, 101))
        val e = WalletEngine(hd(), node)
        val s = e.refresh()
        assertEquals(600_000_000L, s.balance)
        assertEquals(100_000_000L, s.spendable)                        // the 5 WFLX one can only be spent at height 150
        expectFail { e.prepare(Vectors.DEST, 200_000_000L) }
    }

    @Test fun restoringFromTheRecoveryKeyFindsFundsBeyondTheGap() {
        val node = FakeNode()
        val w = hd()
        node.byAddr[w.address(17)] = mutableListOf(AddrUtxo("44".repeat(32), 0, 700_000_000L, 0))   // within the gap of 20
        val e = WalletEngine(HdWallet.fromRecoveryKey(Vectors.RECOVERY, testEd), node)
        val s = e.refresh()
        assertEquals(700_000_000L, s.balance)
        assertEquals(18, e.nextIndex)
        val node2 = FakeNode()
        node2.byAddr[w.address(25)] = mutableListOf(AddrUtxo("55".repeat(32), 0, 1L, 0))             // beyond the gap: not found
        assertEquals(0L, WalletEngine(hd(), node2).refresh().balance)
    }

    // ---------------------------------------------------------------- utilidades
    @Test fun unitsAreIntegerOnly() {
        assertEquals(150_000_000L, Units.parse("1,5")); assertEquals(1L, Units.parse("0.00000001"))
        assertEquals(100_000_000L, Units.parse(" 1 "))
        for (bad in listOf("", "-1", "1.123456789", "1e3", "abc", "1..2", ".5", "92233720368547758079")) assertNull(bad, Units.parse(bad))
        assertEquals("1.50000000", Units.format(150_000_000L)); assertEquals("0.00000001", Units.format(1L))
        assertEquals("0.00000000", Units.format(0L))
    }

    @Test fun nodeUrlPolicy() {
        assertEquals("http://192.168.0.10:8081", NodeUrl.normalize("http://192.168.0.10:8081/"))
        assertEquals("http://10.0.2.2:8081", NodeUrl.normalize("http://10.0.2.2:8081"))
        assertEquals("https://node.example.org", NodeUrl.normalize("https://node.example.org"))
        for (bad in listOf("http://node.example.org", "http://8.8.8.8:8081", "http://172.32.0.1", "ftp://10.0.0.1", "10.0.0.1", "http://", "http://a b"))
            assertNull(bad, NodeUrl.normalize(bad))
        assertNull(NodeUrl.normalize("http://192.168.0.256"))
    }
}
