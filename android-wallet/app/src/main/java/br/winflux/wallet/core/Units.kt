package br.winflux.wallet.core

import java.math.BigDecimal

/** 1 WFLX = 10^8 unidades. Valores são sempre inteiros (Long); nunca float. */
object Units {
    const val DECIMALS = 8
    const val ONE = 100_000_000L

    /** "1,5" ou "1.5" -> unidades. null se inválido, negativo, com mais de 8 casas ou acima de Long. */
    fun parse(text: String): Long? {
        val t = text.trim().replace(',', '.')
        if (!Regex("^[0-9]+(\\.[0-9]{1,8})?$").matches(t)) return null
        return try { BigDecimal(t).movePointRight(DECIMALS).longValueExact() } catch (e: ArithmeticException) { null }
    }

    fun format(units: Long): String {
        val neg = units < 0
        val a = if (neg) -units else units
        return (if (neg) "-" else "") + "${a / ONE}." + (a % ONE).toString().padStart(DECIMALS, '0')
    }
}
