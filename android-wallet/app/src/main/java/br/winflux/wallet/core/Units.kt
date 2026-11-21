package br.winflux.wallet.core

import java.math.BigDecimal

/** 1 WFLX = 10^8 units. Values are always integers (Long); never float. */
object Units {
    const val DECIMALS = 8
    const val ONE = 100_000_000L

    /** "1,5" or "1.5" -> units. null if invalid, negative, with more than 8 decimal places or above Long. */
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
