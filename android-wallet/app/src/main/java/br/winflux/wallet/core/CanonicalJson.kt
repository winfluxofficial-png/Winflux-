package br.winflux.wallet.core

/**
 * Canonical JSON identical to the node's (`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`).
 * Accepts null, Boolean, Int, Long, String, Map<String, *> and List<*>. Any divergence here changes the txid.
 */
object CanonicalJson {
    fun encode(v: Any?): String = StringBuilder().also { write(it, v) }.toString()

    private fun write(sb: StringBuilder, v: Any?) {
        when (v) {
            null -> sb.append("null")
            is Boolean -> sb.append(if (v) "true" else "false")
            is Int -> sb.append(v)
            is Long -> sb.append(v)
            is String -> string(sb, v)
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for (k in v.keys.map { it as String }.sorted()) {
                    if (!first) sb.append(',')
                    first = false
                    string(sb, k)
                    sb.append(':')
                    write(sb, v[k])
                }
                sb.append('}')
            }
            is List<*> -> {
                sb.append('[')
                v.forEachIndexed { i, x -> if (i > 0) sb.append(','); write(sb, x) }
                sb.append(']')
            }
            else -> throw IllegalArgumentException("unsupported type: ${v::class}")
        }
    }

    private fun string(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c == '\b' -> sb.append("\\b")
                c == '\u000c' -> sb.append("\\f")
                c.code < 0x20 || c.code > 0x7e -> sb.append("\\u").append(c.code.toString(16).padStart(4, '0'))
                else -> sb.append(c)
            }
        }
        sb.append('"')
    }
}
