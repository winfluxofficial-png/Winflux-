package br.winflux.wallet.core

/**
 * JSON canônico idêntico ao do nó (`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`).
 * Aceita null, Boolean, Int, Long, String, Map<String, *> e List<*>. Qualquer divergência aqui muda o txid.
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
            else -> throw IllegalArgumentException("tipo não suportado: ${v::class}")
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
