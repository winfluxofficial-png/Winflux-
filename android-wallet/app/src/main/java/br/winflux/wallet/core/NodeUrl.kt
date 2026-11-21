package br.winflux.wallet.core

/** Node address policy: https for any host; http only for localhost/private IP (test nodes). */
object NodeUrl {
    fun normalize(raw: String): String? {
        val t = raw.trim().trimEnd('/')
        val m = Regex("^(https?)://([A-Za-z0-9.-]+)(:[0-9]{1,5})?$").matchEntire(t) ?: return null
        val scheme = m.groupValues[1]
        val host = m.groupValues[2].lowercase()
        if (scheme == "http" && !isPrivateHost(host)) return null
        return t
    }

    fun isPrivateHost(host: String): Boolean {
        if (host == "localhost") return true
        val p = host.split('.').mapNotNull { it.toIntOrNull() }
        if (p.size != 4 || host.split('.').size != 4 || p.any { it !in 0..255 }) return false
        return p[0] == 10 || p[0] == 127 || (p[0] == 192 && p[1] == 168) || (p[0] == 172 && p[1] in 16..31)
    }
}
