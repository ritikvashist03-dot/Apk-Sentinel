package app.apksentinel.networkmonitor

import java.net.Socket

/**
 * The active VpnService installs its own TunnelSocketProtector here before a
 * remote receiver can connect. This process-local seam has no fallback: a
 * missing protector rejects the socket rather than risking a VPN loop.
 */
object RemoteStreamSocketProtectionRuntime {
    private val lock = Any()
    private var protector: TunnelSocketProtector? = null

    fun install(value: TunnelSocketProtector): Boolean = synchronized(lock) {
        if (protector != null) return false
        protector = value
        true
    }

    fun clear(value: TunnelSocketProtector? = null) = synchronized(lock) {
        if (value == null || protector === value) protector = null
    }

    fun protect(socket: Socket): Boolean = synchronized(lock) {
        protector?.protect(socket) == true
    }
}
