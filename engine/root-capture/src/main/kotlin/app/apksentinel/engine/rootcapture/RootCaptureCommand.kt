package app.apksentinel.engine.rootcapture

/** An internal immutable command. Its executable, flags, filter, and interface are all allowlisted. */
class RootCaptureCommand internal constructor(
    val executable: String,
    val arguments: List<String>,
) {
    // Keep value semantics without exposing a public data-class copy() that
    // could bypass the internal constructor and manufacture an unreviewed
    // command.
    override fun equals(other: Any?): Boolean = other is RootCaptureCommand &&
        executable == other.executable && arguments == other.arguments

    override fun hashCode(): Int = 31 * executable.hashCode() + arguments.hashCode()

    operator fun component1(): String = executable
    operator fun component2(): List<String> = arguments

    override fun toString(): String = "RootCaptureCommand(executable=$executable, arguments=$arguments)"
}

/** Fixed mapping controlled by the integrating app after device verification, never by a text field. */
data class RootCaptureTrustedInterfaceMap(
    val allDevice: String = "any",
    val wifi: String = "wlan0",
    val mobile: String = "rmnet_data0",
) {
    init {
        listOf(allDevice, wifi, mobile).forEach {
            require(it.matches(Regex("^[A-Za-z0-9_.:-]{1,32}$"))) { "Trusted interface name is invalid." }
        }
    }

    fun resolve(captureInterface: RootCaptureInterface): String = when (captureInterface) {
        RootCaptureInterface.ALL_DEVICE -> allDevice
        RootCaptureInterface.WIFI -> wifi
        RootCaptureInterface.MOBILE -> mobile
    }
}

object RootCaptureCommandFactory {
    fun tcpdumpProbe(): RootCaptureCommand = RootCaptureCommand("tcpdump", listOf("-h"))

    /**
     * Validates the public request before any root-manager process is started.
     * Header-only remains deliberately fixed at 96 bytes. Full capture must
     * opt into one of the two reviewed packet filters and may choose only a
     * bounded snap length.
     */
    fun isRequestAllowed(request: RootCaptureStartRequest): Boolean = when (request.scope) {
        RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY ->
            request.filter == RootCaptureFilter.IPV4_TCP_CONNECTION_CONTROL_NO_PAYLOAD &&
                request.limits.snapLengthBytes == 96
        RootCaptureScope.FULL_PACKET_CAPTURE ->
            request.limits.snapLengthBytes >= RootCaptureLimits.FULL_CAPTURE_MIN_SNAP_LENGTH_BYTES &&
                (request.filter == RootCaptureFilter.ALL_TRAFFIC ||
                    request.filter == RootCaptureFilter.IPV4_IPV6_TCP_UDP)
    }

    fun create(request: RootCaptureStartRequest, interfaces: RootCaptureTrustedInterfaceMap): RootCaptureCommand = RootCaptureCommand(
        executable = "tcpdump",
        arguments = buildList {
            require(isRequestAllowed(request)) { "Capture scope/filter/snap length is not allowlisted." }
            val snapLength = if (request.scope == RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY) {
                96
            } else {
                request.limits.snapLengthBytes
            }
            addAll(listOf("-U", "-n", "-s", snapLength.toString()))
            addAll(listOf("-c", request.limits.maximumPackets.toString()))
            addAll(listOf("-i", interfaces.resolve(request.captureInterface)))
            // Write libpcap bytes to stdout. The controller pumps the pipe
            // into a private bounded file, so a privileged process receives no
            // writable app path and cannot exceed the app-side byte cap.
            addAll(listOf("-w", "-"))
            addAll(safeFilterArguments(request.filter))
        },
    )

    private fun safeFilterArguments(filter: RootCaptureFilter): List<String> = when (filter) {
        RootCaptureFilter.IPV4_TCP_CONNECTION_CONTROL_NO_PAYLOAD -> listOf(
            "ip", "and", "tcp", "and", "ip[2:2]", "=", "(", "(", "ip[0]", "&", "0x0f", ")", "*", "4", "+", "(", "(", "tcp[12]", "&", "0xf0", ")", "/", "4", ")", ")", "and", "(",
            "tcp[tcpflags]", "&", "(", "tcp-syn", "|", "tcp-fin", "|", "tcp-rst", ")", "!=", "0", ")",
        )
        RootCaptureFilter.ALL_TRAFFIC -> emptyList()
        RootCaptureFilter.IPV4_IPV6_TCP_UDP -> listOf(
            "(", "ip", "or", "ip6", ")", "and", "(", "tcp", "or", "udp", ")",
        )
    }
}

/** Mirrors the fixed BPF contract for tests and defensive integrations that receive raw IPv4 bytes. */
internal object RootCapturePacketShape {
    fun isTcpControlHeaderOnly(packet: ByteArray): Boolean {
        if (packet.size < 20 || packet[0].toInt().ushr(4) != 4) return false
        val ipHeaderBytes = (packet[0].toInt() and 0x0f) * 4
        if (ipHeaderBytes !in 20..packet.size || packet.size - ipHeaderBytes < 20) return false
        if ((packet[9].toInt() and 0xff) != 6) return false
        val totalLength = u16(packet, 2)
        if (totalLength < ipHeaderBytes + 20 || totalLength > packet.size) return false
        val tcpOffset = ipHeaderBytes
        val tcpHeaderBytes = ((packet[tcpOffset + 12].toInt() ushr 4) and 0x0f) * 4
        if (tcpHeaderBytes !in 20..totalLength - tcpOffset) return false
        val flags = packet[tcpOffset + 13].toInt() and 0xff
        if (flags and (0x02 or 0x01 or 0x04) == 0) return false
        return totalLength == tcpOffset + tcpHeaderBytes
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
}

/**
 * `su -c` necessarily receives a shell command on common Android root
 * managers. This serializer quotes every complete token; it never concatenates
 * raw user input and is used only with [RootCaptureCommandFactory] commands.
 */
object RootCaptureSafeShellSerializer {
    fun serialize(command: RootCaptureCommand): String =
        (listOf(command.executable) + command.arguments).joinToString(" ") { token ->
            "'" + token.replace("'", "'\"'\"'") + "'"
        }
}
