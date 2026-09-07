package app.apksentinel.networkmonitor

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import android.system.OsConstants
import java.net.InetSocketAddress
import java.util.LinkedHashMap

/**
 * A packet-flow attribution request.  [local] and [remote] are always in the
 * app-facing direction, including for inbound packets.  Both endpoints are
 * constructed from packet-literal [java.net.InetAddress] values, so no name
 * lookup is ever part of attribution.
 */
data class ConnectionOwnerFlow(
    val protocol: TransportProtocol,
    val local: InetSocketAddress,
    val remote: InetSocketAddress,
)

internal sealed interface ConnectionOwnerUidResult {
    data class Found(val uid: Int) : ConnectionOwnerUidResult

    /** Android had no owner for this exact flow (including [Process.INVALID_UID]). */
    object NoOwner : ConnectionOwnerUidResult

    /** The platform cannot provide a result, for example API < 29 or a security denial. */
    object Unavailable : ConnectionOwnerUidResult
}

internal fun interface ConnectionOwnerUidLookup {
    fun lookup(flow: ConnectionOwnerFlow): ConnectionOwnerUidResult
}

internal fun interface UidPackageLookup {
    fun packageNamesForUid(uid: Int): List<String>
}

/**
 * A bounded, in-memory only adapter for Android's active-VPN owner lookup.
 * This interface keeps the decision and cache testable without an Android
 * framework fake, and deliberately contains no persistence hook.
 */
fun interface FlowAppAttributionProvider {
    fun attributionFor(flow: ConnectionOwnerFlow): AppAttribution
}

/** An optional attribution provider must never terminate packet forwarding. */
internal fun FlowAppAttributionProvider.attributionForSafely(flow: ConnectionOwnerFlow): AppAttribution =
    runCatching { attributionFor(flow) }.getOrElse {
        AppAttribution.Unknown(AttributionUnavailableReason.PLATFORM_MAPPING_UNAVAILABLE)
    }

object NoFlowAppAttributionProvider : FlowAppAttributionProvider {
    override fun attributionFor(flow: ConnectionOwnerFlow): AppAttribution =
        AppAttribution.Unknown(AttributionUnavailableReason.DATA_PLANE_DID_NOT_PROVIDE_UID)
}

/** Lets hosts substitute a reviewed provider while retaining the same conservative result model. */
fun interface FlowAppAttributionProviderFactory {
    fun create(context: Context): FlowAppAttributionProvider
}

/**
 * Android's `getConnectionOwnerUid` is restricted to the active VPN.  The
 * provider is created at service start and the data plane calls it only while
 * its active forwarding runtime exists.
 */
object AndroidFlowAppAttributionProviderFactory : FlowAppAttributionProviderFactory {
    override fun create(context: Context): FlowAppAttributionProvider {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
            ?: return NoFlowAppAttributionProvider
        return CachedFlowAppAttributionProvider(
            ownerLookup = AndroidConnectionOwnerUidLookup(connectivity),
            packageLookup = AndroidUidPackageLookup(context.packageManager),
        )
    }
}

internal class AndroidConnectionOwnerUidLookup(
    private val connectivityManager: ConnectivityManager,
) : ConnectionOwnerUidLookup {
    override fun lookup(flow: ConnectionOwnerFlow): ConnectionOwnerUidResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return ConnectionOwnerUidResult.Unavailable
        val protocol = when (flow.protocol) {
            TransportProtocol.TCP -> OsConstants.IPPROTO_TCP
            TransportProtocol.UDP -> OsConstants.IPPROTO_UDP
            else -> return ConnectionOwnerUidResult.Unavailable
        }
        return try {
            val uid = connectivityManager.getConnectionOwnerUid(protocol, flow.local, flow.remote)
            if (uid == Process.INVALID_UID) ConnectionOwnerUidResult.NoOwner
            else if (uid < 0) ConnectionOwnerUidResult.NoOwner
            else ConnectionOwnerUidResult.Found(uid)
        } catch (_: SecurityException) {
            // This happens when Android does not regard this process as the
            // active VPN.  Never substitute a heuristic owner.
            ConnectionOwnerUidResult.Unavailable
        } catch (_: UnsupportedOperationException) {
            ConnectionOwnerUidResult.Unavailable
        } catch (_: RuntimeException) {
            // OEM implementations must not be able to terminate the VPN
            // forwarding worker through an optional attribution call.
            ConnectionOwnerUidResult.Unavailable
        }
    }
}

internal class AndroidUidPackageLookup(
    private val packageManager: PackageManager,
) : UidPackageLookup {
    override fun packageNamesForUid(uid: Int): List<String> =
        runCatching { packageManager.getPackagesForUid(uid)?.toList().orEmpty() }.getOrDefault(emptyList())
}

/**
 * Caches exact local/remote TCP or UDP tuples for the active process only.
 * A short unknown cache avoids a per-packet platform call while still allowing
 * a later SYN/flow retry to observe a newly visible owner.
 */
internal class CachedFlowAppAttributionProvider(
    private val ownerLookup: ConnectionOwnerUidLookup,
    private val packageLookup: UidPackageLookup,
    private val nowMillis: () -> Long = System::currentTimeMillis,
    private val maximumEntries: Int = DEFAULT_CACHE_ENTRIES,
    private val knownTtlMillis: Long = DEFAULT_KNOWN_TTL_MILLIS,
    private val unknownTtlMillis: Long = DEFAULT_UNKNOWN_TTL_MILLIS,
) : FlowAppAttributionProvider {
    init {
        require(maximumEntries in 1..4_096) { "maximumEntries must be between 1 and 4096." }
        require(knownTtlMillis in 1L..5 * 60_000L) { "knownTtlMillis is outside the supported range." }
        require(unknownTtlMillis in 1L..60_000L) { "unknownTtlMillis is outside the supported range." }
    }

    private val lock = Any()
    private val entries = object : LinkedHashMap<ConnectionOwnerFlow, CachedAttribution>(maximumEntries, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<ConnectionOwnerFlow, CachedAttribution>?): Boolean =
            size > maximumEntries
    }

    override fun attributionFor(flow: ConnectionOwnerFlow): AppAttribution {
        if (flow.protocol != TransportProtocol.TCP && flow.protocol != TransportProtocol.UDP) {
            return AppAttribution.Unknown(AttributionUnavailableReason.UNSUPPORTED_PROTOCOL)
        }
        val now = runCatching { nowMillis() }.getOrElse {
            return AppAttribution.Unknown(AttributionUnavailableReason.PLATFORM_MAPPING_UNAVAILABLE)
        }
        if (now < 0L) {
            return AppAttribution.Unknown(AttributionUnavailableReason.PLATFORM_MAPPING_UNAVAILABLE)
        }
        synchronized(lock) {
            entries[flow]?.takeIf { cached -> now >= cached.atMillis && now - cached.atMillis <= cached.ttlMillis }
                ?.let { return it.attribution }
            entries.remove(flow)
        }

        val attribution = when (val owner = ownerLookup.lookup(flow)) {
            is ConnectionOwnerUidResult.Found -> attributionForUid(owner.uid)
            ConnectionOwnerUidResult.NoOwner -> AppAttribution.Unknown(AttributionUnavailableReason.CONNECTION_OWNER_NOT_FOUND)
            ConnectionOwnerUidResult.Unavailable -> AppAttribution.Unknown(AttributionUnavailableReason.PLATFORM_MAPPING_UNAVAILABLE)
        }
        val ttl = if (attribution is AppAttribution.Known) knownTtlMillis else unknownTtlMillis
        synchronized(lock) { entries[flow] = CachedAttribution(attribution, now, ttl) }
        return attribution
    }

    private fun attributionForUid(uid: Int): AppAttribution {
        val packages = packageLookup.packageNamesForUid(uid).distinct()
        if (packages.size > 1) {
            return AppAttribution.Unknown(AttributionUnavailableReason.SHARED_UID_OR_AMBIGUOUS_OWNER)
        }
        val packageName = packages.singleOrNull()
            ?: return AppAttribution.Unknown(AttributionUnavailableReason.PLATFORM_MAPPING_UNAVAILABLE)
        return runCatching {
            AppAttribution.Known(
                packageName = packageName,
                uid = uid,
                confidence = AttributionConfidence.HIGH,
            )
        }.getOrElse { AppAttribution.Unknown(AttributionUnavailableReason.PLATFORM_MAPPING_UNAVAILABLE) }
    }

    private data class CachedAttribution(
        val attribution: AppAttribution,
        val atMillis: Long,
        val ttlMillis: Long,
    )

    private companion object {
        const val DEFAULT_CACHE_ENTRIES = 256
        const val DEFAULT_KNOWN_TTL_MILLIS = 30_000L
        const val DEFAULT_UNKNOWN_TTL_MILLIS = 1_000L
    }
}

/** Produces the active-VPN API's required endpoint orientation without DNS. */
internal fun TunIpPacket.toConnectionOwnerFlow(direction: PacketDirection): ConnectionOwnerFlow? {
    val (protocol, sourcePort, destinationPort) = when {
        tcp != null -> Triple(TransportProtocol.TCP, tcp.sourcePort, tcp.destinationPort)
        udp != null -> Triple(TransportProtocol.UDP, udp.sourcePort, udp.destinationPort)
        else -> return null
    }
    val outbound = direction == PacketDirection.OUTBOUND
    // InetSocketAddress(InetAddress, port) is resolved from literal packet bytes;
    // never use its String/hostname constructors here.
    val local = if (outbound) InetSocketAddress(source, sourcePort) else InetSocketAddress(destination, destinationPort)
    val remote = if (outbound) InetSocketAddress(destination, destinationPort) else InetSocketAddress(source, sourcePort)
    return ConnectionOwnerFlow(protocol, local, remote)
}
