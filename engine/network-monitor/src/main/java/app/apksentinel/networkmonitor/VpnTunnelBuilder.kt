package app.apksentinel.networkmonitor

import android.content.pm.PackageManager
import android.net.VpnService
import android.os.ParcelFileDescriptor

/**
 * Builds a full-route dual-stack local TUN interface. Call it only after a
 * forwarding data plane has proven it can handle the selected families; a
 * full-route TUN without a forwarder would interrupt user traffic.
 */
internal class LocalVpnTunnelBuilder(
    private val service: VpnService,
) {
    fun establish(configuration: TunnelConfiguration): TunnelEstablishmentResult {
        val builder = service.Builder()
            .setSession(configuration.sessionName)
            .setMtu(configuration.mtu)
            // The built-in forwarder owns a dedicated reader and closes its duplicate
            // descriptor on cancellation. Blocking mode avoids treating EAGAIN as a
            // packet loss event on devices whose Java stream wrappers do not expose it.
            .setBlocking(true)

        if (configuration.enableIpv4) {
            builder
                .addAddress(IPV4_TUNNEL_ADDRESS, IPV4_TUNNEL_PREFIX)
                .addRoute(IPV4_DEFAULT_ROUTE, IPV4_DEFAULT_PREFIX)
        }
        if (configuration.enableIpv6) {
            builder
                .addAddress(IPV6_TUNNEL_ADDRESS, IPV6_TUNNEL_PREFIX)
                .addRoute(IPV6_DEFAULT_ROUTE, IPV6_DEFAULT_PREFIX)
        }

        val selectionResult = applyAppSelection(builder, configuration.appSelection)
        if (selectionResult is AppSelectionResult.Failure) {
            return TunnelEstablishmentResult.Failed(selectionResult.detail)
        }

        return try {
            val descriptor = builder.establish()
                ?: return TunnelEstablishmentResult.Failed("Android did not establish the local VPN interface.")
            TunnelEstablishmentResult.Established(
                descriptor = descriptor,
                skippedUninstalledPackages = (selectionResult as AppSelectionResult.Applied).skippedUninstalledPackages,
            )
        } catch (_: SecurityException) {
            TunnelEstablishmentResult.Failed("Android rejected VPN establishment.")
        } catch (_: IllegalArgumentException) {
            TunnelEstablishmentResult.Failed("VPN tunnel configuration is invalid.")
        } catch (_: IllegalStateException) {
            TunnelEstablishmentResult.Failed("VPN tunnel could not be established.")
        }
    }

    private fun applyAppSelection(
        builder: VpnService.Builder,
        selection: VpnAppSelection,
    ): AppSelectionResult = when (selection) {
        is VpnAppSelection.AllAppsExcept -> {
            val skipped = linkedSetOf<String>()
            val packageNames = (selection.packageNames + service.packageName).sorted()
            packageNames.forEach { packageName ->
                try {
                    builder.addDisallowedApplication(packageName)
                } catch (_: PackageManager.NameNotFoundException) {
                    skipped += packageName
                }
            }
            if (service.packageName in skipped) {
                AppSelectionResult.Failure("The monitor app itself could not be excluded from its VPN route.")
            } else {
                AppSelectionResult.Applied(skipped)
            }
        }

        is VpnAppSelection.OnlyApps -> {
            val skipped = linkedSetOf<String>()
            var allowedCount = 0
            selection.packageNames
                .asSequence()
                .filterNot { it == service.packageName }
                .sorted()
                .forEach { packageName ->
                    try {
                        builder.addAllowedApplication(packageName)
                        allowedCount += 1
                    } catch (_: PackageManager.NameNotFoundException) {
                        skipped += packageName
                    }
                }
            if (allowedCount == 0) {
                AppSelectionResult.Failure("No selected installed app can use the local VPN route.")
            } else {
                AppSelectionResult.Applied(skipped)
            }
        }
    }

    private sealed interface AppSelectionResult {
        data class Applied(val skippedUninstalledPackages: Set<String>) : AppSelectionResult

        data class Failure(val detail: String) : AppSelectionResult
    }

    private companion object {
        const val IPV4_TUNNEL_ADDRESS = "10.77.0.2"
        const val IPV4_TUNNEL_PREFIX = 32
        const val IPV4_DEFAULT_ROUTE = "0.0.0.0"
        const val IPV4_DEFAULT_PREFIX = 0
        const val IPV6_TUNNEL_ADDRESS = "fd77:6170:6b73:656e::2"
        const val IPV6_TUNNEL_PREFIX = 128
        const val IPV6_DEFAULT_ROUTE = "::"
        const val IPV6_DEFAULT_PREFIX = 0
    }
}

internal sealed interface TunnelEstablishmentResult {
    data class Established(
        val descriptor: ParcelFileDescriptor,
        val skippedUninstalledPackages: Set<String>,
    ) : TunnelEstablishmentResult

    data class Failed(val detail: String) : TunnelEstablishmentResult
}
