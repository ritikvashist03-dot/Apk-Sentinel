package app.apksentinel.engine.url

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.URI

class SafeRedirectResolverTest {
    @Test fun rejectsPrivateAndReservedAddresses() {
        listOf("127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.1.1", "172.16.0.1", "192.168.0.1", "198.18.0.1", "::1", "fc00::1", "fe80::1")
            .forEach { assertFalse(it, PublicNetworkTargetPolicy.isPublic(InetAddress.getByName(it))) }
    }

    @Test fun acceptsOrdinaryPublicAddresses() {
        assertTrue(PublicNetworkTargetPolicy.isPublic(InetAddress.getByName("8.8.8.8")))
        assertTrue(PublicNetworkTargetPolicy.isPublic(InetAddress.getByName("2001:4860:4860::8888")))
    }

    @Test fun connectorReceivesOnlyTheAlreadyValidatedAddress() {
        val expected = InetAddress.getByName("8.8.8.8")
        val connector = RecordingConnector(PinnedHeadResponse(200, emptyMap()))
        val resolver = SafeRedirectResolver(
            addressResolver = { arrayOf(expected) },
            pinnedConnector = connector,
        )

        val result = resolver.resolve("https://redirect.example/path")

        assertTrue(result is RedirectResolution.Resolved)
        assertEquals(listOf(expected), connector.addresses)
        assertEquals(listOf("redirect.example"), connector.hostnames)
    }

    @Test fun mixedPublicAndPrivateResultsAreRejectedBeforeAnyConnection() {
        val connector = RecordingConnector(PinnedHeadResponse(200, emptyMap()))
        val resolver = SafeRedirectResolver(
            addressResolver = { arrayOf(InetAddress.getByName("8.8.8.8"), InetAddress.getByName("10.0.0.1")) },
            pinnedConnector = connector,
        )

        val result = resolver.resolve("http://mixed.example/")

        assertTrue(result is RedirectResolution.Rejected)
        assertEquals(RedirectResolutionReason.UNSAFE_NETWORK_TARGET, (result as RedirectResolution.Rejected).reason)
        assertTrue(connector.addresses.isEmpty())
    }

    @Test fun privateResultsAreRejectedBeforeAnyConnection() {
        val connector = RecordingConnector(PinnedHeadResponse(200, emptyMap()))
        val resolver = SafeRedirectResolver(
            addressResolver = { arrayOf(InetAddress.getByName("127.0.0.1")) },
            pinnedConnector = connector,
        )

        val result = resolver.resolve("http://private.example/")

        assertTrue(result is RedirectResolution.Rejected)
        assertEquals(RedirectResolutionReason.UNSAFE_NETWORK_TARGET, (result as RedirectResolution.Rejected).reason)
        assertTrue(connector.addresses.isEmpty())
    }

    private class RecordingConnector(private val response: PinnedHeadResponse) : PinnedHttpConnector {
        val addresses = mutableListOf<InetAddress>()
        val hostnames = mutableListOf<String>()

        override fun head(
            uri: URI,
            hostname: String,
            address: InetAddress,
            connectTimeoutMillis: Int,
            readTimeoutMillis: Int,
        ): PinnedHeadResponse {
            addresses += address
            hostnames += hostname
            return response
        }
    }
}
