package app.apksentinel.networkmonitor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EventStorageAndExportTest {
    @Test
    fun boundedEventStoreEvictsOldestEventAndCountsIt() {
        val store = BoundedInMemoryNetworkEventStore(capacity = 2)

        store.append(stateEvent(1L))
        store.append(stateEvent(2L))
        val result = store.append(stateEvent(3L))

        assertEquals(1, result.evictedCount)
        assertEquals(1L, result.droppedEventCount)
        assertEquals(listOf(2L, 3L), store.snapshot().map { it.atMillis })
    }

    @Test
    fun metadataExporterEscapesValuesAndNeverIncludesCapabilityDetails() {
        val metadata = NetworkSessionMetadata(
            sessionId = "session-\"quoted\"",
            requestedMode = MonitoringMode.METADATA_ONLY,
            state = MonitorLifecycleState.STOPPED,
            startedAtMillis = 1L,
            endedAtMillis = 2L,
            retainedEventCount = 3,
            droppedEventCount = 4L,
            capabilities = CapabilitySnapshot(
                listOf(
                    CapabilityReport(
                        MonitoringCapabilityId.DNS_METADATA,
                        CapabilityAvailability.LIMITED,
                        "This detail must not be placed in export output: private.example",
                    ),
                ),
            ),
            limitations = listOf(
                EngineLimitation(
                    EngineLimitationCode.PACKET_PAYLOADS_NOT_PARSED_OR_REVEALED,
                    "Payloads are not retained.",
                ),
            ),
        )

        val json = SafeSessionMetadataExporter.export(metadata, SessionExportFormat.JSON)
        val csv = SafeSessionMetadataExporter.export(metadata, SessionExportFormat.CSV)

        assertTrue(json.content.contains("session-\\\"quoted\\\""))
        assertFalse(json.content.contains("private.example"))
        assertFalse(json.containsPacketPayload)
        assertFalse(json.containsPlaintextDnsName)
        assertFalse(json.containsDestinationAddress)
        assertTrue(csv.content.contains("\"session-\"\"quoted\"\"\""))
        assertFalse(csv.content.contains("private.example"))
    }

    private fun stateEvent(atMillis: Long): MonitorStateEvent = MonitorStateEvent(
        sessionId = "session",
        atMillis = atMillis,
        state = MonitorLifecycleState.ACTIVE,
        detail = "test",
    )
}
