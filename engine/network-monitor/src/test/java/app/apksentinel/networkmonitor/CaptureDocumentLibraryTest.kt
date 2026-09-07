package app.apksentinel.networkmonitor

import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CaptureDocumentLibraryTest {
    @Test
    fun codecRoundTripsMetadataAndKeepsNewestEntriesWithinEntryBound() {
        val store = InMemoryCaptureMetadataStore()
        val library = CaptureDocumentLibrary(
            metadataStore = store,
            limits = CaptureLibraryLimits(maximumEntries = 2),
            clock = EpochClock { 42L },
        )
        val reader = FakeReader()

        reader.next = reader.readFor("one.pcap")
        library.recordOpened("content://one.pcap", reader)
        reader.next = reader.readFor("two.pcapng")
        library.recordOpened("content://two.pcapng", reader)
        reader.next = reader.readFor("three.har")
        library.recordCreated("content://three.har", reader)

        assertEquals(listOf("content://two.pcapng", "content://three.har"), library.snapshot().map { it.uri })
        val restored = CaptureDocumentLibrary(store, CaptureLibraryLimits(maximumEntries = 2), EpochClock { 99L })
        assertEquals(library.snapshot(), restored.snapshot())
        assertTrue((store.read() as CaptureMetadataReadOutcome.Available).bytes.size <= 96 * 1_024)
        assertEquals(CaptureDocumentOrigin.USER_CREATED, restored.snapshot().last().origin)
    }

    @Test
    fun codecEvictsOldestRecordsUntilEncodedMetadataFitsByteBound() {
        val store = InMemoryCaptureMetadataStore()
        val library = CaptureDocumentLibrary(
            metadataStore = store,
            limits = CaptureLibraryLimits(maximumEntries = 8, maximumMetadataBytes = 4_096),
            clock = EpochClock { 7L },
        )
        val reader = FakeReader()
        repeat(4) { index ->
            val uri = "content://" + index.toString() + "/" + "x".repeat(1_900)
            reader.next = reader.readFor("capture-$index.pcap")
            library.recordOpened(uri, reader)
        }

        assertTrue(library.snapshot().isNotEmpty())
        assertTrue(library.snapshot().size < 4)
        assertTrue((store.read() as CaptureMetadataReadOutcome.Available).bytes.size <= 4_096)
        assertEquals("content://3/" + "x".repeat(1_900), library.snapshot().last().uri)
    }

    @Test
    fun eraseClearsOnlyCatalogAndReleasesPersistedReadGrantsSafely() {
        val library = CaptureDocumentLibrary(clock = EpochClock { 1L })
        val reader = FakeReader()
        reader.next = reader.readFor("granted.pcap", grant = true)
        library.recordOpened("content://granted", reader)
        reader.next = reader.readFor("not-granted.pcap", grant = false)
        library.recordOpened("content://not-granted", reader)
        val released = mutableListOf<String>()

        val erased = library.erase { uri ->
            released += uri
            if (uri == "content://granted") error("provider failure must stay contained")
        }

        assertEquals(2, erased)
        assertTrue(library.snapshot().isEmpty())
        assertEquals(listOf("content://granted"), released)
        assertEquals(0, library.erase { error("no second release") })
    }

    @Test
    fun refreshUpdatesAvailabilityAndGrantWithoutChangingIdentityOrOrigin() {
        val clock = AtomicLong(10L)
        val library = CaptureDocumentLibrary(clock = EpochClock { clock.get() })
        val reader = FakeReader()
        reader.next = reader.readFor("before.pcap", grant = true)
        val created = library.recordCreated("content://refresh", reader)
        reader.next = reader.readFor("after.pcapng", grant = false, available = CaptureDocumentAvailability.MISSING)
        clock.set(20L)

        val refreshed = library.refresh(reader).single()
        assertEquals(created.id, refreshed.id)
        assertEquals(CaptureDocumentOrigin.USER_CREATED, refreshed.origin)
        assertEquals("after.pcapng", refreshed.displayName)
        assertEquals(CaptureDocumentFormat.PCAPNG, refreshed.format)
        assertEquals(CaptureDocumentAvailability.MISSING, refreshed.availability)
        assertFalse(refreshed.persistedGrant)
        assertEquals(10L, refreshed.lastOpenedAtMillis)
    }

    @Test
    fun parsedFormatCanReconcileAFileExtensionWithoutChangingStableIdentity() {
        val library = CaptureDocumentLibrary(clock = EpochClock { 1L })
        val reader = FakeReader().apply { next = readFor("capture.pcap", grant = true) }
        val opened = library.recordOpened("content://capture", reader)
        val updated = library.updateFormat("content://capture", CaptureDocumentFormat.PCAPNG)

        assertEquals(opened.id, updated?.id)
        assertEquals(CaptureDocumentFormat.PCAPNG, updated?.format)
        assertEquals(CaptureDocumentOrigin.USER_OPENED, updated?.origin)
    }

    @Test
    fun malformedOrOversizedStoredBytesDecodeToAnEmptyCatalog() {
        val store = InMemoryCaptureMetadataStore()
        store.write(byteArrayOf(1, 2, 3))
        val malformed = CaptureDocumentLibrary(store)
        assertTrue(malformed.snapshot().isEmpty())
        assertEquals(CaptureMetadataPersistenceState.CORRUPT, malformed.persistenceState())

        store.write(ByteArray(96 * 1_024 + 1))
        val oversized = CaptureDocumentLibrary(store)
        assertTrue(oversized.snapshot().isEmpty())
        assertEquals(CaptureMetadataPersistenceState.CORRUPT, oversized.persistenceState())
    }

    @Test
    fun failedMetadataWriteDoesNotExposeCandidateRecord() {
        val store = FailingCaptureMetadataStore().also { it.failWrite = true }
        val library = CaptureDocumentLibrary(store, clock = EpochClock { 1L })
        val result = library.recordOpenedOutcome("content://failed", FakeReader())

        assertEquals(CaptureMetadataWriteOutcome.UNAVAILABLE, result.outcome)
        assertEquals(null, result.record)
        assertTrue(library.snapshot().isEmpty())
        assertEquals(CaptureMetadataPersistenceState.UNAVAILABLE, library.persistenceState())
    }

    @Test
    fun failedMetadataRemovalRetainsRecordsAndDoesNotReleaseGrant() {
        val store = FailingCaptureMetadataStore()
        val library = CaptureDocumentLibrary(store, clock = EpochClock { 1L })
        val reader = FakeReader().apply { next = readFor("grant.pcap", grant = true) }
        library.recordOpened("content://grant", reader)
        store.failRemove = true
        val released = mutableListOf<String>()

        val result = library.eraseOutcome { released += it }

        assertEquals(CaptureMetadataRemoveOutcome.UNAVAILABLE, result.outcome)
        assertEquals(0, result.removedCount)
        assertEquals(1, library.snapshot().size)
        assertTrue(released.isEmpty())
    }

    private class FakeReader : CaptureDocumentMetadataReader {
        var next: CaptureDocumentRead = readFor("capture.pcap")
        override fun read(uri: String): CaptureDocumentRead = next
        fun readFor(
            name: String,
            grant: Boolean = false,
            available: CaptureDocumentAvailability = CaptureDocumentAvailability.AVAILABLE,
        ): CaptureDocumentRead = CaptureDocumentRead(name, format(name), 12L, 2L, available, grant)

        private fun format(name: String): CaptureDocumentFormat = when (name.substringAfterLast('.')) {
            "pcap" -> CaptureDocumentFormat.PCAP
            "pcapng" -> CaptureDocumentFormat.PCAPNG
            "har" -> CaptureDocumentFormat.HAR
            else -> CaptureDocumentFormat.UNKNOWN
        }
    }

    private class FailingCaptureMetadataStore : CaptureMetadataStore {
        private var bytes: ByteArray? = null
        var failRead = false
        var failWrite = false
        var failRemove = false

        override fun read(): CaptureMetadataReadOutcome = if (failRead) CaptureMetadataReadOutcome.Unavailable
        else bytes?.copyOf()?.let(CaptureMetadataReadOutcome::Available) ?: CaptureMetadataReadOutcome.Missing

        override fun write(value: ByteArray): CaptureMetadataWriteOutcome {
            if (failWrite) return CaptureMetadataWriteOutcome.UNAVAILABLE
            bytes = value.copyOf()
            return CaptureMetadataWriteOutcome.WRITTEN
        }

        override fun remove(): CaptureMetadataRemoveOutcome {
            if (failRemove) return CaptureMetadataRemoveOutcome.UNAVAILABLE
            bytes = null
            return CaptureMetadataRemoveOutcome.REMOVED
        }
    }
}
