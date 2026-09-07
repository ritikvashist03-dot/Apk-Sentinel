package app.apksentinel.engine.rootcapture

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteOrder
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RootCaptureFoundationTest {
    @Test
    fun `default request is disabled and needs fresh start consent`() {
        val request = RootCaptureStartRequest(androidApiLevel = 36, captureInterface = RootCaptureInterface.ALL_DEVICE)
        assertFalse(request.featureEnabled)
        val validation = RootCaptureConsentValidator.validate(
            consent(RootCaptureConsentAction.START_HEADERS_ONLY_CAPTURE, 1_000L),
            RootCaptureConsentAction.START_HEADERS_ONLY_CAPTURE,
            RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY,
            FakeClock(61_001L),
        )
        assertEquals(RootCaptureConsentCheck.Rejected(RootCaptureConsentRejection.ACKNOWLEDGEMENT_STALE), validation)
    }

    @Test
    fun `capability consent cannot be replayed as capture consent`() {
        val validation = RootCaptureConsentValidator.validate(
            consent(RootCaptureConsentAction.CAPABILITY_CHECK, 1_000L),
            RootCaptureConsentAction.START_HEADERS_ONLY_CAPTURE,
            RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY,
            FakeClock(1_100L),
        )
        assertEquals(RootCaptureConsentCheck.Rejected(RootCaptureConsentRejection.WRONG_ACTION), validation)
    }

    @Test
    fun `full consent cannot be reused for the headers-only scope`() {
        val validation = RootCaptureConsentValidator.validate(
            fullConsent(RootCaptureConsentAction.CAPABILITY_CHECK, 1_000L),
            RootCaptureConsentAction.CAPABILITY_CHECK,
            RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY,
            FakeClock(1_100L),
        )
        assertEquals(RootCaptureConsentCheck.Rejected(RootCaptureConsentRejection.WRONG_SCOPE), validation)
    }

    @Test
    fun `full capability probe is scope-bound and reports full limitations`() {
        val result = RootCaptureController(
            runner = FakeRunner(),
            outputStore = FakeStore(),
            clock = FakeClock(1_010L),
            scheduler = FakeScheduler(),
            pumpExecutor = ImmediatePumpExecutor,
        ).checkCapability(
            fullConsent(RootCaptureConsentAction.CAPABILITY_CHECK, 1_000L),
            androidApiLevel = 36,
            scope = RootCaptureScope.FULL_PACKET_CAPTURE,
        )
        assertEquals(RootCaptureCapability.USABLE, result.capability)
        assertEquals(RootCaptureScope.FULL_PACKET_CAPTURE, result.scope)
        assertTrue(result.limitations.contains(RootCaptureLimitation.FULL_PACKET_BYTES_CAPTURED_UP_TO_SNAP_LENGTH))
        assertFalse(result.limitations.contains(RootCaptureLimitation.APPLICATION_PAYLOADS_EXCLUDED))
    }

    @Test
    fun `future api levels still require and perform the explicit capability probe`() {
        val result = RootCaptureController(
            runner = FakeRunner(),
            outputStore = FakeStore(),
            clock = FakeClock(1_010L),
            scheduler = FakeScheduler(),
            pumpExecutor = ImmediatePumpExecutor,
        ).checkCapability(
            consent(RootCaptureConsentAction.CAPABILITY_CHECK, 1_000L),
            androidApiLevel = 10_000,
        )
        assertEquals(RootCaptureCapability.USABLE, result.capability)
    }

    @Test
    fun `consent use ledger rejects replay even when action and scope match`() {
        val ledger = RootCaptureConsentUseLedger()
        val consent = consent(RootCaptureConsentAction.START_HEADERS_ONLY_CAPTURE, 1_000L)
        assertEquals(
            RootCaptureConsentCheck.Accepted,
            ledger.validateAndConsume(
                consent,
                RootCaptureConsentAction.START_HEADERS_ONLY_CAPTURE,
                RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY,
                FakeClock(1_001L),
            ),
        )
        assertEquals(
            RootCaptureConsentCheck.Rejected(RootCaptureConsentRejection.CONSENT_ALREADY_USED),
            ledger.validateAndConsume(
                consent,
                RootCaptureConsentAction.START_HEADERS_ONLY_CAPTURE,
                RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY,
                FakeClock(1_001L),
            ),
        )
    }

    @Test
    fun `command factory admits only trusted interface and fixed no payload filter`() {
        val rejected = runCatching { RootCaptureTrustedInterfaceMap(wifi = "wlan0;id") }.isFailure
        assertTrue(rejected)
        val command = RootCaptureCommandFactory.create(
            RootCaptureStartRequest(
                androidApiLevel = 36,
                featureEnabled = true,
                captureInterface = RootCaptureInterface.WIFI,
            ),
            RootCaptureTrustedInterfaceMap(wifi = "wlan0"),
        )
        assertEquals("tcpdump", command.executable)
        assertTrue(command.arguments.containsAll(listOf(
            "-s", "96", "-w", "-", "ip[2:2]", "=", "ip[0]", "tcp[12]", "/", "4",
        )))
        assertFalse(command.arguments.contains("<="))
        assertFalse(command.arguments.any { it.contains(';') || it.contains('$') || it.contains('`') })
    }

    @Test
    fun `full scope is separately consented and selects only reviewed filters`() {
        val full = RootCaptureStartRequest(
            androidApiLevel = 36,
            featureEnabled = true,
            scope = RootCaptureScope.FULL_PACKET_CAPTURE,
            filter = RootCaptureFilter.ALL_TRAFFIC,
            captureInterface = RootCaptureInterface.ALL_DEVICE,
            limits = RootCaptureLimits.fullPacketCaptureDefaults(),
        )
        val allCommand = RootCaptureCommandFactory.create(full, RootCaptureTrustedInterfaceMap())
        assertTrue(allCommand.arguments.containsAll(listOf("-s", "4096", "-i", "any", "-w", "-")))
        assertFalse(allCommand.arguments.contains("tcp"))

        val narrowCommand = RootCaptureCommandFactory.create(
            full.copy(filter = RootCaptureFilter.IPV4_IPV6_TCP_UDP),
            RootCaptureTrustedInterfaceMap(),
        )
        assertTrue(narrowCommand.arguments.containsAll(listOf("ip", "ip6", "tcp", "udp")))
        val wrongFilter = full.copy(filter = RootCaptureFilter.IPV4_TCP_CONNECTION_CONTROL_NO_PAYLOAD)
        assertFalse(RootCaptureCommandFactory.isRequestAllowed(wrongFilter))
        assertFalse(
            RootCaptureCommandFactory.isRequestAllowed(
                full.copy(limits = RootCaptureLimits(maximumBytes = 2L * 1024L * 1024L, snapLengthBytes = 96)),
            ),
        )
        assertEquals(
            RootCaptureConsentAction.START_FULL_PACKET_CAPTURE,
            RootCaptureScope.FULL_PACKET_CAPTURE.requiredConsentAction(),
        )
    }

    @Test
    fun `no payload contract rejects FIN data and TCP Fast Open SYN data`() {
        val finWithPayload = tcpControlPacket(flags = 0x01, payloadBytes = 1)
        val synWithFastOpenData = tcpControlPacket(flags = 0x02, payloadBytes = 8)
        val headerOnlyFin = tcpControlPacket(flags = 0x01, payloadBytes = 0)

        assertFalse(RootCapturePacketShape.isTcpControlHeaderOnly(finWithPayload))
        assertFalse(RootCapturePacketShape.isTcpControlHeaderOnly(synWithFastOpenData))
        assertTrue(RootCapturePacketShape.isTcpControlHeaderOnly(headerOnlyFin))
    }

    @Test
    fun `serializer quotes every token rather than allowing shell breakout`() {
        val command = RootCaptureCommand("tcpdump", listOf("-i", "wlan0';id", "-w", "-"))
        val serialized = RootCaptureSafeShellSerializer.serialize(command)
        assertTrue(serialized.contains("'wlan0'\"'\"';id'"))
        assertFalse(serialized.contains("wlan0';id -w"))
    }

    @Test
    fun `bounded pump stops exactly at byte cap and zeroizes its buffer`() {
        val sink = ByteArrayOutputStream()
        val pcap = pcap(ByteOrder.LITTLE_ENDIAN, listOf(20))
        val result = RootCaptureBoundedOutputPump.copy(ByteArrayInputStream(pcap), sink, 45L)
        assertEquals(RootCapturePumpResult.ByteCap(24L), result)
        assertEquals(24, sink.size())
    }

    @Test
    fun `bounded pump stops at packet cap without reading or writing a later record`() {
        val pcap = pcap(ByteOrder.LITTLE_ENDIAN, listOf(4, 5, 6))
        val sink = ByteArrayOutputStream()

        val result = RootCaptureBoundedOutputPump.copy(
            ByteArrayInputStream(pcap), sink, maximumBytes = pcap.size.toLong(), maximumPackets = 2,
        )

        assertEquals(RootCapturePumpResult.PacketCap(65L, 2), result)
        assertArrayEquals(pcap.copyOf(65), sink.toByteArray())
    }

    @Test
    fun `bounded pump accepts both classic pcap byte orders and counts complete records`() {
        listOf(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN).forEach { order ->
            val pcap = pcap(order, listOf(0, 3))
            val sink = ByteArrayOutputStream()
            val result = RootCaptureBoundedOutputPump.copy(
                ByteArrayInputStream(pcap), sink, maximumBytes = pcap.size.toLong(), maximumPackets = 10,
            )

            assertEquals(RootCapturePumpResult.Complete(pcap.size.toLong(), 2), result)
            assertArrayEquals(pcap, sink.toByteArray())
        }
    }

    @Test
    fun `bounded full pump handles zero-returning streams and a larger snap length`() {
        val source = ZeroThenDataInputStream(pcap(ByteOrder.BIG_ENDIAN, listOf(120)))
        val sink = ByteArrayOutputStream()
        val input = pcap(ByteOrder.BIG_ENDIAN, listOf(120))
        val result = RootCaptureBoundedOutputPump.copy(
            source,
            sink,
            maximumBytes = input.size.toLong(),
            maximumPackets = 2,
            snapLengthBytes = 128,
        )
        assertEquals(RootCapturePumpResult.Complete(input.size.toLong(), 1), result)
        assertArrayEquals(input, sink.toByteArray())
    }

    @Test
    fun `bounded pump fails closed for a stream that never makes progress`() {
        assertEquals(
            RootCapturePumpResult.Failed,
            RootCaptureBoundedOutputPump.copy(AlwaysZeroInputStream(), ByteArrayOutputStream(), 32_768L),
        )
    }

    @Test
    fun `bounded pump rejects malformed or truncated pcap without accepting a record`() {
        val malformedLength = pcap(ByteOrder.LITTLE_ENDIAN, listOf(97))
        val truncatedPayload = pcap(ByteOrder.BIG_ENDIAN, listOf(8)).copyOf(24 + 16 + 3)
        val truncatedHeader = pcap(ByteOrder.LITTLE_ENDIAN, listOf(1)).copyOf(24 + 7)
        val malformedMagic = pcap(ByteOrder.LITTLE_ENDIAN, listOf(1)).also { it[0] = 0 }
        val malformedOriginalLength = pcap(ByteOrder.LITTLE_ENDIAN, listOf(1)).also { it[24 + 12] = 0 }

        listOf(malformedLength, truncatedPayload, truncatedHeader, malformedMagic, malformedOriginalLength).forEach { input ->
            val sink = ByteArrayOutputStream()
            assertEquals(
                RootCapturePumpResult.Failed,
                RootCaptureBoundedOutputPump.copy(ByteArrayInputStream(input), sink, 32_768L, maximumPackets = 10),
            )
        }
    }

    @Test
    fun `bounded pump does not close caller streams and reports progress after complete writes`() {
        val input = TrackingInputStream(pcap(ByteOrder.LITTLE_ENDIAN, listOf(2)))
        val output = TrackingOutputStream()
        val progress = mutableListOf<Pair<Long, Int>>()

        val result = RootCaptureBoundedOutputPump.copy(
            input,
            output,
            maximumBytes = 32_768L,
            maximumPackets = 10,
            onProgress = { bytes, packets -> progress += bytes to packets },
        )

        assertEquals(RootCapturePumpResult.Complete(42L, 1), result)
        assertFalse(input.closed)
        assertFalse(output.closed)
        assertEquals(listOf(24L to 0, 42L to 1), progress)
    }

    @Test
    fun `denied root is typed and no process starts`() {
        val runner = FakeRunner(root = RootCaptureRootAvailability.ACCESS_DENIED)
        val controller = controller(runner)
        val result = controller.start(
            consent(RootCaptureConsentAction.START_HEADERS_ONLY_CAPTURE, 1_000L),
            request(enabled = true),
        )
        assertEquals(RootCaptureStartResult.Rejected(RootCaptureStartRejection.ROOT_UNAVAILABLE), result)
        assertFalse(runner.started)
    }

    @Test
    fun `tcpdump unavailable is typed and no process starts`() {
        val runner = FakeRunner(tool = RootCaptureCommandAvailability.UNAVAILABLE)
        val result = controller(runner).start(consent(RootCaptureConsentAction.START_HEADERS_ONLY_CAPTURE, 1_000L), request(enabled = true))
        assertEquals(RootCaptureStartResult.Rejected(RootCaptureStartRejection.TCPDUMP_UNAVAILABLE), result)
        assertFalse(runner.started)
    }

    @Test
    fun `stop and privacy erase terminate process and remove temporary output`() {
        val runner = FakeRunner(stdout = ByteArrayInputStream(pcap(ByteOrder.LITTLE_ENDIAN, listOf(2))))
        val store = FakeStore()
        val executor = QueuedPumpExecutor()
        val controller = RootCaptureController(
            runner = runner,
            outputStore = store,
            clock = FakeClock(1_010L),
            scheduler = FakeScheduler(),
            pumpExecutor = executor,
        )
        val started = controller.start(consent(RootCaptureConsentAction.START_HEADERS_ONLY_CAPTURE, 1_000L), request(enabled = true))
        val session = (started as RootCaptureStartResult.Started).session
        val immediate = controller.stop(session.sessionId)!!
        assertTrue(immediate.finalizing)
        assertTrue(runner.process.stopped)
        assertEquals(
            RootCaptureExportResult.Rejected(RootCaptureExportRejection.SESSION_ACTIVE),
            controller.prepareExport(RootCaptureExportRequest(session.sessionId)),
        )
        assertEquals(
            RootCaptureExportResult.Rejected(RootCaptureExportRejection.SESSION_ACTIVE),
            controller.exportToUserChosenDestination(RootCaptureExportRequest(session.sessionId), ByteArrayOutputStream()),
        )
        executor.run()
        assertEquals(RootCaptureExportResult.UserMediatedDestinationRequired, controller.prepareExport(RootCaptureExportRequest(session.sessionId)))
        assertEquals(RootCaptureEraseResult.Erased, controller.eraseAll())
        assertTrue(store.erasedAll)
    }

    @Test
    fun `controller propagates packet cap and observed counters into terminal snapshot`() {
        val pcap = pcap(ByteOrder.BIG_ENDIAN, listOf(2, 2, 2))
        val runner = FakeRunner(stdout = ByteArrayInputStream(pcap))
        val controller = RootCaptureController(
            runner = runner,
            outputStore = FakeStore(),
            clock = FakeClock(1_010L),
            scheduler = FakeScheduler(),
            pumpExecutor = ImmediatePumpExecutor,
        )
        val result = controller.start(
            consent(RootCaptureConsentAction.START_HEADERS_ONLY_CAPTURE, 1_000L),
            request(enabled = true, limits = RootCaptureLimits(maximumPackets = 2)),
        ) as RootCaptureStartResult.Started

        val snapshot = controller.snapshot(result.session.sessionId)!!
        assertFalse(snapshot.active)
        assertEquals(RootCaptureTerminalReason.PACKET_CAP_REACHED, snapshot.terminalReason)
        assertEquals(60L, snapshot.observedBytes)
        assertEquals(2, snapshot.observedPackets)
        assertEquals(RootCaptureOutputStatus.TRUNCATED_AT_PACKET_CAP, snapshot.outputStatus)
        assertTrue(snapshot.exportable)
        assertTrue(runner.process.stopped)
    }

    @Test
    fun `stop wins a pump race and returns an immediate terminal snapshot`() {
        val executor = QueuedPumpExecutor()
        val runner = FakeRunner(stdout = ByteArrayInputStream(pcap(ByteOrder.LITTLE_ENDIAN, listOf(2))))
        val controller = RootCaptureController(
            runner = runner,
            outputStore = FakeStore(),
            clock = FakeClock(1_010L),
            scheduler = FakeScheduler(),
            pumpExecutor = executor,
        )
        val started = controller.start(
            consent(RootCaptureConsentAction.START_HEADERS_ONLY_CAPTURE, 1_000L),
            request(enabled = true),
        ) as RootCaptureStartResult.Started

        val stopped = controller.stop(started.session.sessionId)!!
        assertFalse(stopped.active)
        assertTrue(stopped.finalizing)
        assertEquals(RootCaptureTerminalReason.USER_STOPPED, stopped.terminalReason)
        assertTrue(runner.process.stopped)
        executor.run()
        val finalized = controller.snapshot(started.session.sessionId)!!
        assertFalse(finalized.finalizing)
        assertEquals(RootCaptureTerminalReason.USER_STOPPED, finalized.terminalReason)
        assertEquals(42L, finalized.observedBytes)
        assertEquals(1, finalized.observedPackets)
    }

    @Test
    fun `concurrent starts reserve before probe and erase cancels only the winner`() {
        val enteredProbe = CountDownLatch(1)
        val releaseProbe = CountDownLatch(1)
        val runner = BarrierRunner(enteredProbe, releaseProbe)
        val executor = QueuedPumpExecutor()
        val controller = RootCaptureController(
            runner = runner,
            outputStore = FakeStore(),
            clock = FakeClock(1_010L),
            scheduler = FakeScheduler(),
            pumpExecutor = executor,
        )
        var firstResult: RootCaptureStartResult? = null
        val first = thread {
            firstResult = controller.start(
                consent(RootCaptureConsentAction.START_HEADERS_ONLY_CAPTURE, 1_000L),
                request(enabled = true),
            )
        }
        assertTrue(enteredProbe.await(1L, TimeUnit.SECONDS))
        val secondResult = controller.start(
            consent(RootCaptureConsentAction.START_HEADERS_ONLY_CAPTURE, 1_000L),
            request(enabled = true),
        )
        assertEquals(
            RootCaptureStartResult.Rejected(RootCaptureStartRejection.ANOTHER_CAPTURE_ACTIVE),
            secondResult,
        )
        releaseProbe.countDown()
        first.join(2_000L)
        assertTrue(firstResult is RootCaptureStartResult.Started)
        assertEquals(1, runner.startCount)
        controller.eraseAll()
        assertTrue(runner.process.stopped)
    }

    @Test
    fun `full start consent is single use and cannot be replayed`() {
        val limits = RootCaptureLimits.fullPacketCaptureDefaults()
        val request = RootCaptureStartRequest(
            androidApiLevel = 36,
            featureEnabled = true,
            scope = RootCaptureScope.FULL_PACKET_CAPTURE,
            filter = RootCaptureFilter.ALL_TRAFFIC,
            captureInterface = RootCaptureInterface.ALL_DEVICE,
            limits = limits,
        )
        val consent = fullConsent(RootCaptureConsentAction.START_FULL_PACKET_CAPTURE, 1_000L)
        val controller = RootCaptureController(
            runner = FakeRunner(stdout = ByteArrayInputStream(pcap(ByteOrder.LITTLE_ENDIAN, listOf(4)))),
            outputStore = FakeStore(),
            clock = FakeClock(1_010L),
            scheduler = FakeScheduler(),
            pumpExecutor = ImmediatePumpExecutor,
        )
        val first = controller.start(consent, request)
        assertTrue(first is RootCaptureStartResult.Started)
        assertEquals(
            RootCaptureStartResult.Rejected(RootCaptureStartRejection.CONSENT_REJECTED),
            controller.start(consent, request),
        )
    }

    private fun controller(runner: FakeRunner) = RootCaptureController(
        runner = runner,
        outputStore = FakeStore(),
        clock = FakeClock(1_010L),
        scheduler = FakeScheduler(),
        pumpExecutor = QueuedPumpExecutor(),
    )

    private fun request(enabled: Boolean, limits: RootCaptureLimits = RootCaptureLimits()) = RootCaptureStartRequest(
        androidApiLevel = 36,
        featureEnabled = enabled,
        captureInterface = RootCaptureInterface.ALL_DEVICE,
        limits = limits,
    )

    private fun pcap(order: ByteOrder, lengths: List<Int>): ByteArray {
        val output = ByteArrayOutputStream()
        val globalHeader = ByteArray(24)
        if (order == ByteOrder.LITTLE_ENDIAN) {
            globalHeader[0] = 0xd4.toByte(); globalHeader[1] = 0xc3.toByte()
            globalHeader[2] = 0xb2.toByte(); globalHeader[3] = 0xa1.toByte()
        } else {
            globalHeader[0] = 0xa1.toByte(); globalHeader[1] = 0xb2.toByte()
            globalHeader[2] = 0xc3.toByte(); globalHeader[3] = 0xd4.toByte()
        }
        output.write(globalHeader)
        lengths.forEachIndexed { index, length ->
            val header = ByteArray(16)
            putInt(header, 8, length, order)
            putInt(header, 12, length, order)
            output.write(header)
            output.write(ByteArray(length) { (it + index).toByte() })
        }
        return output.toByteArray()
    }

    private fun putInt(target: ByteArray, offset: Int, value: Int, order: ByteOrder) {
        if (order == ByteOrder.LITTLE_ENDIAN) {
            target[offset] = value.toByte()
            target[offset + 1] = (value ushr 8).toByte()
            target[offset + 2] = (value ushr 16).toByte()
            target[offset + 3] = (value ushr 24).toByte()
        } else {
            target[offset] = (value ushr 24).toByte()
            target[offset + 1] = (value ushr 16).toByte()
            target[offset + 2] = (value ushr 8).toByte()
            target[offset + 3] = value.toByte()
        }
    }

    private fun tcpControlPacket(flags: Int, payloadBytes: Int): ByteArray {
        val packet = ByteArray(40 + payloadBytes)
        packet[0] = 0x45
        packet[2] = ((packet.size ushr 8) and 0xff).toByte()
        packet[3] = (packet.size and 0xff).toByte()
        packet[9] = 6
        packet[20 + 12] = 0x50
        packet[20 + 13] = flags.toByte()
        return packet
    }

    private fun consent(action: RootCaptureConsentAction, acknowledgedAt: Long) = RootCaptureConsent(
        action = action,
        scope = RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY,
        disclosureVersion = "root-capture-v1",
        acknowledgedAtMillis = acknowledgedAt,
        sessionNonce = "0123456789abcdef",
    )

    private fun fullConsent(action: RootCaptureConsentAction, acknowledgedAt: Long) = RootCaptureConsent(
        action = action,
        scope = RootCaptureScope.FULL_PACKET_CAPTURE,
        disclosureVersion = "root-capture-v2",
        acknowledgedAtMillis = acknowledgedAt,
        sessionNonce = "fedcba9876543210",
    )

    private class FakeClock(private val now: Long) : RootCaptureClock { override fun nowMillis(): Long = now }

    private class FakeRunner(
        private val root: RootCaptureRootAvailability = RootCaptureRootAvailability.AVAILABLE,
        private val tool: RootCaptureCommandAvailability = RootCaptureCommandAvailability.AVAILABLE,
        private val stdout: InputStream = ByteArrayInputStream(ByteArray(32)),
    ) : RootCapturePrivilegeRunner {
        var started = false
        val process = FakeProcess(stdout)
        override fun rootAvailability() = root
        override fun commandAvailability(command: RootCaptureCommand) = tool
        override fun start(command: RootCaptureCommand): RootCaptureProcessLaunch {
            started = true
            return RootCaptureProcessLaunch.Started(process)
        }
    }

    private class BarrierRunner(
        private val enteredProbe: CountDownLatch,
        private val releaseProbe: CountDownLatch,
    ) : RootCapturePrivilegeRunner {
        val process = FakeProcess(ByteArrayInputStream(ByteArray(32)))
        var startCount = 0
        override fun rootAvailability(): RootCaptureRootAvailability {
            enteredProbe.countDown()
            releaseProbe.await(2L, TimeUnit.SECONDS)
            return RootCaptureRootAvailability.AVAILABLE
        }
        override fun commandAvailability(command: RootCaptureCommand) = RootCaptureCommandAvailability.AVAILABLE
        override fun start(command: RootCaptureCommand): RootCaptureProcessLaunch {
            startCount += 1
            return RootCaptureProcessLaunch.Started(process)
        }
    }

    private class FakeProcess(private val output: InputStream) : RootCaptureRunningProcess {
        var stopped = false
        private var listener: ((RootCaptureProcessTermination) -> Unit)? = null
        override fun stdout(): InputStream = output
        override fun stop() { stopped = true; listener?.invoke(RootCaptureProcessTermination.EXITED) }
        override fun setTerminationListener(listener: (RootCaptureProcessTermination) -> Unit) { this.listener = listener }
    }

    private class FakeStore : RootCaptureOutputStore {
        var erasedAll = false
        override fun create(sessionId: String): RootCaptureOutputCreate = RootCaptureOutputCreate.Ready(ByteArrayOutputStream())
        override fun erase(sessionId: String): Boolean = true
        override fun eraseAll(): Boolean { erasedAll = true; return true }
        override fun copyTo(sessionId: String, destination: OutputStream, maximumBytes: Long): Boolean = true
    }

    private class FakeScheduler : RootCaptureScheduler {
        override fun once(delayMillis: Long, action: () -> Unit) = FakeTask()
        override fun repeating(intervalMillis: Long, action: () -> Unit) = FakeTask()
    }

    private class FakeTask : RootCaptureScheduledTask { override fun cancel() = Unit }
    private object ImmediatePumpExecutor : RootCapturePumpExecutor {
        override fun execute(action: () -> Unit) = action()
    }

    private class QueuedPumpExecutor : RootCapturePumpExecutor {
        private var action: (() -> Unit)? = null
        override fun execute(action: () -> Unit) { this.action = action }
        fun run() { action?.invoke() }
    }

    private class TrackingInputStream(bytes: ByteArray) : ByteArrayInputStream(bytes) {
        var closed = false
        override fun close() { closed = true }
    }

    private class TrackingOutputStream : ByteArrayOutputStream() {
        var closed = false
        override fun close() { closed = true }
    }

    private class ZeroThenDataInputStream(private val bytes: ByteArray) : InputStream() {
        private var offset = 0
        private var returnedZero = false

        override fun read(target: ByteArray, targetOffset: Int, length: Int): Int {
            if (!returnedZero) {
                returnedZero = true
                return 0
            }
            if (offset >= bytes.size) return -1
            val count = minOf(length, bytes.size - offset)
            bytes.copyInto(target, targetOffset, offset, offset + count)
            offset += count
            return count
        }

        override fun read(): Int = if (offset >= bytes.size) -1 else bytes[offset++].toInt() and 0xff
    }

    private class AlwaysZeroInputStream : InputStream() {
        override fun read(target: ByteArray, targetOffset: Int, length: Int): Int = 0
        override fun read(): Int = 0
    }
}
