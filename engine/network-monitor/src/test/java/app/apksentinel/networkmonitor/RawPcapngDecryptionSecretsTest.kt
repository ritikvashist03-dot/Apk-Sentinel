package app.apksentinel.networkmonitor

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A Decryption Secrets Block is what makes an exported capture decrypt when it is opened,
 * with nothing for the user to configure. These assert the block is structurally what
 * Wireshark expects and that a key never trails the traffic it unlocks.
 */
class RawPcapngDecryptionSecretsTest {

    @Test
    fun aKeyLogIsEmbeddedAsATlsDecryptionSecretsBlock() {
        val output = ByteArrayOutputStream()
        val manager = RawPcapngCaptureManager()
        assertTrue(manager.start(output) is RawPcapngCaptureStartResult.Started)

        manager.offerTlsSecrets(KEY_LOG.toByteArray(Charsets.US_ASCII))
        manager.offerRawIpPacket(ipv4Packet(), 1_000L)
        manager.stop()
        assertTrue(manager.awaitStopped(5_000L))

        val blocks = parseBlocks(output.toByteArray())
        val secrets = blocks.single { it.type == DECRYPTION_SECRETS_BLOCK }
        val body = ByteBuffer.wrap(secrets.body).order(ByteOrder.LITTLE_ENDIAN)

        assertEquals(TLS_KEY_LOG, body.int)
        val length = body.int
        assertEquals(KEY_LOG.length, length)
        val text = ByteArray(length).also { body.get(it) }.toString(Charsets.US_ASCII)
        assertEquals(KEY_LOG, text)
        assertEquals(1L, manager.status().writtenSecretBlocks)
    }

    @Test
    fun secretsArePlacedBeforeThePacketsTheyUnlock() {
        val output = ByteArrayOutputStream()
        val manager = RawPcapngCaptureManager()
        manager.start(output)

        manager.offerTlsSecrets(KEY_LOG.toByteArray(Charsets.US_ASCII))
        manager.offerRawIpPacket(ipv4Packet(), 1_000L)
        manager.stop()
        manager.awaitStopped(5_000L)

        val types = parseBlocks(output.toByteArray()).map { it.type }
        val secretsAt = types.indexOf(DECRYPTION_SECRETS_BLOCK)
        val packetAt = types.indexOf(ENHANCED_PACKET_BLOCK)
        assertTrue("A DSB must be present", secretsAt >= 0)
        assertTrue("A packet must be present", packetAt >= 0)
        assertTrue("Wireshark applies a DSB forward only", secretsAt < packetAt)
    }

    @Test
    fun everyBlockRemainsLengthConsistentSoTheFileStaysReadable() {
        val output = ByteArrayOutputStream()
        val manager = RawPcapngCaptureManager()
        manager.start(output)
        manager.offerTlsSecrets("CLIENT_RANDOM ${"a".repeat(64)} ${"b".repeat(96)}\n".toByteArray())
        repeat(3) { manager.offerRawIpPacket(ipv4Packet(), 1_000L + it) }
        manager.stop()
        manager.awaitStopped(5_000L)

        val bytes = output.toByteArray()
        val blocks = parseBlocks(bytes)
        // Nothing left over: a trailing partial block would make the file unreadable.
        assertEquals(bytes.size, blocks.sumOf { it.totalLength })
        assertTrue(blocks.all { it.totalLength % 4 == 0 })
        assertEquals(bytes.size.toLong(), manager.status().writtenFileBytes)
    }

    @Test
    fun secretsOfferedWithNoRunningCaptureAreDroppedAndWiped() {
        val manager = RawPcapngCaptureManager()
        val block = KEY_LOG.toByteArray(Charsets.US_ASCII)

        manager.offerTlsSecrets(block)

        assertTrue("The caller's key material must not be left in memory", block.all { it.toInt() == 0 })
    }

    @Test
    fun anOversizeSecretBlockIsDroppedRatherThanTruncated() {
        val output = ByteArrayOutputStream()
        val manager = RawPcapngCaptureManager()
        manager.start(output)

        manager.offerTlsSecrets(ByteArray(128 * 1_024) { 0x41 })
        manager.stop()
        manager.awaitStopped(5_000L)

        // A truncated key log is worse than none: it looks decryptable and is not.
        assertFalse(parseBlocks(output.toByteArray()).any { it.type == DECRYPTION_SECRETS_BLOCK })
        assertEquals(1L, manager.status().droppedSecretBlocks)
    }

    private class Block(val type: Int, val totalLength: Int, val body: ByteArray)

    private fun parseBlocks(bytes: ByteArray): List<Block> {
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val blocks = mutableListOf<Block>()
        while (buffer.remaining() >= 12) {
            val start = buffer.position()
            val type = buffer.int
            val totalLength = buffer.int
            if (totalLength < 12 || start + totalLength > bytes.size) break
            val body = ByteArray(totalLength - 12).also { buffer.get(it) }
            val trailing = buffer.int
            assertEquals("Trailing length must repeat the header length", totalLength, trailing)
            blocks += Block(type, totalLength, body)
        }
        return blocks
    }

    private fun ipv4Packet(): ByteArray = ByteArray(20).also {
        it[0] = 0x45
        it[9] = 6
    }

    private companion object {
        const val DECRYPTION_SECRETS_BLOCK = 0x0000000A
        const val ENHANCED_PACKET_BLOCK = 0x00000006
        const val TLS_KEY_LOG = 0x544C534B
        val KEY_LOG = "CLIENT_RANDOM ${"1".repeat(64)} ${"2".repeat(96)}\n"
    }
}
