package app.apksentinel.receiver;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.security.PrivateKey;
import java.util.Objects;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.Set;

/** One explicitly bound local receiver. It never discovers, relays, or resolves names. */
public final class RemoteStreamReceiver implements AutoCloseable {
    public record Limits(int maximumRecordBytes, long maximumPackets, long maximumBytes, int maximumNonceEntries) { }

    private final SSLServerSocket serverSocket;
    private final PrivateKey receiverPrivateKey;
    private final Limits limits;
    private final EnumSet<ReceiverProtocol.Category> categories;
    private final java.io.OutputStream rawEncryptedPacketSink;
    // Insertion-ordered: ReceiverProtocol evicts this bounded replay cache with
    // iterator().next(), which is only the OLDEST entry if the set preserves insertion
    // order. A HashSet made that eviction arbitrary, so a still-relevant nonce could be
    // dropped and then replayed. Re-adding an existing element does not reorder a
    // LinkedHashSet, so first-seen order is what bounds the cache.
    private final Set<String> seenNonces = new LinkedHashSet<>();
    private volatile boolean closed;

    public RemoteStreamReceiver(
            SSLServerSocket serverSocket,
            PrivateKey receiverPrivateKey,
            Limits limits,
            EnumSet<ReceiverProtocol.Category> categories,
            OutputStream rawEncryptedPacketSink
    ) throws IOException {
        if (!serverSocket.getNeedClientAuth()) throw new IllegalArgumentException("Receiver mTLS must require client authentication");
        if (receiverPrivateKey == null || !receiverPrivateKey.getAlgorithm().equalsIgnoreCase("EC")) throw new IllegalArgumentException("Receiver identity must be EC");
        if (limits == null || limits.maximumRecordBytes() < 1 || limits.maximumRecordBytes() > 64 * 1024 ||
                limits.maximumPackets() < 1 || limits.maximumBytes() < 1 || limits.maximumNonceEntries() < 1) {
            throw new IllegalArgumentException("Invalid receiver limits");
        }
        this.serverSocket = serverSocket;
        this.receiverPrivateKey = receiverPrivateKey;
        this.limits = limits;
        if (categories == null || categories.isEmpty()) throw new IllegalArgumentException("At least one receiver category is required");
        this.categories = categories.clone();
        this.rawEncryptedPacketSink = rawEncryptedPacketSink;
    }

    public static RemoteStreamReceiver bind(
            byte[] literalAddress,
            int port,
            javax.net.ssl.SSLContext tlsContext,
            PrivateKey receiverPrivateKey,
            Limits limits,
            EnumSet<ReceiverProtocol.Category> categories,
            OutputStream rawEncryptedPacketSink
    ) throws IOException {
        Objects.requireNonNull(tlsContext, "tlsContext");
        if (literalAddress == null || (literalAddress.length != 4 && literalAddress.length != 16)) throw new IllegalArgumentException("Literal address required");
        if (port < 1 || port > 65535) throw new IllegalArgumentException("Invalid receiver port");
        InetAddress address = InetAddress.getByAddress(literalAddress.clone());
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isMulticastAddress() || isIpv4Broadcast(address)) {
            throw new IllegalArgumentException("Receiver bind address must be a specific unicast interface literal");
        }
        if (rawEncryptedPacketSink != null && !categories.contains(ReceiverProtocol.Category.RAW_ENCRYPTED_PACKET)) throw new IllegalArgumentException("Sink category rejected");
        SSLServerSocketFactory factory = tlsContext.getServerSocketFactory();
        SSLServerSocket socket = (SSLServerSocket) factory.createServerSocket();
        socket.setNeedClientAuth(true);
        socket.bind(new InetSocketAddress(address, port));
        return new RemoteStreamReceiver(socket, receiverPrivateKey, limits, categories, rawEncryptedPacketSink);
    }

    /** Blocks accepting one client at a time; close() interrupts the accept loop. */
    public void serve() throws IOException {
        while (!closed) {
            try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                socket.setUseClientMode(false);
                socket.startHandshake();
                handle(socket.getInputStream(), socket.getOutputStream());
            } catch (ReceiverProtocol.ProtocolException rejected) {
                // Close the connection without logging protocol or plaintext details.
            } catch (IOException rejected) {
                // A hostile or abruptly disconnected client must not stop the
                // explicitly started receiver. close() still terminates serve().
                if (closed) return;
            }
        }
    }

    private void handle(InputStream input, OutputStream output) throws IOException {
        ReceiverProtocol.Attestation attestation = ReceiverProtocol.acceptAttestation(
                input, output, receiverPrivateKey, seenNonces, limits.maximumNonceEntries());
        try (attestation; ReceiverProtocol.FrameVerifier verifier = new ReceiverProtocol.FrameVerifier(
                attestation.sessionKey(), limits.maximumRecordBytes(), limits.maximumPackets(), limits.maximumBytes(), categories, rawEncryptedPacketSink)) {
            byte[] header = new byte[ReceiverProtocol.APSR_HEADER_BYTES];
            try {
                while (!closed) {
                    try {
                        ReceiverProtocol.readFully(input, header);
                    } catch (java.io.EOFException end) {
                        return;
                    }
                    int payloadLength = java.nio.ByteBuffer.wrap(header).getInt(28);
                    if (payloadLength < 1 || payloadLength > limits.maximumRecordBytes()) throw new ReceiverProtocol.ProtocolException("APSR payload limit");
                    byte[] frame = new byte[ReceiverProtocol.APSR_HEADER_BYTES + payloadLength + ReceiverProtocol.GCM_TAG_BYTES];
                    try {
                        System.arraycopy(header, 0, frame, 0, header.length);
                        ReceiverProtocol.readFully(input, frame, header.length, frame.length - header.length);
                        verifier.verifyAndConsume(frame, null);
                    } finally {
                        java.util.Arrays.fill(frame, (byte) 0);
                    }
                }
            } finally {
                java.util.Arrays.fill(header, (byte) 0);
            }
        }
    }

    private static boolean isIpv4Broadcast(InetAddress address) {
        byte[] bytes = address.getAddress();
        if (bytes.length != 4) return false;
        for (byte value : bytes) if ((value & 0xff) != 0xff) return false;
        return true;
    }

    @Override public void close() {
        closed = true;
        try { serverSocket.close(); } catch (IOException ignored) { }
    }
}
