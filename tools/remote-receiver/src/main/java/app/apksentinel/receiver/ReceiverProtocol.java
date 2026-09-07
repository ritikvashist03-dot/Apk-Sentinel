package app.apksentinel.receiver;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.Objects;

/** APS1/APSA attestation and ordered AES-GCM APSR receiver primitives. */
public final class ReceiverProtocol {
    public static final int APS1 = 0x41505331;
    public static final int APSA = 0x41505341;
    public static final int APSR = 0x41505352;
    public static final int VERSION = 1;
    public static final int APSR_HEADER_BYTES = 40;
    public static final int GCM_TAG_BYTES = 16;
    public static final int MAX_P256_SPKI_BYTES = 4096;
    private static final byte[] LABEL = "APK Sentinel Remote Stream v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    private ReceiverProtocol() { }

    public enum Category {
        METADATA,
        RAW_ENCRYPTED_PACKET,
        DECRYPTED_PAYLOAD,
        CREDENTIAL
    }

    public record Attestation(byte[] sessionKey, byte[] nonce) implements AutoCloseable {
        public Attestation {
            sessionKey = sessionKey.clone();
            nonce = nonce.clone();
            if (sessionKey.length != 32 || nonce.length != 32) throw new IllegalArgumentException("Invalid attestation material");
        }

        @Override public void close() {
            java.util.Arrays.fill(sessionKey, (byte) 0);
            java.util.Arrays.fill(nonce, (byte) 0);
        }
    }

    /** Reads one authenticated APS1 request, returns APSA, and derives an ephemeral key. */
    public static Attestation acceptAttestation(
            InputStream input,
            OutputStream output,
            PrivateKey receiverPrivateKey,
            java.util.Set<String> seenNonceFingerprints,
            int maximumNonceEntries
    ) throws IOException {
        Objects.requireNonNull(receiverPrivateKey, "receiverPrivateKey");
        byte[] fixed = new byte[4 + 1 + 32 + 2];
        readFully(input, fixed);
        ByteBuffer header = ByteBuffer.wrap(fixed);
        if (header.getInt() != APS1 || Byte.toUnsignedInt(header.get()) != VERSION) {
            java.util.Arrays.fill(fixed, (byte) 0);
            throw new ProtocolException("Invalid APS1 header");
        }
        byte[] nonce = new byte[32];
        header.get(nonce);
        String nonceFingerprint;
        try {
            nonceFingerprint = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(nonce));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            java.util.Arrays.fill(fixed, (byte) 0);
            java.util.Arrays.fill(nonce, (byte) 0);
            throw new ProtocolException("SHA-256 is unavailable", impossible);
        }
        if (!seenNonceFingerprints.add(nonceFingerprint)) {
            java.util.Arrays.fill(fixed, (byte) 0);
            java.util.Arrays.fill(nonce, (byte) 0);
            throw new ProtocolException("Attestation nonce replay");
        }
        while (seenNonceFingerprints.size() > maximumNonceEntries) {
            var first = seenNonceFingerprints.iterator().next();
            seenNonceFingerprints.remove(first);
        }
        int publicLength = Short.toUnsignedInt(header.getShort());
        if (publicLength < 64 || publicLength > MAX_P256_SPKI_BYTES) {
            java.util.Arrays.fill(fixed, (byte) 0);
            java.util.Arrays.fill(nonce, (byte) 0);
            throw new ProtocolException("Invalid APS1 public key length");
        }
        byte[] ephemeralDer = new byte[publicLength];
        byte[] shared = null;
        try {
            readFully(input, ephemeralDer);
            PublicKey ephemeral = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(ephemeralDer));
            if (!isP256(ephemeral)) throw new ProtocolException("Ephemeral key is not P-256");
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
            agreement.init(receiverPrivateKey);
            agreement.doPhase(ephemeral, true);
            shared = agreement.generateSecret();
            byte[] derivationInput = concat(LABEL, nonce, shared);
            byte[] key;
            try {
                key = MessageDigest.getInstance("SHA-256").digest(derivationInput);
            } finally {
                java.util.Arrays.fill(derivationInput, (byte) 0);
            }
            ByteBuffer response = ByteBuffer.allocate(4 + 1 + 32).putInt(APSA).put((byte) VERSION).put(nonce);
            output.write(response.array());
            output.flush();
            return new Attestation(key, nonce);
        } catch (ProtocolException e) {
            throw e;
        } catch (Exception e) {
            throw new ProtocolException("Attestation failed", e);
        } finally {
            java.util.Arrays.fill(fixed, (byte) 0);
            java.util.Arrays.fill(ephemeralDer, (byte) 0);
            java.util.Arrays.fill(nonce, (byte) 0);
            if (shared != null) java.util.Arrays.fill(shared, (byte) 0);
        }
    }

    public static final class FrameVerifier implements AutoCloseable {
        private byte[] key;
        private final int maximumRecordBytes;
        private final long maximumPackets;
        private final long maximumBytes;
        private final EnumSet<Category> allowedCategories;
        private final OutputStream rawEncryptedPacketSink;
        private long expectedSequence = 1;
        private long acceptedPackets;
        private long acceptedBytes;
        private boolean closed;

        public FrameVerifier(byte[] sessionKey, int maximumRecordBytes, long maximumPackets, long maximumBytes,
                             EnumSet<Category> allowedCategories, OutputStream rawEncryptedPacketSink) {
            if (sessionKey.length != 32 || maximumRecordBytes < 1 || maximumRecordBytes > 64 * 1024 ||
                    maximumPackets < 1 || maximumBytes < 1 || allowedCategories.isEmpty()) {
                throw new IllegalArgumentException("Invalid receiver limits");
            }
            if (rawEncryptedPacketSink != null && !allowedCategories.contains(Category.RAW_ENCRYPTED_PACKET)) {
                throw new IllegalArgumentException("A local sink is only valid for RAW_ENCRYPTED_PACKET");
            }
            this.key = sessionKey.clone();
            this.maximumRecordBytes = maximumRecordBytes;
            this.maximumPackets = maximumPackets;
            this.maximumBytes = maximumBytes;
            this.allowedCategories = allowedCategories.clone();
            this.rawEncryptedPacketSink = rawEncryptedPacketSink;
        }

        /** Verifies one complete APSR frame. Plaintext exists only during this callback. */
        public FrameMetadata verifyAndConsume(byte[] frame, FrameConsumer consumer) throws IOException {
            if (closed) throw new ProtocolException("Verifier is closed");
            if (frame.length < APSR_HEADER_BYTES + GCM_TAG_BYTES ||
                    frame.length > APSR_HEADER_BYTES + maximumRecordBytes + GCM_TAG_BYTES) {
                throw new ProtocolException("Invalid APSR frame length");
            }
            byte[] header = java.util.Arrays.copyOf(frame, APSR_HEADER_BYTES);
            byte[] encrypted = java.util.Arrays.copyOfRange(frame, APSR_HEADER_BYTES, frame.length);
            byte[] nonce = null;
            byte[] plaintext = null;
            try {
                ByteBuffer parsed = ByteBuffer.wrap(header);
                if (parsed.getInt() != APSR || Byte.toUnsignedInt(parsed.get()) != VERSION) throw new ProtocolException("Invalid APSR header");
                int categoryIndex = Byte.toUnsignedInt(parsed.get());
                if (categoryIndex >= Category.values().length || parsed.getShort() != 0) throw new ProtocolException("Invalid APSR category");
                long sequence = parsed.getLong();
                long observedAt = parsed.getLong();
                int payloadLength = parsed.getInt();
                nonce = new byte[12];
                parsed.get(nonce);
                Category category = Category.values()[categoryIndex];
                if (sequence != expectedSequence) throw new ProtocolException(sequence < expectedSequence ? "APSR replay" : "APSR out of order");
                if (!allowedCategories.contains(category) || payloadLength < 1 || payloadLength > maximumRecordBytes ||
                        frame.length != APSR_HEADER_BYTES + payloadLength + GCM_TAG_BYTES) throw new ProtocolException("APSR limits or category rejected");
                if (acceptedPackets >= maximumPackets || payloadLength > maximumBytes - acceptedBytes) throw new ProtocolException("APSR session limit reached");
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
                cipher.updateAAD(header);
                plaintext = cipher.doFinal(encrypted);
                if (plaintext.length != payloadLength) throw new ProtocolException("APSR payload length mismatch");
                if (category == Category.DECRYPTED_PAYLOAD || category == Category.CREDENTIAL) {
                    if (rawEncryptedPacketSink != null) throw new ProtocolException("Sensitive category has no local sink");
                } else if (category == Category.RAW_ENCRYPTED_PACKET && rawEncryptedPacketSink != null) {
                    rawEncryptedPacketSink.write(plaintext);
                    rawEncryptedPacketSink.flush();
                }
                if (consumer != null) consumer.accept(category, sequence, observedAt, plaintext);
                acceptedPackets++;
                acceptedBytes += plaintext.length;
                expectedSequence++;
                return new FrameMetadata(sequence, observedAt, category, plaintext.length);
            } catch (ProtocolException e) {
                throw e;
            } catch (Exception e) {
                throw new ProtocolException("APSR authentication failed", e);
            } finally {
                java.util.Arrays.fill(header, (byte) 0);
                java.util.Arrays.fill(encrypted, (byte) 0);
                if (nonce != null) java.util.Arrays.fill(nonce, (byte) 0);
                if (plaintext != null) java.util.Arrays.fill(plaintext, (byte) 0);
            }
        }

        @Override public void close() {
            if (!closed) {
                closed = true;
                java.util.Arrays.fill(key, (byte) 0);
                key = new byte[0];
            }
        }
    }

    @FunctionalInterface
    public interface FrameConsumer {
        void accept(Category category, long sequence, long observedAtMillis, byte[] plaintext) throws IOException;
    }

    public record FrameMetadata(long sequence, long observedAtMillis, Category category, int byteCount) { }

    public static final class ProtocolException extends IOException {
        private static final long serialVersionUID = 1L;

        public ProtocolException(String message) { super(message); }
        public ProtocolException(String message, Throwable cause) { super(message, cause); }
    }

    public static void readFully(InputStream input, byte[] destination) throws IOException {
        int offset = 0;
        while (offset < destination.length) {
            int read = input.read(destination, offset, destination.length - offset);
            if (read < 0) throw new EOFException("Receiver stream ended early");
            if (read == 0) continue;
            offset += read;
        }
    }

    public static void readFully(InputStream input, byte[] destination, int offset, int length) throws IOException {
        int end = offset + length;
        while (offset < end) {
            int read = input.read(destination, offset, end - offset);
            if (read < 0) throw new EOFException("Receiver stream ended early");
            if (read == 0) continue;
            offset += read;
        }
    }

    public static boolean isP256(PublicKey key) {
        if (!(key instanceof java.security.interfaces.ECPublicKey ec)) return false;
        try {
            var parameters = java.security.AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec expected = parameters.getParameterSpec(ECParameterSpec.class);
            return ec.getParams().getCurve().equals(expected.getCurve()) &&
                    ec.getParams().getGenerator().equals(expected.getGenerator()) &&
                    ec.getParams().getOrder().equals(expected.getOrder()) &&
                    ec.getParams().getCofactor() == expected.getCofactor();
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] concat(byte[]... values) {
        int size = 0;
        for (byte[] value : values) size += value.length;
        byte[] result = new byte[size];
        int offset = 0;
        for (byte[] value : values) {
            System.arraycopy(value, 0, result, offset, value.length);
            offset += value.length;
        }
        return result;
    }
}
