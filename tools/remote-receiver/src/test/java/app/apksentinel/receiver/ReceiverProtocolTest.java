package app.apksentinel.receiver;

import org.junit.Test;

import javax.crypto.KeyAgreement;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.EnumSet;
import java.util.HashSet;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public final class ReceiverProtocolTest {
    @Test public void aps1ApsaDerivesKeyAndRejectsNonceReplay() throws Exception {
        KeyPair receiver = p256();
        KeyPair ephemeral = p256();
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        ByteArrayOutputStream request = new ByteArrayOutputStream();
        request.write(ByteBuffer.allocate(4 + 1 + 32 + 2)
                .putInt(ReceiverProtocol.APS1).put((byte) 1).put(nonce).putShort((short) ephemeral.getPublic().getEncoded().length).array());
        request.write(ephemeral.getPublic().getEncoded());
        ByteArrayOutputStream response = new ByteArrayOutputStream();
        ReceiverProtocol.Attestation attestation = ReceiverProtocol.acceptAttestation(
                new ByteArrayInputStream(request.toByteArray()), response, receiver.getPrivate(), new HashSet<>(), 8);
        byte[] responseBytes = response.toByteArray();
        assertEquals(ReceiverProtocol.APSA, ByteBuffer.wrap(responseBytes).getInt());
        assertArrayEquals(nonce, java.util.Arrays.copyOfRange(responseBytes, 5, 37));
        assertEquals(32, attestation.sessionKey().length);
        attestation.close();
        assertThrows(ReceiverProtocol.ProtocolException.class, () -> ReceiverProtocol.acceptAttestation(
                new ByteArrayInputStream(request.toByteArray()), new ByteArrayOutputStream(), receiver.getPrivate(),
                new HashSet<>(java.util.Set.of(hex(nonce))), 8));
    }

    @Test public void apsrIsOrderedAuthenticatedAndSinkIsRawOnly() throws Exception {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        byte[] first = frame(key, 1, ReceiverProtocol.Category.RAW_ENCRYPTED_PACKET, new byte[]{1, 2, 3});
        byte[] second = frame(key, 2, ReceiverProtocol.Category.RAW_ENCRYPTED_PACKET, new byte[]{4});
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        ReceiverProtocol.FrameVerifier verifier = new ReceiverProtocol.FrameVerifier(
                key, 100, 4, 1000, EnumSet.of(ReceiverProtocol.Category.RAW_ENCRYPTED_PACKET), sink);
        assertEquals(1, verifier.verifyAndConsume(first, null).sequence());
        assertArrayEquals(new byte[]{1, 2, 3}, sink.toByteArray());
        assertThrows(ReceiverProtocol.ProtocolException.class, () -> verifier.verifyAndConsume(first, null));
        assertEquals(2, verifier.verifyAndConsume(second, null).sequence());
        verifier.close();
        java.util.Arrays.fill(key, (byte) 0);
    }

    @Test public void apsrTamperAndSensitiveSinkAreRejected() throws Exception {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        byte[] tampered = frame(key, 1, ReceiverProtocol.Category.RAW_ENCRYPTED_PACKET, new byte[]{9, 8, 7});
        tampered[ReceiverProtocol.APSR_HEADER_BYTES + 1] ^= 0x40;
        ReceiverProtocol.FrameVerifier verifier = new ReceiverProtocol.FrameVerifier(
                key, 100, 4, 1000, EnumSet.of(ReceiverProtocol.Category.RAW_ENCRYPTED_PACKET), new ByteArrayOutputStream());
        assertThrows(ReceiverProtocol.ProtocolException.class, () -> verifier.verifyAndConsume(tampered, null));
        byte[] sensitive = frame(key, 1, ReceiverProtocol.Category.DECRYPTED_PAYLOAD, new byte[]{1});
        ReceiverProtocol.FrameVerifier sensitiveVerifier = new ReceiverProtocol.FrameVerifier(
                key, 100, 4, 1000,
                EnumSet.of(ReceiverProtocol.Category.DECRYPTED_PAYLOAD, ReceiverProtocol.Category.RAW_ENCRYPTED_PACKET),
                new ByteArrayOutputStream());
        assertThrows(ReceiverProtocol.ProtocolException.class, () -> sensitiveVerifier.verifyAndConsume(sensitive, null));
        verifier.close();
        sensitiveVerifier.close();
        java.util.Arrays.fill(key, (byte) 0);
    }

    private static byte[] frame(byte[] key, long sequence, ReceiverProtocol.Category category, byte[] payload) throws Exception {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        byte[] header = ByteBuffer.allocate(ReceiverProtocol.APSR_HEADER_BYTES)
                .putInt(ReceiverProtocol.APSR).put((byte) 1).put((byte) category.ordinal()).putShort((short) 0)
                .putLong(sequence).putLong(1000 + sequence).putInt(payload.length).put(nonce).array();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(header);
        return concat(header, cipher.doFinal(payload));
    }

    private static KeyPair p256() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private static String hex(byte[] bytes) throws Exception { return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
}
