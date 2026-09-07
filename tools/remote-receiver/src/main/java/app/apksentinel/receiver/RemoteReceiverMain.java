package app.apksentinel.receiver;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/** Explicit command-line receiver. Every network and file target is supplied by the operator. */
public final class RemoteReceiverMain {
    private RemoteReceiverMain() { }

    public static void main(String[] args) throws Exception {
        Map<String, String> options = options(args);
        byte[] bindAddress = parseLiteral(options.get("bind"));
        int port = Integer.parseInt(required(options, "port"));
        KeyStore identity = KeyStore.getInstance("PKCS12");
        char[] storePassword = required(options, "storepass").toCharArray();
        try (var input = Files.newInputStream(Path.of(required(options, "identity")))) {
            identity.load(input, storePassword);
        }
        String alias = options.get("alias");
        if (alias == null) {
            var aliases = identity.aliases();
            while (aliases.hasMoreElements()) {
                String candidate = aliases.nextElement();
                if (identity.isKeyEntry(candidate)) { alias = candidate; break; }
            }
        }
        if (alias == null) throw new IllegalArgumentException("The receiver identity has no private-key entry");
        PrivateKey receiverPrivateKey = (PrivateKey) identity.getKey(alias, storePassword);
        if (!ReceiverProtocol.isP256(identity.getCertificate(alias).getPublicKey()) || !receiverPrivateKey.getAlgorithm().equalsIgnoreCase("EC")) {
            throw new IllegalArgumentException("The receiver identity must be a P-256 certificate and private key");
        }
        X509Certificate enrolledClient = loadCertificate(Path.of(required(options, "client-cert")));
        if (!ReceiverProtocol.isP256(enrolledClient.getPublicKey())) throw new IllegalArgumentException("The enrolled client must be P-256");
        OutputStream sink = null;
        if (options.containsKey("raw-sink")) sink = new BoundedFileOutputStream(Path.of(options.get("raw-sink")), Long.parseLong(options.getOrDefault("sink-bytes", "8388608")));
        var tls = RemoteReceiverTls.serverContext(identity, storePassword, enrolledClient.getPublicKey().getEncoded());
        var receiver = RemoteStreamReceiver.bind(
                bindAddress,
                port,
                tls,
                receiverPrivateKey,
                new RemoteStreamReceiver.Limits(16 * 1024, 2_000, 8L * 1024 * 1024, 128),
                EnumSet.of(ReceiverProtocol.Category.METADATA, ReceiverProtocol.Category.RAW_ENCRYPTED_PACKET),
                sink
        );
        Runtime.getRuntime().addShutdownHook(new Thread(receiver::close, "apk-sentinel-receiver-shutdown"));
        try (receiver) {
            receiver.serve();
        } finally {
            if (sink != null) sink.close();
            java.util.Arrays.fill(storePassword, (char) 0);
            java.util.Arrays.fill(bindAddress, (byte) 0);
        }
    }

    private static String required(Map<String, String> options, String key) {
        String value = options.get(key);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing --" + key);
        return value;
    }

    private static Map<String, String> options(String[] args) {
        Map<String, String> values = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            if (!args[i].startsWith("--") || i + 1 >= args.length) throw new IllegalArgumentException("Expected --name value arguments");
            values.put(args[i].substring(2), args[++i]);
        }
        return values;
    }

    private static X509Certificate loadCertificate(Path path) throws Exception {
        byte[] bytes;
        try (var input = Files.newInputStream(path); var collected = new java.io.ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int read;
            while ((read = input.read(buffer, 0, buffer.length)) >= 0) {
                if (read > 0) collected.write(buffer, 0, read);
                if (collected.size() > 64 * 1024) throw new IllegalArgumentException("Client certificate is too large");
            }
            bytes = collected.toByteArray();
            java.util.Arrays.fill(buffer, (byte) 0);
        }
        try {
            String text = new String(bytes, java.nio.charset.StandardCharsets.US_ASCII);
            if (text.contains("BEGIN CERTIFICATE")) {
                text = text.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
                bytes = java.util.Base64.getDecoder().decode(text);
            }
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(bytes));
        } finally {
            java.util.Arrays.fill(bytes, (byte) 0);
        }
    }

    private static byte[] parseLiteral(String value) {
        if (value == null || value.isBlank() || value.indexOf('%') >= 0) throw new IllegalArgumentException("--bind must be an IPv4/IPv6 literal");
        if (value.indexOf(':') < 0) {
            String[] parts = value.split("\\.", -1);
            if (parts.length != 4) throw new IllegalArgumentException("--bind must be an IPv4/IPv6 literal");
            byte[] address = new byte[4];
            for (int i = 0; i < 4; i++) {
                int octet = Integer.parseInt(parts[i]);
                if (octet < 0 || octet > 255 || (parts[i].length() > 1 && parts[i].startsWith("0"))) throw new IllegalArgumentException("Invalid IPv4 literal");
                address[i] = (byte) octet;
            }
            return address;
        }
        int compression = value.indexOf("::");
        if (compression != value.lastIndexOf("::")) throw new IllegalArgumentException("Invalid IPv6 literal");
        String left = compression >= 0 ? value.substring(0, compression) : value;
        String right = compression >= 0 ? value.substring(compression + 2) : "";
        String[] leftParts = left.isEmpty() ? new String[0] : left.split(":", -1);
        String[] rightParts = right.isEmpty() ? new String[0] : right.split(":", -1);
        java.util.List<Integer> leftGroups = parseIpv6Groups(leftParts);
        java.util.List<Integer> rightGroups = parseIpv6Groups(rightParts);
        int totalGroups = leftGroups.size() + rightGroups.size();
        if (totalGroups > 8) throw new IllegalArgumentException("Invalid IPv6 literal");
        int missing = compression >= 0 ? 8 - totalGroups : 0;
        if (compression >= 0 && missing < 1) throw new IllegalArgumentException("Invalid IPv6 literal");
        java.util.List<Integer> expanded = new java.util.ArrayList<>(8);
        expanded.addAll(leftGroups);
        for (int i = 0; i < missing; i++) expanded.add(0);
        expanded.addAll(rightGroups);
        if (expanded.size() != 8) throw new IllegalArgumentException("Invalid IPv6 literal");
        byte[] address = new byte[16];
        for (int i = 0; i < 8; i++) { address[i * 2] = (byte) (expanded.get(i) >>> 8); address[i * 2 + 1] = expanded.get(i).byteValue(); }
        return address;
    }

    private static java.util.List<Integer> parseIpv6Groups(String[] parts) {
        java.util.List<Integer> groups = new java.util.ArrayList<>();
        for (String part : parts) {
            if (part.isEmpty()) throw new IllegalArgumentException("Invalid IPv6 literal");
            if (part.contains(".")) {
                byte[] ipv4 = parseLiteral(part);
                groups.add((Byte.toUnsignedInt(ipv4[0]) << 8) | Byte.toUnsignedInt(ipv4[1]));
                groups.add((Byte.toUnsignedInt(ipv4[2]) << 8) | Byte.toUnsignedInt(ipv4[3]));
            } else {
                if (part.length() > 4) throw new IllegalArgumentException("Invalid IPv6 literal");
                groups.add(Integer.parseInt(part, 16));
            }
        }
        return groups;
    }

    private static final class BoundedFileOutputStream extends OutputStream {
        private final OutputStream delegate;
        private final long maximumBytes;
        private long written;
        BoundedFileOutputStream(Path path, long maximumBytes) throws IOException {
            if (maximumBytes < 1) throw new IllegalArgumentException("sink-bytes must be positive");
            this.delegate = Files.newOutputStream(path);
            this.maximumBytes = maximumBytes;
        }
        @Override public void write(int value) throws IOException { write(new byte[]{(byte) value}); }
        @Override public void write(byte[] bytes, int offset, int length) throws IOException {
            if (length > maximumBytes - written) throw new IOException("Local raw sink limit reached");
            delegate.write(bytes, offset, length); written += length;
        }
        @Override public void flush() throws IOException { delegate.flush(); }
        @Override public void close() throws IOException { delegate.close(); }
    }
}
