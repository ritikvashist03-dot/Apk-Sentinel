import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/** Offline publisher helper. Run only with output paths outside the source tree. */
public final class ThreatFeedKeyTool {
    private ThreatFeedKeyTool() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 3) usage();
        switch (args[0]) {
            case "generate" -> generate(Path.of(args[1]), Path.of(args[2]));
            case "sign" -> sign(Path.of(args[1]), Path.of(args[2]));
            default -> usage();
        }
    }

    private static void generate(Path privateKeyPath, Path publicKeyBase64Path) throws Exception {
        refuseOverwrite(privateKeyPath);
        refuseOverwrite(publicKeyBase64Path);
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var pair = generator.generateKeyPair();
        Files.write(privateKeyPath, pair.getPrivate().getEncoded());
        Files.writeString(publicKeyBase64Path, Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        System.out.println("Generated P-256 feed keys. Protect the PKCS#8 private key; only the public Base64 file is used by Gradle.");
    }

    private static void sign(Path privateKeyPath, Path canonicalFeedPath) throws Exception {
        byte[] feed = Files.readAllBytes(canonicalFeedPath);
        validateCanonicalFeed(feed);
        PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(
            new PKCS8EncodedKeySpec(Files.readAllBytes(privateKeyPath))
        );
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(key);
        signer.update(feed);
        System.out.println(Base64.getEncoder().encodeToString(signer.sign()));
    }

    private static void validateCanonicalFeed(byte[] feed) {
        if (feed.length == 0 || feed[feed.length - 1] != '\n') {
            throw new IllegalArgumentException("Feed must be non-empty and end with LF.");
        }
        for (byte value : feed) if (value == '\r') throw new IllegalArgumentException("Feed must use LF, never CRLF.");
        String text = new String(feed, java.nio.charset.StandardCharsets.UTF_8);
        if (!java.util.Arrays.equals(feed, text.getBytes(java.nio.charset.StandardCharsets.UTF_8)) ||
            !text.startsWith("APK_SENTINEL_FEED_V1\n")) {
            throw new IllegalArgumentException("Feed is not canonical UTF-8 APK_SENTINEL_FEED_V1 data.");
        }
    }

    private static void refuseOverwrite(Path path) {
        if (Files.exists(path)) throw new IllegalArgumentException("Refusing to overwrite: " + path.toAbsolutePath());
    }

    private static void usage() {
        throw new IllegalArgumentException(
            "Usage: generate <private-key.pk8> <public-key-base64.txt> OR sign <private-key.pk8> <canonical-feed.txt>"
        );
    }
}
