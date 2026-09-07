package app.apksentinel.receiver;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/** Builds receiver mTLS around a configured identity and one exact enrolled client SPKI. */
public final class RemoteReceiverTls {
    private RemoteReceiverTls() { }

    public static SSLContext serverContext(KeyStore receiverIdentity, char[] password, byte[] enrolledClientSpki)
            throws Exception {
        if (enrolledClientSpki == null || enrolledClientSpki.length < 64 || enrolledClientSpki.length > 4096) {
            throw new IllegalArgumentException("An enrolled client public certificate is required");
        }
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        var keyManagerFactory = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(receiverIdentity, password);
        var trustManager = new ExactClientTrustManager(enrolledClientSpki);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagerFactory.getKeyManagers(), new TrustManager[]{trustManager}, null);
        return context;
    }

    public static final class ExactClientTrustManager extends X509ExtendedTrustManager {
        private final byte[] expectedSpki;

        public ExactClientTrustManager(byte[] expectedSpki) {
            this.expectedSpki = expectedSpki.clone();
        }

        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            verify(chain);
        }

        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException { verify(chain); }
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine) throws CertificateException { verify(chain); }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) { }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) { }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine) { }
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }

        private void verify(X509Certificate[] chain) throws CertificateException {
            if (chain == null || chain.length == 0) throw new CertificateException("Missing enrolled client certificate");
            X509Certificate leaf = chain[0];
            leaf.checkValidity();
            if (!ReceiverProtocol.isP256(leaf.getPublicKey()) || !MessageDigest.isEqual(leaf.getPublicKey().getEncoded(), expectedSpki)) {
                throw new CertificateException("Client certificate is not the enrolled P-256 identity");
            }
        }

        public void close() { Arrays.fill(expectedSpki, (byte) 0); }
    }
}
