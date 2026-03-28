import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * BlindSSLSocketFactory
 *
 * A custom {@link SocketFactory} that wraps an SSL socket factory configured with a
 * no-op {@link X509TrustManager}. Every certificate — regardless of issuer, expiry,
 * or hostname — is accepted unconditionally.
 *
 * WARNING: This class disables TLS certificate validation entirely.
 * It is intended only for testing against LDAP servers that use self-signed or
 * otherwise untrusted certificates. Do not use in production environments.
 *
 * JNDI picks up this factory when the environment property
 * {@code java.naming.ldap.factory.socket} is set to the fully-qualified name of this class.
 *
 * @author Nirenj George
 */
public class BlindSSLSocketFactory extends SocketFactory {

    /**
     * The underlying SSL socket factory initialised with the trust-all manager.
     * Shared across all instances; initialised once in the static block below.
     */
    private static SocketFactory blindFactory = null;

    // -------------------------------------------------------------------------
    // Static initialiser – build the trust-all SSL context once at class load
    // -------------------------------------------------------------------------

    static {
        /*
         * A trust manager that accepts every certificate without any validation.
         * getAcceptedIssuers() returns null (no trusted root constraints) and the
         * two check* methods are intentionally empty (no validation performed).
         */
        TrustManager[] trustAllManagers = new TrustManager[] {
            new X509TrustManager() {
                /** No issuer constraints — accept certificates from any CA. */
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                /** Skip client-certificate validation entirely. */
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    // Intentionally empty — all client certificates are accepted.
                }

                /** Skip server-certificate validation entirely. */
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    // Intentionally empty — all server certificates are accepted.
                }
            }
        };

        try {
            // Initialise an SSL context backed by the trust-all manager.
            SSLContext sslContext = SSLContext.getInstance("SSL_TLSv2");
            sslContext.init(null, trustAllManagers, new java.security.SecureRandom());
            blindFactory = sslContext.getSocketFactory();
        } catch (GeneralSecurityException e) {
            // If SSL context initialisation fails the factory stays null;
            // subsequent createSocket() calls will throw a NullPointerException.
            System.err.println("BlindSSLSocketFactory: failed to initialise SSL context.");
            e.printStackTrace();
        }
    }

    // -------------------------------------------------------------------------
    // Factory accessor (required by JNDI)
    // -------------------------------------------------------------------------

    /**
     * Returns a new {@link BlindSSLSocketFactory} instance.
     *
     * JNDI calls this static method by convention when looking up the socket factory
     * class specified in the {@code java.naming.ldap.factory.socket} environment property.
     *
     * @return a new {@code BlindSSLSocketFactory}
     */
    public static SocketFactory getDefault() {
        return new BlindSSLSocketFactory();
    }

    // -------------------------------------------------------------------------
    // Socket creation — all delegates to the underlying SSL factory
    // -------------------------------------------------------------------------

    /**
     * Creates an SSL socket connected to the named host on the given port.
     *
     * @param host remote hostname
     * @param port remote port
     * @return connected SSL {@link Socket}
     * @throws IOException           if an I/O error occurs during socket creation
     * @throws UnknownHostException  if the host cannot be resolved
     */
    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        return blindFactory.createSocket(host, port);
    }

    /**
     * Creates an SSL socket connected to the given {@link InetAddress} on the given port.
     *
     * @param address remote IP address
     * @param port    remote port
     * @return connected SSL {@link Socket}
     * @throws IOException if an I/O error occurs during socket creation
     */
    @Override
    public Socket createSocket(InetAddress address, int port) throws IOException {
        return blindFactory.createSocket(address, port);
    }

    /**
     * Creates an SSL socket connected to the named remote host/port,
     * bound locally to the specified local address/port.
     *
     * @param host          remote hostname
     * @param port          remote port
     * @param localAddress  local address to bind to
     * @param localPort     local port to bind to
     * @return connected SSL {@link Socket}
     * @throws IOException          if an I/O error occurs during socket creation
     * @throws UnknownHostException if the remote host cannot be resolved
     */
    @Override
    public Socket createSocket(String host, int port, InetAddress localAddress, int localPort)
            throws IOException, UnknownHostException {
        return blindFactory.createSocket(host, port, localAddress, localPort);
    }

    /**
     * Creates an SSL socket connected to the given remote {@link InetAddress}/port,
     * bound locally to the specified local address/port.
     *
     * @param address       remote IP address
     * @param port          remote port
     * @param localAddress  local address to bind to
     * @param localPort     local port to bind to
     * @return connected SSL {@link Socket}
     * @throws IOException if an I/O error occurs during socket creation
     */
    @Override
    public Socket createSocket(InetAddress address, int port,
                               InetAddress localAddress, int localPort) throws IOException {
        return blindFactory.createSocket(address, port, localAddress, localPort);
    }
}
