import java.util.Hashtable;
import java.util.Iterator;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

/**
 * TestSASLConnection
 *
 * A command-line utility for verifying SASL/SSL authentication against an LDAP server.
 * Establishes a connection using JNDI, reports environment details, and prints timing metrics.
 *
 * Usage: java TestSASLConnection <userdn> <password> <provider_url>
 *   userdn       – Fully qualified DN of the authenticating user
 *                  (e.g. "uid=john,ou=people,dc=example,dc=com")
 *   password     – Credential for the DN above
 *   provider_url – LDAP URL including host and port
 *                  (e.g. "ldap://ldap.example.com:389")
 *
 * @author Nirenj George
 */
public class TestSASLConnection {

    // -------------------------------------------------------------------------
    // LDAP connection-pool tuning constants
    // -------------------------------------------------------------------------

    /** Minimum number of connections kept alive in the pool. */
    private static final String POOL_INIT_SIZE = "5";

    /** Maximum number of connections the pool may grow to. */
    private static final String POOL_MAX_SIZE  = "50";

    // -------------------------------------------------------------------------
    // Entry point
    // -------------------------------------------------------------------------

    /**
     * Authenticates against an LDAP server and prints the resulting context environment.
     *
     * @param args [0] userdn, [1] password, [2] provider URL
     */
    public static void main(String[] args) {

        // Record the wall-clock start time so we can report total authentication latency.
        long startTime = System.currentTimeMillis();

        if (args.length < 3) {
            System.err.println("Usage: java TestSASLConnection <userdn> <password> <provider_url>");
            return;
        }

        String userDn      = args[0];
        String password    = args[1];
        String providerUrl = args[2];

        // Build the JNDI environment properties for the LDAP connection.
        Hashtable<String, String> env = buildEnvironment(userDn, password, providerUrl);

        DirContext ctx = null;

        try {
            // Open the LDAP directory context — this is where authentication happens.
            ctx = new InitialDirContext(env);

            long elapsed = System.currentTimeMillis() - startTime;

            // Print basic context information.
            System.out.println("ctx.getNameInNamespace: " + ctx.getNameInNamespace());
            System.out.println("getEnvironment.size():  " + ctx.getEnvironment().size());

            // Dump every key/value pair from the active context environment for inspection.
            Hashtable<?, ?> ctxEnv = ctx.getEnvironment();
            for (Iterator<?> it = ctxEnv.keySet().iterator(); it.hasNext();) {
                String key = (String) it.next();
                System.out.println("getEnvironment(" + key + "): " + ctxEnv.get(key));
            }

            System.out.println("Successfully authenticated DN: " + userDn
                    + " | elapsed = " + elapsed + " ms");

        } catch (NamingException e) {
            long elapsed = System.currentTimeMillis() - startTime;
            System.out.println("Authentication failed (NamingException) for DN: " + userDn
                    + " | elapsed = " + elapsed + " ms");
            System.out.println("Message:     " + e.getMessage());
            System.out.println("Explanation: " + e.getExplanation());
            e.printStackTrace();

        } catch (Exception e) {
            long elapsed = System.currentTimeMillis() - startTime;
            System.out.println("Authentication failed (Exception) for DN: " + userDn
                    + " | elapsed = " + elapsed + " ms");
            System.out.println("Message: " + e.getMessage());
            e.printStackTrace();

        } finally {
            // Always release the directory context to return connections to the pool.
            if (ctx != null) {
                try {
                    ctx.close();
                    System.out.println("Directory context closed.");
                } catch (NamingException e) {
                    System.err.println("Failed to close directory context: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Builds the JNDI environment {@link Hashtable} used to configure the LDAP connection.
     *
     * Key settings applied here:
     *   Sun LDAP context factory
     *   Connection pooling (init = {@value #POOL_INIT_SIZE}, max = {@value #POOL_MAX_SIZE})
     *   {@link BlindSSLSocketFactory} as the socket factory (bypasses certificate validation)
     *   Simple authentication over SSL
     *
     * @param userDn      Fully qualified DN of the authenticating principal
     * @param password    Credential for the principal
     * @param providerUrl LDAP provider URL (must use a fully qualified hostname)
     * @return Populated environment hashtable ready for {@link InitialDirContext}
     */
    private static Hashtable<String, String> buildEnvironment(
            String userDn, String password, String providerUrl) {

        Hashtable<String, String> env = new Hashtable<>(16);

        // LDAP context factory provided by the JDK.
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

        // Provider URL must use a fully qualified hostname for SSL to work correctly.
        env.put(Context.PROVIDER_URL, providerUrl);

        // Enable LDAP connection pooling and set debug level to "fine" for verbose pool logging.
        env.put("com.sun.jndi.ldap.connect.pool",          "TRUE");
        env.put("com.sun.jndi.ldap.connect.pool.debug",    "fine");
        env.put("com.sun.jndi.ldap.connect.pool.initsize", POOL_INIT_SIZE);
        env.put("com.sun.jndi.ldap.connect.pool.maxsize",  POOL_MAX_SIZE);

        // Use BlindSSLSocketFactory so the connection succeeds even with self-signed certs.
        // WARNING: This disables certificate validation and should only be used for testing.
        env.put("java.naming.ldap.factory.socket", BlindSSLSocketFactory.class.getName());

        // Authenticate with a plain username/password pair ("simple") over an SSL channel.
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PROTOCOL,       "ssl");
        env.put(Context.SECURITY_PRINCIPAL,      userDn);
        env.put(Context.SECURITY_CREDENTIALS,    password);

        return env;
    }
}
