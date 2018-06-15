import java.util.Hashtable;
import java.util.Iterator;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
/**
 * @author Nirenj George
 */
public class TestSASLConnection
{
	public static void main(String[] str)
	{
		long start = System.currentTimeMillis();
		long end = 0;
		long time = 0;
		String userdn 	= str[0];
        String password = str[1];
		Hashtable env = new Hashtable(11);
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

		// Must use fully qualified hostname
		env.put(Context.PROVIDER_URL, str[2]);
		env.put("com.sun.jndi.ldap.connect.pool", "TRUE");
		env.put("com.sun.jndi.ldap.connect.pool.debug", "fine");
		env.put("com.sun.jndi.ldap.connect.pool.initsize", "5");
		env.put("com.sun.jndi.ldap.connect.pool.maxsize", "50");
		env.put("java.naming.ldap.factory.socket", BlindSSLSocketFactory.class.getName());

		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.SECURITY_PROTOCOL, "ssl");
		env.put(Context.SECURITY_PRINCIPAL, userdn);
		env.put(Context.SECURITY_CREDENTIALS, password);
		
		DirContext ctx = null;

		try
		{
			/* Create initial context */
			ctx = new InitialDirContext(env);
			end = System.currentTimeMillis();
			time = end - start;

			// do something useful with ctx
			System.out.println("ctx.getNameInNamespace: " + ctx.getNameInNamespace());	
			System.out.println("getEnvironment.size(): " + ctx.getEnvironment().size());
			Hashtable ctxMap = ctx.getEnvironment();

			for (Iterator it = ctxMap.keySet().iterator(); it.hasNext();)
			{
				String key = (String) it.next();
				System.out.println("getEnvironment(" + key + "): " + ctxMap.get(key));
			}

			// Close the context when we're done
			System.out.println("setLoginMessage: successfully authenticate DN: " + userdn + ", authentication takes = " + time + " millis.");
		}
		catch (NamingException e)
		{
			end = System.currentTimeMillis();
			time = end - start;
			System.out.println("LoginMessage: fail authenticate DN (NamingException): " + userdn + ", authentication takes = " + time + " millis.");
			System.out.println("LoginMessage: " + e.getMessage());
			System.out.println("Explanation: " + e.getExplanation());
			e.printStackTrace();
			return;
		}
		catch (Exception e1)
		{
			end = System.currentTimeMillis();
			time = end - start;
			System.out.println("LoginMessage: fail authenticate DN (Exception): " + userdn + ", authentication takes = " + time + " millis.");
			System.out.println("LoginMessage: " + e1.getMessage());
			e1.printStackTrace();
		}
		finally
		{
			try
			{
				ctx.close();
				System.out.println("Closed.");
			}
			catch (NamingException e1)
			{
				e1.printStackTrace();
			}
		}
	}
}
