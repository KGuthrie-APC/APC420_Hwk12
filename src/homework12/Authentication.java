package homework12;

 
import java.security.PrivilegedAction;
import java.util.*;
import javax.security.auth.login.*;
import javax.security.auth.Subject; 

/**
 * Adapted from examples in 
 *   https://docs.oracle.com/javase/7/docs/technotes/guides/security/jaas/tutorials/GeneralAcnOnly.html
 *   
 * This application attempts to authenticate a user using one of two approaches:
 * 	 1. check stored user name and password
 *   2. use a Kerberos server (through Apache Kerby)
 */
public class Authentication {

	/*
	 * Set system properties for JAAS configuration file location, Kerberos realm and KDC server.
	 */
	static void setProperties() { 
		// TODO
		System.setProperty("java.security.krb5.realm", "CS.UWM.EDU");
		System.setProperty("java.security.krb5.kdc", "localhost");
		
		System.setProperty("java.security.auth.login.config","src/homework12/jaas.config");
		
	}
	
	/*
	 * Return an instance of LoginContext needed for authentication by passing 
	 *    1. the variable 'contextName' (i.e. kerberos or plaintext), 
	 *          which specifies the LoginModule implementation in the JAAS login configuration file and 
	 *    2. an instance of PlaintextCallbackHandler. 
	 * 
	 * Catch any LoginException and SecurityException and take the following actions:
	 *    1. print error message "Cannot create LoginContext"
	 *    2. exit the program using System.exit
	 */
	static LoginContext getLoginContext(String contextName) {
		// TODO
		LoginContext lc = null;
		try {
			return lc = new LoginContext(contextName, new PlaintextCallbackHandler());
		} catch (LoginException | SecurityException e) {
			System.err.println("Cannot create LoginContext. " + e.getMessage());
			System.exit(-1);
		}
	return null;
	}
	
	/*
	 * 1. login using the provided LoginContext object
	 * 
	 * 2. print out the principal(s) associated with the subject afterwards
	 * 
	 * 3. logout
	 * 
	 * Note that login failure will throw a LoginException so this method does not need to consider that.
	 */
	static void attemptLogin(LoginContext lc) throws LoginException {
		// TODO
		try {
			lc.login();
		} catch (LoginException e) {
			System.err.println("Authentaction Failed. " + e.getMessage());
			System.exit(-1);
		}
		Subject sub = lc.getSubject();

		System.out.println("Principals [" + sub.getPrincipals().iterator().next()+ "] have logged in");
		
		lc.logout();
	}
	
	/**
	 * Attempt to authenticate the user.
	 *
	 * Prompt user to select kerberos or plaintext authentication method
	 *
	 * Provide 3 attempts to login (sleep 3 seconds after each failed attempt)
	 *
	 * If login successfully, print the principals of the authenticated subject and then logout
	 */
	public static void main(String[] args) { 
		String choice = "";
		
		while(!choice.equals("kerberos") && !choice.equals("plaintext")) {
			System.out.println("Please select login method: kerberos or plaintext");
			choice = new Scanner(System.in).nextLine();
		} 
		  
		setProperties();
		LoginContext lc = getLoginContext(choice); 
		
		// the user has 3 attempts to authenticate successfully
		int i;
		for (i = 0; i < 3; i++) {
			try {
				attemptLogin(lc);
				// if we return with no exception, authentication succeeded
				break;

			} catch (LoginException le) {
				System.err.println("Authentication failed:");
				System.err.println("  " + le.getMessage());
				try {
					Thread.sleep(3000);
				} catch (Exception e) {
					// ignore
				}
			}
		}

		// did they fail three times?
		if (i == 3) {
			System.out.println("Sorry");
			System.exit(-1);
		}

		System.out.println("Authentication succeeded!");
	}
}


