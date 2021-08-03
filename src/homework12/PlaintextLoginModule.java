package homework12;
 
 
import java.security.NoSuchAlgorithmException;
import java.util.*; 
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import javax.security.auth.spi.*; 

/**
 * 
 * Adapted from examples in 
 * https://docs.oracle.com/javase/7/docs/technotes/guides/security/jaas/tutorials/GeneralAcnOnly.html
 * This LoginModule authenticates users with a username/password pair by compare its hash digest with the stored digest
 *
 * This LoginModule only recognizes one user: "alice"
 * testUser's password is: "Alice's password"
 *
 * If testUser successfully authenticates itself,
 * a PlaintextPrincipal with the testUser's user name is added to the Subject.
 *
 * This LoginModule recognizes the debug option.
 * If set to true in the login Configuration, debug messages will be output to the output stream, System.out.
 *
 */
public class PlaintextLoginModule implements LoginModule {
   // initial state
   private Subject subject;
   private CallbackHandler callbackHandler; 

   // configurable option
   private boolean debug = false;

   // the authentication status
   private boolean succeeded = false;
   private boolean commitSucceeded = false;

   // username and password
   private String username; 

   // testUser's SamplePrincipal
   private PlaintextPrincipal userPrincipal;

   /**
    * Initialize this LoginModule
    *
    * @param subject the Subject to be authenticated.
    *
    * @param callbackHandler a CallbackHandler for communicating with the end user 
    *                       (prompting for user names and passwords, for example).
    *
    * @param sharedState and options are not used here but useful when multiple login modules are used
    */
   public void initialize(Subject subject,
                  CallbackHandler callbackHandler,
                        Map<java.lang.String, ?> sharedState,
                        Map<java.lang.String, ?> options) {

       this.subject = subject;
       this.callbackHandler = callbackHandler; 

       // initialize any configured options
       debug = "true".equalsIgnoreCase((String)options.get("debug"));
   }

   /*
    * Check username and password to see whether they match known username/password by comparing their digests
    * There are two users: alice and bob/SERVICE.
    * 1. Run LoginUtil class to generate the digest of 
    *         'alice' concatenated with her password 
    *         'bob/SERVICE' concatenated with his password
    * 2. In this method, 
    *    a) compute the digest of 'usernameAndPassword' (you can call a method in LoginUtil class)
    *    b) use the 'username' variable to decide which one of the two digests to compare to.
    *    c) return whether the digests match
    */
   private boolean checkPassword(String username, byte[] usernameAndPassword) throws NoSuchAlgorithmException {
	   // TODO
//	   LoginUtil logUtil = new LoginUtil();
	   String alicePW = LoginUtil.getDigest(("aliceAlice's Password").getBytes());
	   String bobPW = LoginUtil.getDigest(("bob/SERVICEBob's Password").getBytes());
	   
	   switch(username) {
	   case("alice"):
		   if(LoginUtil.getDigest(usernameAndPassword).contentEquals(alicePW)) return true;
	   		break;
	   case("bob/SERVICE"):
		   if(LoginUtil.getDigest(usernameAndPassword).contentEquals(bobPW)) return true;
  		break;
	   }

	   return false;
   }
   
   /**
    * Authenticate the user by prompting for a user name and password.
    */
   public boolean login() throws LoginException {

       // prompt for a user name and password
       if (callbackHandler == null)
           throw new LoginException("Error: no CallbackHandler available to garner authentication information from the user");

       Callback[] callbacks = new Callback[2];
       callbacks[0] = new NameCallback("user name: ");
       callbacks[1] = new PasswordCallback("password: ", false);

       try {
           callbackHandler.handle(callbacks);
           username = ((NameCallback) callbacks[0]).getName();
           char[] tmpPassword = ((PasswordCallback) callbacks[1]).getPassword();
           if (tmpPassword == null) {
               // treat a NULL password as an empty password
               tmpPassword = new char[0];
           }
           // print debugging information
           if (debug) {
               System.out.println("\t\t[PlaintextLoginModule] user entered user name: " + username);
               System.out.print("\t\t[PlaintextLoginModule] user entered password: ");
               for (int i = 0; i < tmpPassword.length; i++)
                   System.out.print(tmpPassword[i]);
               System.out.println();
           }
            
           byte[] password = new byte[username.length() + tmpPassword.length];
           System.arraycopy(username.getBytes(), 0, password, 0, username.length());
           System.arraycopy(LoginUtil.toBytes(tmpPassword), 0, password, username.length(), tmpPassword.length);

           ((PasswordCallback) callbacks[1]).clearPassword(); 
           
           boolean passwordCorrect = false;
           
           try {
        	   passwordCorrect = checkPassword(username, password);
           } 
           catch(NoSuchAlgorithmException e) { 
        	   throw new FailedLoginException("no suitable hash algorithm: " + e.getMessage());
           }
           if (passwordCorrect) {
               // authentication succeeded!!! 
               if (debug)
                   System.out.println("\t\t[PlaintextLoginModule] authentication succeeded");
               succeeded = true;
               return true;
           } 
           else {
               // authentication failed -- clean out state
               if (debug)
                   System.out.println("\t\t[PlaintextLoginModule] authentication failed");
               succeeded = false;
               username = null;
               for (int i = 0; i < password.length; i++)
                   password[i] = 0;
               password = null;
                
               throw new FailedLoginException("User Name or Password Incorrect"); 
           } 
       } 
       catch (java.io.IOException ioe) {
           throw new LoginException(ioe.toString());
       } 
       catch (UnsupportedCallbackException uce) {
           throw new LoginException("Error: " + uce.getCallback().toString() +
               " not available to garner authentication information from the user");
       }
   }

   /**
    * This method is called if the LoginContext's overall authentication succeeded
    * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL LoginModules succeeded).
    *
    * If this LoginModule's own authentication attempt succeeded (checked by retrieving the private state saved by the
    * login method), then this method associates a Principal with the Subject located in the LoginModule.  
    * If this LoginModule's own authentication attempted failed, then this method removes any state that was originally saved. 
    */
   public boolean commit() throws LoginException {
       if (succeeded == false) {
           return false;
       } else {
           // add a Principal (authenticated identity)
           // to the Subject

           // assume the user we authenticated is the SamplePrincipal
           userPrincipal = new PlaintextPrincipal(username);
           if (!subject.getPrincipals().contains(userPrincipal))
               subject.getPrincipals().add(userPrincipal);

           if (debug) {
               System.out.println("\t\t[PlaintextLoginModule] added PlaintextPrincipal to Subject");
           }

           // in any case, clean out state
           username = null; 

           commitSucceeded = true;
           return true;
       }
   }

   /**
    * This method is called if the LoginContext's overall authentication failed.
    * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL LoginModules did not succeed).
    *
    * If this LoginModule's own authentication attempt succeeded 
    * (checked by retrieving the private state saved by the login and commit methods),
    * then this method cleans up any state that was originally saved. 
    */
   public boolean abort() throws LoginException {
       if (succeeded == false) {
           return false;
       } else if (succeeded == true && commitSucceeded == false) {
           // login succeeded but overall authentication failed
           succeeded = false;
           username = null; 
           userPrincipal = null;
       } else {
           // overall authentication succeeded and commit succeeded,
           // but someone else's commit failed
           logout();
       }
       return true;
   }

   /**
    * Logout the user.
    *
    * This method removes the Principal that was added by the commit method. 
    */
   public boolean logout() throws LoginException {

       subject.getPrincipals().remove(userPrincipal);
       succeeded = false;
       succeeded = commitSucceeded;
       username = null; 
       userPrincipal = null;
       return true;
   }
}
