package homework12;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class LoginUtil {

	// generate the hash digest for the username and password pair to be used in the login module
	public static void main(String[] args) throws Exception {
		getDigest("alice", "Alice's password");
		getDigest("bob/SERVICE", "Bob's password");
	}
	
	static void getDigest(String username, String password) throws Exception {
		String digest = getDigest((username + password).getBytes());
		System.out.printf("The digest of \"%s\" and \"%s\" is %s\n", username, password, digest);
	}
	
	static String getDigest(byte[] bytes) throws NoSuchAlgorithmException { 
		MessageDigest d = MessageDigest.getInstance("SHA-256"); 
		d.update(bytes);
		String  digest = Base64.getEncoder().encodeToString(d.digest());
		
		return digest;
	}
	static byte[] toBytes(char[] chars) {
	    CharBuffer charBuffer = CharBuffer.wrap(chars);
	    ByteBuffer byteBuffer = Charset.forName("UTF-8").encode(charBuffer);
	    byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
	            byteBuffer.position(), byteBuffer.limit());
	    Arrays.fill(charBuffer.array(), '\u0000'); // clear sensitive data
	    Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
	    return bytes;
	}

}
