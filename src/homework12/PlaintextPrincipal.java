package homework12;

import java.security.Principal;

/**
 * 
 * Adapted from examples in 
 *   https://docs.oracle.com/javase/7/docs/technotes/guides/security/jaas/tutorials/GeneralAcnOnly.html
 *   
 * This class represents an authenticated user.
 *
 * Principals may be associated with a particular Subject to augment that Subject with an additional identity. 
 * Authorization decisions can then be based upon the Principals associated with a Subject.
 * 
 */
public class PlaintextPrincipal implements Principal, java.io.Serializable {
 
	private static final long serialVersionUID = 6145452948223806256L;
 
    private String name;

    /**
     * Create a Principal with a username.
     */
    public PlaintextPrincipal(String name) {
        if (name == null)
            throw new NullPointerException("illegal null input");

        this.name = name;
    }

    /**
     * Return the username for this Principal 
     */
    public String getName() {
        return name;
    }

    /**
     * Return a string representation of this Principal 
     */
    public String toString() {
        return("PlaintextPrincipal:  " + name);
    }

    /**
     * Compares this Principal with the argument based on Principal's name
     */
    public boolean equals(Object o) {
    	boolean ret = false;

    	if (o != null && this != o && o instanceof PlaintextPrincipal) { 
    		PlaintextPrincipal that = (PlaintextPrincipal) o;

    		ret = this.getName().equals(that.getName());
    	}
    	return ret;
    }

    /**
     * Return a hash code for this Principal
     */
    public int hashCode() {
        return name.hashCode();
    }
}