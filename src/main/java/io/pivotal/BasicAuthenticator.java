package io.pivotal;

import java.io.Serializable;
import java.security.Principal;
import java.util.Properties;

import com.gemstone.gemfire.LogWriter;
import com.gemstone.gemfire.distributed.DistributedMember;
import com.gemstone.gemfire.security.AuthenticationFailedException;
import com.gemstone.gemfire.security.Authenticator;

public class BasicAuthenticator implements Authenticator {
	private String systemUsername;
	private String systemPassword;
	private LogWriter logger;

	public static Authenticator create() {
		return new BasicAuthenticator();
	}

	public void init(Properties properties, LogWriter logWriter,
	        LogWriter logWriter2) throws AuthenticationFailedException {
		logger = logWriter;
		systemUsername = System.getProperty("security-username");
		systemPassword = System.getProperty("security-password");
	}

	public Principal authenticate(Properties properties,
	        DistributedMember distributedMember)
	        throws AuthenticationFailedException {
		String givenUsername = properties.getProperty("security-username");
		String givenPassword = properties.getProperty("security-password");

		logger.fine("Authenticating against " + givenUsername + "/"
		        + givenPassword);

		if (!(systemUsername.equals(givenUsername) && systemPassword
		        .equals(givenPassword))) {
			throw new AuthenticationFailedException(
			        "Invalid username/password combination given");
		}

		return new BasicPrincipal(givenUsername);
	}

	public void close() {
	}

	public class BasicPrincipal implements Principal, Serializable {

		private final String username;

		public BasicPrincipal(final String username) {
			this.username = username;
		}

		public String getName() {
			return username;
		}

		@Override
		public String toString() {
			return new String("BasicPrincipal[username=" + username);
		}
	}
}
