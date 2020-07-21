package cz.zcu.connectors.kerberos.exceptions;

import org.identityconnectors.framework.common.exceptions.ConnectorException;

public class KerberosException extends ConnectorException {
	private static final long serialVersionUID = 5556264615426604866L;

	public KerberosException(String message) {
		super(message);
	}

	public KerberosException(String message, Throwable throwable) {
		super(message, throwable);
	}
}
