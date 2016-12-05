package cz.zcu.exceptions;

import org.identityconnectors.framework.common.exceptions.ConnectorException;

public class KerberosException extends ConnectorException {
	public KerberosException(String message) {
		super(message);
	}

	public KerberosException(String message, Throwable throwable) {
		super(message, throwable);
	}
}
