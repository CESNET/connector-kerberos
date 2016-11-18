/*
 * DO NOT REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2016 ForgeRock AS. All rights reserved.
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://opensource.org/licenses/CDDL-1.0
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://opensource.org/licenses/CDDL-1.0
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 */
package cz.zcu;

import org.identityconnectors.common.Assertions;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;


/**
 * Extends the {@link AbstractConfiguration} class to provide all the necessary
 * parameters to initialize the Kerberos Connector.
 */
public class KerberosConfiguration extends AbstractConfiguration {
	// Exposed configuration properties.

	/**
	 * Kerberos realm to work with.
	 */
	private String realm;

	/**
	 * The principal to authenticate with.
	 */
	private String principal = null;

	/**
	 * The keytab to authenticate with.
	 */
	private GuardedString keytab = null;

	/**
	 * Constructor.
	 */
	public KerberosConfiguration() {

	}

	@ConfigurationProperty(order = 1, displayMessageKey = "host.display",
			groupMessageKey = "basic.group", helpMessageKey = "host.help",
			required = true, confidential = false)
	public String getRealm() {
		return realm;
	}

	public void setRealm(String realm) {
		this.realm = realm;
	}

	@ConfigurationProperty(order = 2, displayMessageKey = "remoteUser.display",
			groupMessageKey = "basic.group", helpMessageKey = "remoteUser.help",
			required = true, confidential = false)
	public String getPrincipal() {
		return principal;
	}

	public void setPrincipal(String principal) {
		this.principal = principal;
	}

	@ConfigurationProperty(order = 3, displayMessageKey = "password.display",
			groupMessageKey = "basic.group", helpMessageKey = "password.help",
			confidential = true)
	public GuardedString getKeytab() {
		return keytab;
	}

	public void setKeytab(GuardedString keytab) {
		this.keytab = keytab;
	}

	/**
	 * {@inheritDoc}
	 */
	public void validate() {
		Assertions.nullCheck(keytab, "keytab");
		Assertions.blankCheck(realm, "realm");
		Assertions.blankCheck(principal, "principal");
	}
}
