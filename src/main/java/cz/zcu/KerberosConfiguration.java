package cz.zcu;

import org.identityconnectors.common.Assertions;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.common.StringUtil;
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
	private String realm = null;

	/**
	 * The principal to authenticate with.
	 */
	private String principal = null;

	/**
	 * The password to authenticate with.
	 */
	private GuardedString password = null;

	/**
	 * The keytab to authenticate with.
	 */
	private String keytab = null;

	/**
	 * Administrator credentials lifetime (ms).
	 */
	private int lifeTime = 2 * 3600 * 1000;

	/**
	 * Constructor.
	 */
	public KerberosConfiguration() {

	}

	@ConfigurationProperty(order = 1, displayMessageKey = "realm.display",
			groupMessageKey = "basic.group", helpMessageKey = "realm.help",
			required = false, confidential = false)
	public String getRealm() {
		return realm;
	}

	public void setRealm(String realm) {
		this.realm = realm;
	}

	@ConfigurationProperty(order = 2, displayMessageKey = "adminPrincipal.display",
			groupMessageKey = "basic.group", helpMessageKey = "adminPrincipal.help",
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
	public GuardedString getPassword() {
		return password;
	}

	public void setPassword(GuardedString password) {
		this.password = password;
	}

	@ConfigurationProperty(order = 4, displayMessageKey = "keytab.display",
		groupMessageKey = "basic.group", helpMessageKey = "keytab.help",
		confidential = false)
	public String getKeytab() {
		return keytab;
	}

	public void setKeytab(String keytab) {
		this.keytab = keytab;
	}

	@ConfigurationProperty(order = 5, displayMessageKey = "lifetime.display",
		groupMessageKey = "basic.group", helpMessageKey = "lifetime.help",
		required = true, confidential = false)
	public int getLifeTime() {
		return lifeTime;
	}

	public void setLifeTime(int lifetime) {
		this.lifeTime = lifetime;
	}

	/**
	 * {@inheritDoc}
	 */
	public void validate() {
		if (StringUtil.isBlank(keytab) && password == null) {
			throw new IllegalArgumentException("Both password and keytab location cannot be null or empty");
		}
		Assertions.blankCheck(principal, "principal");
	}
}
