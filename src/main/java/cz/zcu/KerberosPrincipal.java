package cz.zcu;

import org.identityconnectors.framework.common.objects.*;

public class KerberosPrincipal {
	public static final int KRBCONN_PRINCIPAL         = 0x0001;
	public static final int KRBCONN_PRINC_EXPIRE_TIME = 0x0002;
	public static final int KRBCONN_PW_EXPIRATION     = 0x0004;
	public static final int KRBCONN_LAST_PWD_CHANGE   = 0x0008;
	public static final int KRBCONN_ATTRIBUTES        = 0x0010;
	public static final int KRBCONN_POLICY            = 0x0800;

	private String name;
	private long princExpiry;
	private long pwdExpiry;
	private long pwdChange;
	private String modifyPrincipal;
	private long modifyDate;
	private KerberosFlags attributes;
	private String policy;

	public KerberosPrincipal(String name, long princExpiry, long pwdExpiry, long pwdChange, String modifyPrincipal,
	                         long modifyDate, int attributes, String policy) {
		this.name = name;
		this.princExpiry = princExpiry;
		this.pwdExpiry = pwdExpiry;
		this.pwdChange = pwdChange;
		this.modifyPrincipal = modifyPrincipal;
		this.modifyDate = modifyDate;
		this.attributes = new KerberosFlags(attributes);
		this.policy = policy;
	}

	public String getName() {
		return name;
	}

	public long getPrincExpiry() {
		return princExpiry;
	}

	public long getPwdExpiry() {
		return pwdExpiry;
	}

	public long getPwdChange() {
		return pwdChange;
	}

	public String getModifyPrincipal() {
		return modifyPrincipal;
	}

	public long getModifyDate() {
		return modifyDate;
	}

	public KerberosFlags getAttributes() {
		return attributes;
	}

	public String getPolicy() {
		return policy;
	}

	/**
	 * Principal status.
	 *
	 * @return true, if enabled
	 */
	public boolean enabled() {
		return attributes.hasAllowTix();
	}

	public ConnectorObject toConnectorObject() {
		ConnectorObjectBuilder builder = new ConnectorObjectBuilder();

		builder.setUid(name);
		builder.setName(name);
		builder.addAttribute(OperationalAttributes.ENABLE_NAME, enabled());
		if (pwdExpiry != 0)
			builder.addAttribute(OperationalAttributes.PASSWORD_EXPIRATION_DATE_NAME, 1000 * pwdExpiry);
		if (princExpiry != 0)
			builder.addAttribute(OperationalAttributes.DISABLE_DATE_NAME, 1000 * princExpiry);
		if (pwdChange != 0)
			builder.addAttribute("passwordChangeDate", 1000 * pwdChange);
		builder.addAttribute("modifyPrincipal", modifyPrincipal);
		if (modifyDate != 0)
			builder.addAttribute("modifyDate", 1000 * modifyDate);
		builder.addAttribute("attributes", attributes.getAttributes());
		builder.addAttribute("policy", policy);

		builder.addAttribute("allowTix", attributes.hasAllowTix());
		builder.addAttribute("allowForwardable", attributes.hasAllowForwardable());
		builder.addAttribute("allowRenewable", attributes.hasAllowRenewable());
		builder.addAttribute("requiresPreauth", attributes.hasRequiresPreauth());
		builder.addAttribute("requiresHwauth", attributes.hasRequiresHwauth());
		builder.addAttribute("requiresPwchange", attributes.hasRequiresPwchange());

		return builder.build();
	}
}
