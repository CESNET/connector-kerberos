package cz.zcu;

import org.identityconnectors.framework.common.objects.*;

/**
 * Created by majlen on 22.11.16.
 */
public class KerberosPrincipal {
	private String name;
	private long princExpiry;
	private long pwdExpiry;
	private long pwdChange;
	private String modifyPrincipal;
	private long modifyDate;
	private int attributes;
	private String policy;

	public KerberosPrincipal(String name, long princExpiry, long pwdExpiry, long pwdChange, String modifyPrincipal,
	                         long modifyDate, int attributes, String policy) {
		this.name = name;
		this.princExpiry = princExpiry;
		this.pwdExpiry = pwdExpiry;
		this.pwdChange = pwdChange;
		this.modifyPrincipal = modifyPrincipal;
		this.modifyDate = modifyDate;
		this.attributes = attributes;
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

	public int getAttributes() {
		return attributes;
	}

	public String getPolicy() {
		return policy;
	}

	public ConnectorObject toConnectorObject() {
		ConnectorObjectBuilder builder = new ConnectorObjectBuilder();

		builder.setUid(name);
		builder.setName(name);
		builder.addAttribute(OperationalAttributes.PASSWORD_EXPIRATION_DATE_NAME, pwdExpiry);
		builder.addAttribute(OperationalAttributes.DISABLE_DATE_NAME, princExpiry);
		builder.addAttribute("passwordChangeDate", pwdChange);
		builder.addAttribute("modifyPrincipal", modifyPrincipal);
		builder.addAttribute("modifyDate", modifyDate);
		builder.addAttribute("attributes", attributes);
		builder.addAttribute("policy", policy);

		return builder.build();
	}
}
