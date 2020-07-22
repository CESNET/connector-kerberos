package cz.zcu.connectors.kerberos;

import java.util.Set;
import org.identityconnectors.framework.common.objects.*;

public class KerberosPrincipal {
	public static final String OBJECT_CLASS_NAME = "principal";
	public static final ObjectClass OBJECT_CLASS = new ObjectClass(OBJECT_CLASS_NAME);

	public static final int MASK_PRINCIPAL         = 0x0001;
	public static final int MASK_PRINC_EXPIRE_TIME = 0x0002;
	public static final int MASK_PW_EXPIRATION     = 0x0004;
	public static final int MASK_LAST_PWD_CHANGE   = 0x0008;
	public static final int MASK_ATTRIBUTES        = 0x0010;
	public static final int MASK_MAX_LIFE          = 0x0020;
	public static final int MASK_POLICY            = 0x0800;
	public static final int MASK_MAX_RLIFE         = 0x2000;
	public static final int MASK_LAST_SUCCESS      = 0x4000;
	public static final int MASK_LAST_FAILED       = 0x8000;

	// principal attributes
	public static final String ATTR_PASSWORD_CHANGE_DATE = "passwordChangeDate";
	public static final String ATTR_LAST_LOGIN_DATE = "lastLoginDate";
	public static final String ATTR_LAST_FAILED_DATE = "lastFailedDate";
	public static final String ATTR_MODIFY_PRINCIPAL = "modifyPrincipal";
	public static final String ATTR_MODIFY_DATE = "modifyDate";
	public static final String ATTR_ATTRIBUTES = "attributes";
	public static final String ATTR_POLICY = "policy";
	public static final String ATTR_MAX_TICKET_LIFE = "maxTicketLife";
	public static final String ATTR_MAX_RENEWABLE_LIFE = "maxRenewableLife";
	// principal attributes - boolean flags
	public static final String ATTR_ALLOW_TIX = "allowTix";
	public static final String ATTR_ALLOW_FORWARDABLE = "allowForwardable";
	public static final String ATTR_ALLOW_RENEWABLE = "allowRenewable";
	public static final String ATTR_REQUIRES_PREAUTH = "requiresPreauth";
	public static final String ATTR_REQUIRES_HWAUTH = "requiresHwauth";
	public static final String ATTR_REQUIRES_PWCHANGE = "requiresPwchange";

	private String name;
	private long princExpiry;
	private long pwdExpiry;
	private long pwdChange;
	private String modifyPrincipal;
	private long modifyDate;
	private KerberosFlags attributes;
	private String policy;
	private long maxTicketLife;
	private long maxRenewableLife;
	private long lastLoginDate;
	private long lastFailedDate;

	private int updateMask;


	/**
	 * Kerberos principal object constructor
	 *
	 * @param name name
	 * @param princExpiry princExpiry attribute
	 * @param pwdExpiry pwdExpiry attribute
	 * @param pwdChange pwdChange attribute
	 * @param modifyPrincipal modifyPrincipal attribute
	 * @param modifyDate modifyDate attribute
	 * @param attributes attributes attribute
	 * @param policy policy attribute
	 * @param maxTicketLife maxTicketLife attribute
	 * @param maxRenewableLife maxRenewableLife attribute
	 * @param lastLoginDate lastLoginDate attribute
	 * @param lastFailedDate lastFailedDate attribute
	 */
	// keep parameters in sync with java_access.h
	public KerberosPrincipal(String name, long princExpiry, long pwdExpiry, long pwdChange, String modifyPrincipal,
	                         long modifyDate, int attributes, String policy, long maxTicketLife, long maxRenewableLife,
	                         long lastLoginDate, long lastFailedDate) {
		this.name = name;
		this.princExpiry = princExpiry;
		this.pwdExpiry = pwdExpiry;
		this.pwdChange = pwdChange;
		this.modifyPrincipal = modifyPrincipal;
		this.modifyDate = modifyDate;
		this.attributes = new KerberosFlags(attributes);
		this.policy = policy;
		this.maxTicketLife = maxTicketLife;
		this.maxRenewableLife = maxRenewableLife;
		this.lastLoginDate = lastLoginDate;
		this.lastFailedDate = lastFailedDate;

		this.updateMask = 0;
	}

	/**
	 * Kerberos principal object constructor
	 *
	 * @param attrs ConnId attributes
	 */
	public KerberosPrincipal(Set<Attribute> attrs) {
		Attribute attr;

		modifyPrincipal = null;
		modifyDate = 0;
		lastLoginDate = 0;
		lastFailedDate = 0;

		attr = AttributeUtil.find(OperationalAttributes.DISABLE_DATE_NAME, attrs);
		princExpiry = 0;
		if (attr != null) {
			princExpiry = AttributeUtil.getLongValue(attr) / 1000;
			updateMask |= KerberosPrincipal.MASK_PRINC_EXPIRE_TIME;
		}

		attr = AttributeUtil.find(OperationalAttributes.PASSWORD_EXPIRATION_DATE_NAME, attrs);
		pwdExpiry = 0;
		if (attr != null) {
			pwdExpiry = AttributeUtil.getLongValue(attr) / 1000;
			updateMask |= KerberosPrincipal.MASK_PW_EXPIRATION;
		}

		attr = AttributeUtil.find(ATTR_ATTRIBUTES, attrs);
		attributes = new KerberosFlags(0);
		if (attr != null) {
			attributes.setAttributes(AttributeUtil.getIntegerValue(attr));
			updateMask |= KerberosPrincipal.MASK_ATTRIBUTES;
		}

		attr = AttributeUtil.find(ATTR_POLICY, attrs);
		policy = null;
		if (attr != null) {
			policy = AttributeUtil.getStringValue(attr);
			updateMask |= KerberosPrincipal.MASK_POLICY;
		}

		attr = AttributeUtil.find(ATTR_MAX_TICKET_LIFE, attrs);
		maxTicketLife = 0;
		if (attr != null) {
			maxTicketLife = AttributeUtil.getLongValue(attr) / 1000;
			updateMask |= KerberosPrincipal.MASK_MAX_LIFE;
		}

		attr = AttributeUtil.find(ATTR_MAX_RENEWABLE_LIFE, attrs);
		maxRenewableLife = 0;
		if (attr != null) {
			maxRenewableLife = AttributeUtil.getLongValue(attr) / 1000;
			updateMask |= KerberosPrincipal.MASK_MAX_RLIFE;
		}
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

	public long getMaxTicketLife() {
		return maxTicketLife;
	}

	public long getMaxRenewableLife() {
		return maxRenewableLife;
	}

	public long getLastLoginDate() {
		return lastLoginDate;
	}

	public long getLastFailedDate() {
		return lastFailedDate;
	}

	/**
	 * Principal status.
	 *
	 * @return true, if enabled
	 */
	public boolean enabled() {
		return attributes.hasAllowTix();
	}

	/**
	 * Get the update mask for JNI library.
	 *
	 * @return Kerberos connector update mask for krb5_modify() native call
	 */
	public int getUpdateMask() {
		return updateMask;
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
			builder.addAttribute(ATTR_PASSWORD_CHANGE_DATE, 1000 * pwdChange);
		builder.addAttribute(ATTR_MODIFY_PRINCIPAL, modifyPrincipal);
		if (modifyDate != 0)
			builder.addAttribute(ATTR_MODIFY_DATE, 1000 * modifyDate);
		builder.addAttribute(ATTR_ATTRIBUTES, attributes.getAttributes());
		builder.addAttribute(ATTR_POLICY, policy);

		builder.addAttribute(ATTR_MAX_TICKET_LIFE, 1000 * maxTicketLife);
		builder.addAttribute(ATTR_MAX_RENEWABLE_LIFE, 1000 * maxRenewableLife);
		if (lastLoginDate != 0)
			builder.addAttribute(ATTR_LAST_LOGIN_DATE, 1000 * lastLoginDate);
		if (lastFailedDate != 0)
			builder.addAttribute(ATTR_LAST_FAILED_DATE, 1000 * lastFailedDate);

		builder.addAttribute(ATTR_ALLOW_TIX, attributes.hasAllowTix());
		builder.addAttribute(ATTR_ALLOW_FORWARDABLE, attributes.hasAllowForwardable());
		builder.addAttribute(ATTR_ALLOW_RENEWABLE, attributes.hasAllowRenewable());
		builder.addAttribute(ATTR_REQUIRES_PREAUTH, attributes.hasRequiresPreauth());
		builder.addAttribute(ATTR_REQUIRES_HWAUTH, attributes.hasRequiresHwauth());
		builder.addAttribute(ATTR_REQUIRES_PWCHANGE, attributes.hasRequiresPwchange());

		return builder.build();
	}
}
