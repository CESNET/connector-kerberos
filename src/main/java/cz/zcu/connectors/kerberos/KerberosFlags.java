package cz.zcu.connectors.kerberos;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import cz.zcu.connectors.kerberos.exceptions.KerberosException;

/**
 * Kerberos principal flags.
 */
public class KerberosFlags {
	public static final int MASK_DISALLOW_POSTDATED   = 0x0001;
	public static final int MASK_DISALLOW_FORWARDABLE = 0x0002;
	public static final int MASK_DISALLOW_TGT_BASED   = 0x0004;
	public static final int MASK_DISALLOW_RENEWABLE   = 0x0008;
	public static final int MASK_DISALLOW_PROXIABLE   = 0x0010;
	public static final int MASK_DISALLOW_DUP_SKEY    = 0x0020;
	public static final int MASK_DISALLOW_ALL_TIX     = 0x0040;
	public static final int MASK_REQUIRES_PREAUTH     = 0x0080;
	public static final int MASK_REQUIRES_HWAUTH      = 0x0100;
	public static final int MASK_REQUIRES_PWCHANGE    = 0x0200;

	private int attributes;

	// principal flag names as presented in schema attributes
	// (keep in sync with computeAttributes())
	private static final String[] FLAGS_ARRAY = {
		KerberosPrincipal.ATTR_ALLOW_TIX,
		KerberosPrincipal.ATTR_ALLOW_FORWARDABLE,
		KerberosPrincipal.ATTR_ALLOW_RENEWABLE,
		KerberosPrincipal.ATTR_REQUIRES_PREAUTH,
		KerberosPrincipal.ATTR_REQUIRES_HWAUTH,
		KerberosPrincipal.ATTR_REQUIRES_PWCHANGE,
	};

	public static final Set<String> FLAGS = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(FLAGS_ARRAY)));

	public KerberosFlags(int attributes) {
		this.attributes = attributes;
	}

	/**
	 * Select a subset of principal attributes - flag attributes.
	 *
	 * @param attributes attributes to get flags from
	 * @return flag attributes subset
	 */
	public static Set<String> selectFlagAttributes(Set<String> attributes) {
		HashSet<String> flags = new HashSet<String>(Arrays.asList(FLAGS_ARRAY));
		flags.retainAll(attributes);

		return flags;
	}

	/**
	 * Modify principal attributes value using a flag name and its value.
	 *
	 *  @param flag principal flag name
	 *  @param value principal flag value
	 */
	public void setFlag(String flag, boolean value) throws KerberosException {
		int mask;
		boolean set;

		switch(flag) {
		case KerberosPrincipal.ATTR_ALLOW_TIX:
			mask = MASK_DISALLOW_ALL_TIX;
			set = !value;
			break;
		case KerberosPrincipal.ATTR_ALLOW_FORWARDABLE:
			mask = MASK_DISALLOW_FORWARDABLE;
			set = !value;
			break;
		case KerberosPrincipal.ATTR_ALLOW_RENEWABLE:
			mask = MASK_DISALLOW_RENEWABLE;
			set = !value;
			break;
		case KerberosPrincipal.ATTR_REQUIRES_PREAUTH:
			mask = MASK_REQUIRES_PREAUTH;
			set = value;
			break;
		case KerberosPrincipal.ATTR_REQUIRES_HWAUTH:
			mask = MASK_REQUIRES_HWAUTH;
			set = value;
			break;
		case KerberosPrincipal.ATTR_REQUIRES_PWCHANGE:
			mask = MASK_REQUIRES_PWCHANGE;
			set = value;
			break;
		default:
			throw new KerberosException("Unknown kerberos principal flag " + flag);
		}

		if (set)
				attributes = attributes | mask;
		else
				attributes = attributes & ~mask;
	}

	/**
	 * Set all principal flags using integer mask.
	 *
	 * @return current principal attributes mask
	 */
	public int getAttributes() {
		return attributes;
	}

	/**
	 * Set all principal flags using integer mask.
	 *
	 * @param attributes principal attributes mask
	 */
	public void setAttributes(int attributes) {
		this.attributes = attributes;
	}

	/**
	 * Get "allow tix" flag
	 *
	 * @return allowTix flag
	 */
	public boolean hasAllowTix() {
		return (attributes & KerberosFlags.MASK_DISALLOW_ALL_TIX) == 0;
	}

	/**
	 * Get "allow forwardable" flag.
	 *
	 * @return allowForwardable flag
	 */
	public boolean hasAllowForwardable() {
		return (attributes & KerberosFlags.MASK_DISALLOW_FORWARDABLE) == 0;
	}

	/**
	 * Get "allow renewable" flag.
	 *
	 * @return allowRenewable flag
	 */
	public boolean hasAllowRenewable() {
		return (attributes & KerberosFlags.MASK_DISALLOW_RENEWABLE) == 0;
	}

	/**
	 * Get "requires preauth" flag.
	 *
	 * @return requiresPreauth flag
	 */
	public boolean hasRequiresPreauth() {
		return (attributes & KerberosFlags.MASK_REQUIRES_PREAUTH) != 0;
	}

	/**
	 * Get "requires hwauth" flag.
	 *
	 * @return requiresHwauth flag
	 */
	public boolean hasRequiresHwauth() {
		return (attributes & KerberosFlags.MASK_REQUIRES_HWAUTH) != 0;
	}

	/**
	 * Get "requires pwchange" flag.
	 *
	 * @return requiresPwchange flag
	 */
	public boolean hasRequiresPwchange() {
		return (attributes & KerberosFlags.MASK_REQUIRES_PWCHANGE) != 0;
	}
}
