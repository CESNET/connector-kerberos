package cz.zcu;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import cz.zcu.exceptions.KerberosException;

/**
 * Kerberos principal flags.
 */
public class KerberosFlags {
	public static final int KRB5_DISALLOW_POSTDATED   = 0x0001;
	public static final int KRB5_DISALLOW_FORWARDABLE = 0x0002;
	public static final int KRB5_DISALLOW_TGT_BASED   = 0x0004;
	public static final int KRB5_DISALLOW_RENEWABLE   = 0x0008;
	public static final int KRB5_DISALLOW_PROXIABLE   = 0x0010;
	public static final int KRB5_DISALLOW_DUP_SKEY    = 0x0020;
	public static final int KRB5_DISALLOW_ALL_TIX     = 0x0040;
	public static final int KRB5_REQUIRES_PREAUTH     = 0x0080;
	public static final int KRB5_REQUIRES_HWAUTH      = 0x0100;
	public static final int KRB5_REQUIRES_PWCHANGE    = 0x0200;

	private int attributes;

	// principal flag names as presented in schema attributes
	// (keep in sync with computeAttributes())
	private static final String[] flagsArray = {
		"allowTix",
		"allowForwardable",
		"allowRenewable",
		"requiresPreauth",
		"requiresHwauth",
		"requiresPwchange",
	};

	public static final Set<String> flags = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(flagsArray)));

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
		HashSet<String> flags = new HashSet<String>(Arrays.asList(flagsArray));
		flags.retainAll(attributes);

		return flags;
	}

	/**
	 * Modify principal attributes value using a flag name and its value.
	 *
	 *  @param flag principal flag name
	 *  @param value principal flag value
	 *  @param originalAttributes original principal attributes
	 */
	public void setFlag(String flag, boolean value) throws KerberosException {
		int mask;
		boolean set;

		if ("allowTix".equals(flag)) {
			mask = KRB5_DISALLOW_ALL_TIX;
			set = !value;
		} else if ("allowForwardable".equals(flag)) {
			mask = KRB5_DISALLOW_FORWARDABLE;
			set = !value;
		} else if ("allowRenewable".equals(flag)) {
			mask = KRB5_DISALLOW_RENEWABLE;
			set = !value;
		} else if ("requiresPreauth".equals(flag)) {
			mask = KRB5_REQUIRES_PREAUTH;
			set = value;
		} else if ("requiresHwauth".equals(flag)) {
			mask = KRB5_REQUIRES_HWAUTH;
			set = value;
		} else if ("requiresPwchange".equals(flag)) {
			mask = KRB5_REQUIRES_PWCHANGE;
			set = value;
		} else {
			throw new KerberosException("Unknown kerberos principal flag " + flag);
		}

		if (set) attributes = attributes | mask;
		else attributes = attributes & ~mask;
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
	 * Get "allow tix" flag.
	 */
	public boolean hasAllowTix() {
		return (attributes & KerberosFlags.KRB5_DISALLOW_ALL_TIX) == 0;
	}

	/**
	 * Get "allow forwardable" flag.
	 */
	public boolean hasAllowForwardable() {
		return (attributes & KerberosFlags.KRB5_DISALLOW_FORWARDABLE) == 0;
	}

	/**
	 * Get "allow renewable" flag.
	 */
	public boolean hasAllowRenewable() {
		return (attributes & KerberosFlags.KRB5_DISALLOW_RENEWABLE) == 0;
	}

	/**
	 * Get "requires preauth" flag.
	 */
	public boolean hasRequiresPreauth() {
		return (attributes & KerberosFlags.KRB5_REQUIRES_PREAUTH) != 0;
	}

	/**
	 * Get "requires hwauth" flag.
	 */
	public boolean hasRequiresHwauth() {
		return (attributes & KerberosFlags.KRB5_REQUIRES_HWAUTH) != 0;
	}

	/**
	 * Get "requires pwchange" flag.
	 */
	public boolean hasRequiresPwchange() {
		return (attributes & KerberosFlags.KRB5_REQUIRES_PWCHANGE) != 0;
	}
}
