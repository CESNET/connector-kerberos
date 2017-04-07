package cz.zcu;

/**
 * Helper object to keep search results.
 */
// keep in sync with java_access.h
public class KerberosSearchResults {
	KerberosPrincipal[] principals;
	int remaining;

	KerberosSearchResults(KerberosPrincipal[] principals, int remaining) {
		this.principals = principals;
		this.remaining = remaining;
	}
}
