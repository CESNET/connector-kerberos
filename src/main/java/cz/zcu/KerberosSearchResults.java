package cz.zcu;

public class KerberosSearchResults {
	KerberosPrincipal[] principals;
	int remaining;

	KerberosSearchResults(KerberosPrincipal[] principals, int remaining) {
		this.principals = principals;
		this.remaining = remaining;
	}
}
