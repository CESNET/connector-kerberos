package cz.zcu;

/**
 * Created by majlen on 21.11.16.
 */
public class KerberosAdminApp {
	public static void main(String[] args) {
		KerberosConfiguration config = new KerberosConfiguration();
		config.setRealm(args[0]);
		config.setPrincipal(args[1]);
		config.setKeytab(args[2]);

		KerberosConnector connector = new KerberosConnector();
		connector.init(config);
		System.out.println(Long.toHexString(connector.getContextPointer()));
		connector.dispose();
	}
}
