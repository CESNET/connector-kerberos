package cz.zcu;

import org.apache.commons.cli.*;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.*;

import java.util.HashMap;
import java.util.Map;


public class KerberosAdminApp {
	public static void usage(Options options) {
		System.out.println("KerberosAdminApp [OPTIONS]");
		System.out.println("OPTIONS are:");
		System.out.println("  -h, --help ...... " + options.getOption("h").getDescription());
		System.out.println("  -k, --keytab .... " + options.getOption("k").getDescription());
		System.out.println("  -r, --realm ..... " + options.getOption("r").getDescription());
		System.out.println("  -u, --user ...... " + options.getOption("u").getDescription());
		System.out.println("  -p, --password .. " + options.getOption("p").getDescription());
	}

	public static void main(String[] args) {
		KerberosConfiguration config = new KerberosConfiguration();
		CommandLineParser parser = new DefaultParser();
		Options options = new Options();

		options.addOption("h", "help", false, "usage message");
		options.addOption("k", "keytab", true, "admin keytab");
		options.addOption("r", "realm", true, "kerberos realm");
		options.addOption("u", "user", true, "admin principal");
		options.addOption("p", "password", true, "admin password");

		try {
			CommandLine line = parser.parse(options, args);

			if(line.hasOption("h")) {
				usage(options);
				return;
			}
			if(line.hasOption("k")) {
				config.setKeytab(line.getOptionValue("k"));
				System.out.println("Keytab: " + config.getKeytab());
			}
			if(line.hasOption("r")) {
				config.setRealm(line.getOptionValue("r"));
				System.out.println("Realm: " + config.getRealm());
			}
			if(line.hasOption("u")) {
				config.setPrincipal(line.getOptionValue("u"));
				System.out.println("Principal: " + config.getPrincipal());
			}
			if(line.hasOption("p")) {
				config.setPassword(new GuardedString(line.getOptionValue("p").toCharArray()));
				System.out.println("Password: (specified)");
			}
		}
		catch(ParseException exp) {
			System.out.println("Invalid arguments: " + exp.getMessage());
			return;
		}

		KerberosConnector connector = new KerberosConnector();
		connector.init(config);
		System.out.println(Long.toHexString(connector.getContextPointer()));

		Map<String, Object> opts = new HashMap<String, Object>();
		opts.put(OperationOptions.OP_PAGE_SIZE, 20);
		opts.put(OperationOptions.OP_PAGED_RESULTS_OFFSET, 81);

		OperationOptions op = new OperationOptions(opts);

		connector.executeQuery(null, null, new PrintResultsHandler(), op);

		opts.remove(OperationOptions.OP_PAGED_RESULTS_OFFSET);
		opts.put(OperationOptions.OP_PAGED_RESULTS_OFFSET, 101);
		op = new OperationOptions(opts);

		connector.executeQuery(null, null, new PrintResultsHandler(), op);

		connector.dispose();
	}
}
