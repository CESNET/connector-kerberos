package cz.zcu.connectors.kerberos.examples;

import org.apache.commons.cli.*;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.OperationOptions;

import cz.zcu.connectors.kerberos.KerberosConfiguration;
import cz.zcu.connectors.kerberos.KerberosConnector;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class KerberosAdminApp {
	static KerberosConnector connector = new KerberosConnector();
	static KerberosConfiguration config = new KerberosConfiguration();

	public static void usage(Options options) {
		System.out.println("KerberosAdminApp [OPTIONS] COMMAND");
		System.out.println("OPTIONS are:");
		System.out.println("  -h, --help ...... " + options.getOption("h").getDescription());
		System.out.println("  -k, --keytab .... " + options.getOption("k").getDescription());
		System.out.println("  -p, --password .. " + options.getOption("p").getDescription());
		System.out.println("  -r, --realm ..... " + options.getOption("r").getDescription());
		System.out.println("  -u, --user ...... " + options.getOption("u").getDescription());
		System.out.println("COMMAND is:");
		System.out.println("  search ... paged search example");
		System.out.println("  test ..... test connection");
	}

	public static void main(String[] args) {
		config = new KerberosConfiguration();
		CommandLineParser parser = new DefaultParser();
		Options options = new Options();
		List<String> commands;

		options.addOption("h", "help", false, "usage message");
		options.addOption("k", "keytab", true, "admin keytab");
		options.addOption("r", "realm", true, "kerberos realm");
		options.addOption("p", "password", true, "admin password");
		options.addOption("u", "user", true, "admin principal");

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
			if(line.hasOption("p")) {
				config.setPassword(new GuardedString(line.getOptionValue("p").toCharArray()));
				System.out.println("Password: (obtained)");
			}
			if(line.hasOption("r")) {
				config.setRealm(line.getOptionValue("r"));
				System.out.println("Realm: " + config.getRealm());
			}
			if(line.hasOption("u")) {
				config.setPrincipal(line.getOptionValue("u"));
				System.out.println("Principal: " + config.getPrincipal());
			}

			commands = line.getArgList();
		}
		catch(ParseException exp) {
			System.out.println("Invalid arguments: " + exp.getMessage());
			return;
		}

		if ((config.getKeytab() == null || config.getKeytab().equals("")) && config.getPassword() == null) {
			char[] pass = System.console().readPassword("Enter password: ");
			config.setPassword(new GuardedString(pass));
			Arrays.fill(pass, '\0');
		}

		connector.init(config);
		System.out.println(Long.toHexString(connector.getContextPointer()));

		for (String command : commands) {
			if ("search".equals(command)) {
				System.out.println("Command: search");
				Map<String, Object> opts = new HashMap<String, Object>();
				opts.put(OperationOptions.OP_PAGE_SIZE, 20);
				opts.put(OperationOptions.OP_PAGED_RESULTS_OFFSET, 81);

				OperationOptions op = new OperationOptions(opts);

				connector.executeQuery(null, null, new PrintResultsHandler(), op);

				opts.remove(OperationOptions.OP_PAGED_RESULTS_OFFSET);
				opts.put(OperationOptions.OP_PAGED_RESULTS_OFFSET, 101);
				op = new OperationOptions(opts);

				connector.executeQuery(null, null, new PrintResultsHandler(), op);

				Thread[] thrs = new Thread[10];
				for (int i = 0; i < thrs.length; i++) {
					thrs[i] = new Thread(new ExampleThread());
					thrs[i].start();
				}

				for (int i = 0; i < thrs.length; i++) {
					try {
						thrs[i].join();
					} catch (InterruptedException e) {
						System.out.println(e.getMessage());
					}
				}

				System.out.println();
			} else if ("test".equals(command)) {
				System.out.println("Command: test");
				connector.test();
				System.out.println();
			}
		}

		connector.dispose();
	}
}
