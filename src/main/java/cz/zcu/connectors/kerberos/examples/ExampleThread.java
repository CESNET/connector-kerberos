package cz.zcu.connectors.kerberos.examples;

import org.identityconnectors.framework.common.objects.OperationOptions;

import cz.zcu.connectors.kerberos.KerberosConnector;

import static cz.zcu.connectors.kerberos.examples.KerberosAdminApp.config;

import java.util.HashMap;
import java.util.Map;

public class ExampleThread implements Runnable {
	@Override
	public void run() {
		KerberosConnector connector = new KerberosConnector();
		connector.init(config);

		Map<String, Object> opts = new HashMap<String, Object>();
		opts.put(OperationOptions.OP_PAGE_SIZE, 20);
		opts.put(OperationOptions.OP_PAGED_RESULTS_OFFSET, (int)Math.floor(Math.random()*400));
		OperationOptions op = new OperationOptions(opts);

		connector.executeQuery(null, null, new PrintResultsHandler(), op);
		connector.dispose();
	}
}
