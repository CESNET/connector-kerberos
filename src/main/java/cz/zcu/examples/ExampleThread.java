package cz.zcu.examples;

import org.identityconnectors.framework.common.objects.OperationOptions;

import java.util.HashMap;
import java.util.Map;

import static cz.zcu.examples.KerberosAdminApp.connector;

/**
 * Created by majlen on 29.11.16.
 */
public class ExampleThread implements Runnable {
	@Override
	public void run() {
		Map<String, Object> opts = new HashMap<String, Object>();
		opts.put(OperationOptions.OP_PAGE_SIZE, 20);
		opts.put(OperationOptions.OP_PAGED_RESULTS_OFFSET, (int)Math.floor(Math.random()*400));

		OperationOptions op = new OperationOptions(opts);

		connector.executeQuery(null, null, new PrintResultsHandler(), op);
	}
}
