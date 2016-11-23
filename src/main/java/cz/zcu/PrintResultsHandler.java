package cz.zcu;

import org.identityconnectors.framework.common.objects.*;

public class PrintResultsHandler implements ResultsHandler {
	public boolean handle(final ConnectorObject connectorObject) {
		System.out.println(connectorObject.toString());
		return true;
	}
}
