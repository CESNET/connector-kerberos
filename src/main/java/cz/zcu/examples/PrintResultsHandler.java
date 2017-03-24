package cz.zcu.examples;

import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.spi.SearchResultsHandler;

public class PrintResultsHandler implements SearchResultsHandler {
	public boolean handle(final ConnectorObject connectorObject) {
		System.out.println(connectorObject.toString());
		return true;
	}

	public void handleResult(SearchResult result) {
		System.out.println("Progress: " + result.getRemainingPagedResults() + "remaining");
	}
}
