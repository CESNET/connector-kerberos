package cz.zcu;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.exceptions.InvalidPasswordException;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.impl.api.local.LocalConnectorFacadeImpl;
import org.identityconnectors.framework.spi.Connector;
import org.identityconnectors.test.common.PropertyBag;
import org.identityconnectors.test.common.TestHelpers;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * Attempts to test the {@link KerberosConnector} with the framework.
 *
 */
public class KerberosConnectorBadPasswordTests {

	/**
	 * Setup logging for the {@link KerberosConnectorBadPasswordTests}.
	 */
	private static final Log logger = Log.getLog(KerberosConnectorBadPasswordTests.class);

	private ConnectorFacade connectorFacade = null;

	@BeforeClass
	public void setUp() {
		//
		//other setup work to do before running tests
		//

		//Configuration config = new KerberosConfiguration();
		//Map<String, ? extends Object> configData = (Map<String, ? extends Object>) PROPERTIES.getProperty("configuration",Map.class)
		//TestHelpers.fillConfiguration(
		//System.out.println("configuration" + PROPERTIES);
	}

	@AfterClass
	public void tearDown() {
		//
		// clean up resources
		//
		if (connectorFacade instanceof LocalConnectorFacadeImpl) {
			((LocalConnectorFacadeImpl) connectorFacade).dispose();
		}
	}

	@Test(expectedExceptions = { InvalidPasswordException.class })
	public void getObjectTest() {
		logger.info("Running GetObject Test");
		final ConnectorFacade facade = getFacade(KerberosConnector.class, "BadPassword");
		final OperationOptionsBuilder builder = new OperationOptionsBuilder();
		builder.setAttributesToGet(Name.NAME);
		facade.getObject(ObjectClass.ACCOUNT, new Uid("user2"), builder.build());
	}

	@Test(expectedExceptions = { InvalidPasswordException.class })
	public void testTest() {
		logger.info("Running Test Test");

		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		facade.test();
	}

	@Test
	public void validateTest() {
		logger.info("Running Validate Test");

		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		facade.validate();
	}

	protected ConnectorFacade getFacade(KerberosConfiguration config) {
		ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
		// **test only**
		APIConfiguration impl = TestHelpers.createTestConfiguration(KerberosConnector.class, config);
		return factory.newInstance(impl);
	}

	protected ConnectorFacade getFacade(Class<? extends Connector> clazz, String environment) {
		if (null == connectorFacade) {
			synchronized (this) {
				if (null == connectorFacade) {
					connectorFacade = createConnectorFacade(clazz, environment);
				}
			}
		}
		return connectorFacade;
	}

	public ConnectorFacade createConnectorFacade(Class<? extends Connector> clazz,
	                                             String environment) {
		PropertyBag propertyBag = TestHelpers.getProperties(clazz, environment);

		APIConfiguration impl =
				TestHelpers.createTestConfiguration(clazz, propertyBag, "configuration");
		impl.setProducerBufferSize(0);
		impl.getResultsHandlerConfiguration().setEnableAttributesToGetSearchResultsHandler(false);
		impl.getResultsHandlerConfiguration().setEnableCaseInsensitiveFilter(false);
		impl.getResultsHandlerConfiguration().setEnableFilteredResultsHandler(false);
		impl.getResultsHandlerConfiguration().setEnableNormalizingResultsHandler(false);

		//impl.setTimeout(CreateApiOp.class, 25000);
		//impl.setTimeout(UpdateApiOp.class, 25000);
		//impl.setTimeout(DeleteApiOp.class, 25000);

		return ConnectorFacadeFactory.getInstance().newInstance(impl);
	}
}
