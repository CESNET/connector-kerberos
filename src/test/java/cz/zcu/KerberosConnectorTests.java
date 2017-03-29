package cz.zcu;

import java.util.HashSet;
import java.util.Set;

import org.identityconnectors.common.logging.Log;
//import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
//import org.identityconnectors.framework.common.objects.PredefinedAttributes;
import org.identityconnectors.framework.common.objects.ResultsHandler;
//import org.identityconnectors.framework.common.objects.Schema;
//import org.identityconnectors.framework.common.objects.ScriptContextBuilder;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.identityconnectors.framework.impl.api.local.LocalConnectorFacadeImpl;
import org.identityconnectors.framework.spi.Connector;
import org.identityconnectors.test.common.PropertyBag;
import org.identityconnectors.test.common.TestHelpers;
import org.identityconnectors.test.common.ToListResultsHandler;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * Attempts to test the {@link KerberosConnector} with the framework.
 *
 */
public class KerberosConnectorTests {

    /**
    * Setup logging for the {@link KerberosConnectorTests}.
    */
    private static final Log logger = Log.getLog(KerberosConnectorTests.class);

    private ConnectorFacade connectorFacade = null;

    /*
    * Example test properties.
    * See the Javadoc of the TestHelpers class for the location of the public and private configuration files.
    */
    private static final PropertyBag PROPERTIES = TestHelpers.getProperties(KerberosConnector.class);

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

    @Test
    public void exampleTest1() {
        logger.info("Running Test 1...");
        //You can use TestHelpers to do some of the boilerplate work in running a search
        //TestHelpers.search(theConnector, ObjectClass.ACCOUNT, filter, handler, null);
    }

    @Test
    public void exampleTest2() {
        logger.info("Running Test 2...");
        //Another example using TestHelpers
        //List<ConnectorObject> results = TestHelpers.searchToList(theConnector, ObjectClass.GROUP, filter);
    }


    @Test
    public void createTest() {
        logger.info("Running Create Test");
        final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
        final OperationOptionsBuilder builder = new OperationOptionsBuilder();
        Set<Attribute> createAttributes = new HashSet<Attribute>();
        createAttributes.add(new Name("Foo"));
        createAttributes.add(AttributeBuilder.buildPassword("Password".toCharArray()));
        createAttributes.add(AttributeBuilder.buildEnabled(true));
        Uid uid = facade.create(ObjectClass.ACCOUNT, createAttributes, builder.build());
        Assert.assertEquals(uid.getUidValue(), "foo");
    }

    @Test
    public void deleteTest() {
        logger.info("Running Delete Test");
        final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
        final OperationOptionsBuilder builder = new OperationOptionsBuilder();
        facade.delete(ObjectClass.ACCOUNT, new Uid("user3"), builder.build());
    }





    @Test
    public void getObjectTest() {
        logger.info("Running GetObject Test");
        final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
        final OperationOptionsBuilder builder = new OperationOptionsBuilder();
        builder.setAttributesToGet(Name.NAME);
        ConnectorObject co =
                facade.getObject(ObjectClass.ACCOUNT, new Uid(
                        "user2"), builder.build());
        Assert.assertNotNull(co);
        Assert.assertEquals(co.getName().getNameValue(), "user2");
    }

    @Test
    public void searchTest() {
        logger.info("Running Search Test");
        final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
        final OperationOptionsBuilder builder = new OperationOptionsBuilder();
        builder.setPageSize(10);
        final ResultsHandler handler = new ToListResultsHandler();

        SearchResult result =
                facade.search(ObjectClass.ACCOUNT, FilterBuilder.equalTo(new Name("user2")), handler,
                        builder.build());
        Assert.assertEquals(result.getPagedResultsCookie(), "NO_COOKIE");
        Assert.assertEquals(((ToListResultsHandler) handler).getObjects().size(), 1);
    }


    @Test
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

    @Test
    public void updateTest() {
        logger.info("Running Update Test");
        final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
        final OperationOptionsBuilder builder = new OperationOptionsBuilder();
        Set<Attribute> updateAttributes = new HashSet<Attribute>();
        updateAttributes.add(new Name("user-new"));

        Uid uid = facade.update(ObjectClass.ACCOUNT, new Uid("user"), updateAttributes, builder.build());
        Assert.assertEquals(uid.getUidValue(), "user-new");
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
