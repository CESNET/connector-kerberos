package cz.zcu.connectors.kerberos;

import java.util.HashSet;
import java.util.Set;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.Schema;
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

	private static final String realm = PROPERTIES.getProperty("configuration.realm", String.class);

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
	public void createTest() {
		logger.info("Running Create Test");

		final String principal = "Foo@" + realm;
		final long modifyDate = System.currentTimeMillis();
		final long princExpire = modifyDate + 1000 * 7 * 24 * 3600;
		final long maxLife = 1000 * 4 * 3600;
		final long maxRenew = 1000 * 24 * 3600;
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		ConnectorObject co;

		Set<Attribute> createAttributes = new HashSet<Attribute>();
		createAttributes.add(new Name(principal));
		createAttributes.add(AttributeBuilder.buildPassword("Password".toCharArray()));
		createAttributes.add(AttributeBuilder.buildEnabled(true));
		createAttributes.add(AttributeBuilder.buildDisableDate(princExpire));
		createAttributes.add(AttributeBuilder.build("requiresPreauth", true));
		createAttributes.add(AttributeBuilder.build("maxTicketLife", maxLife));
		createAttributes.add(AttributeBuilder.build("maxRenewableLife", maxRenew));
		Uid uid = facade.create(KerberosPrincipal.OBJECT_CLASS, createAttributes, null);
		Assert.assertEquals(uid.getUidValue(), principal);

		co = facade.getObject(KerberosPrincipal.OBJECT_CLASS, new Uid(principal), null);
		Assert.assertNotNull(co);
		long validTo = AttributeUtil.getLongValue(co.getAttributeByName(OperationalAttributes.DISABLE_DATE_NAME));
		long maxLife2 = AttributeUtil.getLongValue(co.getAttributeByName("maxTicketLife"));
		long maxRenew2 = AttributeUtil.getLongValue(co.getAttributeByName("maxRenewableLife"));
		Assert.assertEquals(precRound(validTo, 2 * 1000), precRound(princExpire, 2 * 1000));
		Assert.assertEquals(precRound(maxLife2, 2 * 1000), precRound(maxLife, 2 * 1000));
		Assert.assertEquals(precRound(maxRenew2, 2 * 1000), precRound(maxRenew, 2 * 1000));
		Assert.assertTrue(AttributeUtil.getBooleanValue(co.getAttributeByName("requiresPreauth")));
		Assert.assertEquals((int)AttributeUtil.getIntegerValue(co.getAttributeByName("attributes")), 128);
	}

	@Test
	public void createRandkeyTest() {
		logger.info("Running Create Randkey Test");

		final String principal = "host/foo@" + realm;
		final String policy = "default_nohistory";
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		ConnectorObject co;

		Set<Attribute> createAttributes = new HashSet<Attribute>();
		createAttributes.add(new Name(principal));
		createAttributes.add(AttributeBuilder.build("policy", policy));
		createAttributes.add(AttributeBuilder.build("requiresPreauth", true));
		Uid uid = facade.create(KerberosPrincipal.OBJECT_CLASS, createAttributes, null);
		Assert.assertEquals(uid.getUidValue(), principal);

		co = facade.getObject(KerberosPrincipal.OBJECT_CLASS, new Uid(principal), null);
		Assert.assertNotNull(co);
		Assert.assertTrue(AttributeUtil.getBooleanValue(co.getAttributeByName("requiresPreauth")));
		Assert.assertEquals((int)AttributeUtil.getIntegerValue(co.getAttributeByName("attributes")), 128);
		Assert.assertEquals(AttributeUtil.getStringValue(co.getAttributeByName("policy")), policy);
	}

	@Test
	public void deleteTest() {
		logger.info("Running Delete Test");
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		final OperationOptionsBuilder builder = new OperationOptionsBuilder();
		facade.delete(KerberosPrincipal.OBJECT_CLASS, new Uid("test@" + realm), builder.build());
	}

	@Test(expectedExceptions = { UnknownUidException.class })
	public void deleteFailTest() {
		logger.info("Running Delete Test");
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		final OperationOptionsBuilder builder = new OperationOptionsBuilder();
		facade.delete(KerberosPrincipal.OBJECT_CLASS, new Uid("non-existant-user@" + realm), builder.build());
	}

	@Test
	public void getObjectTest() {
		logger.info("Running GetObject Test");
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		final OperationOptionsBuilder builder = new OperationOptionsBuilder();
		builder.setAttributesToGet(Name.NAME);
		ConnectorObject co =
				facade.getObject(KerberosPrincipal.OBJECT_CLASS, new Uid(
						"user2"), builder.build());
		Assert.assertNotNull(co);
		Assert.assertEquals(co.getName().getNameValue(), "user2@" + realm);
	}

	@Test
	public void getUnknownObjectTest() {
		logger.info("Running GetUnknownObject Test");
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		final OperationOptionsBuilder builder = new OperationOptionsBuilder();
		builder.setAttributesToGet(Name.NAME);
		ConnectorObject co =
				facade.getObject(KerberosPrincipal.OBJECT_CLASS, new Uid(
						"non-existant-unknown-user"), builder.build());
		Assert.assertNull(co);
	}

	@Test
	public void exactSearchTest() {
		logger.info("Running Exact Search Test");

		final String principal = "user2";
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		final OperationOptionsBuilder builder = new OperationOptionsBuilder();
		builder.setPageSize(10);

		final ResultsHandler handler = new ToListResultsHandler();
		SearchResult result = facade.search(KerberosPrincipal.OBJECT_CLASS, FilterBuilder.equalTo(new Name(principal)), handler, builder.build());
		Assert.assertEquals(result.getPagedResultsCookie(), "NO_COOKIE");
		Assert.assertEquals(((ToListResultsHandler) handler).getObjects().size(), 1);

		final ResultsHandler handler2 = new ToListResultsHandler();
		result = facade.search(KerberosPrincipal.OBJECT_CLASS, FilterBuilder.equalTo(new Uid(principal)), handler2, builder.build());
		Assert.assertEquals(((ToListResultsHandler) handler2).getObjects().size(), 1);

		final ResultsHandler handler3 = new ToListResultsHandler();
		result = facade.search(KerberosPrincipal.OBJECT_CLASS, FilterBuilder.equalTo(new Uid(principal + "@" + realm)), handler3, builder.build());
		Assert.assertEquals(((ToListResultsHandler) handler3).getObjects().size(), 1);
	}

	@Test
	public void startsWithSearchTest() {
		logger.info("Running \"Starts with\" Search Test");
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		final OperationOptionsBuilder builder = new OperationOptionsBuilder();
		builder.setPageSize(10);
		final ResultsHandler handler = new ToListResultsHandler();

		SearchResult result =
				facade.search(KerberosPrincipal.OBJECT_CLASS, FilterBuilder.startsWith(new Name("user")), handler,
						builder.build());
		Assert.assertEquals(result.getPagedResultsCookie(), "NO_COOKIE");
		Assert.assertEquals(((ToListResultsHandler) handler).getObjects().size(), 3);
	}

	@Test
	public void endsWithSearchTest() {
		logger.info("Running \"Ends with\" Search Test");
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		final OperationOptionsBuilder builder = new OperationOptionsBuilder();
		ResultsHandler handler;
		builder.setPageSize(10);

		handler = new ToListResultsHandler();
		SearchResult result =
				facade.search(KerberosPrincipal.OBJECT_CLASS, FilterBuilder.endsWith(new Name("3")), handler,
						builder.build());
		Assert.assertEquals(result.getPagedResultsCookie(), "NO_COOKIE");
		Assert.assertEquals(((ToListResultsHandler) handler).getObjects().size(), 1);

		handler = new ToListResultsHandler();
		result =
				facade.search(KerberosPrincipal.OBJECT_CLASS, FilterBuilder.endsWith(new Name("3@" + realm)), handler,
						builder.build());
		Assert.assertEquals(result.getPagedResultsCookie(), "NO_COOKIE");
		Assert.assertEquals(((ToListResultsHandler) handler).getObjects().size(), 1);
	}

	@Test
	public void containsSearchTest() {
		logger.info("Running \"Contains\" Search Test");
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		final OperationOptionsBuilder builder = new OperationOptionsBuilder();
		builder.setPageSize(10);
		final ResultsHandler handler = new ToListResultsHandler();

		SearchResult result =
				facade.search(KerberosPrincipal.OBJECT_CLASS, FilterBuilder.contains(new Name("earch-tes")), handler,
						builder.build());
		Assert.assertEquals(result.getPagedResultsCookie(), "NO_COOKIE");
		Assert.assertEquals(((ToListResultsHandler) handler).getObjects().size(), 1);
	}

	@Test
	/**
	 * Test search with empty filter.
	 */
	public void searchAllTest() {
		logger.info("Running Search All Test");

		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		final OperationOptionsBuilder builder = new OperationOptionsBuilder();
		builder.setPageSize(10);
		final ResultsHandler handler = new ToListResultsHandler();

		SearchResult result =
				facade.search(KerberosPrincipal.OBJECT_CLASS, null, handler,
						builder.build());
		Assert.assertEquals(result.getPagedResultsCookie(), "NO_COOKIE");
		Assert.assertTrue(((ToListResultsHandler) handler).getObjects().size() > 1);
	}

	@Test
	public void searchPageOutOfRangeTest() {
		logger.info("Running \"Page out of range\" Search Test");
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		final OperationOptionsBuilder builder = new OperationOptionsBuilder();
		builder.setPageSize(10);
		builder.setPagedResultsOffset(10000);
		final ResultsHandler handler = new ToListResultsHandler();

		SearchResult result = facade.search(KerberosPrincipal.OBJECT_CLASS, FilterBuilder.startsWith(new Name("user")), handler, builder.build());
		Assert.assertEquals(result.getPagedResultsCookie(), "NO_COOKIE");
		Assert.assertEquals(((ToListResultsHandler) handler).getObjects().size(), 0);
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
	public void renameTest() {
		logger.info("Running Update Name Test");

		final String principal = "rename-test@" + realm;
		final String newPrincipal = "rename-test2@" + realm;
		final Uid testUid = new Uid(principal);
		Uid uid;
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		final OperationOptionsBuilder builder = new OperationOptionsBuilder();
		Set<Attribute> updateAttributes = new HashSet<Attribute>();
		updateAttributes.add(new Name(newPrincipal));

		uid = facade.update(KerberosPrincipal.OBJECT_CLASS, testUid, updateAttributes, builder.build());
		Assert.assertEquals(uid.getUidValue(), newPrincipal);

		ConnectorObject co = facade.getObject(KerberosPrincipal.OBJECT_CLASS, new Uid(newPrincipal), null);
		Assert.assertNotNull(co);
		Assert.assertEquals(co.getName().getNameValue(), newPrincipal);
	}

	@Test(expectedExceptions = { AlreadyExistsException.class })
	public void renameFailTest() {
		logger.info("Running Fail Rename Test");

		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		Set<Attribute> updateAttributes = new HashSet<Attribute>();
		updateAttributes.add(new Name("rename-test-fail2@" + realm));
		facade.update(KerberosPrincipal.OBJECT_CLASS, new Uid("rename-test-fail@" + realm), updateAttributes, null);
	}

	@Test
	void updateDatesTest() {
		logger.info("Running Update Dates Test");

		final String principal = "update-test@" + realm;
		final Uid testUid = new Uid(principal);
		final long modifyDate = System.currentTimeMillis();
		final long expPrincDate = modifyDate + 3600000;
		final long expPwDate = modifyDate + 1800000;
		Uid uid;
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		Set<Attribute> updateAttributes;
		ConnectorObject co;

		updateAttributes = new HashSet<Attribute>();
		updateAttributes.add(AttributeBuilder.build(OperationalAttributes.DISABLE_DATE_NAME, expPrincDate));
		updateAttributes.add(AttributeBuilder.build(OperationalAttributes.PASSWORD_EXPIRATION_DATE_NAME, expPwDate));
		uid = facade.update(KerberosPrincipal.OBJECT_CLASS, testUid, updateAttributes, null);
		Assert.assertEquals(uid.getUidValue(), principal);

		co = facade.getObject(KerberosPrincipal.OBJECT_CLASS, testUid, null);
		Assert.assertNotNull(co);
		Long expPrincDate2 = (Long)co.getAttributeByName(OperationalAttributes.DISABLE_DATE_NAME).getValue().get(0);
		Long expPwDate2 = (Long)co.getAttributeByName(OperationalAttributes.PASSWORD_EXPIRATION_DATE_NAME).getValue().get(0);
		Long modifyDate2 = (Long)co.getAttributeByName("modifyDate").getValue().get(0);
		// permit less precision (1 second)
		Assert.assertEquals(precRound(expPrincDate, 1000 * 2), precRound(expPrincDate2, 1000 * 2));
		Assert.assertEquals(precRound(expPwDate, 1000 * 2), precRound (expPwDate2, 1000 * 2));
		// modifyDate is set independently - permit even less precision
		Assert.assertEquals(precRound(modifyDate, 1000 * 10), precRound(modifyDate2, 1000 * 10));
	}

	@Test
	public void updatePolicyTest() {
		logger.info("Running Update Policy Test");

		final String principal = "update-test@" + realm;
		final Uid testUid = new Uid(principal);
		Uid uid;
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);

		Set<Attribute> updateAttributes = new HashSet<Attribute>();
		updateAttributes.add(AttributeBuilder.build("policy", "mypolicy"));
		uid = facade.update(KerberosPrincipal.OBJECT_CLASS, testUid, updateAttributes, null);
		Assert.assertEquals(uid.getUidValue(), principal);
		ConnectorObject co = facade.getObject(KerberosPrincipal.OBJECT_CLASS, testUid, null);
		Assert.assertNotNull(co);
		Assert.assertEquals(co.getAttributeByName("policy").getValue().get(0), "mypolicy");

		// clear policy
		updateAttributes = new HashSet<Attribute>();
		updateAttributes.add(AttributeBuilder.build("policy"));
		uid = facade.update(KerberosPrincipal.OBJECT_CLASS, testUid, updateAttributes, null);
		Assert.assertEquals(uid.getUidValue(), principal);
		co = facade.getObject(KerberosPrincipal.OBJECT_CLASS, testUid, null);
		Assert.assertNotNull(co);
		Assert.assertNull(co.getAttributeByName("policy").getValue().get(0));
	}

	@Test
	public void updateFlagsTest() {
		logger.info("Running Update Flags Test");

		final String principal = "update-test@" + realm;
		Uid testUid = new Uid(principal);
		Uid uid;
		int mask;
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);

		mask = 0;
		Set<Attribute> updateAttributes = new HashSet<Attribute>();
		updateAttributes.add(AttributeBuilder.build("attributes", 0));
		uid = facade.update(KerberosPrincipal.OBJECT_CLASS, testUid, updateAttributes, null);
		Assert.assertEquals(uid.getUidValue(), principal);
		ConnectorObject co = facade.getObject(KerberosPrincipal.OBJECT_CLASS, testUid, null);
		Assert.assertNotNull(co);
		Assert.assertEquals(co.getAttributeByName("attributes").getValue().get(0), mask);
		Assert.assertEquals(co.getAttributeByName("allowTix").getValue().get(0), true);
		Assert.assertEquals(co.getAttributeByName("requiresPreauth").getValue().get(0), false);

		mask |= 128;
		updateAttributes= new HashSet<Attribute>();
		updateAttributes.add(AttributeBuilder.build("requiresPreauth", true));
		uid = facade.update(KerberosPrincipal.OBJECT_CLASS, testUid, updateAttributes, null);
		Assert.assertEquals(uid.getUidValue(), principal);
		co = facade.getObject(KerberosPrincipal.OBJECT_CLASS, testUid, null);
		Assert.assertNotNull(co);
		Assert.assertEquals(co.getAttributeByName("attributes").getValue().get(0), mask);
		Assert.assertEquals(co.getAttributeByName("requiresPreauth").getValue().get(0), true);

		mask |= 2;
		updateAttributes= new HashSet<Attribute>();
		updateAttributes.add(AttributeBuilder.build("allowForwardable", false));
		uid = facade.update(KerberosPrincipal.OBJECT_CLASS, testUid, updateAttributes, null);
		Assert.assertEquals(uid.getUidValue(), principal);
		co = facade.getObject(KerberosPrincipal.OBJECT_CLASS, testUid, null);
		Assert.assertNotNull(co);
		Assert.assertEquals(co.getAttributeByName("attributes").getValue().get(0), mask);
		Assert.assertEquals(co.getAttributeByName("allowForwardable").getValue().get(0), false);

		mask = 128 | 256;
		updateAttributes= new HashSet<Attribute>();
		updateAttributes.add(AttributeBuilder.build("allowForwardable", true));
		updateAttributes.add(AttributeBuilder.build("requiresHwauth", true));
		uid = facade.update(KerberosPrincipal.OBJECT_CLASS, testUid, updateAttributes, null);
		Assert.assertEquals(uid.getUidValue(), principal);
		co = facade.getObject(KerberosPrincipal.OBJECT_CLASS, testUid, null);
		Assert.assertNotNull(co);
		Assert.assertEquals(co.getAttributeByName("attributes").getValue().get(0), mask);
		Assert.assertEquals(co.getAttributeByName("allowForwardable").getValue().get(0), true);
		Assert.assertEquals(co.getAttributeByName("requiresHwauth").getValue().get(0), true);

		mask = 128 | 8;
		updateAttributes= new HashSet<Attribute>();
		updateAttributes.add(AttributeBuilder.build("allowRenewable", false));
		updateAttributes.add(AttributeBuilder.build("requiresHwauth", false));
		uid = facade.update(KerberosPrincipal.OBJECT_CLASS, testUid, updateAttributes, null);
		Assert.assertEquals(uid.getUidValue(), principal);
		co = facade.getObject(KerberosPrincipal.OBJECT_CLASS, testUid, null);
		Assert.assertNotNull(co);
		Assert.assertEquals(co.getAttributeByName("attributes").getValue().get(0), mask);
		Assert.assertEquals(co.getAttributeByName("allowForwardable").getValue().get(0), true);
		Assert.assertEquals(co.getAttributeByName("requiresHwauth").getValue().get(0), false);
		Assert.assertEquals(co.getAttributeByName("allowRenewable").getValue().get(0), false);

		mask = 128 | 512;
		updateAttributes= new HashSet<Attribute>();
		updateAttributes.add(AttributeBuilder.build("allowRenewable", true));
		updateAttributes.add(AttributeBuilder.build("requiresPwchange", true));
		uid = facade.update(KerberosPrincipal.OBJECT_CLASS, testUid, updateAttributes, null);
		Assert.assertEquals(uid.getUidValue(), principal);
		co = facade.getObject(KerberosPrincipal.OBJECT_CLASS, testUid, null);
		Assert.assertNotNull(co);
		Assert.assertEquals(co.getAttributeByName("attributes").getValue().get(0), mask);
		Assert.assertEquals(co.getAttributeByName("requiresPwchange").getValue().get(0), true);
	}

	@Test
	public void updateLife() {
		logger.info("Running Update Ticket/Renew Life Test");

		final String principal = "update-test@" + realm;
		final long maxTicket = 1000 * 3600 * 4;
		final long maxRenew = 1000 * 3600 * 24;
		final Uid testUid = new Uid(principal);
		Uid uid;
		ConnectorObject co;
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		Set<Attribute> updateAttributes;

		updateAttributes = new HashSet<Attribute>();
		updateAttributes.add(AttributeBuilder.build("maxTicketLife", maxTicket));
		updateAttributes.add(AttributeBuilder.build("maxRenewableLife", maxRenew));
		uid = facade.update(KerberosPrincipal.OBJECT_CLASS, testUid, updateAttributes, null);
		Assert.assertEquals(uid.getUidValue(), principal);
		co = facade.getObject(KerberosPrincipal.OBJECT_CLASS, testUid, null);
		Assert.assertNotNull(co);
		Assert.assertEquals(co.getAttributeByName("maxTicketLife").getValue().get(0), maxTicket);
		Assert.assertEquals(co.getAttributeByName("maxRenewableLife").getValue().get(0), maxRenew);
	}

	@Test
	public void enableTest() {
		logger.info("Running Enable Test");

		final String principal = "update-test@" + realm;
		final Uid testUid = new Uid(principal);
		Uid uid;
		ConnectorObject co;
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		Set<Attribute> updateAttributes;

		// disable
		updateAttributes = new HashSet<Attribute>();
		updateAttributes.add(AttributeBuilder.build(OperationalAttributes.ENABLE_NAME, false));
		uid = facade.update(KerberosPrincipal.OBJECT_CLASS, testUid, updateAttributes, null);
		Assert.assertEquals(uid.getUidValue(), principal);
		co = facade.getObject(KerberosPrincipal.OBJECT_CLASS, testUid, null);
		Assert.assertNotNull(co);
		Assert.assertEquals(co.getAttributeByName("attributes").getValue().get(0), 192);
		Assert.assertEquals(co.getAttributeByName("allowTix").getValue().get(0), false);

		// enable
		updateAttributes= new HashSet<Attribute>();
		updateAttributes.add(AttributeBuilder.build(OperationalAttributes.ENABLE_NAME, true));
		uid = facade.update(KerberosPrincipal.OBJECT_CLASS, testUid, updateAttributes, null);
		Assert.assertEquals(uid.getUidValue(), principal);
		co = facade.getObject(KerberosPrincipal.OBJECT_CLASS, testUid, null);
		Assert.assertNotNull(co);
		Assert.assertEquals(co.getAttributeByName("attributes").getValue().get(0), 128);
		Assert.assertEquals(co.getAttributeByName("allowTix").getValue().get(0), true);
	}

	@Test
	public void changePasswordTest() {
		logger.info("Running Change Password Test");

		final String principal = "password-test@" + realm;
		final Uid testUid = new Uid(principal);
		Uid uid;
		ConnectorObject co;
		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		Set<Attribute> attrs;

		attrs = new HashSet<Attribute>();
		attrs.add(AttributeBuilder.buildPassword("new-password".toCharArray()));
		uid = facade.update(KerberosPrincipal.OBJECT_CLASS, testUid, attrs, null);
		Assert.assertEquals(uid.getUidValue(), principal);
		co = facade.getObject(KerberosPrincipal.OBJECT_CLASS, testUid, null);
		Assert.assertNotNull(co);

		// empty password not supported: ConnId expect always non-empty password
		//attrs.add(AttributeBuilder.build(OperationalAttributes.PASSWORD_NAME));
	}

	@Test
	public void schemaTest() {
		logger.info("Running Schema Test");

		final ConnectorFacade facade = getFacade(KerberosConnector.class, null);
		boolean allowTix = false, name = false, expiration = false;

		Schema schema = facade.schema();
		ObjectClassInfo info = schema.findObjectClassInfo(KerberosPrincipal.OBJECT_CLASS_NAME);
		for (AttributeInfo a : info.getAttributeInfo()) {
			if ("allowTix".equals(a.getName())) allowTix = true;
			if ("__NAME__".equals(a.getName())) name = true;
			if ("__PASSWORD_EXPIRATION_DATE__".equals(a.getName())) expiration = true;
		}
		Assert.assertTrue(allowTix);
		Assert.assertTrue(expiration);
		Assert.assertTrue(name);
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

	private static long precRound(long x, int precision) {
		return Math.round(((double)x) / precision);
	}
}
