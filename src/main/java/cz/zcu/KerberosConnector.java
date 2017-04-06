package cz.zcu;

import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

import cz.zcu.exceptions.KerberosException;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.AttributeInfo.Flags;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.PoolableConnector;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.identityconnectors.framework.spi.operations.*;

/**
 * Main implementation of the Kerberos Connector.
 */
@ConnectorClass(
		displayNameKey = "Kerberos.connector.display",
		configurationClass = KerberosConfiguration.class)
public class KerberosConnector implements PoolableConnector, CreateOp, DeleteOp, SearchOp<String>, UpdateOp, SchemaOp, TestOp {

	/**
	 * Setup logging for the {@link KerberosConnector}.
	 */
	private static final Log logger = Log.getLog(KerberosConnector.class);

	/**
	 * Place holder for the {@link Configuration} passed into the init() method
	 * {@link KerberosConnector#init(org.identityconnectors.framework.spi.Configuration)}.
	 */
	private KerberosConfiguration configuration;

	private Schema schema = null;

	private long contextPointer;

	public long getContextPointer() {
		return this.contextPointer;
	}

	/**
	 * Gets the Configuration context for this connector.
	 *
	 * @return The current {@link Configuration}
	 */
	public Configuration getConfiguration() {
		return this.configuration;
	}

	/**
	 * Callback method to receive the {@link Configuration}.
	 *
	 * @param configuration the new {@link Configuration}
	 * @see org.identityconnectors.framework.spi.Connector#init(org.identityconnectors.framework.spi.Configuration)
	 */
	public void init(final Configuration configuration) {
		this.configuration = (KerberosConfiguration) configuration;
		logger.info("Initializing resource with realm {0}", this.configuration.getRealm());
		krb5_init(GuardedStringAccessor.class);
	}

	/**
	 * Disposes of the {@link KerberosConnector}'s resources.
	 *
	 * @see org.identityconnectors.framework.spi.Connector#dispose()
	 */
	public void dispose() {
		logger.info("Disposing resource");
		krb5_destroy();
		configuration = null;
	}

	/**
	 * Check the instance connection of {@link KerberosConnector} to be reused.
	 *
	 * It only check, if the connection has not been disposed. Otherwise always OK.
	 *
	 * @see org.identityconnectors.framework.spi.PoolableConnector#checkAlive()
	 */
	public void checkAlive() {
		if (configuration == null) {
			throw new ConnectorException("checkAlive(): Connector not initialized");
		}
	}

	private native void krb5_init(Class<GuardedStringAccessor> gsAccessor) throws KerberosException;
	private native void krb5_destroy();
	private native void krb5_renew(Class<GuardedStringAccessor> gsAccessor) throws KerberosException;
	private native void krb5_create(String name, String password, long principalExpiry, long passwordExpiry, int attributes, String policy, int mask) throws KerberosException;
	private native void krb5_delete(String name) throws KerberosException;
	private native void krb5_rename(String name, String newName) throws KerberosException;
	private native void krb5_chpasswd(String name, String password);
	private native void krb5_modify(String name, long principalExpiry, long passwordExpiry, int attributes, String policy, int mask) throws KerberosException;
	private synchronized native KerberosSearchResults krb5_search(String query, int pageSize, int pageOffset);

	/******************
	 * SPI Operations
	 *
	 * Implement the following operations using the contract and
	 * description found in the Javadoc for these methods.
	 ******************/

	/**
	 * {@inheritDoc}
	 */
	public Uid create(final ObjectClass objectClass, final Set<Attribute> createAttributes, final OperationOptions options) {
		if (ObjectClass.ACCOUNT.equals(objectClass)) {
			Attribute tempAttr;

			Name name = AttributeUtil.getNameFromAttributes(createAttributes);
			GuardedString password = AttributeUtil.getPasswordValue(createAttributes);

			//In case of creating a principal, it's necessary to set its name
			int mask = KerberosPrincipal.KRBCONN_PRINCIPAL;

			tempAttr = AttributeUtil.find(OperationalAttributes.DISABLE_DATE_NAME, createAttributes);
			long principalExpiry = 0;
			if (tempAttr != null) {
				principalExpiry = AttributeUtil.getLongValue(tempAttr);
				mask |= KerberosPrincipal.KRBCONN_PRINC_EXPIRE_TIME;
			}

			tempAttr = AttributeUtil.find(OperationalAttributes.PASSWORD_EXPIRATION_DATE_NAME, createAttributes);
			long passwordExpiry = 0;
			if (tempAttr != null) {
				passwordExpiry = AttributeUtil.getLongValue(tempAttr);
				mask |= KerberosPrincipal.KRBCONN_PW_EXPIRATION;
			}

			tempAttr = AttributeUtil.find("attributes", createAttributes);
			int attributes = 0;
			if (tempAttr != null) {
				attributes = AttributeUtil.getIntegerValue(tempAttr);
				mask |= KerberosPrincipal.KRBCONN_ATTRIBUTES;
			}

			tempAttr = AttributeUtil.find("policy", createAttributes);
			String policy = null;
			if (tempAttr != null) {
				policy = AttributeUtil.getStringValue(tempAttr);
				mask |= KerberosPrincipal.KRBCONN_POLICY;
			}

			if (name != null) {
				String guardedPassword = null;
				if (password != null) {
					guardedPassword = GuardedStringAccessor.getString(password);
				}
				logger.info("Creating Kerberos principal {0}", name.getNameValue());
				krb5_create(name.getNameValue(), guardedPassword, principalExpiry, passwordExpiry, attributes, policy, mask);
				return new Uid(AttributeUtil.getStringValue(name).toLowerCase());
			} else {
				throw new InvalidAttributeValueException("Name attribute is required");
			}
		} else {
			logger.warn("Create of type {0} is not supported",
					configuration.getConnectorMessages().format(objectClass.getDisplayNameKey(), objectClass.getObjectClassValue()));
			throw new UnsupportedOperationException("Create of type" + objectClass.getObjectClassValue() + " is not supported");
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void delete(final ObjectClass objectClass, final Uid uid, final OperationOptions options) {
		if (ObjectClass.ACCOUNT.equals(objectClass)) {
			logger.info("Deleting Kerberos principal {0}", uid.getUidValue());
			krb5_delete(uid.getUidValue());
		} else {
			logger.warn("Delete of type {0} is not supported",
					configuration.getConnectorMessages().format(objectClass.getDisplayNameKey(), objectClass.getObjectClassValue()));
			throw new UnsupportedOperationException("Delete of type" + objectClass.getObjectClassValue() + " is not supported");
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public FilterTranslator<String> createFilterTranslator(ObjectClass objectClass, OperationOptions options) {
		return new KerberosFilterTranslator();
	}

	/**
	 * {@inheritDoc}
	 */
	public void executeQuery(ObjectClass objectClass, String query, ResultsHandler handler, OperationOptions options) {
		logger.info("Executing query: {0}", query);
		if (options.getPageSize() != null && 0 < options.getPageSize()) {
			logger.info("Paged search was requested. Offset: {0}. Count: {1}.", options.getPagedResultsOffset(), options.getPageSize());

			KerberosSearchResults results;
			if (options.getPagedResultsOffset() == null) {
				results = krb5_search(query, options.getPageSize(), 0);
			} else {
				results = krb5_search(query, options.getPageSize(), options.getPagedResultsOffset());
			}

			for (KerberosPrincipal principal : results.principals) {
				if (!handler.handle(principal.toConnectorObject())) {
					//Stop iterating because the handler stopped processing
					break;
				}
			}
			((SearchResultsHandler)handler).handleResult(new SearchResult("NO_COOKIE", results.remaining));
		} else {
			logger.info("Full search was requested.");
			KerberosSearchResults results = krb5_search(query, 0, 0);
			for (KerberosPrincipal principal : results.principals) {
				if (!handler.handle(principal.toConnectorObject())) {
					//Stop iterating because the handler stopped processing
					break;
				}
			}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public Uid update(ObjectClass objectClass, Uid uid, Set<Attribute> replaceAttributes, OperationOptions options) {
		Uid returnUid = uid;
		if (ObjectClass.ACCOUNT.equals(objectClass)) {
			AttributesAccessor attributesAccessor = new AttributesAccessor(replaceAttributes);

			long principalExpiry = 0;
			long passwordExpiry = 0;
			KerberosFlags attributes = new KerberosFlags(0);
			String policy = null;
			int mask = 0;

			if (attributesAccessor.hasAttribute(OperationalAttributes.DISABLE_DATE_NAME)) {
				principalExpiry = attributesAccessor.findLong(OperationalAttributes.DISABLE_DATE_NAME);
				mask |= KerberosPrincipal.KRBCONN_PRINC_EXPIRE_TIME;
			}

			if (attributesAccessor.hasAttribute(OperationalAttributes.PASSWORD_EXPIRATION_DATE_NAME)) {
				passwordExpiry = attributesAccessor.findLong(OperationalAttributes.PASSWORD_EXPIRATION_DATE_NAME);
				mask |= KerberosPrincipal.KRBCONN_PW_EXPIRATION;
			}

			if (attributesAccessor.hasAttribute("attributes")) {
				attributes = new KerberosFlags(attributesAccessor.findInteger("attributes"));
				mask |= KerberosPrincipal.KRBCONN_ATTRIBUTES;
			}

			if (attributesAccessor.hasAttribute("policy")) {
				policy = attributesAccessor.findString("policy");
				mask |= KerberosPrincipal.KRBCONN_POLICY;
			}

			// set of principal flags to set
			Set<String> flags = KerberosFlags.selectFlagAttributes(attributesAccessor.listAttributeNames());
			// get current attributes if needed - when setting some flags or enable/disable
			if (!attributesAccessor.hasAttribute("attributes") && (!flags.isEmpty() || attributesAccessor.hasAttribute(OperationalAttributes.ENABLE_NAME))) {
				logger.info("Getting principal {0} to get current attributes", uid.getUidValue());
				KerberosSearchResults results = krb5_search(uid.getUidValue(), 0, 0);
				if (results.principals == null || results.principals.length != 1) {
					throw new KerberosException("Modified principal " + uid.getUidValue() + " not found!");
				}

				attributes = results.principals[0].getAttributes();
				mask |= KerberosPrincipal.KRBCONN_ATTRIBUTES;
			}
			// modify principal attributes
			for (String flag : flags) {
				attributes.setFlag(flag, attributesAccessor.findBoolean(flag));
			}
			// enable/disable principal using "allowTix" flag
			if (attributesAccessor.hasAttribute(OperationalAttributes.ENABLE_NAME)) {
				boolean enable = attributesAccessor.findBoolean(OperationalAttributes.ENABLE_NAME);
				attributes.setFlag("allowTix", enable);
			}

			if (mask != 0) {
				if ((mask & KerberosPrincipal.KRBCONN_ATTRIBUTES) != 0) {
					logger.info("New Kerberos principal attributes of {0}: {1}", uid.getUidValue(), attributes.getAttributes());
				}
				logger.info("Modifying Kerberos principal {0}: mask {1}", uid.getUidValue(), mask);
				krb5_modify(uid.getUidValue(), principalExpiry, passwordExpiry, attributes.getAttributes(), policy, mask);
			}

			if (attributesAccessor.hasAttribute(OperationalAttributes.PASSWORD_NAME)) {
				logger.info("Changing password of Kerberos principal {0}", uid.getUidValue());
				krb5_chpasswd(uid.getUidValue(), GuardedStringAccessor.getString(attributesAccessor.getPassword()));
			}

			if (attributesAccessor.hasAttribute(Name.NAME)) {
				returnUid = new Uid(attributesAccessor.getName().getNameValue());
				logger.info("Renaming Kerberos principal {0} to {1}", uid.getUidValue(), returnUid.getUidValue());
				krb5_rename(uid.getUidValue(), attributesAccessor.getName().getNameValue());
			}
		} else {
			logger.warn("Update of type {0} is not supported",
					configuration.getConnectorMessages().format(objectClass.getDisplayNameKey(), objectClass.getObjectClassValue()));
			throw new UnsupportedOperationException("Update of type" + objectClass.getObjectClassValue() + " is not supported");
		}
		return returnUid;
	}


	public void test() {
		logger.info("Testing connection and credentials");
		krb5_renew(GuardedStringAccessor.class);
	}


	public Schema schema() {
		logger.info("schema()");
		if (schema == null) {
			schema = buildSchema();
		}
		return schema;
	}

	private Schema buildSchema() {
		final SchemaBuilder schemaBuilder = new SchemaBuilder(KerberosConnector.class);
		Set<AttributeInfo> attributes = new HashSet<AttributeInfo>();

		attributes.add(OperationalAttributeInfos.DISABLE_DATE);
		attributes.add(OperationalAttributeInfos.ENABLE);
		attributes.add(OperationalAttributeInfos.PASSWORD);
		attributes.add(OperationalAttributeInfos.PASSWORD_EXPIRATION_DATE);

		attributes.add(AttributeInfoBuilder.build("passwordChangeDate",
			long.class, EnumSet.of(Flags.NOT_UPDATEABLE)));

		attributes.add(AttributeInfoBuilder.build("modifyPrincipal",
			String.class, EnumSet.of(Flags.NOT_UPDATEABLE)));

		attributes.add(AttributeInfoBuilder.build("modifyDate",
			long.class, EnumSet.of(Flags.NOT_UPDATEABLE)));

		attributes.add(AttributeInfoBuilder.build("attributes", int.class));
		attributes.add(AttributeInfoBuilder.build("policy", String.class));

		for (String flag : KerberosFlags.flags) {
			attributes.add(AttributeInfoBuilder.build(flag, boolean.class));
		}

		final ObjectClassInfo ociInfoAccount = new ObjectClassInfoBuilder().setType(ObjectClass.ACCOUNT_NAME).addAllAttributeInfo(attributes).build();
		schemaBuilder.defineObjectClass(ociInfoAccount);

		return schemaBuilder.build();
	}

	static {
		System.loadLibrary("kerberos-connector");
	}
}
