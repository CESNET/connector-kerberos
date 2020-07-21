package cz.zcu.connectors.kerberos;

import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.AttributeInfo.Flags;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.PoolableConnector;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.identityconnectors.framework.spi.operations.*;

import cz.zcu.connectors.kerberos.exceptions.KerberosException;

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

	/**
	 * Last connection time.
	 *
	 * Used for checking credentials validity.
	 */
	private long lastLoginTime = 0;


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
		long currentTime = System.currentTimeMillis();

		this.configuration = (KerberosConfiguration) configuration;
		logger.info("Initializing resource with realm {0}", this.configuration.getRealm());
		krb5_init(GuardedStringAccessor.class);
		this.lastLoginTime = currentTime;
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
		lastLoginTime = 0;
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
		if (configuration.getLifeTime() == 0) {
			throw new ConnectorException("checkAlive(): No connection re-use with credentials lifetime 0");
		}

		long currentTime = System.currentTimeMillis();
		long sessionTime = currentTime - lastLoginTime;
		if (sessionTime >= configuration.getLifeTime()) {
			logger.info("Closing session, connection time: {} s, max time: {} s", sessionTime / 1000, configuration.getLifeTime() / 1000);
			throw new ConnectorException("Credentials lifetime ended");
		}
	}

	private native void krb5_init(Class<GuardedStringAccessor> gsAccessor) throws KerberosException;
	private native void krb5_destroy();
	private native void krb5_renew(Class<GuardedStringAccessor> gsAccessor) throws KerberosException;
	private native void krb5_create(String name, String password, long principalExpiry, long passwordExpiry, int attributes, String policy, long maxTicketLife, long maxRenewableLife, int mask) throws KerberosException;
	private native void krb5_delete(String name) throws KerberosException;
	private native void krb5_rename(String name, String newName) throws KerberosException;
	private native void krb5_chpasswd(String name, String password);
	private native void krb5_modify(String name, long principalExpiry, long passwordExpiry, int attributes, String policy, long maxTicketLife, long maxRenewableLife, int mask) throws KerberosException;
	private native KerberosSearchResults krb5_search(String query, int pageSize, int pageOffset);

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
			AttributesAccessor attributesAccessor = new AttributesAccessor(createAttributes);
			Name name = AttributeUtil.getNameFromAttributes(createAttributes);
			GuardedString password = AttributeUtil.getPasswordValue(createAttributes);

			if (name == null)
				throw new InvalidAttributeValueException("Name attribute is required");

			//In case of creating a principal, it's necessary to set its name
			int mask = KerberosPrincipal.MASK_PRINCIPAL;

			KerberosPrincipal record = new KerberosPrincipal(createAttributes);
			KerberosFlags attributes = record.getAttributes();
			mask = (mask | record.getUpdateMask());

			// set of principal flags to set
			Set<String> flags = KerberosFlags.selectFlagAttributes(attributesAccessor.listAttributeNames());
			// modify principal attributes
			for (String flag : flags) {
				attributes.setFlag(flag, attributesAccessor.findBoolean(flag));
				mask |= KerberosPrincipal.MASK_ATTRIBUTES;
			}
			// enable/disable principal using "allowTix" flag
			if (attributesAccessor.hasAttribute(OperationalAttributes.ENABLE_NAME)) {
				boolean enable = attributesAccessor.findBoolean(OperationalAttributes.ENABLE_NAME);
				attributes.setFlag(KerberosPrincipal.ATTR_ALLOW_TIX, enable);
				mask |= KerberosPrincipal.MASK_ATTRIBUTES;
			}

			String guardedPassword = null;
			if (password != null)
				guardedPassword = GuardedStringAccessor.getString(password);

			logger.info("Creating Kerberos principal {0}, update mask {1}", name.getNameValue(), mask);
			krb5_create(
					name.getNameValue(),
					guardedPassword,
					record.getPrincExpiry(),
					record.getPwdExpiry(),
					attributes.getAttributes(),
					record.getPolicy(),
					record.getMaxTicketLife(),
					record.getMaxRenewableLife(),
					mask);

			return new Uid(AttributeUtil.getStringValue(name));
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
		int remaining = 0;

		logger.info("Executing query: {0}, options {1}", query, options);
		if (options.getPageSize() != null && 0 < options.getPageSize()) {
			logger.info("Paged search was requested. Offset: {0}. Page size: {1}", options.getPagedResultsOffset(), options.getPageSize());

			KerberosSearchResults results;
			int offset = 0;

			if (options.getPagedResultsOffset() != null) {
				offset = options.getPagedResultsOffset();
				if (offset < 1) throw new KerberosException("Page search \"next\" not supported");
				offset--;
			}
			results = krb5_search(query, options.getPageSize(), offset);

			if (results != null) {
				remaining = results.remaining;
				for (KerberosPrincipal principal : results.principals) {
					if (!handler.handle(principal.toConnectorObject())) {
						//Stop iterating because the handler stopped processing
						remaining = -1;
						break;
					}
				}
			}

			if (handler instanceof SearchResultsHandler) {
				logger.info("Page search remaining: {0}", remaining);
				((SearchResultsHandler)handler).handleResult(new SearchResult("NO_COOKIE", remaining));
			}
		} else {
			logger.info("Full search was requested.");
			KerberosSearchResults results = krb5_search(query, 0, 0);
			if (results != null) {
				for (KerberosPrincipal principal : results.principals) {
					if (!handler.handle(principal.toConnectorObject())) {
						//Stop iterating because the handler stopped processing
						break;
					}
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
			KerberosPrincipal record = new KerberosPrincipal(replaceAttributes);
			KerberosFlags attributes = record.getAttributes();
			int mask = record.getUpdateMask();

			// set of principal flags to set
			Set<String> flags = KerberosFlags.selectFlagAttributes(attributesAccessor.listAttributeNames());
			// get current attributes if needed - when setting some flags or enable/disable
			if (!attributesAccessor.hasAttribute("attributes") && (!flags.isEmpty() || attributesAccessor.hasAttribute(OperationalAttributes.ENABLE_NAME))) {
				logger.info("Getting principal {0} to get current attributes", uid.getUidValue());
				KerberosSearchResults results = krb5_search(uid.getUidValue(), 0, 0);
				if (results.principals == null || results.principals.length != 1)
					throw new UnknownUidException("Modified principal " + uid.getUidValue() + " not found!");

				attributes = results.principals[0].getAttributes();
				mask |= KerberosPrincipal.MASK_ATTRIBUTES;
			}
			// modify principal attributes
			for (String flag : flags) {
				attributes.setFlag(flag, attributesAccessor.findBoolean(flag));
				mask |= KerberosPrincipal.MASK_ATTRIBUTES;
			}
			// enable/disable principal using "allowTix" flag
			if (attributesAccessor.hasAttribute(OperationalAttributes.ENABLE_NAME)) {
				boolean enable = attributesAccessor.findBoolean(OperationalAttributes.ENABLE_NAME);
				attributes.setFlag(KerberosPrincipal.ATTR_ALLOW_TIX, enable);
				mask |= KerberosPrincipal.MASK_ATTRIBUTES;
			}

			if (mask != 0) {
				if ((mask & KerberosPrincipal.MASK_ATTRIBUTES) != 0) {
					logger.info("New Kerberos principal attributes of {0}: {1}", uid.getUidValue(), attributes.getAttributes());
				}
				logger.info("Modifying Kerberos principal {0}, update mask {1}", uid.getUidValue(), mask);
				krb5_modify(
					uid.getUidValue(),
					record.getPrincExpiry(),
					record.getPwdExpiry(),
					attributes.getAttributes(),
					record.getPolicy(),
					record.getMaxTicketLife(),
					record.getMaxRenewableLife(),
					mask);
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

		attributes.add(AttributeInfoBuilder.build(KerberosPrincipal.ATTR_PASSWORD_CHANGE_DATE,
				long.class, EnumSet.of(Flags.NOT_CREATABLE, Flags.NOT_UPDATEABLE)));

		attributes.add(AttributeInfoBuilder.build(KerberosPrincipal.ATTR_LAST_LOGIN_DATE,
				long.class, EnumSet.of(Flags.NOT_CREATABLE, Flags.NOT_UPDATEABLE)));

		attributes.add(AttributeInfoBuilder.build(KerberosPrincipal.ATTR_LAST_FAILED_DATE,
				long.class, EnumSet.of(Flags.NOT_CREATABLE, Flags.NOT_UPDATEABLE)));

		attributes.add(AttributeInfoBuilder.build(KerberosPrincipal.ATTR_MODIFY_PRINCIPAL,
			String.class, EnumSet.of(Flags.NOT_CREATABLE, Flags.NOT_UPDATEABLE)));

		attributes.add(AttributeInfoBuilder.build(KerberosPrincipal.ATTR_MODIFY_DATE,
			long.class, EnumSet.of(Flags.NOT_CREATABLE, Flags.NOT_UPDATEABLE)));

		attributes.add(AttributeInfoBuilder.build(KerberosPrincipal.ATTR_ATTRIBUTES, int.class));
		attributes.add(AttributeInfoBuilder.build(KerberosPrincipal.ATTR_POLICY, String.class));
		attributes.add(AttributeInfoBuilder.build(KerberosPrincipal.ATTR_MAX_TICKET_LIFE, long.class));
		attributes.add(AttributeInfoBuilder.build(KerberosPrincipal.ATTR_MAX_RENEWABLE_LIFE, long.class));

		for (String flag : KerberosFlags.FLAGS) {
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
